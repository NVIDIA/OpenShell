// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bytes the workload receives as a read-only file.
//!
//! A [`SealedFile`] holds one immutable byte sequence in an anonymous
//! in-memory file. The bytes are written once, the file is sealed against
//! writes, growing, shrinking, and further sealing, and the only descriptor
//! kept is read-only. Each caller open is a new read-only open file
//! description of that file, positioned at its start, so no two holders share
//! a file offset. The reopen walks no path: it goes through this process's
//! own descriptor table in procfs, opened once and verified to be procfs.
//!
//! This module decides nothing about which workload paths such a file
//! serves; it is the backing that provider files and the supervisor CA trust
//! files share. Its metadata, as the kernel reports it for a descriptor of
//! the file, is also what the broker reports for the virtual path.

#![allow(unsafe_code)]

use std::fs::File;
use std::io::{self, Write as _};
use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd as _, OwnedFd};
use std::sync::{Arc, OnceLock};

use rustix::fs::{Mode, OFlags, SealFlags};

use crate::linux::seccomp_notify::NotificationListener;

/// Every seal a sealed file carries. A file that cannot carry all of them is
/// not published.
const REQUIRED_SEALS: SealFlags = SealFlags::SEAL
    .union(SealFlags::WRITE)
    .union(SealFlags::GROW)
    .union(SealFlags::SHRINK);

/// This process's own descriptor table in procfs.
///
/// Opening a descriptor's entry here yields a new open file description of
/// the same file. The directory is opened once and verified to be procfs, so
/// a later reopen walks no path.
pub struct OwnDescriptors(OwnedFd);

impl OwnDescriptors {
    pub(crate) fn open() -> io::Result<Self> {
        let directory = rustix::fs::open(
            "/proc/self/fd",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        if rustix::fs::fstatfs(&directory)?.f_type != rustix::fs::PROC_SUPER_MAGIC {
            return Err(io::Error::other("/proc/self/fd is not on procfs"));
        }
        Ok(Self(directory))
    }

    /// The descriptor table shared by every sealed file of this process,
    /// opened by the first caller that needs it.
    pub(crate) fn shared() -> io::Result<Arc<Self>> {
        static SHARED: OnceLock<Arc<OwnDescriptors>> = OnceLock::new();
        if let Some(descriptors) = SHARED.get() {
            return Ok(Arc::clone(descriptors));
        }
        let opened = Arc::new(Self::open()?);
        Ok(Arc::clone(SHARED.get_or_init(|| opened)))
    }

    /// A new read-only open file description of the file `descriptor` refers
    /// to, positioned at its start. Duplicating `descriptor` instead would
    /// share one file offset between every holder.
    fn reopen_read_only(&self, descriptor: impl AsFd) -> io::Result<OwnedFd> {
        self.reopen(descriptor, OFlags::RDONLY | OFlags::NOCTTY)
    }

    fn reopen(&self, descriptor: impl AsFd, flags: OFlags) -> io::Result<OwnedFd> {
        Ok(rustix::fs::openat(
            &self.0,
            rustix::path::DecInt::new(descriptor.as_fd().as_raw_fd()),
            flags | OFlags::CLOEXEC,
            Mode::empty(),
        )?)
    }
}

/// The size of the native `struct stat` the `stat` family fills: 144 bytes
/// on x86-64 and 128 bytes on `AArch64`, where the libc layout is the kernel's.
pub const STAT_SIZE: usize = size_of::<libc::stat>();
/// The size of `struct statx`, fixed by the UAPI.
pub const STATX_SIZE: usize = 256;

const _: () = assert!(
    (cfg!(target_arch = "x86_64") && STAT_SIZE == 144)
        || (cfg!(target_arch = "aarch64") && STAT_SIZE == 128)
);

/// A kernel-filled `struct stat`, kept as bytes.
///
/// The kernel zero-fills the whole structure before copying it out, so the
/// bytes carry no padding this process left behind.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct StatBytes(pub [u8; STAT_SIZE]);

/// A kernel-filled `struct statx`, kept as bytes.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct StatxBytes(pub [u8; STATX_SIZE]);

/// One immutable byte sequence, delivered as a read-only file.
///
/// The writable descriptor `memfd_create` returns is closed before the value
/// exists, so no code path holds a descriptor that could change the bytes
/// even without the seals.
pub struct SealedFile {
    anchor: OwnedFd,
    mode: Mode,
    descriptors: Arc<OwnDescriptors>,
}

impl SealedFile {
    /// Write `content` once and seal it. `name` is the memfd's debugging
    /// name, and `mode` is what the file reports to `fstat`; neither
    /// protects the content, the seals and the read-only descriptors do.
    pub(crate) fn create(
        name: &str,
        mode: Mode,
        content: &[u8],
        descriptors: &Arc<OwnDescriptors>,
    ) -> io::Result<Self> {
        let writable = rustix::fs::memfd_create(
            name,
            rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
        )?;
        rustix::fs::fchmod(&writable, mode)?;
        let mut writable = File::from(writable);
        writable.write_all(content)?;
        rustix::fs::fcntl_add_seals(&writable, REQUIRED_SEALS)?;
        // Fail closed: the kernel reported the seals applied, and the file
        // must agree before anything is served from it.
        if !rustix::fs::fcntl_get_seals(&writable)?.contains(REQUIRED_SEALS) {
            return Err(io::Error::other("in-memory file did not accept every seal"));
        }
        let anchor = descriptors.reopen_read_only(&writable)?;
        drop(writable);
        if rustix::fs::fcntl_getfl(&anchor)? & OFlags::ACCMODE != OFlags::RDONLY {
            return Err(io::Error::other(
                "retained in-memory file descriptor is not read-only",
            ));
        }
        Ok(Self {
            anchor,
            mode,
            descriptors: Arc::clone(descriptors),
        })
    }

    /// A descriptor for one caller open: its own read-only open file
    /// description, positioned at the start of the file.
    pub(crate) fn open(&self) -> io::Result<OwnedFd> {
        match self.descriptors.reopen_read_only(&self.anchor) {
            // Every open shares one file, which the workload owns as well and
            // may have made unreadable through a descriptor it holds. Its
            // mode is not what protects the content, so restore it rather
            // than fail opens until the file is replaced.
            Err(error) if error.raw_os_error() == Some(libc::EACCES) => {
                rustix::fs::fchmod(&self.anchor, self.mode)?;
                self.descriptors.reopen_read_only(&self.anchor)
            }
            opened => opened,
        }
    }

    /// Open the file for the notifying workload task and complete its open
    /// syscall with the injected descriptor, in one kernel operation.
    pub(crate) fn inject(
        &self,
        listener: &NotificationListener,
        notification_id: u64,
        close_on_exec: bool,
    ) -> io::Result<()> {
        let file = self.open()?;
        listener.add_fd_and_send(notification_id, file.as_raw_fd(), close_on_exec)?;
        Ok(())
    }

    /// The native `struct stat` of the file, exactly what `fstat` reports on
    /// an injected descriptor.
    pub(crate) fn stat(&self) -> io::Result<StatBytes> {
        let mut bytes = StatBytes([0; STAT_SIZE]);
        // SAFETY: the buffer is a live, 8-byte aligned region of exactly the
        // native struct stat size, which the kernel fills whole.
        let result = unsafe {
            libc::syscall(
                libc::SYS_fstat,
                self.anchor.as_raw_fd(),
                bytes.0.as_mut_ptr(),
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(bytes)
    }

    /// The `struct statx` of the file for `mask`, with `sync_flags` from the
    /// caller's `AT_STATX_SYNC_TYPE` bits: exactly what `statx` reports on an
    /// injected descriptor.
    pub(crate) fn statx(&self, sync_flags: u32, mask: u32) -> io::Result<StatxBytes> {
        let mut bytes = StatxBytes([0; STATX_SIZE]);
        // SAFETY: the empty path is NUL-terminated and the buffer is a live,
        // 8-byte aligned 256-byte region, which the kernel fills whole.
        let result = unsafe {
            libc::syscall(
                libc::SYS_statx,
                self.anchor.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_EMPTY_PATH | i32::try_from(sync_flags).map_err(io::Error::other)?,
                mask,
                bytes.0.as_mut_ptr(),
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(bytes)
    }

    /// The one descriptor retained for the file.
    #[cfg(test)]
    pub(crate) fn anchor(&self) -> std::os::fd::BorrowedFd<'_> {
        self.anchor.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::{OwnDescriptors, REQUIRED_SEALS, SealedFile};
    use std::fs::File;
    use std::io::{self, Read as _, Seek as _, SeekFrom};
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{FileExt as _, MetadataExt as _, PermissionsExt as _};

    const MODE: rustix::fs::Mode = rustix::fs::Mode::from_bits_truncate(0o600);

    fn sealed(content: &[u8]) -> SealedFile {
        SealedFile::create("test", MODE, content, &OwnDescriptors::shared().unwrap()).unwrap()
    }

    fn identity(file: &File) -> (u64, u64) {
        let metadata = file.metadata().unwrap();
        (metadata.dev(), metadata.ino())
    }

    #[test]
    fn binary_and_empty_content_round_trip_exactly() {
        let binary = (0..=255_u8).cycle().take(70_000).collect::<Vec<_>>();
        for content in [binary.as_slice(), b"", b"\0", b"no newline"] {
            let mut read = Vec::new();
            File::from(sealed(content).open().unwrap())
                .read_to_end(&mut read)
                .unwrap();
            assert_eq!(read, content);
        }
    }

    #[test]
    fn every_open_is_an_independent_read_only_description_of_one_sealed_file() {
        let file = sealed(b"0123456789");
        let mut first = File::from(file.open().unwrap());
        let mut second = File::from(file.open().unwrap());

        let mut head = [0_u8; 4];
        first.read_exact(&mut head).unwrap();
        assert_eq!(&head, b"0123");
        let mut whole = Vec::new();
        second.read_to_end(&mut whole).unwrap();
        assert_eq!(whole, b"0123456789");
        let mut rest = Vec::new();
        first.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"456789");
        second.seek(SeekFrom::Start(8)).unwrap();
        assert_eq!(first.stream_position().unwrap(), 10);

        assert_eq!(identity(&first), identity(&second));
        for opened in [&first, &second] {
            assert_eq!(opened.metadata().unwrap().mode() & 0o7777, 0o600);
            assert_eq!(
                rustix::fs::fcntl_getfl(opened).unwrap() & rustix::fs::OFlags::ACCMODE,
                rustix::fs::OFlags::RDONLY
            );
            assert!(
                rustix::fs::fcntl_get_seals(opened)
                    .unwrap()
                    .contains(REQUIRED_SEALS)
            );
            assert!(opened.write_at(b"changed", 0).is_err());
            assert!(opened.set_len(0).is_err());
        }
        assert_eq!(
            rustix::fs::fcntl_getfl(file.anchor()).unwrap() & rustix::fs::OFlags::ACCMODE,
            rustix::fs::OFlags::RDONLY
        );
    }

    #[test]
    fn metadata_describes_the_same_file_an_open_descriptor_does() {
        use std::mem::offset_of;
        let file = sealed(b"0123456789");
        let opened = File::from(file.open().unwrap());
        let expected = opened.metadata().unwrap();

        let stat = file.stat().unwrap();
        let field =
            |offset: usize| u64::from_ne_bytes(stat.0[offset..offset + 8].try_into().unwrap());
        assert_eq!(field(offset_of!(libc::stat, st_ino)), expected.ino());
        assert_eq!(field(offset_of!(libc::stat, st_dev)), expected.dev());
        let size_offset = offset_of!(libc::stat, st_size);
        assert_eq!(
            i64::from_ne_bytes(stat.0[size_offset..size_offset + 8].try_into().unwrap()),
            10
        );
        let mode_offset = offset_of!(libc::stat, st_mode);
        let mode = u32::from_ne_bytes(stat.0[mode_offset..mode_offset + 4].try_into().unwrap());
        assert_eq!(mode, expected.mode());
        assert_eq!(mode & libc::S_IFMT, libc::S_IFREG);

        // statx: mask, mode, inode, and size at their UAPI offsets.
        let statx = file.statx(0, 0x0000_07ff).unwrap();
        let word =
            |offset: usize| u32::from_ne_bytes(statx.0[offset..offset + 4].try_into().unwrap());
        assert_ne!(word(0) & 0x0000_0200, 0, "STATX_SIZE is reported");
        assert_eq!(
            u16::from_ne_bytes(statx.0[28..30].try_into().unwrap()),
            u16::try_from(expected.mode()).unwrap()
        );
        assert_eq!(
            u64::from_ne_bytes(statx.0[32..40].try_into().unwrap()),
            expected.ino()
        );
        assert_eq!(u64::from_ne_bytes(statx.0[40..48].try_into().unwrap()), 10);
    }

    #[test]
    fn seals_hold_against_a_writable_reopen_by_the_owner() {
        let file = sealed(b"sealed");
        let held = File::from(file.open().unwrap());
        let link = format!("/proc/self/fd/{}", held.as_raw_fd());
        for options in [
            std::fs::OpenOptions::new().write(true).clone(),
            std::fs::OpenOptions::new().read(true).write(true).clone(),
            std::fs::OpenOptions::new().append(true).clone(),
        ] {
            if let Ok(writable) = options.open(&link) {
                assert!(writable.write_at(b"changed", 0).is_err());
                assert!(io::Write::write_all(&mut &writable, b"changed").is_err());
                assert!(writable.set_len(0).is_err());
                assert!(writable.set_len(1 << 20).is_err());
                assert!(
                    rustix::fs::fcntl_add_seals(&writable, rustix::fs::SealFlags::empty()).is_err()
                );
            }
        }
        assert!(
            std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&link)
                .is_err()
        );
        let mut content = Vec::new();
        File::from(file.open().unwrap())
            .read_to_end(&mut content)
            .unwrap();
        assert_eq!(content, b"sealed");
    }

    #[test]
    fn a_cleared_mode_does_not_deny_the_next_open() {
        let file = sealed(b"key");
        let held = File::from(file.open().unwrap());
        held.set_permissions(std::fs::Permissions::from_mode(0o000))
            .unwrap();
        // Whether the cleared mode denies the reopen depends on the caller:
        // an identity with CAP_DAC_OVERRIDE is never denied, so there is
        // nothing to restore and the mode may stay cleared.
        let denied = match file.descriptors.reopen_read_only(file.anchor()) {
            Ok(_) => false,
            Err(error) if error.raw_os_error() == Some(libc::EACCES) => true,
            Err(error) => panic!("unexpected reopen failure: {error}"),
        };
        let reopened = File::from(file.open().unwrap());
        if denied {
            assert_eq!(reopened.metadata().unwrap().mode() & 0o7777, 0o600);
        }
        let mut content = Vec::new();
        (&reopened).read_to_end(&mut content).unwrap();
        assert_eq!(content, b"key");
    }
}
