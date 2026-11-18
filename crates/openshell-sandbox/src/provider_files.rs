// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Read-only virtual files: provider files and the supervisor CA trust pair.
//!
//! Neither kind exists on any filesystem. Every workload file open notifies
//! the broker, which serves a path beneath the provider prefix, or one of the
//! two canonical CA trust paths, by injecting a read-only descriptor for a
//! sealed in-memory file, and continues every other open. Every path-based
//! `stat`, `statx`, and `access` call notifies as well; for a virtual path the
//! broker writes the result the injected descriptor would report into the
//! caller's buffer, and continues every other path.
//!
//! What a virtual path supports is exactly this: an absolute, canonical path
//! (no `..`, no trailing slash, no symlink, no relative lookup through a
//! directory descriptor), opened read-only, and queried through `stat`,
//! `lstat`, `fstatat`, `statx`, and `access`. The directories above a virtual
//! file do not exist: `chdir`, `opendir`, and `stat` of the directory are
//! `ENOENT`, and a relative or aliased path is left to the kernel, which finds
//! nothing there. A write-capable open is `EACCES`; `O_DIRECTORY` is
//! `ENOTDIR`; `O_PATH` is `EINVAL`.
//!
//! Two things are kept apart. A [`Revision`] is one immutable version of one
//! file, and a [`Snapshot`] is the complete set a publication replaces at
//! once; neither knows how bytes reach the workload. What a revision prepares
//! at publication is its backing, a [`SealedFile`], created once when the
//! revision is published and reopened for each workload open. The CA trust
//! pair from [`crate::ca_trust_files`] shares the backing but is published
//! separately from, and never removed by, a provider file update.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, RwLock};

use rustix::fs::Mode;

use crate::ca_trust_files::{CaTrustFiles, TrustFile};
use crate::linux::sealed_file::{OwnDescriptors, SealedFile};
use crate::linux::seccomp_notify::{Notification, NotificationListener};
use crate::linux::task_memory;

const PREFIX: &str = "/run/openshell/providers/";
const PROC_PREFIX: &str = "/proc/";
const MAX_FILE_BYTES: usize = 65_536;
pub const MAX_TOTAL_BYTES: usize = 262_144;
const MAX_PATH_BYTES: usize = 4_096;

/// The flags `fstatat` accepts; `statx` also accepts `AT_STATX_SYNC_TYPE`.
const STAT_FLAGS: u32 =
    (libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT | libc::AT_EMPTY_PATH) as u32;
/// `AT_STATX_SYNC_TYPE`: the UAPI mask of the `statx` sync flags, which the
/// `libc` crate does not expose on every target.
const AT_STATX_SYNC_TYPE: u32 = 0x6000;
const STATX_FLAGS: u32 = STAT_FLAGS | AT_STATX_SYNC_TYPE;
/// `AT_EACCESS`, also absent from `libc` on some targets.
const AT_EACCESS: u32 = 0x200;
/// The flags `faccessat2` accepts.
const ACCESS_FLAGS: u32 = AT_EACCESS | (libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH) as u32;
/// The `access` modes: `R_OK | W_OK | X_OK`.
const ACCESS_MODES: u32 = (libc::R_OK | libc::W_OK | libc::X_OK) as u32;
/// `STATX__RESERVED`: a mask with this bit set is refused.
const STATX_RESERVED_MASK: u32 = 0x8000_0000;

/// The mode a provider file reports. It keeps the file's metadata private
/// to the sandbox identity; the seals and the read-only descriptor protect
/// its content.
const FILE_MODE: Mode = Mode::from_bits_truncate(0o600);

/// One immutable version of one provider file: its bytes, and what was
/// prepared at publication to serve them.
struct Revision<Backing> {
    content: Box<[u8]>,
    backing: Backing,
}

/// A complete generation of provider files, by path.
type Snapshot<Backing> = HashMap<String, Arc<Revision<Backing>>>;

/// Build the generation that holds exactly `desired`.
///
/// A path whose bytes are unchanged keeps its revision, and with it the
/// backing every earlier open of that path used. Every other file gets a new
/// revision from `prepare`. Nothing is published here: if `prepare` fails,
/// the revisions already prepared are dropped and `current` is untouched.
fn next_snapshot<Backing>(
    current: &Snapshot<Backing>,
    desired: HashMap<String, String>,
    mut prepare: impl FnMut(&[u8]) -> io::Result<Backing>,
) -> io::Result<Snapshot<Backing>> {
    desired
        .into_iter()
        .map(|(path, content)| {
            let revision = match current.get(&path) {
                Some(revision) if *revision.content == *content.as_bytes() => Arc::clone(revision),
                _ => Arc::new(Revision {
                    backing: prepare(content.as_bytes())?,
                    content: content.into_bytes().into_boxed_slice(),
                }),
            };
            Ok((path, revision))
        })
        .collect()
}

/// The sealed in-memory file behind one provider revision.
fn prepare_backing(content: &[u8]) -> io::Result<SealedFile> {
    SealedFile::create(
        "openshell-provider",
        FILE_MODE,
        content,
        &OwnDescriptors::shared()?,
    )
}

/// The published generation of provider files, and the supervisor trust
/// files served with them.
#[derive(Default)]
struct VirtualFiles {
    /// Replaced as a whole. Open handlers clone the selected revision before
    /// dropping the lock, so an update never waits on a workload open and a
    /// revision outlives its generation for as long as an open uses it.
    current: RwLock<Arc<Snapshot<SealedFile>>>,
    /// Published once the CA material is installed, before the workload
    /// starts. A provider file update does not touch it.
    ca_trust: CaTrustFiles,
}

impl VirtualFiles {
    fn snapshot(&self) -> Arc<Snapshot<SealedFile>> {
        Arc::clone(
            &self
                .current
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    fn revision(&self, path: &str) -> Option<Arc<Revision<SealedFile>>> {
        self.current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(path)
            .cloned()
    }

    fn publish(&self, desired: HashMap<String, String>) -> io::Result<()> {
        self.publish_with(desired, prepare_backing)
    }

    /// Replace the generation with exactly `desired`, or leave it untouched.
    ///
    /// Every new revision is prepared before the publication lock is taken,
    /// which is then held only to exchange the generation. Concurrent
    /// publications each publish a complete generation, and the last to
    /// take the lock is the one new opens see.
    fn publish_with(
        &self,
        desired: HashMap<String, String>,
        prepare: impl FnMut(&[u8]) -> io::Result<SealedFile>,
    ) -> io::Result<()> {
        let next = Arc::new(next_snapshot(&self.snapshot(), desired, prepare)?);
        let replaced = std::mem::replace(
            &mut *self
                .current
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            next,
        );
        // Closes the backing of revisions no open still uses, after the lock.
        drop(replaced);
        Ok(())
    }
}

/// The provider files of one sandbox.
#[derive(Clone, Default)]
pub struct ProviderFiles {
    files: Arc<VirtualFiles>,
}

impl ProviderFiles {
    pub(crate) fn validate(desired: &HashMap<String, String>) -> io::Result<()> {
        if desired.len() > 64 || desired.values().map(String::len).sum::<usize>() > MAX_TOTAL_BYTES
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "provider file set is too large",
            ));
        }
        for (path, content) in desired {
            validate_path(path)?;
            if content.len() > MAX_FILE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "provider file exceeds 64 KiB",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn replace(&self, desired: HashMap<String, String>) -> io::Result<()> {
        Self::validate(&desired)?;
        self.files.publish(desired)
    }

    /// Publish the supervisor CA certificate and combined trust bundle the
    /// workload opens at their canonical paths.
    ///
    /// Call this after the real files are installed and before the workload
    /// starts. The pair is cached and plain read-only opens of exactly those
    /// paths receive a sealed copy. A refused pair fails closed and a
    /// previously published pair stays as it was.
    pub(crate) fn publish_ca_trust(&self, ca_cert: &[u8], ca_bundle: &[u8]) -> io::Result<()> {
        self.files.ca_trust.publish(ca_cert, ca_bundle)
    }

    /// Forget any published trust pair, so every open of the canonical paths
    /// continues to the kernel again.
    ///
    /// Call this before a workload starts without CA material: a pair cached
    /// by an earlier, failed start must not outlive the installation it
    /// mirrored. Independent of provider file updates, which never touch
    /// the pair.
    pub(crate) fn clear_ca_trust(&self) {
        self.files.ca_trust.clear();
    }

    /// The cached trust pair.
    #[cfg(test)]
    pub(crate) fn ca_trust(&self) -> &CaTrustFiles {
        &self.files.ca_trust
    }

    /// Answer a workload `open`, `openat`, or `openat2`.
    pub(crate) fn handle_open(
        &self,
        listener: &NotificationListener,
        notification: Notification,
    ) -> io::Result<()> {
        let syscall = i64::from(notification.syscall);
        let path_address = if syscall == libc::SYS_openat || syscall == libc::SYS_openat2 {
            notification.args[1]
        } else {
            notification.args[0]
        };
        let file = match self.classify(listener, &notification, path_address)? {
            Classified::Served(file) => file,
            Classified::Done => return Ok(()),
            Classified::Proc => {
                if handle_thread_comm_open(listener, notification, path_address)? {
                    return Ok(());
                }
                return listener.respond_continue(notification.id);
            }
        };
        inject_read_only(listener, &notification, file.backing())
    }

    /// Answer a workload path-based `stat`, `statx`, or `access` call.
    pub(crate) fn handle_metadata(
        &self,
        listener: &NotificationListener,
        notification: Notification,
    ) -> io::Result<()> {
        let request = MetadataRequest::parse(&notification)?;
        let file = match self.classify(listener, &notification, request.path_address())? {
            Classified::Served(file) => file,
            Classified::Done => return Ok(()),
            Classified::Proc => return listener.respond_continue(notification.id),
        };
        let backing = file.backing();
        match request {
            MetadataRequest::Stat { flags, buffer, .. } => {
                if flags & !STAT_FLAGS != 0 {
                    return listener.respond_errno(notification.id, libc::EINVAL);
                }
                complete_with_result(listener, &notification, buffer, &backing.stat()?.0)
            }
            MetadataRequest::Statx {
                flags,
                mask,
                buffer,
                ..
            } => {
                if flags & !STATX_FLAGS != 0 || mask & STATX_RESERVED_MASK != 0 {
                    return listener.respond_errno(notification.id, libc::EINVAL);
                }
                let sync = flags & AT_STATX_SYNC_TYPE;
                complete_with_result(
                    listener,
                    &notification,
                    buffer,
                    &backing.statx(sync, mask)?.0,
                )
            }
            MetadataRequest::Access { mode, flags, .. } => {
                if mode & !ACCESS_MODES != 0 || flags & !ACCESS_FLAGS != 0 {
                    return listener.respond_errno(notification.id, libc::EINVAL);
                }
                // The file is readable and nothing else, whichever identity
                // the call checks.
                if mode & ACCESS_MODES != libc::R_OK as u32 && mode != libc::F_OK as u32 {
                    return listener.respond_errno(notification.id, libc::EACCES);
                }
                listener.respond_value(notification.id, 0)
            }
        }
    }

    /// Decide whether the path at `path_address` is a virtual file.
    ///
    /// Every workload open and metadata call reaches the listener, and
    /// nearly all of them name ordinary paths the kernel decides. One exact
    /// copy of the path's first six bytes tells those apart from the paths
    /// served here, at no other cost to an ordinary call. Six bytes are
    /// enough: `/proc/` is six bytes, and every provider path and both CA
    /// trust paths share the first six bytes of the provider prefix and are
    /// longer than that. A copy that fails is an unreadable pointer or a
    /// shorter path ending before an unmapped page: neither is served, and
    /// the kernel resolves the path or reports its own EFAULT.
    ///
    /// The copy only classifies. A candidate has its whole path read and is
    /// decided from that copy alone: a published virtual file is served
    /// whatever the flags, an unpublished path beneath the provider prefix is
    /// `ENOENT`, and everything else, including an alias of a virtual path,
    /// continues to the kernel, which finds nothing of ours there.
    fn classify(
        &self,
        listener: &NotificationListener,
        notification: &Notification,
        path_address: u64,
    ) -> io::Result<Classified> {
        let mut start = [0_u8; PROC_PREFIX.len()];
        if task_memory::read_exact(notification.tid, path_address, &mut start).is_err() {
            listener.respond_continue(notification.id)?;
            return Ok(Classified::Done);
        }
        if start == PROC_PREFIX.as_bytes() {
            return Ok(Classified::Proc);
        }
        if start == PREFIX.as_bytes()[..PROC_PREFIX.len()]
            && let Ok(path) = read_path(notification.tid, path_address)
        {
            if let Some(file) = self.files.lookup(&path) {
                return Ok(Classified::Served(file));
            }
            if path.starts_with(PREFIX) {
                listener.respond_errno(notification.id, libc::ENOENT)?;
                return Ok(Classified::Done);
            }
        }
        listener.respond_continue(notification.id)?;
        Ok(Classified::Done)
    }
}

enum Classified {
    /// A published virtual file; the caller answers from it.
    Served(VirtualFile),
    /// The notification was answered here.
    Done,
    /// A `/proc/` path, which only the open handler looks at further.
    Proc,
}

/// One published file, held so a concurrent publication cannot close its
/// backing while it is served.
enum VirtualFile {
    Provider(Arc<Revision<SealedFile>>),
    Trust(TrustFile),
}

impl VirtualFile {
    fn backing(&self) -> &SealedFile {
        match self {
            Self::Provider(revision) => &revision.backing,
            Self::Trust(file) => file.backing(),
        }
    }
}

impl VirtualFiles {
    fn lookup(&self, path: &str) -> Option<VirtualFile> {
        if path.starts_with(PREFIX) {
            return self.revision(path).map(VirtualFile::Provider);
        }
        self.ca_trust.lookup(path).map(VirtualFile::Trust)
    }
}

/// A notified metadata call, with the arguments the broker checks.
enum MetadataRequest {
    Stat {
        path: u64,
        buffer: u64,
        flags: u32,
    },
    Statx {
        path: u64,
        flags: u32,
        mask: u32,
        buffer: u64,
    },
    Access {
        path: u64,
        mode: u32,
        flags: u32,
    },
}

impl MetadataRequest {
    /// The call's arguments. `int` arguments keep their low 32 bits, as the
    /// kernel reads them.
    fn parse(notification: &Notification) -> io::Result<Self> {
        let args = notification.args;
        #[allow(clippy::cast_possible_truncation)]
        let word = |index: usize| args[index] as u32;
        let syscall = i64::from(notification.syscall);
        if syscall == libc::SYS_newfstatat {
            return Ok(Self::Stat {
                path: args[1],
                buffer: args[2],
                flags: word(3),
            });
        }
        if syscall == libc::SYS_statx {
            return Ok(Self::Statx {
                path: args[1],
                flags: word(2),
                mask: word(3),
                buffer: args[4],
            });
        }
        if syscall == libc::SYS_faccessat {
            return Ok(Self::Access {
                path: args[1],
                mode: word(2),
                flags: 0,
            });
        }
        if syscall == libc::SYS_faccessat2 {
            return Ok(Self::Access {
                path: args[1],
                mode: word(2),
                flags: word(3),
            });
        }
        #[cfg(target_arch = "x86_64")]
        if syscall == libc::SYS_stat || syscall == libc::SYS_lstat {
            return Ok(Self::Stat {
                path: args[0],
                buffer: args[1],
                flags: 0,
            });
        }
        #[cfg(target_arch = "x86_64")]
        if syscall == libc::SYS_access {
            return Ok(Self::Access {
                path: args[0],
                mode: word(1),
                flags: 0,
            });
        }
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    const fn path_address(&self) -> u64 {
        match self {
            Self::Stat { path, .. } | Self::Statx { path, .. } | Self::Access { path, .. } => *path,
        }
    }
}

/// Write `result` into the notifying task at `buffer` and complete the
/// syscall with 0, or fail it with `EFAULT`.
///
/// The target is pinned before anything is written: `/proc/<tid>/mem` is
/// opened and the notification validated afterwards, which proves the pinned
/// address space is the notifying task's (see
/// [`task_memory::PinnedMemory`]). The listener's `WAIT_KILLABLE_RECV` keeps
/// the task in the syscall, so the buffer is still the caller's when the
/// write lands. A buffer the write cannot reach fails the call with `EFAULT`,
/// whatever errno the pinned file reports; every response validates the
/// notification, so a task killed meanwhile is simply no longer answered.
pub fn complete_with_result(
    listener: &NotificationListener,
    notification: &Notification,
    buffer: u64,
    result: &[u8],
) -> io::Result<()> {
    let outcome = match task_memory::PinnedMemory::open(notification.tid) {
        Ok(memory) => {
            // The task may have died between the notification and here: the
            // pinned memory would then belong to a reused TID. ENOENT means
            // the notification is gone; any other ioctl failure is an error.
            match listener.validate_id(notification.id) {
                Ok(()) => {}
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(()),
                Err(error) => return Err(error),
            }
            memory.write_exact(buffer, result)
        }
        // No such task: its procfs entry is gone (ENOENT) or it is exiting
        // (ESRCH). The response below reports whether anything is left.
        Err(error) if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => {
            Err(error)
        }
        Err(error) => return Err(error),
    };
    let response = match outcome {
        Ok(()) => listener.respond_value(notification.id, 0),
        Err(_) => listener.respond_errno(notification.id, libc::EFAULT),
    };
    match response {
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
        other => other,
    }
}

/// Complete a workload open of a virtual file, or refuse it.
///
/// Only a read-only open is served. An open that asks to create, truncate,
/// append, or write is `EACCES`, as on a read-only file; `O_DIRECTORY` is
/// `ENOTDIR`; `O_PATH` and `O_DIRECT` are `EINVAL` (a path-only descriptor
/// cannot be injected: `SECCOMP_IOCTL_NOTIF_ADDFD` refuses `O_PATH` files).
/// Nothing here is continued.
fn inject_read_only(
    listener: &NotificationListener,
    notification: &Notification,
    file: &SealedFile,
) -> io::Result<()> {
    let flags = match open_flags(notification) {
        Ok(flags) => flags,
        Err(error) => {
            return listener.respond_errno(
                notification.id,
                error.raw_os_error().unwrap_or(libc::EINVAL),
            );
        }
    };
    let close_on_exec = flags & libc::O_CLOEXEC != 0;
    // O_TMPFILE includes the O_DIRECTORY bit; a creating open is refused as
    // one before the directory bit is read.
    if flags & libc::O_TMPFILE == libc::O_TMPFILE {
        return listener.respond_errno(notification.id, libc::EACCES);
    }
    if flags & libc::O_DIRECTORY != 0 {
        return listener.respond_errno(notification.id, libc::ENOTDIR);
    }
    if flags & libc::O_ACCMODE != libc::O_RDONLY
        || flags & (libc::O_CREAT | libc::O_EXCL | libc::O_TRUNC | libc::O_APPEND) != 0
    {
        return listener.respond_errno(notification.id, libc::EACCES);
    }
    if flags & (libc::O_PATH | libc::O_DIRECT) != 0 {
        return listener.respond_errno(notification.id, libc::EINVAL);
    }
    file.inject(listener, notification.id, close_on_exec)
}

fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

fn validate_path(path: &str) -> io::Result<()> {
    let suffix = path.strip_prefix(PREFIX).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "provider file escapes managed root",
        )
    })?;
    let (provider, name) = suffix.split_once('/').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "provider file must name a provider and file",
        )
    })?;
    if !safe_component(provider) || !safe_component(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid provider file path",
        ));
    }
    Ok(())
}

/// Serve a write open of the caller's own thread name file.
///
/// `pthread_setname_np` and CUDA's `cuInit` rename threads by writing
/// `/proc/<pid>/task/<tid>/comm`. Landlock keeps `/proc` read-only, so the
/// broker opens the caller's own `comm` file and injects the descriptor; no
/// syscall is continued. The kernel's `comm_write` accepts a write only from
/// the target's own thread group, so a substituted path or reused thread ID
/// cannot rename another process's thread through the descriptor. Returns
/// `false` when the open is not such a request and normal mediation applies.
///
/// Called only for a path whose first six bytes were seen to be `/proc/`.
/// That is a hint, not authority: the path is read whole here and decided
/// from that copy alone.
fn handle_thread_comm_open(
    listener: &NotificationListener,
    notification: Notification,
    path_address: u64,
) -> io::Result<bool> {
    let Ok(flags) = open_flags(&notification) else {
        return Ok(false);
    };
    let access = flags & libc::O_ACCMODE;
    // Reads are already allowed by the read-only /proc rule.
    if access == libc::O_RDONLY {
        return Ok(false);
    }
    let Ok(path) = read_path(notification.tid, path_address) else {
        return Ok(false);
    };
    let Some(caller_group) = thread_group_of(notification.tid) else {
        return Ok(false);
    };
    let Some(target) = comm_target(&path, notification.tid, caller_group) else {
        return Ok(false);
    };
    // Anything else, including another process's thread, is left to
    // Landlock, which denies the write.
    if thread_group_of(target) != Some(caller_group) {
        return Ok(false);
    }
    // A shell redirect opens with O_CREAT|O_TRUNC; both are no-ops on an
    // existing comm file. O_EXCL fails as it would natively.
    if flags & libc::O_EXCL != 0 {
        listener.respond_errno(notification.id, libc::EEXIST)?;
        return Ok(true);
    }
    if flags & (libc::O_TMPFILE | libc::O_DIRECTORY | libc::O_PATH) != 0 {
        listener.respond_errno(notification.id, libc::EINVAL)?;
        return Ok(true);
    }
    let file = std::fs::OpenOptions::new()
        .read(access == libc::O_RDWR)
        .write(true)
        .open(format!("/proc/{caller_group}/task/{target}/comm"))?;
    listener.add_fd_and_send(
        notification.id,
        std::os::fd::AsRawFd::as_raw_fd(&file),
        flags & libc::O_CLOEXEC != 0,
    )?;
    Ok(true)
}

/// Resolve the thread whose `comm` file `path` names, if it is the caller's
/// own thread group.
fn comm_target(path: &str, caller_tid: u32, caller_group: u32) -> Option<u32> {
    let parts = path
        .strip_prefix(PROC_PREFIX)?
        .split('/')
        .collect::<Vec<_>>();
    let own_group = |part: &str| part == "self" || part.parse::<u32>().ok() == Some(caller_group);
    match parts.as_slice() {
        ["thread-self", "comm"] => Some(caller_tid),
        [group, "comm"] if own_group(group) => Some(caller_group),
        [group, "task", tid, "comm"] if own_group(group) => tid.parse().ok(),
        _ => None,
    }
}

/// Thread group (process) ID of a thread, from its procfs status.
fn thread_group_of(tid: u32) -> Option<u32> {
    std::fs::read_to_string(format!("/proc/{tid}/status"))
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("Tgid:"))?
        .trim()
        .parse()
        .ok()
}

fn read_path(tid: u32, mut address: u64) -> io::Result<String> {
    if address == 0 {
        return Err(io::Error::from_raw_os_error(libc::EFAULT));
    }
    let mut path = Vec::with_capacity(128);
    while path.len() < MAX_PATH_BYTES {
        // VMAs are page aligned. Never read across a page boundary before
        // finding NUL, because the following page may be unmapped.
        let page_remaining = 4096 - usize::try_from(address & 4095).expect("page offset fits");
        let length = page_remaining.min(MAX_PATH_BYTES - path.len());
        let mut chunk = vec![0; length];
        task_memory::read_exact(tid, address, &mut chunk)?;
        if let Some(end) = chunk.iter().position(|byte| *byte == 0) {
            path.extend_from_slice(&chunk[..end]);
            return String::from_utf8(path).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL));
        }
        path.extend_from_slice(&chunk);
        address += length as u64;
    }
    Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG))
}

fn open_flags(notification: &Notification) -> io::Result<i32> {
    let syscall = i64::from(notification.syscall);
    if syscall == libc::SYS_openat2 {
        if notification.args[3] < 24 {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        let mut how = [0_u8; 24];
        task_memory::read_exact(notification.tid, notification.args[2], &mut how)?;
        let flags = u64::from_ne_bytes(how[0..8].try_into().expect("eight bytes"));
        let mode = u64::from_ne_bytes(how[8..16].try_into().expect("eight bytes"));
        let resolve = u64::from_ne_bytes(how[16..24].try_into().expect("eight bytes"));
        if mode != 0 || resolve != 0 {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        i32::try_from(flags).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
    } else if syscall == libc::SYS_openat {
        i32::try_from(notification.args[2]).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
    } else {
        i32::try_from(notification.args[1]).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_FILE_BYTES, ProviderFiles, VirtualFiles, comm_target, prepare_backing};
    use crate::ca_trust_files::{CA_BUNDLE_PATH, CA_CERT_PATH};
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::{self, Read as _};
    use std::os::unix::fs::{FileExt as _, MetadataExt as _};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    const CONFIG: &str = "/run/openshell/providers/acme/client.toml";
    const KEY: &str = "/run/openshell/providers/acme/key.pem";
    const TOKEN: &str = "/run/openshell/providers/other/token";

    fn files(entries: &[(&str, &str)]) -> HashMap<String, String> {
        entries
            .iter()
            .map(|(path, content)| ((*path).to_string(), (*content).to_string()))
            .collect()
    }

    fn virtual_files(provider_files: &ProviderFiles) -> &VirtualFiles {
        &provider_files.files
    }

    /// What the broker injects for a workload open of `path`, or `None`
    /// where it answers `ENOENT`.
    fn open(provider_files: &ProviderFiles, path: &str) -> Option<File> {
        let revision = virtual_files(provider_files).revision(path)?;
        Some(File::from(revision.backing.open().expect("open revision")))
    }

    fn read(provider_files: &ProviderFiles, path: &str) -> Option<String> {
        let mut content = String::new();
        open(provider_files, path)?
            .read_to_string(&mut content)
            .unwrap();
        Some(content)
    }

    /// The identity of the file a descriptor refers to.
    fn file_identity(file: &File) -> (u64, u64) {
        let metadata = file.metadata().unwrap();
        (metadata.dev(), metadata.ino())
    }

    #[test]
    fn comm_target_accepts_only_the_callers_own_thread_names() {
        let (caller_tid, group) = (4242, 4200);
        for (path, expected) in [
            ("/proc/thread-self/comm", Some(caller_tid)),
            ("/proc/self/comm", Some(group)),
            ("/proc/4200/comm", Some(group)),
            ("/proc/self/task/4243/comm", Some(4243)),
            ("/proc/4200/task/4243/comm", Some(4243)),
            // Another process's thread, or not a comm file.
            ("/proc/1/task/1/comm", None),
            ("/proc/9999/comm", None),
            ("/proc/self/task/4243/environ", None),
            ("/proc/self/task/4243/comm/extra", None),
            ("/proc/self/mem", None),
        ] {
            assert_eq!(comm_target(path, caller_tid, group), expected, "{path}");
        }
    }

    #[test]
    fn paths_cannot_escape_the_managed_tree() {
        let valid = "/run/openshell/providers/acme/client.toml";
        assert!(ProviderFiles::validate(&HashMap::from([(valid.into(), "ok".into())])).is_ok());
        for path in [
            "/etc/passwd",
            "/run/openshell/providers/acme/../passwd",
            "/run/openshell/providers/acme/sub/file",
            "/run/openshell/providers/../client.toml",
        ] {
            assert!(
                ProviderFiles::validate(&HashMap::from([(path.into(), "ok".into())])).is_err(),
                "{path}"
            );
        }
    }

    #[test]
    fn ca_trust_files_are_independent_of_provider_file_updates() {
        const CERT: &str = "-----BEGIN CERTIFICATE-----\nsupervisor\n-----END CERTIFICATE-----\n";
        let bundle = format!("{}{CERT}", "B".repeat(MAX_FILE_BYTES));
        let provider_files = ProviderFiles::default();
        let trust = provider_files.ca_trust();
        assert!(trust.lookup(CA_CERT_PATH).is_none());
        provider_files
            .publish_ca_trust(CERT.as_bytes(), bundle.as_bytes())
            .unwrap();
        let trust_file = |path: &str| {
            let file = File::from(trust.lookup(path).unwrap().backing().open().unwrap());
            (file.metadata().unwrap().len(), file_identity(&file))
        };
        let (cert_len, cert_identity) = trust_file(CA_CERT_PATH);
        let (bundle_len, bundle_identity) = trust_file(CA_BUNDLE_PATH);
        assert_eq!(cert_len, u64::try_from(CERT.len()).unwrap());
        assert_eq!(bundle_len, u64::try_from(bundle.len()).unwrap());

        provider_files
            .replace(files(&[(CONFIG, "version = 1\n")]))
            .unwrap();
        provider_files.replace(HashMap::new()).unwrap();
        assert_eq!(trust_file(CA_CERT_PATH).1, cert_identity);
        assert_eq!(trust_file(CA_BUNDLE_PATH).1, bundle_identity);
        assert!(
            virtual_files(&provider_files)
                .revision(CA_CERT_PATH)
                .is_none()
        );
        assert!(ProviderFiles::validate(&files(&[(CA_BUNDLE_PATH, "x")])).is_err());
    }

    #[test]
    fn updates_and_detach_change_later_opens_and_keep_open_descriptors() {
        let provider_files = ProviderFiles::default();
        assert!(open(&provider_files, CONFIG).is_none());
        provider_files
            .replace(files(&[(CONFIG, "version = 1\n"), (KEY, "key-1")]))
            .unwrap();
        let old_config = open(&provider_files, CONFIG).unwrap();
        let old_key = open(&provider_files, KEY).unwrap();

        // Change one file, keep one, attach one.
        provider_files
            .replace(files(&[
                (CONFIG, "version = 2\n"),
                (KEY, "key-1"),
                (TOKEN, "token"),
            ]))
            .unwrap();
        let new_config = open(&provider_files, CONFIG).unwrap();
        assert_ne!(file_identity(&new_config), file_identity(&old_config));
        assert_eq!(read(&provider_files, CONFIG).unwrap(), "version = 2\n");
        assert_eq!(read(&provider_files, TOKEN).unwrap(), "token");
        // An unchanged file keeps its revision: the same file as before.
        assert_eq!(
            file_identity(&open(&provider_files, KEY).unwrap()),
            file_identity(&old_key)
        );

        // An identical update changes nothing an open can observe.
        provider_files
            .replace(files(&[
                (CONFIG, "version = 2\n"),
                (KEY, "key-1"),
                (TOKEN, "token"),
            ]))
            .unwrap();
        assert_eq!(
            file_identity(&open(&provider_files, CONFIG).unwrap()),
            file_identity(&new_config)
        );
        assert_eq!(
            file_identity(&open(&provider_files, KEY).unwrap()),
            file_identity(&old_key)
        );

        // Detach one provider, then everything.
        provider_files.replace(files(&[(TOKEN, "token")])).unwrap();
        assert!(open(&provider_files, CONFIG).is_none());
        assert!(open(&provider_files, KEY).is_none());
        assert_eq!(read(&provider_files, TOKEN).unwrap(), "token");
        provider_files.replace(HashMap::new()).unwrap();
        assert!(open(&provider_files, TOKEN).is_none());

        // Reattaching the same bytes is a new revision, not the detached one.
        provider_files.replace(files(&[(KEY, "key-1")])).unwrap();
        assert_ne!(
            file_identity(&open(&provider_files, KEY).unwrap()),
            file_identity(&old_key)
        );

        // Descriptors opened before any of this still read what they opened.
        for (held, expected) in [
            (old_config, "version = 1\n"),
            (new_config, "version = 2\n"),
            (old_key, "key-1"),
        ] {
            let mut content = vec![0_u8; expected.len() + 1];
            let length = held.read_at(&mut content, 0).unwrap();
            assert_eq!(&content[..length], expected.as_bytes());
        }
    }

    #[test]
    fn a_refused_publication_leaves_the_published_generation() {
        let provider_files = ProviderFiles::default();
        provider_files
            .replace(files(&[(CONFIG, "version = 1\n"), (KEY, "key-1")]))
            .unwrap();
        let published = [CONFIG, KEY].map(|path| {
            (
                file_identity(&open(&provider_files, path).unwrap()),
                read(&provider_files, path).unwrap(),
            )
        });
        let unchanged = || {
            for (path, (identity, content)) in [CONFIG, KEY].into_iter().zip(&published) {
                assert_eq!(&read(&provider_files, path).unwrap(), content);
                assert_eq!(
                    &file_identity(&open(&provider_files, path).unwrap()),
                    identity
                );
            }
            assert!(open(&provider_files, TOKEN).is_none());
        };

        // Input the validation refuses, alongside otherwise valid changes.
        let oversized = "x".repeat(MAX_FILE_BYTES + 1);
        let mut too_many = files(&[(CONFIG, "version = 2\n")]);
        for index in 0..64 {
            too_many.insert(format!("/run/openshell/providers/many/{index}"), "x".into());
        }
        for refused in [
            files(&[(CONFIG, "version = 2\n"), (TOKEN, &oversized)]),
            files(&[(CONFIG, "version = 2\n"), ("/etc/passwd", "x")]),
            files(&[
                (CONFIG, "version = 2\n"),
                ("/run/openshell/providers/a/../b", "x"),
            ]),
            too_many,
        ] {
            let error = provider_files.replace(refused).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            unchanged();
        }

        // A revision that cannot be prepared, after another one was.
        let files_state = virtual_files(&provider_files);
        let mut prepared = 0;
        let error = files_state
            .publish_with(
                files(&[(CONFIG, "version = 2\n"), (KEY, "key-2"), (TOKEN, "token")]),
                |content| {
                    prepared += 1;
                    if prepared == 2 {
                        return Err(io::Error::from_raw_os_error(libc::EMFILE));
                    }
                    prepare_backing(content)
                },
            )
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EMFILE));
        assert_eq!(prepared, 2);
        unchanged();

        // Publication still works afterwards.
        provider_files.replace(files(&[(TOKEN, "token")])).unwrap();
        assert_eq!(read(&provider_files, TOKEN).unwrap(), "token");
        assert!(open(&provider_files, CONFIG).is_none());
    }

    #[test]
    fn concurrent_publications_and_opens_observe_only_complete_revisions() {
        const PATHS: [&str; 3] = [CONFIG, KEY, TOKEN];
        const GENERATIONS: usize = 150;
        // Every file of a generation carries the generation's token on
        // every line, so a partial or mixed file is recognizable.
        fn generation(token: usize) -> HashMap<String, String> {
            let document = format!("{token:08}\n").repeat(512);
            files(&PATHS.map(|path| (path, document.as_str())))
        }
        let token_of = |content: &str| -> usize {
            let first = content
                .lines()
                .next()
                .expect("a published file is not empty");
            assert_eq!(content.len(), 512 * 9, "partial file");
            assert!(content.lines().all(|line| line == first), "mixed file");
            first.parse().expect("token")
        };

        let provider_files = ProviderFiles::default();
        provider_files.replace(generation(0)).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let readers = (0..3)
            .map(|_| {
                let provider_files = provider_files.clone();
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    let mut opened = 0_usize;
                    while !stop.load(Ordering::Acquire) {
                        let held = PATHS.map(|path| {
                            let mut file =
                                open(&provider_files, path).expect("the file is always published");
                            let mut content = String::new();
                            file.read_to_string(&mut content).unwrap();
                            (file, token_of(&content))
                        });
                        opened += held.len();
                        // Descriptors opened earlier keep their revision
                        // while newer generations are published.
                        for (file, token) in held {
                            let mut again = vec![0_u8; 512 * 9];
                            file.read_exact_at(&mut again, 0).unwrap();
                            assert_eq!(token_of(std::str::from_utf8(&again).unwrap()), token);
                        }
                    }
                    opened
                })
            })
            .collect::<Vec<_>>();
        let publishers = [1_000, 2_000].map(|base| {
            let provider_files = provider_files.clone();
            std::thread::spawn(move || {
                for step in 0..GENERATIONS {
                    provider_files.replace(generation(base + step)).unwrap();
                }
            })
        });
        for publisher in publishers {
            publisher.join().expect("publisher");
        }
        stop.store(true, Ordering::Release);
        for reader in readers {
            assert!(reader.join().expect("reader") > 0);
        }
        // What stays published is one publisher's last generation, whole.
        let last = PATHS.map(|path| token_of(&read(&provider_files, path).unwrap()));
        assert!(last[0] == 1_000 + GENERATIONS - 1 || last[0] == 2_000 + GENERATIONS - 1);
        assert_eq!(last, [last[0]; 3]);
    }
}
