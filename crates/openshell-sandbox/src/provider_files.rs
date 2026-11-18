// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Read-only provider files.
//!
//! Delivery is chosen once, before the workload listener is installed:
//!
//! - **Virtual** (the default): every workload file open notifies the
//!   broker, which serves a path beneath the provider prefix by injecting a
//!   read-only descriptor for a sealed in-memory file.
//! - **Native**: the driver provisioned a validated
//!   [`crate::provider_store::NativeStore`]. Provider files are real files on
//!   a mount the workload can only read, so read-only opens no longer notify.
//!
//! Virtual delivery keeps two things apart. A [`Revision`] is one immutable
//! version of one file, and a [`Snapshot`] is the complete set a publication
//! replaces at once; neither knows how bytes reach the workload. What a
//! delivery prepares for a revision is its backing: here a [`SealedFile`],
//! created once when the revision is published and reopened for each
//! workload open.
//!
//! The same virtual delivery also answers opens of the two canonical
//! supervisor CA trust paths from [`crate::ca_trust_files`], which share the
//! backing but are published separately from, and never removed by, a
//! provider file update.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock};

use rustix::fs::Mode;

use openshell_sandbox_backend::boundary_protocol::ProviderFileStore;

use crate::ca_trust_files::CaTrustFiles;
use crate::linux::sealed_file::{OwnDescriptors, SealedFile};
use crate::linux::seccomp_notify::{Notification, NotificationListener, OpenMediation};
use crate::linux::task_memory;
use crate::provider_store::{NativeStore, PUBLIC_ROOT};

const PREFIX: &str = "/run/openshell/providers/";
const PROC_PREFIX: &str = "/proc/";
const MAX_FILE_BYTES: usize = 65_536;
pub const MAX_TOTAL_BYTES: usize = 262_144;
const MAX_PATH_BYTES: usize = 4_096;

/// The mode a provider file reports. It keeps the file's metadata private
/// to the sandbox identity; the seals and the read-only descriptor protect
/// its content.
const FILE_MODE: Mode = Mode::from_bits_truncate(0o600);

/// One immutable version of one provider file: its bytes, and what the
/// delivery prepared at publication to serve them.
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

/// The published generation of virtually delivered provider files, and the
/// supervisor trust files the same delivery serves.
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

/// The public root of the native store this process selected, if any.
///
/// Set at most once, before any workload process is prepared. Child Landlock
/// preparation reads it to keep provider files readable under a user policy.
static NATIVE_PUBLIC_ROOT: OnceLock<PathBuf> = OnceLock::new();

/// The path a user filesystem policy must leave readable for natively
/// delivered provider files, or `None` under virtual delivery.
pub fn native_public_root() -> Option<&'static Path> {
    NATIVE_PUBLIC_ROOT.get().map(PathBuf::as_path)
}

#[derive(Clone)]
enum Delivery {
    /// Sealed in-memory files, injected into each workload open.
    Virtual(Arc<VirtualFiles>),
    /// Real files in a validated store.
    Native(Arc<NativeStore>),
}

/// The provider files of one sandbox and how the workload receives them.
#[derive(Clone)]
pub struct ProviderFiles {
    delivery: Delivery,
}

impl Default for ProviderFiles {
    fn default() -> Self {
        Self {
            delivery: Delivery::Virtual(Arc::default()),
        }
    }
}

impl ProviderFiles {
    /// Choose delivery from the driver's bootstrap, before the workload
    /// listener exists.
    ///
    /// No declared store means virtual delivery, exactly as before the store
    /// existed. A declared store must pass every check of
    /// [`NativeStore::open`], or startup fails. There is no fallback to
    /// virtual delivery for a store that fails: the driver mounted it at the
    /// provider path, where files from an earlier run could remain readable
    /// through a relative open that path interception does not see, and a
    /// mount that is not what the driver declared is not one to work around.
    /// A driver that cannot provision a store declares none.
    ///
    /// One outcome is neither of those. A store that passed every check, on
    /// a kernel whose Landlock refuses an open caught by a generation
    /// exchange, is delivered virtually. That is a property of the kernel,
    /// not a fault in the store, and it is taken only once the store is
    /// proven empty, so no provider file is left at the provider path. The
    /// native public root stays unset, so no policy grant is added for it.
    pub(crate) fn select(store: Option<&ProviderFileStore>) -> Result<Self, String> {
        let Some(config) = store else {
            return Ok(Self::default());
        };
        Self::selected(NativeStore::open(config))
    }

    fn selected(opened: io::Result<Option<NativeStore>>) -> Result<Self, String> {
        let Some(store) =
            opened.map_err(|error| format!("provider file store failed validation: {error}"))?
        else {
            openshell_ocsf::ocsf_emit!(
                openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                    .severity(openshell_ocsf::SeverityId::Low)
                    .status(openshell_ocsf::StatusId::Success)
                    .state(openshell_ocsf::StateId::Disabled, "virtual")
                    .message(
                        "Provider files delivered virtually: kernel Landlock refuses opens in a replaced generation"
                            .to_string()
                    )
                    .build()
            );
            return Ok(Self::default());
        };
        // First selection wins; a process selects once.
        let _ = NATIVE_PUBLIC_ROOT.set(PathBuf::from(PUBLIC_ROOT));
        openshell_ocsf::ocsf_emit!(
            openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                .severity(openshell_ocsf::SeverityId::Informational)
                .status(openshell_ocsf::StatusId::Success)
                .state(openshell_ocsf::StateId::Enabled, "native")
                .message("Provider files delivered from a read-only mount".to_string())
                .build()
        );
        Ok(Self {
            delivery: Delivery::Native(Arc::new(store)),
        })
    }

    /// Which workload opens must reach the broker for this delivery.
    pub(crate) fn open_mediation(&self) -> OpenMediation {
        match self.delivery {
            Delivery::Virtual(_) => OpenMediation::All,
            Delivery::Native(_) => OpenMediation::WriteCapable,
        }
    }

    #[cfg(any(test, feature = "perf-harness"))]
    pub(crate) fn native_for_test(store: NativeStore) -> Self {
        Self {
            delivery: Delivery::Native(Arc::new(store)),
        }
    }

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
        match &self.delivery {
            Delivery::Virtual(files) => files.publish(desired),
            Delivery::Native(store) => store.publish(&desired),
        }
    }

    /// Publish the supervisor CA certificate and combined trust bundle the
    /// workload opens at their canonical paths.
    ///
    /// Call this after the real files are installed and before the workload
    /// starts. Under virtual delivery the pair is cached and plain read-only
    /// opens of exactly those paths receive a sealed copy; under native
    /// delivery read-only opens run in the kernel and reach the installed
    /// files, so only the pair's validity is checked. Either way a refused
    /// pair fails closed and a previously published pair stays as it was.
    pub(crate) fn publish_ca_trust(&self, ca_cert: &[u8], ca_bundle: &[u8]) -> io::Result<()> {
        match &self.delivery {
            Delivery::Virtual(files) => files.ca_trust.publish(ca_cert, ca_bundle),
            Delivery::Native(_) => crate::ca_trust_files::validate_pair(ca_cert, ca_bundle),
        }
    }

    /// Forget any published trust pair, so every open of the canonical paths
    /// continues to the kernel again.
    ///
    /// Call this before a workload starts without CA material: a pair cached
    /// by an earlier, failed start must not outlive the installation it
    /// mirrored. Independent of provider file updates, which never touch
    /// the pair. Nothing to do under native delivery, which caches nothing.
    pub(crate) fn clear_ca_trust(&self) {
        if let Delivery::Virtual(files) = &self.delivery {
            files.ca_trust.clear();
        }
    }

    /// The cached trust pair, under virtual delivery.
    #[cfg(test)]
    pub(crate) fn ca_trust(&self) -> Option<&CaTrustFiles> {
        match &self.delivery {
            Delivery::Virtual(files) => Some(&files.ca_trust),
            Delivery::Native(_) => None,
        }
    }

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
        // Every workload open reaches the listener, and nearly all of them
        // are ordinary paths the kernel decides. One exact copy of the
        // path's first six bytes tells those apart from the paths served
        // here; an ordinary open costs nothing else, and in particular no
        // read of an `openat2` argument structure.
        //
        // Six bytes are enough. `/proc/` is six bytes, and every provider
        // path and both supervisor CA trust paths start with the first six
        // bytes of the provider prefix and are longer than that, so every
        // served kind always has six readable bytes. A copy that fails is an
        // unreadable pointer or a shorter path that ends before an unmapped
        // page: neither is served here, and the kernel resolves the path or
        // reports its own EFAULT.
        //
        // The copy only classifies. Every served kind reads the whole path
        // again and decides from that copy alone. A served open is never
        // continued; an open that is continued, including a CA trust open
        // this delivery does not serve, is authorized by the kernel and
        // Landlock exactly as any ordinary open.
        let mut start = [0_u8; PROC_PREFIX.len()];
        if task_memory::read_exact(notification.tid, path_address, &mut start).is_err() {
            return listener.respond_continue(notification.id);
        }
        if start == PROC_PREFIX.as_bytes() {
            if handle_thread_comm_open(listener, notification, path_address)? {
                return Ok(());
            }
            return listener.respond_continue(notification.id);
        }
        let files = match &self.delivery {
            Delivery::Virtual(files) => files,
            // Provider files and the CA trust files are real files the
            // workload reads natively. Only opens that can change the
            // filesystem and `openat2` notify, and the kernel decides each
            // of them: Landlock and the mounts refuse a write.
            Delivery::Native(_) => return listener.respond_continue(notification.id),
        };
        if start != PREFIX.as_bytes()[..PROC_PREFIX.len()] {
            return listener.respond_continue(notification.id);
        }
        // A failed or non-absolute lookup is left to the kernel. In particular,
        // this preserves its normal EFAULT result for an invalid path pointer.
        let Ok(path) = read_path(notification.tid, path_address) else {
            return listener.respond_continue(notification.id);
        };
        if path.starts_with(PREFIX) {
            let Some(revision) = files.revision(&path) else {
                return listener.respond_errno(notification.id, libc::ENOENT);
            };
            return inject_read_only(listener, &notification, &revision.backing);
        }
        // Exactly a canonical CA trust path with a published pair. Any other
        // path, including an alias of one or either path before publication,
        // continues to the kernel, which resolves it against the installed
        // files under Landlock.
        if let Some(trust_file) = files.ca_trust.lookup(&path) {
            return inject_plain_read_or_continue(listener, &notification, trust_file.backing());
        }
        listener.respond_continue(notification.id)
    }
}

/// Serve a plain read-only `open` or `openat` of a CA trust file, and leave
/// every other form of open to the kernel.
///
/// The installed file exists at the same path, so an open this delivery does
/// not serve keeps its native result: a write-capable open fails on the
/// `0444` file, `O_DIRECTORY` is `ENOTDIR`, `O_PATH` succeeds, and `openat2`
/// with its own resolution constraints is decided in the kernel without a
/// copy of its `open_how`. Continuing authorizes nothing: the kernel and
/// Landlock decide these opens exactly as before the pair was cached.
fn inject_plain_read_or_continue(
    listener: &NotificationListener,
    notification: &Notification,
    file: &SealedFile,
) -> io::Result<()> {
    const UNSERVED: i32 = libc::O_CREAT
        | libc::O_EXCL
        | libc::O_TRUNC
        | libc::O_TMPFILE
        | libc::O_APPEND
        | libc::O_DIRECTORY
        | libc::O_PATH
        | libc::O_DIRECT;
    if i64::from(notification.syscall) == libc::SYS_openat2 {
        return listener.respond_continue(notification.id);
    }
    let Ok(flags) = open_flags(notification) else {
        return listener.respond_continue(notification.id);
    };
    if flags & libc::O_ACCMODE != libc::O_RDONLY || flags & UNSERVED != 0 {
        return listener.respond_continue(notification.id);
    }
    file.inject(listener, notification.id, flags & libc::O_CLOEXEC != 0)
}

/// Complete a workload open of a sealed file, or refuse it.
///
/// Only a plain read-only open is served. An open that asks to create,
/// truncate, append, or write is `EACCES`, as it would be on the read-only
/// installed file; one that asks for a directory, a path-only descriptor, or
/// direct I/O is `EINVAL`. Nothing here is continued.
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
    if flags & libc::O_ACCMODE != libc::O_RDONLY
        || flags & (libc::O_CREAT | libc::O_EXCL | libc::O_TRUNC | libc::O_TMPFILE | libc::O_APPEND)
            != 0
    {
        return listener.respond_errno(notification.id, libc::EACCES);
    }
    if flags & (libc::O_DIRECTORY | libc::O_PATH | libc::O_DIRECT) != 0 {
        return listener.respond_errno(notification.id, libc::EINVAL);
    }
    file.inject(listener, notification.id, flags & libc::O_CLOEXEC != 0)
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
    provider_and_file(path).map(|_| ())
}

/// Split a provider file path into its validated provider and file names.
pub fn provider_and_file(path: &str) -> io::Result<(&str, &str)> {
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
    Ok((provider, name))
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
    use super::{
        Delivery, MAX_FILE_BYTES, OpenMediation, ProviderFileStore, ProviderFiles, VirtualFiles,
        comm_target, prepare_backing,
    };
    use crate::ca_trust_files::{CA_BUNDLE_PATH, CA_CERT_PATH};
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::{self, Read as _, Seek as _, SeekFrom};
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{FileExt as _, MetadataExt as _, PermissionsExt as _};
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
        match &provider_files.delivery {
            Delivery::Virtual(files) => files,
            Delivery::Native(_) => panic!("virtual delivery expected"),
        }
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
    fn only_an_unqualified_kernel_falls_back_to_virtual_delivery() {
        // No declared store: virtual, as before the store existed.
        let absent = ProviderFiles::select(None).unwrap();
        assert!(matches!(absent.open_mediation(), OpenMediation::All));
        // A valid, empty store on a kernel that failed the capability probe.
        let fallback = ProviderFiles::selected(Ok(None)).unwrap();
        assert!(matches!(fallback.open_mediation(), OpenMediation::All));
        // A declared store that fails validation, or whose probe or cleanup
        // failed, stops startup instead.
        for (private_root, public_root) in [
            ("/tmp/provider-files", "/run/openshell"),
            ("/.openshell/provider-files", "/run/other"),
            ("/.openshell/missing-provider-files", "/run/openshell"),
        ] {
            let error = ProviderFiles::select(Some(&ProviderFileStore {
                private_root: private_root.into(),
                public_root: public_root.into(),
            }))
            .err()
            .unwrap_or_else(|| panic!("{private_root} {public_root} must fail startup"));
            assert!(error.contains("failed validation"), "{error}");
        }
        let error = ProviderFiles::selected(Err(io::Error::other("probe incomplete")))
            .err()
            .expect("an incomplete probe must fail startup");
        assert!(error.contains("probe incomplete"), "{error}");
        // None of these selected native delivery.
        assert!(super::native_public_root().is_none());
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
    fn each_open_is_its_own_read_only_description_of_one_sealed_file() {
        let provider_files = ProviderFiles::default();
        provider_files
            .replace(files(&[(CONFIG, "0123456789")]))
            .unwrap();
        let mut first = open(&provider_files, CONFIG).unwrap();
        let mut second = open(&provider_files, CONFIG).unwrap();

        // Both opens are positioned at the start, and neither moves the
        // other: a duplicated descriptor would share one offset.
        let mut head = [0_u8; 4];
        first.read_exact(&mut head).unwrap();
        assert_eq!(&head, b"0123");
        let mut whole = String::new();
        second.read_to_string(&mut whole).unwrap();
        assert_eq!(whole, "0123456789");
        let mut rest = String::new();
        first.read_to_string(&mut rest).unwrap();
        assert_eq!(rest, "456789");
        second.seek(SeekFrom::Start(8)).unwrap();
        assert_eq!(first.stream_position().unwrap(), 10);

        // One file serves every open of a revision.
        assert_eq!(file_identity(&first), file_identity(&second));
        for file in [&first, &second] {
            assert_eq!(file.metadata().unwrap().mode() & 0o7777, 0o600);
            assert_eq!(
                rustix::fs::fcntl_getfl(file).unwrap() & rustix::fs::OFlags::ACCMODE,
                rustix::fs::OFlags::RDONLY
            );
            let seals = rustix::fs::fcntl_get_seals(file).unwrap();
            assert!(seals.contains(
                rustix::fs::SealFlags::SEAL
                    | rustix::fs::SealFlags::WRITE
                    | rustix::fs::SealFlags::GROW
                    | rustix::fs::SealFlags::SHRINK
            ));
            assert!(file.write_at(b"changed", 0).is_err());
            assert!(file.set_len(0).is_err());
        }

        // The workload owns the file and can reopen its descriptor for
        // writing. The seals, not the descriptor's access mode, are what
        // keep the content, and they cannot be lifted.
        let link = format!("/proc/self/fd/{}", first.as_raw_fd());
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
            }
        }
        assert!(
            std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&link)
                .is_err()
        );
        assert_eq!(read(&provider_files, CONFIG).unwrap(), "0123456789");

        // The descriptor the runtime keeps for the revision is read-only too.
        let revision = virtual_files(&provider_files).revision(CONFIG).unwrap();
        assert_eq!(
            rustix::fs::fcntl_getfl(revision.backing.anchor()).unwrap()
                & rustix::fs::OFlags::ACCMODE,
            rustix::fs::OFlags::RDONLY
        );
    }

    #[test]
    fn ca_trust_files_are_independent_of_provider_file_updates() {
        const CERT: &str = "-----BEGIN CERTIFICATE-----\nsupervisor\n-----END CERTIFICATE-----\n";
        let bundle = format!("{}{CERT}", "B".repeat(200 * 1024));
        let provider_files = ProviderFiles::default();
        let trust = provider_files.ca_trust().unwrap();
        assert!(trust.lookup(CA_CERT_PATH).is_none());
        provider_files
            .publish_ca_trust(CERT.as_bytes(), bundle.as_bytes())
            .unwrap();
        let trust_read = |path: &str| {
            let file = File::from(trust.lookup(path).unwrap().backing().open().unwrap());
            let mut content = Vec::new();
            (&file).read_to_end(&mut content).unwrap();
            (content, file_identity(&file))
        };
        let (published_cert, cert_identity) = trust_read(CA_CERT_PATH);
        let (published_bundle, bundle_identity) = trust_read(CA_BUNDLE_PATH);
        assert_eq!(published_cert, CERT.as_bytes());
        assert_eq!(published_bundle.len(), bundle.len());
        assert!(published_bundle.len() > MAX_FILE_BYTES);

        // Provider publications, including an empty one, change nothing
        // about the trust pair, and the trust paths are not provider paths.
        provider_files
            .replace(files(&[(CONFIG, "version = 1\n")]))
            .unwrap();
        provider_files.replace(HashMap::new()).unwrap();
        assert_eq!(trust_read(CA_CERT_PATH).1, cert_identity);
        assert_eq!(trust_read(CA_BUNDLE_PATH).1, bundle_identity);
        assert!(
            virtual_files(&provider_files)
                .revision(CA_CERT_PATH)
                .is_none()
        );
        assert!(
            ProviderFiles::validate(&files(&[(CA_BUNDLE_PATH, "x")])).is_err(),
            "trust paths are not publishable as provider files"
        );

        // A refused pair leaves the published one, and the same pair again
        // keeps the files earlier opens used.
        assert!(
            provider_files
                .publish_ca_trust(CERT.as_bytes(), b"not the bundle")
                .is_err()
        );
        provider_files
            .publish_ca_trust(CERT.as_bytes(), bundle.as_bytes())
            .unwrap();
        assert_eq!(trust_read(CA_CERT_PATH).1, cert_identity);
        assert_eq!(trust_read(CA_BUNDLE_PATH).1, bundle_identity);
    }

    #[test]
    fn a_cleared_mode_does_not_deny_later_opens() {
        let provider_files = ProviderFiles::default();
        provider_files.replace(files(&[(KEY, "key-1")])).unwrap();
        let held = open(&provider_files, KEY).unwrap();
        // The workload owns the shared file and can change its mode.
        held.set_permissions(std::fs::Permissions::from_mode(0o000))
            .unwrap();
        assert_eq!(read(&provider_files, KEY).unwrap(), "key-1");
        // An identical update keeps the revision; it must stay readable.
        provider_files.replace(files(&[(KEY, "key-1")])).unwrap();
        assert_eq!(read(&provider_files, KEY).unwrap(), "key-1");
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

        // The delivery still publishes afterwards.
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
