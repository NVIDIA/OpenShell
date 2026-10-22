// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Read-only provider files served on demand through seccomp FD injection.

use std::collections::HashMap;
use std::fs::{File, Permissions};
use std::io::{self, Seek as _, SeekFrom, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::PermissionsExt as _;
use std::sync::{Arc, RwLock};

use crate::linux::seccomp_notify::{Notification, NotificationListener};
use crate::linux::task_memory;

const PREFIX: &str = "/run/openshell/providers/";
const PROC_PREFIX: &str = "/proc/";
const MAX_FILE_BYTES: usize = 65_536;
const MAX_TOTAL_BYTES: usize = 262_144;
const MAX_PATH_BYTES: usize = 4_096;

type Snapshot = HashMap<String, Arc<[u8]>>;

/// A complete provider-file generation. Open handlers clone the selected
/// content before dropping the lock, so updates never block on a child open.
#[derive(Clone, Default)]
pub struct ProviderFiles {
    current: Arc<RwLock<Arc<Snapshot>>>,
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
        let next = desired
            .into_iter()
            .map(|(path, content)| (path, Arc::<[u8]>::from(content.into_bytes())))
            .collect();
        *self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(next);
        Ok(())
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
        if handle_thread_comm_open(listener, notification, path_address)? {
            return Ok(());
        }
        // Every workload open reaches the listener. Copy only the reserved
        // prefix for ordinary paths; full path reads are rare.
        let mut prefix = [0_u8; PREFIX.len()];
        if task_memory::read_exact(notification.tid, path_address, &mut prefix).is_err()
            || prefix != PREFIX.as_bytes()
        {
            return listener.respond_continue(notification.id);
        }
        // A failed or non-absolute lookup is left to the kernel. In particular,
        // this preserves its normal EFAULT result for an invalid path pointer.
        let Ok(path) = read_path(notification.tid, path_address) else {
            return listener.respond_continue(notification.id);
        };
        if !path.starts_with(PREFIX) {
            return listener.respond_continue(notification.id);
        }
        let content = self
            .current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&path)
            .cloned();
        let Some(content) = content else {
            return listener.respond_errno(notification.id, libc::ENOENT);
        };
        let flags = match open_flags(&notification) {
            Ok(flags) => flags,
            Err(error) => {
                return listener.respond_errno(
                    notification.id,
                    error.raw_os_error().unwrap_or(libc::EINVAL),
                );
            }
        };
        if flags & libc::O_ACCMODE != libc::O_RDONLY
            || flags
                & (libc::O_CREAT | libc::O_EXCL | libc::O_TRUNC | libc::O_TMPFILE | libc::O_APPEND)
                != 0
        {
            return listener.respond_errno(notification.id, libc::EACCES);
        }
        if flags & (libc::O_DIRECTORY | libc::O_PATH | libc::O_DIRECT) != 0 {
            return listener.respond_errno(notification.id, libc::EINVAL);
        }
        let file = sealed_memfd(&content)?;
        listener.add_fd_and_send(
            notification.id,
            file.as_raw_fd(),
            flags & libc::O_CLOEXEC != 0,
        )?;
        Ok(())
    }
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
    let mut prefix = [0_u8; PROC_PREFIX.len()];
    if task_memory::read_exact(notification.tid, path_address, &mut prefix).is_err()
        || prefix != PROC_PREFIX.as_bytes()
    {
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
        file.as_raw_fd(),
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

fn sealed_memfd(content: &[u8]) -> io::Result<File> {
    let fd = rustix::fs::memfd_create(
        "openshell-provider",
        rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
    )?;
    let mut file = File::from(fd);
    // Keep metadata private as well as the returned descriptor read-only.
    file.set_permissions(Permissions::from_mode(0o600))?;
    file.write_all(content)?;
    file.seek(SeekFrom::Start(0))?;
    rustix::fs::fcntl_add_seals(
        &file,
        rustix::fs::SealFlags::SEAL
            | rustix::fs::SealFlags::WRITE
            | rustix::fs::SealFlags::GROW
            | rustix::fs::SealFlags::SHRINK,
    )?;
    // memfd_create returns O_RDWR. Reopen the sealed object through our own
    // procfs descriptor so the child receives an actual O_RDONLY description.
    File::open(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

#[cfg(test)]
mod tests {
    use super::{ProviderFiles, comm_target, sealed_memfd};
    use std::collections::HashMap;
    use std::io::Read as _;
    use std::os::unix::fs::PermissionsExt as _;

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
    fn memfd_is_read_only_and_positioned_at_start() {
        let mut file = sealed_memfd(b"version = 1\n").unwrap();
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        let flags = rustix::fs::fcntl_getfl(&file).unwrap();
        assert_eq!(
            flags & rustix::fs::OFlags::ACCMODE,
            rustix::fs::OFlags::RDONLY
        );
        let mut read = String::new();
        file.read_to_string(&mut read).unwrap();
        assert_eq!(read, "version = 1\n");
        assert!(std::io::Write::write_all(&mut file, b"changed").is_err());
    }
}
