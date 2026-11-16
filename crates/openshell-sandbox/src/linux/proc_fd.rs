// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Strict `/proc/<tid>/fd` socket identity helpers.

use std::fs;
use std::io;
use std::os::fd::RawFd;

/// Snapshot socket inodes installed in process descriptor tables other than
/// `excluded_pid`.
///
/// Inaccessible or concurrently disappearing entries are
/// skipped. Callers use this only to reclaim bounded mediation metadata; a
/// later operation on an unregistered descriptor fails closed.
pub fn installed_socket_inodes_excluding(
    excluded_pid: u32,
) -> io::Result<std::collections::BTreeSet<u64>> {
    let mut inodes = std::collections::BTreeSet::new();
    for process in fs::read_dir("/proc")? {
        let Ok(process) = process else { continue };
        let Some(name) = process.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        if pid == excluded_pid {
            continue;
        }
        let Ok(descriptors) = fs::read_dir(process.path().join("fd")) else {
            continue;
        };
        for descriptor in descriptors.flatten() {
            let Ok(target) = fs::read_link(descriptor.path()) else {
                continue;
            };
            let Some(target) = target.to_str() else {
                continue;
            };
            let Some(digits) = target
                .strip_prefix("socket:[")
                .and_then(|value| value.strip_suffix(']'))
            else {
                continue;
            };
            if let Ok(inode) = digits.parse::<u64>() {
                inodes.insert(inode);
            }
        }
    }
    Ok(inodes)
}

/// Return the socket inode currently installed at `fd` in `tid`'s descriptor
/// table.
///
/// The result is only a snapshot. Callers must revalidate the seccomp
/// notification, task generation, and any retained socket cookie before a
/// state-changing operation.
pub fn socket_inode(tid: u32, fd: RawFd) -> io::Result<u64> {
    socket_inode_if_socket(tid, fd)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "procfs descriptor is not a socket",
        )
    })
}

/// Return `None` only after procfs confirms that the descriptor is not a socket.
///
/// An unreadable or missing descriptor remains an error so callers cannot
/// mistake failed inspection for a safe native socket operation.
pub fn socket_inode_if_socket(tid: u32, fd: RawFd) -> io::Result<Option<u64>> {
    if tid == 0 || fd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TID must be nonzero and FD must be nonnegative",
        ));
    }
    let target = match fs::read_link(format!("/proc/{tid}/fd/{fd}")) {
        Ok(target) => target,
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
            // A missing descriptor should keep the syscall's EBADF result.
            // Check the parent so a vanished task or inaccessible procfs does
            // not get mistaken for a closed descriptor.
            fs::metadata(format!("/proc/{tid}/fd"))?;
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        Err(error) => return Err(error),
    };
    let target = target.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "procfs descriptor target is not UTF-8",
        )
    })?;
    let digits = target
        .strip_prefix("socket:[")
        .and_then(|value| value.strip_suffix(']'));
    let Some(digits) = digits else {
        return if target.starts_with("socket:") {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "procfs socket inode has an invalid representation",
            ))
        } else {
            Ok(None)
        };
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "procfs socket inode has an invalid representation",
        ));
    }
    digits.parse::<u64>().map(Some).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("procfs socket inode does not fit u64: {error}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    use super::*;

    #[test]
    fn identifies_socket_and_rejects_regular_file() {
        let (left, _right) = UnixStream::pair().expect("socketpair");
        assert!(socket_inode(std::process::id(), left.as_raw_fd()).unwrap() > 0);
        assert_eq!(
            socket_inode_if_socket(std::process::id(), left.as_raw_fd()).unwrap(),
            Some(socket_inode(std::process::id(), left.as_raw_fd()).unwrap())
        );

        let file = File::open("/dev/null").expect("open regular descriptor");
        assert_eq!(
            socket_inode_if_socket(std::process::id(), file.as_raw_fd()).unwrap(),
            None
        );
        assert_eq!(
            socket_inode(std::process::id(), file.as_raw_fd())
                .expect_err("regular descriptor")
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn missing_descriptor_is_not_classified_as_non_socket() {
        assert_eq!(
            socket_inode_if_socket(std::process::id(), i32::MAX)
                .expect_err("closed descriptor cannot be inspected")
                .raw_os_error(),
            Some(libc::EBADF)
        );
        assert_eq!(
            socket_inode_if_socket(u32::MAX, 3)
                .expect_err("missing task must remain an inspection error")
                .raw_os_error(),
            Some(libc::ENOENT)
        );
    }

    #[test]
    fn installed_socket_snapshot_can_exclude_the_broker() {
        let (left, _right) = UnixStream::pair().expect("socketpair");
        let inode = socket_inode(std::process::id(), left.as_raw_fd()).unwrap();

        assert!(
            installed_socket_inodes_excluding(u32::MAX)
                .unwrap()
                .contains(&inode)
        );
        assert!(
            !installed_socket_inodes_excluding(std::process::id())
                .unwrap()
                .contains(&inode)
        );
    }
}
