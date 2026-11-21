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

/// Count this process's open descriptors, as one enumeration of
/// `/proc/self/fd` reports them.
///
/// An enumeration opens the directory it lists, so its result is the number
/// of descriptors open before the call plus one. Callers size their headroom
/// against that value. Linux 6.2 and later report the open-descriptor count as
/// the size of `/proc/self/fd`, which costs one `stat` instead of an open,
/// one directory read per batch of entries, and a close. Support is
/// established once by an active probe, never from the kernel version, and
/// the fast count adds one to stay equal to an enumeration. Any kernel,
/// profile, or procfs that does not pass the probe keeps enumerating.
pub fn open_descriptor_count() -> io::Result<usize> {
    static STAT_COUNT_SUPPORTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let supported = *STAT_COUNT_SUPPORTED.get_or_init(|| {
        stat_count_tracks_enumeration(
            stat_descriptor_count,
            || enumerate_descriptor_count().ok(),
            || rustix::event::eventfd(0, rustix::event::EventfdFlags::CLOEXEC).ok(),
        )
    });
    if supported && let Some(open) = stat_descriptor_count() {
        return Ok(open.saturating_add(1));
    }
    enumerate_descriptor_count()
}

fn enumerate_descriptor_count() -> io::Result<usize> {
    fs::read_dir("/proc/self/fd").map(Iterator::count)
}

/// Open-descriptor count from the directory size, or `None` where the kernel
/// does not report one (older kernels report a size of zero).
fn stat_descriptor_count() -> Option<usize> {
    let size = fs::metadata("/proc/self/fd").ok()?.len();
    usize::try_from(size).ok().filter(|count| *count > 0)
}

/// Decide whether `stat` reports a live descriptor count.
///
/// A sample qualifies only when two `stat` counts bracketing an enumeration
/// agree, the enumeration reports exactly one more (its own directory
/// descriptor), and holding one extra descriptor raises the `stat` count by
/// exactly one. Other threads open and close descriptors concurrently, so a
/// disturbed sample is retried a few times; persistent disagreement selects
/// enumeration.
fn stat_count_tracks_enumeration<Held>(
    mut stat: impl FnMut() -> Option<usize>,
    mut enumerate: impl FnMut() -> Option<usize>,
    mut hold_descriptor: impl FnMut() -> Option<Held>,
) -> bool {
    const ATTEMPTS: usize = 8;
    for _ in 0..ATTEMPTS {
        let Some(before) = stat() else {
            return false;
        };
        let Some(enumerated) = enumerate() else {
            return false;
        };
        let Some(held) = hold_descriptor() else {
            return false;
        };
        let with_held = stat();
        drop(held);
        let after = stat();
        if after == Some(before)
            && with_held == before.checked_add(1)
            && Some(enumerated) == before.checked_add(1)
        {
            return true;
        }
    }
    false
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

    #[test]
    fn stat_count_is_used_only_when_it_tracks_descriptors() {
        let hold = || Some(());
        // A kernel that reports no size never qualifies.
        assert!(!stat_count_tracks_enumeration(|| None, || Some(8), hold));
        // A size that ignores a newly held descriptor is not a count.
        assert!(!stat_count_tracks_enumeration(|| Some(7), || Some(8), hold));
        // An enumeration that does not include its own descriptor disagrees.
        let mut counts = [7, 8, 7].into_iter().cycle();
        assert!(!stat_count_tracks_enumeration(
            || counts.next(),
            || Some(7),
            hold
        ));
        // A consistent sample qualifies: before, with one held, after.
        let mut counts = [7, 8, 7].into_iter().cycle();
        assert!(stat_count_tracks_enumeration(
            || counts.next(),
            || Some(8),
            hold
        ));
        // A sample disturbed by concurrent descriptor churn is retried.
        let mut counts = [7, 9, 8, 8, 9, 8].into_iter();
        assert!(stat_count_tracks_enumeration(
            || counts.next(),
            || Some(9),
            hold
        ));
        // Failing to enumerate or to hold a descriptor never qualifies.
        assert!(!stat_count_tracks_enumeration(|| Some(7), || None, hold));
        assert!(!stat_count_tracks_enumeration(
            || Some(7),
            || Some(8),
            || None::<()>
        ));
    }

    #[test]
    fn descriptor_count_follows_open_descriptors() {
        // Other tests open and close descriptors concurrently, so compare
        // against a large deliberate change rather than an exact value.
        const HELD: usize = 64;
        let before = open_descriptor_count().unwrap();
        assert!(before > 3, "count includes the standard descriptors");
        let held = (0..HELD)
            .map(|_| File::open("/dev/null").expect("open descriptor"))
            .collect::<Vec<_>>();
        let during = open_descriptor_count().unwrap();
        drop(held);
        let after = open_descriptor_count().unwrap();
        assert!(during >= before + HELD / 2, "{before} -> {during}");
        assert!(after + HELD / 2 <= during, "{during} -> {after}");
        // The fast count and an enumeration agree to within concurrent churn.
        let enumerated = enumerate_descriptor_count().unwrap();
        let counted = open_descriptor_count().unwrap();
        assert!(
            enumerated.abs_diff(counted) < HELD / 2,
            "{enumerated} vs {counted}"
        );
    }
}
