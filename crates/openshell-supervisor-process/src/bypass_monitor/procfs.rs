// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Linux `/proc` filesystem reading for bypass-monitor process identity.
//!
//! Trimmed copy of `openshell-supervisor-network`'s `procfs` module: only
//! the helpers the bypass monitor calls when resolving the originating PID
//! and binary for an nftables LOG entry. The networking leaf keeps its own
//! richer copy because it also needs sha256 hashing, cmdline scraping, and
//! ambiguity-failure helpers for its proxy identity cache.

use miette::Result;
use std::collections::HashSet;
use std::path::PathBuf;

/// Where a socket owner was discovered while scanning `/proc`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SocketOwnerSource {
    /// Owner was found in the entrypoint process tree at the given BFS depth.
    Descendant { depth: usize },
    /// Owner was found by scanning all of `/proc` after the descendant scan.
    ProcFallback,
}

/// A process with an fd pointing at a target socket inode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocketOwner {
    pub pid: u32,
    pub source: SocketOwnerSource,
}

/// All process owners for a TCP peer socket.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpPeerSocketOwners {
    pub inode: u64,
    pub owners: Vec<SocketOwner>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DescendantPid {
    pid: u32,
    depth: usize,
}

/// Read the binary path of a process via `/proc/{pid}/exe` symlink.
///
/// Strips the kernel-added `" (deleted)"` suffix when the raw readlink
/// target cannot be stat'd, so callers see a clean path. See the networking
/// crate's procfs documentation for the full rationale.
pub fn binary_path(pid: i32) -> Result<PathBuf> {
    use std::ffi::OsString;
    use std::io::ErrorKind;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    const DELETED_SUFFIX: &[u8] = b" (deleted)";

    let link = format!("/proc/{pid}/exe");
    let target = std::fs::read_link(&link).map_err(|e| {
        miette::miette!(
            "Failed to read /proc/{pid}/exe: {e}. \
             Cannot determine binary identity — denying request. \
             Hint: the proxy may need CAP_SYS_PTRACE or to run as the same user."
        )
    })?;

    let raw_target_missing =
        matches!(std::fs::metadata(&target), Err(err) if err.kind() == ErrorKind::NotFound);

    let bytes = target.as_os_str().as_bytes();
    if raw_target_missing && bytes.ends_with(DELETED_SUFFIX) {
        let stripped = bytes[..bytes.len() - DELETED_SUFFIX.len()].to_vec();
        return Ok(PathBuf::from(OsString::from_vec(stripped)));
    }

    Ok(target)
}

/// Resolve all process owners for the TCP peer inside a sandbox network namespace.
pub fn resolve_tcp_peer_socket_owners(
    entrypoint_pid: u32,
    peer_port: u16,
) -> Result<TcpPeerSocketOwners> {
    let inode = parse_proc_net_tcp(entrypoint_pid, peer_port)?;
    let owners = find_socket_inode_owners(inode, entrypoint_pid)?;
    Ok(TcpPeerSocketOwners { inode, owners })
}

/// Read the `PPid` (parent PID) from `/proc/<pid>/status`.
fn read_ppid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// Walk the process tree upward from `pid`, collecting binary paths.
///
/// Stops at PID 1 (init), `stop_pid` (the entrypoint process), or after
/// 64 ancestors. The returned vec excludes `pid` itself.
#[allow(clippy::similar_names)]
pub fn collect_ancestor_binaries(pid: u32, stop_pid: u32) -> Vec<PathBuf> {
    const MAX_DEPTH: usize = 64;
    let mut ancestors = Vec::new();
    let mut current = pid;

    for _ in 0..MAX_DEPTH {
        let ppid = match read_ppid(current) {
            Some(p) if p > 0 && p != current => p,
            _ => break,
        };

        if let Ok(path) = binary_path(ppid.cast_signed()) {
            ancestors.push(path);
        }

        if ppid == stop_pid || ppid == 1 {
            break;
        }
        current = ppid;
    }

    ancestors
}

fn parse_proc_net_tcp(pid: u32, peer_port: u16) -> Result<u64> {
    for suffix in &["tcp", "tcp6"] {
        let path = format!("/proc/{pid}/net/{suffix}");
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };

        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }

            let local_addr = fields[1];
            let local_port = match local_addr.rsplit_once(':') {
                Some((_, port_hex)) => u16::from_str_radix(port_hex, 16).unwrap_or(0),
                None => continue,
            };

            let state = fields[3];
            if state != "01" {
                continue;
            }

            if local_port == peer_port {
                let inode: u64 = fields[9]
                    .parse()
                    .map_err(|_| miette::miette!("Failed to parse inode from {}", fields[9]))?;
                if inode == 0 {
                    continue;
                }
                return Ok(inode);
            }
        }
    }

    Err(miette::miette!(
        "No ESTABLISHED TCP connection found for port {} in /proc/{}/net/tcp{{,6}}",
        peer_port,
        pid
    ))
}

fn find_socket_inode_owners(inode: u64, entrypoint_pid: u32) -> Result<Vec<SocketOwner>> {
    let target = format!("socket:[{inode}]");
    let mut owners = Vec::new();
    let mut checked = HashSet::new();

    let descendants = collect_descendant_pids_with_depth(entrypoint_pid);

    for descendant in &descendants {
        checked.insert(descendant.pid);
        if check_pid_fds(descendant.pid, &target) {
            owners.push(SocketOwner {
                pid: descendant.pid,
                source: SocketOwnerSource::Descendant {
                    depth: descendant.depth,
                },
            });
        }
    }

    if let Ok(proc_dir) = std::fs::read_dir("/proc") {
        let mut proc_pids = Vec::new();
        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            if let Ok(pid) = name.to_string_lossy().parse::<u32>() {
                proc_pids.push(pid);
            }
        }
        proc_pids.sort_unstable();

        for pid in proc_pids {
            if checked.contains(&pid) {
                continue;
            }
            checked.insert(pid);
            if check_pid_fds(pid, &target) {
                owners.push(SocketOwner {
                    pid,
                    source: SocketOwnerSource::ProcFallback,
                });
            }
        }
    }

    if !owners.is_empty() {
        return Ok(owners);
    }

    Err(miette::miette!(
        "No process found owning socket inode {} \
         (scanned {} descendants of entrypoint PID {}). \
         Hint: the container may need --cap-add=SYS_PTRACE to read /proc/<pid>/fd/ \
         for processes running as a different user.",
        inode,
        descendants.len(),
        entrypoint_pid
    ))
}

fn check_pid_fds(pid: u32, target: &str) -> bool {
    let fd_dir = format!("/proc/{pid}/fd");
    let Some(fds) = std::fs::read_dir(&fd_dir).ok() else {
        return false;
    };
    for fd_entry in fds.flatten() {
        if let Ok(link) = std::fs::read_link(fd_entry.path())
            && link.to_string_lossy() == target
        {
            return true;
        }
    }
    false
}

fn collect_descendant_pids_with_depth(root_pid: u32) -> Vec<DescendantPid> {
    let mut pids = vec![DescendantPid {
        pid: root_pid,
        depth: 0,
    }];
    let mut seen = HashSet::from([root_pid]);
    let mut i = 0;
    while i < pids.len() {
        let pid = pids[i].pid;
        let child_depth = pids[i].depth + 1;
        let task_dir = format!("/proc/{pid}/task");
        if let Ok(tasks) = std::fs::read_dir(&task_dir) {
            for task_entry in tasks.flatten() {
                let children_path = task_entry.path().join("children");
                if let Ok(children_str) = std::fs::read_to_string(&children_path) {
                    for child in children_str.split_whitespace() {
                        if let Ok(child_pid) = child.parse::<u32>()
                            && seen.insert(child_pid)
                        {
                            pids.push(DescendantPid {
                                pid: child_pid,
                                depth: child_depth,
                            });
                        }
                    }
                }
            }
        }
        i += 1;
    }
    pids
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_path_reads_current_process() {
        let pid = std::process::id().cast_signed();
        let path = binary_path(pid).unwrap();
        assert!(path.exists());
    }

    #[test]
    #[allow(clippy::similar_names)]
    fn read_ppid_returns_parent() {
        let pid = std::process::id();
        let ppid = read_ppid(pid);
        assert!(ppid.is_some(), "Should be able to read PPid of self");
        assert!(ppid.unwrap() > 0, "PPid should be > 0");
    }

    #[test]
    fn read_ppid_nonexistent_pid() {
        let result = read_ppid(999_999_999);
        assert!(result.is_none());
    }

    #[test]
    fn collect_ancestor_binaries_returns_parents() {
        let pid = std::process::id();
        let ancestors = collect_ancestor_binaries(pid, 1);
        assert!(
            !ancestors.is_empty(),
            "Should have at least one ancestor binary"
        );
        for path in &ancestors {
            assert!(
                !path.as_os_str().is_empty(),
                "Ancestor path should not be empty"
            );
        }
    }
}
