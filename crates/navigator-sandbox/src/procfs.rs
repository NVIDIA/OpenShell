// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Linux `/proc` filesystem reading for process identity.
//!
//! Provides functions to resolve binary paths and compute file hashes
//! for process-identity binding in the OPA proxy policy engine.

use miette::{IntoDiagnostic, Result};
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

/// Read the binary path of a process via `/proc/{pid}/exe` symlink.
///
/// Returns the canonical path to the executable that the process is running.
/// Fails hard if the exe symlink is not readable — we never fall back to
/// `/proc/{pid}/cmdline` because `argv[0]` is trivially spoofable by any
/// process and must not be used as a trusted identity source.
///
/// If this fails, ensure the proxy process has permission to read
/// `/proc/<pid>/exe` (e.g. same user, or `CAP_SYS_PTRACE`).
#[cfg(target_os = "linux")]
pub fn binary_path(pid: i32) -> Result<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe")).map_err(|e| {
        miette::miette!(
            "Failed to read /proc/{pid}/exe: {e}. \
             Cannot determine binary identity — denying request. \
             Hint: the proxy may need CAP_SYS_PTRACE or to run as the same user."
        )
    })
}

/// Resolve the binary path of the TCP peer inside a sandbox network namespace.
///
/// Uses `/proc/<entrypoint_pid>/net/tcp` to find the socket inode for the given
/// ephemeral port, then scans the entrypoint process tree to find which PID owns
/// that socket, and finally reads `/proc/<pid>/exe` to get the binary path.
#[cfg(target_os = "linux")]
pub fn resolve_tcp_peer_binary(entrypoint_pid: u32, peer_port: u16) -> Result<PathBuf> {
    let inode = parse_proc_net_tcp(entrypoint_pid, peer_port)?;
    let pid = find_pid_by_socket_inode(inode, entrypoint_pid)?;
    binary_path(pid.cast_signed())
}

/// Like `resolve_tcp_peer_binary`, but also returns the PID that owns the socket.
///
/// Needed for the ancestor walk: we must know the PID to walk `/proc/<pid>/status` PPid chain.
#[cfg(target_os = "linux")]
pub fn resolve_tcp_peer_identity(entrypoint_pid: u32, peer_port: u16) -> Result<(PathBuf, u32)> {
    let inode = parse_proc_net_tcp(entrypoint_pid, peer_port)?;
    let pid = find_pid_by_socket_inode(inode, entrypoint_pid)?;
    let path = binary_path(pid.cast_signed())?;
    Ok((path, pid))
}

/// Read the `PPid` (parent PID) from `/proc/<pid>/status`.
#[cfg(target_os = "linux")]
pub fn read_ppid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// Walk the process tree upward from `pid`, collecting the binary path of each ancestor.
///
/// Stops at PID 1 (init), `stop_pid` (the entrypoint process), or after 64 ancestors
/// as a safety limit. The returned vec does NOT include `pid` itself — only its parents.
#[cfg(target_os = "linux")]
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

        // Stop if we've reached the entrypoint or init
        if ppid == stop_pid || ppid == 1 {
            break;
        }
        current = ppid;
    }

    ancestors
}

/// Extract absolute paths from `/proc/<pid>/cmdline`.
///
/// Reads the null-separated cmdline and returns any argv entries that look like
/// absolute paths (starting with `/`). This captures script paths that don't
/// appear in `/proc/<pid>/exe` — e.g. when `#!/usr/bin/env node` runs
/// `/usr/local/bin/claude`, the exe is `/usr/bin/node` but cmdline contains
/// `node\0/usr/local/bin/claude\0...`.
#[cfg(target_os = "linux")]
pub fn cmdline_absolute_paths(pid: u32) -> Vec<PathBuf> {
    let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return vec![];
    };
    cmdline
        .split(|&b| b == 0)
        .filter(|arg| arg.first() == Some(&b'/'))
        .map(|arg| PathBuf::from(String::from_utf8_lossy(arg).into_owned()))
        .collect()
}

/// Collect cmdline absolute paths for a PID and its ancestor chain.
///
/// Returns deduplicated absolute paths from `/proc/<pid>/cmdline` for the given
/// PID and each ancestor up to `stop_pid` / PID 1. Paths already present in
/// `exclude` (typically the exe-based paths) are omitted to avoid duplicates.
#[cfg(target_os = "linux")]
#[allow(clippy::similar_names)]
pub fn collect_cmdline_paths(pid: u32, stop_pid: u32, exclude: &[PathBuf]) -> Vec<PathBuf> {
    const MAX_DEPTH: usize = 64;
    let mut paths = Vec::new();
    let mut current = pid;

    // Collect from the immediate PID first
    for p in cmdline_absolute_paths(current) {
        if !exclude.contains(&p) && !paths.contains(&p) {
            paths.push(p);
        }
    }

    // Then walk ancestors (same traversal as collect_ancestor_binaries)
    for _ in 0..MAX_DEPTH {
        let ppid = match read_ppid(current) {
            Some(p) if p > 0 && p != current => p,
            _ => break,
        };

        for p in cmdline_absolute_paths(ppid) {
            if !exclude.contains(&p) && !paths.contains(&p) {
                paths.push(p);
            }
        }

        if ppid == stop_pid || ppid == 1 {
            break;
        }
        current = ppid;
    }

    paths
}

/// Parse `/proc/<pid>/net/tcp` (and `/proc/<pid>/net/tcp6`) to find the socket
/// inode for a given local port.
///
/// Checks both IPv4 and IPv6 tables because some clients (notably gRPC C-core)
/// use `AF_INET6` sockets with IPv4-mapped addresses even for IPv4 connections.
///
/// Format of `/proc/net/tcp`:
/// ```text
///   sl  local_address rem_address   st tx_queue:rx_queue ... inode
///    0: 0200C80A:8F4C 0100C80A:0C38 01 00000000:00000000 ... 12345
/// ```
/// - Addresses: hex IP (host byte order) `:` hex port
/// - State `01` = ESTABLISHED
/// - Inode is field index 9 (0-indexed)
#[cfg(target_os = "linux")]
fn parse_proc_net_tcp(pid: u32, peer_port: u16) -> Result<u64> {
    // Check IPv4 first (most common), then IPv6.
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

            // Parse local_address to extract port.
            // IPv4 format: AABBCCDD:PORT
            // IPv6 format: 00000000000000000000000000000000:PORT
            let local_addr = fields[1];
            let local_port = match local_addr.rsplit_once(':') {
                Some((_, port_hex)) => u16::from_str_radix(port_hex, 16).unwrap_or(0),
                None => continue,
            };

            // Check state is ESTABLISHED (01)
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

/// Scan process tree to find which PID owns a given socket inode.
///
/// First scans descendants of `entrypoint_pid` (most likely owners), then falls
/// back to scanning all of `/proc`. Requires `CAP_SYS_PTRACE` to read
/// `/proc/<pid>/fd/` for processes running as a different user.
#[cfg(target_os = "linux")]
fn find_pid_by_socket_inode(inode: u64, entrypoint_pid: u32) -> Result<u32> {
    let target = format!("socket:[{inode}]");

    // First: scan descendants of the entrypoint process (targeted, most likely to succeed)
    let descendants = collect_descendant_pids(entrypoint_pid);
    for &pid in &descendants {
        if let Some(found) = check_pid_fds(pid, &target) {
            return Ok(found);
        }
    }

    // Fallback: scan all of /proc in case the process isn't in the tree
    // (e.g., if /proc/<pid>/task/<tid>/children wasn't available)
    if let Ok(proc_dir) = std::fs::read_dir("/proc") {
        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let pid: u32 = match name.to_string_lossy().parse() {
                Ok(p) => p,
                Err(_) => continue,
            };
            // Skip PIDs we already checked
            if descendants.contains(&pid) {
                continue;
            }
            if let Some(found) = check_pid_fds(pid, &target) {
                return Ok(found);
            }
        }
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

/// Check if a PID has an fd pointing to the given socket target string.
#[cfg(target_os = "linux")]
fn check_pid_fds(pid: u32, target: &str) -> Option<u32> {
    let fd_dir = format!("/proc/{pid}/fd");
    let fds = std::fs::read_dir(&fd_dir).ok()?;
    for fd_entry in fds.flatten() {
        if let Ok(link) = std::fs::read_link(fd_entry.path())
            && link.to_string_lossy() == target
        {
            return Some(pid);
        }
    }
    None
}

/// Collect all descendant PIDs of a root process using `/proc/<pid>/task/<tid>/children`.
///
/// Performs a BFS walk of the process tree. If `/proc/<pid>/task/<tid>/children`
/// is not available (requires `CONFIG_PROC_CHILDREN`), returns only the root PID.
#[cfg(target_os = "linux")]
fn collect_descendant_pids(root_pid: u32) -> Vec<u32> {
    let mut pids = vec![root_pid];
    let mut i = 0;
    while i < pids.len() {
        let pid = pids[i];
        let task_dir = format!("/proc/{pid}/task");
        if let Ok(tasks) = std::fs::read_dir(&task_dir) {
            for task_entry in tasks.flatten() {
                let children_path = task_entry.path().join("children");
                if let Ok(children_str) = std::fs::read_to_string(&children_path) {
                    for child in children_str.split_whitespace() {
                        if let Ok(child_pid) = child.parse::<u32>() {
                            pids.push(child_pid);
                        }
                    }
                }
            }
        }
        i += 1;
    }
    pids
}

/// Compute the SHA256 hash of a file, returned as a hex-encoded string.
///
/// Used for binary integrity verification in the trust-on-first-use (TOFU)
/// model: the proxy hashes a binary on first network request and caches the
/// result. Subsequent requests from the same binary path must produce the
/// same hash, or the request is denied.
pub fn file_sha256(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};

    let bytes = std::fs::read(path).into_diagnostic()?;
    let hash = Sha256::digest(&bytes);
    Ok(hex::encode(hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn file_sha256_computes_correct_hash() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"hello world").unwrap();
        tmp.flush().unwrap();

        let hash = file_sha256(tmp.path()).unwrap();
        // SHA256 of "hello world"
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn file_sha256_different_content_different_hash() {
        let mut tmp1 = tempfile::NamedTempFile::new().unwrap();
        tmp1.write_all(b"content a").unwrap();
        tmp1.flush().unwrap();

        let mut tmp2 = tempfile::NamedTempFile::new().unwrap();
        tmp2.write_all(b"content b").unwrap();
        tmp2.flush().unwrap();

        let hash1 = file_sha256(tmp1.path()).unwrap();
        let hash2 = file_sha256(tmp2.path()).unwrap();
        assert_ne!(hash1, hash2);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn binary_path_reads_current_process() {
        let pid = std::process::id().cast_signed();
        let path = binary_path(pid).unwrap();
        // Should resolve to the test runner binary
        assert!(path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn collect_descendants_includes_self() {
        let pid = std::process::id();
        let pids = collect_descendant_pids(pid);
        assert!(pids.contains(&pid));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[allow(clippy::similar_names)]
    fn read_ppid_returns_parent() {
        let pid = std::process::id();
        let ppid = read_ppid(pid);
        assert!(ppid.is_some(), "Should be able to read PPid of self");
        assert!(ppid.unwrap() > 0, "PPid should be > 0");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_ppid_nonexistent_pid() {
        // PID 0 is the kernel scheduler, reading its status should fail or return None
        let result = read_ppid(999_999_999);
        assert!(result.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn collect_ancestor_binaries_returns_parents() {
        let pid = std::process::id();
        // stop_pid=1 means walk all the way up to init
        let ancestors = collect_ancestor_binaries(pid, 1);
        // We should have at least one ancestor (our parent process)
        assert!(
            !ancestors.is_empty(),
            "Should have at least one ancestor binary"
        );
        // Each ancestor should be a real path
        for path in &ancestors {
            assert!(
                !path.as_os_str().is_empty(),
                "Ancestor path should not be empty"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[allow(clippy::similar_names)]
    fn collect_ancestor_binaries_stops_at_stop_pid() {
        let pid = std::process::id();
        let ppid = read_ppid(pid).unwrap();
        // If we set stop_pid to our direct parent, we should get exactly 1 ancestor
        let ancestors = collect_ancestor_binaries(pid, ppid);
        assert_eq!(ancestors.len(), 1, "Should stop at stop_pid (our parent)");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cmdline_absolute_paths_returns_paths() {
        let pid = std::process::id();
        let paths = cmdline_absolute_paths(pid);
        // The test runner binary should appear as an absolute path in cmdline
        assert!(
            !paths.is_empty(),
            "Should find at least one absolute path in cmdline"
        );
        for p in &paths {
            assert!(
                p.is_absolute(),
                "All returned paths should be absolute: {}",
                p.display()
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cmdline_absolute_paths_nonexistent_pid() {
        let paths = cmdline_absolute_paths(999_999_999);
        assert!(paths.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn collect_cmdline_paths_excludes_known() {
        let pid = std::process::id();
        let exe = binary_path(pid.cast_signed()).unwrap();
        // When we exclude the exe path, it shouldn't appear in cmdline_paths
        let paths = collect_cmdline_paths(pid, 1, std::slice::from_ref(&exe));
        assert!(
            !paths.contains(&exe),
            "Should not contain excluded exe path"
        );
    }
}
