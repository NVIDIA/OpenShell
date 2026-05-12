// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Linux `/proc` filesystem reading for process identity.
//!
//! Provides functions to resolve binary paths and compute file hashes
//! for process-identity binding in the OPA proxy policy engine.

use miette::Result;
#[cfg(target_os = "linux")]
use std::collections::HashSet;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use tracing::debug;

/// Where a socket owner was discovered while scanning `/proc`.
#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SocketOwnerSource {
    /// Owner was found in the entrypoint process tree at the given BFS depth.
    Descendant { depth: usize },
    /// Owner was found by scanning all of `/proc` after the descendant scan.
    ProcFallback,
}

/// A process with an fd pointing at a target socket inode.
#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocketOwner {
    pub pid: u32,
    pub source: SocketOwnerSource,
}

/// All process owners for a TCP peer socket.
#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpPeerSocketOwners {
    pub inode: u64,
    pub owners: Vec<SocketOwner>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct DescendantPid {
    pid: u32,
    depth: usize,
}

/// Read the binary path of a process via `/proc/{pid}/exe` symlink.
///
/// Returns the canonical path to the executable that the process is running.
/// Fails hard if the exe symlink is not readable — we never fall back to
/// `/proc/{pid}/cmdline` because `argv[0]` is trivially spoofable by any
/// process and must not be used as a trusted identity source.
///
/// ### Unlinked binaries (`(deleted)` suffix)
///
/// When a running binary is unlinked from its filesystem path — the common
/// case is a hot-swap of `/opt/openshell/bin/openshell-sandbox` during a
/// development upgrade — the kernel appends the
/// literal string `" (deleted)"` to the `/proc/<pid>/exe` readlink target.
/// The raw tainted path (e.g. `"/opt/openshell/bin/openshell-sandbox (deleted)"`)
/// is not a real filesystem path: any downstream `stat()` fails with `ENOENT`.
///
/// We strip the suffix so callers see a clean, grep-friendly path suitable
/// for cache keys and log messages. The strip is guarded: we only strip when
/// `stat()` on the raw readlink target reports `NotFound`, so a live executable
/// whose basename literally ends with `" (deleted)"` is returned unchanged.
/// The comparison is done on raw bytes via `OsStrExt`, so filenames that are
/// not valid UTF-8 are still handled correctly. Exactly one kernel-added
/// suffix is stripped.
///
/// This does NOT claim the file at the stripped path is the same binary that
/// the process is executing — the on-disk inode may now be arbitrary. Callers
/// that need to verify the running binary's *contents* (for integrity
/// checking) should read the magic `/proc/<pid>/exe` symlink directly via
/// `File::open`, which procfs resolves to the live in-memory executable even
/// when the original inode has been unlinked.
///
/// If the readlink itself fails, ensure the proxy process has permission
/// to read `/proc/<pid>/exe` (e.g. same user, or `CAP_SYS_PTRACE`).
#[cfg(target_os = "linux")]
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

    // Only strip when the raw readlink target cannot be stat'd and its bytes
    // end with the kernel-added suffix. This preserves live executables whose
    // basename legitimately ends with " (deleted)" and handles non-UTF-8
    // filenames correctly.
    let raw_target_missing =
        matches!(std::fs::metadata(&target), Err(err) if err.kind() == ErrorKind::NotFound);

    let bytes = target.as_os_str().as_bytes();
    if raw_target_missing && bytes.ends_with(DELETED_SUFFIX) {
        let stripped = bytes[..bytes.len() - DELETED_SUFFIX.len()].to_vec();
        return Ok(PathBuf::from(OsString::from_vec(stripped)));
    }

    Ok(target)
}

/// Resolve the binary path of the TCP peer inside a sandbox network namespace.
///
/// Uses `/proc/<entrypoint_pid>/net/tcp` to find the socket inode for the given
/// ephemeral port, then scans the entrypoint process tree to find which PID owns
/// that socket, and finally reads `/proc/<pid>/exe` to get the binary path.
#[cfg(target_os = "linux")]
pub fn resolve_tcp_peer_binary(
    entrypoint_pid: u32,
    peer_port: u16,
    remote_port: u16,
    sandbox_netns_inode: u64,
) -> Result<PathBuf> {
    let owner =
        resolve_single_tcp_peer_owner(entrypoint_pid, peer_port, remote_port, sandbox_netns_inode)?;
    binary_path(owner.pid.cast_signed())
}

/// Resolve all process owners for the TCP peer inside a sandbox network namespace.
///
/// Multiple processes can legitimately hold the same socket inode after `fork()`
/// or fd passing. Callers that make security decisions must evaluate the full
/// owner set instead of selecting the first PID returned by `/proc` traversal.
///
/// `sandbox_netns_inode` is the `nsfs` inode of the sandbox network namespace
/// (zero means unknown / not configured). When non-zero, the cross-netns
/// fallback only considers PIDs whose `/proc/<pid>/ns/net` resolves to the
/// same inode, so the proxy never attributes a connection to a process
/// living in some other sandbox or the host. Without it, no fallback is
/// attempted — better to fail closed than to attribute the connection to
/// the wrong tenant.
#[cfg(target_os = "linux")]
pub fn resolve_tcp_peer_socket_owners(
    entrypoint_pid: u32,
    peer_port: u16,
    remote_port: u16,
    sandbox_netns_inode: u64,
) -> Result<TcpPeerSocketOwners> {
    let inode = parse_proc_net_tcp(entrypoint_pid, peer_port, remote_port, sandbox_netns_inode)?;
    let owners = find_socket_inode_owners(inode, entrypoint_pid)?;
    Ok(TcpPeerSocketOwners { inode, owners })
}

/// Resolve exactly one owner for the TCP peer, failing closed on ambiguity.
#[cfg(target_os = "linux")]
fn resolve_single_tcp_peer_owner(
    entrypoint_pid: u32,
    peer_port: u16,
    remote_port: u16,
    sandbox_netns_inode: u64,
) -> Result<SocketOwner> {
    let socket_owners = resolve_tcp_peer_socket_owners(
        entrypoint_pid,
        peer_port,
        remote_port,
        sandbox_netns_inode,
    )?;
    match socket_owners.owners.as_slice() {
        [owner] => Ok(owner.clone()),
        owners => {
            let mut pids: Vec<u32> = owners.iter().map(|owner| owner.pid).collect();
            pids.sort_unstable();
            Err(miette::miette!(
                "Ambiguous socket ownership for inode {}: PIDs [{}] all hold the same socket",
                socket_owners.inode,
                pids.iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        }
    }
}

/// Like `resolve_tcp_peer_binary`, but also returns the PID that owns the socket.
///
/// Needed for the ancestor walk: we must know the PID to walk `/proc/<pid>/status` `PPid` chain.
#[cfg(target_os = "linux")]
pub fn resolve_tcp_peer_identity(
    entrypoint_pid: u32,
    peer_port: u16,
    remote_port: u16,
    sandbox_netns_inode: u64,
) -> Result<(PathBuf, u32)> {
    let owner =
        resolve_single_tcp_peer_owner(entrypoint_pid, peer_port, remote_port, sandbox_netns_inode)?;
    let path = binary_path(owner.pid.cast_signed())?;
    Ok((path, owner.pid))
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
/// inode for a given local port and known proxy remote port.
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
///
/// Matches the socket whose **local port** equals `peer_port` *and* whose
/// **remote port** equals `remote_port`. The remote-port filter is a sanity
/// check, not a tenancy boundary — different sandbox netns can legitimately
/// have identical `(local_port, remote_port)` pairs because each sandbox
/// uses the same `10.200.0.0/24` veth subnet and the proxy listens on the
/// same port in every supervisor instance.
///
/// To stay tenant-correct, the cross-netns fallback is gated by
/// `sandbox_netns_inode`: only `/proc/<pid>` entries whose `ns/net` resolves
/// to that exact `nsfs` inode are considered. When `sandbox_netns_inode`
/// is zero (caller has no netns identity to compare against), the fallback
/// is skipped entirely and the function fails closed.
///
/// Socket inodes are kernel-global, so the inode returned from a confirmed
/// sandbox-netns scan is the same one that `find_socket_inode_owners` will
/// resolve to FD-holding processes downstream.
#[cfg(target_os = "linux")]
fn parse_proc_net_tcp(
    pid: u32,
    peer_port: u16,
    remote_port: u16,
    sandbox_netns_inode: u64,
) -> Result<u64> {
    // Try the cached entrypoint PID first, but only if it actually lives
    // inside the expected sandbox netns. Without this gate a recycled PID
    // — now owned by an unrelated process in a different netns — could
    // expose a `(local_port, remote_port)` collision and let us
    // misattribute the connection.
    let primary_in_sandbox =
        sandbox_netns_inode == 0 || pid_lives_in_netns(pid, sandbox_netns_inode);
    if primary_in_sandbox {
        match scan_pid_net_tcp(pid, peer_port, remote_port) {
            ScanOutcome::Found(inode) => return Ok(inode),
            ScanOutcome::Empty => {
                // We got the full netns view through `pid` and the
                // connection wasn't there. No further PID in the same
                // namespace can help — fail closed.
                if sandbox_netns_inode != 0 {
                    return Err(miette::miette!(
                        "No ESTABLISHED TCP connection found for local port {peer_port} \
                         and remote port {remote_port} in /proc/{pid}/net/tcp{{,6}} \
                         (sandbox netns inode {sandbox_netns_inode}, view confirmed empty)"
                    ));
                }
            }
            ScanOutcome::Unreadable => {
                // Couldn't read the entrypoint's procfs view at all —
                // fall through to the walk so another live PID in the
                // same netns can supply the view.
            }
        }
    }

    // Without a sandbox-netns reference there is no safe way to confirm
    // that a candidate process actually belongs to this sandbox, so refuse
    // to walk into other tenants' procfs entries.
    if sandbox_netns_inode == 0 {
        return Err(miette::miette!(
            "No ESTABLISHED TCP connection found for local port {peer_port} \
             and remote port {remote_port} in /proc/{pid}/net/tcp{{,6}}; \
             cross-netns fallback disabled (no sandbox netns inode configured)"
        ));
    }

    // Fallback: the entrypoint PID is either in a different netns from
    // the one we expect, or its procfs view couldn't be read. Walk
    // `/proc` for another live PID in the sandbox netns and scan that
    // PID's `/proc/<pid>/net/tcp`. The first PID that produces a
    // readable view defines the answer — every process in the same
    // netns sees the same kernel TCP table.
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Err(miette::miette!(
            "No ESTABLISHED TCP connection found for local port {peer_port} \
             and remote port {remote_port} in /proc/{pid}/net/tcp{{,6}}; \
             also failed to enumerate /proc for netns fallback"
        ));
    };

    for entry in entries.flatten() {
        let Ok(other_pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if other_pid == pid {
            continue;
        }
        if !pid_lives_in_netns(other_pid, sandbox_netns_inode) {
            continue;
        }
        match scan_pid_net_tcp(other_pid, peer_port, remote_port) {
            ScanOutcome::Found(inode) => return Ok(inode),
            ScanOutcome::Empty => {
                // Confirmed netns view via `other_pid` — no need to
                // probe more PIDs in the same namespace.
                return Err(miette::miette!(
                    "No ESTABLISHED TCP connection found for local port {peer_port} \
                     and remote port {remote_port} in sandbox netns \
                     (inode {sandbox_netns_inode}, view confirmed via /proc/{other_pid})"
                ));
            }
            ScanOutcome::Unreadable => {
                // `other_pid` exited between the netns stat and the
                // tcp/tcp6 read. Try the next PID in the same netns
                // rather than concluding the namespace is empty.
            }
        }
    }

    Err(miette::miette!(
        "No ESTABLISHED TCP connection found for local port {peer_port} \
         and remote port {remote_port}: no live PID in sandbox netns \
         (inode {sandbox_netns_inode}) had a readable /proc/<pid>/net/tcp"
    ))
}

/// Result of a single PID's `/proc/<pid>/net/tcp{,6}` scan.
///
/// Distinguishing `Empty` from `Unreadable` is what lets the walk in
/// [`parse_proc_net_tcp`] avoid the race where a PID exits between
/// stat'ing `ns/net` and reading the TCP table — a transient read
/// failure must not be treated as "no match in this namespace".
#[cfg(target_os = "linux")]
enum ScanOutcome {
    /// The TCP table contained an ESTABLISHED row matching the requested
    /// `(local_port, remote_port)`; carries the kernel socket inode.
    Found(u64),
    /// At least one of `tcp` / `tcp6` was successfully read and no row
    /// matched. The caller has a confirmed netns view.
    Empty,
    /// Neither `tcp` nor `tcp6` was readable (PID exited mid-scan or the
    /// procfs entry is otherwise inaccessible).
    Unreadable,
}

/// Scan a single PID's `/proc/<pid>/net/tcp` (and `tcp6`) for an ESTABLISHED
/// connection matching `(local_port, remote_port)`. Returns the kernel socket
/// inode on first match. The tri-state return lets the caller tell a
/// confirmed "no match in this namespace" apart from a transient
/// "could not read the procfs entry".
#[cfg(target_os = "linux")]
fn scan_pid_net_tcp(pid: u32, peer_port: u16, remote_port: u16) -> ScanOutcome {
    let mut any_readable = false;
    for suffix in &["tcp", "tcp6"] {
        let path = format!("/proc/{pid}/net/{suffix}");
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        any_readable = true;

        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }

            // Check state is ESTABLISHED (01) before parsing ports.
            if fields[3] != "01" {
                continue;
            }

            // Parse local_address to extract port.
            // IPv4 format: AABBCCDD:PORT
            // IPv6 format: 00000000000000000000000000000000:PORT
            let Some(local_port) = parse_hex_port(fields[1]) else {
                continue;
            };
            let Some(rem_port) = parse_hex_port(fields[2]) else {
                continue;
            };

            if local_port == peer_port && rem_port == remote_port {
                let Ok(inode) = fields[9].parse::<u64>() else {
                    // Malformed inode column — skip the row rather than
                    // abandoning the whole scan.
                    continue;
                };
                if inode == 0 {
                    continue;
                }
                return ScanOutcome::Found(inode);
            }
        }
    }
    if any_readable {
        ScanOutcome::Empty
    } else {
        ScanOutcome::Unreadable
    }
}

/// Check whether `/proc/<pid>/ns/net` resolves to the given `nsfs` inode.
/// Returns `false` if the procfs entry cannot be stat'd (PID exited, or
/// permissions prevent the lookup) — fail closed instead of optimistically
/// admitting the PID into the sandbox-netns-gated scan.
#[cfg(target_os = "linux")]
fn pid_lives_in_netns(pid: u32, netns_inode: u64) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(format!("/proc/{pid}/ns/net")).is_ok_and(|m| m.ino() == netns_inode)
}

/// Parse the hex port suffix of a `/proc/net/tcp` address field
/// (`<hex_ip>:<hex_port>`).
#[cfg(target_os = "linux")]
fn parse_hex_port(addr: &str) -> Option<u16> {
    let (_, port_hex) = addr.rsplit_once(':')?;
    u16::from_str_radix(port_hex, 16).ok()
}

/// Scan `/proc` to find every PID that owns a given socket inode.
///
/// First scans descendants of `entrypoint_pid` (most likely owners), then falls
/// back to scanning all of `/proc`. Requires `CAP_SYS_PTRACE` to read
/// `/proc/<pid>/fd/` for processes running as a different user.
#[cfg(target_os = "linux")]
fn find_socket_inode_owners(inode: u64, entrypoint_pid: u32) -> Result<Vec<SocketOwner>> {
    let target = format!("socket:[{inode}]");
    let mut owners = Vec::new();
    let mut checked = HashSet::new();

    // First: scan descendants of the entrypoint process
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

    // Fallback: scan all of /proc in case the process isn't in the tree
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

/// Check if a PID has an fd pointing to the given socket target string.
#[cfg(target_os = "linux")]
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

/// Collect all descendant PIDs of a root process using `/proc/<pid>/task/<tid>/children`.
///
/// Performs a BFS walk of the process tree. If `/proc/<pid>/task/<tid>/children`
/// is not available (requires `CONFIG_PROC_CHILDREN`), returns only the root PID.
#[cfg(all(test, target_os = "linux"))]
fn collect_descendant_pids(root_pid: u32) -> Vec<u32> {
    collect_descendant_pids_with_depth(root_pid)
        .into_iter()
        .map(|descendant| descendant.pid)
        .collect()
}

/// Collect descendant PIDs with BFS depth, deduping children reported by multiple tasks.
#[cfg(target_os = "linux")]
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

/// Compute the SHA256 hash of a file, returned as a hex-encoded string.
///
/// Used for binary integrity verification in the trust-on-first-use (TOFU)
/// model: the proxy hashes a binary on first network request and caches the
/// result. Subsequent requests from the same binary path must produce the
/// same hash, or the request is denied.
pub fn file_sha256(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let start = std::time::Instant::now();
    let mut file = std::fs::File::open(path)
        .map_err(|e| miette::miette!("Failed to open {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 65536].into_boxed_slice();
    let mut total_read = 0u64;
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| miette::miette!("Failed to read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        total_read += n as u64;
        hasher.update(&buf[..n]);
    }

    let hash = hasher.finalize();
    debug!(
        "        file_sha256: {}ms size={} path={}",
        start.elapsed().as_millis(),
        total_read,
        path.display()
    );
    Ok(hex::encode(hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Block until `/proc/<pid>/exe` points at `target`. `Command::spawn` returns
    /// once the child is scheduled, not once it has completed `exec()`; on
    /// contended runners the readlink can still show the parent (test harness)
    /// binary for a brief window. Byte-level `starts_with` tolerates the kernel's
    /// `" (deleted)"` suffix on unlinked executables.
    #[cfg(target_os = "linux")]
    fn wait_for_child_exec(pid: i32, target: &Path) {
        use std::os::unix::ffi::OsStrExt as _;
        let target_bytes = target.as_os_str().as_bytes();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if let Ok(link) = std::fs::read_link(format!("/proc/{pid}/exe"))
                && link.as_os_str().as_bytes().starts_with(target_bytes)
            {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "child pid {pid} did not exec into {target:?} within 2s"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// Retry `Command::spawn` on `ETXTBSY`. The kernel rejects `execve` when
    /// `inode->i_writecount > 0`, and the release of that counter after the
    /// writer fd is closed isn't synchronous with `close(2)` under contention —
    /// so the very-next-instruction `execve` can still race it. Any other error
    /// surfaces immediately.
    #[cfg(target_os = "linux")]
    fn spawn_retrying_on_etxtbsy(cmd: &mut std::process::Command) -> std::process::Child {
        let mut attempts = 0;
        loop {
            match cmd.spawn() {
                Ok(child) => return child,
                Err(err)
                    if err.kind() == std::io::ErrorKind::ExecutableFileBusy && attempts < 20 =>
                {
                    attempts += 1;
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(err) => panic!("spawn failed after {attempts} ETXTBSY retries: {err}"),
            }
        }
    }

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

    /// Verify that an unlinked binary's path is returned without the
    /// kernel's " (deleted)" suffix. This is the common case during a
    /// `docker cp` hot-swap of the supervisor binary — before this strip,
    /// callers that `stat()` the returned path get `ENOENT` and the
    /// ancestor integrity check in the CONNECT proxy denies every request.
    #[cfg(target_os = "linux")]
    #[test]
    fn binary_path_strips_deleted_suffix() {
        use std::os::unix::fs::PermissionsExt;

        // Copy /bin/sleep to a temp path we control so we can unlink it.
        let tmp = tempfile::TempDir::new().unwrap();
        let exe_path = tmp.path().join("deleted-sleep");
        std::fs::copy("/bin/sleep", &exe_path).unwrap();
        std::fs::set_permissions(&exe_path, std::fs::Permissions::from_mode(0o755)).unwrap();

        // Spawn a child from the temp binary, then unlink it while the
        // child is still running. The child keeps the exec mapping via
        // `/proc/<pid>/exe`, but readlink will now return the tainted
        // "<path> (deleted)" string.
        let mut cmd = std::process::Command::new(&exe_path);
        cmd.arg("5");
        let mut child = spawn_retrying_on_etxtbsy(&mut cmd);
        let pid: i32 = child.id().cast_signed();
        wait_for_child_exec(pid, &exe_path);
        std::fs::remove_file(&exe_path).unwrap();

        // Sanity check: the raw readlink should contain " (deleted)".
        let raw = std::fs::read_link(format!("/proc/{pid}/exe"))
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(
            raw.ends_with(" (deleted)"),
            "kernel should append ' (deleted)' to unlinked exe readlink; got {raw:?}"
        );

        // The public API should return the stripped path, not the tainted one.
        let resolved = binary_path(pid).expect("binary_path should succeed for deleted binary");
        assert_eq!(
            resolved, exe_path,
            "binary_path should strip the ' (deleted)' suffix"
        );
        let resolved_str = resolved.to_string_lossy();
        assert!(
            !resolved_str.contains("(deleted)"),
            "stripped path must not contain '(deleted)'; got {resolved_str:?}"
        );

        let _ = child.kill();
        let _ = child.wait();
    }

    /// A live executable whose basename literally ends with `" (deleted)"`
    /// must be returned unchanged — we only strip when `stat()` reports
    /// the raw readlink target missing. This guards against the trusted
    /// identity source misattributing a running binary to a truncated
    /// sibling path.
    #[cfg(target_os = "linux")]
    #[test]
    fn binary_path_preserves_live_deleted_basename() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        // Basename literally ends with " (deleted)" while the file is still
        // on disk — a pathological but legal filename.
        let exe_path = tmp.path().join("sleepy (deleted)");
        std::fs::copy("/bin/sleep", &exe_path).unwrap();
        std::fs::set_permissions(&exe_path, std::fs::Permissions::from_mode(0o755)).unwrap();

        let mut cmd = std::process::Command::new(&exe_path);
        cmd.arg("5");
        let mut child = spawn_retrying_on_etxtbsy(&mut cmd);
        let pid: i32 = child.id().cast_signed();
        wait_for_child_exec(pid, &exe_path);

        // File is still linked — binary_path must return the path unchanged,
        // suffix and all.
        let resolved = binary_path(pid).expect("binary_path should succeed for live binary");
        assert_eq!(
            resolved, exe_path,
            "binary_path must NOT strip ' (deleted)' from a live executable's basename"
        );
        assert!(
            resolved.to_string_lossy().ends_with(" (deleted)"),
            "stripped path unexpectedly trimmed a real filename: {resolved:?}"
        );

        let _ = child.kill();
        let _ = child.wait();
    }

    /// An unlinked executable whose filename contains non-UTF-8 bytes must
    /// still strip exactly one kernel-added `" (deleted)"` suffix. We operate
    /// on raw bytes via `OsStrExt`, so invalid UTF-8 is not a reason to skip
    /// the strip and return a path that downstream `stat()` calls will reject.
    #[cfg(target_os = "linux")]
    #[test]
    fn binary_path_strips_suffix_for_non_utf8_filename() {
        use std::ffi::OsString;
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        // 0xFF is not valid UTF-8. Build the filename on raw bytes.
        let mut raw_name: Vec<u8> = b"badname-".to_vec();
        raw_name.push(0xFF);
        raw_name.extend_from_slice(b".bin");
        let exe_path = tmp.path().join(OsString::from_vec(raw_name));

        std::fs::copy("/bin/sleep", &exe_path).unwrap();
        std::fs::set_permissions(&exe_path, std::fs::Permissions::from_mode(0o755)).unwrap();

        let mut cmd = std::process::Command::new(&exe_path);
        cmd.arg("5");
        let mut child = spawn_retrying_on_etxtbsy(&mut cmd);
        let pid: i32 = child.id().cast_signed();
        wait_for_child_exec(pid, &exe_path);
        std::fs::remove_file(&exe_path).unwrap();

        // Sanity: raw readlink ends with " (deleted)" and is not valid UTF-8.
        let raw = std::fs::read_link(format!("/proc/{pid}/exe")).unwrap();
        let raw_bytes = raw.as_os_str().as_bytes();
        assert!(
            raw_bytes.ends_with(b" (deleted)"),
            "kernel should append ' (deleted)' to unlinked exe readlink"
        );
        assert!(
            std::str::from_utf8(raw_bytes).is_err(),
            "test precondition: raw readlink must contain non-UTF-8 bytes"
        );

        let resolved =
            binary_path(pid).expect("binary_path should succeed for non-UTF-8 unlinked path");
        assert_eq!(
            resolved, exe_path,
            "binary_path must strip exactly one ' (deleted)' suffix for non-UTF-8 paths"
        );
        assert!(
            !resolved.as_os_str().as_bytes().ends_with(b" (deleted)"),
            "stripped path must not end with ' (deleted)'"
        );

        let _ = child.kill();
        let _ = child.wait();
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
    fn collect_descendants_dedupes_pids() {
        let pid = std::process::id();
        let pids = collect_descendant_pids(pid);
        let unique = pids.iter().copied().collect::<HashSet<_>>();
        assert_eq!(pids.len(), unique.len());
    }

    /// `/proc/self/ns/net` inode for the test process — used as the
    /// sandbox-netns identity in tests where the listener and the test
    /// process share a namespace.
    #[cfg(target_os = "linux")]
    fn self_netns_inode() -> u64 {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata("/proc/self/ns/net")
            .expect("stat /proc/self/ns/net")
            .ino()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_tcp_peer_socket_owners_returns_all_forked_socket_holders() {
        use std::net::{TcpListener, TcpStream};
        use std::time::{Duration, Instant};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let listener_port = listener.local_addr().unwrap().port();
        let stream = TcpStream::connect(("127.0.0.1", listener_port)).expect("connect");
        let peer_port = stream.local_addr().unwrap().port();
        let (_accepted, _) = listener.accept().expect("accept");

        // libc/syscall FFI requires unsafe
        #[allow(unsafe_code)]
        let child_pid = unsafe { libc::fork() };
        assert!(child_pid >= 0, "fork failed");
        if child_pid == 0 {
            // libc/syscall FFI requires unsafe
            #[allow(unsafe_code)]
            unsafe {
                libc::sleep(30);
                libc::_exit(0);
            }
        }

        let child_pid_u32 = child_pid.cast_unsigned();
        let entrypoint_pid = std::process::id();
        let netns_ino = self_netns_inode();
        let deadline = Instant::now() + Duration::from_secs(2);
        let owners = loop {
            let owners =
                resolve_tcp_peer_socket_owners(entrypoint_pid, peer_port, listener_port, netns_ino)
                    .expect("resolve socket owners");
            let owner_pids = owners
                .owners
                .iter()
                .map(|owner| owner.pid)
                .collect::<HashSet<_>>();
            if owner_pids.contains(&entrypoint_pid) && owner_pids.contains(&child_pid_u32) {
                break owners;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for forked child to appear as a socket owner; got {owner_pids:?}"
            );
            std::thread::sleep(Duration::from_millis(20));
        };

        // libc/syscall FFI requires unsafe
        #[allow(unsafe_code)]
        unsafe {
            libc::kill(child_pid, libc::SIGKILL);
            libc::waitpid(child_pid, std::ptr::null_mut(), 0);
        }

        let owner_pids = owners
            .owners
            .iter()
            .map(|owner| owner.pid)
            .collect::<HashSet<_>>();
        assert!(owner_pids.contains(&entrypoint_pid));
        assert!(owner_pids.contains(&child_pid_u32));
    }

    /// When the given `entrypoint_pid` does not exist (or its `/proc/<pid>/`
    /// directory is missing) but a sandbox netns inode is supplied, the
    /// fallback walks `/proc` and only considers PIDs whose `ns/net`
    /// resolves to that inode. Here the listener and the test process
    /// share a namespace, so the test process's procfs view is the one
    /// the fallback should pick up.
    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_tcp_peer_socket_owners_falls_back_to_proc_walk_when_entrypoint_pid_is_dead() {
        use std::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let listener_port = listener.local_addr().unwrap().port();
        let stream = TcpStream::connect(("127.0.0.1", listener_port)).expect("connect");
        let peer_port = stream.local_addr().unwrap().port();
        let (_accepted, _) = listener.accept().expect("accept");

        // PID 999_999_999 is virtually guaranteed not to exist on Linux
        // (PID_MAX_LIMIT is typically 4 194 304). The first scan attempt
        // misses immediately; the fallback walk picks up the connection
        // from this process's own /proc/<self>/net/tcp because we're
        // gating on this test process's netns inode.
        let dead_pid = 999_999_999;
        let owners =
            resolve_tcp_peer_socket_owners(dead_pid, peer_port, listener_port, self_netns_inode())
                .expect("fallback walk should locate the live connection");

        let owner_pids: HashSet<u32> = owners.owners.iter().map(|owner| owner.pid).collect();
        assert!(
            owner_pids.contains(&std::process::id()),
            "fallback walk should attribute the socket to this test process; got {owner_pids:?}"
        );
    }

    /// When the entrypoint PID is dead and `sandbox_netns_inode` is zero
    /// (caller has no netns identity), `parse_proc_net_tcp` must fail
    /// closed instead of attributing the connection to whichever PID it
    /// happens to find in another namespace.
    #[cfg(target_os = "linux")]
    #[test]
    fn parse_proc_net_tcp_fails_closed_without_sandbox_netns_inode() {
        use std::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let listener_port = listener.local_addr().unwrap().port();
        let stream = TcpStream::connect(("127.0.0.1", listener_port)).expect("connect");
        let peer_port = stream.local_addr().unwrap().port();
        let (_accepted, _) = listener.accept().expect("accept");

        // Connection exists and would be found by the fallback if it were
        // permitted to run — but without a sandbox netns reference the
        // scan must refuse to cross into other procfs entries.
        let dead_pid = 999_999_999;
        let result = parse_proc_net_tcp(dead_pid, peer_port, listener_port, 0);
        assert!(
            result.is_err(),
            "fallback must be disabled when sandbox_netns_inode == 0"
        );
    }

    /// The primary `pid` scan must be gated by `sandbox_netns_inode` too.
    /// If the cached entrypoint PID has been recycled to a process living
    /// in a different namespace, the proxy must not trust its TCP table
    /// even when a `(local_port, remote_port)` collision happens to match.
    /// Simulated by passing the test process's PID — which does live in
    /// some real netns — together with a `sandbox_netns_inode` that
    /// belongs to a different namespace (here, `u64::MAX`).
    #[cfg(target_os = "linux")]
    #[test]
    fn parse_proc_net_tcp_refuses_recycled_primary_pid_in_wrong_netns() {
        use std::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let listener_port = listener.local_addr().unwrap().port();
        let stream = TcpStream::connect(("127.0.0.1", listener_port)).expect("connect");
        let peer_port = stream.local_addr().unwrap().port();
        let (_accepted, _) = listener.accept().expect("accept");

        let pid = std::process::id();
        let actual_netns = self_netns_inode();
        // Sanity: under our own netns the scan succeeds.
        parse_proc_net_tcp(pid, peer_port, listener_port, actual_netns)
            .expect("scan should succeed when sandbox netns matches the primary PID");

        // Passing a different (here: nonexistent) sandbox netns inode
        // must reject the primary PID before reading its TCP table.
        let result = parse_proc_net_tcp(pid, peer_port, listener_port, u64::MAX);
        assert!(
            result.is_err(),
            "primary PID scan must be gated when sandbox netns inode disagrees"
        );
    }

    /// When the supplied `sandbox_netns_inode` does not match any PID's
    /// `ns/net` inode (simulating a sandbox whose every process has died),
    /// the fallback walk must come up empty rather than reattributing the
    /// connection to a co-tenant.
    #[cfg(target_os = "linux")]
    #[test]
    fn parse_proc_net_tcp_refuses_to_cross_into_other_netns() {
        use std::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let listener_port = listener.local_addr().unwrap().port();
        let stream = TcpStream::connect(("127.0.0.1", listener_port)).expect("connect");
        let peer_port = stream.local_addr().unwrap().port();
        let (_accepted, _) = listener.accept().expect("accept");

        // u64::MAX is not a real nsfs inode, so no /proc/<pid>/ns/net will
        // match. With the connection clearly visible in the test process's
        // own netns, the fallback must still refuse to attribute it.
        let dead_pid = 999_999_999;
        let bogus_netns = u64::MAX;
        let result = parse_proc_net_tcp(dead_pid, peer_port, listener_port, bogus_netns);
        assert!(
            result.is_err(),
            "fallback must not attribute connection when no PID lives in the expected netns"
        );
    }

    /// `(peer_port, remote_port)` matching prevents a port-only collision in
    /// the same netns from being treated as the target connection. Two
    /// independent ESTABLISHED connections share `peer_port` only if the
    /// remote ports differ; the scan must select the one whose `rem_port`
    /// matches the requested `remote_port`.
    #[cfg(target_os = "linux")]
    #[test]
    fn parse_proc_net_tcp_filters_by_remote_port() {
        use std::net::{TcpListener, TcpStream};

        // Two listeners on different ports — connections to each will share
        // the same client-side peer port only by accident, but each socket
        // has a distinct (local_port, rem_port) pair so the filter works.
        let listener_a = TcpListener::bind("127.0.0.1:0").expect("bind A");
        let listener_b = TcpListener::bind("127.0.0.1:0").expect("bind B");
        let port_a = listener_a.local_addr().unwrap().port();
        let port_b = listener_b.local_addr().unwrap().port();

        let stream_a = TcpStream::connect(("127.0.0.1", port_a)).expect("connect A");
        let stream_b = TcpStream::connect(("127.0.0.1", port_b)).expect("connect B");
        let _accepted_a = listener_a.accept().expect("accept A");
        let _accepted_b = listener_b.accept().expect("accept B");

        let peer_a = stream_a.local_addr().unwrap().port();
        let peer_b = stream_b.local_addr().unwrap().port();
        assert_ne!(peer_a, peer_b, "client-side ephemeral ports collided");

        let pid = std::process::id();
        let netns_ino = self_netns_inode();

        // Asking for (peer_a, port_a) must match connection A's inode.
        let inode_a = parse_proc_net_tcp(pid, peer_a, port_a, netns_ino)
            .expect("connection A must be resolvable");
        // Asking for (peer_a, port_b) must fail — that pair does not exist.
        let mismatch = parse_proc_net_tcp(pid, peer_a, port_b, netns_ino);
        assert!(
            mismatch.is_err(),
            "remote-port mismatch must not resolve to a stale inode"
        );

        // Sanity: connection B has its own distinct inode.
        let inode_b = parse_proc_net_tcp(pid, peer_b, port_b, netns_ino)
            .expect("connection B must be resolvable");
        assert_ne!(inode_a, inode_b);
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
