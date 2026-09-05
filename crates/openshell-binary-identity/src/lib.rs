// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared executable-identity resolution for RFC 0012 isolation backends.
//!
//! Runtime-specific observation remains inside each isolation backend. Once an
//! observer has an authoritative PID in its procfs view, this crate
//! canonicalizes the executable path, hashes the live executable object, and
//! collects its process ancestry. Backends bind the returned identity to the
//! intercepted connection before constructing a `MediatedConnection`.

#[cfg(target_os = "linux")]
use openshell_isolation_interface::contract::Sha256Digest;
use openshell_isolation_interface::contract::{BinaryIdentity, ResolveError};

/// Resolves executable identity from a Linux procfs process identifier.
///
/// The configured scope bounds ancestry and cmdline collection to the observed
/// PID namespace or a known workload process tree.
#[derive(Clone, Copy, Debug)]
pub struct ProcfsIdentityResolver {
    ancestry_scope: AncestryScope,
}

#[derive(Clone, Copy, Debug)]
enum AncestryScope {
    PidNamespace,
    ProcessTree(u32),
}

impl Default for ProcfsIdentityResolver {
    fn default() -> Self {
        Self::for_pid_namespace()
    }
}

impl ProcfsIdentityResolver {
    /// Build a resolver that discovers a nested PID namespace's init process
    /// and never reports host-runtime ancestors outside that namespace.
    #[must_use]
    pub const fn for_pid_namespace() -> Self {
        Self {
            ancestry_scope: AncestryScope::PidNamespace,
        }
    }

    /// Build a resolver bounded by the workload's trusted process-tree root.
    #[must_use]
    pub const fn for_process_tree(ancestor_root: u32) -> Self {
        Self {
            ancestry_scope: AncestryScope::ProcessTree(ancestor_root),
        }
    }

    /// Resolve the identity for an authoritative process ID.
    pub fn resolve(self, pid: u32) -> Result<BinaryIdentity, ResolveError> {
        #[cfg(target_os = "linux")]
        {
            let ancestor_root = match self.ancestry_scope {
                AncestryScope::PidNamespace => nested_pid_namespace_init(pid),
                AncestryScope::ProcessTree(root) => Some(root),
            };
            resolve_linux_process(pid, ancestor_root)
        }

        #[cfg(not(target_os = "linux"))]
        {
            match self.ancestry_scope {
                AncestryScope::PidNamespace => {}
                AncestryScope::ProcessTree(ancestor_root) => {
                    let _ = ancestor_root;
                }
            }
            let _ = pid;
            Err(ResolveError::Failed(
                "procfs binary identity is only available on Linux".to_string(),
            ))
        }
    }
}

#[cfg(target_os = "linux")]
fn resolve_linux_process(
    pid: u32,
    ancestor_root: Option<u32>,
) -> Result<BinaryIdentity, ResolveError> {
    let (snapshot, mut executable) = open_process_snapshot(pid)?;
    let binary_path = snapshot.binary_path.clone();
    let binary_digest = Some(hash_executable(pid, &mut executable)?);
    let ancestor_processes = collect_ancestor_processes(&snapshot, ancestor_root);
    let ancestors = ancestor_processes
        .iter()
        .map(|snapshot| snapshot.binary_path.clone())
        .collect::<Vec<_>>();

    let mut excluded_paths = ancestors.clone();
    excluded_paths.push(binary_path.clone());
    let cmdline_paths = cmdline_absolute_paths(&snapshot.cmdline)
        .into_iter()
        .chain(
            ancestor_processes
                .iter()
                .flat_map(|snapshot| cmdline_absolute_paths(&snapshot.cmdline)),
        )
        .filter(|path| !excluded_paths.contains(path))
        .fold(Vec::new(), |mut paths, path| {
            if !paths.contains(&path) {
                paths.push(path);
            }
            paths
        });

    validate_process_snapshot(pid, &snapshot)?;
    for ancestor in &ancestor_processes {
        validate_process_snapshot(ancestor.pid, ancestor)?;
    }

    Ok(BinaryIdentity {
        binary_path,
        binary_digest,
        ancestors,
        cmdline_paths,
    })
}

#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
struct ProcessSnapshot {
    pid: u32,
    parent_pid: u32,
    binary_path: std::path::PathBuf,
    executable_device: u64,
    executable_inode: u64,
    start_time: u64,
    cmdline: Vec<u8>,
}

#[cfg(target_os = "linux")]
fn open_process_snapshot(pid: u32) -> Result<(ProcessSnapshot, std::fs::File), ResolveError> {
    use std::os::unix::fs::MetadataExt as _;

    let path = format!("/proc/{pid}/exe");
    let binary_path = executable_path(pid)?;
    let executable = std::fs::File::open(&path)
        .map_err(|error| ResolveError::Failed(format!("open {path}: {error}")))?;
    let metadata = executable
        .metadata()
        .map_err(|error| ResolveError::Failed(format!("stat {path}: {error}")))?;
    let (parent_pid, start_time) = process_stat(pid)?;
    let snapshot = ProcessSnapshot {
        pid,
        parent_pid,
        binary_path,
        executable_device: metadata.dev(),
        executable_inode: metadata.ino(),
        start_time,
        cmdline: read_process_cmdline(pid)?,
    };
    validate_process_snapshot(pid, &snapshot)?;
    Ok((snapshot, executable))
}

#[cfg(target_os = "linux")]
fn validate_process_snapshot(pid: u32, expected: &ProcessSnapshot) -> Result<(), ResolveError> {
    use std::os::unix::fs::MetadataExt as _;

    let path = format!("/proc/{pid}/exe");
    let metadata = std::fs::metadata(&path)
        .map_err(|error| ResolveError::Failed(format!("stat {path}: {error}")))?;
    let (parent_pid, start_time) = process_stat(pid)?;
    let current = ProcessSnapshot {
        pid,
        parent_pid,
        binary_path: executable_path(pid)?,
        executable_device: metadata.dev(),
        executable_inode: metadata.ino(),
        start_time,
        cmdline: read_process_cmdline(pid)?,
    };
    if &current == expected {
        Ok(())
    } else {
        Err(ResolveError::Failed(format!(
            "process {pid} changed while its executable identity was collected"
        )))
    }
}

#[cfg(target_os = "linux")]
fn process_stat(pid: u32) -> Result<(u32, u64), ResolveError> {
    let path = format!("/proc/{pid}/stat");
    let stat = std::fs::read_to_string(&path)
        .map_err(|error| ResolveError::Failed(format!("read {path}: {error}")))?;
    let fields = stat
        .rsplit_once(") ")
        .map(|(_, fields)| fields)
        .ok_or_else(|| ResolveError::Failed(format!("parse {path}: missing command field")))?;
    let mut fields = fields.split_whitespace();
    let _state = fields.next();
    let parent_pid = fields
        .next()
        .ok_or_else(|| ResolveError::Failed(format!("parse {path}: missing parent PID")))?
        .parse()
        .map_err(|error| ResolveError::Failed(format!("parse {path} parent PID: {error}")))?;
    let start_time = fields
        .nth(17)
        .ok_or_else(|| ResolveError::Failed(format!("parse {path}: missing start time")))?
        .parse()
        .map_err(|error| ResolveError::Failed(format!("parse {path} start time: {error}")))?;
    Ok((parent_pid, start_time))
}

#[cfg(target_os = "linux")]
fn read_process_cmdline(pid: u32) -> Result<Vec<u8>, ResolveError> {
    let path = format!("/proc/{pid}/cmdline");
    std::fs::read(&path).map_err(|error| ResolveError::Failed(format!("read {path}: {error}")))
}

#[cfg(target_os = "linux")]
fn executable_path(pid: u32) -> Result<std::path::PathBuf, ResolveError> {
    use std::ffi::OsString;
    use std::io::ErrorKind;
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};

    const DELETED_SUFFIX: &[u8] = b" (deleted)";

    let link = format!("/proc/{pid}/exe");
    let target = std::fs::read_link(&link)
        .map_err(|error| ResolveError::Failed(format!("read {link}: {error}")))?;
    let target_missing =
        matches!(std::fs::metadata(&target), Err(error) if error.kind() == ErrorKind::NotFound);
    let bytes = target.as_os_str().as_bytes();

    if target_missing && bytes.ends_with(DELETED_SUFFIX) {
        let stripped = bytes[..bytes.len() - DELETED_SUFFIX.len()].to_vec();
        return Ok(std::path::PathBuf::from(OsString::from_vec(stripped)));
    }

    Ok(target)
}

#[cfg(target_os = "linux")]
fn hash_executable(pid: u32, executable: &mut std::fs::File) -> Result<Sha256Digest, ResolveError> {
    use sha2::{Digest as _, Sha256};
    use std::io::Read as _;

    let path = format!("/proc/{pid}/exe");
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let length = executable
            .read(&mut buffer)
            .map_err(|error| ResolveError::Failed(format!("hash {path}: {error}")))?;
        if length == 0 {
            break;
        }
        digest.update(&buffer[..length]);
    }
    format!("{:x}", digest.finalize()).parse()
}

#[cfg(target_os = "linux")]
fn collect_ancestor_processes(
    process: &ProcessSnapshot,
    ancestor_root: Option<u32>,
) -> Vec<ProcessSnapshot> {
    const MAX_DEPTH: usize = 64;

    if ancestor_root == Some(process.pid) {
        return Vec::new();
    }

    let mut ancestors = Vec::new();
    let mut parent = process.parent_pid;
    for _ in 0..MAX_DEPTH {
        if parent == 0
            || ancestors
                .iter()
                .any(|current: &ProcessSnapshot| current.pid == parent)
        {
            break;
        }

        // PID 1 is host or guest init rather than workload ancestry unless it
        // is the explicitly supplied process-tree root.
        if parent == 1 && ancestor_root != Some(1) {
            break;
        }

        let Ok((snapshot, _executable)) = open_process_snapshot(parent) else {
            break;
        };
        let next_parent = snapshot.parent_pid;
        ancestors.push(snapshot);
        if ancestor_root == Some(parent) || parent == 1 {
            break;
        }
        parent = next_parent;
    }
    ancestors
}

#[cfg(target_os = "linux")]
fn parent_pid(pid: u32) -> Option<u32> {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))?
        .trim()
        .parse()
        .ok()
}

#[cfg(target_os = "linux")]
fn nested_pid_namespace_init(pid: u32) -> Option<u32> {
    const MAX_DEPTH: usize = 64;

    let mut current = pid;
    for _ in 0..MAX_DEPTH {
        if namespace_pid(current) == Some(1) {
            // Host PID 1 is outside every workload. A nested namespace init
            // has a distinct host PID and is a valid workload ancestry root.
            return (current != 1).then_some(current);
        }
        current = parent_pid(current).filter(|parent| *parent > 0 && *parent != current)?;
    }
    None
}

#[cfg(target_os = "linux")]
fn namespace_pid(pid: u32) -> Option<u32> {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("NSpid:"))?
        .split_whitespace()
        .next_back()?
        .parse()
        .ok()
}

#[cfg(target_os = "linux")]
fn cmdline_absolute_paths(cmdline: &[u8]) -> Vec<std::path::PathBuf> {
    cmdline
        .split(|byte| *byte == 0)
        .filter(|argument| argument.first() == Some(&b'/'))
        .map(|argument| std::path::PathBuf::from(String::from_utf8_lossy(argument).into_owned()))
        .collect()
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn resolves_current_process_from_live_executable() {
        let identity = ProcfsIdentityResolver::for_pid_namespace()
            .resolve(std::process::id())
            .expect("resolve current process");

        assert!(identity.binary_path.is_absolute());
        assert!(identity.binary_digest.is_some());
    }

    #[test]
    fn process_tree_root_does_not_escape_into_host_ancestry() {
        let pid = std::process::id();
        let identity = ProcfsIdentityResolver::for_process_tree(pid)
            .resolve(pid)
            .expect("resolve process-tree root");

        assert!(identity.ancestors.is_empty());
    }
}
