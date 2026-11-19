// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared executable-identity resolution for RFC 0012 isolation backends.
//!
//! Runtime-specific observation remains inside each isolation backend. Once an
//! observer has an authoritative PID in its procfs view, this crate
//! canonicalizes the executable path, hashes the live executable object, and
//! collects its process ancestry. Backends bind the returned identity to the
//! intercepted connection before constructing a `MediatedConnection`.

use openshell_isolation_interface::contract::{BinaryIdentity, ResolveError};
#[cfg(target_os = "linux")]
use openshell_isolation_interface::contract::{ExecutableIdentity, Sha256Digest};
#[cfg(target_os = "linux")]
use std::collections::{HashMap, HashSet};
#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex};

#[cfg(target_os = "linux")]
const EXECUTABLE_DIGEST_CACHE_CAPACITY: usize = 1_024;

/// Bounds the total cmdline bytes read from `/proc/<pid>/cmdline`. This is a
/// diagnostic-read cap on the whole command line, not a per-argument limit:
/// the kernel allows a single argument larger than this cap, so one
/// maximum-size argument plus argv[0] already exceeds it and is truncated.
#[cfg(target_os = "linux")]
const CMDLINE_READ_LIMIT: usize = 128 * 1024;

/// Resolves executable identity from a Linux procfs process identifier.
///
/// The configured scope bounds ancestry and cmdline collection to the observed
/// PID namespace or a known workload process tree.
#[derive(Clone, Debug)]
pub struct ProcfsIdentityResolver {
    ancestry_scope: AncestryScope,
    #[cfg(target_os = "linux")]
    cache: Arc<Mutex<HashMap<ExecutableCacheKey, Sha256Digest>>>,
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
    pub fn for_pid_namespace() -> Self {
        Self {
            ancestry_scope: AncestryScope::PidNamespace,
            #[cfg(target_os = "linux")]
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Build a resolver bounded by the workload's trusted process-tree root.
    #[must_use]
    pub fn for_process_tree(ancestor_root: u32) -> Self {
        Self {
            ancestry_scope: AncestryScope::ProcessTree(ancestor_root),
            #[cfg(target_os = "linux")]
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Resolve the identity for an authoritative process ID.
    pub fn resolve(&self, pid: u32) -> Result<BinaryIdentity, ResolveError> {
        #[cfg(target_os = "linux")]
        {
            let ancestor_root = match self.ancestry_scope {
                AncestryScope::PidNamespace => nested_pid_namespace_init(pid),
                AncestryScope::ProcessTree(root) => Some(root),
            };
            resolve_linux_process(pid, ancestor_root, &self.cache)
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
    cache: &Mutex<HashMap<ExecutableCacheKey, Sha256Digest>>,
) -> Result<BinaryIdentity, ResolveError> {
    let (snapshot, mut executable) = open_process_snapshot(pid)?;
    let mut ancestor_processes = collect_ancestor_processes(&snapshot, ancestor_root)?;

    let mut excluded_paths = ancestor_processes
        .iter()
        .map(|(snapshot, _)| snapshot.binary_path.clone())
        .collect::<Vec<_>>();
    excluded_paths.push(snapshot.binary_path.clone());
    let cmdline_paths = collect_cmdline_paths(
        &snapshot.cmdline,
        ancestor_processes
            .iter()
            .map(|(snapshot, _)| snapshot.cmdline.as_slice()),
        &excluded_paths,
    );

    // Digests computed during this call. They reach the shared cache only after
    // every snapshot validates, but later processes in the chain reuse them.
    let mut pending_cache_entries = HashMap::new();
    let executable_identity = resolve_open_executable(
        &snapshot,
        &mut executable,
        cache,
        &mut pending_cache_entries,
    )?;
    let mut ancestors = Vec::with_capacity(ancestor_processes.len());
    for (ancestor, executable) in &mut ancestor_processes {
        ancestors.push(resolve_open_executable(
            ancestor,
            executable,
            cache,
            &mut pending_cache_entries,
        )?);
    }

    validate_process_snapshot(pid, &snapshot)?;
    for (ancestor, _) in &ancestor_processes {
        validate_process_snapshot(ancestor.pid, ancestor)?;
    }
    for (key, digest) in pending_cache_entries {
        cache_executable_digest(cache, key, digest);
    }

    Ok(BinaryIdentity {
        executable: executable_identity,
        ancestors,
        cmdline_paths,
    })
}

#[cfg(target_os = "linux")]
fn resolve_open_executable(
    snapshot: &ProcessSnapshot,
    executable: &mut std::fs::File,
    cache: &Mutex<HashMap<ExecutableCacheKey, Sha256Digest>>,
    pending: &mut HashMap<ExecutableCacheKey, Sha256Digest>,
) -> Result<ExecutableIdentity, ResolveError> {
    let key = snapshot.executable_cache_key();
    let known = pending
        .get(&key)
        .copied()
        .or_else(|| cached_executable_digest(cache, key));
    let digest = known.map_or_else(|| hash_executable(snapshot.pid, executable), Ok)?;
    if known.is_none() {
        pending.insert(key, digest);
    }
    Ok(ExecutableIdentity {
        path: snapshot.binary_path.clone(),
        digest: Some(digest),
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
    executable_size: u64,
    executable_mtime: i64,
    executable_mtime_nsec: i64,
    executable_ctime: i64,
    executable_ctime_nsec: i64,
    start_time: u64,
    cmdline: Vec<u8>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ExecutableCacheKey {
    device: u64,
    inode: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

#[cfg(target_os = "linux")]
impl ProcessSnapshot {
    fn executable_cache_key(&self) -> ExecutableCacheKey {
        ExecutableCacheKey {
            device: self.executable_device,
            inode: self.executable_inode,
            size: self.executable_size,
            mtime: self.executable_mtime,
            mtime_nsec: self.executable_mtime_nsec,
            ctime: self.executable_ctime,
            ctime_nsec: self.executable_ctime_nsec,
        }
    }
}

#[cfg(target_os = "linux")]
fn cached_executable_digest(
    cache: &Mutex<HashMap<ExecutableCacheKey, Sha256Digest>>,
    key: ExecutableCacheKey,
) -> Option<Sha256Digest> {
    cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&key)
        .copied()
}

#[cfg(target_os = "linux")]
fn cache_executable_digest(
    cache: &Mutex<HashMap<ExecutableCacheKey, Sha256Digest>>,
    key: ExecutableCacheKey,
    digest: Sha256Digest,
) {
    let mut cache = cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if cache.len() >= EXECUTABLE_DIGEST_CACHE_CAPACITY {
        // Evict a single arbitrary entry: clearing the whole cache would
        // force a rehash of every live executable after one capacity crossing.
        if let Some(evict) = cache.keys().next().copied() {
            cache.remove(&evict);
        }
    }
    cache.insert(key, digest);
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
        executable_size: metadata.size(),
        executable_mtime: metadata.mtime(),
        executable_mtime_nsec: metadata.mtime_nsec(),
        executable_ctime: metadata.ctime(),
        executable_ctime_nsec: metadata.ctime_nsec(),
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
        executable_size: metadata.size(),
        executable_mtime: metadata.mtime(),
        executable_mtime_nsec: metadata.mtime_nsec(),
        executable_ctime: metadata.ctime(),
        executable_ctime_nsec: metadata.ctime_nsec(),
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
    use std::io::Read as _;

    let path = format!("/proc/{pid}/cmdline");
    let file = std::fs::File::open(&path)
        // Keep the message prefix std::fs::read produced, so denial-path
        // strings downstream stay byte-identical.
        .map_err(|error| ResolveError::Failed(format!("read {path}: {error}")))?;
    // Reading one byte past the limit makes the truncation predicate exact:
    // a cmdline of exactly CMDLINE_READ_LIMIT bytes is kept whole.
    let mut buffer = Vec::new();
    file.take(CMDLINE_READ_LIMIT as u64 + 1)
        .read_to_end(&mut buffer)
        .map_err(|error| ResolveError::Failed(format!("read {path}: {error}")))?;
    Ok(cap_cmdline(buffer))
}

#[cfg(target_os = "linux")]
fn cap_cmdline(mut buffer: Vec<u8>) -> Vec<u8> {
    if buffer.len() <= CMDLINE_READ_LIMIT {
        return buffer;
    }
    buffer.truncate(CMDLINE_READ_LIMIT);
    // Drop the last argument whether it is partial or happens to end exactly
    // at the cap: a truncated fragment must not reach cmdline_absolute_paths,
    // and diagnostic-only data does not justify boundary-case recovery.
    if buffer.last().is_some_and(|byte| *byte == 0) {
        buffer.pop();
    }
    match buffer.iter().rposition(|byte| *byte == 0) {
        Some(index) => buffer.truncate(index + 1),
        None => buffer.clear(),
    }
    buffer
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
// Stack buffer by design: no heap allocation per cache miss. The array is
// zeroed on each call, a negligible cost next to hashing the executable.
// The 64 KiB size exceeds clippy's 16 KiB large_stack_arrays default, which
// is far below every thread stack in this call path.
#[allow(clippy::large_stack_arrays)]
fn hash_executable(pid: u32, executable: &mut std::fs::File) -> Result<Sha256Digest, ResolveError> {
    use std::fmt::Write as _;
    use std::io::Read as _;

    let path = format!("/proc/{pid}/exe");
    let crypto_error = |error| ResolveError::Failed(format!("hash executable: {error}"));
    let mut digest = openshell_crypto::sha256_digest().map_err(crypto_error)?;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let length = executable
            .read(&mut buffer)
            .map_err(|error| ResolveError::Failed(format!("hash {path}: {error}")))?;
        if length == 0 {
            break;
        }
        digest.update(&buffer[..length]).map_err(crypto_error)?;
    }
    let bytes = digest.finish().map_err(crypto_error)?;
    let mut hex = String::with_capacity(64);
    for byte in bytes {
        write!(&mut hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    hex.parse()
}

#[cfg(target_os = "linux")]
fn collect_ancestor_processes(
    process: &ProcessSnapshot,
    ancestor_root: Option<u32>,
) -> Result<Vec<(ProcessSnapshot, std::fs::File)>, ResolveError> {
    const MAX_DEPTH: usize = 64;

    if ancestor_root == Some(process.pid) {
        return Ok(Vec::new());
    }

    let mut ancestors: Vec<(ProcessSnapshot, std::fs::File)> = Vec::new();
    let mut parent = process.parent_pid;
    for _ in 0..MAX_DEPTH {
        if parent == 0 || ancestors.iter().any(|(current, _)| current.pid == parent) {
            break;
        }

        // PID 1 is host or guest init rather than workload ancestry unless it
        // is the explicitly supplied process-tree root.
        if parent == 1 && ancestor_root != Some(1) {
            break;
        }

        let (snapshot, executable) = open_process_snapshot(parent)?;
        let next_parent = snapshot.parent_pid;
        ancestors.push((snapshot, executable));
        if ancestor_root == Some(parent) || parent == 1 {
            break;
        }
        parent = next_parent;
    }
    Ok(ancestors)
}

#[cfg(target_os = "linux")]
#[derive(Debug, Default, PartialEq, Eq)]
struct ProcessStatus {
    ppid: Option<u32>,
    innermost_nspid: Option<u32>,
}

#[cfg(target_os = "linux")]
fn read_process_status(pid: u32) -> Option<ProcessStatus> {
    let path = format!("/proc/{pid}/status");
    Some(parse_process_status(&std::fs::read_to_string(path).ok()?))
}

#[cfg(target_os = "linux")]
fn parse_process_status(status: &str) -> ProcessStatus {
    let mut parsed = ProcessStatus::default();
    for line in status.lines() {
        match line.split_once(':') {
            Some(("PPid", value)) => parsed.ppid = value.trim().parse().ok(),
            Some(("NSpid", value)) => {
                parsed.innermost_nspid = value
                    .split_whitespace()
                    .next_back()
                    .and_then(|nspid| nspid.parse().ok());
            }
            _ => {}
        }
    }
    parsed
}

#[cfg(target_os = "linux")]
fn nested_pid_namespace_init(pid: u32) -> Option<u32> {
    const MAX_DEPTH: usize = 64;

    let mut current = pid;
    for _ in 0..MAX_DEPTH {
        // One status read per hop carries both the namespace PID check and
        // the parent PID for the next hop.
        let status = read_process_status(current)?;
        if status.innermost_nspid == Some(1) {
            // Host PID 1 is outside every workload. A nested namespace init
            // has a distinct host PID and is a valid workload ancestry root.
            return (current != 1).then_some(current);
        }
        current = status
            .ppid
            .filter(|parent| *parent > 0 && *parent != current)?;
    }
    None
}

#[cfg(target_os = "linux")]
fn cmdline_absolute_paths(cmdline: &[u8]) -> Vec<std::path::PathBuf> {
    cmdline
        .split(|byte| *byte == 0)
        .filter(|argument| argument.first() == Some(&b'/'))
        .map(|argument| std::path::PathBuf::from(String::from_utf8_lossy(argument).into_owned()))
        .collect()
}

#[cfg(target_os = "linux")]
fn collect_cmdline_paths<'a>(
    own_cmdline: &'a [u8],
    ancestor_cmdlines: impl Iterator<Item = &'a [u8]>,
    excluded_paths: &[std::path::PathBuf],
) -> Vec<std::path::PathBuf> {
    // Insertion order is load-bearing: consumers compare the collected
    // vectors wholesale, so the own cmdline comes first and ancestors follow
    // nearest-first. The excluded-paths scan stays a bounded linear check
    // over binary paths only. Candidates stream one cmdline at a time, and a
    // PathBuf is cloned only for unique survivors, never for duplicates or
    // excluded paths.
    let mut paths = Vec::new();
    let mut seen_paths: HashSet<std::path::PathBuf> = HashSet::new();
    for cmdline in std::iter::once(own_cmdline).chain(ancestor_cmdlines) {
        for path in cmdline_absolute_paths(cmdline) {
            if excluded_paths.contains(&path) || seen_paths.contains(&path) {
                continue;
            }
            seen_paths.insert(path.clone());
            paths.push(path);
        }
    }
    paths
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    const IDENTITY_HELPER_READY: &str = "identity helper ready\n";

    struct ChildGuard(std::process::Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolver_cache_is_owned_and_only_explicit_clones_share_it() {
        let pid = std::process::id();
        let first = ProcfsIdentityResolver::for_process_tree(pid);
        let shared = first.clone();
        let separate = ProcfsIdentityResolver::for_process_tree(pid);
        assert!(Arc::ptr_eq(&first.cache, &shared.cache));
        assert!(!Arc::ptr_eq(&first.cache, &separate.cache));
        first.resolve(pid).unwrap();
        assert!(!shared.cache.lock().unwrap().is_empty());
        assert!(separate.cache.lock().unwrap().is_empty());
    }

    #[test]
    fn resolves_current_process_from_live_executable() {
        let pid = std::process::id();
        let identity = ProcfsIdentityResolver::for_process_tree(pid)
            .resolve(pid)
            .expect("resolve current process");

        assert!(identity.executable.path.is_absolute());
        assert!(identity.executable.digest.is_some());
    }

    #[test]
    #[ignore = "subprocess fixture for executable identity tests"]
    fn identity_helper_process() {
        let mut stdout = std::io::stdout();
        std::io::Write::write_all(&mut stdout, IDENTITY_HELPER_READY.as_bytes())
            .expect("signal helper readiness");
        std::io::Write::flush(&mut stdout).expect("flush helper readiness");

        // Stay alive until the parent closes stdin or ChildGuard terminates us.
        let _ = std::io::Read::read(&mut std::io::stdin(), &mut [0_u8]);
    }

    /// Spawns `identity_helper_process` with optional extra argv entries and
    /// waits for its readiness signal. Only the spawn itself reports errors:
    /// callers decide how to react (the long-cmdline test skips on E2BIG).
    fn spawn_identity_helper(extra_args: &[String]) -> std::io::Result<ChildGuard> {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "tests::identity_helper_process"])
            .args(extra_args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()?;
        let mut child_stdout = std::io::BufReader::new(child.stdout.take().expect("child stdout"));
        let mut line = String::new();
        // Wait until the helper has entered the test before taking the
        // fail-closed procfs snapshot of the newly spawned process.
        loop {
            line.clear();
            let bytes_read = std::io::BufRead::read_line(&mut child_stdout, &mut line)
                .expect("read child readiness");
            assert_ne!(bytes_read, 0, "child exited before signaling readiness");
            if line == IDENTITY_HELPER_READY {
                break;
            }
        }
        Ok(ChildGuard(child))
    }

    #[test]
    fn resolves_child_and_hashes_ancestor_chain() {
        let parent_pid = std::process::id();
        let child = spawn_identity_helper(&[]).expect("spawn child");

        let identity = ProcfsIdentityResolver::for_process_tree(parent_pid)
            .resolve(child.0.id())
            .expect("resolve child identity");

        assert!(identity.executable.path.is_absolute());
        assert!(identity.executable.digest.is_some());
        let parent = identity.ancestors.last().expect("process-tree root");
        assert_eq!(parent.path, std::env::current_exe().unwrap());
        assert!(parent.digest.is_some());
    }

    #[test]
    fn executable_is_hashed_once_per_resolution() {
        let pid = std::process::id();
        let (snapshot, mut executable) = open_process_snapshot(pid).unwrap();
        let cache = Mutex::new(HashMap::new());
        let mut pending = HashMap::new();

        let hashed =
            resolve_open_executable(&snapshot, &mut executable, &cache, &mut pending).unwrap();
        assert_eq!(pending.len(), 1);

        // A sentinel proves a pending digest is reused instead of rehashed.
        let sentinel: Sha256Digest = "ab".repeat(32).parse().unwrap();
        assert_ne!(hashed.digest, Some(sentinel));
        pending.insert(snapshot.executable_cache_key(), sentinel);
        let reused =
            resolve_open_executable(&snapshot, &mut executable, &cache, &mut pending).unwrap();
        assert_eq!(reused.digest, Some(sentinel));
        assert!(cache.lock().unwrap().is_empty());
    }

    #[test]
    fn hash_executable_matches_one_shot_sha256_over_the_same_file() {
        let current_exe = std::env::current_exe().unwrap();
        let mut executable = std::fs::File::open(&current_exe).unwrap();

        let streamed = hash_executable(std::process::id(), &mut executable).unwrap();
        let one_shot = openshell_crypto::sha256(&std::fs::read(&current_exe).unwrap()).unwrap();

        assert_eq!(streamed.as_bytes(), &one_shot);
    }

    #[test]
    fn cache_executable_digest_evicts_one_entry_at_capacity() {
        let sentinel: Sha256Digest = "ab".repeat(32).parse().unwrap();
        let cache = Mutex::new(HashMap::new());
        for index in 0..EXECUTABLE_DIGEST_CACHE_CAPACITY as u64 {
            cache_executable_digest(&cache, synthetic_cache_key(index), sentinel);
        }
        assert_eq!(
            cache.lock().unwrap().len(),
            EXECUTABLE_DIGEST_CACHE_CAPACITY
        );

        let newest_key = synthetic_cache_key(EXECUTABLE_DIGEST_CACHE_CAPACITY as u64);
        let newest_sentinel: Sha256Digest = "cd".repeat(32).parse().unwrap();
        cache_executable_digest(&cache, newest_key, newest_sentinel);

        // Crossing the capacity evicts exactly one entry, not the whole cache.
        // Which entry drops is arbitrary, so only the size and the newest
        // mapping are asserted.
        let cache = cache.lock().unwrap();
        assert_eq!(cache.len(), EXECUTABLE_DIGEST_CACHE_CAPACITY);
        assert_eq!(cache.get(&newest_key), Some(&newest_sentinel));
    }

    #[test]
    fn process_tree_root_does_not_escape_into_host_ancestry() {
        let pid = std::process::id();
        let identity = ProcfsIdentityResolver::for_process_tree(pid)
            .resolve(pid)
            .expect("resolve process-tree root");

        assert!(identity.ancestors.is_empty());
    }

    fn synthetic_cache_key(index: u64) -> ExecutableCacheKey {
        ExecutableCacheKey {
            device: 1,
            inode: index,
            size: 1,
            mtime: 0,
            mtime_nsec: 0,
            ctime: 0,
            ctime_nsec: 0,
        }
    }

    #[test]
    fn resolves_child_with_cmdline_beyond_the_read_limit() {
        // The kernel caps a single argument at a size that already reaches
        // the whole-cmdline cap, so one oversized argument fails spawn with
        // E2BIG before the child ever runs. The cmdline is instead pushed
        // past CMDLINE_READ_LIMIT with several arguments that each stay under
        // the per-argument limit. Separately, the whole argv+env list is
        // capped at RLIMIT_STACK/4, so a host with a small stack limit can
        // still reject the filler list with E2BIG; that skips the test
        // instead of failing it.
        let filler = "x".repeat(64 * 1024);
        let fillers = [filler.clone(), filler.clone(), filler];
        let parent_pid = std::process::id();
        let child = match spawn_identity_helper(&fillers) {
            Ok(child) => child,
            Err(error) if error.kind() == std::io::ErrorKind::ArgumentListTooLong => {
                eprintln!(
                    "skipping: host argv+env limit (RLIMIT_STACK/4) too small for the filler arguments"
                );
                return;
            }
            Err(error) => panic!("spawn child: {error}"),
        };

        let identity = ProcfsIdentityResolver::for_process_tree(parent_pid)
            .resolve(child.0.id())
            .expect("resolve child identity");
        assert!(identity.executable.digest.is_some());

        let cmdline = read_process_cmdline(child.0.id()).expect("read capped cmdline");
        assert!(cmdline.len() <= CMDLINE_READ_LIMIT);
        // The capped cmdline ends on an argument boundary, not mid-argument.
        assert_eq!(cmdline.last(), Some(&0));
        // Every surviving filler argument is complete: the argv prefix
        // (executable path plus harness flags) is far below one filler, so
        // the cut lands inside the second filler and only the first one,
        // which ends before the cap, survives whole.
        let complete_fillers = cmdline
            .split(|byte| *byte == 0)
            .filter(|argument| !argument.is_empty() && argument.iter().all(|byte| *byte == b'x'))
            .count();
        assert_eq!(complete_fillers, 1);
    }

    #[test]
    fn cap_cmdline_keeps_cmdline_at_the_limit_whole() {
        let mut buffer = b"/bin/one\0".to_vec();
        buffer.extend(vec![b'a'; CMDLINE_READ_LIMIT - buffer.len() - 1]);
        buffer.push(0);
        assert_eq!(buffer.len(), CMDLINE_READ_LIMIT);

        assert_eq!(cap_cmdline(buffer.clone()), buffer);
    }

    #[test]
    fn cap_cmdline_truncates_over_limit_cmdline_and_drops_last_argument() {
        let mut buffer = b"/bin/one\0".to_vec();
        buffer.extend(vec![b'a'; CMDLINE_READ_LIMIT - buffer.len() - 1]);
        buffer.push(0);
        buffer.push(b'x');
        assert_eq!(buffer.len(), CMDLINE_READ_LIMIT + 1);

        assert_eq!(cap_cmdline(buffer), b"/bin/one\0");
    }

    #[test]
    fn cap_cmdline_drops_argument_terminated_at_the_cut_point() {
        // The NUL terminating the second argument is the last byte of the
        // cut region: the argument is complete, but the cap deliberately
        // drops it rather than recover boundary-case arguments.
        let mut buffer = b"/bin/one\0".to_vec();
        buffer.extend(vec![b'a'; CMDLINE_READ_LIMIT - buffer.len() - 1]);
        buffer.push(0);
        buffer.extend(b"/bin/two\0");
        assert!(buffer.len() > CMDLINE_READ_LIMIT);

        assert_eq!(cap_cmdline(buffer), b"/bin/one\0");
    }

    #[test]
    fn cap_cmdline_drops_sole_argument_over_the_limit_entirely() {
        let buffer = vec![b'a'; CMDLINE_READ_LIMIT + 1];

        assert_eq!(cap_cmdline(buffer), Vec::<u8>::new());
    }

    #[test]
    fn cap_cmdline_passes_short_cmdlines_through() {
        let without_trailing_nul = b"/bin/one\0/bin/two".to_vec();
        assert_eq!(
            cap_cmdline(without_trailing_nul.clone()),
            without_trailing_nul
        );

        assert_eq!(cap_cmdline(Vec::new()), Vec::<u8>::new());
    }

    #[test]
    fn read_process_cmdline_maps_a_missing_process_to_a_read_error() {
        // u32::MAX - 1 is beyond the kernel PID ceiling, so reading
        // /proc/<pid>/cmdline fails. The message prefix must match what
        // std::fs::read produced, since the string reaches identity-source
        // denial paths downstream.
        let pid = u32::MAX - 1;
        match read_process_cmdline(pid) {
            Err(ResolveError::Failed(message)) => {
                let expected = format!("read /proc/{pid}/cmdline: ");
                assert!(
                    message.starts_with(&expected),
                    "unexpected error message: {message}"
                );
            }
            other => panic!("expected a failed cmdline read, got {other:?}"),
        }
    }

    #[test]
    fn parse_process_status_reads_ppid_and_innermost_nspid() {
        let status = "Name:\tbash\nUmask:\t0022\nState:\tS\nPPid:\t1234\n\
                      NSpid:\t5678\t9\n";
        let parsed = parse_process_status(status);
        assert_eq!(parsed.ppid, Some(1234));
        // The last NSpid field is the innermost namespace PID.
        assert_eq!(parsed.innermost_nspid, Some(9));
    }

    #[test]
    fn parse_process_status_keeps_a_zero_ppid_distinct_from_a_missing_one() {
        // Some(0) vs None is load-bearing: the ancestry walk's `parent > 0`
        // termination filter relies on a present-but-zero PPid being Some.
        let parsed = parse_process_status("Name:\tkthreadd\nPPid:\t0\nNSpid:\t2\n");
        assert_eq!(parsed.ppid, Some(0));
        assert_eq!(parsed.innermost_nspid, Some(2));
    }

    #[test]
    fn parse_process_status_reports_missing_fields_as_none() {
        let parsed = parse_process_status("Name:\tbash\nState:\tS\n");
        assert_eq!(parsed.ppid, None);
        assert_eq!(parsed.innermost_nspid, None);
    }

    #[test]
    fn parse_process_status_reports_garbage_as_none() {
        let parsed = parse_process_status("");
        assert_eq!(parsed.ppid, None);
        assert_eq!(parsed.innermost_nspid, None);

        let parsed = parse_process_status("PPid:\tnot-a-pid\nNSpid:\talso not pids\n");
        assert_eq!(parsed.ppid, None);
        assert_eq!(parsed.innermost_nspid, None);
    }

    #[test]
    fn read_process_status_returns_none_for_a_missing_process() {
        // u32::MAX - 1 is beyond the kernel PID ceiling, so the status file
        // cannot be read and the namespace walk terminates on this hop.
        // parse_process_status alone never yields None: only the failed read
        // does, which keeps a garbage status distinct from an absent one.
        assert_eq!(read_process_status(u32::MAX - 1), None);
    }

    #[test]
    fn collect_cmdline_paths_preserves_order_and_deduplicates() {
        let own = b"/own/exe\0/usr/bin/dupe\0relative\0".to_vec();
        let ancestors = [
            b"/anc/one\0/usr/bin/dupe\0".to_vec(),
            b"/anc/one\0/anc/two\0".to_vec(),
        ];
        let excluded_paths = vec![std::path::PathBuf::from("/own/exe")];

        let paths =
            collect_cmdline_paths(&own, ancestors.iter().map(Vec::as_slice), &excluded_paths);

        let expected = [
            std::path::PathBuf::from("/usr/bin/dupe"),
            std::path::PathBuf::from("/anc/one"),
            std::path::PathBuf::from("/anc/two"),
        ];
        assert_eq!(paths, expected);
    }
}
