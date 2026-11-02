// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Local, operator-initiated inspection and cleanup of VM root-disk caches.

#![allow(unsafe_code)]

use super::{
    IMAGE_CACHE_ROOTFS_IMAGE, IMAGE_IDENTITY_FILE, SANDBOX_REQUEST_FILE, image_cache_dir,
    image_cache_root_dir, sandboxes_root_dir, sanitize_image_identity,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const LOCK_FILE: &str = ".image-cache.lock";
const METADATA_FILE: &str = "cache-metadata.json";
pub(super) const BOOTSTRAP_IDENTITY_FILE: &str = "bootstrap-image-identity";
const MAX_METADATA_BYTES: u64 = 16 * 1024;
static METADATA_WRITE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LockMode {
    Shared,
    Exclusive,
}

pub struct CacheLease {
    _file: File,
    state_dir: PathBuf,
    mode: LockMode,
}

impl CacheLease {
    pub fn list(&self) -> io::Result<Vec<CacheEntry>> {
        list(&self.state_dir)
    }

    pub fn prune_unused(&self, dry_run: bool) -> io::Result<PruneReport> {
        if !dry_run {
            if self.mode != LockMode::Exclusive {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "prune requires an exclusive image cache lease",
                ));
            }
            refuse_live_legacy_driver(&self.state_dir)?;
        }
        prune_unused(&self.state_dir, dry_run)
    }
}

/// A shared lease covers the driver and its image workers. Prune takes the
/// exclusive lease, so it cannot remove a disk being prepared or attached.
pub fn lock_cache(state_dir: &Path, mode: LockMode) -> io::Result<CacheLease> {
    fs::create_dir_all(state_dir)?;
    let state_dir = fs::canonicalize(state_dir)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(state_dir.join(LOCK_FILE))?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("image cache lock is not a regular file"));
    }
    let operation = match mode {
        LockMode::Shared => libc::LOCK_SH,
        LockMode::Exclusive => libc::LOCK_EX,
    } | libc::LOCK_NB;
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        // SAFETY: flock receives a valid borrowed file descriptor and no pointers.
        if unsafe { libc::flock(file.as_raw_fd(), operation) } == 0 {
            return Ok(CacheLease {
                _file: file,
                state_dir,
                mode,
            });
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::WouldBlock {
            return Err(error);
        }
        if mode == LockMode::Shared || Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "image cache is busy; stop the VM gateway before pruning",
            ));
        }
        // A process starting during a read can inherit the shared descriptor
        // briefly. Wait for that transient lease before reporting a live driver.
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Older driver binaries do not hold the cache lease. Detect the default
/// gateway socket before deleting anything in a state dir they may be using.
fn refuse_live_legacy_driver(state_dir: &Path) -> io::Result<()> {
    let socket = state_dir.join("run").join("compute-driver.sock");
    match UnixStream::connect(socket) {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "VM gateway is running; stop it before pruning",
        )),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheMetadata {
    image_ref: String,
    last_used_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheEntry {
    pub id: String,
    pub image_ref: Option<String>,
    pub allocated_bytes: u64,
    pub apparent_bytes: u64,
    pub last_used_unix_ms: Option<u64>,
    pub cache_version: String,
    pub sandboxes: Vec<String>,
}

#[derive(Debug, Default)]
pub struct PruneReport {
    pub entries: Vec<CacheEntry>,
    pub allocated_bytes: u64,
}

/// Metadata is best effort: a full disk must not prevent an otherwise ready
/// sandbox from starting. It is never used to decide whether pruning is safe.
pub fn record_use(state_dir: &Path, id: &str, image_ref: &str) -> io::Result<()> {
    let dir = image_cache_dir(state_dir, id);
    require_regular_file(&dir.join(IMAGE_CACHE_ROOTFS_IMAGE))?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?;
    let metadata = CacheMetadata {
        image_ref: image_ref.to_owned(),
        last_used_unix_ms: u64::try_from(timestamp.as_millis()).map_err(io::Error::other)?,
    };
    let sequence = METADATA_WRITE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temporary = dir.join(format!(
        ".{METADATA_FILE}.{}.{sequence}.tmp",
        std::process::id()
    ));
    let destination = dir.join(METADATA_FILE);
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        serde_json::to_writer(&mut file, &metadata)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, destination)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn list(state_dir: &Path) -> io::Result<Vec<CacheEntry>> {
    let references = sandbox_references(state_dir)?;
    let root = image_cache_root_dir(state_dir);
    if !directory_exists(&root)? {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for item in fs::read_dir(root)? {
        let item = item?;
        let id = item.file_name().to_string_lossy().into_owned();
        if !id.starts_with("sandbox-") || id.contains(".staging-") {
            continue;
        }
        if !item.file_type()?.is_dir() {
            return Err(io::Error::other(format!(
                "cache entry {id} is not a directory"
            )));
        }
        let disk = item.path().join(IMAGE_CACHE_ROOTFS_IMAGE);
        let disk_metadata = match fs::symlink_metadata(&disk) {
            Ok(metadata) if metadata.is_file() => metadata,
            Ok(_) => {
                return Err(io::Error::other(format!(
                    "cache disk for {id} is not a regular file"
                )));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let metadata = read_metadata(&item.path().join(METADATA_FILE))?;
        let mut sandboxes = references.by_id.get(&id).cloned().unwrap_or_default();
        if id.starts_with("sandbox-bootstrap-") {
            sandboxes.extend(references.legacy_bootstrap.iter().cloned());
        }
        sandboxes.sort();
        sandboxes.dedup();
        entries.push(CacheEntry {
            cache_version: id
                .split_once("-openshell-")
                .map_or_else(|| "unknown".to_owned(), |(version, _)| version.to_owned()),
            id,
            image_ref: metadata.as_ref().map(|value| value.image_ref.clone()),
            allocated_bytes: disk_metadata.blocks().saturating_mul(512),
            apparent_bytes: disk_metadata.len(),
            last_used_unix_ms: metadata.map(|value| value.last_used_unix_ms),
            sandboxes,
        });
    }
    entries.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(entries)
}

/// The caller must hold an exclusive cache lease for a real prune.
fn prune_unused(state_dir: &Path, dry_run: bool) -> io::Result<PruneReport> {
    let mut report = PruneReport::default();
    for entry in list(state_dir)? {
        if !entry.sandboxes.is_empty() {
            continue;
        }
        if !dry_run {
            fs::remove_dir_all(image_cache_root_dir(state_dir).join(&entry.id))?;
        }
        report.allocated_bytes = report.allocated_bytes.saturating_add(entry.allocated_bytes);
        report.entries.push(entry);
    }
    Ok(report)
}

fn read_metadata(path: &Path) -> io::Result<Option<CacheMetadata>> {
    if !regular_file_exists(path)? {
        return Ok(None);
    }
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if file.metadata()?.len() > MAX_METADATA_BYTES {
        return Ok(None);
    }
    Ok(serde_json::from_reader(file).ok())
}

#[derive(Default)]
struct SandboxReferences {
    by_id: HashMap<String, Vec<String>>,
    legacy_bootstrap: Vec<String>,
}

fn sandbox_references(state_dir: &Path) -> io::Result<SandboxReferences> {
    let root = sandboxes_root_dir(state_dir);
    if !directory_exists(&root)? {
        return Ok(SandboxReferences::default());
    }
    let mut references: HashMap<String, Vec<String>> = HashMap::new();
    let mut legacy_bootstrap = Vec::new();
    for item in fs::read_dir(root)? {
        let item = item?;
        if !item.file_type()?.is_dir() {
            return Err(io::Error::other(
                "sandbox state contains a non-directory entry",
            ));
        }
        let sandbox_id = item.file_name().to_string_lossy().into_owned();
        let path = item.path();
        let request = path.join(SANDBOX_REQUEST_FILE);
        let image_identity = path.join(IMAGE_IDENTITY_FILE);
        let request_exists = regular_file_exists(&request)?;
        let image_exists = regular_file_exists(&image_identity)?;
        if !request_exists && !image_exists {
            continue;
        }
        if !image_exists {
            return Err(io::Error::other(format!(
                "sandbox {sandbox_id} has no image identity; cache prune is unsafe"
            )));
        }
        let image_id = read_identity(&image_identity)?;
        references
            .entry(sanitize_image_identity(&image_id))
            .or_default()
            .push(sandbox_id.clone());
        let bootstrap_path = path.join(BOOTSTRAP_IDENTITY_FILE);
        if regular_file_exists(&bootstrap_path)? {
            let bootstrap_id = read_identity(&bootstrap_path)?;
            references
                .entry(sanitize_image_identity(&bootstrap_id))
                .or_default()
                .push(sandbox_id);
        } else {
            legacy_bootstrap.push(sandbox_id);
        }
    }
    Ok(SandboxReferences {
        by_id: references,
        legacy_bootstrap,
    })
}

fn read_identity(path: &Path) -> io::Result<String> {
    if fs::metadata(path)?.len() > 1024 {
        return Err(io::Error::other("sandbox image identity is too large"));
    }
    let value = fs::read_to_string(path)?;
    let value = value.trim();
    if value.is_empty() || value.contains(['\n', '\r']) {
        return Err(io::Error::other("sandbox image identity is invalid"));
    }
    Ok(value.to_owned())
}

fn directory_exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => Ok(true),
        Ok(_) => Err(io::Error::other(format!(
            "{} is not a directory",
            path.display()
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn regular_file_exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => Err(io::Error::other(format!(
            "{} is not a regular file",
            path.display()
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn require_regular_file(path: &Path) -> io::Result<()> {
    if regular_file_exists(path)? {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("cache disk missing at {}", path.display()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn list_locked(root: &Path) -> io::Result<Vec<CacheEntry>> {
        let lease = lock_cache(root, LockMode::Shared)?;
        let entries = lease.list()?;
        drop(lease);
        Ok(entries)
    }

    fn prune_locked(root: &Path, dry_run: bool) -> io::Result<PruneReport> {
        let mode = if dry_run {
            LockMode::Shared
        } else {
            LockMode::Exclusive
        };
        lock_cache(root, mode)?.prune_unused(dry_run)
    }

    fn cache_disk(root: &Path, id: &str) {
        let dir = image_cache_root_dir(root).join(id);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(IMAGE_CACHE_ROOTFS_IMAGE), b"cached disk").unwrap();
    }

    fn sandbox(root: &Path, id: &str, image_id: Option<&str>, bootstrap_id: Option<&str>) {
        let dir = sandboxes_root_dir(root).join(id);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(SANDBOX_REQUEST_FILE), b"request").unwrap();
        if let Some(image_id) = image_id {
            fs::write(dir.join(IMAGE_IDENTITY_FILE), image_id).unwrap();
        }
        if let Some(bootstrap_id) = bootstrap_id {
            fs::write(dir.join(BOOTSTRAP_IDENTITY_FILE), bootstrap_id).unwrap();
        }
    }

    #[test]
    fn list_and_prune_preserve_kept_sandboxes() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let used = "sandbox-prepared-rootfs-ext4-umoci-v4-openshell-test-used";
        let unused = "sandbox-prepared-rootfs-ext4-umoci-v3-openshell-test-unused";
        let bootstrap = "sandbox-bootstrap-rootfs-ext4-v6-openshell-test-boot";
        for id in [used, unused, bootstrap] {
            cache_disk(root, id);
        }
        sandbox(root, "kept-stopped", Some(used), Some(bootstrap));
        record_use(root, unused, "example/agent:v1").unwrap();
        let entries = list_locked(root).unwrap();
        assert_eq!(entries.len(), 3);
        let unused_entry = entries.iter().find(|entry| entry.id == unused).unwrap();
        assert_eq!(unused_entry.image_ref.as_deref(), Some("example/agent:v1"));
        assert!(unused_entry.last_used_unix_ms.is_some());
        assert!(unused_entry.allocated_bytes > 0);
        assert_eq!(
            unused_entry.cache_version,
            "sandbox-prepared-rootfs-ext4-umoci-v3"
        );
        assert!(unused_entry.sandboxes.is_empty());
        assert_eq!(
            entries
                .iter()
                .find(|entry| entry.id == used)
                .unwrap()
                .sandboxes,
            ["kept-stopped"]
        );
        assert_eq!(
            entries
                .iter()
                .find(|entry| entry.id == bootstrap)
                .unwrap()
                .sandboxes,
            ["kept-stopped"]
        );

        let dry_run = prune_locked(root, true).unwrap();
        assert_eq!(dry_run.entries.len(), 1);
        assert!(image_cache_dir(root, unused).exists());
        let pruned = prune_locked(root, false).unwrap();
        assert_eq!(pruned.entries.len(), 1);
        assert!(!image_cache_dir(root, unused).exists());
        assert!(image_cache_dir(root, used).exists());
        assert!(image_cache_dir(root, bootstrap).exists());
    }

    #[test]
    fn legacy_sandbox_protects_all_bootstrap_disks() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let bootstrap = "sandbox-bootstrap-rootfs-ext4-v5-openshell-old";
        cache_disk(root, bootstrap);
        sandbox(root, "legacy-stopped", Some("sandbox-prepared-old"), None);
        assert_eq!(list_locked(root).unwrap()[0].sandboxes, ["legacy-stopped"]);
        assert!(prune_locked(root, false).unwrap().entries.is_empty());
    }

    #[test]
    fn incomplete_sandbox_blocks_prune() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let unused = "sandbox-prepared-rootfs-ext4-v4-openshell-unused";
        cache_disk(root, unused);
        sandbox(root, "incomplete", None, None);
        assert!(prune_locked(root, false).is_err());
        assert!(image_cache_dir(root, unused).exists());
    }

    #[test]
    fn symlinked_cache_disk_blocks_prune() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let id = "sandbox-prepared-rootfs-ext4-v4-openshell-link";
        let dir = image_cache_dir(root, id);
        fs::create_dir_all(&dir).unwrap();
        let outside = root.join("outside");
        fs::write(&outside, b"keep").unwrap();
        symlink(&outside, dir.join(IMAGE_CACHE_ROOTFS_IMAGE)).unwrap();
        assert!(prune_locked(root, false).is_err());
        assert_eq!(fs::read(outside).unwrap(), b"keep");
    }

    #[test]
    fn live_driver_lease_blocks_prune_lease() {
        let temp = tempfile::tempdir().unwrap();
        let driver = lock_cache(temp.path(), LockMode::Shared).unwrap();
        let _reader = lock_cache(temp.path(), LockMode::Shared).unwrap();
        assert_eq!(
            driver.prune_unused(false).err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            lock_cache(temp.path(), LockMode::Exclusive)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::WouldBlock
        );
    }
}
