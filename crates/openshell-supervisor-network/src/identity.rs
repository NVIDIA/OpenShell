// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! SHA256 trust-on-first-use (TOFU) binary identity cache.
//!
//! On first network request from a binary, the proxy computes its SHA256 hash
//! and caches it as the "golden" hash. Subsequent requests from the same binary
//! path must match the cached hash. A mismatch indicates the binary was replaced
//! mid-sandbox and the request is denied.

use crate::procfs;
use miette::Result;
use openshell_isolation_interface::contract::BinaryIdentity;
use std::collections::HashMap;
use std::fs::Metadata;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tracing::debug;

const MAX_IDENTITY_CACHE_ENTRIES: usize = 4096;

#[derive(Clone)]
struct FileFingerprint {
    len: u64,
    mtime: Option<(i64, i64)>,
    ctime: Option<(i64, i64)>,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
}

impl FileFingerprint {
    fn from_metadata(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        let (mtime, ctime) = (
            Some((metadata.mtime(), metadata.mtime_nsec())),
            Some((metadata.ctime(), metadata.ctime_nsec())),
        );
        #[cfg(not(unix))]
        let (mtime, ctime) = (
            metadata.modified().ok().and_then(system_time_parts),
            metadata.created().ok().and_then(system_time_parts),
        );
        Self {
            len: metadata.len(),
            mtime,
            ctime,
            #[cfg(unix)]
            dev: metadata.dev(),
            #[cfg(unix)]
            ino: metadata.ino(),
        }
    }
}

#[cfg(not(unix))]
fn system_time_parts(time: std::time::SystemTime) -> Option<(i64, i64)> {
    let duration = time.duration_since(std::time::UNIX_EPOCH).ok()?;
    Some((
        i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        i64::from(duration.subsec_nanos()),
    ))
}

impl PartialEq for FileFingerprint {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len
            && self.mtime.is_some()
            && other.mtime.is_some()
            && self.mtime == other.mtime
            && self.ctime.is_some()
            && other.ctime.is_some()
            && self.ctime == other.ctime
            && {
                #[cfg(unix)]
                {
                    self.dev == other.dev && self.ino == other.ino
                }
                #[cfg(not(unix))]
                {
                    true
                }
            }
    }
}

#[derive(Clone)]
struct CachedBinary {
    hash: String,
    fingerprint: Option<FileFingerprint>,
}

/// Thread-safe cache of binary SHA256 hashes for TOFU enforcement.
pub struct BinaryIdentityCache {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    hashes: Mutex<HashMap<PathBuf, CachedBinary>>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SuppliedIdentityError {
    #[error("{0}")]
    Unavailable(String),
    #[error(
        "Binary identity cache capacity exhausted (maximum {MAX_IDENTITY_CACHE_ENTRIES} pinned paths)"
    )]
    CapacityExhausted,
}

impl Default for BinaryIdentityCache {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryIdentityCache {
    pub fn new() -> Self {
        Self {
            hashes: Mutex::new(HashMap::new()),
        }
    }

    /// Verify a binary's integrity or cache its hash on first use.
    ///
    /// - First call for a given path: computes SHA256, caches it, returns the hash.
    /// - Subsequent calls: returns cached hash when file fingerprint is unchanged.
    ///   Recomputes SHA256 only when fingerprint changes.
    ///   Returns `Ok(hash)` if it matches, `Err` if the hash changed (binary tampered).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn verify_or_cache(&self, path: &Path) -> Result<String> {
        self.verify_or_cache_with_paths(path, path, procfs::file_sha256)
    }

    /// Atomically verify or pin every authorization-capable executable in a
    /// backend-supplied identity chain.
    pub(crate) fn verify_or_cache_supplied_identity(
        &self,
        identity: &BinaryIdentity,
    ) -> std::result::Result<(), SuppliedIdentityError> {
        let mut supplied = HashMap::new();
        for executable in std::iter::once(&identity.executable).chain(&identity.ancestors) {
            if executable.path.as_os_str().is_empty() || !executable.path.is_absolute() {
                return Err(SuppliedIdentityError::Unavailable(format!(
                    "Invalid executable identity path: {} must be absolute",
                    executable.path.display()
                )));
            }
            let digest = executable.digest.ok_or_else(|| {
                SuppliedIdentityError::Unavailable(format!(
                    "Invalid executable identity evidence: {} has missing digest",
                    executable.path.display()
                ))
            })?;
            if let Some(existing) = supplied.insert(executable.path.clone(), digest)
                && existing != digest
            {
                return Err(SuppliedIdentityError::Unavailable(format!(
                    "Invalid executable identity: conflicting evidence for {}",
                    executable.path.display()
                )));
            }
        }

        let mut hashes = self.hashes.lock().map_err(|_| {
            SuppliedIdentityError::Unavailable("Binary identity cache lock poisoned".to_string())
        })?;

        for (path, digest) in &supplied {
            if let Some(existing) = hashes.get(path)
                && existing.hash != digest.to_string()
            {
                return Err(SuppliedIdentityError::Unavailable(format!(
                    "Binary integrity violation: {} executable changed",
                    path.display()
                )));
            }
        }

        let new_entry_count = supplied
            .keys()
            .filter(|path| !hashes.contains_key(*path))
            .count();
        if new_entry_count > MAX_IDENTITY_CACHE_ENTRIES.saturating_sub(hashes.len()) {
            return Err(SuppliedIdentityError::CapacityExhausted);
        }

        for (path, digest) in supplied {
            hashes.entry(path).or_insert_with(|| CachedBinary {
                hash: digest.to_string(),
                fingerprint: None,
            });
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn verify_or_cache_process_exe(&self, display_path: &Path, pid: u32) -> Result<String> {
        let proc_exe = PathBuf::from(format!("/proc/{pid}/exe"));
        self.verify_or_cache_with_paths(display_path, &proc_exe, procfs::file_sha256)
    }

    fn verify_or_cache_with_paths<F>(
        &self,
        cache_path: &Path,
        access_path: &Path,
        mut hash_file: F,
    ) -> Result<String>
    where
        F: FnMut(&Path) -> Result<String>,
    {
        let start = std::time::Instant::now();
        let metadata = std::fs::metadata(access_path)
            .map_err(|error| miette::miette!("Failed to stat {}: {error}", cache_path.display()))?;
        let fingerprint = FileFingerprint::from_metadata(&metadata);

        let cached = self
            .hashes
            .lock()
            .map_err(|_| miette::miette!("Binary identity cache lock poisoned"))?
            .get(cache_path)
            .cloned();

        if let Some(cached_binary) = &cached
            && cached_binary.fingerprint.as_ref() == Some(&fingerprint)
        {
            debug!(
                "      verify_or_cache: {}ms CACHE HIT path={}",
                start.elapsed().as_millis(),
                cache_path.display()
            );
            return Ok(cached_binary.hash.clone());
        }

        debug!(
            "      verify_or_cache: CACHE MISS size={} path={}",
            metadata.len(),
            cache_path.display()
        );

        let current_hash = hash_file(access_path)?;

        let mut hashes = self
            .hashes
            .lock()
            .map_err(|_| miette::miette!("Binary identity cache lock poisoned"))?;

        if let Some(existing) = hashes.get(cache_path)
            && existing.hash != current_hash
        {
            return Err(miette::miette!(
                "Binary integrity violation: {} executable changed",
                cache_path.display()
            ));
        }

        if !hashes.contains_key(cache_path) && hashes.len() >= MAX_IDENTITY_CACHE_ENTRIES {
            return Err(miette::miette!(
                "Binary identity cache capacity exhausted (maximum {MAX_IDENTITY_CACHE_ENTRIES} pinned paths)"
            ));
        }

        hashes.insert(
            cache_path.to_path_buf(),
            CachedBinary {
                hash: current_hash.clone(),
                fingerprint: Some(fingerprint),
            },
        );

        debug!(
            "      verify_or_cache TOTAL (cold): {}ms path={}",
            start.elapsed().as_millis(),
            cache_path.display()
        );

        Ok(current_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::procfs;
    use openshell_isolation_interface::contract::{
        BinaryIdentity, ExecutableIdentity, Sha256Digest,
    };
    use std::io::Write;
    use std::time::Duration;

    fn digest(value: &str) -> Sha256Digest {
        value.repeat(32).parse().unwrap()
    }

    fn supplied_identity(
        executable_path: &str,
        executable_digest: Option<&str>,
        ancestors: &[(&str, Option<&str>)],
    ) -> BinaryIdentity {
        BinaryIdentity {
            executable: ExecutableIdentity {
                path: PathBuf::from(executable_path),
                digest: executable_digest.map(digest),
            },
            ancestors: ancestors
                .iter()
                .map(|(path, digest_value)| ExecutableIdentity {
                    path: PathBuf::from(path),
                    digest: digest_value.map(digest),
                })
                .collect(),
            cmdline_paths: Vec::new(),
        }
    }

    #[test]
    fn supplied_identity_reuses_pin_and_rejects_leaf_replacement() {
        let cache = BinaryIdentityCache::new();
        let original = supplied_identity("/sandbox/tool", Some("11"), &[]);
        let replaced = supplied_identity("/sandbox/tool", Some("22"), &[]);

        cache.verify_or_cache_supplied_identity(&original).unwrap();
        cache.verify_or_cache_supplied_identity(&original).unwrap();
        let error = cache
            .verify_or_cache_supplied_identity(&replaced)
            .unwrap_err()
            .to_string();

        assert!(error.contains("/sandbox/tool"));
        assert!(error.contains("integrity violation"));
        assert!(!error.contains(&"11".repeat(32)));
        assert!(!error.contains(&"22".repeat(32)));
    }

    #[test]
    fn supplied_identity_rejects_ancestor_replacement() {
        let cache = BinaryIdentityCache::new();
        cache
            .verify_or_cache_supplied_identity(&supplied_identity(
                "/sandbox/tool",
                Some("11"),
                &[("/sandbox/launcher", Some("22"))],
            ))
            .unwrap();

        let error = cache
            .verify_or_cache_supplied_identity(&supplied_identity(
                "/sandbox/tool",
                Some("11"),
                &[("/sandbox/launcher", Some("33"))],
            ))
            .unwrap_err()
            .to_string();

        assert!(error.contains("/sandbox/launcher"));
        assert!(!error.contains(&"22".repeat(32)));
        assert!(!error.contains(&"33".repeat(32)));
    }

    #[test]
    fn supplied_identity_rejects_missing_evidence() {
        let cache = BinaryIdentityCache::new();
        let missing_leaf = supplied_identity("/sandbox/tool", None, &[]);
        let missing_ancestor =
            supplied_identity("/sandbox/tool", Some("11"), &[("/sandbox/launcher", None)]);

        let leaf_error = cache
            .verify_or_cache_supplied_identity(&missing_leaf)
            .unwrap_err()
            .to_string();
        let ancestor_error = cache
            .verify_or_cache_supplied_identity(&missing_ancestor)
            .unwrap_err()
            .to_string();

        assert!(leaf_error.contains("/sandbox/tool"));
        assert!(leaf_error.contains("missing digest"));
        assert!(ancestor_error.contains("/sandbox/launcher"));
        assert!(ancestor_error.contains("missing digest"));
    }

    #[test]
    fn supplied_identity_rejects_non_absolute_or_empty_paths() {
        let cache = BinaryIdentityCache::new();
        for path in ["", "sandbox/tool"] {
            let error = cache
                .verify_or_cache_supplied_identity(&supplied_identity(path, Some("11"), &[]))
                .unwrap_err()
                .to_string();
            assert!(error.contains("must be absolute"));
        }
        assert!(cache.hashes.lock().unwrap().is_empty());
    }

    #[test]
    fn supplied_identity_deduplicates_matching_paths() {
        let cache = BinaryIdentityCache::new();
        let identity = supplied_identity(
            "/sandbox/tool",
            Some("11"),
            &[("/sandbox/tool", Some("11"))],
        );

        cache.verify_or_cache_supplied_identity(&identity).unwrap();

        assert_eq!(cache.hashes.lock().unwrap().len(), 1);
    }

    #[test]
    fn supplied_identity_conflicting_duplicate_is_atomic() {
        let cache = BinaryIdentityCache::new();
        let identity = supplied_identity(
            "/sandbox/tool",
            Some("11"),
            &[
                ("/sandbox/new-sibling", Some("33")),
                ("/sandbox/tool", Some("22")),
            ],
        );

        let error = cache
            .verify_or_cache_supplied_identity(&identity)
            .unwrap_err()
            .to_string();

        assert!(error.contains("/sandbox/tool"));
        assert!(error.contains("conflicting evidence"));
        assert!(cache.hashes.lock().unwrap().is_empty());
    }

    #[test]
    fn supplied_identity_conflict_with_existing_pin_is_atomic() {
        let cache = BinaryIdentityCache::new();
        cache
            .verify_or_cache_supplied_identity(&supplied_identity("/sandbox/tool", Some("11"), &[]))
            .unwrap();
        let conflicting_chain = supplied_identity(
            "/sandbox/other",
            Some("33"),
            &[("/sandbox/tool", Some("22"))],
        );

        cache
            .verify_or_cache_supplied_identity(&conflicting_chain)
            .unwrap_err();

        assert!(
            !cache
                .hashes
                .lock()
                .unwrap()
                .contains_key(Path::new("/sandbox/other"))
        );
    }

    #[test]
    fn supplied_identity_capacity_rejection_is_atomic() {
        let cache = BinaryIdentityCache::new();
        for index in 0..4095 {
            cache
                .verify_or_cache_supplied_identity(&supplied_identity(
                    &format!("/sandbox/pinned-{index}"),
                    Some("11"),
                    &[],
                ))
                .unwrap();
        }
        let overflowing_chain = supplied_identity(
            "/sandbox/new-leaf",
            Some("22"),
            &[("/sandbox/new-ancestor", Some("33"))],
        );

        let error = cache
            .verify_or_cache_supplied_identity(&overflowing_chain)
            .unwrap_err()
            .to_string();

        assert!(error.contains("capacity"));
        let hashes = cache.hashes.lock().unwrap();
        assert_eq!(hashes.len(), 4095);
        assert!(!hashes.contains_key(Path::new("/sandbox/new-leaf")));
        assert!(!hashes.contains_key(Path::new("/sandbox/new-ancestor")));
    }

    #[test]
    fn legacy_identity_observation_respects_cache_capacity() {
        let executable = tempfile::NamedTempFile::new().unwrap();
        let cache = BinaryIdentityCache::new();
        for index in 0..4096 {
            cache
                .verify_or_cache_with_paths(
                    &PathBuf::from(format!("/sandbox/pinned-{index}")),
                    executable.path(),
                    |_| Ok("11".repeat(32)),
                )
                .unwrap();
        }

        let error = cache
            .verify_or_cache_with_paths(Path::new("/sandbox/overflow"), executable.path(), |_| {
                Ok("11".repeat(32))
            })
            .unwrap_err()
            .to_string();

        assert!(error.contains("capacity"));
        assert_eq!(cache.hashes.lock().unwrap().len(), 4096);
    }

    #[test]
    fn supplied_identity_shares_pin_with_legacy_observation() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"binary content").unwrap();
        tmp.flush().unwrap();
        let path = tmp.path();
        let cache = BinaryIdentityCache::new();
        let legacy_digest = cache.verify_or_cache(path).unwrap();
        let same = BinaryIdentity {
            executable: ExecutableIdentity {
                path: path.to_path_buf(),
                digest: Some(legacy_digest.parse().unwrap()),
            },
            ancestors: Vec::new(),
            cmdline_paths: Vec::new(),
        };
        let different = supplied_identity(path.to_str().unwrap(), Some("11"), &[]);

        cache.verify_or_cache_supplied_identity(&same).unwrap();
        cache
            .verify_or_cache_supplied_identity(&different)
            .unwrap_err();
    }

    #[test]
    fn legacy_observation_validates_and_attaches_to_supplied_pin() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("binary");
        std::fs::write(&path, b"binary content").unwrap();
        let live_digest = procfs::file_sha256(&path).unwrap();
        let supplied = BinaryIdentity {
            executable: ExecutableIdentity {
                path: path.clone(),
                digest: Some(live_digest.parse().unwrap()),
            },
            ancestors: Vec::new(),
            cmdline_paths: Vec::new(),
        };
        let cache = BinaryIdentityCache::new();

        cache.verify_or_cache_supplied_identity(&supplied).unwrap();
        assert_eq!(cache.verify_or_cache(&path).unwrap(), live_digest);

        let original_mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
        std::fs::write(&path, b"replaced content").unwrap();
        let bumped_mtime = original_mtime.checked_add(Duration::from_secs(2)).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(bumped_mtime)
            .unwrap();

        cache.verify_or_cache(&path).unwrap_err();
    }

    #[test]
    fn first_call_caches_hash() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"binary content").unwrap();
        tmp.flush().unwrap();

        let cache = BinaryIdentityCache::new();
        let hash = cache.verify_or_cache(tmp.path()).unwrap();
        assert!(!hash.is_empty());
    }

    #[test]
    fn second_call_matches_cached() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"binary content").unwrap();
        tmp.flush().unwrap();

        let cache = BinaryIdentityCache::new();
        let hash1 = cache.verify_or_cache(tmp.path()).unwrap();
        let hash2 = cache.verify_or_cache(tmp.path()).unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn unchanged_fingerprint_skips_rehash() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"binary content").unwrap();
        tmp.flush().unwrap();

        let cache = BinaryIdentityCache::new();
        let mut hash_calls = 0;

        let hash1 = cache
            .verify_or_cache_with_paths(tmp.path(), tmp.path(), |path| {
                hash_calls += 1;
                procfs::file_sha256(path)
            })
            .unwrap();
        let hash2 = cache
            .verify_or_cache_with_paths(tmp.path(), tmp.path(), |path| {
                hash_calls += 1;
                procfs::file_sha256(path)
            })
            .unwrap();

        assert_eq!(hash1, hash2);
        assert_eq!(hash_calls, 1);
    }

    #[test]
    fn changed_fingerprint_triggers_rehash() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"binary content").unwrap();
        tmp.flush().unwrap();

        let cache = BinaryIdentityCache::new();
        let mut hash_calls = 0;

        let hash1 = cache
            .verify_or_cache_with_paths(tmp.path(), tmp.path(), |path| {
                hash_calls += 1;
                procfs::file_sha256(path)
            })
            .unwrap();

        let modified = std::fs::metadata(tmp.path()).unwrap().modified().unwrap();
        let bumped_modified = modified.checked_add(Duration::from_secs(2)).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(tmp.path())
            .unwrap()
            .set_modified(bumped_modified)
            .unwrap();

        let hash2 = cache
            .verify_or_cache_with_paths(tmp.path(), tmp.path(), |path| {
                hash_calls += 1;
                procfs::file_sha256(path)
            })
            .unwrap();

        assert_eq!(hash1, hash2);
        assert_eq!(hash_calls, 2);
    }

    #[test]
    fn restoring_mtime_still_detects_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("binary");
        std::fs::write(&path, b"0123456789abcdef").unwrap();

        let original_mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
        let cache = BinaryIdentityCache::new();
        let mut hash_calls = 0;

        cache
            .verify_or_cache_with_paths(&path, &path, |path| {
                hash_calls += 1;
                procfs::file_sha256(path)
            })
            .unwrap();

        std::thread::sleep(Duration::from_millis(5));
        // Use different-length content so the fingerprint's `len` field
        // always differs, regardless of filesystem timestamp resolution.
        std::fs::write(&path, b"tampered").unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(original_mtime)
            .unwrap();

        let result = cache.verify_or_cache_with_paths(&path, &path, |path| {
            hash_calls += 1;
            procfs::file_sha256(path)
        });

        assert!(result.is_err());
        assert_eq!(hash_calls, 2);
    }

    #[test]
    fn display_path_can_differ_from_access_path() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"binary content").unwrap();
        tmp.flush().unwrap();
        let display_path = Path::new("/usr/bin/python3");

        let cache = BinaryIdentityCache::new();
        let hash = cache
            .verify_or_cache_with_paths(display_path, tmp.path(), procfs::file_sha256)
            .unwrap();

        assert!(!hash.is_empty());
        assert!(
            cache
                .hashes
                .lock()
                .unwrap()
                .contains_key(Path::new("/usr/bin/python3"))
        );
    }

    #[test]
    fn hash_mismatch_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("binary");

        // Write initial content and cache it
        std::fs::write(&path, b"original content").unwrap();
        let initial_mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
        let cache = BinaryIdentityCache::new();
        let _hash = cache.verify_or_cache(&path).unwrap();

        // Modify the file to simulate binary replacement.
        // Force mtime to move forward so the fingerprint changes on filesystems
        // with coarse timestamp resolution.
        std::fs::write(&path, b"tampered content").unwrap();
        let bumped_mtime = initial_mtime.checked_add(Duration::from_secs(2)).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(bumped_mtime)
            .unwrap();

        let result = cache.verify_or_cache(&path);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("integrity violation"),
            "Expected integrity violation error, got: {err}"
        );
    }
}
