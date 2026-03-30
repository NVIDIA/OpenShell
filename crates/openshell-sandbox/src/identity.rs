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
use std::collections::HashMap;
use std::fs::Metadata;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tracing::debug;

#[derive(Clone)]
struct FileFingerprint {
    len: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
    ctime_sec: i64,
    ctime_nsec: i64,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
}

impl FileFingerprint {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            len: metadata.len(),
            mtime_sec: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime_sec: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
            #[cfg(unix)]
            dev: metadata.dev(),
            #[cfg(unix)]
            ino: metadata.ino(),
        }
    }
}

impl PartialEq for FileFingerprint {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len
            && self.mtime_sec == other.mtime_sec
            && self.mtime_nsec == other.mtime_nsec
            && self.ctime_sec == other.ctime_sec
            && self.ctime_nsec == other.ctime_nsec
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
    fingerprint: FileFingerprint,
}

/// Thread-safe cache of binary SHA256 hashes for TOFU enforcement.
pub struct BinaryIdentityCache {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    hashes: Mutex<HashMap<PathBuf, CachedBinary>>,
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
        self.verify_or_cache_with_hasher(path, procfs::file_sha256)
    }

    fn verify_or_cache_with_hasher<F>(&self, path: &Path, mut hash_file: F) -> Result<String>
    where
        F: FnMut(&Path) -> Result<String>,
    {
        let start = std::time::Instant::now();
        let metadata = std::fs::metadata(path)
            .map_err(|error| miette::miette!("Failed to stat {}: {error}", path.display()))?;
        let fingerprint = FileFingerprint::from_metadata(&metadata);

        let cached = self
            .hashes
            .lock()
            .map_err(|_| miette::miette!("Binary identity cache lock poisoned"))?
            .get(path)
            .cloned();

        if let Some(cached_binary) = &cached
            && cached_binary.fingerprint == fingerprint
        {
            debug!(
                "      verify_or_cache: {}ms CACHE HIT path={}",
                start.elapsed().as_millis(),
                path.display()
            );
            return Ok(cached_binary.hash.clone());
        }

        debug!(
            "      verify_or_cache: CACHE MISS size={} path={}",
            metadata.len(),
            path.display()
        );

        let current_hash = hash_file(path)?;

        let mut hashes = self
            .hashes
            .lock()
            .map_err(|_| miette::miette!("Binary identity cache lock poisoned"))?;

        if let Some(existing) = hashes.get(path)
            && existing.hash != current_hash
        {
            return Err(miette::miette!(
                "Binary integrity violation: {} hash changed (cached: {}, current: {})",
                path.display(),
                existing.hash,
                current_hash
            ));
        }

        hashes.insert(
            path.to_path_buf(),
            CachedBinary {
                hash: current_hash.clone(),
                fingerprint,
            },
        );

        debug!(
            "      verify_or_cache TOTAL (cold): {}ms path={}",
            start.elapsed().as_millis(),
            path.display()
        );

        Ok(current_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::procfs;
    use std::io::Write;
    use std::time::Duration;

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
            .verify_or_cache_with_hasher(tmp.path(), |path| {
                hash_calls += 1;
                procfs::file_sha256(path)
            })
            .unwrap();
        let hash2 = cache
            .verify_or_cache_with_hasher(tmp.path(), |path| {
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
            .verify_or_cache_with_hasher(tmp.path(), |path| {
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
            .verify_or_cache_with_hasher(tmp.path(), |path| {
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
            .verify_or_cache_with_hasher(&path, |path| {
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

        let result = cache.verify_or_cache_with_hasher(&path, |path| {
            hash_calls += 1;
            procfs::file_sha256(path)
        });

        assert!(result.is_err());
        assert_eq!(hash_calls, 2);
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
