//! SHA256 trust-on-first-use (TOFU) binary identity cache.
//!
//! On first network request from a binary, the proxy computes its SHA256 hash
//! and caches it as the "golden" hash. Subsequent requests from the same binary
//! path must match the cached hash. A mismatch indicates the binary was replaced
//! mid-sandbox and the request is denied.

use crate::procfs;
use miette::Result;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Thread-safe cache of binary SHA256 hashes for TOFU enforcement.
pub struct BinaryIdentityCache {
    hashes: Mutex<HashMap<PathBuf, String>>,
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
    /// - Subsequent calls: computes SHA256, compares with cached value.
    ///   Returns `Ok(hash)` if it matches, `Err` if the hash changed (binary tampered).
    pub fn verify_or_cache(&self, path: &Path) -> Result<String> {
        let current_hash = procfs::file_sha256(path)?;
        let mut hashes = self
            .hashes
            .lock()
            .map_err(|_| miette::miette!("Binary identity cache lock poisoned"))?;

        if let Some(cached) = hashes.get(path) {
            if *cached != current_hash {
                return Err(miette::miette!(
                    "Binary integrity violation: {} hash changed (cached: {}, current: {})",
                    path.display(),
                    cached,
                    current_hash
                ));
            }
            return Ok(current_hash);
        }

        hashes.insert(path.to_path_buf(), current_hash.clone());
        Ok(current_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

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
    fn hash_mismatch_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("binary");

        // Write initial content and cache it
        std::fs::write(&path, b"original content").unwrap();
        let cache = BinaryIdentityCache::new();
        let _hash = cache.verify_or_cache(&path).unwrap();

        // Modify the file to simulate binary replacement
        std::fs::write(&path, b"tampered content").unwrap();
        let result = cache.verify_or_cache(&path);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("integrity violation"),
            "Expected integrity violation error, got: {err}"
        );
    }
}
