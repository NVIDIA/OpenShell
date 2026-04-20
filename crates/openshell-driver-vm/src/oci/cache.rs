// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! On-disk content-addressed cache for OCI artifacts and built RO fs images.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::metadata::{LaunchMetadata, Platform};

/// Directory layout for the OCI cache.
///
/// ```text
/// <root>/
///   blobs/sha256/<digest>          raw manifest/config/layer bytes
///   fs/<digest>.<platform>.squashfs  RO base image
///   meta/<digest>.<platform>.json    launch metadata
///   tmp/                              atomic-write staging
/// ```
#[derive(Debug, Clone)]
pub struct CacheLayout {
    root: PathBuf,
}

impl CacheLayout {
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn blob_path(&self, digest: &str) -> PathBuf {
        let (algo, hex) = split_digest(digest);
        self.root.join("blobs").join(algo).join(hex)
    }

    #[must_use]
    pub fn fs_image_path(&self, manifest_digest: &str, platform: Platform) -> PathBuf {
        let hex = strip_algo(manifest_digest);
        self.root
            .join("fs")
            .join(format!("{hex}.{}.squashfs", platform.cache_tag()))
    }

    #[must_use]
    pub fn metadata_path(&self, manifest_digest: &str, platform: Platform) -> PathBuf {
        let hex = strip_algo(manifest_digest);
        self.root
            .join("meta")
            .join(format!("{hex}.{}.json", platform.cache_tag()))
    }

    #[must_use]
    pub fn tmp_dir(&self) -> PathBuf {
        self.root.join("tmp")
    }

    /// Create all cache subdirectories. Idempotent.
    pub fn ensure_dirs(&self) -> io::Result<()> {
        fs::create_dir_all(self.root.join("blobs/sha256"))?;
        fs::create_dir_all(self.root.join("fs"))?;
        fs::create_dir_all(self.root.join("meta"))?;
        fs::create_dir_all(self.tmp_dir())?;
        Ok(())
    }

    /// Check whether a cached fs image + metadata pair is present for this image.
    #[must_use]
    pub fn lookup(&self, manifest_digest: &str, platform: Platform) -> Option<CachedImage> {
        let fs_path = self.fs_image_path(manifest_digest, platform);
        let meta_path = self.metadata_path(manifest_digest, platform);
        if !fs_path.is_file() || !meta_path.is_file() {
            return None;
        }
        let metadata_json = fs::read_to_string(&meta_path).ok()?;
        let metadata: CachedMetadata = serde_json::from_str(&metadata_json).ok()?;
        Some(CachedImage {
            fs_image: fs_path,
            metadata: metadata.launch,
        })
    }

    /// Atomically write launch metadata for a built image.
    pub fn write_metadata(
        &self,
        manifest_digest: &str,
        platform: Platform,
        metadata: &LaunchMetadata,
    ) -> io::Result<()> {
        self.ensure_dirs()?;
        let target = self.metadata_path(manifest_digest, platform);
        let payload = serde_json::to_vec_pretty(&CachedMetadata {
            schema: METADATA_SCHEMA_V1,
            launch: metadata.clone(),
        })
        .map_err(io::Error::other)?;
        atomic_write(&self.tmp_dir(), &target, &payload)
    }

    /// Atomically move a built fs image into its cache slot. The source path
    /// must live on the same filesystem as the cache root (callers typically
    /// build inside [`Self::tmp_dir`]).
    pub fn install_fs_image(
        &self,
        manifest_digest: &str,
        platform: Platform,
        built_image: &Path,
    ) -> io::Result<PathBuf> {
        self.ensure_dirs()?;
        let dest = self.fs_image_path(manifest_digest, platform);
        if dest.exists() {
            fs::remove_file(&dest)?;
        }
        fs::rename(built_image, &dest)?;
        Ok(dest)
    }
}

/// A cache hit with both the RO fs image path and its launch metadata.
#[derive(Debug, Clone)]
pub struct CachedImage {
    pub fs_image: PathBuf,
    pub metadata: LaunchMetadata,
}

const METADATA_SCHEMA_V1: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedMetadata {
    schema: u32,
    launch: LaunchMetadata,
}

fn split_digest(digest: &str) -> (&str, &str) {
    match digest.split_once(':') {
        Some((algo, hex)) => (algo, hex),
        None => ("sha256", digest),
    }
}

fn strip_algo(digest: &str) -> &str {
    split_digest(digest).1
}

/// Write `bytes` to `target` via a rename inside `tmp_dir`, ensuring readers
/// never see a partial file.
fn atomic_write(tmp_dir: &Path, target: &Path, bytes: &[u8]) -> io::Result<()> {
    fs::create_dir_all(tmp_dir)?;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    let file_name = target
        .file_name()
        .ok_or_else(|| io::Error::other("cache target has no file name"))?;
    let staging = tmp_dir.join(format!(
        "{}.{}.tmp",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    fs::write(&staging, bytes)?;
    fs::rename(&staging, target)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn sample_metadata() -> LaunchMetadata {
        LaunchMetadata {
            argv: vec!["/bin/sh".to_string(), "-c".to_string(), "true".to_string()],
            env: vec![("A".to_string(), "1".to_string())],
            workdir: "/sandbox".to_string(),
            labels: BTreeMap::new(),
            stop_signal: String::new(),
        }
    }

    #[test]
    fn digest_with_algo_splits_into_blob_path() {
        let layout = CacheLayout::new(PathBuf::from("/cache"));
        let path = layout.blob_path("sha256:abc123");
        assert_eq!(path, PathBuf::from("/cache/blobs/sha256/abc123"));
    }

    #[test]
    fn digest_without_algo_defaults_to_sha256() {
        let layout = CacheLayout::new(PathBuf::from("/cache"));
        let path = layout.blob_path("abc123");
        assert_eq!(path, PathBuf::from("/cache/blobs/sha256/abc123"));
    }

    #[test]
    fn fs_and_metadata_paths_include_platform_tag() {
        let layout = CacheLayout::new(PathBuf::from("/cache"));
        assert_eq!(
            layout.fs_image_path("sha256:deadbeef", Platform::LinuxAmd64),
            PathBuf::from("/cache/fs/deadbeef.amd64.squashfs")
        );
        assert_eq!(
            layout.metadata_path("sha256:deadbeef", Platform::LinuxArm64),
            PathBuf::from("/cache/meta/deadbeef.arm64.json")
        );
    }

    #[test]
    fn lookup_returns_none_when_either_file_is_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = CacheLayout::new(tmp.path().to_path_buf());
        layout.ensure_dirs().unwrap();
        assert!(layout.lookup("sha256:abc", Platform::LinuxAmd64).is_none());

        // write metadata but no fs image
        layout
            .write_metadata("sha256:abc", Platform::LinuxAmd64, &sample_metadata())
            .unwrap();
        assert!(layout.lookup("sha256:abc", Platform::LinuxAmd64).is_none());
    }

    #[test]
    fn lookup_returns_paired_fs_image_and_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = CacheLayout::new(tmp.path().to_path_buf());
        layout.ensure_dirs().unwrap();

        // Seed the fs image slot with a placeholder file.
        let fs_slot = layout.fs_image_path("sha256:abc", Platform::LinuxAmd64);
        fs::create_dir_all(fs_slot.parent().unwrap()).unwrap();
        fs::write(&fs_slot, b"stub").unwrap();

        layout
            .write_metadata("sha256:abc", Platform::LinuxAmd64, &sample_metadata())
            .unwrap();

        let hit = layout
            .lookup("sha256:abc", Platform::LinuxAmd64)
            .expect("expected cache hit");
        assert_eq!(hit.fs_image, fs_slot);
        assert_eq!(hit.metadata.argv, sample_metadata().argv);
    }

    #[test]
    fn write_metadata_is_atomic_under_repeat_writes() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = CacheLayout::new(tmp.path().to_path_buf());
        layout
            .write_metadata("sha256:abc", Platform::LinuxAmd64, &sample_metadata())
            .unwrap();

        let mut updated = sample_metadata();
        updated.argv.push("extra".to_string());
        layout
            .write_metadata("sha256:abc", Platform::LinuxAmd64, &updated)
            .unwrap();

        let hit = layout.lookup("sha256:abc", Platform::LinuxAmd64);
        // no fs image, so lookup returns None; re-read the metadata directly.
        assert!(hit.is_none());
        let raw =
            fs::read_to_string(layout.metadata_path("sha256:abc", Platform::LinuxAmd64)).unwrap();
        assert!(raw.contains("extra"));
    }

    #[test]
    fn install_fs_image_moves_built_image_into_slot() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = CacheLayout::new(tmp.path().to_path_buf());
        layout.ensure_dirs().unwrap();
        let built = layout.tmp_dir().join("built.squashfs");
        fs::write(&built, b"squashed").unwrap();

        let slot = layout
            .install_fs_image("sha256:xyz", Platform::LinuxAmd64, &built)
            .unwrap();
        assert!(slot.is_file());
        assert!(!built.exists(), "source should be renamed, not copied");
        assert_eq!(fs::read(&slot).unwrap(), b"squashed");
    }
}
