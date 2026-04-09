// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Embedded VM runtime resources.
//!
//! Native libraries (libkrun, libkrunfw, gvproxy) and the rootfs are embedded as
//! zstd-compressed byte arrays and extracted to XDG cache directories on first use.
//!
//! Cache locations:
//! - Runtime: `~/.local/share/openshell/vm-runtime/{version}/`
//! - Rootfs:  `~/.local/share/openshell/openshell-vm/{version}/instances/<name>/rootfs/`

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use indicatif::{ProgressBar, ProgressStyle};

use crate::VmError;

// ── Platform-specific embedded resources ───────────────────────────────────

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod resources {
    pub const LIBKRUN: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/libkrun.dylib.zst"));
    pub const LIBKRUNFW: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/libkrunfw.5.dylib.zst"));
    pub const GVPROXY: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/gvproxy.zst"));
    pub const ROOTFS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rootfs.tar.zst"));
    pub const LIBKRUN_NAME: &str = "libkrun.dylib";
    pub const LIBKRUNFW_NAME: &str = "libkrunfw.5.dylib";
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod resources {
    pub const LIBKRUN: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/libkrun.so.zst"));
    pub const LIBKRUNFW: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/libkrunfw.so.5.zst"));
    pub const GVPROXY: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/gvproxy.zst"));
    pub const ROOTFS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rootfs.tar.zst"));
    pub const LIBKRUN_NAME: &str = "libkrun.so";
    pub const LIBKRUNFW_NAME: &str = "libkrunfw.so.5";
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod resources {
    pub const LIBKRUN: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/libkrun.so.zst"));
    pub const LIBKRUNFW: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/libkrunfw.so.5.zst"));
    pub const GVPROXY: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/gvproxy.zst"));
    pub const ROOTFS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rootfs.tar.zst"));
    pub const LIBKRUN_NAME: &str = "libkrun.so";
    pub const LIBKRUNFW_NAME: &str = "libkrunfw.so.5";
}

// Fallback for unsupported platforms (will fail at runtime)
#[cfg(not(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(target_os = "linux", target_arch = "aarch64"),
    all(target_os = "linux", target_arch = "x86_64"),
)))]
mod resources {
    pub const LIBKRUN: &[u8] = &[];
    pub const LIBKRUNFW: &[u8] = &[];
    pub const GVPROXY: &[u8] = &[];
    pub const ROOTFS: &[u8] = &[];
    pub const LIBKRUN_NAME: &str = "libkrun";
    pub const LIBKRUNFW_NAME: &str = "libkrunfw";
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

// ── Public API ─────────────────────────────────────────────────────────────

/// Ensures the embedded VM runtime is extracted to the cache directory.
///
/// Returns the path to the runtime directory containing:
/// - libkrun.{dylib,so}
/// - libkrunfw.{5.dylib,.so.5}
/// - gvproxy
///
/// On first call, this extracts the compressed embedded resources to the cache.
/// Subsequent calls return the cached path if valid.
pub fn ensure_runtime_extracted() -> Result<PathBuf, VmError> {
    // Check if embedded resources are available (non-empty)
    if resources::LIBKRUN.is_empty() {
        return Err(VmError::HostSetup(
            "VM runtime not embedded for this platform. \
             Supported: macOS ARM64, Linux ARM64, Linux x86_64"
                .to_string(),
        ));
    }

    let cache_dir = runtime_cache_dir()?;
    let version_marker = cache_dir.join(".version");

    // Cache key: version + content fingerprint (so dev builds at 0.0.0
    // still invalidate when the embedded libraries change).
    let cache_key = runtime_cache_key();

    // Check if already extracted with the correct cache key
    if version_marker.exists()
        && let Ok(cached_key) = fs::read_to_string(&version_marker)
        && cached_key.trim() == cache_key
    {
        // Validate files exist
        if validate_runtime_dir(&cache_dir).is_ok() {
            tracing::debug!(
                path = %cache_dir.display(),
                "Using cached VM runtime"
            );
            return Ok(cache_dir);
        }
    }

    // Clean up old versions before extracting new one
    cleanup_old_versions(&cache_dir)?;

    // Create fresh directory
    if cache_dir.exists() {
        fs::remove_dir_all(&cache_dir)
            .map_err(|e| VmError::HostSetup(format!("remove old cache: {e}")))?;
    }
    fs::create_dir_all(&cache_dir)
        .map_err(|e| VmError::HostSetup(format!("create cache dir: {e}")))?;

    tracing::info!(
        path = %cache_dir.display(),
        version = VERSION,
        "Extracting embedded VM runtime"
    );

    // Extract all resources
    extract_resource(resources::LIBKRUN, &cache_dir.join(resources::LIBKRUN_NAME))?;
    extract_resource(
        resources::LIBKRUNFW,
        &cache_dir.join(resources::LIBKRUNFW_NAME),
    )?;
    extract_resource(resources::GVPROXY, &cache_dir.join("gvproxy"))?;

    // On macOS, libkrun.dylib references libkrunfw via @loader_path/libkrunfw.dylib
    // (the unversioned name), but we embed as libkrunfw.5.dylib. Create the
    // unversioned name so dyld can resolve the dependency.
    #[cfg(target_os = "macos")]
    {
        let unversioned = cache_dir.join("libkrunfw.dylib");
        if !unversioned.exists() {
            std::os::unix::fs::symlink(resources::LIBKRUNFW_NAME, &unversioned)
                .map_err(|e| VmError::HostSetup(format!("symlink libkrunfw.dylib: {e}")))?;
        }
    }

    // Make gvproxy executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(cache_dir.join("gvproxy"), fs::Permissions::from_mode(0o755))
            .map_err(|e| VmError::HostSetup(format!("chmod gvproxy: {e}")))?;
    }

    // Write version marker (includes content fingerprint for cache invalidation)
    fs::write(&version_marker, runtime_cache_key())
        .map_err(|e| VmError::HostSetup(format!("write version marker: {e}")))?;

    tracing::info!(
        path = %cache_dir.display(),
        "VM runtime extracted successfully"
    );

    Ok(cache_dir)
}

/// Returns the path where the runtime would be cached (without extracting).
pub fn runtime_cache_path() -> Result<PathBuf, VmError> {
    runtime_cache_dir()
}

/// Extract the embedded rootfs to the given destination directory.
///
/// If the destination already exists, it is returned as-is (no re-extraction).
/// Otherwise the embedded `rootfs.tar.zst` is decompressed and unpacked into `dest`.
///
/// A `.version` marker is written after successful extraction so that
/// version-mismatched rootfs directories are detected and rebuilt.
pub fn extract_rootfs_to(dest: &Path) -> Result<(), VmError> {
    if resources::ROOTFS.is_empty() {
        return Err(VmError::HostSetup(
            "Rootfs not embedded. Build with: mise run vm:build:embedded".to_string(),
        ));
    }

    let version_marker = dest.join(".version");

    // Already extracted with the correct version — nothing to do.
    if version_marker.exists()
        && let Ok(cached_version) = fs::read_to_string(&version_marker)
        && cached_version.trim() == VERSION
    {
        tracing::debug!(
            path = %dest.display(),
            "Using cached rootfs"
        );
        return Ok(());
    }

    // Remove existing if present (version mismatch or incomplete extraction).
    if dest.exists() {
        eprintln!("Removing outdated rootfs at {}...", dest.display());
        fs::remove_dir_all(dest)
            .map_err(|e| VmError::HostSetup(format!("remove old rootfs: {e}")))?;
    }

    // Extract with progress bar.
    extract_rootfs_with_progress(resources::ROOTFS, dest)?;

    // Write version marker.
    fs::write(&version_marker, VERSION)
        .map_err(|e| VmError::HostSetup(format!("write rootfs version marker: {e}")))?;

    Ok(())
}

/// Clean up rootfs directories from older versions.
///
/// Call this periodically (e.g. at startup) to reclaim disk from previous
/// releases. Removes all version directories under the openshell-vm base
/// except the current version.
pub fn cleanup_old_rootfs() -> Result<(), VmError> {
    let base = rootfs_cache_base()?;
    if !base.exists() {
        return Ok(());
    }

    let current_version_dir = base.join(VERSION);
    cleanup_old_versions_in_base(&base, &current_version_dir)
}

/// Check if the rootfs is embedded (non-empty).
pub fn has_embedded_rootfs() -> bool {
    !resources::ROOTFS.is_empty()
}

// ── Internal helpers ───────────────────────────────────────────────────────

/// Build a cache key that combines the version string with a short content
/// fingerprint of the embedded runtime bytes.
///
/// Using the version alone is insufficient for dev builds (all `0.0.0`)
/// because the embedded libraries can change between compiles without the
/// version changing. The fingerprint is a simple XOR-fold of the first few
/// bytes of each embedded resource — cheap to compute at startup without
/// pulling in a hash dependency.
fn runtime_cache_key() -> String {
    // XOR-fold the first 64 bytes of each resource to get a cheap fingerprint.
    let mut fp: u64 = 0;
    for (i, chunk) in [resources::LIBKRUN, resources::LIBKRUNFW, resources::GVPROXY]
        .iter()
        .enumerate()
    {
        let sample = &chunk[..chunk.len().min(64)];
        let mut word: u64 = 0;
        for (j, &b) in sample.iter().enumerate() {
            word ^= (b as u64) << ((j % 8) * 8);
        }
        // Mix in resource index so identical resources don't cancel out.
        fp ^= word.rotate_left((i as u32) * 13 + 7);
        // Also mix in the total length so size changes are detected.
        fp ^= (chunk.len() as u64).rotate_left((i as u32) * 17 + 3);
    }
    format!("{VERSION}-{fp:016x}")
}

fn runtime_cache_dir() -> Result<PathBuf, VmError> {
    let base = openshell_core::paths::xdg_data_dir()
        .map_err(|e| VmError::HostSetup(format!("resolve XDG data dir: {e}")))?;
    Ok(base.join("openshell").join("vm-runtime").join(VERSION))
}

fn runtime_cache_base() -> Result<PathBuf, VmError> {
    let base = openshell_core::paths::xdg_data_dir()
        .map_err(|e| VmError::HostSetup(format!("resolve XDG data dir: {e}")))?;
    Ok(base.join("openshell").join("vm-runtime"))
}

fn rootfs_cache_base() -> Result<PathBuf, VmError> {
    let base = openshell_core::paths::xdg_data_dir()
        .map_err(|e| VmError::HostSetup(format!("resolve XDG data dir: {e}")))?;
    Ok(base.join("openshell").join("openshell-vm"))
}

fn cleanup_old_versions(current_dir: &Path) -> Result<(), VmError> {
    cleanup_old_versions_in_base(&runtime_cache_base()?, current_dir)
}

fn cleanup_old_versions_in_base(base: &Path, current_dir: &Path) -> Result<(), VmError> {
    if !base.exists() {
        return Ok(());
    }

    let entries = match fs::read_dir(base) {
        Ok(e) => e,
        Err(_) => return Ok(()), // Can't read, skip cleanup
    };

    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        // Skip if this is the current version directory or a parent of it
        if path.is_dir() && !current_dir.starts_with(&path) && path != current_dir {
            tracing::debug!(
                path = %path.display(),
                "Cleaning up old version"
            );
            if let Err(e) = fs::remove_dir_all(&path) {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "Failed to clean up old version"
                );
            }
        }
    }

    Ok(())
}

fn extract_resource(compressed: &[u8], dest: &Path) -> Result<(), VmError> {
    if compressed.is_empty() {
        return Err(VmError::HostSetup(format!(
            "embedded resource is empty: {}",
            dest.display()
        )));
    }

    let decompressed = zstd::decode_all(compressed)
        .map_err(|e| VmError::HostSetup(format!("decompress {}: {e}", dest.display())))?;

    let mut file = fs::File::create(dest)
        .map_err(|e| VmError::HostSetup(format!("create {}: {e}", dest.display())))?;

    file.write_all(&decompressed)
        .map_err(|e| VmError::HostSetup(format!("write {}: {e}", dest.display())))?;

    tracing::debug!(
        path = %dest.display(),
        compressed_size = compressed.len(),
        decompressed_size = decompressed.len(),
        "Extracted resource"
    );

    Ok(())
}

fn extract_rootfs_with_progress(compressed: &[u8], dest: &Path) -> Result<(), VmError> {
    eprintln!("Extracting VM environment (first run)...");

    // Create progress bar for decompression
    let pb = ProgressBar::new(compressed.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("  Decompressing [{bar:40.cyan/blue}] {bytes}/{total_bytes}")
            .unwrap()
            .progress_chars("=>-"),
    );

    // Wrap the compressed data in a progress reader
    let reader = ProgressReader::new(std::io::Cursor::new(compressed), pb.clone());

    // Decompress zstd stream
    let decoder = zstd::Decoder::new(reader)
        .map_err(|e| VmError::HostSetup(format!("create zstd decoder: {e}")))?;

    pb.finish_and_clear();

    // Create destination directory
    fs::create_dir_all(dest).map_err(|e| VmError::HostSetup(format!("create rootfs dir: {e}")))?;

    // Extract tar archive with progress
    eprintln!("  Extracting rootfs...");
    let mut archive = tar::Archive::new(decoder);
    archive
        .unpack(dest)
        .map_err(|e| VmError::HostSetup(format!("extract rootfs tarball: {e}")))?;

    eprintln!("  Rootfs extracted to {}", dest.display());

    Ok(())
}

/// A reader wrapper that updates a progress bar as data is read.
struct ProgressReader<R> {
    inner: R,
    progress: ProgressBar,
}

impl<R> ProgressReader<R> {
    fn new(inner: R, progress: ProgressBar) -> Self {
        Self { inner, progress }
    }
}

impl<R: Read> Read for ProgressReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.progress.inc(n as u64);
        Ok(n)
    }
}

fn validate_runtime_dir(dir: &Path) -> Result<(), VmError> {
    let libkrun = dir.join(resources::LIBKRUN_NAME);
    let libkrunfw = dir.join(resources::LIBKRUNFW_NAME);
    let gvproxy = dir.join("gvproxy");

    for path in [&libkrun, &libkrunfw, &gvproxy] {
        if !path.exists() {
            return Err(VmError::HostSetup(format!(
                "missing runtime file: {}",
                path.display()
            )));
        }

        // Check file is not empty (would indicate a stub)
        let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        if size == 0 {
            return Err(VmError::HostSetup(format!(
                "runtime file is empty (stub): {}",
                path.display()
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resources_not_empty() {
        // On supported platforms, resources should be non-empty
        #[cfg(any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64"),
        ))]
        {
            // Note: This test only passes if `mise run vm:setup` was run
            // before building. In CI without compressed artifacts, resources will be
            // empty stubs.
            if !resources::LIBKRUN.is_empty() {
                assert!(!resources::LIBKRUNFW.is_empty());
                assert!(!resources::GVPROXY.is_empty());
            }
        }
    }
}
