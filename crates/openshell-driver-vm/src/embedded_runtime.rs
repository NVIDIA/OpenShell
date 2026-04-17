// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Embedded libkrun runtime resources for the VM driver.

use std::fs;
use std::path::{Path, PathBuf};

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod resources {
    pub const LIBKRUN: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/libkrun.dylib.zst"));
    pub const LIBKRUNFW: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/libkrunfw.5.dylib.zst"));
    pub const GVPROXY: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/gvproxy.zst"));
    pub const LIBKRUN_NAME: &str = "libkrun.dylib";
    pub const LIBKRUNFW_NAME: &str = "libkrunfw.5.dylib";
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod resources {
    pub const LIBKRUN: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/libkrun.so.zst"));
    pub const LIBKRUNFW: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/libkrunfw.so.5.zst"));
    pub const GVPROXY: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/gvproxy.zst"));
    pub const LIBKRUN_NAME: &str = "libkrun.so";
    pub const LIBKRUNFW_NAME: &str = "libkrunfw.so.5";
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod resources {
    pub const LIBKRUN: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/libkrun.so.zst"));
    pub const LIBKRUNFW: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/libkrunfw.so.5.zst"));
    pub const GVPROXY: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/gvproxy.zst"));
    pub const LIBKRUN_NAME: &str = "libkrun.so";
    pub const LIBKRUNFW_NAME: &str = "libkrunfw.so.5";
}

#[cfg(not(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(target_os = "linux", target_arch = "aarch64"),
    all(target_os = "linux", target_arch = "x86_64"),
)))]
mod resources {
    pub const LIBKRUN: &[u8] = &[];
    pub const LIBKRUNFW: &[u8] = &[];
    pub const GVPROXY: &[u8] = &[];
    pub const LIBKRUN_NAME: &str = "libkrun";
    pub const LIBKRUNFW_NAME: &str = "libkrunfw";
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn ensure_runtime_extracted() -> Result<PathBuf, String> {
    if resources::LIBKRUN.is_empty() {
        return Err(
            "VM runtime not embedded for this platform. Supported: macOS ARM64, Linux ARM64, Linux x86_64"
                .to_string(),
        );
    }

    let cache_dir = runtime_cache_dir()?;
    let version_marker = cache_dir.join(".version");
    let cache_key = runtime_cache_key();

    if version_marker.exists()
        && let Ok(cached_key) = fs::read_to_string(&version_marker)
        && cached_key.trim() == cache_key
        && validate_runtime_dir(&cache_dir).is_ok()
    {
        return Ok(cache_dir);
    }

    cleanup_old_versions(&cache_dir)?;

    if cache_dir.exists() {
        fs::remove_dir_all(&cache_dir)
            .map_err(|e| format!("remove old runtime cache {}: {e}", cache_dir.display()))?;
    }
    fs::create_dir_all(&cache_dir)
        .map_err(|e| format!("create runtime cache {}: {e}", cache_dir.display()))?;

    extract_resource(resources::LIBKRUN, &cache_dir.join(resources::LIBKRUN_NAME))?;
    extract_resource(
        resources::LIBKRUNFW,
        &cache_dir.join(resources::LIBKRUNFW_NAME),
    )?;
    extract_resource(resources::GVPROXY, &cache_dir.join("gvproxy"))?;

    #[cfg(target_os = "macos")]
    {
        let unversioned = cache_dir.join("libkrunfw.dylib");
        if !unversioned.exists() {
            std::os::unix::fs::symlink(resources::LIBKRUNFW_NAME, &unversioned)
                .map_err(|e| format!("symlink {}: {e}", unversioned.display()))?;
        }
    }

    fs::write(&version_marker, cache_key)
        .map_err(|e| format!("write runtime marker {}: {e}", version_marker.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(cache_dir.join("gvproxy"), fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod gvproxy: {e}"))?;
    }

    Ok(cache_dir)
}

pub fn validate_runtime_dir(dir: &Path) -> Result<(), String> {
    let libkrun = dir.join(resources::LIBKRUN_NAME);
    let libkrunfw = dir.join(resources::LIBKRUNFW_NAME);
    let gvproxy = dir.join("gvproxy");

    for path in [&libkrun, &libkrunfw, &gvproxy] {
        if !path.is_file() {
            return Err(format!("missing runtime file: {}", path.display()));
        }
        let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        if size == 0 {
            return Err(format!("runtime file is empty (stub): {}", path.display()));
        }
    }

    Ok(())
}

fn runtime_cache_key() -> String {
    let mut fp: u64 = 0;
    for (index, chunk) in [resources::LIBKRUN, resources::LIBKRUNFW]
        .into_iter()
        .chain(std::iter::once(resources::GVPROXY))
        .enumerate()
    {
        let sample = &chunk[..chunk.len().min(64)];
        let mut word: u64 = 0;
        for (offset, byte) in sample.iter().enumerate() {
            word ^= (*byte as u64) << ((offset % 8) * 8);
        }
        fp ^= word.rotate_left((index as u32) * 13 + 7);
        fp ^= (chunk.len() as u64).rotate_left((index as u32) * 17 + 3);
    }
    format!("{VERSION}-{fp:016x}")
}

fn runtime_cache_dir() -> Result<PathBuf, String> {
    let base =
        openshell_core::paths::xdg_data_dir().map_err(|e| format!("resolve XDG data dir: {e}"))?;
    Ok(base.join("openshell").join("vm-runtime").join(VERSION))
}

fn runtime_cache_base() -> Result<PathBuf, String> {
    let base =
        openshell_core::paths::xdg_data_dir().map_err(|e| format!("resolve XDG data dir: {e}"))?;
    Ok(base.join("openshell").join("vm-runtime"))
}

fn cleanup_old_versions(current_dir: &Path) -> Result<(), String> {
    let base = runtime_cache_base()?;
    if !base.exists() {
        return Ok(());
    }

    let entries = fs::read_dir(&base).map_err(|e| format!("read {}: {e}", base.display()))?;
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() && !current_dir.starts_with(&path) && path != current_dir {
            let _ = fs::remove_dir_all(&path);
        }
    }
    Ok(())
}

fn extract_resource(compressed: &[u8], dest: &Path) -> Result<(), String> {
    if compressed.is_empty() {
        return Err(format!("embedded resource is empty: {}", dest.display()));
    }

    let decompressed =
        zstd::decode_all(compressed).map_err(|e| format!("decompress {}: {e}", dest.display()))?;
    fs::write(dest, decompressed).map_err(|e| format!("write {}: {e}", dest.display()))
}
