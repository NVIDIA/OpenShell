// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use miette::Result;
use openshell_core::paths::xdg_config_dir;
use std::path::PathBuf;
use std::sync::RwLock;

/// Env var pointing at a system-level gateway registry directory.
///
/// Set by installers (snap, deb, systemd unit, dev wrappers) that want
/// to surface deployment-provided gateways without requiring the user to
/// register them. The directory has the same layout as the per-user XDG
/// gateways directory: `<dir>/<name>/metadata.json` plus an optional
/// top-level `active_gateway` file. CLI behaviour treats it as read-only;
/// all writes go to the per-user XDG location, which shadows system
/// entries on name collision.
pub const SYSTEM_GATEWAY_DIR_ENV: &str = "OPENSHELL_SYSTEM_GATEWAY_DIR";

/// Path to the file that stores the active gateway name.
///
/// Location: `$XDG_CONFIG_HOME/openshell/active_gateway`
pub fn active_gateway_path() -> Result<PathBuf> {
    Ok(xdg_config_dir()?.join("openshell").join("active_gateway"))
}

/// Base directory for all gateway metadata files.
///
/// Location: `$XDG_CONFIG_HOME/openshell/gateways/`
pub fn gateways_dir() -> Result<PathBuf> {
    Ok(xdg_config_dir()?.join("openshell").join("gateways"))
}

/// Cached resolution of `OPENSHELL_SYSTEM_GATEWAY_DIR`.
enum CachedSystemDir {
    Uninit,
    Cached(Option<PathBuf>),
}

static CACHED_SYSTEM_GATEWAYS_DIR: RwLock<CachedSystemDir> = RwLock::new(CachedSystemDir::Uninit);

/// Optional system-level gateway directory provided by an installer.
///
/// `OPENSHELL_SYSTEM_GATEWAY_DIR` is read on the first call and cached for
/// the lifetime of the process so all callers observe a consistent value
/// even if the environment is mutated mid-run.
pub fn system_gateways_dir() -> Option<PathBuf> {
    if let CachedSystemDir::Cached(value) = &*CACHED_SYSTEM_GATEWAYS_DIR.read().unwrap() {
        return value.clone();
    }
    let mut guard = CACHED_SYSTEM_GATEWAYS_DIR.write().unwrap();
    if let CachedSystemDir::Cached(value) = &*guard {
        return value.clone();
    }
    let value = std::env::var_os(SYSTEM_GATEWAY_DIR_ENV).map(PathBuf::from);
    *guard = CachedSystemDir::Cached(value.clone());
    value
}

/// Test-only: clear the cached `system_gateways_dir` value so the next call
/// re-reads the environment. Required because the cache outlives any single
/// test in the same process.
#[cfg(test)]
pub fn reset_system_gateways_dir_cache() {
    *CACHED_SYSTEM_GATEWAYS_DIR.write().unwrap() = CachedSystemDir::Uninit;
}

/// Optional system-level "active gateway" file (sibling of the gateways dir).
pub fn system_active_gateway_path() -> Option<PathBuf> {
    system_gateways_dir().map(|d| d.join("active_gateway"))
}

/// Path to the file that stores the last-used sandbox name for a gateway.
///
/// Location: `$XDG_CONFIG_HOME/openshell/gateways/<gateway>/last_sandbox`
pub fn last_sandbox_path(gateway: &str) -> Result<PathBuf> {
    Ok(gateways_dir()?.join(gateway).join("last_sandbox"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(unsafe_code)]
    fn last_sandbox_path_layout() {
        let _guard = crate::XDG_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().unwrap();
        let orig = std::env::var("XDG_CONFIG_HOME").ok();
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", tmp.path());
        }
        let path = last_sandbox_path("my-gateway").unwrap();
        assert!(
            path.ends_with("openshell/gateways/my-gateway/last_sandbox"),
            "unexpected path: {path:?}"
        );
        unsafe {
            match orig {
                Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
        }
    }
}
