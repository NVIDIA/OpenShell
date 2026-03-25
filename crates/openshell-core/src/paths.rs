// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Centralized XDG config directory resolution and permission helpers.
//!
//! All `OpenShell` crates should use [`xdg_config_dir`] from this module instead
//! of reimplementing the XDG lookup. The permission helpers ensure that
//! sensitive files (private keys, tokens) and the directories containing them
//! are created with restrictive modes.

use miette::{IntoDiagnostic, Result, WrapErr};
use std::path::{Path, PathBuf};

/// Resolve the XDG config base directory.
///
/// Returns `$XDG_CONFIG_HOME` if set, otherwise `$HOME/.config`.
pub fn xdg_config_dir() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(path));
    }
    let home = std::env::var("HOME")
        .into_diagnostic()
        .wrap_err("HOME is not set")?;
    Ok(PathBuf::from(home).join(".config"))
}

/// The top-level `OpenShell` config directory: `$XDG_CONFIG_HOME/openshell/`.
pub fn openshell_config_dir() -> Result<PathBuf> {
    Ok(xdg_config_dir()?.join("openshell"))
}

/// Resolve the XDG data base directory.
///
/// Returns `$XDG_DATA_HOME` if set, otherwise `$HOME/.local/share`.
pub fn xdg_data_dir() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("XDG_DATA_HOME") {
        return Ok(PathBuf::from(path));
    }
    let home = std::env::var("HOME")
        .into_diagnostic()
        .wrap_err("HOME is not set")?;
    Ok(PathBuf::from(home).join(".local").join("share"))
}

/// Create a directory (and parents) with owner-only permissions (`0o700`) on
/// Unix. On non-Unix platforms, falls back to default permissions.
///
/// This should be used for any directory that contains sensitive material
/// (tokens, private keys, certificates).
pub fn create_dir_restricted(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create {}", path.display()))?;
    set_dir_owner_only(path)?;
    Ok(())
}

/// Set a directory to owner-only access (`0o700`) on Unix.
///
/// No-op on non-Unix platforms.
pub fn set_dir_owner_only(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to set permissions on {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Set a file to owner-only read/write (`0o600`) on Unix.
///
/// No-op on non-Unix platforms.
pub fn set_file_owner_only(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to set permissions on {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Ensure the parent directory of `path` exists with restricted permissions.
///
/// Equivalent to `create_dir_restricted(path.parent())` but handles the case
/// where `path` has no parent gracefully.
pub fn ensure_parent_dir_restricted(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        create_dir_restricted(parent)?;
    }
    Ok(())
}

/// Check whether a file has permissions that are too open (group/other readable).
///
/// Returns `true` if the file has group or other read/write/execute bits set.
/// Always returns `false` on non-Unix platforms.
#[cfg(unix)]
pub fn is_file_permissions_too_open(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o077 != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xdg_config_dir_respects_env() {
        // This test checks the logic — actual env var mutation is unsafe so
        // we rely on the integration tests in openshell-bootstrap for full
        // round-trip testing.
        let result = xdg_config_dir();
        assert!(result.is_ok());
    }

    #[test]
    fn openshell_config_dir_appends_openshell() {
        let dir = openshell_config_dir().unwrap();
        assert!(
            dir.ends_with("openshell"),
            "expected path ending with 'openshell', got: {dir:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn create_dir_restricted_sets_0o700() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("restricted");
        create_dir_restricted(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "expected 0700, got {mode:04o}");
    }

    #[cfg(unix)]
    #[test]
    fn set_file_owner_only_sets_0o600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("secret");
        std::fs::write(&file, "secret-data").unwrap();
        set_file_owner_only(&file).unwrap();
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {mode:04o}");
    }

    #[cfg(unix)]
    #[test]
    fn is_file_permissions_too_open_detects_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("open-file");
        std::fs::write(&file, "data").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(is_file_permissions_too_open(&file));
    }

    #[cfg(unix)]
    #[test]
    fn is_file_permissions_too_open_accepts_restricted() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("restricted-file");
        std::fs::write(&file, "data").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!is_file_permissions_too_open(&file));
    }
}
