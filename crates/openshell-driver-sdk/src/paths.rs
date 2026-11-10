// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Path utilities shared by the compute drivers: XDG state and data directory
//! resolution and permission helpers that create sensitive files and the
//! directories containing them with restrictive modes.

use miette::{IntoDiagnostic, Result, WrapErr};
use std::path::{Path, PathBuf};
/// Resolve the XDG state base directory.
///
/// Returns `$XDG_STATE_HOME` if set, otherwise `$HOME/.local/state`.
pub fn xdg_state_dir() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("XDG_STATE_HOME") {
        return Ok(PathBuf::from(path));
    }
    #[cfg(target_os = "windows")]
    if let Ok(path) = std::env::var("LOCALAPPDATA") {
        return Ok(PathBuf::from(path));
    }
    let home = std::env::var("HOME")
        .into_diagnostic()
        .wrap_err("HOME is not set")?;
    Ok(PathBuf::from(home).join(".local").join("state"))
}

/// Resolve the XDG data base directory.
///
/// Returns `$XDG_DATA_HOME` if set, otherwise `$HOME/.local/share`.
pub fn xdg_data_dir() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("XDG_DATA_HOME") {
        return Ok(PathBuf::from(path));
    }
    #[cfg(target_os = "windows")]
    if let Ok(path) = std::env::var("LOCALAPPDATA") {
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

/// Whether `path` is absolute under POSIX rules, whatever the host platform.
pub fn is_posix_absolute(path: &Path) -> bool {
    path.to_str().is_some_and(|path| path.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_posix_absolute_ignores_host_path_syntax() {
        assert!(is_posix_absolute(Path::new("/run/backend.sock")));
        assert!(is_posix_absolute(Path::new("/")));
        for path in ["", "relative", "./run", r"\run", r"C:\run", "C:/run"] {
            assert!(!is_posix_absolute(Path::new(path)), "{path}");
        }
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
}
