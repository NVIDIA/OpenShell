// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Edge authentication token storage.
//!
//! Stores the bearer token for edge-authenticated gateways at
//! `$XDG_CONFIG_HOME/openshell/gateways/<name>/edge_token`.
//! The token is a plain-text JWT string with `0600` permissions.

use crate::paths::gateways_dir;
use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_core::paths::{ensure_parent_dir_restricted, set_file_owner_only};
use std::path::PathBuf;

/// Path to the stored edge auth token for a gateway.
pub fn edge_token_path(gateway_name: &str) -> Result<PathBuf> {
    Ok(gateways_dir()?.join(gateway_name).join("edge_token"))
}

/// Legacy path used before the rename to `edge_token`.
fn legacy_token_path(gateway_name: &str) -> Result<PathBuf> {
    Ok(gateways_dir()?.join(gateway_name).join("cf_token"))
}

/// Store an edge authentication token for a gateway.
pub fn store_edge_token(gateway_name: &str, token: &str) -> Result<()> {
    let path = edge_token_path(gateway_name)?;
    ensure_parent_dir_restricted(&path)?;
    std::fs::write(&path, token)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write edge token to {}", path.display()))?;
    // Restrict permissions to owner-only (0600).
    set_file_owner_only(&path)?;
    Ok(())
}

/// Load a stored edge authentication token for a gateway.
///
/// Returns `None` if no token file exists or the file is empty.
/// Falls back to the legacy `cf_token` path for backwards compatibility.
/// When loading from the legacy path, migrates the token to the new path
/// with proper permissions.
pub fn load_edge_token(gateway_name: &str) -> Option<String> {
    // Try the new path first.
    if let Some(path) = edge_token_path(gateway_name).ok().filter(|p| p.exists()) {
        let contents = std::fs::read_to_string(&path).ok()?;
        let token = contents.trim().to_string();
        if !token.is_empty() {
            return Some(token);
        }
    }

    // Fall back to the legacy cf_token path.
    let legacy_path = legacy_token_path(gateway_name)
        .ok()
        .filter(|p| p.exists())?;
    let contents = std::fs::read_to_string(&legacy_path).ok()?;
    let token = contents.trim().to_string();
    if token.is_empty() {
        return None;
    }

    // Migrate: write to new path with proper permissions, then remove legacy.
    if store_edge_token(gateway_name, &token).is_ok() {
        let _ = std::fs::remove_file(&legacy_path);
    }

    Some(token)
}

/// Remove a stored edge authentication token.
pub fn remove_edge_token(gateway_name: &str) -> Result<()> {
    // Remove both new and legacy paths.
    for path in [
        edge_token_path(gateway_name)?,
        legacy_token_path(gateway_name)?,
    ] {
        if path.exists() {
            std::fs::remove_file(&path)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to remove {}", path.display()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: hold the shared XDG test lock, set `XDG_CONFIG_HOME` to a
    /// tempdir, run `f`, then restore the original value.
    #[allow(unsafe_code)]
    fn with_tmp_xdg<F: FnOnce()>(tmp: &std::path::Path, f: F) {
        let _guard = crate::XDG_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let orig = std::env::var("XDG_CONFIG_HOME").ok();
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", tmp);
        }
        f();
        unsafe {
            match orig {
                Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
        }
    }

    #[test]
    fn store_and_load_edge_token_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        with_tmp_xdg(tmp.path(), || {
            store_edge_token("test-gateway", "eyJhbGciOiJSUzI1NiJ9.test.sig").unwrap();
            assert_eq!(
                load_edge_token("test-gateway"),
                Some("eyJhbGciOiJSUzI1NiJ9.test.sig".to_string())
            );
        });
    }

    #[test]
    fn load_edge_token_returns_none_when_not_set() {
        let tmp = tempfile::tempdir().unwrap();
        with_tmp_xdg(tmp.path(), || {
            assert_eq!(load_edge_token("no-such-gateway"), None);
        });
    }

    #[test]
    fn store_edge_token_overwrites_previous() {
        let tmp = tempfile::tempdir().unwrap();
        with_tmp_xdg(tmp.path(), || {
            store_edge_token("c1", "token-1").unwrap();
            store_edge_token("c1", "token-2").unwrap();
            assert_eq!(load_edge_token("c1"), Some("token-2".to_string()));
        });
    }

    #[test]
    fn remove_edge_token_deletes_file() {
        let tmp = tempfile::tempdir().unwrap();
        with_tmp_xdg(tmp.path(), || {
            store_edge_token("c2", "token").unwrap();
            assert!(load_edge_token("c2").is_some());
            remove_edge_token("c2").unwrap();
            assert_eq!(load_edge_token("c2"), None);
        });
    }

    #[test]
    fn remove_edge_token_noop_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        with_tmp_xdg(tmp.path(), || {
            // Should not error when file doesn't exist.
            remove_edge_token("nonexistent").unwrap();
        });
    }

    #[test]
    fn load_edge_token_trims_whitespace() {
        let tmp = tempfile::tempdir().unwrap();
        with_tmp_xdg(tmp.path(), || {
            // Write manually with whitespace.
            let path = edge_token_path("ws-gateway").unwrap();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "  my-token \n").unwrap();
            assert_eq!(load_edge_token("ws-gateway"), Some("my-token".to_string()));
        });
    }

    #[test]
    fn load_edge_token_returns_none_for_empty_file() {
        let tmp = tempfile::tempdir().unwrap();
        with_tmp_xdg(tmp.path(), || {
            let path = edge_token_path("empty-gateway").unwrap();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "   \n").unwrap();
            assert_eq!(load_edge_token("empty-gateway"), None);
        });
    }

    #[test]
    fn load_edge_token_falls_back_to_legacy_cf_token() {
        let tmp = tempfile::tempdir().unwrap();
        with_tmp_xdg(tmp.path(), || {
            // Write to the legacy cf_token path.
            let path = legacy_token_path("legacy-gateway").unwrap();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "legacy-jwt").unwrap();
            assert_eq!(
                load_edge_token("legacy-gateway"),
                Some("legacy-jwt".to_string())
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn store_edge_token_sets_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        with_tmp_xdg(tmp.path(), || {
            store_edge_token("perm-test", "secret").unwrap();
            let path = edge_token_path("perm-test").unwrap();
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "expected 0600 permissions, got {mode:04o}");
        });
    }
}
