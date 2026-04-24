// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OIDC token storage.
//!
//! Stores OIDC token bundles (access token, refresh token, metadata) at
//! `$XDG_CONFIG_HOME/openshell/gateways/<name>/oidc_token.json`.
//! File permissions are `0600` (owner-only).

use crate::paths::gateways_dir;
use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_core::paths::{ensure_parent_dir_restricted, set_file_owner_only};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// OIDC token bundle persisted to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcTokenBundle {
    /// `OAuth2` access token (JWT).
    pub access_token: String,

    /// `OAuth2` refresh token. `None` for `client_credentials` grants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,

    /// Unix timestamp when the access token expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,

    /// OIDC issuer URL.
    pub issuer: String,

    /// OIDC client ID used to obtain the token.
    pub client_id: String,
}

/// Path to the stored OIDC token bundle for a gateway.
pub fn oidc_token_path(gateway_name: &str) -> Result<PathBuf> {
    Ok(gateways_dir()?.join(gateway_name).join("oidc_token.json"))
}

/// Store an OIDC token bundle for a gateway.
pub fn store_oidc_token(gateway_name: &str, bundle: &OidcTokenBundle) -> Result<()> {
    let path = oidc_token_path(gateway_name)?;
    ensure_parent_dir_restricted(&path)?;
    let json = serde_json::to_string_pretty(bundle)
        .into_diagnostic()
        .wrap_err("failed to serialize OIDC token bundle")?;
    std::fs::write(&path, json)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write OIDC token to {}", path.display()))?;
    set_file_owner_only(&path)?;
    Ok(())
}

/// Load a stored OIDC token bundle for a gateway.
///
/// Returns `None` if the token file does not exist or cannot be parsed.
pub fn load_oidc_token(gateway_name: &str) -> Option<OidcTokenBundle> {
    let path = oidc_token_path(gateway_name).ok()?;
    if !path.exists() {
        return None;
    }
    let contents = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&contents).ok()
}

/// Remove a stored OIDC token.
pub fn remove_oidc_token(gateway_name: &str) -> Result<()> {
    let path = oidc_token_path(gateway_name)?;
    if path.exists() {
        std::fs::remove_file(&path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to remove {}", path.display()))?;
    }
    Ok(())
}

/// Check if the stored access token is expired or near expiry.
///
/// Returns `true` if the token expires within the next 30 seconds.
pub fn is_token_expired(bundle: &OidcTokenBundle) -> bool {
    let Some(expires_at) = bundle.expires_at else {
        // No expiry info — assume valid.
        return false;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now + 30 >= expires_at
}
