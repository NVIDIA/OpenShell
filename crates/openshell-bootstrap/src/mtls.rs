// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::paths::user_gateway_dir;
use crate::pki::PkiBundle;
use miette::{IntoDiagnostic, Result};
use openshell_core::paths::{create_dir_restricted, set_file_owner_only};
use std::path::PathBuf;

/// Store the PKI bundle's client materials (ca.crt, tls.crt, tls.key) to the
/// local filesystem so the CLI can use them for mTLS connections.
///
/// Files are written atomically: temp dir -> validate -> rename over target.
/// Directories are created with `0o700` and `tls.key` is set to `0o600`.
pub fn store_pki_bundle(name: &str, bundle: &PkiBundle) -> Result<()> {
    let dir = cli_mtls_dir(name)?;
    let temp_dir = cli_mtls_temp_dir(name)?;
    let backup_dir = cli_mtls_backup_dir(name)?;

    if temp_dir.exists() {
        std::fs::remove_dir_all(&temp_dir)
            .into_diagnostic()
            .map_err(|e| e.wrap_err(format!("failed to remove {}", temp_dir.display())))?;
    }

    // Create the temp dir with restricted permissions so the private key
    // is never world-readable, even momentarily.
    create_dir_restricted(&temp_dir)?;

    std::fs::write(temp_dir.join("ca.crt"), &bundle.ca_cert_pem)
        .into_diagnostic()
        .map_err(|e| e.wrap_err("failed to write ca.crt"))?;
    std::fs::write(temp_dir.join("tls.crt"), &bundle.client_cert_pem)
        .into_diagnostic()
        .map_err(|e| e.wrap_err("failed to write tls.crt"))?;
    std::fs::write(temp_dir.join("tls.key"), &bundle.client_key_pem)
        .into_diagnostic()
        .map_err(|e| e.wrap_err("failed to write tls.key"))?;

    // Restrict the private key to owner-only.
    set_file_owner_only(&temp_dir.join("tls.key"))?;

    validate_cli_mtls_bundle_dir(&temp_dir)?;

    let had_backup = if dir.exists() {
        if backup_dir.exists() {
            std::fs::remove_dir_all(&backup_dir)
                .into_diagnostic()
                .map_err(|e| e.wrap_err(format!("failed to remove {}", backup_dir.display())))?;
        }
        std::fs::rename(&dir, &backup_dir)
            .into_diagnostic()
            .map_err(|e| e.wrap_err(format!("failed to rename {}", dir.display())))?;
        true
    } else {
        false
    };

    if let Err(err) = std::fs::rename(&temp_dir, &dir)
        .into_diagnostic()
        .map_err(|e| e.wrap_err(format!("failed to move {}", temp_dir.display())))
    {
        if had_backup {
            let _ = std::fs::rename(&backup_dir, &dir);
        }
        return Err(err);
    }

    // Ensure the final directory also has restricted permissions after rename.
    create_dir_restricted(&dir)?;

    if had_backup {
        std::fs::remove_dir_all(&backup_dir)
            .into_diagnostic()
            .map_err(|e| e.wrap_err(format!("failed to remove {}", backup_dir.display())))?;
    }
    Ok(())
}

fn cli_mtls_dir(name: &str) -> Result<PathBuf> {
    Ok(user_gateway_dir(name)?.join("mtls"))
}

fn cli_mtls_temp_dir(name: &str) -> Result<PathBuf> {
    Ok(cli_mtls_dir(name)?.with_extension("tmp"))
}

fn cli_mtls_backup_dir(name: &str) -> Result<PathBuf> {
    Ok(cli_mtls_dir(name)?.with_extension("bak"))
}

fn validate_cli_mtls_bundle_dir(dir: &std::path::Path) -> Result<()> {
    for name in ["ca.crt", "tls.crt", "tls.key"] {
        let path = dir.join(name);
        let metadata = std::fs::metadata(&path)
            .into_diagnostic()
            .map_err(|e| e.wrap_err(format!("failed to read {}", path.display())))?;
        if metadata.len() == 0 {
            return Err(miette::miette!("{} is empty", path.display()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn store_pki_bundle_rejects_multi_component_gateway_names() {
        let tmp = tempfile::tempdir().unwrap();
        with_tmp_xdg(tmp.path(), || {
            let bundle = PkiBundle {
                ca_cert_pem: "ca".to_string(),
                ca_key_pem: "cakey".to_string(),
                server_cert_pem: "server".to_string(),
                server_key_pem: "serverkey".to_string(),
                client_cert_pem: "client".to_string(),
                client_key_pem: "clientkey".to_string(),
                jwt_signing_key_pem: "signing".to_string(),
                jwt_public_key_pem: "public".to_string(),
                jwt_key_id: "kid".to_string(),
            };
            assert!(store_pki_bundle("../escape", &bundle).is_err());
        });
    }
}
