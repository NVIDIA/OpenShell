// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use miette::Result;
use openshell_core::paths::{xdg_config_dir, xdg_data_dir};
use std::path::PathBuf;

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

/// Path to the file that stores the last-used sandbox name for a gateway.
///
/// Location: `$XDG_CONFIG_HOME/openshell/gateways/<gateway>/last_sandbox`
pub fn last_sandbox_path(gateway: &str) -> Result<PathBuf> {
    Ok(gateways_dir()?.join(gateway).join("last_sandbox"))
}

/// Base directory for openshell-vm data (without version).
///
/// Location: `$XDG_DATA_HOME/openshell/openshell-vm/`
pub fn openshell_vm_base_dir() -> Result<PathBuf> {
    Ok(xdg_data_dir()?.join("openshell").join("openshell-vm"))
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
