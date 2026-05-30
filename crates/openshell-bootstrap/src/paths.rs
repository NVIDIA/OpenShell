// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use miette::Result;
use openshell_core::paths::openshell_config_dir;
use std::path::PathBuf;

/// Env var pointing at a system-level `OpenShell` config root override.
///
/// Set by installers (snap, deb, systemd unit, dev wrappers) that want
/// to surface deployment-provided gateways without requiring the user to
/// register them. The directory uses the same layout as the per-user config
/// root: `active_gateway` plus `gateways/<name>/metadata.json`. CLI behaviour
/// treats it as read-only; all writes go to the per-user XDG location, which
/// shadows system entries on name collision. When unset, `OpenShell` falls
/// back to `/etc/openshell`.
pub(crate) const SYSTEM_GATEWAY_DIR_ENV: &str = "OPENSHELL_SYSTEM_GATEWAY_DIR";

const DEFAULT_SYSTEM_CONFIG_DIR: &str = "/etc/openshell";

/// Path to the file that stores the active gateway name.
///
/// Location: `$XDG_CONFIG_HOME/openshell/active_gateway`
pub fn user_active_gateway_path() -> Result<PathBuf> {
    Ok(openshell_config_dir()?.join("active_gateway"))
}

/// Base directory for all gateway metadata files.
///
/// Location: `$XDG_CONFIG_HOME/openshell/gateways/`
pub fn user_gateways_dir() -> Result<PathBuf> {
    Ok(openshell_config_dir()?.join("gateways"))
}

/// Read-only system-level `OpenShell` config root.
///
/// Uses `OPENSHELL_SYSTEM_GATEWAY_DIR` when set; otherwise falls back to
/// `/etc/openshell`.
pub(crate) fn system_config_dir() -> PathBuf {
    std::env::var_os(SYSTEM_GATEWAY_DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SYSTEM_CONFIG_DIR))
}

/// Read-only system-level gateway metadata directory.
pub(crate) fn system_gateways_dir() -> PathBuf {
    system_config_dir().join("gateways")
}

/// Optional system-level active gateway file within the system config root.
pub(crate) fn system_active_gateway_path() -> PathBuf {
    system_config_dir().join("active_gateway")
}

/// Path to the file that stores the last-used sandbox name for a gateway.
///
/// Location: `$XDG_CONFIG_HOME/openshell/gateways/<gateway>/last_sandbox`
pub fn last_sandbox_path(gateway: &str) -> Result<PathBuf> {
    Ok(user_gateways_dir()?.join(gateway).join("last_sandbox"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(unsafe_code)]
    fn system_config_dir_defaults_to_etc_openshell() {
        let _guard = crate::XDG_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let orig_sys = std::env::var(SYSTEM_GATEWAY_DIR_ENV).ok();
        unsafe {
            std::env::remove_var(SYSTEM_GATEWAY_DIR_ENV);
        }
        assert_eq!(system_config_dir(), PathBuf::from("/etc/openshell"));
        assert_eq!(
            system_gateways_dir(),
            PathBuf::from("/etc/openshell/gateways")
        );
        assert_eq!(
            system_active_gateway_path(),
            PathBuf::from("/etc/openshell/active_gateway")
        );
        unsafe {
            match orig_sys {
                Some(v) => std::env::set_var(SYSTEM_GATEWAY_DIR_ENV, v),
                None => std::env::remove_var(SYSTEM_GATEWAY_DIR_ENV),
            }
        }
    }

    #[test]
    #[allow(unsafe_code)]
    fn system_config_dir_prefers_env_override() {
        let _guard = crate::XDG_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().unwrap();
        let override_dir = tmp.path().join("openshell-system");
        let orig_sys = std::env::var(SYSTEM_GATEWAY_DIR_ENV).ok();
        unsafe {
            std::env::set_var(SYSTEM_GATEWAY_DIR_ENV, &override_dir);
        }
        assert_eq!(system_config_dir(), override_dir);
        assert_eq!(
            system_gateways_dir(),
            tmp.path().join("openshell-system/gateways")
        );
        assert_eq!(
            system_active_gateway_path(),
            tmp.path().join("openshell-system/active_gateway")
        );
        unsafe {
            match orig_sys {
                Some(v) => std::env::set_var(SYSTEM_GATEWAY_DIR_ENV, v),
                None => std::env::remove_var(SYSTEM_GATEWAY_DIR_ENV),
            }
        }
    }

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
