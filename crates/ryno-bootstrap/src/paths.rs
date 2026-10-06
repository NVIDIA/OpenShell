// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use miette::Result;
use ryno_core::paths::ryno_config_dir;
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

/// Env var pointing at a system-level `Ryno` config root override.
///
/// Set by installers (snap, deb, systemd unit, dev wrappers) that want
/// to surface deployment-provided gateways without requiring the user to
/// register them. The directory uses the same layout as the per-user config
/// root: `active_gateway` plus `gateways/<name>/metadata.json`. CLI behaviour
/// treats it as read-only; all writes go to the per-user XDG location, which
/// shadows system entries on name collision. When unset, `Ryno` falls
/// back to `/etc/ryno`.
pub const SYSTEM_GATEWAY_DIR_ENV: &str = "RYNO_SYSTEM_GATEWAY_DIR";

/// Legacy override honored for one release cycle after the `OpenShell` ->
/// `Ryno` rename. Removed together with the other rename shims.
const LEGACY_SYSTEM_GATEWAY_DIR_ENV: &str = "OPENSHELL_SYSTEM_GATEWAY_DIR";

const DEFAULT_SYSTEM_CONFIG_DIR: &str = "/etc/ryno";
/// Legacy system config root, used as a read-only fallback for one release
/// cycle when `/etc/ryno` does not exist.
const LEGACY_SYSTEM_CONFIG_DIR: &str = "/etc/openshell";

fn system_config_dir_override() -> Option<PathBuf> {
    if let Some(path) = validated_override(SYSTEM_GATEWAY_DIR_ENV) {
        return Some(path);
    }
    if std::env::var_os(LEGACY_SYSTEM_GATEWAY_DIR_ENV).is_some() {
        tracing::warn!(
            env = LEGACY_SYSTEM_GATEWAY_DIR_ENV,
            "legacy override is deprecated; use {SYSTEM_GATEWAY_DIR_ENV}"
        );
    }
    validated_override(LEGACY_SYSTEM_GATEWAY_DIR_ENV)
}

fn validated_override(env: &str) -> Option<PathBuf> {
    let path = PathBuf::from(std::env::var_os(env)?);
    if path.as_os_str().is_empty() {
        tracing::warn!(env, "ignoring empty system gateway dir override");
        return None;
    }
    if !path.is_absolute() {
        tracing::warn!(
            env,
            path = %path.display(),
            "ignoring relative system gateway dir override"
        );
        return None;
    }
    Some(path)
}

pub fn validated_gateway_name(name: &str) -> Result<&str> {
    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(component)), None) if component == OsStr::new(name) => Ok(name),
        _ => Err(miette::miette!(
            "invalid gateway name '{name}': expected a single path component"
        )),
    }
}

pub fn user_gateway_dir(name: &str) -> Result<PathBuf> {
    Ok(user_gateways_dir()?.join(validated_gateway_name(name)?))
}

pub fn system_gateway_dir(name: &str) -> Result<PathBuf> {
    Ok(system_gateways_dir().join(validated_gateway_name(name)?))
}

/// Path to the file that stores the active gateway name.
///
/// Location: `$XDG_CONFIG_HOME/ryno/active_gateway`
pub fn user_active_gateway_path() -> Result<PathBuf> {
    Ok(ryno_config_dir()?.join("active_gateway"))
}

/// Base directory for all gateway metadata files.
///
/// Location: `$XDG_CONFIG_HOME/ryno/gateways/`
pub fn user_gateways_dir() -> Result<PathBuf> {
    Ok(ryno_config_dir()?.join("gateways"))
}

/// Read-only system-level `Ryno` config root.
///
/// Uses `RYNO_SYSTEM_GATEWAY_DIR` when set (legacy
/// `OPENSHELL_SYSTEM_GATEWAY_DIR` when the new variable is unset); otherwise
/// falls back to `/etc/ryno`, or to the legacy `/etc/openshell` when the new
/// directory does not exist yet.
pub fn system_config_dir() -> PathBuf {
    if let Some(dir) = system_config_dir_override() {
        return dir;
    }
    let current = PathBuf::from(DEFAULT_SYSTEM_CONFIG_DIR);
    if current.exists() {
        return current;
    }
    let legacy = PathBuf::from(LEGACY_SYSTEM_CONFIG_DIR);
    if legacy.exists() {
        tracing::warn!(
            path = %legacy.display(),
            "using legacy system config dir; migrate to /etc/ryno"
        );
        return legacy;
    }
    current
}

/// Read-only system-level gateway metadata directory.
pub fn system_gateways_dir() -> PathBuf {
    system_config_dir().join("gateways")
}

/// Optional system-level active gateway file within the system config root.
pub fn system_active_gateway_path() -> PathBuf {
    system_config_dir().join("active_gateway")
}

/// Path to the file that stores the last-used sandbox name for a gateway.
///
/// Location: `$XDG_CONFIG_HOME/ryno/gateways/<gateway>/last_sandbox`
pub fn last_sandbox_path(gateway: &str) -> Result<PathBuf> {
    Ok(user_gateway_dir(gateway)?.join("last_sandbox"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(unsafe_code)]
    fn system_config_dir_defaults_to_etc_ryno() {
        let _guard = crate::XDG_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let orig_sys = std::env::var(SYSTEM_GATEWAY_DIR_ENV).ok();
        unsafe {
            std::env::remove_var(SYSTEM_GATEWAY_DIR_ENV);
        }
        assert_eq!(system_config_dir(), PathBuf::from("/etc/ryno"));
        assert_eq!(system_gateways_dir(), PathBuf::from("/etc/ryno/gateways"));
        assert_eq!(
            system_active_gateway_path(),
            PathBuf::from("/etc/ryno/active_gateway")
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
        let override_dir = tmp.path().join("ryno-system");
        let orig_sys = std::env::var(SYSTEM_GATEWAY_DIR_ENV).ok();
        unsafe {
            std::env::set_var(SYSTEM_GATEWAY_DIR_ENV, &override_dir);
        }
        assert_eq!(system_config_dir(), override_dir);
        assert_eq!(
            system_gateways_dir(),
            tmp.path().join("ryno-system/gateways")
        );
        assert_eq!(
            system_active_gateway_path(),
            tmp.path().join("ryno-system/active_gateway")
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
    fn system_config_dir_ignores_empty_env_override() {
        let _guard = crate::XDG_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let orig_sys = std::env::var(SYSTEM_GATEWAY_DIR_ENV).ok();
        unsafe {
            std::env::set_var(SYSTEM_GATEWAY_DIR_ENV, "");
        }
        assert_eq!(system_config_dir(), PathBuf::from("/etc/ryno"));
        unsafe {
            match orig_sys {
                Some(v) => std::env::set_var(SYSTEM_GATEWAY_DIR_ENV, v),
                None => std::env::remove_var(SYSTEM_GATEWAY_DIR_ENV),
            }
        }
    }

    #[test]
    #[allow(unsafe_code)]
    fn system_config_dir_ignores_relative_env_override() {
        let _guard = crate::XDG_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let orig_sys = std::env::var(SYSTEM_GATEWAY_DIR_ENV).ok();
        unsafe {
            std::env::set_var(SYSTEM_GATEWAY_DIR_ENV, "relative/ryno-system");
        }
        assert_eq!(system_config_dir(), PathBuf::from("/etc/ryno"));
        unsafe {
            match orig_sys {
                Some(v) => std::env::set_var(SYSTEM_GATEWAY_DIR_ENV, v),
                None => std::env::remove_var(SYSTEM_GATEWAY_DIR_ENV),
            }
        }
    }

    #[test]
    #[allow(unsafe_code)]
    fn user_gateway_dir_layout() {
        let _guard = crate::XDG_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().unwrap();
        let orig = std::env::var("XDG_CONFIG_HOME").ok();
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", tmp.path());
        }
        assert_eq!(
            user_gateway_dir("my-gateway").unwrap(),
            tmp.path().join("ryno/gateways/my-gateway")
        );
        unsafe {
            match orig {
                Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
        }
    }

    #[test]
    #[allow(unsafe_code)]
    fn user_gateway_dir_rejects_multi_component_gateway_names() {
        let _guard = crate::XDG_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().unwrap();
        let orig = std::env::var("XDG_CONFIG_HOME").ok();
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", tmp.path());
        }
        let err = user_gateway_dir("../escape").unwrap_err();
        assert!(err.to_string().contains("single path component"));
        unsafe {
            match orig {
                Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
        }
    }

    #[test]
    #[allow(unsafe_code)]
    fn system_gateway_dir_layout() {
        let _guard = crate::XDG_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().unwrap();
        let override_dir = tmp.path().join("ryno-system");
        let orig_sys = std::env::var(SYSTEM_GATEWAY_DIR_ENV).ok();
        unsafe {
            std::env::set_var(SYSTEM_GATEWAY_DIR_ENV, &override_dir);
        }
        assert_eq!(
            system_gateway_dir("my-gateway").unwrap(),
            override_dir.join("gateways/my-gateway")
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
    fn system_gateway_dir_rejects_multi_component_gateway_names() {
        let _guard = crate::XDG_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().unwrap();
        let override_dir = tmp.path().join("ryno-system");
        let orig_sys = std::env::var(SYSTEM_GATEWAY_DIR_ENV).ok();
        unsafe {
            std::env::set_var(SYSTEM_GATEWAY_DIR_ENV, &override_dir);
        }
        let err = system_gateway_dir("../escape").unwrap_err();
        assert!(err.to_string().contains("single path component"));
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
            path.ends_with("ryno/gateways/my-gateway/last_sandbox"),
            "unexpected path: {path:?}"
        );
        unsafe {
            match orig {
                Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
        }
    }

    #[allow(unsafe_code)]
    #[test]
    fn last_sandbox_path_rejects_multi_component_gateway_names() {
        let _guard = crate::XDG_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().unwrap();
        let orig = std::env::var("XDG_CONFIG_HOME").ok();
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", tmp.path());
        }
        let err = last_sandbox_path("../escape").unwrap_err();
        assert!(err.to_string().contains("single path component"));
        unsafe {
            match orig {
                Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
        }
    }

    #[test]
    #[allow(unsafe_code)]
    fn system_config_dir_prefers_new_override_over_legacy() {
        let _guard = crate::XDG_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().unwrap();
        let new_dir = tmp.path().join("new-system");
        let legacy_dir = tmp.path().join("legacy-system");
        let orig_new = std::env::var(SYSTEM_GATEWAY_DIR_ENV).ok();
        let orig_legacy = std::env::var(LEGACY_SYSTEM_GATEWAY_DIR_ENV).ok();
        unsafe {
            std::env::set_var(SYSTEM_GATEWAY_DIR_ENV, &new_dir);
            std::env::set_var(LEGACY_SYSTEM_GATEWAY_DIR_ENV, &legacy_dir);
        }
        assert_eq!(system_config_dir(), new_dir);
        unsafe {
            match orig_new {
                Some(v) => std::env::set_var(SYSTEM_GATEWAY_DIR_ENV, v),
                None => std::env::remove_var(SYSTEM_GATEWAY_DIR_ENV),
            }
            match orig_legacy {
                Some(v) => std::env::set_var(LEGACY_SYSTEM_GATEWAY_DIR_ENV, v),
                None => std::env::remove_var(LEGACY_SYSTEM_GATEWAY_DIR_ENV),
            }
        }
    }

    #[test]
    #[allow(unsafe_code)]
    fn system_config_dir_falls_back_to_legacy_override() {
        let _guard = crate::XDG_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().unwrap();
        let legacy_dir = tmp.path().join("legacy-system");
        let orig_new = std::env::var(SYSTEM_GATEWAY_DIR_ENV).ok();
        let orig_legacy = std::env::var(LEGACY_SYSTEM_GATEWAY_DIR_ENV).ok();
        unsafe {
            std::env::remove_var(SYSTEM_GATEWAY_DIR_ENV);
            std::env::set_var(LEGACY_SYSTEM_GATEWAY_DIR_ENV, &legacy_dir);
        }
        assert_eq!(system_config_dir(), legacy_dir);
        unsafe {
            match orig_new {
                Some(v) => std::env::set_var(SYSTEM_GATEWAY_DIR_ENV, v),
                None => std::env::remove_var(SYSTEM_GATEWAY_DIR_ENV),
            }
            match orig_legacy {
                Some(v) => std::env::set_var(LEGACY_SYSTEM_GATEWAY_DIR_ENV, v),
                None => std::env::remove_var(LEGACY_SYSTEM_GATEWAY_DIR_ENV),
            }
        }
    }

    #[test]
    #[allow(unsafe_code)]
    fn apply_legacy_env_bridges_unset_variables() {
        let _guard = crate::XDG_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let orig_new = std::env::var("RYNO_TEST_BRIDGE_PROBE").ok();
        let orig_legacy = std::env::var("OPENSHELL_TEST_BRIDGE_PROBE").ok();
        unsafe {
            std::env::remove_var("RYNO_TEST_BRIDGE_PROBE");
            std::env::set_var("OPENSHELL_TEST_BRIDGE_PROBE", "bridged");
        }
        ryno_core::compat::apply_legacy_env();
        assert_eq!(
            std::env::var("RYNO_TEST_BRIDGE_PROBE").as_deref(),
            Ok("bridged")
        );
        unsafe {
            match orig_new {
                Some(v) => std::env::set_var("RYNO_TEST_BRIDGE_PROBE", v),
                None => std::env::remove_var("RYNO_TEST_BRIDGE_PROBE"),
            }
            match orig_legacy {
                Some(v) => std::env::set_var("OPENSHELL_TEST_BRIDGE_PROBE", v),
                None => std::env::remove_var("OPENSHELL_TEST_BRIDGE_PROBE"),
            }
        }
    }

    #[test]
    #[allow(unsafe_code)]
    fn ryno_config_dir_migrates_legacy_openshell_dir() {
        let _guard = crate::XDG_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().unwrap();
        let orig = std::env::var("XDG_CONFIG_HOME").ok();
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", tmp.path());
        }
        let legacy_file = tmp.path().join("openshell/active_gateway");
        std::fs::create_dir_all(legacy_file.parent().unwrap()).unwrap();
        std::fs::write(&legacy_file, "my-gateway").unwrap();
        let dir = ryno_config_dir().unwrap();
        assert_eq!(dir, tmp.path().join("ryno"));
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("ryno/active_gateway")).unwrap(),
            "my-gateway"
        );
        assert!(
            legacy_file.exists(),
            "migration must copy, never move, the legacy directory"
        );
        unsafe {
            match orig {
                Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
        }
    }
}
