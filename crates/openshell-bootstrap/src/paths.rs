// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use miette::Result;
use openshell_core::paths::openshell_config_dir;
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

/// Env var pointing at a system-level `OpenShell` config root override.
///
/// Set by installers (snap, deb, systemd unit, dev wrappers) that want
/// to surface deployment-provided gateways without requiring the user to
/// register them. The directory uses the same layout as the per-user config
/// root: `active_gateway` plus `gateways/<name>/metadata.json`. CLI behaviour
/// treats it as read-only; all writes go to the per-user XDG location, which
/// shadows system entries on name collision. When unset, `OpenShell` falls
/// back to `/etc/openshell`.
pub const SYSTEM_GATEWAY_DIR_ENV: &str = "OPENSHELL_SYSTEM_GATEWAY_DIR";

const DEFAULT_SYSTEM_CONFIG_DIR: &str = "/etc/openshell";
fn system_config_dir_override() -> Option<PathBuf> {
    let path = PathBuf::from(std::env::var_os(SYSTEM_GATEWAY_DIR_ENV)?);
    if path.as_os_str().is_empty() {
        tracing::warn!(
            env = SYSTEM_GATEWAY_DIR_ENV,
            "ignoring empty system gateway dir override"
        );
        return None;
    }
    if !path.is_absolute() {
        tracing::warn!(
            env = SYSTEM_GATEWAY_DIR_ENV,
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
pub fn system_config_dir() -> PathBuf {
    system_config_dir_override().unwrap_or_else(|| PathBuf::from(DEFAULT_SYSTEM_CONFIG_DIR))
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
/// Location: `$XDG_CONFIG_HOME/openshell/gateways/<gateway>/last_sandbox`
pub fn last_sandbox_path(gateway: &str) -> Result<PathBuf> {
    Ok(user_gateway_dir(gateway)?.join("last_sandbox"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_environment::Environment;

    #[test]
    fn system_config_dir_defaults_to_etc_openshell() {
        Environment::new().remove(SYSTEM_GATEWAY_DIR_ENV).run(|| {
            assert_eq!(system_config_dir(), PathBuf::from("/etc/openshell"));
            assert_eq!(
                system_gateways_dir(),
                PathBuf::from("/etc/openshell/gateways")
            );
            assert_eq!(
                system_active_gateway_path(),
                PathBuf::from("/etc/openshell/active_gateway")
            );
        });
    }

    #[test]
    fn system_config_dir_prefers_env_override() {
        let tmp = tempfile::tempdir().unwrap();
        let override_dir = tmp.path().join("openshell-system");

        Environment::new()
            .set(SYSTEM_GATEWAY_DIR_ENV, &override_dir)
            .run(|| {
                let override_dir = PathBuf::from(std::env::var_os(SYSTEM_GATEWAY_DIR_ENV).unwrap());
                assert_eq!(system_config_dir(), override_dir);
                assert_eq!(system_gateways_dir(), override_dir.join("gateways"));
                assert_eq!(
                    system_active_gateway_path(),
                    override_dir.join("active_gateway")
                );
            });
    }

    #[test]
    fn system_config_dir_ignores_empty_env_override() {
        Environment::new().set(SYSTEM_GATEWAY_DIR_ENV, "").run(|| {
            assert_eq!(system_config_dir(), PathBuf::from("/etc/openshell"));
        });
    }

    #[test]
    fn system_config_dir_ignores_relative_env_override() {
        Environment::new()
            .set(SYSTEM_GATEWAY_DIR_ENV, "relative/openshell-system")
            .run(|| {
                assert_eq!(system_config_dir(), PathBuf::from("/etc/openshell"));
            });
    }

    #[test]
    fn user_gateway_dir_layout() {
        let tmp = tempfile::tempdir().unwrap();

        Environment::new()
            .set("XDG_CONFIG_HOME", tmp.path())
            .run(|| {
                let tmp = PathBuf::from(std::env::var_os("XDG_CONFIG_HOME").unwrap());
                assert_eq!(
                    user_gateway_dir("my-gateway").unwrap(),
                    tmp.join("openshell/gateways/my-gateway")
                );
            });
    }

    #[test]
    fn user_gateway_dir_rejects_multi_component_gateway_names() {
        let tmp = tempfile::tempdir().unwrap();

        Environment::new()
            .set("XDG_CONFIG_HOME", tmp.path())
            .run(|| {
                let err = user_gateway_dir("../escape").unwrap_err();
                assert!(err.to_string().contains("single path component"));
            });
    }

    #[test]
    fn system_gateway_dir_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let override_dir = tmp.path().join("openshell-system");

        Environment::new()
            .set(SYSTEM_GATEWAY_DIR_ENV, &override_dir)
            .run(|| {
                let override_dir = PathBuf::from(std::env::var_os(SYSTEM_GATEWAY_DIR_ENV).unwrap());
                assert_eq!(
                    system_gateway_dir("my-gateway").unwrap(),
                    override_dir.join("gateways/my-gateway")
                );
            });
    }

    #[test]
    fn system_gateway_dir_rejects_multi_component_gateway_names() {
        let tmp = tempfile::tempdir().unwrap();
        let override_dir = tmp.path().join("openshell-system");

        Environment::new()
            .set(SYSTEM_GATEWAY_DIR_ENV, &override_dir)
            .run(|| {
                let err = system_gateway_dir("../escape").unwrap_err();
                assert!(err.to_string().contains("single path component"));
            });
    }

    #[test]
    fn last_sandbox_path_layout() {
        let tmp = tempfile::tempdir().unwrap();

        Environment::new()
            .set("XDG_CONFIG_HOME", tmp.path())
            .run(|| {
                let path = last_sandbox_path("my-gateway").unwrap();
                assert!(
                    path.ends_with("openshell/gateways/my-gateway/last_sandbox"),
                    "unexpected path: {path:?}"
                );
            });
    }

    #[test]
    fn last_sandbox_path_rejects_multi_component_gateway_names() {
        let tmp = tempfile::tempdir().unwrap();

        Environment::new()
            .set("XDG_CONFIG_HOME", tmp.path())
            .run(|| {
                let err = last_sandbox_path("../escape").unwrap_err();
                assert!(err.to_string().contains("single path component"));
            });
    }
}
