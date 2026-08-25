// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Selected compute-driver config construction.
//!
//! This module owns loading the selected driver config from TOML, applying
//! driver-specific environment overrides, and applying gateway startup defaults.
//! It does not acquire, connect to, or start compute drivers.

#[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
pub mod builtin;

use crate::config_file;
use crate::defaults::LocalTlsPaths;
use openshell_core::{Error, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestTlsPaths {
    ca: PathBuf,
    cert: PathBuf,
    key: PathBuf,
}

impl GuestTlsPaths {
    pub(crate) fn as_paths(&self) -> (&std::path::Path, &std::path::Path, &std::path::Path) {
        (&self.ca, &self.cert, &self.key)
    }
}

impl From<&LocalTlsPaths> for GuestTlsPaths {
    fn from(paths: &LocalTlsPaths) -> Self {
        Self {
            ca: paths.ca.clone(),
            cert: paths.client_cert.clone(),
            key: paths.client_key.clone(),
        }
    }
}

#[derive(Clone, Copy)]
pub struct DriverStartupContext<'a> {
    pub file: Option<&'a config_file::ConfigFile>,
    pub guest_tls: Option<&'a GuestTlsPaths>,
    pub gateway_port: u16,
    pub gateway_tls_enabled: bool,
    pub endpoint_overrides: &'a BTreeMap<String, PathBuf>,
}

pub fn remote_driver_config_from_context(
    context: DriverStartupContext<'_>,
    name: &str,
) -> Result<RemoteDriverConfig> {
    let mut cfg = RemoteDriverConfig::default();
    if let Some(file) = context.file {
        let merged = config_file::driver_table(
            name,
            &file.openshell.gateway,
            file.openshell.drivers.get(name),
        );
        if let Some(socket_path) = merged.get("socket_path").and_then(toml::Value::as_str) {
            cfg.socket_path = PathBuf::from(socket_path);
        }
    }
    apply_remote_driver_overrides(&mut cfg, context, name);
    validate_remote_driver_config(&cfg, name)?;
    Ok(cfg)
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct RemoteDriverConfig {
    #[serde(default)]
    pub socket_path: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct KubernetesSaBootstrapConfig {
    pub namespace: String,
    pub service_account_name: String,
    pub workspace_mode: String,
    pub gateway_id: String,
}

impl Default for KubernetesSaBootstrapConfig {
    fn default() -> Self {
        Self {
            namespace: "openshell".to_string(),
            service_account_name: "default".to_string(),
            workspace_mode: "shared".to_string(),
            gateway_id: "openshell".to_string(),
        }
    }
}

pub fn kubernetes_sa_bootstrap_config(
    file: Option<&config_file::ConfigFile>,
) -> Result<KubernetesSaBootstrapConfig> {
    let Some(file) = file else {
        return Err(Error::config(
            "K8s ServiceAccount bootstrap requires [openshell.drivers.kubernetes] when sandbox JWT issuing is enabled in-cluster",
        ));
    };
    if !file.openshell.drivers.contains_key("kubernetes") {
        return Err(Error::config(
            "K8s ServiceAccount bootstrap requires [openshell.drivers.kubernetes] when sandbox JWT issuing is enabled in-cluster",
        ));
    }
    let merged = config_file::driver_table(
        "kubernetes",
        &file.openshell.gateway,
        file.openshell.drivers.get("kubernetes"),
    );
    merged.try_into().map_err(|error| {
        Error::config(format!(
            "invalid Kubernetes ServiceAccount bootstrap config: {error}"
        ))
    })
}

pub fn driver_config_from_context<T>(
    context: DriverStartupContext<'_>,
    driver_name: &str,
) -> Result<T>
where
    T: Default + serde::de::DeserializeOwned,
{
    driver_config_from_file(context.file, driver_name)
}

fn driver_config_from_file<T>(
    file: Option<&config_file::ConfigFile>,
    driver_name: &str,
) -> Result<T>
where
    T: Default + serde::de::DeserializeOwned,
{
    let Some(file) = file else {
        return Ok(T::default());
    };
    let merged = config_file::driver_table(
        driver_name,
        &file.openshell.gateway,
        file.openshell.drivers.get(driver_name),
    );
    merged.try_into().map_err(|e| {
        Error::config(format!(
            "invalid [openshell.drivers.{driver_name}] table: {e}"
        ))
    })
}

fn apply_remote_driver_overrides(
    cfg: &mut RemoteDriverConfig,
    context: DriverStartupContext<'_>,
    name: &str,
) {
    if let Some(socket_path) = context.endpoint_overrides.get(name) {
        cfg.socket_path.clone_from(socket_path);
    }
}

fn validate_remote_driver_config(cfg: &RemoteDriverConfig, name: &str) -> Result<()> {
    if !cfg.socket_path.as_os_str().is_empty() {
        return Ok(());
    }
    Err(Error::config(format!(
        "remote compute driver '{name}' requires socket_path"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn test_context(file: Option<&config_file::ConfigFile>) -> DriverStartupContext<'_> {
        static EMPTY_ENDPOINT_OVERRIDES: std::sync::LazyLock<BTreeMap<String, PathBuf>> =
            std::sync::LazyLock::new(BTreeMap::new);
        test_context_with_endpoint_overrides(file, &EMPTY_ENDPOINT_OVERRIDES)
    }

    fn test_context_with_endpoint_overrides<'a>(
        file: Option<&'a config_file::ConfigFile>,
        endpoint_overrides: &'a BTreeMap<String, PathBuf>,
    ) -> DriverStartupContext<'a> {
        DriverStartupContext {
            file,
            guest_tls: None,
            gateway_port: openshell_core::config::DEFAULT_SERVER_PORT,
            gateway_tls_enabled: false,
            endpoint_overrides,
        }
    }

    #[test]
    fn remote_driver_config_reads_socket_path_from_named_table() {
        let file: config_file::ConfigFile = toml::from_str(
            r#"
[openshell.drivers.kyma]
socket_path = "/run/openshell/kyma.sock"
"#,
        )
        .expect("valid config");

        let cfg = remote_driver_config_from_context(test_context(Some(&file)), "kyma")
            .expect("remote config");

        assert_eq!(cfg.socket_path, PathBuf::from("/run/openshell/kyma.sock"));
    }

    #[test]
    fn remote_driver_config_ignores_in_process_driver_fields() {
        let file: config_file::ConfigFile = toml::from_str(
            r#"
[openshell.gateway]
sandbox_namespace = "sandboxes"

[openshell.drivers.kubernetes]
socket_path = "/run/openshell/kubernetes.sock"
workspace_mode = "shared"
service_account_name = "sandbox-sa"
"#,
        )
        .expect("valid config");

        let cfg = remote_driver_config_from_context(test_context(Some(&file)), "kubernetes")
            .expect("remote config");
        assert_eq!(
            cfg.socket_path,
            PathBuf::from("/run/openshell/kubernetes.sock")
        );
    }

    #[test]
    fn kubernetes_sa_bootstrap_uses_public_gateway_config() {
        let file: config_file::ConfigFile = toml::from_str(
            r#"
[openshell.gateway]
sandbox_namespace = "sandboxes"

[openshell.drivers.kubernetes]
socket_path = "/run/openshell/kubernetes.sock"
workspace_mode = "managed"
gateway_id = "gateway-a"
service_account_name = "sandbox-sa"
"#,
        )
        .expect("valid config");

        let cfg = kubernetes_sa_bootstrap_config(Some(&file)).expect("bootstrap config");
        assert_eq!(cfg.namespace, "sandboxes");
        assert_eq!(cfg.workspace_mode, "managed");
        assert_eq!(cfg.gateway_id, "gateway-a");
        assert_eq!(cfg.service_account_name, "sandbox-sa");
    }

    #[test]
    fn remote_driver_config_uses_endpoint_override_without_file() {
        let endpoint_overrides =
            BTreeMap::from([("kyma".to_string(), PathBuf::from("/tmp/kyma.sock"))]);

        let cfg = remote_driver_config_from_context(
            test_context_with_endpoint_overrides(None, &endpoint_overrides),
            "kyma",
        )
        .expect("remote config");

        assert_eq!(cfg.socket_path, PathBuf::from("/tmp/kyma.sock"));
    }

    #[test]
    fn remote_driver_config_endpoint_override_wins_over_file() {
        let file: config_file::ConfigFile = toml::from_str(
            r#"
[openshell.drivers.kyma]
socket_path = "/run/openshell/kyma.sock"
"#,
        )
        .expect("valid config");
        let endpoint_overrides =
            BTreeMap::from([("kyma".to_string(), PathBuf::from("/tmp/kyma.sock"))]);

        let cfg = remote_driver_config_from_context(
            test_context_with_endpoint_overrides(Some(&file), &endpoint_overrides),
            "kyma",
        )
        .expect("remote config");

        assert_eq!(cfg.socket_path, PathBuf::from("/tmp/kyma.sock"));
    }

    #[test]
    fn remote_driver_config_rejects_missing_socket_path() {
        let err = remote_driver_config_from_context(test_context(None), "kyma").unwrap_err();

        assert!(
            err.to_string()
                .contains("remote compute driver 'kyma' requires socket_path")
        );
    }
}
