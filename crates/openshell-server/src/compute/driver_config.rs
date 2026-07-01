// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Selected compute-driver config construction.
//!
//! This module owns loading the selected driver config from TOML, applying
//! driver-specific environment overrides, and applying gateway startup defaults.
//! It does not acquire, connect to, or start compute drivers.

use crate::config_file;
use crate::defaults::LocalTlsPaths;
use openshell_core::{ComputeDriverKind, Error, Result};
use openshell_driver_docker::DockerComputeConfig;
use openshell_driver_kubernetes::KubernetesComputeConfig;
use openshell_driver_podman::PodmanComputeConfig;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;

use super::VmComputeConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestTlsPaths {
    ca: PathBuf,
    cert: PathBuf,
    key: PathBuf,
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

/// Build the selected Kubernetes config from TOML plus runtime defaults.
pub fn kubernetes_config_from_context(
    context: DriverStartupContext<'_>,
) -> Result<KubernetesComputeConfig> {
    let mut cfg = driver_config_from_context(context, ComputeDriverKind::Kubernetes.as_str())?;
    apply_kubernetes_runtime_defaults(&mut cfg);
    Ok(cfg)
}

pub fn kubernetes_config_for_k8s_sa_bootstrap(
    file: Option<&config_file::ConfigFile>,
) -> Result<KubernetesComputeConfig> {
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
    driver_config_from_file(Some(file), ComputeDriverKind::Kubernetes.as_str())
}

/// Build the selected Podman config from TOML plus runtime defaults.
pub fn podman_config_from_context(
    context: DriverStartupContext<'_>,
) -> Result<PodmanComputeConfig> {
    let mut podman = driver_config_from_context(context, ComputeDriverKind::Podman.as_str())?;
    apply_podman_runtime_defaults(&mut podman, context);
    Ok(podman)
}

/// Build the selected Docker config from TOML plus runtime defaults.
pub fn docker_config_from_context(
    context: DriverStartupContext<'_>,
) -> Result<DockerComputeConfig> {
    let mut cfg = driver_config_from_context(context, ComputeDriverKind::Docker.as_str())?;
    apply_docker_runtime_defaults(&mut cfg, context);
    Ok(cfg)
}

/// Build the selected VM config from TOML plus runtime defaults.
pub fn vm_config_from_context(context: DriverStartupContext<'_>) -> Result<VmComputeConfig> {
    let mut cfg = driver_config_from_context(context, ComputeDriverKind::Vm.as_str())?;
    apply_vm_runtime_defaults(&mut cfg, context);
    Ok(cfg)
}

pub fn remote_driver_config_from_context(
    context: DriverStartupContext<'_>,
    name: &str,
) -> Result<RemoteDriverConfig> {
    let mut cfg = driver_config_from_context(context, name)?;
    apply_remote_driver_overrides(&mut cfg, context, name);
    validate_remote_driver_config(&cfg, name)?;
    Ok(cfg)
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemoteDriverConfig {
    #[serde(default)]
    pub socket_path: PathBuf,
}

fn driver_config_from_context<T>(context: DriverStartupContext<'_>, driver_name: &str) -> Result<T>
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

fn apply_kubernetes_runtime_defaults(k8s: &mut KubernetesComputeConfig) {
    if let Ok(size) = std::env::var("OPENSHELL_K8S_WORKSPACE_DEFAULT_STORAGE_SIZE") {
        k8s.workspace_default_storage_size = size;
    }
}

fn apply_podman_runtime_defaults(
    podman: &mut PodmanComputeConfig,
    context: DriverStartupContext<'_>,
) {
    podman.gateway_port = context.gateway_port;
    apply_podman_env_overrides(podman);
    apply_guest_tls_defaults_to_split_fields(
        &mut podman.guest_tls_ca,
        &mut podman.guest_tls_cert,
        &mut podman.guest_tls_key,
        context.guest_tls,
    );
}

fn apply_docker_runtime_defaults(cfg: &mut DockerComputeConfig, context: DriverStartupContext<'_>) {
    apply_guest_tls_defaults_to_split_fields(
        &mut cfg.guest_tls_ca,
        &mut cfg.guest_tls_cert,
        &mut cfg.guest_tls_key,
        context.guest_tls,
    );
}

fn apply_vm_runtime_defaults(cfg: &mut VmComputeConfig, context: DriverStartupContext<'_>) {
    if cfg.state_dir.as_os_str().is_empty() {
        cfg.state_dir = VmComputeConfig::default_state_dir();
    }
    if cfg.grpc_endpoint.trim().is_empty()
        && (!context.gateway_tls_enabled || context.guest_tls.is_some())
    {
        let scheme = if context.gateway_tls_enabled {
            "https"
        } else {
            "http"
        };
        cfg.grpc_endpoint = format!("{scheme}://127.0.0.1:{}", context.gateway_port);
    }

    apply_guest_tls_defaults_to_split_fields(
        &mut cfg.guest_tls_ca,
        &mut cfg.guest_tls_cert,
        &mut cfg.guest_tls_key,
        context.guest_tls,
    );
}

fn apply_podman_env_overrides(podman: &mut PodmanComputeConfig) {
    if let Ok(p) = std::env::var("OPENSHELL_PODMAN_SOCKET") {
        podman.socket_path = PathBuf::from(p);
    }
    if let Ok(ip) = std::env::var("OPENSHELL_PODMAN_HOST_GATEWAY_IP") {
        podman.host_gateway_ip = ip;
    }
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

fn apply_guest_tls_defaults_to_split_fields(
    ca: &mut Option<PathBuf>,
    cert: &mut Option<PathBuf>,
    key: &mut Option<PathBuf>,
    defaults: Option<&GuestTlsPaths>,
) {
    if ca.is_none()
        && cert.is_none()
        && key.is_none()
        && let Some(paths) = defaults
    {
        *ca = Some(paths.ca.clone());
        *cert = Some(paths.cert.clone());
        *key = Some(paths.key.clone());
    }
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
    fn k8s_sa_bootstrap_rejects_missing_kubernetes_driver_config() {
        let err = kubernetes_config_for_k8s_sa_bootstrap(None).unwrap_err();
        assert!(err.to_string().contains("[openshell.drivers.kubernetes]"));

        let file: config_file::ConfigFile =
            toml::from_str("[openshell.gateway]\n").expect("valid config");
        let err = kubernetes_config_for_k8s_sa_bootstrap(Some(&file)).unwrap_err();
        assert!(err.to_string().contains("[openshell.drivers.kubernetes]"));
    }

    #[test]
    fn k8s_sa_bootstrap_uses_configured_namespace_and_service_account() {
        let file: config_file::ConfigFile = toml::from_str(
            r#"
[openshell.gateway]

[openshell.drivers.kubernetes]
namespace = "sandboxes"
service_account_name = "sandbox-sa"
"#,
        )
        .expect("valid config");

        let cfg = kubernetes_config_for_k8s_sa_bootstrap(Some(&file)).unwrap();
        assert_eq!(cfg.namespace, "sandboxes");
        assert_eq!(cfg.service_account_name, "sandbox-sa");
    }

    #[test]
    fn podman_config_reads_bind_mount_opt_in_from_driver_table() {
        let file: config_file::ConfigFile = toml::from_str(
            r"
[openshell.drivers.podman]
enable_bind_mounts = true
",
        )
        .expect("valid config");

        let cfg = podman_config_from_context(test_context(Some(&file))).expect("podman config");

        assert!(cfg.enable_bind_mounts);
    }

    #[test]
    fn docker_config_reads_bind_mount_opt_in_from_driver_table() {
        let file: config_file::ConfigFile = toml::from_str(
            r"
[openshell.drivers.docker]
enable_bind_mounts = true
",
        )
        .expect("valid config");

        let cfg = docker_config_from_context(test_context(Some(&file))).expect("docker config");

        assert!(cfg.enable_bind_mounts);
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

    #[test]
    fn docker_config_reports_selected_invalid_driver_table() {
        let file: config_file::ConfigFile = toml::from_str(
            r"
[openshell.drivers.docker]
unknown_docker_key = true
",
        )
        .expect("valid config");

        let err = docker_config_from_context(test_context(Some(&file))).unwrap_err();

        assert!(
            err.to_string()
                .contains("invalid [openshell.drivers.docker] table")
        );
    }

    #[test]
    fn vm_config_reports_selected_invalid_driver_table() {
        let file: config_file::ConfigFile = toml::from_str(
            r#"
[openshell.drivers.vm]
mem_mib = "not-a-number"
"#,
        )
        .expect("valid config");

        let err = vm_config_from_context(test_context(Some(&file))).unwrap_err();

        assert!(
            err.to_string()
                .contains("invalid [openshell.drivers.vm] table")
        );
    }
}
