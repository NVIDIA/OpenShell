// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configuration construction for built-in compute drivers.

use super::{DriverStartupContext, GuestTlsPaths, driver_config_from_context};
use crate::compute::VmComputeConfig;
#[cfg(test)]
use crate::config_file;
use openshell_core::{ComputeDriverKind, Result};
use openshell_driver_docker::DockerComputeConfig;
use openshell_driver_kubernetes::KubernetesComputeConfig;
use openshell_driver_podman::PodmanComputeConfig;
use std::path::PathBuf;

/// Build the selected Kubernetes config from TOML plus runtime defaults.
pub fn kubernetes_config_from_context(
    context: DriverStartupContext<'_>,
) -> Result<KubernetesComputeConfig> {
    let mut cfg = driver_config_from_context(context, ComputeDriverKind::Kubernetes.as_str())?;
    apply_kubernetes_runtime_defaults(&mut cfg);
    Ok(cfg)
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

fn apply_kubernetes_runtime_defaults(k8s: &mut KubernetesComputeConfig) {
    if let Ok(size) = std::env::var("OPENSHELL_K8S_WORKSPACE_DEFAULT_STORAGE_SIZE") {
        k8s.workspace_default_storage_size = size;
    }
    if let Ok(storage_class) = std::env::var("OPENSHELL_K8S_WORKSPACE_STORAGE_CLASS") {
        k8s.workspace_storage_class = storage_class;
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

fn apply_podman_env_overrides(podman: &mut PodmanComputeConfig) {
    if let Ok(p) = std::env::var("OPENSHELL_PODMAN_SOCKET") {
        podman.socket_path = Some(PathBuf::from(p));
    }
    if let Ok(ip) = std::env::var("OPENSHELL_PODMAN_HOST_GATEWAY_IP") {
        podman.host_gateway_ip = ip;
    }
    if let Ok(mode) = std::env::var("OPENSHELL_PODMAN_USERNS") {
        podman.userns = Some(mode);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn test_context(file: Option<&config_file::ConfigFile>) -> DriverStartupContext<'_> {
        static EMPTY_ENDPOINT_OVERRIDES: std::sync::LazyLock<BTreeMap<String, PathBuf>> =
            std::sync::LazyLock::new(BTreeMap::new);
        DriverStartupContext {
            file,
            guest_tls: None,
            gateway_port: openshell_core::config::DEFAULT_SERVER_PORT,
            gateway_tls_enabled: false,
            endpoint_overrides: &EMPTY_ENDPOINT_OVERRIDES,
        }
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
    fn docker_config_reads_socket_path_from_driver_table() {
        let file: config_file::ConfigFile = toml::from_str(
            r#"
[openshell.drivers.docker]
socket_path = "/tmp/docker.sock"
"#,
        )
        .expect("valid config");

        let cfg = docker_config_from_context(test_context(Some(&file))).expect("docker config");

        assert_eq!(cfg.socket_path, Some(PathBuf::from("/tmp/docker.sock")));
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
