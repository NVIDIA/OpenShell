// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Standard gateway binary composition.
//!
//! The server remains backend-agnostic. This crate is the composition boundary
//! that links first-party compute drivers into the distributed gateway binary.

#[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
mod vm;

#[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
use openshell_core::telemetry::TelemetryComputeDriver;
#[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
use openshell_server::ComputeDriverRegistration;
use openshell_server::ComputeDriverRegistry;

/// Install every first-party compute driver linked into the standard gateway.
#[must_use]
pub fn install_default_compute_drivers() -> ComputeDriverRegistry {
    #[allow(unused_mut)]
    let mut registry = ComputeDriverRegistry::new();
    #[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
    install_in_tree_compute_drivers(&mut registry);
    registry
}

#[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
fn install_in_tree_compute_drivers(registry: &mut ComputeDriverRegistry) {
    for registration in [
        ComputeDriverRegistration::new(
            "kubernetes",
            100,
            Some(|| std::env::var_os("KUBERNETES_SERVICE_HOST").is_some()),
            KubernetesFactory,
        )
        .map(|registration| {
            registration
                .with_telemetry_category(TelemetryComputeDriver::anonymous_category("kubernetes"))
                .without_mtls_user_auth()
                .with_token_bootstrap(kubernetes_token_bootstrap)
                .with_inherited_config_keys(&[
                    "namespace",
                    "default_image",
                    "supervisor_image",
                    "client_tls_secret_name",
                    "service_account_name",
                    "host_gateway_ip",
                    "enable_user_namespaces",
                    "sa_token_ttl_secs",
                ])
        }),
        ComputeDriverRegistration::new(
            "podman",
            200,
            Some(openshell_driver_podman::driver::is_available),
            PodmanFactory,
        )
        .map(|registration| {
            registration
                .with_telemetry_category(TelemetryComputeDriver::anonymous_category("podman"))
                .with_local_singleplayer()
                .with_tracing_setup(podman_tracing_setup)
                .with_inherited_config_keys(&[
                    "default_image",
                    "supervisor_image",
                    "host_gateway_ip",
                    "guest_tls_ca",
                    "guest_tls_cert",
                    "guest_tls_key",
                ])
        }),
        ComputeDriverRegistration::new(
            "docker",
            300,
            Some(openshell_driver_docker::is_available),
            DockerFactory,
        )
        .map(|registration| {
            registration
                .with_telemetry_category(TelemetryComputeDriver::anonymous_category("docker"))
                .with_local_singleplayer()
                .with_inherited_config_keys(&[
                    "sandbox_namespace",
                    "default_image",
                    "supervisor_image",
                    "host_gateway_ip",
                    "guest_tls_ca",
                    "guest_tls_cert",
                    "guest_tls_key",
                ])
        }),
        ComputeDriverRegistration::new("vm", u16::MAX, None, VmFactory).map(|registration| {
            registration
                .with_telemetry_category(TelemetryComputeDriver::anonymous_category("vm"))
                .with_local_singleplayer()
                .with_inherited_config_keys(&[
                    "default_image",
                    "guest_tls_ca",
                    "guest_tls_cert",
                    "guest_tls_key",
                ])
        }),
    ] {
        registry
            .install(registration.expect("first-party driver name is valid"))
            .expect("first-party driver names are unique");
    }
}

#[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
fn kubernetes_token_bootstrap(
    context: &openshell_server::ComputeDriverBuildContext<'_>,
) -> openshell_core::Result<Option<openshell_server::config_file::SandboxTokenBootstrapConfig>> {
    let config: openshell_driver_kubernetes::KubernetesComputeConfig = context.driver_config()?;
    Ok(Some(kubernetes_token_bootstrap_from_config(config)))
}

#[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
fn kubernetes_token_bootstrap_from_config(
    config: openshell_driver_kubernetes::KubernetesComputeConfig,
) -> openshell_server::config_file::SandboxTokenBootstrapConfig {
    use openshell_driver_kubernetes::WorkspaceMode;

    let (namespace, namespace_prefix, namespace_label, namespace_file) = match config.workspace_mode
    {
        WorkspaceMode::Shared => (Some(config.namespace), None, None, None),
        WorkspaceMode::Managed => (
            None,
            Some(openshell_driver_kubernetes::managed_namespace_prefix(
                &config.gateway_id,
            )),
            None,
            None,
        ),
        WorkspaceMode::Operator => (
            None,
            None,
            config.operator_namespace_label,
            config.operator_namespace_file.map(std::path::PathBuf::from),
        ),
    };

    openshell_server::config_file::SandboxTokenBootstrapConfig::KubernetesServiceAccount {
        service_account_name: config.service_account_name,
        namespace,
        namespace_prefix,
        namespace_label,
        namespace_file,
    }
}

#[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
fn podman_tracing_setup(
    otlp_endpoint: Option<&str>,
) -> openshell_server::ComputeDriverTracingSetup {
    let (provider, error) = openshell_driver_podman::otel_tracing::provider_for(otlp_endpoint);
    let layer = provider.as_ref().map(|provider| {
        let layer: openshell_server::ComputeDriverTracingLayer = Box::new(
            openshell_driver_podman::otel_tracing::in_process_layer(provider),
        );
        layer
    });
    let shutdown = provider.map(|provider| {
        let shutdown: openshell_server::ComputeDriverTracingShutdown =
            Box::new(move || provider.shutdown().map_err(|error| error.to_string()));
        shutdown
    });
    openshell_server::ComputeDriverTracingSetup::new(
        layer,
        shutdown,
        error.map(|error| error.to_string()),
        Some(openshell_driver_podman::otel_tracing::IN_PROCESS_TARGET_PREFIX),
    )
}

#[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
#[derive(Clone, Copy)]
struct KubernetesFactory;

#[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
#[async_trait::async_trait]
impl openshell_server::ComputeDriverFactory for KubernetesFactory {
    async fn build(
        &self,
        context: openshell_server::ComputeDriverBuildContext<'_>,
    ) -> openshell_core::Result<openshell_server::ComputeDriverInstance> {
        let mut config: openshell_driver_kubernetes::KubernetesComputeConfig =
            context.driver_config()?;
        if let Ok(size) = std::env::var("OPENSHELL_K8S_WORKSPACE_DEFAULT_STORAGE_SIZE") {
            config.workspace_default_storage_size = size;
        }
        if let Ok(storage_class) = std::env::var("OPENSHELL_K8S_WORKSPACE_STORAGE_CLASS") {
            config.workspace_storage_class = storage_class;
        }
        let driver = openshell_driver_kubernetes::KubernetesComputeDriver::new(
            config,
            context.shutdown_receiver(),
        )
        .await
        .map_err(|error| openshell_core::Error::execution(error.to_string()))?;
        let driver = openshell_driver_kubernetes::ComputeDriverService::new(driver);
        Ok(openshell_server::ComputeDriverInstance::InProcess(
            std::sync::Arc::new(driver),
        ))
    }
}

#[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
#[derive(Clone, Copy)]
struct DockerFactory;

#[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
#[async_trait::async_trait]
impl openshell_server::ComputeDriverFactory for DockerFactory {
    async fn build(
        &self,
        context: openshell_server::ComputeDriverBuildContext<'_>,
    ) -> openshell_core::Result<openshell_server::ComputeDriverInstance> {
        let mut config: openshell_driver_docker::DockerComputeConfig = context.driver_config()?;
        apply_guest_tls(
            &mut config.guest_tls_ca,
            &mut config.guest_tls_cert,
            &mut config.guest_tls_key,
            context.guest_tls_paths(),
        );
        let driver = openshell_driver_docker::DockerComputeDriver::new(
            context.gateway_bind_address(),
            context.gateway_log_level(),
            &config,
        )
        .await
        .map_err(|error| openshell_core::Error::execution(error.to_string()))?;
        Ok(openshell_server::ComputeDriverInstance::InProcess(
            std::sync::Arc::new(driver),
        ))
    }
}

#[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
#[derive(Clone, Copy)]
struct PodmanFactory;

#[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
#[async_trait::async_trait]
impl openshell_server::ComputeDriverFactory for PodmanFactory {
    async fn build(
        &self,
        context: openshell_server::ComputeDriverBuildContext<'_>,
    ) -> openshell_core::Result<openshell_server::ComputeDriverInstance> {
        let mut config: openshell_driver_podman::PodmanComputeConfig = context.driver_config()?;
        config.gateway_port = context.gateway_port();
        if let Ok(path) = std::env::var("OPENSHELL_PODMAN_SOCKET") {
            config.socket_path = Some(path.into());
        }
        if let Ok(ip) = std::env::var("OPENSHELL_PODMAN_HOST_GATEWAY_IP") {
            config.host_gateway_ip = ip;
        }
        if let Ok(mode) = std::env::var("OPENSHELL_PODMAN_USERNS") {
            config.userns = Some(mode);
        }
        apply_guest_tls(
            &mut config.guest_tls_ca,
            &mut config.guest_tls_cert,
            &mut config.guest_tls_key,
            context.guest_tls_paths(),
        );
        let driver = openshell_driver_podman::PodmanComputeDriver::new(config)
            .await
            .map_err(|error| openshell_core::Error::execution(error.to_string()))?;
        let driver = openshell_driver_podman::ComputeDriverService::new(driver);
        Ok(openshell_server::ComputeDriverInstance::InProcess(
            std::sync::Arc::new(driver),
        ))
    }
}

#[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
#[derive(Clone, Copy)]
struct VmFactory;

#[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
#[async_trait::async_trait]
impl openshell_server::ComputeDriverFactory for VmFactory {
    async fn build(
        &self,
        context: openshell_server::ComputeDriverBuildContext<'_>,
    ) -> openshell_core::Result<openshell_server::ComputeDriverInstance> {
        let mut config: vm::VmComputeConfig = context.driver_config()?;
        if config.state_dir.as_os_str().is_empty() {
            config.state_dir = vm::VmComputeConfig::default_state_dir();
        }
        if config.grpc_endpoint.trim().is_empty()
            && (!context.gateway_tls_enabled() || context.guest_tls_paths().is_some())
        {
            let scheme = if context.gateway_tls_enabled() {
                "https"
            } else {
                "http"
            };
            config.grpc_endpoint = format!("{scheme}://127.0.0.1:{}", context.gateway_port());
        }
        apply_guest_tls(
            &mut config.guest_tls_ca,
            &mut config.guest_tls_cert,
            &mut config.guest_tls_key,
            context.guest_tls_paths(),
        );
        let endpoint =
            vm::spawn(context.gateway_log_level(), &config, context.otlp_config()).await?;
        Ok(openshell_server::ComputeDriverInstance::ManagedRemote(
            endpoint,
        ))
    }
}

#[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
fn apply_guest_tls(
    ca: &mut Option<std::path::PathBuf>,
    cert: &mut Option<std::path::PathBuf>,
    key: &mut Option<std::path::PathBuf>,
    defaults: Option<(&std::path::Path, &std::path::Path, &std::path::Path)>,
) {
    if ca.is_none()
        && cert.is_none()
        && key.is_none()
        && let Some((default_ca, default_cert, default_key)) = defaults
    {
        *ca = Some(default_ca.to_owned());
        *cert = Some(default_cert.to_owned());
        *key = Some(default_key.to_owned());
    }
}

#[cfg(all(test, not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
mod tests {
    use super::*;
    use openshell_driver_kubernetes::{KubernetesComputeConfig, WorkspaceMode};
    use openshell_server::config_file::SandboxTokenBootstrapConfig;

    #[test]
    fn kubernetes_bootstrap_compatibility_uses_managed_namespace_prefix() {
        let config = KubernetesComputeConfig {
            workspace_mode: WorkspaceMode::Managed,
            gateway_id: "test-gateway".to_string(),
            service_account_name: "sandbox-sa".to_string(),
            ..KubernetesComputeConfig::default()
        };

        assert_eq!(
            kubernetes_token_bootstrap_from_config(config),
            SandboxTokenBootstrapConfig::KubernetesServiceAccount {
                service_account_name: "sandbox-sa".to_string(),
                namespace: None,
                namespace_prefix: Some("openshell-test-gateway-".to_string()),
                namespace_label: None,
                namespace_file: None,
            }
        );
    }
}
