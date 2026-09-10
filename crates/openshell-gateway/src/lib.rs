// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Standard gateway binary composition.
//!
//! The server remains backend-agnostic. This crate is the composition boundary
//! that links first-party compute drivers into the distributed gateway binary.

// `defaults-without-telemetry` is an alias for the default feature set minus
// `telemetry`, not a switch that turns telemetry off. Cargo cannot subtract a
// default feature, so adding it on top of the defaults would otherwise produce
// a telemetry-on build that reads as telemetry-free. Fail the build instead.
#[cfg(all(feature = "telemetry", feature = "defaults-without-telemetry"))]
compile_error!(
    "features `telemetry` and `defaults-without-telemetry` are mutually exclusive; \
     build a telemetry-free gateway with `--no-default-features --features defaults-without-telemetry`"
);

#[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
mod vm;

#[cfg(feature = "in-tree-compute-drivers")]
use openshell_core::telemetry::TelemetryComputeDriver;
#[cfg(feature = "in-tree-compute-drivers")]
use openshell_server::ComputeDriverRegistration;
use openshell_server::ComputeDriverRegistry;

/// Install every first-party compute driver linked into the standard gateway.
#[must_use]
pub fn install_default_compute_drivers() -> ComputeDriverRegistry {
    #[allow(unused_mut)]
    let mut registry = ComputeDriverRegistry::new();
    #[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
    install_in_tree_compute_drivers(&mut registry);
    #[cfg(all(target_os = "windows", feature = "in-tree-compute-drivers"))]
    install_mxc_compute_driver(&mut registry);
    registry
}

#[cfg(all(target_os = "windows", feature = "in-tree-compute-drivers"))]
fn install_mxc_compute_driver(registry: &mut ComputeDriverRegistry) {
    let registration = ComputeDriverRegistration::new("mxc", u16::MAX, None, MxcFactory)
        .expect("first-party driver name is valid")
        .with_telemetry_category(TelemetryComputeDriver::anonymous_category("mxc"))
        .with_local_singleplayer();
    registry
        .install(registration)
        .expect("first-party driver names are unique");

    for name in ["docker", "kubernetes", "podman", "vm"] {
        let registration = ComputeDriverRegistration::new(
            name,
            u16::MAX,
            None,
            UnsupportedWindowsFactory { name },
        )
        .expect("first-party driver name is valid");
        registry
            .install(registration)
            .expect("first-party driver names are unique");
    }
}

#[cfg(all(target_os = "windows", feature = "in-tree-compute-drivers"))]
#[derive(Clone, Copy)]
struct UnsupportedWindowsFactory {
    name: &'static str,
}

#[cfg(all(target_os = "windows", feature = "in-tree-compute-drivers"))]
#[async_trait::async_trait]
impl openshell_server::ComputeDriverFactory for UnsupportedWindowsFactory {
    async fn build(
        &self,
        _context: openshell_server::ComputeDriverBuildContext<'_>,
    ) -> openshell_core::Result<openshell_server::ComputeDriverInstance> {
        Err(unsupported_windows_compute_driver(self.name))
    }
}

#[cfg(all(target_os = "windows", feature = "in-tree-compute-drivers"))]
fn unsupported_windows_compute_driver(name: &str) -> openshell_core::Error {
    openshell_core::Error::config(format!("compute driver '{name}' is unsupported on Windows"))
}

#[cfg(all(target_os = "windows", feature = "in-tree-compute-drivers"))]
#[derive(Clone, Copy)]
struct MxcFactory;

#[cfg(all(target_os = "windows", feature = "in-tree-compute-drivers"))]
#[async_trait::async_trait]
impl openshell_server::ComputeDriverFactory for MxcFactory {
    async fn build(
        &self,
        context: openshell_server::ComputeDriverBuildContext<'_>,
    ) -> openshell_core::Result<openshell_server::ComputeDriverInstance> {
        let config: openshell_driver_mxc::MxcComputeConfig = context.driver_config()?;
        let backend = openshell_driver_mxc::MxcComputeBackend::new(config);
        let driver = openshell_driver_mxc::ComputeDriverService::new(backend);
        Ok(openshell_server::ComputeDriverInstance::InProcess(
            std::sync::Arc::new(driver),
        ))
    }
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
                .with_in_process_tracing(openshell_driver_kubernetes::otel_tracing::TRACING)
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
                .with_in_process_tracing(openshell_driver_podman::otel_tracing::TRACING)
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
                .with_in_process_tracing(openshell_driver_docker::otel_tracing::TRACING)
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
        let driver = openshell_driver_kubernetes::ComputeDriverService::new_in_process(driver);
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
        let driver = openshell_driver_docker::ComputeDriverService::new_in_process(driver);
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
        let driver = openshell_driver_podman::ComputeDriverService::new_in_process(driver);
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
        let endpoint = vm::spawn(
            context.gateway_log_level(),
            context.gateway_name(),
            &config,
            context.otlp_config(),
        )
        .await?;
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

#[cfg(all(test, target_os = "windows", feature = "in-tree-compute-drivers"))]
mod windows_tests {
    use super::*;

    #[test]
    fn windows_builtin_compute_drivers_report_unsupported() {
        let registry = install_default_compute_drivers();
        assert_eq!(
            registry.installed_driver_names().collect::<Vec<_>>(),
            ["docker", "kubernetes", "mxc", "podman", "vm"]
        );

        for name in ["docker", "kubernetes", "podman", "vm"] {
            let message = unsupported_windows_compute_driver(name).to_string();
            assert!(
                message.contains("unsupported on Windows"),
                "{name} rejection should be explicit, got: {message}"
            );
        }
    }
}
