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

#[cfg(all(not(target_os = "windows"), feature = "compute-driver-vm"))]
mod vm;

#[cfg(any(
    all(target_os = "windows", feature = "compute-driver-mxc"),
    all(
        not(target_os = "windows"),
        any(
            feature = "compute-driver-docker",
            feature = "compute-driver-kubernetes",
            feature = "compute-driver-podman",
            feature = "compute-driver-vm"
        )
    )
))]
use openshell_core::telemetry::TelemetryComputeDriver;
#[cfg(any(
    target_os = "windows",
    feature = "compute-driver-docker",
    feature = "compute-driver-kubernetes",
    feature = "compute-driver-podman",
    feature = "compute-driver-vm"
))]
use openshell_server::ComputeDriverRegistration;
use openshell_server::ComputeDriverRegistry;

/// Install every first-party compute driver linked into the standard gateway.
#[must_use]
pub fn install_default_compute_drivers() -> ComputeDriverRegistry {
    #[allow(unused_mut)]
    let mut registry = ComputeDriverRegistry::new();
    #[cfg(all(
        not(target_os = "windows"),
        any(
            feature = "compute-driver-docker",
            feature = "compute-driver-kubernetes",
            feature = "compute-driver-podman",
            feature = "compute-driver-vm"
        )
    ))]
    install_in_tree_compute_drivers(&mut registry);
    #[cfg(all(target_os = "windows", feature = "compute-driver-mxc"))]
    install_mxc_compute_driver(&mut registry);
    #[cfg(target_os = "windows")]
    install_unsupported_windows_compute_drivers(&mut registry);
    registry
}

#[cfg(all(target_os = "windows", feature = "compute-driver-mxc"))]
fn install_mxc_compute_driver(registry: &mut ComputeDriverRegistry) {
    let registration = ComputeDriverRegistration::new("mxc", u16::MAX, None, MxcFactory)
        .expect("first-party driver name is valid")
        .with_telemetry_category(TelemetryComputeDriver::anonymous_category("mxc"))
        .with_local_singleplayer();
    registry
        .install(registration)
        .expect("first-party driver names are unique");
}

#[cfg(target_os = "windows")]
fn install_unsupported_windows_compute_drivers(registry: &mut ComputeDriverRegistry) {
    let names: &[&str] = &[
        #[cfg(feature = "compute-driver-docker")]
        "docker",
        #[cfg(feature = "compute-driver-kubernetes")]
        "kubernetes",
        #[cfg(feature = "compute-driver-podman")]
        "podman",
        #[cfg(feature = "compute-driver-vm")]
        "vm",
    ];
    for &name in names {
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

#[cfg(target_os = "windows")]
#[derive(Clone, Copy)]
struct UnsupportedWindowsFactory {
    name: &'static str,
}

#[cfg(target_os = "windows")]
#[async_trait::async_trait]
impl openshell_server::ComputeDriverFactory for UnsupportedWindowsFactory {
    fn supports_config_preflight(&self) -> bool {
        true
    }

    fn validate_config(
        &self,
        _context: openshell_server::ComputeDriverConfigContext<'_>,
    ) -> openshell_core::Result<()> {
        Err(unsupported_windows_compute_driver(self.name))
    }

    async fn build(
        &self,
        _context: openshell_server::ComputeDriverBuildContext<'_>,
    ) -> openshell_core::Result<openshell_server::ComputeDriverInstance> {
        Err(unsupported_windows_compute_driver(self.name))
    }
}

#[cfg(target_os = "windows")]
fn unsupported_windows_compute_driver(name: &str) -> openshell_core::Error {
    openshell_core::Error::config(format!("compute driver '{name}' is unsupported on Windows"))
}

#[cfg(all(target_os = "windows", feature = "compute-driver-mxc"))]
#[derive(Clone, Copy)]
struct MxcFactory;

#[cfg(all(target_os = "windows", feature = "compute-driver-mxc"))]
#[async_trait::async_trait]
impl openshell_server::ComputeDriverFactory for MxcFactory {
    fn supports_config_preflight(&self) -> bool {
        true
    }

    fn validate_config(
        &self,
        context: openshell_server::ComputeDriverConfigContext<'_>,
    ) -> openshell_core::Result<()> {
        let _: openshell_driver_mxc::MxcComputeConfig = context.driver_config()?;
        Ok(())
    }

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

#[cfg(all(
    not(target_os = "windows"),
    any(
        feature = "compute-driver-docker",
        feature = "compute-driver-kubernetes",
        feature = "compute-driver-podman",
        feature = "compute-driver-vm"
    )
))]
fn install_in_tree_compute_drivers(registry: &mut ComputeDriverRegistry) {
    for registration in [
        #[cfg(feature = "compute-driver-kubernetes")]
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
        }),
        #[cfg(feature = "compute-driver-podman")]
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
        }),
        #[cfg(feature = "compute-driver-docker")]
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
        }),
        #[cfg(feature = "compute-driver-vm")]
        ComputeDriverRegistration::new("vm", u16::MAX, None, VmFactory).map(|registration| {
            registration
                .with_telemetry_category(TelemetryComputeDriver::anonymous_category("vm"))
                .with_local_singleplayer()
        }),
    ] {
        registry
            .install(registration.expect("first-party driver name is valid"))
            .expect("first-party driver names are unique");
    }
}

#[cfg(all(not(target_os = "windows"), feature = "compute-driver-kubernetes"))]
#[derive(Clone, Copy)]
struct KubernetesFactory;

#[cfg(all(not(target_os = "windows"), feature = "compute-driver-kubernetes"))]
#[async_trait::async_trait]
impl openshell_server::ComputeDriverFactory for KubernetesFactory {
    fn supports_config_preflight(&self) -> bool {
        true
    }

    fn validate_config(
        &self,
        context: openshell_server::ComputeDriverConfigContext<'_>,
    ) -> openshell_core::Result<()> {
        kubernetes_config(context)?
            .validate_configuration()
            .map_err(openshell_core::Error::config)
    }

    async fn build(
        &self,
        context: openshell_server::ComputeDriverBuildContext<'_>,
    ) -> openshell_core::Result<openshell_server::ComputeDriverInstance> {
        let config = kubernetes_config(context.config_context())?;
        let driver = openshell_driver_kubernetes::KubernetesComputeDriver::new(
            config,
            context.shutdown_receiver(),
            context.network_trust_bundle().cloned(),
        )
        .await
        .map_err(|error| openshell_core::Error::execution(error.to_string()))?;
        let driver = openshell_driver_kubernetes::ComputeDriverService::new_in_process(driver);
        Ok(openshell_server::ComputeDriverInstance::InProcess(
            std::sync::Arc::new(driver),
        ))
    }
}

#[cfg(all(not(target_os = "windows"), feature = "compute-driver-kubernetes"))]
fn kubernetes_config(
    context: openshell_server::ComputeDriverConfigContext<'_>,
) -> openshell_core::Result<openshell_driver_kubernetes::KubernetesComputeConfig> {
    let mut config: openshell_driver_kubernetes::KubernetesComputeConfig =
        context.driver_config()?;
    if let Ok(size) = std::env::var("OPENSHELL_K8S_WORKSPACE_DEFAULT_STORAGE_SIZE") {
        config.workspace_default_storage_size = size;
    }
    if let Ok(storage_class) = std::env::var("OPENSHELL_K8S_WORKSPACE_STORAGE_CLASS") {
        config.workspace_storage_class = storage_class;
    }
    Ok(config)
}

#[cfg(all(not(target_os = "windows"), feature = "compute-driver-docker"))]
#[derive(Clone, Copy)]
struct DockerFactory;

#[cfg(all(not(target_os = "windows"), feature = "compute-driver-docker"))]
#[async_trait::async_trait]
impl openshell_server::ComputeDriverFactory for DockerFactory {
    fn supports_config_preflight(&self) -> bool {
        true
    }

    fn validate_config(
        &self,
        context: openshell_server::ComputeDriverConfigContext<'_>,
    ) -> openshell_core::Result<()> {
        let config: openshell_driver_docker::DockerComputeConfig = context.driver_config()?;
        config.validate_configuration(context.gateway_bind_address())
    }

    async fn build(
        &self,
        context: openshell_server::ComputeDriverBuildContext<'_>,
    ) -> openshell_core::Result<openshell_server::ComputeDriverInstance> {
        let mut config: openshell_driver_docker::DockerComputeConfig = context.driver_config()?;
        require_guest_tls_for_local_driver(&context, "docker")?;
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
            context
                .network_trust_bundle()
                .map(openshell_core::NetworkSupervisorTrustBundle::artifact_path),
        )
        .await
        .map_err(|error| openshell_core::Error::execution(error.to_string()))?;
        let driver = openshell_driver_docker::ComputeDriverService::new_in_process(driver);
        Ok(openshell_server::ComputeDriverInstance::InProcess(
            std::sync::Arc::new(driver),
        ))
    }
}

#[cfg(all(not(target_os = "windows"), feature = "compute-driver-podman"))]
#[derive(Clone, Copy)]
struct PodmanFactory;

#[cfg(all(not(target_os = "windows"), feature = "compute-driver-podman"))]
#[async_trait::async_trait]
impl openshell_server::ComputeDriverFactory for PodmanFactory {
    fn supports_config_preflight(&self) -> bool {
        true
    }

    fn validate_config(
        &self,
        context: openshell_server::ComputeDriverConfigContext<'_>,
    ) -> openshell_core::Result<()> {
        podman_config(context)?
            .validate_configuration()
            .map_err(|error| openshell_core::Error::config(error.to_string()))
    }

    async fn build(
        &self,
        context: openshell_server::ComputeDriverBuildContext<'_>,
    ) -> openshell_core::Result<openshell_server::ComputeDriverInstance> {
        let mut config = podman_config(context.config_context())?;
        require_guest_tls_for_local_driver(&context, "podman")?;
        apply_guest_tls(
            &mut config.guest_tls_ca,
            &mut config.guest_tls_cert,
            &mut config.guest_tls_key,
            context.guest_tls_paths(),
        );
        let driver = openshell_driver_podman::PodmanComputeDriver::new(
            config,
            context
                .network_trust_bundle()
                .map(openshell_core::NetworkSupervisorTrustBundle::artifact_path),
        )
        .await
        .map_err(|error| openshell_core::Error::execution(error.to_string()))?;
        let driver = openshell_driver_podman::ComputeDriverService::new_in_process(driver);
        Ok(openshell_server::ComputeDriverInstance::InProcess(
            std::sync::Arc::new(driver),
        ))
    }
}

#[cfg(all(not(target_os = "windows"), feature = "compute-driver-podman"))]
fn podman_config(
    context: openshell_server::ComputeDriverConfigContext<'_>,
) -> openshell_core::Result<openshell_driver_podman::PodmanComputeConfig> {
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
    Ok(config)
}

#[cfg(all(not(target_os = "windows"), feature = "compute-driver-vm"))]
#[derive(Clone, Copy)]
struct VmFactory;

#[cfg(all(not(target_os = "windows"), feature = "compute-driver-vm"))]
#[async_trait::async_trait]
impl openshell_server::ComputeDriverFactory for VmFactory {
    fn supports_config_preflight(&self) -> bool {
        true
    }

    fn validate_config(
        &self,
        context: openshell_server::ComputeDriverConfigContext<'_>,
    ) -> openshell_core::Result<()> {
        let mut config = vm_config(context)?;
        if config.grpc_endpoint.trim().is_empty() {
            let scheme = if context.gateway_tls_enabled() {
                "https"
            } else {
                "http"
            };
            config.grpc_endpoint = format!("{scheme}://127.0.0.1:{}", context.gateway_port());
        }
        config.validate_configuration()
    }

    async fn build(
        &self,
        context: openshell_server::ComputeDriverBuildContext<'_>,
    ) -> openshell_core::Result<openshell_server::ComputeDriverInstance> {
        let mut config = vm_config(context.config_context())?;
        require_guest_tls_for_local_driver(&context, "vm")?;
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
            context
                .network_trust_bundle()
                .map(openshell_core::NetworkSupervisorTrustBundle::artifact_path),
        )
        .await?;
        Ok(openshell_server::ComputeDriverInstance::ManagedRemote(
            endpoint,
        ))
    }
}

#[cfg(all(not(target_os = "windows"), feature = "compute-driver-vm"))]
fn vm_config(
    context: openshell_server::ComputeDriverConfigContext<'_>,
) -> openshell_core::Result<vm::VmComputeConfig> {
    let mut config: vm::VmComputeConfig = context.driver_config()?;
    if config.state_dir.as_os_str().is_empty() {
        config.state_dir = vm::VmComputeConfig::default_state_dir();
    }
    Ok(config)
}

#[cfg(all(
    not(target_os = "windows"),
    any(
        feature = "compute-driver-docker",
        feature = "compute-driver-podman",
        feature = "compute-driver-vm"
    )
))]
fn require_guest_tls_for_local_driver(
    context: &openshell_server::ComputeDriverBuildContext<'_>,
    driver_name: &str,
) -> openshell_core::Result<()> {
    validate_local_driver_guest_tls(
        context.gateway_tls_enabled(),
        context.guest_tls_paths().is_some(),
        driver_name,
    )
}

#[cfg(all(
    not(target_os = "windows"),
    any(
        feature = "compute-driver-docker",
        feature = "compute-driver-podman",
        feature = "compute-driver-vm"
    )
))]
fn validate_local_driver_guest_tls(
    gateway_tls_enabled: bool,
    has_guest_tls: bool,
    driver_name: &str,
) -> openshell_core::Result<()> {
    if gateway_tls_enabled && !has_guest_tls {
        return Err(openshell_core::Error::config(format!(
            "gateway TLS requires guest_tls_ca, guest_tls_cert, and guest_tls_key in [openshell.gateway] when using the {driver_name} compute driver"
        )));
    }
    Ok(())
}

#[cfg(all(
    not(target_os = "windows"),
    any(
        feature = "compute-driver-docker",
        feature = "compute-driver-podman",
        feature = "compute-driver-vm"
    )
))]
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

#[cfg(all(
    test,
    not(target_os = "windows"),
    any(
        feature = "compute-driver-docker",
        feature = "compute-driver-podman",
        feature = "compute-driver-vm"
    )
))]
mod local_driver_tests {
    use super::{apply_guest_tls, validate_local_driver_guest_tls};
    use std::path::{Path, PathBuf};

    #[test]
    #[cfg(feature = "in-tree-compute-drivers")]
    fn linux_builtin_compute_driver_registry_has_expected_names() {
        assert_eq!(
            super::install_default_compute_drivers()
                .installed_driver_names()
                .collect::<Vec<_>>(),
            ["docker", "kubernetes", "podman", "vm"]
        );
    }

    #[test]
    fn tls_enabled_local_drivers_require_a_guest_bundle() {
        for driver_name in ["docker", "podman", "vm"] {
            let error = validate_local_driver_guest_tls(true, false, driver_name)
                .expect_err("TLS-enabled local driver must require guest TLS");
            let message = error.to_string();
            assert!(message.contains(driver_name));
            assert!(message.contains("guest_tls_ca"));
        }
        validate_local_driver_guest_tls(true, true, "docker")
            .expect("a complete guest bundle satisfies the requirement");
        validate_local_driver_guest_tls(false, false, "docker")
            .expect("plaintext gateways do not require guest TLS");
    }

    #[test]
    fn package_managed_guest_bundle_is_injected_when_driver_paths_are_absent() {
        let mut ca = None;
        let mut cert = None;
        let mut key = None;
        apply_guest_tls(
            &mut ca,
            &mut cert,
            &mut key,
            Some((
                Path::new("/managed/ca.pem"),
                Path::new("/managed/client.pem"),
                Path::new("/managed/client-key.pem"),
            )),
        );
        assert_eq!(ca, Some(PathBuf::from("/managed/ca.pem")));
        assert_eq!(cert, Some(PathBuf::from("/managed/client.pem")));
        assert_eq!(key, Some(PathBuf::from("/managed/client-key.pem")));
    }
}

#[cfg(all(test, target_os = "windows"))]
mod windows_tests {
    use super::*;

    #[test]
    fn windows_builtin_compute_drivers_report_unsupported() {
        let registry = install_default_compute_drivers();
        for name in registry
            .installed_driver_names()
            .filter(|name| *name != "mxc")
        {
            let message = unsupported_windows_compute_driver(name).to_string();
            assert!(
                message.contains("unsupported on Windows"),
                "{name} rejection should be explicit, got: {message}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_registry_contains_exactly_the_enabled_compute_drivers() {
        let expected: Vec<&str> = vec![
            #[cfg(feature = "compute-driver-docker")]
            "docker",
            #[cfg(feature = "compute-driver-kubernetes")]
            "kubernetes",
            #[cfg(all(target_os = "windows", feature = "compute-driver-mxc"))]
            "mxc",
            #[cfg(feature = "compute-driver-podman")]
            "podman",
            #[cfg(feature = "compute-driver-vm")]
            "vm",
        ];
        assert_eq!(
            install_default_compute_drivers()
                .installed_driver_names()
                .collect::<Vec<_>>(),
            expected
        );
    }
}
