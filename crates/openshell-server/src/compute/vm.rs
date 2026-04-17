// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! VM compute driver plumbing.
//!
//! This module owns everything needed to hand the gateway a `Channel` speaking
//! the `openshell.compute.v1.ComputeDriver` RPC surface against an
//! `openshell-driver-vm` subprocess over a Unix domain socket:
//!
//! - [`VmComputeConfig`]: gateway-local configuration (state dir, driver binary,
//!   VM shape, guest TLS material).
//! - [`spawn`]: spawn the driver subprocess, wait for its UDS to be ready,
//!   and return a live gRPC channel plus a [`ManagedDriverProcess`] handle
//!   that will reap the subprocess and clean up the socket on drop.
//! - Helpers to resolve the driver binary, compute the socket path, and
//!   validate guest TLS material when the gateway runs an `https://` control
//!   plane.
//!
//! The VM-driver fields deliberately live here rather than in
//! [`openshell_core::Config`] so the shared core stays free of driver-specific
//! plumbing.
//!
//! TODO(driver-abstraction): this module still assumes the concrete VM driver
//! (argv shape, guest-TLS flags, libkrun-specific settings). Once we land the
//! generalized compute-driver interface, the CLI-arg plumbing below should
//! be replaced with a driver-agnostic launcher that speaks gRPC to
//! configure the driver — and this file should collapse to the types that
//! are genuinely VM-specific (libkrun log level, vCPU / memory shape) plus a
//! trait implementation registering the VM driver against the generic
//! interface.

#[cfg(unix)]
use super::ManagedDriverProcess;
#[cfg(unix)]
use hyper_util::rt::TokioIo;
#[cfg(unix)]
use openshell_core::proto::compute::v1::{
    GetCapabilitiesRequest, compute_driver_client::ComputeDriverClient,
};
use openshell_core::{Config, Error, Result};
use std::path::PathBuf;
#[cfg(unix)]
use std::{io::ErrorKind, process::Stdio, sync::Arc, time::Duration};
#[cfg(unix)]
use tokio::net::UnixStream;
#[cfg(unix)]
use tokio::process::Command;
use tonic::transport::Channel;
#[cfg(unix)]
use tonic::transport::Endpoint;
#[cfg(unix)]
use tower::service_fn;

/// Configuration for launching and talking to the VM compute driver.
#[derive(Debug, Clone)]
pub struct VmComputeConfig {
    /// Working directory for VM driver sandbox state.
    pub state_dir: PathBuf,

    /// Optional override for the `openshell-driver-vm` binary path.
    /// When `None`, the gateway resolves a sibling of its own executable.
    pub compute_driver_bin: Option<PathBuf>,

    /// libkrun log level used by the VM driver helper.
    pub krun_log_level: u32,

    /// Default vCPU count for VM sandboxes.
    pub vcpus: u8,

    /// Default memory allocation for VM sandboxes, in MiB.
    pub mem_mib: u32,

    /// Host-side CA certificate for the guest's mTLS client bundle.
    pub guest_tls_ca: Option<PathBuf>,

    /// Host-side client certificate for the guest's mTLS client bundle.
    pub guest_tls_cert: Option<PathBuf>,

    /// Host-side private key for the guest's mTLS client bundle.
    pub guest_tls_key: Option<PathBuf>,
}

impl VmComputeConfig {
    /// Default working directory for VM driver state.
    #[must_use]
    pub fn default_state_dir() -> PathBuf {
        PathBuf::from("target/openshell-vm-driver")
    }

    /// Default libkrun log level.
    #[must_use]
    pub const fn default_krun_log_level() -> u32 {
        1
    }

    /// Default vCPU count.
    #[must_use]
    pub const fn default_vcpus() -> u8 {
        2
    }

    /// Default memory allocation, in MiB.
    #[must_use]
    pub const fn default_mem_mib() -> u32 {
        2048
    }
}

impl Default for VmComputeConfig {
    fn default() -> Self {
        Self {
            state_dir: Self::default_state_dir(),
            compute_driver_bin: None,
            krun_log_level: Self::default_krun_log_level(),
            vcpus: Self::default_vcpus(),
            mem_mib: Self::default_mem_mib(),
            guest_tls_ca: None,
            guest_tls_cert: None,
            guest_tls_key: None,
        }
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VmGuestTlsPaths {
    pub(crate) ca: PathBuf,
    pub(crate) cert: PathBuf,
    pub(crate) key: PathBuf,
}

/// Resolve the `openshell-driver-vm` binary path, falling back to a sibling
/// of the gateway's own executable when an override is not supplied.
pub(crate) fn resolve_compute_driver_bin(vm_config: &VmComputeConfig) -> Result<PathBuf> {
    let path = if let Some(path) = vm_config.compute_driver_bin.clone() {
        path
    } else {
        let current_exe = std::env::current_exe()
            .map_err(|e| Error::config(format!("failed to resolve current executable: {e}")))?;
        let Some(parent) = current_exe.parent() else {
            return Err(Error::config(format!(
                "current executable '{}' has no parent directory",
                current_exe.display()
            )));
        };
        parent.join("openshell-driver-vm")
    };

    if !path.is_file() {
        return Err(Error::config(format!(
            "vm compute driver binary '{}' does not exist; set --vm-compute-driver-bin or OPENSHELL_VM_COMPUTE_DRIVER_BIN",
            path.display()
        )));
    }

    Ok(path)
}

/// Path of the Unix domain socket the driver will listen on.
pub(crate) fn compute_driver_socket_path(vm_config: &VmComputeConfig) -> PathBuf {
    vm_config.state_dir.join("compute-driver.sock")
}

#[cfg(unix)]
pub(crate) fn compute_driver_guest_tls_paths(
    config: &Config,
    vm_config: &VmComputeConfig,
) -> Result<Option<VmGuestTlsPaths>> {
    if !config.grpc_endpoint.starts_with("https://") {
        return Ok(None);
    }

    let provided = [
        vm_config.guest_tls_ca.as_ref(),
        vm_config.guest_tls_cert.as_ref(),
        vm_config.guest_tls_key.as_ref(),
    ];
    if provided.iter().all(Option::is_none) {
        return Err(Error::config(
            "vm compute driver requires --vm-tls-ca, --vm-tls-cert, and --vm-tls-key when OPENSHELL_GRPC_ENDPOINT uses https://",
        ));
    }

    let Some(ca) = vm_config.guest_tls_ca.clone() else {
        return Err(Error::config(
            "--vm-tls-ca is required when VM guest TLS materials are configured",
        ));
    };
    let Some(cert) = vm_config.guest_tls_cert.clone() else {
        return Err(Error::config(
            "--vm-tls-cert is required when VM guest TLS materials are configured",
        ));
    };
    let Some(key) = vm_config.guest_tls_key.clone() else {
        return Err(Error::config(
            "--vm-tls-key is required when VM guest TLS materials are configured",
        ));
    };

    for path in [&ca, &cert, &key] {
        if !path.is_file() {
            return Err(Error::config(format!(
                "vm guest TLS material '{}' does not exist or is not a file",
                path.display()
            )));
        }
    }

    Ok(Some(VmGuestTlsPaths { ca, cert, key }))
}

/// Launch the VM compute-driver subprocess, wait for its UDS to come up,
/// and return a gRPC `Channel` connected to it plus a process handle that
/// kills the subprocess and removes the socket on drop.
#[cfg(unix)]
pub(crate) async fn spawn(
    config: &Config,
    vm_config: &VmComputeConfig,
) -> Result<(Channel, Arc<ManagedDriverProcess>)> {
    if config.grpc_endpoint.trim().is_empty() {
        return Err(Error::config(
            "grpc_endpoint is required when using the vm compute driver",
        ));
    }

    let driver_bin = resolve_compute_driver_bin(vm_config)?;
    let socket_path = compute_driver_socket_path(vm_config);
    let guest_tls_paths = compute_driver_guest_tls_paths(config, vm_config)?;
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::execution(format!(
                "failed to create vm compute driver socket dir '{}': {e}",
                parent.display()
            ))
        })?;
    }
    match std::fs::remove_file(&socket_path) {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            return Err(Error::execution(format!(
                "failed to remove stale vm compute driver socket '{}': {err}",
                socket_path.display()
            )));
        }
    }

    let mut command = Command::new(&driver_bin);
    command.kill_on_drop(true);
    command.stdin(Stdio::null());
    command.stdout(Stdio::inherit());
    command.stderr(Stdio::inherit());
    command.arg("--bind-socket").arg(&socket_path);
    command.arg("--log-level").arg(&config.log_level);
    command
        .arg("--openshell-endpoint")
        .arg(&config.grpc_endpoint);
    command.arg("--state-dir").arg(&vm_config.state_dir);
    command
        .arg("--ssh-handshake-secret")
        .arg(&config.ssh_handshake_secret);
    command
        .arg("--ssh-handshake-skew-secs")
        .arg(config.ssh_handshake_skew_secs.to_string());
    command
        .arg("--krun-log-level")
        .arg(vm_config.krun_log_level.to_string());
    command.arg("--vcpus").arg(vm_config.vcpus.to_string());
    command.arg("--mem-mib").arg(vm_config.mem_mib.to_string());
    if let Some(tls) = guest_tls_paths {
        command.arg("--guest-tls-ca").arg(tls.ca);
        command.arg("--guest-tls-cert").arg(tls.cert);
        command.arg("--guest-tls-key").arg(tls.key);
    }

    let mut child = command.spawn().map_err(|e| {
        Error::execution(format!(
            "failed to launch vm compute driver '{}': {e}",
            driver_bin.display()
        ))
    })?;
    let channel = wait_for_compute_driver(&socket_path, &mut child).await?;
    let process = Arc::new(ManagedDriverProcess::new(child, socket_path));
    Ok((channel, process))
}

#[cfg(not(unix))]
pub(crate) async fn spawn(
    _config: &Config,
    _vm_config: &VmComputeConfig,
) -> Result<(Channel, std::sync::Arc<super::ManagedDriverProcess>)> {
    Err(Error::config(
        "the vm compute driver requires unix domain socket support",
    ))
}

#[cfg(unix)]
async fn wait_for_compute_driver(
    socket_path: &std::path::Path,
    child: &mut tokio::process::Child,
) -> Result<Channel> {
    let mut last_error: Option<String> = None;
    for _ in 0..100 {
        if let Some(status) = child.try_wait().map_err(|e| {
            Error::execution(format!("failed to poll vm compute driver process: {e}"))
        })? {
            return Err(Error::execution(format!(
                "vm compute driver exited before becoming ready with status {status}"
            )));
        }

        match connect_compute_driver(socket_path).await {
            Ok(channel) => {
                let mut client = ComputeDriverClient::new(channel.clone());
                match client
                    .get_capabilities(tonic::Request::new(GetCapabilitiesRequest {}))
                    .await
                {
                    Ok(_) => return Ok(channel),
                    Err(status) => last_error = Some(status.to_string()),
                }
            }
            Err(err) => last_error = Some(err.to_string()),
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    Err(Error::execution(format!(
        "timed out waiting for vm compute driver socket '{}': {}",
        socket_path.display(),
        last_error.unwrap_or_else(|| "unknown error".to_string())
    )))
}

#[cfg(unix)]
async fn connect_compute_driver(socket_path: &std::path::Path) -> Result<Channel> {
    let socket_path = socket_path.to_path_buf();
    let display_path = socket_path.clone();
    Endpoint::from_static("http://[::]:50051")
        .connect_with_connector(service_fn(move |_: tonic::transport::Uri| {
            let socket_path = socket_path.clone();
            async move { UnixStream::connect(socket_path).await.map(TokioIo::new) }
        }))
        .await
        .map_err(|e| {
            Error::execution(format!(
                "failed to connect to vm compute driver socket '{}': {e}",
                display_path.display()
            ))
        })
}

#[cfg(all(test, unix))]
mod tests {
    use super::{VmComputeConfig, compute_driver_guest_tls_paths};
    use openshell_core::{Config, TlsConfig};
    use tempfile::tempdir;

    #[test]
    fn vm_compute_driver_tls_requires_explicit_guest_bundle() {
        let dir = tempdir().unwrap();
        let server_cert = dir.path().join("server.crt");
        let server_key = dir.path().join("server.key");
        let server_ca = dir.path().join("client-ca.crt");
        std::fs::write(&server_cert, "server-cert").unwrap();
        std::fs::write(&server_key, "server-key").unwrap();
        std::fs::write(&server_ca, "client-ca").unwrap();

        let config = Config::new(Some(TlsConfig {
            cert_path: server_cert,
            key_path: server_key,
            client_ca_path: server_ca,
            allow_unauthenticated: false,
        }))
        .with_grpc_endpoint("https://gateway.internal:8443");

        let err = compute_driver_guest_tls_paths(&config, &VmComputeConfig::default())
            .expect_err("https vm endpoints should require an explicit guest client bundle");
        assert!(
            err.to_string()
                .contains("--vm-tls-ca, --vm-tls-cert, and --vm-tls-key")
        );
    }

    #[test]
    fn vm_compute_driver_tls_uses_guest_bundle_not_gateway_server_identity() {
        let dir = tempdir().unwrap();
        let server_cert = dir.path().join("server.crt");
        let server_key = dir.path().join("server.key");
        let server_ca = dir.path().join("client-ca.crt");
        let guest_ca = dir.path().join("guest-ca.crt");
        let guest_cert = dir.path().join("guest.crt");
        let guest_key = dir.path().join("guest.key");
        for path in [
            &server_cert,
            &server_key,
            &server_ca,
            &guest_ca,
            &guest_cert,
            &guest_key,
        ] {
            std::fs::write(path, path.display().to_string()).unwrap();
        }

        let config = Config::new(Some(TlsConfig {
            cert_path: server_cert.clone(),
            key_path: server_key.clone(),
            client_ca_path: server_ca,
            allow_unauthenticated: false,
        }))
        .with_grpc_endpoint("https://gateway.internal:8443");
        let vm_config = VmComputeConfig {
            guest_tls_ca: Some(guest_ca.clone()),
            guest_tls_cert: Some(guest_cert.clone()),
            guest_tls_key: Some(guest_key.clone()),
            ..Default::default()
        };

        let guest_paths = compute_driver_guest_tls_paths(&config, &vm_config)
            .unwrap()
            .expect("https vm endpoints should pass an explicit guest client bundle");
        assert_eq!(guest_paths.ca, guest_ca);
        assert_eq!(guest_paths.cert, guest_cert);
        assert_eq!(guest_paths.key, guest_key);
        assert_ne!(guest_paths.cert, server_cert);
        assert_ne!(guest_paths.key, server_key);
    }
}
