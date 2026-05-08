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
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
#[cfg(unix)]
use std::path::Path;
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

const DRIVER_BIN_NAME: &str = "openshell-driver-vm";
const COMPUTE_DRIVER_SOCKET_RUN_DIR: &str = "run";
const COMPUTE_DRIVER_SOCKET_NAME: &str = "compute-driver.sock";

/// Configuration for launching and talking to the VM compute driver.
#[derive(Debug, Clone)]
pub struct VmComputeConfig {
    /// Working directory for VM driver sandbox state.
    pub state_dir: PathBuf,

    /// Directory to search for compute-driver binaries before the gateway
    /// falls back to its conventional install paths and sibling binary.
    pub driver_dir: Option<PathBuf>,

    /// Default sandbox image the driver should use when a request omits one.
    pub default_image: String,

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

    #[must_use]
    fn default_driver_search_dirs(home: Option<PathBuf>) -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        if let Some(home) = home {
            dirs.push(home.join(".local").join("libexec").join("openshell"));
        }
        push_unique_path(&mut dirs, PathBuf::from("/usr/libexec/openshell"));
        push_unique_path(&mut dirs, PathBuf::from("/usr/local/libexec/openshell"));
        push_unique_path(&mut dirs, PathBuf::from("/usr/local/libexec"));
        dirs
    }
}

impl Default for VmComputeConfig {
    fn default() -> Self {
        Self {
            state_dir: Self::default_state_dir(),
            driver_dir: None,
            default_image: String::new(),
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
pub struct VmGuestTlsPaths {
    pub ca: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// Resolve the `openshell-driver-vm` binary path.
///
/// Resolution order:
/// 1. `{driver_dir}/openshell-driver-vm`, where `driver_dir` comes from
///    `--driver-dir` / `OPENSHELL_DRIVER_DIR`.
/// 2. Conventional install directories:
///    `~/.local/libexec/openshell`, `/usr/libexec/openshell`,
///    `/usr/local/libexec/openshell`, `/usr/local/libexec`.
/// 3. Sibling of the gateway's own executable (last-resort fallback so
///    local development builds still work out of the box).
pub fn resolve_compute_driver_bin(vm_config: &VmComputeConfig) -> Result<PathBuf> {
    let mut searched: Vec<PathBuf> = Vec::new();

    // 1. Configured driver directory, or the conventional install locations
    // when no explicit override is configured.
    for dir in resolve_driver_search_dirs(vm_config) {
        let candidate = dir.join(DRIVER_BIN_NAME);
        if candidate.is_file() {
            return Ok(candidate);
        }
        push_unique_path(&mut searched, candidate);
    }

    // 2. Sibling-of-gateway fallback.
    let current_exe = std::env::current_exe()
        .map_err(|e| Error::config(format!("failed to resolve current executable: {e}")))?;
    let Some(parent) = current_exe.parent() else {
        return Err(Error::config(format!(
            "current executable '{}' has no parent directory",
            current_exe.display()
        )));
    };
    let sibling = parent.join(DRIVER_BIN_NAME);
    if sibling.is_file() {
        return Ok(sibling);
    }
    push_unique_path(&mut searched, sibling);

    let searched_display = searched
        .iter()
        .map(|p| format!("'{}'", p.display()))
        .collect::<Vec<_>>()
        .join(", ");
    Err(Error::config(format!(
        "vm compute driver binary not found (searched {searched_display}); install it under --driver-dir / OPENSHELL_DRIVER_DIR, a conventional libexec path such as ~/.local/libexec/openshell, /usr/libexec/openshell, or /usr/local/libexec{{,/openshell}}, or place it next to the gateway binary"
    )))
}

fn resolve_driver_search_dirs(vm_config: &VmComputeConfig) -> Vec<PathBuf> {
    vm_config.driver_dir.clone().map_or_else(
        || VmComputeConfig::default_driver_search_dirs(std::env::var_os("HOME").map(PathBuf::from)),
        |dir| vec![dir],
    )
}

fn push_unique_path(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.iter().any(|existing| existing == &path) {
        paths.push(path);
    }
}

/// Path of the Unix domain socket the driver will listen on.
pub fn compute_driver_socket_path(vm_config: &VmComputeConfig) -> PathBuf {
    vm_config
        .state_dir
        .join(COMPUTE_DRIVER_SOCKET_RUN_DIR)
        .join(COMPUTE_DRIVER_SOCKET_NAME)
}

#[cfg(unix)]
fn prepare_compute_driver_socket_path(
    vm_config: &VmComputeConfig,
    socket_path: &Path,
) -> Result<()> {
    let expected_uid = current_euid();
    prepare_vm_state_dir(&vm_config.state_dir, expected_uid)?;
    let parent = socket_path.parent().ok_or_else(|| {
        Error::execution(format!(
            "vm compute driver socket path '{}' has no parent directory",
            socket_path.display()
        ))
    })?;
    prepare_private_socket_dir(parent, expected_uid)?;
    remove_stale_socket(socket_path, expected_uid)
}

#[cfg(unix)]
fn current_euid() -> u32 {
    nix::unistd::Uid::effective().as_raw()
}

#[cfg(unix)]
fn prepare_vm_state_dir(state_dir: &Path, expected_uid: u32) -> Result<()> {
    std::fs::create_dir_all(state_dir).map_err(|err| {
        Error::execution(format!(
            "failed to create vm driver state dir '{}': {err}",
            state_dir.display()
        ))
    })?;
    let metadata = checked_directory_metadata(state_dir, expected_uid, "vm driver state dir")?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o022 != 0 {
        return Err(Error::execution(format!(
            "vm driver state dir '{}' must not be group/world-writable (mode {mode:03o})",
            state_dir.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn prepare_private_socket_dir(socket_dir: &Path, expected_uid: u32) -> Result<()> {
    std::fs::create_dir_all(socket_dir).map_err(|err| {
        Error::execution(format!(
            "failed to create vm compute driver socket dir '{}': {err}",
            socket_dir.display()
        ))
    })?;
    let _ = checked_directory_metadata(socket_dir, expected_uid, "vm compute driver socket dir")?;
    std::fs::set_permissions(socket_dir, std::fs::Permissions::from_mode(0o700)).map_err(|err| {
        Error::execution(format!(
            "failed to restrict vm compute driver socket dir '{}': {err}",
            socket_dir.display()
        ))
    })
}

#[cfg(unix)]
fn checked_directory_metadata(
    path: &Path,
    expected_uid: u32,
    label: &str,
) -> Result<std::fs::Metadata> {
    let metadata = std::fs::symlink_metadata(path).map_err(|err| {
        Error::execution(format!(
            "failed to stat {label} '{}': {err}",
            path.display()
        ))
    })?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(Error::execution(format!(
            "{label} '{}' is a symlink; refusing to use it",
            path.display()
        )));
    }
    if !file_type.is_dir() {
        return Err(Error::execution(format!(
            "{label} '{}' is not a directory",
            path.display()
        )));
    }
    if metadata.uid() != expected_uid {
        return Err(Error::execution(format!(
            "{label} '{}' is owned by uid {} but current euid is {}",
            path.display(),
            metadata.uid(),
            expected_uid
        )));
    }
    Ok(metadata)
}

#[cfg(unix)]
fn remove_stale_socket(socket_path: &Path, expected_uid: u32) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(socket_path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(Error::execution(format!(
                "failed to stat vm compute driver socket '{}': {err}",
                socket_path.display()
            )));
        }
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(Error::execution(format!(
            "vm compute driver socket '{}' is a symlink; refusing to remove it",
            socket_path.display()
        )));
    }
    if metadata.uid() != expected_uid {
        return Err(Error::execution(format!(
            "vm compute driver socket '{}' is owned by uid {} but current euid is {}",
            socket_path.display(),
            metadata.uid(),
            expected_uid
        )));
    }
    if !file_type.is_socket() {
        return Err(Error::execution(format!(
            "vm compute driver socket path '{}' exists but is not a Unix socket",
            socket_path.display()
        )));
    }
    std::fs::remove_file(socket_path).map_err(|err| {
        Error::execution(format!(
            "failed to remove stale vm compute driver socket '{}': {err}",
            socket_path.display()
        ))
    })
}

#[cfg(unix)]
pub fn compute_driver_guest_tls_paths(
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
pub async fn spawn(
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
    prepare_compute_driver_socket_path(vm_config, &socket_path)?;

    let mut command = Command::new(&driver_bin);
    command.kill_on_drop(true);
    command.stdin(Stdio::null());
    command.stdout(Stdio::inherit());
    command.stderr(Stdio::inherit());
    command.arg("--bind-socket").arg(&socket_path);
    command
        .arg("--expected-peer-pid")
        .arg(std::process::id().to_string());
    command.arg("--log-level").arg(&config.log_level);
    command
        .arg("--openshell-endpoint")
        .arg(&config.grpc_endpoint);
    command.arg("--state-dir").arg(&vm_config.state_dir);
    if !vm_config.default_image.trim().is_empty() {
        command.arg("--default-image").arg(&vm_config.default_image);
    }
    // Only forward the handshake secret when one is configured. The VM
    // driver does not consume it, but accepts it for parity with the
    // Kubernetes/Podman drivers; passing an empty value is noise.
    if !config.ssh_handshake_secret.is_empty() {
        command
            .arg("--ssh-handshake-secret")
            .arg(&config.ssh_handshake_secret);
    }
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
pub async fn spawn(
    _config: &Config,
    _vm_config: &VmComputeConfig,
) -> Result<(Channel, std::sync::Arc<super::ManagedDriverProcess>)> {
    Err(Error::config(
        "the vm compute driver requires unix domain socket support",
    ))
}

#[cfg(unix)]
async fn wait_for_compute_driver(
    socket_path: &Path,
    child: &mut tokio::process::Child,
) -> Result<Channel> {
    let mut last_error: Option<String> = None;
    for _ in 0..100 {
        let try_wait_result = child.try_wait().map_err(|e| {
            Error::execution(format!("failed to poll vm compute driver process: {e}"))
        })?;
        if let Some(status) = try_wait_result {
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
async fn connect_compute_driver(socket_path: &Path) -> Result<Channel> {
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
    use super::{
        VmComputeConfig, compute_driver_guest_tls_paths, compute_driver_socket_path, current_euid,
        prepare_compute_driver_socket_path, prepare_vm_state_dir, resolve_compute_driver_bin,
        resolve_driver_search_dirs,
    };
    use openshell_core::{Config, TlsConfig};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener as StdUnixListener;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn resolve_driver_bin_uses_driver_dir_when_binary_present() {
        let dir = tempdir().unwrap();
        let bin = dir.path().join("openshell-driver-vm");
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        let vm_config = VmComputeConfig {
            driver_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        assert_eq!(resolve_compute_driver_bin(&vm_config).unwrap(), bin);
    }

    #[test]
    fn resolve_driver_bin_error_mentions_driver_dir_hint() {
        let dir = tempdir().unwrap(); // empty — no driver binary present

        let vm_config = VmComputeConfig {
            driver_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let err = resolve_compute_driver_bin(&vm_config)
            .unwrap_err()
            .to_string();
        assert!(err.contains("--driver-dir"));
        assert!(err.contains("OPENSHELL_DRIVER_DIR"));
        assert!(err.contains("openshell-driver-vm"));
    }

    #[test]
    fn resolve_driver_search_dirs_include_libexec_fallbacks() {
        let dirs = resolve_driver_search_dirs(&VmComputeConfig {
            driver_dir: None,
            ..Default::default()
        });

        assert!(dirs.contains(&PathBuf::from("/usr/libexec/openshell")));
        assert!(dirs.contains(&PathBuf::from("/usr/local/libexec/openshell")));
        assert!(dirs.contains(&PathBuf::from("/usr/local/libexec")));
    }

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

    #[test]
    fn compute_driver_socket_path_uses_private_run_dir() {
        let state_dir = PathBuf::from("/tmp/openshell-vm-state");
        let vm_config = VmComputeConfig {
            state_dir: state_dir.clone(),
            ..Default::default()
        };

        assert_eq!(
            compute_driver_socket_path(&vm_config),
            state_dir.join("run").join("compute-driver.sock")
        );
    }

    #[test]
    fn prepare_compute_driver_socket_path_creates_private_run_dir() {
        let dir = tempdir().unwrap();
        let vm_config = VmComputeConfig {
            state_dir: dir.path().join("state"),
            ..Default::default()
        };
        let socket_path = compute_driver_socket_path(&vm_config);

        prepare_compute_driver_socket_path(&vm_config, &socket_path).unwrap();

        let mode = std::fs::metadata(vm_config.state_dir.join("run"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn prepare_compute_driver_socket_path_restricts_existing_run_dir() {
        let dir = tempdir().unwrap();
        let vm_config = VmComputeConfig {
            state_dir: dir.path().join("state"),
            ..Default::default()
        };
        let run_dir = vm_config.state_dir.join("run");
        std::fs::create_dir_all(&run_dir).unwrap();
        std::fs::set_permissions(&run_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let socket_path = compute_driver_socket_path(&vm_config);

        prepare_compute_driver_socket_path(&vm_config, &socket_path).unwrap();

        let mode = std::fs::metadata(run_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn prepare_compute_driver_socket_path_rejects_writable_state_dir() {
        let dir = tempdir().unwrap();
        let vm_config = VmComputeConfig {
            state_dir: dir.path().join("state"),
            ..Default::default()
        };
        std::fs::create_dir_all(&vm_config.state_dir).unwrap();
        std::fs::set_permissions(&vm_config.state_dir, std::fs::Permissions::from_mode(0o777))
            .unwrap();
        let socket_path = compute_driver_socket_path(&vm_config);

        let err = prepare_compute_driver_socket_path(&vm_config, &socket_path)
            .expect_err("world-writable state dir should be rejected")
            .to_string();
        assert!(err.contains("must not be group/world-writable"));
    }

    #[test]
    fn prepare_compute_driver_socket_path_rejects_symlinked_state_dir() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("target");
        let state_link = dir.path().join("state-link");
        std::fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&target, &state_link).unwrap();
        let vm_config = VmComputeConfig {
            state_dir: state_link,
            ..Default::default()
        };
        let socket_path = compute_driver_socket_path(&vm_config);

        let err = prepare_compute_driver_socket_path(&vm_config, &socket_path)
            .expect_err("symlinked state dir should be rejected")
            .to_string();
        assert!(err.contains("is a symlink"));
    }

    #[test]
    fn prepare_compute_driver_socket_path_rejects_symlinked_run_dir() {
        let dir = tempdir().unwrap();
        let vm_config = VmComputeConfig {
            state_dir: dir.path().join("state"),
            ..Default::default()
        };
        let target = dir.path().join("run-target");
        std::fs::create_dir_all(&vm_config.state_dir).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&target, vm_config.state_dir.join("run")).unwrap();
        let socket_path = compute_driver_socket_path(&vm_config);

        let err = prepare_compute_driver_socket_path(&vm_config, &socket_path)
            .expect_err("symlinked run dir should be rejected")
            .to_string();
        assert!(err.contains("is a symlink"));
    }

    #[test]
    fn prepare_vm_state_dir_rejects_wrong_owner() {
        let dir = tempdir().unwrap();
        let state_dir = dir.path().join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        let wrong_uid = if current_euid() == u32::MAX {
            u32::MAX - 1
        } else {
            current_euid() + 1
        };

        let err = prepare_vm_state_dir(&state_dir, wrong_uid)
            .expect_err("wrong owner should be rejected")
            .to_string();
        assert!(err.contains("is owned by uid"));
    }

    #[test]
    fn prepare_compute_driver_socket_path_rejects_symlinked_socket() {
        let dir = tempdir().unwrap();
        let vm_config = VmComputeConfig {
            state_dir: dir.path().join("state"),
            ..Default::default()
        };
        let socket_path = compute_driver_socket_path(&vm_config);
        std::fs::create_dir_all(socket_path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink("/tmp/not-a-socket", &socket_path).unwrap();

        let err = prepare_compute_driver_socket_path(&vm_config, &socket_path)
            .expect_err("symlinked socket should be rejected")
            .to_string();
        assert!(err.contains("is a symlink"));
    }

    #[test]
    fn prepare_compute_driver_socket_path_rejects_non_socket_stale_path() {
        let dir = tempdir().unwrap();
        let vm_config = VmComputeConfig {
            state_dir: dir.path().join("state"),
            ..Default::default()
        };
        let socket_path = compute_driver_socket_path(&vm_config);
        std::fs::create_dir_all(socket_path.parent().unwrap()).unwrap();
        std::fs::write(&socket_path, "not a socket").unwrap();

        let err = prepare_compute_driver_socket_path(&vm_config, &socket_path)
            .expect_err("regular file should be rejected")
            .to_string();
        assert!(err.contains("is not a Unix socket"));
    }

    #[test]
    fn prepare_compute_driver_socket_path_removes_same_owner_stale_socket() {
        let dir = tempdir().unwrap();
        let vm_config = VmComputeConfig {
            state_dir: dir.path().join("state"),
            ..Default::default()
        };
        let socket_path = compute_driver_socket_path(&vm_config);
        std::fs::create_dir_all(socket_path.parent().unwrap()).unwrap();
        let listener = StdUnixListener::bind(&socket_path).unwrap();

        prepare_compute_driver_socket_path(&vm_config, &socket_path).unwrap();

        drop(listener);
        assert!(!socket_path.exists());
    }
}
