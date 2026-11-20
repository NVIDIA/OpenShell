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
//! Process launch remains deliberately VM-specific at this binary composition
//! boundary: it writes the standalone driver's startup document, starts the
//! driver with `--config`, and then connects through the same public
//! compute-driver RPC interface used by operator-managed external drivers.

#[cfg(unix)]
use hyper_util::rt::TokioIo;
#[cfg(unix)]
use openshell_core::proto::compute::v1::{
    GetCapabilitiesRequest, compute_driver_client::ComputeDriverClient,
};
use openshell_core::{Error, NetworkSupervisorTrustBundle, Result, UpstreamProxyConfig};
#[cfg(unix)]
use openshell_otel::TraceContextInterceptor;
use openshell_server::AcquiredRemoteDriverEndpoint;
#[cfg(unix)]
use openshell_server::ManagedDriverProcess;
use openshell_server::config_file::OtlpConfig;
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VmComputeConfig {
    pub allow_driver_config: bool,
    pub resource_admission: openshell_core::resource_admission::ResourceAdmissionConfig,
    /// Working directory for VM driver sandbox state.
    pub state_dir: PathBuf,

    /// Directory to search for compute-driver binaries before the gateway
    /// falls back to its conventional install paths and sibling binary.
    pub driver_dir: Option<PathBuf>,

    /// Default sandbox image the driver should use when a request omits one.
    pub default_image: String,

    /// Gateway gRPC endpoint the sandbox guest connects back to.
    pub grpc_endpoint: String,

    /// Bootstrap image used to boot and prepare VM sandbox target images.
    pub bootstrap_image: String,

    /// libkrun log level used by the VM driver helper.
    pub krun_log_level: u32,

    /// Default vCPU count for VM sandboxes.
    pub vcpus: u8,

    /// Default memory allocation for VM sandboxes, in MiB.
    pub mem_mib: u32,

    /// Writable overlay disk size for each VM sandbox, in MiB.
    pub overlay_disk_mib: u64,

    /// Optional UID override for the VM guest sandbox account.
    pub sandbox_uid: Option<u32>,

    /// Optional GID override for the VM guest sandbox account.
    pub sandbox_gid: Option<u32>,

    /// Directory shared with the gateway for request-scoped rootfs tar staging.
    pub rootfs_tar_staging_dir: Option<PathBuf>,

    /// Maximum accepted rootfs tar size, in bytes, before and after decompression.
    pub rootfs_tar_max_bytes: Option<u64>,

    /// Host-side CA certificate used to authenticate the gateway.
    pub guest_tls_ca: Option<PathBuf>,

    /// Corporate forward-proxy settings passed to the VM driver. Flattening
    /// preserves the shared local-driver TOML field names.
    #[serde(flatten)]
    pub upstream_proxy: UpstreamProxyConfig,

    /// Path on the gateway host to a PEM CA bundle trusted for the corporate
    /// proxy and for server certificates re-signed by a TLS-intercepting proxy.
    pub proxy_ca_bundle: Option<PathBuf>,

    /// Explicit guest-reachable SPIFFE Workload API TCP listener. VM guests
    /// cannot receive a host UNIX socket, so this requires acknowledgement.
    pub provider_spiffe_workload_api_tcp_endpoint: Option<String>,
    #[serde(default)]
    pub provider_spiffe_allow_guest_tcp: bool,

    /// Allow bind-mounting host directories into VM sandboxes.
    #[serde(default)]
    pub enable_bind_mounts: bool,
}

impl VmComputeConfig {
    /// Default working directory for VM driver state.
    #[must_use]
    pub fn default_state_dir() -> PathBuf {
        openshell_core::paths::openshell_state_dir().map_or_else(
            |_| PathBuf::from("target/openshell-vm-driver"),
            |dir| dir.join("vm-driver"),
        )
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

    /// Default writable overlay disk size, in MiB.
    #[must_use]
    pub const fn default_overlay_disk_mib() -> u64 {
        4096
    }

    /// Validate startup configuration without resolving binaries, creating
    /// state directories, spawning a process, or connecting a socket.
    pub fn validate_configuration(&self) -> Result<()> {
        self.resource_admission.validate().map_err(Error::config)?;
        if self.grpc_endpoint.trim().is_empty() {
            return Err(Error::config(
                "grpc_endpoint is required when using the vm compute driver",
            ));
        }
        if self.bootstrap_image.trim().is_empty() && self.default_image.trim().is_empty() {
            return Err(Error::config(
                "bootstrap_image or default_image is required when using the vm compute driver; sandbox images cannot be used as VM bootstrap images",
            ));
        }
        validate_vm_sandbox_identity(self)?;
        if self
            .rootfs_tar_staging_dir
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(Error::config(
                "rootfs_tar_staging_dir must not be empty when set",
            ));
        }
        if self.rootfs_tar_max_bytes == Some(0) {
            return Err(Error::config(
                "rootfs_tar_max_bytes must be greater than zero when set",
            ));
        }
        self.validate_proxy_config()?;
        if let Some(endpoint) = self.provider_spiffe_workload_api_tcp_endpoint.as_deref() {
            openshell_core::driver_utils::validate_guest_spiffe_tcp_endpoint(
                endpoint,
                self.provider_spiffe_allow_guest_tcp,
            )
            .map_err(Error::config)?;
        } else if self.provider_spiffe_allow_guest_tcp {
            return Err(Error::config(
                "provider_spiffe_allow_guest_tcp is set but no provider_spiffe_workload_api_tcp_endpoint is configured",
            ));
        }
        Ok(())
    }

    fn validate_proxy_config(&self) -> Result<()> {
        self.upstream_proxy.validate().map_err(Error::config)?;
        if let Some(path) = self.proxy_ca_bundle.as_ref() {
            if path.as_os_str().is_empty() {
                return Err(Error::config("proxy_ca_bundle must not be empty when set"));
            }
            if self.upstream_proxy.https_proxy.is_none() {
                return Err(Error::config(
                    "proxy_ca_bundle is set but no https_proxy is configured",
                ));
            }
        }
        Ok(())
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
            allow_driver_config: false,
            resource_admission:
                openshell_core::resource_admission::ResourceAdmissionConfig::default(),
            driver_dir: None,
            default_image: openshell_core::image::default_sandbox_image(),
            grpc_endpoint: String::new(),
            bootstrap_image: String::new(),
            krun_log_level: Self::default_krun_log_level(),
            vcpus: Self::default_vcpus(),
            mem_mib: Self::default_mem_mib(),
            overlay_disk_mib: Self::default_overlay_disk_mib(),
            sandbox_uid: None,
            sandbox_gid: None,
            rootfs_tar_staging_dir: None,
            rootfs_tar_max_bytes: None,
            guest_tls_ca: None,
            upstream_proxy: UpstreamProxyConfig::default(),
            proxy_ca_bundle: None,
            provider_spiffe_workload_api_tcp_endpoint: None,
            provider_spiffe_allow_guest_tcp: false,
            enable_bind_mounts: false,
        }
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmGuestTlsPaths {
    pub ca: PathBuf,
}

/// Resolve the `openshell-driver-vm` binary path.
///
/// Resolution order:
/// 1. `{driver_dir}/openshell-driver-vm`, where `driver_dir` comes from
///    `[openshell.drivers.vm].driver_dir`.
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
        "vm compute driver binary not found (searched {searched_display}); install it under [openshell.drivers.vm].driver_dir, a conventional libexec path such as ~/.local/libexec/openshell, /usr/libexec/openshell, or /usr/local/libexec{{,/openshell}}, or place it next to the gateway binary"
    )))
}

fn resolve_driver_search_dirs(vm_config: &VmComputeConfig) -> Vec<PathBuf> {
    vm_config.driver_dir.clone().map_or_else(
        || {
            let mut dirs = Vec::new();
            if let Ok(current_exe) = std::env::current_exe()
                && let Some(prefix) = current_exe.parent().and_then(Path::parent)
            {
                push_unique_path(&mut dirs, prefix.join("libexec"));
                push_unique_path(&mut dirs, prefix.join("libexec").join("openshell"));
            }
            for dir in VmComputeConfig::default_driver_search_dirs(
                std::env::var_os("HOME").map(PathBuf::from),
            ) {
                push_unique_path(&mut dirs, dir);
            }
            dirs
        },
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
    rustix::process::geteuid().as_raw()
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
    if mode != 0o700 {
        std::fs::set_permissions(state_dir, std::fs::Permissions::from_mode(0o700)).map_err(
            |err| {
                Error::execution(format!(
                    "failed to restrict vm driver state dir '{}': {err}",
                    state_dir.display()
                ))
            },
        )?;
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
    vm_config: &VmComputeConfig,
) -> Result<Option<VmGuestTlsPaths>> {
    if !vm_config.grpc_endpoint.starts_with("https://") {
        return Ok(None);
    }

    if vm_config.guest_tls_ca.is_none() {
        return Err(Error::config(
            "vm compute driver requires guest_tls_ca when grpc_endpoint uses https://",
        ));
    }

    let Some(ca) = vm_config.guest_tls_ca.clone() else {
        return Err(Error::config(
            "guest_tls_ca is required when VM guest TLS materials are configured",
        ));
    };
    for path in [&ca] {
        if !path.is_file() {
            return Err(Error::config(format!(
                "vm guest TLS material '{}' does not exist or is not a file",
                path.display()
            )));
        }
    }

    Ok(Some(VmGuestTlsPaths { ca }))
}

/// Launch the VM compute-driver subprocess, wait for its UDS to come up,
/// and return a gRPC `Channel` connected to it plus a process handle that
/// kills the subprocess and removes the socket on drop.
#[cfg(unix)]
pub async fn spawn(
    gateway_log_level: &str,
    gateway_name: &str,
    vm_config: &VmComputeConfig,
    otlp_config: Option<&OtlpConfig>,
    additional_ca_bundle: Option<&NetworkSupervisorTrustBundle>,
) -> Result<AcquiredRemoteDriverEndpoint> {
    vm_config.validate_configuration()?;
    let driver_bin = resolve_compute_driver_bin(vm_config)?;
    let socket_path = compute_driver_socket_path(vm_config);
    let guest_tls_paths = compute_driver_guest_tls_paths(vm_config)?;
    prepare_compute_driver_socket_path(vm_config, &socket_path)?;

    let startup_path = startup_document_path(&socket_path);
    let document = vm_startup_document(
        gateway_log_level,
        gateway_name,
        vm_config,
        otlp_config,
        additional_ca_bundle,
        &socket_path,
        guest_tls_paths.as_ref().map(|tls| tls.ca.as_path()),
    )?;
    write_startup_document(&startup_path, &document)?;

    let mut command = Command::new(&driver_bin);
    command.kill_on_drop(true);
    command.stdin(Stdio::null());
    command.stdout(Stdio::inherit());
    command.stderr(Stdio::inherit());
    command.arg("--config").arg(&startup_path);
    apply_trace_headers_env(&mut command, otlp_config);

    let mut child = command.spawn().map_err(|e| {
        remove_startup_document(&startup_path);
        Error::execution(format!(
            "failed to launch vm compute driver '{}': {e}",
            driver_bin.display()
        ))
    })?;
    let ready = wait_for_compute_driver(&socket_path, &mut child).await;
    // The driver reads the document before it binds its socket, so it is no
    // longer needed once the driver is ready or has failed.
    remove_startup_document(&startup_path);
    let channel = ready?;
    let process = Arc::new(ManagedDriverProcess::new(child, socket_path));
    Ok(AcquiredRemoteDriverEndpoint::managed(
        "vm", channel, process,
    ))
}

fn validate_vm_sandbox_identity(config: &VmComputeConfig) -> Result<()> {
    let range = openshell_policy::MIN_SANDBOX_UID..=openshell_policy::MAX_SANDBOX_UID;
    for (field, value) in [
        ("sandbox_uid", config.sandbox_uid),
        ("sandbox_gid", config.sandbox_gid),
    ] {
        if let Some(value) = value
            && !range.contains(&value)
        {
            return Err(Error::config(format!(
                "{field} {value} is outside the allowed range [{}, {}]",
                openshell_policy::MIN_SANDBOX_UID,
                openshell_policy::MAX_SANDBOX_UID
            )));
        }
    }
    Ok(())
}

/// File name of the startup document, written beside the driver socket in its
/// private run directory.
#[cfg(unix)]
const STARTUP_DOCUMENT_NAME: &str = "startup.toml";

/// `VmComputeConfig` keys that the startup document carries in its gateway
/// context, or that the launcher consumes, instead of in `[driver_config]`.
#[cfg(unix)]
const GATEWAY_OWNED_KEYS: &[&str] = &[
    "allow_driver_config",
    "resource_admission",
    "driver_dir",
    "grpc_endpoint",
    "guest_tls_ca",
    "https_proxy",
    "no_proxy",
    "proxy_auth_file",
    "proxy_auth_allow_insecure",
    "proxy_connect_by_hostname",
    "proxy_ca_bundle",
];

#[cfg(unix)]
fn startup_document_path(socket_path: &Path) -> PathBuf {
    socket_path.with_file_name(STARTUP_DOCUMENT_NAME)
}

/// The VM driver's `[driver_config]` table: the VM-specific settings, without
/// the ones the gateway context carries.
#[cfg(unix)]
fn vm_driver_config_table(config: &VmComputeConfig) -> Result<toml::Table> {
    let mut table =
        toml::Table::try_from(config).map_err(|error| Error::config(error.to_string()))?;
    for key in GATEWAY_OWNED_KEYS {
        table.remove(*key);
    }
    for key in ["default_image", "bootstrap_image"] {
        if table
            .get(key)
            .and_then(toml::Value::as_str)
            .is_some_and(|value| value.trim().is_empty())
        {
            table.remove(key);
        }
    }
    Ok(table)
}

#[cfg(unix)]
fn vm_startup_document(
    gateway_log_level: &str,
    gateway_name: &str,
    vm_config: &VmComputeConfig,
    otlp_config: Option<&OtlpConfig>,
    additional_ca_bundle: Option<&NetworkSupervisorTrustBundle>,
    socket_path: &Path,
    tls_ca: Option<&Path>,
) -> Result<openshell_driver_sdk::StartupDocument> {
    let admission = openshell_core::resource_admission::DriverAdmissionConfig {
        allow_driver_config: vm_config.allow_driver_config,
        resource_admission: vm_config.resource_admission.clone(),
    };
    crate::startup_document::GatewayStartup {
        bind_socket: socket_path,
        log_level: gateway_log_level,
        gateway_name,
        grpc_endpoint: &vm_config.grpc_endpoint,
        tls_ca,
        admission: &admission,
        otlp: otlp_config,
        upstream_proxy: &vm_config.upstream_proxy,
        proxy_ca_bundle: vm_config.proxy_ca_bundle.as_deref(),
        network_trust: additional_ca_bundle,
    }
    .into_document(vm_driver_config_table(vm_config)?)
}

/// Write the document with mode 0600. The run directory is private (0700), so
/// the file is not readable by other users.
#[cfg(unix)]
fn write_startup_document(
    path: &Path,
    document: &openshell_driver_sdk::StartupDocument,
) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let text = document
        .to_toml()
        .map_err(|error| Error::config(error.to_string()))?;
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(Error::execution(format!(
                "failed to remove stale startup document '{}': {error}",
                path.display()
            )));
        }
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut file| file.write_all(text.as_bytes()))
        .map_err(|error| {
            Error::execution(format!(
                "failed to write startup document '{}': {error}",
                path.display()
            ))
        })
}

#[cfg(unix)]
fn remove_startup_document(path: &Path) {
    let _ = std::fs::remove_file(path);
}

/// The driver's own trace exporter reads these headers like any OTLP SDK.
/// They stay in the environment so they never reach the startup document or
/// process listings.
#[cfg(unix)]
fn apply_trace_headers_env(command: &mut Command, otlp_config: Option<&OtlpConfig>) {
    if let Some(headers) = openshell_server::gateway_trace_headers(otlp_config) {
        command.env("OTEL_EXPORTER_OTLP_TRACES_HEADERS", headers.expose_secret());
    }
}

#[cfg(not(unix))]
pub async fn spawn(
    _gateway_log_level: &str,
    _gateway_name: &str,
    _vm_config: &VmComputeConfig,
    _otlp_config: Option<&OtlpConfig>,
    _additional_ca_bundle: Option<&NetworkSupervisorTrustBundle>,
) -> Result<AcquiredRemoteDriverEndpoint> {
    Err(Error::config(
        "the vm compute driver requires unix domain socket support",
    ))
}

#[cfg(unix)]
#[tracing::instrument(
    name = "driver.wait_for_ready",
    skip_all,
    fields(
        otel.name = "driver.wait_for_ready",
        otel.status_code = tracing::field::Empty,
        driver.name = "vm",
    )
)]
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
                let mut client =
                    ComputeDriverClient::with_interceptor(channel.clone(), TraceContextInterceptor);
                match client
                    .get_capabilities(tonic::Request::new(GetCapabilitiesRequest {
                        gateway: Some(openshell_core::extension_protocol::gateway_metadata(
                            openshell_core::extension_protocol::ExtensionFamily::Compute,
                        )),
                    }))
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
        VmComputeConfig, apply_trace_headers_env, compute_driver_guest_tls_paths,
        compute_driver_socket_path, current_euid, prepare_compute_driver_socket_path,
        prepare_vm_state_dir, resolve_compute_driver_bin, resolve_driver_search_dirs,
        startup_document_path, validate_vm_sandbox_identity, vm_driver_config_table,
        vm_startup_document, write_startup_document,
    };
    use openshell_core::sandbox_env::OtlpProtocol;
    use openshell_core::{NetworkSupervisorTrustBundle, UpstreamProxyConfig};
    use openshell_server::config_file::{
        AgentOtlpConfig, OcsfOtlpConfig, OtlpCollectorConfig, OtlpConfig, OtlpTracesConfig,
    };
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener as StdUnixListener;
    use std::path::{Path, PathBuf};
    use tempfile::tempdir;

    /// A `VmComputeConfig` with every setting populated, matching the VM
    /// startup fixture.
    fn populated_vm_config() -> VmComputeConfig {
        VmComputeConfig {
            allow_driver_config: true,
            resource_admission: openshell_core::resource_admission::ResourceAdmissionConfig {
                enabled: true,
                required_labels: [(
                    "openshell.ai/sandbox-attachable".to_string(),
                    "true".to_string(),
                )]
                .into(),
            },
            state_dir: PathBuf::from("/var/lib/openshell/vm"),
            driver_dir: Some(PathBuf::from("/usr/libexec/openshell")),
            default_image: "openshell/sandbox:default".into(),
            grpc_endpoint: "https://127.0.0.1:8080".into(),
            bootstrap_image: "openshell/sandbox-bootstrap:latest".into(),
            krun_log_level: 2,
            vcpus: 4,
            mem_mib: 4096,
            overlay_disk_mib: 8192,
            sandbox_uid: Some(2000),
            sandbox_gid: Some(3000),
            rootfs_tar_staging_dir: Some(PathBuf::from("/var/lib/openshell/rootfs-staging")),
            rootfs_tar_max_bytes: Some(1_073_741_824),
            guest_tls_ca: Some(PathBuf::from("/etc/openshell/tls/ca.pem")),
            upstream_proxy: UpstreamProxyConfig {
                https_proxy: Some("http://proxy.example:3128".into()),
                no_proxy: Some("localhost,127.0.0.1".into()),
                proxy_auth_file: Some("/etc/openshell/proxy-auth".into()),
                proxy_auth_allow_insecure: Some(true),
                proxy_connect_by_hostname: Some(true),
            },
            proxy_ca_bundle: Some(PathBuf::from("/etc/openshell/proxy-ca.pem")),
            provider_spiffe_workload_api_tcp_endpoint: Some("tcp:10.0.0.5:8081".into()),
            provider_spiffe_allow_guest_tcp: true,
            enable_bind_mounts: true,
        }
    }

    /// The document the gateway writes for a fully configured VM driver is the
    /// one the driver's own overlay test reads, so a setting either side stops
    /// writing or reading fails a test.
    #[test]
    fn a_fully_configured_vm_gateway_writes_the_documented_startup_document() {
        let dir = tempdir().unwrap();
        let certified = rcgen::generate_simple_self_signed(vec!["collector".into()]).unwrap();
        let [ca, cert, key] = ["ca.pem", "client.pem", "client-key.pem"].map(|name| {
            let path = dir.path().join(name);
            let pem = if name == "client-key.pem" {
                certified.signing_key.serialize_pem()
            } else {
                certified.cert.pem()
            };
            std::fs::write(&path, pem).unwrap();
            path
        });
        let otlp = OtlpConfig {
            metrics: None,
            service_name: None,
            traces: Some(OtlpTracesConfig {
                collector: OtlpCollectorConfig::new(
                    "https://collector.example:4317",
                    OtlpProtocol::Grpc,
                )
                .with_tls_files(Some(ca), Some(cert), Some(key))
                .unwrap(),
            }),
            ocsf: Some(OcsfOtlpConfig {
                collector: OtlpCollectorConfig::new(
                    "https://collector.example:4318",
                    OtlpProtocol::HttpProtobuf,
                ),
                schema_version: None,
            }),
            agent: Some(AgentOtlpConfig {
                collector: OtlpCollectorConfig::new(
                    "https://collector.example:4319",
                    OtlpProtocol::Grpc,
                ),
            }),
        };
        let trust = NetworkSupervisorTrustBundle::new(
            b"pem".to_vec(),
            3,
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            PathBuf::from("/var/lib/openshell/trust/bundle.pem"),
        );
        let config = populated_vm_config();

        let mut document = vm_startup_document(
            "debug",
            "gateway-a",
            &config,
            Some(&otlp),
            Some(&trust),
            Path::new("/var/lib/openshell/vm/run/compute-driver.sock"),
            config.guest_tls_ca.as_deref(),
        )
        .unwrap();

        document.gateway.expected_peer_pid = 4242;
        let tls = document.gateway.telemetry.collector.as_mut().unwrap();
        tls.ca_file = Some("/etc/openshell/otlp/ca.pem".into());
        tls.cert_file = Some("/etc/openshell/otlp/cert.pem".into());
        tls.key_file = Some("/etc/openshell/otlp/key.pem".into());

        let fixture = openshell_driver_sdk::StartupDocument::parse(include_str!(
            "../../openshell-driver-vm/tests/fixtures/startup-vm.toml"
        ))
        .unwrap();
        assert_eq!(document, fixture);
    }

    #[test]
    fn vm_driver_config_table_omits_gateway_owned_and_blank_settings() {
        let table = vm_driver_config_table(&populated_vm_config()).unwrap();
        for owned in super::GATEWAY_OWNED_KEYS {
            assert!(
                !table.contains_key(*owned),
                "{owned} belongs to the gateway context"
            );
        }

        let blank = vm_driver_config_table(&VmComputeConfig {
            default_image: " ".into(),
            bootstrap_image: String::new(),
            ..populated_vm_config()
        })
        .unwrap();
        assert!(!blank.contains_key("default_image"));
        assert!(!blank.contains_key("bootstrap_image"));
    }

    #[test]
    fn the_startup_document_is_private_and_carries_no_proxy_credentials() {
        let dir = tempdir().unwrap();
        let socket = dir.path().join("compute-driver.sock");
        let path = startup_document_path(&socket);
        assert_eq!(path, dir.path().join("startup.toml"));

        let document = vm_startup_document(
            "info",
            "gateway",
            &populated_vm_config(),
            None,
            None,
            &socket,
            None,
        )
        .unwrap();
        write_startup_document(&path, &document).unwrap();
        // Rewriting replaces a stale file instead of failing on it.
        write_startup_document(&path, &document).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("/etc/openshell/proxy-auth"),
            "the credential file path is referenced"
        );
        assert!(!text.contains("user:pass"));
    }

    #[test]
    fn vm_uses_nvidia_ubuntu_default_image() {
        assert_eq!(
            VmComputeConfig::default().default_image,
            openshell_core::image::DEFAULT_SANDBOX_BASE_IMAGE
        );
    }

    #[test]
    fn vm_gateway_requires_a_trusted_bootstrap_image_source() {
        let config = VmComputeConfig {
            grpc_endpoint: "http://127.0.0.1:50051".to_string(),
            default_image: String::new(),
            bootstrap_image: String::new(),
            ..Default::default()
        };
        let error = config
            .validate_configuration()
            .expect_err("the gateway must reject an empty bootstrap configuration");
        assert!(error.to_string().contains("sandbox images cannot be used"));

        VmComputeConfig {
            default_image: "openshell/sandbox:default".to_string(),
            ..config.clone()
        }
        .validate_configuration()
        .expect("the operator-controlled default image is a valid fallback");

        VmComputeConfig {
            bootstrap_image: "openshell/sandbox-bootstrap:latest".to_string(),
            ..config
        }
        .validate_configuration()
        .expect("an explicit bootstrap image is valid");
    }

    #[test]
    fn vm_driver_receives_trace_headers_in_its_environment_only() {
        crate::test_environment::Environment::new()
            .remove("OTEL_EXPORTER_OTLP_HEADERS")
            .remove("OTEL_EXPORTER_OTLP_TRACES_HEADERS")
            .run(|| {
                let otlp: OtlpConfig = toml::from_str(
                    "endpoint = 'http://collector.internal:4318'\n\
                 headers = { authorization = 'Bearer secret-token' }\n",
                )
                .unwrap();
                let mut command = tokio::process::Command::new("openshell-driver-vm");
                apply_trace_headers_env(&mut command, Some(&otlp));

                let env = command
                    .as_std()
                    .get_envs()
                    .find(|(name, _)| *name == "OTEL_EXPORTER_OTLP_TRACES_HEADERS")
                    .and_then(|(_, value)| value)
                    .map(|value| value.to_string_lossy().into_owned());
                assert_eq!(env.as_deref(), Some("authorization=Bearer%20secret-token"));
                assert!(
                    command
                        .as_std()
                        .get_args()
                        .all(|arg| !arg.to_string_lossy().contains("secret-token"))
                );
            });
    }

    #[test]
    fn invalid_corporate_proxy_config_is_rejected_before_the_driver_starts() {
        let err = UpstreamProxyConfig {
            https_proxy: Some("socks5://proxy.corp.com:1080".to_string()),
            ..Default::default()
        }
        .validate()
        .expect_err("only http:// and https:// proxies are supported");
        assert!(err.contains("https_proxy"), "{err}");

        VmComputeConfig {
            proxy_ca_bundle: Some(PathBuf::from("/etc/openshell/tls/proxy-ca.pem")),
            ..Default::default()
        }
        .validate_proxy_config()
        .expect_err("a CA bundle without a proxy URL must fail closed");

        VmComputeConfig {
            upstream_proxy: UpstreamProxyConfig {
                https_proxy: Some("http://proxy.corp.com:8080".to_string()),
                ..Default::default()
            },
            ..Default::default()
        }
        .validate_proxy_config()
        .expect("a lone proxy URL is a complete configuration");
    }

    #[test]
    fn vm_gateway_toml_accepts_rootfs_tar_settings() {
        let config: VmComputeConfig = toml::from_str(
            r#"
                grpc_endpoint = "http://127.0.0.1:50051"
                rootfs_tar_staging_dir = "/var/lib/openshell/rootfs-tar-staging"
                rootfs_tar_max_bytes = 1073741824
            "#,
        )
        .expect("schema-v2 VM rootfs tar settings must deserialize");
        config
            .validate_configuration()
            .expect("rootfs tar settings must pass static validation");
        let table = vm_driver_config_table(&config).unwrap();
        assert_eq!(
            table["rootfs_tar_staging_dir"].as_str(),
            Some("/var/lib/openshell/rootfs-tar-staging")
        );
        assert_eq!(
            table["rootfs_tar_max_bytes"].as_integer(),
            Some(1_073_741_824)
        );
    }

    #[test]
    fn vm_gateway_rejects_zero_rootfs_tar_limit() {
        let config = VmComputeConfig {
            grpc_endpoint: "http://127.0.0.1:50051".to_string(),
            rootfs_tar_max_bytes: Some(0),
            ..Default::default()
        };

        let error = config
            .validate_configuration()
            .expect_err("a zero rootfs tar limit must fail before driver startup");
        assert!(error.to_string().contains("rootfs_tar_max_bytes"));
    }

    #[test]
    fn vm_gateway_config_rejects_root_identity() {
        let config = VmComputeConfig {
            sandbox_uid: Some(0),
            ..Default::default()
        };
        let error = validate_vm_sandbox_identity(&config).expect_err("root UID must fail");
        assert!(error.to_string().contains("sandbox_uid 0"));
    }

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
        assert!(err.contains("[openshell.drivers.vm].driver_dir"));
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
        let vm_config = VmComputeConfig {
            grpc_endpoint: "https://gateway.internal:8443".to_string(),
            ..Default::default()
        };

        let err = compute_driver_guest_tls_paths(&vm_config)
            .expect_err("https vm endpoints should require an explicit gateway CA");
        assert!(err.to_string().contains("guest_tls_ca"));
    }

    #[test]
    fn vm_compute_driver_tls_uses_only_gateway_ca() {
        let dir = tempdir().unwrap();
        let guest_ca = dir.path().join("guest-ca.crt");
        std::fs::write(&guest_ca, guest_ca.display().to_string()).unwrap();

        let vm_config = VmComputeConfig {
            grpc_endpoint: "https://gateway.internal:8443".to_string(),
            guest_tls_ca: Some(guest_ca.clone()),
            ..Default::default()
        };

        let guest_paths = compute_driver_guest_tls_paths(&vm_config)
            .unwrap()
            .expect("https vm endpoints should pass an explicit gateway CA");
        assert_eq!(guest_paths.ca, guest_ca);
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
    fn prepare_compute_driver_socket_path_restricts_existing_state_dir() {
        let dir = tempdir().unwrap();
        let vm_config = VmComputeConfig {
            state_dir: dir.path().join("state"),
            ..Default::default()
        };
        std::fs::create_dir_all(&vm_config.state_dir).unwrap();
        std::fs::set_permissions(&vm_config.state_dir, std::fs::Permissions::from_mode(0o777))
            .unwrap();
        let socket_path = compute_driver_socket_path(&vm_config);

        prepare_compute_driver_socket_path(&vm_config, &socket_path).unwrap();

        let mode = std::fs::metadata(vm_config.state_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
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
