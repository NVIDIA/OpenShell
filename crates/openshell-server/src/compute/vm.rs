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
//! are genuinely VM-specific (hypervisor helper log level, vCPU / memory shape) plus a
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
use std::ffi::OsString;
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
#[cfg(unix)]
const VM_DRIVER_CONFIG_ENV_VARS: &[&str] = &[
    "OPENSHELL_GRPC_ENDPOINT",
    "OPENSHELL_SANDBOX_IMAGE",
    "OPENSHELL_VM_BOOTSTRAP_IMAGE",
    "OPENSHELL_VM_DRIVER_STATE_DIR",
    "OPENSHELL_VM_HYPERVISOR_LOG_LEVEL",
    "OPENSHELL_VM_KRUN_LOG_LEVEL",
    "OPENSHELL_VM_DRIVER_VCPUS",
    "OPENSHELL_VM_DRIVER_MEM_MIB",
    "OPENSHELL_VM_OVERLAY_DISK_MIB",
    "OPENSHELL_VM_GPU",
    "OPENSHELL_VM_GPU_MEM_MIB",
    "OPENSHELL_VM_GPU_VCPUS",
    "OPENSHELL_VM_TLS_CA",
    "OPENSHELL_VM_TLS_CERT",
    "OPENSHELL_VM_TLS_KEY",
];

/// Configuration for launching and talking to the VM compute driver.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VmComputeConfig {
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

    /// Hypervisor helper log level used by the VM driver.
    #[serde(alias = "krun_log_level")]
    pub hypervisor_log_level: u32,

    /// Default vCPU count for VM sandboxes.
    pub vcpus: u8,

    /// Default memory allocation for VM sandboxes, in MiB.
    pub mem_mib: u32,

    /// Writable overlay disk size for each VM sandbox, in MiB.
    pub overlay_disk_mib: u64,

    /// Host-side CA certificate for the guest's mTLS client bundle.
    pub guest_tls_ca: Option<PathBuf>,

    /// Host-side client certificate for the guest's mTLS client bundle.
    pub guest_tls_cert: Option<PathBuf>,

    /// Host-side private key for the guest's mTLS client bundle.
    pub guest_tls_key: Option<PathBuf>,

    /// Enable host GPU passthrough support in the VM driver.
    pub gpu_enabled: bool,

    /// Memory allocation for GPU VM sandboxes, in MiB.
    pub gpu_mem_mib: u32,

    /// vCPU count for GPU VM sandboxes.
    pub gpu_vcpus: u8,
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

    /// Default hypervisor helper log level.
    #[must_use]
    pub const fn default_hypervisor_log_level() -> u32 {
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

    /// Default memory allocation for GPU VM sandboxes, in MiB.
    #[must_use]
    pub const fn default_gpu_mem_mib() -> u32 {
        8192
    }

    /// Default vCPU count for GPU VM sandboxes.
    #[must_use]
    pub const fn default_gpu_vcpus() -> u8 {
        4
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
            default_image: openshell_core::image::default_sandbox_image(),
            grpc_endpoint: String::new(),
            bootstrap_image: String::new(),
            hypervisor_log_level: Self::default_hypervisor_log_level(),
            vcpus: Self::default_vcpus(),
            mem_mib: Self::default_mem_mib(),
            overlay_disk_mib: Self::default_overlay_disk_mib(),
            guest_tls_ca: None,
            guest_tls_cert: None,
            guest_tls_key: None,
            gpu_enabled: false,
            gpu_mem_mib: Self::default_gpu_mem_mib(),
            gpu_vcpus: Self::default_gpu_vcpus(),
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

    let provided = [
        vm_config.guest_tls_ca.as_ref(),
        vm_config.guest_tls_cert.as_ref(),
        vm_config.guest_tls_key.as_ref(),
    ];
    if provided.iter().all(Option::is_none) {
        return Err(Error::config(
            "vm compute driver requires guest_tls_ca, guest_tls_cert, and guest_tls_key when grpc_endpoint uses https://",
        ));
    }

    let Some(ca) = vm_config.guest_tls_ca.clone() else {
        return Err(Error::config(
            "guest_tls_ca is required when VM guest TLS materials are configured",
        ));
    };
    let Some(cert) = vm_config.guest_tls_cert.clone() else {
        return Err(Error::config(
            "guest_tls_cert is required when VM guest TLS materials are configured",
        ));
    };
    let Some(key) = vm_config.guest_tls_key.clone() else {
        return Err(Error::config(
            "guest_tls_key is required when VM guest TLS materials are configured",
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

#[cfg(unix)]
fn vm_config_with_env_overrides(vm_config: &VmComputeConfig) -> Result<VmComputeConfig> {
    let mut cfg = vm_config.clone();

    if let Some(endpoint) = env_string("OPENSHELL_GRPC_ENDPOINT")? {
        cfg.grpc_endpoint = endpoint;
    }
    if let Some(image) = env_string("OPENSHELL_SANDBOX_IMAGE")? {
        cfg.default_image = image;
    }
    if let Some(image) = env_string("OPENSHELL_VM_BOOTSTRAP_IMAGE")? {
        cfg.bootstrap_image = image;
    }
    if let Some(path) = std::env::var_os("OPENSHELL_VM_DRIVER_STATE_DIR") {
        cfg.state_dir = PathBuf::from(path);
    }
    if let Some(value) = env_parse("OPENSHELL_VM_HYPERVISOR_LOG_LEVEL")? {
        cfg.hypervisor_log_level = value;
    } else if let Some(value) = env_parse("OPENSHELL_VM_KRUN_LOG_LEVEL")? {
        cfg.hypervisor_log_level = value;
    }
    if let Some(value) = env_parse("OPENSHELL_VM_DRIVER_VCPUS")? {
        cfg.vcpus = value;
    }
    if let Some(value) = env_parse("OPENSHELL_VM_DRIVER_MEM_MIB")? {
        cfg.mem_mib = value;
    }
    if let Some(value) = env_parse("OPENSHELL_VM_OVERLAY_DISK_MIB")? {
        cfg.overlay_disk_mib = value;
    }
    if let Some(value) = env_bool("OPENSHELL_VM_GPU")? {
        cfg.gpu_enabled = value;
    }
    if let Some(value) = env_parse("OPENSHELL_VM_GPU_MEM_MIB")? {
        cfg.gpu_mem_mib = value;
    }
    if let Some(value) = env_parse("OPENSHELL_VM_GPU_VCPUS")? {
        cfg.gpu_vcpus = value;
    }
    if let Some(path) = std::env::var_os("OPENSHELL_VM_TLS_CA") {
        cfg.guest_tls_ca = Some(PathBuf::from(path));
    }
    if let Some(path) = std::env::var_os("OPENSHELL_VM_TLS_CERT") {
        cfg.guest_tls_cert = Some(PathBuf::from(path));
    }
    if let Some(path) = std::env::var_os("OPENSHELL_VM_TLS_KEY") {
        cfg.guest_tls_key = Some(PathBuf::from(path));
    }

    if cfg.state_dir.as_os_str().is_empty() {
        cfg.state_dir = VmComputeConfig::default_state_dir();
    }

    Ok(cfg)
}

#[cfg(unix)]
fn env_string(name: &'static str) -> Result<Option<String>> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(Error::config(format!("{name} must be valid UTF-8")))
        }
    }
}

#[cfg(unix)]
fn env_parse<T>(name: &'static str) -> Result<Option<T>>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let Some(value) = env_string(name)? else {
        return Ok(None);
    };
    value
        .parse::<T>()
        .map(Some)
        .map_err(|err| Error::config(format!("invalid {name} value '{value}': {err}")))
}

#[cfg(unix)]
fn env_bool(name: &'static str) -> Result<Option<bool>> {
    let Some(value) = env_string(name)? else {
        return Ok(None);
    };
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(Some(true)),
        "0" | "false" | "no" | "off" => Ok(Some(false)),
        _ => Err(Error::config(format!(
            "invalid {name} value '{value}': expected true or false"
        ))),
    }
}

#[cfg(unix)]
fn compute_driver_args(
    config: &Config,
    vm_config: &VmComputeConfig,
    socket_path: &Path,
    expected_peer_pid: u32,
    guest_tls_paths: Option<&VmGuestTlsPaths>,
) -> Vec<OsString> {
    let mut args = vec![
        OsString::from("--bind-socket"),
        socket_path.as_os_str().to_os_string(),
        OsString::from("--expected-peer-pid"),
        OsString::from(expected_peer_pid.to_string()),
        OsString::from("--log-level"),
        OsString::from(&config.log_level),
        OsString::from("--openshell-endpoint"),
        OsString::from(&vm_config.grpc_endpoint),
        OsString::from("--state-dir"),
        vm_config.state_dir.as_os_str().to_os_string(),
    ];

    if !vm_config.default_image.trim().is_empty() {
        args.push(OsString::from("--default-image"));
        args.push(OsString::from(&vm_config.default_image));
    }
    if !vm_config.bootstrap_image.trim().is_empty() {
        args.push(OsString::from("--bootstrap-image"));
        args.push(OsString::from(&vm_config.bootstrap_image));
    }

    args.push(OsString::from("--krun-log-level"));
    args.push(OsString::from(vm_config.hypervisor_log_level.to_string()));
    args.push(OsString::from("--vcpus"));
    args.push(OsString::from(vm_config.vcpus.to_string()));
    args.push(OsString::from("--mem-mib"));
    args.push(OsString::from(vm_config.mem_mib.to_string()));
    args.push(OsString::from("--overlay-disk-mib"));
    args.push(OsString::from(vm_config.overlay_disk_mib.to_string()));

    if vm_config.gpu_enabled {
        args.push(OsString::from("--gpu"));
    }
    args.push(OsString::from("--gpu-mem-mib"));
    args.push(OsString::from(vm_config.gpu_mem_mib.to_string()));
    args.push(OsString::from("--gpu-vcpus"));
    args.push(OsString::from(vm_config.gpu_vcpus.to_string()));

    if let Some(tls) = guest_tls_paths {
        args.push(OsString::from("--guest-tls-ca"));
        args.push(tls.ca.as_os_str().to_os_string());
        args.push(OsString::from("--guest-tls-cert"));
        args.push(tls.cert.as_os_str().to_os_string());
        args.push(OsString::from("--guest-tls-key"));
        args.push(tls.key.as_os_str().to_os_string());
    }

    args
}

/// Launch the VM compute-driver subprocess, wait for its UDS to come up,
/// and return a gRPC `Channel` connected to it plus a process handle that
/// kills the subprocess and removes the socket on drop.
#[cfg(unix)]
pub async fn spawn(
    config: &Config,
    vm_config: &VmComputeConfig,
) -> Result<(Channel, Arc<ManagedDriverProcess>)> {
    let vm_config = vm_config_with_env_overrides(vm_config)?;
    if vm_config.grpc_endpoint.trim().is_empty() {
        return Err(Error::config(
            "grpc_endpoint is required when using the vm compute driver",
        ));
    }

    let driver_bin = resolve_compute_driver_bin(&vm_config)?;
    let socket_path = compute_driver_socket_path(&vm_config);
    let guest_tls_paths = compute_driver_guest_tls_paths(&vm_config)?;
    prepare_compute_driver_socket_path(&vm_config, &socket_path)?;

    let mut command = Command::new(&driver_bin);
    command.kill_on_drop(true);
    command.stdin(Stdio::null());
    command.stdout(Stdio::inherit());
    command.stderr(Stdio::inherit());
    for key in VM_DRIVER_CONFIG_ENV_VARS {
        command.env_remove(key);
    }
    for arg in compute_driver_args(
        config,
        &vm_config,
        &socket_path,
        std::process::id(),
        guest_tls_paths.as_ref(),
    ) {
        command.arg(arg);
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
        VM_DRIVER_CONFIG_ENV_VARS, VmComputeConfig, compute_driver_args,
        compute_driver_guest_tls_paths, compute_driver_socket_path, current_euid,
        prepare_compute_driver_socket_path, prepare_vm_state_dir, resolve_compute_driver_bin,
        resolve_driver_search_dirs, vm_config_with_env_overrides,
    };
    use crate::TEST_ENV_LOCK as ENV_LOCK;
    use openshell_core::Config;
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener as StdUnixListener;
    use std::path::{Path, PathBuf};
    use tempfile::tempdir;

    fn args_to_strings(args: Vec<OsString>) -> Vec<String> {
        args.into_iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    fn arg_value(args: &[String], flag: &str) -> Option<String> {
        args.windows(2)
            .find(|window| window[0] == flag)
            .map(|window| window[1].clone())
    }

    struct EnvVarGuard {
        key: &'static str,
        original: Option<OsString>,
    }

    impl EnvVarGuard {
        #[allow(unsafe_code)]
        fn set(key: &'static str, value: &str) -> Self {
            let original = std::env::var_os(key);
            // SAFETY: tests serialize environment mutation with ENV_LOCK.
            unsafe { std::env::set_var(key, value) };
            Self { key, original }
        }

        #[allow(unsafe_code)]
        fn remove(key: &'static str) -> Self {
            let original = std::env::var_os(key);
            // SAFETY: tests serialize environment mutation with ENV_LOCK.
            unsafe { std::env::remove_var(key) };
            Self { key, original }
        }
    }

    impl Drop for EnvVarGuard {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            match self.original.as_ref() {
                // SAFETY: tests serialize environment mutation with ENV_LOCK.
                Some(value) => unsafe { std::env::set_var(self.key, value) },
                // SAFETY: tests serialize environment mutation with ENV_LOCK.
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    fn remove_vm_env_overrides() -> Vec<EnvVarGuard> {
        VM_DRIVER_CONFIG_ENV_VARS
            .iter()
            .map(|key| EnvVarGuard::remove(key))
            .collect()
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
    fn vm_compute_config_deserializes_gpu_fields() {
        let cfg: VmComputeConfig = toml::from_str(
            r"
gpu_enabled = true
gpu_mem_mib = 12288
gpu_vcpus = 6
",
        )
        .unwrap();

        assert!(cfg.gpu_enabled);
        assert_eq!(cfg.gpu_mem_mib, 12288);
        assert_eq!(cfg.gpu_vcpus, 6);
    }

    #[test]
    fn vm_compute_config_deserializes_hypervisor_log_level_aliases() {
        let cfg: VmComputeConfig = toml::from_str("hypervisor_log_level = 4").unwrap();
        assert_eq!(cfg.hypervisor_log_level, 4);

        let legacy: VmComputeConfig = toml::from_str("krun_log_level = 2").unwrap();
        assert_eq!(legacy.hypervisor_log_level, 2);
    }

    #[test]
    fn vm_compute_config_rejects_unknown_fields() {
        let err = toml::from_str::<VmComputeConfig>(
            r"
unknown_vm_field = true
",
        )
        .expect_err("unknown fields should be rejected");

        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn vm_config_env_overrides_apply_to_effective_spawn_config() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _env = remove_vm_env_overrides();
        let _g1 = EnvVarGuard::set("OPENSHELL_GRPC_ENDPOINT", "http://env-gateway:17670");
        let _g2 = EnvVarGuard::set("OPENSHELL_SANDBOX_IMAGE", "env-sandbox:latest");
        let _g3 = EnvVarGuard::set("OPENSHELL_VM_BOOTSTRAP_IMAGE", "env-bootstrap:latest");
        let _g4 = EnvVarGuard::set("OPENSHELL_VM_DRIVER_STATE_DIR", "/tmp/env-vm-state");
        let _g5 = EnvVarGuard::set("OPENSHELL_VM_HYPERVISOR_LOG_LEVEL", "3");
        let _g6 = EnvVarGuard::set("OPENSHELL_VM_DRIVER_VCPUS", "5");
        let _g7 = EnvVarGuard::set("OPENSHELL_VM_DRIVER_MEM_MIB", "5120");
        let _g8 = EnvVarGuard::set("OPENSHELL_VM_OVERLAY_DISK_MIB", "8192");
        let _g9 = EnvVarGuard::set("OPENSHELL_VM_GPU", "true");
        let _g10 = EnvVarGuard::set("OPENSHELL_VM_GPU_MEM_MIB", "24576");
        let _g11 = EnvVarGuard::set("OPENSHELL_VM_GPU_VCPUS", "10");
        let base = VmComputeConfig {
            grpc_endpoint: "http://file-gateway:17670".to_string(),
            default_image: "file-sandbox:latest".to_string(),
            bootstrap_image: "file-bootstrap:latest".to_string(),
            state_dir: PathBuf::from("/tmp/file-vm-state"),
            hypervisor_log_level: 1,
            vcpus: 2,
            mem_mib: 2048,
            overlay_disk_mib: 4096,
            gpu_enabled: false,
            gpu_mem_mib: 8192,
            gpu_vcpus: 4,
            ..Default::default()
        };

        let cfg = vm_config_with_env_overrides(&base).unwrap();

        assert_eq!(cfg.grpc_endpoint, "http://env-gateway:17670");
        assert_eq!(cfg.default_image, "env-sandbox:latest");
        assert_eq!(cfg.bootstrap_image, "env-bootstrap:latest");
        assert_eq!(cfg.state_dir, PathBuf::from("/tmp/env-vm-state"));
        assert_eq!(cfg.hypervisor_log_level, 3);
        assert_eq!(cfg.vcpus, 5);
        assert_eq!(cfg.mem_mib, 5120);
        assert_eq!(cfg.overlay_disk_mib, 8192);
        assert!(cfg.gpu_enabled);
        assert_eq!(cfg.gpu_mem_mib, 24576);
        assert_eq!(cfg.gpu_vcpus, 10);
    }

    #[test]
    fn vm_config_env_overrides_accept_legacy_krun_log_level() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _env = remove_vm_env_overrides();
        let _legacy = EnvVarGuard::set("OPENSHELL_VM_KRUN_LOG_LEVEL", "4");
        let base = VmComputeConfig {
            hypervisor_log_level: 1,
            ..Default::default()
        };

        let cfg = vm_config_with_env_overrides(&base).unwrap();

        assert_eq!(cfg.hypervisor_log_level, 4);
    }

    #[test]
    fn vm_config_env_prefers_hypervisor_log_level_over_legacy_krun() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _env = remove_vm_env_overrides();
        let _preferred = EnvVarGuard::set("OPENSHELL_VM_HYPERVISOR_LOG_LEVEL", "5");
        let _legacy = EnvVarGuard::set("OPENSHELL_VM_KRUN_LOG_LEVEL", "4");
        let base = VmComputeConfig {
            hypervisor_log_level: 1,
            ..Default::default()
        };

        let cfg = vm_config_with_env_overrides(&base).unwrap();

        assert_eq!(cfg.hypervisor_log_level, 5);
    }

    #[test]
    fn vm_driver_args_omit_gpu_flag_when_disabled() {
        let config = Config::new(None).with_log_level("debug");
        let vm_config = VmComputeConfig {
            grpc_endpoint: "http://127.0.0.1:17670".to_string(),
            state_dir: PathBuf::from("/tmp/openshell-vm"),
            gpu_enabled: false,
            gpu_mem_mib: 12288,
            gpu_vcpus: 6,
            ..Default::default()
        };

        let args = args_to_strings(compute_driver_args(
            &config,
            &vm_config,
            Path::new("/tmp/openshell-vm.sock"),
            1234,
            None,
        ));

        assert!(!args.iter().any(|arg| arg == "--gpu"));
        assert_eq!(arg_value(&args, "--gpu-mem-mib").as_deref(), Some("12288"));
        assert_eq!(arg_value(&args, "--gpu-vcpus").as_deref(), Some("6"));
    }

    #[test]
    fn vm_driver_args_include_gpu_flag_when_enabled() {
        let config = Config::new(None).with_log_level("debug");
        let vm_config = VmComputeConfig {
            grpc_endpoint: "http://127.0.0.1:17670".to_string(),
            state_dir: PathBuf::from("/tmp/openshell-vm"),
            bootstrap_image: "ghcr.io/nvidia/openshell/bootstrap:test".to_string(),
            gpu_enabled: true,
            gpu_mem_mib: 16384,
            gpu_vcpus: 8,
            ..Default::default()
        };

        let args = args_to_strings(compute_driver_args(
            &config,
            &vm_config,
            Path::new("/tmp/openshell-vm.sock"),
            1234,
            None,
        ));

        assert!(args.iter().any(|arg| arg == "--gpu"));
        assert_eq!(arg_value(&args, "--log-level").as_deref(), Some("debug"));
        assert_eq!(
            arg_value(&args, "--openshell-endpoint").as_deref(),
            Some("http://127.0.0.1:17670")
        );
        assert_eq!(
            arg_value(&args, "--bootstrap-image").as_deref(),
            Some("ghcr.io/nvidia/openshell/bootstrap:test")
        );
        assert_eq!(arg_value(&args, "--vcpus").as_deref(), Some("2"));
        assert_eq!(arg_value(&args, "--mem-mib").as_deref(), Some("2048"));
        assert_eq!(
            arg_value(&args, "--overlay-disk-mib").as_deref(),
            Some("4096")
        );
        assert_eq!(arg_value(&args, "--gpu-mem-mib").as_deref(), Some("16384"));
        assert_eq!(arg_value(&args, "--gpu-vcpus").as_deref(), Some("8"));
    }

    #[test]
    fn vm_compute_driver_tls_requires_explicit_guest_bundle() {
        let vm_config = VmComputeConfig {
            grpc_endpoint: "https://gateway.internal:8443".to_string(),
            ..Default::default()
        };

        let err = compute_driver_guest_tls_paths(&vm_config)
            .expect_err("https vm endpoints should require an explicit guest client bundle");
        assert!(
            err.to_string()
                .contains("guest_tls_ca, guest_tls_cert, and guest_tls_key")
        );
    }

    #[test]
    fn vm_compute_driver_tls_uses_guest_bundle_not_gateway_server_identity() {
        let dir = tempdir().unwrap();
        let server_cert = dir.path().join("server.crt");
        let server_key = dir.path().join("server.key");
        let guest_ca = dir.path().join("guest-ca.crt");
        let guest_cert = dir.path().join("guest.crt");
        let guest_key = dir.path().join("guest.key");
        for path in [
            &server_cert,
            &server_key,
            &guest_ca,
            &guest_cert,
            &guest_key,
        ] {
            std::fs::write(path, path.display().to_string()).unwrap();
        }

        let vm_config = VmComputeConfig {
            grpc_endpoint: "https://gateway.internal:8443".to_string(),
            guest_tls_ca: Some(guest_ca.clone()),
            guest_tls_cert: Some(guest_cert.clone()),
            guest_tls_key: Some(guest_key.clone()),
            ..Default::default()
        };

        let guest_paths = compute_driver_guest_tls_paths(&vm_config)
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
