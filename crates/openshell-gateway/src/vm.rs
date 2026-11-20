// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! VM compute driver plumbing.
//!
//! This module owns everything needed to hand the gateway a `Channel` speaking
//! the `openshell.compute.v1.ComputeDriver` RPC surface against an
//! `openshell-driver-vm` subprocess over a Unix domain socket:
//!
//! - [`VmLaunchSettings`]: the launcher's own keys (`driver_dir`, `state_dir`)
//!   from the operator's `[openshell.drivers.vm]` table. The VM driver owns and
//!   validates the rest of the table, which the gateway passes through.
//! - [`spawn`]: write the driver's startup document, spawn the subprocess, wait
//!   for its UDS to be ready, and return a live gRPC channel plus a
//!   [`ManagedDriverProcess`] handle that will reap the subprocess and clean up
//!   the socket on drop.
//! - Helpers to resolve the driver binary and compute and prepare the socket
//!   path.
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
use openshell_core::{Error, NetworkSupervisorTrustBundle, Result};
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

/// The launcher's view of `[openshell.drivers.vm]`. The VM driver owns and
/// validates the rest of the table, which the gateway passes through.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct VmLaunchSettings {
    /// Directory to search for compute-driver binaries before the gateway
    /// falls back to its conventional install paths and sibling binary.
    pub driver_dir: Option<PathBuf>,
    /// Working directory for VM driver state, which holds the private run
    /// directory with the driver socket and startup document.
    pub state_dir: Option<PathBuf>,
}

impl VmLaunchSettings {
    /// Default working directory for VM driver state.
    #[must_use]
    pub fn default_state_dir() -> PathBuf {
        openshell_core::paths::openshell_state_dir().map_or_else(
            |_| PathBuf::from("target/openshell-vm-driver"),
            |dir| dir.join("vm-driver"),
        )
    }

    /// Read the launcher's keys from the operator's driver table.
    ///
    /// # Errors
    ///
    /// Returns an error when `driver_dir` or `state_dir` has the wrong type.
    pub fn from_table(table: &toml::Table) -> Result<Self> {
        let mut settings: Self =
            toml::Value::Table(table.clone())
                .try_into()
                .map_err(|error: toml::de::Error| {
                    Error::config(format!("invalid [openshell.drivers.vm] table: {error}"))
                })?;
        if settings
            .state_dir
            .as_ref()
            .is_none_or(|dir| dir.as_os_str().is_empty())
        {
            settings.state_dir = Some(Self::default_state_dir());
        }
        Ok(settings)
    }

    fn state_dir(&self) -> PathBuf {
        self.state_dir
            .clone()
            .unwrap_or_else(Self::default_state_dir)
    }

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
pub fn resolve_compute_driver_bin(settings: &VmLaunchSettings) -> Result<PathBuf> {
    let mut searched: Vec<PathBuf> = Vec::new();

    // 1. Configured driver directory, or the conventional install locations
    // when no explicit override is configured.
    for dir in resolve_driver_search_dirs(settings) {
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

fn resolve_driver_search_dirs(settings: &VmLaunchSettings) -> Vec<PathBuf> {
    settings.driver_dir.clone().map_or_else(
        || {
            let mut dirs = Vec::new();
            if let Ok(current_exe) = std::env::current_exe()
                && let Some(prefix) = current_exe.parent().and_then(Path::parent)
            {
                push_unique_path(&mut dirs, prefix.join("libexec"));
                push_unique_path(&mut dirs, prefix.join("libexec").join("openshell"));
            }
            for dir in VmLaunchSettings::default_driver_search_dirs(
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
pub fn compute_driver_socket_path(settings: &VmLaunchSettings) -> PathBuf {
    settings
        .state_dir()
        .join(COMPUTE_DRIVER_SOCKET_RUN_DIR)
        .join(COMPUTE_DRIVER_SOCKET_NAME)
}

#[cfg(unix)]
fn prepare_compute_driver_socket_path(
    settings: &VmLaunchSettings,
    socket_path: &Path,
) -> Result<()> {
    let expected_uid = current_euid();
    prepare_vm_state_dir(&settings.state_dir(), expected_uid)?;
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

/// Everything the gateway supplies to launch the VM driver.
pub struct VmLaunch<'a> {
    pub gateway_log_level: &'a str,
    pub gateway_name: &'a str,
    pub gateway_port: u16,
    /// The gateway's `guest_tls_ca`, when it serves TLS.
    pub tls_ca: Option<&'a Path>,
    pub otlp_config: Option<&'a OtlpConfig>,
    pub network_trust: Option<&'a NetworkSupervisorTrustBundle>,
    pub settings: &'a VmLaunchSettings,
    /// The operator's `[openshell.drivers.vm]` table, passed through.
    pub driver_config: toml::Table,
}

/// Launch the VM compute-driver subprocess, wait for its UDS to come up,
/// and return a gRPC `Channel` connected to it plus a process handle that
/// kills the subprocess and removes the socket on drop.
#[cfg(unix)]
pub async fn spawn(launch: VmLaunch<'_>) -> Result<AcquiredRemoteDriverEndpoint> {
    let driver_bin = resolve_compute_driver_bin(launch.settings)?;
    let socket_path = compute_driver_socket_path(launch.settings);
    prepare_compute_driver_socket_path(launch.settings, &socket_path)?;

    let startup_path = startup_document_path(&socket_path);
    let otlp_config = launch.otlp_config;
    let document = vm_startup_document(launch, &socket_path)?;
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

/// File name of the startup document, written beside the driver socket in its
/// private run directory.
#[cfg(unix)]
const STARTUP_DOCUMENT_NAME: &str = "startup.toml";

#[cfg(unix)]
fn startup_document_path(socket_path: &Path) -> PathBuf {
    socket_path.with_file_name(STARTUP_DOCUMENT_NAME)
}

/// The VM driver's `[driver_config]`: the operator's table, passed through,
/// without the launcher-owned `driver_dir`.
#[cfg(unix)]
fn vm_driver_config_table(mut table: toml::Table) -> toml::Table {
    table.remove("driver_dir");
    table
}

#[cfg(unix)]
fn vm_startup_document(
    launch: VmLaunch<'_>,
    socket_path: &Path,
) -> Result<openshell_driver_sdk::StartupDocument> {
    crate::startup_document::GatewayStartup {
        bind_socket: socket_path,
        log_level: launch.gateway_log_level,
        gateway_name: launch.gateway_name,
        gateway_port: launch.gateway_port,
        tls_ca: launch.tls_ca,
        otlp: launch.otlp_config,
        network_trust: launch.network_trust,
    }
    .into_document(vm_driver_config_table(launch.driver_config))
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
pub async fn spawn(_launch: VmLaunch<'_>) -> Result<AcquiredRemoteDriverEndpoint> {
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
        VmLaunch, VmLaunchSettings, apply_trace_headers_env, compute_driver_socket_path,
        current_euid, prepare_compute_driver_socket_path, prepare_vm_state_dir,
        resolve_compute_driver_bin, resolve_driver_search_dirs, startup_document_path,
        vm_driver_config_table, vm_startup_document, write_startup_document,
    };
    use openshell_core::NetworkSupervisorTrustBundle;
    use openshell_core::sandbox_env::OtlpProtocol;
    use openshell_server::config_file::{
        AgentOtlpConfig, OcsfOtlpConfig, OtlpCollectorConfig, OtlpConfig, OtlpTracesConfig,
    };
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener as StdUnixListener;
    use std::path::{Path, PathBuf};
    use tempfile::tempdir;

    const VM_STARTUP_FIXTURE: &str =
        include_str!("../../openshell-driver-vm/tests/fixtures/startup-vm.toml");

    fn fixture_driver_config() -> toml::Table {
        let document = openshell_driver_sdk::StartupDocument::parse(VM_STARTUP_FIXTURE).unwrap();
        document.driver_config
    }

    /// The gateway passes the operator's table through unchanged, apart from
    /// the launcher-owned `driver_dir`, and adds the gateway context the
    /// driver's own tests read from the same fixture.
    #[test]
    fn the_gateway_writes_the_documented_startup_document() {
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
        let mut operator_table = fixture_driver_config();
        operator_table.insert("driver_dir".into(), "/usr/libexec/openshell".into());
        let settings = VmLaunchSettings::from_table(&operator_table).unwrap();
        let tls_ca = Path::new("/etc/openshell/tls/ca.pem");

        let mut document = vm_startup_document(
            VmLaunch {
                gateway_log_level: "debug",
                gateway_name: "gateway-a",
                gateway_port: 8080,
                tls_ca: Some(tls_ca),
                otlp_config: Some(&otlp),
                network_trust: Some(&trust),
                settings: &settings,
                driver_config: operator_table,
            },
            Path::new("/var/lib/openshell/vm/run/compute-driver.sock"),
        )
        .unwrap();

        document.gateway.expected_peer_pid = 4242;
        let tls = document.gateway.telemetry.collector.as_mut().unwrap();
        tls.ca_file = Some("/etc/openshell/otlp/ca.pem".into());
        tls.cert_file = Some("/etc/openshell/otlp/cert.pem".into());
        tls.key_file = Some("/etc/openshell/otlp/key.pem".into());

        let fixture = openshell_driver_sdk::StartupDocument::parse(VM_STARTUP_FIXTURE).unwrap();
        assert_eq!(document, fixture);
    }

    #[test]
    fn only_the_launcher_owned_key_is_removed_from_the_operator_table() {
        let mut table = fixture_driver_config();
        let before = table.clone();
        table.insert("driver_dir".into(), "/opt/drivers".into());
        assert_eq!(vm_driver_config_table(table), before);
    }

    #[test]
    fn launch_settings_default_the_state_dir_and_read_the_driver_dir() {
        let settings = VmLaunchSettings::from_table(&toml::Table::new()).unwrap();
        assert_eq!(settings.state_dir(), VmLaunchSettings::default_state_dir());
        assert!(settings.driver_dir.is_none());

        let table: toml::Table =
            toml::from_str("driver_dir = '/opt/drivers'\nstate_dir = '/var/lib/vm'\nvcpus = 4\n")
                .unwrap();
        let settings = VmLaunchSettings::from_table(&table).unwrap();
        assert_eq!(
            settings.driver_dir.as_deref(),
            Some(Path::new("/opt/drivers"))
        );
        assert_eq!(settings.state_dir(), PathBuf::from("/var/lib/vm"));
    }

    #[test]
    fn the_startup_document_is_private_and_replaced_when_stale() {
        let dir = tempdir().unwrap();
        let socket = dir.path().join("compute-driver.sock");
        let path = startup_document_path(&socket);
        assert_eq!(path, dir.path().join("startup.toml"));

        let settings = VmLaunchSettings::default();
        let make = || {
            vm_startup_document(
                VmLaunch {
                    gateway_log_level: "info",
                    gateway_name: "gateway",
                    gateway_port: 8080,
                    tls_ca: None,
                    otlp_config: None,
                    network_trust: None,
                    settings: &settings,
                    driver_config: fixture_driver_config(),
                },
                &socket,
            )
            .unwrap()
        };
        write_startup_document(&path, &make()).unwrap();
        write_startup_document(&path, &make()).unwrap();

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
    fn resolve_driver_bin_uses_driver_dir_when_binary_present() {
        let dir = tempdir().unwrap();
        let bin = dir.path().join("openshell-driver-vm");
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        let vm_config = VmLaunchSettings {
            driver_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        assert_eq!(resolve_compute_driver_bin(&vm_config).unwrap(), bin);
    }

    #[test]
    fn resolve_driver_bin_error_mentions_driver_dir_hint() {
        let dir = tempdir().unwrap(); // empty — no driver binary present

        let vm_config = VmLaunchSettings {
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
        let dirs = resolve_driver_search_dirs(&VmLaunchSettings {
            driver_dir: None,
            ..Default::default()
        });

        assert!(dirs.contains(&PathBuf::from("/usr/libexec/openshell")));
        assert!(dirs.contains(&PathBuf::from("/usr/local/libexec/openshell")));
        assert!(dirs.contains(&PathBuf::from("/usr/local/libexec")));
    }

    #[test]
    fn compute_driver_socket_path_uses_private_run_dir() {
        let state_dir = PathBuf::from("/tmp/openshell-vm-state");
        let vm_config = VmLaunchSettings {
            state_dir: Some(state_dir.clone()),
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
        let vm_config = VmLaunchSettings {
            state_dir: Some(dir.path().join("state")),
            ..Default::default()
        };
        let socket_path = compute_driver_socket_path(&vm_config);

        prepare_compute_driver_socket_path(&vm_config, &socket_path).unwrap();

        let mode = std::fs::metadata(vm_config.state_dir().join("run"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn prepare_compute_driver_socket_path_restricts_existing_run_dir() {
        let dir = tempdir().unwrap();
        let vm_config = VmLaunchSettings {
            state_dir: Some(dir.path().join("state")),
            ..Default::default()
        };
        let run_dir = vm_config.state_dir().join("run");
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
        let vm_config = VmLaunchSettings {
            state_dir: Some(dir.path().join("state")),
            ..Default::default()
        };
        std::fs::create_dir_all(vm_config.state_dir()).unwrap();
        std::fs::set_permissions(
            vm_config.state_dir(),
            std::fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        let socket_path = compute_driver_socket_path(&vm_config);

        prepare_compute_driver_socket_path(&vm_config, &socket_path).unwrap();

        let mode = std::fs::metadata(vm_config.state_dir())
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
        let vm_config = VmLaunchSettings {
            state_dir: Some(state_link),
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
        let vm_config = VmLaunchSettings {
            state_dir: Some(dir.path().join("state")),
            ..Default::default()
        };
        let target = dir.path().join("run-target");
        std::fs::create_dir_all(vm_config.state_dir()).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&target, vm_config.state_dir().join("run")).unwrap();
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
        let vm_config = VmLaunchSettings {
            state_dir: Some(dir.path().join("state")),
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
        let vm_config = VmLaunchSettings {
            state_dir: Some(dir.path().join("state")),
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
        let vm_config = VmLaunchSettings {
            state_dir: Some(dir.path().join("state")),
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
