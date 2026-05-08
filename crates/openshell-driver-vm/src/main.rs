// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use futures::Stream;
use miette::{IntoDiagnostic, Result};
use openshell_core::VERSION;
use openshell_core::proto::compute::v1::compute_driver_server::ComputeDriverServer;
#[cfg(target_os = "macos")]
use openshell_driver_vm::{VM_RUNTIME_DIR_ENV, configured_runtime_dir};
use openshell_driver_vm::{VmBackend, VmDriver, VmDriverConfig, VmLaunchConfig, procguard, run_vm};
use std::io;
use std::net::SocketAddr;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::net::{UnixListener, UnixStream};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "openshell-driver-vm")]
#[command(version = VERSION)]
#[allow(clippy::struct_excessive_bools)]
struct Args {
    #[arg(long, hide = true, default_value_t = false)]
    internal_run_vm: bool,

    #[arg(long = "vm-root-disk", hide = true, alias = "vm-rootfs")]
    vm_root_disk: Option<PathBuf>,

    #[arg(long, hide = true)]
    vm_exec: Option<String>,

    #[arg(long, hide = true, default_value = "/")]
    vm_workdir: String,

    #[arg(long, hide = true)]
    vm_env: Vec<String>,

    #[arg(long, hide = true)]
    vm_console_output: Option<PathBuf>,

    #[arg(long, hide = true, default_value_t = 2)]
    vm_vcpus: u8,

    #[arg(long, hide = true, default_value_t = 2048)]
    vm_mem_mib: u32,

    #[arg(long, hide = true, default_value_t = 1)]
    vm_krun_log_level: u32,

    #[arg(long, env = "OPENSHELL_COMPUTE_DRIVER_BIND")]
    bind_address: Option<SocketAddr>,

    #[arg(long, env = "OPENSHELL_COMPUTE_DRIVER_SOCKET")]
    bind_socket: Option<PathBuf>,

    #[arg(long, hide = true)]
    expected_peer_pid: Option<u32>,

    #[arg(
        long,
        env = "OPENSHELL_COMPUTE_DRIVER_ALLOW_UNAUTHENTICATED_TCP",
        default_value_t = false
    )]
    allow_unauthenticated_tcp: bool,

    #[arg(
        long,
        env = "OPENSHELL_COMPUTE_DRIVER_ALLOW_SAME_UID_PEER",
        default_value_t = false
    )]
    allow_same_uid_peer: bool,

    #[arg(long, env = "OPENSHELL_LOG_LEVEL", default_value = "info")]
    log_level: String,

    #[arg(long, env = "OPENSHELL_GRPC_ENDPOINT")]
    openshell_endpoint: Option<String>,

    #[arg(long, env = "OPENSHELL_SANDBOX_IMAGE", default_value = "")]
    default_image: String,

    #[arg(
        long,
        env = "OPENSHELL_VM_DRIVER_STATE_DIR",
        default_value = "target/openshell-vm-driver"
    )]
    state_dir: PathBuf,

    #[arg(long, env = "OPENSHELL_SSH_HANDSHAKE_SECRET")]
    ssh_handshake_secret: Option<String>,

    #[arg(long, env = "OPENSHELL_SSH_HANDSHAKE_SKEW_SECS", default_value_t = 300)]
    ssh_handshake_skew_secs: u64,

    #[arg(long = "guest-tls-ca", env = "OPENSHELL_VM_TLS_CA")]
    guest_tls_ca: Option<PathBuf>,

    #[arg(long = "guest-tls-cert", env = "OPENSHELL_VM_TLS_CERT")]
    guest_tls_cert: Option<PathBuf>,

    #[arg(long = "guest-tls-key", env = "OPENSHELL_VM_TLS_KEY")]
    guest_tls_key: Option<PathBuf>,

    #[arg(long, env = "OPENSHELL_VM_KRUN_LOG_LEVEL", default_value_t = 1)]
    krun_log_level: u32,

    #[arg(long, env = "OPENSHELL_VM_DRIVER_VCPUS", default_value_t = 2)]
    vcpus: u8,

    #[arg(long, env = "OPENSHELL_VM_DRIVER_MEM_MIB", default_value_t = 2048)]
    mem_mib: u32,

    #[arg(long, env = "OPENSHELL_VM_GPU")]
    gpu: bool,

    #[arg(long, env = "OPENSHELL_VM_GPU_MEM_MIB", default_value_t = 8192)]
    gpu_mem_mib: u32,

    #[arg(long, env = "OPENSHELL_VM_GPU_VCPUS", default_value_t = 4)]
    gpu_vcpus: u8,

    #[arg(long, hide = true)]
    vm_backend: Option<String>,

    #[arg(long, hide = true)]
    vm_gpu_bdf: Option<String>,

    #[arg(long, hide = true)]
    vm_tap_device: Option<String>,

    #[arg(long, hide = true)]
    vm_guest_ip: Option<String>,

    #[arg(long, hide = true)]
    vm_host_ip: Option<String>,

    #[arg(long, hide = true)]
    vm_vsock_cid: Option<u32>,

    #[arg(long, hide = true)]
    vm_guest_mac: Option<String>,

    #[arg(long, hide = true)]
    vm_gateway_port: Option<u16>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if args.internal_run_vm {
        // We intentionally defer procguard arming until `run_vm()` so
        // that the only arm is the one that knows how to clean up
        // gvproxy. Racing two watchers against the same parent-death
        // event causes the bare arm's `exit(1)` to win, skipping the
        // gvproxy cleanup and leaking the helper. The risk window
        // before `run_vm` arms procguard is ~a few syscalls long
        // (`build_vm_launch_config`, `configured_runtime_dir`), which
        // is negligible next to the parent gRPC server's uptime.
        maybe_reexec_internal_vm_with_runtime_env()?;
        let config = build_vm_launch_config(&args).map_err(|err| miette::miette!("{err}"))?;
        run_vm(&config).map_err(|err| miette::miette!("{err}"))?;
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level)),
        )
        .init();

    let listen_mode = compute_driver_listen_mode(&args).map_err(|err| miette::miette!("{err}"))?;

    // Arm procguard so that if the gateway is killed (SIGKILL or crash)
    // we also die. Without this the driver is reparented to init and
    // keeps its per-sandbox VM launchers alive forever. Launchers have
    // their own procguards (armed in `run_vm`) which cascade cleanup of
    // gvproxy and the libkrun worker the moment this driver exits.
    if let Err(err) = procguard::die_with_parent() {
        tracing::warn!(
            error = %err,
            "procguard arm failed; gateway crashes may orphan this driver"
        );
    }

    let driver = VmDriver::new(VmDriverConfig {
        openshell_endpoint: args
            .openshell_endpoint
            .ok_or_else(|| miette::miette!("OPENSHELL_GRPC_ENDPOINT is required"))?,
        state_dir: args.state_dir.clone(),
        launcher_bin: None,
        default_image: args.default_image.clone(),
        ssh_handshake_secret: args.ssh_handshake_secret.clone().unwrap_or_default(),
        ssh_handshake_skew_secs: args.ssh_handshake_skew_secs,
        log_level: args.log_level.clone(),
        krun_log_level: args.krun_log_level,
        vcpus: args.vcpus,
        mem_mib: args.mem_mib,
        guest_tls_ca: args.guest_tls_ca.clone(),
        guest_tls_cert: args.guest_tls_cert.clone(),
        guest_tls_key: args.guest_tls_key.clone(),
        gpu_enabled: args.gpu,
        gpu_mem_mib: args.gpu_mem_mib,
        gpu_vcpus: args.gpu_vcpus,
    })
    .await
    .map_err(|err| miette::miette!("{err}"))?;

    match listen_mode {
        ComputeDriverListenMode::Unix {
            socket_path,
            expected_peer_pid,
        } => {
            prepare_compute_driver_socket(&socket_path).map_err(|err| miette::miette!("{err}"))?;

            info!(socket = %socket_path.display(), "Starting vm compute driver");
            let listener = UnixListener::bind(&socket_path).into_diagnostic()?;
            restrict_socket_permissions(&socket_path).map_err(|err| miette::miette!("{err}"))?;
            let result = tonic::transport::Server::builder()
                .add_service(ComputeDriverServer::new(driver))
                .serve_with_incoming(AuthenticatedUnixIncoming::new(listener, expected_peer_pid))
                .await
                .into_diagnostic();
            let _ = std::fs::remove_file(&socket_path);
            result
        }
        ComputeDriverListenMode::Tcp(bind_address) => {
            info!(address = %bind_address, "Starting unauthenticated dev vm compute driver");
            tonic::transport::Server::builder()
                .add_service(ComputeDriverServer::new(driver))
                .serve(bind_address)
                .await
                .into_diagnostic()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ComputeDriverListenMode {
    Unix {
        socket_path: PathBuf,
        expected_peer_pid: Option<u32>,
    },
    Tcp(SocketAddr),
}

fn compute_driver_listen_mode(args: &Args) -> std::result::Result<ComputeDriverListenMode, String> {
    if let Some(socket_path) = args.bind_socket.clone() {
        if args.expected_peer_pid.is_none() && !args.allow_same_uid_peer {
            return Err(
                "--expected-peer-pid is required with --bind-socket; use --allow-same-uid-peer only for local development"
                    .to_string(),
            );
        }
        return Ok(ComputeDriverListenMode::Unix {
            socket_path,
            expected_peer_pid: args.expected_peer_pid,
        });
    }

    if !args.allow_unauthenticated_tcp {
        return Err(
            "--bind-socket is required; unauthenticated TCP mode is disabled unless --allow-unauthenticated-tcp is set for local development"
                .to_string(),
        );
    }

    let Some(bind_address) = args.bind_address else {
        return Err("--bind-address is required with --allow-unauthenticated-tcp".to_string());
    };

    Ok(ComputeDriverListenMode::Tcp(bind_address))
}

fn prepare_compute_driver_socket(socket_path: &Path) -> std::result::Result<(), String> {
    let Some(parent) = socket_path.parent() else {
        return Err(format!(
            "vm compute driver socket path '{}' has no parent directory",
            socket_path.display()
        ));
    };
    let expected_uid = current_euid();
    prepare_private_socket_dir(parent, expected_uid)?;
    remove_stale_socket(socket_path, expected_uid)
}

fn current_euid() -> u32 {
    nix::unistd::Uid::effective().as_raw()
}

fn prepare_private_socket_dir(
    socket_dir: &Path,
    expected_uid: u32,
) -> std::result::Result<(), String> {
    std::fs::create_dir_all(socket_dir)
        .map_err(|err| format!("create socket dir {}: {err}", socket_dir.display()))?;
    let metadata = std::fs::symlink_metadata(socket_dir)
        .map_err(|err| format!("stat socket dir {}: {err}", socket_dir.display()))?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(format!(
            "socket dir {} is a symlink; refusing to use it",
            socket_dir.display()
        ));
    }
    if !file_type.is_dir() {
        return Err(format!(
            "socket dir {} is not a directory",
            socket_dir.display()
        ));
    }
    if metadata.uid() != expected_uid {
        return Err(format!(
            "socket dir {} is owned by uid {} but current euid is {}",
            socket_dir.display(),
            metadata.uid(),
            expected_uid
        ));
    }
    std::fs::set_permissions(socket_dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|err| format!("chmod socket dir {}: {err}", socket_dir.display()))
}

fn remove_stale_socket(socket_path: &Path, expected_uid: u32) -> std::result::Result<(), String> {
    let metadata = match std::fs::symlink_metadata(socket_path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(format!("stat socket {}: {err}", socket_path.display())),
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(format!(
            "socket {} is a symlink; refusing to remove it",
            socket_path.display()
        ));
    }
    if metadata.uid() != expected_uid {
        return Err(format!(
            "socket {} is owned by uid {} but current euid is {}",
            socket_path.display(),
            metadata.uid(),
            expected_uid
        ));
    }
    if !file_type.is_socket() {
        return Err(format!(
            "socket path {} exists but is not a Unix socket",
            socket_path.display()
        ));
    }
    std::fs::remove_file(socket_path)
        .map_err(|err| format!("remove stale socket {}: {err}", socket_path.display()))
}

fn restrict_socket_permissions(socket_path: &Path) -> std::result::Result<(), String> {
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
        .map_err(|err| format!("chmod socket {}: {err}", socket_path.display()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PeerCredentials {
    uid: u32,
    pid: Option<i32>,
}

fn peer_credentials(stream: &UnixStream) -> std::result::Result<PeerCredentials, String> {
    let credentials = stream
        .peer_cred()
        .map_err(|err| format!("read peer credentials: {err}"))?;
    Ok(PeerCredentials {
        uid: credentials.uid(),
        pid: credentials.pid(),
    })
}

fn authorize_peer_credentials(
    peer: PeerCredentials,
    driver_uid: u32,
    gateway_pid: Option<u32>,
) -> std::result::Result<(), String> {
    if peer.uid != driver_uid {
        return Err(format!(
            "peer uid {} does not match current euid {}",
            peer.uid, driver_uid
        ));
    }
    let Some(gateway_pid) = gateway_pid else {
        return Ok(());
    };
    let Some(peer_process_id) = peer.pid.and_then(|pid| u32::try_from(pid).ok()) else {
        return Err(format!(
            "peer pid is unavailable; expected gateway pid {gateway_pid}"
        ));
    };
    if peer_process_id != gateway_pid {
        return Err(format!(
            "peer pid {peer_process_id} does not match expected gateway pid {gateway_pid}"
        ));
    }
    Ok(())
}

struct AuthenticatedUnixIncoming {
    listener: UnixListener,
    expected_uid: u32,
    expected_peer_pid: Option<u32>,
}

impl AuthenticatedUnixIncoming {
    fn new(listener: UnixListener, expected_peer_pid: Option<u32>) -> Self {
        Self {
            listener,
            expected_uid: current_euid(),
            expected_peer_pid,
        }
    }
}

impl Stream for AuthenticatedUnixIncoming {
    type Item = io::Result<UnixStream>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            match this.listener.poll_accept(cx) {
                Poll::Ready(Ok((stream, _addr))) => {
                    let authorized = peer_credentials(&stream).and_then(|peer| {
                        authorize_peer_credentials(peer, this.expected_uid, this.expected_peer_pid)
                    });
                    match authorized {
                        Ok(()) => return Poll::Ready(Some(Ok(stream))),
                        Err(err) => {
                            tracing::warn!(
                                error = %err,
                                "rejected vm compute driver UDS client"
                            );
                        }
                    }
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Some(Err(err))),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

fn build_vm_launch_config(args: &Args) -> std::result::Result<VmLaunchConfig, String> {
    let root_disk = args
        .vm_root_disk
        .clone()
        .ok_or_else(|| "--vm-root-disk is required in internal VM mode".to_string())?;
    let exec_path = args
        .vm_exec
        .clone()
        .ok_or_else(|| "--vm-exec is required in internal VM mode".to_string())?;
    let console_output = args
        .vm_console_output
        .clone()
        .ok_or_else(|| "--vm-console-output is required in internal VM mode".to_string())?;

    let backend = match args.vm_backend.as_deref() {
        Some("qemu") => VmBackend::Qemu,
        Some("libkrun") | None => VmBackend::Libkrun,
        Some(other) => return Err(format!("unknown VM backend: {other}")),
    };

    Ok(VmLaunchConfig {
        root_disk,
        vcpus: args.vm_vcpus,
        mem_mib: args.vm_mem_mib,
        exec_path,
        args: Vec::new(),
        env: args.vm_env.clone(),
        workdir: args.vm_workdir.clone(),
        log_level: args.vm_krun_log_level,
        console_output,
        backend,
        gpu_bdf: args.vm_gpu_bdf.clone(),
        tap_device: args.vm_tap_device.clone(),
        guest_ip: args.vm_guest_ip.clone(),
        host_ip: args.vm_host_ip.clone(),
        vsock_cid: args.vm_vsock_cid,
        guest_mac: args.vm_guest_mac.clone(),
        gateway_port: args.vm_gateway_port,
    })
}

#[cfg(target_os = "macos")]
fn maybe_reexec_internal_vm_with_runtime_env() -> Result<()> {
    use std::os::unix::process::CommandExt as _;

    const REEXEC_ENV: &str = "__OPENSHELL_DRIVER_VM_REEXEC";

    if std::env::var_os(REEXEC_ENV).is_some() {
        return Ok(());
    }

    let runtime_dir = configured_runtime_dir().map_err(|err| miette::miette!("{err}"))?;
    let runtime_str = runtime_dir.to_string_lossy();
    let needs_reexec = std::env::var_os("DYLD_LIBRARY_PATH")
        .is_none_or(|value| !value.to_string_lossy().contains(runtime_str.as_ref()));
    if !needs_reexec {
        return Ok(());
    }

    let mut dyld_paths = vec![runtime_dir.clone()];
    if let Some(existing) = std::env::var_os("DYLD_LIBRARY_PATH") {
        dyld_paths.extend(std::env::split_paths(&existing));
    }
    let joined = std::env::join_paths(&dyld_paths)
        .map_err(|err| miette::miette!("join DYLD_LIBRARY_PATH: {err}"))?;
    let exe = std::env::current_exe().into_diagnostic()?;
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Use execvp() so the current process is *replaced* by the re-exec'd
    // binary — no wrapper process sits between the compute driver and
    // the actually-running VM launcher. That avoids two problems:
    //   1. An extra process level that survives SIGKILL of the driver
    //      (the wrapper was reparenting the re-exec'd child to init).
    //   2. Signal forwarding: with a wrapper, a SIGTERM to the wrapper
    //      doesn't reach the child unless we hand-roll forwarding.
    // After exec, the child inherits our PID and our procguard arming.
    let err = std::process::Command::new(exe)
        .args(&args)
        .env("DYLD_LIBRARY_PATH", &joined)
        .env(VM_RUNTIME_DIR_ENV, runtime_dir)
        .env(REEXEC_ENV, "1")
        .exec();
    // `exec()` only returns on failure.
    Err(miette::miette!("failed to re-exec with runtime env: {err}"))
}

#[cfg(not(target_os = "macos"))]
// Signature must match the macOS variant which can fail.
#[allow(clippy::unnecessary_wraps)]
fn maybe_reexec_internal_vm_with_runtime_env() -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        Args, ComputeDriverListenMode, PeerCredentials, authorize_peer_credentials,
        compute_driver_listen_mode,
    };
    use clap::Parser;
    use std::path::PathBuf;

    #[test]
    fn peer_authorization_accepts_matching_uid_and_pid() {
        authorize_peer_credentials(
            PeerCredentials {
                uid: 1000,
                pid: Some(42),
            },
            1000,
            Some(42),
        )
        .unwrap();
    }

    #[test]
    fn peer_authorization_rejects_wrong_pid() {
        let err = authorize_peer_credentials(
            PeerCredentials {
                uid: 1000,
                pid: Some(7),
            },
            1000,
            Some(42),
        )
        .expect_err("wrong pid should be rejected");
        assert!(err.contains("does not match expected gateway pid"));
    }

    #[test]
    fn peer_authorization_rejects_wrong_uid() {
        let err = authorize_peer_credentials(
            PeerCredentials {
                uid: 1001,
                pid: Some(42),
            },
            1000,
            Some(42),
        )
        .expect_err("wrong uid should be rejected");
        assert!(err.contains("does not match current euid"));
    }

    #[test]
    fn peer_authorization_rejects_missing_pid_when_expected() {
        let err = authorize_peer_credentials(
            PeerCredentials {
                uid: 1000,
                pid: None,
            },
            1000,
            Some(42),
        )
        .expect_err("missing pid should be rejected");
        assert!(err.contains("peer pid is unavailable"));
    }

    #[test]
    fn peer_authorization_accepts_matching_uid_without_expected_pid() {
        authorize_peer_credentials(
            PeerCredentials {
                uid: 1000,
                pid: None,
            },
            1000,
            None,
        )
        .unwrap();
    }

    #[test]
    fn listen_mode_rejects_default_tcp() {
        let args = Args::parse_from(["openshell-driver-vm"]);
        let err = compute_driver_listen_mode(&args).expect_err("default TCP should be disabled");
        assert!(err.contains("--bind-socket is required"));
    }

    #[test]
    fn listen_mode_rejects_bind_address_without_tcp_opt_in() {
        let args = Args::parse_from(["openshell-driver-vm", "--bind-address", "127.0.0.1:50061"]);
        let err =
            compute_driver_listen_mode(&args).expect_err("TCP bind should require explicit opt-in");
        assert!(err.contains("--allow-unauthenticated-tcp"));
    }

    #[test]
    fn listen_mode_requires_bind_address_with_tcp_opt_in() {
        let args = Args::parse_from(["openshell-driver-vm", "--allow-unauthenticated-tcp"]);
        let err =
            compute_driver_listen_mode(&args).expect_err("TCP opt-in should require an address");
        assert!(err.contains("--bind-address is required"));
    }

    #[test]
    fn listen_mode_accepts_explicit_unauthenticated_tcp() {
        let args = Args::parse_from([
            "openshell-driver-vm",
            "--allow-unauthenticated-tcp",
            "--bind-address",
            "127.0.0.1:50061",
        ]);
        assert_eq!(
            compute_driver_listen_mode(&args).unwrap(),
            ComputeDriverListenMode::Tcp("127.0.0.1:50061".parse().unwrap())
        );
    }

    #[test]
    fn listen_mode_requires_expected_peer_pid_for_uds() {
        let args = Args::parse_from([
            "openshell-driver-vm",
            "--bind-socket",
            "/tmp/compute-driver.sock",
        ]);
        let err = compute_driver_listen_mode(&args)
            .expect_err("UDS should require gateway peer pid by default");
        assert!(err.contains("--expected-peer-pid is required"));
    }

    #[test]
    fn listen_mode_accepts_uds_with_expected_peer_pid() {
        let args = Args::parse_from([
            "openshell-driver-vm",
            "--bind-socket",
            "/tmp/compute-driver.sock",
            "--expected-peer-pid",
            "42",
        ]);
        assert_eq!(
            compute_driver_listen_mode(&args).unwrap(),
            ComputeDriverListenMode::Unix {
                socket_path: PathBuf::from("/tmp/compute-driver.sock"),
                expected_peer_pid: Some(42),
            }
        );
    }

    #[test]
    fn listen_mode_accepts_explicit_same_uid_uds_dev_mode() {
        let args = Args::parse_from([
            "openshell-driver-vm",
            "--bind-socket",
            "/tmp/compute-driver.sock",
            "--allow-same-uid-peer",
        ]);
        assert_eq!(
            compute_driver_listen_mode(&args).unwrap(),
            ComputeDriverListenMode::Unix {
                socket_path: PathBuf::from("/tmp/compute-driver.sock"),
                expected_peer_pid: None,
            }
        );
    }
}
