// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use miette::{IntoDiagnostic, Result};
use openshell_core::VERSION;
use openshell_core::proto::compute::v1::compute_driver_server::ComputeDriverServer;
use openshell_driver_vm::{
    VM_RUNTIME_DIR_ENV, VmDriver, VmDriverConfig, VmLaunchConfig, configured_runtime_dir,
    procguard, run_vm,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "openshell-driver-vm")]
#[command(version = VERSION)]
struct Args {
    #[arg(long, hide = true, default_value_t = false)]
    internal_run_vm: bool,

    #[arg(long, hide = true)]
    vm_rootfs: Option<PathBuf>,

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

    #[arg(
        long,
        env = "OPENSHELL_COMPUTE_DRIVER_BIND",
        default_value = "127.0.0.1:50061"
    )]
    bind_address: SocketAddr,

    #[arg(long, env = "OPENSHELL_COMPUTE_DRIVER_SOCKET")]
    bind_socket: Option<PathBuf>,

    #[arg(long, env = "OPENSHELL_LOG_LEVEL", default_value = "info")]
    log_level: String,

    #[arg(long, env = "OPENSHELL_GRPC_ENDPOINT")]
    openshell_endpoint: Option<String>,

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
        state_dir: args.state_dir,
        launcher_bin: None,
        ssh_handshake_secret: args.ssh_handshake_secret.unwrap_or_default(),
        ssh_handshake_skew_secs: args.ssh_handshake_skew_secs,
        log_level: args.log_level,
        krun_log_level: args.krun_log_level,
        vcpus: args.vcpus,
        mem_mib: args.mem_mib,
        guest_tls_ca: args.guest_tls_ca,
        guest_tls_cert: args.guest_tls_cert,
        guest_tls_key: args.guest_tls_key,
    })
    .await
    .map_err(|err| miette::miette!("{err}"))?;

    if let Some(socket_path) = args.bind_socket {
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent).into_diagnostic()?;
        }
        match std::fs::remove_file(&socket_path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err).into_diagnostic(),
        }

        info!(socket = %socket_path.display(), "Starting vm compute driver");
        let listener = UnixListener::bind(&socket_path).into_diagnostic()?;
        let result = tonic::transport::Server::builder()
            .add_service(ComputeDriverServer::new(driver))
            .serve_with_incoming(UnixListenerStream::new(listener))
            .await
            .into_diagnostic();
        let _ = std::fs::remove_file(&socket_path);
        result
    } else {
        info!(address = %args.bind_address, "Starting vm compute driver");
        tonic::transport::Server::builder()
            .add_service(ComputeDriverServer::new(driver))
            .serve(args.bind_address)
            .await
            .into_diagnostic()
    }
}

fn build_vm_launch_config(args: &Args) -> std::result::Result<VmLaunchConfig, String> {
    let rootfs = args
        .vm_rootfs
        .clone()
        .ok_or_else(|| "--vm-rootfs is required in internal VM mode".to_string())?;
    let exec_path = args
        .vm_exec
        .clone()
        .ok_or_else(|| "--vm-exec is required in internal VM mode".to_string())?;
    let console_output = args
        .vm_console_output
        .clone()
        .ok_or_else(|| "--vm-console-output is required in internal VM mode".to_string())?;

    Ok(VmLaunchConfig {
        rootfs,
        vcpus: args.vm_vcpus,
        mem_mib: args.vm_mem_mib,
        exec_path,
        args: Vec::new(),
        env: args.vm_env.clone(),
        workdir: args.vm_workdir.clone(),
        log_level: args.vm_krun_log_level,
        console_output,
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
fn maybe_reexec_internal_vm_with_runtime_env() -> Result<()> {
    Ok(())
}
