// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{Args, Parser, Subcommand};
use openshell_core::policy::{
    FilesystemPolicy, LandlockPolicy, NetworkPolicy, ProcessPolicy, SandboxPolicy,
};
use openshell_driver_firecracker::{
    BACKEND_NAME, DEFAULT_GUEST_CONFIG_PATH, FirecrackerHostBackend, FirecrackerLaunchConfig,
    FirecrackerTopology, FirecrackerVm, run_guest,
};
use openshell_isolation::AgentSpec;
use openshell_isolation::contract::{
    BackendRegistry, BoundaryExitStatus, INTERFACE_VERSION, SandboxContext, TopologyDescriptor,
};

#[derive(Debug, Parser)]
#[command(about = "Experimental OpenShell Firecracker isolation driver")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Boot and wait for one Firecracker VM.
    Launch(LaunchArgs),
    /// Drive the RFC 0012 lifecycle from the host.
    Supervise(SuperviseArgs),
    /// Run the private process-supervisor leaf transport inside the guest.
    Guest(GuestArgs),
}

#[derive(Debug, Args)]
struct LaunchArgs {
    #[arg(
        long,
        env = "OPENSHELL_FIRECRACKER_BINARY",
        default_value = "firecracker"
    )]
    firecracker_binary: PathBuf,
    #[arg(long)]
    kernel_image: PathBuf,
    #[arg(long)]
    root_disk: PathBuf,
    #[arg(long)]
    run_dir: PathBuf,
    #[arg(long)]
    console_output: PathBuf,
    #[arg(
        long,
        default_value = "/opt/openshell/bin/openshell-driver-firecracker"
    )]
    guest_init: String,
    #[arg(long, default_value_t = 2)]
    vcpus: u8,
    #[arg(long, default_value_t = 512)]
    mem_mib: u32,
    #[arg(long)]
    vsock_cid: u32,
}

#[derive(Debug, Args)]
struct SuperviseArgs {
    #[arg(long)]
    boundary_id: String,
    #[arg(long)]
    vsock_uds_path: PathBuf,
    #[arg(long, default_value_t = 5500)]
    vsock_port: u32,
    #[arg(long)]
    bootstrap_token_file: PathBuf,
    #[arg(long, default_value = "/sandbox")]
    workdir: String,
    #[arg(long, default_value_t = 300)]
    timeout_seconds: u64,
    #[arg(required = true, trailing_var_arg = true)]
    command: Vec<String>,
}

#[derive(Debug, Args)]
struct GuestArgs {
    #[arg(long, default_value = DEFAULT_GUEST_CONFIG_PATH)]
    config: PathBuf,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Firecracker driver failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();
    let command = match cli.command {
        Some(command) => command,
        None if std::process::id() == 1 => Command::Guest(GuestArgs {
            config: PathBuf::from(DEFAULT_GUEST_CONFIG_PATH),
        }),
        None => return Err("a subcommand is required outside a Firecracker guest".to_string()),
    };
    match command {
        Command::Guest(args) => run_guest(&args.config),
        Command::Launch(args) => launch(args),
        Command::Supervise(args) => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|error| format!("create host runtime: {error}"))?;
            runtime.block_on(supervise(args))
        }
    }
}

fn launch(args: LaunchArgs) -> Result<(), String> {
    let config = FirecrackerLaunchConfig {
        firecracker_binary: resolve_executable(&args.firecracker_binary)?,
        kernel_image: args.kernel_image,
        root_disk: args.root_disk,
        run_dir: args.run_dir,
        console_output: args.console_output,
        guest_init: args.guest_init,
        vcpus: args.vcpus,
        mem_mib: args.mem_mib,
        vsock_cid: args.vsock_cid,
    };
    let mut vm = FirecrackerVm::launch(&config)?;
    let status = vm.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("Firecracker exited with status {status}"))
    }
}

async fn supervise(args: SuperviseArgs) -> Result<(), String> {
    let bootstrap_token = std::fs::read_to_string(&args.bootstrap_token_file)
        .map_err(|error| {
            format!(
                "read bootstrap token file {}: {error}",
                args.bootstrap_token_file.display()
            )
        })?
        .trim()
        .to_string();
    let topology = FirecrackerTopology {
        boundary_id: args.boundary_id.clone(),
        vsock_uds_path: args.vsock_uds_path,
        control_port: args.vsock_port,
        bootstrap_token,
    };
    let descriptor = TopologyDescriptor {
        version: INTERFACE_VERSION,
        backend_name: BACKEND_NAME.to_string(),
        payload: topology.encode().map_err(|error| error.to_string())?,
    };
    let mut registry = BackendRegistry::new();
    registry
        .register(Arc::new(FirecrackerHostBackend))
        .map_err(|error| error.to_string())?;
    let (backend, verified) = registry
        .resolve(descriptor, BACKEND_NAME)
        .map_err(|error| error.to_string())?;
    let (program, command_args) = args
        .command
        .split_first()
        .ok_or_else(|| "agent command must not be empty".to_string())?;
    let sandbox = SandboxContext {
        sandbox_id: args.boundary_id,
        policy: restrictive_host_policy(),
        agent: AgentSpec {
            program: program.clone(),
            args: command_args.to_vec(),
            workdir: Some(args.workdir),
            timeout_secs: args.timeout_seconds,
            interactive: false,
        },
    };
    let bound = backend
        .attach(verified, sandbox)
        .await
        .map_err(|error| error.to_string())?;
    let ready = bound.confirm().await.map_err(|error| error.to_string())?;
    let running = ready
        .start_agent()
        .await
        .map_err(|error| error.to_string())?;
    let process = running.agent();
    let wait = process.wait();
    tokio::pin!(wait);
    let status = tokio::select! {
        result = &mut wait => result.map_err(|error| error.to_string())?,
        signal = tokio::signal::ctrl_c() => {
            signal.map_err(|error| format!("wait for interrupt: {error}"))?;
            process.terminate().await.map_err(|error| error.to_string())?;
            process.wait().await.map_err(|error| error.to_string())?
        }
    };
    println!("agent exited: {status:?}");
    match status {
        BoundaryExitStatus::Exited(0) => Ok(()),
        _ => Err(format!("agent exited unsuccessfully: {status:?}")),
    }
}

fn restrictive_host_policy() -> SandboxPolicy {
    SandboxPolicy {
        version: 1,
        filesystem: FilesystemPolicy {
            read_only: ["/usr", "/lib", "/proc", "/dev/urandom", "/etc", "/var/log"]
                .into_iter()
                .map(PathBuf::from)
                .collect(),
            read_write: ["/sandbox", "/tmp", "/dev/null"]
                .into_iter()
                .map(PathBuf::from)
                .collect(),
            include_workdir: true,
        },
        network: NetworkPolicy::default(),
        landlock: LandlockPolicy::default(),
        process: ProcessPolicy::default(),
    }
}

fn resolve_executable(path: &Path) -> Result<PathBuf, String> {
    if path.components().count() > 1 || path.is_absolute() {
        return path
            .is_file()
            .then(|| path.to_path_buf())
            .ok_or_else(|| format!("executable not found: {}", path.display()));
    }
    let search_path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&search_path)
        .map(|directory| directory.join(path))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| format!("executable not found on PATH: {}", path.display()))
}
