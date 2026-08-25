// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{Args, Parser, Subcommand};
use openshell_core::policy::{
    FilesystemPolicy, LandlockPolicy, NetworkPolicy, ProcessPolicy, SandboxPolicy,
};
use openshell_core::proto::compute::v1::compute_driver_server::ComputeDriverServer;
use openshell_driver_firecracker::{
    BACKEND_NAME, DEFAULT_GUEST_CONFIG_PATH, FirecrackerComputeConfig, FirecrackerComputeDriver,
    FirecrackerHostBackend, FirecrackerLaunchConfig, FirecrackerTopology, FirecrackerVm, run_guest,
};
use openshell_isolation::AgentSpec;
use openshell_isolation::contract::{
    BackendRegistry, BoundaryExitStatus, INTERFACE_VERSION, SandboxContext, TopologyDescriptor,
};
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;

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
    /// Serve the gateway compute-driver contract over a Unix socket.
    ComputeDriver(ComputeDriverArgs),
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

#[derive(Debug, Args)]
struct ComputeDriverArgs {
    #[arg(long, env = "OPENSHELL_COMPUTE_DRIVER_SOCKET")]
    bind_socket: PathBuf,
    #[arg(long, env = "OPENSHELL_GRPC_ENDPOINT")]
    gateway_endpoint: String,
    #[arg(long, env = "OPENSHELL_FIRECRACKER_STATE_DIR")]
    state_dir: PathBuf,
    #[arg(long, env = "OPENSHELL_FIRECRACKER_BINARY")]
    firecracker_binary: PathBuf,
    #[arg(long, env = "OPENSHELL_FIRECRACKER_KERNEL_IMAGE")]
    kernel_image: PathBuf,
    #[arg(long, env = "OPENSHELL_FIRECRACKER_ROOT_DISK")]
    root_disk: PathBuf,
    #[arg(long, env = "OPENSHELL_FIRECRACKER_SUPERVISOR_BIN")]
    supervisor_binary: PathBuf,
    #[arg(long, default_value = "firecracker-rootfs")]
    default_image: String,
    #[arg(long, default_value_t = 2)]
    vcpus: u8,
    #[arg(long, default_value_t = 512)]
    mem_mib: u32,
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
        Command::ComputeDriver(args) => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|error| format!("create compute-driver runtime: {error}"))?;
            runtime.block_on(serve_compute_driver(args))
        }
    }
}

async fn serve_compute_driver(args: ComputeDriverArgs) -> Result<(), String> {
    nix::sys::prctl::set_pdeathsig(nix::sys::signal::Signal::SIGTERM)
        .map_err(|error| format!("arm compute-driver parent-death signal: {error}"))?;
    prepare_compute_socket(&args.bind_socket)?;
    let driver_binary = std::env::current_exe()
        .map_err(|error| format!("resolve Firecracker driver binary: {error}"))?;
    let driver = FirecrackerComputeDriver::new(FirecrackerComputeConfig {
        gateway_endpoint: args.gateway_endpoint,
        state_dir: args.state_dir,
        firecracker_binary: resolve_executable(&args.firecracker_binary)?,
        kernel_image: args.kernel_image,
        root_disk: args.root_disk,
        supervisor_binary: args.supervisor_binary,
        driver_binary,
        default_image: args.default_image,
        vcpus: args.vcpus,
        mem_mib: args.mem_mib,
    })?;
    let listener = UnixListener::bind(&args.bind_socket)
        .map_err(|error| format!("bind compute-driver socket: {error}"))?;
    std::fs::set_permissions(&args.bind_socket, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("restrict compute-driver socket: {error}"))?;
    eprintln!(
        "Firecracker compute driver listening on {}",
        args.bind_socket.display()
    );
    let result = tonic::transport::Server::builder()
        .add_service(ComputeDriverServer::new(driver))
        .serve_with_incoming(UnixListenerStream::new(listener))
        .await
        .map_err(|error| format!("serve compute driver: {error}"));
    let _ = std::fs::remove_file(&args.bind_socket);
    result
}

fn prepare_compute_socket(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "compute-driver socket requires a parent directory".to_string())?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("create compute-driver socket directory: {error}"))?;
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("restrict compute-driver socket directory: {error}"))?;
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => std::fs::remove_file(path)
            .map_err(|error| format!("remove stale compute-driver socket: {error}")),
        Ok(_) => Err(format!(
            "refusing to replace non-socket compute-driver path {}",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("inspect compute-driver socket: {error}")),
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
