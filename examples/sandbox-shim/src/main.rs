// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use openshell_sandbox_shim::{
    driver, guest, init,
    launch::{self, Launch, Privilege, Substrate},
    lifecycle,
};

#[derive(Parser)]
#[command(about = "Experimental OpenShell sandbox shim for Firecracker and gVisor guests")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Guest PID 1: set up the guest, run `serve`, reap orphans.
    Init {
        #[arg(long, value_enum)]
        substrate: Substrate,
    },
    /// Hold a privileged workload's namespaces open; does nothing else.
    #[command(hide = true)]
    Hold,
    /// Serve the Isolation Backend and Sandbox Protocol inside the guest.
    Serve {
        #[arg(long, value_enum)]
        substrate: Substrate,
    },
    /// Run the host compute driver for one substrate and privilege setting.
    Driver(Box<DriverArgs>),
}

#[derive(clap::Args)]
struct DriverArgs {
    #[arg(long)]
    state_dir: PathBuf,
    #[arg(long, value_enum)]
    substrate: Substrate,
    /// Explicit workload privilege; there is no default.
    #[arg(long, value_enum)]
    privilege: Privilege,
    /// SHA-256 of the workload rootfs source tree, before the driver's
    /// ownership transform.
    #[arg(long)]
    rootfs_source_digest: String,
    /// Static shim binary placed in the guest's own root.
    #[arg(long)]
    shim: PathBuf,
    /// Unique per run; scopes Docker container names and labels.
    #[arg(long)]
    run_id: String,
    #[arg(long)]
    supervisor: PathBuf,
    #[arg(long)]
    policy_rules: PathBuf,
    #[arg(long, env = "OPENSHELL_GATEWAY_ENDPOINT")]
    gateway_endpoint: String,
    #[arg(long)]
    socket: Option<PathBuf>,
    #[arg(long, required_if_eq("substrate", "firecracker"))]
    firecracker: Option<PathBuf>,
    #[arg(long, required_if_eq("substrate", "firecracker"))]
    kernel: Option<PathBuf>,
    #[arg(long, required_if_eq("substrate", "firecracker"))]
    rootfs_image: Option<PathBuf>,
    #[arg(long, default_value_t = 2)]
    vcpus: u8,
    #[arg(long, default_value_t = 1024)]
    memory_mib: u32,
    #[arg(long, required_if_eq("substrate", "gvisor"))]
    runsc_dir: Option<PathBuf>,
    #[arg(long, required_if_eq("substrate", "gvisor"))]
    rootfs_dir: Option<PathBuf>,
    #[arg(long, default_value = "buildpack-deps:26.04")]
    docker_image: String,
}

fn read_launch(substrate: Substrate) -> Result<Launch> {
    match substrate {
        Substrate::Firecracker => {
            let path = PathBuf::from(init::CONFIG_MOUNT).join("launch.json");
            let launch = serde_json::from_slice(&std::fs::read(&path)?)?;
            // The workload never sees the launch credentials.
            init::unmount(init::CONFIG_MOUNT).context("unmount launch config disk")?;
            Ok(launch)
        }
        Substrate::Gvisor => {
            let launch = serde_json::from_slice(&std::fs::read(init::GVISOR_LAUNCH)?)?;
            std::fs::remove_file(init::GVISOR_LAUNCH).context("remove launch file")?;
            Ok(launch)
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Command::Init { substrate } = cli.command {
        // PID 1 stays single-threaded; `serve` runs as its child.
        return init::run(substrate);
    }
    if let Command::Hold = cli.command {
        loop {
            // SAFETY: pause only waits for a signal.
            unsafe { libc::pause() };
        }
    }
    // Broker and relay diagnostics from openshell-sandbox go to the console.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .init();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(cli.command))
}

async fn run(command: Command) -> Result<()> {
    match command {
        Command::Init { .. } | Command::Hold => unreachable!(),
        Command::Serve { substrate } => {
            let launch = read_launch(substrate)?;
            let listen = match substrate {
                Substrate::Firecracker => lifecycle::Listen::Vsock(launch::VSOCK_PORT),
                Substrate::Gvisor => {
                    lifecycle::Listen::Unix(PathBuf::from(init::CHANNEL_DIR).join("backend.sock"))
                }
            };
            lifecycle::serve(launch, listen).await
        }
        Command::Driver(args) => {
            let DriverArgs {
                state_dir,
                substrate,
                privilege,
                rootfs_source_digest,
                shim,
                run_id,
                supervisor,
                policy_rules,
                gateway_endpoint,
                socket,
                firecracker,
                kernel,
                rootfs_image,
                vcpus,
                memory_mib,
                runsc_dir,
                rootfs_dir,
                docker_image,
            } = *args;
            anyhow::ensure!(
                !run_id.is_empty() && run_id.bytes().all(|b| b.is_ascii_alphanumeric()),
                "run id must be alphanumeric"
            );
            let shim = shim.canonicalize()?;
            let image = launch::Image {
                rootfs_source_sha256: rootfs_source_digest,
                shim_sha256: launch::file_sha256(&shim)?,
            };
            let canonical = |path: Option<PathBuf>| -> Result<PathBuf> {
                Ok(path.context("missing substrate path")?.canonicalize()?)
            };
            let substrate = match substrate {
                Substrate::Firecracker => {
                    std::fs::create_dir_all(&state_dir)?;
                    let initramfs = state_dir.join("initramfs.cpio");
                    guest::write_initramfs(&shim, &initramfs)?;
                    guest::Substrate::Firecracker(guest::FirecrackerConfig {
                        firecracker: canonical(firecracker)?,
                        kernel: canonical(kernel)?,
                        initramfs,
                        rootfs_image: canonical(rootfs_image)?,
                        vcpus,
                        memory_mib,
                    })
                }
                Substrate::Gvisor => guest::Substrate::Gvisor(guest::GvisorConfig {
                    runsc_dir: canonical(runsc_dir)?,
                    rootfs_dir: canonical(rootfs_dir)?,
                    shim,
                    docker_image,
                    run_id,
                }),
            };
            let socket = socket.unwrap_or_else(|| state_dir.join("compute.sock"));
            let driver = driver::Driver::new(
                state_dir,
                supervisor,
                gateway_endpoint,
                policy_rules,
                privilege,
                image,
                substrate,
            )?;
            driver::serve(Arc::new(driver), socket).await
        }
    }
}
