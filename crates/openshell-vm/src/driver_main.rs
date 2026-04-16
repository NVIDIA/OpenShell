// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use miette::{IntoDiagnostic, Result};
use openshell_core::VERSION;
use openshell_core::proto::compute_driver_server::ComputeDriverServer;
use openshell_vm::{VmDriver, VmDriverConfig};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "openshell-driver-vm")]
#[command(version = VERSION)]
struct Args {
    #[arg(
        long,
        env = "OPENSHELL_COMPUTE_DRIVER_BIND",
        default_value = "127.0.0.1:50061"
    )]
    bind_address: SocketAddr,

    #[arg(long, env = "OPENSHELL_LOG_LEVEL", default_value = "info")]
    log_level: String,

    #[arg(long, env = "OPENSHELL_GRPC_ENDPOINT")]
    openshell_endpoint: String,

    #[arg(long, env = "OPENSHELL_VM_BIN")]
    vm_bin: Option<PathBuf>,

    #[arg(
        long,
        env = "OPENSHELL_VM_DRIVER_STATE_DIR",
        default_value = "target/openshell-vm-driver"
    )]
    state_dir: PathBuf,

    #[arg(long, env = "OPENSHELL_SSH_HANDSHAKE_SECRET")]
    ssh_handshake_secret: String,

    #[arg(long, env = "OPENSHELL_SSH_HANDSHAKE_SKEW_SECS", default_value_t = 300)]
    ssh_handshake_skew_secs: u64,

    #[arg(long, env = "OPENSHELL_TLS_CA")]
    tls_ca: Option<PathBuf>,

    #[arg(long, env = "OPENSHELL_TLS_CERT")]
    tls_cert: Option<PathBuf>,

    #[arg(long, env = "OPENSHELL_TLS_KEY")]
    tls_key: Option<PathBuf>,

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
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level)),
        )
        .init();

    let vm_bin = resolve_vm_binary(args.vm_bin).map_err(|err| miette::miette!("{err}"))?;

    let driver = VmDriver::new(VmDriverConfig {
        vm_bin,
        openshell_endpoint: args.openshell_endpoint,
        state_dir: args.state_dir,
        ssh_handshake_secret: args.ssh_handshake_secret,
        ssh_handshake_skew_secs: args.ssh_handshake_skew_secs,
        log_level: args.log_level,
        krun_log_level: args.krun_log_level,
        vcpus: args.vcpus,
        mem_mib: args.mem_mib,
        tls_ca: args.tls_ca,
        tls_cert: args.tls_cert,
        tls_key: args.tls_key,
    })
    .await
    .map_err(|err| miette::miette!("{err}"))?;

    info!(address = %args.bind_address, "Starting vm compute driver");
    tonic::transport::Server::builder()
        .add_service(ComputeDriverServer::new(driver))
        .serve(args.bind_address)
        .await
        .into_diagnostic()
}

fn resolve_vm_binary(explicit: Option<PathBuf>) -> std::result::Result<PathBuf, String> {
    if let Some(path) = explicit {
        return Ok(path);
    }

    let current_exe = std::env::current_exe()
        .map_err(|err| format!("failed to resolve current executable: {err}"))?;
    let suffix = std::env::consts::EXE_SUFFIX;
    Ok(current_exe.with_file_name(format!("openshell-vm{suffix}")))
}
