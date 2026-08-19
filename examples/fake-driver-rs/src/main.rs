// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Scriptable fake compute driver for testing gateway integration.
//!
//! Implements the `ComputeDriver` gRPC service with responses driven by a
//! TOML config file. Each RPC has an ordered sequence of scripted responses;
//! when the sequence is exhausted the last entry repeats.
//!
//! # Usage
//!
//! ```text
//! fake-driver-rs --socket /tmp/fake-driver.sock --config scenario.toml
//! ```
//!
//! Point the gateway at it via its remote driver config:
//!
//! ```toml
//! [compute]
//! driver = "remote"
//!
//! [compute.remote]
//! socket = "/tmp/fake-driver.sock"
//! ```

use std::path::PathBuf;

use clap::Parser;
use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_core::proto::compute::v1::compute_driver_server::ComputeDriverServer;
use tokio::net::UnixListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio_stream::wrappers::UnixListenerStream;
use tracing::info;
use tracing_subscriber::EnvFilter;

mod config;
mod driver;
mod sequence;

use config::Config;
use driver::FakeDriver;

#[derive(Parser)]
#[command(name = "fake-driver-rs")]
#[command(about = "Scriptable fake compute driver for testing gateway integration")]
struct Args {
    /// Unix socket path the driver will listen on.
    #[arg(long, env = "FAKE_DRIVER_SOCKET")]
    socket: PathBuf,

    /// Path to the TOML scenario config file.
    #[arg(long, env = "FAKE_DRIVER_CONFIG")]
    config: PathBuf,

    #[arg(long, env = "FAKE_DRIVER_LOG_LEVEL", default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level)),
        )
        .init();

    let raw = std::fs::read_to_string(&args.config)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read config from {}", args.config.display()))?;
    let config: Config = toml::from_str(&raw)
        .into_diagnostic()
        .wrap_err("failed to parse config")?;

    // Remove a stale socket file if present so bind succeeds.
    if args.socket.exists() {
        std::fs::remove_file(&args.socket)
            .into_diagnostic()
            .wrap_err("failed to remove stale socket")?;
    }

    let listener = UnixListener::bind(&args.socket)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to bind socket {}", args.socket.display()))?;

    info!(socket = %args.socket.display(), "fake-driver-rs listening");

    let service = ComputeDriverServer::new(FakeDriver::new(config));

    let mut sigterm = signal(SignalKind::terminate()).into_diagnostic()?;

    tonic::transport::Server::builder()
        .add_service(service)
        .serve_with_incoming_shutdown(UnixListenerStream::new(listener), async move {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = sigterm.recv() => {}
            }
            info!("received shutdown signal");
        })
        .await
        .into_diagnostic()
}
