// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Dedicated in-MXC sandbox executable; the supervisor remains on the host.

use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(name = "openshell-windows-sandbox", version)]
#[command(about = "OpenShell Windows MXC isolation boundary")]
struct Args {
    /// Protected one-use bootstrap configuration staged by the MXC driver.
    #[arg(long)]
    bootstrap: PathBuf,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, default_value = "warn", env = "OPENSHELL_LOG_LEVEL")]
    log_level: String,
}

#[cfg(target_os = "windows")]
fn run(args: &Args) -> Result<(), String> {
    use openshell_ocsf::OcsfShorthandLayer;
    use tracing_subscriber::{EnvFilter, Layer, layer::SubscriberExt, util::SubscriberInitExt};

    let console_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level));
    let _ = tracing_subscriber::registry()
        .with(
            OcsfShorthandLayer::new(std::io::stderr())
                .with_non_ocsf(true)
                .with_filter(console_filter),
        )
        .try_init();
    openshell_mxc_boundary::run(&args.bootstrap)
}

#[cfg(not(target_os = "windows"))]
fn run(_args: &Args) -> Result<(), String> {
    Err("openshell-windows-sandbox requires Windows MXC".to_string())
}

fn main() -> ExitCode {
    match run(&Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
