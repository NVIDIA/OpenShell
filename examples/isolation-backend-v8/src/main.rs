// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{path::PathBuf, sync::Arc};

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(about = "Network-disabled JavaScript sandbox and local compute driver")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the JavaScript runtime on its authenticated Unix socket.
    Serve {
        #[arg(long, env = "JS_SBX_STATE")]
        state_dir: PathBuf,
    },
    /// Run the local-development compute driver on a private Unix socket.
    Driver {
        #[arg(long, env = "JS_SBX_STATE")]
        state_dir: PathBuf,
        #[arg(long)]
        socket: Option<PathBuf>,
        #[arg(long, default_value = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/debug/openshell-supervisor"))]
        supervisor: PathBuf,
        #[arg(long, default_value = "guest.js")]
        script: PathBuf,
        #[arg(
            long,
            env = "OPENSHELL_GATEWAY_ENDPOINT",
            default_value = "http://127.0.0.1:18770"
        )]
        gateway_endpoint: String,
        #[arg(long, default_value = concat!(env!("CARGO_MANIFEST_DIR"), "/../../crates/openshell-supervisor-network/data/sandbox-policy.rego"))]
        policy_rules: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Serve { state_dir } => {
            rustls::crypto::aws_lc_rs::default_provider()
                .install_default()
                .ok();
            js_sbx::lifecycle::serve(state_dir).await?;
        }
        Command::Driver {
            state_dir,
            socket,
            supervisor,
            script,
            gateway_endpoint,
            policy_rules,
        } => {
            let socket = socket.unwrap_or_else(|| state_dir.join("compute.sock"));
            let driver = js_sbx::driver::Driver::new(
                state_dir,
                supervisor,
                script,
                gateway_endpoint,
                policy_rules,
            )?;
            js_sbx::driver::serve(Arc::new(driver), socket).await?;
        }
    }
    Ok(())
}
