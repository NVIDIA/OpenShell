// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    io::{self, Write},
    path::PathBuf,
    sync::Arc,
};

use anyhow::Result;
use clap::{Parser, Subcommand};
use openshell_v8_backend_example::guest::{Guest, GuestStatus, read_script};

#[derive(Parser)]
#[command(about = "Local V8 backend, example compute driver, and guest runner")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve driver-provisioned launches over authenticated TLS.
    Backend {
        #[arg(long, env = "V8_DEMO_STATE")]
        state_dir: PathBuf,
    },
    /// Run the local-development compute driver on a private Unix socket.
    Driver {
        #[arg(long, env = "V8_DEMO_STATE")]
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
    /// Run a guest locally, without supervisor admission.
    Run { script: PathBuf },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Backend { state_dir } => {
            rustls::crypto::aws_lc_rs::default_provider()
                .install_default()
                .ok();
            openshell_v8_backend_example::lifecycle::serve(state_dir).await?;
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
            let driver = openshell_v8_backend_example::driver::Driver::new(
                state_dir,
                supervisor,
                script,
                gateway_endpoint,
                policy_rules,
            )?;
            openshell_v8_backend_example::driver::serve(Arc::new(driver), socket).await?;
        }
        Command::Run { script } => {
            let bytes = read_script(&script)?;
            let result =
                tokio::task::spawn_blocking(move || Guest::new(&bytes)?.run(None, |_, _| {}))
                    .await??;
            io::stdout().write_all(&result.stdout)?;
            io::stderr().write_all(&result.stderr)?;
            eprintln!("{}", serde_json::to_string(&result)?);
            if result.status != GuestStatus::Exited || result.exit_code != Some(0) {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}
