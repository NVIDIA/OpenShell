// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    io::{self, Write},
    path::PathBuf,
    sync::Arc,
};

use anyhow::Result;
use clap::{Parser, Subcommand};
use openshell_wasi_backend_example::{
    backend::{Backend, Provisioned},
    guest::{DEFAULT_FUEL, Guest, GuestStatus, read_module},
    protocol::{
        BACKEND, boundary::sandbox_boundary_server::SandboxBoundaryServer,
        control::sandbox_backend_server::SandboxBackendServer,
    },
};
use tokio_stream::{StreamExt, wrappers::TcpListenerStream};

#[derive(Parser)]
#[command(about = "Partial WASI backend service and a separate local guest runner")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a guest locally, without supervisor admission.
    Run {
        module: PathBuf,
        #[arg(long)]
        workspace: PathBuf,
    },
    /// Serve the partial protobuf contract on an ephemeral loopback port.
    Serve {
        module: PathBuf,
        #[arg(long)]
        sandbox_id: String,
        #[arg(long)]
        session_id: String,
        #[arg(long)]
        generation_id: String,
        #[arg(long)]
        token_file: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Run { module, workspace } => {
            let bytes = read_module(&module)?;
            let result = tokio::task::spawn_blocking(move || {
                Guest::new(&bytes)?.run(&workspace, DEFAULT_FUEL)
            })
            .await??;
            io::stdout().write_all(&result.stdout)?;
            io::stderr().write_all(&result.stderr)?;
            eprintln!("{}", serde_json::to_string(&result)?);
            if result.status != GuestStatus::Exited || result.exit_code != Some(0) {
                std::process::exit(1);
            }
        }
        Command::Serve {
            module,
            sandbox_id,
            session_id,
            generation_id,
            token_file,
        } => {
            let token = std::fs::read_to_string(token_file)?.trim().to_string();
            let launch = Provisioned::new(
                sandbox_id,
                session_id,
                generation_id,
                token,
                &read_module(&module)?,
            )?;
            let descriptor: serde_json::Value = serde_json::from_slice(&launch.descriptor)?;
            let backend = Arc::new(Backend::new(launch));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            println!(
                "{}",
                serde_json::json!({"endpoint": listener.local_addr()?.to_string(), "backend_name": BACKEND, "descriptor": descriptor})
            );
            io::stdout().flush()?;
            // Custom incoming streams bypass Tonic's TCP settings.
            let incoming = TcpListenerStream::new(listener).map(|accepted| {
                accepted.inspect(|socket| {
                    let _ = socket.set_nodelay(true);
                })
            });
            tonic::transport::Server::builder()
                .add_service(
                    SandboxBackendServer::from_arc(backend.clone())
                        .max_decoding_message_size(1024 * 1024),
                )
                .add_service(
                    SandboxBoundaryServer::from_arc(backend).max_decoding_message_size(1024 * 1024),
                )
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await?;
        }
    }
    Ok(())
}
