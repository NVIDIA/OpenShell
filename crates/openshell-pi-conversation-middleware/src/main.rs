// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;

use clap::Parser;
use miette::{IntoDiagnostic, Result};
use openshell_core::proto::middleware::v1::supervisor_middleware_server::SupervisorMiddlewareServer;
use openshell_pi_conversation_middleware::PrototypeService;
use tonic::transport::Server;

#[derive(Debug, Parser)]
#[command(about = "Run the Pi conversation reference gRPC middleware")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:50061")]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    tracing::info!(listen = %args.listen, "Pi conversation middleware listening");
    Server::builder()
        .add_service(SupervisorMiddlewareServer::new(PrototypeService::new()))
        .serve(args.listen)
        .await
        .into_diagnostic()
}
