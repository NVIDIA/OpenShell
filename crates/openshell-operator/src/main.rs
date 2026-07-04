// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OpenShell Kubernetes Operator for declarative sandbox lifecycle management.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "openshell-operator",
    about = "Kubernetes operator for SandboxRuntime CRDs"
)]
struct Args {
    /// Namespace to watch (empty = all namespaces).
    #[arg(long, env = "WATCH_NAMESPACE", default_value = "")]
    namespace: String,

    /// Metrics bind address.
    #[arg(
        long,
        env = "METRICS_BIND_ADDRESS",
        default_value = "0.0.0.0:8080"
    )]
    metrics_addr: String,

    /// Webhook server bind address.
    #[arg(
        long,
        env = "WEBHOOK_BIND_ADDRESS",
        default_value = "0.0.0.0:9443"
    )]
    webhook_addr: String,

    /// Path to TLS certificate for webhook server.
    #[arg(long, env = "WEBHOOK_TLS_CERT")]
    tls_cert: Option<String>,

    /// Path to TLS key for webhook server.
    #[arg(long, env = "WEBHOOK_TLS_KEY")]
    tls_key: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,kube=warn".into()),
        )
        .json()
        .init();

    let config = openshell_operator::OperatorConfig {
        namespace: if args.namespace.is_empty() {
            None
        } else {
            Some(args.namespace)
        },
        metrics_addr: args.metrics_addr,
        webhook_addr: args.webhook_addr,
        tls_cert_path: args.tls_cert,
        tls_key_path: args.tls_key,
    };

    openshell_operator::run(config).await
}
