// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Navigator Sandbox - process sandbox and monitor.

use clap::Parser;
use miette::Result;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};

use navigator_sandbox::run_sandbox;

/// Navigator Sandbox - process isolation and monitoring.
#[derive(Parser, Debug)]
#[command(name = "navigator-sandbox")]
#[command(about = "Process sandbox and monitor", long_about = None)]
struct Args {
    /// Command to execute in the sandbox.
    /// Can also be provided via `NAVIGATOR_SANDBOX_COMMAND` environment variable.
    /// Defaults to `/bin/bash` if neither is provided.
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,

    /// Working directory for the sandboxed process.
    #[arg(long, short)]
    workdir: Option<String>,

    /// Timeout in seconds (0 = no timeout).
    #[arg(long, short, default_value = "0")]
    timeout: u64,

    /// Run in interactive mode (inherit process group for terminal control).
    #[arg(long, short = 'i')]
    interactive: bool,

    /// Sandbox ID for fetching policy via gRPC from Navigator server.
    /// Requires --navigator-endpoint to be set.
    #[arg(long, env = "NAVIGATOR_SANDBOX_ID")]
    sandbox_id: Option<String>,

    /// Navigator server gRPC endpoint for fetching policy.
    /// Required when using --sandbox-id.
    #[arg(long, env = "NAVIGATOR_ENDPOINT")]
    navigator_endpoint: Option<String>,

    /// Path to Rego policy file for OPA-based network access control.
    /// Requires --policy-data to also be set.
    #[arg(long, env = "NAVIGATOR_POLICY_RULES")]
    policy_rules: Option<String>,

    /// Path to YAML data file containing network policies and sandbox config.
    /// Requires --policy-rules to also be set.
    #[arg(long, env = "NAVIGATOR_POLICY_DATA")]
    policy_data: Option<String>,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, default_value = "warn", env = "NAVIGATOR_LOG_LEVEL")]
    log_level: String,

    /// SSH listen address for sandbox access.
    #[arg(long, env = "NAVIGATOR_SSH_LISTEN_ADDR")]
    ssh_listen_addr: Option<String>,

    /// Shared secret for gateway-to-sandbox SSH handshake.
    #[arg(long, env = "NAVIGATOR_SSH_HANDSHAKE_SECRET")]
    ssh_handshake_secret: Option<String>,

    /// Allowed clock skew for SSH handshake validation.
    #[arg(long, env = "NAVIGATOR_SSH_HANDSHAKE_SKEW_SECS", default_value = "300")]
    ssh_handshake_skew_secs: u64,

    /// Path to YAML inference routes for standalone routing.
    /// When set, inference routes are loaded from this file instead of
    /// fetching a bundle from the gateway.
    #[arg(long, env = "NAVIGATOR_INFERENCE_ROUTES")]
    inference_routes: Option<String>,

    /// Enable health check endpoint.
    #[arg(long)]
    health_check: bool,

    /// Port for health check endpoint.
    #[arg(long, default_value = "8080")]
    health_port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Try to open the log file; fall back to stdout-only logging if it fails
    // (e.g., /var/log is not writable in custom workload images).
    let file_logging = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/var/log/navigator.log")
        .ok()
        .map(|file| {
            let (writer, guard) = tracing_appender::non_blocking(file);
            (writer, guard)
        });

    let stdout_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level));

    // Install rustls crypto provider before any TLS connections (including log push).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Set up optional log push layer (gRPC mode only).
    let log_push_state = if let (Some(sandbox_id), Some(endpoint)) =
        (&args.sandbox_id, &args.navigator_endpoint)
    {
        let (tx, handle) =
            navigator_sandbox::log_push::spawn_log_push_task(endpoint.clone(), sandbox_id.clone());
        let layer = navigator_sandbox::log_push::LogPushLayer::new(sandbox_id.clone(), tx);
        Some((layer, handle))
    } else {
        None
    };
    let push_layer = log_push_state.as_ref().map(|(layer, _)| layer.clone());
    let _log_push_handle = log_push_state.map(|(_, handle)| handle);

    // Keep the file guard alive for the entire process. When the guard is
    // dropped the non-blocking writer flushes remaining logs.
    let _file_guard = if let Some((file_writer, file_guard)) = file_logging {
        let file_filter = EnvFilter::new("info");
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(std::io::stdout)
                    .with_filter(stdout_filter),
            )
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(file_writer)
                    .with_ansi(false)
                    .with_filter(file_filter),
            )
            .with(push_layer.clone())
            .init();
        Some(file_guard)
    } else {
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(std::io::stdout)
                    .with_filter(stdout_filter),
            )
            .with(push_layer)
            .init();
        // Log the warning after the subscriber is initialized
        warn!("Could not open /var/log/navigator.log; using stdout-only logging");
        None
    };

    // Get command - either from CLI args, environment variable, or default to /bin/bash
    let command = if !args.command.is_empty() {
        args.command
    } else if let Ok(c) = std::env::var("NAVIGATOR_SANDBOX_COMMAND") {
        // Simple shell-like splitting on whitespace
        c.split_whitespace().map(String::from).collect()
    } else {
        vec!["/bin/bash".to_string()]
    };

    info!(command = ?command, "Starting sandbox");

    let exit_code = run_sandbox(
        command,
        args.workdir,
        args.timeout,
        args.interactive,
        args.sandbox_id,
        args.navigator_endpoint,
        args.policy_rules,
        args.policy_data,
        args.ssh_listen_addr,
        args.ssh_handshake_secret,
        args.ssh_handshake_skew_secs,
        args.health_check,
        args.health_port,
        args.inference_routes,
    )
    .await?;

    std::process::exit(exit_code);
}
