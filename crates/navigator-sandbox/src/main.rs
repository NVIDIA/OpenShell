//! Navigator Sandbox - process sandbox and monitor.

use clap::Parser;
use miette::{IntoDiagnostic, Result};
use tracing::info;
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
    /// Requires --rego-data to also be set.
    #[arg(long, env = "NAVIGATOR_REGO_POLICY")]
    rego_policy: Option<String>,

    /// Path to Rego data file containing network policies and sandbox config.
    /// Requires --rego-policy to also be set.
    #[arg(long, env = "NAVIGATOR_REGO_DATA")]
    rego_data: Option<String>,

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

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/var/log/navigator.log")
        .into_diagnostic()?;
    let (file_writer, _file_guard) = tracing_appender::non_blocking(file);

    let stdout_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level));
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
        .init();

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
        args.rego_policy,
        args.rego_data,
        args.ssh_listen_addr,
        args.ssh_handshake_secret,
        args.ssh_handshake_skew_secs,
        args.health_check,
        args.health_port,
    )
    .await?;

    std::process::exit(exit_code);
}
