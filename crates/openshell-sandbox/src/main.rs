// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `OpenShell` Sandbox - process sandbox and monitor.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use clap::Parser;
use miette::{IntoDiagnostic, Result};
use openshell_ocsf::{OcsfJsonlLayer, OcsfShorthandLayer};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};

use openshell_sandbox::run_sandbox;

/// Subcommand name used to self-copy the supervisor binary into a shared volume.
///
/// The supervisor image only ships the binary itself, so init containers
/// cannot rely on `sh`/`cp` to copy the binary out. Invoking the binary itself
/// with this argument performs the copy in pure Rust.
const COPY_SELF_SUBCOMMAND: &str = "copy-self";

/// `OpenShell` Sandbox - process isolation and monitoring.
#[derive(Parser, Debug)]
#[command(name = "openshell-sandbox")]
#[command(version = openshell_core::VERSION)]
#[command(about = "Process sandbox and monitor", long_about = None)]
struct Args {
    /// Command to execute in the sandbox.
    /// Can also be provided via `OPENSHELL_SANDBOX_COMMAND` environment variable.
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

    /// Sandbox ID for fetching policy via gRPC from `OpenShell` server.
    /// Requires --openshell-endpoint to be set.
    #[arg(long, env = "OPENSHELL_SANDBOX_ID")]
    sandbox_id: Option<String>,

    /// Sandbox (used for policy sync when the sandbox discovers policy
    /// from disk or falls back to the restrictive default).
    #[arg(long, env = "OPENSHELL_SANDBOX")]
    sandbox: Option<String>,

    /// `OpenShell` server gRPC endpoint for fetching policy.
    /// Required when using --sandbox-id.
    #[arg(long, env = "OPENSHELL_ENDPOINT")]
    openshell_endpoint: Option<String>,

    /// Path to Rego policy file for OPA-based network access control.
    /// Requires --policy-data to also be set.
    #[arg(long, env = "OPENSHELL_POLICY_RULES")]
    policy_rules: Option<String>,

    /// Path to YAML data file containing network policies and sandbox config.
    /// Requires --policy-rules to also be set.
    #[arg(long, env = "OPENSHELL_POLICY_DATA")]
    policy_data: Option<String>,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, default_value = "warn", env = "OPENSHELL_LOG_LEVEL")]
    log_level: String,

    /// Filesystem path to the Unix socket the embedded SSH daemon binds.
    /// The supervisor bridges `RelayStream` traffic from the gateway onto
    /// this socket; nothing else should connect to it.
    #[arg(long, env = "OPENSHELL_SSH_SOCKET_PATH")]
    ssh_socket_path: Option<String>,

    /// Shared secret for gateway-to-sandbox SSH handshake.
    #[arg(long, env = "OPENSHELL_SSH_HANDSHAKE_SECRET")]
    ssh_handshake_secret: Option<String>,

    /// Allowed clock skew for SSH handshake validation.
    #[arg(long, env = "OPENSHELL_SSH_HANDSHAKE_SKEW_SECS", default_value = "300")]
    ssh_handshake_skew_secs: u64,

    /// Path to YAML inference routes for standalone routing.
    /// When set, inference routes are loaded from this file instead of
    /// fetching a bundle from the gateway.
    #[arg(long, env = "OPENSHELL_INFERENCE_ROUTES")]
    inference_routes: Option<String>,

    /// Enable health check endpoint.
    #[arg(long)]
    health_check: bool,

    /// Port for health check endpoint.
    #[arg(long, default_value = "8080")]
    health_port: u16,
}

/// Copy the running executable to `dest`, creating parent directories as
/// needed and ensuring the result is executable (mode `0755`).
///
/// If `dest` already exists as a directory, the binary is placed inside it
/// using the source executable's file name. This mirrors `cp` semantics so
/// callers can pass either a full target path or a directory.
fn copy_self(dest: &str) -> Result<()> {
    let exe = std::env::current_exe().into_diagnostic()?;

    let dest_path = Path::new(dest);
    let final_path = if dest_path.is_dir() {
        let file_name = exe
            .file_name()
            .ok_or_else(|| miette::miette!("current_exe has no file name: {}", exe.display()))?;
        dest_path.join(file_name)
    } else {
        dest_path.to_path_buf()
    };

    if let Some(parent) = final_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).into_diagnostic()?;
    }

    std::fs::copy(&exe, &final_path).into_diagnostic()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&final_path)
            .into_diagnostic()?
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&final_path, perms).into_diagnostic()?;
    }

    Ok(())
}

fn main() -> Result<()> {
    // Handle `copy-self <DEST>` before clap so it works without any of the
    // sandbox flags. The supervisor image only ships the binary itself, and
    // Kubernetes init containers invoke this path to seed an emptyDir volume
    // that the agent container then executes from.
    let raw_args: Vec<String> = std::env::args().collect();
    if raw_args.get(1).map(String::as_str) == Some(COPY_SELF_SUBCOMMAND) {
        let dest = raw_args.get(2).ok_or_else(|| {
            miette::miette!("usage: openshell-sandbox {COPY_SELF_SUBCOMMAND} <DEST>")
        })?;
        return copy_self(dest);
    }

    let args = Args::parse();

    // Try to open a rolling log file; fall back to stderr-only logging if it fails
    // (e.g., /var/log is not writable in custom workload images).
    // Rotates daily, keeps the 3 most recent files to bound disk usage.
    let file_logging = tracing_appender::rolling::RollingFileAppender::builder()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("openshell")
        .filename_suffix("log")
        .max_log_files(3)
        .build("/var/log")
        .ok()
        .map(|roller| {
            let (writer, guard) = tracing_appender::non_blocking(roller);
            (writer, guard)
        });

    let console_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .into_diagnostic()?;

    let exit_code = runtime.block_on(async move {
        // Install rustls crypto provider before any TLS connections (including log push).
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Set up optional log push layer (gRPC mode only).
        let log_push_state = if let (Some(sandbox_id), Some(endpoint)) =
            (&args.sandbox_id, &args.openshell_endpoint)
        {
            let (tx, handle) = openshell_sandbox::log_push::spawn_log_push_task(
                endpoint.clone(),
                sandbox_id.clone(),
            );
            let layer = openshell_sandbox::log_push::LogPushLayer::new(sandbox_id.clone(), tx);
            Some((layer, handle))
        } else {
            None
        };
        let push_layer = log_push_state.as_ref().map(|(layer, _)| layer.clone());
        let _log_push_handle = log_push_state.map(|(_, handle)| handle);

        // Shared flag: the sandbox poll loop toggles this when the
        // `ocsf_json_enabled` setting changes. The JSONL layer checks it
        // on each event and short-circuits when false.
        let ocsf_enabled = Arc::new(AtomicBool::new(false));

        // Keep guards alive for the entire process. When a guard is dropped the
        // non-blocking writer flushes remaining logs.
        let (_file_guard, _jsonl_guard) = if let Some((file_writer, file_guard)) = file_logging {
            let file_filter = EnvFilter::new("info");

            // OCSF JSONL file: rolling appender matching the main log file
            // (daily rotation, 3 files max). Created eagerly but gated by the
            // enabled flag — no JSONL is written until ocsf_json_enabled is set.
            let jsonl_logging = tracing_appender::rolling::RollingFileAppender::builder()
                .rotation(tracing_appender::rolling::Rotation::DAILY)
                .filename_prefix("openshell-ocsf")
                .filename_suffix("log")
                .max_log_files(3)
                .build("/var/log")
                .ok()
                .map(|roller| {
                    let (writer, guard) = tracing_appender::non_blocking(roller);
                    let layer = OcsfJsonlLayer::new(writer).with_enabled_flag(ocsf_enabled.clone());
                    (layer, guard)
                });
            let (jsonl_layer, jsonl_guard) = match jsonl_logging {
                Some((layer, guard)) => (Some(layer), Some(guard)),
                None => (None, None),
            };

            tracing_subscriber::registry()
                .with(
                    OcsfShorthandLayer::new(std::io::stderr())
                        .with_non_ocsf(true)
                        .with_filter(console_filter),
                )
                .with(
                    OcsfShorthandLayer::new(file_writer)
                        .with_non_ocsf(true)
                        .with_filter(file_filter),
                )
                .with(jsonl_layer.with_filter(LevelFilter::INFO))
                .with(push_layer.clone())
                .init();
            (Some(file_guard), jsonl_guard)
        } else {
            tracing_subscriber::registry()
                .with(
                    OcsfShorthandLayer::new(std::io::stderr())
                        .with_non_ocsf(true)
                        .with_filter(console_filter),
                )
                .with(push_layer)
                .init();
            // Log the warning after the subscriber is initialized
            warn!("Could not open /var/log for log rotation; using stderr-only logging");
            (None, None)
        };

        // Get command - either from CLI args, environment variable, or default to /bin/bash
        let command = if !args.command.is_empty() {
            args.command
        } else if let Ok(c) = std::env::var("OPENSHELL_SANDBOX_COMMAND") {
            // Simple shell-like splitting on whitespace
            c.split_whitespace().map(String::from).collect()
        } else {
            vec!["/bin/bash".to_string()]
        };

        info!(command = ?command, "Starting sandbox");
        // Note: "Starting sandbox" stays as plain info!() since the OCSF context
        // is not yet initialized at this point (run_sandbox hasn't been called).
        // The shorthand layer will render it in fallback format.

        run_sandbox(
            command,
            args.workdir,
            args.timeout,
            args.interactive,
            args.sandbox_id,
            args.sandbox,
            args.openshell_endpoint,
            args.policy_rules,
            args.policy_data,
            args.ssh_socket_path,
            args.ssh_handshake_secret,
            args.ssh_handshake_skew_secs,
            args.health_check,
            args.health_port,
            args.inference_routes,
            ocsf_enabled,
        )
        .await
    })?;

    std::process::exit(exit_code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Drives `copy_self`'s file-copy logic against an arbitrary source path
    /// so tests don't depend on `current_exe()`.
    fn copy_executable(src: &Path, dest: &Path) -> Result<()> {
        let final_path = if dest.is_dir() {
            dest.join(src.file_name().unwrap())
        } else {
            dest.to_path_buf()
        };
        if let Some(parent) = final_path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).into_diagnostic()?;
        }
        std::fs::copy(src, &final_path).into_diagnostic()?;
        let mut perms = std::fs::metadata(&final_path)
            .into_diagnostic()?
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&final_path, perms).into_diagnostic()?;
        Ok(())
    }

    #[test]
    fn copy_self_writes_executable_at_target_path() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("source-bin");
        std::fs::write(&src, b"#!/bin/false\n").unwrap();

        let dest = tmp.path().join("subdir/openshell-sandbox");
        copy_executable(&src, &dest).unwrap();

        assert!(dest.exists(), "destination file should exist");
        let mode = std::fs::metadata(&dest).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755, "destination must be 0755");
        let copied = std::fs::read(&dest).unwrap();
        assert_eq!(copied, b"#!/bin/false\n");
    }

    #[test]
    fn copy_self_into_existing_directory_uses_source_filename() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("openshell-sandbox");
        std::fs::write(&src, b"binary").unwrap();

        let dest_dir = tmp.path().join("bin");
        std::fs::create_dir_all(&dest_dir).unwrap();

        copy_executable(&src, &dest_dir).unwrap();

        let final_path = dest_dir.join("openshell-sandbox");
        assert!(final_path.exists(), "binary should land inside dest dir");
    }
}
