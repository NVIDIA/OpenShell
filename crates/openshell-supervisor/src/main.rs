// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `OpenShell` supervisor executable.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use clap::Parser;
use miette::{IntoDiagnostic, Result};
use openshell_isolation_interface::contract::TopologyDescriptor;
use openshell_ocsf::{OcsfJsonlLayer, OcsfShorthandLayer};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::{Layer as _, layer::SubscriberExt as _, util::SubscriberInitExt as _};

const DEBUG_RPC_SUBCOMMAND: &str = "debug-rpc";
const HEALTH_SUBCOMMAND: &str = "health";

#[derive(Parser, Debug)]
#[command(name = "openshell-supervisor health")]
struct HealthArgs {
    /// Private supervisor readiness socket.
    #[arg(long, env = "OPENSHELL_HEALTH_SOCKET_PATH")]
    socket: PathBuf,
}

#[derive(Parser, Debug)]
#[command(name = "openshell-supervisor")]
#[command(version = openshell_core::VERSION)]
#[command(about = "OpenShell policy and workload supervisor")]
#[allow(clippy::struct_excessive_bools)]
struct Args {
    /// Command to execute as the canonical workload process.
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,

    #[arg(long, short)]
    workdir: Option<String>,

    #[arg(long, short, default_value = "0")]
    timeout: u64,

    #[arg(long, short = 'i')]
    interactive: bool,

    #[arg(long, env = openshell_core::sandbox_env::SANDBOX_ID)]
    sandbox_id: Option<String>,

    #[arg(long, env = openshell_core::sandbox_env::SANDBOX)]
    sandbox: Option<String>,

    #[arg(long, env = openshell_core::sandbox_env::ENDPOINT)]
    openshell_endpoint: Option<String>,

    #[arg(long, env = "OPENSHELL_POLICY_RULES")]
    policy_rules: Option<String>,

    #[arg(long, env = "OPENSHELL_POLICY_DATA")]
    policy_data: Option<String>,

    #[arg(long, env = openshell_core::sandbox_env::SSH_SOCKET_PATH)]
    ssh_socket_path: Option<String>,

    #[arg(long, env = "OPENSHELL_INFERENCE_ROUTES")]
    inference_routes: Option<String>,

    #[arg(long, default_value = "warn", env = openshell_core::sandbox_env::LOG_LEVEL)]
    log_level: String,

    /// Create the private readiness socket after boundary and gateway attach.
    #[arg(long, env = "OPENSHELL_HEALTH_SOCKET_PATH")]
    health_socket_path: Option<PathBuf>,

    #[arg(long)]
    upstream_proxy: Option<String>,

    /// Driver-pinned TCP dial address for the configured upstream proxy.
    #[arg(long)]
    upstream_proxy_dial_ip: Option<std::net::IpAddr>,

    #[arg(long)]
    upstream_no_proxy: Option<String>,

    #[arg(long)]
    upstream_proxy_auth_file: Option<String>,

    #[arg(long)]
    upstream_proxy_auth_allow_insecure: bool,

    #[arg(long)]
    upstream_proxy_connect_by_hostname: bool,

    #[arg(long)]
    upstream_proxy_ca_bundle: Option<String>,

    #[arg(long)]
    topology_backend_name: String,

    #[arg(long)]
    topology_payload_file: PathBuf,

    #[arg(long, hide = true)]
    main_exit_marker: Option<PathBuf>,
}

fn topology(args: &Args) -> Result<TopologyDescriptor> {
    let payload = std::fs::read(&args.topology_payload_file).map_err(|error| {
        miette::miette!(
            "read topology payload {}: {error}",
            args.topology_payload_file.display()
        )
    })?;
    Ok(TopologyDescriptor {
        backend_name: args.topology_backend_name.clone(),
        payload,
    })
}

fn validate_main_exit_marker(marker: Option<&Path>) -> Result<()> {
    if let Some(marker) = marker
        && !marker.is_absolute()
    {
        return Err(miette::miette!(
            "--main-exit-marker must be an absolute path"
        ));
    }
    Ok(())
}

fn main() -> Result<()> {
    let raw_args = std::env::args().collect::<Vec<_>>();
    if raw_args.get(1).map(String::as_str) == Some(DEBUG_RPC_SUBCOMMAND) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .into_diagnostic()?;
        return runtime.block_on(async move {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let exit = openshell_supervisor_process::debug_rpc::run(&raw_args[2..]).await?;
            std::process::exit(exit);
        });
    }
    if raw_args.get(1).map(String::as_str) == Some(HEALTH_SUBCOMMAND) {
        let args = HealthArgs::parse_from(&raw_args[1..]);
        return openshell_supervisor::check_control_readiness(&args.socket);
    }

    let args = Args::parse();
    validate_main_exit_marker(args.main_exit_marker.as_deref())?;
    let topology = topology(&args)?;

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
        let _ = rustls::crypto::ring::default_provider().install_default();
        let log_push_state = if let (Some(sandbox_id), Some(endpoint)) =
            (&args.sandbox_id, &args.openshell_endpoint)
        {
            let (tx, handle) = openshell_supervisor_process::log_push::spawn_log_push_task(
                endpoint.clone(),
                sandbox_id.clone(),
            );
            let layer =
                openshell_supervisor_process::log_push::LogPushLayer::new(sandbox_id.clone(), tx);
            Some((layer, handle))
        } else {
            None
        };
        let push_layer = log_push_state.as_ref().map(|(layer, _)| layer.clone());
        let _log_push_handle = log_push_state.map(|(_, handle)| handle);
        let ocsf_enabled = Arc::new(AtomicBool::new(false));

        let (_file_guard, _jsonl_guard) = if let Some((file_writer, file_guard)) = file_logging {
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
            let (jsonl_layer, jsonl_guard) =
                jsonl_logging.map_or((None, None), |(layer, guard)| (Some(layer), Some(guard)));
            tracing_subscriber::registry()
                .with(
                    OcsfShorthandLayer::new(std::io::stderr())
                        .with_non_ocsf(true)
                        .with_filter(console_filter),
                )
                .with(
                    OcsfShorthandLayer::new(file_writer)
                        .with_non_ocsf(true)
                        .with_filter(EnvFilter::new("info")),
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
            warn!("Could not open /var/log for log rotation; using stderr-only logging");
            (None, None)
        };

        let workdir = args.workdir.clone();
        let (command, interactive, await_main_process_attachment) = if !args.command.is_empty() {
            (args.command, args.interactive, false)
        } else if let Ok(json) = std::env::var(openshell_core::sandbox_env::MAIN_PROCESS_SPEC) {
            let config = openshell_core::sandbox_env::MainProcessConfig::decode(&json)
                .map_err(|error| miette::miette!("{error}"))?;
            (
                config.command,
                config.tty,
                config.await_main_process_attachment,
            )
        } else {
            let config = openshell_core::sandbox_env::MainProcessConfig::scratch();
            (
                config.command,
                config.tty,
                config.await_main_process_attachment,
            )
        };
        info!(command = ?command, "Starting sandbox supervision");

        let upstream_proxy_args = openshell_supervisor_network::upstream_proxy::UpstreamProxyArgs {
            https_proxy: args.upstream_proxy,
            proxy_dial_ip: args.upstream_proxy_dial_ip,
            no_proxy: args.upstream_no_proxy,
            proxy_auth_file: args.upstream_proxy_auth_file,
            proxy_auth_allow_insecure: args.upstream_proxy_auth_allow_insecure,
            proxy_connect_by_hostname: args.upstream_proxy_connect_by_hostname,
            proxy_ca_bundle: args.upstream_proxy_ca_bundle,
        };
        let admitted_isolation_backend =
            std::env::var(openshell_core::sandbox_env::ADMITTED_ISOLATION_BACKEND).ok();

        openshell_supervisor::run_sandbox(
            command,
            workdir,
            args.timeout,
            interactive,
            await_main_process_attachment,
            args.sandbox_id,
            args.sandbox,
            args.openshell_endpoint,
            args.policy_rules,
            args.policy_data,
            args.ssh_socket_path,
            args.health_socket_path,
            args.inference_routes,
            ocsf_enabled,
            upstream_proxy_args,
            topology,
            admitted_isolation_backend,
            args.main_exit_marker,
        )
        .await
    })?;

    std::process::exit(exit_code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_specific_cli_has_no_mode_switch() {
        let directory = tempfile::tempdir().expect("temporary topology directory");
        let topology_path = directory.path().join("topology.json");
        std::fs::write(&topology_path, [0]).expect("write topology payload");
        let args = Args::try_parse_from([
            "openshell-supervisor",
            "--topology-backend-name",
            "test",
            "--topology-payload-file",
            topology_path.to_str().expect("UTF-8 topology path"),
        ])
        .expect("supervisor arguments");
        assert_eq!(topology(&args).expect("topology").payload, vec![0]);
    }

    #[test]
    fn topology_payload_is_mandatory() {
        assert!(
            Args::try_parse_from(["openshell-supervisor", "--topology-backend-name", "test"])
                .is_err()
        );
    }

    #[test]
    fn completion_marker_must_be_absolute() {
        assert!(validate_main_exit_marker(Some(Path::new("relative"))).is_err());
        assert!(validate_main_exit_marker(Some(Path::new("/run/openshell/main-exit"))).is_ok());
    }
}
