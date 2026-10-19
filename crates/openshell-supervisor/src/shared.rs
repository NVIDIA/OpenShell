// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor shared by the sandboxes of one gateway (experimental).

use clap::Parser;
use miette::{IntoDiagnostic, Result, WrapErr};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Time a removed or shut-down session may take to stop its workload.
const SESSION_REMOVAL_GRACE: Duration = Duration::from_secs(20);

#[derive(Debug, Parser)]
#[command(name = "openshell-supervisor experimental-host")]
#[command(about = "Supervise the sandboxes a gateway registers with this process")]
struct Args {
    /// Private socket reporting process health, not session readiness.
    #[arg(long)]
    health_socket: PathBuf,

    /// Gateway gRPC endpoint; each session authenticates with its own credentials.
    #[arg(long, env = openshell_core::sandbox_env::ENDPOINT)]
    openshell_endpoint: String,

    /// Mutually authenticated session-control listener used by the gateway.
    #[arg(long)]
    session_control_listen: SocketAddr,

    /// Directory with the session-control `tls.crt`, `tls.key`, and client `ca.crt`.
    #[arg(long)]
    session_control_tls_dir: PathBuf,

    /// Listener for routed runtime-initiated Sandbox Protocol connections.
    #[arg(long)]
    runtime_listen: SocketAddr,

    /// Private directory for per-session files.
    #[arg(long)]
    session_root: PathBuf,

    #[arg(long, default_value = "warn", env = openshell_core::sandbox_env::LOG_LEVEL)]
    log_level: String,
}

pub fn run(raw_args: &[String]) -> Result<()> {
    let args = Args::parse_from(raw_args);
    run_platform(args)
}

#[cfg(unix)]
fn run_platform(args: Args) -> Result<()> {
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use tracing_subscriber::{Layer as _, layer::SubscriberExt as _, util::SubscriberInitExt as _};

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .into_diagnostic()?;
    runtime.block_on(async {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let console_filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&args.log_level));
        // Process-wide OCSF JSON output stays off; each session's own
        // settings apply to the events its threads emit.
        let (logging_layers, _logging_guards, _) = crate::logging::layers(
            std::io::stderr(),
            std::path::Path::new("/var/log"),
            console_filter,
            Arc::new(AtomicBool::new(false)),
            Arc::new(std::sync::Mutex::new(String::new())),
        );
        tracing_subscriber::registry()
            .with(logging_layers)
            .with(openshell_supervisor_process::log_push::LogPushLayer::thread_bound())
            .with(
                openshell_ocsf::OcsfShorthandLayer::new(
                    openshell_supervisor::session_host::SessionDenialWriter,
                )
                .with_non_ocsf(false)
                .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
            )
            .init();

        // Install shutdown handlers before publishing health.
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .into_diagnostic()?;
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .into_diagnostic()?;
        let tls_file = |name: &str| {
            let path = args.session_control_tls_dir.join(name);
            std::fs::read(&path)
                .into_diagnostic()
                .wrap_err_with(|| format!("read session-control TLS file {}", path.display()))
        };
        let control_tls = openshell_sandbox_backend::session_control::server_tls_config(
            &tls_file("tls.crt")?,
            &tls_file("tls.key")?,
            &tls_file("ca.crt")?,
        )
        .map_err(|error| miette::miette!("{error}"))?;
        let host = openshell_supervisor::shared_host::SharedHost::start(
            openshell_supervisor::shared_host::SharedHostConfig {
                gateway_endpoint: args.openshell_endpoint.clone(),
                session_root: args.session_root.clone(),
                runtime_listen: args.runtime_listen,
                removal_grace: SESSION_REMOVAL_GRACE,
            },
        )?;
        let control = tokio::net::TcpListener::bind(args.session_control_listen)
            .await
            .into_diagnostic()
            .wrap_err("bind session-control listener")?;

        // The private emptyDir survives a container restart after an unclean exit.
        match std::fs::remove_file(&args.health_socket) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).into_diagnostic(),
        }
        let health = tokio::net::UnixListener::bind(&args.health_socket).into_diagnostic()?;
        tracing::info!(
            runtime = %host.runtime_addr(),
            control = %args.session_control_listen,
            "Shared supervisor ready for sessions"
        );
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let serve = tokio::spawn(openshell_supervisor::shared_host::serve_session_control(
            host.clone(),
            control,
            control_tls,
            async move {
                let mut stopped = stopped;
                let _ = stopped.wait_for(|stop| *stop).await;
            },
        ));
        let result = loop {
            tokio::select! {
                result = health.accept() => {
                    if let Err(error) = result {
                        break Err(error).into_diagnostic();
                    }
                }
                _ = terminate.recv() => break Ok(()),
                _ = interrupt.recv() => break Ok(()),
            }
        };
        drop(health);
        let _ = std::fs::remove_file(&args.health_socket);
        stop.send_replace(true);
        let _ = serve.await;
        // Sandboxes lose supervision with this process and fail closed.
        host.remove_all().await;
        result
    })
}

#[cfg(not(unix))]
fn run_platform(_args: Args) -> Result<()> {
    Err(miette::miette!("experimental-host requires Unix"))
}
