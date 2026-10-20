// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor shared by the sandboxes of one gateway (experimental).

use miette::Result;

pub fn run(args: crate::Args) -> Result<()> {
    run_platform(args)
}

#[cfg(unix)]
fn run_platform(args: crate::Args) -> Result<()> {
    use miette::{IntoDiagnostic as _, WrapErr as _};
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use tracing_subscriber::{Layer as _, layer::SubscriberExt as _, util::SubscriberInitExt as _};

    let address = args
        .address
        .ok_or_else(|| miette::miette!("--address is required for --mode=shared"))?;
    let gateway_endpoint = args
        .gateway_endpoint
        .ok_or_else(|| miette::miette!("--gateway-endpoint is required for --mode=shared"))?;
    let session_control_tls_dir = args.session_control_tls_dir.ok_or_else(|| {
        miette::miette!("--session-control-tls-dir is required for --mode=shared")
    })?;
    let runtime_listen = args
        .runtime_listen
        .ok_or_else(|| miette::miette!("--runtime-listen is required for --mode=shared"))?;
    let session_root = args
        .session_root
        .ok_or_else(|| miette::miette!("--session-root is required for --mode=shared"))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .into_diagnostic()?;
    runtime.block_on(async {
        openshell_crypto::tls::ensure_default_provider();
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

        // Install shutdown handlers before the control listener starts
        // answering health probes.
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .into_diagnostic()?;
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .into_diagnostic()?;
        let tls_file = |name: &str| {
            let path = session_control_tls_dir.join(name);
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
                gateway_endpoint,
                session_root,
                runtime_listen,
                removal_grace: openshell_sandbox_backend::session_control::SESSION_REMOVAL_GRACE,
            },
        )?;
        let control = tokio::net::TcpListener::bind(address)
            .await
            .into_diagnostic()
            .wrap_err("bind session-control listener")?;
        tracing::info!(
            runtime = %host.runtime_addr(),
            control = %address,
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
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
        stop.send_replace(true);
        let _ = serve.await;
        // Sandboxes lose supervision with this process and fail closed.
        host.remove_all().await;
        Ok(())
    })
}

#[cfg(not(unix))]
fn run_platform(_args: crate::Args) -> Result<()> {
    Err(miette::miette!("--mode=shared requires Unix"))
}
