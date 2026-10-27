// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor host shared by the sandboxes of one gateway.

/// How long a leaving pool member waits for the gateway to move its sandbox
/// instances to other members before it relinquishes the rest. Shorter than
/// the Pod's termination grace period.
#[cfg(unix)]
const POOL_LEAVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(40);

use miette::Result;
#[cfg(unix)]
use std::future::Future;

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
    let token_file = args
        .token_file
        .ok_or_else(|| miette::miette!("--token-file is required for --mode=shared"))?;
    let runtime_listen = args
        .runtime_listen
        .ok_or_else(|| miette::miette!("--runtime-listen is required for --mode=shared"))?;
    // `--session-root` keeps its established flag name.
    let instance_root = args
        .session_root
        .ok_or_else(|| miette::miette!("--session-root is required for --mode=shared"))?;
    // Every shared supervisor is a member of the gateway's supervisor pool.
    let missing = [
        (
            args.pool_member_id.is_none(),
            "--pool-member-id (OPENSHELL_SUPERVISOR_POOL_MEMBER_ID, a stable member ID)",
        ),
        (
            args.pool_advertise_ip.is_none(),
            "--pool-advertise-ip (OPENSHELL_SUPERVISOR_POOL_ADVERTISE_IP, an IP reachable \
from sandbox runtimes)",
        ),
    ]
    .into_iter()
    .filter_map(|(missing, setting)| missing.then_some(setting))
    .collect::<Vec<_>>();
    let (Some(name), Some(advertise_ip)) = (args.pool_member_id, args.pool_advertise_ip) else {
        return Err(miette::miette!(
            "--mode=shared runs a supervisor pool member and needs {}",
            missing.join(", ")
        ));
    };
    let pool = openshell_supervisor::shared_host::PoolIdentity {
        member_id: name,
        runtime_address: std::net::SocketAddr::new(advertise_ip, runtime_listen.port()),
    };
    // The supervisor token travels only over TLS; the host verifies the
    // gateway the way every sandbox instance does, with `OPENSHELL_TLS_CA`
    // and `OPENSHELL_GATEWAY_TLS_SERVER_NAME`.
    if !gateway_endpoint.starts_with("https://") {
        return Err(miette::miette!(
            "--gateway-endpoint must be https for --mode=shared"
        ));
    }
    if std::env::var_os(openshell_core::sandbox_env::TLS_CA).is_none() {
        return Err(miette::miette!(
            "{} is required for --mode=shared",
            openshell_core::sandbox_env::TLS_CA
        ));
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .into_diagnostic()?;
    runtime.block_on(async {
        openshell_crypto::tls::ensure_default_provider();
        let console_filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&args.log_level));
        // Process-wide OCSF JSON output stays off; each sandbox instance's own
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
                    openshell_supervisor::sandbox_instance_host::SandboxInstanceDenialWriter,
                )
                .with_non_ocsf(false)
                .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
            )
            .init();

        // Install shutdown handlers before the health listener starts
        // answering probes.
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .into_diagnostic()?;
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .into_diagnostic()?;
        let link = openshell_supervisor::shared_host::GatewayLink {
            endpoint: gateway_endpoint.clone(),
            token_file,
        };
        let host = openshell_supervisor::shared_host::SharedHost::start(
            openshell_supervisor::shared_host::SharedHostConfig {
                gateway_endpoint,
                instance_root,
                runtime_listen,
                removal_grace: openshell_supervisor_control::INSTANCE_REMOVAL_GRACE,
                pool,
            },
        )?;
        let health = tokio::net::TcpListener::bind(address)
            .await
            .into_diagnostic()
            .wrap_err("bind health listener")?;
        tracing::info!(
            runtime = %host.runtime_addr(),
            health = %address,
            pool_member = %host.pool().member_id,
            "Shared supervisor ready for sandbox instance assignments"
        );
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let wait_stopped = |mut stopped: tokio::sync::watch::Receiver<bool>| async move {
            let _ = stopped.wait_for(|stop| *stop).await;
        };
        let probes = tokio::spawn(serve_health(health, wait_stopped(stopped.clone())));
        let attachment = tokio::spawn(openshell_supervisor::shared_host::attach_to_gateway(
            host.clone(),
            link,
            wait_stopped(stopped),
        ));
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
        // A pool member hands its instances to other members while it still
        // hears from the gateway.
        host.leave(POOL_LEAVE_TIMEOUT).await;
        stop.send_replace(true);
        let _ = probes.await;
        let _ = attachment.await;
        // The member relinquishes what it still hosts to the members the
        // gateway grants it to; the workloads keep running.
        host.shut_down().await;
        Ok(())
    })
}

/// Answer kubelet `tcpSocket` probes: accept and close. Liveness means the
/// process runs; sandbox instance readiness is reported to the gateway.
#[cfg(unix)]
async fn serve_health(listener: tokio::net::TcpListener, shutdown: impl Future<Output = ()>) {
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => break,
            accepted = listener.accept() => {
                if accepted.is_err() {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }
}

#[cfg(not(unix))]
fn run_platform(_args: crate::Args) -> Result<()> {
    Err(miette::miette!("--mode=shared requires Unix"))
}
