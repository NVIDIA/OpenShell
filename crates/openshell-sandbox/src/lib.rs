// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `OpenShell` Sandbox library.
//!
//! This crate provides process sandboxing and monitoring capabilities.

mod activity_aggregator;
mod denial_aggregator;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod google_cloud_metadata;
mod mechanistic_mapper;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod metadata_server;

use miette::Result;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::time::Duration;
use tracing::{debug, info, warn};

use openshell_ocsf::{
    ActionId, ActivityId, AppLifecycleBuilder, ConfigStateChangeBuilder, DetectionFindingBuilder,
    DispositionId, FindingInfo, SandboxContext, SeverityId, StateId, StatusId, ocsf_emit,
};

// ---------------------------------------------------------------------------
// OCSF Context
// ---------------------------------------------------------------------------
//
// The following log sites intentionally remain as plain `tracing` macros
// and are NOT migrated to OCSF builders:
//
// - DEBUG/TRACE events (zombie reaping, ip commands, gRPC connects, PTY state)
// - Transient "about to do X" events where the result is logged separately
//   (e.g., "Fetching sandbox policy via gRPC", "Creating OPA engine from proto")
// - Internal SSH channel warnings (unknown channel, PTY resize failures)
// - Denial flush telemetry (the individual denials are already OCSF events)
// - Status reporting failures (sync to gateway, non-actionable)
// - Route refresh interval validation warnings
//
// These are operational plumbing that don't represent security decisions,
// policy changes, or observable sandbox behavior worth structuring.
// ---------------------------------------------------------------------------

/// Re-export the process-wide OCSF sandbox context getter.
///
/// The singleton lives in `openshell-ocsf` so both supervisor leaves can
/// reach it without depending on `openshell-sandbox`. Initialised once during
/// `run_sandbox()` startup via `openshell_ocsf::ctx::set_ctx`.
pub(crate) use openshell_ocsf::ctx::ctx as ocsf_ctx;

/// Process-wide flag for the agent-driven policy proposal surface.
/// Set once during `run_sandbox()` startup and updated by the settings poll
/// loop when `agent_policy_proposals_enabled` changes. Read by the
/// `policy.local` route handler and the L7 deny body's `next_steps` builder
/// to gate the agent-controlled mutation surface. Exposed `pub(crate)` so
/// unit tests in sibling modules can flip the flag through a serialized
/// guard (see `policy_local::tests::ProposalsFlagGuard`).
pub(crate) use openshell_core::proposals::AGENT_PROPOSALS_ENABLED;

use openshell_core::denial::DenialEvent;
use openshell_core::policy::{NetworkMode, NetworkPolicy, ProxyPolicy, SandboxPolicy};
use openshell_core::provider_credentials::ProviderCredentialState;
use openshell_supervisor_network::opa::OpaEngine;
pub use openshell_supervisor_process::process::{ProcessHandle, ProcessStatus};
use openshell_supervisor_process::skills;
use tokio::sync::mpsc::UnboundedSender;
#[cfg(target_os = "linux")]
use tokio::time::timeout;

/// Run a command in the sandbox.
///
/// # Errors
///
/// Returns an error if the command fails to start or encounters a fatal error.
#[allow(
    clippy::too_many_arguments,
    clippy::similar_names,
    clippy::fn_params_excessive_bools
)]
pub async fn run_sandbox(
    command: Vec<String>,
    workdir: Option<String>,
    timeout_secs: u64,
    interactive: bool,
    sandbox_id: Option<String>,
    sandbox: Option<String>,
    openshell_endpoint: Option<String>,
    policy_rules: Option<String>,
    policy_data: Option<String>,
    ssh_socket_path: Option<String>,
    _health_check: bool,
    _health_port: u16,
    inference_routes: Option<String>,
    ocsf_enabled: Arc<std::sync::atomic::AtomicBool>,
    network_enabled: bool,
    process_enabled: bool,
) -> Result<i32> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| miette::miette!("No command specified"))?;

    // Initialize the process-wide OCSF context early so that events emitted
    // during policy loading (filesystem config, validation) have a context.
    // Proxy IP/port use defaults here; they are only significant for network
    // events which happen after the netns is created.
    {
        let hostname = std::fs::read_to_string("/etc/hostname").map_or_else(
            |_| "openshell-sandbox".to_string(),
            |s| s.trim().to_string(),
        );

        if !openshell_ocsf::ctx::set_ctx(SandboxContext {
            sandbox_id: sandbox_id.clone().unwrap_or_default(),
            sandbox_name: sandbox.as_deref().unwrap_or_default().to_string(),
            container_image: std::env::var("OPENSHELL_CONTAINER_IMAGE").unwrap_or_default(),
            hostname,
            product_version: openshell_core::VERSION.to_string(),
            proxy_ip: std::net::IpAddr::from([127, 0, 0, 1]),
            proxy_port: 3128,
        }) {
            debug!("OCSF context already initialized, keeping existing");
        }
    }

    // Load policy and initialize OPA engine
    let openshell_endpoint_for_proxy = openshell_endpoint.clone();
    let sandbox_name_for_agg = sandbox.clone();
    let (mut policy, opa_engine, retained_proto) = load_policy(
        sandbox_id.clone(),
        sandbox,
        openshell_endpoint.clone(),
        policy_rules,
        policy_data,
    )
    .await?;

    // Override the policy's process identity with the driver-resolved UID/GID
    // from the pod environment. The policy defaults to the name "sandbox" which
    // resolves via /etc/passwd, but the driver may have chosen a different
    // numeric UID (e.g. from OpenShift SCC annotations).
    // Validate overrides against the same rules as the policy layer to prevent
    // env-injected values (e.g. GID 0) from bypassing policy restrictions.
    if let Ok(uid) = std::env::var(openshell_core::sandbox_env::SANDBOX_UID)
        && !uid.is_empty()
    {
        if !openshell_policy::is_valid_sandbox_identity(&uid) {
            return Err(miette::miette!(
                "OPENSHELL_SANDBOX_UID contains invalid sandbox identity '{uid}'; \
                 expected 'sandbox' or a numeric UID in range [{}, {}]",
                openshell_policy::MIN_SANDBOX_UID,
                openshell_policy::MAX_SANDBOX_UID,
            ));
        }
        policy.process.run_as_user = Some(uid);
    }
    if let Ok(gid) = std::env::var(openshell_core::sandbox_env::SANDBOX_GID)
        && !gid.is_empty()
    {
        if !openshell_policy::is_valid_sandbox_identity(&gid) {
            return Err(miette::miette!(
                "OPENSHELL_SANDBOX_GID contains invalid sandbox identity '{gid}'; \
                 expected 'sandbox' or a numeric GID in range [{}, {}]",
                openshell_policy::MIN_SANDBOX_UID,
                openshell_policy::MAX_SANDBOX_UID,
            ));
        }
        policy.process.run_as_group = Some(gid);
    }

    // Fetch provider environment variables from the server.
    // This is done after loading the policy so the sandbox can still start
    // even if provider env fetch fails (graceful degradation).
    let (
        provider_env_revision,
        provider_env,
        provider_credential_expires_at_ms,
        dynamic_credentials,
    ) = if let (Some(id), Some(endpoint)) = (&sandbox_id, &openshell_endpoint) {
        match openshell_core::grpc_client::fetch_provider_environment(endpoint, id).await {
            Ok(result) => {
                ocsf_emit!(
                    ConfigStateChangeBuilder::new(ocsf_ctx())
                        .severity(SeverityId::Informational)
                        .status(StatusId::Success)
                        .state(StateId::Enabled, "loaded")
                        .message(format!(
                            "Fetched provider environment [env_count:{}]",
                            result.environment.len()
                        ))
                        .build()
                );
                (
                    result.provider_env_revision,
                    result.environment,
                    result.credential_expires_at_ms,
                    result.dynamic_credentials,
                )
            }
            Err(e) => {
                ocsf_emit!(
                    ConfigStateChangeBuilder::new(ocsf_ctx())
                        .severity(SeverityId::Medium)
                        .status(StatusId::Failure)
                        .state(StateId::Other, "degraded")
                        .message(format!(
                            "Failed to fetch provider environment, continuing without: {e}"
                        ))
                        .build()
                );
                (
                    0,
                    std::collections::HashMap::new(),
                    std::collections::HashMap::new(),
                    std::collections::HashMap::new(),
                )
            }
        }
    } else {
        (
            0,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        )
    };

    let provider_credentials = ProviderCredentialState::from_environment(
        provider_env_revision,
        provider_env,
        provider_credential_expires_at_ms,
        dynamic_credentials,
    );
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut provider_env = provider_credentials.child_env_with_gcp_resolved();

    // Initialize the agent-proposals feature flag. Default false until the
    // initial settings fetch (or the poll loop) tells us otherwise. The flag
    // gates the skill install, the policy.local route handler, and the L7
    // deny body's `next_steps` field — see `agent_proposals_enabled()`.
    let proposals_enabled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    if AGENT_PROPOSALS_ENABLED
        .set(proposals_enabled.clone())
        .is_err()
    {
        debug!("agent proposals flag already initialized, keeping existing");
    }

    // Shared PID: set after process spawn so the proxy can look up
    // the entrypoint process's /proc/net/tcp for identity binding.
    let entrypoint_pid = Arc::new(AtomicU32::new(0));

    // Create the workload's network namespace. It is shared infrastructure:
    // the proxy binds to its host-side veth IP, the bypass monitor reads
    // /dev/kmsg from inside it, and the workload child / SSH sessions enter
    // it via setns(). The RAII handle lives in this frame for the duration
    // of the sandbox.
    #[cfg(target_os = "linux")]
    let netns = if network_enabled {
        openshell_supervisor_process::netns::create_netns_for_proxy(&policy)?
    } else {
        None
    };

    // The denial channel is owned by the orchestrator: the proxy (in the
    // networking leaf) and the bypass monitor (in the process leaf) both
    // produce DenialEvents that the denial aggregator (orchestrator-side)
    // consumes via the matching receiver. Both leaves are pure producers;
    // the orchestrator owns the consumer task spawned below.
    let (denial_tx, denial_rx, bypass_denial_tx): (
        Option<UnboundedSender<DenialEvent>>,
        _,
        Option<UnboundedSender<DenialEvent>>,
    ) = if sandbox_id.is_some() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let bypass_tx = tx.clone();
        (Some(tx), Some(rx), Some(bypass_tx))
    } else {
        (None, None, None)
    };
    #[cfg(not(target_os = "linux"))]
    drop(bypass_denial_tx);

    // Anonymous activity channel: same orchestrator-owned pattern as the
    // denial channel. The proxy and the bypass monitor both emit per-event
    // activity records; the orchestrator-side aggregator drains, sanitizes,
    // and flushes anonymous summaries to the gateway.
    let (activity_tx, activity_rx, bypass_activity_tx) = if sandbox_id.is_some() {
        let (tx, rx) =
            tokio::sync::mpsc::channel(openshell_core::activity::ACTIVITY_EVENT_QUEUE_CAPACITY);
        let bypass_tx = tx.clone();
        (Some(tx), Some(rx), Some(bypass_tx))
    } else {
        (None, None, None)
    };
    #[cfg(not(target_os = "linux"))]
    drop(bypass_activity_tx);

    let networking = if network_enabled {
        #[cfg(target_os = "linux")]
        let proxy_bind_ip = netns
            .as_ref()
            .map(openshell_supervisor_process::netns::NetworkNamespace::host_ip);
        #[cfg(not(target_os = "linux"))]
        let proxy_bind_ip: Option<std::net::IpAddr> = None;

        Some(
            openshell_supervisor_network::run::run_networking(
                &policy,
                proxy_bind_ip,
                opa_engine.as_ref(),
                retained_proto.as_ref(),
                entrypoint_pid.clone(),
                process_enabled,
                &provider_credentials,
                sandbox_id.as_deref(),
                sandbox_name_for_agg.as_deref(),
                openshell_endpoint_for_proxy.as_deref(),
                inference_routes.as_deref(),
                denial_tx,
                activity_tx,
            )
            .await?,
        )
    } else {
        None
    };

    // Spawn the denial-aggregator flush task. The aggregator drains denial
    // events from the proxy + bypass monitor, batches them, and ships
    // summaries to the gateway via `SubmitPolicyAnalysis`.
    if let (Some(rx), Some(endpoint)) = (denial_rx, openshell_endpoint_for_proxy.as_deref()) {
        // SubmitPolicyAnalysis resolves by sandbox *name*, not UUID — fall
        // back to the ID when the name isn't set.
        let agg_name = sandbox_name_for_agg
            .clone()
            .or_else(|| sandbox_id.clone())
            .unwrap_or_default();
        let agg_endpoint = endpoint.to_string();
        let flush_interval_secs: u64 = std::env::var("OPENSHELL_DENIAL_FLUSH_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10);

        let aggregator = denial_aggregator::DenialAggregator::new(rx, flush_interval_secs);

        tokio::spawn(async move {
            aggregator
                .run(|summaries| {
                    let endpoint = agg_endpoint.clone();
                    let sandbox_name = agg_name.clone();
                    async move {
                        if let Err(e) =
                            flush_proposals_to_gateway(&endpoint, &sandbox_name, summaries).await
                        {
                            warn!(error = %e, "Failed to flush denial summaries to gateway");
                        }
                    }
                })
                .await;
        });
    }

    // Spawn the activity-aggregator flush task. The aggregator drains
    // anonymous activity events from the proxy, sanitizes deny groups,
    // and ships periodic summaries to the gateway.
    if let (Some(rx), Some(endpoint)) = (activity_rx, openshell_endpoint_for_proxy.as_deref()) {
        let agg_name = sandbox_name_for_agg
            .clone()
            .or_else(|| sandbox_id.clone())
            .unwrap_or_default();
        let agg_endpoint = endpoint.to_string();
        let flush_interval_secs = activity_aggregator::activity_flush_interval_secs_from_env(
            std::env::var("OPENSHELL_ACTIVITY_FLUSH_INTERVAL_SECS")
                .ok()
                .as_deref(),
        );

        let aggregator = activity_aggregator::ActivityAggregator::new(rx, flush_interval_secs);

        tokio::spawn(async move {
            aggregator
                .run(move |summary| {
                    let endpoint = agg_endpoint.clone();
                    let sandbox_name = agg_name.clone();
                    async move {
                        if let Err(e) =
                            flush_activity_to_gateway(&endpoint, &sandbox_name, summary).await
                        {
                            warn!(error = %e, "Failed to flush activity summary to gateway");
                        }
                    }
                })
                .await;
        });
    }

    // Spawn background policy poll task (gRPC mode only).
    if let (Some(id), Some(endpoint), Some(engine)) = (
        sandbox_id.as_deref(),
        openshell_endpoint.as_deref(),
        opa_engine.as_ref(),
    ) {
        let poll_id = id.to_string();
        let poll_endpoint = endpoint.to_string();
        let poll_engine = engine.clone();
        let poll_ocsf_enabled = ocsf_enabled.clone();
        let poll_pid = entrypoint_pid.clone();
        let poll_provider_credentials = provider_credentials.clone();
        let poll_policy_local = networking.as_ref().map(|n| n.policy_local_ctx.clone());
        let poll_interval_secs: u64 = std::env::var("OPENSHELL_POLICY_POLL_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10);
        let poll_ctx = PolicyPollLoopContext {
            endpoint: poll_endpoint,
            sandbox_id: poll_id,
            opa_engine: poll_engine,
            entrypoint_pid: poll_pid,
            interval_secs: poll_interval_secs,
            ocsf_enabled: poll_ocsf_enabled,
            provider_credentials: poll_provider_credentials,
            policy_local_ctx: poll_policy_local,
        };

        tokio::spawn(async move {
            if let Err(e) = run_policy_poll_loop(poll_ctx).await {
                ocsf_emit!(
                    AppLifecycleBuilder::new(ocsf_ctx())
                        .activity(ActivityId::Fail)
                        .severity(SeverityId::Medium)
                        .status(StatusId::Failure)
                        .message(format!("Policy poll loop exited with error: {e}"))
                        .build()
                );
            }
        });
    }

    // Start GCE metadata loopback server inside the network namespace so
    // Go's cloud.google.com/go/compute/metadata (which bypasses HTTP_PROXY)
    // can reach it via direct TCP. Must start before the process leaf so SSH
    // sessions also see corrected env vars on bind failure.
    #[cfg(target_os = "linux")]
    if let Some(ns) = netns.as_ref()
        && provider_credentials
            .snapshot()
            .child_env
            .contains_key("GCE_METADATA_HOST")
    {
        let ctx = google_cloud_metadata::MetadataContext::new(provider_credentials.clone());
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        match ns
            .bind_tcp_in_netns(openshell_core::google_cloud::METADATA_LOOPBACK_ADDR)
            .await
        {
            Ok(listener) => {
                tokio::spawn(metadata_server::run(listener, ctx, ready_tx));
                if let Ok(Ok(addr)) = timeout(Duration::from_secs(5), ready_rx).await {
                    info!(addr = %addr, "GCE metadata loopback server ready");
                } else {
                    warn!("GCE metadata server failed to become ready, removing metadata env vars");
                    provider_env.remove("GCE_METADATA_HOST");
                    provider_env.remove("GCE_METADATA_IP");
                    provider_env.remove("METADATA_SERVER_DETECTION");
                    provider_credentials.remove_env_key("GCE_METADATA_HOST");
                }
            }
            Err(e) => {
                warn!(error = %e, "GCE metadata server bind failed, Go SDK may not discover credentials");
                provider_env.remove("GCE_METADATA_HOST");
                provider_env.remove("GCE_METADATA_IP");
                provider_env.remove("METADATA_SERVER_DETECTION");
                provider_credentials.remove_env_key("GCE_METADATA_HOST");
            }
        }
    }

    let exit_code = if process_enabled {
        let ca_file_paths = networking.as_ref().and_then(|n| n.ca_file_paths.clone());

        openshell_supervisor_process::run::run_process(
            program,
            args,
            workdir.as_deref(),
            timeout_secs,
            interactive,
            sandbox_id.as_deref(),
            openshell_endpoint.as_deref(),
            ssh_socket_path,
            &policy,
            entrypoint_pid,
            provider_credentials,
            provider_env,
            ca_file_paths,
            #[cfg(target_os = "linux")]
            netns.as_ref(),
            #[cfg(target_os = "linux")]
            bypass_denial_tx,
            #[cfg(target_os = "linux")]
            bypass_activity_tx,
        )
        .await?
    } else {
        // Network-only sidecar mode: keep the proxy and its background
        // tasks alive (held via the `networking` value) until SIGINT or
        // SIGTERM. Exit 0 on clean shutdown.
        wait_for_shutdown_signal().await;
        0
    };

    // Drop networking explicitly so the proxy + bypass monitor RAII
    // handles tear down before we return.
    drop(networking);

    Ok(exit_code)
}

/// Wait for SIGINT or SIGTERM. Used in network-only mode where there is
/// no entrypoint child whose lifetime drives the supervisor's exit.
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Failed to install SIGTERM handler; waiting on SIGINT only"
                );
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Received SIGINT, shutting down network-only supervisor");
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM, shutting down network-only supervisor");
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        info!("Received Ctrl-C, shutting down network-only supervisor");
    }
}

/// Flush aggregated denial summaries to the gateway via `SubmitPolicyAnalysis`.
async fn flush_proposals_to_gateway(
    endpoint: &str,
    sandbox_name: &str,
    summaries: Vec<denial_aggregator::FlushableDenialSummary>,
) -> Result<()> {
    use openshell_core::grpc_client::CachedOpenShellClient;
    use openshell_core::proto::{DenialSummary, L7RequestSample};

    let client = CachedOpenShellClient::connect(endpoint).await?;

    let proto_summaries: Vec<DenialSummary> = summaries
        .into_iter()
        .map(|s| DenialSummary {
            sandbox_id: String::new(),
            host: s.host,
            port: u32::from(s.port),
            binary: s.binary,
            ancestors: s.ancestors,
            deny_reason: s.deny_reason,
            first_seen_ms: s.first_seen_ms,
            last_seen_ms: s.last_seen_ms,
            count: s.count,
            suppressed_count: 0,
            total_count: s.count,
            sample_cmdlines: s.sample_cmdlines,
            binary_sha256: String::new(),
            persistent: false,
            denial_stage: s.denial_stage,
            l7_request_samples: s
                .l7_samples
                .into_iter()
                .map(|l| L7RequestSample {
                    method: l.method,
                    path: l.path,
                    decision: "deny".to_string(),
                    count: l.count,
                })
                .collect(),
            l7_inspection_active: false,
        })
        .collect();

    // Run the mechanistic mapper sandbox-side to generate proposals.
    // The gateway is a thin persistence + validation layer — it never
    // generates proposals itself.
    let proposals = mechanistic_mapper::generate_proposals(&proto_summaries);

    info!(
        sandbox_name = %sandbox_name,
        summaries = proto_summaries.len(),
        proposals = proposals.len(),
        "Flushed denial analysis to gateway"
    );

    client
        .submit_policy_analysis(
            sandbox_name,
            proto_summaries,
            proposals,
            Vec::new(),
            "mechanistic",
        )
        .await?;

    Ok(())
}

/// Flush an anonymous activity summary to the gateway via `SubmitPolicyAnalysis`.
async fn flush_activity_to_gateway(
    endpoint: &str,
    sandbox_name: &str,
    summary: activity_aggregator::FlushableActivitySummary,
) -> Result<()> {
    use openshell_core::grpc_client::CachedOpenShellClient;
    use openshell_core::proto::{DenialGroupCount, NetworkActivitySummary};

    let client = CachedOpenShellClient::connect(endpoint).await?;

    let proto_summary = NetworkActivitySummary {
        network_activity_count: summary.network_activity_count,
        denied_action_count: summary.denied_action_count,
        denials_by_group: summary
            .denials_by_group
            .into_iter()
            .map(|(group, count)| DenialGroupCount {
                deny_group: group,
                denied_count: count,
            })
            .collect(),
    };

    info!(
        sandbox_name = %sandbox_name,
        network_activity_count = proto_summary.network_activity_count,
        denied_action_count = proto_summary.denied_action_count,
        "Flushed activity summary to gateway"
    );

    client
        .submit_policy_analysis(
            sandbox_name,
            Vec::new(),
            Vec::new(),
            vec![proto_summary],
            "activity",
        )
        .await?;

    Ok(())
}

// ============================================================================
// Baseline filesystem path enrichment
// ============================================================================

/// Minimum read-only paths required for a proxy-mode sandbox child process to
/// function: dynamic linker, shared libraries, DNS resolution, CA certs,
/// Python venv, openshell logs, process info, and random bytes.
///
/// `/proc` and `/dev/urandom` are included here for the same reasons they
/// appear in `restrictive_default_policy()`: virtually every process needs
/// them.  Before the Landlock per-path fix (#677) these were effectively free
/// because a missing path silently disabled the entire ruleset; now they must
/// be explicit.
const PROXY_BASELINE_READ_ONLY: &[&str] = &[
    "/usr",
    "/lib",
    "/etc",
    "/app",
    "/var/log",
    "/proc",
    "/dev/urandom",
];

/// Minimum read-write paths required for a proxy-mode sandbox child process:
/// user working directory and temporary files.
const PROXY_BASELINE_READ_WRITE: &[&str] = &["/sandbox", "/tmp"];

/// GPU read-only paths.
///
/// `/run/nvidia-persistenced`: NVML tries to connect to the persistenced
/// socket at init time.  If the directory exists but Landlock denies traversal
/// (EACCES vs ECONNREFUSED), NVML returns `NVML_ERROR_INSUFFICIENT_PERMISSIONS`
/// even though the daemon is optional.  Only read/traversal access is needed.
///
/// `/usr/lib/wsl`: On WSL2, CDI bind-mounts GPU libraries (libdxcore.so,
/// libcuda.so.1.1, etc.) into paths under `/usr/lib/wsl/`.  Although `/usr`
/// is already in `PROXY_BASELINE_READ_ONLY`, individual file bind-mounts may
/// not be covered by the parent-directory Landlock rule when the mount crosses
/// a filesystem boundary.  Listing `/usr/lib/wsl` explicitly ensures traversal
/// is permitted regardless of Landlock's cross-mount behaviour.
const GPU_BASELINE_READ_ONLY: &[&str] = &[
    "/run/nvidia-persistenced",
    "/usr/lib/wsl", // WSL2: CDI-injected GPU library directory
];

/// GPU read-write paths (static).
///
/// `/dev/nvidiactl`, `/dev/nvidia-uvm`, `/dev/nvidia-uvm-tools`,
/// `/dev/nvidia-modeset`: control and UVM devices injected by CDI on native
/// Linux.  Landlock restricts `open(2)` on device files even when DAC allows
/// it; these need read-write because NVML/CUDA opens them with `O_RDWR`.
/// These devices do not exist on WSL2 and will be skipped by the existence
/// check in `enrich_proto_baseline_paths()`.
///
/// `/dev/dxg`: On WSL2, NVIDIA GPUs are exposed through the DXG kernel driver
/// (DirectX Graphics) rather than the native nvidia* devices.  CDI injects
/// `/dev/dxg` as the sole GPU device node; it does not exist on native Linux
/// and will be skipped there by the existence check.
///
/// `/proc`: CUDA writes to `/proc/<pid>/task/<tid>/comm` during `cuInit()`
/// to set thread names.  Without write access, `cuInit()` returns error 304.
/// Must use `/proc` (not `/proc/self/task`) because Landlock rules bind to
/// inodes and child processes have different procfs inodes than the parent.
///
/// Per-GPU device files (`/dev/nvidia0`, …) are enumerated at runtime by
/// `enumerate_gpu_device_nodes()` since the count varies.
const GPU_BASELINE_READ_WRITE: &[&str] = &[
    "/dev/nvidiactl",
    "/dev/nvidia-uvm",
    "/dev/nvidia-uvm-tools",
    "/dev/nvidia-modeset",
    "/dev/dxg", // WSL2: DXG device (GPU via DirectX kernel driver, injected by CDI)
    "/proc",
];

/// Returns true if GPU devices are present in the container.
///
/// Checks both the native Linux NVIDIA control device (`/dev/nvidiactl`) and
/// the WSL2 DXG device (`/dev/dxg`).  CDI injects exactly one of these
/// depending on the host kernel; the other will not exist.
fn has_gpu_devices() -> bool {
    std::path::Path::new("/dev/nvidiactl").exists() || std::path::Path::new("/dev/dxg").exists()
}

/// Enumerate per-GPU device nodes (`/dev/nvidia0`, `/dev/nvidia1`, …).
fn enumerate_gpu_device_nodes() -> Vec<String> {
    let mut paths = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/dev") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(suffix) = name.strip_prefix("nvidia") {
                if suffix.is_empty() || !suffix.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }
                paths.push(entry.path().to_string_lossy().into_owned());
            }
        }
    }
    paths
}

fn push_unique(paths: &mut Vec<String>, path: String) {
    if !paths.iter().any(|p| p == &path) {
        paths.push(path);
    }
}

fn collect_baseline_enrichment_paths(
    include_proxy: bool,
    include_gpu: bool,
    gpu_device_nodes: Vec<String>,
) -> (Vec<String>, Vec<String>) {
    let mut ro = Vec::new();
    let mut rw = Vec::new();

    if include_proxy {
        for &path in PROXY_BASELINE_READ_ONLY {
            push_unique(&mut ro, path.to_string());
        }
        for &path in PROXY_BASELINE_READ_WRITE {
            push_unique(&mut rw, path.to_string());
        }
    }

    if include_gpu {
        for &path in GPU_BASELINE_READ_ONLY {
            push_unique(&mut ro, path.to_string());
        }
        for &path in GPU_BASELINE_READ_WRITE {
            push_unique(&mut rw, path.to_string());
        }
        for path in gpu_device_nodes {
            push_unique(&mut rw, path);
        }
    }

    // A path promoted to read_write (e.g. /proc for GPU) should not also
    // appear in read_only — Landlock handles the overlap correctly but the
    // duplicate is confusing when inspecting the effective policy.
    ro.retain(|p| !rw.contains(p));

    (ro, rw)
}

fn active_baseline_enrichment_paths(include_proxy: bool) -> (Vec<String>, Vec<String>) {
    let include_gpu = has_gpu_devices();
    let gpu_device_nodes = if include_gpu {
        enumerate_gpu_device_nodes()
    } else {
        Vec::new()
    };
    collect_baseline_enrichment_paths(include_proxy, include_gpu, gpu_device_nodes)
}

/// Collect all active baseline paths for tests and diagnostics.
/// Returns `(read_only, read_write)` as owned `String` vecs.
#[cfg(test)]
fn baseline_enrichment_paths() -> (Vec<String>, Vec<String>) {
    active_baseline_enrichment_paths(true)
}

fn enrich_proto_baseline_paths_with<F>(
    proto: &mut openshell_core::proto::SandboxPolicy,
    ro: &[String],
    rw: &[String],
    path_exists: F,
) -> bool
where
    F: Fn(&str) -> bool,
{
    if ro.is_empty() && rw.is_empty() {
        return false;
    }

    let fs = proto
        .filesystem
        .get_or_insert_with(|| openshell_core::proto::FilesystemPolicy {
            include_workdir: true,
            ..Default::default()
        });

    let mut modified = false;
    for path in ro {
        if !fs.read_only.iter().any(|p| p == path) && !fs.read_write.iter().any(|p| p == path) {
            if !path_exists(path) {
                debug!(
                    path,
                    "Baseline read-only path does not exist, skipping enrichment"
                );
                continue;
            }
            fs.read_only.push(path.clone());
            modified = true;
        }
    }
    for path in rw {
        if fs.read_write.iter().any(|p| p == path) {
            continue;
        }
        if !path_exists(path) {
            debug!(
                path,
                "Baseline read-write path does not exist, skipping enrichment"
            );
            continue;
        }
        if fs.read_only.iter().any(|p| p == path) {
            if path == "/proc" {
                info!(
                    path,
                    "Promoting /proc from read-only to read-write for GPU runtime compatibility"
                );
                fs.read_only.retain(|p| p != path);
                fs.read_write.push(path.clone());
                modified = true;
            }
            continue;
        }
        fs.read_write.push(path.clone());
        modified = true;
    }

    modified
}

/// Ensure a proto `SandboxPolicy` includes the baseline filesystem paths
/// required by proxy-mode sandboxes and GPU runtimes. Paths are only added if
/// missing; user-specified paths are never removed.
///
/// Returns `true` if the policy was modified (caller may want to sync back).
fn enrich_proto_baseline_paths(proto: &mut openshell_core::proto::SandboxPolicy) -> bool {
    let (ro, rw) = active_baseline_enrichment_paths(!proto.network_policies.is_empty());

    // Baseline paths are system-injected, not user-specified.  Skip paths
    // that do not exist in this container image to avoid noisy warnings from
    // Landlock and, more critically, to prevent a single missing baseline
    // path from abandoning the entire Landlock ruleset under best-effort
    // mode (see issue #664).
    let modified = enrich_proto_baseline_paths_with(proto, &ro, &rw, |path| {
        std::path::Path::new(path).exists()
    });

    if modified {
        ocsf_emit!(
            ConfigStateChangeBuilder::new(ocsf_ctx())
                .severity(SeverityId::Informational)
                .status(StatusId::Success)
                .state(StateId::Enabled, "enriched")
                .message("Enriched policy with baseline filesystem paths for proxy mode")
                .build()
        );
    }

    modified
}

fn strip_proto_provider_policy_entries(proto: &mut openshell_core::proto::SandboxPolicy) -> bool {
    openshell_policy::strip_provider_rule_names(proto)
}

fn proto_sync_payload_for_enriched_policy(
    proto: &openshell_core::proto::SandboxPolicy,
    enriched: bool,
) -> Option<openshell_core::proto::SandboxPolicy> {
    if !enriched {
        return None;
    }

    let mut sync_policy = proto.clone();
    strip_proto_provider_policy_entries(&mut sync_policy);
    Some(sync_policy)
}

/// Ensure a `SandboxPolicy` (Rust type) includes the baseline filesystem
/// paths required by proxy-mode sandboxes and GPU runtimes. Used for the
/// local-file code path where no proto is available.
fn enrich_sandbox_baseline_paths(policy: &mut SandboxPolicy) {
    let (ro, rw) =
        active_baseline_enrichment_paths(matches!(policy.network.mode, NetworkMode::Proxy));
    if ro.is_empty() && rw.is_empty() {
        return;
    }

    let mut modified = false;
    for path in &ro {
        let p = std::path::PathBuf::from(path);
        if !policy.filesystem.read_only.contains(&p) && !policy.filesystem.read_write.contains(&p) {
            if !p.exists() {
                debug!(
                    path,
                    "Baseline read-only path does not exist, skipping enrichment"
                );
                continue;
            }
            policy.filesystem.read_only.push(p);
            modified = true;
        }
    }
    for path in &rw {
        let p = std::path::PathBuf::from(path);
        if policy.filesystem.read_only.contains(&p) || policy.filesystem.read_write.contains(&p) {
            continue;
        }
        if !p.exists() {
            debug!(
                path,
                "Baseline read-write path does not exist, skipping enrichment"
            );
            continue;
        }
        policy.filesystem.read_write.push(p);
        modified = true;
    }

    if modified {
        ocsf_emit!(
            ConfigStateChangeBuilder::new(ocsf_ctx())
                .severity(SeverityId::Informational)
                .status(StatusId::Success)
                .state(StateId::Enabled, "enriched")
                .message("Enriched policy with baseline filesystem paths for proxy mode")
                .build()
        );
    }
}

#[cfg(test)]
#[allow(
    clippy::needless_raw_string_hashes,
    clippy::iter_on_single_items,
    clippy::similar_names,
    clippy::manual_string_new,
    clippy::doc_markdown,
    reason = "Test code: test fixtures often use idiomatic forms not flagged in production."
)]
mod baseline_tests {
    use super::*;
    use openshell_core::policy::{FilesystemPolicy, LandlockPolicy, ProcessPolicy};

    #[test]
    fn proc_not_in_both_read_only_and_read_write_when_gpu_present() {
        // When GPU devices are present, /proc is promoted to read_write
        // (CUDA needs to write /proc/<pid>/task/<tid>/comm). It should
        // NOT also appear in read_only.
        if !has_gpu_devices() {
            // Can't test GPU dedup without GPU devices; skip silently.
            return;
        }
        let (ro, rw) = baseline_enrichment_paths();
        assert!(
            rw.contains(&"/proc".to_string()),
            "/proc should be in read_write when GPU is present"
        );
        assert!(
            !ro.contains(&"/proc".to_string()),
            "/proc should NOT be in read_only when it is already in read_write"
        );
    }

    #[test]
    fn proc_in_read_only_without_gpu() {
        if has_gpu_devices() {
            // On a GPU host we can't test the non-GPU path; skip silently.
            return;
        }
        let (ro, _rw) = baseline_enrichment_paths();
        assert!(
            ro.contains(&"/proc".to_string()),
            "/proc should be in read_only when GPU is not present"
        );
    }

    #[test]
    fn baseline_read_write_always_includes_sandbox_and_tmp() {
        let (_ro, rw) = baseline_enrichment_paths();
        assert!(rw.contains(&"/sandbox".to_string()));
        assert!(rw.contains(&"/tmp".to_string()));
    }

    #[test]
    fn enumerate_gpu_device_nodes_skips_bare_nvidia() {
        // "nvidia" (without a trailing digit) is a valid /dev entry on some
        // systems but is not a per-GPU device node.  The enumerator must
        // not match it.
        let nodes = enumerate_gpu_device_nodes();
        assert!(
            !nodes.contains(&"/dev/nvidia".to_string()),
            "bare /dev/nvidia should not be enumerated: {nodes:?}"
        );
    }

    #[test]
    fn no_duplicate_paths_in_baseline() {
        let (ro, rw) = baseline_enrichment_paths();
        // No path should appear in both lists.
        for path in &ro {
            assert!(
                !rw.contains(path),
                "path {path} appears in both read_only and read_write"
            );
        }
    }

    #[test]
    fn proto_enrichment_preserves_explicit_read_only_for_baseline_read_write_paths() {
        let mut policy = openshell_policy::restrictive_default_policy();
        policy.filesystem = Some(openshell_core::proto::FilesystemPolicy {
            read_only: vec!["/tmp".to_string()],
            read_write: vec![],
            include_workdir: false,
        });
        policy.network_policies.insert(
            "test".into(),
            openshell_core::proto::NetworkPolicyRule {
                name: "test-rule".into(),
                endpoints: vec![openshell_core::proto::NetworkEndpoint {
                    host: "example.com".into(),
                    port: 443,
                    ..Default::default()
                }],
                ..Default::default()
            },
        );

        enrich_proto_baseline_paths(&mut policy);

        let filesystem = policy.filesystem.expect("filesystem policy");
        assert!(
            filesystem.read_only.contains(&"/tmp".to_string()),
            "explicit read_only baseline path should be preserved"
        );
        assert!(
            !filesystem.read_write.contains(&"/tmp".to_string()),
            "baseline enrichment must not promote explicit read_only /tmp to read_write"
        );
    }

    #[test]
    fn proto_strip_provider_policy_entries_removes_only_reserved_entries() {
        let mut policy = openshell_policy::restrictive_default_policy();
        policy.network_policies.insert(
            "_provider_work_github".to_string(),
            openshell_core::proto::NetworkPolicyRule {
                name: "_provider_work_github".to_string(),
                ..Default::default()
            },
        );
        policy.network_policies.insert(
            "sandbox_only".to_string(),
            openshell_core::proto::NetworkPolicyRule {
                name: "sandbox_only".to_string(),
                ..Default::default()
            },
        );

        assert!(strip_proto_provider_policy_entries(&mut policy));
        assert!(
            !policy
                .network_policies
                .contains_key("_provider_work_github")
        );
        assert!(policy.network_policies.contains_key("sandbox_only"));
        assert!(!strip_proto_provider_policy_entries(&mut policy));
    }

    #[test]
    fn proto_sync_payload_not_created_for_provider_entries_without_enrichment() {
        let mut runtime_policy = openshell_policy::restrictive_default_policy();
        runtime_policy.network_policies.insert(
            "_provider_work_github".to_string(),
            openshell_core::proto::NetworkPolicyRule {
                name: "_provider_work_github".to_string(),
                ..Default::default()
            },
        );

        assert!(proto_sync_payload_for_enriched_policy(&runtime_policy, false).is_none());
        assert!(
            runtime_policy
                .network_policies
                .contains_key("_provider_work_github"),
            "provider-derived rules alone must not trigger sync or mutate runtime policy"
        );
    }

    #[test]
    fn proto_sync_payload_for_enrichment_strips_provider_entries_without_mutating_runtime_policy() {
        let mut runtime_policy = openshell_policy::restrictive_default_policy();
        runtime_policy.network_policies.insert(
            "_provider_work_github".to_string(),
            openshell_core::proto::NetworkPolicyRule {
                name: "_provider_work_github".to_string(),
                ..Default::default()
            },
        );
        runtime_policy.network_policies.insert(
            "sandbox_only".to_string(),
            openshell_core::proto::NetworkPolicyRule {
                name: "sandbox_only".to_string(),
                ..Default::default()
            },
        );

        let sync_policy = proto_sync_payload_for_enriched_policy(&runtime_policy, true)
            .expect("enrichment should create a sync payload");

        assert!(
            runtime_policy
                .network_policies
                .contains_key("_provider_work_github"),
            "runtime policy must retain provider-derived rules for OPA input"
        );
        assert!(
            !sync_policy
                .network_policies
                .contains_key("_provider_work_github")
        );
        assert!(sync_policy.network_policies.contains_key("sandbox_only"));
    }

    #[test]
    fn proto_gpu_enrichment_promotes_proc_without_network_policy() {
        let mut policy = openshell_policy::restrictive_default_policy();
        assert!(
            policy.network_policies.is_empty(),
            "regression setup must exercise the no-network default path"
        );
        let (ro, rw) =
            collect_baseline_enrichment_paths(false, true, vec!["/dev/nvidia0".to_string()]);

        let enriched = enrich_proto_baseline_paths_with(&mut policy, &ro, &rw, |path| {
            matches!(path, "/proc" | "/dev/nvidia0")
        });

        let filesystem = policy.filesystem.expect("filesystem policy");
        assert!(
            enriched,
            "GPU enrichment should not require network policies"
        );
        assert!(
            filesystem.read_write.contains(&"/dev/nvidia0".to_string()),
            "GPU enrichment should add enumerated device nodes without network policies"
        );
        assert!(
            !filesystem.read_only.contains(&"/proc".to_string()),
            "GPU enrichment should remove /proc from read_only"
        );
        assert!(
            filesystem.read_write.contains(&"/proc".to_string()),
            "GPU enrichment should promote /proc to read_write"
        );
    }

    #[test]
    fn gpu_baseline_read_write_contains_dxg() {
        // /dev/dxg must be present so WSL2 sandboxes get the Landlock
        // read-write rule for the CDI-injected DXG device.  The existence
        // check in enrich_proto_baseline_paths() skips it on native Linux.
        assert!(
            GPU_BASELINE_READ_WRITE.contains(&"/dev/dxg"),
            "/dev/dxg must be in GPU_BASELINE_READ_WRITE for WSL2 support"
        );
    }

    #[test]
    fn local_enrichment_preserves_explicit_read_only_for_baseline_read_write_paths() {
        let mut policy = SandboxPolicy {
            version: 1,
            filesystem: FilesystemPolicy {
                read_only: vec![std::path::PathBuf::from("/tmp")],
                read_write: vec![],
                include_workdir: false,
            },
            network: NetworkPolicy {
                mode: NetworkMode::Proxy,
                proxy: Some(ProxyPolicy { http_addr: None }),
            },
            landlock: LandlockPolicy::default(),
            process: ProcessPolicy::default(),
        };

        enrich_sandbox_baseline_paths(&mut policy);

        assert!(
            policy
                .filesystem
                .read_only
                .contains(&std::path::PathBuf::from("/tmp")),
            "explicit read_only baseline path should be preserved"
        );
        assert!(
            !policy
                .filesystem
                .read_write
                .contains(&std::path::PathBuf::from("/tmp")),
            "baseline enrichment must not promote explicit read_only /tmp to read_write"
        );
    }

    #[test]
    fn gpu_baseline_read_only_contains_usr_lib_wsl() {
        // /usr/lib/wsl must be present so CDI-injected WSL2 GPU library
        // bind-mounts are accessible under Landlock.  Skipped on native Linux.
        assert!(
            GPU_BASELINE_READ_ONLY.contains(&"/usr/lib/wsl"),
            "/usr/lib/wsl must be in GPU_BASELINE_READ_ONLY for WSL2 CDI library paths"
        );
    }

    #[test]
    fn has_gpu_devices_reflects_dxg_or_nvidiactl() {
        // Verify the OR logic: result must match the manual disjunction of
        // the two path checks.  Passes in all environments.
        let nvidiactl = std::path::Path::new("/dev/nvidiactl").exists();
        let dxg = std::path::Path::new("/dev/dxg").exists();
        assert_eq!(
            has_gpu_devices(),
            nvidiactl || dxg,
            "has_gpu_devices() should be true iff /dev/nvidiactl or /dev/dxg exists"
        );
    }
}

/// Returns `true` if the error is transient and worth retrying.
///
/// Walks the `miette::Report` error chain looking for a `tonic::Status`. If
/// found, only the gRPC codes that represent transient failures are retryable.
/// If no `tonic::Status` is present (e.g. a raw connection error), assume the
/// failure is transient.
fn is_retryable_error(err: &miette::Report) -> bool {
    let mut source: Option<&dyn std::error::Error> = Some(err.as_ref());
    while let Some(e) = source {
        if let Some(status) = e.downcast_ref::<tonic::Status>() {
            return matches!(
                status.code(),
                tonic::Code::Unavailable
                    | tonic::Code::DeadlineExceeded
                    | tonic::Code::ResourceExhausted
                    | tonic::Code::Aborted
                    | tonic::Code::Internal
                    | tonic::Code::Unknown
            );
        }
        source = e.source();
    }
    true
}

/// Retry a gRPC operation with exponential backoff (capped at 4 s).
///
/// Non-transient gRPC errors (e.g. `NOT_FOUND`, `INVALID_ARGUMENT`,
/// `PERMISSION_DENIED`) are returned immediately without retrying.
async fn grpc_retry<T, F, Fut>(op_name: &str, f: F) -> Result<T>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let mut last_err = None;
    for attempt in 1..=5u32 {
        match f().await {
            Ok(val) => return Ok(val),
            Err(e) => {
                if !is_retryable_error(&e) {
                    return Err(e);
                }
                if attempt < 5 {
                    warn!(
                        attempt,
                        max_attempts = 5,
                        error = %e,
                        "{op_name} failed, retrying"
                    );
                    let backoff = Duration::from_secs((1u64 << (attempt - 1)).min(4));
                    tokio::time::sleep(backoff).await;
                }
                last_err = Some(e);
            }
        }
    }
    Err(miette::miette!(
        "{op_name} failed after 5 attempts: {}",
        last_err.expect("loop executed at least once")
    ))
}

/// Load sandbox policy from local files or gRPC.
///
/// Priority:
/// 1. If `policy_rules` and `policy_data` are provided, load OPA engine from local files
/// 2. If `sandbox_id` and `openshell_endpoint` are provided, fetch via gRPC
/// 3. If the server returns no policy, discover from disk or use restrictive default
/// 4. Otherwise, return an error
///
/// Returns the policy, the OPA engine, and (for gRPC mode) the original proto
/// policy. The proto is retained so the OPA engine can be rebuilt with symlink
/// resolution after the container entrypoint starts.
async fn load_policy(
    sandbox_id: Option<String>,
    sandbox: Option<String>,
    openshell_endpoint: Option<String>,
    policy_rules: Option<String>,
    policy_data: Option<String>,
) -> Result<(
    SandboxPolicy,
    Option<Arc<OpaEngine>>,
    Option<openshell_core::proto::SandboxPolicy>,
)> {
    // File mode: load OPA engine from rego rules + YAML data (dev override)
    if let (Some(policy_file), Some(data_file)) = (&policy_rules, &policy_data) {
        ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .state(StateId::Other, "loading")
            .unmapped("policy_rules", serde_json::json!(policy_file))
            .unmapped("policy_data", serde_json::json!(data_file))
            .message(format!(
                "Loading OPA policy engine from local files [rules:{policy_file} data:{data_file}]"
            ))
            .build());
        let engine = OpaEngine::from_files(
            std::path::Path::new(policy_file),
            std::path::Path::new(data_file),
        )?;
        let config = engine.query_sandbox_config()?;
        let mut policy = SandboxPolicy {
            version: 1,
            filesystem: config.filesystem,
            network: NetworkPolicy {
                mode: NetworkMode::Proxy,
                proxy: Some(ProxyPolicy { http_addr: None }),
            },
            landlock: config.landlock,
            process: config.process,
        };
        enrich_sandbox_baseline_paths(&mut policy);
        return Ok((policy, Some(Arc::new(engine)), None));
    }

    // gRPC mode: fetch typed proto policy, construct OPA engine from baked rules + proto data
    if let (Some(id), Some(endpoint)) = (&sandbox_id, &openshell_endpoint) {
        info!(
            sandbox_id = %id,
            endpoint = %endpoint,
            "Fetching sandbox policy via gRPC"
        );
        let proto_policy = grpc_retry("Policy fetch", || {
            openshell_core::grpc_client::fetch_policy(endpoint, id)
        })
        .await?;

        let mut proto_policy = if let Some(p) = proto_policy {
            p
        } else {
            // No policy configured on the server. Discover from disk or
            // fall back to the restrictive default, then sync to the
            // gateway so it becomes the authoritative baseline.
            ocsf_emit!(
                ConfigStateChangeBuilder::new(ocsf_ctx())
                    .severity(SeverityId::Informational)
                    .status(StatusId::Success)
                    .state(StateId::Other, "discovery")
                    .message("Server returned no policy; attempting local discovery")
                    .build()
            );
            let mut discovered = discover_policy_from_disk_or_default();
            // Enrich before syncing so the gateway baseline includes
            // baseline paths from the start.
            enrich_proto_baseline_paths(&mut discovered);
            strip_proto_provider_policy_entries(&mut discovered);
            let sandbox = sandbox.as_deref().ok_or_else(|| {
                miette::miette!(
                    "Cannot sync discovered policy: sandbox not available.\n\
                     Set OPENSHELL_SANDBOX or --sandbox to enable policy sync."
                )
            })?;

            // Sync and re-fetch over a single connection to avoid extra
            // TLS handshakes.
            grpc_retry("Policy discovery sync", || {
                openshell_core::grpc_client::discover_and_sync_policy(
                    endpoint,
                    id,
                    sandbox,
                    &discovered,
                )
            })
            .await?
        };

        // Ensure baseline filesystem paths are present for proxy-mode
        // sandboxes.  If the policy was enriched, sync the updated version
        // back to the gateway so users can see the effective policy.
        let enriched = enrich_proto_baseline_paths(&mut proto_policy);
        let sync_policy = proto_sync_payload_for_enriched_policy(&proto_policy, enriched);
        if let Some(sync_policy) = sync_policy
            && let Some(sandbox_name) = sandbox.as_deref()
            && let Err(e) =
                openshell_core::grpc_client::sync_policy(endpoint, sandbox_name, &sync_policy).await
        {
            warn!(
                error = %e,
                "Failed to sync enriched policy back to gateway (non-fatal)"
            );
        }

        // Build OPA engine from baked-in rules + typed proto data.
        // In cluster mode, proxy networking is always enabled so OPA is
        // always required for allow/deny decisions.
        // The initial load uses pid=0 (no symlink resolution) because the
        // container hasn't started yet. After the entrypoint spawns, the
        // engine is rebuilt with the real PID for symlink resolution.
        info!("Creating OPA engine from proto policy data");
        let opa_engine = Some(Arc::new(OpaEngine::from_proto(&proto_policy)?));

        let policy = SandboxPolicy::try_from(proto_policy.clone())?;
        return Ok((policy, opa_engine, Some(proto_policy)));
    }

    // No policy source available
    Err(miette::miette!(
        "Sandbox policy required. Provide one of:\n\
         - --policy-rules and --policy-data (or OPENSHELL_POLICY_RULES and OPENSHELL_POLICY_DATA env vars)\n\
         - --sandbox-id and --openshell-endpoint (or OPENSHELL_SANDBOX_ID and OPENSHELL_ENDPOINT env vars)"
    ))
}

/// Try to discover a sandbox policy from the well-known disk path, falling
/// back to the legacy path, then to the hardcoded restrictive default.
fn discover_policy_from_disk_or_default() -> openshell_core::proto::SandboxPolicy {
    let primary = std::path::Path::new(openshell_policy::CONTAINER_POLICY_PATH);
    if primary.exists() {
        return discover_policy_from_path(primary);
    }
    let legacy = std::path::Path::new(openshell_policy::LEGACY_CONTAINER_POLICY_PATH);
    if legacy.exists() {
        ocsf_emit!(
            ConfigStateChangeBuilder::new(ocsf_ctx())
                .severity(SeverityId::Informational)
                .status(StatusId::Success)
                .state(StateId::Enabled, "loaded")
                .unmapped(
                    "legacy_path",
                    serde_json::json!(legacy.display().to_string())
                )
                .unmapped("new_path", serde_json::json!(primary.display().to_string()))
                .message(format!(
                    "Policy found at legacy path; consider moving [legacy_path:{} new_path:{}]",
                    legacy.display(),
                    primary.display()
                ))
                .build()
        );
        return discover_policy_from_path(legacy);
    }
    discover_policy_from_path(primary)
}

/// Try to read a sandbox policy YAML from `path`, falling back to the
/// hardcoded restrictive default if the file is missing or invalid.
fn discover_policy_from_path(path: &std::path::Path) -> openshell_core::proto::SandboxPolicy {
    use openshell_policy::{
        parse_sandbox_policy, restrictive_default_policy, validate_sandbox_policy,
    };

    let Ok(yaml) = std::fs::read_to_string(path) else {
        ocsf_emit!(
            ConfigStateChangeBuilder::new(ocsf_ctx())
                .severity(SeverityId::Informational)
                .status(StatusId::Success)
                .state(StateId::Enabled, "default")
                .message(format!(
                    "No policy file on disk, using restrictive default [path:{}]",
                    path.display()
                ))
                .build()
        );
        return restrictive_default_policy();
    };
    ocsf_emit!(
        ConfigStateChangeBuilder::new(ocsf_ctx())
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .state(StateId::Enabled, "loaded")
            .message(format!(
                "Loaded sandbox policy from container disk [path:{}]",
                path.display()
            ))
            .build()
    );
    match parse_sandbox_policy(&yaml) {
        Ok(policy) => {
            // Validate the disk-loaded policy for safety.
            if let Err(violations) = validate_sandbox_policy(&policy) {
                let messages: Vec<String> = violations.iter().map(ToString::to_string).collect();
                ocsf_emit!(DetectionFindingBuilder::new(ocsf_ctx())
                    .activity(ActivityId::Open)
                    .severity(SeverityId::Medium)
                    .action(ActionId::Denied)
                    .disposition(DispositionId::Blocked)
                    .finding_info(
                        FindingInfo::new(
                            "unsafe-disk-policy",
                            "Unsafe Disk Policy Content",
                        )
                        .with_desc(&format!(
                            "Disk policy at {} contains unsafe content: {}",
                            path.display(),
                            messages.join("; "),
                        )),
                    )
                    .message(format!(
                        "Disk policy contains unsafe content, using restrictive default [path:{}]",
                        path.display()
                    ))
                    .build());
                return restrictive_default_policy();
            }
            policy
        }
        Err(e) => {
            ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
                .severity(SeverityId::Medium)
                .status(StatusId::Failure)
                .state(StateId::Other, "fallback")
                .message(format!(
                    "Failed to parse disk policy, using restrictive default [path:{} error:{e}]",
                    path.display()
                ))
                .build());
            restrictive_default_policy()
        }
    }
}

/// Background loop that polls the server for policy updates.
///
/// When a new version is detected, attempts to reload the OPA engine via
/// `reload_from_proto_with_pid()`. Reports load success/failure back to the
/// server. On failure, the previous engine is untouched (LKG behavior).
///
/// When the entrypoint PID is available, policy reloads include symlink
/// resolution for binary paths via the container filesystem.
struct PolicyPollLoopContext {
    endpoint: String,
    sandbox_id: String,
    opa_engine: Arc<OpaEngine>,
    entrypoint_pid: Arc<AtomicU32>,
    interval_secs: u64,
    ocsf_enabled: Arc<std::sync::atomic::AtomicBool>,
    provider_credentials: ProviderCredentialState,
    policy_local_ctx: Option<Arc<openshell_supervisor_network::policy_local::PolicyLocalContext>>,
}

async fn run_policy_poll_loop(ctx: PolicyPollLoopContext) -> Result<()> {
    use openshell_core::grpc_client::CachedOpenShellClient;
    use openshell_core::proto::PolicySource;
    use std::sync::atomic::Ordering;

    let client = CachedOpenShellClient::connect(&ctx.endpoint).await?;
    let mut current_config_revision: u64 = 0;
    let mut current_provider_env_revision: u64 = ctx.provider_credentials.snapshot().revision;
    let mut current_policy_hash = String::new();
    let mut current_settings: std::collections::HashMap<
        String,
        openshell_core::proto::EffectiveSetting,
    > = std::collections::HashMap::new();

    // Initialize revision from the first poll.
    match client.poll_settings(&ctx.sandbox_id).await {
        Ok(result) => {
            apply_ocsf_json_setting(&ctx.ocsf_enabled, &result.settings);
            current_config_revision = result.config_revision;
            current_policy_hash = result.policy_hash.clone();
            current_settings = result.settings;
            debug!(
                config_revision = current_config_revision,
                "Settings poll: initial config revision"
            );
        }
        Err(e) => {
            warn!(error = %e, "Settings poll: failed to fetch initial version, will retry");
        }
    }

    let interval = Duration::from_secs(ctx.interval_secs);
    loop {
        tokio::time::sleep(interval).await;

        let result = match client.poll_settings(&ctx.sandbox_id).await {
            Ok(r) => r,
            Err(e) => {
                debug!(error = %e, "Settings poll: server unreachable, will retry");
                continue;
            }
        };

        let provider_env_changed = result.provider_env_revision != current_provider_env_revision;
        if result.config_revision == current_config_revision && !provider_env_changed {
            continue;
        }

        let policy_changed = result.policy_hash != current_policy_hash;

        // Log which settings changed.
        log_setting_changes(&current_settings, &result.settings);

        ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .state(StateId::Other, "detected")
            .unmapped("old_config_revision", serde_json::json!(current_config_revision))
            .unmapped("new_config_revision", serde_json::json!(result.config_revision))
            .unmapped("policy_changed", serde_json::json!(policy_changed))
            .unmapped("provider_env_changed", serde_json::json!(provider_env_changed))
            .message(format!(
                "Settings poll: config change detected [old_revision:{current_config_revision} new_revision:{} policy_changed:{policy_changed} provider_env_changed:{provider_env_changed}]",
                result.config_revision
            ))
            .build());

        if provider_env_changed {
            match openshell_core::grpc_client::fetch_provider_environment(
                &ctx.endpoint,
                &ctx.sandbox_id,
            )
            .await
            {
                Ok(env_result) => {
                    let env_count = ctx.provider_credentials.install_environment(
                        env_result.provider_env_revision,
                        env_result.environment,
                        env_result.credential_expires_at_ms,
                        env_result.dynamic_credentials,
                    );
                    current_provider_env_revision = env_result.provider_env_revision;
                    ocsf_emit!(
                        ConfigStateChangeBuilder::new(ocsf_ctx())
                            .severity(SeverityId::Informational)
                            .status(StatusId::Success)
                            .state(StateId::Enabled, "loaded")
                            .unmapped(
                                "provider_env_revision",
                                serde_json::json!(current_provider_env_revision)
                            )
                            .message(format!(
                                "Provider environment refreshed [revision:{current_provider_env_revision} env_count:{env_count}]"
                            ))
                            .build()
                    );
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        provider_env_revision = result.provider_env_revision,
                        "Settings poll: failed to refresh provider environment"
                    );
                }
            }
        }

        // Only reload OPA when the policy payload actually changed.
        if policy_changed {
            let Some(policy) = result.policy.as_ref() else {
                ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
                    .severity(SeverityId::Medium)
                    .status(StatusId::Failure)
                    .state(StateId::Other, "skipped")
                    .message("Settings poll: policy hash changed but no policy payload present; skipping reload")
                    .build());
                current_config_revision = result.config_revision;
                current_policy_hash = result.policy_hash;
                current_settings = result.settings;
                continue;
            };

            let pid = ctx.entrypoint_pid.load(Ordering::Acquire);
            match ctx.opa_engine.reload_from_proto_with_pid(policy, pid) {
                Ok(()) => {
                    if let Some(policy_local_ctx) = ctx.policy_local_ctx.as_ref() {
                        policy_local_ctx.set_current_policy(policy.clone()).await;
                    }
                    if result.global_policy_version > 0 {
                        ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
                            .severity(SeverityId::Informational)
                            .status(StatusId::Success)
                            .state(StateId::Enabled, "loaded")
                            .unmapped("policy_hash", serde_json::json!(&result.policy_hash))
                            .unmapped("global_version", serde_json::json!(result.global_policy_version))
                            .message(format!(
                                "Policy reloaded successfully (global) [policy_hash:{} global_version:{}]",
                                result.policy_hash,
                                result.global_policy_version
                            ))
                            .build());
                    } else {
                        ocsf_emit!(
                            ConfigStateChangeBuilder::new(ocsf_ctx())
                                .severity(SeverityId::Informational)
                                .status(StatusId::Success)
                                .state(StateId::Enabled, "loaded")
                                .unmapped("policy_hash", serde_json::json!(&result.policy_hash))
                                .message(format!(
                                    "Policy reloaded successfully [policy_hash:{}]",
                                    result.policy_hash
                                ))
                                .build()
                        );
                    }
                    if result.version > 0
                        && result.policy_source == PolicySource::Sandbox
                        && let Err(e) = client
                            .report_policy_status(&ctx.sandbox_id, result.version, true, "")
                            .await
                    {
                        warn!(error = %e, "Failed to report policy load success");
                    }
                }
                Err(e) => {
                    ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
                        .severity(SeverityId::Medium)
                        .status(StatusId::Failure)
                        .state(StateId::Other, "failed")
                        .unmapped("version", serde_json::json!(result.version))
                        .unmapped("error", serde_json::json!(e.to_string()))
                        .message(format!(
                            "Policy reload failed, keeping last-known-good policy [version:{} error:{e}]",
                            result.version
                        ))
                        .build());
                    if result.version > 0
                        && result.policy_source == PolicySource::Sandbox
                        && let Err(report_err) = client
                            .report_policy_status(
                                &ctx.sandbox_id,
                                result.version,
                                false,
                                &e.to_string(),
                            )
                            .await
                    {
                        warn!(error = %report_err, "Failed to report policy load failure");
                    }
                }
            }
        }

        // Apply OCSF JSON toggle from the `ocsf_json_enabled` setting.
        apply_ocsf_json_setting(&ctx.ocsf_enabled, &result.settings);

        // Apply the agent-proposals feature toggle. On a false→true transition
        // we lazily install the skill so a sandbox that started with the flag
        // off picks up the surface without a recreate. We never uninstall on
        // a true→false transition: stale skill content on disk is harmless
        // because route_request and agent_next_steps both gate on the live
        // atomic, so the agent that reads the skill will see 404s and an
        // empty `next_steps` array regardless.
        if let Some(flag) = AGENT_PROPOSALS_ENABLED.get() {
            let new_proposals = extract_bool_setting(
                &result.settings,
                openshell_core::settings::AGENT_POLICY_PROPOSALS_ENABLED_KEY,
            )
            .unwrap_or(false);
            let prev_proposals = flag.swap(new_proposals, Ordering::Relaxed);
            if new_proposals != prev_proposals {
                info!(
                    agent_policy_proposals_enabled = new_proposals,
                    "agent-driven policy proposals toggled"
                );
                if new_proposals && !prev_proposals {
                    match skills::install_static_skills() {
                        Ok(installed) => info!(
                            path = %installed.policy_advisor.display(),
                            "Installed sandbox agent skill on toggle-on"
                        ),
                        Err(error) => warn!(
                            error = %error,
                            "Failed to install sandbox agent skill on toggle-on"
                        ),
                    }
                }
            }
        }

        current_config_revision = result.config_revision;
        current_policy_hash = result.policy_hash;
        current_settings = result.settings;
    }
}

fn apply_ocsf_json_setting(
    enabled: &std::sync::atomic::AtomicBool,
    settings: &std::collections::HashMap<String, openshell_core::proto::EffectiveSetting>,
) {
    use std::sync::atomic::Ordering;

    let new_ocsf = extract_bool_setting(settings, "ocsf_json_enabled").unwrap_or(false);
    let prev_ocsf = enabled.swap(new_ocsf, Ordering::Relaxed);
    if new_ocsf != prev_ocsf {
        info!(ocsf_json_enabled = new_ocsf, "OCSF JSONL logging toggled");
    }
}

/// Extract a bool value from an effective setting, if present.
fn extract_bool_setting(
    settings: &std::collections::HashMap<String, openshell_core::proto::EffectiveSetting>,
    key: &str,
) -> Option<bool> {
    use openshell_core::proto::setting_value;
    settings
        .get(key)
        .and_then(|es| es.value.as_ref())
        .and_then(|sv| sv.value.as_ref())
        .and_then(|v| match v {
            setting_value::Value::BoolValue(b) => Some(*b),
            _ => None,
        })
}

/// Log individual setting changes between two snapshots.
fn log_setting_changes(
    old: &std::collections::HashMap<String, openshell_core::proto::EffectiveSetting>,
    new: &std::collections::HashMap<String, openshell_core::proto::EffectiveSetting>,
) {
    for (key, new_es) in new {
        let new_val = format_setting_value(new_es);
        match old.get(key) {
            Some(old_es) => {
                let old_val = format_setting_value(old_es);
                if old_val != new_val {
                    ocsf_emit!(
                        ConfigStateChangeBuilder::new(ocsf_ctx())
                            .severity(SeverityId::Informational)
                            .status(StatusId::Success)
                            .state(StateId::Enabled, "updated")
                            .unmapped("key", serde_json::json!(key))
                            .unmapped("old", serde_json::json!(old_val.clone()))
                            .unmapped("new", serde_json::json!(new_val.clone()))
                            .message(format!(
                                "Setting changed [key:{key} old:{old_val} new:{new_val}]"
                            ))
                            .build()
                    );
                }
            }
            None => {
                ocsf_emit!(
                    ConfigStateChangeBuilder::new(ocsf_ctx())
                        .severity(SeverityId::Informational)
                        .status(StatusId::Success)
                        .state(StateId::Enabled, "enabled")
                        .unmapped("key", serde_json::json!(key))
                        .unmapped("value", serde_json::json!(new_val.clone()))
                        .message(format!("Setting added [key:{key} value:{new_val}]"))
                        .build()
                );
            }
        }
    }
    for key in old.keys() {
        if !new.contains_key(key) {
            ocsf_emit!(
                ConfigStateChangeBuilder::new(ocsf_ctx())
                    .severity(SeverityId::Informational)
                    .status(StatusId::Success)
                    .state(StateId::Disabled, "disabled")
                    .unmapped("key", serde_json::json!(key))
                    .message(format!("Setting removed [key:{key}]"))
                    .build()
            );
        }
    }
}

/// Format an `EffectiveSetting` value for log display.
fn format_setting_value(es: &openshell_core::proto::EffectiveSetting) -> String {
    use openshell_core::proto::setting_value;
    match es.value.as_ref().and_then(|sv| sv.value.as_ref()) {
        None => "<unset>".to_string(),
        Some(setting_value::Value::StringValue(v)) => v.clone(),
        Some(setting_value::Value::BoolValue(v)) => v.to_string(),
        Some(setting_value::Value::IntValue(v)) => v.to_string(),
        Some(setting_value::Value::BytesValue(_)) => "<bytes>".to_string(),
    }
}

#[cfg(test)]
#[allow(
    clippy::needless_raw_string_hashes,
    clippy::iter_on_single_items,
    clippy::similar_names,
    clippy::manual_string_new,
    clippy::doc_markdown,
    reason = "Test code: test fixtures often use idiomatic forms not flagged in production."
)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn effective_bool(value: bool) -> openshell_core::proto::EffectiveSetting {
        openshell_core::proto::EffectiveSetting {
            value: Some(openshell_core::proto::SettingValue {
                value: Some(openshell_core::proto::setting_value::Value::BoolValue(
                    value,
                )),
            }),
            scope: openshell_core::proto::SettingScope::Global.into(),
        }
    }

    #[test]
    fn apply_ocsf_json_setting_enables_from_initial_settings_snapshot() {
        let enabled = AtomicBool::new(false);
        let mut settings = std::collections::HashMap::new();
        settings.insert("ocsf_json_enabled".to_string(), effective_bool(true));

        apply_ocsf_json_setting(&enabled, &settings);

        assert!(enabled.load(Ordering::Relaxed));
    }

    #[test]
    fn apply_ocsf_json_setting_disables_when_setting_is_unset() {
        let enabled = AtomicBool::new(true);
        let settings = std::collections::HashMap::new();

        apply_ocsf_json_setting(&enabled, &settings);

        assert!(!enabled.load(Ordering::Relaxed));
    }

    // ---- Policy disk discovery tests ----

    #[test]
    fn discover_policy_from_nonexistent_path_returns_restrictive_default() {
        let path = std::path::Path::new("/nonexistent/policy.yaml");
        let policy = discover_policy_from_path(path);
        // Restrictive default has no network policies.
        assert!(policy.network_policies.is_empty());
        // But does have filesystem and process policies.
        assert!(policy.filesystem.is_some());
        assert!(policy.process.is_some());
    }

    #[test]
    fn discover_policy_from_valid_yaml_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        std::fs::write(
            &path,
            r#"
version: 1
filesystem_policy:
  include_workdir: false
  read_only:
    - /usr
  read_write:
    - /tmp
network_policies:
  test:
    name: test
    endpoints:
      - { host: example.com, port: 443 }
    binaries:
      - { path: /usr/bin/curl }
"#,
        )
        .unwrap();

        let policy = discover_policy_from_path(&path);
        assert_eq!(policy.network_policies.len(), 1);
        assert!(policy.network_policies.contains_key("test"));
        let fs = policy.filesystem.unwrap();
        assert!(!fs.include_workdir);
    }

    #[test]
    fn discover_policy_from_invalid_yaml_returns_restrictive_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        std::fs::write(&path, "this is not valid yaml: [[[").unwrap();

        let policy = discover_policy_from_path(&path);
        // Falls back to restrictive default.
        assert!(policy.network_policies.is_empty());
        assert!(policy.filesystem.is_some());
    }

    #[test]
    fn discover_policy_from_unsafe_yaml_falls_back_to_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        std::fs::write(
            &path,
            r#"
version: 1
process:
  run_as_user: root
  run_as_group: root
filesystem_policy:
  include_workdir: true
  read_only:
    - /usr
  read_write:
    - /tmp
"#,
        )
        .unwrap();

        let policy = discover_policy_from_path(&path);
        // Falls back to restrictive default because of root user.
        let proc = policy.process.unwrap();
        assert_eq!(proc.run_as_user, "sandbox");
        assert_eq!(proc.run_as_group, "sandbox");
    }

    #[test]
    fn discover_policy_restrictive_default_blocks_network() {
        // In cluster mode we keep proxy mode enabled so `inference.local`
        // can always be routed through proxy/OPA controls.
        let proto = openshell_policy::restrictive_default_policy();
        let local_policy = SandboxPolicy::try_from(proto).expect("conversion should succeed");
        assert!(matches!(local_policy.network.mode, NetworkMode::Proxy));
    }
}
