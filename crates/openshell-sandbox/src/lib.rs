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
mod sidecar_control;

use miette::{IntoDiagnostic, Result, WrapErr};
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

use openshell_core::denial::DenialEvent;
use openshell_core::policy::{NetworkMode, NetworkPolicy, ProxyPolicy, SandboxPolicy};
use openshell_core::proposals::AgentProposals;
use openshell_core::provider_credentials::ProviderCredentialState;
use openshell_supervisor_network::opa::OpaEngine;
use openshell_supervisor_process::process::ProcessEnforcementMode;
pub use openshell_supervisor_process::process::{ProcessHandle, ProcessStatus};
use openshell_supervisor_process::skills;
use tokio::sync::mpsc::UnboundedSender;
#[cfg(any(test, target_os = "linux"))]
use tokio::time::timeout;

const SIDECAR_NETWORK_ENFORCEMENT_MODE: &str = "sidecar-nftables";
const SIDECAR_TLS_DIR: &str = "/etc/openshell-tls/proxy";
const SIDECAR_CA_CERT: &str = "openshell-ca.pem";
const SIDECAR_CA_BUNDLE: &str = "ca-bundle.pem";
const SIDECAR_PROCESS_PROXY_ADDR: &str = "127.0.0.1:3128";
const SIDECAR_READY_TIMEOUT_SECS: u64 = 120;

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
    upstream_proxy_args: openshell_supervisor_network::upstream_proxy::UpstreamProxyArgs,
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

    let sidecar_network_enforcement = sidecar_network_enforcement_enabled();
    let process_enforcement_mode = process_enforcement_mode();
    let process_uses_sidecar_control =
        process_enabled && !network_enabled && sidecar_network_enforcement;
    let mut process_control_connection = None;
    let sidecar_bootstrap = if process_uses_sidecar_control {
        let socket = sidecar_control_socket().ok_or_else(|| {
            miette::miette!(
                "{} is required for process-only sidecar topology",
                openshell_core::sandbox_env::SIDECAR_CONTROL_SOCKET
            )
        })?;
        let (bootstrap, connection) = sidecar_control::connect_process_client(
            &socket,
            Duration::from_secs(SIDECAR_READY_TIMEOUT_SECS),
        )
        .await?;
        process_control_connection = Some(connection);
        Some(bootstrap)
    } else {
        None
    };

    // Load policy and initialize OPA engine
    let openshell_endpoint_for_proxy = openshell_endpoint.clone();
    let sandbox_name_for_agg = sandbox.clone();
    let (
        mut policy,
        opa_engine,
        retained_proto,
        middleware_registry_status,
        loaded_policy_origin,
        initial_agent_proposals_enabled,
    ) = if let Some(bootstrap) = sidecar_bootstrap.as_ref() {
        let (policy, opa_engine, retained_proto, loaded_policy_origin) =
            load_policy_from_sidecar_bootstrap(bootstrap)?;
        (
            policy,
            opa_engine,
            retained_proto,
            MiddlewareRegistryStatus::Synchronized,
            loaded_policy_origin,
            bootstrap.agent_proposals_enabled,
        )
    } else {
        load_policy(
            sandbox_id.clone(),
            sandbox,
            openshell_endpoint.clone(),
            policy_rules,
            policy_data,
        )
        .await?
    };

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

    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let (provider_credentials, mut provider_env) =
        if let Some(bootstrap) = sidecar_bootstrap.as_ref() {
            let provider_credentials = ProviderCredentialState::from_child_env_snapshot(
                bootstrap.provider_env_revision,
                bootstrap.provider_child_env.clone(),
            );
            (provider_credentials, bootstrap.provider_child_env.clone())
        } else {
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
            let provider_env = provider_credentials.child_env_with_gcp_resolved();
            (provider_credentials, provider_env)
        };

    // Shared agent-proposals feature flag. Seed from the same initial settings
    // snapshot that produced the policy so networking and process setup agree
    // before the poll loop starts reconciling later changes.
    let agent_proposals = AgentProposals::new(initial_agent_proposals_enabled);

    let process_control_writer = process_control_connection
        .as_ref()
        .map(|connection| connection.writer.clone());
    let mut process_control_closed = None;
    if let Some(connection) = process_control_connection {
        process_control_closed = Some(connection.closed);
        spawn_sidecar_control_update_watcher(
            connection.updates,
            provider_credentials.clone(),
            agent_proposals.clone(),
        );
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
    let netns = if network_enabled && !sidecar_network_enforcement {
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

    // Workspace watch: the policy poll loop learns the workspace from
    // GetSandboxConfig and broadcasts it. Flush tasks and the policy.local
    // API read the current value so proposals target the correct workspace.
    let (workspace_tx, workspace_rx) = tokio::sync::watch::channel(String::new());

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
                agent_proposals.clone(),
                workspace_rx.clone(),
                &upstream_proxy_args,
            )
            .await?,
        )
    } else {
        None
    };

    #[cfg(target_os = "linux")]
    let sidecar_control_server = if network_enabled && sidecar_network_enforcement {
        if !matches!(policy.network.mode, NetworkMode::Proxy) {
            return Err(miette::miette!(
                "sidecar network enforcement requires proxy network mode"
            ));
        }
        let socket = sidecar_control_socket().ok_or_else(|| {
            miette::miette!(
                "{} is required for sidecar topology",
                openshell_core::sandbox_env::SIDECAR_CONTROL_SOCKET
            )
        })?;
        let proto = retained_proto.as_ref().ok_or_else(|| {
            miette::miette!(
                "sidecar topology requires gateway policy data for the process supervisor"
            )
        })?;
        let ca_paths = networking.as_ref().and_then(|n| n.ca_file_paths.clone());
        Some(sidecar_control::spawn_server(
            &socket,
            sidecar_control::BootstrapData {
                policy_proto: proto.clone(),
                provider_env_revision: provider_credentials.snapshot().revision,
                provider_child_env: provider_env.clone(),
                agent_proposals_enabled: agent_proposals.enabled(),
                proxy_ca_cert_path: ca_paths.as_ref().map(|paths| paths.0.clone()),
                proxy_ca_bundle_path: ca_paths.as_ref().map(|paths| paths.1.clone()),
            },
            sidecar_expected_peer()?,
        )?)
    } else {
        None
    };
    #[cfg(not(target_os = "linux"))]
    let sidecar_control_server: Option<sidecar_control::ServerHandle> = None;

    let sidecar_control_publisher = sidecar_control_server
        .as_ref()
        .map(sidecar_control::ServerHandle::publisher);

    #[cfg(target_os = "linux")]
    let mut sidecar_control_task = None;

    #[cfg(target_os = "linux")]
    if network_enabled
        && sidecar_network_enforcement
        && let Some(server) = sidecar_control_server
    {
        let trusted_ssh_socket_path = ssh_socket_path.clone().ok_or_else(|| {
            miette::miette!(
                "{} is required for sidecar network topology",
                openshell_core::sandbox_env::SSH_SOCKET_PATH
            )
        })?;
        let (entrypoint_rx, connection_task) = server.into_runtime_parts();
        sidecar_control_task = Some(connection_task);
        spawn_sidecar_entrypoint_handler(
            entrypoint_rx,
            entrypoint_pid.clone(),
            opa_engine.clone(),
            retained_proto.clone(),
            openshell_endpoint.clone(),
            sandbox_id.clone(),
            std::path::PathBuf::from(trusted_ssh_socket_path),
        );
    }

    #[cfg(not(target_os = "linux"))]
    if network_enabled && sidecar_network_enforcement {
        return Err(miette::miette!(
            "sidecar network enforcement is only supported on Linux"
        ));
    }

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
        let denial_workspace_gate = workspace_rx.clone();
        let denial_workspace_rx = workspace_rx.clone();

        tokio::spawn(async move {
            aggregator
                .run(
                    |summaries| {
                        let endpoint = agg_endpoint.clone();
                        let sandbox_name = agg_name.clone();
                        let workspace = denial_workspace_rx.borrow().clone();
                        async move {
                            if let Err(e) = flush_proposals_to_gateway(
                                &endpoint,
                                &sandbox_name,
                                &workspace,
                                summaries,
                            )
                            .await
                            {
                                warn!(error = %e, "Failed to flush denial summaries to gateway");
                            }
                        }
                    },
                    move || !denial_workspace_gate.borrow().is_empty(),
                )
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
        let activity_workspace_gate = workspace_rx.clone();
        let activity_workspace_rx = workspace_rx.clone();

        tokio::spawn(async move {
            aggregator
                .run(
                    move |summary| {
                        let endpoint = agg_endpoint.clone();
                        let sandbox_name = agg_name.clone();
                        let workspace = activity_workspace_rx.borrow().clone();
                        async move {
                            if let Err(e) = flush_activity_to_gateway(
                                &endpoint,
                                &sandbox_name,
                                &workspace,
                                summary,
                            )
                            .await
                            {
                                warn!(error = %e, "Failed to flush activity summary to gateway");
                            }
                        }
                    },
                    move || !activity_workspace_gate.borrow().is_empty(),
                )
                .await;
        });
    }

    // Spawn background policy poll task (gRPC mode only).
    if !process_uses_sidecar_control
        && let (Some(id), Some(endpoint), Some(engine)) = (
            sandbox_id.as_deref(),
            openshell_endpoint.as_deref(),
            opa_engine.as_ref(),
        )
    {
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
            loaded_policy_origin,
            entrypoint_pid: poll_pid,
            interval_secs: poll_interval_secs,
            ocsf_enabled: poll_ocsf_enabled,
            provider_credentials: poll_provider_credentials,
            policy_local_ctx: poll_policy_local,
            agent_proposals: agent_proposals.clone(),
            middleware_registry_status,
            sidecar_control_publisher: sidecar_control_publisher.clone(),
            workspace_tx,
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

    let process_policy = process_policy_for_topology(&policy, sidecar_network_enforcement)?;
    let sidecar_bootstrap_ca_file_paths = sidecar_bootstrap.as_ref().and_then(|bootstrap| {
        bootstrap
            .proxy_ca_cert_path
            .clone()
            .zip(bootstrap.proxy_ca_bundle_path.clone())
    });

    let exit_code = if process_enabled {
        let ca_file_paths = networking
            .as_ref()
            .and_then(|n| n.ca_file_paths.clone())
            .or_else(|| {
                if sidecar_network_enforcement {
                    sidecar_bootstrap_ca_file_paths
                        .clone()
                        .or_else(sidecar_ca_file_paths)
                } else {
                    None
                }
            });

        let entrypoint_started_tx =
            if process_uses_sidecar_control && let Some(writer) = process_control_writer.clone() {
                let (tx, rx) = tokio::sync::oneshot::channel();
                tokio::spawn(async move {
                    match rx.await {
                        Ok(pid) => {
                            if let Err(err) =
                                sidecar_control::send_entrypoint_started(&writer, pid).await
                            {
                                warn!(error = %err, "Failed to send sidecar entrypoint event");
                            }
                        }
                        Err(_closed) => {
                            debug!("Entrypoint exited before sidecar entrypoint event was sent");
                        }
                    }
                });
                Some(tx)
            } else {
                None
            };

        let process = openshell_supervisor_process::run::run_process(
            program,
            args,
            workdir.as_deref(),
            timeout_secs,
            interactive,
            sandbox_id.as_deref(),
            openshell_endpoint.as_deref(),
            ssh_socket_path,
            sidecar_network_enforcement,
            &process_policy,
            process_enforcement_mode,
            entrypoint_pid,
            entrypoint_started_tx,
            provider_credentials,
            provider_env,
            ca_file_paths,
            agent_proposals.clone(),
            #[cfg(target_os = "linux")]
            netns.as_ref(),
            #[cfg(target_os = "linux")]
            bypass_denial_tx,
            #[cfg(target_os = "linux")]
            bypass_activity_tx,
        );

        if let Some(control_closed) = process_control_closed.as_mut() {
            tokio::select! {
                result = process => result?,
                _ = control_closed => {
                    ocsf_emit!(
                        AppLifecycleBuilder::new(ocsf_ctx())
                            .activity(ActivityId::Fail)
                            .severity(SeverityId::High)
                            .status(StatusId::Failure)
                            .message(
                                "Authoritative network-sidecar control channel closed; terminating process container"
                            )
                            .build()
                    );
                    return Err(miette::miette!(
                        "authoritative network-sidecar control channel closed"
                    ));
                }
            }
        } else {
            process.await?
        }
    } else {
        // Network-only sidecar mode: keep the proxy and its background
        // tasks alive (held via the `networking` value) until shutdown. If the
        // sole authenticated process-supervisor control connection closes,
        // exit non-zero so Kubernetes restarts the network sidecar and creates
        // a fresh one-client bootstrap listener for the restarted agent.
        #[cfg(target_os = "linux")]
        if let Some(control_task) = sidecar_control_task {
            tokio::select! {
                () = wait_for_shutdown_signal() => 0,
                result = control_task => {
                    warn!(?result, "Authoritative sidecar control channel exited; restarting sidecar");
                    1
                }
            }
        } else {
            wait_for_shutdown_signal().await;
            0
        }
        #[cfg(not(target_os = "linux"))]
        {
            wait_for_shutdown_signal().await;
            0
        }
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

fn sidecar_network_enforcement_enabled() -> bool {
    std::env::var(openshell_core::sandbox_env::NETWORK_ENFORCEMENT_MODE)
        .is_ok_and(|value| value == SIDECAR_NETWORK_ENFORCEMENT_MODE)
}

fn process_enforcement_mode() -> ProcessEnforcementMode {
    match std::env::var(openshell_core::sandbox_env::SUPERVISOR_TOPOLOGY)
        .ok()
        .as_deref()
    {
        Some("sidecar") => ProcessEnforcementMode::NetworkOnly,
        _ => ProcessEnforcementMode::Full,
    }
}

fn sidecar_control_socket() -> Option<std::path::PathBuf> {
    std::env::var(openshell_core::sandbox_env::SIDECAR_CONTROL_SOCKET)
        .ok()
        .filter(|path| !path.is_empty())
        .map(std::path::PathBuf::from)
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn sidecar_expected_peer() -> Result<sidecar_control::ExpectedPeer> {
    fn required_numeric_env(name: &str) -> Result<u32> {
        let value = std::env::var(name)
            .into_diagnostic()
            .wrap_err_with(|| format!("{name} is required for sidecar control authentication"))?;
        value.parse::<u32>().into_diagnostic().wrap_err_with(|| {
            format!("{name} must be a numeric ID for sidecar control authentication")
        })
    }

    Ok(sidecar_control::ExpectedPeer {
        uid: required_numeric_env(openshell_core::sandbox_env::SANDBOX_UID)?,
        gid: required_numeric_env(openshell_core::sandbox_env::SANDBOX_GID)?,
    })
}

type LoadedPolicyBundle = (
    SandboxPolicy,
    Option<Arc<OpaEngine>>,
    Option<openshell_core::proto::SandboxPolicy>,
    LoadedPolicyOrigin,
);

fn load_policy_from_sidecar_bootstrap(
    bootstrap: &sidecar_control::BootstrapData,
) -> Result<LoadedPolicyBundle> {
    let proto = bootstrap.policy_proto.clone();
    let opa_engine = Some(Arc::new(OpaEngine::from_proto(&proto)?));
    let policy = SandboxPolicy::try_from(proto.clone())?;
    info!("Loaded sidecar policy from control socket bootstrap");
    Ok((
        policy,
        opa_engine,
        Some(proto),
        LoadedPolicyOrigin::Gateway { revision: None },
    ))
}

fn spawn_sidecar_control_update_watcher(
    mut updates: tokio::sync::mpsc::UnboundedReceiver<sidecar_control::ControlUpdate>,
    provider_credentials: ProviderCredentialState,
    agent_proposals: AgentProposals,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(update) = updates.recv().await {
            match update {
                sidecar_control::ControlUpdate::ProviderEnv {
                    revision,
                    provider_child_env,
                } => {
                    if revision <= provider_credentials.snapshot().revision {
                        continue;
                    }
                    let env_count = provider_credentials
                        .install_child_env_snapshot(revision, provider_child_env);
                    ocsf_emit!(
                        ConfigStateChangeBuilder::new(ocsf_ctx())
                            .severity(SeverityId::Informational)
                            .status(StatusId::Success)
                            .state(StateId::Enabled, "loaded")
                            .unmapped("provider_env_revision", serde_json::json!(revision))
                            .message(format!(
                                "Sidecar provider environment refreshed [revision:{revision} env_count:{env_count}]"
                            ))
                            .build()
                    );
                }
                sidecar_control::ControlUpdate::Policy {
                    policy_proto,
                    policy_hash,
                    config_revision,
                } => {
                    debug!(
                        version = policy_proto.version,
                        policy_hash,
                        config_revision,
                        "Received sidecar policy update for process supervisor"
                    );
                }
                sidecar_control::ControlUpdate::AgentProposals {
                    enabled,
                    config_revision,
                } => {
                    apply_agent_proposals_enabled(
                        &agent_proposals,
                        enabled,
                        "sidecar control",
                        Some(config_revision),
                        None,
                        skills::install_static_skills,
                    );
                }
            }
        }
    })
}

#[cfg(target_os = "linux")]
fn spawn_sidecar_entrypoint_handler(
    mut entrypoint_rx: tokio::sync::mpsc::Receiver<sidecar_control::EntrypointStarted>,
    entrypoint_pid: Arc<AtomicU32>,
    opa_engine: Option<Arc<OpaEngine>>,
    retained_proto: Option<openshell_core::proto::SandboxPolicy>,
    openshell_endpoint: Option<String>,
    sandbox_id: Option<String>,
    trusted_ssh_socket_path: std::path::PathBuf,
) {
    tokio::spawn(async move {
        let mut session_started = false;
        let mut trusted_supervisor_pid = None;
        while let Some(started) = entrypoint_rx.recv().await {
            entrypoint_pid.store(started.pid, std::sync::atomic::Ordering::Release);
            if started.start_session {
                info!(
                    pid = started.pid,
                    ssh_socket = %trusted_ssh_socket_path.display(),
                    "Sidecar process supervisor reported entrypoint start"
                );
            } else {
                trusted_supervisor_pid = Some(started.pid);
                info!(
                    pid = started.pid,
                    "Sidecar process supervisor reported initial process anchor"
                );
            }

            if let (Some(engine), Some(proto)) = (opa_engine.as_ref(), retained_proto.as_ref()) {
                match engine.reload_from_proto_with_pid(proto, started.pid) {
                    Ok(()) => info!(
                        pid = started.pid,
                        "Policy binary symlink resolution complete for sidecar process anchor"
                    ),
                    Err(err) => warn!(
                        error = %err,
                        pid = started.pid,
                        "Failed to rebuild OPA engine with sidecar process anchor PID"
                    ),
                }
            }

            if started.start_session
                && !session_started
                && let (Some(endpoint), Some(id)) =
                    (openshell_endpoint.as_ref(), sandbox_id.as_ref())
            {
                let Some(supervisor_pid) = trusted_supervisor_pid else {
                    warn!(
                        pid = started.pid,
                        "Ignoring sidecar entrypoint event before authenticated supervisor anchor"
                    );
                    continue;
                };
                openshell_supervisor_process::supervisor_session::spawn(
                    endpoint.clone(),
                    id.clone(),
                    trusted_ssh_socket_path.clone(),
                    None,
                    Some(supervisor_pid),
                );
                session_started = true;
                info!("sidecar supervisor session task spawned");
            }
        }
    });
}

fn sidecar_ca_file_paths() -> Option<(std::path::PathBuf, std::path::PathBuf)> {
    let tls_dir = std::env::var(openshell_core::sandbox_env::PROXY_TLS_DIR)
        .unwrap_or_else(|_| SIDECAR_TLS_DIR.to_string());
    let cert = std::path::Path::new(&tls_dir).join(SIDECAR_CA_CERT);
    let bundle = std::path::Path::new(&tls_dir).join(SIDECAR_CA_BUNDLE);
    (cert.exists() && bundle.exists()).then_some((cert, bundle))
}

fn process_policy_for_topology(
    policy: &SandboxPolicy,
    sidecar_network_enforcement: bool,
) -> Result<SandboxPolicy> {
    let mut process_policy = policy.clone();
    if sidecar_network_enforcement && matches!(process_policy.network.mode, NetworkMode::Proxy) {
        let proxy = process_policy
            .network
            .proxy
            .get_or_insert(ProxyPolicy { http_addr: None });
        if proxy.http_addr.is_none() {
            proxy.http_addr = Some(SIDECAR_PROCESS_PROXY_ADDR.parse().into_diagnostic()?);
        }
    }
    Ok(process_policy)
}

/// Flush aggregated denial summaries to the gateway via `SubmitPolicyAnalysis`.
async fn flush_proposals_to_gateway(
    endpoint: &str,
    sandbox_name: &str,
    workspace: &str,
    summaries: Vec<denial_aggregator::FlushableDenialSummary>,
) -> Result<()> {
    use openshell_core::grpc_client::CachedOpenShellClient;
    use openshell_core::proto::{DenialSummary, L7RequestSample};

    let client = CachedOpenShellClient::connect(endpoint).await?;
    client.set_workspace(workspace.to_string());

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
    workspace: &str,
    summary: activity_aggregator::FlushableActivitySummary,
) -> Result<()> {
    use openshell_core::grpc_client::CachedOpenShellClient;
    use openshell_core::proto::{DenialGroupCount, NetworkActivitySummary};

    let client = CachedOpenShellClient::connect(endpoint).await?;
    client.set_workspace(workspace.to_string());

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
    MiddlewareRegistryStatus,
    LoadedPolicyOrigin,
    bool,
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
        let validate_middleware_config = |implementation: &str, config: &prost_types::Struct| {
            openshell_supervisor_middleware_builtins::validate_config(implementation, config)
                .map_err(|error| error.to_string())
        };
        let engine = OpaEngine::from_files_with_middleware_config(
            std::path::Path::new(policy_file),
            std::path::Path::new(data_file),
            Some(&validate_middleware_config),
        )?;
        let middleware_registry =
            openshell_supervisor_middleware::MiddlewareRegistry::connect_services(
                openshell_supervisor_middleware_builtins::services(),
                Vec::new(),
            )
            .await?;
        engine.replace_middleware_registry(middleware_registry)?;
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
        // File mode has no operator-registered middleware to connect.
        return Ok((
            policy,
            Some(Arc::new(engine)),
            None,
            MiddlewareRegistryStatus::Synchronized,
            LoadedPolicyOrigin::LocalOverride,
            false,
        ));
    }

    // gRPC mode: fetch typed proto policy, construct OPA engine from baked rules + proto data
    if let (Some(id), Some(endpoint)) = (&sandbox_id, &openshell_endpoint) {
        info!(
            sandbox_id = %id,
            endpoint = %endpoint,
            "Fetching sandbox policy via gRPC"
        );
        let mut snapshot = grpc_retry("Policy fetch", || {
            openshell_core::grpc_client::fetch_settings_snapshot(endpoint, id)
        })
        .await?;

        let mut proto_policy = if let Some(p) = snapshot.policy.clone() {
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
            let ws = snapshot.workspace.clone();
            snapshot = grpc_retry("Policy discovery sync", || {
                openshell_core::grpc_client::sync_policy_and_fetch_snapshot(
                    endpoint,
                    id,
                    sandbox,
                    &discovered,
                    &ws,
                )
            })
            .await?;
            snapshot.policy.clone().ok_or_else(|| {
                miette::miette!("Server still returned no policy after sync — this is a bug")
            })?
        };

        // True only while `snapshot` describes the exact policy that will be
        // constructed below. If enrichment cannot be synced and re-fetched,
        // the policy remains enforceable but cannot be acknowledged by
        // inferred structural equality.
        let mut policy_bound_to_snapshot = true;

        // Ensure baseline filesystem paths are present for proxy-mode
        // sandboxes.  If the policy was enriched, sync the updated version
        // back to the gateway so users can see the effective policy.
        let enriched = enrich_proto_baseline_paths(&mut proto_policy);
        let sync_policy = proto_sync_payload_for_enriched_policy(&proto_policy, enriched);
        if let Some(sync_policy) = sync_policy {
            if let Some(sandbox_name) = sandbox.as_deref() {
                match openshell_core::grpc_client::sync_policy_and_fetch_snapshot(
                    endpoint,
                    id,
                    sandbox_name,
                    &sync_policy,
                    &snapshot.workspace,
                )
                .await
                {
                    Ok(canonical) => {
                        if let Some(policy) = canonical.policy.clone() {
                            proto_policy = policy;
                            snapshot = canonical;
                        } else {
                            policy_bound_to_snapshot = false;
                            warn!(
                                "Gateway returned no policy after enrichment sync; initial revision will be reconciled"
                            );
                        }
                    }
                    Err(e) => {
                        policy_bound_to_snapshot = false;
                        warn!(
                            error = %e,
                            "Failed to sync enriched policy back to gateway; initial revision will be reconciled"
                        );
                    }
                }
            } else {
                policy_bound_to_snapshot = false;
            }
        }

        let loaded_policy_revision =
            policy_bound_to_snapshot.then(|| LoadedPolicyRevision::from_snapshot(&snapshot));

        // Build OPA engine from baked-in rules + typed proto data.
        // In cluster mode, proxy networking is always enabled so OPA is
        // always required for allow/deny decisions.
        // The initial load uses pid=0 (no symlink resolution) because the
        // container hasn't started yet. After the entrypoint spawns, the
        // engine is rebuilt with the real PID for symlink resolution.
        info!("Creating OPA engine from proto policy data");
        let engine = match OpaEngine::from_proto(&proto_policy) {
            Ok(engine) => engine,
            Err(e) => {
                report_initial_policy_failure(endpoint, id, loaded_policy_revision.as_ref(), &e)
                    .await;
                return Err(e);
            }
        };

        // Install the in-process catalog before any external connection can
        // fail. A newly started sandbox must always be able to resolve built-in
        // bindings, even while operator-run services are unavailable.
        install_builtin_middleware_registry(&engine).await?;

        // Connect operator-registered middleware services. A connect/describe
        // failure keeps the built-in registry active so each request's
        // `on_error` policy governs matched traffic. The policy poll loop
        // retries the install without waiting for a config change.
        let middleware_services = snapshot.supervisor_middleware_services.clone();
        let middleware_registry_status = if middleware_services.is_empty() {
            MiddlewareRegistryStatus::Synchronized
        } else if let Err(error) = grpc_retry("Middleware connect", || {
            openshell_supervisor_middleware::MiddlewareRegistry::connect_services(
                openshell_supervisor_middleware_builtins::services(),
                middleware_services.clone(),
            )
        })
        .await
        .and_then(|registry| engine.replace_middleware_registry(registry))
        {
            ocsf_emit!(
                ConfigStateChangeBuilder::new(ocsf_ctx())
                    .severity(SeverityId::Medium)
                    .status(StatusId::Failure)
                    .state(StateId::Other, "degraded")
                    .unmapped(
                        "supervisor_middleware_service_count",
                        serde_json::json!(middleware_services.len())
                    )
                    .message(format!(
                        "Supervisor middleware connect failed at startup; continuing with built-in middleware only, per-request on_error governs matched requests [error:{error}]"
                    ))
                    .build()
            );
            MiddlewareRegistryStatus::NeedsReconciliation
        } else {
            MiddlewareRegistryStatus::Synchronized
        };
        let opa_engine = Some(Arc::new(engine));

        let policy = match SandboxPolicy::try_from(proto_policy.clone()) {
            Ok(policy) => policy,
            Err(e) => {
                report_initial_policy_failure(endpoint, id, loaded_policy_revision.as_ref(), &e)
                    .await;
                return Err(e);
            }
        };
        return Ok((
            policy,
            opa_engine,
            Some(proto_policy),
            middleware_registry_status,
            LoadedPolicyOrigin::Gateway {
                revision: loaded_policy_revision,
            },
            agent_proposals_enabled_from_settings(&snapshot.settings),
        ));
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MiddlewareRegistryStatus {
    Synchronized,
    NeedsReconciliation,
}

/// True when the installed middleware registry no longer matches the desired
/// service set and must be rebuilt (reconnecting every delivered service).
///
/// A policy-only change never requires a rebuild: middleware configs were
/// validated at gateway admission and the installed registry's manifests
/// already cover the unchanged service set, so requiring the services to be
/// reachable would only let a middleware outage block the policy update.
fn middleware_registry_needs_rebuild(
    registry_status: MiddlewareRegistryStatus,
    current_services: &[openshell_core::proto::SupervisorMiddlewareService],
    desired_services: &[openshell_core::proto::SupervisorMiddlewareService],
) -> bool {
    registry_status == MiddlewareRegistryStatus::NeedsReconciliation
        || current_services != desired_services
}

fn gateway_policy_runtime_needs_reconciliation(
    reloads_gateway_policy: bool,
    current_policy_hash: &str,
    desired_policy_hash: &str,
    current_services: &[openshell_core::proto::SupervisorMiddlewareService],
    desired_services: &[openshell_core::proto::SupervisorMiddlewareService],
    registry_status: MiddlewareRegistryStatus,
) -> bool {
    reloads_gateway_policy
        && (current_policy_hash != desired_policy_hash
            || middleware_registry_needs_rebuild(
                registry_status,
                current_services,
                desired_services,
            ))
}

/// Identity returned with the exact policy snapshot used to construct OPA.
#[derive(Clone, Debug, PartialEq, Eq)]
struct LoadedPolicyRevision {
    version: u32,
    policy_hash: String,
    config_revision: u64,
    policy_source: openshell_core::proto::PolicySource,
}

/// Identifies where the policy currently loaded into OPA came from.
///
/// A missing gateway revision means the policy was loaded from the gateway but
/// could not be bound to an authoritative snapshot (for example, enrichment
/// sync failed). That state must reconcile on the first successful poll. A
/// local-file override is different: gateway policy revisions are observed for
/// settings/provider refreshes but must never replace the explicit local OPA
/// policy.
#[derive(Clone, Debug, PartialEq, Eq)]
enum LoadedPolicyOrigin {
    LocalOverride,
    Gateway {
        revision: Option<LoadedPolicyRevision>,
    },
}

impl LoadedPolicyOrigin {
    fn allows_gateway_policy_reload(&self) -> bool {
        matches!(self, Self::Gateway { .. })
    }
}

impl LoadedPolicyRevision {
    fn from_snapshot(snapshot: &openshell_core::grpc_client::SettingsPollResult) -> Self {
        Self {
            version: snapshot.version,
            policy_hash: snapshot.policy_hash.clone(),
            config_revision: snapshot.config_revision,
            policy_source: snapshot.policy_source,
        }
    }
}

/// A sandbox-scoped policy revision that was constructed successfully at
/// startup and must be acknowledged to the gateway exactly once.
#[derive(Clone, Debug, PartialEq, Eq)]
struct InitialPolicyAck {
    version: u32,
    policy_hash: String,
    config_revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PolicyStatusUpdate {
    version: u32,
    loaded: bool,
    error: String,
    initial_policy_hash: Option<String>,
}

impl PolicyStatusUpdate {
    fn initial_loaded(ack: &InitialPolicyAck) -> Self {
        Self {
            version: ack.version,
            loaded: true,
            error: String::new(),
            initial_policy_hash: Some(ack.policy_hash.clone()),
        }
    }

    fn loaded(version: u32) -> Self {
        Self {
            version,
            loaded: true,
            error: String::new(),
            initial_policy_hash: None,
        }
    }

    fn failed(version: u32, error: String) -> Self {
        Self {
            version,
            loaded: false,
            error,
            initial_policy_hash: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum InitialPollDisposition {
    Acknowledge(InitialPolicyAck),
    Reconcile,
    TrackOnly,
}

/// Determine whether the initially loaded policy corresponds to an
/// authoritative sandbox-scoped revision that must be acknowledged.
///
/// Returns `Some` only for sandbox-sourced revisions (version > 0) whose
/// captured gateway identity matches the current version and hash. Global
/// policies, local-file development policies, version zero, and changed
/// identities yield `None`, so those paths never emit a sandbox-revision
/// acknowledgement.
fn initial_policy_ack_candidate(
    loaded: Option<&LoadedPolicyRevision>,
    canonical: &openshell_core::grpc_client::SettingsPollResult,
) -> Option<InitialPolicyAck> {
    let loaded = loaded?;
    if loaded.policy_source != openshell_core::proto::PolicySource::Sandbox
        || canonical.policy_source != openshell_core::proto::PolicySource::Sandbox
    {
        return None;
    }
    if loaded.version == 0 || canonical.version == 0 {
        return None;
    }
    if loaded.version != canonical.version
        || loaded.policy_hash != canonical.policy_hash
        || canonical.config_revision < loaded.config_revision
    {
        return None;
    }
    Some(InitialPolicyAck {
        version: loaded.version,
        policy_hash: loaded.policy_hash.clone(),
        config_revision: canonical.config_revision,
    })
}

fn initial_poll_disposition(
    origin: &LoadedPolicyOrigin,
    canonical: &openshell_core::grpc_client::SettingsPollResult,
) -> InitialPollDisposition {
    match origin {
        LoadedPolicyOrigin::LocalOverride => InitialPollDisposition::TrackOnly,
        LoadedPolicyOrigin::Gateway { revision } => {
            initial_policy_ack_candidate(revision.as_ref(), canonical).map_or(
                InitialPollDisposition::Reconcile,
                InitialPollDisposition::Acknowledge,
            )
        }
    }
}

/// Deliver policy status updates independently from policy reconciliation.
///
/// The channel is FIFO, so a delayed older status can never arrive after a
/// newer status and move the gateway's active version backward. Delivery uses
/// the existing bounded retry, but failures never delay policy enforcement.
async fn run_policy_status_reporter(
    client: openshell_core::grpc_client::CachedOpenShellClient,
    sandbox_id: String,
    mut updates: tokio::sync::mpsc::UnboundedReceiver<PolicyStatusUpdate>,
) {
    'updates: while let Some(update) = updates.recv().await {
        let operation = if update.initial_policy_hash.is_some() {
            "Initial policy acknowledgement"
        } else {
            "Policy status report"
        };
        let mut attempt = 1_u32;
        loop {
            let sandbox_id = sandbox_id.clone();
            let error = update.error.clone();
            let client = client.clone();
            match client
                .report_policy_status(&sandbox_id, update.version, update.loaded, &error)
                .await
            {
                Ok(()) => break,
                Err(error) if is_retryable_error(&error) => {
                    let backoff = Duration::from_secs(1_u64 << attempt.saturating_sub(1).min(5));
                    warn!(
                        %error,
                        attempt,
                        version = update.version,
                        loaded = update.loaded,
                        retry_in_secs = backoff.as_secs(),
                        "{operation} failed transiently; retaining ordered update"
                    );
                    tokio::time::sleep(backoff).await;
                    attempt = attempt.saturating_add(1);
                }
                Err(error) => {
                    warn!(
                        %error,
                        version = update.version,
                        loaded = update.loaded,
                        "Discarding terminal policy status update"
                    );
                    continue 'updates;
                }
            }
        }

        if let Some(policy_hash) = update.initial_policy_hash {
            ocsf_emit!(
                ConfigStateChangeBuilder::new(ocsf_ctx())
                    .severity(SeverityId::Informational)
                    .status(StatusId::Success)
                    .state(StateId::Enabled, "loaded")
                    .unmapped("version", serde_json::json!(update.version))
                    .unmapped("policy_hash", serde_json::json!(policy_hash))
                    .message(format!(
                        "Acknowledged initial policy revision as loaded [version:{}]",
                        update.version
                    ))
                    .build()
            );
        }
    }
}

fn enqueue_policy_status(sender: &UnboundedSender<PolicyStatusUpdate>, update: PolicyStatusUpdate) {
    let version = update.version;
    if let Err(error) = sender.send(update) {
        warn!(
            %error,
            version,
            "Policy status reporter unavailable during shutdown"
        );
    }
}

/// Best-effort `FAILED` acknowledgement when initial policy construction or
/// conversion fails.
///
/// Uses the revision identity captured with the policy that failed to build,
/// and preserves the original construction error as the reported message. A
/// delivery failure here is swallowed so it can never mask that error.
async fn report_initial_policy_failure(
    endpoint: &str,
    sandbox_id: &str,
    revision: Option<&LoadedPolicyRevision>,
    error: &miette::Report,
) {
    let Some(revision) = revision.filter(|revision| {
        revision.version > 0
            && revision.policy_source == openshell_core::proto::PolicySource::Sandbox
    }) else {
        return;
    };
    let client = match openshell_core::grpc_client::CachedOpenShellClient::connect(endpoint).await {
        Ok(client) => client,
        Err(e) => {
            warn!(error = %e, "Failed to connect to report initial policy failure");
            return;
        }
    };
    let message = error.to_string();
    if let Err(e) = grpc_retry("Initial policy failure report", || {
        let client = client.clone();
        let message = message.clone();
        async move {
            client
                .report_policy_status(sandbox_id, revision.version, false, &message)
                .await
        }
    })
    .await
    {
        warn!(error = %e, version = revision.version, "Failed to report initial policy failure");
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
    /// Source of the policy currently loaded into OPA. This distinguishes an
    /// explicit local-file override from an unbound gateway revision so the
    /// former is never replaced by policy polling.
    loaded_policy_origin: LoadedPolicyOrigin,
    entrypoint_pid: Arc<AtomicU32>,
    interval_secs: u64,
    ocsf_enabled: Arc<std::sync::atomic::AtomicBool>,
    provider_credentials: ProviderCredentialState,
    policy_local_ctx: Option<Arc<openshell_supervisor_network::policy_local::PolicyLocalContext>>,
    agent_proposals: AgentProposals,
    middleware_registry_status: MiddlewareRegistryStatus,
    sidecar_control_publisher: Option<sidecar_control::Publisher>,
    workspace_tx: tokio::sync::watch::Sender<String>,
}

async fn connect_middleware_registry(
    services: &[openshell_core::proto::SupervisorMiddlewareService],
) -> Result<openshell_supervisor_middleware::MiddlewareRegistry> {
    openshell_supervisor_middleware::MiddlewareRegistry::connect_services(
        openshell_supervisor_middleware_builtins::services(),
        services.to_vec(),
    )
    .await
}

async fn install_builtin_middleware_registry(opa_engine: &OpaEngine) -> Result<()> {
    let registry = openshell_supervisor_middleware::MiddlewareRegistry::connect_services(
        openshell_supervisor_middleware_builtins::services(),
        Vec::new(),
    )
    .await?;
    opa_engine.replace_middleware_registry(registry)
}

async fn reconcile_middleware_registry(
    opa_engine: &OpaEngine,
    desired_services: &[openshell_core::proto::SupervisorMiddlewareService],
    current_services: &mut Vec<openshell_core::proto::SupervisorMiddlewareService>,
    status: &mut MiddlewareRegistryStatus,
) {
    if *status == MiddlewareRegistryStatus::Synchronized
        && desired_services == current_services.as_slice()
    {
        return;
    }

    match connect_middleware_registry(desired_services)
        .await
        .and_then(|registry| opa_engine.replace_middleware_registry(registry))
    {
        Ok(()) => {
            current_services.clear();
            current_services.extend_from_slice(desired_services);
            *status = MiddlewareRegistryStatus::Synchronized;
            ocsf_emit!(
                ConfigStateChangeBuilder::new(ocsf_ctx())
                    .severity(SeverityId::Informational)
                    .status(StatusId::Success)
                    .state(StateId::Enabled, "loaded")
                    .unmapped(
                        "supervisor_middleware_service_count",
                        serde_json::json!(current_services.len())
                    )
                    .message(format!(
                        "Supervisor middleware registry reloaded [service_count:{}]",
                        current_services.len()
                    ))
                    .build()
            );
        }
        Err(error) => {
            // Emit only on the transition into the failed state to avoid
            // repeating the same finding on every poll during an outage.
            if *status == MiddlewareRegistryStatus::Synchronized {
                ocsf_emit!(
                    ConfigStateChangeBuilder::new(ocsf_ctx())
                        .severity(SeverityId::Medium)
                        .status(StatusId::Failure)
                        .state(StateId::Other, "failed")
                        .message(format!(
                            "Supervisor middleware registry reload failed, keeping last-known-good registry [error:{error}]"
                        ))
                        .build()
                );
            }
            *status = MiddlewareRegistryStatus::NeedsReconciliation;
        }
    }
}

async fn run_policy_poll_loop(ctx: PolicyPollLoopContext) -> Result<()> {
    use openshell_core::grpc_client::CachedOpenShellClient;
    use openshell_core::proto::PolicySource;
    use std::sync::atomic::Ordering;

    let client = CachedOpenShellClient::connect(&ctx.endpoint).await?;
    let (status_sender, status_receiver) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(run_policy_status_reporter(
        client.clone(),
        ctx.sandbox_id.clone(),
        status_receiver,
    ));

    let mut current_config_revision: u64 = 0;
    let mut current_provider_env_revision: u64 = ctx.provider_credentials.snapshot().revision;
    let mut current_policy_hash = String::new();
    let mut current_middleware_services = Vec::new();
    let mut middleware_registry_status = ctx.middleware_registry_status;
    let mut current_settings: std::collections::HashMap<
        String,
        openshell_core::proto::EffectiveSetting,
    > = std::collections::HashMap::new();
    let reloads_gateway_policy = ctx.loaded_policy_origin.allows_gateway_policy_reload();
    let mut last_failed_runtime_revision: Option<(u64, String)> = None;

    // A first poll that does not match the policy already loaded into OPA must
    // pass through the normal reconciliation path immediately. It must never
    // seed the applied-state trackers before OPA actually loads it.
    let mut pending_result = None;

    // Initialize revision from the first poll and acknowledge the initial
    // policy revision the supervisor actually loaded. A mismatched result is
    // reconciled below instead of being recorded as already applied.
    match client.poll_settings(&ctx.sandbox_id).await {
        Ok(result) => {
            let _ = ctx.workspace_tx.send(client.workspace());
            match initial_poll_disposition(&ctx.loaded_policy_origin, &result) {
                InitialPollDisposition::Acknowledge(candidate) => {
                    apply_ocsf_json_setting(&ctx.ocsf_enabled, &result.settings);
                    apply_agent_proposals_enabled(
                        &ctx.agent_proposals,
                        agent_proposals_enabled_from_settings(&result.settings),
                        "initial settings poll",
                        Some(candidate.config_revision),
                        ctx.sidecar_control_publisher.as_ref(),
                        skills::install_static_skills,
                    );
                    current_config_revision = candidate.config_revision;
                    current_policy_hash.clone_from(&candidate.policy_hash);
                    current_middleware_services = result.supervisor_middleware_services;
                    current_settings = result.settings;
                    enqueue_policy_status(
                        &status_sender,
                        PolicyStatusUpdate::initial_loaded(&candidate),
                    );
                    debug!(
                        config_revision = current_config_revision,
                        "Settings poll: initial policy matches loaded revision"
                    );
                }
                InitialPollDisposition::Reconcile => pending_result = Some(result),
                InitialPollDisposition::TrackOnly => {
                    apply_ocsf_json_setting(&ctx.ocsf_enabled, &result.settings);
                    apply_agent_proposals_enabled(
                        &ctx.agent_proposals,
                        agent_proposals_enabled_from_settings(&result.settings),
                        "initial settings poll",
                        Some(result.config_revision),
                        ctx.sidecar_control_publisher.as_ref(),
                        skills::install_static_skills,
                    );
                    current_config_revision = result.config_revision;
                    current_policy_hash = result.policy_hash.clone();
                    current_middleware_services = result.supervisor_middleware_services;
                    current_settings = result.settings;
                    debug!(
                        config_revision = current_config_revision,
                        "Settings poll: tracking gateway config while preserving local policy override"
                    );
                }
            }
        }
        Err(e) => {
            warn!(error = %e, "Settings poll: failed to fetch initial version, will retry");
        }
    }

    let interval = Duration::from_secs(ctx.interval_secs);
    loop {
        let result = if let Some(result) = pending_result.take() {
            result
        } else {
            tokio::time::sleep(interval).await;
            match client.poll_settings(&ctx.sandbox_id).await {
                Ok(result) => {
                    let _ = ctx.workspace_tx.send(client.workspace());
                    result
                }
                Err(e) => {
                    debug!(error = %e, "Settings poll: server unreachable, will retry");
                    continue;
                }
            }
        };

        let config_changed = result.config_revision != current_config_revision;
        let provider_env_changed = result.provider_env_revision != current_provider_env_revision;
        let policy_changed = result.policy_hash != current_policy_hash;
        let middleware_registry_changed = middleware_registry_needs_rebuild(
            middleware_registry_status,
            &current_middleware_services,
            &result.supervisor_middleware_services,
        );
        let policy_runtime_changed = gateway_policy_runtime_needs_reconciliation(
            reloads_gateway_policy,
            &current_policy_hash,
            &result.policy_hash,
            &current_middleware_services,
            &result.supervisor_middleware_services,
            middleware_registry_status,
        );

        // A local policy override is not coupled to the gateway policy
        // snapshot, so its service registry can still be reconciled alone.
        // Gateway policy snapshots, however, must install policy and registry
        // as one generation below.
        if !reloads_gateway_policy {
            reconcile_middleware_registry(
                &ctx.opa_engine,
                &result.supervisor_middleware_services,
                &mut current_middleware_services,
                &mut middleware_registry_status,
            )
            .await;
        }

        if !config_changed && !provider_env_changed && !policy_runtime_changed {
            continue;
        }

        if config_changed || provider_env_changed {
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
        }

        if provider_env_changed {
            match openshell_core::grpc_client::fetch_provider_environment(
                &ctx.endpoint,
                &ctx.sandbox_id,
            )
            .await
            {
                Ok(env_result) => {
                    ctx.provider_credentials.install_environment(
                        env_result.provider_env_revision,
                        env_result.environment,
                        env_result.credential_expires_at_ms,
                        env_result.dynamic_credentials,
                    );
                    let child_env = ctx.provider_credentials.child_env_with_gcp_resolved();
                    let env_count = child_env.len();
                    if let Some(publisher) = ctx.sidecar_control_publisher.as_ref() {
                        publisher.publish_provider_env(
                            env_result.provider_env_revision,
                            child_env.clone(),
                        );
                    }
                    current_provider_env_revision = env_result.provider_env_revision;
                    ocsf_emit!(
                        ConfigStateChangeBuilder::new(ocsf_ctx())
                            .severity(SeverityId::Informational)
                            .status(StatusId::Success)
                            .state(StateId::Enabled, "loaded")
                            .unmapped(
                                "provider_env_revision",
                                serde_json::json!(env_result.provider_env_revision)
                            )
                            .message(format!(
                                "Provider environment refreshed [revision:{} env_count:{env_count}]",
                                env_result.provider_env_revision
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

        if policy_runtime_changed {
            let pid = ctx.entrypoint_pid.load(Ordering::Acquire);
            let runtime_result = match result.policy.as_ref() {
                Some(policy) if middleware_registry_changed => {
                    match connect_middleware_registry(&result.supervisor_middleware_services).await
                    {
                        Ok(registry) => ctx
                            .opa_engine
                            .reload_policy_and_middleware_from_proto_with_pid(
                                policy, pid, registry,
                            ),
                        Err(error) => Err(error),
                    }
                }
                // Policy-only change: the installed registry already matches
                // the delivered service set, so swap the engine alone. This
                // must not require middleware reachability.
                Some(policy) => ctx.opa_engine.reload_from_proto_with_pid(policy, pid),
                None => Err(miette::miette!(
                    "runtime reload requires a policy payload but none was returned"
                )),
            };

            match runtime_result {
                Ok(()) => {
                    let policy = result
                        .policy
                        .as_ref()
                        .expect("successful runtime reload requires a policy payload");
                    if policy_changed {
                        if let Some(policy_local_ctx) = ctx.policy_local_ctx.as_ref() {
                            policy_local_ctx.set_current_policy(policy.clone()).await;
                        }
                        if let Some(publisher) = ctx.sidecar_control_publisher.as_ref() {
                            publisher.publish_policy(
                                policy.clone(),
                                result.policy_hash.clone(),
                                result.config_revision,
                            );
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
                        if result.version > 0 && result.policy_source == PolicySource::Sandbox {
                            enqueue_policy_status(
                                &status_sender,
                                PolicyStatusUpdate::loaded(result.version),
                            );
                        }
                    }

                    if middleware_registry_changed {
                        ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
                            .severity(SeverityId::Informational)
                            .status(StatusId::Success)
                            .state(StateId::Enabled, "loaded")
                            .unmapped(
                                "supervisor_middleware_service_count",
                                serde_json::json!(result.supervisor_middleware_services.len())
                            )
                            .message(format!(
                                "Supervisor policy runtime reloaded atomically [service_count:{}]",
                                result.supervisor_middleware_services.len()
                            ))
                            .build());
                    }

                    current_policy_hash.clone_from(&result.policy_hash);
                    current_middleware_services.clone_from(&result.supervisor_middleware_services);
                    middleware_registry_status = MiddlewareRegistryStatus::Synchronized;
                    last_failed_runtime_revision = None;
                }
                Err(e) => {
                    let failed_revision = (result.config_revision, result.policy_hash.clone());
                    if last_failed_runtime_revision.as_ref() != Some(&failed_revision) {
                        ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
                            .severity(SeverityId::Medium)
                            .status(StatusId::Failure)
                            .state(StateId::Other, "failed")
                            .unmapped("version", serde_json::json!(result.version))
                            .unmapped("error", serde_json::json!(e.to_string()))
                            .message(format!(
                                "Policy and middleware runtime reload failed, keeping last-known-good runtime [version:{} error:{e}]",
                                result.version
                            ))
                            .build());
                        if policy_changed
                            && result.version > 0
                            && result.policy_source == PolicySource::Sandbox
                        {
                            enqueue_policy_status(
                                &status_sender,
                                PolicyStatusUpdate::failed(result.version, e.to_string()),
                            );
                        }
                    }
                    last_failed_runtime_revision = Some(failed_revision);
                    // Nothing was installed, so the registry status still
                    // describes the live registry. The retry is driven by the
                    // persisting hash/service-set mismatch (or an existing
                    // NeedsReconciliation), not by degrading the status here.
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
        // shared flag, so the agent that reads the skill will see 404s and an
        // empty `next_steps` array regardless.
        apply_agent_proposals_enabled(
            &ctx.agent_proposals,
            agent_proposals_enabled_from_settings(&result.settings),
            "settings poll",
            Some(result.config_revision),
            ctx.sidecar_control_publisher.as_ref(),
            skills::install_static_skills,
        );

        current_config_revision = result.config_revision;
        if !reloads_gateway_policy {
            current_policy_hash = result.policy_hash;
        }
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

fn agent_proposals_enabled_from_settings(
    settings: &std::collections::HashMap<String, openshell_core::proto::EffectiveSetting>,
) -> bool {
    extract_bool_setting(
        settings,
        openshell_core::settings::AGENT_POLICY_PROPOSALS_ENABLED_KEY,
    )
    .unwrap_or(false)
}

fn apply_agent_proposals_enabled(
    agent_proposals: &AgentProposals,
    enabled: bool,
    source: &'static str,
    config_revision: Option<u64>,
    sidecar_control_publisher: Option<&sidecar_control::Publisher>,
    install_static_skills: impl FnOnce() -> Result<skills::InstalledSkills>,
) {
    let previously_enabled = agent_proposals.swap_enabled(enabled);
    if enabled == previously_enabled {
        return;
    }

    info!(
        agent_policy_proposals_enabled = enabled,
        source, config_revision, "agent-driven policy proposals toggled"
    );

    if let (Some(publisher), Some(config_revision)) = (sidecar_control_publisher, config_revision) {
        publisher.publish_agent_proposals(enabled, config_revision);
    }

    if enabled && !previously_enabled {
        match install_static_skills() {
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
    use openshell_core::policy::{
        FilesystemPolicy, LandlockPolicy, NetworkMode, NetworkPolicy, ProcessPolicy, ProxyPolicy,
    };
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn proxy_policy(http_addr: Option<std::net::SocketAddr>) -> SandboxPolicy {
        SandboxPolicy {
            version: 1,
            filesystem: FilesystemPolicy::default(),
            network: NetworkPolicy {
                mode: NetworkMode::Proxy,
                proxy: Some(ProxyPolicy { http_addr }),
            },
            landlock: LandlockPolicy::default(),
            process: ProcessPolicy::default(),
        }
    }

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
    fn sidecar_process_policy_sets_loopback_proxy_addr() {
        let policy = proxy_policy(None);

        let process_policy = process_policy_for_topology(&policy, true).unwrap();

        let http_addr = process_policy
            .network
            .proxy
            .and_then(|proxy| proxy.http_addr)
            .expect("sidecar process policy should set proxy address");
        assert_eq!(http_addr.to_string(), SIDECAR_PROCESS_PROXY_ADDR);
        assert!(
            policy
                .network
                .proxy
                .as_ref()
                .expect("original policy should keep proxy config")
                .http_addr
                .is_none(),
            "process policy normalization must not mutate the network policy"
        );
    }

    #[test]
    fn non_sidecar_process_policy_preserves_proxy_addr() {
        let policy = proxy_policy(None);

        let process_policy = process_policy_for_topology(&policy, false).unwrap();

        assert!(
            process_policy
                .network
                .proxy
                .and_then(|proxy| proxy.http_addr)
                .is_none()
        );
    }

    #[tokio::test]
    async fn sidecar_control_provider_env_update_installs_newer_revision() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let provider_credentials = ProviderCredentialState::from_child_env_snapshot(
            1,
            std::collections::HashMap::from([("TOKEN".to_string(), "old".to_string())]),
        );
        let handle = spawn_sidecar_control_update_watcher(
            rx,
            provider_credentials.clone(),
            AgentProposals::default(),
        );

        tx.send(sidecar_control::ControlUpdate::ProviderEnv {
            revision: 2,
            provider_child_env: std::collections::HashMap::from([(
                "TOKEN".to_string(),
                "new".to_string(),
            )]),
        })
        .unwrap();

        timeout(Duration::from_secs(1), async {
            loop {
                if provider_credentials.snapshot().revision == 2 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let snapshot = provider_credentials.snapshot();
        assert_eq!(snapshot.revision, 2);
        assert_eq!(
            snapshot.child_env.get("TOKEN").map(String::as_str),
            Some("new")
        );

        tx.send(sidecar_control::ControlUpdate::ProviderEnv {
            revision: 1,
            provider_child_env: std::collections::HashMap::from([(
                "TOKEN".to_string(),
                "stale".to_string(),
            )]),
        })
        .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            provider_credentials
                .snapshot()
                .child_env
                .get("TOKEN")
                .map(String::as_str),
            Some("new")
        );
        handle.abort();
    }

    #[tokio::test]
    async fn sidecar_control_agent_proposals_update_flips_shared_state() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let provider_credentials =
            ProviderCredentialState::from_child_env_snapshot(0, std::collections::HashMap::new());
        let agent_proposals = AgentProposals::new(true);
        let handle =
            spawn_sidecar_control_update_watcher(rx, provider_credentials, agent_proposals.clone());

        tx.send(sidecar_control::ControlUpdate::AgentProposals {
            enabled: false,
            config_revision: 5,
        })
        .unwrap();

        timeout(Duration::from_secs(1), async {
            loop {
                if !agent_proposals.enabled() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        handle.abort();
    }

    #[test]
    fn apply_agent_proposals_enabled_installs_only_on_false_to_true() {
        let agent_proposals = AgentProposals::default();
        let installs = AtomicUsize::new(0);

        apply_agent_proposals_enabled(&agent_proposals, true, "test", Some(1), None, || {
            installs.fetch_add(1, Ordering::Relaxed);
            Ok(skills::InstalledSkills {
                policy_advisor: std::path::PathBuf::from("/tmp/policy_advisor.md"),
                policy_advisor_skill: std::path::PathBuf::from("/tmp/SKILL.md"),
                agents: None,
            })
        });
        assert!(agent_proposals.enabled());
        assert_eq!(installs.load(Ordering::Relaxed), 1);

        apply_agent_proposals_enabled(&agent_proposals, true, "test", Some(2), None, || {
            installs.fetch_add(1, Ordering::Relaxed);
            Ok(skills::InstalledSkills {
                policy_advisor: std::path::PathBuf::from("/tmp/policy_advisor.md"),
                policy_advisor_skill: std::path::PathBuf::from("/tmp/SKILL.md"),
                agents: None,
            })
        });
        assert_eq!(installs.load(Ordering::Relaxed), 1);

        apply_agent_proposals_enabled(&agent_proposals, false, "test", Some(3), None, || {
            installs.fetch_add(1, Ordering::Relaxed);
            Ok(skills::InstalledSkills {
                policy_advisor: std::path::PathBuf::from("/tmp/policy_advisor.md"),
                policy_advisor_skill: std::path::PathBuf::from("/tmp/SKILL.md"),
                agents: None,
            })
        });
        assert!(!agent_proposals.enabled());
        assert_eq!(installs.load(Ordering::Relaxed), 1);
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

    #[test]
    fn agent_proposals_setting_enables_from_initial_settings_snapshot() {
        let mut settings = std::collections::HashMap::new();
        settings.insert(
            openshell_core::settings::AGENT_POLICY_PROPOSALS_ENABLED_KEY.to_string(),
            effective_bool(true),
        );

        assert!(agent_proposals_enabled_from_settings(&settings));
    }

    #[test]
    fn agent_proposals_setting_defaults_false_when_unset() {
        let settings = std::collections::HashMap::new();

        assert!(!agent_proposals_enabled_from_settings(&settings));
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

    // ---- Initial policy acknowledgement tests ----

    fn proto_policy_fixture() -> openshell_core::proto::SandboxPolicy {
        openshell_policy::restrictive_default_policy()
    }

    fn settings_poll_result(
        policy: Option<openshell_core::proto::SandboxPolicy>,
        version: u32,
        source: openshell_core::proto::PolicySource,
    ) -> openshell_core::grpc_client::SettingsPollResult {
        openshell_core::grpc_client::SettingsPollResult {
            policy,
            version,
            policy_hash: format!("hash-v{version}"),
            config_revision: u64::from(version) * 100,
            policy_source: source,
            settings: std::collections::HashMap::new(),
            global_policy_version: 0,
            provider_env_revision: 0,
            supervisor_middleware_services: Vec::new(),
            workspace: String::new(),
        }
    }

    #[tokio::test]
    async fn failed_external_startup_registry_build_preserves_installed_builtins() {
        let engine = OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine");
        install_builtin_middleware_registry(&engine)
            .await
            .expect("install built-in middleware registry");
        let builtins_generation = engine.current_generation();
        assert_eq!(builtins_generation, 1);

        let invalid_external = openshell_core::proto::SupervisorMiddlewareService {
            name: "unavailable-guard".into(),
            grpc_endpoint: "http://127.0.0.1:1".into(),
            max_body_bytes: 1024,
            ..Default::default()
        };
        connect_middleware_registry(&[invalid_external])
            .await
            .expect_err("unavailable external service must not replace built-ins");

        assert_eq!(engine.current_generation(), builtins_generation);
    }

    #[test]
    fn failed_gateway_runtime_snapshot_is_retried_without_revision_change() {
        let services = Vec::new();

        assert!(gateway_policy_runtime_needs_reconciliation(
            true,
            "hash-v1",
            "hash-v1",
            &services,
            &services,
            MiddlewareRegistryStatus::NeedsReconciliation,
        ));
        assert!(!gateway_policy_runtime_needs_reconciliation(
            true,
            "hash-v1",
            "hash-v1",
            &services,
            &services,
            MiddlewareRegistryStatus::Synchronized,
        ));
    }

    #[test]
    fn gateway_runtime_reconciliation_tracks_policy_and_service_changes() {
        let no_services = Vec::new();
        let desired_services = vec![openshell_core::proto::SupervisorMiddlewareService {
            name: "guard".into(),
            ..Default::default()
        }];

        assert!(gateway_policy_runtime_needs_reconciliation(
            true,
            "hash-v1",
            "hash-v2",
            &no_services,
            &no_services,
            MiddlewareRegistryStatus::Synchronized,
        ));
        assert!(gateway_policy_runtime_needs_reconciliation(
            true,
            "hash-v1",
            "hash-v1",
            &no_services,
            &desired_services,
            MiddlewareRegistryStatus::Synchronized,
        ));
        assert!(!gateway_policy_runtime_needs_reconciliation(
            false,
            "local-policy",
            "hash-v2",
            &no_services,
            &desired_services,
            MiddlewareRegistryStatus::NeedsReconciliation,
        ));
    }

    #[test]
    fn policy_only_change_does_not_rebuild_middleware_registry() {
        let services = vec![openshell_core::proto::SupervisorMiddlewareService {
            name: "guard".into(),
            ..Default::default()
        }];

        // The runtime must reconcile, but the registry (and therefore
        // middleware reachability) is not part of that reconciliation.
        assert!(gateway_policy_runtime_needs_reconciliation(
            true,
            "hash-v1",
            "hash-v2",
            &services,
            &services,
            MiddlewareRegistryStatus::Synchronized,
        ));
        assert!(!middleware_registry_needs_rebuild(
            MiddlewareRegistryStatus::Synchronized,
            &services,
            &services,
        ));
    }

    #[test]
    fn registry_rebuild_requires_service_set_change_or_degraded_registry() {
        let no_services = Vec::new();
        let desired_services = vec![openshell_core::proto::SupervisorMiddlewareService {
            name: "guard".into(),
            ..Default::default()
        }];

        assert!(middleware_registry_needs_rebuild(
            MiddlewareRegistryStatus::Synchronized,
            &no_services,
            &desired_services,
        ));
        assert!(middleware_registry_needs_rebuild(
            MiddlewareRegistryStatus::NeedsReconciliation,
            &desired_services,
            &desired_services,
        ));
        assert!(!middleware_registry_needs_rebuild(
            MiddlewareRegistryStatus::Synchronized,
            &desired_services,
            &desired_services,
        ));
    }

    #[test]
    fn initial_ack_candidate_matches_sandbox_revision() {
        let canonical = settings_poll_result(
            Some(proto_policy_fixture()),
            2,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let loaded = LoadedPolicyRevision::from_snapshot(&canonical);

        let ack = initial_policy_ack_candidate(Some(&loaded), &canonical)
            .expect("sandbox-sourced matching revision should be acknowledged");

        assert_eq!(ack.version, 2);
        assert_eq!(ack.policy_hash, "hash-v2");
        assert_eq!(ack.config_revision, 200);
    }

    #[test]
    fn initial_ack_candidate_ignores_global_policy() {
        let canonical = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Global,
        );
        let loaded = LoadedPolicyRevision::from_snapshot(&canonical);

        assert!(initial_policy_ack_candidate(Some(&loaded), &canonical).is_none());
    }

    #[test]
    fn initial_ack_candidate_ignores_version_zero() {
        let canonical = settings_poll_result(
            Some(proto_policy_fixture()),
            0,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let loaded = LoadedPolicyRevision::from_snapshot(&canonical);

        assert!(initial_policy_ack_candidate(Some(&loaded), &canonical).is_none());
    }

    #[test]
    fn initial_ack_candidate_ignores_local_file_mode() {
        // Local-file mode retains no proto policy, so there is nothing to
        // acknowledge to the gateway.
        let canonical = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );

        assert!(initial_policy_ack_candidate(None, &canonical).is_none());
    }

    #[test]
    fn initial_ack_candidate_rejects_mismatched_identity() {
        let loaded_snapshot = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let loaded = LoadedPolicyRevision::from_snapshot(&loaded_snapshot);
        let canonical = settings_poll_result(
            Some(proto_policy_fixture()),
            2,
            openshell_core::proto::PolicySource::Sandbox,
        );

        assert!(initial_policy_ack_candidate(Some(&loaded), &canonical).is_none());
    }

    #[test]
    fn initial_poll_reconciles_provider_composition_that_was_not_loaded() {
        let loaded_snapshot = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let loaded = LoadedPolicyRevision::from_snapshot(&loaded_snapshot);
        let mut newer = proto_policy_fixture();
        newer.network_policies.insert(
            "_provider_work_github".to_string(),
            openshell_core::proto::NetworkPolicyRule::default(),
        );
        let canonical =
            settings_poll_result(Some(newer), 1, openshell_core::proto::PolicySource::Sandbox);
        let canonical = openshell_core::grpc_client::SettingsPollResult {
            policy_hash: "hash-provider-change".to_string(),
            config_revision: loaded.config_revision + 1,
            ..canonical
        };

        assert_eq!(
            initial_poll_disposition(
                &LoadedPolicyOrigin::Gateway {
                    revision: Some(loaded),
                },
                &canonical,
            ),
            InitialPollDisposition::Reconcile
        );
    }

    #[test]
    fn initial_poll_tracks_local_override_without_reconciliation() {
        let canonical = settings_poll_result(
            Some(proto_policy_fixture()),
            2,
            openshell_core::proto::PolicySource::Sandbox,
        );

        assert_eq!(
            initial_poll_disposition(&LoadedPolicyOrigin::LocalOverride, &canonical),
            InitialPollDisposition::TrackOnly
        );
        assert!(!LoadedPolicyOrigin::LocalOverride.allows_gateway_policy_reload());
    }

    #[test]
    fn initial_poll_reconciles_unbound_gateway_policy() {
        let canonical = settings_poll_result(
            Some(proto_policy_fixture()),
            2,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let origin = LoadedPolicyOrigin::Gateway { revision: None };

        assert_eq!(
            initial_poll_disposition(&origin, &canonical),
            InitialPollDisposition::Reconcile
        );
        assert!(origin.allows_gateway_policy_reload());
    }

    #[test]
    fn policy_status_outbox_preserves_all_revision_order() {
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        for version in 1..=128 {
            enqueue_policy_status(&sender, PolicyStatusUpdate::loaded(version));
        }

        for version in 1..=128 {
            assert_eq!(
                receiver.try_recv().unwrap(),
                PolicyStatusUpdate::loaded(version)
            );
        }
    }

    #[test]
    fn settings_snapshot_carries_workspace_for_policy_sync() {
        let mut snapshot = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        snapshot.workspace = "beta".to_string();

        let revision = LoadedPolicyRevision::from_snapshot(&snapshot);
        assert_eq!(revision.version, 1);
        assert_eq!(
            snapshot.workspace, "beta",
            "workspace must survive the snapshot so sync_policy_and_fetch_snapshot receives it"
        );
    }
}
