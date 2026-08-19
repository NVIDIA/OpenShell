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
#[cfg(target_os = "linux")]
use std::sync::atomic::Ordering;
use std::sync::atomic::{AtomicBool, AtomicU32};
use std::time::Duration;
use tracing::{debug, info, warn};

use openshell_core::PolicyValidationFailureMode;

use openshell_ocsf::{
    ActionId, ActivityId, AppLifecycleBuilder, ConfidenceId, ConfigStateChangeBuilder,
    DetectionFindingBuilder, DispositionId, FindingInfo, OcsfEvent, SandboxContext, SeverityId,
    StateId, StatusId, ocsf_emit,
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
const SIDECAR_TLS_DIR: &str = openshell_core::container_paths::SIDECAR_TLS_DIR;
const SIDECAR_CA_CERT: &str = "openshell-ca.pem";
const SIDECAR_CA_BUNDLE: &str = "ca-bundle.pem";

#[cfg(any(test, target_os = "linux"))]
fn has_network_runtime_capability(capabilities: Option<&str>, required: &str) -> bool {
    capabilities.is_some_and(|capabilities| {
        capabilities
            .split(',')
            .any(|capability| capability.trim() == required)
    })
}
const SIDECAR_PROCESS_PROXY_ADDR: &str = "127.0.0.1:3128";
const SIDECAR_READY_TIMEOUT_SECS: u64 = 120;

/// Run a command in the sandbox.
///
/// # Errors
///
/// Returns an error if the command fails to start or encounters a fatal error.
#[allow(
    clippy::too_many_arguments,
    clippy::implicit_hasher,
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
    ocsf_enabled: Arc<AtomicBool>,
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

    // Extension credentials are owned by this supervisor and shared by every
    // gateway connection it opens, so the middleware registry's bearer slots
    // and the policy poll loop that rotates them stay the same objects.
    let extension_credentials = openshell_extension_core::ExtensionCredentialStore::new();

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
        initial_extension_authentication_enabled,
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
            false,
        )
    } else {
        load_policy(
            sandbox_id.clone(),
            sandbox,
            openshell_endpoint.clone(),
            policy_rules,
            policy_data,
            &extension_credentials,
        )
        .await?
    };

    // Normalize the active driver's identity contract once, while both the
    // policy and launched image filesystem are available. Kubernetes and
    // OpenShift retain their authoritative numeric pair; Docker fills only
    // omitted policy fields from OCI Config.User.
    #[cfg(unix)]
    let (resolved_process_identity, workspace) = {
        let driver_identity = openshell_supervisor_process::identity::DriverIdentity::from_env()?;
        let use_workdir_as_home = matches!(
            &driver_identity,
            openshell_supervisor_process::identity::DriverIdentity::OciUser { .. }
        );
        let resolved = openshell_supervisor_process::identity::resolve_process_identity(
            &mut policy,
            &driver_identity,
        )?;
        (
            resolved,
            openshell_supervisor_process::process::ResolvedWorkspace::new(
                workdir.clone(),
                use_workdir_as_home,
            ),
        )
    };
    #[cfg(not(unix))]
    let (resolved_process_identity, workspace) = (
        openshell_supervisor_process::process::ResolvedProcessIdentity::default(),
        openshell_supervisor_process::process::ResolvedWorkspace::new(workdir.clone(), false),
    );

    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let (provider_credentials, mut provider_env) = if let Some(bootstrap) =
        sidecar_bootstrap.as_ref()
    {
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
            static_credential_bindings,
            non_secret_environment_keys,
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
                        result.static_credential_bindings,
                        result.non_secret_environment_keys,
                    )
                }
                Err(e) => {
                    ocsf_emit!(
                        ConfigStateChangeBuilder::new(ocsf_ctx())
                            .severity(SeverityId::High)
                            .status(StatusId::Failure)
                            .state(StateId::Disabled, "fail_closed")
                            .message(format!(
                                "Failed to fetch provider environment; no provider credentials are active: {e}"
                            ))
                            .build()
                    );
                    (
                        0,
                        std::collections::HashMap::new(),
                        std::collections::HashMap::new(),
                        std::collections::HashMap::new(),
                        std::collections::HashMap::new(),
                        Vec::new(),
                    )
                }
            }
        } else {
            (
                0,
                std::collections::HashMap::new(),
                std::collections::HashMap::new(),
                std::collections::HashMap::new(),
                std::collections::HashMap::new(),
                Vec::new(),
            )
        };

        let dynamic_credentials_fallback = dynamic_credentials.clone();
        let provider_credentials = match ProviderCredentialState::from_bound_environment(
            provider_env_revision,
            provider_env,
            provider_credential_expires_at_ms,
            dynamic_credentials,
            static_credential_bindings,
            non_secret_environment_keys,
        ) {
            Ok(credentials) => credentials,
            Err(error) => {
                ocsf_emit!(
                        ConfigStateChangeBuilder::new(ocsf_ctx())
                            .severity(SeverityId::High)
                            .status(StatusId::Failure)
                            .state(StateId::Disabled, "fail_closed")
                            .message(format!(
                                "Rejected provider environment bindings; static provider credentials were revoked; fetched dynamic token grants remain active: {error}"
                            ))
                            .build()
                    );
                ProviderCredentialState::from_environment(
                    provider_env_revision,
                    std::collections::HashMap::new(),
                    std::collections::HashMap::new(),
                    dynamic_credentials_fallback,
                )
            }
        };
        let provider_env = provider_credentials.child_env_with_gcp_resolved();
        (provider_credentials, provider_env)
    };

    if credential_gating_unavailable(
        &loaded_policy_origin,
        provider_credentials.resolver().is_some(),
        network_enabled,
    ) {
        report_credential_gating_unavailable();
    }

    // Canonical-process overrides are deliberately applied only to the main
    // child. Keep the provider snapshot pristine because Kubernetes forwards
    // it to the process sidecar for later exec/editor/SFTP children.

    // Shared agent-proposals feature flag. Seed from the same initial settings
    // snapshot that produced the policy so networking and process setup agree
    // before the poll loop starts reconciling later changes.
    let agent_proposals = AgentProposals::new(initial_agent_proposals_enabled);

    let process_control_writer = process_control_connection
        .as_ref()
        .map(|connection| connection.writer.clone());
    let process_exit_ack = Arc::new(tokio::sync::Mutex::new(None));
    let mut process_control_closed = None;
    if let Some(connection) = process_control_connection {
        process_control_closed = Some(connection.closed);
        spawn_sidecar_control_update_watcher(
            connection.updates,
            provider_credentials.clone(),
            agent_proposals.clone(),
            Arc::clone(&process_exit_ack),
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

    #[cfg(target_os = "linux")]
    let transparent_tcp_requested = opa_engine
        .as_ref()
        .map(|engine| engine.policy_dns_eligibility_snapshot())
        .transpose()?
        .is_some_and(|snapshot| !snapshot.endpoints.is_empty());
    #[cfg(target_os = "linux")]
    let runtime_capabilities =
        std::env::var(openshell_core::sandbox_env::NETWORK_RUNTIME_CAPABILITIES).ok();
    #[cfg(target_os = "linux")]
    let transparent_tcp_capable = has_network_runtime_capability(
        runtime_capabilities.as_deref(),
        openshell_core::sandbox_env::POLICY_DNS_TRANSPARENT_TCP_CAPABILITY,
    );
    #[cfg(not(target_os = "linux"))]
    let transparent_tcp_capable = false;
    #[cfg(target_os = "linux")]
    let transparent_runtime = if transparent_tcp_requested {
        if !transparent_tcp_capable {
            ocsf_emit!(
                ConfigStateChangeBuilder::new(ocsf_ctx())
                    .severity(SeverityId::Medium)
                    .status(StatusId::Failure)
                    .state(StateId::Disabled, "unsupported_runtime")
                    .message(
                        "Policy DNS and transparent TCP unavailable: runtime capability is missing"
                    )
                    .build()
            );
            return Err(miette::miette!(
                "policy contains protocol: tcp endpoints, but the selected runtime does not advertise policy DNS and transparent TCP support"
            ));
        }
        if sidecar_network_enforcement {
            ocsf_emit!(
                ConfigStateChangeBuilder::new(ocsf_ctx())
                    .severity(SeverityId::Medium)
                    .status(StatusId::Failure)
                    .state(StateId::Disabled, "unsupported_topology")
                    .message("Policy DNS and transparent TCP unavailable: sidecar topology is unsupported")
                    .build()
            );
            return Err(miette::miette!(
                "policy DNS and transparent TCP are not yet supported by the sidecar topology"
            ));
        }
        let namespace = netns.as_ref().ok_or_else(|| {
            miette::miette!("policy DNS and transparent TCP require a workload network namespace")
        })?;
        let listeners = namespace
            .bind_transparent_tcp_listeners()
            .await
            .into_diagnostic()
            .wrap_err("failed to bind transparent TCP listeners")?;
        let (dns_udp, dns_tcp) = namespace
            .bind_policy_dns_sockets()
            .await
            .into_diagnostic()
            .wrap_err("failed to bind policy DNS listeners")?;
        let proxy_port = policy
            .network
            .proxy
            .as_ref()
            .and_then(|proxy| proxy.http_addr)
            .map_or(3128, |address| address.port());
        let runtime = openshell_supervisor_network::run::TransparentRuntimeSetup::new(
            listeners,
            dns_udp,
            dns_tcp,
            sandbox_id.as_deref(),
        )?;
        let (ipv4_cidr, ipv6_cidr) = runtime.synthetic_cidrs();
        namespace.install_transparent_tcp_rules(proxy_port, &ipv4_cidr, &ipv6_cidr)?;
        Some(runtime)
    } else {
        None
    };
    #[cfg(target_os = "linux")]
    let transparent_tcp_substrate_ready = transparent_runtime.is_some();
    #[cfg(not(target_os = "linux"))]
    let transparent_tcp_substrate_ready = false;
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
                #[cfg(target_os = "linux")]
                transparent_runtime,
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
            SidecarEntrypointHandler {
                entrypoint_pid: entrypoint_pid.clone(),
                opa_engine: opa_engine.clone(),
                retained_proto: retained_proto.clone(),
                openshell_endpoint: openshell_endpoint.clone(),
                sandbox_id: sandbox_id.clone(),
                trusted_ssh_socket_path: std::path::PathBuf::from(trusted_ssh_socket_path),
                control_publisher: sidecar_control_publisher.clone(),
            },
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
            extension_credentials: extension_credentials.clone(),
            extension_authentication_enabled: initial_extension_authentication_enabled,
            middleware_connector: default_middleware_connector(),
            transparent_tcp: TransparentTcpReloadState {
                capable: transparent_tcp_capable,
                substrate_ready: transparent_tcp_substrate_ready,
            },
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
    let main_env = provider_env.clone();
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
                        Ok((pid, instance_id)) => {
                            if let Err(err) =
                                sidecar_control::send_entrypoint_started(&writer, pid, instance_id)
                                    .await
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
        let sidecar_exit_tx =
            if process_uses_sidecar_control && let Some(writer) = process_control_writer.clone() {
                let exit_ack = Arc::clone(&process_exit_ack);
                let (tx, mut rx) = tokio::sync::mpsc::channel::<
                    openshell_supervisor_process::run::SidecarExitReport,
                >(1);
                tokio::spawn(async move {
                    while let Some((instance_id, exit_code, ack)) = rx.recv().await {
                        let (durable_tx, durable_rx) = tokio::sync::oneshot::channel();
                        *exit_ack.lock().await = Some((instance_id.clone(), durable_tx));
                        let result = match sidecar_control::send_main_process_exited(
                            &writer,
                            instance_id,
                            exit_code,
                        )
                        .await
                        {
                            Ok(()) => durable_rx.await.map_err(|_| {
                                "sidecar durable exit acknowledgement closed".to_string()
                            }),
                            Err(error) => Err(error.to_string()),
                        };
                        let _ = ack.send(result);
                    }
                });
                Some(tx)
            } else {
                None
            };

        let process = openshell_supervisor_process::run::run_process(
            program,
            args,
            workspace,
            timeout_secs,
            interactive,
            sandbox_id.as_deref(),
            openshell_endpoint.as_deref(),
            ssh_socket_path,
            sidecar_network_enforcement,
            &process_policy,
            resolved_process_identity,
            process_enforcement_mode,
            entrypoint_pid,
            entrypoint_started_tx,
            sidecar_exit_tx,
            provider_credentials,
            main_env,
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

type MainProcessExitAckWaiter =
    Arc<tokio::sync::Mutex<Option<(String, tokio::sync::oneshot::Sender<()>)>>>;

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
        LoadedPolicyOrigin::Gateway {
            revision: None,
            has_last_valid_policy: true,
        },
    ))
}

fn spawn_sidecar_control_update_watcher(
    mut updates: tokio::sync::mpsc::UnboundedReceiver<sidecar_control::ControlUpdate>,
    provider_credentials: ProviderCredentialState,
    agent_proposals: AgentProposals,
    exit_ack: MainProcessExitAckWaiter,
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
                sidecar_control::ControlUpdate::MainProcessExitAck { instance_id } => {
                    let mut waiter = exit_ack.lock().await;
                    if waiter
                        .as_ref()
                        .is_some_and(|(expected, _)| expected == &instance_id)
                        && let Some((_, ack)) = waiter.take()
                    {
                        let _ = ack.send(());
                    }
                }
            }
        }
    })
}

#[cfg(target_os = "linux")]
struct SidecarEntrypointHandler {
    entrypoint_pid: Arc<AtomicU32>,
    opa_engine: Option<Arc<OpaEngine>>,
    retained_proto: Option<openshell_core::proto::SandboxPolicy>,
    openshell_endpoint: Option<String>,
    sandbox_id: Option<String>,
    trusted_ssh_socket_path: std::path::PathBuf,
    control_publisher: Option<sidecar_control::Publisher>,
}

#[cfg(target_os = "linux")]
fn spawn_sidecar_entrypoint_handler(
    mut entrypoint_rx: tokio::sync::mpsc::Receiver<sidecar_control::EntrypointStarted>,
    handler: SidecarEntrypointHandler,
) {
    tokio::spawn(async move {
        let SidecarEntrypointHandler {
            entrypoint_pid,
            opa_engine,
            retained_proto,
            openshell_endpoint,
            sandbox_id,
            trusted_ssh_socket_path,
            control_publisher,
        } = handler;
        let mut session_started = false;
        let mut trusted_supervisor_pid = None;
        let terminating = Arc::new(AtomicBool::new(false));
        while let Some(started) = entrypoint_rx.recv().await {
            if let Some(exit_code) = started.exit_code {
                terminating.store(true, Ordering::Release);
                if let (Some(endpoint), Some(id)) =
                    (openshell_endpoint.as_ref(), sandbox_id.as_ref())
                {
                    let mut delay = Duration::from_millis(250);
                    loop {
                        match openshell_supervisor_process::supervisor_session::report_main_process_exit(
                            endpoint,
                            id,
                            &started.instance_id,
                            exit_code,
                        )
                        .await
                        {
                            Ok(()) => break,
                            Err(error) => {
                                warn!(%error, "sidecar main-process exit report failed; retrying");
                                tokio::time::sleep(delay).await;
                                delay = (delay * 2).min(Duration::from_secs(2));
                            }
                        }
                    }
                    if let Some(publisher) = control_publisher.as_ref() {
                        publisher.publish_main_process_exit_ack(started.instance_id.clone());
                    }
                }
                break;
            }
            entrypoint_pid.store(started.pid, Ordering::Release);
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
                    Arc::clone(&terminating),
                    started.instance_id.clone(),
                );
                session_started = true;
                info!("sidecar supervisor session task spawned");
            }
        }
        terminating.store(true, Ordering::Release);
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

/// Minimum read-write paths required for a proxy-mode sandbox child process.
/// The active workspace is granted separately through `include_workdir`.
const PROXY_BASELINE_READ_WRITE: &[&str] = &["/tmp"];

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
    use std::path::PathBuf;

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
    fn baseline_read_write_does_not_hardcode_sandbox() {
        let (_ro, rw) = baseline_enrichment_paths();
        assert!(rw.contains(&"/tmp".to_string()));
        assert!(!rw.contains(&"/sandbox".to_string()));
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
                read_only: vec![PathBuf::from("/tmp")],
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
            policy.filesystem.read_only.contains(&PathBuf::from("/tmp")),
            "explicit read_only baseline path should be preserved"
        );
        assert!(
            !policy
                .filesystem
                .read_write
                .contains(&PathBuf::from("/tmp")),
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
    extension_credentials: &openshell_extension_core::ExtensionCredentialStore,
) -> Result<(
    SandboxPolicy,
    Option<Arc<OpaEngine>>,
    Option<openshell_core::proto::SandboxPolicy>,
    MiddlewareRegistryStatus,
    LoadedPolicyOrigin,
    bool,
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

        let mut loaded_policy_revision =
            policy_bound_to_snapshot.then(|| LoadedPolicyRevision::from_snapshot(&snapshot));

        // Build OPA engine from baked-in rules + typed proto data.
        // In cluster mode, proxy networking is always enabled so OPA is
        // always required for allow/deny decisions.
        // The initial load uses pid=0 (no symlink resolution) because the
        // container hasn't started yet. After the entrypoint spawns, the
        // engine is rebuilt with the real PID for symlink resolution.
        info!("Creating OPA engine from proto policy data");
        let mut has_last_valid_policy = true;
        let engine = match OpaEngine::from_proto(&proto_policy) {
            Ok(engine) => Arc::new(engine),
            Err(e) => {
                report_initial_policy_failure(endpoint, id, loaded_policy_revision.as_ref(), &e)
                    .await;
                let validation_error = e.to_string();
                let candidate_version = snapshot.version;
                let candidate_hash = snapshot.policy_hash.clone();
                // There is no in-memory last-known-good generation during
                // startup, so both configured modes necessarily fail closed.
                // Load the restrictive default atomically and keep the
                // rejected revision unacknowledged for poll reconciliation.
                has_last_valid_policy = false;
                proto_policy = openshell_policy::restrictive_default_policy();
                let engine = Arc::new(OpaEngine::from_proto(&proto_policy)?);
                let disposition = apply_policy_validation_failure(
                    &engine,
                    snapshot.policy_validation_failure_mode,
                    has_last_valid_policy,
                    candidate_version,
                    &validation_error,
                )?;
                emit_policy_validation_failure(
                    &disposition,
                    candidate_version,
                    &candidate_hash,
                    &validation_error,
                );
                loaded_policy_revision = None;
                engine
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
            let middleware_services = middleware_services.clone();
            let extension_credentials = extension_credentials.clone();
            let extension_authentication_enabled = snapshot.extension_authentication_enabled;
            async move {
                let credentials = if extension_authentication_enabled {
                    // Share the supervisor's store so the slots installed here
                    // are the ones the policy poll loop later rotates in place.
                    openshell_core::grpc_client::CachedOpenShellClient::connect_with_credentials(
                        endpoint,
                        extension_credentials,
                    )
                    .await?
                    .refresh_extension_credentials(&middleware_services)
                    .await?
                } else {
                    std::collections::HashMap::new()
                };
                connect_middleware_registry(
                    &middleware_services,
                    &MiddlewareAuthentication {
                        credentials,
                        enabled: extension_authentication_enabled,
                    },
                )
                .await
            }
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
        let opa_engine = Some(engine);

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
                has_last_valid_policy,
            },
            agent_proposals_enabled_from_settings(&snapshot.settings),
            snapshot.extension_authentication_enabled,
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

#[derive(Debug)]
enum GatewayRuntimeReloadError {
    PolicyValidation(miette::Report),
    TransparentTcpPrerequisite(miette::Report),
    MiddlewareRegistry(miette::Report),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GatewayRuntimeFailureClass {
    PolicyValidation,
    TransparentTcpPrerequisite,
    MiddlewareRegistry,
}

impl GatewayRuntimeReloadError {
    fn class(&self) -> GatewayRuntimeFailureClass {
        match self {
            Self::PolicyValidation(_) => GatewayRuntimeFailureClass::PolicyValidation,
            Self::TransparentTcpPrerequisite(_) => {
                GatewayRuntimeFailureClass::TransparentTcpPrerequisite
            }
            Self::MiddlewareRegistry(_) => GatewayRuntimeFailureClass::MiddlewareRegistry,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct FailedRuntimeRevision {
    config_revision: u64,
    policy_hash: String,
    failure_class: GatewayRuntimeFailureClass,
}

impl FailedRuntimeRevision {
    fn new(config_revision: u64, policy_hash: &str, failure: &GatewayRuntimeReloadError) -> Self {
        Self {
            config_revision,
            policy_hash: policy_hash.to_string(),
            failure_class: failure.class(),
        }
    }
}

struct MiddlewareReloadContext<'a> {
    desired_services: &'a [openshell_core::proto::SupervisorMiddlewareService],
    authentication: &'a MiddlewareAuthentication,
    registry_changed: bool,
    connector: &'a MiddlewareConnector,
}

async fn reload_gateway_policy_runtime(
    engine: &OpaEngine,
    policy: Option<&openshell_core::proto::SandboxPolicy>,
    entrypoint_pid: u32,
    middleware: MiddlewareReloadContext<'_>,
    transparent_tcp: TransparentTcpReloadState,
) -> std::result::Result<(), GatewayRuntimeReloadError> {
    if let Some(policy) = policy
        && policy_contains_explicit_tcp(policy)
    {
        if !transparent_tcp.capable {
            return Err(GatewayRuntimeReloadError::TransparentTcpPrerequisite(
                miette::miette!(
                    "candidate policy introduces protocol: tcp, but the runtime does not advertise transparent TCP support; previous policy remains active"
                ),
            ));
        }
        if !transparent_tcp.substrate_ready {
            return Err(GatewayRuntimeReloadError::TransparentTcpPrerequisite(
                miette::miette!(
                    "candidate policy introduces protocol: tcp, but this sandbox started without the transparent TCP substrate; recreate the sandbox to enable TCP; previous policy remains active"
                ),
            ));
        }
    }
    match policy {
        Some(policy) if middleware.registry_changed => {
            let registry = (middleware.connector)(
                middleware.desired_services.to_vec(),
                middleware.authentication.clone(),
            )
            .await
            .map_err(GatewayRuntimeReloadError::MiddlewareRegistry)?;
            engine
                .reload_policy_and_middleware_from_proto_with_pid(policy, entrypoint_pid, registry)
                .map_err(GatewayRuntimeReloadError::PolicyValidation)
        }
        // Policy-only change: the installed registry already matches the
        // delivered service set, so swap the engine alone. This must not
        // require middleware reachability.
        Some(policy) => engine
            .reload_from_proto_with_pid(policy, entrypoint_pid)
            .map_err(GatewayRuntimeReloadError::PolicyValidation),
        None => Err(GatewayRuntimeReloadError::PolicyValidation(
            miette::miette!("runtime reload requires a policy payload but none was returned"),
        )),
    }
}

fn policy_contains_explicit_tcp(policy: &openshell_core::proto::SandboxPolicy) -> bool {
    policy.network_policies.values().any(|rule| {
        rule.endpoints
            .iter()
            .any(|endpoint| endpoint.protocol.eq_ignore_ascii_case("tcp"))
    })
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct TransparentTcpReloadState {
    capable: bool,
    substrate_ready: bool,
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
        has_last_valid_policy: bool,
    },
}

impl LoadedPolicyOrigin {
    fn allows_gateway_policy_reload(&self) -> bool {
        matches!(self, Self::Gateway { .. })
    }

    fn has_last_valid_policy(&self) -> bool {
        match self {
            Self::LocalOverride => true,
            Self::Gateway {
                has_last_valid_policy,
                ..
            } => *has_last_valid_policy,
        }
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
    success_event: Option<PolicyStatusSuccessEvent>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PolicyStatusSuccessEvent {
    InitialAcknowledgement { policy_hash: String },
    UnchangedAcknowledgement { policy_hash: String },
}

impl PolicyStatusUpdate {
    fn initial_loaded(ack: &InitialPolicyAck) -> Self {
        Self {
            version: ack.version,
            loaded: true,
            error: String::new(),
            success_event: Some(PolicyStatusSuccessEvent::InitialAcknowledgement {
                policy_hash: ack.policy_hash.clone(),
            }),
        }
    }

    fn loaded(version: u32) -> Self {
        Self {
            version,
            loaded: true,
            error: String::new(),
            success_event: None,
        }
    }

    fn unchanged_loaded(version: u32, policy_hash: String) -> Self {
        Self {
            version,
            loaded: true,
            error: String::new(),
            success_event: Some(PolicyStatusSuccessEvent::UnchangedAcknowledgement { policy_hash }),
        }
    }

    fn failed(version: u32, error: String) -> Self {
        Self {
            version,
            loaded: false,
            error,
            success_event: None,
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
        LoadedPolicyOrigin::Gateway { revision, .. } => {
            initial_policy_ack_candidate(revision.as_ref(), canonical).map_or(
                InitialPollDisposition::Reconcile,
                InitialPollDisposition::Acknowledge,
            )
        }
    }
}

fn unchanged_policy_revision_candidate(
    reloads_gateway_policy: bool,
    recovering_rejected_policy: bool,
    current_policy_version: u32,
    current_policy_hash: &str,
    result: &openshell_core::grpc_client::SettingsPollResult,
) -> Option<u32> {
    (reloads_gateway_policy
        && !recovering_rejected_policy
        && !current_policy_hash.is_empty()
        && result.policy_source == openshell_core::proto::PolicySource::Sandbox
        && result.version > current_policy_version
        && result.policy_hash == current_policy_hash)
        .then_some(result.version)
}

fn unchanged_policy_revision_ready_to_ack(
    candidate: Option<u32>,
    policy_runtime_changed: bool,
    policy_runtime_reconciled: bool,
) -> Option<u32> {
    candidate.filter(|_| !policy_runtime_changed || policy_runtime_reconciled)
}

/// Whether the credential-provenance gates cannot apply to the loaded policy.
///
/// The gateway derives `provider_credentialed` and deliberately keeps it out of
/// the policy YAML schema, so a local-file policy never carries it and never
/// will: gateway revisions are observed for settings and providers but must not
/// replace the local OPA policy. Provider credentials still arrive from the
/// gateway on that path, so the raw-tunnel and WebSocket binary-frame refusals
/// have nothing to match on. The request-body backstop is unaffected because it
/// keys off the secret resolver rather than endpoint provenance.
fn credential_gating_unavailable(
    origin: &LoadedPolicyOrigin,
    has_resolver: bool,
    network_enabled: bool,
) -> bool {
    network_enabled && has_resolver && matches!(origin, LoadedPolicyOrigin::LocalOverride)
}

/// Report that credential provenance is unavailable for the loaded policy.
///
/// Carries no credential name, host, or value: the finding states which
/// controls are inactive, nothing about what they would have protected.
fn report_credential_gating_unavailable() {
    ocsf_emit!(
        DetectionFindingBuilder::new(ocsf_ctx())
            .activity(ActivityId::Open)
            .severity(SeverityId::High)
            .confidence(ConfidenceId::High)
            .is_alert(true)
            .finding_info(
                FindingInfo::new(
                    "credential-gating-unavailable",
                    "Credential Provenance Unavailable",
                )
                .with_desc(
                    "Provider credentials are injected, but the loaded policy comes from local \
                     files and carries no gateway-derived credential provenance. Uninspected \
                     credentialed tunnels and WebSocket binary frames are not refused. Load \
                     policy from the gateway to enable these controls."
                ),
            )
            .evidence_pairs(&[
                ("policy_source", "local-override"),
                ("uninspected_connect_gate", "inactive"),
                ("websocket_binary_gate", "inactive"),
                ("request_body_backstop", "active"),
            ])
            .remediation(
                "Remove the local policy override so the gateway-delivered effective policy \
                 applies, or detach provider credentials from this sandbox."
            )
            .message(
                "Credential provenance unavailable for local-file policy; uninspected credential gates inactive"
            )
            .build()
    );
}

/// Deliver policy status updates independently from policy reconciliation.
///
/// The channel is FIFO, so a delayed older status can never arrive after a
/// newer status and move the gateway's active version backward. Delivery uses
/// the existing bounded retry, but failures never delay policy enforcement.
#[tonic::async_trait]
trait PolicyGatewayClient: Clone + Send + Sync + 'static {
    async fn poll_settings(
        &self,
        sandbox_id: &str,
    ) -> Result<openshell_core::grpc_client::SettingsPollResult>;

    async fn report_policy_status(
        &self,
        sandbox_id: &str,
        version: u32,
        loaded: bool,
        error: &str,
    ) -> Result<()>;

    async fn refresh_installed_extension_credentials(&self) -> Result<()> {
        Ok(())
    }

    async fn extension_credentials_for(
        &self,
        _services: &[openshell_core::proto::SupervisorMiddlewareService],
    ) -> Result<std::collections::HashMap<String, openshell_extension_core::BearerTokenSlot>> {
        Ok(std::collections::HashMap::new())
    }

    fn workspace(&self) -> String;
}

#[tonic::async_trait]
impl PolicyGatewayClient for openshell_core::grpc_client::CachedOpenShellClient {
    async fn poll_settings(
        &self,
        sandbox_id: &str,
    ) -> Result<openshell_core::grpc_client::SettingsPollResult> {
        self.poll_settings(sandbox_id).await
    }

    async fn report_policy_status(
        &self,
        sandbox_id: &str,
        version: u32,
        loaded: bool,
        error: &str,
    ) -> Result<()> {
        self.report_policy_status(sandbox_id, version, loaded, error)
            .await
    }

    async fn refresh_installed_extension_credentials(&self) -> Result<()> {
        self.refresh_installed_extension_credentials().await
    }

    async fn extension_credentials_for(
        &self,
        services: &[openshell_core::proto::SupervisorMiddlewareService],
    ) -> Result<std::collections::HashMap<String, openshell_extension_core::BearerTokenSlot>> {
        self.extension_credentials_for(services).await
    }

    fn workspace(&self) -> String {
        self.workspace()
    }
}

async fn run_policy_status_reporter<C: PolicyGatewayClient>(
    client: C,
    sandbox_id: String,
    mut updates: tokio::sync::mpsc::UnboundedReceiver<PolicyStatusUpdate>,
) {
    'updates: while let Some(update) = updates.recv().await {
        let operation = if matches!(
            update.success_event,
            Some(PolicyStatusSuccessEvent::InitialAcknowledgement { .. })
        ) {
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

        if let Some(event) = update.success_event {
            let (policy_hash, message) = match event {
                PolicyStatusSuccessEvent::InitialAcknowledgement { policy_hash } => (
                    policy_hash,
                    format!(
                        "Acknowledged initial policy revision as loaded [version:{}]",
                        update.version
                    ),
                ),
                PolicyStatusSuccessEvent::UnchangedAcknowledgement { policy_hash } => (
                    policy_hash,
                    format!(
                        "Acknowledged unchanged policy revision as loaded [version:{}]",
                        update.version
                    ),
                ),
            };
            ocsf_emit!(
                ConfigStateChangeBuilder::new(ocsf_ctx())
                    .severity(SeverityId::Informational)
                    .status(StatusId::Success)
                    .state(StateId::Enabled, "loaded")
                    .unmapped("version", serde_json::json!(update.version))
                    .unmapped("policy_hash", serde_json::json!(policy_hash))
                    .message(message)
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
    ocsf_enabled: Arc<AtomicBool>,
    provider_credentials: ProviderCredentialState,
    policy_local_ctx: Option<Arc<openshell_supervisor_network::policy_local::PolicyLocalContext>>,
    agent_proposals: AgentProposals,
    middleware_registry_status: MiddlewareRegistryStatus,
    sidecar_control_publisher: Option<sidecar_control::Publisher>,
    workspace_tx: tokio::sync::watch::Sender<String>,
    extension_credentials: openshell_extension_core::ExtensionCredentialStore,
    extension_authentication_enabled: bool,
    middleware_connector: MiddlewareConnector,
    /// Immutable driver capability and startup substrate state.
    transparent_tcp: TransparentTcpReloadState,
}

type MiddlewareConnector = Arc<
    dyn Fn(
            Vec<openshell_core::proto::SupervisorMiddlewareService>,
            MiddlewareAuthentication,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<openshell_supervisor_middleware::MiddlewareRegistry>,
                    > + Send,
            >,
        > + Send
        + Sync,
>;

#[derive(Clone, Default)]
struct MiddlewareAuthentication {
    credentials: std::collections::HashMap<String, openshell_extension_core::BearerTokenSlot>,
    enabled: bool,
}

fn default_middleware_connector() -> MiddlewareConnector {
    Arc::new(|services, authentication| {
        Box::pin(async move { connect_middleware_registry(&services, &authentication).await })
    })
}

async fn connect_middleware_registry(
    services: &[openshell_core::proto::SupervisorMiddlewareService],
    authentication: &MiddlewareAuthentication,
) -> Result<openshell_supervisor_middleware::MiddlewareRegistry> {
    if authentication.enabled {
        openshell_supervisor_middleware::MiddlewareRegistry::connect_services_authenticated(
            openshell_supervisor_middleware_builtins::services(),
            services.to_vec(),
            &authentication.credentials,
        )
        .await
    } else {
        openshell_supervisor_middleware::MiddlewareRegistry::connect_services(
            openshell_supervisor_middleware_builtins::services(),
            services.to_vec(),
        )
        .await
    }
}

async fn install_builtin_middleware_registry(opa_engine: &OpaEngine) -> Result<()> {
    let registry = openshell_supervisor_middleware::MiddlewareRegistry::connect_services(
        openshell_supervisor_middleware_builtins::services(),
        Vec::new(),
    )
    .await?;
    opa_engine.replace_middleware_registry(registry)
}

/// Wait the configured poll interval, but never past the point at which an
/// installed extension credential must be rotated.
fn next_poll_delay(
    store: &openshell_extension_core::ExtensionCredentialStore,
    interval: Duration,
) -> Duration {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        });
    store.next_refresh_delay(interval, now_ms)
}

/// Drop credentials for services no longer in the installed registry.
///
/// Call only after a registry swap succeeds, so a failed candidate cannot
/// invalidate the last-known-good clients.
fn retain_extension_credentials(
    store: &openshell_extension_core::ExtensionCredentialStore,
    installed: &[openshell_core::proto::SupervisorMiddlewareService],
    extension_authentication_enabled: bool,
) {
    let retained = if extension_authentication_enabled {
        installed
            .iter()
            .map(|service| service.name.as_str())
            .collect()
    } else {
        std::collections::HashSet::default()
    };
    store.retain(&retained);
}

struct MiddlewareRegistryReconciliation<'a> {
    desired_services: &'a [openshell_core::proto::SupervisorMiddlewareService],
    authentication: MiddlewareAuthentication,
    registry_changed: bool,
    extension_credentials: &'a openshell_extension_core::ExtensionCredentialStore,
    current_services: &'a mut Vec<openshell_core::proto::SupervisorMiddlewareService>,
    status: &'a mut MiddlewareRegistryStatus,
}

async fn reconcile_middleware_registry(
    opa_engine: &OpaEngine,
    middleware_connector: &MiddlewareConnector,
    reconciliation: MiddlewareRegistryReconciliation<'_>,
) {
    if !reconciliation.registry_changed {
        return;
    }

    match middleware_connector(
        reconciliation.desired_services.to_vec(),
        reconciliation.authentication.clone(),
    )
    .await
    .and_then(|registry| opa_engine.replace_middleware_registry(registry))
    {
        Ok(()) => {
            retain_extension_credentials(
                reconciliation.extension_credentials,
                reconciliation.desired_services,
                reconciliation.authentication.enabled,
            );
            reconciliation.current_services.clear();
            reconciliation
                .current_services
                .extend_from_slice(reconciliation.desired_services);
            *reconciliation.status = MiddlewareRegistryStatus::Synchronized;
            ocsf_emit!(
                ConfigStateChangeBuilder::new(ocsf_ctx())
                    .severity(SeverityId::Informational)
                    .status(StatusId::Success)
                    .state(StateId::Enabled, "loaded")
                    .unmapped(
                        "supervisor_middleware_service_count",
                        serde_json::json!(reconciliation.current_services.len())
                    )
                    .message(format!(
                        "Supervisor middleware registry reloaded [service_count:{}]",
                        reconciliation.current_services.len()
                    ))
                    .build()
            );
        }
        Err(error) => {
            // Emit only on the transition into the failed state to avoid
            // repeating the same finding on every poll during an outage.
            if *reconciliation.status == MiddlewareRegistryStatus::Synchronized {
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
            *reconciliation.status = MiddlewareRegistryStatus::NeedsReconciliation;
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct PolicyValidationFailureDisposition {
    configured_mode: PolicyValidationFailureMode,
    mode: PolicyValidationFailureMode,
    previous_policy_active: bool,
    active_generation: u64,
}

struct RejectedPolicyGeneration {
    version: u32,
    policy_hash: String,
    validation_error: String,
    configured_mode: PolicyValidationFailureMode,
}

enum GatewayRuntimeFailureDisposition {
    PolicyRejected {
        error: String,
        disposition: PolicyValidationFailureDisposition,
    },
    MiddlewareUnavailable {
        error: String,
    },
    TransparentTcpExpansionRejected {
        error: String,
        active_generation: u64,
    },
}

fn apply_gateway_runtime_reload_failure(
    engine: &OpaEngine,
    failure: GatewayRuntimeReloadError,
    configured_mode: PolicyValidationFailureMode,
    has_last_valid_policy: bool,
    version: u32,
) -> Result<GatewayRuntimeFailureDisposition> {
    match failure {
        GatewayRuntimeReloadError::PolicyValidation(error) => {
            let error = error.to_string();
            let disposition = apply_policy_validation_failure(
                engine,
                configured_mode,
                has_last_valid_policy,
                version,
                &error,
            )?;
            Ok(GatewayRuntimeFailureDisposition::PolicyRejected { error, disposition })
        }
        GatewayRuntimeReloadError::TransparentTcpPrerequisite(error) => Ok(
            GatewayRuntimeFailureDisposition::TransparentTcpExpansionRejected {
                error: error.to_string(),
                active_generation: engine.current_generation(),
            },
        ),
        GatewayRuntimeReloadError::MiddlewareRegistry(error) => {
            Ok(GatewayRuntimeFailureDisposition::MiddlewareUnavailable {
                error: error.to_string(),
            })
        }
    }
}

fn emit_transparent_tcp_expansion_rejection(
    version: u32,
    policy_hash: &str,
    active_generation: u64,
    error: &str,
) {
    let message = format!(
        "Transparent TCP policy expansion rejected; previous policy IS active [version:{version} active_generation:{active_generation} error:{error}]"
    );
    ocsf_emit!(
        ConfigStateChangeBuilder::new(ocsf_ctx())
            .severity(SeverityId::High)
            .status(StatusId::Failure)
            .state(StateId::Enabled, "retained_previous_policy")
            .unmapped("candidate_version", serde_json::json!(version))
            .unmapped("candidate_policy_hash", serde_json::json!(policy_hash))
            .unmapped("previous_policy_active", serde_json::json!(true))
            .unmapped("active_generation", serde_json::json!(active_generation))
            .unmapped("validation_error", serde_json::json!(error))
            .message(message)
            .build()
    );
}

fn apply_policy_validation_failure(
    engine: &OpaEngine,
    configured_mode: PolicyValidationFailureMode,
    has_last_valid_policy: bool,
    version: u32,
    error: &str,
) -> Result<PolicyValidationFailureDisposition> {
    let mode = if has_last_valid_policy {
        configured_mode
    } else {
        PolicyValidationFailureMode::FailClosed
    };
    match mode {
        PolicyValidationFailureMode::FailClosed => {
            let reason = format!(
                "policy validation failed; fail-closed quarantine is active; candidate version {version} rejected: {error}"
            );
            let active_generation = engine.enter_fail_closed(reason)?;
            Ok(PolicyValidationFailureDisposition {
                configured_mode,
                mode,
                previous_policy_active: false,
                active_generation,
            })
        }
        PolicyValidationFailureMode::RetainLastValid => {
            let active_generation = engine.exit_fail_closed()?;
            Ok(PolicyValidationFailureDisposition {
                configured_mode,
                mode,
                previous_policy_active: true,
                active_generation,
            })
        }
    }
}

fn policy_validation_failure_events(
    disposition: &PolicyValidationFailureDisposition,
    version: u32,
    policy_hash: &str,
    error: &str,
) -> [OcsfEvent; 2] {
    let previous_policy_state = if disposition.previous_policy_active {
        "IS active"
    } else {
        "IS NOT active"
    };
    let state = if disposition.previous_policy_active {
        (StateId::Enabled, "retained_last_valid")
    } else {
        (StateId::Disabled, "fail_closed")
    };
    let message = format!(
        "Policy validation failed; configured_mode={} effective_mode={}; previous policy {previous_policy_state} [version:{version} active_generation:{} error:{error}]",
        disposition.configured_mode.as_str(),
        disposition.mode.as_str(),
        disposition.active_generation,
    );
    let finding_uid = format!("policy-validation-failed-{version}");
    let version_string = version.to_string();
    let config = ConfigStateChangeBuilder::new(ocsf_ctx())
        .severity(SeverityId::High)
        .status(StatusId::Failure)
        .state(state.0, state.1)
        .unmapped("candidate_version", serde_json::json!(version))
        .unmapped("candidate_policy_hash", serde_json::json!(policy_hash))
        .unmapped(
            "validation_failure_mode",
            serde_json::json!(disposition.mode.as_str()),
        )
        .unmapped(
            "configured_validation_failure_mode",
            serde_json::json!(disposition.configured_mode.as_str()),
        )
        .unmapped(
            "previous_policy_active",
            serde_json::json!(disposition.previous_policy_active),
        )
        .unmapped(
            "active_generation",
            serde_json::json!(disposition.active_generation),
        )
        .unmapped("validation_error", serde_json::json!(error))
        .message(message.clone())
        .build();
    let finding = DetectionFindingBuilder::new(ocsf_ctx())
        .activity(ActivityId::Open)
        .action(ActionId::Denied)
        .disposition(DispositionId::Blocked)
        .severity(SeverityId::High)
        .is_alert(true)
        .finding_info(
            FindingInfo::new(&finding_uid, "Invalid policy generation rejected").with_desc(error),
        )
        .evidence_pairs(&[
            ("candidate_version", &version_string),
            ("candidate_policy_hash", policy_hash),
            ("validation_failure_mode", disposition.mode.as_str()),
            (
                "configured_validation_failure_mode",
                disposition.configured_mode.as_str(),
            ),
            (
                "previous_policy_active",
                if disposition.previous_policy_active {
                    "true"
                } else {
                    "false"
                },
            ),
        ])
        .remediation("Submit a valid, unambiguous policy generation")
        .message(message)
        .build();
    [config, finding]
}

fn emit_policy_validation_failure(
    disposition: &PolicyValidationFailureDisposition,
    version: u32,
    policy_hash: &str,
    error: &str,
) {
    for event in policy_validation_failure_events(disposition, version, policy_hash, error) {
        ocsf_emit!(event);
    }
}

async fn run_policy_poll_loop(ctx: PolicyPollLoopContext) -> Result<()> {
    let client = openshell_core::grpc_client::CachedOpenShellClient::connect_with_credentials(
        &ctx.endpoint,
        ctx.extension_credentials.clone(),
    )
    .await?;
    run_policy_poll_loop_with_client(ctx, client).await
}

async fn run_policy_poll_loop_with_client<C: PolicyGatewayClient>(
    ctx: PolicyPollLoopContext,
    client: C,
) -> Result<()> {
    use openshell_core::proto::PolicySource;
    use std::sync::atomic::Ordering;

    let (status_sender, status_receiver) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(run_policy_status_reporter(
        client.clone(),
        ctx.sandbox_id.clone(),
        status_receiver,
    ));

    let mut current_config_revision: u64 = 0;
    let mut current_provider_env_revision: u64 = ctx.provider_credentials.snapshot().revision;
    let mut current_policy_version: u32 = 0;
    let mut current_policy_hash = String::new();
    let mut current_middleware_services = Vec::new();
    let mut current_extension_authentication_enabled = ctx.extension_authentication_enabled;
    let mut middleware_registry_status = ctx.middleware_registry_status;
    let mut current_settings: std::collections::HashMap<
        String,
        openshell_core::proto::EffectiveSetting,
    > = std::collections::HashMap::new();
    let reloads_gateway_policy = ctx.loaded_policy_origin.allows_gateway_policy_reload();
    let mut last_failed_runtime_revision: Option<FailedRuntimeRevision> = None;
    let mut rejected_policy_generation: Option<RejectedPolicyGeneration> = None;
    let mut has_last_valid_policy = ctx.loaded_policy_origin.has_last_valid_policy();

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
                    current_policy_version = candidate.version;
                    current_policy_hash.clone_from(&candidate.policy_hash);
                    current_middleware_services = result.supervisor_middleware_services;
                    current_extension_authentication_enabled =
                        result.extension_authentication_enabled;
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
                    current_extension_authentication_enabled =
                        result.extension_authentication_enabled;
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
            tokio::time::sleep(next_poll_delay(&ctx.extension_credentials, interval)).await;
            match client.poll_settings(&ctx.sandbox_id).await {
                Ok(result) => {
                    let _ = ctx.workspace_tx.send(client.workspace());
                    result
                }
                Err(e) => {
                    debug!(error = %e, "Settings poll: server unreachable, will retry");
                    if current_extension_authentication_enabled
                        && let Err(refresh_error) =
                            client.refresh_installed_extension_credentials().await
                    {
                        warn!(
                            error = %refresh_error,
                            "Settings poll: extension credential refresh failed while configuration was unavailable"
                        );
                    }
                    continue;
                }
            }
        };

        // Reuse installed per-service credentials, rotating only when one is
        // missing or due. Rotation happens on the existing gateway channel and
        // updates slots in place, so it is independent of config revision and
        // registry equality.
        let middleware_credentials = if result.extension_authentication_enabled {
            match client
                .extension_credentials_for(&result.supervisor_middleware_services)
                .await
            {
                Ok(credentials) => credentials,
                Err(error) => {
                    warn!(error = %error, "Settings poll: extension credential refresh failed");
                    std::collections::HashMap::new()
                }
            }
        } else {
            std::collections::HashMap::new()
        };

        let config_changed = result.config_revision != current_config_revision;
        let provider_env_changed = result.provider_env_revision != current_provider_env_revision;
        let policy_changed = result.policy_hash != current_policy_hash;
        let extension_authentication_changed =
            current_extension_authentication_enabled != result.extension_authentication_enabled;
        let middleware_registry_changed = extension_authentication_changed
            || middleware_registry_needs_rebuild(
                middleware_registry_status,
                &current_middleware_services,
                &result.supervisor_middleware_services,
            );
        // A valid candidate may intentionally restore byte-for-byte policy
        // content that was active before a rejected update. Its hash then
        // equals `current_policy_hash`, but the runtime is still quarantined
        // and must reload (or it would remain deny-all indefinitely).
        let recovering_rejected_policy = reloads_gateway_policy
            && rejected_policy_generation
                .as_ref()
                .is_some_and(|rejected| rejected.policy_hash != result.policy_hash);
        let policy_runtime_changed = recovering_rejected_policy
            || extension_authentication_changed
            || gateway_policy_runtime_needs_reconciliation(
                reloads_gateway_policy,
                &current_policy_hash,
                &result.policy_hash,
                &current_middleware_services,
                &result.supervisor_middleware_services,
                middleware_registry_status,
            );
        // Recovery already has its own acknowledgement path below. Giving it
        // precedence here prevents a restored last-known-good policy from
        // also being acknowledged as an ordinary same-hash revision.
        let unchanged_policy_revision = unchanged_policy_revision_candidate(
            reloads_gateway_policy,
            recovering_rejected_policy,
            current_policy_version,
            &current_policy_hash,
            &result,
        );
        let mut policy_runtime_reconciled = false;

        // A local policy override is not coupled to the gateway policy
        // snapshot, so its service registry can still be reconciled alone.
        // Gateway policy snapshots, however, must install policy and registry
        // as one generation below.
        if !reloads_gateway_policy {
            reconcile_middleware_registry(
                &ctx.opa_engine,
                &ctx.middleware_connector,
                MiddlewareRegistryReconciliation {
                    desired_services: &result.supervisor_middleware_services,
                    authentication: MiddlewareAuthentication {
                        credentials: middleware_credentials.clone(),
                        enabled: result.extension_authentication_enabled,
                    },
                    registry_changed: middleware_registry_changed,
                    extension_credentials: &ctx.extension_credentials,
                    current_services: &mut current_middleware_services,
                    status: &mut middleware_registry_status,
                },
            )
            .await;
            if middleware_registry_status == MiddlewareRegistryStatus::Synchronized {
                current_extension_authentication_enabled = result.extension_authentication_enabled;
            }
        }

        if !config_changed
            && !provider_env_changed
            && !policy_runtime_changed
            && unchanged_policy_revision.is_none()
        {
            continue;
        }

        if config_changed || provider_env_changed {
            // Log which settings changed.
            log_setting_changes(&current_settings, &result.settings);

            // A posture change after a rejected update takes effect immediately.
            // The compiled last-known-good engine remains available beneath a
            // fail-closed quarantine, so an explicit retain_last_valid selection
            // can reactivate it without accepting any part of the invalid policy.
            if !policy_changed && let Some(rejected) = rejected_policy_generation.as_mut() {
                let mode = result.policy_validation_failure_mode;
                if mode != rejected.configured_mode {
                    let disposition = apply_policy_validation_failure(
                        &ctx.opa_engine,
                        mode,
                        has_last_valid_policy,
                        rejected.version,
                        &rejected.validation_error,
                    )?;
                    emit_policy_validation_failure(
                        &disposition,
                        rejected.version,
                        &rejected.policy_hash,
                        &rejected.validation_error,
                    );
                    rejected.configured_mode = mode;
                }
            }

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
                    let provider_env_revision = env_result.provider_env_revision;
                    let install_result = ctx.provider_credentials.install_bound_environment(
                        provider_env_revision,
                        env_result.environment,
                        env_result.credential_expires_at_ms,
                        env_result.dynamic_credentials,
                        env_result.static_credential_bindings,
                        env_result.non_secret_environment_keys,
                    );
                    if let Err(error) = install_result {
                        ocsf_emit!(
                            ConfigStateChangeBuilder::new(ocsf_ctx())
                                .severity(SeverityId::High)
                                .status(StatusId::Failure)
                                .state(StateId::Disabled, "fail_closed")
                                .message(format!(
                                    "Rejected provider environment refresh; static provider credentials were revoked; fetched dynamic token grants remain active: {error}"
                                ))
                                .build()
                        );
                    } else {
                        let child_env = ctx.provider_credentials.child_env_with_gcp_resolved();
                        let env_count = child_env.len();
                        if let Some(publisher) = ctx.sidecar_control_publisher.as_ref() {
                            publisher
                                .publish_provider_env(provider_env_revision, child_env.clone());
                        }
                        current_provider_env_revision = provider_env_revision;
                        ocsf_emit!(
                            ConfigStateChangeBuilder::new(ocsf_ctx())
                                .severity(SeverityId::Informational)
                                .status(StatusId::Success)
                                .state(StateId::Enabled, "loaded")
                                .unmapped(
                                    "provider_env_revision",
                                    serde_json::json!(provider_env_revision)
                                )
                                .message(format!(
                                    "Provider environment refreshed [revision:{provider_env_revision} env_count:{env_count}]"
                                ))
                                .build()
                        );
                    }
                }
                Err(e) => {
                    ctx.provider_credentials
                        .revoke_static_provider_environment(result.provider_env_revision);
                    warn!(
                        error = %e,
                        provider_env_revision = result.provider_env_revision,
                        "Settings poll: failed to refresh provider environment; static provider credentials were revoked; previous dynamic token grants remain active"
                    );
                    ocsf_emit!(
                        ConfigStateChangeBuilder::new(ocsf_ctx())
                            .severity(SeverityId::High)
                            .status(StatusId::Failure)
                            .state(StateId::Disabled, "fail_closed")
                            .message(
                                "Provider environment refresh failed; static provider credentials were revoked; previous dynamic token grants remain active"
                            )
                            .build()
                    );
                }
            }
        }

        if policy_runtime_changed {
            let pid = ctx.entrypoint_pid.load(Ordering::Acquire);
            let runtime_result = reload_gateway_policy_runtime(
                &ctx.opa_engine,
                result.policy.as_ref(),
                pid,
                MiddlewareReloadContext {
                    desired_services: &result.supervisor_middleware_services,
                    authentication: &MiddlewareAuthentication {
                        credentials: middleware_credentials.clone(),
                        enabled: result.extension_authentication_enabled,
                    },
                    registry_changed: middleware_registry_changed,
                    connector: &ctx.middleware_connector,
                },
                ctx.transparent_tcp,
            )
            .await;

            match runtime_result {
                Ok(()) => {
                    policy_runtime_reconciled = true;
                    let policy = result
                        .policy
                        .as_ref()
                        .expect("successful runtime reload requires a policy payload");
                    has_last_valid_policy = true;
                    rejected_policy_generation = None;
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
                            current_policy_version = result.version;
                        }
                    } else if recovering_rejected_policy
                        && result.version > 0
                        && result.policy_source == PolicySource::Sandbox
                    {
                        ocsf_emit!(
                            ConfigStateChangeBuilder::new(ocsf_ctx())
                                .severity(SeverityId::Informational)
                                .status(StatusId::Success)
                                .state(StateId::Enabled, "loaded")
                                .unmapped("policy_hash", serde_json::json!(&result.policy_hash))
                                .message(format!(
                                    "Policy reloaded successfully and fail-closed quarantine cleared [policy_hash:{}]",
                                    result.policy_hash
                                ))
                                .build()
                        );
                        enqueue_policy_status(
                            &status_sender,
                            PolicyStatusUpdate::loaded(result.version),
                        );
                        current_policy_version = result.version;
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
                    current_extension_authentication_enabled =
                        result.extension_authentication_enabled;
                    retain_extension_credentials(
                        &ctx.extension_credentials,
                        &result.supervisor_middleware_services,
                        result.extension_authentication_enabled,
                    );
                    middleware_registry_status = MiddlewareRegistryStatus::Synchronized;
                    last_failed_runtime_revision = None;
                }
                Err(failure) => {
                    let failed_revision = FailedRuntimeRevision::new(
                        result.config_revision,
                        &result.policy_hash,
                        &failure,
                    );
                    if last_failed_runtime_revision.as_ref() != Some(&failed_revision) {
                        let failure_mode = result.policy_validation_failure_mode;
                        match apply_gateway_runtime_reload_failure(
                            &ctx.opa_engine,
                            failure,
                            failure_mode,
                            has_last_valid_policy,
                            result.version,
                        )? {
                            GatewayRuntimeFailureDisposition::PolicyRejected {
                                error,
                                disposition,
                            } => {
                                emit_policy_validation_failure(
                                    &disposition,
                                    result.version,
                                    &result.policy_hash,
                                    &error,
                                );
                                rejected_policy_generation = Some(RejectedPolicyGeneration {
                                    version: result.version,
                                    policy_hash: result.policy_hash.clone(),
                                    validation_error: error.clone(),
                                    configured_mode: failure_mode,
                                });
                                if policy_changed
                                    && result.version > 0
                                    && result.policy_source == PolicySource::Sandbox
                                {
                                    enqueue_policy_status(
                                        &status_sender,
                                        PolicyStatusUpdate::failed(result.version, error),
                                    );
                                }
                            }
                            GatewayRuntimeFailureDisposition::MiddlewareUnavailable { error } => {
                                ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
                                    .severity(SeverityId::Medium)
                                    .status(StatusId::Failure)
                                    .state(StateId::Other, "failed")
                                    .unmapped("version", serde_json::json!(result.version))
                                    .unmapped("error", serde_json::json!(&error))
                                    .unmapped("previous_policy_active", serde_json::json!(true))
                                    .message(format!(
                                        "Supervisor middleware registry unavailable, keeping last-known-good policy runtime active [version:{} error:{error}]",
                                        result.version
                                    ))
                                    .build());
                            }
                            GatewayRuntimeFailureDisposition::TransparentTcpExpansionRejected {
                                error,
                                active_generation,
                            } => {
                                emit_transparent_tcp_expansion_rejection(
                                    result.version,
                                    &result.policy_hash,
                                    active_generation,
                                    &error,
                                );
                                if policy_changed
                                    && result.version > 0
                                    && result.policy_source == PolicySource::Sandbox
                                {
                                    enqueue_policy_status(
                                        &status_sender,
                                        PolicyStatusUpdate::failed(result.version, error),
                                    );
                                }
                            }
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

        if let Some(version) = unchanged_policy_revision_ready_to_ack(
            unchanged_policy_revision,
            policy_runtime_changed,
            policy_runtime_reconciled,
        ) {
            enqueue_policy_status(
                &status_sender,
                PolicyStatusUpdate::unchanged_loaded(version, result.policy_hash.clone()),
            );
            current_policy_version = version;
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
    enabled: &AtomicBool,
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

    #[test]
    fn transparent_tcp_capability_requires_exact_driver_marker() {
        let required = openshell_core::sandbox_env::POLICY_DNS_TRANSPARENT_TCP_CAPABILITY;
        assert!(!has_network_runtime_capability(None, required));
        assert!(!has_network_runtime_capability(Some(""), required));
        assert!(!has_network_runtime_capability(
            Some("policy-dns-transparent-tcp-extra"),
            required
        ));
        assert!(has_network_runtime_capability(
            Some("other, policy-dns-transparent-tcp"),
            required
        ));
    }
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
            Arc::new(tokio::sync::Mutex::new(None)),
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
        let handle = spawn_sidecar_control_update_watcher(
            rx,
            provider_credentials,
            agent_proposals.clone(),
            Arc::new(tokio::sync::Mutex::new(None)),
        );

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
        // It keeps filesystem restrictions while leaving identity to the
        // active compute driver.
        assert!(policy.filesystem.is_some());
        assert!(policy.process.is_none());
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
        assert!(policy.process.is_none());
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

    fn proto_tcp_policy_fixture() -> openshell_core::proto::SandboxPolicy {
        openshell_policy::parse_sandbox_policy(
            r#"
version: 1
network_policies:
  redis:
    name: redis
    endpoints:
      - host: redis.example.com
        port: 6379
        protocol: tcp
    binaries:
      - path: /usr/bin/redis-cli
"#,
        )
        .expect("parse TCP policy")
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
            policy_validation_failure_mode: PolicyValidationFailureMode::default(),
            extension_authentication_enabled: false,
        }
    }

    #[derive(Clone)]
    struct ScriptedPolicyGateway {
        polls: Arc<
            tokio::sync::Mutex<
                tokio::sync::mpsc::UnboundedReceiver<
                    openshell_core::grpc_client::SettingsPollResult,
                >,
            >,
        >,
        reports: UnboundedSender<(u32, bool, String)>,
    }

    #[tonic::async_trait]
    impl PolicyGatewayClient for ScriptedPolicyGateway {
        async fn poll_settings(
            &self,
            _sandbox_id: &str,
        ) -> Result<openshell_core::grpc_client::SettingsPollResult> {
            self.polls
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| miette::miette!("scripted policy poll channel closed"))
        }

        async fn report_policy_status(
            &self,
            _sandbox_id: &str,
            version: u32,
            loaded: bool,
            error: &str,
        ) -> Result<()> {
            self.reports
                .send((version, loaded, error.to_string()))
                .map_err(|_| miette::miette!("scripted policy report channel closed"))
        }

        fn workspace(&self) -> String {
            "test-workspace".to_string()
        }
    }

    #[derive(Clone)]
    struct CredentialRejectingPolicyGateway {
        inner: ScriptedPolicyGateway,
        credential_requests: Arc<AtomicUsize>,
    }

    #[tonic::async_trait]
    impl PolicyGatewayClient for CredentialRejectingPolicyGateway {
        async fn poll_settings(
            &self,
            sandbox_id: &str,
        ) -> Result<openshell_core::grpc_client::SettingsPollResult> {
            self.inner.poll_settings(sandbox_id).await
        }

        async fn report_policy_status(
            &self,
            sandbox_id: &str,
            version: u32,
            loaded: bool,
            error: &str,
        ) -> Result<()> {
            self.inner
                .report_policy_status(sandbox_id, version, loaded, error)
                .await
        }

        async fn extension_credentials_for(
            &self,
            _services: &[openshell_core::proto::SupervisorMiddlewareService],
        ) -> Result<std::collections::HashMap<String, openshell_extension_core::BearerTokenSlot>>
        {
            self.credential_requests.fetch_add(1, Ordering::SeqCst);
            Err(miette::miette!(
                "gateway extension authentication is unavailable"
            ))
        }

        fn workspace(&self) -> String {
            self.inner.workspace()
        }
    }

    fn scripted_policy_gateway() -> (
        ScriptedPolicyGateway,
        UnboundedSender<openshell_core::grpc_client::SettingsPollResult>,
        tokio::sync::mpsc::UnboundedReceiver<(u32, bool, String)>,
    ) {
        let (poll_tx, poll_rx) = tokio::sync::mpsc::unbounded_channel();
        let (report_tx, report_rx) = tokio::sync::mpsc::unbounded_channel();
        (
            ScriptedPolicyGateway {
                polls: Arc::new(tokio::sync::Mutex::new(poll_rx)),
                reports: report_tx,
            },
            poll_tx,
            report_rx,
        )
    }

    fn policy_poll_test_context(
        opa_engine: Arc<OpaEngine>,
        loaded_policy_origin: LoadedPolicyOrigin,
        middleware_connector: MiddlewareConnector,
    ) -> PolicyPollLoopContext {
        let (workspace_tx, _workspace_rx) = tokio::sync::watch::channel(String::new());
        PolicyPollLoopContext {
            endpoint: String::new(),
            sandbox_id: "sandbox-test".to_string(),
            opa_engine,
            loaded_policy_origin,
            entrypoint_pid: Arc::new(AtomicU32::new(0)),
            interval_secs: 0,
            ocsf_enabled: Arc::new(AtomicBool::new(false)),
            provider_credentials: ProviderCredentialState::from_child_env_snapshot(
                0,
                std::collections::HashMap::new(),
            ),
            policy_local_ctx: None,
            agent_proposals: AgentProposals::default(),
            middleware_registry_status: MiddlewareRegistryStatus::Synchronized,
            sidecar_control_publisher: None,
            workspace_tx,
            extension_credentials: openshell_extension_core::ExtensionCredentialStore::new(),
            extension_authentication_enabled: false,
            middleware_connector,
            transparent_tcp: TransparentTcpReloadState::default(),
        }
    }

    async fn expect_policy_report(
        reports: &mut tokio::sync::mpsc::UnboundedReceiver<(u32, bool, String)>,
        version: u32,
    ) {
        let report = timeout(Duration::from_secs(1), reports.recv())
            .await
            .expect("policy report timed out")
            .expect("policy reporter stopped");
        assert_eq!(report, (version, true, String::new()));
    }

    async fn expect_no_policy_report(
        reports: &mut tokio::sync::mpsc::UnboundedReceiver<(u32, bool, String)>,
    ) {
        assert!(
            timeout(Duration::from_millis(50), reports.recv())
                .await
                .is_err(),
            "unexpected policy status report"
        );
    }

    #[tokio::test]
    async fn same_hash_poll_revision_is_acknowledged_once_without_opa_reload() {
        let mut v1 = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        v1.policy_hash = "same-policy".to_string();
        let mut v2 = v1.clone();
        v2.version = 2;
        v2.config_revision = 200;

        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        let loaded_revision = LoadedPolicyRevision::from_snapshot(&v1);
        let ctx = policy_poll_test_context(
            engine.clone(),
            LoadedPolicyOrigin::Gateway {
                revision: Some(loaded_revision),
                has_last_valid_policy: true,
            },
            default_middleware_connector(),
        );
        let (client, polls, mut reports) = scripted_policy_gateway();
        polls.send(v1).unwrap();

        let handle = tokio::spawn(run_policy_poll_loop_with_client(ctx, client));
        expect_policy_report(&mut reports, 1).await;

        polls.send(v2.clone()).unwrap();
        expect_policy_report(&mut reports, 2).await;
        polls.send(v2).unwrap();
        expect_no_policy_report(&mut reports).await;

        assert_eq!(
            engine.current_generation(),
            0,
            "same-hash acknowledgement must not reload OPA"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn poll_rejects_first_tcp_expansion_and_reports_previous_policy_active() {
        let v1 = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let v2 = settings_poll_result(
            Some(proto_tcp_policy_fixture()),
            2,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        let active_generation = engine.current_generation();
        let loaded_revision = LoadedPolicyRevision::from_snapshot(&v1);
        let mut ctx = policy_poll_test_context(
            engine.clone(),
            LoadedPolicyOrigin::Gateway {
                revision: Some(loaded_revision),
                has_last_valid_policy: true,
            },
            default_middleware_connector(),
        );
        ctx.transparent_tcp = TransparentTcpReloadState {
            capable: true,
            substrate_ready: false,
        };
        let (client, polls, mut reports) = scripted_policy_gateway();
        polls.send(v1).unwrap();

        let handle = tokio::spawn(run_policy_poll_loop_with_client(ctx, client));
        expect_policy_report(&mut reports, 1).await;
        polls.send(v2).unwrap();
        let report = timeout(Duration::from_secs(1), reports.recv())
            .await
            .expect("TCP rejection report timed out")
            .expect("policy reporter stopped");

        assert_eq!(report.0, 2);
        assert!(!report.1);
        assert!(report.2.contains("recreate the sandbox"), "{}", report.2);
        assert!(report.2.contains("previous policy remains active"));
        assert_eq!(engine.current_generation(), active_generation);
        assert!(engine.fail_closed_reason().is_none());
        handle.abort();
    }

    #[tokio::test]
    async fn same_hash_ack_waits_for_failed_middleware_reconciliation_and_retries_once() {
        let mut v1 = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        v1.policy_hash = "same-policy".to_string();
        let mut v2 = v1.clone();
        v2.version = 2;
        v2.config_revision = 200;
        v2.supervisor_middleware_services =
            vec![openshell_core::proto::SupervisorMiddlewareService {
                name: "scripted-guard".to_string(),
                grpc_endpoint: "http://scripted.invalid".to_string(),
                ..Default::default()
            }];

        let connector_attempts = Arc::new(AtomicUsize::new(0));
        let (attempt_tx, mut attempt_rx) = tokio::sync::mpsc::unbounded_channel();
        let middleware_connector: MiddlewareConnector = {
            let connector_attempts = connector_attempts.clone();
            Arc::new(move |_services, _authentication| {
                let attempt = connector_attempts.fetch_add(1, Ordering::SeqCst) + 1;
                attempt_tx.send(attempt).unwrap();
                Box::pin(async move {
                    if attempt == 1 {
                        Err(miette::miette!("scripted middleware connection failure"))
                    } else {
                        connect_middleware_registry(&[], &MiddlewareAuthentication::default()).await
                    }
                })
            })
        };

        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        let loaded_revision = LoadedPolicyRevision::from_snapshot(&v1);
        let ctx = policy_poll_test_context(
            engine.clone(),
            LoadedPolicyOrigin::Gateway {
                revision: Some(loaded_revision),
                has_last_valid_policy: true,
            },
            middleware_connector,
        );
        let (client, polls, mut reports) = scripted_policy_gateway();
        polls.send(v1).unwrap();

        let handle = tokio::spawn(run_policy_poll_loop_with_client(ctx, client));
        expect_policy_report(&mut reports, 1).await;

        polls.send(v2.clone()).unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), attempt_rx.recv())
                .await
                .unwrap(),
            Some(1)
        );
        expect_no_policy_report(&mut reports).await;
        assert_eq!(engine.current_generation(), 0);

        polls.send(v2.clone()).unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), attempt_rx.recv())
                .await
                .unwrap(),
            Some(2)
        );
        expect_policy_report(&mut reports, 2).await;
        assert_eq!(engine.current_generation(), 1);

        polls.send(v2).unwrap();
        expect_no_policy_report(&mut reports).await;
        assert_eq!(connector_attempts.load(Ordering::SeqCst), 2);
        handle.abort();
    }

    #[tokio::test]
    async fn no_signer_capability_uses_legacy_middleware_connector_without_credentials() {
        let mut v1 = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        v1.policy_hash = "same-policy".to_string();
        let mut v2 = v1.clone();
        v2.version = 2;
        v2.config_revision = 200;
        v2.supervisor_middleware_services =
            vec![openshell_core::proto::SupervisorMiddlewareService {
                name: "legacy-guard".to_string(),
                grpc_endpoint: "http://legacy.invalid".to_string(),
                ..Default::default()
            }];
        assert!(!v2.extension_authentication_enabled);

        let (inner, polls, mut reports) = scripted_policy_gateway();
        let credential_requests = Arc::new(AtomicUsize::new(0));
        let client = CredentialRejectingPolicyGateway {
            inner,
            credential_requests: credential_requests.clone(),
        };
        let (connector_tx, mut connector_rx) = tokio::sync::mpsc::unbounded_channel();
        let connector: MiddlewareConnector = Arc::new(move |_services, authentication| {
            connector_tx
                .send((authentication.credentials.len(), authentication.enabled))
                .unwrap();
            Box::pin(async move {
                connect_middleware_registry(&[], &MiddlewareAuthentication::default()).await
            })
        });
        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        let loaded_revision = LoadedPolicyRevision::from_snapshot(&v1);
        let ctx = policy_poll_test_context(
            engine,
            LoadedPolicyOrigin::Gateway {
                revision: Some(loaded_revision),
                has_last_valid_policy: true,
            },
            connector,
        );

        polls.send(v1).unwrap();
        let handle = tokio::spawn(run_policy_poll_loop_with_client(ctx, client));
        expect_policy_report(&mut reports, 1).await;
        polls.send(v2).unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), connector_rx.recv())
                .await
                .unwrap(),
            Some((0, false))
        );
        expect_policy_report(&mut reports, 2).await;
        assert_eq!(credential_requests.load(Ordering::SeqCst), 0);
        handle.abort();
    }

    #[tokio::test]
    async fn enabled_extension_authentication_keeps_credential_failure_fail_closed() {
        let mut v1 = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        v1.policy_hash = "same-policy".to_string();
        let mut v2 = v1.clone();
        v2.version = 2;
        v2.config_revision = 200;
        v2.extension_authentication_enabled = true;
        v2.supervisor_middleware_services =
            vec![openshell_core::proto::SupervisorMiddlewareService {
                name: "authenticated-guard".to_string(),
                grpc_endpoint: "https://guard.invalid".to_string(),
                ..Default::default()
            }];

        let (inner, polls, mut reports) = scripted_policy_gateway();
        let credential_requests = Arc::new(AtomicUsize::new(0));
        let client = CredentialRejectingPolicyGateway {
            inner,
            credential_requests: credential_requests.clone(),
        };
        let (connector_tx, mut connector_rx) = tokio::sync::mpsc::unbounded_channel();
        let connector: MiddlewareConnector = Arc::new(move |_services, authentication| {
            connector_tx
                .send((authentication.credentials.len(), authentication.enabled))
                .unwrap();
            Box::pin(async move {
                if authentication.enabled && authentication.credentials.is_empty() {
                    Err(miette::miette!(
                        "missing authenticated middleware credential"
                    ))
                } else {
                    connect_middleware_registry(&[], &authentication).await
                }
            })
        });
        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        let loaded_revision = LoadedPolicyRevision::from_snapshot(&v1);
        let ctx = policy_poll_test_context(
            engine,
            LoadedPolicyOrigin::Gateway {
                revision: Some(loaded_revision),
                has_last_valid_policy: true,
            },
            connector,
        );

        polls.send(v1).unwrap();
        let handle = tokio::spawn(run_policy_poll_loop_with_client(ctx, client));
        expect_policy_report(&mut reports, 1).await;
        polls.send(v2).unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), connector_rx.recv())
                .await
                .unwrap(),
            Some((0, true))
        );
        expect_no_policy_report(&mut reports).await;
        assert_eq!(credential_requests.load(Ordering::SeqCst), 1);
        handle.abort();
    }

    async fn assert_poll_does_not_use_same_hash_acknowledgement(
        initial: openshell_core::grpc_client::SettingsPollResult,
        next: openshell_core::grpc_client::SettingsPollResult,
        origin: LoadedPolicyOrigin,
        initial_report: Option<u32>,
    ) {
        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        let ctx = policy_poll_test_context(engine.clone(), origin, default_middleware_connector());
        let (client, polls, mut reports) = scripted_policy_gateway();
        polls.send(initial).unwrap();
        let handle = tokio::spawn(run_policy_poll_loop_with_client(ctx, client));

        if let Some(version) = initial_report {
            expect_policy_report(&mut reports, version).await;
        } else {
            expect_no_policy_report(&mut reports).await;
        }

        polls.send(next).unwrap();
        expect_no_policy_report(&mut reports).await;
        assert_eq!(
            engine.current_generation(),
            0,
            "negative same-hash scope must not reload OPA"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn same_hash_ack_poll_loop_rejects_local_global_empty_equal_and_older_scopes() {
        let mut sandbox_v1 = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        sandbox_v1.policy_hash = "same-policy".to_string();
        let loaded_v1 = LoadedPolicyRevision::from_snapshot(&sandbox_v1);
        let mut sandbox_v2 = sandbox_v1.clone();
        sandbox_v2.version = 2;
        sandbox_v2.config_revision = 200;

        assert_poll_does_not_use_same_hash_acknowledgement(
            sandbox_v1.clone(),
            sandbox_v2.clone(),
            LoadedPolicyOrigin::LocalOverride,
            None,
        )
        .await;

        let mut global_v2 = sandbox_v2.clone();
        global_v2.policy_source = openshell_core::proto::PolicySource::Global;
        assert_poll_does_not_use_same_hash_acknowledgement(
            sandbox_v1.clone(),
            global_v2,
            LoadedPolicyOrigin::Gateway {
                revision: Some(loaded_v1.clone()),
                has_last_valid_policy: true,
            },
            Some(1),
        )
        .await;

        let mut empty_v1 = sandbox_v1.clone();
        empty_v1.policy_hash.clear();
        let empty_loaded = LoadedPolicyRevision::from_snapshot(&empty_v1);
        let mut empty_v2 = sandbox_v2.clone();
        empty_v2.policy_hash.clear();
        assert_poll_does_not_use_same_hash_acknowledgement(
            empty_v1,
            empty_v2,
            LoadedPolicyOrigin::Gateway {
                revision: Some(empty_loaded),
                has_last_valid_policy: true,
            },
            Some(1),
        )
        .await;

        assert_poll_does_not_use_same_hash_acknowledgement(
            sandbox_v1.clone(),
            sandbox_v1.clone(),
            LoadedPolicyOrigin::Gateway {
                revision: Some(loaded_v1.clone()),
                has_last_valid_policy: true,
            },
            Some(1),
        )
        .await;

        let loaded_v2 = LoadedPolicyRevision::from_snapshot(&sandbox_v2);
        assert_poll_does_not_use_same_hash_acknowledgement(
            sandbox_v2,
            sandbox_v1,
            LoadedPolicyOrigin::Gateway {
                revision: Some(loaded_v2),
                has_last_valid_policy: true,
            },
            Some(2),
        )
        .await;
    }

    #[tokio::test]
    async fn changed_hash_poll_uses_normal_opa_reload_and_status_path() {
        let v1 = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let v2 = settings_poll_result(
            Some(proto_policy_fixture()),
            2,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let loaded_revision = LoadedPolicyRevision::from_snapshot(&v1);
        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        let ctx = policy_poll_test_context(
            engine.clone(),
            LoadedPolicyOrigin::Gateway {
                revision: Some(loaded_revision),
                has_last_valid_policy: true,
            },
            default_middleware_connector(),
        );
        let (client, polls, mut reports) = scripted_policy_gateway();
        polls.send(v1).unwrap();
        let handle = tokio::spawn(run_policy_poll_loop_with_client(ctx, client));

        expect_policy_report(&mut reports, 1).await;
        polls.send(v2).unwrap();
        expect_policy_report(&mut reports, 2).await;
        assert_eq!(
            engine.current_generation(),
            1,
            "changed policy content must still reload OPA"
        );
        handle.abort();
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
            max_payload_bytes: 1024,
            ..Default::default()
        };
        connect_middleware_registry(&[invalid_external], &MiddlewareAuthentication::default())
            .await
            .expect_err("unavailable external service must not replace built-ins");

        assert_eq!(engine.current_generation(), builtins_generation);
    }

    #[tokio::test]
    async fn unavailable_middleware_reload_keeps_last_known_good_runtime_active() {
        let engine = OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine");
        install_builtin_middleware_registry(&engine)
            .await
            .expect("install built-in middleware registry");
        let active_generation = engine.current_generation();
        let unavailable_service = openshell_core::proto::SupervisorMiddlewareService {
            name: "unavailable-guard".into(),
            grpc_endpoint: "http://127.0.0.1:1".into(),
            max_payload_bytes: 1024,
            ..Default::default()
        };

        let failure = reload_gateway_policy_runtime(
            &engine,
            Some(&proto_policy_fixture()),
            0,
            MiddlewareReloadContext {
                desired_services: &[unavailable_service],
                authentication: &MiddlewareAuthentication::default(),
                registry_changed: true,
                connector: &default_middleware_connector(),
            },
            TransparentTcpReloadState::default(),
        )
        .await
        .expect_err("unavailable middleware must fail candidate preparation");
        let disposition = apply_gateway_runtime_reload_failure(
            &engine,
            failure,
            PolicyValidationFailureMode::FailClosed,
            true,
            2,
        )
        .expect("middleware failure handling must succeed");

        assert!(matches!(
            disposition,
            GatewayRuntimeFailureDisposition::MiddlewareUnavailable { .. }
        ));
        assert_eq!(engine.current_generation(), active_generation);
        assert!(engine.fail_closed_reason().is_none());
    }

    #[tokio::test]
    async fn tcp_policy_reload_without_startup_substrate_is_rejected_and_keeps_previous_policy() {
        let engine = OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine");
        let active_generation = engine.current_generation();

        let failure = reload_gateway_policy_runtime(
            &engine,
            Some(&proto_tcp_policy_fixture()),
            0,
            MiddlewareReloadContext {
                desired_services: &[],
                authentication: &MiddlewareAuthentication::default(),
                registry_changed: false,
                connector: &default_middleware_connector(),
            },
            TransparentTcpReloadState {
                capable: true,
                substrate_ready: false,
            },
        )
        .await
        .expect_err("TCP expansion must require startup substrate");
        let disposition = apply_gateway_runtime_reload_failure(
            &engine,
            failure,
            PolicyValidationFailureMode::FailClosed,
            true,
            2,
        )
        .expect("runtime prerequisite failure handling must succeed");

        assert!(matches!(
            disposition,
            GatewayRuntimeFailureDisposition::TransparentTcpExpansionRejected {
                active_generation: generation,
                ..
            } if generation == active_generation
        ));
        assert_eq!(engine.current_generation(), active_generation);
        assert!(engine.fail_closed_reason().is_none());
    }

    #[tokio::test]
    async fn tcp_policy_reload_on_unsupported_runtime_is_rejected() {
        let engine = OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine");

        let failure = reload_gateway_policy_runtime(
            &engine,
            Some(&proto_tcp_policy_fixture()),
            0,
            MiddlewareReloadContext {
                desired_services: &[],
                authentication: &MiddlewareAuthentication::default(),
                registry_changed: false,
                connector: &default_middleware_connector(),
            },
            TransparentTcpReloadState::default(),
        )
        .await
        .expect_err("unsupported runtime must reject TCP expansion");

        assert!(matches!(
            failure,
            GatewayRuntimeReloadError::TransparentTcpPrerequisite(_)
        ));
        assert_eq!(engine.current_generation(), 0);
    }

    #[test]
    fn policy_rejection_after_middleware_outage_is_not_deduplicated() {
        let engine = OpaEngine::from_strings(
            include_str!("../../openshell-supervisor-network/data/sandbox-policy.rego"),
            "network_policies: {}\n",
        )
        .unwrap();
        let middleware_failure = GatewayRuntimeReloadError::MiddlewareRegistry(miette::miette!(
            "middleware service unavailable"
        ));
        let first_failure = FailedRuntimeRevision::new(42, "sha256:candidate", &middleware_failure);
        let middleware_disposition = apply_gateway_runtime_reload_failure(
            &engine,
            middleware_failure,
            PolicyValidationFailureMode::FailClosed,
            true,
            7,
        )
        .unwrap();

        assert!(matches!(
            middleware_disposition,
            GatewayRuntimeFailureDisposition::MiddlewareUnavailable { .. }
        ));
        assert!(engine.fail_closed_reason().is_none());

        let policy_failure = GatewayRuntimeReloadError::PolicyValidation(miette::miette!(
            "conflicting endpoint metadata"
        ));
        let second_failure = FailedRuntimeRevision::new(42, "sha256:candidate", &policy_failure);
        assert_ne!(
            first_failure, second_failure,
            "a changed failure class for the same candidate must be handled"
        );

        let policy_disposition = apply_gateway_runtime_reload_failure(
            &engine,
            policy_failure,
            PolicyValidationFailureMode::FailClosed,
            true,
            7,
        )
        .unwrap();
        assert!(matches!(
            policy_disposition,
            GatewayRuntimeFailureDisposition::PolicyRejected { .. }
        ));
        assert!(engine.fail_closed_reason().is_some());
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
                    has_last_valid_policy: true,
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
        let origin = LoadedPolicyOrigin::Gateway {
            revision: None,
            has_last_valid_policy: true,
        };

        assert_eq!(
            initial_poll_disposition(&origin, &canonical),
            InitialPollDisposition::Reconcile
        );
        assert!(origin.allows_gateway_policy_reload());
    }

    #[test]
    fn unchanged_sandbox_policy_revision_candidate_is_strictly_scoped() {
        let sandbox_result = openshell_core::grpc_client::SettingsPollResult {
            policy_hash: "same-policy".to_string(),
            ..settings_poll_result(
                Some(proto_policy_fixture()),
                2,
                openshell_core::proto::PolicySource::Sandbox,
            )
        };

        assert_eq!(
            unchanged_policy_revision_candidate(true, false, 1, "same-policy", &sandbox_result),
            Some(2)
        );
        assert_eq!(
            unchanged_policy_revision_candidate(true, false, 2, "same-policy", &sandbox_result),
            None
        );
        assert_eq!(
            unchanged_policy_revision_candidate(
                true,
                false,
                1,
                "different-policy",
                &sandbox_result,
            ),
            None
        );
        assert_eq!(
            unchanged_policy_revision_candidate(false, false, 1, "same-policy", &sandbox_result),
            None
        );
        assert_eq!(
            unchanged_policy_revision_candidate(true, false, 1, "", &sandbox_result),
            None
        );
        assert_eq!(
            unchanged_policy_revision_candidate(true, true, 1, "same-policy", &sandbox_result),
            None
        );

        let global_result = openshell_core::grpc_client::SettingsPollResult {
            policy_hash: "same-policy".to_string(),
            ..settings_poll_result(
                Some(proto_policy_fixture()),
                2,
                openshell_core::proto::PolicySource::Global,
            )
        };
        assert_eq!(
            unchanged_policy_revision_candidate(true, false, 1, "same-policy", &global_result),
            None
        );
    }

    #[test]
    fn unchanged_policy_revision_waits_for_required_runtime_reconciliation() {
        assert_eq!(
            unchanged_policy_revision_ready_to_ack(Some(2), false, false),
            Some(2),
            "a same-hash revision needs no OPA reload"
        );
        assert_eq!(
            unchanged_policy_revision_ready_to_ack(Some(2), true, false),
            None,
            "failed runtime reconciliation must keep the revision pending"
        );
        assert_eq!(
            unchanged_policy_revision_ready_to_ack(Some(2), true, true),
            Some(2),
            "successful runtime reconciliation permits acknowledgement"
        );
        assert_eq!(
            unchanged_policy_revision_ready_to_ack(None, false, true),
            None,
            "runtime success cannot manufacture a revision candidate"
        );
    }

    #[test]
    fn credential_gating_unavailable_for_local_override_with_credentials() {
        assert!(credential_gating_unavailable(
            &LoadedPolicyOrigin::LocalOverride,
            true,
            true
        ));
    }

    #[test]
    fn credential_gating_available_without_local_override_or_credentials() {
        // A gateway policy is stamped with provenance, so the gates apply.
        assert!(!credential_gating_unavailable(
            &LoadedPolicyOrigin::Gateway {
                revision: None,
                has_last_valid_policy: true,
            },
            true,
            true
        ));
        // No provider credentials means there is nothing to leak.
        assert!(!credential_gating_unavailable(
            &LoadedPolicyOrigin::LocalOverride,
            false,
            true
        ));
        // Without networking the proxy never evaluates endpoint provenance.
        assert!(!credential_gating_unavailable(
            &LoadedPolicyOrigin::LocalOverride,
            true,
            false
        ));
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
    #[test]
    fn fail_closed_validation_failure_deactivates_previous_generation() {
        let engine = OpaEngine::from_strings(
            include_str!("../../openshell-supervisor-network/data/sandbox-policy.rego"),
            "network_policies: {}\n",
        )
        .unwrap();
        let previous_generation = engine.current_generation();

        let disposition = apply_policy_validation_failure(
            &engine,
            PolicyValidationFailureMode::FailClosed,
            true,
            7,
            "conflicting tls metadata",
        )
        .unwrap();

        assert!(!disposition.previous_policy_active);
        assert!(disposition.active_generation > previous_generation);
        assert!(
            engine
                .fail_closed_reason()
                .expect("quarantine reason")
                .contains("candidate version 7 rejected")
        );
    }

    #[test]
    fn retain_validation_failure_keeps_previous_generation_active() {
        let engine = OpaEngine::from_strings(
            include_str!("../../openshell-supervisor-network/data/sandbox-policy.rego"),
            "network_policies: {}\n",
        )
        .unwrap();
        let previous_generation = engine.current_generation();

        let quarantined = apply_policy_validation_failure(
            &engine,
            PolicyValidationFailureMode::FailClosed,
            true,
            6,
            "conflicting tls metadata",
        )
        .unwrap();
        assert!(!quarantined.previous_policy_active);

        let disposition = apply_policy_validation_failure(
            &engine,
            PolicyValidationFailureMode::RetainLastValid,
            true,
            7,
            "conflicting tls metadata",
        )
        .unwrap();

        assert!(disposition.previous_policy_active);
        assert!(disposition.active_generation > quarantined.active_generation);
        assert!(disposition.active_generation > previous_generation);
        assert!(engine.fail_closed_reason().is_none());
    }

    #[test]
    fn retain_validation_failure_without_last_valid_policy_stays_fail_closed() {
        let engine = OpaEngine::from_strings(
            include_str!("../../openshell-supervisor-network/data/sandbox-policy.rego"),
            "network_policies: {}\n",
        )
        .unwrap();

        let disposition = apply_policy_validation_failure(
            &engine,
            PolicyValidationFailureMode::RetainLastValid,
            false,
            1,
            "conflicting tls metadata",
        )
        .unwrap();

        assert_eq!(
            disposition.configured_mode,
            PolicyValidationFailureMode::RetainLastValid
        );
        assert_eq!(disposition.mode, PolicyValidationFailureMode::FailClosed);
        assert!(!disposition.previous_policy_active);
        assert!(engine.fail_closed_reason().is_some());

        let [config, _] = policy_validation_failure_events(
            &disposition,
            1,
            "sha256:test",
            "conflicting tls metadata",
        );
        let config = config.to_json().unwrap();
        assert_eq!(config["unmapped"]["validation_failure_mode"], "fail_closed");
        assert_eq!(
            config["unmapped"]["configured_validation_failure_mode"],
            "retain_last_valid"
        );
        assert!(
            config["message"]
                .as_str()
                .unwrap()
                .contains("previous policy IS NOT active")
        );
    }

    #[test]
    fn validation_failure_ocsf_states_whether_previous_policy_is_active() {
        let fail_closed = PolicyValidationFailureDisposition {
            configured_mode: PolicyValidationFailureMode::FailClosed,
            mode: PolicyValidationFailureMode::FailClosed,
            previous_policy_active: false,
            active_generation: 9,
        };
        let [config, finding] = policy_validation_failure_events(
            &fail_closed,
            8,
            "sha256:test",
            "conflicting tls metadata",
        );
        let config = config.to_json().unwrap();
        assert_eq!(config["class_uid"], 5019);
        assert_eq!(config["status"], "Failure");
        assert_eq!(config["unmapped"]["validation_failure_mode"], "fail_closed");
        assert_eq!(
            config["unmapped"]["configured_validation_failure_mode"],
            "fail_closed"
        );
        assert_eq!(config["unmapped"]["previous_policy_active"], false);
        assert_eq!(
            config["unmapped"]["validation_error"],
            "conflicting tls metadata"
        );
        assert!(
            config["message"]
                .as_str()
                .unwrap()
                .contains("previous policy IS NOT active")
        );
        assert!(
            config["message"]
                .as_str()
                .unwrap()
                .contains("error:conflicting tls metadata")
        );

        let finding = finding.to_json().unwrap();
        assert_eq!(finding["class_uid"], 2004);
        assert_eq!(finding["action"], "Denied");
        assert_eq!(finding["disposition"], "Blocked");

        let retained = PolicyValidationFailureDisposition {
            configured_mode: PolicyValidationFailureMode::RetainLastValid,
            mode: PolicyValidationFailureMode::RetainLastValid,
            previous_policy_active: true,
            active_generation: 4,
        };
        let [config, _] = policy_validation_failure_events(
            &retained,
            8,
            "sha256:test",
            "conflicting tls metadata",
        );
        let config = config.to_json().unwrap();
        assert_eq!(config["unmapped"]["previous_policy_active"], true);
        assert!(
            config["message"]
                .as_str()
                .unwrap()
                .contains("previous policy IS active")
        );
    }
}
