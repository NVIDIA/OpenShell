// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `OpenShell` Sandbox library.
//!
//! This crate provides process sandboxing and monitoring capabilities.

// `defaults-without-telemetry` is an alias for the default feature set minus
// `telemetry`, not a switch that turns telemetry off. Cargo cannot subtract a
// default feature, so adding it on top of the defaults would otherwise produce
// a telemetry-on build that reads as telemetry-free. Fail the build instead.
#[cfg(all(feature = "telemetry", feature = "defaults-without-telemetry"))]
compile_error!(
    "features `telemetry` and `defaults-without-telemetry` are mutually exclusive; \
     build a telemetry-free supervisor with `--no-default-features --features defaults-without-telemetry`"
);

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
use std::pin::Pin;
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::atomic::Ordering;
use std::sync::atomic::{AtomicBool, AtomicU32};
use std::time::Duration;
use tracing::{debug, info, warn};

use openshell_core::PolicyValidationFailureMode;

use openshell_ocsf::{
    ActionId, ActivityId, AppLifecycleBuilder, ConfidenceId, ConfigStateChangeBuilder,
    DetectionFindingBuilder, DispositionId, EventContext, FindingInfo, SeverityId, StateId,
    StatusId, ocsf_emit,
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
use openshell_supervisor_network::proxy::ProxyHandle;
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
    await_main_process_attachment: bool,
    sandbox_id: Option<String>,
    sandbox: Option<String>,
    openshell_endpoint: Option<String>,
    policy_rules: Option<String>,
    policy_data: Option<String>,
    ssh_socket_path: Option<String>,
    _health_check: bool,
    _health_port: u16,
    ocsf_enabled: Arc<AtomicBool>,
    ocsf_schema_version: Arc<std::sync::Mutex<String>>,
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

        if !openshell_ocsf::ctx::set_ctx(EventContext {
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

    let main_process_instance_id = sidecar_bootstrap
        .as_ref()
        .map(|bootstrap| bootstrap.main_process_instance_id.clone())
        .filter(|instance_id| !instance_id.is_empty())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    // Revision-2 gateway-backed startup receives desired state from the
    // persistent supervisor stream before constructing policy, networking, or
    // the workload. Process-only sidecars receive the same state through the
    // authenticated local sidecar bootstrap instead.
    let mut prepared_supervisor_session = if process_uses_sidecar_control {
        None
    } else if let (Some(endpoint), Some(id)) = (&openshell_endpoint, &sandbox_id) {
        Some(
            openshell_supervisor_process::supervisor_session::prepare(
                endpoint.clone(),
                id.clone(),
                main_process_instance_id.clone(),
            )
            .await
            .map_err(|error| {
                miette::miette!("failed to establish supervisor bootstrap session: {error}")
            })?,
        )
    } else {
        None
    };
    let mut stream_bootstrap = prepared_supervisor_session.as_mut().and_then(
        openshell_supervisor_process::supervisor_session::PreparedSupervisorSession::take_bootstrap,
    );

    // A sandbox created without an explicit policy historically discovers the
    // image's baked-in policy on first boot. The runtime also enriches explicit
    // policies with image-specific baseline paths before installing Landlock.
    // Commit either startup repair before initialization, then reopen
    // ConnectSupervisor: runtime state still comes only from the fresh
    // authoritative bootstrap, never from the mutation response.
    let uses_stream_configuration = prepared_supervisor_session.as_ref().is_some_and(
        openshell_supervisor_process::supervisor_session::PreparedSupervisorSession::uses_stream_configuration,
    );
    let initial_policy_repair =
        if uses_stream_configuration && policy_rules.is_none() && policy_data.is_none() {
            stream_bootstrap
                .as_ref()
                .and_then(|bootstrap| bootstrap.sandbox_config.as_ref())
                .and_then(|snapshot| {
                    snapshot.policy.clone().map_or_else(
                        || {
                            let mut discovered = discover_policy_from_disk_or_default();
                            enrich_proto_baseline_paths(&mut discovered);
                            strip_proto_provider_policy_entries(&mut discovered);
                            Some(discovered)
                        },
                        |mut policy| {
                            let enriched = enrich_proto_baseline_paths(&mut policy);
                            proto_sync_payload_for_enriched_policy(&policy, enriched)
                        },
                    )
                })
        } else {
            None
        };
    if let Some(initial_policy_repair) = initial_policy_repair {
        let endpoint = openshell_endpoint.as_deref().ok_or_else(|| {
            miette::miette!("gateway-backed policy discovery requires an OpenShell endpoint")
        })?;
        let id = sandbox_id.as_deref().ok_or_else(|| {
            miette::miette!("gateway-backed policy discovery requires a sandbox ID")
        })?;
        let sandbox_name = sandbox.as_deref().ok_or_else(|| {
            miette::miette!("gateway-backed policy discovery requires a sandbox name")
        })?;
        let workspace = stream_bootstrap
            .as_ref()
            .and_then(|bootstrap| bootstrap.sandbox_config.as_ref())
            .map(|snapshot| snapshot.workspace.clone())
            .ok_or_else(|| {
                miette::miette!("supervisor bootstrap omitted required sandbox configuration")
            })?;
        grpc_retry("Initial policy bootstrap repair", || {
            let initial_policy_repair = initial_policy_repair.clone();
            let workspace = workspace.clone();
            async move {
                openshell_core::grpc_client::sync_policy_and_fetch_snapshot(
                    endpoint,
                    id,
                    sandbox_name,
                    &initial_policy_repair,
                    &workspace,
                )
                .await
                .map(|_| ())
            }
        })
        .await?;

        prepared_supervisor_session = Some(
            openshell_supervisor_process::supervisor_session::prepare(
                endpoint.to_string(),
                id.to_string(),
                main_process_instance_id.clone(),
            )
            .await
            .map_err(|error| {
                miette::miette!(
                    "failed to reestablish supervisor session after policy bootstrap repair: {error}"
                )
            })?,
        );
        stream_bootstrap = prepared_supervisor_session.as_mut().and_then(
            openshell_supervisor_process::supervisor_session::PreparedSupervisorSession::take_bootstrap,
        );
    }
    if stream_bootstrap
        .as_ref()
        .is_some_and(|bootstrap| bootstrap.sandbox_config.is_none())
    {
        return Err(miette::miette!(
            "supervisor bootstrap omitted required sandbox configuration"
        ));
    }
    if uses_stream_configuration
        && stream_bootstrap
            .as_ref()
            .and_then(|bootstrap| bootstrap.sandbox_config.as_ref())
            .is_some_and(|snapshot| snapshot.policy.is_none())
    {
        return Err(miette::miette!(
            "supervisor bootstrap omitted required sandbox policy"
        ));
    }

    // Extension credentials are owned by this supervisor and shared by every
    // gateway connection it opens, so the middleware registry's bearer slots
    // and the stream configuration loop that rotates them stay the same objects.
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
        mut initial_agent_proposals_enabled,
        mut _initial_extension_authentication_enabled,
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
            openshell_endpoint.clone(),
            policy_rules,
            policy_data,
            &extension_credentials,
            stream_bootstrap
                .as_ref()
                .and_then(|bootstrap| bootstrap.sandbox_config.clone()),
        )
        .await?
    };
    if let Some(snapshot) = stream_bootstrap
        .as_ref()
        .and_then(|bootstrap| bootstrap.sandbox_config.as_ref())
    {
        initial_agent_proposals_enabled = agent_proposals_enabled_from_settings(&snapshot.settings);
        _initial_extension_authentication_enabled = snapshot.extension_authentication_enabled;
    }

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
    #[allow(clippy::option_if_let_else)]
    let (provider_credentials, mut provider_env, provider_bootstrap_degraded) = if let Some(
        bootstrap,
    ) =
        sidecar_bootstrap.as_ref()
    {
        let provider_credentials = ProviderCredentialState::from_child_env_snapshot(
            bootstrap.provider_env_revision,
            bootstrap.provider_child_env.clone(),
        );
        (
            provider_credentials,
            bootstrap.provider_child_env.clone(),
            false,
        )
    } else if let Some(snapshot) = stream_bootstrap
        .as_ref()
        .and_then(|bootstrap| bootstrap.provider_environment.clone())
    {
        let result: openshell_core::grpc_client::ProviderEnvironmentResult = snapshot.into();
        let dynamic_credentials_fallback = result.dynamic_credentials.clone();
        let mut degraded = false;
        let provider_credentials = ProviderCredentialState::from_bound_environment(
            result.provider_env_revision,
            result.environment,
            result.credential_expires_at_ms,
            result.dynamic_credentials,
            result.static_credential_bindings,
            result.non_secret_environment_keys,
        )
        .unwrap_or_else(|error| {
            degraded = true;
            ocsf_emit!(
                ConfigStateChangeBuilder::new(ocsf_ctx())
                    .severity(SeverityId::High)
                    .status(StatusId::Failure)
                    .state(StateId::Disabled, "fail_closed")
                    .message(format!(
                        "Rejected streamed provider environment bindings; static provider credentials were revoked; delivered dynamic token grants remain active: {error}"
                    ))
                    .build()
            );
            ProviderCredentialState::from_environment(
                result.provider_env_revision,
                std::collections::HashMap::new(),
                std::collections::HashMap::new(),
                dynamic_credentials_fallback,
            )
        });
        let provider_env = provider_credentials.child_env_with_gcp_resolved();
        (provider_credentials, provider_env, degraded)
    } else if stream_bootstrap.is_some() {
        (
            ProviderCredentialState::from_child_env_snapshot(0, std::collections::HashMap::new()),
            std::collections::HashMap::new(),
            true,
        )
    } else {
        // Offline/file mode has no gateway-owned provider state. Online mode
        // receives the complete environment in the required stream bootstrap.
        (
            ProviderCredentialState::from_child_env_snapshot(0, std::collections::HashMap::new()),
            std::collections::HashMap::new(),
            false,
        )
    };

    let mut prepared_bootstrap_result = stream_bootstrap.as_ref().map(|bootstrap| {
        use openshell_core::proto::{ConfigApplyOutcome, ConfigBootstrapResult, ConfigComponent};
        let mut results = Vec::with_capacity(2);
        if let Some(snapshot) = bootstrap.provider_environment.as_ref() {
            let revision = provider_config_revision(snapshot.provider_env_revision);
            let outcome = if provider_bootstrap_degraded {
                ConfigApplyOutcome::Degraded
            } else {
                ConfigApplyOutcome::Applied
            };
            results.push(config_apply_result(
                ConfigComponent::ProviderEnvironment,
                revision,
                Some(revision),
                outcome,
                None,
            ));
        }
        if let Some(snapshot) = bootstrap.sandbox_config.as_ref() {
            let settings: openshell_core::grpc_client::SettingsPollResult = snapshot.clone().into();
            let revision = sandbox_config_revision(&settings);
            let outcome = if loaded_policy_origin.allows_gateway_policy_reload() {
                ConfigApplyOutcome::Applied
            } else {
                ConfigApplyOutcome::RetainedLocalOverride
            };
            let applied_revision =
                (outcome != ConfigApplyOutcome::RetainedLocalOverride).then_some(revision);
            results.push(config_apply_result(
                ConfigComponent::SandboxConfig,
                revision,
                applied_revision,
                outcome,
                None,
            ));
        }
        ConfigBootstrapResult { results }
    });

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
    // before the configuration stream starts reconciling later changes.
    let agent_proposals = AgentProposals::new(initial_agent_proposals_enabled);

    let process_control_writer = process_control_connection
        .as_ref()
        .map(|connection| connection.writer.clone());
    let process_exit_ack = Arc::new(tokio::sync::Mutex::new(None));
    let initial_provider_env_generation = sidecar_bootstrap
        .as_ref()
        .map_or(0, |bootstrap| bootstrap.provider_env_generation);
    let mut process_control_closed = None;
    if let Some(connection) = process_control_connection {
        process_control_closed = Some(connection.closed);
        spawn_sidecar_control_update_watcher(
            connection.updates,
            provider_credentials.clone(),
            agent_proposals.clone(),
            Arc::clone(&process_exit_ack),
            initial_provider_env_generation,
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

    // Workspace watch: the stream bootstrap supplies the workspace and the
    // configuration loop broadcasts it. Flush tasks and the policy.local
    // API read the current value so proposals target the correct workspace.
    let (workspace_tx, workspace_rx) = tokio::sync::watch::channel(String::new());
    let (config_apply_tx, config_apply_rx) = tokio::sync::mpsc::channel(16);
    let mut config_apply_rx = Some(config_apply_rx);

    let mut networking = if network_enabled {
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
                main_process_instance_id: main_process_instance_id.clone(),
                policy_proto: proto.clone(),
                provider_env_revision: provider_credentials.snapshot().revision,
                provider_env_generation: 0,
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
                config_apply_tx: config_apply_tx.clone(),
                prepared_supervisor_session: prepared_supervisor_session.take(),
                prepared_bootstrap_result: prepared_bootstrap_result.take(),
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

    // Spawn the stream configuration apply task (gRPC mode only).
    if !process_uses_sidecar_control
        && sandbox_id.is_some()
        && let (Some(endpoint), Some(engine)) = (openshell_endpoint.as_deref(), opa_engine.as_ref())
    {
        let stream_endpoint = endpoint.to_string();
        let stream_engine = engine.clone();
        let stream_ocsf_enabled = ocsf_enabled.clone();
        let stream_ocsf_schema_version = ocsf_schema_version.clone();
        let stream_pid = entrypoint_pid.clone();
        let stream_provider_credentials = provider_credentials.clone();
        let stream_policy_local = networking.as_ref().map(|n| n.policy_local_ctx.clone());
        let credential_refresh_interval_secs = 10;
        let stream_config_ctx = StreamConfigLoopContext {
            endpoint: stream_endpoint,
            opa_engine: stream_engine,
            loaded_policy_origin,
            entrypoint_pid: stream_pid,
            interval_secs: credential_refresh_interval_secs,
            ocsf_enabled: stream_ocsf_enabled,
            ocsf_schema_version: stream_ocsf_schema_version,
            provider_credentials: stream_provider_credentials,
            policy_local_ctx: stream_policy_local,
            agent_proposals: agent_proposals.clone(),
            middleware_registry_status,
            sidecar_control_publisher: sidecar_control_publisher.clone(),
            workspace_tx,
            extension_credentials: extension_credentials.clone(),
            middleware_connector: default_middleware_connector(),
            transparent_tcp: TransparentTcpReloadState {
                capable: transparent_tcp_capable,
                substrate_ready: transparent_tcp_substrate_ready,
            },
            config_apply_rx: config_apply_rx.take(),
            initial_stream_snapshot: stream_bootstrap
                .as_ref()
                .and_then(|bootstrap| bootstrap.sandbox_config.clone())
                .map(Into::into),
        };

        tokio::spawn(async move {
            if let Err(e) = run_stream_config_loop(stream_config_ctx).await {
                ocsf_emit!(
                    AppLifecycleBuilder::new(ocsf_ctx())
                        .activity(ActivityId::Fail)
                        .severity(SeverityId::Medium)
                        .status(StatusId::Failure)
                        .message(format!(
                            "Stream configuration apply loop exited with error: {e}"
                        ))
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

    let proxy_exited: Pin<Box<dyn Future<Output = ()> + Send>> = if let Some(rx) = networking
        .as_mut()
        .and_then(|n| n.proxy.as_mut())
        .and_then(ProxyHandle::take_exit_receiver)
    {
        Box::pin(async {
            let _ = rx.await;
        })
    } else {
        Box::pin(std::future::pending())
    };
    tokio::pin!(proxy_exited);

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

        let (ssh_exit_tx, ssh_exit_rx) = if ssh_socket_path.is_some() {
            let (tx, rx) = tokio::sync::oneshot::channel::<()>();
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        let ssh_exited: Pin<Box<dyn Future<Output = ()> + Send>> = if let Some(rx) = ssh_exit_rx {
            Box::pin(async {
                let _ = rx.await;
            })
        } else {
            Box::pin(std::future::pending())
        };
        tokio::pin!(ssh_exited);

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
        let sidecar_exit_tx = if process_uses_sidecar_control
            && let Some(writer) = process_control_writer.clone()
        {
            let exit_ack = Arc::clone(&process_exit_ack);
            let (tx, mut rx) = tokio::sync::mpsc::channel::<
                openshell_supervisor_process::run::SidecarExitReport,
            >(1);
            tokio::spawn(async move {
                while let Some(report) = rx.recv().await {
                    match report {
                        openshell_supervisor_process::run::SidecarExitReport::Exited {
                            instance_id,
                            exit_code,
                            ack,
                        } => {
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
                        openshell_supervisor_process::run::SidecarExitReport::Finalized {
                            instance_id,
                            ack,
                        } => {
                            let result =
                                sidecar_control::send_main_process_finalized(&writer, instance_id)
                                    .await
                                    .map_err(|error| error.to_string());
                            let _ = ack.send(result);
                        }
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
            workspace,
            timeout_secs,
            interactive,
            await_main_process_attachment,
            sandbox_id.as_deref(),
            openshell_endpoint.as_deref(),
            ssh_socket_path,
            sidecar_network_enforcement,
            ssh_exit_tx,
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
            main_process_instance_id,
            prepared_supervisor_session.take(),
            prepared_bootstrap_result.take(),
            Some(config_apply_tx.clone()),
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
                () = &mut proxy_exited => {
                    ocsf_emit!(
                        AppLifecycleBuilder::new(ocsf_ctx())
                            .activity(ActivityId::Fail)
                            .severity(SeverityId::High)
                            .status(StatusId::Failure)
                            .message(
                                "Proxy accept loop exited unexpectedly; terminating sandbox"
                            )
                            .build()
                    );
                    return Err(miette::miette!(
                        "proxy accept loop exited unexpectedly"
                    ));
                }
                () = &mut ssh_exited => {
                    ocsf_emit!(
                        AppLifecycleBuilder::new(ocsf_ctx())
                            .activity(ActivityId::Fail)
                            .severity(SeverityId::High)
                            .status(StatusId::Failure)
                            .message(
                                "SSH accept loop exited unexpectedly; terminating sandbox"
                            )
                            .build()
                    );
                    return Err(miette::miette!(
                        "SSH accept loop exited unexpectedly"
                    ));
                }
            }
        } else {
            tokio::select! {
                result = process => result?,
                () = &mut proxy_exited => {
                    ocsf_emit!(
                        AppLifecycleBuilder::new(ocsf_ctx())
                            .activity(ActivityId::Fail)
                            .severity(SeverityId::High)
                            .status(StatusId::Failure)
                            .message(
                                "Proxy accept loop exited unexpectedly; terminating sandbox"
                            )
                            .build()
                    );
                    return Err(miette::miette!(
                        "proxy accept loop exited unexpectedly"
                    ));
                }
                () = &mut ssh_exited => {
                    ocsf_emit!(
                        AppLifecycleBuilder::new(ocsf_ctx())
                            .activity(ActivityId::Fail)
                            .severity(SeverityId::High)
                            .status(StatusId::Failure)
                            .message(
                                "SSH accept loop exited unexpectedly; terminating sandbox"
                            )
                            .build()
                    );
                    return Err(miette::miette!(
                        "SSH accept loop exited unexpectedly"
                    ));
                }
            }
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
                () = &mut proxy_exited => {
                    ocsf_emit!(
                        AppLifecycleBuilder::new(ocsf_ctx())
                            .activity(ActivityId::Fail)
                            .severity(SeverityId::High)
                            .status(StatusId::Failure)
                            .message(
                                "Proxy accept loop exited unexpectedly; terminating sandbox"
                            )
                            .build()
                    );
                    return Err(miette::miette!(
                        "proxy accept loop exited unexpectedly"
                    ));
                }
            }
        } else {
            tokio::select! {
                () = wait_for_shutdown_signal() => 0,
                () = &mut proxy_exited => {
                    ocsf_emit!(
                        AppLifecycleBuilder::new(ocsf_ctx())
                            .activity(ActivityId::Fail)
                            .severity(SeverityId::High)
                            .status(StatusId::Failure)
                            .message(
                                "Proxy accept loop exited unexpectedly; terminating sandbox"
                            )
                            .build()
                    );
                    return Err(miette::miette!(
                        "proxy accept loop exited unexpectedly"
                    ));
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            tokio::select! {
                () = wait_for_shutdown_signal() => 0,
                () = &mut proxy_exited => {
                    ocsf_emit!(
                        AppLifecycleBuilder::new(ocsf_ctx())
                            .activity(ActivityId::Fail)
                            .severity(SeverityId::High)
                            .status(StatusId::Failure)
                            .message(
                                "Proxy accept loop exited unexpectedly; terminating sandbox"
                            )
                            .build()
                    );
                    return Err(miette::miette!(
                        "proxy accept loop exited unexpectedly"
                    ));
                }
            }
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
    mut provider_env_generation: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(update) = updates.recv().await {
            match update {
                sidecar_control::ControlUpdate::ProviderEnv {
                    revision,
                    generation,
                    provider_child_env,
                } => {
                    if generation <= provider_env_generation {
                        continue;
                    }
                    let env_count = provider_credentials
                        .install_child_env_snapshot(revision, provider_child_env);
                    provider_env_generation = generation;
                    ocsf_emit!(
                        ConfigStateChangeBuilder::new(ocsf_ctx())
                            .severity(SeverityId::Informational)
                            .status(StatusId::Success)
                            .state(StateId::Enabled, "loaded")
                            .unmapped("provider_env_revision", serde_json::json!(revision))
                            .unmapped("provider_env_generation", serde_json::json!(generation))
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
    config_apply_tx: tokio::sync::mpsc::Sender<
        openshell_supervisor_process::supervisor_session::ConfigApplyRequest,
    >,
    prepared_supervisor_session:
        Option<openshell_supervisor_process::supervisor_session::PreparedSupervisorSession>,
    prepared_bootstrap_result: Option<openshell_core::proto::ConfigBootstrapResult>,
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
            config_apply_tx,
            mut prepared_supervisor_session,
            mut prepared_bootstrap_result,
        } = handler;
        let mut session_started = false;
        let mut session_task: Option<tokio::task::JoinHandle<()>> = None;
        let mut trusted_supervisor_pid = None;
        let terminating = Arc::new(AtomicBool::new(false));
        while let Some(started) = entrypoint_rx.recv().await {
            if started.finalized {
                if let (Some(endpoint), Some(id)) =
                    (openshell_endpoint.as_ref(), sandbox_id.as_ref())
                {
                    let mut delay = Duration::from_millis(250);
                    loop {
                        match openshell_supervisor_process::supervisor_session::finalize_main_process_exit(
                            endpoint,
                            id,
                            &started.instance_id,
                        )
                        .await
                        {
                            Ok(()) => break,
                            Err(error) => {
                                warn!(%error, "sidecar main-process finalization failed; retrying");
                                tokio::time::sleep(delay).await;
                                delay = (delay * 2).min(Duration::from_secs(2));
                            }
                        }
                    }
                }
                terminating.store(true, Ordering::Release);
                if let Some(task) = session_task.take() {
                    task.abort();
                }
                break;
            }
            if let Some(exit_code) = started.exit_code {
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
                continue;
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
                session_task = if let Some(prepared) = prepared_supervisor_session.take() {
                    Some(
                        openshell_supervisor_process::supervisor_session::spawn_prepared(
                            prepared,
                            prepared_bootstrap_result.take(),
                            trusted_ssh_socket_path.clone(),
                            None,
                            Some(supervisor_pid),
                            Arc::clone(&terminating),
                            config_apply_tx.clone(),
                        ),
                    )
                } else {
                    Some(openshell_supervisor_process::supervisor_session::spawn(
                        endpoint.clone(),
                        id.clone(),
                        trusted_ssh_socket_path.clone(),
                        None,
                        Some(supervisor_pid),
                        Arc::clone(&terminating),
                        started.instance_id.clone(),
                        Some(config_apply_tx.clone()),
                    ))
                };
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
    openshell_endpoint: Option<String>,
    policy_rules: Option<String>,
    policy_data: Option<String>,
    extension_credentials: &openshell_extension_core::ExtensionCredentialStore,
    initial_snapshot: Option<openshell_core::proto::SandboxConfigSnapshot>,
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
        let initial_services = initial_snapshot.as_ref().map_or_else(Vec::new, |snapshot| {
            snapshot.supervisor_middleware_services.clone()
        });
        let initial_extension_authentication_enabled = initial_snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.extension_authentication_enabled);
        let middleware_authentication = if initial_extension_authentication_enabled {
            if let Some(endpoint) = openshell_endpoint.as_deref() {
                let credentials =
                    openshell_core::grpc_client::CachedOpenShellClient::connect_with_credentials(
                        endpoint,
                        extension_credentials.clone(),
                    )
                    .await?
                    .refresh_extension_credentials(&initial_services)
                    .await?;
                MiddlewareAuthentication {
                    credentials,
                    enabled: true,
                }
            } else {
                MiddlewareAuthentication::default()
            }
        } else {
            MiddlewareAuthentication::default()
        };
        let middleware_registry_status = match connect_middleware_registry(
            &initial_services,
            &middleware_authentication,
        )
        .await
        {
            Ok(registry) => {
                engine.replace_middleware_registry(registry)?;
                MiddlewareRegistryStatus::Synchronized
            }
            Err(error) => {
                warn!(error = %error, "Local policy middleware registry is degraded at startup");
                let middleware_registry =
                    openshell_supervisor_middleware::MiddlewareRegistry::connect_services(
                        openshell_supervisor_middleware_builtins::services(),
                        Vec::new(),
                    )
                    .await?;
                engine.replace_middleware_registry(middleware_registry)?;
                MiddlewareRegistryStatus::NeedsReconciliation
            }
        };
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
            middleware_registry_status,
            LoadedPolicyOrigin::LocalOverride,
            initial_snapshot
                .as_ref()
                .is_some_and(|snapshot| agent_proposals_enabled_from_settings(&snapshot.settings)),
            initial_extension_authentication_enabled,
        ));
    }

    // Gateway mode: consume the required stream bootstrap, then construct the
    // OPA engine. Configuration fetch polling is not a protocol fallback.
    if let (Some(id), Some(endpoint)) = (&sandbox_id, &openshell_endpoint) {
        info!(sandbox_id = %id, "Loading sandbox policy from supervisor bootstrap");
        let snapshot: openshell_core::grpc_client::SettingsPollResult = initial_snapshot
            .ok_or_else(|| miette::miette!("supervisor stream bootstrap is required"))?
            .into();
        let mut proto_policy = snapshot.policy.clone().ok_or_else(|| {
            miette::miette!("supervisor bootstrap omitted required sandbox policy")
        })?;

        // Ensure baseline filesystem paths are present for proxy-mode
        // sandboxes.  If the policy was enriched, sync the updated version
        // back to the gateway so users can see the effective policy.
        let enriched = enrich_proto_baseline_paths(&mut proto_policy);
        let sync_policy = proto_sync_payload_for_enriched_policy(&proto_policy, enriched);
        if sync_policy.is_some() {
            return Err(miette::miette!(
                "supervisor bootstrap policy omitted required baseline paths"
            ));
        }
        let loaded_policy_revision = LoadedPolicyRevision::from_snapshot(&snapshot);

        // Build OPA engine from baked-in rules + typed proto data.
        // In cluster mode, proxy networking is always enabled so OPA is
        // always required for allow/deny decisions.
        // The initial load uses pid=0 (no symlink resolution) because the
        // container hasn't started yet. After the entrypoint spawns, the
        // engine is rebuilt with the real PID for symlink resolution.
        info!("Creating OPA engine from proto policy data");
        let has_last_valid_policy = true;
        let engine = Arc::new(
            OpaEngine::from_proto(&proto_policy)
                .wrap_err("failed to install required sandbox policy from supervisor bootstrap")?,
        );

        // Install the in-process catalog before any external connection can
        // fail. A newly started sandbox must always be able to resolve built-in
        // bindings, even while operator-run services are unavailable.
        install_builtin_middleware_registry(&engine).await?;

        // Connect operator-registered middleware services. A connect/describe
        // failure keeps the built-in registry active so each request's
        // `on_error` policy governs matched traffic. The stream configuration loop
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
                    // are the ones the stream configuration loop later rotates in place.
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
            return Err(error).wrap_err(
                "failed to install required middleware runtime from supervisor bootstrap",
            );
        } else {
            MiddlewareRegistryStatus::Synchronized
        };
        let opa_engine = Some(engine);

        let policy = match SandboxPolicy::try_from(proto_policy.clone()) {
            Ok(policy) => policy,
            Err(e) => {
                report_initial_policy_failure(endpoint, id, Some(&loaded_policy_revision), &e)
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
                revision: Some(loaded_policy_revision),
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

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GatewayRuntimeFailureClass {
    PolicyValidation,
    TransparentTcpPrerequisite,
    MiddlewareRegistry,
}

impl GatewayRuntimeReloadError {
    #[cfg(test)]
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

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
struct FailedRuntimeRevision {
    config_revision: u64,
    policy_hash: String,
    failure_class: GatewayRuntimeFailureClass,
}

#[cfg(test)]
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

#[cfg(test)]
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
/// sync failed). That state must reconcile on the first successful streamed
/// snapshot. A
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

#[tonic::async_trait]
trait PolicyGatewayClient: Clone + Send + Sync + 'static {
    async fn refresh_installed_extension_credentials(&self) -> Result<()> {
        Ok(())
    }

    async fn extension_credentials_for(
        &self,
        _services: &[openshell_core::proto::SupervisorMiddlewareService],
    ) -> Result<std::collections::HashMap<String, openshell_extension_core::BearerTokenSlot>> {
        Ok(std::collections::HashMap::new())
    }
}

#[tonic::async_trait]
impl PolicyGatewayClient for openshell_core::grpc_client::CachedOpenShellClient {
    async fn refresh_installed_extension_credentials(&self) -> Result<()> {
        self.refresh_installed_extension_credentials().await
    }

    async fn extension_credentials_for(
        &self,
        services: &[openshell_core::proto::SupervisorMiddlewareService],
    ) -> Result<std::collections::HashMap<String, openshell_extension_core::BearerTokenSlot>> {
        self.extension_credentials_for(services).await
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

/// Background loop that applies complete desired-state snapshots delivered by
/// the authenticated supervisor stream.
struct StreamConfigLoopContext {
    endpoint: String,
    opa_engine: Arc<OpaEngine>,
    /// Source of the policy currently loaded into OPA. This distinguishes an
    /// explicit local-file override from an unbound gateway revision so the
    /// former is never replaced by a gateway-delivered policy snapshot.
    loaded_policy_origin: LoadedPolicyOrigin,
    entrypoint_pid: Arc<AtomicU32>,
    interval_secs: u64,
    ocsf_enabled: Arc<AtomicBool>,
    ocsf_schema_version: Arc<std::sync::Mutex<String>>,
    provider_credentials: ProviderCredentialState,
    policy_local_ctx: Option<Arc<openshell_supervisor_network::policy_local::PolicyLocalContext>>,
    agent_proposals: AgentProposals,
    middleware_registry_status: MiddlewareRegistryStatus,
    sidecar_control_publisher: Option<sidecar_control::Publisher>,
    workspace_tx: tokio::sync::watch::Sender<String>,
    extension_credentials: openshell_extension_core::ExtensionCredentialStore,
    middleware_connector: MiddlewareConnector,
    /// Immutable driver capability and startup substrate state.
    transparent_tcp: TransparentTcpReloadState,
    config_apply_rx: Option<
        tokio::sync::mpsc::Receiver<
            openshell_supervisor_process::supervisor_session::ConfigApplyRequest,
        >,
    >,
    /// The required stream bootstrap already initialized runtime state; this
    /// seeds exact revision tracking for subsequent complete snapshots.
    initial_stream_snapshot: Option<openshell_core::grpc_client::SettingsPollResult>,
}

type MiddlewareConnector = Arc<
    dyn Fn(
            Vec<openshell_core::proto::SupervisorMiddlewareService>,
            MiddlewareAuthentication,
        ) -> Pin<
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

/// Wait the configured refresh interval, but never past the point at which an
/// installed extension credential must be rotated.
fn next_refresh_delay(
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

#[allow(dead_code)]
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

#[cfg(test)]
fn policy_validation_failure_events(
    disposition: &PolicyValidationFailureDisposition,
    version: u32,
    policy_hash: &str,
    error: &str,
) -> [openshell_ocsf::OcsfEvent; 2] {
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

async fn receive_config_apply(
    receiver: &mut Option<
        tokio::sync::mpsc::Receiver<
            openshell_supervisor_process::supervisor_session::ConfigApplyRequest,
        >,
    >,
) -> Option<openshell_supervisor_process::supervisor_session::ConfigApplyRequest> {
    match receiver {
        Some(receiver) => receiver.recv().await,
        None => std::future::pending().await,
    }
}

fn sandbox_config_revision(
    snapshot: &openshell_core::grpc_client::SettingsPollResult,
) -> openshell_core::proto::ConfigSnapshotRevision {
    openshell_core::proto::ConfigSnapshotRevision {
        component: Some(
            openshell_core::proto::config_snapshot_revision::Component::SandboxConfig(
                openshell_core::proto::SandboxConfigRevision {
                    config_revision: snapshot.config_revision,
                    policy_version: snapshot.version,
                    policy_source: snapshot.policy_source.into(),
                    global_policy_version: snapshot.global_policy_version,
                    settings_revision: snapshot.settings_revision,
                },
            ),
        ),
    }
}

fn provider_config_revision(revision: u64) -> openshell_core::proto::ConfigSnapshotRevision {
    openshell_core::proto::ConfigSnapshotRevision {
        component: Some(
            openshell_core::proto::config_snapshot_revision::Component::ProviderEnvironment(
                revision,
            ),
        ),
    }
}

fn config_apply_result(
    component: openshell_core::proto::ConfigComponent,
    requested_revision: openshell_core::proto::ConfigSnapshotRevision,
    applied_revision: Option<openshell_core::proto::ConfigSnapshotRevision>,
    outcome: openshell_core::proto::ConfigApplyOutcome,
    failure: Option<(&str, String, bool)>,
) -> openshell_core::proto::ConfigComponentApplyResult {
    openshell_core::proto::ConfigComponentApplyResult {
        component: component.into(),
        requested_revision: Some(requested_revision),
        applied_revision,
        outcome: outcome.into(),
        failure: failure.map(|(code, message, retryable)| {
            openshell_core::proto::ConfigApplyFailure {
                code: code.to_string(),
                message: message.chars().take(1024).collect(),
                retryable,
            }
        }),
    }
}

#[allow(clippy::too_many_arguments)]
async fn apply_stream_config_request<C: PolicyGatewayClient>(
    ctx: &StreamConfigLoopContext,
    client: &C,
    request: openshell_supervisor_process::supervisor_session::ConfigApplyRequest,
    current_config_revision: &mut u64,
    current_stream_sandbox_revision: &mut Option<openshell_core::proto::ConfigSnapshotRevision>,
    current_provider_env_revision: &mut u64,
    current_policy_version: &mut u32,
    current_policy_hash: &mut String,
    current_middleware_services: &mut Vec<openshell_core::proto::SupervisorMiddlewareService>,
    current_extension_authentication_enabled: &mut bool,
    middleware_registry_status: &mut MiddlewareRegistryStatus,
    current_settings: &mut std::collections::HashMap<
        String,
        openshell_core::proto::EffectiveSetting,
    >,
    reloads_gateway_policy: bool,
    has_last_valid_policy: &mut bool,
) {
    use openshell_core::proto::{ConfigBootstrapResult, ConfigUpdateResult, config_update};
    use openshell_supervisor_process::supervisor_session::ConfigApplyRequest;

    match request {
        ConfigApplyRequest::Bootstrap {
            bootstrap,
            response,
        } => {
            let mut results = Vec::with_capacity(2);
            if let Some(snapshot) = bootstrap.provider_environment {
                results.push(apply_stream_provider_snapshot(
                    ctx,
                    snapshot,
                    current_provider_env_revision,
                ));
            }
            if let Some(snapshot) = bootstrap.sandbox_config {
                results.push(
                    apply_stream_sandbox_snapshot(
                        ctx,
                        client,
                        snapshot.into(),
                        current_config_revision,
                        current_stream_sandbox_revision,
                        current_policy_version,
                        current_policy_hash,
                        current_middleware_services,
                        current_extension_authentication_enabled,
                        middleware_registry_status,
                        current_settings,
                        reloads_gateway_policy,
                        has_last_valid_policy,
                    )
                    .await,
                );
            }
            let _ = response.send(ConfigBootstrapResult { results });
        }
        ConfigApplyRequest::Update { update, response } => {
            let result = match update.component {
                Some(config_update::Component::SandboxConfig(snapshot)) => {
                    apply_stream_sandbox_snapshot(
                        ctx,
                        client,
                        snapshot.into(),
                        current_config_revision,
                        current_stream_sandbox_revision,
                        current_policy_version,
                        current_policy_hash,
                        current_middleware_services,
                        current_extension_authentication_enabled,
                        middleware_registry_status,
                        current_settings,
                        reloads_gateway_policy,
                        has_last_valid_policy,
                    )
                    .await
                }
                Some(config_update::Component::ProviderEnvironment(snapshot)) => {
                    apply_stream_provider_snapshot(ctx, snapshot, current_provider_env_revision)
                }
                None => config_apply_result(
                    openshell_core::proto::ConfigComponent::Unspecified,
                    openshell_core::proto::ConfigSnapshotRevision::default(),
                    None,
                    openshell_core::proto::ConfigApplyOutcome::Unsupported,
                    Some((
                        "unsupported_component",
                        "configuration update has no supported component".to_string(),
                        false,
                    )),
                ),
            };
            let _ = response.send(ConfigUpdateResult {
                update_id: update.update_id,
                component_sequence: update.component_sequence,
                result: Some(result),
            });
        }
    }
}

fn apply_stream_provider_snapshot(
    ctx: &StreamConfigLoopContext,
    snapshot: openshell_core::proto::ProviderEnvironmentSnapshot,
    current_revision: &mut u64,
) -> openshell_core::proto::ConfigComponentApplyResult {
    use openshell_core::proto::{ConfigApplyOutcome, ConfigComponent};

    let requested_revision = provider_config_revision(snapshot.provider_env_revision);
    if snapshot.provider_env_revision == *current_revision {
        return config_apply_result(
            ConfigComponent::ProviderEnvironment,
            requested_revision,
            Some(requested_revision),
            ConfigApplyOutcome::IgnoredDuplicate,
            None,
        );
    }
    let result: openshell_core::grpc_client::ProviderEnvironmentResult = snapshot.into();
    let revision = result.provider_env_revision;
    match ctx.provider_credentials.install_bound_environment(
        revision,
        result.environment,
        result.credential_expires_at_ms,
        result.dynamic_credentials,
        result.static_credential_bindings,
        result.non_secret_environment_keys,
    ) {
        Ok(_) => {
            let child_env = ctx.provider_credentials.child_env_with_gcp_resolved();
            if let Some(publisher) = ctx.sidecar_control_publisher.as_ref() {
                publisher.publish_provider_env(revision, child_env);
            }
            *current_revision = revision;
            config_apply_result(
                ConfigComponent::ProviderEnvironment,
                requested_revision,
                Some(requested_revision),
                ConfigApplyOutcome::Applied,
                None,
            )
        }
        Err(error) => {
            let child_env = ctx.provider_credentials.child_env_with_gcp_resolved();
            if let Some(publisher) = ctx.sidecar_control_publisher.as_ref() {
                publisher.publish_provider_env(revision, child_env);
            }
            *current_revision = revision;
            config_apply_result(
                ConfigComponent::ProviderEnvironment,
                requested_revision,
                Some(requested_revision),
                ConfigApplyOutcome::Degraded,
                Some(("invalid_provider_environment", error.to_string(), false)),
            )
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn apply_stream_sandbox_snapshot<C: PolicyGatewayClient>(
    ctx: &StreamConfigLoopContext,
    client: &C,
    snapshot: openshell_core::grpc_client::SettingsPollResult,
    current_config_revision: &mut u64,
    current_stream_revision: &mut Option<openshell_core::proto::ConfigSnapshotRevision>,
    current_policy_version: &mut u32,
    current_policy_hash: &mut String,
    current_middleware_services: &mut Vec<openshell_core::proto::SupervisorMiddlewareService>,
    current_extension_authentication_enabled: &mut bool,
    middleware_registry_status: &mut MiddlewareRegistryStatus,
    current_settings: &mut std::collections::HashMap<
        String,
        openshell_core::proto::EffectiveSetting,
    >,
    reloads_gateway_policy: bool,
    has_last_valid_policy: &mut bool,
) -> openshell_core::proto::ConfigComponentApplyResult {
    use openshell_core::proto::{ConfigApplyOutcome, ConfigComponent, PolicySource};
    use std::sync::atomic::Ordering;

    let requested_revision = sandbox_config_revision(&snapshot);
    if snapshot.config_revision == *current_config_revision {
        return config_apply_result(
            ConfigComponent::SandboxConfig,
            requested_revision,
            Some(requested_revision),
            ConfigApplyOutcome::IgnoredDuplicate,
            None,
        );
    }

    let _ = ctx.workspace_tx.send(snapshot.workspace.clone());
    let middleware_credentials = if snapshot.extension_authentication_enabled {
        client
            .extension_credentials_for(&snapshot.supervisor_middleware_services)
            .await
            .unwrap_or_default()
    } else {
        std::collections::HashMap::new()
    };
    let registry_changed = *current_extension_authentication_enabled
        != snapshot.extension_authentication_enabled
        || middleware_registry_needs_rebuild(
            *middleware_registry_status,
            current_middleware_services,
            &snapshot.supervisor_middleware_services,
        );

    let outcome = if reloads_gateway_policy {
        let runtime_changed = *current_policy_hash != snapshot.policy_hash || registry_changed;
        if runtime_changed {
            match reload_gateway_policy_runtime(
                &ctx.opa_engine,
                snapshot.policy.as_ref(),
                ctx.entrypoint_pid.load(Ordering::Acquire),
                MiddlewareReloadContext {
                    desired_services: &snapshot.supervisor_middleware_services,
                    authentication: &MiddlewareAuthentication {
                        credentials: middleware_credentials,
                        enabled: snapshot.extension_authentication_enabled,
                    },
                    registry_changed,
                    connector: &ctx.middleware_connector,
                },
                ctx.transparent_tcp,
            )
            .await
            {
                Ok(()) => {
                    if let Some(policy) = snapshot.policy.as_ref() {
                        if let Some(policy_local_ctx) = ctx.policy_local_ctx.as_ref() {
                            policy_local_ctx.set_current_policy(policy.clone()).await;
                        }
                        if let Some(publisher) = ctx.sidecar_control_publisher.as_ref() {
                            publisher.publish_policy(
                                policy.clone(),
                                snapshot.policy_hash.clone(),
                                snapshot.config_revision,
                            );
                        }
                    }
                    *has_last_valid_policy = true;
                    current_policy_hash.clone_from(&snapshot.policy_hash);
                    current_middleware_services
                        .clone_from(&snapshot.supervisor_middleware_services);
                    *current_extension_authentication_enabled =
                        snapshot.extension_authentication_enabled;
                    *middleware_registry_status = MiddlewareRegistryStatus::Synchronized;
                    Ok(ConfigApplyOutcome::Applied)
                }
                Err(failure) => {
                    let failure_mode = snapshot.policy_validation_failure_mode;
                    let error = match apply_gateway_runtime_reload_failure(
                        &ctx.opa_engine,
                        failure,
                        failure_mode,
                        *has_last_valid_policy,
                        snapshot.version,
                    ) {
                        Ok(
                            GatewayRuntimeFailureDisposition::PolicyRejected { error, .. }
                            | GatewayRuntimeFailureDisposition::MiddlewareUnavailable { error }
                            | GatewayRuntimeFailureDisposition::TransparentTcpExpansionRejected {
                                error,
                                ..
                            },
                        ) => error,
                        Err(error) => error.to_string(),
                    };
                    Err(error)
                }
            }
        } else {
            Ok(ConfigApplyOutcome::Applied)
        }
    } else {
        reconcile_middleware_registry(
            &ctx.opa_engine,
            &ctx.middleware_connector,
            MiddlewareRegistryReconciliation {
                desired_services: &snapshot.supervisor_middleware_services,
                authentication: MiddlewareAuthentication {
                    credentials: middleware_credentials,
                    enabled: snapshot.extension_authentication_enabled,
                },
                registry_changed,
                extension_credentials: &ctx.extension_credentials,
                current_services: current_middleware_services,
                status: middleware_registry_status,
            },
        )
        .await;
        Ok(ConfigApplyOutcome::RetainedLocalOverride)
    };

    log_setting_changes(current_settings, &snapshot.settings);
    apply_ocsf_json_setting(&ctx.ocsf_enabled, &snapshot.settings);
    apply_ocsf_schema_version_setting(&ctx.ocsf_schema_version, &snapshot.settings);
    apply_agent_proposals_enabled(
        &ctx.agent_proposals,
        agent_proposals_enabled_from_settings(&snapshot.settings),
        "stream snapshot",
        Some(snapshot.config_revision),
        ctx.sidecar_control_publisher.as_ref(),
        skills::install_static_skills,
    );
    *current_settings = snapshot.settings;

    match outcome {
        Ok(outcome) => {
            *current_config_revision = snapshot.config_revision;
            if snapshot.version > 0 && snapshot.policy_source == PolicySource::Sandbox {
                *current_policy_version = snapshot.version;
            }
            let applied_revision = (outcome != ConfigApplyOutcome::RetainedLocalOverride)
                .then_some(requested_revision);
            if let Some(applied_revision) = applied_revision.as_ref() {
                *current_stream_revision = Some(*applied_revision);
            }
            config_apply_result(
                ConfigComponent::SandboxConfig,
                requested_revision,
                applied_revision,
                outcome,
                None,
            )
        }
        Err(error) => {
            let outcome = if snapshot.policy_validation_failure_mode
                == PolicyValidationFailureMode::RetainLastValid
                && *has_last_valid_policy
            {
                ConfigApplyOutcome::FailedRetainedLastKnownGood
            } else {
                ConfigApplyOutcome::FailedClosed
            };
            let applied_revision = (outcome == ConfigApplyOutcome::FailedRetainedLastKnownGood)
                .then_some(*current_stream_revision)
                .flatten();
            config_apply_result(
                ConfigComponent::SandboxConfig,
                requested_revision,
                applied_revision,
                outcome,
                Some(("runtime_apply_failed", error, true)),
            )
        }
    }
}

async fn run_stream_config_loop(ctx: StreamConfigLoopContext) -> Result<()> {
    let client = openshell_core::grpc_client::CachedOpenShellClient::connect_with_credentials(
        &ctx.endpoint,
        ctx.extension_credentials.clone(),
    )
    .await?;
    run_stream_config_loop_with_client(ctx, client).await
}

async fn run_stream_config_loop_with_client<C: PolicyGatewayClient>(
    mut ctx: StreamConfigLoopContext,
    client: C,
) -> Result<()> {
    let mut config_apply_rx = ctx.config_apply_rx.take();

    let initial_stream_snapshot = ctx
        .initial_stream_snapshot
        .take()
        .ok_or_else(|| miette::miette!("supervisor stream bootstrap is required"))?;
    let mut current_config_revision: u64 = initial_stream_snapshot.config_revision;
    let mut current_stream_sandbox_revision = ctx
        .loaded_policy_origin
        .allows_gateway_policy_reload()
        .then(|| sandbox_config_revision(&initial_stream_snapshot));
    let mut current_provider_env_revision: u64 = ctx.provider_credentials.snapshot().revision;
    let mut current_policy_version: u32 = initial_stream_snapshot.version;
    let mut current_policy_hash = initial_stream_snapshot.policy_hash.clone();
    let mut current_middleware_services = initial_stream_snapshot
        .supervisor_middleware_services
        .clone();
    let mut current_extension_authentication_enabled =
        initial_stream_snapshot.extension_authentication_enabled;
    let mut middleware_registry_status = ctx.middleware_registry_status;
    let mut current_settings: std::collections::HashMap<
        String,
        openshell_core::proto::EffectiveSetting,
    > = initial_stream_snapshot.settings.clone();
    let reloads_gateway_policy = ctx.loaded_policy_origin.allows_gateway_policy_reload();
    let mut has_last_valid_policy = ctx.loaded_policy_origin.has_last_valid_policy();
    {
        let snapshot = &initial_stream_snapshot;
        let _ = ctx.workspace_tx.send(snapshot.workspace.clone());
        apply_ocsf_json_setting(&ctx.ocsf_enabled, &snapshot.settings);
        apply_ocsf_schema_version_setting(&ctx.ocsf_schema_version, &snapshot.settings);
    }

    let interval = Duration::from_secs(ctx.interval_secs);
    loop {
        let delay = next_refresh_delay(&ctx.extension_credentials, interval);
        tokio::select! {
            request = receive_config_apply(&mut config_apply_rx) => {
                let Some(request) = request else {
                    return Err(miette::miette!("stream configuration apply channel closed"));
                };
                apply_stream_config_request(
                    &ctx,
                    &client,
                    request,
                    &mut current_config_revision,
                    &mut current_stream_sandbox_revision,
                    &mut current_provider_env_revision,
                    &mut current_policy_version,
                    &mut current_policy_hash,
                    &mut current_middleware_services,
                    &mut current_extension_authentication_enabled,
                    &mut middleware_registry_status,
                    &mut current_settings,
                    reloads_gateway_policy,
                    &mut has_last_valid_policy,
                ).await;
            }
            () = tokio::time::sleep(delay) => {
                if current_extension_authentication_enabled
                    && let Err(error) = client.refresh_installed_extension_credentials().await
                {
                    warn!(error = %error, "Extension credential refresh failed");
                }
            }
        }
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

fn apply_ocsf_schema_version_setting(
    version: &std::sync::Mutex<String>,
    settings: &std::collections::HashMap<String, openshell_core::proto::EffectiveSetting>,
) {
    let new_version = extract_string_setting(settings, "ocsf_schema_version").unwrap_or_default();
    if let Ok(mut current) = version.lock()
        && *current != new_version
    {
        info!(
            ocsf_schema_version = %new_version,
            "OCSF schema version target changed"
        );
        *current = new_version;
    }
}

fn extract_string_setting(
    settings: &std::collections::HashMap<String, openshell_core::proto::EffectiveSetting>,
    key: &str,
) -> Option<String> {
    use openshell_core::proto::setting_value;
    settings
        .get(key)
        .and_then(|es| es.value.as_ref())
        .and_then(|sv| sv.value.as_ref())
        .and_then(|v| match v {
            setting_value::Value::StringValue(s) => Some(s.clone()),
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
    dead_code,
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
    async fn sidecar_control_provider_env_update_orders_by_generation() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let provider_credentials = ProviderCredentialState::from_child_env_snapshot(
            u64::MAX,
            std::collections::HashMap::from([("TOKEN".to_string(), "old".to_string())]),
        );
        let agent_proposals = AgentProposals::new(true);
        let handle = spawn_sidecar_control_update_watcher(
            rx,
            provider_credentials.clone(),
            agent_proposals.clone(),
            Arc::new(tokio::sync::Mutex::new(None)),
            10,
        );

        tx.send(sidecar_control::ControlUpdate::ProviderEnv {
            revision: 1,
            generation: 11,
            provider_child_env: std::collections::HashMap::from([(
                "TOKEN".to_string(),
                "new".to_string(),
            )]),
        })
        .unwrap();

        timeout(Duration::from_secs(1), async {
            loop {
                if provider_credentials.snapshot().revision == 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let snapshot = provider_credentials.snapshot();
        assert_eq!(snapshot.revision, 1);
        assert_eq!(
            snapshot.child_env.get("TOKEN").map(String::as_str),
            Some("new")
        );

        tx.send(sidecar_control::ControlUpdate::ProviderEnv {
            revision: 2,
            generation: 11,
            provider_child_env: std::collections::HashMap::from([(
                "TOKEN".to_string(),
                "duplicate-generation".to_string(),
            )]),
        })
        .unwrap();
        tx.send(sidecar_control::ControlUpdate::AgentProposals {
            enabled: false,
            config_revision: 1,
        })
        .unwrap();
        timeout(Duration::from_secs(1), async {
            while agent_proposals.enabled() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            provider_credentials
                .snapshot()
                .child_env
                .get("TOKEN")
                .map(String::as_str),
            Some("new")
        );

        tx.send(sidecar_control::ControlUpdate::ProviderEnv {
            revision: 2,
            generation: 12,
            provider_child_env: std::collections::HashMap::from([(
                "TOKEN".to_string(),
                "newest".to_string(),
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

        tx.send(sidecar_control::ControlUpdate::ProviderEnv {
            revision: u64::MAX,
            generation: 11,
            provider_child_env: std::collections::HashMap::from([(
                "TOKEN".to_string(),
                "stale".to_string(),
            )]),
        })
        .unwrap();
        tx.send(sidecar_control::ControlUpdate::AgentProposals {
            enabled: true,
            config_revision: 2,
        })
        .unwrap();
        timeout(Duration::from_secs(1), async {
            while !agent_proposals.enabled() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let snapshot = provider_credentials.snapshot();
        assert_eq!(snapshot.revision, 2);
        assert_eq!(
            snapshot.child_env.get("TOKEN").map(String::as_str),
            Some("newest")
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
            0,
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
        // Cluster sandboxes keep proxy mode enabled so egress is evaluated by
        // the network policy engine.
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
            settings_revision: 0,
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
    struct ScriptedPolicyGateway;

    #[tonic::async_trait]
    impl PolicyGatewayClient for ScriptedPolicyGateway {}

    fn policy_poll_test_context(
        opa_engine: Arc<OpaEngine>,
        loaded_policy_origin: LoadedPolicyOrigin,
        middleware_connector: MiddlewareConnector,
    ) -> StreamConfigLoopContext {
        let (workspace_tx, _workspace_rx) = tokio::sync::watch::channel(String::new());
        StreamConfigLoopContext {
            endpoint: String::new(),
            opa_engine,
            loaded_policy_origin,
            entrypoint_pid: Arc::new(AtomicU32::new(0)),
            interval_secs: 0,
            ocsf_enabled: Arc::new(AtomicBool::new(false)),
            ocsf_schema_version: Arc::new(std::sync::Mutex::new(String::new())),
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
            middleware_connector,
            transparent_tcp: TransparentTcpReloadState::default(),
            config_apply_rx: None,
            initial_stream_snapshot: None,
        }
    }

    #[tokio::test]
    async fn stream_provider_snapshot_applies_without_fetching() {
        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        let ctx = policy_poll_test_context(
            engine,
            LoadedPolicyOrigin::Gateway {
                revision: None,
                has_last_valid_policy: true,
            },
            default_middleware_connector(),
        );
        let mut revision = 0;
        let result = apply_stream_provider_snapshot(
            &ctx,
            openshell_core::proto::ProviderEnvironmentSnapshot {
                provider_env_revision: 17,
                values: vec![openshell_core::proto::ProviderEnvironmentValue {
                    name: "REGION".to_string(),
                    value: "west".to_string(),
                    classification:
                        openshell_core::proto::ProviderEnvironmentValueClassification::NonSecret
                            .into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
            &mut revision,
        );

        assert_eq!(revision, 17);
        assert_eq!(
            openshell_core::proto::ConfigApplyOutcome::try_from(result.outcome).unwrap(),
            openshell_core::proto::ConfigApplyOutcome::Applied
        );
        assert!(
            ctx.provider_credentials
                .snapshot()
                .child_env
                .contains_key("REGION")
        );
    }

    #[tokio::test]
    async fn stream_sandbox_snapshot_applies_without_fetching() {
        let initial = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let desired = settings_poll_result(
            Some(proto_policy_fixture()),
            2,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        let ctx = policy_poll_test_context(
            engine,
            LoadedPolicyOrigin::Gateway {
                revision: Some(LoadedPolicyRevision::from_snapshot(&initial)),
                has_last_valid_policy: true,
            },
            default_middleware_connector(),
        );
        let client = ScriptedPolicyGateway;
        let mut config_revision = initial.config_revision;
        let mut stream_revision = Some(sandbox_config_revision(&initial));
        let mut policy_version = initial.version;
        let mut policy_hash = initial.policy_hash;
        let mut middleware_services = Vec::new();
        let mut extension_authentication_enabled = false;
        let mut middleware_registry_status = MiddlewareRegistryStatus::Synchronized;
        let mut settings = std::collections::HashMap::new();
        let mut has_last_valid_policy = true;

        let result = apply_stream_sandbox_snapshot(
            &ctx,
            &client,
            desired.clone(),
            &mut config_revision,
            &mut stream_revision,
            &mut policy_version,
            &mut policy_hash,
            &mut middleware_services,
            &mut extension_authentication_enabled,
            &mut middleware_registry_status,
            &mut settings,
            true,
            &mut has_last_valid_policy,
        )
        .await;

        assert_eq!(config_revision, desired.config_revision);
        assert_eq!(policy_version, desired.version);
        assert_eq!(policy_hash, desired.policy_hash);
        assert_eq!(
            openshell_core::proto::ConfigApplyOutcome::try_from(result.outcome).unwrap(),
            openshell_core::proto::ConfigApplyOutcome::Applied
        );
    }

    #[tokio::test]
    async fn revision_three_stream_applies_provider_update() {
        let initial = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        let mut ctx = policy_poll_test_context(
            engine,
            LoadedPolicyOrigin::Gateway {
                revision: Some(LoadedPolicyRevision::from_snapshot(&initial)),
                has_last_valid_policy: true,
            },
            default_middleware_connector(),
        );
        ctx.initial_stream_snapshot = Some(initial);
        let (config_apply_tx, config_apply_rx) = tokio::sync::mpsc::channel(1);
        ctx.config_apply_rx = Some(config_apply_rx);
        let client = ScriptedPolicyGateway;

        let handle = tokio::spawn(run_stream_config_loop_with_client(ctx, client));
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        config_apply_tx
            .send(
                openshell_supervisor_process::supervisor_session::ConfigApplyRequest::Update {
                    update: openshell_core::proto::ConfigUpdate {
                        update_id: "provider-2".to_string(),
                        component_sequence: 1,
                        component: Some(
                            openshell_core::proto::config_update::Component::ProviderEnvironment(
                                openshell_core::proto::ProviderEnvironmentSnapshot {
                                    provider_env_revision: 2,
                                    ..Default::default()
                                },
                            ),
                        ),
                    },
                    response: response_tx,
                },
            )
            .await
            .unwrap();
        timeout(Duration::from_secs(1), response_rx)
            .await
            .expect("stream update timed out")
            .expect("stream update responder stopped");

        handle.abort();
    }

    #[tokio::test]
    async fn failed_stream_snapshot_remains_retryable() {
        let initial = settings_poll_result(
            Some(proto_policy_fixture()),
            1,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let mut desired = settings_poll_result(
            Some(proto_policy_fixture()),
            2,
            openshell_core::proto::PolicySource::Sandbox,
        );
        desired.policy_validation_failure_mode = PolicyValidationFailureMode::RetainLastValid;
        desired.supervisor_middleware_services =
            vec![openshell_core::proto::SupervisorMiddlewareService {
                name: "unavailable-guard".into(),
                grpc_endpoint: "http://127.0.0.1:1".into(),
                max_payload_bytes: 1024,
                ..Default::default()
            }];
        let engine =
            Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).expect("build OPA engine"));
        install_builtin_middleware_registry(&engine)
            .await
            .expect("install built-in middleware registry");
        let ctx = policy_poll_test_context(
            engine,
            LoadedPolicyOrigin::Gateway {
                revision: Some(LoadedPolicyRevision::from_snapshot(&initial)),
                has_last_valid_policy: true,
            },
            default_middleware_connector(),
        );
        let client = ScriptedPolicyGateway;
        let mut config_revision = initial.config_revision;
        let initial_revision = sandbox_config_revision(&initial);
        let mut stream_revision = Some(initial_revision);
        let mut policy_version = initial.version;
        let mut policy_hash = initial.policy_hash.clone();
        let mut middleware_services = Vec::new();
        let mut extension_authentication_enabled = false;
        let mut middleware_registry_status = MiddlewareRegistryStatus::Synchronized;
        let mut settings = std::collections::HashMap::new();
        let mut has_last_valid_policy = true;

        let result = apply_stream_sandbox_snapshot(
            &ctx,
            &client,
            desired,
            &mut config_revision,
            &mut stream_revision,
            &mut policy_version,
            &mut policy_hash,
            &mut middleware_services,
            &mut extension_authentication_enabled,
            &mut middleware_registry_status,
            &mut settings,
            true,
            &mut has_last_valid_policy,
        )
        .await;

        assert_eq!(config_revision, initial.config_revision);
        assert_eq!(policy_version, initial.version);
        assert_eq!(policy_hash, initial.policy_hash);
        assert_eq!(result.applied_revision, Some(initial_revision));
        assert_eq!(
            openshell_core::proto::ConfigApplyOutcome::try_from(result.outcome).unwrap(),
            openshell_core::proto::ConfigApplyOutcome::FailedRetainedLastKnownGood
        );
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
