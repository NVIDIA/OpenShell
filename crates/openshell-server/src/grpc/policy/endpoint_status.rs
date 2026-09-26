// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Passive network results for configured tool server endpoints.

use super::{
    apply_effective_policy_context, canonical_policy_record_identity,
    compute_provider_env_revision_with_catalog_and_policy_bindings,
    current_effective_policy_for_sandbox, decode_policy_from_global_settings,
    deterministic_policy_hash, load_global_settings, policy_static_credential_endpoint_bindings,
};
use crate::ServerState;
use crate::compute::MutationScope;
use crate::persistence::{
    ObjectCursor, ObjectId, ObjectListQuery, ObjectWorkspace, PersistenceError,
};
use crate::policy_store::PolicyStoreExt;
use crate::provider_profile_sources::EffectiveProviderProfileCatalog;
use crate::supervisor_owner::{OWNER_TTL, SupervisorOwnerIndex};
use crate::supervisor_session::EndpointReportCursor;
use futures::TryStreamExt;
use openshell_core::GetResourceVersion;
use openshell_core::endpoint_status::initial_endpoint_status;
use openshell_core::mcp::is_mcp_protocol;
use openshell_core::proto::{
    EndpointResult, EndpointStatus, PolicySource, ReportEndpointStatusRequest,
    ReportEndpointStatusResponse, Sandbox, SandboxPolicy as ProtoSandboxPolicy, SandboxStatus,
};
use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::warn;

const ENDPOINT_STARTUP_RECONCILIATION_PAGE_SIZE: u32 = 100;
/// Sandboxes reconciled at once, matching the four-connection mutation lock
/// pool.
const ENDPOINT_STARTUP_RECONCILIATION_CONCURRENCY: usize = 4;
/// Guarded attempts per sandbox before a concurrent write fails startup.
const ENDPOINT_STARTUP_RECONCILIATION_ATTEMPTS: usize = 5;
const ENDPOINT_DISCONNECT_RETRY_INITIAL_BACKOFF: std::time::Duration =
    std::time::Duration::from_millis(100);
const ENDPOINT_DISCONNECT_RETRY_MAX_BACKOFF: std::time::Duration =
    std::time::Duration::from_secs(5);

#[derive(Clone, Debug, PartialEq)]
struct ExpectedEndpoint {
    // Credential attribution is derived from the effective policy so a
    // sandbox cannot claim credential failure for an unauthenticated endpoint.
    provider_credentialed: bool,
    // The public status comes only from the validated policy endpoint,
    // never from observed request data or supervisor-supplied text.
    status: EndpointStatus,
}

struct EndpointContext {
    policy_hash: String,
    provider_env_revision: u64,
    endpoints: BTreeMap<String, ExpectedEndpoint>,
}

/// Accept the last observed result for each configured tool server endpoint.
///
/// Addresses and identifiers come from the authoritative policy. The supervisor
/// supplies only typed results, so request data and upstream text cannot enter status.
pub(in crate::grpc) async fn handle_report_endpoint_status(
    state: &Arc<ServerState>,
    request: Request<ReportEndpointStatusRequest>,
) -> Result<Response<ReportEndpointStatusResponse>, Status> {
    let sandbox_id = request.get_ref().sandbox_id.clone();
    crate::auth::guard::enforce_sandbox_scope(&request, &sandbox_id)?;
    let req = request.into_inner();
    if let Some(owner) =
        crate::supervisor_session::remote_supervisor_owner(state, &sandbox_id).await?
    {
        let response =
            crate::supervisor_session::forward_endpoint_status_to_owner(state, &owner, req).await?;
        return Ok(Response::new(response));
    }
    handle_report_endpoint_status_inner(state, req).await
}

pub(in crate::grpc) async fn handle_peer_report_endpoint_status(
    state: &Arc<ServerState>,
    request: Request<ReportEndpointStatusRequest>,
) -> Result<Response<ReportEndpointStatusResponse>, Status> {
    if !matches!(
        request
            .extensions()
            .get::<crate::auth::principal::Principal>(),
        Some(crate::auth::principal::Principal::Peer(_))
    ) {
        return Err(Status::permission_denied(
            "gateway peer principal is required",
        ));
    }
    handle_report_endpoint_status_inner(state, request.into_inner()).await
}

async fn handle_report_endpoint_status_inner(
    state: &Arc<ServerState>,
    req: ReportEndpointStatusRequest,
) -> Result<Response<ReportEndpointStatusResponse>, Status> {
    if req.sandbox_id.is_empty() {
        return Err(Status::invalid_argument("sandbox_id is required"));
    }
    if req.policy_hash.is_empty() {
        return Err(Status::invalid_argument("policy_hash is required"));
    }
    if req.supervisor_session_id.is_empty() {
        return Err(Status::invalid_argument(
            "supervisor_session_id is required",
        ));
    }
    if req.report_sequence == 0 {
        return Err(Status::invalid_argument("report_sequence is required"));
    }

    // Session validation, configuration derivation, and persistence share the
    // sandbox mutation boundary. A newly registered supervisor can therefore
    // invalidate its predecessor before any stale report reaches the CAS.
    let Some(_mutation_guard) = state
        .compute
        .sandbox_mutation_guard_by_id(&req.sandbox_id)
        .await
        .map_err(|error| {
            super::super::persistence_error_to_status(
                error,
                "acquire endpoint status mutation lock",
            )
        })?
    else {
        return Err(Status::not_found("sandbox not found"));
    };
    if !state
        .supervisor_sessions
        .is_endpoint_status_authority(&req.sandbox_id, &req.supervisor_session_id)
    {
        return Err(Status::permission_denied(
            "tool server endpoint status requires the active supervisor session",
        ));
    }
    let sandbox = state
        .store
        .get_message::<Sandbox>(&req.sandbox_id)
        .await
        .map_err(|error| Status::internal(format!("fetch sandbox failed: {error}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let context = active_endpoint_context(state.as_ref(), &sandbox).await?;
    if req.policy_hash != context.policy_hash
        || req.provider_env_revision != context.provider_env_revision
    {
        return Err(Status::failed_precondition(
            "tool server endpoint status revisions do not match the current sandbox configuration",
        ));
    }

    let current_cursor = state
        .supervisor_sessions
        .endpoint_report_cursor(&req.sandbox_id, &req.supervisor_session_id);
    let report_digest: [u8; 32] = Sha256::digest(req.encode_to_vec()).into();
    if let Some(cursor) = current_cursor.as_ref() {
        if req.report_sequence < cursor.report_sequence {
            return Err(Status::failed_precondition(
                "tool server endpoint report sequence is older than the current session cursor",
            ));
        }
        if req.report_sequence == cursor.report_sequence {
            if cursor.policy_hash != req.policy_hash
                || cursor.provider_env_revision != req.provider_env_revision
                || cursor.report_digest != report_digest
            {
                return Err(Status::invalid_argument(
                    "a tool server endpoint report sequence must reuse the identical request",
                ));
            }
            // The prior write committed but its acknowledgement was lost. Do
            // not fabricate observation times by reconciling the same batch.
            return Ok(Response::new(ReportEndpointStatusResponse {}));
        }
    }
    // Sequences belong to the authenticated session, not configuration values.
    // Gaps represent snapshots superseded by an inventory reset; accepting a
    // newer complete snapshot retires every lower sequence, including an RPC
    // cancelled after dispatch or a report from an earlier equal-valued epoch.

    let (reports, observed_endpoint_ids) = validate_endpoint_snapshot(
        &req.observations,
        &req.observed_endpoint_ids,
        &context.endpoints,
    )?;
    validate_endpoint_observation_markers(&sandbox, &reports, &observed_endpoint_ids)?;
    let now = openshell_core::time::timestamp_from_system_time(std::time::SystemTime::now())
        .map_err(|error| Status::internal(format!("create endpoint report timestamp: {error}")))?;
    let expected_resource_version = sandbox.get_resource_version();
    let updated = state
        .store
        .update_message_cas::<Sandbox, _>(&req.sandbox_id, expected_resource_version, |sandbox| {
            reconcile_endpoint_statuses(sandbox, &reports, &observed_endpoint_ids, &now);
        })
        .await
        .map_err(|error| {
            super::super::persistence_error_to_status(error, "persist tool server endpoint status")
        })?;

    state.sandbox_index.update_from_sandbox(&updated);
    state.sandbox_watch_bus.notify(&req.sandbox_id);
    if !state.supervisor_sessions.commit_endpoint_report_cursor(
        &req.sandbox_id,
        &req.supervisor_session_id,
        EndpointReportCursor {
            policy_hash: req.policy_hash,
            provider_env_revision: req.provider_env_revision,
            report_sequence: req.report_sequence,
            report_digest,
        },
    ) {
        return Err(Status::permission_denied(
            "tool server endpoint status supervisor session was replaced while persisting the report",
        ));
    }

    Ok(Response::new(ReportEndpointStatusResponse {}))
}

async fn current_endpoint_context(
    state: &ServerState,
    sandbox: &Sandbox,
) -> Result<EndpointContext, Status> {
    let workspace = sandbox.object_workspace();
    let catalog = state
        .provider_profile_sources
        .snapshot_catalog(state.store.as_ref(), workspace)
        .await?;
    let policy = current_effective_policy_for_sandbox(
        state,
        &catalog,
        workspace,
        sandbox,
        sandbox.object_id(),
    )
    .await?;
    derive_endpoint_context(state, sandbox, &catalog, policy).await
}

async fn active_endpoint_context(
    state: &ServerState,
    sandbox: &Sandbox,
) -> Result<EndpointContext, Status> {
    let version = sandbox.current_policy_version();
    if version == 0 {
        // Before the first load acknowledgement there is no active revision.
        // The effective policy is the candidate sent to the supervisor, so it
        // is the only configuration against which the initial session can be
        // reset and subsequently report.
        return current_endpoint_context(state, sandbox).await;
    }

    // A newer stored policy may still be pending while the supervisor runs the
    // acknowledged revision. Endpoint observations belong to that active runtime
    // configuration until another load acknowledgement commits the transition.
    endpoint_context_for_loaded_policy(state, sandbox, i64::from(version)).await
}

async fn endpoint_context_for_loaded_policy(
    state: &ServerState,
    sandbox: &Sandbox,
    version: i64,
) -> Result<EndpointContext, Status> {
    let workspace = sandbox.object_workspace();
    let catalog = state
        .provider_profile_sources
        .snapshot_catalog(state.store.as_ref(), workspace)
        .await?;
    let global_settings = load_global_settings(state.store.as_ref()).await?;
    let global_policy = decode_policy_from_global_settings(&global_settings)?;
    endpoint_context_for_loaded_policy_with_inputs(
        state,
        sandbox,
        version,
        &catalog,
        global_policy.as_ref(),
    )
    .await
}

async fn endpoint_context_for_loaded_policy_with_inputs(
    state: &ServerState,
    sandbox: &Sandbox,
    version: i64,
    catalog: &EffectiveProviderProfileCatalog,
    global_policy: Option<&ProtoSandboxPolicy>,
) -> Result<EndpointContext, Status> {
    let workspace = sandbox.object_workspace();
    let provider_names = sandbox
        .spec
        .as_ref()
        .map(|spec| spec.providers.clone())
        .unwrap_or_default();
    let policy = if let Some(global_policy) = global_policy {
        apply_effective_policy_context(
            state,
            catalog,
            workspace,
            &provider_names,
            global_policy.clone(),
            PolicySource::Global,
        )
        .await?
    } else {
        let record = state
            .store
            .get_policy_by_version(sandbox.object_id(), version)
            .await
            .map_err(|error| Status::internal(format!("fetch policy revision failed: {error}")))?
            .ok_or_else(|| Status::not_found("policy revision not found"))?;
        let policy = canonical_policy_record_identity(&record)?.0;
        apply_effective_policy_context(
            state,
            catalog,
            workspace,
            &provider_names,
            policy,
            PolicySource::Sandbox,
        )
        .await?
    };
    derive_endpoint_context(state, sandbox, catalog, policy).await
}

async fn derive_endpoint_context(
    state: &ServerState,
    sandbox: &Sandbox,
    catalog: &EffectiveProviderProfileCatalog,
    policy: ProtoSandboxPolicy,
) -> Result<EndpointContext, Status> {
    let workspace = sandbox.object_workspace();
    let provider_names = sandbox
        .spec
        .as_ref()
        .map(|spec| spec.providers.clone())
        .unwrap_or_default();
    let bindings = policy_static_credential_endpoint_bindings(Some(&policy))?;
    let provider_env_revision = compute_provider_env_revision_with_catalog_and_policy_bindings(
        state.store.as_ref(),
        catalog,
        workspace,
        &provider_names,
        &bindings,
    )
    .await?;

    Ok(EndpointContext {
        policy_hash: deterministic_policy_hash(&policy),
        provider_env_revision,
        endpoints: expected_endpoint_statuses(&policy),
    })
}

fn unknown_endpoint_reports(
    endpoints: &BTreeMap<String, ExpectedEndpoint>,
) -> BTreeMap<String, EndpointStatus> {
    endpoints
        .iter()
        .map(|(endpoint_id, endpoint)| {
            (
                endpoint_id.clone(),
                EndpointStatus {
                    last_result: EndpointResult::NoObservedExchange as i32,
                    ..endpoint.status.clone()
                },
            )
        })
        .collect()
}

/// Reset endpoint evidence before acknowledging a newly authenticated supervisor.
pub async fn reset_endpoint_status_for_supervisor_session(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    supervisor_session_id: &str,
) -> Result<(), Status> {
    let Some(_mutation_guard) = state
        .compute
        .sandbox_mutation_guard_by_id(sandbox_id)
        .await
        .map_err(|error| {
            super::super::persistence_error_to_status(
                error,
                "acquire endpoint status mutation lock",
            )
        })?
    else {
        return Err(Status::not_found("sandbox not found"));
    };
    if !state
        .supervisor_sessions
        .is_current_session(sandbox_id, supervisor_session_id)
    {
        return Err(Status::failed_precondition(
            "supervisor session was replaced before endpoint status reset",
        ));
    }
    let sandbox = state
        .store
        .get_message::<Sandbox>(sandbox_id)
        .await
        .map_err(|error| Status::internal(format!("fetch sandbox failed: {error}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let context = active_endpoint_context(state.as_ref(), &sandbox).await?;
    let reports = unknown_endpoint_reports(&context.endpoints);
    let now = openshell_core::time::timestamp_from_system_time(std::time::SystemTime::now())
        .map_err(|error| Status::internal(format!("create endpoint reset timestamp: {error}")))?;
    let expected_resource_version = sandbox.get_resource_version();
    let updated = state
        .store
        .update_message_cas::<Sandbox, _>(sandbox_id, expected_resource_version, |sandbox| {
            reconcile_endpoint_statuses(sandbox, &reports, &HashSet::new(), &now);
        })
        .await
        .map_err(|error| {
            super::super::persistence_error_to_status(
                error,
                "reset tool server endpoint status for supervisor",
            )
        })?;
    state.sandbox_index.update_from_sandbox(&updated);
    state.sandbox_watch_bus.notify(sandbox_id);
    Ok(())
}

/// Reset endpoint observations after the active supervisor stream disconnects.
///
/// A concurrently registered replacement owns its own pre-acknowledgement
/// reset, so this path leaves that session's cursor alone. A replacement that
/// already exists is detected before the mutation guard, so the reset does not
/// wait behind other mutations of the sandbox.
pub async fn reset_endpoint_status_after_supervisor_disconnect(
    state: &Arc<ServerState>,
    sandbox_id: &str,
) -> Result<(), Status> {
    if disconnect_reset_is_superseded(state, sandbox_id).await? {
        return Ok(());
    }
    let Some(_mutation_guard) = state
        .compute
        .sandbox_mutation_guard_by_id(sandbox_id)
        .await
        .map_err(|error| {
            super::super::persistence_error_to_status(
                error,
                "acquire endpoint status mutation lock",
            )
        })?
    else {
        return Err(Status::not_found("sandbox not found"));
    };
    // Re-check under the guard: a replacement's pre-acknowledgement reset runs
    // under the same sandbox key, and resetting after it would wipe the
    // replacement's fresh evidence.
    if disconnect_reset_is_superseded(state, sandbox_id).await? {
        return Ok(());
    }
    let sandbox = state
        .store
        .get_message::<Sandbox>(sandbox_id)
        .await
        .map_err(|error| Status::internal(format!("fetch sandbox failed: {error}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let context = active_endpoint_context(state.as_ref(), &sandbox).await?;
    let reports = unknown_endpoint_reports(&context.endpoints);
    let now = openshell_core::time::timestamp_from_system_time(std::time::SystemTime::now())
        .map_err(|error| Status::internal(format!("create endpoint reset timestamp: {error}")))?;
    let expected_resource_version = sandbox.get_resource_version();
    let updated = state
        .store
        .update_message_cas::<Sandbox, _>(sandbox_id, expected_resource_version, |sandbox| {
            reconcile_endpoint_statuses(sandbox, &reports, &HashSet::new(), &now);
        })
        .await
        .map_err(|error| {
            super::super::persistence_error_to_status(
                error,
                "reset tool server endpoint status after disconnect",
            )
        })?;
    state.sandbox_index.update_from_sandbox(&updated);
    state.sandbox_watch_bus.notify(sandbox_id);
    Ok(())
}

/// Retry disconnect invalidation until it is durable or a replacement session
/// takes ownership.
///
/// A transient storage failure must not leave a previously successful endpoint
/// usable after its observation authority has disappeared. Gateway restart is
/// covered separately by startup reconciliation before listeners are bound.
pub async fn retry_endpoint_status_after_supervisor_disconnect(
    state: Arc<ServerState>,
    sandbox_id: String,
) {
    let mut backoff = ENDPOINT_DISCONNECT_RETRY_INITIAL_BACKOFF;
    loop {
        match reset_endpoint_status_after_supervisor_disconnect(&state, &sandbox_id).await {
            Ok(()) => return,
            Err(error) if error.code() == tonic::Code::NotFound => return,
            Err(error) => {
                warn!(
                    sandbox_id = %sandbox_id,
                    error = %error,
                    retry_after_ms = backoff.as_millis(),
                    "supervisor session: retrying tool server endpoint-status invalidation"
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(ENDPOINT_DISCONNECT_RETRY_MAX_BACKOFF);
            }
        }
    }
}

/// Invalidate endpoint results left by sessions from an earlier gateway process.
///
/// Supervisor sessions are intentionally process-local. This reconciliation
/// runs before gateway listeners are bound. A fresh shared owner preserves its
/// evidence; records without one are reset so stale success is never served.
///
/// Each sandbox is reset under its own mutation guard, so other replicas keep
/// mutating unrelated sandboxes during the scan. Keyset paging keeps the scan
/// stable when sandboxes are deleted mid-scan.
pub async fn invalidate_endpoint_status_on_startup(state: &Arc<ServerState>) -> Result<(), Status> {
    let mut cursor: Option<ObjectCursor> = None;
    loop {
        let page = state
            .store
            .list_message_page::<Sandbox>(
                ObjectListQuery::AllWorkspaces,
                cursor.as_ref(),
                ENDPOINT_STARTUP_RECONCILIATION_PAGE_SIZE,
            )
            .await
            .map_err(|error| {
                Status::internal(format!(
                    "list sandboxes for tool server endpoint-status startup reconciliation failed: {error}"
                ))
            })?;
        // Each future holds at most its own sandbox guard and never waits on
        // another, so running them in one task cannot deadlock.
        futures::stream::iter(
            page.messages
                .iter()
                .filter(|sandbox| has_endpoint_status(sandbox))
                .map(Ok::<_, Status>),
        )
        .try_for_each_concurrent(ENDPOINT_STARTUP_RECONCILIATION_CONCURRENCY, |candidate| {
            invalidate_sandbox_endpoint_status_on_startup(state, candidate)
        })
        .await?;
        let Some(next_cursor) = page.next_cursor else {
            return Ok(());
        };
        cursor = Some(next_cursor);
    }
}

async fn invalidate_sandbox_endpoint_status_on_startup(
    state: &Arc<ServerState>,
    candidate: &Sandbox,
) -> Result<(), Status> {
    // A live owner keeps its evidence, so it costs no guard.
    if has_fresh_shared_owner(state, candidate.object_id()).await? {
        return Ok(());
    }
    retry_startup_reconciliation(|| invalidate_sandbox_endpoint_status_once(state, candidate)).await
}

/// Outcome of one guarded startup-reconciliation attempt.
enum StartupAttempt {
    Done,
    /// The write hit a concurrent change, a row deleted after the re-read, or
    /// another database error; re-read and try again.
    Retry(PersistenceError),
}

/// Run `attempt` until it is done, at most
/// `ENDPOINT_STARTUP_RECONCILIATION_ATTEMPTS` times. An error from `attempt`
/// is returned without a retry.
async fn retry_startup_reconciliation<F, Fut>(mut attempt: F) -> Result<(), Status>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<StartupAttempt, Status>>,
{
    let mut attempts = 1;
    loop {
        match attempt().await? {
            StartupAttempt::Done => return Ok(()),
            StartupAttempt::Retry(error)
                if attempts >= ENDPOINT_STARTUP_RECONCILIATION_ATTEMPTS =>
            {
                return Err(super::super::persistence_error_to_status(
                    error,
                    "invalidate tool server endpoint status during gateway startup",
                ));
            }
            StartupAttempt::Retry(_) => attempts += 1,
        }
    }
}

async fn invalidate_sandbox_endpoint_status_once(
    state: &Arc<ServerState>,
    candidate: &Sandbox,
) -> Result<StartupAttempt, Status> {
    let sandbox_id = candidate.object_id();
    let _mutation_guard = state
        .compute
        .mutation_guard(MutationScope::sandbox(
            candidate.object_workspace(),
            sandbox_id,
        ))
        .await
        .map_err(|error| {
            super::super::persistence_error_to_status(
                error,
                "acquire endpoint status startup reconciliation lock",
            )
        })?;
    // A supervisor may have connected to another replica while this waited.
    if has_fresh_shared_owner(state, sandbox_id).await? {
        return Ok(StartupAttempt::Done);
    }
    let Some(current) = state
        .store
        .get_message::<Sandbox>(sandbox_id)
        .await
        .map_err(|error| Status::internal(format!("fetch sandbox failed: {error}")))?
    else {
        return Ok(StartupAttempt::Done);
    };
    if !has_endpoint_status(&current) {
        return Ok(StartupAttempt::Done);
    }
    match state
        .store
        .update_message_cas::<Sandbox, _>(
            sandbox_id,
            current.get_resource_version(),
            invalidate_endpoint_status_without_session,
        )
        .await
    {
        Ok(updated) => {
            state.sandbox_index.update_from_sandbox(&updated);
            Ok(StartupAttempt::Done)
        }
        // Lifecycle writers on other replicas take no distributed guard, and a
        // delete between the re-read and the write surfaces as a database
        // error. Retry with a fresh read after this guard drops.
        Err(error @ (PersistenceError::Conflict { .. } | PersistenceError::Database(_))) => {
            Ok(StartupAttempt::Retry(error))
        }
        Err(error) => Err(super::super::persistence_error_to_status(
            error,
            "invalidate tool server endpoint status during gateway startup",
        )),
    }
}

fn has_endpoint_status(sandbox: &Sandbox) -> bool {
    sandbox
        .status
        .as_ref()
        .is_some_and(|status| !status.endpoint_statuses.is_empty())
}

async fn has_fresh_shared_owner(
    state: &Arc<ServerState>,
    sandbox_id: &str,
) -> Result<bool, Status> {
    SupervisorOwnerIndex::new(state.store.clone(), OWNER_TTL)
        .read(sandbox_id)
        .await
        .map(|owner| owner.is_some_and(|owner| owner.is_fresh(OWNER_TTL)))
        .map_err(|error| Status::unavailable(format!("resolve supervisor owner failed: {error}")))
}

/// True when a replacement supervisor session (local, or a fresh owner on a
/// peer) now owns endpoint observation, so a disconnect must not reset.
async fn disconnect_reset_is_superseded(
    state: &Arc<ServerState>,
    sandbox_id: &str,
) -> Result<bool, Status> {
    if state
        .supervisor_sessions
        .current_session_id(sandbox_id)
        .is_some()
    {
        return Ok(true);
    }
    has_fresh_shared_owner(state, sandbox_id).await
}

fn invalidate_endpoint_status_without_session(sandbox: &mut Sandbox) {
    let Some(status) = sandbox.status.as_mut() else {
        return;
    };
    // Losing observation authority clears evidence, while policy-derived identity
    // remains available so callers can still identify the configured endpoint.
    for endpoint in &mut status.endpoint_statuses {
        endpoint.last_result = EndpointResult::NoObservedExchange as i32;
        endpoint.last_reported_time = None;
    }
}

fn expected_endpoint_statuses(policy: &ProtoSandboxPolicy) -> BTreeMap<String, ExpectedEndpoint> {
    let mut endpoints = BTreeMap::new();
    for endpoint in policy
        .network_policies
        .values()
        .flat_map(|rule| &rule.endpoints)
        .filter(|endpoint| is_mcp_protocol(&endpoint.protocol))
    {
        let status = initial_endpoint_status(endpoint);
        endpoints
            .entry(status.endpoint_id.clone())
            .and_modify(|expected: &mut ExpectedEndpoint| {
                expected.provider_credentialed |= endpoint.provider_credentialed;
            })
            .or_insert(ExpectedEndpoint {
                provider_credentialed: endpoint.provider_credentialed,
                status,
            });
    }
    endpoints
}

fn validate_endpoint_snapshot(
    reported: &[openshell_core::proto::EndpointObservation],
    reported_observed_endpoint_ids: &[String],
    expected: &BTreeMap<String, ExpectedEndpoint>,
) -> Result<(BTreeMap<String, EndpointStatus>, HashSet<String>), Status> {
    let mut validated = BTreeMap::new();
    for endpoint in reported {
        if endpoint.endpoint_id.is_empty() {
            return Err(Status::invalid_argument("endpoint_id is required"));
        }
        let Some(expected_endpoint) = expected.get(&endpoint.endpoint_id) else {
            return Err(Status::failed_precondition(
                "tool server endpoint status contains an endpoint_id outside the current policy",
            ));
        };
        let result = EndpointResult::try_from(endpoint.result)
            .map_err(|_| Status::invalid_argument("tool server endpoint result is invalid"))?;
        if result == EndpointResult::Unspecified {
            return Err(Status::invalid_argument(
                "tool server endpoint result is required",
            ));
        }
        if result == EndpointResult::CredentialUnavailable
            && !expected_endpoint.provider_credentialed
        {
            return Err(Status::invalid_argument(
                "credential-unavailable requires a credentialed tool server endpoint",
            ));
        }
        if validated
            .insert(
                endpoint.endpoint_id.clone(),
                EndpointStatus {
                    last_result: result as i32,
                    ..expected_endpoint.status.clone()
                },
            )
            .is_some()
        {
            return Err(Status::invalid_argument("endpoint_ids must be unique"));
        }
    }
    if validated.len() != expected.len()
        || validated
            .keys()
            .zip(expected.keys())
            .any(|(reported, expected)| reported != expected)
    {
        return Err(Status::failed_precondition(
            "tool server endpoint status must contain the complete current endpoint set",
        ));
    }
    let mut observed_endpoint_ids = HashSet::new();
    for endpoint_id in reported_observed_endpoint_ids {
        let Some(endpoint) = validated.get(endpoint_id) else {
            return Err(Status::failed_precondition(
                "observed endpoint_id is outside the current snapshot",
            ));
        };
        if endpoint.last_result == EndpointResult::NoObservedExchange as i32 {
            return Err(Status::invalid_argument(
                "an observed tool server endpoint cannot report no observed exchange",
            ));
        }
        if !observed_endpoint_ids.insert(endpoint_id.clone()) {
            return Err(Status::invalid_argument(
                "observed endpoint_ids must be unique",
            ));
        }
    }
    Ok((validated, observed_endpoint_ids))
}

fn validate_endpoint_observation_markers(
    sandbox: &Sandbox,
    reports: &BTreeMap<String, EndpointStatus>,
    observed_endpoint_ids: &HashSet<String>,
) -> Result<(), Status> {
    let previous = sandbox
        .status
        .as_ref()
        .map(|status| {
            status
                .endpoint_statuses
                .iter()
                .map(|endpoint| (endpoint.endpoint_id.as_str(), endpoint.last_result))
                .collect::<HashMap<_, _>>()
        })
        .unwrap_or_default();

    for (endpoint_id, report) in reports {
        if report.last_result == EndpointResult::NoObservedExchange as i32 {
            continue;
        }
        // A retained result may reuse its previous report time. New evidence,
        // including evidence accepted after a reset, must carry a marker.
        if previous.get(endpoint_id.as_str()) != Some(&report.last_result)
            && !observed_endpoint_ids.contains(endpoint_id)
        {
            return Err(Status::invalid_argument(
                "a new tool server endpoint result must be marked as observed",
            ));
        }
    }
    Ok(())
}

/// Build an endpoint reset only when the acknowledged policy changes observations' configuration.
/// The caller commits any reset and the active policy version in one CAS.
pub(super) async fn endpoint_status_reset_for_loaded_policy(
    state: &ServerState,
    sandbox: &Sandbox,
    version: i64,
) -> Result<Option<BTreeMap<String, EndpointStatus>>, Status> {
    // Both policy versions must use one provider/profile and global-policy view;
    // an external catalog can change between independent snapshot requests.
    let catalog = state
        .provider_profile_sources
        .snapshot_catalog(state.store.as_ref(), sandbox.object_workspace())
        .await?;
    let global_settings = load_global_settings(state.store.as_ref()).await?;
    let global_policy = decode_policy_from_global_settings(&global_settings)?;
    let context = endpoint_context_for_loaded_policy_with_inputs(
        state,
        sandbox,
        version,
        &catalog,
        global_policy.as_ref(),
    )
    .await?;
    let current_version = i64::from(sandbox.current_policy_version());
    let same_configuration = if current_version == version {
        // An acknowledgement can be retried after endpoint reports have already
        // committed. Repeating activation must not erase their accepted evidence.
        true
    } else if current_version != 0 {
        // Metadata-only revisions do not reinstall the runtime policy. Compare
        // the active policy, not the report cursor: a cursor can outlive an
        // intervening policy reset and cannot prove an A -> B -> A transition.
        let current = endpoint_context_for_loaded_policy_with_inputs(
            state,
            sandbox,
            current_version,
            &catalog,
            global_policy.as_ref(),
        )
        .await?;
        current.policy_hash == context.policy_hash
    } else {
        // The first endpoint report and load acknowledgement travel independently.
        // Only the current session's accepted report proves which configuration
        // produced evidence before any loaded policy version has been recorded.
        state
            .supervisor_sessions
            .current_session_id(sandbox.object_id())
            .and_then(|session_id| {
                state
                    .supervisor_sessions
                    .endpoint_report_cursor(sandbox.object_id(), &session_id)
            })
            .is_some_and(|cursor| {
                cursor.policy_hash == context.policy_hash
                    && cursor.provider_env_revision == context.provider_env_revision
            })
    };
    Ok((!same_configuration).then(|| unknown_endpoint_reports(&context.endpoints)))
}

/// Replace the endpoint inventory and evidence without changing lifecycle state.
pub(super) fn reconcile_endpoint_statuses(
    sandbox: &mut Sandbox,
    reports: &BTreeMap<String, EndpointStatus>,
    observed_endpoint_ids: &HashSet<String>,
    now: &prost_types::Timestamp,
) {
    let phase = sandbox.phase();
    let current_policy_version = sandbox.current_policy_version();
    let status = sandbox.status.get_or_insert_with(|| SandboxStatus {
        phase,
        current_policy_version,
        ..Default::default()
    });
    let previous = status
        .endpoint_statuses
        .iter()
        .map(|endpoint| (endpoint.endpoint_id.as_str(), endpoint.last_reported_time))
        .collect::<HashMap<_, _>>();
    // Replace the complete inventory to remove retired endpoints atomically.
    // Only newly accepted evidence advances the gateway acceptance timestamp;
    // unchanged evidence retains its timestamp and unknown results have none.
    status.endpoint_statuses = reports
        .iter()
        .map(|(endpoint_id, report)| {
            let mut endpoint = report.clone();
            endpoint.last_reported_time =
                if endpoint.last_result == EndpointResult::NoObservedExchange as i32 {
                    None
                } else if observed_endpoint_ids.contains(endpoint_id) {
                    Some(*now)
                } else {
                    previous
                        .get(endpoint_id.as_str())
                        .copied()
                        .unwrap_or_default()
                };
            endpoint
        })
        .collect();
}

#[cfg(test)]
#[path = "endpoint_status_tests.rs"]
mod tests;
