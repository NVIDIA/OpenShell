// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provider views of common configuration operations and session-bound evidence.

#![allow(clippy::result_large_err)] // The RPC boundary returns tonic status values.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use openshell_core::proto::{
    GetSandboxProviderStatusRequest, GetSandboxProviderStatusResponse, Provider,
    ProviderDesiredIdentity, ProviderMutationKind, ProviderMutationReceipt,
    ProviderReadinessObservation, ProviderReadinessReason, ProviderReadinessState,
    ProviderReadinessStatus, ReportProviderReadinessRequest, ReportProviderReadinessResponse,
    Sandbox, SandboxPhase, SupervisorHello,
};
use openshell_core::{ObjectId, ObjectName, ObjectWorkspace};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::ServerState;
use crate::auth::guard::{enforce_sandbox_scope, ensure_sandbox_principal_scope};
use crate::auth::workspace_authz::{MinWorkspaceRole, authorize_workspace_selector};
use crate::config_update_operation;
use crate::persistence::ObjectType;

const REPORT_INTERVAL_SECONDS: u32 = 5;
const OBSERVATION_TTL_SECONDS: u32 = 15;

/// Installation evidence owned by one live `ConnectSupervisor` session.
/// Replacing or removing that session discards this evidence with it.
#[derive(Clone, Debug)]
pub struct ProviderReadinessEvidence {
    network_instance_id: String,
    supported: bool,
    process_instance_id: Option<String>,
    last_seen: Instant,
    observation: Option<ProviderReadinessObservation>,
    observed_time: Option<prost_types::Timestamp>,
}

impl ProviderReadinessEvidence {
    /// Require the instance last accepted into the persisted sandbox lifecycle.
    /// A local session alone cannot prove ownership across gateway replicas.
    pub(crate) fn belongs_to_instance(&self, active_instance_id: &str) -> bool {
        !active_instance_id.is_empty() && self.network_instance_id == active_instance_id
    }

    /// Capture capability and instance identity from the authenticated hello.
    pub(crate) fn from_hello(hello: &SupervisorHello) -> Result<Self, Status> {
        if hello.supports_provider_readiness {
            canonical_uuid(&hello.sandbox_id)?;
            canonical_uuid(&hello.instance_id)?;
        }
        Ok(Self {
            network_instance_id: hello.instance_id.clone(),
            supported: hello.supports_provider_readiness,
            process_instance_id: None,
            last_seen: Instant::now(),
            observation: None,
            observed_time: None,
        })
    }

    /// Accept an ordered report after the registry verifies session ownership.
    /// Retrying an identical report never extends its original acceptance time.
    pub(crate) fn accept(
        &mut self,
        observation: ProviderReadinessObservation,
    ) -> Result<(), Status> {
        if !self.supported {
            return Err(Status::failed_precondition(
                "supervisor did not advertise provider readiness support",
            ));
        }
        if observation.sequence == 0 {
            return Err(Status::invalid_argument("report sequence is required"));
        }
        if let Some(last) = self.observation.as_ref() {
            if observation.sequence == last.sequence {
                return if &observation == last {
                    Ok(())
                } else {
                    Err(Status::invalid_argument(
                        "a provider report sequence must reuse the identical observation",
                    ))
                };
            }
            if observation.sequence < last.sequence {
                return Err(Status::failed_precondition(
                    "provider readiness observation is out of order",
                ));
            }
        }
        if observation.session_id.is_empty() {
            return Err(Status::failed_precondition(
                "supervisor session identity is required",
            ));
        }
        ProviderReadinessReason::try_from(observation.reason)
            .map_err(|_| Status::invalid_argument("unknown readiness reason"))?;
        if !observation.attachment_epoch.is_empty() {
            canonical_uuid(&observation.attachment_epoch)?;
        }
        if observation.policy_hash.len() > 128
            || !observation
                .policy_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(Status::invalid_argument("invalid policy fingerprint"));
        }
        if observation.launch_environment_installed && observation.process_instance_id.is_empty() {
            return Err(Status::invalid_argument(
                "process instance identity is required",
            ));
        }
        let observed_time = now_timestamp()?;
        if !observation.process_instance_id.is_empty() {
            canonical_uuid(&observation.process_instance_id)?;
            if self
                .process_instance_id
                .as_ref()
                .is_some_and(|process_id| process_id != &observation.process_instance_id)
            {
                return Err(Status::failed_precondition("process instance changed"));
            }
            // The supervisor reports its authenticated boundary's process
            // identity. A boundary replacement requires a new control session.
            self.process_instance_id = Some(observation.process_instance_id.clone());
        }
        self.last_seen = Instant::now();
        self.observed_time = Some(observed_time);
        self.observation = Some(observation);
        Ok(())
    }
}

fn registry_unavailable() -> Status {
    Status::unavailable("provider readiness state is unavailable")
}

fn now_timestamp() -> Result<prost_types::Timestamp, Status> {
    openshell_core::time::timestamp_from_system_time(SystemTime::now())
        .map_err(|error| Status::internal(format!("create provider readiness timestamp: {error}")))
}

fn canonical_uuid(value: &str) -> Result<(), Status> {
    let parsed = Uuid::parse_str(value)
        .map_err(|_| Status::invalid_argument("invalid readiness instance identity"))?;
    if parsed.is_nil() || parsed.to_string() != value {
        return Err(Status::invalid_argument(
            "invalid readiness instance identity",
        ));
    }
    Ok(())
}

/// Persist an immutable receipt for the target frozen before a source mutation.
/// Expected provider identity prevents a competing update from acquiring this
/// receipt even when snapshot reads happen after the source CAS.
pub(super) async fn record_provider_mutation(
    state: &Arc<ServerState>,
    sandbox: &Sandbox,
    provider_name: &str,
    kind: ProviderMutationKind,
    expected_provider: Option<(&str, u64)>,
    mutation_id: &str,
) -> Result<ProviderMutationReceipt, Status> {
    let mut desired = target_identity(sandbox, expected_provider);
    let snapshot_reason = match load_current_snapshot(state, sandbox, provider_name).await {
        Ok((snapshot, _)) if same_authority(&desired, &snapshot) => {
            desired = snapshot;
            ProviderReadinessReason::Unspecified
        }
        Ok(_) => ProviderReadinessReason::SnapshotMismatch,
        Err(_) => ProviderReadinessReason::CredentialsWithheld,
    };
    let receipt = ProviderMutationReceipt {
        receipt_id: Uuid::new_v4().to_string(),
        mutation_id: mutation_id.to_string(),
        provider_name: provider_name.to_string(),
        workspace: sandbox.object_workspace().to_string(),
        kind: kind.into(),
        desired: Some(desired),
        persisted_time: Some(now_timestamp()?),
    };
    config_update_operation::record_provider_operation(
        state.store.as_ref(),
        receipt,
        snapshot_reason,
    )
    .await
}

fn target_identity(sandbox: &Sandbox, provider: Option<(&str, u64)>) -> ProviderDesiredIdentity {
    // The empty initial epoch remains an opaque identity paired with the
    // sandbox UUID. Every provider-set mutation atomically replaces the epoch.
    ProviderDesiredIdentity {
        sandbox_id: sandbox.object_id().to_string(),
        sandbox_name: sandbox.object_name().to_string(),
        attachment_epoch: sandbox
            .spec
            .as_ref()
            .map(|spec| spec.provider_attachment_epoch.clone())
            .unwrap_or_default(),
        provider_id: provider.map_or_else(String::new, |(id, _)| id.to_string()),
        provider_resource_version: provider.map_or(0, |(_, version)| version),
        ..Default::default()
    }
}

fn same_authority(left: &ProviderDesiredIdentity, right: &ProviderDesiredIdentity) -> bool {
    left.sandbox_id == right.sandbox_id
        && left.sandbox_name == right.sandbox_name
        && left.attachment_epoch == right.attachment_epoch
        && left.provider_id == right.provider_id
        && left.provider_resource_version == right.provider_resource_version
}

async fn current_target_identity(
    state: &Arc<ServerState>,
    sandbox: &Sandbox,
    provider_name: &str,
) -> Result<ProviderDesiredIdentity, Status> {
    let attached = sandbox
        .spec
        .as_ref()
        .is_some_and(|spec| spec.providers.iter().any(|name| name == provider_name));
    let provider = if attached {
        state
            .store
            .get_by_name(
                Provider::object_type(),
                sandbox.object_workspace(),
                provider_name,
            )
            .await
            .map_err(|_| registry_unavailable())?
    } else {
        None
    };
    Ok(target_identity(
        sandbox,
        provider
            .as_ref()
            .map(|provider| (provider.id.as_str(), provider.resource_version)),
    ))
}

/// Bracket independently stored config and credential records with exact
/// identity reads. Inconsistent reads remain pending; revisions are never
/// treated as counters or compared with greater-than ordering.
async fn load_current_snapshot(
    state: &Arc<ServerState>,
    sandbox: &Sandbox,
    provider_name: &str,
) -> Result<(ProviderDesiredIdentity, ProviderReadinessReason), Status> {
    let mut desired = current_target_identity(state, sandbox, provider_name).await?;
    let config = super::policy::load_sandbox_config(state, sandbox).await?;
    let environment =
        super::policy::load_sandbox_provider_environment(state, sandbox, true).await?;
    let current = state
        .store
        .get_message::<Sandbox>(sandbox.object_id())
        .await
        .map_err(|_| registry_unavailable())?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let after = current_target_identity(state, &current, provider_name).await?;
    let final_config = super::policy::load_sandbox_config(state, &current).await?;
    if !same_authority(&desired, &after)
        || config.provider_attachment_epoch != environment.provider_attachment_epoch
        || config.provider_env_revision != environment.provider_env_revision
        || (config.policy.is_some() && config.policy_hash != environment.policy_hash)
        || config.config_revision != final_config.config_revision
        || config.provider_env_revision != final_config.provider_env_revision
        || config.policy_hash != final_config.policy_hash
    {
        return Err(Status::aborted("provider readiness snapshot changed"));
    }
    desired.provider_env_revision = config.provider_env_revision;
    desired.config_revision = config.config_revision;
    desired.policy_hash = config.policy_hash;
    let reason = if config.policy.is_none() {
        ProviderReadinessReason::LocalPolicy
    } else {
        ProviderReadinessReason::try_from(environment.readiness_reason)
            .unwrap_or(ProviderReadinessReason::CredentialsWithheld)
    };
    Ok((desired, reason))
}

/// Return a redacted operator view. Receipt-less lookup reconstructs current
/// intent only; it never claims that a mutation lost before persistence finished.
pub(super) async fn handle_get_sandbox_provider_status(
    state: &Arc<ServerState>,
    request: Request<GetSandboxProviderStatusRequest>,
) -> Result<Response<GetSandboxProviderStatusResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let request = request.into_inner();
    let authz = authorize_workspace_selector(
        &state.store,
        &state.admin_role,
        &principal,
        request.workspace_scope.as_ref(),
        MinWorkspaceRole::User,
    )
    .await?;
    let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &authz.workspace)
        .await?
        .name;
    // Validate the selector before it can contribute to a durable observation.
    if request.provider_name.len() > super::MAX_NAME_LEN {
        return Err(Status::invalid_argument(
            "provider_name exceeds maximum length",
        ));
    }
    let sandbox = state
        .store
        .get_message_by_name::<Sandbox>(&workspace, &request.sandbox_name)
        .await
        .map_err(|_| registry_unavailable())?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let receipt_id = if request.receipt_id.is_empty() {
        if request.provider_name.is_empty() {
            return Err(Status::invalid_argument(
                "provider_name or receipt_id is required",
            ));
        }
        // Only existing workspace providers can create observation operations.
        // A detached provider still has a useful absent-reference target;
        // historical receipts remain queryable after the provider is deleted.
        state
            .store
            .get_by_name(Provider::object_type(), &workspace, &request.provider_name)
            .await
            .map_err(|_| registry_unavailable())?
            .ok_or_else(|| Status::not_found("provider not found"))?;
        let current = current_target_identity(state, &sandbox, &request.provider_name).await?;
        let provider = (!current.provider_id.is_empty()).then_some((
            current.provider_id.as_str(),
            current.provider_resource_version,
        ));
        record_provider_mutation(
            state,
            &sandbox,
            &request.provider_name,
            ProviderMutationKind::Observe,
            provider,
            &Uuid::new_v4().to_string(),
        )
        .await?
        .receipt_id
    } else {
        canonical_uuid(&request.receipt_id)?;
        request.receipt_id
    };
    let stored = config_update_operation::get_provider_operation(
        state.store.as_ref(),
        &receipt_id,
        &workspace,
    )
    .await?;
    let receipt = stored.receipt;
    if receipt.workspace != workspace
        || receipt
            .desired
            .as_ref()
            .is_none_or(|desired| desired.sandbox_id != sandbox.object_id())
        || (!request.provider_name.is_empty() && receipt.provider_name != request.provider_name)
    {
        return Err(Status::not_found("provider receipt not found"));
    }
    let current_authority =
        current_target_identity(state, &sandbox, &receipt.provider_name).await?;
    let (current, current_reason) = if let Ok(snapshot) =
        load_current_snapshot(state, &sandbox, &receipt.provider_name).await
    {
        snapshot
    } else {
        // A temporarily unreadable config cannot prove supersession or
        // completion. Metadata changes remain comparable independently.
        let mut fallback = current_authority;
        if let Some(desired) = receipt.desired.as_ref() {
            fallback.provider_env_revision = desired.provider_env_revision;
            fallback.config_revision = desired.config_revision;
            fallback.policy_hash.clone_from(&desired.policy_hash);
        }
        (fallback, ProviderReadinessReason::CredentialsWithheld)
    };
    // Refresh lifecycle identity after configuration reads. Another gateway
    // replica may have accepted a new supervisor while this replica retained
    // the predecessor's local connection and installation evidence.
    let active_sandbox = state
        .store
        .get_message::<Sandbox>(sandbox.object_id())
        .await
        .map_err(|_| registry_unavailable())?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let active_instance_id = active_sandbox
        .status
        .as_ref()
        .map_or("", |status| status.main_process_instance_id.as_str());
    let session = state
        .supervisor_sessions
        .provider_readiness(sandbox.object_id())?;
    let mut status = evaluate_status(
        receipt,
        stored.snapshot_reason,
        &current,
        current_reason,
        active_sandbox.phase() == SandboxPhase::Ready as i32,
        active_instance_id,
        session.as_ref(),
    )?;
    config_update_operation::observe_provider_status(state.store.as_ref(), &mut status).await?;
    Ok(Response::new(GetSandboxProviderStatusResponse {
        status: Some(status),
    }))
}

fn observation_matches(
    observation: &ProviderReadinessObservation,
    desired: &ProviderDesiredIdentity,
) -> bool {
    observation.attachment_epoch == desired.attachment_epoch
        && observation.provider_env_revision == desired.provider_env_revision
        && observation.config_revision == desired.config_revision
        && observation.policy_hash == desired.policy_hash
}

fn failure_state(reason: ProviderReadinessReason) -> ProviderReadinessState {
    match reason {
        ProviderReadinessReason::CredentialsWithheld
        | ProviderReadinessReason::CredentialExpired => ProviderReadinessState::Withheld,
        ProviderReadinessReason::CredentialInstallFailed
        | ProviderReadinessReason::PolicyActivationFailed
        | ProviderReadinessReason::ProcessInstallFailed
        | ProviderReadinessReason::UnsupportedSupervisor
        | ProviderReadinessReason::LocalPolicy => ProviderReadinessState::Failed,
        _ => ProviderReadinessState::Pending,
    }
}

fn evaluate_status(
    receipt: ProviderMutationReceipt,
    snapshot_reason: ProviderReadinessReason,
    current: &ProviderDesiredIdentity,
    current_reason: ProviderReadinessReason,
    running: bool,
    active_instance_id: &str,
    session: Option<&ProviderReadinessEvidence>,
) -> Result<ProviderReadinessStatus, Status> {
    let mut status = ProviderReadinessStatus {
        receipt: Some(receipt.clone()),
        state: ProviderReadinessState::Persisted.into(),
        reason: ProviderReadinessReason::WaitingForSupervisor.into(),
        observed: session.and_then(|session| session.observation.clone()),
        network_instance_id: session
            .map(|session| session.network_instance_id.clone())
            .unwrap_or_default(),
        observed_time: session.and_then(|session| session.observed_time),
        evaluated_time: Some(now_timestamp()?),
        operation: None,
    };
    let set = |status: &mut ProviderReadinessStatus,
               state: ProviderReadinessState,
               reason: ProviderReadinessReason| {
        status.state = state.into();
        status.reason = reason.into();
    };
    let Some(desired) = receipt.desired.as_ref() else {
        set(
            &mut status,
            ProviderReadinessState::Failed,
            ProviderReadinessReason::SnapshotMismatch,
        );
        return Ok(status);
    };
    if !same_authority(desired, current)
        || (snapshot_reason == ProviderReadinessReason::Unspecified && desired != current)
    {
        set(
            &mut status,
            ProviderReadinessState::Superseded,
            ProviderReadinessReason::DesiredStateChanged,
        );
    } else if snapshot_reason != ProviderReadinessReason::Unspecified {
        set(&mut status, ProviderReadinessState::Failed, snapshot_reason);
    } else if current_reason != ProviderReadinessReason::Unspecified {
        set(&mut status, failure_state(current_reason), current_reason);
    } else if !running {
        set(
            &mut status,
            ProviderReadinessState::Pending,
            ProviderReadinessReason::SupervisorDisconnected,
        );
    } else if let Some(session) = session {
        if !session.belongs_to_instance(active_instance_id) {
            set(
                &mut status,
                ProviderReadinessState::Pending,
                ProviderReadinessReason::SupervisorDisconnected,
            );
        } else if session.last_seen.elapsed()
            >= Duration::from_secs(u64::from(OBSERVATION_TTL_SECONDS))
        {
            set(
                &mut status,
                ProviderReadinessState::Pending,
                ProviderReadinessReason::SupervisorLeaseExpired,
            );
        } else if !session.supported {
            set(
                &mut status,
                ProviderReadinessState::Failed,
                ProviderReadinessReason::UnsupportedSupervisor,
            );
        } else if let Some(observation) = session.observation.as_ref() {
            let reason = ProviderReadinessReason::try_from(observation.reason)
                .unwrap_or(ProviderReadinessReason::SnapshotMismatch);
            // Installation failures describe one snapshot. A retained failure
            // from an older poll must not fail a newly persisted authority.
            if !observation_matches(observation, desired) {
                set(
                    &mut status,
                    ProviderReadinessState::Pending,
                    ProviderReadinessReason::SnapshotMismatch,
                );
            } else if reason != ProviderReadinessReason::Unspecified {
                set(&mut status, failure_state(reason), reason);
            } else if !observation.credentials_installed {
                set(
                    &mut status,
                    ProviderReadinessState::Pending,
                    ProviderReadinessReason::WaitingForCredentials,
                );
            } else if !observation.policy_active {
                set(
                    &mut status,
                    ProviderReadinessState::Pending,
                    ProviderReadinessReason::WaitingForPolicy,
                );
            } else if !observation.launch_environment_installed
                || observation.process_instance_id.is_empty()
            {
                set(
                    &mut status,
                    ProviderReadinessState::Pending,
                    ProviderReadinessReason::WaitingForProcess,
                );
            } else {
                let state = if desired.provider_id.is_empty() {
                    ProviderReadinessState::Revoked
                } else {
                    ProviderReadinessState::Ready
                };
                set(&mut status, state, ProviderReadinessReason::Unspecified);
            }
        }
    }
    Ok(status)
}

fn authorize_provider_readiness<T>(
    request: &Request<T>,
    sandbox_id: &str,
) -> Result<crate::auth::principal::Principal, Status> {
    let principal = enforce_sandbox_scope(request, sandbox_id)?;
    ensure_sandbox_principal_scope(&principal, sandbox_id)?;
    Ok(principal)
}

/// Accept installation evidence only from the sandbox's current supervisor.
/// Authorization is independent from operator permission to inspect progress.
pub(super) async fn handle_report_provider_readiness(
    state: &Arc<ServerState>,
    request: Request<ReportProviderReadinessRequest>,
) -> Result<Response<ReportProviderReadinessResponse>, Status> {
    let sandbox_id = request.get_ref().sandbox_id.clone();
    let principal = authorize_provider_readiness(&request, &sandbox_id)?;
    canonical_uuid(&sandbox_id)?;
    let observation = request
        .into_inner()
        .observation
        .ok_or_else(|| Status::invalid_argument("provider readiness observation is required"))?;
    canonical_uuid(&observation.session_id)?;
    // A valid session must still belong to an existing sandbox. The registry
    // performs the final current-session check atomically with accepting evidence,
    // so a reconnect during this read cannot publish into its replacement.
    let sandbox =
        super::sandbox::fetch_and_authorize_sandbox(state, &principal, &sandbox_id).await?;
    if sandbox.phase() != SandboxPhase::Ready as i32 {
        return Err(Status::failed_precondition(
            "sandbox supervisor is not ready",
        ));
    }
    let active_instance_id = sandbox
        .status
        .as_ref()
        .map_or("", |status| status.main_process_instance_id.as_str());
    let accepted_sequence = observation.sequence;
    state.supervisor_sessions.accept_provider_readiness(
        &sandbox_id,
        active_instance_id,
        observation,
    )?;
    Ok(Response::new(ReportProviderReadinessResponse {
        accepted_sequence,
        report_interval: Some(
            openshell_core::time::duration_from_std(Duration::from_secs(u64::from(
                REPORT_INTERVAL_SECONDS,
            )))
            .map_err(|error| Status::internal(format!("create report interval: {error}")))?,
        ),
        observation_ttl: Some(
            openshell_core::time::duration_from_std(Duration::from_secs(u64::from(
                OBSERVATION_TTL_SECONDS,
            )))
            .map_err(|error| Status::internal(format!("create observation TTL: {error}")))?,
        ),
    }))
}

#[cfg(test)]
#[path = "provider_readiness_tests.rs"]
mod tests;
