// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Publish complete template snapshots; the driver owns inventory and election.
use super::{SandboxWorkloadTemplate, driver_sandbox_spec_from_public};
use crate::persistence::ObjectType;
use openshell_core::proto::compute::v1::{SyncWarmPoolsRequest, WarmPoolTarget};
use openshell_core::{ObjectId, ObjectName};
use std::{sync::Arc, time::Duration};
use tokio::sync::watch;
use tonic::{Code, Request, Status};
use tracing::warn;

pub fn spawn(state: Arc<crate::ServerState>, mut shutdown: watch::Receiver<bool>) {
    let mut recovery_shutdown = shutdown.clone();
    tokio::spawn(async move {
        // Slow claim recovery must not prevent refreshing the preparation snapshot.
        // If publication reports an unsupported driver, stop both loops.
        let publication = async {
            let mut interval = tokio::time::interval(Duration::from_secs(15));
            loop {
                tokio::select! { _ = shutdown.changed() => break, _ = interval.tick() => {} }
                if *shutdown.borrow() {
                    break;
                }
                if let Err(error) = publish(&state).await {
                    if error.code() == Code::Unimplemented {
                        break;
                    }
                    warn!(%error, "could not refresh warm pool targets");
                }
            }
        };
        let recovery = async {
            let mut interval = tokio::time::interval(Duration::from_secs(15));
            loop {
                tokio::select! { _ = recovery_shutdown.changed() => break, _ = interval.tick() => {} }
                if *recovery_shutdown.borrow() {
                    break;
                }
                tokio::select! {
                    _ = recovery_shutdown.changed() => break,
                    result = recover(&state) => {
                        if let Err(error) = result { warn!(%error, "warm allocation recovery failed"); }
                    }
                }
            }
        };
        tokio::select! { () = publication => {}, () = recovery => {} }
    });
}

async fn publish(state: &crate::ServerState) -> Result<(), Status> {
    let Some(authority) = &state.sandbox_session_jwt_authority else {
        return Ok(());
    };
    let (gateway_id, verification_keys) = authority.preparation_trust()?;
    let mut pools = Vec::new();
    let mut offset = 0;
    loop {
        let templates = state
            .store
            .list_all_messages::<SandboxWorkloadTemplate>(100, offset)
            .await
            .map_err(|_| Status::unavailable("pool template inventory unavailable"))?;
        let count = templates.len();
        for template in templates {
            let Some(metadata) = template.metadata.as_ref() else {
                continue;
            };
            let Some(startup) = template
                .spec
                .as_ref()
                .and_then(|s| s.desired_service_level.as_ref())
                .and_then(|s| s.startup.as_ref())
            else {
                continue;
            };
            if metadata.deletion_time.is_some()
                || startup.ready_within.is_none()
                || startup.max_burst == 0
            {
                continue;
            }
            let spec = crate::grpc::sandbox::sandbox_spec_from_stored_workload_template(&template)?;
            pools.push(WarmPoolTarget {
                template_id: metadata.id.clone(),
                template_name: metadata.name.clone(),
                workspace: metadata.workspace.clone(),
                target: startup.max_burst,
                spec: Some(
                    driver_sandbox_spec_from_public(&spec, state.compute.configured_driver_name())
                        .map_err(|e| *e)?,
                ),
            });
        }
        if count < 100 {
            break;
        }
        offset += 100;
    }
    let request = SyncWarmPoolsRequest {
        pools,
        gateway_id,
        verification_keys,
    };
    state
        .compute
        .driver
        .call(
            openshell_otel::rpc::SYNC_WARM_POOLS,
            None,
            |driver| async move { driver.sync_warm_pools(Request::new(request)).await },
        )
        .await?;
    Ok(())
}

const CANDIDATE: &str = "internal.openshell.ai/warm-pair-candidate";
const PENDING: &str = "internal.openshell.ai/warm-pair-pending";
const ATTACHMENT: &str = "internal.openshell.ai/warm-pair-await-attachment";
const MAX_ALLOCATION_ATTEMPTS: usize = 4;

pub(super) fn allocation_claim(
    runtime: &super::ComputeRuntime,
    sandbox: &openshell_core::proto::Sandbox,
) -> Result<Option<crate::persistence::AllocationClaim>, Status> {
    let Some(pair) = candidate(sandbox)? else {
        return Ok(None);
    };
    let attempt = sandbox
        .status
        .as_ref()
        .and_then(|status| status.provisioning.as_ref())
        .ok_or_else(|| Status::internal("missing provisioning attempt"))?;
    Ok(Some(crate::persistence::AllocationClaim {
        target: serde_json::to_string(&(
            runtime.configured_driver_name(),
            &pair.namespace,
            &pair.uid,
        ))
        .map_err(|_| Status::internal("encode allocation target"))?,
        sandbox_id: sandbox.object_id().into(),
        attempt_id: attempt.attempt_id.clone(),
        runtime_generation: super::sandbox_runtime_generation(sandbox)
            .map_err(Status::internal)?
            .into_string(),
    }))
}

pub(super) async fn release_allocation(
    runtime: &super::ComputeRuntime,
    sandbox: &openshell_core::proto::Sandbox,
) -> Result<(), Status> {
    if let Some(claim) = allocation_claim(runtime, sandbox)? {
        runtime
            .store
            .release_allocation(&claim)
            .await
            .map_err(|_| Status::unavailable("allocation release unavailable"))?;
    }
    Ok(())
}

async fn reserve(
    runtime: &super::ComputeRuntime,
    sandbox: &mut openshell_core::proto::Sandbox,
) -> Result<(), Status> {
    let claim = allocation_claim(runtime, sandbox)?;
    let result = runtime
        .store
        .put_sandbox_allocation(
            sandbox,
            claim.as_ref(),
            crate::persistence::WriteCondition::MatchResourceVersion(
                super::sandbox_resource_version(sandbox),
            ),
        )
        .await
        .map_err(|error| match error {
            crate::persistence::PersistenceError::AllocationTargetReserved => {
                Status::already_exists("allocation target is reserved")
            }
            crate::persistence::PersistenceError::Conflict { .. } => {
                Status::aborted("sandbox changed during allocation")
            }
            _ => Status::unavailable("allocation reservation unavailable"),
        })?;
    sandbox
        .metadata
        .as_mut()
        .expect("metadata")
        .resource_version = result.resource_version;
    runtime.sandbox_index.update_from_sandbox(sandbox);
    runtime.sandbox_watch_bus.notify(sandbox.object_id());
    Ok(())
}

pub fn candidate(
    sandbox: &openshell_core::proto::Sandbox,
) -> Result<Option<openshell_core::proto::compute::v1::WarmPairCandidate>, Status> {
    use prost::Message;
    sandbox
        .metadata
        .as_ref()
        .and_then(|m| m.annotations.get(CANDIDATE))
        .map(|value| {
            let bytes =
                hex::decode(value).map_err(|_| Status::internal("invalid persisted pair"))?;
            openshell_core::proto::compute::v1::WarmPairCandidate::decode(bytes.as_slice())
                .map_err(|_| Status::internal("invalid persisted pair"))
        })
        .transpose()
}

pub fn pending(sandbox: &openshell_core::proto::Sandbox) -> bool {
    sandbox
        .metadata
        .as_ref()
        .is_some_and(|m| m.annotations.contains_key(PENDING))
}

/// Finish claim recovery without discarding the physical assignment or reservation.
/// A restart must persist this together with its new provisioning attempt.
pub(super) fn clear_pending(sandbox: &mut openshell_core::proto::Sandbox) {
    if let Some(metadata) = sandbox.metadata.as_mut() {
        metadata.annotations.remove(PENDING);
    }
}

pub(super) fn has_allocation(sandbox: &openshell_core::proto::Sandbox) -> bool {
    sandbox.metadata.as_ref().is_some_and(|metadata| {
        [CANDIDATE, PENDING, ATTACHMENT]
            .iter()
            .any(|key| metadata.annotations.contains_key(*key))
    })
}

pub(super) fn clear_allocation(sandbox: &mut openshell_core::proto::Sandbox) {
    if let Some(metadata) = sandbox.metadata.as_mut() {
        for key in [CANDIDATE, PENDING, ATTACHMENT] {
            metadata.annotations.remove(key);
        }
    }
}

/// Retire an unassigned candidate through the driver's claim CAS. If the claim
/// won, normal `StopSandbox` reclaims its compute while retaining restartable storage.
pub(super) async fn retire_pending_allocation(
    runtime: &super::ComputeRuntime,
    sandbox: &openshell_core::proto::Sandbox,
) -> Result<(), Status> {
    let Some(pair) = candidate(sandbox)? else {
        return Ok(());
    };
    if let Some(claim) = allocation_claim(runtime, sandbox)?
        && runtime
            .store
            .allocation_conflicts(&claim)
            .await
            .map_err(|_| Status::unavailable("allocation ownership unavailable"))?
    {
        return Ok(());
    }
    let request = openshell_core::proto::compute::v1::DeleteSandboxRequest {
        sandbox_id: sandbox.object_id().into(),
        name: sandbox.object_name().into(),
        warm_pair: Some(pair),
        only_unassigned_pair: true,
    };
    match runtime
        .driver
        .call(
            openshell_otel::rpc::DELETE_SANDBOX,
            Some(sandbox.object_id()),
            |driver| async move { driver.delete_sandbox(Request::new(request)).await },
        )
        .await
    {
        Ok(_) => Ok(()),
        // The candidate is already owned by this sandbox. Do not delete its storage.
        Err(error) if error.code() == Code::FailedPrecondition => Ok(()),
        Err(error) => Err(error),
    }
}

fn same_allocation(
    current: &openshell_core::proto::Sandbox,
    expected: &openshell_core::proto::Sandbox,
) -> Result<bool, Status> {
    fn attempt(sandbox: &openshell_core::proto::Sandbox) -> Option<&str> {
        sandbox
            .status
            .as_ref()
            .and_then(|status| status.provisioning.as_ref())
            .map(|record| record.attempt_id.as_str())
    }
    Ok(attempt(current) == attempt(expected)
        && super::sandbox_runtime_generation(current).map_err(Status::internal)?
            == super::sandbox_runtime_generation(expected).map_err(Status::internal)?
        && candidate(current)? == candidate(expected)?)
}

pub async fn prepare(
    state: &crate::ServerState,
    sandbox: &mut openshell_core::proto::Sandbox,
    identity: &mut crate::auth::sandbox_session::PersistedSandboxIdentity,
    attachment: bool,
) -> Result<(), Status> {
    if let Some(metadata) = &sandbox.metadata {
        validate_user_annotations(&metadata.annotations)?;
    }
    if state.sandbox_session_jwt_authority.is_none() {
        return Ok(());
    }
    if let Some(pair) = select(state, sandbox, &[]).await? {
        bind_candidate(sandbox, identity, Some(pair))?;
        sandbox
            .metadata
            .as_mut()
            .expect("validated metadata")
            .annotations
            .insert(ATTACHMENT.into(), attachment.to_string());
    }
    Ok(())
}

async fn select(
    state: &crate::ServerState,
    sandbox: &openshell_core::proto::Sandbox,
    excluded: &[String],
) -> Result<Option<openshell_core::proto::compute::v1::WarmPairCandidate>, Status> {
    use openshell_core::ObjectWorkspace;
    let Some(provenance) = &sandbox.created_from_workload_template else {
        return Ok(None);
    };
    let Some(template) = state
        .store
        .get_message_by_name::<SandboxWorkloadTemplate>(
            sandbox.object_workspace(),
            &provenance.name,
        )
        .await
        .map_err(|_| Status::unavailable("template lookup unavailable"))?
    else {
        return Ok(None);
    };
    let Some(metadata) = &template.metadata else {
        return Ok(None);
    };
    if metadata.deletion_time.is_some()
        || metadata.resource_version.to_string() != provenance.resource_version
    {
        return Ok(None);
    }
    let request = openshell_core::proto::compute::v1::SelectWarmPairRequest {
        excluded_candidate_uids: excluded.to_vec(),
        template_id: metadata.id.clone(),
        sandbox: Some(
            super::driver_sandbox_from_public(sandbox, state.compute.configured_driver_name())
                .map_err(|e| *e)?,
        ),
    };
    match state
        .compute
        .driver
        .call(
            openshell_otel::rpc::SELECT_WARM_PAIR,
            None,
            |driver| async move { driver.select_warm_pair(Request::new(request)).await },
        )
        .await
    {
        Ok(response) => Ok(response.into_inner().candidate),
        Err(error) if error.code() == Code::Unimplemented => Ok(None),
        // Selection has no side effects; cold fallback is safe if discovery fails.
        Err(error) => {
            warn!(%error, "warm pair discovery unavailable; using cold creation");
            Ok(None)
        }
    }
}

pub(super) fn bind_candidate(
    sandbox: &mut openshell_core::proto::Sandbox,
    identity: &mut crate::auth::sandbox_session::PersistedSandboxIdentity,
    pair: Option<openshell_core::proto::compute::v1::WarmPairCandidate>,
) -> Result<(), Status> {
    use prost::Message;
    let annotations = &mut sandbox
        .metadata
        .as_mut()
        .ok_or_else(|| Status::internal("missing metadata"))?
        .annotations;
    if let Some(pair) = pair {
        if pair.uid.is_empty() || pair.name.is_empty() || pair.namespace.is_empty() {
            return Err(Status::internal("incomplete warm candidate"));
        }
        identity.runtime_generation =
            openshell_core::sandbox_generation::SandboxGenerationId::parse(
                pair.runtime_generation.clone(),
            )
            .map_err(|_| Status::internal("invalid prepared generation"))?;
        annotations.insert(CANDIDATE.into(), hex::encode(pair.encode_to_vec()));
    } else {
        annotations.remove(CANDIDATE);
    }
    identity.write(annotations);
    annotations.insert(PENDING.into(), "true".into());
    Ok(())
}

/// CAS preserves watch updates, deletion, refresh lineage, and other replicas' intents.
async fn save(
    runtime: &super::ComputeRuntime,
    sandbox: &mut openshell_core::proto::Sandbox,
) -> Result<(), Status> {
    use openshell_core::{ObjectLabels, ObjectWorkspace};
    use prost::Message;
    let metadata = sandbox
        .metadata
        .as_ref()
        .ok_or_else(|| Status::internal("missing metadata"))?;
    let labels = serde_json::to_string(&sandbox.object_labels())
        .map_err(|_| Status::internal("encode labels"))?;
    let result = runtime
        .store
        .put_if(
            openshell_core::proto::Sandbox::object_type(),
            sandbox.object_id(),
            sandbox.object_name(),
            sandbox.object_workspace(),
            &sandbox.encode_to_vec(),
            Some(&labels),
            crate::persistence::WriteCondition::MatchResourceVersion(metadata.resource_version),
        )
        .await
        .map_err(|_| Status::aborted("sandbox changed during warm allocation"))?;
    sandbox
        .metadata
        .as_mut()
        .expect("metadata")
        .resource_version = result.resource_version;
    runtime.sandbox_index.update_from_sandbox(sandbox);
    runtime.sandbox_watch_bus.notify(sandbox.object_id());
    Ok(())
}

pub async fn completed(
    runtime: &super::ComputeRuntime,
    expected: &openshell_core::proto::Sandbox,
) -> Result<(), Status> {
    // The driver has durably claimed the pair. Wake local waiters even if the
    // bookkeeping update below needs recovery. Registration revalidates identity.
    runtime.assignment_notifications.send_replace(());
    let sandbox_id = expected.object_id();
    for _ in 0..4 {
        let _global = runtime.sync_lock.lock().await;
        let Some(mut sandbox) = runtime
            .store
            .get_message::<openshell_core::proto::Sandbox>(sandbox_id)
            .await
            .map_err(|_| Status::unavailable("sandbox store unavailable"))?
        else {
            return Ok(());
        };
        if !same_allocation(&sandbox, expected)? {
            return Ok(());
        }
        if !pending(&sandbox)
            || sandbox.phase() == openshell_core::proto::SandboxPhase::Deleting as i32
            || sandbox
                .metadata
                .as_ref()
                .is_some_and(|m| m.deletion_time.is_some())
        {
            return Ok(());
        }
        sandbox = Box::pin(
            runtime.refresh_provisioning_deadline(sandbox, openshell_core::time::now_ms()),
        )
        .await
        .map_err(Status::unavailable)?;
        if super::provisioning_deadline::timed_out(&sandbox) {
            return Ok(());
        }
        clear_pending(&mut sandbox);
        match save(runtime, &mut sandbox).await {
            Ok(()) => return Ok(()),
            Err(e) if e.code() == Code::Aborted => {}
            Err(e) => return Err(e),
        }
    }
    Err(Status::aborted("allocation completion contended"))
}

async fn recover(state: &crate::ServerState) -> Result<(), Status> {
    let mut offset = 0;
    loop {
        let sandboxes = state
            .store
            .list_all_messages::<openshell_core::proto::Sandbox>(100, offset)
            .await
            .map_err(|_| Status::unavailable("allocation inventory unavailable"))?;
        let count = sandboxes.len();
        for sandbox in sandboxes {
            if !(pending(&sandbox)
                || super::provisioning_deadline::cleanup_pending(&sandbox)
                || (candidate(&sandbox)?.is_some()
                    && sandbox.phase() == openshell_core::proto::SandboxPhase::Deleting as i32))
            {
                continue;
            }
            match tokio::time::timeout(
                Duration::from_secs(30),
                recover_one(state, sandbox.object_id()),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    warn!(%error, sandbox_id = sandbox.object_id(), "warm allocation will retry");
                }
                Err(_) => warn!(
                    sandbox_id = sandbox.object_id(),
                    "warm allocation timed out; retaining durable intent"
                ),
            }
        }
        if count < 100 {
            break;
        }
        offset += 100;
    }
    Ok(())
}

/// Re-read durable intent after every driver operation. A retry never follows a
/// different attempt, generation, or candidate installed by another worker.
async fn reload(
    state: &crate::ServerState,
    guard: &super::SandboxLifecycleGuard,
    id: &str,
    expected: Option<&openshell_core::proto::Sandbox>,
) -> Result<Option<openshell_core::proto::Sandbox>, Status> {
    let _global = state.compute.lock_global_for_lifecycle(guard).await;
    let Some(current) = state
        .store
        .get_message::<openshell_core::proto::Sandbox>(id)
        .await
        .map_err(|_| Status::unavailable("sandbox store unavailable"))?
    else {
        return Ok(None);
    };
    if let Some(expected) = expected
        && !same_allocation(&current, expected)?
    {
        return Ok(None);
    }
    Box::pin(
        state
            .compute
            .refresh_provisioning_deadline(current, openshell_core::time::now_ms()),
    )
    .await
    .map(Some)
    .map_err(Status::unavailable)
}

async fn finish_if_inactive(
    state: &crate::ServerState,
    sandbox: &openshell_core::proto::Sandbox,
    guard: &super::SandboxLifecycleGuard,
) -> Result<bool, Status> {
    use openshell_core::proto::{SandboxPhase, compute::v1::DeleteSandboxRequest};
    let id = sandbox.object_id();
    if sandbox.phase() == SandboxPhase::Deleting as i32
        || sandbox
            .metadata
            .as_ref()
            .is_some_and(|m| m.deletion_time.is_some())
    {
        let request = DeleteSandboxRequest {
            sandbox_id: id.into(),
            name: sandbox.object_name().into(),
            warm_pair: candidate(sandbox)?,
            ..Default::default()
        };
        state
            .compute
            .driver
            .call(
                openshell_otel::rpc::DELETE_SANDBOX,
                Some(id),
                |driver| async move { driver.delete_sandbox(Request::new(request)).await },
            )
            .await?;
        if state
            .compute
            .get_driver_sandbox(id, sandbox.object_name())
            .await
            .map_err(Status::unavailable)?
            .is_none()
            && !state
                .compute
                .remove_deleting_sandbox_record(guard, id)
                .await
        {
            return Err(Status::unavailable(
                "pair was deleted; logical cleanup will retry",
            ));
        }
        return Ok(true);
    }
    if super::provisioning_deadline::timed_out(sandbox) {
        state
            .compute
            .reclaim_provisioning_timeout(sandbox, guard)
            .await
            .map_err(Status::unavailable)?;
        return Ok(true);
    }
    if !pending(sandbox) {
        return Ok(true);
    }
    if matches!(
        SandboxPhase::try_from(sandbox.phase()),
        Ok(SandboxPhase::Ready | SandboxPhase::Completed)
    ) || super::is_failed_main_process_result(sandbox)
    {
        // A short-lived workload can finish before the claim is acknowledged.
        // Its process result proves activation just as readiness does.
        completed(&state.compute, sandbox).await?;
        return Ok(true);
    }
    Ok(!matches!(
        SandboxPhase::try_from(sandbox.phase()),
        Ok(SandboxPhase::Provisioning | SandboxPhase::Starting)
    ))
}

fn allocation_request(
    state: &crate::ServerState,
    sandbox: &openshell_core::proto::Sandbox,
) -> Result<openshell_core::proto::compute::v1::CreateSandboxRequest, Status> {
    use crate::auth::sandbox_session::PersistedSandboxIdentity;
    let metadata = sandbox
        .metadata
        .as_ref()
        .ok_or_else(|| Status::internal("missing metadata"))?;
    let identity = PersistedSandboxIdentity::read(&metadata.annotations)
        .map_err(|_| Status::internal("missing runtime identity"))?;
    let authority = state
        .sandbox_session_jwt_authority
        .as_ref()
        .ok_or_else(|| Status::unavailable("session authority unavailable"))?;
    let authentication = authority.mint_persisted_launch(sandbox.object_id(), &identity)?;
    let mut driver_sandbox =
        super::driver_sandbox_from_public(sandbox, state.compute.configured_driver_name())
            .map_err(|e| *e)?;
    if let Some(spec) = driver_sandbox.spec.as_mut() {
        spec.launch_authentication = serde_json::to_vec(&authentication)
            .map_err(|_| Status::internal("encode authentication"))?;
        spec.sandbox_token = authentication
            .supervisor
            .gateway_token
            .expose_secret()
            .to_string();
        spec.await_main_process_attachment = metadata
            .annotations
            .get(ATTACHMENT)
            .is_some_and(|v| v == "true");
    }
    Ok(openshell_core::proto::compute::v1::CreateSandboxRequest {
        sandbox: Some(driver_sandbox),
        warm_pair: candidate(sandbox)?,
    })
}

struct AllocationRetry {
    remaining: usize,
    until: tokio::time::Instant,
    excluded: Vec<String>,
}

impl AllocationRetry {
    fn new() -> Self {
        Self {
            remaining: MAX_ALLOCATION_ATTEMPTS,
            until: tokio::time::Instant::now() + Duration::from_secs(2),
            excluded: Vec::new(),
        }
    }

    fn reject(&mut self, pair: &openshell_core::proto::compute::v1::WarmPairCandidate) {
        if !self.excluded.contains(&pair.uid) {
            self.excluded.push(pair.uid.clone());
        }
    }

    async fn replacement(
        &self,
        state: &crate::ServerState,
        sandbox: &openshell_core::proto::Sandbox,
    ) -> Result<Option<openshell_core::proto::compute::v1::WarmPairCandidate>, Status> {
        if self.remaining == 0 || tokio::time::Instant::now() >= self.until {
            return Ok(None);
        }
        let pair = match tokio::time::timeout_at(self.until, select(state, sandbox, &self.excluded))
            .await
        {
            Ok(result) => result?,
            Err(_) => return Ok(None),
        };
        // Older drivers may ignore the additive exclusion field.
        Ok(pair.filter(|pair| !self.excluded.contains(&pair.uid)))
    }
}

/// Initial creation uses the same reservation and immediate recovery path as a
/// restarted gateway. Failed target reservations never reach the driver.
pub async fn create(
    state: &crate::ServerState,
    mut sandbox: openshell_core::proto::Sandbox,
    mut sandbox_sync_guard: Option<tokio::sync::OwnedMutexGuard<()>>,
) -> Result<openshell_core::proto::Sandbox, Status> {
    use crate::auth::sandbox_session::PersistedSandboxIdentity;
    let mut retry = AllocationRetry::new();
    loop {
        let pair = candidate(&sandbox)?;
        if pair.is_some() {
            retry.remaining = retry.remaining.saturating_sub(1);
        }
        let request = allocation_request(state, &sandbox)?;
        let spec = request
            .sandbox
            .and_then(|sandbox| sandbox.spec)
            .ok_or_else(|| Status::internal("missing driver sandbox spec"))?;
        match state
            .compute
            .create_sandbox_authenticated_with_guard(
                sandbox.clone(),
                Some(spec.sandbox_token),
                Some(spec.launch_authentication),
                spec.await_main_process_attachment,
                &mut sandbox_sync_guard,
            )
            .await
        {
            Ok(_) => break,
            Err(error) if pair.is_some() && error.code() == Code::Aborted => {
                // The atomic insert rolled back: this candidate belongs to someone else.
                retry.reject(pair.as_ref().expect("warm candidate"));
                let next = retry.replacement(state, &sandbox).await?;
                let mut identity = PersistedSandboxIdentity::new()
                    .map_err(|_| Status::internal("new runtime identity"))?;
                bind_candidate(&mut sandbox, &mut identity, next)?;
            }
            Err(error) => return Err(error),
        }
    }
    let id = sandbox.object_id();
    // Uncertain outcomes retain the exact persisted target. Repeating that claim
    // is idempotent; switching targets still requires a definite rejection.
    match tokio::time::timeout(
        Duration::from_secs(30),
        recover_with_retry(state, id, &mut retry),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            warn!(%error, sandbox_id = id, "allocation remains pending reconciliation");
        }
        Err(_) => warn!(
            sandbox_id = id,
            "allocation timed out; retaining durable intent"
        ),
    }
    state
        .store
        .get_message(id)
        .await
        .map_err(|_| Status::unavailable("sandbox store unavailable"))?
        .ok_or_else(|| Status::not_found("sandbox removed during allocation"))
}

pub(super) async fn recover_one(state: &crate::ServerState, id: &str) -> Result<(), Status> {
    recover_with_retry(state, id, &mut AllocationRetry::new()).await
}

async fn recover_with_retry(
    state: &crate::ServerState,
    id: &str,
    retry: &mut AllocationRetry,
) -> Result<(), Status> {
    use crate::auth::sandbox_session::PersistedSandboxIdentity;
    use openshell_core::proto::compute::v1::DeleteSandboxRequest;
    let guard = state.compute.lifecycle_gates.lock_for(id).await;
    let mut expected = None;
    let mut replace = false;
    loop {
        let Some(mut sandbox) = reload(state, &guard, id, expected.as_ref()).await? else {
            return Ok(());
        };
        if Box::pin(finish_if_inactive(state, &sandbox, &guard)).await? {
            return Ok(());
        }
        expected = Some(sandbox.clone());
        if replace {
            let next = retry.replacement(state, &sandbox).await?;
            let Some(current) = reload(state, &guard, id, Some(&sandbox)).await? else {
                return Ok(());
            };
            if Box::pin(finish_if_inactive(state, &current, &guard)).await? {
                return Ok(());
            }
            sandbox = current;
            let mut identity = PersistedSandboxIdentity::new()
                .map_err(|_| Status::internal("new runtime identity"))?;
            bind_candidate(&mut sandbox, &mut identity, next)?;
        }
        let pair = candidate(&sandbox)?;
        if pair.is_some() {
            retry.remaining = retry.remaining.saturating_sub(1);
        }
        match reserve(&state.compute, &mut sandbox).await {
            Ok(()) => {}
            Err(error) if pair.is_some() && error.code() == Code::AlreadyExists => {
                retry.reject(pair.as_ref().expect("warm candidate"));
                // No ownership was acquired. Do not retire the winner's target.
                replace = true;
                continue;
            }
            Err(error) => return Err(error),
        }
        expected = Some(sandbox.clone());
        let request = allocation_request(state, &sandbox)?;
        let result = state
            .compute
            .driver
            .call(
                openshell_otel::rpc::CREATE_SANDBOX,
                Some(id),
                |driver| async move { driver.create_sandbox(Request::new(request)).await },
            )
            .await;
        let Some(current) = reload(state, &guard, id, Some(&sandbox)).await? else {
            return Ok(());
        };
        if Box::pin(finish_if_inactive(state, &current, &guard)).await? {
            return Ok(());
        }
        match result {
            Ok(_) => return completed(&state.compute, &current).await,
            Err(error) if pair.is_none() && error.code() == Code::AlreadyExists => {
                return completed(&state.compute, &current).await;
            }
            Err(error) if pair.is_some() && error.code() == Code::Aborted => {
                let pair = pair.expect("warm candidate");
                let request = DeleteSandboxRequest {
                    sandbox_id: id.into(),
                    name: current.object_name().into(),
                    warm_pair: Some(pair.clone()),
                    only_unassigned_pair: true,
                };
                match state
                    .compute
                    .driver
                    .call(
                        openshell_otel::rpc::DELETE_SANDBOX,
                        Some(id),
                        |driver| async move { driver.delete_sandbox(Request::new(request)).await },
                    )
                    .await
                {
                    Ok(_) => {}
                    // Another replica claimed this same intent. Retry its idempotent claim.
                    Err(error) if error.code() == Code::FailedPrecondition => {
                        if retry.remaining == 0 {
                            return Err(error);
                        }
                        replace = false;
                        continue;
                    }
                    Err(error) => return Err(error),
                }
                release_allocation(&state.compute, &current).await?;
                retry.reject(&pair);
                replace = true;
            }
            Err(error) => return Err(error),
        }
    }
}
pub fn validate_user_annotations(
    annotations: &std::collections::HashMap<String, String>,
) -> Result<(), Status> {
    if annotations
        .keys()
        .any(|key| [CANDIDATE, PENDING, ATTACHMENT].contains(&key.as_str()))
    {
        return Err(Status::invalid_argument(
            "warm pair annotations are gateway-owned",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn a_new_gateway_recovers_the_persisted_pair_and_deletes_it_without_repooling() {
        use crate::{
            Config, ServerState,
            auth::{
                sandbox_jwt::SandboxSessionJwtAuthority, sandbox_session::PersistedSandboxIdentity,
            },
            persistence::Store,
        };
        use openshell_core::proto::{
            Sandbox, SandboxPhase, compute::v1::WarmPairCandidate, datamodel::v1::ObjectMeta,
        };
        let store = Arc::new(Store::connect("sqlite::memory:").await.unwrap());
        let mut sandbox = Sandbox {
            metadata: Some(ObjectMeta {
                id: "logical".into(),
                name: "warm".into(),
                workspace: "default".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Provisioning as i32);
        sandbox.status.as_mut().unwrap().provisioning = Some(
            super::super::provisioning_deadline::new_record(openshell_core::time::now_ms()),
        );
        let mut identity = PersistedSandboxIdentity::new().unwrap();
        let pair = WarmPairCandidate {
            namespace: "openshell".into(),
            name: "physical".into(),
            uid: "parent-uid".into(),
            runtime_generation: "prepared-generation".into(),
            ..Default::default()
        };
        bind_candidate(&mut sandbox, &mut identity, Some(pair.clone())).unwrap();
        store.put_message(&sandbox).await.unwrap();
        // Construct fresh gateway memory after the candidate was durably written.
        let runtime = super::super::new_test_runtime(store.clone()).await;
        let mut state = ServerState::new(
            Config::new(None).with_credential_drivers(["test-static"]),
            store.clone(),
            runtime.clone(),
            runtime.sandbox_index.clone(),
            runtime.sandbox_watch_bus.clone(),
            runtime.tracing_log_bus.clone(),
            runtime.supervisor_sessions.clone(),
            None,
        );
        let key = openshell_bootstrap::jwt::generate_jwt_key().unwrap();
        state.sandbox_session_jwt_authority = Some(Arc::new(
            SandboxSessionJwtAuthority::from_pem(
                key.signing_key_pem.as_bytes(),
                key.public_key_pem.as_bytes(),
                key.kid,
                "gateway",
                Duration::from_hours(1),
            )
            .unwrap(),
        ));
        let mut previous_allocation = sandbox.clone();
        previous_allocation
            .metadata
            .as_mut()
            .unwrap()
            .annotations
            .remove(CANDIDATE);
        completed(&state.compute, &previous_allocation)
            .await
            .unwrap();
        assert!(
            pending(
                &store
                    .get_message::<Sandbox>("logical")
                    .await
                    .unwrap()
                    .unwrap()
            ),
            "a stale completion must not clear another candidate"
        );
        recover_one(&state, "logical").await.unwrap();
        let mut recovered = store
            .get_message::<Sandbox>("logical")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(candidate(&recovered).unwrap(), Some(pair));
        assert!(!pending(&recovered));
        assert_eq!(
            PersistedSandboxIdentity::read(&recovered.metadata.as_ref().unwrap().annotations)
                .unwrap(),
            identity
        );
        recovered.set_phase(SandboxPhase::Deleting as i32);
        store.put_message(&recovered).await.unwrap();
        recover_one(&state, "logical").await.unwrap();
        assert!(
            store
                .get_message::<Sandbox>("logical")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn warm_allocation_annotations_cannot_be_changed_through_public_updates() {
        for key in [CANDIDATE, PENDING, ATTACHMENT] {
            assert_eq!(
                validate_user_annotations(&[(key.into(), "forged".into())].into())
                    .unwrap_err()
                    .code(),
                Code::InvalidArgument
            );
        }
        assert!(
            validate_user_annotations(&[("example.com/user".into(), "value".into())].into())
                .is_ok()
        );
    }
}
