// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Durable preparation and claim of a physical runtime on its reserved host.

use super::*;
use crate::auth::sandbox_session::PreparedRuntimeIdentity;
use crate::persistence::ObjectType;
use openshell_supervisor_control::{
    PendingWarmClaim, PreparedRuntimeRegistration, SandboxInstanceRegistration, WarmClaimIntent,
    WarmClaimInventory, WarmClaimLookup, WarmClaimReservation,
};

const CLAIM_LINK: &str = "internal.openshell.ai/warm-claim-intent";

#[derive(Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum LaunchDecision {
    #[default]
    Warm,
    Cold,
    Cancelled,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimLink {
    route: String,
    generation: openshell_core::sandbox_generation::SandboxGenerationId,
    auth_epoch: openshell_core::jwt::CredentialEpoch,
    #[serde(default)]
    decision: LaunchDecision,
}

impl SupervisorPool {
    pub(super) async fn warm_claim_for_launch(
        &self,
        lookup: WarmClaimLookup,
    ) -> Result<Option<WarmClaimIntent>, String> {
        let sandbox = self
            .store
            .get_message::<Sandbox>(&lookup.sandbox_id)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("claiming sandbox disappeared")?;
        if sandbox.object_workspace() != lookup.workspace {
            return Err("claim lookup workspace mismatch".into());
        }
        let Some(value) = sandbox
            .metadata
            .as_ref()
            .and_then(|meta| meta.annotations.get(CLAIM_LINK))
        else {
            return Ok(None);
        };
        let link: ClaimLink = serde_json::from_str(value).map_err(|_| "invalid warm claim link")?;
        if link.generation != lookup.expected_generation
            || link.auth_epoch != lookup.expected_auth_epoch
        {
            return Ok(None);
        }
        match link.decision {
            LaunchDecision::Cold => return Ok(None),
            LaunchDecision::Cancelled => return Err("warm launch was cancelled".into()),
            LaunchDecision::Warm => {}
        }
        let intent = self.warm_claim(&lookup.workspace, &link.route).await?;
        if intent.registration.sandbox_id != lookup.sandbox_id
            || intent.expected_generation != lookup.expected_generation
            || intent.expected_auth_epoch != lookup.expected_auth_epoch
        {
            return Err("warm claim link does not match its launch".into());
        }
        Ok(Some(intent))
    }

    pub(super) async fn choose_cold_launch(
        &self,
        lookup: WarmClaimLookup,
    ) -> Result<Option<WarmClaimIntent>, String> {
        let mut write_error = None;
        for _ in 0..TRANSITION_ATTEMPTS {
            let row = self
                .store
                .get(Sandbox::object_type(), &lookup.sandbox_id)
                .await
                .map_err(|e| e.to_string())?
                .ok_or("claiming sandbox disappeared")?;
            let mut sandbox = Sandbox::decode(row.payload.as_slice()).map_err(|e| e.to_string())?;
            if sandbox.object_workspace() != lookup.workspace {
                return Err("cold launch workspace mismatch".into());
            }
            if let Some(link) = read_claim_link(&sandbox)?
                && link.generation == lookup.expected_generation
                && link.auth_epoch == lookup.expected_auth_epoch
            {
                return match link.decision {
                    LaunchDecision::Warm => self.warm_claim_for_launch(lookup).await,
                    LaunchDecision::Cold if launch_is_current(&sandbox, &lookup) => Ok(None),
                    LaunchDecision::Cold => Err("cold launch is no longer current".into()),
                    LaunchDecision::Cancelled => Err("warm launch was cancelled".into()),
                };
            }
            if !launch_is_current(&sandbox, &lookup) {
                return Err("cold decision does not match the current sandbox launch".into());
            }
            write_claim_link(
                &mut sandbox,
                &ClaimLink {
                    route: String::new(),
                    generation: lookup.expected_generation.clone(),
                    auth_epoch: lookup.expected_auth_epoch,
                    decision: LaunchDecision::Cold,
                },
            )?;
            match self
                .store
                .write_atomically(&[AtomicWrite::Update {
                    object_type: Sandbox::object_type().into(),
                    id: lookup.sandbox_id.clone(),
                    payload: sandbox.encode_to_vec(),
                    expected_version: row.resource_version,
                }])
                .await
            {
                Ok(_) => return Ok(None),
                Err(PersistenceError::Conflict { .. }) => {}
                // A lost reply may follow a committed decision. The next read
                // resolves it before another write or any cold provisioning.
                Err(error) => write_error = Some(format!("persist cold launch decision: {error}")),
            }
        }
        Err(write_error
            .unwrap_or_else(|| "sandbox launch changed repeatedly during cold selection".into()))
    }

    pub(super) async fn reserve_warm_claim(
        &self,
        workspace: &str,
        intent: WarmClaimIntent,
    ) -> Result<WarmClaimReservation, String> {
        match self.record_warm_claim(workspace, intent.clone()).await {
            Ok(intent) => Ok(WarmClaimReservation::Reserved(Box::new(intent))),
            Err(error) => {
                // A missing row or failed read is not proof that a write lost.
                let record = self
                    .assignment(&intent.registration.route)
                    .await
                    .map_err(|e| e.to_string())?;
                if let Some(record) = record
                    && record.payload.workspace == workspace
                    && record.payload.dedicated == self.dedicated
                {
                    if record.payload.phase == RecordPhase::Retired {
                        return Ok(WarmClaimReservation::Unavailable);
                    }
                    if !record.payload.claim_handle.is_empty() {
                        let previous = self
                            .warm_claim(workspace, &intent.registration.route)
                            .await?;
                        if previous.registration.sandbox_id != intent.registration.sandbox_id {
                            return Ok(WarmClaimReservation::Unavailable);
                        }
                        return matching_claim(intent, previous)
                            .map(|intent| WarmClaimReservation::Reserved(Box::new(intent)));
                    }
                }
                let sandbox = self
                    .store
                    .get_message::<Sandbox>(&intent.registration.sandbox_id)
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or("claiming sandbox disappeared")?;
                if sandbox.object_workspace() == workspace
                    && let Some(link) = read_claim_link(&sandbox)?
                    && link.generation == intent.expected_generation
                    && link.auth_epoch == intent.expected_auth_epoch
                    && (link.decision == LaunchDecision::Cold
                        || (link.decision == LaunchDecision::Warm
                            && link.route != intent.registration.route))
                {
                    return Ok(WarmClaimReservation::Unavailable);
                }
                Err(error)
            }
        }
    }

    /// Include reservations whose CR binding never happened. Invalid launches
    /// are cancelled with the same assignment/Sandbox CAS as activation.
    pub(super) async fn pending_warm_claims(
        &self,
        pools: Vec<(String, String)>,
        route: Option<String>,
    ) -> Result<openshell_supervisor_control::WarmClaimInventories, String> {
        let mut grouped: BTreeMap<_, Vec<_>> =
            pools.into_iter().map(|scope| (scope, Vec::new())).collect();
        if grouped.is_empty() {
            return Ok(BTreeMap::new());
        }
        let records = if let Some(route) = route {
            self.assignment(&route)
                .await
                .map_err(|e| e.to_string())?
                .into_iter()
                .collect()
        } else {
            self.all_assignments()
                .await
                .map_err(|e| e.to_string())?
                .into_values()
                .collect::<Vec<_>>()
        };
        for record in &records {
            let payload = &record.payload;
            if !payload.prepared
                || payload.dedicated != self.dedicated
                || !(payload.phase == RecordPhase::Retired
                    || (payload.phase == RecordPhase::Published
                        && !payload.claim_handle.is_empty()))
            {
                continue;
            }
            if let Some(id) = &payload.pool_id {
                if let Some(group) = grouped.get_mut(&(payload.workspace.clone(), id.clone())) {
                    group.push(record);
                }
            } else {
                // Older assignments lack a pool id. Keep their workspace recovery coverage.
                for ((workspace, _), group) in &mut grouped {
                    if workspace == &payload.workspace {
                        group.push(record);
                    }
                }
            }
        }
        let mut inventories = BTreeMap::new();
        for (scope, records) in grouped {
            let result = self.resolve_pending_warm_claims(&scope.0, records).await;
            inventories.insert(scope, result);
        }
        Ok(inventories)
    }

    async fn resolve_pending_warm_claims(
        &self,
        workspace: &str,
        records: Vec<&AssignmentRecord>,
    ) -> Result<WarmClaimInventory, String> {
        let mut inventory = WarmClaimInventory::default();
        for record in records {
            let retirement = PreparationRetirement {
                workspace: workspace.into(),
                route: record.payload.route.clone(),
                generation: openshell_core::sandbox_generation::SandboxGenerationId::parse(
                    record.payload.generation.clone(),
                )
                .map_err(|e| e.to_string())?,
                auth_epoch: openshell_core::jwt::CredentialEpoch::new(
                    record.payload.prepared_epoch,
                )
                .map_err(|e| e.to_string())?,
            };
            if record.payload.phase == RecordPhase::Retired {
                inventory.retired.push(retirement);
                continue;
            }
            let bytes = self.load_material(&claim_material(&record.payload)).await?;
            let intent: WarmClaimIntent =
                serde_json::from_slice(&bytes).map_err(|_| "invalid persisted warm claim")?;
            let sandbox = self
                .store
                .get_message::<Sandbox>(&intent.registration.sandbox_id)
                .await
                .map_err(|e| e.to_string())?;
            if let Some(sandbox) = sandbox
                && claim_is_current(&sandbox, workspace, &intent)?
            {
                let mut sandbox =
                    crate::compute::driver_sandbox_from_public(&sandbox, "kubernetes")
                        .map_err(|error| error.to_string())?;
                let process = openshell_core::sandbox_env::MainProcessConfig::decode(
                    &intent.registration.main_process_spec,
                )?;
                if let Some(spec) = sandbox.spec.as_mut() {
                    spec.await_main_process_attachment = process.await_main_process_attachment;
                }
                inventory.pending.push(PendingWarmClaim { sandbox, intent });
            } else if self
                .cancel_warm_claim_inner(workspace, &record.payload.route, true)
                .await?
            {
                inventory.retired.push(retirement);
            }
        }
        Ok(inventory)
    }

    pub(super) async fn cancel_abandoned_warm_claims(
        &self,
        records: &BTreeMap<String, AssignmentRecord>,
    ) -> bool {
        let mut changed = false;
        for record in records.values().filter(|record| {
            record.payload.prepared
                && record.payload.phase == RecordPhase::Published
                && !record.payload.claim_handle.is_empty()
        }) {
            match self
                .cancel_warm_claim_inner(&record.payload.workspace, &record.payload.route, true)
                .await
            {
                Ok(cancelled) => changed |= cancelled,
                Err(error) => {
                    warn!(route = %record.payload.route, %error, "warm claim cancellation will be reconciled");
                }
            }
        }
        changed
    }

    pub(super) async fn cancel_warm_claim(
        &self,
        workspace: &str,
        route: &str,
    ) -> Result<bool, String> {
        self.cancel_warm_claim_inner(workspace, route, false).await
    }

    async fn cancel_warm_claim_inner(
        &self,
        workspace: &str,
        route: &str,
        only_abandoned: bool,
    ) -> Result<bool, String> {
        for _ in 0..TRANSITION_ATTEMPTS {
            let record = self
                .assignment(route)
                .await
                .map_err(|e| e.to_string())?
                .ok_or("warm claim disappeared")?;
            if record.payload.workspace != workspace || record.payload.dedicated != self.dedicated {
                return Err("warm claim cancellation scope mismatch".into());
            }
            if !record.payload.prepared {
                return Ok(false);
            }
            if record.payload.phase == RecordPhase::Retired {
                return Ok(true);
            }
            if record.payload.claim_handle.is_empty() {
                return Err("runtime has no warm claim to cancel".into());
            }
            let bytes = self.load_material(&claim_material(&record.payload)).await?;
            let intent: WarmClaimIntent =
                serde_json::from_slice(&bytes).map_err(|_| "invalid persisted warm claim")?;
            let mut writes = Vec::new();
            if let Some(row) = self
                .store
                .get(Sandbox::object_type(), &intent.registration.sandbox_id)
                .await
                .map_err(|e| e.to_string())?
            {
                let mut sandbox =
                    Sandbox::decode(row.payload.as_slice()).map_err(|e| e.to_string())?;
                let current_launch = claim_is_current(&sandbox, workspace, &intent)?;
                if only_abandoned && current_launch {
                    return Ok(false);
                }
                if let Some(mut link) = read_claim_link(&sandbox)?
                    && sandbox.object_workspace() == workspace
                    && link.route == route
                    && link.generation == intent.expected_generation
                    && link.auth_epoch == intent.expected_auth_epoch
                {
                    if link.decision == LaunchDecision::Warm
                        && let Some(operation) = sandbox
                            .status
                            .as_mut()
                            .and_then(|s| s.provisioning.as_mut())
                        && operation.driver_operation_pending
                        && !operation.driver_operation_id.is_empty()
                        && record.payload.claim_operation_id.as_deref()
                            == Some(&operation.driver_operation_id)
                    {
                        operation.driver_operation_pending = false;
                        if current_launch {
                            crate::compute::record_warm_create_failure(&mut sandbox);
                        }
                    }
                    link.decision = LaunchDecision::Cancelled;
                    write_claim_link(&mut sandbox, &link)?;
                }
                // Even an unchanged Sandbox must fence a concurrent lifecycle edit.
                writes.push(AtomicWrite::Update {
                    object_type: Sandbox::object_type().into(),
                    id: intent.registration.sandbox_id.clone(),
                    payload: sandbox.encode_to_vec(),
                    expected_version: row.resource_version,
                });
            }
            if self.commit_retirement(&record, writes).await? {
                return Ok(true);
            }
        }
        Err("warm claim changed repeatedly during cancellation".into())
    }

    pub(super) async fn runtime_assignment(
        &self,
        workspace: &str,
        route: &str,
    ) -> Result<Option<SandboxInstanceAssignment>, String> {
        let Some(record) = self.assignment(route).await.map_err(|e| e.to_string())? else {
            return Ok(None);
        };
        let payload = &record.payload;
        if payload.workspace != workspace || payload.dedicated != self.dedicated {
            return Err("runtime belongs to another workspace or supervisor topology".into());
        }
        if payload.phase != RecordPhase::Published {
            return Err("runtime is not published".into());
        }
        Ok(Some(SandboxInstanceAssignment {
            route: payload.route.clone(),
            sandbox_id: payload.sandbox_id.clone(),
            generation: payload.generation.clone(),
            prepared: payload.prepared,
            launch_material: self.load_material(payload).await?,
            ..Default::default()
        }))
    }

    pub(super) async fn warm_claim(
        &self,
        workspace: &str,
        route: &str,
    ) -> Result<WarmClaimIntent, String> {
        let record = self
            .assignment(route)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("warm claim has no preparation")?;
        if record.payload.workspace != workspace
            || record.payload.dedicated != self.dedicated
            || record.payload.phase != RecordPhase::Published
            || record.payload.claim_handle.is_empty()
        {
            return Err("warm claim is unavailable".into());
        }
        let bytes = self.load_material(&claim_material(&record.payload)).await?;
        serde_json::from_slice(&bytes).map_err(|_| "invalid persisted warm claim".into())
    }

    pub(super) async fn record_warm_claim(
        &self,
        workspace: &str,
        intent: WarmClaimIntent,
    ) -> Result<WarmClaimIntent, String> {
        intent.registration.validate().map_err(|e| e.to_string())?;
        let route = &intent.registration.route;
        let record = self
            .assignment(route)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("warm claim has no preparation")?;
        if record.payload.workspace != workspace
            || record.payload.dedicated != self.dedicated
            || record.payload.phase != RecordPhase::Published
        {
            return Err("warm preparation is unavailable".into());
        }
        if !record.payload.claim_handle.is_empty() {
            let previous = self.warm_claim(workspace, route).await?;
            return matching_claim(intent, previous);
        }
        if !record.payload.prepared {
            return Err("runtime is already assigned".into());
        }
        let assignment = self
            .runtime_assignment(workspace, route)
            .await?
            .ok_or("warm preparation disappeared")?;
        PreparedRuntimeRegistration::from_assignment(&assignment)
            .map_err(|e| e.to_string())?
            .validate_activation(&intent.registration)
            .map_err(|e| e.to_string())?;
        let sandbox_row = self
            .store
            .get(Sandbox::object_type(), &intent.registration.sandbox_id)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("claiming sandbox disappeared")?;
        let mut sandbox =
            Sandbox::decode(sandbox_row.payload.as_slice()).map_err(|e| e.to_string())?;
        let identity = sandbox
            .metadata
            .as_ref()
            .and_then(|meta| PersistedSandboxIdentity::read(&meta.annotations).ok())
            .ok_or("invalid claiming sandbox identity")?;
        if sandbox.object_workspace() != workspace
            || identity.runtime_generation != intent.expected_generation
            || identity.auth_epoch != intent.expected_auth_epoch
            || identity.prepared_runtime.is_some()
            || crate::compute::provisioning_deadline::timed_out(&sandbox)
            || !matches!(
                SandboxPhase::try_from(sandbox.phase()),
                Ok(SandboxPhase::Provisioning | SandboxPhase::Starting)
            )
        {
            return Err("claim intent does not match the current sandbox launch".into());
        }
        let annotations = &mut sandbox
            .metadata
            .as_mut()
            .ok_or("sandbox metadata missing")?
            .annotations;
        if let Some(previous) = annotations.get(CLAIM_LINK) {
            let link: ClaimLink =
                serde_json::from_str(previous).map_err(|_| "invalid warm claim link")?;
            if link.generation == intent.expected_generation
                && link.auth_epoch == intent.expected_auth_epoch
                && (link.route != *route || link.decision != LaunchDecision::Warm)
            {
                return Err("this sandbox launch already has a different warm claim intent".into());
            }
        }
        annotations.insert(
            CLAIM_LINK.into(),
            serde_json::to_string(&ClaimLink {
                route: route.clone(),
                generation: intent.expected_generation.clone(),
                auth_epoch: intent.expected_auth_epoch,
                decision: LaunchDecision::Warm,
            })
            .map_err(|e| e.to_string())?,
        );
        let bytes = encode(&intent)?;
        if bytes.len() > openshell_supervisor_control::MAX_LAUNCH_MATERIAL_BYTES {
            return Err("warm claim intent is too large".into());
        }
        // Use the physical route's owner even after activation. Each writer gets
        // a fresh credential path, and the staging row fences late publication.
        let mut staged_payload = claim_material(&record.payload);
        let handle = self.store_material(&staged_payload, &bytes).await?;
        staged_payload.material_handle = handle.encode_to_vec();
        staged_payload.activation_candidate = true;
        staged_payload.phase = RecordPhase::Admitting;
        let candidate = Uuid::new_v4().to_string();
        let staged = match self
            .store
            .put_if(
                MATERIAL_CANDIDATE_OBJECT_TYPE,
                &candidate,
                &candidate,
                "",
                &encode(&staged_payload)?,
                None,
                WriteCondition::MustCreate,
            )
            .await
        {
            Ok(staged) => staged,
            Err(error) => {
                let _ = self.delete_material(&staged_payload, handle).await;
                return Err(format!("stage warm claim: {error}"));
            }
        };
        #[cfg(test)]
        {
            let gate = lock(&self.staged_gate).take();
            if let Some((reached, resume)) = gate {
                let _ = reached.send(());
                let _ = resume.await;
            }
        }
        let mut payload = record.payload.clone();
        payload.claim_operation_id = sandbox
            .status
            .as_ref()
            .and_then(|status| status.provisioning.as_ref())
            .filter(|op| op.driver_operation_pending)
            .map(|op| op.driver_operation_id.clone());
        payload
            .claim_handle
            .clone_from(&staged_payload.material_handle);
        let result = self
            .store
            .write_atomically(&[
                AtomicWrite::Update {
                    object_type: ASSIGNMENT_OBJECT_TYPE.into(),
                    id: assignment_object_id(route, &payload.writer),
                    payload: encode(&payload)?,
                    expected_version: record.resource_version,
                },
                // Choose one intent for this logical launch before any CR binding.
                // This also fences concurrent stop, restart, or another spare.
                AtomicWrite::Update {
                    object_type: Sandbox::object_type().into(),
                    id: intent.registration.sandbox_id.clone(),
                    payload: sandbox.encode_to_vec(),
                    expected_version: sandbox_row.resource_version,
                },
                AtomicWrite::Delete {
                    object_type: MATERIAL_CANDIDATE_OBJECT_TYPE.into(),
                    id: candidate,
                    expected_version: staged.resource_version,
                },
            ])
            .await;
        match result {
            Ok(_) => Ok(intent),
            Err(PersistenceError::Conflict { .. }) => {
                let previous = self.warm_claim(workspace, route).await?;
                matching_claim(intent, previous)
            }
            Err(error) => Err(format!("persist warm claim: {error}")),
        }
    }

    /// Read only a committed, still-current launch for this physical supervisor.
    /// A prepared row is a pending registration, never a reason to reconnect.
    pub(crate) async fn dedicated_registration(
        &self,
        expected: &openshell_core::proto::compute::v1::SupervisorRegistrationIdentity,
    ) -> Result<Option<Vec<u8>>, tonic::Status> {
        self.check_dedicated_registration(expected)
            .await
            .map(|(_, material)| material)
    }

    pub(crate) async fn check_dedicated_registration(
        &self,
        expected: &openshell_core::proto::compute::v1::SupervisorRegistrationIdentity,
    ) -> Result<(crate::persistence::ObjectStamp, Option<Vec<u8>>), tonic::Status> {
        let refused =
            || tonic::Status::permission_denied("physical supervisor has no current claim");
        let record = self
            .assignment(&expected.route)
            .await
            .map_err(|_| tonic::Status::unavailable("cannot read supervisor assignment"))?
            .ok_or_else(refused)?;
        let payload = &record.payload;
        let stamp = crate::persistence::ObjectStamp {
            id: assignment_object_id(&payload.route, &payload.writer),
            resource_version: record.resource_version,
        };
        if !self.dedicated
            || !payload.dedicated
            || payload.phase != RecordPhase::Published
            || payload.generation != expected.generation
        {
            return Err(refused());
        }
        let material = self
            .load_material(payload)
            .await
            .map_err(|_| tonic::Status::unavailable("cannot read supervisor launch material"))?;
        let assignment = SandboxInstanceAssignment {
            route: payload.route.clone(),
            generation: payload.generation.clone(),
            sandbox_id: payload.sandbox_id.clone(),
            prepared: payload.prepared,
            launch_material: material.clone(),
            ..Default::default()
        };
        let descriptor = if payload.prepared {
            PreparedRuntimeRegistration::from_assignment(&assignment)
                .map_err(|_| refused())?
                .runtime_descriptor
        } else {
            SandboxInstanceRegistration::from_assignment(&assignment)
                .map_err(|_| refused())?
                .runtime_descriptor
        };
        if descriptor.session_id.to_string() != expected.session_id
            || (descriptor.resource_claims.len() != expected.resource_claims.len()
                || descriptor
                    .resource_claims
                    .iter()
                    .any(|(key, value)| expected.resource_claims.get(key) != Some(value)))
        {
            return Err(refused());
        }
        if payload.prepared {
            return Ok((stamp, None));
        }
        let registration =
            SandboxInstanceRegistration::from_assignment(&assignment).map_err(|_| refused())?;
        let authenticated = self
            .authority
            .verify_gateway_token(registration.auth.gateway_token.expose_secret())
            .map_err(|_| refused())?;
        if authenticated.sandbox_id.as_str() != payload.sandbox_id {
            return Err(refused());
        }
        let (sandbox, identity) =
            crate::auth::sandbox_session::authorize_persisted_sandbox(&self.store, &authenticated)
                .await
                .map_err(|rejection| {
                    if rejection.status.code() == tonic::Code::Unavailable {
                        tonic::Status::unavailable("cannot read sandbox identity")
                    } else {
                        refused()
                    }
                })?;
        if sandbox.object_workspace() != payload.workspace
            || !matches!(
                SandboxPhase::try_from(sandbox.phase()),
                Ok(SandboxPhase::Provisioning | SandboxPhase::Starting | SandboxPhase::Ready)
            )
            || identity.runtime_generation != registration.auth.runtime_generation
            || identity.auth_epoch != registration.auth.auth_epoch
            || identity.prepared_runtime.as_ref().is_none_or(|binding| {
                binding.session_id() != descriptor.session_id
                    || binding.resource_claims() != &descriptor.resource_claims
            })
        {
            return Err(refused());
        }
        Ok((stamp, Some(material)))
    }

    pub(super) async fn prepared_runtimes(
        &self,
        workspace: &str,
        routes: Vec<String>,
    ) -> Result<Vec<PreparedRuntime>, String> {
        if workspace.is_empty() {
            return Err("a prepared runtime inventory requires a workspace".into());
        }
        if routes.is_empty() {
            return Ok(Vec::new());
        }
        let mut records = Vec::with_capacity(routes.len());
        for route in routes {
            if let Some(record) = self.assignment(&route).await.map_err(|e| e.to_string())? {
                records.push(record);
            }
        }
        let (owners, members) = if self.dedicated {
            Default::default()
        } else {
            tokio::try_join!(self.owners(), self.live_members()).map_err(|e| e.to_string())?
        };
        let mut runtimes = Vec::new();
        for record in records.iter().filter(|record| {
            record.payload.prepared
                && record.payload.dedicated == self.dedicated
                && record.payload.workspace == workspace
                && record.payload.phase == RecordPhase::Published
        }) {
            let payload = &record.payload;
            let registration =
                PreparedRuntimeRegistration::from_assignment(&SandboxInstanceAssignment {
                    route: payload.route.clone(),
                    generation: payload.generation.clone(),
                    launch_material: self.load_material(payload).await?,
                    prepared: true,
                    ..Default::default()
                })
                .map_err(|e| e.to_string())?;
            let auth_epoch = openshell_core::jwt::CredentialEpoch::new(payload.prepared_epoch)
                .map_err(|e| e.to_string())?;
            let owner = owners
                .get(&payload.route)
                .filter(|owner| {
                    owner.payload.phase == OwnerPhase::Granted
                        && owner.payload.sandbox_id.is_empty()
                        && owner.payload.generation == payload.generation
                        && owner.payload.auth_epoch == payload.prepared_epoch
                })
                .map(|owner| PreparedRuntimeOwner {
                    member_id: owner.payload.member_id.clone(),
                    process_id: owner.payload.process_id.clone(),
                    available: owner_alive(&owner.payload, &members),
                });
            let owner = if self.dedicated {
                // Pod liveness and the parked TLS connection are checked by the
                // driver against the immutable supervisor Pod UID.
                registration
                    .runtime_descriptor
                    .resource_claims
                    .get("kubernetes.supervisor_pod_uid")
                    .map(|uid| PreparedRuntimeOwner {
                        member_id: uid.clone(),
                        process_id: uid.clone(),
                        available: true,
                    })
            } else {
                owner
            };
            runtimes.push(PreparedRuntime {
                revision: PreparationRevision {
                    workspace: workspace.to_string(),
                    route: payload.route.clone(),
                    reservation_id: payload.writer.clone(),
                    resource_version: record.resource_version,
                },
                registration,
                auth_epoch,
                published_at_ms: record.updated_at_ms,
                owner,
            });
        }
        Ok(runtimes)
    }

    pub(super) async fn release_preparation(
        &self,
        revision: PreparationRevision,
    ) -> Result<PreparationRelease, String> {
        if revision.workspace.is_empty()
            || revision.route.is_empty()
            || revision.reservation_id.is_empty()
            || revision.resource_version == 0
        {
            return Err("release requires an exact prepared runtime revision".into());
        }
        let Some(row) = self
            .store
            .get_by_name(ASSIGNMENT_OBJECT_TYPE, "", &revision.route)
            .await
            .map_err(|e| e.to_string())?
        else {
            return Ok(PreparationRelease::Absent);
        };
        let record = decode_assignment(&row)
            .ok_or("invalid supervisor pool assignment during preparation release")?;
        if record.payload.prepared
            && record.payload.phase == RecordPhase::Retired
            && record.payload.workspace == revision.workspace
            && record.payload.writer == revision.reservation_id
        {
            return Ok(PreparationRelease::Released);
        }
        if !record.payload.prepared
            || !record.payload.claim_handle.is_empty()
            || record.payload.phase != RecordPhase::Published
            || record.payload.workspace != revision.workspace
            || record.payload.writer != revision.reservation_id
            || record.resource_version != revision.resource_version
        {
            return Ok(PreparationRelease::Changed);
        }
        // Activation updates the same assignment version in its transaction.
        // Losing this CAS must never enqueue a route-only withdrawal, which
        // would delete the winning claim on the next reconciliation pass.
        if self.try_retire_assignment(&record).await? {
            Ok(PreparationRelease::Released)
        } else {
            Ok(PreparationRelease::Changed)
        }
    }

    pub(super) async fn prepare_runtime(&self, request: PreparationRequest) -> Result<(), String> {
        if request.workspace.is_empty() {
            return Err("a runtime preparation requires a workspace".into());
        }
        let assignment = request
            .registration
            .to_assignment()
            .map_err(|e| e.to_string())?;
        if self.dedicated {
            if !request
                .registration
                .runtime_descriptor
                .resource_claims
                .contains_key("kubernetes.supervisor_pod_uid")
            {
                return Err("dedicated preparation requires its supervisor Pod identity".into());
            }
            return self
                .record_assignment_scoped(
                    &assignment,
                    RecordPhase::Published,
                    Some((
                        &request.workspace,
                        request.auth_epoch.get(),
                        &request.pool_id,
                    )),
                )
                .await
                .map(drop);
        }
        self.place_scoped(
            PlacementRequest {
                assignment,
                auth_epoch: request.auth_epoch.get(),
            },
            Some((&request.workspace, &request.pool_id)),
        )
        .await
    }

    /// Retire from physical coordinates, including before a reservation exists.
    /// Insertion and preparation contend on the route's unique name; updates and
    /// activation contend on the assignment version. There is no unfenced gap.
    pub(super) async fn retire_preparation(
        &self,
        retirement: PreparationRetirement,
    ) -> Result<PreparationRelease, String> {
        if retirement.workspace.is_empty() || retirement.route.is_empty() {
            return Err("retirement requires scoped physical runtime coordinates".into());
        }
        for _ in 0..TRANSITION_ATTEMPTS {
            let row = self
                .store
                .get_by_name(ASSIGNMENT_OBJECT_TYPE, "", &retirement.route)
                .await
                .map_err(|e| e.to_string())?;
            if let Some(row) = row {
                let record = decode_assignment(&row)
                    .ok_or("invalid supervisor pool assignment during retirement")?;
                let payload = &record.payload;
                if !payload.prepared
                    || !payload.claim_handle.is_empty()
                    || !payload.sandbox_id.is_empty()
                    || payload.workspace != retirement.workspace
                    || payload.generation != retirement.generation.as_str()
                    || payload.prepared_epoch != retirement.auth_epoch.get()
                {
                    return Ok(PreparationRelease::Changed);
                }
                if payload.phase == RecordPhase::Retired
                    || self.try_retire_assignment(&record).await?
                {
                    return Ok(PreparationRelease::Released);
                }
            } else {
                let payload = AssignmentPayload {
                    dedicated: self.dedicated,
                    route: retirement.route.clone(),
                    sandbox_id: String::new(),
                    generation: retirement.generation.to_string(),
                    workspace: retirement.workspace.clone(),
                    phase: RecordPhase::Retired,
                    writer: Uuid::new_v4().to_string(),
                    material_handle: Vec::new(),
                    prepared: true,
                    prepared_epoch: retirement.auth_epoch.get(),
                    prepared_session: retirement
                        .route
                        .strip_prefix("rt-")
                        .and_then(|session| session.parse().ok()),
                    activation_candidate: false,
                    claim_handle: Vec::new(),
                    pool_id: None,
                    claim_operation_id: None,
                };
                match self
                    .store
                    .put_if(
                        ASSIGNMENT_OBJECT_TYPE,
                        &assignment_object_id(&payload.route, &payload.writer),
                        &payload.route,
                        "",
                        &encode(&payload)?,
                        None,
                        WriteCondition::MustCreate,
                    )
                    .await
                {
                    Ok(_) => {
                        self.registrations.notify(&retirement.route);
                        return Ok(PreparationRelease::Released);
                    }
                    Err(
                        PersistenceError::UniqueViolation { .. }
                        | PersistenceError::Conflict { .. },
                    ) => {}
                    Err(error) => {
                        return Err(format!("fence physical runtime retirement: {error}"));
                    }
                }
            }
        }
        Err("physical runtime changed repeatedly during retirement".into())
    }

    /// Replace the material and logical identity in one write, conditioned on
    /// the preparation, its owner, the Sandbox identity, and a material staging
    /// row. The owner process and capacity row never change during a claim.
    pub(super) async fn activate_runtime(
        &self,
        request: ActivationRequest,
    ) -> Result<SandboxInstanceAssignment, String> {
        self.activate_runtime_attempt(request, 4).await
    }

    async fn activate_runtime_attempt(
        &self,
        request: ActivationRequest,
        retries: u8,
    ) -> Result<SandboxInstanceAssignment, String> {
        let assignment = &request.assignment;
        let mut registration =
            SandboxInstanceRegistration::from_assignment(assignment).map_err(|e| e.to_string())?;
        let launch_epoch = registration.auth.auth_epoch.get();
        if assignment.takeover.is_some() {
            return Err("activation must use the prepared launch epoch".into());
        }
        let record = self
            .assignment(&assignment.route)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("the runtime has no durable preparation")?;
        if record.payload.dedicated != self.dedicated
            || record.payload.phase != RecordPhase::Published
        {
            return Err("the runtime preparation has not been admitted".into());
        }
        let material = self.load_material(&record.payload).await?;
        if !record.payload.prepared {
            // The gateway minted the stored credentials. Compare the driver's
            // immutable request using those credentials, then return the winner
            // rather than minting again after an ambiguous response.
            let winning = SandboxInstanceAssignment {
                route: record.payload.route.clone(),
                sandbox_id: record.payload.sandbox_id.clone(),
                generation: record.payload.generation.clone(),
                launch_material: material,
                ..Default::default()
            };
            let stored = SandboxInstanceRegistration::from_assignment(&winning)
                .map_err(|e| e.to_string())?;
            let current = self
                .store
                .get_message::<Sandbox>(&winning.sandbox_id)
                .await
                .map_err(|e| e.to_string())?
                .ok_or("the claiming sandbox no longer exists")?;
            let identity = current
                .metadata
                .as_ref()
                .and_then(|meta| PersistedSandboxIdentity::read(&meta.annotations).ok())
                .ok_or("the claiming sandbox identity is invalid")?;
            let binding = identity.prepared_runtime.as_ref();
            if current.object_workspace() != record.payload.workspace
                || !matches!(
                    SandboxPhase::try_from(current.phase()),
                    Ok(SandboxPhase::Provisioning | SandboxPhase::Starting | SandboxPhase::Ready)
                )
                || identity.runtime_generation != stored.auth.runtime_generation
                || identity.auth_epoch != stored.auth.auth_epoch
                || binding.is_none_or(|binding| {
                    binding.session_id() != stored.runtime_descriptor.session_id
                        || binding.resource_claims() != &stored.runtime_descriptor.resource_claims
                })
            {
                return Err("the winning claim is no longer the sandbox's current launch".into());
            }
            replace_session_tokens(&mut registration.auth, stored.auth);
            return if registration.to_assignment().map_err(|e| e.to_string())? == winning {
                Ok(winning)
            } else {
                Err("the runtime has already been claimed".into())
            };
        }
        let prepared = PreparedRuntimeRegistration::from_assignment(&SandboxInstanceAssignment {
            route: record.payload.route.clone(),
            generation: record.payload.generation.clone(),
            launch_material: material,
            prepared: true,
            ..Default::default()
        })
        .map_err(|e| e.to_string())?;
        prepared
            .validate_activation(&registration)
            .map_err(|e| e.to_string())?;
        if record.payload.prepared_epoch != launch_epoch {
            return Err("the prepared runtime launch epoch changed".into());
        }
        let owner = if self.dedicated {
            None
        } else {
            let Reconciled::Changed(owner) = self
                .reload(&assignment.route)
                .await
                .map_err(|e| e.to_string())?
            else {
                return Err("the prepared runtime has no reserved supervisor".into());
            };
            let members = self.live_members().await.map_err(|e| e.to_string())?;
            if owner.payload.phase != OwnerPhase::Granted
                || !owner.payload.sandbox_id.is_empty()
                || owner.payload.generation != assignment.generation
                || owner.payload.auth_epoch != launch_epoch
                || record.payload.prepared_epoch != launch_epoch
                || !owner_alive(&owner.payload, &members)
            {
                return Err(
                    "the prepared runtime's supervisor or launch epoch is no longer available"
                        .into(),
                );
            }
            Some(owner)
        };
        let sandbox_row = self
            .store
            .get(Sandbox::object_type(), &assignment.sandbox_id)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("the claiming sandbox does not exist")?;
        let mut sandbox = Sandbox::decode(sandbox_row.payload.as_slice())
            .map_err(|_| "the claiming sandbox is invalid")?;
        let mut identity = sandbox
            .metadata
            .as_ref()
            .and_then(|meta| PersistedSandboxIdentity::read(&meta.annotations).ok())
            .ok_or("the claiming sandbox identity is invalid")?;
        if sandbox.object_workspace() != record.payload.workspace
            || crate::compute::provisioning_deadline::timed_out(&sandbox)
            || identity.runtime_generation != request.expected_generation
            || identity.auth_epoch != request.expected_auth_epoch
            || !matches!(
                SandboxPhase::try_from(sandbox.phase()),
                Ok(SandboxPhase::Provisioning | SandboxPhase::Starting)
            )
        {
            return Err(
                "the claim does not match the prepared workspace, generation, and epoch".into(),
            );
        }
        let claim_link = read_claim_link(&sandbox)?;
        if let Some(link) = &claim_link
            && link.generation == request.expected_generation
            && link.auth_epoch == request.expected_auth_epoch
            && (link.decision != LaunchDecision::Warm || link.route != assignment.route)
        {
            return Err("activation lost the sandbox launch decision".into());
        }
        if request.runtime_identity.is_empty() {
            return Err("warm activation requires a compute runtime identity".into());
        }
        if let Some(operation) = sandbox
            .status
            .as_mut()
            .and_then(|status| status.provisioning.as_mut())
        {
            let owns_launch = claim_link.as_ref().is_some_and(|link| {
                link.generation == request.expected_generation
                    && link.auth_epoch == request.expected_auth_epoch
                    && link.route == assignment.route
                    && link.decision == LaunchDecision::Warm
            });
            if !owns_launch
                || !operation.driver_operation_pending
                || record
                    .payload
                    .claim_operation_id
                    .as_ref()
                    .is_some_and(|id| id != &operation.driver_operation_id)
            {
                return Err("warm claim driver operation changed".into());
            }
            // The activation CAS is the durable CREATE result, including when
            // another replica completes this reservation after the caller exits.
            operation.driver_operation_pending = false;
            operation.cleanup_completed_time = None;
        }
        let mut binding = PreparedRuntimeIdentity::new(
            prepared.runtime_descriptor.session_id,
            prepared.runtime_descriptor.resource_claims.clone(),
        )
        .map_err(|e| e.to_string())?;
        if identity.prepared_runtime.is_some() {
            return Err("the sandbox generation has already claimed a runtime".into());
        }
        binding
            .set_claim_source(identity.runtime_generation.clone(), identity.auth_epoch)
            .map_err(|error| error.to_string())?;
        identity.prepared_runtime = Some(binding);
        identity.runtime_generation = registration.auth.runtime_generation.clone();
        identity.auth_epoch = registration.auth.auth_epoch;
        // Credentials minted for the proposed cold launch must no longer work
        // once the Sandbox adopts the warm runtime's physical generation.
        identity.gateway_token_id = Uuid::new_v4();
        identity.refresh_replay = None;
        // All replicas renew this same physical binding, including a renewal
        // before the first authenticated Sandbox Protocol call.
        let authentication = self
            .authority
            .mint_persisted_launch(&assignment.sandbox_id, &identity)
            .map_err(|_| "could not mint prepared runtime credentials")?;
        replace_session_tokens(&mut registration.auth, authentication.supervisor);
        let annotations = &mut sandbox
            .metadata
            .as_mut()
            .ok_or("sandbox metadata is missing")?
            .annotations;
        identity.write(annotations);
        annotations.insert(
            crate::compute::COMPUTE_DRIVER_ANNOTATION.into(),
            "kubernetes".into(),
        );
        annotations.insert(
            crate::compute::COMPUTE_RUNTIME_IDENTITY_ANNOTATION.into(),
            request.runtime_identity.clone(),
        );
        let assignment = registration.to_assignment().map_err(|e| e.to_string())?;
        let assignment = &assignment;

        let mut payload = AssignmentPayload {
            sandbox_id: assignment.sandbox_id.clone(),
            prepared: false,
            ..record.payload.clone()
        };
        let handle = self
            .store_material(&payload, &assignment.launch_material)
            .await?;
        payload.material_handle = handle.encode_to_vec();
        let candidate = Uuid::new_v4().to_string();
        let staged_payload = AssignmentPayload {
            activation_candidate: true,
            phase: RecordPhase::Admitting,
            ..payload.clone()
        };
        let staged = self
            .store
            .put_if(
                MATERIAL_CANDIDATE_OBJECT_TYPE,
                &candidate,
                &candidate,
                "",
                &encode(&staged_payload)?,
                None,
                WriteCondition::MustCreate,
            )
            .await;
        let staged = match staged {
            Ok(staged) => staged,
            Err(error) => {
                // This task can no longer publish. If the staging write was
                // ambiguous, its candidate remains safe for later collection.
                if let Err(cleanup) = self.delete_material(&payload, handle).await {
                    warn!(route = %assignment.route, %cleanup, "could not remove unstaged activation material");
                }
                return Err(format!("stage runtime activation: {error}"));
            }
        };
        #[cfg(test)]
        {
            let gate = lock(&self.staged_gate).take();
            if let Some((reached, resume)) = gate {
                let _ = reached.send(());
                let _ = resume.await;
            }
        }
        // Credential storage can be slow. Recheck membership after staging so
        // a claim stalled past expiry or a host restart does not knowingly
        // publish to the obsolete process. Loss after this check is handled by
        // the ordinary assigned-instance lifecycle.
        let members = self.live_members().await.map_err(|e| e.to_string())?;
        if owner
            .as_ref()
            .is_some_and(|owner| !owner_alive(&owner.payload, &members))
        {
            return Err("the reserved supervisor became unavailable during activation".into());
        }
        let activated_owner = owner.as_ref().map(|owner| OwnerPayload {
            sandbox_id: assignment.sandbox_id.clone(),
            ..owner.payload.clone()
        });
        let obsolete = Uuid::new_v4().to_string();
        let mut writes = vec![
            AtomicWrite::Update {
                object_type: ASSIGNMENT_OBJECT_TYPE.into(),
                id: assignment_object_id(&record.payload.route, &record.payload.writer),
                payload: encode(&payload)?,
                expected_version: record.resource_version,
            },
            // Fence a concurrent stop, deletion, or credential-epoch change.
            AtomicWrite::Update {
                object_type: Sandbox::object_type().into(),
                id: assignment.sandbox_id.clone(),
                payload: sandbox.encode_to_vec(),
                expected_version: sandbox_row.resource_version,
            },
            AtomicWrite::Delete {
                object_type: MATERIAL_CANDIDATE_OBJECT_TYPE.into(),
                id: candidate.clone(),
                expected_version: staged.resource_version,
            },
            material_candidate(&obsolete, &record.payload)?,
        ];
        if let (Some(owner), Some(activated)) = (&owner, &activated_owner) {
            writes.insert(
                1,
                AtomicWrite::Update {
                    object_type: OWNER_OBJECT_TYPE.into(),
                    id: owner_object_id(&assignment.route),
                    payload: encode(activated)?,
                    expected_version: owner.resource_version,
                },
            );
        }
        // Keep staged material on failure: even an ambiguous database outcome
        // is safe. Collection fences the staging row before deleting its secret.
        let results = match self.store.write_atomically(&writes).await {
            Ok(results) => results,
            Err(error @ PersistenceError::Conflict { .. }) if retries > 0 => {
                // A concurrent reconciliation can refresh the owner or publish
                // this same claim. Reload all fences before retrying, unless
                // collection has already fenced this activation's material.
                let candidate_unchanged = self
                    .store
                    .get(MATERIAL_CANDIDATE_OBJECT_TYPE, &candidate)
                    .await
                    .map_err(|e| format!("reload activation candidate: {e}"))?
                    .is_some_and(|row| row.resource_version == staged.resource_version);
                if !candidate_unchanged {
                    return Err(format!("claim prepared runtime: {error}"));
                }
                self.discard_candidate(&candidate, &staged_payload).await;
                return Box::pin(self.activate_runtime_attempt(request, retries - 1)).await;
            }
            Err(error) => return Err(format!("claim prepared runtime: {error}")),
        };
        self.registrations.notify(&assignment.route);
        if let Some(activated_owner) = activated_owner {
            lock(&self.materials).insert(assignment.route.clone(), assignment.clone());
            self.placed(
                assignment,
                OwnerRecord {
                    payload: activated_owner,
                    resource_version: results[1]
                        .as_ref()
                        .map_or(0, |written| written.resource_version),
                },
            );
        }
        self.discard_candidate(&obsolete, &record.payload).await;
        Ok(assignment.clone())
    }

    /// Fence an activation before deleting its material. Publication deletes
    /// exactly the original candidate version, so it cannot race collection.
    pub(super) async fn collect_activation_candidate(
        &self,
        candidate: &ObjectRecord,
        mut payload: AssignmentPayload,
    ) {
        if payload.phase != RecordPhase::Reserved {
            payload.phase = RecordPhase::Reserved;
            let Ok(bytes) = encode(&payload) else {
                return;
            };
            if self
                .store
                .put_if(
                    MATERIAL_CANDIDATE_OBJECT_TYPE,
                    &candidate.id,
                    &candidate.name,
                    "",
                    &bytes,
                    None,
                    WriteCondition::MatchResourceVersion(candidate.resource_version),
                )
                .await
                .is_err()
            {
                return;
            }
        }
        self.discard_candidate(&candidate.id, &payload).await;
    }

    /// Fence the record before collecting its material. Deleting the secret
    /// first could destroy a preparation that concurrently won activation.
    pub(super) async fn retire_assignment(&self, record: &AssignmentRecord) -> Result<(), String> {
        if self.try_retire_assignment(record).await? {
            Ok(())
        } else {
            Err("the runtime assignment changed during withdrawal".into())
        }
    }

    async fn try_retire_assignment(&self, record: &AssignmentRecord) -> Result<bool, String> {
        if record.payload.prepared && !record.payload.claim_handle.is_empty() {
            return Ok(false);
        }
        self.commit_retirement(record, Vec::new()).await
    }

    async fn commit_retirement(
        &self,
        record: &AssignmentRecord,
        mut writes: Vec<AtomicWrite>,
    ) -> Result<bool, String> {
        let candidate = Uuid::new_v4().to_string();
        let retire = if record.payload.prepared || record.payload.prepared_epoch != 0 {
            let payload = AssignmentPayload {
                phase: RecordPhase::Retired,
                material_handle: Vec::new(),
                claim_handle: Vec::new(),
                ..record.payload.clone()
            };
            AtomicWrite::Update {
                object_type: ASSIGNMENT_OBJECT_TYPE.into(),
                id: assignment_object_id(&payload.route, &payload.writer),
                payload: encode(&payload)?,
                expected_version: record.resource_version,
            }
        } else {
            AtomicWrite::Delete {
                object_type: ASSIGNMENT_OBJECT_TYPE.into(),
                id: assignment_object_id(&record.payload.route, &record.payload.writer),
                expected_version: record.resource_version,
            }
        };
        writes.push(retire);
        if !record.payload.claim_handle.is_empty() {
            writes.push(material_candidate(
                &Uuid::new_v4().to_string(),
                &claim_material(&record.payload),
            )?);
        }
        // Reserved/admitting recordings already have a candidate (or are still
        // writing one). Their original version can no longer publish it.
        let collect = record.payload.phase == RecordPhase::Published;
        if collect {
            writes.push(material_candidate(&candidate, &record.payload)?);
        }
        match self.store.write_atomically(&writes).await {
            Ok(_) => {
                self.registrations.notify(&record.payload.route);
                lock(&self.materials).remove(&record.payload.route);
                if collect {
                    self.discard_candidate(&candidate, &record.payload).await;
                }
                Ok(true)
            }
            Err(PersistenceError::Conflict { .. }) => Ok(false),
            Err(error) => Err(format!("withdraw runtime assignment: {error}")),
        }
    }
}

fn read_claim_link(sandbox: &Sandbox) -> Result<Option<ClaimLink>, String> {
    sandbox
        .metadata
        .as_ref()
        .and_then(|meta| meta.annotations.get(CLAIM_LINK))
        .map(|value| serde_json::from_str(value).map_err(|_| "invalid warm claim link".into()))
        .transpose()
}

fn write_claim_link(sandbox: &mut Sandbox, link: &ClaimLink) -> Result<(), String> {
    sandbox
        .metadata
        .as_mut()
        .ok_or("sandbox metadata missing")?
        .annotations
        .insert(
            CLAIM_LINK.into(),
            serde_json::to_string(link).map_err(|e| e.to_string())?,
        );
    Ok(())
}

fn launch_is_current(sandbox: &Sandbox, lookup: &WarmClaimLookup) -> bool {
    let identity = sandbox
        .metadata
        .as_ref()
        .and_then(|meta| PersistedSandboxIdentity::read(&meta.annotations).ok());
    sandbox.object_workspace() == lookup.workspace
        && !crate::compute::provisioning_deadline::timed_out(sandbox)
        && matches!(
            SandboxPhase::try_from(sandbox.phase()),
            Ok(SandboxPhase::Provisioning | SandboxPhase::Starting)
        )
        && identity.is_some_and(|identity| {
            identity.runtime_generation == lookup.expected_generation
                && identity.auth_epoch == lookup.expected_auth_epoch
                && identity.prepared_runtime.is_none()
        })
}

fn claim_is_current(
    sandbox: &Sandbox,
    workspace: &str,
    intent: &WarmClaimIntent,
) -> Result<bool, String> {
    Ok(launch_is_current(
        sandbox,
        &WarmClaimLookup {
            workspace: workspace.into(),
            sandbox_id: intent.registration.sandbox_id.clone(),
            expected_generation: intent.expected_generation.clone(),
            expected_auth_epoch: intent.expected_auth_epoch,
        },
    ) && read_claim_link(sandbox)?.is_some_and(|link| {
        link.decision == LaunchDecision::Warm
            && link.route == intent.registration.route
            && link.generation == intent.expected_generation
            && link.auth_epoch == intent.expected_auth_epoch
    }))
}

/// Keep the launch's SSH identity, telemetry, and session rotation, while the
/// gateway owns the session credentials. The physical session and generation
/// have already been checked against the prepared descriptor.
fn replace_session_tokens(
    auth: &mut openshell_core::jwt::SupervisorAuthBundle,
    issued: openshell_core::jwt::SupervisorAuthBundle,
) {
    auth.gateway_token = issued.gateway_token;
    auth.gateway_expires_at = issued.gateway_expires_at;
    auth.sandbox_token = issued.sandbox_token;
    auth.sandbox_expires_at = issued.sandbox_expires_at;
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|_| "could not encode runtime reservation".into())
}

fn material_candidate(id: &str, payload: &AssignmentPayload) -> Result<AtomicWrite, String> {
    Ok(AtomicWrite::Create {
        object_type: MATERIAL_CANDIDATE_OBJECT_TYPE.into(),
        id: id.into(),
        name: id.into(),
        workspace: String::new(),
        payload: encode(payload)?,
    })
}

/// The intent is always owned by the physical route, including after activation.
fn claim_material(payload: &AssignmentPayload) -> AssignmentPayload {
    AssignmentPayload {
        prepared: true,
        sandbox_id: String::new(),
        material_handle: payload.claim_handle.clone(),
        claim_handle: Vec::new(),
        activation_candidate: false,
        ..payload.clone()
    }
}

fn matching_claim(
    mut requested: WarmClaimIntent,
    previous: WarmClaimIntent,
) -> Result<WarmClaimIntent, String> {
    // Attempt-local material and refreshed session tokens do not replace the
    // winner. Activation issues credentials for the persisted physical binding.
    replace_session_tokens(
        &mut requested.registration.auth,
        previous.registration.auth.clone(),
    );
    requested
        .registration
        .proxy_ca
        .clone_from(&previous.registration.proxy_ca);
    requested
        .registration
        .trace_context
        .clone_from(&previous.registration.trace_context);
    if encode(&requested)? != encode(&previous)? {
        return Err("warm runtime already has a different claim intent".into());
    }
    Ok(previous)
}
