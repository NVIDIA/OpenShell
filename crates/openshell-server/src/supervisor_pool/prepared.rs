// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Durable preparation and claim of a physical runtime on its reserved host.

use super::*;
use crate::auth::sandbox_session::PreparedRuntimeIdentity;
use crate::persistence::ObjectType;
use openshell_supervisor_control::{PreparedRuntimeRegistration, SandboxInstanceRegistration};

impl SupervisorPool {
    /// Read only a committed, still-current launch for this physical supervisor.
    /// A prepared row is a pending registration, never a reason to reconnect.
    pub(crate) async fn dedicated_registration(
        &self,
        expected: &openshell_core::proto::compute::v1::SupervisorRegistrationIdentity,
    ) -> Result<Option<Vec<u8>>, tonic::Status> {
        let refused =
            || tonic::Status::permission_denied("physical supervisor has no current claim");
        let record = self
            .assignment(&expected.route)
            .await
            .map_err(|_| tonic::Status::unavailable("cannot read supervisor assignment"))?
            .ok_or_else(refused)?;
        let payload = &record.payload;
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
            return Ok(None);
        }
        let registration =
            SandboxInstanceRegistration::from_assignment(&assignment).map_err(|_| refused())?;
        let sandbox = self
            .store
            .get_message::<Sandbox>(&payload.sandbox_id)
            .await
            .map_err(|_| tonic::Status::unavailable("cannot read sandbox claim"))?
            .ok_or_else(refused)?;
        let identity = sandbox
            .metadata
            .as_ref()
            .and_then(|meta| PersistedSandboxIdentity::read(&meta.annotations).ok())
            .ok_or_else(refused)?;
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
        let authenticated = self
            .authority
            .verify_gateway_token(registration.auth.gateway_token.expose_secret())
            .map_err(|_| refused())?;
        crate::auth::sandbox_session::authorize_persisted(&self.store, &authenticated)
            .await
            .map_err(|_| refused())?;
        Ok(Some(material))
    }

    pub(super) async fn prepared_runtimes(
        &self,
        workspace: &str,
    ) -> Result<Vec<PreparedRuntime>, String> {
        if workspace.is_empty() {
            return Err("a prepared runtime inventory requires a workspace".into());
        }
        // This inventory authorizes infrastructure cleanup. Do not silently
        // omit a malformed row as the best-effort pool view does.
        let records = self
            .list_all(ASSIGNMENT_OBJECT_TYPE)
            .await
            .map_err(|e| e.to_string())?
            .iter()
            .map(|row| {
                decode_assignment(row).ok_or_else(|| {
                    "invalid supervisor pool assignment in preparation inventory".to_string()
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let owners = self.owners().await.map_err(|e| e.to_string())?;
        let members = self.live_members().await.map_err(|e| e.to_string())?;
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
                    Some((&request.workspace, request.auth_epoch.get())),
                )
                .await
                .map(drop);
        }
        self.place_scoped(
            PlacementRequest {
                assignment,
                auth_epoch: request.auth_epoch.get(),
            },
            Some(&request.workspace),
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
                    activation_candidate: false,
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
                    Ok(_) => return Ok(PreparationRelease::Released),
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
        identity.write(
            &mut sandbox
                .metadata
                .as_mut()
                .ok_or("sandbox metadata is missing")?
                .annotations,
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
                id: candidate,
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
        let results = self
            .store
            .write_atomically(&writes)
            .await
            .map_err(|e| format!("claim prepared runtime: {e}"))?;
        lock(&self.materials).insert(assignment.route.clone(), assignment.clone());
        self.claim_changed.notify_waiters();
        if let Some(activated_owner) = activated_owner {
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
        let candidate = Uuid::new_v4().to_string();
        let retire = if record.payload.prepared || record.payload.prepared_epoch != 0 {
            let payload = AssignmentPayload {
                phase: RecordPhase::Retired,
                material_handle: Vec::new(),
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
        let mut writes = vec![retire];
        // Reserved/admitting recordings already have a candidate (or are still
        // writing one). Their original version can no longer publish it.
        let collect = record.payload.phase == RecordPhase::Published;
        if collect {
            writes.push(material_candidate(&candidate, &record.payload)?);
        }
        match self.store.write_atomically(&writes).await {
            Ok(_) => {
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
