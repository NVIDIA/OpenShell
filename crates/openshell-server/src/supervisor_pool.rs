// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Durable state of a highly available pool of shared supervisors.
//!
//! The pool reuses the gateway's own HA pattern for the shared supervisor's
//! sandbox instances:
//!
//! - **Membership.** The gateway replica serving a member's stream refreshes a
//!   store record for it; a record older than [`MEMBER_TTL`] is dead. A member
//!   that announces it is leaving is out of the pool at once, and a member
//!   whose process changed lost every instance its previous process owned.
//! - **Placement.** A consistent-hash ring ([`GatewayRing`]) over live members
//!   chooses the member a new instance launches on.
//! - **Ownership.** A store record per instance, written only with
//!   compare-and-swap, names the owning member, its process, and the ownership
//!   term. It is authoritative: a live owner keeps its instances whatever the
//!   ring says, so membership changes move nothing that is healthy.
//! - **Takeover.** Only an instance whose owner failed or left moves, to the
//!   ring's choice among live members. The takeover first records its intent
//!   (new owner, next term, the process identity the runtime will pin, and a
//!   new gateway-token lineage), then advances the sandbox's persisted
//!   credential epoch to the new term, which revokes every credential of the
//!   previous owner on every gateway replica, and only then is granted. Any
//!   replica resumes an interrupted intent; a stopping, stopped, or deleted
//!   sandbox, or a replaced generation, cancels it.
//!
//! - **Desired set.** Every pool instance has a store record, written on the
//!   gateway replica that launches it before its owner is recorded, and
//!   removed when it is withdrawn, its generation ends, or the compute
//!   driver's recovery no longer lists it. Its launch material is kept in the
//!   gateway's credential store, as sandbox SSH host keys are, and the record
//!   holds only the handle. Every replica derives the pool's desired set from
//!   these records, whether or not it runs the compute driver's watch, and
//!   loads the material of the instances its own members own.
//! - **Observations.** The replica serving an owner records what the owner
//!   reports of its instances, so every replica can judge an instance whose
//!   owner streams elsewhere.
//!
//! Each replica serves the members connected to it the credentials of their
//! terms, minted from the granted record and the persisted identity.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use openshell_core::ObjectWorkspace as _;
use openshell_core::jwt::{SandboxId, SupervisorTakeover};
use openshell_core::proto::datamodel::v1::{CredentialHandle, ObjectMeta, Provider};
use openshell_core::proto::{Sandbox, SandboxPhase};
use openshell_core::time::now_ms;
use openshell_supervisor_control::proto::{
    SandboxInstanceAssignment, SandboxInstanceStatus, SandboxInstanceTakeover,
};
use openshell_supervisor_control::{
    ConnectedMember, InstanceOwner, InstancePlacement, MAX_ASSIGNED_INSTANCES, MAX_POOL_INSTANCES,
    MemberView, PlacementFuture, PlacementRequest, PoolView, SupervisorHostController,
};
use prost::Message as _;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::auth::sandbox_jwt::SandboxSessionJwtAuthority;
use crate::auth::sandbox_session::{
    PersistedSandboxIdentity, TakeoverIdentity, advance_identity_for_takeover,
};
use crate::credentials::CredentialRuntime;
use crate::gateway_ring::GatewayRing;
use crate::persistence::{ObjectRecord, PersistenceError, Store, WriteCondition};

const MEMBER_OBJECT_TYPE: &str = "supervisor_pool_member";
const OWNER_OBJECT_TYPE: &str = "supervisor_instance_owner";
const ASSIGNMENT_OBJECT_TYPE: &str = "supervisor_instance_assignment";
/// Launch material stored for an instance record not yet written; the row
/// owns the material's handle until the record does, so a cancelled or
/// failed recording never loses the only handle.
const MATERIAL_CANDIDATE_OBJECT_TYPE: &str = "supervisor_instance_material_candidate";
const REPORT_OBJECT_TYPE: &str = "supervisor_instance_report";
/// Credential key of an instance's launch material in the credential store.
const LAUNCH_MATERIAL_KEY: &str = "SHARED_INSTANCE_LAUNCH_MATERIAL";

/// How long a member's record stays live without a refresh.
pub const MEMBER_TTL: Duration = Duration::from_secs(15);
/// How often each gateway replica refreshes its members and reconciles.
pub const RECONCILE_INTERVAL: Duration = Duration::from_secs(2);
/// How long a desired instance may lack an owner record before a replica
/// places it by takeover; a launch records its owner within this.
const UNOWNED_GRACE: Duration = Duration::from_secs(10);
/// Lifetime of the takeover grants this gateway mints.
const TAKEOVER_GRANT_TTL: Duration = Duration::from_mins(10);
/// How long minted takeover credentials are served before they are minted
/// again from the persisted identity, which bounds how stale their grant and
/// gateway-token lineage can be when a host starts the term.
const TAKEOVER_CREDENTIAL_REFRESH: Duration = Duration::from_mins(1);
/// Records read back per list page.
const LIST_LIMIT: u32 = 1024;
/// How long after this replica starts it leaves instances of members that
/// look failed alone, so members cut off by a gateway restart reconnect and
/// refresh their records before anything moves.
const TAKEOVER_STARTUP_GRACE: Duration = Duration::from_secs(30);
/// Most records of ended generations removed per pass.
const CLEANUP_PER_PASS: usize = 64;
/// Most launch materials one pass loads from the credential store.
const LOAD_PER_PASS: usize = 64;
/// How long the owner record of a withdrawn instance is kept, so its owner is
/// told to stop it, when its generation has not visibly ended.
const WITHDRAWN_OWNER_RETENTION: Duration = Duration::from_mins(2);
/// How long a recording may hold its route's reservation before any replica
/// fences it, so a recording that stalled or died cannot block its route. A
/// fenced recording can no longer publish. Liveness only: collection keeps
/// the material of a recording that may still publish by its reservation,
/// not by age.
const RESERVATION_GRACE: Duration = Duration::from_mins(2);
/// Age before which a material candidate is left to the recording that staged
/// it, which removes the candidate itself; collection is safe at any age.
const MATERIAL_CANDIDATE_GRACE: Duration = Duration::from_mins(2);

fn member_object_id(member_id: &str) -> String {
    format!("supervisor-pool-member:{member_id}")
}

fn owner_object_id(route: &str) -> String {
    format!("supervisor-instance-owner:{route}")
}

/// One recording's row of `route`. The store's unique object name, the route,
/// keeps one row per route; the writer in the id keeps a recording from ever
/// updating another recording's row, even one that replaced its own.
fn assignment_object_id(route: &str, writer: &str) -> String {
    format!("supervisor-instance-assignment:{route}:{writer}")
}

fn report_object_id(route: &str) -> String {
    format!("supervisor-instance-report:{route}")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MemberPayload {
    member_id: String,
    member_uid: String,
    process_id: String,
    runtime_address: String,
    #[serde(default)]
    leaving: bool,
    /// When the stream that wrote this record was accepted.
    #[serde(default)]
    connected_at_ms: i64,
    gateway_replica: String,
}

/// A pool member whose record is live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveMember {
    pub member_id: String,
    pub process_id: String,
    pub runtime_address: String,
    pub leaving: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OwnerPhase {
    /// Intent recorded; the sandbox's credential epoch may not be advanced
    /// yet, so no credentials of the term may be issued.
    Granting,
    /// The term is in force.
    Granted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct OwnerPayload {
    route: String,
    sandbox_id: String,
    generation: String,
    member_id: String,
    process_id: String,
    /// Ownership term: the sandbox credential epoch of the owner.
    auth_epoch: u64,
    /// Process identity granted for a takeover term; absent for the launch
    /// term, whose process pins itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    supervisor_instance_id: Option<String>,
    /// Gateway-token lineage started by a takeover term.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gateway_token_id: Option<String>,
    phase: OwnerPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_member_id: Option<String>,
}

#[derive(Debug, Clone)]
struct OwnerRecord {
    payload: OwnerPayload,
    resource_version: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RecordPhase {
    /// A recording reserved the route; nothing is published.
    Reserved,
    /// The pool must run the instance, with this launch material.
    Published,
}

/// A pool instance the gateway must run, or a recording's reservation of its
/// route. The launch material lives in the credential store; the record
/// holds its handle. Material candidates have the same shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AssignmentPayload {
    route: String,
    sandbox_id: String,
    generation: String,
    /// Workspace of the sandbox, which scopes the material's credential.
    workspace: String,
    phase: RecordPhase,
    /// Token of the recording that reserved the route. It publishes only by
    /// advancing its own reservation.
    writer: String,
    /// Credential handle of the launch material (encoded `CredentialHandle`);
    /// empty in a reservation.
    material_handle: Vec<u8>,
}

#[derive(Debug, Clone)]
struct AssignmentRecord {
    payload: AssignmentPayload,
    resource_version: u64,
    /// When the route was reserved, which bounds a reservation's life.
    created_at_ms: i64,
    /// When the row was last written: for a published record, its
    /// publication, the one change after its reservation.
    updated_at_ms: i64,
}

/// What an owner reported of one instance, for gateway replicas that do not
/// serve the owner. Error text is not recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReportPayload {
    route: String,
    member_id: String,
    process_id: String,
    auth_epoch: u64,
    sandbox_id: String,
    phase: i32,
    ready: bool,
    exit_code: i32,
}

/// What reconciling one route did to its owner record.
#[derive(Debug)]
enum Reconciled {
    Unchanged,
    /// The record now reads as this.
    Changed(Box<OwnerRecord>),
    /// The record is gone.
    Removed,
}

/// One gateway replica's view and maintenance of the pool.
pub struct SupervisorPool {
    store: Arc<Store>,
    controller: SupervisorHostController,
    authority: Arc<SandboxSessionJwtAuthority>,
    /// Keeps the pool's launch material.
    credentials: CredentialRuntime,
    replica_id: String,
    member_ttl: Duration,
    unowned_grace: Duration,
    /// No takeover before this instant; see [`TAKEOVER_STARTUP_GRACE`].
    takeovers_from: tokio::time::Instant,
    /// When each desired route without an owner record was first seen.
    unowned_since: Mutex<HashMap<String, tokio::time::Instant>>,
    /// Takeover credentials minted for terms of members this replica serves.
    minted: Mutex<HashMap<(String, u64), (SandboxInstanceTakeover, tokio::time::Instant)>>,
    /// Launch material loaded for instances owned by members this replica
    /// serves, or launched here.
    materials: Mutex<HashMap<String, SandboxInstanceAssignment>>,
    /// The last report this replica recorded of each route.
    recorded_reports: Mutex<HashMap<String, ReportPayload>>,
    /// When each owner record of an instance that is no longer desired was
    /// first seen.
    withdrawn_since: Mutex<HashMap<String, tokio::time::Instant>>,
    /// Where the next pass resumes checking records for ended generations.
    sweep_from: Mutex<usize>,
    /// See [`MATERIAL_CANDIDATE_GRACE`].
    candidate_grace: Duration,
    /// See [`RESERVATION_GRACE`].
    reservation_grace: Duration,
    /// Pauses the next recording once its material is staged.
    #[cfg(test)]
    staged_gate: Mutex<
        Option<(
            tokio::sync::oneshot::Sender<()>,
            tokio::sync::oneshot::Receiver<()>,
        )>,
    >,
}

impl std::fmt::Debug for SupervisorPool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SupervisorPool")
            .field("replica_id", &self.replica_id)
            .finish_non_exhaustive()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The ring over live members that are not leaving.
fn ring_of(members: &[LiveMember]) -> GatewayRing {
    GatewayRing::new(
        members
            .iter()
            .filter(|member| !member.leaving)
            .map(|member| member.member_id.as_str()),
    )
}

/// The member to place `sandbox_id`'s instance on: the ring's choice while
/// it has room, else the least loaded live member that has. `load` counts
/// the instances each member owns.
fn choose<'a>(
    ring: &GatewayRing,
    members: &'a [LiveMember],
    sandbox_id: &str,
    load: &HashMap<String, usize>,
) -> Option<&'a LiveMember> {
    let has_room = |member: &&LiveMember| {
        !member.leaving
            && load.get(&member.member_id).copied().unwrap_or(0) < MAX_ASSIGNED_INSTANCES
    };
    let preferred = ring.owner_for(sandbox_id);
    members
        .iter()
        .find(|member| Some(member.member_id.as_str()) == preferred)
        .filter(has_room)
        .or_else(|| {
            members
                .iter()
                .filter(has_room)
                .min_by_key(|member| load.get(&member.member_id).copied().unwrap_or(0))
        })
}

/// Instances each member owns, pending takeovers included.
fn load_of<'a>(owners: impl IntoIterator<Item = &'a OwnerRecord>) -> HashMap<String, usize> {
    let mut load = HashMap::new();
    for record in owners {
        *load.entry(record.payload.member_id.clone()).or_insert(0) += 1;
    }
    load
}

/// Whether the process that owns `owner` still serves its member.
fn owner_alive(owner: &OwnerPayload, members: &[LiveMember]) -> bool {
    members.iter().any(|member| {
        member.member_id == owner.member_id
            && member.process_id == owner.process_id
            && !member.leaving
    })
}

fn decode_owner(record: &ObjectRecord) -> Option<OwnerRecord> {
    let payload = serde_json::from_slice::<OwnerPayload>(&record.payload).ok()?;
    (record.id == owner_object_id(&payload.route)).then_some(OwnerRecord {
        payload,
        resource_version: record.resource_version,
    })
}

fn decode_assignment(record: &ObjectRecord) -> Option<AssignmentRecord> {
    let payload = serde_json::from_slice::<AssignmentPayload>(&record.payload).ok()?;
    (record.id == assignment_object_id(&payload.route, &payload.writer)
        && record.name == payload.route)
        .then_some(AssignmentRecord {
            payload,
            resource_version: record.resource_version,
            created_at_ms: record.created_at_ms,
            updated_at_ms: record.updated_at_ms,
        })
}

fn decode_report(record: &ObjectRecord) -> Option<ReportPayload> {
    let payload = serde_json::from_slice::<ReportPayload>(&record.payload).ok()?;
    (record.id == report_object_id(&payload.route)).then_some(payload)
}

/// The synthetic credential owner of one sandbox's launch material, scoped
/// like the sandbox's SSH host key.
fn material_owner(payload: &AssignmentPayload) -> (String, &str, &str) {
    (
        format!("sandbox-instance-{}", payload.sandbox_id),
        payload.workspace.as_str(),
        payload.sandbox_id.as_str(),
    )
}

/// Whether `generation` of `sandbox` can still run: the sandbox exists,
/// still runs that generation, and is neither stopped nor being deleted.
fn generation_runs(sandbox: Option<&Sandbox>, generation: &str) -> bool {
    sandbox.is_some_and(|sandbox| {
        !matches!(
            SandboxPhase::try_from(sandbox.phase()).unwrap_or(SandboxPhase::Unknown),
            SandboxPhase::Stopped | SandboxPhase::Deleting
        ) && sandbox
            .metadata
            .as_ref()
            .and_then(|metadata| PersistedSandboxIdentity::read(&metadata.annotations).ok())
            .is_some_and(|identity| identity.runtime_generation.as_str() == generation)
    })
}

impl SupervisorPool {
    #[must_use]
    pub fn new(
        store: Arc<Store>,
        controller: SupervisorHostController,
        authority: Arc<SandboxSessionJwtAuthority>,
        credentials: CredentialRuntime,
        replica_id: String,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            controller,
            authority,
            credentials,
            replica_id,
            member_ttl: MEMBER_TTL,
            unowned_grace: UNOWNED_GRACE,
            takeovers_from: tokio::time::Instant::now() + TAKEOVER_STARTUP_GRACE,
            unowned_since: Mutex::new(HashMap::new()),
            minted: Mutex::new(HashMap::new()),
            materials: Mutex::new(HashMap::new()),
            recorded_reports: Mutex::new(HashMap::new()),
            withdrawn_since: Mutex::new(HashMap::new()),
            sweep_from: Mutex::new(0),
            candidate_grace: MATERIAL_CANDIDATE_GRACE,
            reservation_grace: RESERVATION_GRACE,
            #[cfg(test)]
            staged_gate: Mutex::new(None),
        })
    }

    /// Pause the next recording once it has staged its material, until the
    /// returned sender fires; the receiver fires when it pauses.
    #[cfg(test)]
    fn pause_next_recording_after_staging(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (staged, staged_rx) = tokio::sync::oneshot::channel();
        let (publish, publish_rx) = tokio::sync::oneshot::channel();
        *lock(&self.staged_gate) = Some((staged, publish_rx));
        (staged_rx, publish)
    }

    /// Install this pool as the controller's launch placement and keep the
    /// pool reconciled until shutdown.
    pub fn start(self: &Arc<Self>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        self.controller
            .install_placement(Arc::new(PoolPlacement(self.clone())));
        let pool = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(RECONCILE_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {}
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            return;
                        }
                        continue;
                    }
                }
                if let Err(error) = pool.reconcile_once().await {
                    warn!(%error, "supervisor pool reconciliation failed; retrying");
                }
            }
        });
    }

    /// Refresh the records of members this replica serves. A record written
    /// for a newer stream of the member elsewhere is left alone.
    async fn refresh_members(&self) {
        for member in self.controller.connected_members() {
            if let Err(error) = self.write_member(&member).await {
                warn!(member = %member.member_id, %error, "supervisor pool member refresh failed");
            }
        }
    }

    async fn write_member(&self, member: &ConnectedMember) -> Result<(), PersistenceError> {
        let id = member_object_id(&member.member_id);
        let existing = self.store.get(MEMBER_OBJECT_TYPE, &id).await?;
        if let Some(record) = &existing
            && let Ok(current) = serde_json::from_slice::<MemberPayload>(&record.payload)
            && current.process_id != member.process_id
            && current.connected_at_ms > member.connected_at_ms
            && self.fresh(record)
        {
            return Ok(());
        }
        let payload = MemberPayload {
            member_id: member.member_id.clone(),
            member_uid: member.member_uid.clone(),
            process_id: member.process_id.clone(),
            runtime_address: member.runtime_address.clone(),
            leaving: member.leaving,
            connected_at_ms: member.connected_at_ms,
            gateway_replica: self.replica_id.clone(),
        };
        let bytes = serde_json::to_vec(&payload)
            .map_err(|error| PersistenceError::Encode(error.to_string()))?;
        let condition = existing.map_or(WriteCondition::MustCreate, |record| {
            WriteCondition::MatchResourceVersion(record.resource_version)
        });
        match self
            .store
            .put_if(
                MEMBER_OBJECT_TYPE,
                &id,
                &member.member_id,
                "",
                &bytes,
                None,
                condition,
            )
            .await
        {
            // Another replica refreshed it at the same moment; the next
            // pass decides again.
            Ok(_)
            | Err(PersistenceError::Conflict { .. } | PersistenceError::UniqueViolation { .. }) => {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn fresh(&self, record: &ObjectRecord) -> bool {
        let ttl_ms = i64::try_from(self.member_ttl.as_millis()).unwrap_or(i64::MAX);
        now_ms().saturating_sub(record.updated_at_ms).max(0) < ttl_ms
    }

    /// Every record of `object_type`, page by page.
    async fn list_all(&self, object_type: &str) -> Result<Vec<ObjectRecord>, PersistenceError> {
        let mut records = Vec::new();
        loop {
            let offset = u32::try_from(records.len()).unwrap_or(u32::MAX);
            let page = self
                .store
                .list_by_type(object_type, LIST_LIMIT, offset)
                .await?;
            let complete = page.len() < LIST_LIMIT as usize;
            records.extend(page);
            if complete {
                return Ok(records);
            }
        }
    }

    /// Members whose records are live, in a stable order.
    async fn live_members(&self) -> Result<Vec<LiveMember>, PersistenceError> {
        let records = self.list_all(MEMBER_OBJECT_TYPE).await?;
        let ttl_ms = i64::try_from(self.member_ttl.as_millis()).unwrap_or(i64::MAX);
        let mut members = Vec::new();
        for record in records {
            if !self.fresh(&record) {
                // Records of members that died without leaving would crowd
                // live ones out of the listing limit.
                if now_ms().saturating_sub(record.updated_at_ms) >= ttl_ms.saturating_mul(4) {
                    let _ = self
                        .store
                        .delete_if(MEMBER_OBJECT_TYPE, &record.id, record.resource_version)
                        .await;
                }
                continue;
            }
            let Ok(payload) = serde_json::from_slice::<MemberPayload>(&record.payload) else {
                continue;
            };
            members.push(LiveMember {
                member_id: payload.member_id,
                process_id: payload.process_id,
                runtime_address: payload.runtime_address,
                leaving: payload.leaving,
            });
        }
        members.sort_by(|left, right| left.member_id.cmp(&right.member_id));
        members.dedup_by(|left, right| left.member_id == right.member_id);
        Ok(members)
    }

    async fn owners(&self) -> Result<BTreeMap<String, OwnerRecord>, PersistenceError> {
        Ok(self
            .list_all(OWNER_OBJECT_TYPE)
            .await?
            .iter()
            .filter_map(decode_owner)
            .map(|record| (record.payload.route.clone(), record))
            .collect())
    }

    async fn write_owner(
        &self,
        payload: &OwnerPayload,
        condition: WriteCondition,
    ) -> Result<OwnerRecord, PersistenceError> {
        let bytes = serde_json::to_vec(payload)
            .map_err(|error| PersistenceError::Encode(error.to_string()))?;
        let written = self
            .store
            .put_if(
                OWNER_OBJECT_TYPE,
                &owner_object_id(&payload.route),
                &payload.route,
                "",
                &bytes,
                None,
                condition,
            )
            .await?;
        Ok(OwnerRecord {
            payload: payload.clone(),
            resource_version: written.resource_version,
        })
    }

    /// Every instance record and reservation, by route.
    async fn all_assignments(
        &self,
    ) -> Result<BTreeMap<String, AssignmentRecord>, PersistenceError> {
        Ok(self
            .list_all(ASSIGNMENT_OBJECT_TYPE)
            .await?
            .iter()
            .filter_map(decode_assignment)
            .map(|record| (record.payload.route.clone(), record))
            .collect())
    }

    /// The published instance records, by route.
    async fn assignments(&self) -> Result<BTreeMap<String, AssignmentRecord>, PersistenceError> {
        let mut records = self.all_assignments().await?;
        records.retain(|_, record| record.payload.phase == RecordPhase::Published);
        Ok(records)
    }

    /// The record or reservation of `route`.
    async fn assignment(&self, route: &str) -> Result<Option<AssignmentRecord>, PersistenceError> {
        Ok(self
            .store
            .get_by_name(ASSIGNMENT_OBJECT_TYPE, "", route)
            .await?
            .as_ref()
            .and_then(decode_assignment))
    }

    /// Keep `material` in the credential store under a fresh path, so a
    /// record that loses a race never overwrites or deletes the winner's.
    async fn store_material(
        &self,
        payload: &AssignmentPayload,
        material: &[u8],
    ) -> Result<CredentialHandle, String> {
        let value = std::str::from_utf8(material)
            .map_err(|_| "sandbox instance launch material is not UTF-8".to_string())?;
        let (name, workspace, owner_id) = material_owner(payload);
        let handles = self
            .credentials
            .store_provider_credentials_with_object_id(
                &name,
                workspace,
                owner_id,
                &Uuid::new_v4().to_string(),
                &HashMap::from([(LAUNCH_MATERIAL_KEY.to_string(), value.to_string())]),
                &HashMap::new(),
            )
            .await
            .map_err(|status| {
                format!(
                    "store sandbox instance launch material: {}",
                    status.message()
                )
            })?;
        handles
            .get(LAUNCH_MATERIAL_KEY)
            .cloned()
            .ok_or_else(|| "the credential store kept no launch material".to_string())
    }

    async fn load_material(&self, payload: &AssignmentPayload) -> Result<Vec<u8>, String> {
        let handle = CredentialHandle::decode(payload.material_handle.as_slice())
            .map_err(|_| "invalid launch material credential handle".to_string())?;
        let (name, workspace, owner_id) = material_owner(payload);
        let owner = Provider {
            metadata: Some(ObjectMeta {
                id: owner_id.to_string(),
                name,
                workspace: workspace.to_string(),
                ..Default::default()
            }),
            credential_handles: HashMap::from([(LAUNCH_MATERIAL_KEY.to_string(), handle)]),
            ..Default::default()
        };
        let mut resolved = self
            .credentials
            .resolve_provider_handles(&owner, 0)
            .await
            .map_err(|status| {
                format!(
                    "load sandbox instance launch material: {}",
                    status.message()
                )
            })?;
        resolved
            .values
            .remove(LAUNCH_MATERIAL_KEY)
            .map(String::into_bytes)
            .ok_or_else(|| "sandbox instance launch material is unavailable".to_string())
    }

    async fn delete_material(
        &self,
        payload: &AssignmentPayload,
        handle: CredentialHandle,
    ) -> Result<(), String> {
        let (name, workspace, owner_id) = material_owner(payload);
        self.credentials
            .delete_provider_credential_handles(
                &name,
                workspace,
                owner_id,
                &HashMap::from([(LAUNCH_MATERIAL_KEY.to_string(), handle)]),
            )
            .await
            .map_err(|status| {
                format!(
                    "delete sandbox instance launch material: {}",
                    status.message()
                )
            })
    }

    /// Durably record an instance the pool must run, launch material
    /// included. Recording the same generation again keeps the first record.
    ///
    /// The recording first reserves the route with a record of its own (a
    /// fresh writer token in its id), then stores the material under a fresh
    /// path, has a candidate row own the handle, and publishes by advancing
    /// exactly its reservation's version. Every step is one atomic store
    /// write, so nothing is held across them. Collection deletes a candidate's
    /// material only once that candidate's recording no longer holds its
    /// reservation, after which its publication can never succeed (see
    /// [`Self::remove_stale_candidates`]). A recording whose reservation is
    /// fenced or withdrawn first fails and deletes its own material; a
    /// failure to do so leaves the candidate for collection to retry.
    async fn record_assignment(
        &self,
        assignment: &SandboxInstanceAssignment,
    ) -> Result<AssignmentRecord, String> {
        let read = |error: PersistenceError| format!("read supervisor pool instance: {error}");
        let existing = |record: AssignmentRecord| match record.payload.phase {
            RecordPhase::Published
                if record.payload.generation == assignment.generation
                    && record.payload.sandbox_id == assignment.sandbox_id =>
            {
                Ok(record)
            }
            RecordPhase::Published => {
                Err("the sandbox instance route is recorded for another generation".to_string())
            }
            RecordPhase::Reserved => {
                Err("the sandbox instance is being recorded by another gateway task".to_string())
            }
        };
        if let Some(record) = self.assignment(&assignment.route).await.map_err(read)? {
            return existing(record);
        }
        let sandbox = self
            .store
            .get_message::<Sandbox>(&assignment.sandbox_id)
            .await
            .map_err(read)?
            .ok_or_else(|| "the sandbox of the instance does not exist".to_string())?;
        let mut payload = AssignmentPayload {
            route: assignment.route.clone(),
            sandbox_id: assignment.sandbox_id.clone(),
            generation: assignment.generation.clone(),
            workspace: sandbox.object_workspace().to_string(),
            phase: RecordPhase::Reserved,
            writer: Uuid::new_v4().to_string(),
            material_handle: Vec::new(),
        };
        let id = assignment_object_id(&payload.route, &payload.writer);
        let encode = |payload: &AssignmentPayload| {
            serde_json::to_vec(payload)
                .map_err(|error| format!("encode supervisor pool instance: {error}"))
        };
        let reservation = match self
            .store
            .put_if(
                ASSIGNMENT_OBJECT_TYPE,
                &id,
                &payload.route,
                "",
                &encode(&payload)?,
                None,
                WriteCondition::MustCreate,
            )
            .await
        {
            Ok(written) => written.resource_version,
            // Another recording reserved or published the route first.
            Err(PersistenceError::UniqueViolation { .. }) => {
                return existing(
                    self.assignment(&payload.route)
                        .await
                        .map_err(read)?
                        .ok_or_else(|| {
                            "the sandbox instance record was concurrently removed".to_string()
                        })?,
                );
            }
            Err(error) => return Err(format!("reserve supervisor pool instance: {error}")),
        };
        let unreserve = |version| {
            let store = self.store.clone();
            let id = id.clone();
            async move {
                let _ = store.delete_if(ASSIGNMENT_OBJECT_TYPE, &id, version).await;
            }
        };
        let handle = match self
            .store_material(&payload, &assignment.launch_material)
            .await
        {
            Ok(handle) => handle,
            Err(error) => {
                unreserve(reservation).await;
                return Err(error);
            }
        };
        payload.material_handle = handle.encode_to_vec();
        let candidate = Uuid::new_v4().to_string();
        if let Err(error) = self
            .store
            .put_if(
                MATERIAL_CANDIDATE_OBJECT_TYPE,
                &candidate,
                &candidate,
                "",
                &encode(&payload)?,
                None,
                WriteCondition::MustCreate,
            )
            .await
        {
            if let Err(cleanup) = self.delete_material(&payload, handle).await {
                warn!(route = %payload.route, error = %cleanup, "could not remove launch material that no candidate owns");
            }
            unreserve(reservation).await;
            return Err(format!("stage supervisor pool instance: {error}"));
        }
        #[cfg(test)]
        {
            let gate = lock(&self.staged_gate).take();
            if let Some((staged, publish)) = gate {
                let _ = staged.send(());
                let _ = publish.await;
            }
        }
        payload.phase = RecordPhase::Published;
        let published = self
            .store
            .put_if(
                ASSIGNMENT_OBJECT_TYPE,
                &id,
                &payload.route,
                "",
                &encode(&payload)?,
                None,
                WriteCondition::MatchResourceVersion(reservation),
            )
            .await;
        match published {
            Ok(written) => {
                // The record owns the material now; a candidate row that
                // outlives this is released by collection.
                if let Err(error) = self
                    .store
                    .delete(MATERIAL_CANDIDATE_OBJECT_TYPE, &candidate)
                    .await
                {
                    warn!(route = %payload.route, %error, "could not release a supervisor pool material candidate; retrying later");
                }
                lock(&self.materials).insert(payload.route.clone(), assignment.clone());
                Ok(AssignmentRecord {
                    payload,
                    resource_version: written.resource_version,
                    created_at_ms: written.created_at_ms,
                    updated_at_ms: written.updated_at_ms,
                })
            }
            Err(error) => {
                // The reservation was fenced or withdrawn, so this handle can
                // never be published.
                payload.phase = RecordPhase::Reserved;
                self.discard_candidate(&candidate, &payload).await;
                Err(match error {
                    PersistenceError::Conflict { .. } => {
                        "the sandbox instance reservation was withdrawn before publication"
                            .to_string()
                    }
                    error => format!("publish supervisor pool instance: {error}"),
                })
            }
        }
    }

    /// Delete a candidate's material, and then the candidate. A failure
    /// keeps the candidate, so a later pass retries.
    async fn discard_candidate(&self, candidate: &str, payload: &AssignmentPayload) {
        let deleted = match CredentialHandle::decode(payload.material_handle.as_slice()) {
            Ok(handle) => self.delete_material(payload, handle).await,
            Err(_) => Err("invalid launch material credential handle".to_string()),
        };
        if let Err(error) = deleted {
            warn!(route = %payload.route, %error, "could not delete unrecorded launch material; retrying later");
            return;
        }
        if let Err(error) = self
            .store
            .delete(MATERIAL_CANDIDATE_OBJECT_TYPE, candidate)
            .await
        {
            warn!(route = %payload.route, %error, "could not remove a supervisor pool material candidate; retrying later");
        }
    }

    /// Fence reservations older than [`RESERVATION_GRACE`]: their recording
    /// stalled or died, and once its reservation is gone it can never
    /// publish. A recording that published first keeps its record.
    async fn fence_stale_reservations(&self, records: &BTreeMap<String, AssignmentRecord>) {
        let grace_ms = i64::try_from(self.reservation_grace.as_millis()).unwrap_or(i64::MAX);
        let stale = records
            .values()
            .filter(|record| {
                record.payload.phase == RecordPhase::Reserved
                    && now_ms().saturating_sub(record.created_at_ms) >= grace_ms
            })
            .take(CLEANUP_PER_PASS);
        for record in stale {
            info!(
                route = %record.payload.route,
                "fencing a supervisor pool instance reservation that did not publish in time"
            );
            if let Err(error) = self
                .store
                .delete_if(
                    ASSIGNMENT_OBJECT_TYPE,
                    &assignment_object_id(&record.payload.route, &record.payload.writer),
                    record.resource_version,
                )
                .await
                && !matches!(error, PersistenceError::Conflict { .. })
            {
                warn!(route = %record.payload.route, %error, "could not fence a supervisor pool instance reservation");
            }
        }
    }

    /// Settle material candidates older than the candidate grace. One whose
    /// recording still holds its route's reservation is left to it; one whose
    /// handle the route's published record holds is released; any other
    /// belongs to a recording whose reservation is gone or was never its
    /// route's, which can never publish, so its material is deleted. A
    /// recording publishes only by advancing its own reservation, a row no
    /// other recording ever writes and that is never recreated once removed,
    /// so this check cannot race a publication. A bounded number per pass.
    async fn remove_stale_candidates(&self) {
        let candidates = match self
            .store
            .list_by_type(
                MATERIAL_CANDIDATE_OBJECT_TYPE,
                u32::try_from(CLEANUP_PER_PASS).unwrap_or(u32::MAX),
                0,
            )
            .await
        {
            Ok(candidates) => candidates,
            Err(error) => {
                warn!(%error, "could not list supervisor pool material candidates");
                return;
            }
        };
        let grace_ms = i64::try_from(self.candidate_grace.as_millis()).unwrap_or(i64::MAX);
        for candidate in candidates {
            if now_ms().saturating_sub(candidate.created_at_ms) < grace_ms {
                continue;
            }
            let Ok(payload) = serde_json::from_slice::<AssignmentPayload>(&candidate.payload)
            else {
                let _ = self
                    .store
                    .delete(MATERIAL_CANDIDATE_OBJECT_TYPE, &candidate.id)
                    .await;
                continue;
            };
            let record = match self.assignment(&payload.route).await {
                Ok(record) => record,
                Err(error) => {
                    warn!(route = %payload.route, %error, "could not check a supervisor pool material candidate");
                    continue;
                }
            };
            match record {
                Some(record)
                    if record.payload.phase == RecordPhase::Reserved
                        && record.payload.writer == payload.writer => {}
                Some(record)
                    if record.payload.phase == RecordPhase::Published
                        && record.payload.material_handle == payload.material_handle =>
                {
                    let _ = self
                        .store
                        .delete(MATERIAL_CANDIDATE_OBJECT_TYPE, &candidate.id)
                        .await;
                }
                _ => self.discard_candidate(&candidate.id, &payload).await,
            }
        }
    }

    /// Remove an instance record and its launch material, or a reservation,
    /// which fences its recording. The material goes first, so a failure
    /// leaves the record to retry from.
    async fn delete_assignment(&self, record: &AssignmentRecord) -> Result<(), String> {
        if record.payload.phase == RecordPhase::Published {
            let handle = CredentialHandle::decode(record.payload.material_handle.as_slice())
                .map_err(|_| "invalid launch material credential handle".to_string())?;
            self.delete_material(&record.payload, handle).await?;
        }
        match self
            .store
            .delete_if(
                ASSIGNMENT_OBJECT_TYPE,
                &assignment_object_id(&record.payload.route, &record.payload.writer),
                record.resource_version,
            )
            .await
        {
            Ok(_) | Err(PersistenceError::Conflict { .. }) => {
                lock(&self.materials).remove(&record.payload.route);
                Ok(())
            }
            Err(error) => Err(format!("remove supervisor pool instance: {error}")),
        }
    }

    /// Routes of the published instances, with when each was published. A
    /// reservation can predate a driver recovery's listing while its
    /// publication races it, so the reservation time would let recovery
    /// prune an instance its listing could not have seen.
    async fn recorded(&self) -> Result<BTreeMap<String, i64>, String> {
        Ok(self
            .assignments()
            .await
            .map_err(|error| format!("list supervisor pool instances: {error}"))?
            .into_iter()
            .map(|(route, record)| (route, record.updated_at_ms))
            .collect())
    }

    /// Remove the records of instances withdrawn on this replica.
    async fn remove_withdrawn(&self) {
        for route in self.controller.pool_withdrawals() {
            let removed = match self.assignment(&route).await {
                Ok(Some(record)) => self.delete_assignment(&record).await,
                Ok(None) => Ok(()),
                Err(error) => Err(error.to_string()),
            };
            match removed {
                Ok(()) => self.controller.forget_withdrawal(&route),
                Err(error) => {
                    warn!(route, %error, "could not remove a withdrawn supervisor pool instance; retrying");
                }
            }
        }
    }

    /// Record a new instance and the owner of its launch term, on the member
    /// the ring prefers among live members with room. The instance is
    /// recorded first, so every recorded owner has its instance recorded.
    async fn place_launch(&self, request: PlacementRequest) -> Result<(), String> {
        let assignment = &request.assignment;
        let members = self
            .live_members()
            .await
            .map_err(|error| format!("read supervisor pool membership: {error}"))?;
        let owners = self
            .owners()
            .await
            .map_err(|error| format!("read supervisor instance owners: {error}"))?;
        if owners.len() >= MAX_POOL_INSTANCES && !owners.contains_key(&assignment.route) {
            return Err("the supervisor pool runs as many sandbox instances as it can".to_string());
        }
        let ring = ring_of(&members);
        let target = choose(
            &ring,
            &members,
            &assignment.sandbox_id,
            &load_of(owners.values()),
        )
        .ok_or_else(|| {
            "no shared supervisor replica is available with room for another sandbox".to_string()
        })?;
        self.record_assignment(assignment).await?;
        let payload = OwnerPayload {
            route: assignment.route.clone(),
            sandbox_id: assignment.sandbox_id.clone(),
            generation: assignment.generation.clone(),
            member_id: target.member_id.clone(),
            process_id: target.process_id.clone(),
            auth_epoch: request.auth_epoch,
            supervisor_instance_id: None,
            gateway_token_id: None,
            phase: OwnerPhase::Granted,
            previous_member_id: None,
        };
        let record = match self.write_owner(&payload, WriteCondition::MustCreate).await {
            Ok(record) => record,
            // A retried launch keeps the owner it already recorded.
            Err(PersistenceError::UniqueViolation { .. }) => match self
                .reload(&assignment.route)
                .await
                .map_err(|error| format!("read supervisor instance owner: {error}"))?
            {
                Reconciled::Changed(existing)
                    if existing.payload.generation == assignment.generation =>
                {
                    *existing
                }
                _ => {
                    return Err(
                        "the sandbox instance route is owned by another generation".to_string()
                    );
                }
            },
            Err(error) => return Err(format!("record supervisor instance owner: {error}")),
        };
        info!(
            sandbox_id = %assignment.sandbox_id,
            route = %assignment.route,
            member = %record.payload.member_id,
            "placed shared sandbox instance on supervisor pool member"
        );
        if record.payload.phase == OwnerPhase::Granted
            && record.payload.supervisor_instance_id.is_none()
        {
            self.controller.place_owner(
                &assignment.route,
                InstanceOwner {
                    member_id: record.payload.member_id,
                    process_id: record.payload.process_id,
                    auth_epoch: record.payload.auth_epoch,
                    supervisor_instance_id: None,
                    takeover: None,
                },
            );
        }
        Ok(())
    }

    /// One reconciliation pass: refresh served members and remove withdrawn
    /// instances; then place, take over, complete, and clean up from the
    /// records; record what served owners report; load the material served
    /// members need; and publish the resulting view.
    pub async fn reconcile_once(&self) -> Result<(), PersistenceError> {
        self.refresh_members().await;
        self.remove_withdrawn().await;
        let members = self.live_members().await?;
        let ring = ring_of(&members);
        let listed_at = tokio::time::Instant::now();
        let mut owners = self.owners().await?;
        // Listed after the owners: an instance is published before its owner
        // is recorded, so every owner listed has its instance listed unless
        // it was withdrawn.
        let withdrawals = self
            .controller
            .pool_withdrawals()
            .into_iter()
            .collect::<BTreeSet<_>>();
        let records = self.all_assignments().await?;
        self.fence_stale_reservations(&records).await;
        self.remove_stale_candidates().await;
        let desired = records
            .into_iter()
            .filter(|(route, record)| {
                record.payload.phase == RecordPhase::Published && !withdrawals.contains(route)
            })
            .collect::<BTreeMap<_, _>>();
        let mut load = load_of(owners.values());
        let stopping = self.controller.stopping_routes();
        self.forget_owned(&desired, &owners);
        for (route, instance) in &desired {
            if stopping.contains(route) {
                continue;
            }
            let takeovers_allowed = tokio::time::Instant::now() >= self.takeovers_from;
            let outcome = match owners.get(route) {
                None if takeovers_allowed => {
                    self.place_unowned(route, &instance.payload, &ring, &members, &load)
                        .await
                }
                // An intent recorded by any replica, including one that
                // crashed before granting it.
                Some(record) if record.payload.phase == OwnerPhase::Granting => {
                    self.complete_takeover(record.clone()).await
                }
                Some(record) if takeovers_allowed && !owner_alive(&record.payload, &members) => {
                    self.take_over(record, &ring, &members, &load).await
                }
                // A live owner keeps its instance; nothing is placed or
                // taken over during the startup grace.
                _ => Ok(Reconciled::Unchanged),
            };
            match outcome {
                Ok(Reconciled::Changed(record)) => {
                    if let Some(previous) = owners.get(route)
                        && let Some(count) = load.get_mut(&previous.payload.member_id)
                    {
                        *count = count.saturating_sub(1);
                    }
                    *load.entry(record.payload.member_id.clone()).or_insert(0) += 1;
                    owners.insert(route.clone(), *record);
                }
                Ok(Reconciled::Removed) => {
                    if let Some(previous) = owners.remove(route)
                        && let Some(count) = load.get_mut(&previous.payload.member_id)
                    {
                        *count = count.saturating_sub(1);
                    }
                }
                Ok(Reconciled::Unchanged) => {}
                Err(error) => {
                    warn!(route, %error, "supervisor pool could not reconcile an instance owner");
                }
            }
        }
        self.remove_withdrawn_owners(&desired, &mut owners).await;
        self.sweep_ended_instances(&desired).await;
        self.record_reports().await;
        let reports = self.reports(&owners).await?;
        let materials = self.load_materials(&owners, &desired).await;
        // Only granted terms are served; pending intents stay recorded for
        // the next pass.
        if let Some(view) = self
            .view(&members, &owners, &desired, materials, reports)
            .await
        {
            self.controller.update_pool(view, listed_at);
        }
        Ok(())
    }

    /// Remove the owner records of instances that are no longer desired: at
    /// once when their generation ended, else once their owner had time to be
    /// told to stop them.
    async fn remove_withdrawn_owners(
        &self,
        desired: &BTreeMap<String, AssignmentRecord>,
        owners: &mut BTreeMap<String, OwnerRecord>,
    ) {
        let now = tokio::time::Instant::now();
        let withdrawn = {
            let mut since = lock(&self.withdrawn_since);
            since.retain(|route, _| owners.contains_key(route) && !desired.contains_key(route));
            owners
                .values()
                .filter(|record| !desired.contains_key(&record.payload.route))
                .take(CLEANUP_PER_PASS)
                .map(|record| {
                    let first_seen = *since.entry(record.payload.route.clone()).or_insert(now);
                    (record.clone(), now.duration_since(first_seen))
                })
                .collect::<Vec<_>>()
        };
        for (record, withdrawn_for) in withdrawn {
            let removed = if withdrawn_for >= WITHDRAWN_OWNER_RETENTION {
                self.remove_owner(&record).await
            } else {
                self.remove_if_ended(&record).await
            };
            match removed {
                Ok(Reconciled::Changed(current)) => {
                    owners.insert(record.payload.route.clone(), *current);
                }
                Ok(Reconciled::Removed) => {
                    owners.remove(&record.payload.route);
                    let _ = self
                        .store
                        .delete(REPORT_OBJECT_TYPE, &report_object_id(&record.payload.route))
                        .await;
                    lock(&self.recorded_reports).remove(&record.payload.route);
                }
                Ok(Reconciled::Unchanged) => {}
                Err(error) => {
                    warn!(route = %record.payload.route, %error, "could not remove the owner of a withdrawn supervisor pool instance");
                }
            }
        }
    }

    /// Withdraw instances whose generation visibly ended, a bounded number
    /// of records per pass, so an instance whose withdrawal was lost with a
    /// gateway replica does not stay desired.
    async fn sweep_ended_instances(&self, desired: &BTreeMap<String, AssignmentRecord>) {
        if desired.is_empty() {
            return;
        }
        let start = {
            let mut from = lock(&self.sweep_from);
            let start = *from % desired.len();
            *from = start + CLEANUP_PER_PASS;
            start
        };
        let batch = desired
            .values()
            .cycle()
            .skip(start)
            .take(CLEANUP_PER_PASS.min(desired.len()))
            .cloned()
            .collect::<Vec<_>>();
        for record in batch {
            let sandbox = match self
                .store
                .get_message::<Sandbox>(&record.payload.sandbox_id)
                .await
            {
                Ok(sandbox) => sandbox,
                Err(error) => {
                    warn!(route = %record.payload.route, %error, "could not check a supervisor pool instance's generation");
                    continue;
                }
            };
            if generation_runs(sandbox.as_ref(), &record.payload.generation) {
                continue;
            }
            info!(
                sandbox_id = %record.payload.sandbox_id,
                route = %record.payload.route,
                "withdrawing a supervisor pool instance whose generation ended"
            );
            self.controller.unassign(&record.payload.route);
        }
    }

    /// Record what the owners this replica serves report of their instances.
    async fn record_reports(&self) {
        for report in self.controller.owned_reports() {
            let payload = ReportPayload {
                route: report.route,
                member_id: report.owner.member_id,
                process_id: report.owner.process_id,
                auth_epoch: report.owner.auth_epoch,
                sandbox_id: report.status.sandbox_id,
                phase: report.status.phase,
                ready: report.status.ready,
                exit_code: report.status.exit_code,
            };
            if lock(&self.recorded_reports).get(&payload.route) == Some(&payload) {
                continue;
            }
            let Ok(bytes) = serde_json::to_vec(&payload) else {
                continue;
            };
            match self
                .store
                .put_if(
                    REPORT_OBJECT_TYPE,
                    &report_object_id(&payload.route),
                    &payload.route,
                    "",
                    &bytes,
                    None,
                    WriteCondition::Unconditional,
                )
                .await
            {
                Ok(_) => {
                    lock(&self.recorded_reports).insert(payload.route.clone(), payload);
                }
                Err(error) => {
                    warn!(route = %payload.route, %error, "could not record a supervisor pool instance report");
                }
            }
        }
    }

    /// Recorded reports of each route's current, granted owner term.
    async fn reports(
        &self,
        owners: &BTreeMap<String, OwnerRecord>,
    ) -> Result<BTreeMap<String, SandboxInstanceStatus>, PersistenceError> {
        Ok(self
            .list_all(REPORT_OBJECT_TYPE)
            .await?
            .iter()
            .filter_map(decode_report)
            .filter(|report| {
                owners.get(&report.route).is_some_and(|owner| {
                    owner.payload.phase == OwnerPhase::Granted
                        && owner.payload.member_id == report.member_id
                        && owner.payload.process_id == report.process_id
                        && owner.payload.auth_epoch == report.auth_epoch
                })
            })
            .map(|report| {
                (
                    report.route.clone(),
                    SandboxInstanceStatus {
                        route: report.route,
                        sandbox_id: report.sandbox_id,
                        phase: report.phase,
                        ready: report.ready,
                        exit_code: report.exit_code,
                        error: String::new(),
                    },
                )
            })
            .collect())
    }

    /// Launch material of the desired instances owned, or about to be taken
    /// over, by member processes this replica serves; at most
    /// [`LOAD_PER_PASS`] new loads per pass.
    async fn load_materials(
        &self,
        owners: &BTreeMap<String, OwnerRecord>,
        desired: &BTreeMap<String, AssignmentRecord>,
    ) -> BTreeMap<String, SandboxInstanceAssignment> {
        let served = self
            .controller
            .connected_members()
            .into_iter()
            .map(|member| (member.member_id, member.process_id))
            .collect::<BTreeSet<_>>();
        let wanted = desired
            .iter()
            .filter(|(route, _)| {
                owners.get(*route).is_some_and(|owner| {
                    served.contains(&(
                        owner.payload.member_id.clone(),
                        owner.payload.process_id.clone(),
                    ))
                })
            })
            .collect::<BTreeMap<_, _>>();
        let missing = {
            let mut materials = lock(&self.materials);
            materials.retain(|route, assignment| {
                wanted
                    .get(route)
                    .is_some_and(|record| record.payload.generation == assignment.generation)
            });
            wanted
                .iter()
                .filter(|(route, _)| !materials.contains_key(**route))
                .take(LOAD_PER_PASS)
                .map(|(_, record)| (*record).clone())
                .collect::<Vec<_>>()
        };
        for record in missing {
            match self.load_material(&record.payload).await {
                Ok(launch_material) => {
                    lock(&self.materials).insert(
                        record.payload.route.clone(),
                        SandboxInstanceAssignment {
                            route: record.payload.route,
                            sandbox_id: record.payload.sandbox_id,
                            generation: record.payload.generation,
                            launch_material,
                            takeover: None,
                        },
                    );
                }
                Err(error) => {
                    warn!(route = %record.payload.route, %error, "could not load a supervisor pool instance's launch material; retrying");
                }
            }
        }
        lock(&self.materials)
            .iter()
            .filter(|(route, _)| wanted.contains_key(*route))
            .map(|(route, assignment)| (route.clone(), assignment.clone()))
            .collect()
    }

    /// The stored owner record of `route` after a write lost a race.
    async fn reload(&self, route: &str) -> Result<Reconciled, PersistenceError> {
        Ok(self
            .store
            .get(OWNER_OBJECT_TYPE, &owner_object_id(route))
            .await?
            .as_ref()
            .and_then(decode_owner)
            .map_or(Reconciled::Removed, |record| {
                Reconciled::Changed(Box::new(record))
            }))
    }

    /// Track desired routes without an owner record; forget the rest.
    fn forget_owned(
        &self,
        desired: &BTreeMap<String, AssignmentRecord>,
        owners: &BTreeMap<String, OwnerRecord>,
    ) {
        let now = tokio::time::Instant::now();
        let mut unowned = lock(&self.unowned_since);
        unowned.retain(|route, _| desired.contains_key(route) && !owners.contains_key(route));
        for route in desired.keys() {
            if !owners.contains_key(route) {
                unowned.entry(route.clone()).or_insert(now);
            }
        }
    }

    /// Place a desired instance that has no owner record, such as one whose
    /// launch predates the pool. Whichever process may already supervise
    /// it is fenced, as for any takeover.
    async fn place_unowned(
        &self,
        route: &str,
        assignment: &AssignmentPayload,
        ring: &GatewayRing,
        members: &[LiveMember],
        load: &HashMap<String, usize>,
    ) -> Result<Reconciled, PersistenceError> {
        let unowned_for = lock(&self.unowned_since)
            .get(route)
            .map(tokio::time::Instant::elapsed);
        if unowned_for.is_none_or(|elapsed| elapsed < self.unowned_grace) {
            return Ok(Reconciled::Unchanged);
        }
        let Some(target) = choose(ring, members, &assignment.sandbox_id, load) else {
            return Ok(Reconciled::Unchanged);
        };
        let Some(sandbox) = self
            .store
            .get_message::<Sandbox>(&assignment.sandbox_id)
            .await?
        else {
            return Ok(Reconciled::Unchanged);
        };
        let Some(identity) = sandbox
            .metadata
            .as_ref()
            .and_then(|metadata| PersistedSandboxIdentity::read(&metadata.annotations).ok())
            .filter(|identity| identity.runtime_generation.as_str() == assignment.generation)
        else {
            return Ok(Reconciled::Unchanged);
        };
        let intent = OwnerPayload {
            route: route.to_string(),
            sandbox_id: assignment.sandbox_id.clone(),
            generation: assignment.generation.clone(),
            member_id: target.member_id.clone(),
            process_id: target.process_id.clone(),
            auth_epoch: identity.auth_epoch.get().saturating_add(1),
            supervisor_instance_id: Some(Uuid::new_v4().to_string()),
            gateway_token_id: Some(Uuid::new_v4().to_string()),
            phase: OwnerPhase::Granting,
            previous_member_id: None,
        };
        match self.write_owner(&intent, WriteCondition::MustCreate).await {
            Ok(record) => self.complete_takeover(record).await,
            // A launch or another replica recorded it first.
            Err(PersistenceError::UniqueViolation { .. }) => self.reload(route).await,
            Err(error) => Err(error),
        }
    }

    /// Move an instance whose owner failed or left to the ring's choice.
    async fn take_over(
        &self,
        record: &OwnerRecord,
        ring: &GatewayRing,
        members: &[LiveMember],
        load: &HashMap<String, usize>,
    ) -> Result<Reconciled, PersistenceError> {
        let Some(target) = choose(ring, members, &record.payload.sandbox_id, load) else {
            return Ok(Reconciled::Unchanged);
        };
        let intent = OwnerPayload {
            member_id: target.member_id.clone(),
            process_id: target.process_id.clone(),
            auth_epoch: record.payload.auth_epoch.saturating_add(1),
            supervisor_instance_id: Some(Uuid::new_v4().to_string()),
            gateway_token_id: Some(Uuid::new_v4().to_string()),
            phase: OwnerPhase::Granting,
            previous_member_id: Some(record.payload.member_id.clone()),
            ..record.payload.clone()
        };
        match self
            .write_owner(
                &intent,
                WriteCondition::MatchResourceVersion(record.resource_version),
            )
            .await
        {
            Ok(intent) => {
                info!(
                    sandbox_id = %intent.payload.sandbox_id,
                    route = %intent.payload.route,
                    from = %record.payload.member_id,
                    to = %intent.payload.member_id,
                    term = intent.payload.auth_epoch,
                    "taking over a shared sandbox instance from a failed supervisor"
                );
                self.complete_takeover(intent).await
            }
            // Another replica moved it first.
            Err(PersistenceError::Conflict { .. }) => self.reload(&record.payload.route).await,
            Err(error) => Err(error),
        }
    }

    /// Advance the sandbox's credential epoch to the intent's term and grant
    /// it, or cancel the intent when the sandbox refuses the takeover.
    async fn complete_takeover(&self, record: OwnerRecord) -> Result<Reconciled, PersistenceError> {
        let (Some(epoch), Some(gateway_token_id)) = (
            openshell_core::jwt::CredentialEpoch::new(record.payload.auth_epoch).ok(),
            record
                .payload
                .gateway_token_id
                .as_deref()
                .and_then(|id| Uuid::parse_str(id).ok()),
        ) else {
            return Ok(Reconciled::Unchanged);
        };
        match advance_identity_for_takeover(
            &self.store,
            &record.payload.sandbox_id,
            &record.payload.generation,
            epoch,
            gateway_token_id,
        )
        .await?
        {
            TakeoverIdentity::Advanced | TakeoverIdentity::AlreadyAdvanced => {
                let granted = OwnerPayload {
                    phase: OwnerPhase::Granted,
                    ..record.payload.clone()
                };
                match self
                    .write_owner(
                        &granted,
                        WriteCondition::MatchResourceVersion(record.resource_version),
                    )
                    .await
                {
                    Ok(granted) => Ok(Reconciled::Changed(Box::new(granted))),
                    Err(PersistenceError::Conflict { .. }) => {
                        self.reload(&record.payload.route).await
                    }
                    Err(error) => Err(error),
                }
            }
            TakeoverIdentity::Refused(reason) => {
                info!(
                    sandbox_id = %record.payload.sandbox_id,
                    route = %record.payload.route,
                    reason,
                    "cancelled a shared sandbox instance takeover"
                );
                match self
                    .store
                    .delete_if(
                        OWNER_OBJECT_TYPE,
                        &owner_object_id(&record.payload.route),
                        record.resource_version,
                    )
                    .await
                {
                    Ok(_) => Ok(Reconciled::Removed),
                    Err(PersistenceError::Conflict { .. }) => {
                        self.reload(&record.payload.route).await
                    }
                    Err(error) => Err(error),
                }
            }
        }
    }

    /// Remove the owner record of an instance that is no longer desired once
    /// its generation has ended: the sandbox is gone, runs another one, or
    /// was stopped or is being deleted, so the generation never runs again.
    async fn remove_if_ended(&self, record: &OwnerRecord) -> Result<Reconciled, PersistenceError> {
        let sandbox = self
            .store
            .get_message::<Sandbox>(&record.payload.sandbox_id)
            .await?;
        if generation_runs(sandbox.as_ref(), &record.payload.generation) {
            return Ok(Reconciled::Unchanged);
        }
        self.remove_owner(record).await
    }

    async fn remove_owner(&self, record: &OwnerRecord) -> Result<Reconciled, PersistenceError> {
        match self
            .store
            .delete_if(
                OWNER_OBJECT_TYPE,
                &owner_object_id(&record.payload.route),
                record.resource_version,
            )
            .await
        {
            Ok(_) => Ok(Reconciled::Removed),
            Err(PersistenceError::Conflict { .. }) => self.reload(&record.payload.route).await,
            Err(error) => Err(error),
        }
    }

    /// The pool view to serve: live members and the granted owners, with
    /// takeover credentials for the members this replica serves. `None` keeps
    /// the published view, when credentials a served owner needs cannot be
    /// minted yet.
    async fn view(
        &self,
        members: &[LiveMember],
        owners: &BTreeMap<String, OwnerRecord>,
        desired: &BTreeMap<String, AssignmentRecord>,
        assignments: BTreeMap<String, SandboxInstanceAssignment>,
        reports: BTreeMap<String, SandboxInstanceStatus>,
    ) -> Option<PoolView> {
        let served = self
            .controller
            .connected_members()
            .into_iter()
            .map(|member| (member.member_id, member.process_id))
            .collect::<BTreeSet<_>>();
        let mut view = PoolView {
            members: members
                .iter()
                .map(|member| MemberView {
                    member_id: member.member_id.clone(),
                    process_id: member.process_id.clone(),
                    runtime_address: member.runtime_address.clone(),
                    leaving: member.leaving,
                })
                .collect(),
            owners: BTreeMap::new(),
            desired: desired.keys().cloned().collect(),
            assignments,
            reports,
        };
        let mut current_terms = std::collections::HashSet::new();
        for record in owners.values() {
            let owner = &record.payload;
            if owner.phase != OwnerPhase::Granted {
                continue;
            }
            current_terms.insert((owner.route.clone(), owner.auth_epoch));
            let takeover = if owner.supervisor_instance_id.is_some()
                && served.contains(&(owner.member_id.clone(), owner.process_id.clone()))
            {
                match self.takeover_credentials(owner).await {
                    Ok(Some(credentials)) => Some(credentials),
                    // The sandbox already moved past this record's term; the
                    // next pass reads the record that replaced it.
                    Ok(None) => continue,
                    Err(error) => {
                        warn!(route = %owner.route, %error, "could not mint supervisor takeover credentials; keeping the published pool view");
                        return None;
                    }
                }
            } else {
                None
            };
            view.owners.insert(
                owner.route.clone(),
                InstanceOwner {
                    member_id: owner.member_id.clone(),
                    process_id: owner.process_id.clone(),
                    auth_epoch: owner.auth_epoch,
                    supervisor_instance_id: owner.supervisor_instance_id.clone(),
                    takeover,
                },
            );
        }
        lock(&self.minted).retain(|term, _| current_terms.contains(term));
        Some(view)
    }

    /// Credentials of a granted takeover term, minted again every
    /// [`TAKEOVER_CREDENTIAL_REFRESH`]. A host already supervising the term
    /// keeps its own credentials, refreshed since; only one that starts the
    /// term uses these.
    async fn takeover_credentials(
        &self,
        owner: &OwnerPayload,
    ) -> Result<Option<SandboxInstanceTakeover>, String> {
        let term = (owner.route.clone(), owner.auth_epoch);
        if let Some((minted, at)) = lock(&self.minted).get(&term)
            && at.elapsed() < TAKEOVER_CREDENTIAL_REFRESH
        {
            return Ok(Some(minted.clone()));
        }
        let minted = self.mint_takeover(owner).await?;
        if let Some(minted) = &minted {
            lock(&self.minted).insert(term, (minted.clone(), tokio::time::Instant::now()));
        }
        Ok(minted)
    }

    /// Mint a takeover term's grant and session credentials from the granted
    /// record and the persisted identity, which must be at the same term.
    async fn mint_takeover(
        &self,
        owner: &OwnerPayload,
    ) -> Result<Option<SandboxInstanceTakeover>, String> {
        let Some(instance) = &owner.supervisor_instance_id else {
            return Ok(None);
        };
        let Some(sandbox) = self
            .store
            .get_message::<Sandbox>(&owner.sandbox_id)
            .await
            .map_err(|error| error.to_string())?
        else {
            return Ok(None);
        };
        let Some(identity) = sandbox
            .metadata
            .as_ref()
            .and_then(|metadata| PersistedSandboxIdentity::read(&metadata.annotations).ok())
            .filter(|identity| {
                identity.runtime_generation.as_str() == owner.generation
                    && identity.auth_epoch.get() == owner.auth_epoch
            })
        else {
            return Ok(None);
        };
        let launch = self
            .authority
            .mint_persisted_launch(&owner.sandbox_id, &identity)
            .map_err(|status| status.message().to_string())?;
        let grant = self
            .authority
            .mint_supervisor_takeover(
                &SupervisorTakeover {
                    sandbox_id: SandboxId::parse(owner.sandbox_id.clone())
                        .map_err(|error| error.to_string())?,
                    runtime_generation: identity.runtime_generation.clone(),
                    auth_epoch: identity.auth_epoch,
                    supervisor_instance: instance.clone(),
                    owner: owner.member_id.clone(),
                },
                TAKEOVER_GRANT_TTL,
            )
            .map_err(|error| error.to_string())?;
        let auth = launch.supervisor;
        Ok(Some(SandboxInstanceTakeover {
            auth_epoch: owner.auth_epoch,
            supervisor_instance_id: instance.clone(),
            grant: grant.token.expose_secret().to_string(),
            gateway_token: auth.gateway_token.expose_secret().to_string(),
            gateway_expires_at: auth.gateway_expires_at,
            sandbox_token: auth.sandbox_token.expose_secret().to_string(),
            sandbox_expires_at: auth.sandbox_expires_at,
        }))
    }
}

/// The pool's launch placement, installed into the controller.
#[derive(Debug)]
struct PoolPlacement(Arc<SupervisorPool>);

/// Run a durable pool write on its own task, so a caller that is cancelled,
/// such as a launch whose request ended, cannot stop it halfway.
async fn detached<T: Send + 'static>(
    write: impl Future<Output = Result<T, String>> + Send + 'static,
) -> Result<T, String> {
    tokio::spawn(write)
        .await
        .map_err(|_| "supervisor pool write task failed".to_string())?
}

impl InstancePlacement for PoolPlacement {
    fn place_launch(&self, request: PlacementRequest) -> PlacementFuture {
        let pool = self.0.clone();
        Box::pin(detached(async move { pool.place_launch(request).await }))
    }

    fn recorded(&self) -> PlacementFuture<BTreeMap<String, i64>> {
        let pool = self.0.clone();
        Box::pin(async move { pool.recorded().await })
    }

    fn record_recovered(&self, assignment: SandboxInstanceAssignment) -> PlacementFuture {
        let pool = self.0.clone();
        Box::pin(detached(async move {
            pool.record_assignment(&assignment).await.map(drop)
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::sandbox_session::PersistedSandboxIdentity;
    use openshell_core::jwt::{AuthenticatedSandboxSession, CredentialEpoch};
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    use openshell_core::proto::{SandboxPhase, SandboxStatus};
    use openshell_core::sandbox_generation::SandboxGenerationId;
    use openshell_supervisor_control::proto::SandboxInstanceAssignment;

    struct Fixture {
        store: Arc<Store>,
        authority: Arc<SandboxSessionJwtAuthority>,
        credentials: CredentialRuntime,
    }

    impl Fixture {
        async fn new() -> Self {
            let material = openshell_bootstrap::jwt::generate_jwt_key().expect("jwt key");
            let store = Arc::new(crate::persistence::test_store().await);
            let config = crate::Config::new(None)
                .with_credential_drivers(["test-static"])
                .with_default_credential_driver(Some("test-static"));
            Self {
                credentials: CredentialRuntime::from_config_with_store(&config, store.clone())
                    .expect("credential runtime"),
                store,
                authority: Arc::new(
                    SandboxSessionJwtAuthority::from_pem(
                        material.signing_key_pem.as_bytes(),
                        material.public_key_pem.as_bytes(),
                        material.kid,
                        "test-gateway",
                        Some(Duration::from_mins(15)),
                    )
                    .expect("authority"),
                ),
            }
        }

        /// A gateway replica's pool over this store, with its own controller.
        fn replica(&self, replica_id: &str) -> Arc<SupervisorPool> {
            let controller = SupervisorHostController::new();
            controller.enable_pool(openshell_supervisor_control::POOL_RECOVERY_TIMEOUT_SECS);
            let mut pool = SupervisorPool::new(
                self.store.clone(),
                controller,
                self.authority.clone(),
                self.credentials.clone(),
                replica_id.to_string(),
            );
            let unique = Arc::get_mut(&mut pool).expect("unique");
            unique.unowned_grace = Duration::ZERO;
            unique.candidate_grace = Duration::ZERO;
            unique.takeovers_from = tokio::time::Instant::now();
            pool
        }

        /// A replica that just started, within its takeover grace.
        fn starting_replica(&self, replica_id: &str) -> Arc<SupervisorPool> {
            let controller = SupervisorHostController::new();
            controller.enable_pool(openshell_supervisor_control::POOL_RECOVERY_TIMEOUT_SECS);
            SupervisorPool::new(
                self.store.clone(),
                controller,
                self.authority.clone(),
                self.credentials.clone(),
                replica_id.to_string(),
            )
        }

        async fn sandbox(&self, sandbox_id: &str, generation: &str, phase: SandboxPhase) {
            let identity = PersistedSandboxIdentity {
                runtime_generation: SandboxGenerationId::parse(generation).unwrap(),
                auth_epoch: CredentialEpoch::new(1).unwrap(),
                gateway_token_id: Uuid::new_v4(),
                refresh_replay: None,
            };
            let mut metadata = ObjectMeta {
                id: sandbox_id.to_string(),
                name: sandbox_id.to_string(),
                workspace: "default".to_string(),
                ..Default::default()
            };
            identity.write(&mut metadata.annotations);
            self.store
                .put_message(&Sandbox {
                    metadata: Some(metadata),
                    status: Some(SandboxStatus {
                        phase: phase as i32,
                        ..Default::default()
                    }),
                    ..Default::default()
                })
                .await
                .expect("persist sandbox");
        }

        async fn identity(&self, sandbox_id: &str) -> PersistedSandboxIdentity {
            let sandbox = self
                .store
                .get_message::<Sandbox>(sandbox_id)
                .await
                .unwrap()
                .unwrap();
            PersistedSandboxIdentity::read(&sandbox.metadata.unwrap().annotations).unwrap()
        }

        async fn set_phase(&self, sandbox_id: &str, phase: SandboxPhase) {
            self.store
                .update_message_cas::<Sandbox, _>(sandbox_id, 0, |sandbox| {
                    sandbox.set_phase(phase as i32);
                })
                .await
                .unwrap();
        }

        async fn member(&self, member_id: &str, process_id: &str, leaving: bool) {
            let pool = self.replica("membership-writer");
            pool.write_member(&ConnectedMember {
                member_id: member_id.to_string(),
                member_uid: format!("uid-{member_id}"),
                process_id: process_id.to_string(),
                runtime_address: "10.0.0.1:5500".to_string(),
                leaving,
                connected_at_ms: now_ms(),
            })
            .await
            .unwrap();
        }

        async fn remove_member(&self, member_id: &str) {
            self.store
                .delete(MEMBER_OBJECT_TYPE, &member_object_id(member_id))
                .await
                .unwrap();
        }

        async fn owner(&self, route: &str) -> Option<OwnerPayload> {
            self.store
                .get(OWNER_OBJECT_TYPE, &owner_object_id(route))
                .await
                .unwrap()
                .and_then(|record| decode_owner(&record))
                .map(|record| record.payload)
        }

        async fn candidates(&self) -> usize {
            self.store
                .list_by_type(MATERIAL_CANDIDATE_OBJECT_TYPE, 100, 0)
                .await
                .unwrap()
                .len()
        }

        async fn instance(&self, route: &str) -> Option<AssignmentRecord> {
            self.store
                .get_by_name(ASSIGNMENT_OBJECT_TYPE, "", route)
                .await
                .unwrap()
                .and_then(|record| decode_assignment(&record))
        }
    }

    fn assignment(route: &str, sandbox_id: &str, generation: &str) -> SandboxInstanceAssignment {
        SandboxInstanceAssignment {
            route: route.to_string(),
            sandbox_id: sandbox_id.to_string(),
            generation: generation.to_string(),
            launch_material: format!("{{\"launch\":\"{route}\"}}").into_bytes(),
            takeover: None,
        }
    }

    fn launch(route: &str, sandbox_id: &str, generation: &str) -> PlacementRequest {
        PlacementRequest {
            assignment: assignment(route, sandbox_id, generation),
            auth_epoch: 1,
        }
    }

    #[tokio::test]
    async fn launches_follow_the_ring_and_healthy_owners_never_move() {
        let fixture = Fixture::new().await;
        fixture.member("m1", "p1", false).await;
        fixture.member("m2", "p2", false).await;
        let pool = fixture.replica("gw-a");
        let mut routes = Vec::new();
        for index in 0..24 {
            let (route, sandbox) = (format!("rt-route-{index:04}"), format!("sandbox-{index}"));
            fixture
                .sandbox(&sandbox, "generation-1", SandboxPhase::Ready)
                .await;
            pool.place_launch(launch(&route, &sandbox, "generation-1"))
                .await
                .unwrap();
            routes.push((route, sandbox));
        }
        let ring = GatewayRing::new(["m1", "m2"]);
        let mut before = BTreeMap::new();
        for (route, sandbox) in &routes {
            let owner = fixture.owner(route).await.unwrap();
            assert_eq!(Some(owner.member_id.as_str()), ring.owner_for(sandbox));
            assert_eq!(owner.auth_epoch, 1);
            assert!(owner.supervisor_instance_id.is_none());
            before.insert(route.clone(), owner);
        }
        assert!(before.values().any(|owner| owner.member_id == "m1"));
        assert!(before.values().any(|owner| owner.member_id == "m2"));

        // A new member changes where new launches go, not who owns what.
        fixture.member("m3", "p3", false).await;
        pool.reconcile_once().await.unwrap();
        for (route, owner) in &before {
            assert_eq!(fixture.owner(route).await.as_ref(), Some(owner));
        }
        let view = pool.controller.pool_view().unwrap();
        assert_eq!(view.owners.len(), routes.len());
        assert_eq!(view.members.len(), 3);
        // With no live member a launch is refused before its workload runs.
        let empty = Fixture::new().await;
        assert!(
            empty
                .replica("gw-b")
                .place_launch(launch("rt-route-none", "sandbox-x", "generation-1"))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_failed_owner_is_taken_over_once_and_fenced_everywhere() {
        let fixture = Fixture::new().await;
        fixture.member("m1", "p1", false).await;
        fixture
            .sandbox("sandbox-a", "generation-1", SandboxPhase::Ready)
            .await;
        let replica_a = fixture.replica("gw-a");
        let replica_b = fixture.replica("gw-b");
        replica_a
            .place_launch(launch("rt-route-a000", "sandbox-a", "generation-1"))
            .await
            .unwrap();
        let launch_identity = fixture.identity("sandbox-a").await;

        // The owner's process dies; another member is live. Two replicas
        // reconcile at once and grant exactly one new term.
        fixture.member("m2", "p2", false).await;
        fixture.remove_member("m1").await;
        let (first, second) = tokio::join!(replica_a.reconcile_once(), replica_b.reconcile_once());
        first.unwrap();
        second.unwrap();
        replica_a.reconcile_once().await.unwrap();
        let owner = fixture.owner("rt-route-a000").await.unwrap();
        assert_eq!(owner.member_id, "m2");
        assert_eq!(owner.process_id, "p2");
        assert_eq!(owner.auth_epoch, 2);
        assert_eq!(owner.phase, OwnerPhase::Granted);
        assert_eq!(owner.previous_member_id.as_deref(), Some("m1"));
        let identity = fixture.identity("sandbox-a").await;
        assert_eq!(identity.auth_epoch.get(), 2);
        assert_eq!(
            Some(identity.gateway_token_id.to_string()),
            owner.gateway_token_id
        );

        // Every credential of the replaced term is refused by the gateway,
        // and refresh cannot carry it into the new term.
        let stale = AuthenticatedSandboxSession {
            sandbox_id: SandboxId::parse("sandbox-a").unwrap(),
            runtime_generation: launch_identity.runtime_generation.clone(),
            auth_epoch: launch_identity.auth_epoch,
            token_id: launch_identity.gateway_token_id,
            issued_at: 1,
            expires_at: 2,
        };
        assert!(
            crate::auth::sandbox_session::authorize_persisted(&fixture.store, &stale)
                .await
                .is_err()
        );
        let request_hash =
            crate::auth::sandbox_session::RefreshRequestHash::from_extension_services(&[]).unwrap();
        assert!(
            crate::auth::sandbox_session::authorize_refresh(
                &fixture.store,
                &stale,
                &request_hash,
                now_ms() / 1000
            )
            .await
            .is_err()
        );

        // The new term's credentials name its process and the new lineage.
        let minted = replica_a.mint_takeover(&owner).await.unwrap().unwrap();
        assert_eq!(minted.auth_epoch, 2);
        assert_eq!(
            Some(minted.supervisor_instance_id.as_str()),
            owner.supervisor_instance_id.as_deref()
        );
        let gateway = replica_a
            .authority
            .verify_gateway_token(&minted.gateway_token)
            .unwrap();
        assert_eq!(gateway.auth_epoch.get(), 2);
        crate::auth::sandbox_session::authorize_persisted(&fixture.store, &gateway)
            .await
            .expect("new term's gateway credential is current");

        // A healthy new owner stays put on later passes.
        replica_b.reconcile_once().await.unwrap();
        assert_eq!(fixture.owner("rt-route-a000").await.unwrap(), owner);
    }

    #[tokio::test]
    async fn restarted_and_leaving_members_lose_their_instances() {
        let fixture = Fixture::new().await;
        fixture.member("m1", "p1", false).await;
        for sandbox in ["sandbox-a", "sandbox-b"] {
            fixture
                .sandbox(sandbox, "generation-1", SandboxPhase::Ready)
                .await;
        }
        let pool = fixture.replica("gw-a");
        pool.place_launch(launch("rt-route-a000", "sandbox-a", "generation-1"))
            .await
            .unwrap();
        pool.place_launch(launch("rt-route-b000", "sandbox-b", "generation-1"))
            .await
            .unwrap();

        // The member's container restarts: its new process owns nothing until
        // the instances are taken over, here by the same member.
        fixture.member("m1", "p1-restarted", false).await;
        pool.reconcile_once().await.unwrap();
        for route in ["rt-route-a000", "rt-route-b000"] {
            let owner = fixture.owner(route).await.unwrap();
            assert_eq!(
                (owner.member_id.as_str(), owner.process_id.as_str()),
                ("m1", "p1-restarted")
            );
            assert_eq!(owner.auth_epoch, 2);
        }

        // A member that announces it is leaving is drained at once.
        fixture.member("m2", "p2", false).await;
        fixture.member("m1", "p1-restarted", true).await;
        pool.reconcile_once().await.unwrap();
        for route in ["rt-route-a000", "rt-route-b000"] {
            let owner = fixture.owner(route).await.unwrap();
            assert_eq!(owner.member_id, "m2");
            assert_eq!(owner.auth_epoch, 3);
        }
    }

    #[tokio::test]
    async fn stop_delete_and_replaced_generations_cancel_takeover() {
        let fixture = Fixture::new().await;
        fixture.member("m1", "p1", false).await;
        let pool = fixture.replica("gw-a");
        for (sandbox, route) in [
            ("sandbox-stopping", "rt-route-s000"),
            ("sandbox-deleted", "rt-route-d000"),
            ("sandbox-restarted", "rt-route-r000"),
        ] {
            fixture
                .sandbox(sandbox, "generation-1", SandboxPhase::Ready)
                .await;
            pool.place_launch(launch(route, sandbox, "generation-1"))
                .await
                .unwrap();
        }
        fixture
            .set_phase("sandbox-stopping", SandboxPhase::Stopping)
            .await;
        fixture
            .store
            .delete("sandbox", "sandbox-deleted")
            .await
            .unwrap();
        fixture
            .sandbox("sandbox-restarted", "generation-2", SandboxPhase::Ready)
            .await;
        fixture.member("m2", "p2", false).await;
        fixture.remove_member("m1").await;
        pool.reconcile_once().await.unwrap();
        for route in ["rt-route-s000", "rt-route-d000", "rt-route-r000"] {
            assert!(fixture.owner(route).await.is_none(), "{route}");
        }
        assert_eq!(
            fixture.identity("sandbox-stopping").await.auth_epoch.get(),
            1
        );
        assert_eq!(
            fixture.identity("sandbox-restarted").await.auth_epoch.get(),
            1
        );
    }

    #[tokio::test]
    async fn interrupted_takeovers_and_unowned_instances_are_completed() {
        let fixture = Fixture::new().await;
        fixture.member("m1", "p1", false).await;
        fixture
            .sandbox("sandbox-a", "generation-1", SandboxPhase::Ready)
            .await;
        fixture
            .sandbox("sandbox-b", "generation-1", SandboxPhase::Ready)
            .await;
        let pool = fixture.replica("gw-a");
        // A replica crashed after recording intent, before advancing the
        // sandbox identity.
        pool.write_owner(
            &OwnerPayload {
                route: "rt-route-a000".to_string(),
                sandbox_id: "sandbox-a".to_string(),
                generation: "generation-1".to_string(),
                member_id: "m1".to_string(),
                process_id: "p1".to_string(),
                auth_epoch: 2,
                supervisor_instance_id: Some(Uuid::new_v4().to_string()),
                gateway_token_id: Some(Uuid::new_v4().to_string()),
                phase: OwnerPhase::Granting,
                previous_member_id: Some("m0".to_string()),
            },
            WriteCondition::MustCreate,
        )
        .await
        .unwrap();
        for (route, sandbox) in [
            ("rt-route-a000", "sandbox-a"),
            // Recorded by a driver recovery: launched before the pool
            // recorded owners.
            ("rt-route-b000", "sandbox-b"),
        ] {
            pool.record_assignment(&assignment(route, sandbox, "generation-1"))
                .await
                .unwrap();
        }
        pool.reconcile_once().await.unwrap();
        pool.reconcile_once().await.unwrap();
        let resumed = fixture.owner("rt-route-a000").await.unwrap();
        assert_eq!(resumed.phase, OwnerPhase::Granted);
        assert_eq!(resumed.auth_epoch, 2);
        assert_eq!(fixture.identity("sandbox-a").await.auth_epoch.get(), 2);
        // An unowned instance is placed by a takeover, which fences
        // whichever process may already supervise it.
        let placed = fixture.owner("rt-route-b000").await.unwrap();
        assert_eq!(placed.phase, OwnerPhase::Granted);
        assert_eq!(placed.auth_epoch, 2);
        assert!(placed.supervisor_instance_id.is_some());
        assert_eq!(fixture.identity("sandbox-b").await.auth_epoch.get(), 2);
        // Only granted owners are served.
        let view = pool.controller.pool_view().unwrap();
        assert_eq!(view.owners.len(), 2);
    }

    #[tokio::test]
    async fn one_pass_completes_every_pending_intent_behind_a_healthy_route() {
        let fixture = Fixture::new().await;
        fixture.member("m1", "p1", false).await;
        fixture.member("m2", "p2", false).await;
        let pool = fixture.replica("gw-a");
        for sandbox in ["sandbox-a", "sandbox-b", "sandbox-c", "sandbox-d"] {
            fixture
                .sandbox(sandbox, "generation-1", SandboxPhase::Ready)
                .await;
        }
        // The first route in reconciliation order is healthy.
        pool.place_launch(launch("rt-route-a000", "sandbox-a", "generation-1"))
            .await
            .unwrap();
        let healthy = fixture.owner("rt-route-a000").await.unwrap();
        let intent = |route: &str, sandbox: &str, member: &str, process: &str| OwnerPayload {
            route: route.to_string(),
            sandbox_id: sandbox.to_string(),
            generation: "generation-1".to_string(),
            member_id: member.to_string(),
            process_id: process.to_string(),
            auth_epoch: 2,
            supervisor_instance_id: Some(Uuid::new_v4().to_string()),
            gateway_token_id: Some(Uuid::new_v4().to_string()),
            phase: OwnerPhase::Granting,
            previous_member_id: Some("m0".to_string()),
        };
        // A gateway replica crashed after recording intent (b), after also
        // advancing the sandbox identity (c), and after recording intent for
        // a term another takeover already holds (d).
        let b = intent("rt-route-b000", "sandbox-b", "m1", "p1");
        let c = intent("rt-route-c000", "sandbox-c", "m2", "p2");
        let d = intent("rt-route-d000", "sandbox-d", "m2", "p2");
        for pending in [&b, &c, &d] {
            pool.write_owner(pending, WriteCondition::MustCreate)
                .await
                .unwrap();
        }
        let advance = |sandbox: &'static str, token: Uuid| {
            let store = fixture.store.clone();
            async move {
                advance_identity_for_takeover(
                    &store,
                    sandbox,
                    "generation-1",
                    CredentialEpoch::new(2).unwrap(),
                    token,
                )
                .await
                .unwrap()
            }
        };
        let c_token = Uuid::parse_str(c.gateway_token_id.as_deref().unwrap()).unwrap();
        assert_eq!(
            advance("sandbox-c", c_token).await,
            TakeoverIdentity::Advanced
        );
        assert_eq!(
            advance("sandbox-d", Uuid::new_v4()).await,
            TakeoverIdentity::Advanced
        );
        for (route, sandbox) in [
            ("rt-route-b000", "sandbox-b"),
            ("rt-route-c000", "sandbox-c"),
            ("rt-route-d000", "sandbox-d"),
        ] {
            pool.record_assignment(&assignment(route, sandbox, "generation-1"))
                .await
                .unwrap();
        }

        pool.reconcile_once().await.unwrap();
        assert_eq!(fixture.owner("rt-route-a000").await.unwrap(), healthy);
        for (route, sandbox, pending) in [
            ("rt-route-b000", "sandbox-b", &b),
            ("rt-route-c000", "sandbox-c", &c),
        ] {
            let granted = fixture.owner(route).await.unwrap();
            assert_eq!(
                granted,
                OwnerPayload {
                    phase: OwnerPhase::Granted,
                    ..pending.clone()
                },
                "{route}"
            );
            let identity = fixture.identity(sandbox).await;
            assert_eq!(identity.auth_epoch.get(), 2);
            assert_eq!(
                Some(identity.gateway_token_id.to_string()),
                granted.gateway_token_id
            );
        }
        // The intent that lost its term is cancelled, never granted with
        // credentials of a lineage the gateway does not recognize, and the
        // instance is placed again at a later term.
        assert!(fixture.owner("rt-route-d000").await.is_none());
        let view = pool.controller.pool_view().unwrap();
        assert_eq!(view.owners.len(), 3);
        assert!(!view.owners.contains_key("rt-route-d000"));
        pool.reconcile_once().await.unwrap();
        let replaced = fixture.owner("rt-route-d000").await.unwrap();
        assert_eq!(
            (replaced.phase, replaced.auth_epoch),
            (OwnerPhase::Granted, 3)
        );
        assert_eq!(fixture.identity("sandbox-d").await.auth_epoch.get(), 3);
    }

    #[tokio::test]
    async fn records_of_ended_generations_are_removed() {
        let fixture = Fixture::new().await;
        fixture.member("m1", "p1", false).await;
        fixture
            .sandbox("sandbox-a", "generation-1", SandboxPhase::Ready)
            .await;
        let pool = fixture.replica("gw-a");
        pool.place_launch(launch("rt-route-a000", "sandbox-a", "generation-1"))
            .await
            .unwrap();
        // Withdrawn while still the sandbox's generation: the record and its
        // material go at once; the owner record stays for its owner to be
        // told to stop it.
        pool.controller.unassign("rt-route-a000");
        pool.reconcile_once().await.unwrap();
        assert!(fixture.instance("rt-route-a000").await.is_none());
        assert!(pool.controller.pool_withdrawals().is_empty());
        assert_eq!(fixture.credentials.stored_credential_count(), Some(0));
        assert!(fixture.owner("rt-route-a000").await.is_some());
        fixture
            .sandbox("sandbox-a", "generation-2", SandboxPhase::Ready)
            .await;
        pool.reconcile_once().await.unwrap();
        assert!(fixture.owner("rt-route-a000").await.is_none());

        // A stopped sandbox never runs its generation again, even when its
        // withdrawal was lost with a gateway replica.
        fixture
            .sandbox("sandbox-b", "generation-1", SandboxPhase::Ready)
            .await;
        pool.place_launch(launch("rt-route-b000", "sandbox-b", "generation-1"))
            .await
            .unwrap();
        pool.reconcile_once().await.unwrap();
        assert!(fixture.owner("rt-route-b000").await.is_some());
        fixture.set_phase("sandbox-b", SandboxPhase::Stopped).await;
        pool.reconcile_once().await.unwrap();
        pool.reconcile_once().await.unwrap();
        assert!(fixture.instance("rt-route-b000").await.is_none());
        assert!(fixture.owner("rt-route-b000").await.is_none());
        assert_eq!(fixture.credentials.stored_credential_count(), Some(0));
    }

    #[tokio::test]
    async fn a_starting_sandbox_is_taken_over_but_not_by_a_replica_that_just_started() {
        let fixture = Fixture::new().await;
        fixture.member("m1", "p1", false).await;
        fixture
            .sandbox("sandbox-a", "generation-1", SandboxPhase::Starting)
            .await;
        let starting = fixture.starting_replica("gw-new");
        starting
            .place_launch(launch("rt-route-a000", "sandbox-a", "generation-1"))
            .await
            .unwrap();
        fixture.member("m2", "p2", false).await;
        fixture.remove_member("m1").await;
        // Members cut off by a gateway restart get time to reconnect.
        starting.reconcile_once().await.unwrap();
        assert_eq!(fixture.owner("rt-route-a000").await.unwrap().auth_epoch, 1);
        // A replica past its grace takes the starting instance over.
        let settled = fixture.replica("gw-settled");
        settled.reconcile_once().await.unwrap();
        let owner = fixture.owner("rt-route-a000").await.unwrap();
        assert_eq!((owner.member_id.as_str(), owner.auth_epoch), ("m2", 2));
        assert_eq!(owner.phase, OwnerPhase::Granted);
    }

    #[tokio::test]
    async fn every_replica_derives_the_desired_set_and_material_from_records() {
        let fixture = Fixture::new().await;
        fixture.member("m1", "p1", false).await;
        fixture
            .sandbox("sandbox-a", "generation-1", SandboxPhase::Ready)
            .await;
        let launching = fixture.replica("gw-launch");
        let other = fixture.replica("gw-other");
        let launched = assignment("rt-route-a000", "sandbox-a", "generation-1");
        launching
            .place_launch(launch("rt-route-a000", "sandbox-a", "generation-1"))
            .await
            .unwrap();
        // The record keeps only the material's credential handle.
        let record = fixture.instance("rt-route-a000").await.unwrap();
        let stored = fixture
            .store
            .get_by_name(ASSIGNMENT_OBJECT_TYPE, "", "rt-route-a000")
            .await
            .unwrap()
            .unwrap();
        assert!(!String::from_utf8_lossy(&stored.payload).contains("{\"launch\""));
        assert_eq!(record.payload.workspace, "default");

        // A replica that never saw the launch, and runs no compute watch,
        // derives the instance, its owner, and its material from the records.
        other.reconcile_once().await.unwrap();
        let view = other.controller.pool_view().unwrap();
        assert!(view.desired.contains("rt-route-a000"));
        assert_eq!(view.owners["rt-route-a000"].member_id, "m1");
        assert_eq!(
            other.load_material(&record.payload).await.unwrap(),
            launched.launch_material
        );
        assert!(
            other
                .recorded()
                .await
                .unwrap()
                .contains_key("rt-route-a000")
        );

        // Recording the generation again keeps the first record and material;
        // another generation on its route is refused.
        other.record_assignment(&launched).await.unwrap();
        assert_eq!(fixture.credentials.stored_credential_count(), Some(1));
        assert!(
            other
                .record_assignment(&assignment("rt-route-a000", "sandbox-a", "generation-2"))
                .await
                .is_err()
        );

        // A withdrawal through either replica removes the record and its
        // material, and leaves the desired set of both.
        other.controller.unassign("rt-route-a000");
        other.reconcile_once().await.unwrap();
        assert!(fixture.instance("rt-route-a000").await.is_none());
        assert_eq!(fixture.credentials.stored_credential_count(), Some(0));
        launching.reconcile_once().await.unwrap();
        assert!(
            !launching
                .controller
                .pool_view()
                .unwrap()
                .desired
                .contains("rt-route-a000")
        );
    }

    #[tokio::test]
    async fn racing_records_of_one_instance_keep_one_material() {
        let fixture = Fixture::new().await;
        fixture
            .sandbox("sandbox-a", "generation-1", SandboxPhase::Ready)
            .await;
        let (first, second) = (fixture.replica("gw-a"), fixture.replica("gw-b"));
        let instance = assignment("rt-route-a000", "sandbox-a", "generation-1");
        let results: [_; 2] = tokio::join!(
            first.record_assignment(&instance),
            second.record_assignment(&instance)
        )
        .into();
        // One recording reserves the route and publishes; the other finds the
        // reservation or the record, and stores no material.
        let record = fixture.instance("rt-route-a000").await.unwrap();
        assert_eq!(record.payload.phase, RecordPhase::Published);
        for result in results {
            match result {
                Ok(recorded) => assert_eq!(
                    recorded.payload.material_handle,
                    record.payload.material_handle
                ),
                Err(error) => assert!(error.contains("being recorded"), "{error}"),
            }
        }
        assert_eq!(fixture.credentials.stored_credential_count(), Some(1));
        assert_eq!(fixture.candidates().await, 0);
        assert_eq!(
            first.load_material(&record.payload).await.unwrap(),
            instance.launch_material
        );
    }

    #[tokio::test]
    async fn a_fenced_recording_whose_cleanup_fails_keeps_its_material_owned() {
        let fixture = Fixture::new().await;
        fixture
            .sandbox("sandbox-a", "generation-1", SandboxPhase::Ready)
            .await;
        let pool = fixture.replica("gw-a");
        let instance = assignment("rt-route-a000", "sandbox-a", "generation-1");
        let (staged, publish) = pool.pause_next_recording_after_staging();
        let recording = {
            let (pool, instance) = (pool.clone(), instance.clone());
            tokio::spawn(async move { pool.record_assignment(&instance).await })
        };
        staged.await.unwrap();
        // The instance is withdrawn while it is being recorded: removing its
        // reservation fences the recording.
        pool.controller.unassign("rt-route-a000");
        pool.remove_withdrawn().await;
        assert!(fixture.instance("rt-route-a000").await.is_none());
        // The recording cannot publish, and its cleanup fails; its material
        // stays owned by its candidate.
        fixture.credentials.fail_next_delete();
        publish.send(()).unwrap();
        let error = recording.await.unwrap().unwrap_err();
        assert!(error.contains("withdrawn before publication"), "{error}");
        assert!(fixture.instance("rt-route-a000").await.is_none());
        assert_eq!(fixture.credentials.stored_credential_count(), Some(1));
        assert_eq!(fixture.candidates().await, 1);
        // Collection deletes it.
        pool.remove_stale_candidates().await;
        assert_eq!(fixture.credentials.stored_credential_count(), Some(0));
        assert_eq!(fixture.candidates().await, 0);
    }

    #[tokio::test]
    async fn collection_never_deletes_the_material_of_a_recording_in_progress() {
        let fixture = Fixture::new().await;
        fixture
            .sandbox("sandbox-a", "generation-1", SandboxPhase::Ready)
            .await;
        // Candidates are collectable at once (grace zero).
        let pool = fixture.replica("gw-a");
        let instance = assignment("rt-route-a000", "sandbox-a", "generation-1");
        let (staged, publish) = pool.pause_next_recording_after_staging();
        let recording = {
            let (pool, instance) = (pool.clone(), instance.clone());
            tokio::spawn(async move { pool.record_assignment(&instance).await })
        };
        staged.await.unwrap();
        // Staged and unpublished: material stored, candidate written, the
        // route only reserved. Collection runs now, alone and as part of a
        // whole pass, and must not delete the material.
        assert_eq!(fixture.candidates().await, 1);
        assert_eq!(
            fixture
                .instance("rt-route-a000")
                .await
                .unwrap()
                .payload
                .phase,
            RecordPhase::Reserved
        );
        pool.remove_stale_candidates().await;
        pool.reconcile_once().await.unwrap();
        assert_eq!(fixture.credentials.stored_credential_count(), Some(1));
        assert_eq!(fixture.candidates().await, 1);
        // A driver recovery begins listing after the reservation but before
        // the publication, which its listing may then miss.
        let reserved_at = fixture
            .instance("rt-route-a000")
            .await
            .unwrap()
            .created_at_ms;
        while now_ms() <= reserved_at {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let listing_began = now_ms();
        while now_ms() <= listing_began {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        // The recording publishes, and its record's material resolves.
        publish.send(()).unwrap();
        let record = recording.await.unwrap().unwrap();
        // Recovery sees when it was published, not reserved, so it keeps it.
        assert!(pool.recorded().await.unwrap()["rt-route-a000"] > listing_began);
        pool.remove_stale_candidates().await;
        assert_eq!(
            pool.load_material(&record.payload).await.unwrap(),
            instance.launch_material
        );
        assert_eq!(fixture.candidates().await, 0);
        assert_eq!(fixture.credentials.stored_credential_count(), Some(1));
    }

    #[tokio::test]
    async fn a_stalled_recording_is_fenced_and_never_publishes_its_material() {
        let fixture = Fixture::new().await;
        fixture
            .sandbox("sandbox-a", "generation-1", SandboxPhase::Ready)
            .await;
        let mut pool = fixture.replica("gw-a");
        Arc::get_mut(&mut pool).expect("unique").reservation_grace = Duration::ZERO;
        let instance = assignment("rt-route-a000", "sandbox-a", "generation-1");
        let (staged, publish) = pool.pause_next_recording_after_staging();
        let recording = {
            let (pool, instance) = (pool.clone(), instance.clone());
            tokio::spawn(async move { pool.record_assignment(&instance).await })
        };
        staged.await.unwrap();
        // The recording outlives its reservation's grace: a pass fences it and
        // collects its material.
        pool.reconcile_once().await.unwrap();
        assert!(fixture.instance("rt-route-a000").await.is_none());
        assert_eq!(fixture.credentials.stored_credential_count(), Some(0));
        assert_eq!(fixture.candidates().await, 0);
        // When it resumes, its publication fails: no record ever names the
        // deleted material.
        publish.send(()).unwrap();
        assert!(recording.await.unwrap().is_err());
        assert!(fixture.instance("rt-route-a000").await.is_none());
        assert_eq!(fixture.credentials.stored_credential_count(), Some(0));
        // The route can be recorded again.
        let record = pool.record_assignment(&instance).await.unwrap();
        assert_eq!(
            pool.load_material(&record.payload).await.unwrap(),
            instance.launch_material
        );
    }

    #[tokio::test]
    async fn a_fenced_recording_cannot_publish_over_the_next_reservation() {
        let fixture = Fixture::new().await;
        fixture
            .sandbox("sandbox-a", "generation-1", SandboxPhase::Ready)
            .await;
        let instance = assignment("rt-route-a000", "sandbox-a", "generation-1");
        let record_paused = |pool: Arc<SupervisorPool>| {
            let (staged, publish) = pool.pause_next_recording_after_staging();
            let instance = instance.clone();
            let recording = tokio::spawn(async move { pool.record_assignment(&instance).await });
            (staged, publish, recording)
        };
        // The first recording stalls after staging and is fenced; its
        // material is collected.
        let (staged, publish_first, first) = record_paused(fixture.replica("gw-a"));
        staged.await.unwrap();
        let mut fencing = fixture.replica("gw-fence");
        Arc::get_mut(&mut fencing)
            .expect("unique")
            .reservation_grace = Duration::ZERO;
        fencing.reconcile_once().await.unwrap();
        assert_eq!(fixture.credentials.stored_credential_count(), Some(0));
        // A second recording reserves the route anew, at the same store
        // version the first one reserved at, and stalls after staging.
        let second_pool = fixture.replica("gw-b");
        let (staged, publish_second, second) = record_paused(second_pool.clone());
        staged.await.unwrap();
        // The first recording resumes: it cannot publish over the second's
        // reservation.
        publish_first.send(()).unwrap();
        assert!(first.await.unwrap().is_err());
        assert_eq!(
            fixture
                .instance("rt-route-a000")
                .await
                .unwrap()
                .payload
                .phase,
            RecordPhase::Reserved
        );
        // The second publishes, and its material resolves.
        publish_second.send(()).unwrap();
        let record = second.await.unwrap().unwrap();
        assert_eq!(
            second_pool.load_material(&record.payload).await.unwrap(),
            instance.launch_material
        );
        assert_eq!(fixture.credentials.stored_credential_count(), Some(1));
    }

    #[tokio::test]
    async fn a_cancelled_launch_still_completes_its_durable_records() {
        let fixture = Fixture::new().await;
        fixture.member("m1", "p1", false).await;
        fixture
            .sandbox("sandbox-a", "generation-1", SandboxPhase::Ready)
            .await;
        let placement = PoolPlacement(fixture.replica("gw-a"));
        let (entered, release) = fixture.credentials.gate_next_store();
        let launching = tokio::spawn(placement.place_launch(launch(
            "rt-route-a000",
            "sandbox-a",
            "generation-1",
        )));
        entered.await.unwrap();
        // The launch's caller goes away while its material is being stored.
        launching.abort();
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            while fixture.owner("rt-route-a000").await.is_none() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the detached launch completes");
        assert!(fixture.instance("rt-route-a000").await.is_some());
        assert_eq!(fixture.candidates().await, 0);
        assert_eq!(fixture.credentials.stored_credential_count(), Some(1));
    }

    #[tokio::test]
    async fn recorded_reports_of_the_current_owner_term_reach_every_replica() {
        let fixture = Fixture::new().await;
        fixture.member("m1", "p1", false).await;
        fixture
            .sandbox("sandbox-a", "generation-1", SandboxPhase::Ready)
            .await;
        let pool = fixture.replica("gw-a");
        pool.place_launch(launch("rt-route-a000", "sandbox-a", "generation-1"))
            .await
            .unwrap();
        let report = |process: &str, ready| ReportPayload {
            route: "rt-route-a000".to_string(),
            member_id: "m1".to_string(),
            process_id: process.to_string(),
            auth_epoch: 1,
            sandbox_id: "sandbox-a".to_string(),
            phase: 2,
            ready,
            exit_code: 0,
        };
        let record = |payload: ReportPayload| {
            let store = fixture.store.clone();
            async move {
                store
                    .put_if(
                        REPORT_OBJECT_TYPE,
                        &report_object_id(&payload.route),
                        &payload.route,
                        "",
                        &serde_json::to_vec(&payload).unwrap(),
                        None,
                        WriteCondition::Unconditional,
                    )
                    .await
                    .unwrap();
            }
        };
        // The replica serving the owner recorded that it is ready; this
        // replica, which does not serve it, reads the verdict.
        record(report("p1", true)).await;
        pool.reconcile_once().await.unwrap();
        assert!(matches!(
            pool.controller.observed("rt-route-a000"),
            openshell_supervisor_control::ObservedInstance::Reported(status) if status.ready
        ));
        // A report of another process is not the current owner's.
        record(report("p1-restarted", true)).await;
        pool.reconcile_once().await.unwrap();
        assert_eq!(
            pool.controller.observed("rt-route-a000"),
            openshell_supervisor_control::ObservedInstance::NoHost
        );
    }

    #[test]
    fn placement_prefers_the_ring_and_moves_on_only_when_a_member_is_full() {
        let member = |id: &str, leaving| LiveMember {
            member_id: id.to_string(),
            process_id: format!("p-{id}"),
            runtime_address: "10.0.0.1:5500".to_string(),
            leaving,
        };
        let members = vec![member("m1", false), member("m2", false), member("m3", true)];
        let ring = ring_of(&members);
        let sandbox = (0..64)
            .map(|index| format!("sandbox-{index}"))
            .find(|sandbox| ring.owner_for(sandbox) == Some("m1"))
            .expect("a sandbox the ring places on m1");
        let load = |m1, m2| HashMap::from([("m1".to_string(), m1), ("m2".to_string(), m2)]);
        let chosen = |load: HashMap<String, usize>| {
            choose(&ring, &members, &sandbox, &load).map(|member| member.member_id.clone())
        };
        assert_eq!(
            chosen(load(MAX_ASSIGNED_INSTANCES - 1, 0)).as_deref(),
            Some("m1")
        );
        // A full member is skipped for the least loaded one with room; a
        // leaving member never receives instances.
        assert_eq!(
            chosen(load(MAX_ASSIGNED_INSTANCES, 3)).as_deref(),
            Some("m2")
        );
        assert_eq!(
            chosen(load(MAX_ASSIGNED_INSTANCES, MAX_ASSIGNED_INSTANCES)),
            None
        );
    }
}
