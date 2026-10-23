// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Durable state of a highly available pool of shared supervisors.
//!
//! The pool reuses the gateway's own HA pattern for the shared supervisor's
//! sandbox instances:
//!
//! - **Membership.** The gateway replica serving a member's stream refreshes a
//!   store record for it, from its own task and never behind a reconciliation
//!   pass; a record older than [`MEMBER_TTL`] is dead. Only the member's
//!   newest stream writes its record. A member that announces it is leaving
//!   is out of the pool at once, and a member whose process changed lost
//!   every instance its previous process owned. See
//!   [`openshell_supervisor_control::pool_timing`].
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
use openshell_supervisor_control::pool_timing::RECORD_WRITE_BOUND;
use openshell_supervisor_control::proto::{
    SandboxInstanceAssignment, SandboxInstanceStatus, SandboxInstanceTakeover,
};
use openshell_supervisor_control::{
    ConnectedMember, InstanceOwner, InstancePlacement, MAX_ASSIGNED_INSTANCES, MAX_POOL_INSTANCES,
    MemberReport, MemberView, PlacementFuture, PlacementRequest, PoolView,
    SupervisorHostController,
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
use crate::persistence::{
    AtomicWrite, ObjectCursor, ObjectRecord, PersistenceError, Store, WriteCondition,
};

const MEMBER_OBJECT_TYPE: &str = "supervisor_pool_member";
const OWNER_OBJECT_TYPE: &str = "supervisor_instance_owner";
const ASSIGNMENT_OBJECT_TYPE: &str = "supervisor_instance_assignment";
/// Launch material stored for an instance record not yet written; the row
/// owns the material's handle until the record does, so a cancelled or
/// failed recording never loses the only handle.
const MATERIAL_CANDIDATE_OBJECT_TYPE: &str = "supervisor_instance_material_candidate";
const REPORT_OBJECT_TYPE: &str = "supervisor_instance_report";
/// The routes one member is charged for: exactly the routes whose owner record,
/// in any phase, names the member. Every owner change updates it in the same
/// atomic write, so a member is never charged for more than
/// [`MAX_ASSIGNED_INSTANCES`] routes across gateway replicas.
const CAPACITY_OBJECT_TYPE: &str = "supervisor_pool_capacity";
/// Attempts of one owner change against concurrent changes of the same
/// members' capacity.
const TRANSITION_ATTEMPTS: usize = 16;
/// Credential key of an instance's launch material in the credential store.
const LAUNCH_MATERIAL_KEY: &str = "SHARED_INSTANCE_LAUNCH_MATERIAL";

/// How long a member's record stays live without a refresh.
pub const MEMBER_TTL: Duration = openshell_supervisor_control::pool_timing::MEMBER_TTL;
/// How often each gateway replica reconciles.
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

fn capacity_object_id(member_id: &str) -> String {
    format!("supervisor-pool-capacity:{member_id}")
}

/// One ownership term's report row of `route`. A writer of an older term
/// can never overwrite a newer term's row.
fn report_object_id(route: &str, auth_epoch: u64) -> String {
    format!("supervisor-instance-report:{route}:{auth_epoch}")
}

fn report_object_name(route: &str, auth_epoch: u64) -> String {
    format!("{route}:{auth_epoch}")
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

/// What an owner reported of one instance in one ownership term, for gateway
/// replicas that do not serve the owner. Error text is not recorded.
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
    /// When the reporting stream was accepted; within one term, a newer
    /// stream's report wins.
    #[serde(default)]
    connected_at_ms: i64,
}

/// Listed report rows by object id, with their resource versions.
type ReportRows = BTreeMap<String, (ReportPayload, u64)>;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct CapacityPayload {
    member_id: String,
    routes: BTreeSet<String>,
}

/// A member's capacity row as read, or an empty one not yet written.
#[derive(Debug, Clone)]
struct Capacity {
    payload: CapacityPayload,
    resource_version: Option<u64>,
}

impl Capacity {
    fn empty(member_id: &str) -> Self {
        Self {
            payload: CapacityPayload {
                member_id: member_id.to_string(),
                routes: BTreeSet::new(),
            },
            resource_version: None,
        }
    }

    /// Whether `route` can be charged here: it already is, or a slot is free.
    fn has_room_for(&self, route: &str) -> bool {
        self.payload.routes.contains(route) || self.payload.routes.len() < MAX_ASSIGNED_INSTANCES
    }

    /// The write that makes this row charge exactly `routes`.
    fn write(&self, routes: BTreeSet<String>) -> Result<AtomicWrite, PersistenceError> {
        let payload = serde_json::to_vec(&CapacityPayload {
            member_id: self.payload.member_id.clone(),
            routes,
        })
        .map_err(|error| PersistenceError::Encode(error.to_string()))?;
        let id = capacity_object_id(&self.payload.member_id);
        Ok(match self.resource_version {
            None => AtomicWrite::Create {
                object_type: CAPACITY_OBJECT_TYPE.to_string(),
                id,
                name: self.payload.member_id.clone(),
                workspace: String::new(),
                payload,
            },
            Some(expected_version) => AtomicWrite::Update {
                object_type: CAPACITY_OBJECT_TYPE.to_string(),
                id,
                payload,
                expected_version,
            },
        })
    }
}

fn decode_capacity(record: &ObjectRecord) -> Option<Capacity> {
    let payload = serde_json::from_slice::<CapacityPayload>(&record.payload).ok()?;
    (record.id == capacity_object_id(&payload.member_id)).then_some(Capacity {
        payload,
        resource_version: Some(record.resource_version),
    })
}

/// How an owner change ended.
#[derive(Debug)]
enum Transition {
    /// Applied; the owner record now reads as this, or is gone.
    Applied(Option<Box<OwnerRecord>>),
    /// The target member has no free slot for the route.
    Full,
    /// The owner record is not what the change was based on.
    OwnerChanged,
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
    /// How often the records of served members are refreshed.
    member_refresh: Duration,
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
    #[cfg(test)]
    hooks: TestHooks,
}

/// A pause one test sets and one task takes: it reports reaching the pause
/// and waits to be resumed.
#[cfg(test)]
type Gate = (
    tokio::sync::oneshot::Sender<()>,
    tokio::sync::oneshot::Receiver<()>,
);

/// A pause of owner changes: reports reaching it, if asked, and waits on a
/// barrier shared with competing changes.
#[cfg(test)]
type TransitionGate = (
    Option<tokio::sync::oneshot::Sender<()>>,
    Arc<tokio::sync::Barrier>,
);

/// Points where tests pause or perturb a pass.
#[cfg(test)]
#[derive(Default)]
struct TestHooks {
    /// Pauses the next listing of an object type after its first page.
    listing_gate: Mutex<Option<(String, Gate)>>,
    /// Routes dropped from assignment and owner listings, as a listing that
    /// is not a snapshot can miss rows.
    listing_omits: Mutex<BTreeSet<String>>,
    /// Pauses the next reconciliation pass before it does anything.
    reconcile_gate: Mutex<Option<Gate>>,
    /// Replaces the members whose streams the controller serves.
    served_members: Mutex<Option<Vec<ConnectedMember>>>,
    /// Replaces what served members report.
    served_reports: Mutex<Option<Vec<MemberReport>>>,
    /// Pauses the next report recording after it read what members report.
    report_gate: Mutex<Option<Gate>>,
    /// Pauses the next owner change after it read capacity, before it
    /// writes: signals arrival, then waits on the barrier.
    transition_gate: Mutex<Option<TransitionGate>>,
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

/// Members to place `route` (of `sandbox_id`) on, best first: `same`, the
/// route's previous member, when its live process may re-adopt it; the
/// ring's choice; then the others, least charged first. Only members that
/// seem to have room for the route are listed; the owner change itself
/// re-checks room atomically. `charges` counts the routes each member is
/// charged for and lists them.
fn candidates<'a>(
    ring: &GatewayRing,
    members: &'a [LiveMember],
    sandbox_id: &str,
    route: &str,
    charges: &BTreeMap<String, BTreeSet<String>>,
    same: Option<&str>,
) -> Vec<&'a LiveMember> {
    let routes_of = |member: &LiveMember| charges.get(&member.member_id);
    let has_room = |member: &&LiveMember| {
        !member.leaving
            && routes_of(member).is_none_or(|routes| {
                routes.contains(route) || routes.len() < MAX_ASSIGNED_INSTANCES
            })
    };
    let load = |member: &LiveMember| routes_of(member).map_or(0, BTreeSet::len);
    let preferred = ring.owner_for(sandbox_id);
    let mut ordered = members.iter().filter(has_room).collect::<Vec<_>>();
    ordered.sort_by_key(|member| {
        (
            Some(member.member_id.as_str()) != same,
            Some(member.member_id.as_str()) != preferred,
            load(member),
            member.member_id.clone(),
        )
    });
    ordered
}

/// The routes each member is charged for, from capacity rows.
fn charges_of(capacities: &[Capacity]) -> BTreeMap<String, BTreeSet<String>> {
    capacities
        .iter()
        .map(|capacity| {
            (
                capacity.payload.member_id.clone(),
                capacity.payload.routes.clone(),
            )
        })
        .collect()
}

/// Move `route`'s charge in a local copy after an owner change.
fn recharge(
    charges: &mut BTreeMap<String, BTreeSet<String>>,
    route: &str,
    before: Option<&str>,
    after: Option<&str>,
) {
    if let Some(before) = before
        && let Some(routes) = charges.get_mut(before)
    {
        routes.remove(route);
    }
    if let Some(after) = after {
        charges
            .entry(after.to_string())
            .or_default()
            .insert(route.to_string());
    }
}

/// Whether the process that owns `owner` still serves its member.
fn owner_alive(owner: &OwnerPayload, members: &[LiveMember]) -> bool {
    members.iter().any(|member| {
        member.member_id == owner.member_id
            && member.process_id == owner.process_id
            && !member.leaving
    })
}

/// Why `owner`, which [`owner_alive`] rejects, loses its instance: its
/// member is leaving, runs a new process, or has no live record.
fn takeover_cause(owner: &OwnerPayload, members: &[LiveMember]) -> &'static str {
    match members
        .iter()
        .find(|member| member.member_id == owner.member_id)
    {
        Some(member) if member.process_id != owner.process_id => "restarted",
        Some(_) => "leaving",
        None => "expired",
    }
}

fn decode_owner(record: &ObjectRecord) -> Option<OwnerRecord> {
    let payload = serde_json::from_slice::<OwnerPayload>(&record.payload).ok()?;
    (record.id == owner_object_id(&payload.route)).then_some(OwnerRecord {
        payload,
        resource_version: record.resource_version,
    })
}

/// The report row of each route's current, granted owner term.
fn reports_of_owners(
    owners: &BTreeMap<String, OwnerRecord>,
    rows: &ReportRows,
) -> BTreeMap<String, SandboxInstanceStatus> {
    owners
        .values()
        .filter(|owner| owner.payload.phase == OwnerPhase::Granted)
        .filter_map(|owner| {
            let (report, _) = rows.get(&report_object_id(
                &owner.payload.route,
                owner.payload.auth_epoch,
            ))?;
            (report.member_id == owner.payload.member_id
                && report.process_id == owner.payload.process_id)
                .then(|| {
                    (
                        report.route.clone(),
                        SandboxInstanceStatus {
                            route: report.route.clone(),
                            sandbox_id: report.sandbox_id.clone(),
                            phase: report.phase,
                            ready: report.ready,
                            exit_code: report.exit_code,
                            error: String::new(),
                        },
                    )
                })
        })
        .collect()
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
    (record.id == report_object_id(&payload.route, payload.auth_epoch)).then_some(payload)
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
            member_refresh: openshell_supervisor_control::pool_timing::MEMBER_REFRESH_INTERVAL,
            unowned_grace: UNOWNED_GRACE,
            takeovers_from: tokio::time::Instant::now() + TAKEOVER_STARTUP_GRACE,
            unowned_since: Mutex::new(HashMap::new()),
            minted: Mutex::new(HashMap::new()),
            materials: Mutex::new(HashMap::new()),
            withdrawn_since: Mutex::new(HashMap::new()),
            sweep_from: Mutex::new(0),
            candidate_grace: MATERIAL_CANDIDATE_GRACE,
            reservation_grace: RESERVATION_GRACE,
            #[cfg(test)]
            staged_gate: Mutex::new(None),
            #[cfg(test)]
            hooks: TestHooks::default(),
        })
    }

    /// Pause the next listing of `object_type` after its first page.
    #[cfg(test)]
    fn pause_listing_after_first_page(
        &self,
        object_type: &str,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (paused, paused_rx) = tokio::sync::oneshot::channel();
        let (resume, resume_rx) = tokio::sync::oneshot::channel();
        *lock(&self.hooks.listing_gate) = Some((object_type.to_string(), (paused, resume_rx)));
        (paused_rx, resume)
    }

    /// Pause the next owner change after it read capacity, until the
    /// barrier releases it.
    #[cfg(test)]
    fn pause_next_transition(&self, barrier: Arc<tokio::sync::Barrier>) {
        *lock(&self.hooks.transition_gate) = Some((None, barrier));
    }

    /// Like [`Self::pause_next_transition`]; the receiver resolves once the
    /// change read capacity and waits on the barrier.
    #[cfg(test)]
    fn pause_next_transition_reached(
        &self,
        barrier: Arc<tokio::sync::Barrier>,
    ) -> tokio::sync::oneshot::Receiver<()> {
        let (reached, arrival) = tokio::sync::oneshot::channel();
        *lock(&self.hooks.transition_gate) = Some((Some(reached), barrier));
        arrival
    }

    /// The owner record of `route`.
    #[cfg(test)]
    async fn reload_owner(&self, route: &str) -> OwnerRecord {
        self.store
            .get(OWNER_OBJECT_TYPE, &owner_object_id(route))
            .await
            .unwrap()
            .as_ref()
            .and_then(decode_owner)
            .unwrap()
    }

    /// Drop `route` from assignment and owner listings.
    #[cfg(test)]
    fn omit_from_listings(&self, route: &str) {
        lock(&self.hooks.listing_omits).insert(route.to_string());
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

    /// Report `reports` as if served members had made them.
    #[cfg(test)]
    fn serve_reports(&self, reports: Vec<MemberReport>) {
        *lock(&self.hooks.served_reports) = Some(reports);
    }

    /// Pause the next report recording after it read what members report.
    #[cfg(test)]
    fn pause_next_report_recording(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (paused, paused_rx) = tokio::sync::oneshot::channel();
        let (resume, resume_rx) = tokio::sync::oneshot::channel();
        *lock(&self.hooks.report_gate) = Some((paused, resume_rx));
        (paused_rx, resume)
    }

    /// Pause the next reconciliation pass before it starts.
    #[cfg(test)]
    fn pause_next_pass(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (paused, paused_rx) = tokio::sync::oneshot::channel();
        let (resume, resume_rx) = tokio::sync::oneshot::channel();
        *lock(&self.hooks.reconcile_gate) = Some((paused, resume_rx));
        (paused_rx, resume)
    }

    /// Serve `members` as if their streams were connected here.
    #[cfg(test)]
    fn serve(&self, members: Vec<ConnectedMember>) {
        *lock(&self.hooks.served_members) = Some(members);
    }

    /// Members whose streams this replica serves.
    fn served_members(&self) -> Vec<ConnectedMember> {
        #[cfg(test)]
        {
            let members = lock(&self.hooks.served_members).clone();
            if let Some(members) = members {
                return members;
            }
        }
        self.controller.connected_members()
    }

    /// Install this pool as the controller's launch placement, keep the
    /// records of served members fresh, and keep the pool reconciled until
    /// shutdown.
    pub fn start(self: &Arc<Self>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        self.controller
            .install_placement(Arc::new(PoolPlacement(self.clone())));
        self.start_membership_heartbeat(shutdown.clone());
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

    /// Refresh served members' records every [`Self::member_refresh`], and
    /// at once when a member attaches, leaves, or detaches. Independent of
    /// reconciliation, so a slow pass never lets a served member expire.
    fn start_membership_heartbeat(
        self: &Arc<Self>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        let pool = self.clone();
        tokio::spawn(async move {
            let mut membership = pool.controller.membership_changes();
            let mut ticker = tokio::time::interval(pool.member_refresh);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {}
                    changed = membership.changed() => {
                        if changed.is_err() {
                            return;
                        }
                    }
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            return;
                        }
                        continue;
                    }
                }
                pool.refresh_members().await;
            }
        });
    }

    /// Refresh the records of members this replica serves, all at once and
    /// each within [`RECORD_WRITE_BOUND`]; a write that does not finish is
    /// abandoned and the next round starts over. A record a newer stream of
    /// the member wrote is left alone.
    async fn refresh_members(&self) {
        let members = self.served_members();
        let writes = members.iter().map(|member| async move {
            match tokio::time::timeout(RECORD_WRITE_BOUND, self.write_member(member)).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    warn!(member = %member.member_id, %error, "supervisor pool member refresh failed");
                }
                Err(_) => {
                    warn!(member = %member.member_id, "supervisor pool member refresh did not finish in time");
                }
            }
        });
        futures::future::join_all(writes).await;
    }

    async fn write_member(&self, member: &ConnectedMember) -> Result<(), PersistenceError> {
        let id = member_object_id(&member.member_id);
        let existing = self.store.get(MEMBER_OBJECT_TYPE, &id).await?;
        // A newer stream of the member, from its process or a new one, wrote
        // the record; this replica's older stream is stale.
        if let Some(record) = &existing
            && let Ok(current) = serde_json::from_slice::<MemberPayload>(&record.payload)
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

    /// Every record of `object_type`, page by page after an immutable
    /// cursor, so rows removed meanwhile cannot shift others out of the
    /// listing. It is still not a snapshot: a row written meanwhile can be
    /// missed, so a pass confirms an apparent disappearance before acting on
    /// it (see [`Self::confirm_absences`]).
    async fn list_all(&self, object_type: &str) -> Result<Vec<ObjectRecord>, PersistenceError> {
        let mut records = Vec::new();
        let mut after: Option<ObjectCursor> = None;
        loop {
            let page = self
                .store
                .list_by_type_after(object_type, after.as_ref(), LIST_LIMIT)
                .await?;
            let complete = page.len() < LIST_LIMIT as usize;
            after = page.last().map(ObjectCursor::from);
            records.extend(page);
            if complete {
                break;
            }
            #[cfg(test)]
            {
                let gate = {
                    let mut gate = lock(&self.hooks.listing_gate);
                    if gate.as_ref().is_some_and(|(kind, _)| kind == object_type) {
                        gate.take()
                    } else {
                        None
                    }
                };
                if let Some((_, (paused, resume))) = gate {
                    let _ = paused.send(());
                    let _ = resume.await;
                }
            }
        }
        #[cfg(test)]
        if object_type == ASSIGNMENT_OBJECT_TYPE || object_type == OWNER_OBJECT_TYPE {
            let omits = lock(&self.hooks.listing_omits).clone();
            records.retain(|record| !omits.contains(&record.name));
        }
        Ok(records)
    }

    /// Keep what a listing seems to have lost until a point read confirms it
    /// is gone: owners the published view has, and instances it or an owner
    /// record names. A route that disappears is stopped or released, which a
    /// missed row must never cause. A failed read fails the pass, which then
    /// publishes nothing.
    async fn confirm_absences(
        &self,
        owners: &mut BTreeMap<String, OwnerRecord>,
        desired: &mut BTreeMap<String, AssignmentRecord>,
        withdrawals: &BTreeSet<String>,
    ) -> Result<(), PersistenceError> {
        let Some(previous) = self.controller.pool_view() else {
            return Ok(());
        };
        for route in previous.owners.keys() {
            if owners.contains_key(route) {
                continue;
            }
            if let Some(record) = self
                .store
                .get(OWNER_OBJECT_TYPE, &owner_object_id(route))
                .await?
                .as_ref()
                .and_then(decode_owner)
            {
                warn!(
                    route,
                    "a supervisor instance owner was missing from its listing"
                );
                owners.insert(route.clone(), record);
            }
        }
        let suspects = previous
            .desired
            .iter()
            .chain(owners.keys())
            .filter(|route| !desired.contains_key(*route) && !withdrawals.contains(*route))
            .cloned()
            .collect::<BTreeSet<_>>();
        for route in suspects {
            if let Some(record) = self.assignment(&route).await?
                && record.payload.phase == RecordPhase::Published
            {
                warn!(
                    route,
                    "a supervisor pool instance was missing from its listing"
                );
                desired.insert(route, record);
            }
        }
        Ok(())
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

    /// Record a new owner as a test would find it written by another
    /// replica, charging its member like every owner change.
    #[cfg(test)]
    async fn write_owner(
        &self,
        payload: &OwnerPayload,
        condition: WriteCondition,
    ) -> Result<OwnerRecord, PersistenceError> {
        assert!(matches!(condition, WriteCondition::MustCreate));
        match self.transition(&payload.route, None, Some(payload)).await? {
            Transition::Applied(Some(record)) => Ok(*record),
            _ => Err(PersistenceError::Conflict {
                current_resource_version: None,
            }),
        }
    }

    async fn capacity(&self, member_id: &str) -> Result<Capacity, PersistenceError> {
        Ok(self
            .store
            .get(CAPACITY_OBJECT_TYPE, &capacity_object_id(member_id))
            .await?
            .as_ref()
            .and_then(decode_capacity)
            .unwrap_or_else(|| Capacity::empty(member_id)))
    }

    async fn capacities(&self) -> Result<Vec<Capacity>, PersistenceError> {
        Ok(self
            .list_all(CAPACITY_OBJECT_TYPE)
            .await?
            .iter()
            .filter_map(decode_capacity)
            .collect())
    }

    /// Change `route`'s owner record from `before` (absent when `None`) to
    /// `after` (removed when `None`), and move the route's capacity charge
    /// from `before`'s member to `after`'s, in one atomic write. A target
    /// member without a free slot refuses the change before anything is
    /// written; a concurrent change of the same members' capacity is retried
    /// on fresh rows while the owner record is still `before`.
    async fn transition(
        &self,
        route: &str,
        before: Option<&OwnerRecord>,
        after: Option<&OwnerPayload>,
    ) -> Result<Transition, PersistenceError> {
        let from = before.map(|record| record.payload.member_id.as_str());
        let to = after.map(|payload| payload.member_id.as_str());
        let encode = |payload: &OwnerPayload| {
            serde_json::to_vec(payload).map_err(|error| PersistenceError::Encode(error.to_string()))
        };
        for _ in 0..TRANSITION_ATTEMPTS {
            let mut writes = Vec::new();
            if let Some(to) = to {
                let capacity = self.capacity(to).await?;
                if !capacity.has_room_for(route) {
                    return Ok(Transition::Full);
                }
                if !capacity.payload.routes.contains(route) {
                    let mut routes = capacity.payload.routes.clone();
                    routes.insert(route.to_string());
                    writes.push(capacity.write(routes)?);
                }
            }
            if let Some(from) = from
                && Some(from) != to
            {
                let capacity = self.capacity(from).await?;
                if capacity.payload.routes.contains(route) {
                    let mut routes = capacity.payload.routes.clone();
                    routes.remove(route);
                    writes.push(capacity.write(routes)?);
                }
            }
            #[cfg(test)]
            {
                let gate = lock(&self.hooks.transition_gate).take();
                if let Some((reached, barrier)) = gate {
                    if let Some(reached) = reached {
                        let _ = reached.send(());
                    }
                    barrier.wait().await;
                }
            }
            let owner_index = writes.len();
            writes.push(match (before, after) {
                (None, Some(payload)) => AtomicWrite::Create {
                    object_type: OWNER_OBJECT_TYPE.to_string(),
                    id: owner_object_id(route),
                    name: route.to_string(),
                    workspace: String::new(),
                    payload: encode(payload)?,
                },
                (Some(record), Some(payload)) => AtomicWrite::Update {
                    object_type: OWNER_OBJECT_TYPE.to_string(),
                    id: owner_object_id(route),
                    payload: encode(payload)?,
                    expected_version: record.resource_version,
                },
                (Some(record), None) => AtomicWrite::Delete {
                    object_type: OWNER_OBJECT_TYPE.to_string(),
                    id: owner_object_id(route),
                    expected_version: record.resource_version,
                },
                (None, None) => return Ok(Transition::Applied(None)),
            });
            match self.store.write_atomically(&writes).await {
                Ok(results) => {
                    return Ok(Transition::Applied(after.map(|payload| {
                        Box::new(OwnerRecord {
                            payload: payload.clone(),
                            resource_version: results[owner_index]
                                .as_ref()
                                .map_or(0, |written| written.resource_version),
                        })
                    })));
                }
                Err(
                    PersistenceError::Conflict { .. } | PersistenceError::UniqueViolation { .. },
                ) => {
                    let current = self
                        .store
                        .get(OWNER_OBJECT_TYPE, &owner_object_id(route))
                        .await?
                        .as_ref()
                        .and_then(decode_owner);
                    let unchanged = match (before, &current) {
                        (None, None) => true,
                        (Some(before), Some(current)) => {
                            current.resource_version == before.resource_version
                        }
                        _ => false,
                    };
                    if !unchanged {
                        return Ok(Transition::OwnerChanged);
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Err(PersistenceError::Conflict {
            current_resource_version: None,
        })
    }

    /// What an owner change did to `route`'s record.
    async fn reconciled(
        &self,
        route: &str,
        transition: Transition,
    ) -> Result<Reconciled, PersistenceError> {
        match transition {
            Transition::Applied(Some(record)) => Ok(Reconciled::Changed(record)),
            Transition::Applied(None) => Ok(Reconciled::Removed),
            Transition::Full => Ok(Reconciled::Unchanged),
            Transition::OwnerChanged => self.reload(route).await,
        }
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
        let charges = charges_of(
            &self
                .capacities()
                .await
                .map_err(|error| format!("read supervisor pool capacity: {error}"))?,
        );
        let ring = ring_of(&members);
        let targets = candidates(
            &ring,
            &members,
            &assignment.sandbox_id,
            &assignment.route,
            &charges,
            None,
        );
        let no_room = || {
            "no shared supervisor replica is available with room for another sandbox".to_string()
        };
        if targets.is_empty() {
            return Err(no_room());
        }
        self.record_assignment(assignment).await?;
        let mut placed = None;
        for target in targets {
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
            match self
                .transition(&assignment.route, None, Some(&payload))
                .await
                .map_err(|error| format!("record supervisor instance owner: {error}"))?
            {
                Transition::Applied(record) => {
                    placed = record.map(|record| *record);
                    break;
                }
                Transition::Full => {}
                // A retried launch keeps the owner it already recorded.
                Transition::OwnerChanged => match self
                    .reload(&assignment.route)
                    .await
                    .map_err(|error| format!("read supervisor instance owner: {error}"))?
                {
                    Reconciled::Changed(existing)
                        if existing.payload.generation == assignment.generation =>
                    {
                        placed = Some(*existing);
                        break;
                    }
                    _ => {
                        return Err(
                            "the sandbox instance route is owned by another generation".to_string()
                        );
                    }
                },
            }
        }
        let record = placed.ok_or_else(no_room)?;
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

    /// One reconciliation pass: remove withdrawn instances; then place, take
    /// over, complete, and clean up from the records; record what served
    /// owners report; load the material served members need; and publish the
    /// resulting view.
    pub async fn reconcile_once(&self) -> Result<(), PersistenceError> {
        #[cfg(test)]
        {
            let gate = lock(&self.hooks.reconcile_gate).take();
            if let Some((paused, resume)) = gate {
                let _ = paused.send(());
                let _ = resume.await;
            }
        }
        self.remove_withdrawn().await;
        let members = self.live_members().await?;
        let ring = ring_of(&members);
        let listed_at = tokio::time::Instant::now();
        // Listed before the owners, so a report row of a term newer than the
        // route's listed owner cannot exist among them, and cleanup, which
        // removes only rows of older terms or of routes without an owner,
        // never removes a row a new term wrote meanwhile.
        let report_rows = self.report_rows().await?;
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
        let mut desired = records
            .into_iter()
            .filter(|(route, record)| {
                record.payload.phase == RecordPhase::Published && !withdrawals.contains(route)
            })
            .collect::<BTreeMap<_, _>>();
        self.confirm_absences(&mut owners, &mut desired, &withdrawals)
            .await?;
        let mut charges = charges_of(&self.capacities().await?);
        let stopping = self.controller.stopping_routes();
        self.forget_owned(&desired, &owners);
        for (route, instance) in &desired {
            if stopping.contains(route) {
                continue;
            }
            let takeovers_allowed = tokio::time::Instant::now() >= self.takeovers_from;
            let outcome = match owners.get(route) {
                None if takeovers_allowed => {
                    self.place_unowned(route, &instance.payload, &ring, &members, &charges)
                        .await
                }
                // An intent recorded by any replica, including one that
                // crashed before granting it.
                Some(record) if record.payload.phase == OwnerPhase::Granting => {
                    self.complete_takeover(record.clone()).await
                }
                Some(record) if takeovers_allowed && !owner_alive(&record.payload, &members) => {
                    self.take_over(record, &ring, &members, &charges).await
                }
                // A live owner keeps its instance; nothing is placed or
                // taken over during the startup grace.
                _ => Ok(Reconciled::Unchanged),
            };
            match outcome {
                Ok(Reconciled::Changed(record)) => {
                    recharge(
                        &mut charges,
                        route,
                        owners
                            .get(route)
                            .map(|previous| previous.payload.member_id.as_str()),
                        Some(&record.payload.member_id),
                    );
                    owners.insert(route.clone(), *record);
                }
                Ok(Reconciled::Removed) => {
                    let previous = owners.remove(route);
                    recharge(
                        &mut charges,
                        route,
                        previous
                            .as_ref()
                            .map(|previous| previous.payload.member_id.as_str()),
                        None,
                    );
                }
                Ok(Reconciled::Unchanged) => {}
                Err(error) => {
                    warn!(route, %error, "supervisor pool could not reconcile an instance owner");
                }
            }
        }
        self.remove_withdrawn_owners(&desired, &mut owners).await;
        self.sweep_ended_instances(&desired).await;
        self.record_reports(&owners, &report_rows).await;
        self.remove_stale_reports(&owners, &report_rows).await;
        let reports = reports_of_owners(&owners, &report_rows);
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
                // Its report rows are removed with the other rows of routes
                // without an owner.
                Ok(Reconciled::Removed) => {
                    owners.remove(&record.payload.route);
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

    /// Every report row, by object id.
    async fn report_rows(&self) -> Result<ReportRows, PersistenceError> {
        Ok(self
            .list_all(REPORT_OBJECT_TYPE)
            .await?
            .iter()
            .filter_map(|record| {
                decode_report(record)
                    .map(|payload| (record.id.clone(), (payload, record.resource_version)))
            })
            .collect())
    }

    /// Reports of the members this replica serves.
    fn served_reports(&self) -> Vec<MemberReport> {
        #[cfg(test)]
        {
            let reports = lock(&self.hooks.served_reports).clone();
            if let Some(reports) = reports {
                return reports;
            }
        }
        self.controller.member_reports()
    }

    /// Record what the owners this replica serves report of their instances,
    /// each only if the term its stream acknowledged is the granted term this
    /// pass's owner records show, so a status from an earlier term is never
    /// relabelled as a later one, even from the same process. A row is
    /// rewritten whenever it differs from the report, conditioned on the row
    /// as listed, so a row another writer replaced or removed is repaired by
    /// the next pass; a row a newer stream of the same term wrote is kept.
    async fn record_reports(&self, owners: &BTreeMap<String, OwnerRecord>, rows: &ReportRows) {
        let reports = self.served_reports();
        #[cfg(test)]
        {
            let gate = lock(&self.hooks.report_gate).take();
            if let Some((paused, resume)) = gate {
                let _ = paused.send(());
                let _ = resume.await;
            }
        }
        for report in reports {
            let route = report.status.route.clone();
            if !owners.get(&route).is_some_and(|owner| {
                owner.payload.phase == OwnerPhase::Granted
                    && owner.payload.member_id == report.member_id
                    && owner.payload.process_id == report.process_id
                    && owner.payload.auth_epoch == report.auth_epoch
            }) {
                continue;
            }
            let auth_epoch = report.auth_epoch;
            let payload = ReportPayload {
                route: route.clone(),
                member_id: report.member_id,
                process_id: report.process_id,
                auth_epoch,
                sandbox_id: report.status.sandbox_id,
                phase: report.status.phase,
                ready: report.status.ready,
                exit_code: report.status.exit_code,
                connected_at_ms: report.connected_at_ms,
            };
            let id = report_object_id(&route, auth_epoch);
            let listed = rows.get(&id);
            if listed.is_some_and(|(current, _)| {
                current == &payload || current.connected_at_ms > payload.connected_at_ms
            }) {
                continue;
            }
            let Ok(bytes) = serde_json::to_vec(&payload) else {
                continue;
            };
            let condition = listed.map_or(WriteCondition::MustCreate, |(_, version)| {
                WriteCondition::MatchResourceVersion(*version)
            });
            match self
                .store
                .put_if(
                    REPORT_OBJECT_TYPE,
                    &id,
                    &report_object_name(&route, auth_epoch),
                    "",
                    &bytes,
                    None,
                    condition,
                )
                .await
            {
                // Another writer changed the row since it was listed; the
                // next pass compares against what it wrote.
                Ok(_)
                | Err(
                    PersistenceError::Conflict { .. } | PersistenceError::UniqueViolation { .. },
                ) => {}
                Err(error) => {
                    warn!(route, %error, "could not record a supervisor pool instance report");
                }
            }
        }
    }

    /// Remove listed report rows of terms older than their route's owner, or
    /// of routes without one; a bounded number per pass, each only as listed.
    async fn remove_stale_reports(
        &self,
        owners: &BTreeMap<String, OwnerRecord>,
        rows: &ReportRows,
    ) {
        let stale = rows
            .iter()
            .filter(|(_, (report, _))| {
                owners
                    .get(&report.route)
                    .is_none_or(|owner| owner.payload.auth_epoch > report.auth_epoch)
            })
            .take(CLEANUP_PER_PASS);
        for (id, (_, version)) in stale {
            let _ = self.store.delete_if(REPORT_OBJECT_TYPE, id, *version).await;
        }
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
        charges: &BTreeMap<String, BTreeSet<String>>,
    ) -> Result<Reconciled, PersistenceError> {
        let unowned_for = lock(&self.unowned_since)
            .get(route)
            .map(tokio::time::Instant::elapsed);
        if unowned_for.is_none_or(|elapsed| elapsed < self.unowned_grace) {
            return Ok(Reconciled::Unchanged);
        }
        let targets = candidates(ring, members, &assignment.sandbox_id, route, charges, None);
        if targets.is_empty() {
            return Ok(Reconciled::Unchanged);
        }
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
        for target in targets {
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
            match self.transition(route, None, Some(&intent)).await? {
                Transition::Applied(Some(record)) => return self.complete_takeover(*record).await,
                Transition::Full => {}
                // A launch or another replica recorded it first.
                transition => return self.reconciled(route, transition).await,
            }
        }
        Ok(Reconciled::Unchanged)
    }

    /// Move an instance whose owner failed or left to the ring's choice.
    async fn take_over(
        &self,
        record: &OwnerRecord,
        ring: &GatewayRing,
        members: &[LiveMember],
        charges: &BTreeMap<String, BTreeSet<String>>,
    ) -> Result<Reconciled, PersistenceError> {
        // A member whose process restarted re-adopts its routes first: their
        // slots are already charged to it, so this needs no free capacity.
        let targets = candidates(
            ring,
            members,
            &record.payload.sandbox_id,
            &record.payload.route,
            charges,
            Some(&record.payload.member_id),
        );
        for target in targets {
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
                .transition(&record.payload.route, Some(record), Some(&intent))
                .await?
            {
                Transition::Applied(Some(intent)) => {
                    info!(
                        sandbox_id = %intent.payload.sandbox_id,
                        route = %intent.payload.route,
                        from = %record.payload.member_id,
                        to = %intent.payload.member_id,
                        term = intent.payload.auth_epoch,
                        cause = %takeover_cause(&record.payload, members),
                        "taking over a shared sandbox instance from a failed supervisor"
                    );
                    return self.complete_takeover(*intent).await;
                }
                Transition::Full => {}
                // Another replica moved it first.
                transition => return self.reconciled(&record.payload.route, transition).await,
            }
        }
        Ok(Reconciled::Unchanged)
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
                let transition = self
                    .transition(&record.payload.route, Some(&record), Some(&granted))
                    .await?;
                self.reconciled(&record.payload.route, transition).await
            }
            TakeoverIdentity::Refused(reason) => {
                info!(
                    sandbox_id = %record.payload.sandbox_id,
                    route = %record.payload.route,
                    reason,
                    "cancelled a shared sandbox instance takeover"
                );
                let transition = self
                    .transition(&record.payload.route, Some(&record), None)
                    .await?;
                self.reconciled(&record.payload.route, transition).await
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
        let transition = self
            .transition(&record.payload.route, Some(record), None)
            .await?;
        self.reconciled(&record.payload.route, transition).await
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
    use crate::persistence::test_postgres::TestSchema;
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
            Self::with_store(crate::persistence::test_store().await)
        }

        /// A fixture over `store`, such as one connected to `PostgreSQL`.
        fn with_store(store: Store) -> Self {
            let material = openshell_bootstrap::jwt::generate_jwt_key().expect("jwt key");
            let store = Arc::new(store);
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

        /// A replica whose member records expire after `ttl` and are
        /// refreshed every `refresh`.
        fn timed_replica(
            &self,
            replica_id: &str,
            ttl: Duration,
            refresh: Duration,
        ) -> Arc<SupervisorPool> {
            let mut pool = self.replica(replica_id);
            let unique = Arc::get_mut(&mut pool).expect("unique");
            unique.member_ttl = ttl;
            unique.member_refresh = refresh;
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

        async fn remove_owner_record(&self, route: &str) {
            self.store
                .delete(OWNER_OBJECT_TYPE, &owner_object_id(route))
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

        /// A published instance record written directly, as another replica
        /// would.
        async fn publish(&self, route: &str, sandbox_id: &str, generation: &str) {
            let payload = AssignmentPayload {
                route: route.to_string(),
                sandbox_id: sandbox_id.to_string(),
                generation: generation.to_string(),
                workspace: "default".to_string(),
                phase: RecordPhase::Published,
                writer: Uuid::new_v4().to_string(),
                material_handle: b"handle".to_vec(),
            };
            self.store
                .put_if(
                    ASSIGNMENT_OBJECT_TYPE,
                    &assignment_object_id(route, &payload.writer),
                    route,
                    "",
                    &serde_json::to_vec(&payload).unwrap(),
                    None,
                    WriteCondition::MustCreate,
                )
                .await
                .unwrap();
        }

        /// The launch-term owner of `route`, written directly.
        async fn own(&self, route: &str, sandbox_id: &str, member: &str, process: &str) {
            self.replica("owner-writer")
                .write_owner(
                    &OwnerPayload {
                        route: route.to_string(),
                        sandbox_id: sandbox_id.to_string(),
                        generation: "generation-1".to_string(),
                        member_id: member.to_string(),
                        process_id: process.to_string(),
                        auth_epoch: 1,
                        supervisor_instance_id: None,
                        gateway_token_id: None,
                        phase: OwnerPhase::Granted,
                        previous_member_id: None,
                    },
                    WriteCondition::MustCreate,
                )
                .await
                .unwrap();
        }

        /// `count` running instances owned by `member`'s `process`, each
        /// with its sandbox and published record.
        async fn fill(&self, member: &str, process: &str, count: usize) -> Vec<String> {
            let mut routes = Vec::with_capacity(count);
            for index in 0..count {
                let route = format!("rt-{member}-{index:05}");
                let sandbox = format!("sandbox-{member}-{index}");
                self.sandbox(&sandbox, "generation-1", SandboxPhase::Ready)
                    .await;
                self.publish(&route, &sandbox, "generation-1").await;
                self.own(&route, &sandbox, member, process).await;
                routes.push(route);
            }
            routes
        }

        /// Write `payload` as its term's report row, as any writer could.
        async fn write_report(&self, payload: ReportPayload) {
            self.store
                .put_if(
                    REPORT_OBJECT_TYPE,
                    &report_object_id(&payload.route, payload.auth_epoch),
                    &report_object_name(&payload.route, payload.auth_epoch),
                    "",
                    &serde_json::to_vec(&payload).unwrap(),
                    None,
                    WriteCondition::Unconditional,
                )
                .await
                .unwrap();
        }

        /// Every report row of `route`, by term.
        async fn report_rows(&self, route: &str) -> BTreeMap<u64, ReportPayload> {
            self.replica("report-reader")
                .report_rows()
                .await
                .unwrap()
                .into_values()
                .map(|(payload, _)| (payload.auth_epoch, payload))
                .filter(|(_, payload)| payload.route == route)
                .collect()
        }

        /// Routes `member` is charged for.
        async fn charged(&self, member: &str) -> BTreeSet<String> {
            self.replica("capacity-reader")
                .capacity(member)
                .await
                .unwrap()
                .payload
                .routes
        }

        async fn withdraw_record(&self, route: &str) {
            let record = self.instance(route).await.unwrap();
            self.store
                .delete(
                    ASSIGNMENT_OBJECT_TYPE,
                    &assignment_object_id(route, &record.payload.writer),
                )
                .await
                .unwrap();
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
            connected_at_ms: 0,
        };
        let record = |payload: ReportPayload| fixture.write_report(payload);
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

    /// One more instance than a listing page, the live one listed last and
    /// owned by `m1`; returns the routes and a replica that places nothing,
    /// whose first pass has loaded the view.
    async fn two_page_pool(fixture: &Fixture) -> (Vec<String>, Arc<SupervisorPool>) {
        fixture.member("m1", "p1", false).await;
        let count = LIST_LIMIT as usize + 1;
        let routes = (0..count)
            .map(|index| format!("rt-route-{index:05}"))
            .collect::<Vec<_>>();
        for (index, route) in routes.iter().enumerate() {
            let sandbox = format!("sandbox-{index}");
            fixture
                .sandbox(&sandbox, "generation-1", SandboxPhase::Ready)
                .await;
            fixture.publish(route, &sandbox, "generation-1").await;
        }
        fixture
            .own(
                &routes[count - 1],
                &format!("sandbox-{}", count - 1),
                "m1",
                "p1",
            )
            .await;
        let pool = fixture.starting_replica("gw-a");
        pool.reconcile_once().await.unwrap();
        assert!(
            pool.controller
                .pool_view()
                .unwrap()
                .desired
                .contains(&routes[count - 1])
        );
        (routes, pool)
    }

    #[tokio::test]
    async fn a_row_removed_between_listing_pages_shifts_nothing_out() {
        let fixture = Fixture::new().await;
        let (routes, pool) = two_page_pool(&fixture).await;
        let live = routes.last().unwrap();
        // Another replica withdraws an instance page one already returned.
        let (paused, resume) = pool.pause_listing_after_first_page(ASSIGNMENT_OBJECT_TYPE);
        let listing = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.list_all(ASSIGNMENT_OBJECT_TYPE).await })
        };
        paused.await.unwrap();
        fixture.withdraw_record(&routes[0]).await;
        resume.send(()).unwrap();
        // Page two starts after page one's last row instead of skipping one.
        let listed = listing.await.unwrap().unwrap();
        assert_eq!(listed.len(), routes.len());
        assert!(listed.iter().any(|record| record.name == *live));
    }

    #[tokio::test]
    async fn a_row_removed_mid_pass_never_stops_a_live_route() {
        let fixture = Fixture::new().await;
        let (routes, pool) = two_page_pool(&fixture).await;
        let live = routes.last().unwrap();
        let (paused, resume) = pool.pause_listing_after_first_page(ASSIGNMENT_OBJECT_TYPE);
        let pass = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.reconcile_once().await })
        };
        paused.await.unwrap();
        fixture.withdraw_record(&routes[0]).await;
        resume.send(()).unwrap();
        pass.await.unwrap().unwrap();
        // The live route stays desired and owned, so its owner is never told
        // to stop it; the withdrawn one is no longer desired.
        let view = pool.controller.pool_view().unwrap();
        assert!(view.desired.contains(live));
        assert_eq!(view.owners[live.as_str()].member_id, "m1");
        assert!(!pool.controller.stopping_routes().contains(live));
        pool.reconcile_once().await.unwrap();
        assert!(
            !pool
                .controller
                .pool_view()
                .unwrap()
                .desired
                .contains(&routes[0])
        );
    }

    #[tokio::test]
    async fn a_route_a_listing_misses_is_confirmed_before_it_is_stopped() {
        let fixture = Fixture::new().await;
        fixture.member("m1", "p1", false).await;
        for (route, sandbox) in [
            ("rt-route-live", "sandbox-a"),
            ("rt-route-gone", "sandbox-b"),
        ] {
            fixture
                .sandbox(sandbox, "generation-1", SandboxPhase::Ready)
                .await;
            fixture.publish(route, sandbox, "generation-1").await;
            fixture.own(route, sandbox, "m1", "p1").await;
        }
        let pool = fixture.starting_replica("gw-a");
        pool.reconcile_once().await.unwrap();
        // A listing misses a live route's instance and owner rows; a real
        // withdrawal removes the other's instance record.
        pool.omit_from_listings("rt-route-live");
        fixture.withdraw_record("rt-route-gone").await;
        pool.reconcile_once().await.unwrap();
        let view = pool.controller.pool_view().unwrap();
        assert!(view.desired.contains("rt-route-live"));
        assert!(view.owners.contains_key("rt-route-live"));
        assert!(!pool.controller.stopping_routes().contains("rt-route-live"));
        // The confirmed withdrawal still stops its instance.
        assert!(!view.desired.contains("rt-route-gone"));
        assert!(pool.controller.stopping_routes().contains("rt-route-gone"));
    }

    #[tokio::test]
    async fn the_last_slot_of_a_member_is_admitted_once_across_replicas() {
        the_last_slot_of_a_member_is_admitted_once_across_replicas_on(&Fixture::new().await).await;
    }

    #[tokio::test]
    #[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
    async fn postgres_the_last_slot_of_a_member_is_admitted_once_across_replicas() {
        let schema = TestSchema::create("supervisor_pool").await;
        the_last_slot_of_a_member_is_admitted_once_across_replicas_on(&Fixture::with_store(
            schema.connect_store().await,
        ))
        .await;
        schema.drop_schema().await;
    }

    async fn the_last_slot_of_a_member_is_admitted_once_across_replicas_on(fixture: &Fixture) {
        fixture.member("m1", "p1", false).await;
        fixture.fill("m1", "p1", MAX_ASSIGNED_INSTANCES - 1).await;
        for sandbox in ["sandbox-x", "sandbox-y"] {
            fixture
                .sandbox(sandbox, "generation-1", SandboxPhase::Ready)
                .await;
        }
        // Both launches read 255 charged routes before either writes.
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let (first, second) = (fixture.replica("gw-a"), fixture.replica("gw-b"));
        first.pause_next_transition(barrier.clone());
        second.pause_next_transition(barrier);
        let (x, y) = tokio::join!(
            first.place_launch(launch("rt-route-x000", "sandbox-x", "generation-1")),
            second.place_launch(launch("rt-route-y000", "sandbox-y", "generation-1")),
        );
        assert_eq!(
            usize::from(x.is_ok()) + usize::from(y.is_ok()),
            1,
            "{x:?} {y:?}"
        );
        assert_eq!(fixture.charged("m1").await.len(), MAX_ASSIGNED_INSTANCES);
        let owned = [
            fixture.owner("rt-route-x000").await,
            fixture.owner("rt-route-y000").await,
        ];
        assert_eq!(owned.iter().flatten().count(), 1);
    }

    #[tokio::test]
    async fn a_takeover_and_a_launch_compete_for_the_last_slot() {
        a_takeover_and_a_launch_compete_for_the_last_slot_on(&Fixture::new().await).await;
    }

    #[tokio::test]
    #[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
    async fn postgres_a_takeover_and_a_launch_compete_for_the_last_slot() {
        let schema = TestSchema::create("supervisor_pool").await;
        a_takeover_and_a_launch_compete_for_the_last_slot_on(&Fixture::with_store(
            schema.connect_store().await,
        ))
        .await;
        schema.drop_schema().await;
    }

    async fn a_takeover_and_a_launch_compete_for_the_last_slot_on(fixture: &Fixture) {
        fixture.member("m1", "p1", false).await;
        fixture.member("m2", "p2", false).await;
        let orphaned = fixture.fill("m1", "p1", 1).await.remove(0);
        fixture.fill("m2", "p2", MAX_ASSIGNED_INSTANCES - 1).await;
        fixture
            .sandbox("sandbox-new", "generation-1", SandboxPhase::Ready)
            .await;
        // m1 fails; its route and a new launch both need m2's last slot.
        fixture.remove_member("m1").await;
        let (taking, launching) = (fixture.replica("gw-a"), fixture.replica("gw-b"));
        let members = taking.live_members().await.unwrap();
        let charges = charges_of(&taking.capacities().await.unwrap());
        let record = taking.reload_owner(&orphaned).await;
        let ring = ring_of(&members);
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        taking.pause_next_transition(barrier.clone());
        launching.pause_next_transition(barrier);
        let (taken, launched) = tokio::join!(
            taking.take_over(&record, &ring, &members, &charges),
            launching.place_launch(launch("rt-route-new0", "sandbox-new", "generation-1")),
        );
        taken.unwrap();
        let moved = fixture.owner(&orphaned).await.unwrap().member_id == "m2";
        assert_ne!(moved, launched.is_ok(), "exactly one gets the slot");
        assert_eq!(fixture.charged("m2").await.len(), MAX_ASSIGNED_INSTANCES);
        // A takeover that lost the slot leaves the route charged to m1.
        assert_eq!(fixture.charged("m1").await.contains(&orphaned), !moved);
    }

    #[tokio::test]
    async fn a_stalled_admission_cannot_take_a_slot_consumed_meanwhile() {
        a_stalled_admission_cannot_take_a_slot_consumed_meanwhile_on(&Fixture::new().await).await;
    }

    #[tokio::test]
    #[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
    async fn postgres_a_stalled_admission_cannot_take_a_slot_consumed_meanwhile() {
        let schema = TestSchema::create("supervisor_pool").await;
        a_stalled_admission_cannot_take_a_slot_consumed_meanwhile_on(&Fixture::with_store(
            schema.connect_store().await,
        ))
        .await;
        schema.drop_schema().await;
    }

    async fn a_stalled_admission_cannot_take_a_slot_consumed_meanwhile_on(fixture: &Fixture) {
        fixture.member("m1", "p1", false).await;
        fixture.fill("m1", "p1", MAX_ASSIGNED_INSTANCES - 1).await;
        for sandbox in ["sandbox-x", "sandbox-y"] {
            fixture
                .sandbox(sandbox, "generation-1", SandboxPhase::Ready)
                .await;
        }
        // One launch stalls after reading 255 charged routes; another
        // admits the last slot meanwhile.
        let stalled = fixture.replica("gw-a");
        let release = Arc::new(tokio::sync::Barrier::new(2));
        let reached = stalled.pause_next_transition_reached(release.clone());
        let stalled_launch = {
            let stalled = stalled.clone();
            tokio::spawn(async move {
                stalled
                    .place_launch(launch("rt-route-x000", "sandbox-x", "generation-1"))
                    .await
            })
        };
        reached.await.unwrap();
        fixture
            .replica("gw-b")
            .place_launch(launch("rt-route-y000", "sandbox-y", "generation-1"))
            .await
            .unwrap();
        release.wait().await;
        assert!(stalled_launch.await.unwrap().is_err());
        assert!(fixture.owner("rt-route-x000").await.is_none());
        assert_eq!(fixture.charged("m1").await.len(), MAX_ASSIGNED_INSTANCES);
    }

    #[tokio::test]
    async fn a_failed_contender_for_an_owned_route_charges_nothing() {
        a_failed_contender_for_an_owned_route_charges_nothing_on(&Fixture::new().await).await;
    }

    #[tokio::test]
    #[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
    async fn postgres_a_failed_contender_for_an_owned_route_charges_nothing() {
        let schema = TestSchema::create("supervisor_pool").await;
        a_failed_contender_for_an_owned_route_charges_nothing_on(&Fixture::with_store(
            schema.connect_store().await,
        ))
        .await;
        schema.drop_schema().await;
    }

    async fn a_failed_contender_for_an_owned_route_charges_nothing_on(fixture: &Fixture) {
        fixture.member("m1", "p1", false).await;
        fixture.member("m2", "p2", false).await;
        let route = fixture.fill("m1", "p1", 1).await.remove(0);
        let contender = fixture.replica("gw-b");
        let mut payload = fixture.owner(&route).await.unwrap();
        payload.member_id = "m2".to_string();
        payload.process_id = "p2".to_string();
        assert!(matches!(
            contender
                .transition(&route, None, Some(&payload))
                .await
                .unwrap(),
            Transition::OwnerChanged
        ));
        assert!(fixture.charged("m2").await.is_empty());
        assert!(fixture.charged("m1").await.contains(&route));
        assert_eq!(fixture.owner(&route).await.unwrap().member_id, "m1");
    }

    #[tokio::test]
    async fn a_restarted_member_of_a_full_pool_re_adopts_its_routes_in_place() {
        a_restarted_member_of_a_full_pool_re_adopts_its_routes_in_place_on(&Fixture::new().await)
            .await;
    }

    #[tokio::test]
    #[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
    async fn postgres_a_restarted_member_of_a_full_pool_re_adopts_its_routes_in_place() {
        let schema = TestSchema::create("supervisor_pool").await;
        a_restarted_member_of_a_full_pool_re_adopts_its_routes_in_place_on(&Fixture::with_store(
            schema.connect_store().await,
        ))
        .await;
        schema.drop_schema().await;
    }

    async fn a_restarted_member_of_a_full_pool_re_adopts_its_routes_in_place_on(fixture: &Fixture) {
        fixture.member("m1", "p1", false).await;
        fixture.member("m2", "p2", false).await;
        let routes = fixture.fill("m1", "p1", MAX_ASSIGNED_INSTANCES).await;
        fixture.fill("m2", "p2", MAX_ASSIGNED_INSTANCES).await;
        fixture
            .sandbox("sandbox-new", "generation-1", SandboxPhase::Ready)
            .await;
        // m1's supervisor restarts inside its Pod: same member, new process.
        fixture.member("m1", "p1-restarted", false).await;
        let pool = fixture.replica("gw-a");
        let launching = fixture.replica("gw-b");
        let (pass, launched) = tokio::join!(
            pool.reconcile_once(),
            launching.place_launch(launch("rt-route-new0", "sandbox-new", "generation-1")),
        );
        pass.unwrap();
        // Every route is re-adopted by the new process at the next term,
        // without needing a free slot, and the launch found none.
        for route in &routes {
            let owner = fixture.owner(route).await.unwrap();
            assert_eq!(
                (
                    owner.member_id.as_str(),
                    owner.process_id.as_str(),
                    owner.auth_epoch,
                    owner.phase
                ),
                ("m1", "p1-restarted", 2, OwnerPhase::Granted),
                "{route}"
            );
        }
        assert!(launched.is_err());
        assert!(fixture.owner("rt-route-new0").await.is_none());
        assert_eq!(fixture.charged("m1").await.len(), MAX_ASSIGNED_INSTANCES);
        assert_eq!(fixture.charged("m2").await.len(), MAX_ASSIGNED_INSTANCES);
    }

    /// A member stream accepted at `connected_at_ms`.
    fn stream(member_id: &str, process_id: &str, connected_at_ms: i64) -> ConnectedMember {
        ConnectedMember {
            member_id: member_id.to_string(),
            member_uid: format!("uid-{member_id}"),
            process_id: process_id.to_string(),
            runtime_address: "10.0.0.1:5500".to_string(),
            leaving: false,
            connected_at_ms,
        }
    }

    /// Short membership timings, so expiry happens within a test.
    const TEST_TTL: Duration = Duration::from_millis(600);
    const TEST_REFRESH: Duration = Duration::from_millis(100);

    /// Start `pool`; the returned sender stops it.
    fn run(pool: &Arc<SupervisorPool>) -> tokio::sync::watch::Sender<bool> {
        let (stop, stopped) = tokio::sync::watch::channel(false);
        pool.start(stopped);
        stop
    }

    async fn member_record(fixture: &Fixture, member_id: &str) -> MemberPayload {
        let record = fixture
            .store
            .get(MEMBER_OBJECT_TYPE, &member_object_id(member_id))
            .await
            .unwrap()
            .unwrap();
        serde_json::from_slice(&record.payload).unwrap()
    }

    #[tokio::test]
    async fn a_stalled_pass_never_lets_a_served_member_expire() {
        let fixture = Fixture::new().await;
        let serving = fixture.timed_replica("gw-a", TEST_TTL, TEST_REFRESH);
        serving.serve(vec![stream("m1", "p1", now_ms())]);
        let (paused, resume) = serving.pause_next_pass();
        let stop = run(&serving);
        paused.await.unwrap();
        // The pass stays stalled for several TTLs.
        tokio::time::sleep(TEST_TTL * 4).await;
        let observer = fixture.timed_replica("gw-b", TEST_TTL, TEST_REFRESH);
        let live = observer.live_members().await.unwrap();
        assert_eq!(
            live.iter()
                .map(|member| member.member_id.as_str())
                .collect::<Vec<_>>(),
            ["m1"]
        );
        let _ = resume.send(());
        stop.send_replace(true);
    }

    #[tokio::test]
    async fn a_member_that_reconnects_past_a_frozen_replica_keeps_its_instances() {
        let fixture = Fixture::new().await;
        let route = fixture.fill("m1", "p1", 1).await.remove(0);
        let first_stream = now_ms();
        let frozen = fixture.timed_replica("gw-a", TEST_TTL, TEST_REFRESH);
        frozen.serve(vec![stream("m1", "p1", first_stream)]);
        let peer = fixture.timed_replica("gw-b", TEST_TTL, TEST_REFRESH);
        peer.serve(vec![stream("m2", "p2", first_stream)]);
        let stop_frozen = run(&frozen);
        let stop_peer = run(&peer);
        tokio::time::sleep(TEST_REFRESH * 2).await;
        // gw-a freezes; m1 notices and reconnects through gw-b well within
        // the TTL, keeping its process.
        stop_frozen.send_replace(true);
        tokio::time::sleep(TEST_REFRESH * 2).await;
        peer.serve(vec![
            stream("m1", "p1", first_stream + 1_000),
            stream("m2", "p2", first_stream),
        ]);
        // Any replica reconciling meanwhile leaves m1's instance alone.
        let judge = fixture.timed_replica("gw-c", TEST_TTL, TEST_REFRESH);
        let until = tokio::time::Instant::now() + TEST_TTL * 4;
        while tokio::time::Instant::now() < until {
            judge.reconcile_once().await.unwrap();
            let owner = fixture.owner(&route).await.unwrap();
            assert_eq!(
                (owner.member_id.as_str(), owner.auth_epoch),
                ("m1", 1),
                "m1 kept its instance"
            );
            tokio::time::sleep(TEST_REFRESH).await;
        }
        // gw-a thaws with the member's stale stream still open: its refresh
        // leaves the newer stream's record alone.
        frozen.refresh_members().await;
        let record = member_record(&fixture, "m1").await;
        assert_eq!(
            (record.gateway_replica.as_str(), record.connected_at_ms),
            ("gw-b", first_stream + 1_000)
        );
        stop_peer.send_replace(true);
    }

    #[tokio::test]
    async fn a_member_no_replica_serves_expires_and_its_instances_move() {
        let fixture = Fixture::new().await;
        let route = fixture.fill("m1", "p1", 1).await.remove(0);
        let lost = fixture.timed_replica("gw-a", TEST_TTL, TEST_REFRESH);
        lost.serve(vec![stream("m1", "p1", now_ms())]);
        let peer = fixture.timed_replica("gw-b", TEST_TTL, TEST_REFRESH);
        peer.serve(vec![stream("m2", "p2", now_ms())]);
        let stop_lost = run(&lost);
        let stop_peer = run(&peer);
        tokio::time::sleep(TEST_REFRESH * 2).await;
        // m1 is cut off from every replica.
        lost.serve(Vec::new());
        let judge = fixture.timed_replica("gw-c", TEST_TTL, TEST_REFRESH);
        judge.reconcile_once().await.unwrap();
        assert_eq!(fixture.owner(&route).await.unwrap().member_id, "m1");
        tokio::time::sleep(TEST_TTL + TEST_REFRESH * 2).await;
        judge.reconcile_once().await.unwrap();
        let owner = fixture.owner(&route).await.unwrap();
        assert_eq!((owner.member_id.as_str(), owner.auth_epoch), ("m2", 2));
        stop_lost.send_replace(true);
        stop_peer.send_replace(true);
    }

    /// What `member`'s `process` reported of `route` under `auth_epoch`.
    fn member_report(
        (member_id, process_id, auth_epoch): (&str, &str, u64),
        route: &str,
        sandbox_id: &str,
        (phase, ready): (i32, bool),
        connected_at_ms: i64,
    ) -> MemberReport {
        MemberReport {
            member_id: member_id.to_string(),
            process_id: process_id.to_string(),
            auth_epoch,
            connected_at_ms,
            status: SandboxInstanceStatus {
                route: route.to_string(),
                sandbox_id: sandbox_id.to_string(),
                phase,
                ready,
                exit_code: 0,
                error: String::new(),
            },
        }
    }

    /// Grant `route` to `member`'s `process` at the next term, as a
    /// completed takeover would.
    async fn grant_next_term(fixture: &Fixture, route: &str, member_id: &str, process_id: &str) {
        let mover = fixture.replica("mover");
        let record = mover.reload_owner(route).await;
        let next = OwnerPayload {
            member_id: member_id.to_string(),
            process_id: process_id.to_string(),
            auth_epoch: record.payload.auth_epoch + 1,
            supervisor_instance_id: Some(Uuid::new_v4().to_string()),
            gateway_token_id: Some(Uuid::new_v4().to_string()),
            phase: OwnerPhase::Granted,
            previous_member_id: Some(record.payload.member_id.clone()),
            ..record.payload.clone()
        };
        assert!(matches!(
            mover
                .transition(route, Some(&record), Some(&next))
                .await
                .unwrap(),
            Transition::Applied(Some(_))
        ));
    }

    /// The status a replica's last pass published for `route`.
    fn published_report(pool: &SupervisorPool, route: &str) -> Option<(i32, bool)> {
        pool.controller
            .pool_view()
            .unwrap()
            .reports
            .get(route)
            .map(|status| (status.phase, status.ready))
    }

    #[tokio::test]
    async fn a_paused_report_of_an_earlier_term_never_hides_the_new_terms() {
        let fixture = Fixture::new().await;
        fixture.member("m1", "p1", false).await;
        fixture.member("m2", "p2", false).await;
        let route = fixture.fill("m1", "p1", 1).await.remove(0);
        let sandbox = fixture.owner(&route).await.unwrap().sandbox_id;
        // The replica serving m1 read m1's term-1 report and stalls before
        // writing it.
        let old = fixture.replica("gw-a");
        old.serve_reports(vec![member_report(
            ("m1", "p1", 1),
            &route,
            &sandbox,
            (2, true),
            1,
        )]);
        let (paused, resume) = old.pause_next_report_recording();
        let stalled = {
            let old = old.clone();
            tokio::spawn(async move { old.reconcile_once().await })
        };
        paused.await.unwrap();
        // m2 takes the route over at term 2 and reports it starting.
        grant_next_term(&fixture, &route, "m2", "p2").await;
        let new = fixture.replica("gw-b");
        new.serve_reports(vec![member_report(
            ("m2", "p2", 2),
            &route,
            &sandbox,
            (1, false),
            1,
        )]);
        new.reconcile_once().await.unwrap();
        // The stalled write lands afterwards.
        let _ = resume.send(());
        stalled.await.unwrap().unwrap();
        let judge = fixture.replica("gw-c");
        judge.reconcile_once().await.unwrap();
        assert_eq!(published_report(&judge, &route), Some((1, false)));
        // The earlier term's row is gone; term 2's row is untouched, and an
        // unchanged report leaves it so.
        let rows = fixture.report_rows(&route).await;
        assert_eq!(rows.keys().copied().collect::<Vec<_>>(), [2]);
        new.reconcile_once().await.unwrap();
        judge.reconcile_once().await.unwrap();
        assert_eq!(published_report(&judge, &route), Some((1, false)));
    }

    #[tokio::test]
    async fn an_unchanged_report_whose_row_was_replaced_or_removed_is_rewritten() {
        let fixture = Fixture::new().await;
        fixture.member("m1", "p1", false).await;
        let route = fixture.fill("m1", "p1", 1).await.remove(0);
        let sandbox = fixture.owner(&route).await.unwrap().sandbox_id;
        let serving = fixture.replica("gw-a");
        serving.serve_reports(vec![member_report(
            ("m1", "p1", 1),
            &route,
            &sandbox,
            (2, true),
            5,
        )]);
        serving.reconcile_once().await.unwrap();
        let written = fixture.report_rows(&route).await.remove(&1).unwrap();
        assert!(written.ready);
        // Another writer replaced the row; the same report repairs it.
        fixture
            .write_report(ReportPayload {
                ready: false,
                connected_at_ms: 0,
                ..written.clone()
            })
            .await;
        serving.reconcile_once().await.unwrap();
        assert_eq!(fixture.report_rows(&route).await.get(&1), Some(&written));
        // So it does after the row was removed.
        fixture
            .store
            .delete(REPORT_OBJECT_TYPE, &report_object_id(&route, 1))
            .await
            .unwrap();
        serving.reconcile_once().await.unwrap();
        assert_eq!(fixture.report_rows(&route).await.get(&1), Some(&written));
    }

    #[tokio::test]
    async fn the_newest_stream_of_a_term_keeps_its_report() {
        let fixture = Fixture::new().await;
        fixture.member("m1", "p1", false).await;
        let route = fixture.fill("m1", "p1", 1).await.remove(0);
        let sandbox = fixture.owner(&route).await.unwrap().sandbox_id;
        let current = fixture.replica("gw-b");
        current.serve_reports(vec![member_report(
            ("m1", "p1", 1),
            &route,
            &sandbox,
            (2, true),
            2_000,
        )]);
        // A replica still holding the process's older stream.
        let stale = fixture.replica("gw-a");
        stale.serve_reports(vec![member_report(
            ("m1", "p1", 1),
            &route,
            &sandbox,
            (1, false),
            1_000,
        )]);
        current.reconcile_once().await.unwrap();
        stale.reconcile_once().await.unwrap();
        let row = fixture.report_rows(&route).await.remove(&1).unwrap();
        assert_eq!((row.ready, row.connected_at_ms), (true, 2_000));
    }

    #[tokio::test]
    async fn reports_count_only_for_their_owners_term() {
        let fixture = Fixture::new().await;
        fixture.member("m1", "p1", false).await;
        let route = fixture.fill("m1", "p1", 1).await.remove(0);
        let sandbox = fixture.owner(&route).await.unwrap().sandbox_id;
        // The route returns to the same process at term 2; its stream has
        // only acknowledged term 1.
        grant_next_term(&fixture, &route, "m1", "p1").await;
        let serving = fixture.replica("gw-a");
        serving.serve_reports(vec![member_report(
            ("m1", "p1", 1),
            &route,
            &sandbox,
            (2, true),
            1,
        )]);
        serving.reconcile_once().await.unwrap();
        assert!(fixture.report_rows(&route).await.is_empty());
        assert_eq!(published_report(&serving, &route), None);
    }

    #[tokio::test]
    async fn cleanup_removes_only_rows_older_than_the_listed_owner() {
        let fixture = Fixture::new().await;
        fixture.member("m1", "p1", false).await;
        let route = fixture.fill("m1", "p1", 1).await.remove(0);
        let pool = fixture.replica("gw-a");
        let listed = pool.owners().await.unwrap();
        for auth_epoch in [1, 2] {
            fixture
                .write_report(ReportPayload {
                    route: route.clone(),
                    member_id: "m1".to_string(),
                    process_id: "p1".to_string(),
                    auth_epoch,
                    sandbox_id: "sandbox".to_string(),
                    phase: 2,
                    ready: true,
                    exit_code: 0,
                    connected_at_ms: 0,
                })
                .await;
        }
        // Term 2's row is newer than the listed owner (term 1): kept, as is
        // the listed owner's own row.
        let rows = pool.report_rows().await.unwrap();
        pool.remove_stale_reports(&listed, &rows).await;
        assert_eq!(
            fixture
                .report_rows(&route)
                .await
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            [1, 2]
        );
        // Once the owner is listed at term 2, term 1's row goes.
        grant_next_term(&fixture, &route, "m1", "p1").await;
        let listed = pool.owners().await.unwrap();
        pool.remove_stale_reports(&listed, &rows).await;
        assert_eq!(
            fixture
                .report_rows(&route)
                .await
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            [2]
        );
        // A row changed since it was listed is left for the next pass.
        fixture
            .write_report(ReportPayload {
                route: route.clone(),
                member_id: "m1".to_string(),
                process_id: "p1".to_string(),
                auth_epoch: 2,
                sandbox_id: "sandbox".to_string(),
                phase: 2,
                ready: false,
                exit_code: 0,
                connected_at_ms: 0,
            })
            .await;
        let rows = pool.report_rows().await.unwrap();
        fixture.remove_owner_record(&route).await;
        fixture
            .write_report(ReportPayload {
                route: route.clone(),
                member_id: "m1".to_string(),
                process_id: "p1".to_string(),
                auth_epoch: 2,
                sandbox_id: "sandbox".to_string(),
                phase: 3,
                ready: false,
                exit_code: 0,
                connected_at_ms: 0,
            })
            .await;
        pool.remove_stale_reports(&BTreeMap::new(), &rows).await;
        assert_eq!(
            fixture
                .report_rows(&route)
                .await
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            [2]
        );
        // Without an owner, a row as listed goes.
        let rows = pool.report_rows().await.unwrap();
        pool.remove_stale_reports(&BTreeMap::new(), &rows).await;
        assert!(fixture.report_rows(&route).await.is_empty());
    }

    #[test]
    fn a_takeover_names_why_the_owner_lost_its_instance() {
        let owner = OwnerPayload {
            route: "rt-a".to_string(),
            sandbox_id: "sandbox-a".to_string(),
            generation: "generation-1".to_string(),
            member_id: "m1".to_string(),
            process_id: "p1".to_string(),
            auth_epoch: 1,
            supervisor_instance_id: None,
            gateway_token_id: None,
            phase: OwnerPhase::Granted,
            previous_member_id: None,
        };
        let member = |process_id: &str, leaving| LiveMember {
            member_id: "m1".to_string(),
            process_id: process_id.to_string(),
            runtime_address: "10.0.0.1:5500".to_string(),
            leaving,
        };
        assert_eq!(takeover_cause(&owner, &[]), "expired");
        assert_eq!(takeover_cause(&owner, &[member("p1", true)]), "leaving");
        assert_eq!(takeover_cause(&owner, &[member("p2", false)]), "restarted");
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
        let routes_for = |member: &str, count: usize| {
            (
                member.to_string(),
                (0..count)
                    .map(|index| format!("rt-{member}-{index}"))
                    .collect::<BTreeSet<_>>(),
            )
        };
        let order = |charges: BTreeMap<String, BTreeSet<String>>, route: &str, same| {
            candidates(&ring, &members, &sandbox, route, &charges, same)
                .into_iter()
                .map(|member| member.member_id.clone())
                .collect::<Vec<_>>()
        };
        let charges = |m1, m2| BTreeMap::from([routes_for("m1", m1), routes_for("m2", m2)]);
        assert_eq!(
            order(charges(MAX_ASSIGNED_INSTANCES - 1, 0), "rt-new", None),
            ["m1", "m2"]
        );
        // A full member is skipped for the least charged one with room; a
        // leaving member never receives instances.
        assert_eq!(
            order(charges(MAX_ASSIGNED_INSTANCES, 3), "rt-new", None),
            ["m2"]
        );
        assert!(
            order(
                charges(MAX_ASSIGNED_INSTANCES, MAX_ASSIGNED_INSTANCES),
                "rt-new",
                None
            )
            .is_empty()
        );
        // A full member still has room for a route it is charged for, and
        // its restarted process re-adopts it before any other member.
        assert_eq!(
            order(
                charges(MAX_ASSIGNED_INSTANCES, MAX_ASSIGNED_INSTANCES),
                "rt-m2-0",
                Some("m2")
            ),
            ["m2"]
        );
    }
}
