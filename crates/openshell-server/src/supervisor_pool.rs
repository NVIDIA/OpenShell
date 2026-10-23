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
//! Each replica serves the members connected to it the credentials of their
//! terms, minted from the granted record and the persisted identity.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use openshell_core::jwt::{SandboxId, SupervisorTakeover};
use openshell_core::proto::{Sandbox, SandboxPhase};
use openshell_core::time::now_ms;
use openshell_supervisor_control::proto::SandboxInstanceTakeover;
use openshell_supervisor_control::{
    ConnectedMember, InstanceOwner, InstancePlacement, MAX_ASSIGNED_INSTANCES, MemberView,
    PlacementFuture, PlacementRequest, PoolView, SupervisorHostController,
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::auth::sandbox_jwt::SandboxSessionJwtAuthority;
use crate::auth::sandbox_session::{
    PersistedSandboxIdentity, TakeoverIdentity, advance_identity_for_takeover,
};
use crate::gateway_ring::GatewayRing;
use crate::persistence::{ObjectRecord, PersistenceError, Store, WriteCondition};

const MEMBER_OBJECT_TYPE: &str = "supervisor_pool_member";
const OWNER_OBJECT_TYPE: &str = "supervisor_instance_owner";

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

fn member_object_id(member_id: &str) -> String {
    format!("supervisor-pool-member:{member_id}")
}

fn owner_object_id(route: &str) -> String {
    format!("supervisor-instance-owner:{route}")
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
    replica_id: String,
    member_ttl: Duration,
    unowned_grace: Duration,
    /// No takeover before this instant; see [`TAKEOVER_STARTUP_GRACE`].
    takeovers_from: tokio::time::Instant,
    /// When each desired route without an owner record was first seen.
    unowned_since: Mutex<HashMap<String, tokio::time::Instant>>,
    /// Takeover credentials minted for terms of members this replica serves.
    minted: Mutex<HashMap<(String, u64), (SandboxInstanceTakeover, tokio::time::Instant)>>,
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

impl SupervisorPool {
    #[must_use]
    pub fn new(
        store: Arc<Store>,
        controller: SupervisorHostController,
        authority: Arc<SandboxSessionJwtAuthority>,
        replica_id: String,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            controller,
            authority,
            replica_id,
            member_ttl: MEMBER_TTL,
            unowned_grace: UNOWNED_GRACE,
            takeovers_from: tokio::time::Instant::now() + TAKEOVER_STARTUP_GRACE,
            unowned_since: Mutex::new(HashMap::new()),
            minted: Mutex::new(HashMap::new()),
        })
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

    /// Record the owner of a new instance's launch term, on the member the
    /// ring prefers among live members.
    async fn place_launch(&self, request: PlacementRequest) -> Result<(), String> {
        let members = self
            .live_members()
            .await
            .map_err(|error| format!("read supervisor pool membership: {error}"))?;
        let owners = self
            .owners()
            .await
            .map_err(|error| format!("read supervisor instance owners: {error}"))?;
        let ring = ring_of(&members);
        let target = choose(
            &ring,
            &members,
            &request.sandbox_id,
            &load_of(owners.values()),
        )
        .ok_or_else(|| {
            "no shared supervisor replica is available with room for another sandbox".to_string()
        })?;
        let payload = OwnerPayload {
            route: request.route.clone(),
            sandbox_id: request.sandbox_id.clone(),
            generation: request.generation.clone(),
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
                .reload(&request.route)
                .await
                .map_err(|error| format!("read supervisor instance owner: {error}"))?
            {
                Reconciled::Changed(existing)
                    if existing.payload.generation == request.generation =>
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
            sandbox_id = %request.sandbox_id,
            route = %request.route,
            member = %record.payload.member_id,
            "placed shared sandbox instance on supervisor pool member"
        );
        if record.payload.phase == OwnerPhase::Granted
            && record.payload.supervisor_instance_id.is_none()
        {
            self.controller.place_owner(
                &request.route,
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

    /// One reconciliation pass: refresh served members, then place, take over,
    /// complete, and clean up owner records, and publish the resulting view.
    pub async fn reconcile_once(&self) -> Result<(), PersistenceError> {
        self.refresh_members().await;
        let members = self.live_members().await?;
        let ring = ring_of(&members);
        let listed_at = tokio::time::Instant::now();
        let mut owners = self.owners().await?;
        let mut load = load_of(owners.values());
        if self.controller.is_initialized() {
            let stopping = self.controller.stopping_routes();
            let desired = self
                .controller
                .assignments()
                .into_iter()
                .map(|assignment| (assignment.route.clone(), assignment))
                .collect::<BTreeMap<_, _>>();
            self.forget_owned(&desired, &owners);
            for (route, assignment) in &desired {
                if stopping.contains(route) {
                    continue;
                }
                let takeovers_allowed = tokio::time::Instant::now() >= self.takeovers_from;
                let outcome = match owners.get(route) {
                    None if takeovers_allowed => {
                        self.place_unowned(route, assignment, &ring, &members, &load)
                            .await
                    }
                    // An intent recorded by any replica, including one that
                    // crashed before granting it.
                    Some(record) if record.payload.phase == OwnerPhase::Granting => {
                        self.complete_takeover(record.clone()).await
                    }
                    Some(record)
                        if takeovers_allowed && !owner_alive(&record.payload, &members) =>
                    {
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
            let ended = owners
                .values()
                .filter(|record| !desired.contains_key(&record.payload.route))
                .take(CLEANUP_PER_PASS)
                .cloned()
                .collect::<Vec<_>>();
            for record in ended {
                match self.remove_if_ended(&record).await {
                    Ok(Reconciled::Changed(current)) => {
                        owners.insert(record.payload.route.clone(), *current);
                    }
                    Ok(Reconciled::Removed) => {
                        owners.remove(&record.payload.route);
                    }
                    Ok(Reconciled::Unchanged) => {}
                    Err(error) => {
                        warn!(route = %record.payload.route, %error, "could not remove an ended supervisor instance owner");
                    }
                }
            }
        }
        // Only granted terms are served; pending intents stay recorded for
        // the next pass.
        if let Some(view) = self.view(&members, &owners).await {
            self.controller.update_pool(view, listed_at);
        }
        Ok(())
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
        desired: &BTreeMap<String, openshell_supervisor_control::proto::SandboxInstanceAssignment>,
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
        assignment: &openshell_supervisor_control::proto::SandboxInstanceAssignment,
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
        let running = sandbox.as_ref().is_some_and(|sandbox| {
            !matches!(
                SandboxPhase::try_from(sandbox.phase()).unwrap_or(SandboxPhase::Unknown),
                SandboxPhase::Stopped | SandboxPhase::Deleting
            ) && sandbox
                .metadata
                .as_ref()
                .and_then(|metadata| PersistedSandboxIdentity::read(&metadata.annotations).ok())
                .is_some_and(|identity| {
                    identity.runtime_generation.as_str() == record.payload.generation
                })
        });
        if running {
            return Ok(Reconciled::Unchanged);
        }
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
    ) -> Option<PoolView> {
        let served = self
            .controller
            .connected_members()
            .into_iter()
            .map(|member| (member.member_id, member.process_id))
            .collect::<std::collections::BTreeSet<_>>();
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

impl InstancePlacement for PoolPlacement {
    fn place_launch(&self, request: PlacementRequest) -> PlacementFuture {
        let pool = self.0.clone();
        Box::pin(async move { pool.place_launch(request).await })
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
    }

    impl Fixture {
        async fn new() -> Self {
            let material = openshell_bootstrap::jwt::generate_jwt_key().expect("jwt key");
            Self {
                store: Arc::new(crate::persistence::test_store().await),
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
            controller.enable_pool();
            let mut pool = SupervisorPool::new(
                self.store.clone(),
                controller,
                self.authority.clone(),
                replica_id.to_string(),
            );
            let unique = Arc::get_mut(&mut pool).expect("unique");
            unique.unowned_grace = Duration::ZERO;
            unique.takeovers_from = tokio::time::Instant::now();
            pool
        }

        /// A replica that just started, within its takeover grace.
        fn starting_replica(&self, replica_id: &str) -> Arc<SupervisorPool> {
            let controller = SupervisorHostController::new();
            controller.enable_pool();
            SupervisorPool::new(
                self.store.clone(),
                controller,
                self.authority.clone(),
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
    }

    fn assignment(route: &str, sandbox_id: &str, generation: &str) -> SandboxInstanceAssignment {
        SandboxInstanceAssignment {
            route: route.to_string(),
            sandbox_id: sandbox_id.to_string(),
            generation: generation.to_string(),
            launch_material: b"opaque".to_vec(),
            takeover: None,
        }
    }

    fn launch(route: &str, sandbox_id: &str, generation: &str) -> PlacementRequest {
        PlacementRequest {
            route: route.to_string(),
            sandbox_id: sandbox_id.to_string(),
            generation: generation.to_string(),
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
        pool.controller
            .replace_assignments(
                0,
                routes
                    .iter()
                    .map(|(route, sandbox)| assignment(route, sandbox, "generation-1")),
            )
            .unwrap();
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
        for replica in [&replica_a, &replica_b] {
            replica
                .controller
                .replace_assignments(
                    0,
                    [assignment("rt-route-a000", "sandbox-a", "generation-1")],
                )
                .unwrap();
        }

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
        pool.controller
            .replace_assignments(
                0,
                [
                    assignment("rt-route-a000", "sandbox-a", "generation-1"),
                    assignment("rt-route-b000", "sandbox-b", "generation-1"),
                ],
            )
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
        pool.controller
            .replace_assignments(
                0,
                [
                    assignment("rt-route-s000", "sandbox-stopping", "generation-1"),
                    assignment("rt-route-d000", "sandbox-deleted", "generation-1"),
                    assignment("rt-route-r000", "sandbox-restarted", "generation-1"),
                ],
            )
            .unwrap();
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
        pool.controller
            .replace_assignments(
                0,
                [
                    assignment("rt-route-a000", "sandbox-a", "generation-1"),
                    // Launched before the pool recorded owners.
                    assignment("rt-route-b000", "sandbox-b", "generation-1"),
                ],
            )
            .unwrap();
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
        pool.controller
            .replace_assignments(
                0,
                [
                    assignment("rt-route-a000", "sandbox-a", "generation-1"),
                    assignment("rt-route-b000", "sandbox-b", "generation-1"),
                    assignment("rt-route-c000", "sandbox-c", "generation-1"),
                    assignment("rt-route-d000", "sandbox-d", "generation-1"),
                ],
            )
            .unwrap();

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
        pool.controller.replace_assignments(0, []).unwrap();
        // Still the sandbox's generation: kept for other replicas.
        pool.reconcile_once().await.unwrap();
        assert!(fixture.owner("rt-route-a000").await.is_some());
        fixture
            .sandbox("sandbox-a", "generation-2", SandboxPhase::Ready)
            .await;
        pool.reconcile_once().await.unwrap();
        assert!(fixture.owner("rt-route-a000").await.is_none());

        // A stopped sandbox never runs its generation again.
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
        assert!(fixture.owner("rt-route-b000").await.is_none());
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
        starting
            .controller
            .replace_assignments(
                0,
                [assignment("rt-route-a000", "sandbox-a", "generation-1")],
            )
            .unwrap();
        fixture.member("m2", "p2", false).await;
        fixture.remove_member("m1").await;
        // Members cut off by a gateway restart get time to reconnect.
        starting.reconcile_once().await.unwrap();
        assert_eq!(fixture.owner("rt-route-a000").await.unwrap().auth_epoch, 1);
        // A replica past its grace takes the starting instance over.
        let settled = fixture.replica("gw-settled");
        settled
            .controller
            .replace_assignments(
                0,
                [assignment("rt-route-a000", "sandbox-a", "generation-1")],
            )
            .unwrap();
        settled.reconcile_once().await.unwrap();
        let owner = fixture.owner("rt-route-a000").await.unwrap();
        assert_eq!((owner.member_id.as_str(), owner.auth_epoch), ("m2", 2));
        assert_eq!(owner.phase, OwnerPhase::Granted);
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
