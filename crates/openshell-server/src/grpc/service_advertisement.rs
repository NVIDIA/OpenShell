// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Expiring installation evidence. Addresses always cross the trusted driver
//! boundary; the authenticated supervisor supplies only installed declarations.

use std::sync::Arc;
use std::time::Duration;

use openshell_core::proto::{Sandbox, SandboxServiceRoute, SupervisorServiceAdvertisement};
use openshell_core::{ObjectId, ObjectWorkspace};
use prost::Message as _;
use serde::{Deserialize, Serialize};
use tonic::Status;

use crate::ServerState;
use crate::compute::{COMPUTE_RUNTIME_IDENTITY_ANNOTATION, MutationScope};
use crate::persistence::{ObjectCursor, ObjectRecord, WriteCondition, current_time_ms};
use crate::supervisor_owner::{OWNER_TTL, OwnerGuard, SupervisorOwnerIndex};

pub const OBJECT_TYPE: &str = "supervisor_service_installation";
pub const LEASE: Duration = Duration::from_secs(15);
pub const REPORT_INTERVAL: Duration = Duration::from_secs(5);
const MAX_ROUTES: usize = 1024;

/// Trusted driver resolution scoped to one session and one lease exchange.
#[derive(Clone)]
pub struct LeaseAuthority {
    sandbox_id: String,
    session_id: String,
    supervisor_instance_id: String,
    connection_epoch: u64,
    auth_epoch: Option<openshell_core::jwt::CredentialEpoch>,
    endpoint: openshell_core::proto::compute::v1::SupervisorAppEndpoint,
}

impl LeaseAuthority {
    fn matches(&self, owner: &OwnerGuard) -> bool {
        self.sandbox_id == owner.sandbox_id
            && self.session_id == owner.session_id
            && self.supervisor_instance_id == owner.supervisor_instance_id
            && self.connection_epoch == owner.connection_epoch
            && self.auth_epoch == owner.auth_epoch
    }
}

pub struct ClaimedLease {
    authority: LeaseAuthority,
    expires_at_ms: i64,
}

/// A challenge is session-local and single-use. Its monotonic deadline starts
/// before transmission, so delayed answers never receive a fresh receipt lease.
pub struct LeaseWindow {
    sequence: u64,
    deadline: tokio::time::Instant,
    expires_at_ms: i64,
    authority: Option<LeaseAuthority>,
}

impl Default for LeaseWindow {
    fn default() -> Self {
        Self {
            sequence: 0,
            deadline: tokio::time::Instant::now(),
            expires_at_ms: 0,
            authority: None,
        }
    }
}

impl LeaseWindow {
    pub fn issue(
        &mut self,
        authority: LeaseAuthority,
    ) -> Option<openshell_core::proto::ServiceRouteLease> {
        self.sequence = self.sequence.checked_add(1)?;
        self.deadline = tokio::time::Instant::now() + LEASE;
        self.expires_at_ms =
            current_time_ms() + i64::try_from(LEASE.as_millis()).expect("bounded lease");
        self.authority = Some(authority);
        Some(openshell_core::proto::ServiceRouteLease {
            sequence: self.sequence,
            duration: openshell_core::time::duration_from_std(LEASE).ok(),
            expires_at: openshell_core::time::timestamp_from_millis(self.expires_at_ms).ok(),
        })
    }

    pub fn claim(&mut self, sequence: u64) -> Option<ClaimedLease> {
        if sequence != self.sequence || tokio::time::Instant::now() >= self.deadline {
            return None;
        }
        Some(ClaimedLease {
            authority: self.authority.take()?,
            expires_at_ms: self.expires_at_ms,
        })
    }
}

/// One record per immutable sandbox identity. These records are ephemeral:
/// reads revalidate owner, configuration, generation, and expiry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Installation {
    pub sandbox_id: String,
    pub session_id: String,
    pub supervisor_instance_id: String,
    pub connection_epoch: u64,
    pub runtime_identity: String,
    #[serde(default)]
    pub ownership_epoch: u64,
    #[serde(default)]
    pub pool_route: String,
    pub service_domain: String,
    pub configuration_instance_id: String,
    pub config_revision: u64,
    pub sequence: u64,
    pub host: String,
    pub port: u32,
    pub expires_at_ms: i64,
    pub routes: Vec<Vec<u8>>,
}

fn runtime_identity(sandbox: &Sandbox) -> Result<&str, Status> {
    sandbox
        .metadata
        .as_ref()
        .and_then(|meta| meta.annotations.get(COMPUTE_RUNTIME_IDENTITY_ANNOTATION))
        .filter(|identity| !identity.is_empty())
        .map(String::as_str)
        .ok_or_else(|| Status::failed_precondition("sandbox runtime identity unavailable"))
}

fn validate_routes(
    report: &SupervisorServiceAdvertisement,
    declared: &[SandboxServiceRoute],
) -> Result<(), Status> {
    if report.routes.len() > MAX_ROUTES {
        return Err(Status::resource_exhausted(
            "too many installed service routes",
        ));
    }
    let mut ids = std::collections::BTreeSet::new();
    for route in &report.routes {
        if !ids.insert(&route.endpoint_id)
            || route.endpoint_id.is_empty()
            || !declared.contains(route)
        {
            return Err(Status::failed_precondition(
                "installed service route is not a current declaration",
            ));
        }
    }
    // Nonempty reports are complete replacements, never partial declarations.
    if !report.routes.is_empty() && report.routes.len() != declared.len() {
        return Err(Status::failed_precondition(
            "incomplete installed service report",
        ));
    }
    Ok(())
}

fn sandbox_term_matches(
    sandbox: &Sandbox,
    epoch: Option<openshell_core::jwt::CredentialEpoch>,
) -> bool {
    let stored = sandbox.metadata.as_ref().and_then(|m| {
        m.annotations
            .get(crate::auth::sandbox_session::AUTH_EPOCH_ANNOTATION)
    });
    match (stored, epoch) {
        (None, None) => true,
        (Some(value), Some(epoch)) => value.parse::<u64>().ok() == Some(epoch.get()),
        _ => false,
    }
}

async fn endpoint_authority_current(
    state: &ServerState,
    sandbox: &Sandbox,
    owner: &OwnerGuard,
    endpoint: &openshell_core::proto::compute::v1::SupervisorAppEndpoint,
) -> Result<bool, Status> {
    if !sandbox_term_matches(sandbox, owner.auth_epoch)
        || endpoint.runtime_identity != runtime_identity(sandbox)?
        || endpoint.port != u32::from(state.config.supervisor_app_listener.port)
        || endpoint.host.parse::<std::net::IpAddr>().is_err()
    {
        return Ok(false);
    }
    if !endpoint.pool_route.is_empty()
        && (owner
            .auth_epoch
            .map_or(0, openshell_core::jwt::CredentialEpoch::get)
            != endpoint.ownership_epoch
            || !crate::supervisor_pool::app_endpoint_current(&state.store, sandbox, endpoint)
                .await
                .map_err(|_| Status::unavailable("pool application authority unavailable"))?)
    {
        return Ok(false);
    }
    Ok(true)
}

async fn current_endpoint(
    state: &ServerState,
    sandbox: &Sandbox,
    owner: &OwnerGuard,
) -> Result<Option<openshell_core::proto::compute::v1::SupervisorAppEndpoint>, Status> {
    let Some(endpoint) = state.compute.supervisor_app_endpoint(sandbox).await? else {
        return Ok(None);
    };
    Ok(endpoint_authority_current(state, sandbox, owner, &endpoint)
        .await?
        .then_some(endpoint))
}

/// A serving lease is issued only while the session still has durable runtime
/// authority. This check is repeated for every lease, independently of config.
pub async fn prepare_lease(
    state: &ServerState,
    owner: &OwnerGuard,
) -> Result<Option<LeaseAuthority>, Status> {
    let Some(sandbox) = state
        .store
        .get_message::<Sandbox>(&owner.sandbox_id)
        .await
        .map_err(|_| Status::unavailable("sandbox storage unavailable"))?
    else {
        return Ok(None);
    };
    if sandbox
        .metadata
        .as_ref()
        .is_some_and(|m| m.deletion_time.is_some())
    {
        return Ok(None);
    }
    let current = SupervisorOwnerIndex::new(state.store.clone(), OWNER_TTL)
        .read(&owner.sandbox_id)
        .await
        .map_err(|_| Status::unavailable("supervisor ownership unavailable"))?;
    if current.is_none_or(|current| {
        !current.is_fresh(OWNER_TTL)
            || current.session_id != owner.session_id
            || current.auth_epoch != owner.auth_epoch
            || current.supervisor_instance_id != owner.supervisor_instance_id
            || current.connection_epoch != owner.connection_epoch
    }) {
        return Ok(None);
    }
    if !state.config.supervisor_app_listener.enabled {
        return Ok(None);
    }
    Ok(current_endpoint(state, &sandbox, owner)
        .await?
        .map(|endpoint| LeaseAuthority {
            sandbox_id: owner.sandbox_id.clone(),
            session_id: owner.session_id.clone(),
            supervisor_instance_id: owner.supervisor_instance_id.clone(),
            connection_epoch: owner.connection_epoch,
            auth_epoch: owner.auth_epoch,
            endpoint,
        }))
}

pub async fn accept_lease(
    state: &Arc<ServerState>,
    owner: &OwnerGuard,
    report: &SupervisorServiceAdvertisement,
    lease: ClaimedLease,
) -> Result<(), Status> {
    if !lease.authority.matches(owner) {
        return Err(Status::failed_precondition(
            "service lease session replaced",
        ));
    }
    accept_inner(
        state,
        owner,
        report,
        lease.expires_at_ms,
        Some(lease.authority.endpoint),
    )
    .await
}

// Tests can install records directly without performing a session exchange.
#[cfg(test)]
pub async fn accept(
    state: &Arc<ServerState>,
    owner: &OwnerGuard,
    report: &SupervisorServiceAdvertisement,
    expires_at_ms: i64,
) -> Result<(), Status> {
    accept_inner(state, owner, report, expires_at_ms, None).await
}

async fn accept_inner(
    state: &Arc<ServerState>,
    owner: &OwnerGuard,
    report: &SupervisorServiceAdvertisement,
    expires_at_ms: i64,
    resolved_endpoint: Option<openshell_core::proto::compute::v1::SupervisorAppEndpoint>,
) -> Result<(), Status> {
    if !state.config.supervisor_app_listener.enabled {
        return Ok(());
    }
    if report.routes.len() > MAX_ROUTES {
        return Err(Status::resource_exhausted(
            "too many installed service routes",
        ));
    }
    let initial = state
        .store
        .get_message::<Sandbox>(&owner.sandbox_id)
        .await
        .map_err(|_| Status::unavailable("sandbox storage unavailable"))?
        .ok_or_else(|| Status::not_found("sandbox removed"))?;
    let _guard = state
        .compute
        .mutation_guard(MutationScope::sandbox(
            initial.object_workspace(),
            &owner.sandbox_id,
        ))
        .await
        .map_err(|_| Status::unavailable("service installation lock unavailable"))?;
    let sandbox = state
        .store
        .get_message::<Sandbox>(&owner.sandbox_id)
        .await
        .map_err(|_| Status::unavailable("sandbox storage unavailable"))?
        .ok_or_else(|| Status::not_found("sandbox removed"))?;
    if sandbox
        .metadata
        .as_ref()
        .is_some_and(|m| m.deletion_time.is_some())
    {
        return Err(Status::failed_precondition("sandbox deleting"));
    }
    let index = SupervisorOwnerIndex::new(state.store.clone(), OWNER_TTL);
    let current = index
        .read(&owner.sandbox_id)
        .await
        .map_err(|_| Status::unavailable("supervisor ownership unavailable"))?
        .ok_or_else(|| Status::failed_precondition("supervisor ownership missing"))?;
    if !current.is_fresh(OWNER_TTL)
        || current.session_id != owner.session_id
        || current.supervisor_instance_id != owner.supervisor_instance_id
        || current.connection_epoch != owner.connection_epoch
        || current.auth_epoch != owner.auth_epoch
    {
        return Err(Status::failed_precondition("supervisor ownership replaced"));
    }
    let mut record = Installation {
        sandbox_id: owner.sandbox_id.clone(),
        session_id: owner.session_id.clone(),
        supervisor_instance_id: owner.supervisor_instance_id.clone(),
        connection_epoch: owner.connection_epoch,
        runtime_identity: runtime_identity(&sandbox)?.to_string(),
        ownership_epoch: owner
            .auth_epoch
            .map_or(0, openshell_core::jwt::CredentialEpoch::get),
        pool_route: String::new(),
        service_domain: report.service_domain.clone(),
        configuration_instance_id: report.configuration_instance_id.clone(),
        config_revision: report.config_revision,
        sequence: report.lease_sequence,
        host: String::new(),
        port: 0,
        expires_at_ms,
        routes: report
            .routes
            .iter()
            .map(prost::Message::encode_to_vec)
            .collect(),
    };
    if !report.routes.is_empty() {
        if report.service_domain != state.config.supervisor_app_listener.domain {
            return Err(Status::failed_precondition(
                "installed listener domain is not current",
            ));
        }
        let config = super::policy::build_sandbox_config_snapshot(state, &sandbox).await?;
        if !config.configuration_admitted
            || config.configuration_instance_id != report.configuration_instance_id
            || config.config_revision != report.config_revision
        {
            return Err(Status::failed_precondition(
                "installed configuration is not current",
            ));
        }
        validate_routes(report, &config.service_routes)?;
        let endpoint = if let Some(endpoint) = resolved_endpoint {
            // Reuse only the challenge's driver result. Recheck durable pool
            // authority after configuration validation and before publication.
            if !endpoint_authority_current(state, &sandbox, owner, &endpoint).await? {
                return Err(Status::failed_precondition(
                    "service lease endpoint authority replaced",
                ));
            }
            endpoint
        } else {
            current_endpoint(state, &sandbox, owner)
                .await?
                .ok_or_else(|| {
                    Status::failed_precondition("trusted supervisor app endpoint unavailable")
                })?
        };
        record.pool_route = endpoint.pool_route;
        record.host = endpoint.host;
        record.port = endpoint.port;
    }
    // Recheck after external calls: a session replacement need not take the
    // sandbox mutation lock. Readers make the same ownership check.
    let current = index
        .read(&owner.sandbox_id)
        .await
        .map_err(|_| Status::unavailable("supervisor ownership unavailable"))?
        .ok_or_else(|| Status::failed_precondition("supervisor ownership missing"))?;
    if !current.is_fresh(OWNER_TTL)
        || current.session_id != record.session_id
        || current.supervisor_instance_id != record.supervisor_instance_id
        || current.connection_epoch != record.connection_epoch
        || current.auth_epoch != owner.auth_epoch
    {
        return Err(Status::failed_precondition("supervisor ownership replaced"));
    }
    if expires_at_ms <= current_time_ms() {
        return Err(Status::failed_precondition(
            "service installation lease expired",
        ));
    }
    let installation_id = format!("service-installation:{}", sandbox.object_id());
    let previous = state
        .store
        .get(OBJECT_TYPE, &installation_id)
        .await
        .map_err(|_| Status::unavailable("service installation storage unavailable"))?;
    if let Some(previous) = &previous {
        let old: Installation = serde_json::from_slice(&previous.payload)
            .map_err(|_| Status::internal("invalid stored installation"))?;
        if old.session_id == record.session_id && old.sequence >= record.sequence {
            return Err(Status::failed_precondition(
                "service installation report replayed",
            ));
        }
    }
    let payload =
        serde_json::to_vec(&record).map_err(|_| Status::internal("encode service installation"))?;
    state
        .store
        .put_if(
            OBJECT_TYPE,
            &installation_id,
            sandbox.object_id(),
            sandbox.object_workspace(),
            &payload,
            None,
            previous.map_or(WriteCondition::MustCreate, |p| {
                WriteCondition::MatchResourceVersion(p.resource_version)
            }),
        )
        .await
        .map_err(|_| Status::unavailable("service installation write failed"))?;
    Ok(())
}

/// Discovery must call this before publishing each persisted installation.
/// Freshness failures are absence; storage/decoding failures are errors.
pub async fn is_current(state: &ServerState, record: &Installation) -> Result<bool, Status> {
    if !state.config.supervisor_app_listener.enabled
        || record.expires_at_ms <= current_time_ms()
        || record.service_domain != state.config.supervisor_app_listener.domain
        || record.routes.is_empty()
    {
        return Ok(false);
    }
    let Some(sandbox) = state
        .store
        .get_message::<Sandbox>(&record.sandbox_id)
        .await
        .map_err(|_| Status::unavailable("sandbox storage unavailable"))?
    else {
        return Ok(false);
    };
    if sandbox
        .metadata
        .as_ref()
        .is_some_and(|m| m.deletion_time.is_some())
        || runtime_identity(&sandbox)? != record.runtime_identity
    {
        return Ok(false);
    }
    let Some(owner) = SupervisorOwnerIndex::new(state.store.clone(), OWNER_TTL)
        .read(&record.sandbox_id)
        .await
        .map_err(|_| Status::unavailable("supervisor ownership unavailable"))?
    else {
        return Ok(false);
    };
    if !owner.is_fresh(OWNER_TTL)
        || owner.session_id != record.session_id
        || owner.supervisor_instance_id != record.supervisor_instance_id
        || owner.connection_epoch != record.connection_epoch
        || owner
            .auth_epoch
            .map_or(0, openshell_core::jwt::CredentialEpoch::get)
            != record.ownership_epoch
        || !sandbox_term_matches(&sandbox, owner.auth_epoch)
    {
        return Ok(false);
    }
    if !record.pool_route.is_empty() {
        let endpoint = openshell_core::proto::compute::v1::SupervisorAppEndpoint {
            host: record.host.clone(),
            port: record.port,
            runtime_identity: record.runtime_identity.clone(),
            pool_route: record.pool_route.clone(),
            ownership_epoch: record.ownership_epoch,
        };
        if !crate::supervisor_pool::app_endpoint_current(&state.store, &sandbox, &endpoint)
            .await
            .map_err(|_| Status::unavailable("pool application authority unavailable"))?
        {
            return Ok(false);
        }
    }
    let config = super::policy::build_sandbox_config_snapshot(state, &sandbox).await?;
    if !config.configuration_admitted
        || config.configuration_instance_id != record.configuration_instance_id
        || config.config_revision != record.config_revision
    {
        return Ok(false);
    }
    let routes = record
        .routes
        .iter()
        .map(|bytes| SandboxServiceRoute::decode(bytes.as_slice()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Status::internal("invalid stored service route"))?;
    let report = SupervisorServiceAdvertisement {
        routes,
        ..Default::default()
    };
    Ok(validate_routes(&report, &config.service_routes).is_ok())
}

const CLEANUP_PAGE_SIZE: u16 = 128;
const CLEANUP_RECORD_TIMEOUT: Duration = Duration::from_secs(1);

async fn cleanup_record(state: &ServerState, record: ObjectRecord) -> Result<(), Status> {
    let installation: Installation = serde_json::from_slice(&record.payload)
        .map_err(|_| Status::internal("invalid stored service installation"))?;
    if installation.expires_at_ms <= current_time_ms() || !is_current(state, &installation).await? {
        // Conditional deletion cannot erase a concurrent renewal.
        state
            .store
            .delete_if(OBJECT_TYPE, &record.id, record.resource_version)
            .await
            .map_err(|_| Status::unavailable("service installation cleanup failed"))?;
    }
    Ok(())
}

async fn cleanup_page<F, Fut>(
    page: Vec<ObjectRecord>,
    cursor: &mut Option<ObjectCursor>,
    mut process: F,
) where
    F: FnMut(ObjectRecord) -> Fut,
    Fut: Future<Output = Result<(), Status>>,
{
    let last_page = page.len() < usize::from(CLEANUP_PAGE_SIZE);
    for record in page {
        let next = ObjectCursor::from(&record);
        if !matches!(
            tokio::time::timeout(CLEANUP_RECORD_TIMEOUT, process(record)).await,
            Ok(Ok(()))
        ) {
            tracing::debug!("service installation cleanup attempt failed or timed out");
        }
        // Commit progress before the sweep can be cancelled. A failed bounded
        // attempt leaves the record intact and revisits it on the next scan.
        *cursor = Some(next);
    }
    if last_page {
        *cursor = None;
    }
}

pub fn spawn_cleanup(state: Arc<ServerState>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    tokio::spawn(async move {
        let mut cursor: Option<ObjectCursor> = None;
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = interval.tick() => {}
            }
            let sweep = async {
                let page = state
                    .store
                    .list_by_type_after(OBJECT_TYPE, cursor.as_ref(), u32::from(CLEANUP_PAGE_SIZE))
                    .await?;
                cleanup_page(page, &mut cursor, |record| cleanup_record(&state, record)).await;
                Ok::<_, crate::persistence::PersistenceError>(())
            };
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = tokio::time::timeout(Duration::from_secs(5), sweep) => {}
            }
        }
    });
}

#[cfg(test)]
pub mod tests {
    use super::*;

    fn test_lease_authority() -> LeaseAuthority {
        LeaseAuthority {
            sandbox_id: "sandbox".into(),
            session_id: "session".into(),
            supervisor_instance_id: "instance".into(),
            connection_epoch: 1,
            auth_epoch: None,
            endpoint: openshell_core::proto::compute::v1::SupervisorAppEndpoint {
                host: "10.0.0.7".into(),
                port: 9443,
                runtime_identity: "runtime-a".into(),
                ..Default::default()
            },
        }
    }

    struct CountingEndpointResolver {
        calls: std::sync::atomic::AtomicUsize,
        fail: std::sync::atomic::AtomicBool,
    }

    #[tonic::async_trait]
    impl openshell_core::proto::compute::v1::compute_driver_app_endpoints_server::ComputeDriverAppEndpoints for CountingEndpointResolver {
        async fn resolve_supervisor_app_endpoint(
            &self,
            request: tonic::Request<openshell_core::proto::compute::v1::ResolveSupervisorAppEndpointRequest>,
        ) -> Result<tonic::Response<openshell_core::proto::compute::v1::ResolveSupervisorAppEndpointResponse>, Status> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(Status::unavailable("endpoint lookup failed"));
            }
            Ok(tonic::Response::new(openshell_core::proto::compute::v1::ResolveSupervisorAppEndpointResponse {
                sandbox_id: request.into_inner().sandbox_id,
                supervisor_app_endpoint: Some(test_lease_authority().endpoint),
            }))
        }
    }

    async fn counted_fixture() -> (
        Arc<ServerState>,
        OwnerGuard,
        SupervisorServiceAdvertisement,
        Arc<CountingEndpointResolver>,
    ) {
        let (mut state, owner, report) = installed_fixture().await;
        let resolver = Arc::new(CountingEndpointResolver {
            calls: std::sync::atomic::AtomicUsize::new(0),
            fail: std::sync::atomic::AtomicBool::new(false),
        });
        let inner = Arc::get_mut(&mut state).unwrap();
        inner.compute = inner
            .compute
            .clone()
            .with_app_endpoint_resolver(Some(resolver.clone()));
        (state, owner, report, resolver)
    }

    #[tokio::test]
    async fn lease_exchange_resolves_once_and_withdrawals_do_not_resolve_again() {
        use std::sync::atomic::Ordering;
        let (state, owner, mut report, resolver) = counted_fixture().await;
        let mut window = LeaseWindow::default();
        for expected_calls in 1..=2 {
            let authority = prepare_lease(&state, &owner).await.unwrap().unwrap();
            let lease = window.issue(authority).unwrap();
            report.lease_sequence = lease.sequence;
            let claimed = window.claim(lease.sequence).unwrap();
            let expiry = claimed.expires_at_ms;
            accept_lease(&state, &owner, &report, claimed)
                .await
                .unwrap();
            assert!(window.claim(lease.sequence).is_none());
            assert_eq!(resolver.calls.load(Ordering::SeqCst), expected_calls);
            let row = state
                .store
                .get(OBJECT_TYPE, "service-installation:sandbox")
                .await
                .unwrap()
                .unwrap();
            let record: Installation = serde_json::from_slice(&row.payload).unwrap();
            assert_eq!(record.expires_at_ms, expiry);
        }
        let lease = window
            .issue(prepare_lease(&state, &owner).await.unwrap().unwrap())
            .unwrap();
        resolver.fail.store(true, Ordering::SeqCst);
        report.lease_sequence = lease.sequence;
        report.routes.clear();
        accept_lease(
            &state,
            &owner,
            &report,
            window.claim(lease.sequence).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 3);
        assert!(prepare_lease(&state, &owner).await.is_err());
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn resolved_lease_rejects_identity_changes_and_durable_owner_replacement() {
        let (state, owner, mut report, _) = counted_fixture().await;
        let authority = prepare_lease(&state, &owner).await.unwrap().unwrap();
        // None of these mismatches may reuse another session's resolution.
        for field in 0..5 {
            let mut changed = owner.clone();
            match field {
                0 => changed.sandbox_id = "another-sandbox".into(),
                1 => changed.session_id = "another-session".into(),
                2 => changed.supervisor_instance_id = "another-instance".into(),
                3 => changed.connection_epoch += 1,
                _ => changed.auth_epoch = openshell_core::jwt::CredentialEpoch::new(1).ok(),
            }
            let mut window = LeaseWindow::default();
            let lease = window.issue(authority.clone()).unwrap();
            assert!(
                accept_lease(
                    &state,
                    &changed,
                    &report,
                    window.claim(lease.sequence).unwrap()
                )
                .await
                .is_err()
            );
        }
        let mut window = LeaseWindow::default();
        let lease = window.issue(authority).unwrap();
        report.lease_sequence = lease.sequence;
        SupervisorOwnerIndex::new(state.store.clone(), OWNER_TTL)
            .release_if_current(&owner)
            .await
            .unwrap();
        SupervisorOwnerIndex::new(state.store.clone(), OWNER_TTL)
            .publish(
                "sandbox",
                "replacement-session",
                "replacement-instance",
                2,
                "other-replica",
                "local://other",
            )
            .await
            .unwrap();
        // The passed guard still matches the challenge, but storage no longer does.
        assert!(
            accept_lease(
                &state,
                &owner,
                &report,
                window.claim(lease.sequence).unwrap()
            )
            .await
            .is_err()
        );
        assert!(prepare_lease(&state, &owner).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn resolved_lease_rechecks_runtime_configuration_expiry_and_pool_authority() {
        for change in 0..4 {
            let (state, owner, mut report, _) = counted_fixture().await;
            let mut authority = prepare_lease(&state, &owner).await.unwrap().unwrap();
            if change == 3 {
                authority.endpoint.pool_route = "replaced-pool-route".into();
            }
            let mut window = LeaseWindow::default();
            let lease = window.issue(authority).unwrap();
            report.lease_sequence = lease.sequence;
            let mut claimed = window.claim(lease.sequence).unwrap();
            match change {
                0 => {
                    let mut sandbox = state
                        .store
                        .get_message::<Sandbox>("sandbox")
                        .await
                        .unwrap()
                        .unwrap();
                    sandbox.metadata.as_mut().unwrap().annotations.insert(
                        COMPUTE_RUNTIME_IDENTITY_ANNOTATION.into(),
                        "runtime-b".into(),
                    );
                    state.store.put_message(&sandbox).await.unwrap();
                }
                1 => report.config_revision += 1,
                2 => claimed.expires_at_ms = current_time_ms() - 1,
                _ => {}
            }
            assert!(
                accept_lease(&state, &owner, &report, claimed)
                    .await
                    .is_err()
            );
            assert!(
                state
                    .store
                    .get(OBJECT_TYPE, "service-installation:sandbox")
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }

    fn cleanup_test_record(index: usize) -> ObjectRecord {
        ObjectRecord {
            object_type: OBJECT_TYPE.into(),
            id: format!("{index:04}"),
            name: format!("{index:04}"),
            workspace: "default".into(),
            payload: Vec::new(),
            created_at_ms: 0,
            updated_at_ms: 0,
            labels: None,
            resource_version: 1,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn cleanup_resumes_timed_out_pages_and_wraps_after_the_final_page() {
        let records: Vec<_> = (0..130).map(cleanup_test_record).collect();
        let mut cursor: Option<ObjectCursor> = None;
        let processed = std::sync::Mutex::new(Vec::new());
        let mut sweeps = 0;
        loop {
            let page = records
                .iter()
                .filter(|record| cursor.as_ref().is_none_or(|c| record.id > c.id))
                .take(usize::from(CLEANUP_PAGE_SIZE))
                .cloned()
                .collect();
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                cleanup_page(page, &mut cursor, |record| {
                    let processed = &processed;
                    async move {
                        tokio::time::sleep(Duration::from_millis(900)).await;
                        processed.lock().unwrap().push(record.id);
                        Ok(())
                    }
                }),
            )
            .await;
            sweeps += 1;
            if cursor.is_none() {
                assert!(result.is_ok());
                break;
            }
            assert!(sweeps < 40, "cleanup did not advance");
        }
        assert!(sweeps > 1);
        assert_eq!(
            *processed.lock().unwrap(),
            records.iter().map(|r| r.id.clone()).collect::<Vec<_>>()
        );
        // The final partial page resets the cursor so retained records are revisited.
        assert!(cursor.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn cleanup_skips_failed_and_stalled_attempts_without_starving_later_records() {
        let mut cursor = None;
        let processed = std::sync::Mutex::new(Vec::new());
        cleanup_page(
            (0..3).map(cleanup_test_record).collect(),
            &mut cursor,
            |record| {
                let processed = &processed;
                async move {
                    match record.id.as_str() {
                        "0000" => Err(Status::internal("malformed record")),
                        "0001" => std::future::pending().await,
                        _ => {
                            processed.lock().unwrap().push(record.id);
                            Ok(())
                        }
                    }
                }
            },
        )
        .await;
        assert_eq!(*processed.lock().unwrap(), vec!["0002"]);
        assert!(cursor.is_none());
    }

    #[tokio::test]
    async fn cleanup_preserves_concurrent_renewals_and_rejects_malformed_records() {
        let (state, owner, mut report) = installed_fixture().await;
        accept(&state, &owner, &report, current_time_ms() + 10_000)
            .await
            .unwrap();
        let id = "service-installation:sandbox";
        let row = state.store.get(OBJECT_TYPE, id).await.unwrap().unwrap();
        let mut expired: Installation = serde_json::from_slice(&row.payload).unwrap();
        expired.expires_at_ms = 0;
        state
            .store
            .put_if(
                OBJECT_TYPE,
                id,
                &row.name,
                &row.workspace,
                &serde_json::to_vec(&expired).unwrap(),
                None,
                WriteCondition::MatchResourceVersion(row.resource_version),
            )
            .await
            .unwrap();
        let expired_record = state.store.get(OBJECT_TYPE, id).await.unwrap().unwrap();
        report.lease_sequence += 1;
        accept(&state, &owner, &report, current_time_ms() + 10_000)
            .await
            .unwrap();
        let renewed = state.store.get(OBJECT_TYPE, id).await.unwrap().unwrap();
        let _ = cleanup_record(&state, expired_record).await;
        assert_eq!(
            state
                .store
                .get(OBJECT_TYPE, id)
                .await
                .unwrap()
                .unwrap()
                .resource_version,
            renewed.resource_version
        );
        let mut malformed = renewed;
        malformed.payload = b"invalid JSON".to_vec();
        assert!(cleanup_record(&state, malformed).await.is_err());
        assert!(state.store.get(OBJECT_TYPE, id).await.unwrap().is_some());
    }

    fn route() -> SandboxServiceRoute {
        SandboxServiceRoute {
            endpoint_id: "endpoint".into(),
            name: "web".into(),
            target_port: 8080,
            authorization_mode: 1,
            resource_version: 2,
            application_hostname: String::new(),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn lease_is_single_use_and_delayed_or_superseded_reports_do_not_extend_it() {
        let mut window = LeaseWindow::default();
        assert!(window.claim(0).is_none());
        let first = window.issue(test_lease_authority()).unwrap();
        let first_expiry = window.expires_at_ms;
        tokio::time::advance(Duration::from_secs(8)).await;
        assert_eq!(
            window
                .claim(first.sequence)
                .map(|lease| lease.expires_at_ms),
            Some(first_expiry)
        );
        assert!(window.claim(first.sequence).is_none());
        let second = window.issue(test_lease_authority()).unwrap();
        assert!(window.claim(first.sequence).is_none());
        tokio::time::advance(LEASE).await;
        assert!(window.claim(second.sequence).is_none());
    }

    #[tokio::test]
    async fn withdrawals_persist_but_old_sessions_and_replays_are_rejected() {
        use openshell_core::proto::datamodel::v1::ObjectMeta;
        let mut state = crate::grpc::test_support::test_server_state().await;
        Arc::get_mut(&mut state)
            .unwrap()
            .config
            .supervisor_app_listener
            .enabled = true;
        let sandbox = Sandbox {
            metadata: Some(ObjectMeta {
                id: "sandbox".into(),
                name: "demo".into(),
                workspace: "default".into(),
                annotations: [(
                    COMPUTE_RUNTIME_IDENTITY_ANNOTATION.into(),
                    "runtime-a".into(),
                )]
                .into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        state.store.put_message(&sandbox).await.unwrap();
        let owners = SupervisorOwnerIndex::new(state.store.clone(), OWNER_TTL);
        let first = owners
            .publish(
                "sandbox",
                "session-a",
                "instance",
                1,
                "replica-a",
                "local://replica-a",
            )
            .await
            .unwrap();
        let report = SupervisorServiceAdvertisement {
            lease_sequence: 1,
            ..Default::default()
        };
        let expires = current_time_ms() + 10_000;
        accept(&state, &first, &report, expires).await.unwrap();
        let stored = state
            .store
            .get(OBJECT_TYPE, "service-installation:sandbox")
            .await
            .unwrap()
            .unwrap();
        let installation: Installation = serde_json::from_slice(&stored.payload).unwrap();
        assert_eq!(installation.session_id, "session-a");
        assert!(installation.routes.is_empty());
        assert!(!is_current(&state, &installation).await.unwrap());
        assert_eq!(
            accept(&state, &first, &report, expires)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::FailedPrecondition
        );
        let second = owners
            .publish(
                "sandbox",
                "session-b",
                "instance",
                2,
                "replica-b",
                "local://replica-b",
            )
            .await
            .unwrap();
        let later = SupervisorServiceAdvertisement {
            lease_sequence: 2,
            ..Default::default()
        };
        assert!(accept(&state, &first, &later, expires).await.is_err());
        accept(&state, &second, &report, expires).await.unwrap();
        assert!(
            accept(&state, &second, &later, current_time_ms() - 1)
                .await
                .is_err()
        );
        state.store.close().await;
        assert_eq!(
            accept(&state, &second, &later, expires)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unavailable
        );
    }

    pub async fn installed_fixture()
    -> (Arc<ServerState>, OwnerGuard, SupervisorServiceAdvertisement) {
        installed_fixture_for_gateway(
            "gateway-a",
            openshell_core::config::ServiceHostnameFormat::Readable,
        )
        .await
    }

    pub async fn installed_fixture_for_gateway(
        gateway: &str,
        format: openshell_core::config::ServiceHostnameFormat,
    ) -> (Arc<ServerState>, OwnerGuard, SupervisorServiceAdvertisement) {
        use openshell_core::proto::datamodel::v1::ObjectMeta;
        use openshell_core::proto::{SandboxPolicy, SandboxSpec, ServiceEndpoint};
        let endpoint = openshell_core::proto::compute::v1::SupervisorAppEndpoint {
            host: "10.0.0.7".into(),
            port: 9443,
            runtime_identity: "runtime-a".into(),
            ..Default::default()
        };
        let driver = Arc::new(crate::compute::NoopTestDriver::with_app_endpoint(endpoint));
        let mut state = crate::grpc::test_support::test_server_state_with_compute_driver(
            "test",
            driver.clone(),
        )
        .await;
        {
            let inner = Arc::get_mut(&mut state).unwrap();
            inner.compute = inner
                .compute
                .clone()
                .with_app_endpoint_resolver(Some(driver));
        }
        Arc::get_mut(&mut state)
            .unwrap()
            .config
            .supervisor_app_listener = openshell_core::app_listener::AppListenerConfig {
            public_url: None,
            enabled: true,
            port: 9443,
            domain: "services.example.com".into(),
        };
        let inner = Arc::get_mut(&mut state).unwrap();
        inner.config.name = gateway.into();
        inner.config.service_routing.service_hostname_format = format;
        inner.admin_role = "openshell-admin".into();
        let sandbox = Sandbox {
            metadata: Some(ObjectMeta {
                id: "sandbox".into(),
                name: "demo".into(),
                workspace: "default".into(),
                annotations: [(
                    COMPUTE_RUNTIME_IDENTITY_ANNOTATION.into(),
                    "runtime-a".into(),
                )]
                .into(),
                ..Default::default()
            }),
            spec: Some(SandboxSpec {
                policy: Some(SandboxPolicy::default()),
                ..Default::default()
            }),
            ..Default::default()
        };
        state.store.put_message(&sandbox).await.unwrap();
        let endpoint = ServiceEndpoint {
            metadata: Some(ObjectMeta {
                id: "endpoint".into(),
                name: "demo--web".into(),
                workspace: "default".into(),
                labels: [("sandbox".into(), "demo".into())].into(),
                ..Default::default()
            }),
            sandbox_id: "sandbox".into(),
            sandbox: "demo".into(),
            name: "web".into(),
            target_port: 8080,
            domain: true,
            authorization_mode: 1,
        };
        state.store.put_message(&endpoint).await.unwrap();
        let owner = SupervisorOwnerIndex::new(state.store.clone(), OWNER_TTL)
            .publish(
                "sandbox",
                "session",
                "instance",
                1,
                "replica",
                "local://replica",
            )
            .await
            .unwrap();
        let config = super::super::policy::build_sandbox_config_snapshot(&state, &sandbox)
            .await
            .unwrap();
        assert!(
            config.configuration_admitted,
            "{}",
            config.configuration_error
        );
        let report = SupervisorServiceAdvertisement {
            service_domain: "services.example.com".into(),
            lease_sequence: 1,
            configuration_instance_id: config.configuration_instance_id,
            config_revision: config.config_revision,
            routes: config.service_routes,
        };
        (state, owner, report)
    }

    #[tokio::test]
    async fn accepted_installs_use_trusted_endpoints_and_withdraw_on_declaration_or_owner_change() {
        let (state, owner, mut report) = installed_fixture().await;
        accept(&state, &owner, &report, current_time_ms() + 10_000)
            .await
            .unwrap();
        let stored = state
            .store
            .get(OBJECT_TYPE, "service-installation:sandbox")
            .await
            .unwrap()
            .unwrap();
        let installation: Installation = serde_json::from_slice(&stored.payload).unwrap();
        assert_eq!(installation.host, "10.0.0.7");
        assert_eq!(installation.port, 9443);
        assert!(is_current(&state, &installation).await.unwrap());
        report.lease_sequence += 1;
        report.routes[0].resource_version += 1;
        assert!(
            accept(&state, &owner, &report, current_time_ms() + 10_000)
                .await
                .is_err()
        );
        let mut endpoint = state
            .store
            .get_message::<openshell_core::proto::ServiceEndpoint>("endpoint")
            .await
            .unwrap()
            .unwrap();
        endpoint.target_port = 9090;
        state.store.put_message(&endpoint).await.unwrap();
        assert!(!is_current(&state, &installation).await.unwrap());
        let index = SupervisorOwnerIndex::new(state.store.clone(), OWNER_TTL);
        index
            .publish(
                "sandbox",
                "replacement",
                "instance",
                2,
                "other-replica",
                "local://other",
            )
            .await
            .unwrap();
        assert!(
            accept(&state, &owner, &report, current_time_ms() + 10_000)
                .await
                .is_err()
        );
    }

    #[test]
    fn reports_cannot_broaden_or_partially_install_declarations() {
        let declared = route();
        let mut report = SupervisorServiceAdvertisement {
            routes: vec![declared.clone()],
            ..Default::default()
        };
        validate_routes(&report, std::slice::from_ref(&declared)).unwrap();
        report.routes[0].target_port = 9090;
        assert!(validate_routes(&report, std::slice::from_ref(&declared)).is_err());
        report.routes = vec![declared.clone(), declared.clone()];
        assert!(validate_routes(&report, std::slice::from_ref(&declared)).is_err());
        report.routes = vec![declared.clone()];
        let mut second = declared.clone();
        second.endpoint_id = "second".into();
        second.name = "other".into();
        assert!(validate_routes(&report, &[declared.clone(), second]).is_err());
        report.routes.clear();
        validate_routes(&report, &[declared]).unwrap();
    }
}
