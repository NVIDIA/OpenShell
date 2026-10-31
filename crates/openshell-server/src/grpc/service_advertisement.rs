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
use crate::persistence::{ObjectCursor, WriteCondition, current_time_ms};
use crate::supervisor_owner::{OWNER_TTL, OwnerGuard, SupervisorOwnerIndex};

pub const OBJECT_TYPE: &str = "supervisor_service_installation";
pub const LEASE: Duration = Duration::from_secs(15);
pub const REPORT_INTERVAL: Duration = Duration::from_secs(5);
const MAX_ROUTES: usize = 1024;

/// A challenge is session-local and single-use. Its monotonic deadline starts
/// before transmission, so delayed answers never receive a fresh receipt lease.
pub struct LeaseWindow {
    sequence: u64,
    deadline: tokio::time::Instant,
    expires_at_ms: i64,
    answered: bool,
}

impl Default for LeaseWindow {
    fn default() -> Self {
        Self {
            sequence: 0,
            deadline: tokio::time::Instant::now(),
            expires_at_ms: 0,
            answered: true,
        }
    }
}

impl LeaseWindow {
    pub fn issue(&mut self) -> Option<openshell_core::proto::ServiceRouteLease> {
        self.sequence = self.sequence.checked_add(1)?;
        self.deadline = tokio::time::Instant::now() + LEASE;
        self.expires_at_ms =
            current_time_ms() + i64::try_from(LEASE.as_millis()).expect("bounded lease");
        self.answered = false;
        Some(openshell_core::proto::ServiceRouteLease {
            sequence: self.sequence,
            duration: openshell_core::time::duration_from_std(LEASE).ok(),
            expires_at: openshell_core::time::timestamp_from_millis(self.expires_at_ms).ok(),
        })
    }

    pub fn claim(&mut self, sequence: u64) -> Option<i64> {
        if self.answered
            || sequence != self.sequence
            || tokio::time::Instant::now() >= self.deadline
        {
            return None;
        }
        self.answered = true;
        Some(self.expires_at_ms)
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

async fn current_endpoint(
    state: &ServerState,
    sandbox: &Sandbox,
    owner: &OwnerGuard,
) -> Result<Option<openshell_core::proto::compute::v1::SupervisorAppEndpoint>, Status> {
    if !sandbox_term_matches(sandbox, owner.auth_epoch) {
        return Ok(None);
    }
    let Some(endpoint) = state.compute.supervisor_app_endpoint(sandbox).await? else {
        return Ok(None);
    };
    if !endpoint.pool_route.is_empty()
        && (owner
            .auth_epoch
            .map_or(0, openshell_core::jwt::CredentialEpoch::get)
            != endpoint.ownership_epoch
            || !crate::supervisor_pool::app_endpoint_current(&state.store, sandbox, &endpoint)
                .await
                .map_err(|_| Status::unavailable("pool application authority unavailable"))?)
    {
        return Ok(None);
    }
    Ok(Some(endpoint))
}

/// A serving lease is issued only while the session still has durable runtime
/// authority. This check is repeated for every lease, independently of config.
pub async fn may_lease(state: &ServerState, owner: &OwnerGuard) -> Result<bool, Status> {
    let Some(sandbox) = state
        .store
        .get_message::<Sandbox>(&owner.sandbox_id)
        .await
        .map_err(|_| Status::unavailable("sandbox storage unavailable"))?
    else {
        return Ok(false);
    };
    if sandbox
        .metadata
        .as_ref()
        .is_some_and(|m| m.deletion_time.is_some())
    {
        return Ok(false);
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
        return Ok(false);
    }
    Ok(current_endpoint(state, &sandbox, owner).await?.is_some())
}

pub async fn accept(
    state: &Arc<ServerState>,
    owner: &OwnerGuard,
    report: &SupervisorServiceAdvertisement,
    expires_at_ms: i64,
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
        let endpoint = current_endpoint(state, &sandbox, owner)
            .await?
            .ok_or_else(|| {
                Status::failed_precondition("trusted supervisor app endpoint unavailable")
            })?;
        if endpoint.runtime_identity != record.runtime_identity
            || endpoint.port != u32::from(state.config.supervisor_app_listener.port)
            || endpoint.host.parse::<std::net::IpAddr>().is_err()
        {
            return Err(Status::failed_precondition(
                "driver endpoint does not match current runtime",
            ));
        }
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
                    .list_by_type_after(OBJECT_TYPE, cursor.as_ref(), 128)
                    .await
                    .map_err(|_| ())?;
                let next = (page.len() == 128)
                    .then(|| ObjectCursor::from(page.last().expect("full page")));
                for record in page {
                    let installation: Installation =
                        serde_json::from_slice(&record.payload).map_err(|_| ())?;
                    if installation.expires_at_ms <= current_time_ms()
                        || matches!(is_current(&state, &installation).await, Ok(false))
                    {
                        // Conditional deletion cannot erase a concurrent renewal.
                        let _ = state
                            .store
                            .delete_if(OBJECT_TYPE, &record.id, record.resource_version)
                            .await;
                    }
                }
                Ok::<_, ()>(next)
            };
            tokio::select! {
                _ = shutdown.changed() => return,
                result = tokio::time::timeout(Duration::from_secs(5), sweep) => {
                    if let Ok(Ok(next)) = result { cursor = next; }
                }
            }
        }
    });
}

#[cfg(test)]
pub mod tests {
    use super::*;

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
        let first = window.issue().unwrap();
        let first_expiry = window.expires_at_ms;
        tokio::time::advance(Duration::from_secs(8)).await;
        assert_eq!(window.claim(first.sequence), Some(first_expiry));
        assert!(window.claim(first.sequence).is_none());
        let second = window.issue().unwrap();
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
