// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded, full-replacement workspace views of accepted app installations.

use std::sync::Arc;
use std::time::Duration;

use openshell_core::proto::{
    DiscoveredServiceRoute, GetServiceRouteSnapshotRequest, GetServiceRouteSnapshotResponse,
    Sandbox, ServiceRouteEndpoint, ServiceRouteSnapshot, WatchServiceRoutesRequest,
    WatchServiceRoutesResponse,
};
use openshell_core::{ObjectName, ObjectWorkspace};
use prost::Message as _;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use super::service_advertisement::{Installation, OBJECT_TYPE, current_routes};
use crate::ServerState;
use crate::auth::principal::Principal;
use crate::auth::workspace_authz::{
    MinWorkspaceRole, authorize_workspace, selected_workspace_name,
};
use crate::persistence::{ObjectCursor, ObjectRecord, current_time_ms};

const MAX_RECORDS: usize = 1000;
const MAX_ROUTES: usize = 4096;
const MAX_BYTES: usize = 4 * 1024 * 1024;
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(10);
const WATCH_LIFETIME: Duration = Duration::from_mins(1);
const REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const SEND_TIMEOUT: Duration = Duration::from_secs(5);
pub type RouteWatchStream = ReceiverStream<Result<WatchServiceRoutesResponse, Status>>;

// Per-process limits. Key maps retain only live permits; callers cannot grow
// them indefinitely by varying subjects or workspace names.
const MAX_UNARY: usize = 16;
const MAX_COLLECTIONS: usize = 4;
const MAX_CACHED_WORKSPACES: usize = 16;
const WATCHES_PER_PRINCIPAL: usize = 4;
const WATCHES_PER_WORKSPACE: usize = 16;
type CachedView = Option<(tokio::time::Instant, Result<ServiceRouteSnapshot, Status>)>;
type CacheSlot = Arc<tokio::sync::Mutex<CachedView>>;

#[derive(Debug)]
pub struct DiscoveryState {
    unary: Arc<tokio::sync::Semaphore>,
    collections: Arc<tokio::sync::Semaphore>,
    shares: std::sync::Mutex<
        std::collections::HashMap<String, std::sync::Weak<tokio::sync::Semaphore>>,
    >,
    cache: tokio::sync::Mutex<std::collections::HashMap<String, (tokio::time::Instant, CacheSlot)>>,
}

impl Default for DiscoveryState {
    fn default() -> Self {
        Self {
            unary: Arc::new(tokio::sync::Semaphore::new(MAX_UNARY)),
            collections: Arc::new(tokio::sync::Semaphore::new(MAX_COLLECTIONS)),
            shares: std::sync::Mutex::default(),
            cache: tokio::sync::Mutex::default(),
        }
    }
}

fn principal_key(principal: &Principal) -> Result<String, Status> {
    match principal {
        Principal::User(user) => Ok(format!(
            "user:{:?}:{}",
            user.identity.provider, user.identity.subject
        )),
        Principal::Operator(operator) => Ok(format!("operator:{}", operator.certificate_sha256)),
        _ => Err(Status::permission_denied(
            "service discovery requires a user/API identity",
        )),
    }
}

impl DiscoveryState {
    fn share(
        &self,
        key: String,
        limit: usize,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, Status> {
        let mut shares = self
            .shares
            .lock()
            .map_err(|_| Status::internal("discovery limits unavailable"))?;
        shares.retain(|_, value| value.strong_count() > 0);
        let semaphore = shares
            .get(&key)
            .and_then(std::sync::Weak::upgrade)
            .unwrap_or_else(|| {
                let semaphore = Arc::new(tokio::sync::Semaphore::new(limit));
                shares.insert(key, Arc::downgrade(&semaphore));
                semaphore
            });
        semaphore
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("discovery caller or workspace limit exceeded"))
    }

    pub(crate) fn admit(
        &self,
        principal: &Principal,
        workspaces: &[String],
        watch: bool,
    ) -> Result<Vec<tokio::sync::OwnedSemaphorePermit>, Status> {
        let kind = if watch { "watch" } else { "snapshot" };
        let mut permits = Vec::new();
        if !watch {
            permits.push(
                self.unary.clone().try_acquire_owned().map_err(|_| {
                    Status::resource_exhausted("too many discovery snapshot requests")
                })?,
            );
        }
        permits.push(self.share(
            format!("{kind}:{}", principal_key(principal)?),
            WATCHES_PER_PRINCIPAL,
        )?);
        for workspace in workspaces {
            permits.push(self.share(
                format!("{kind}:workspace:{workspace}"),
                if watch { WATCHES_PER_WORKSPACE } else { 8 },
            )?);
        }
        Ok(permits)
    }

    async fn slot(&self, workspace: &str) -> Result<CacheSlot, Status> {
        let mut cache = self.cache.lock().await;
        let now = tokio::time::Instant::now();
        if let Some((used, slot)) = cache.get_mut(workspace) {
            *used = now;
            return Ok(slot.clone());
        }
        if cache.len() >= MAX_CACHED_WORKSPACES {
            let oldest = cache
                .iter()
                .filter(|(_, (_, slot))| Arc::strong_count(slot) == 1)
                .min_by_key(|(_, (used, _))| *used)
                .map(|(name, _)| name.clone());
            if let Some(oldest) = oldest {
                cache.remove(&oldest);
            } else {
                return Err(Status::resource_exhausted("discovery cache busy"));
            }
        }
        let slot = Arc::new(tokio::sync::Mutex::new(None));
        cache.insert(workspace.to_string(), (now, slot.clone()));
        Ok(slot)
    }
}

async fn cached_snapshot(
    state: &ServerState,
    workspace: &str,
) -> Result<ServiceRouteSnapshot, Status> {
    tokio::time::timeout(SNAPSHOT_TIMEOUT, async {
        let slot = state.discovery.slot(workspace).await?;
        let mut cached = slot.lock().await;
        if let Some((collected, result)) = cached.as_ref()
            && collected.elapsed() < REFRESH_INTERVAL
        {
            // A cached route must never outlive the independently enforced lease.
            let snapshot = result.clone()?;
            return if snapshot.routes.iter().all(route_is_live) {
                Ok(snapshot)
            } else {
                finish_snapshot(snapshot.routes)
            };
        }
        let _permit = state
            .discovery
            .collections
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("too many discovery collections"))?;
        let result = snapshot(state, workspace).await;
        *cached = Some((tokio::time::Instant::now(), result.clone()));
        result
    })
    .await
    .map_err(|_| Status::unavailable("service discovery collection timed out"))?
}

/// Captured only by discovery streams; credentials are never logged or persisted.
#[derive(Clone)]
pub struct BearerRecheck {
    pub(crate) chain: crate::auth::authenticator::AuthenticatorChain,
    pub(crate) headers: http::HeaderMap,
    pub(crate) policy: Option<crate::auth::authz::AuthzPolicy>,
    pub(crate) path: String,
}

impl BearerRecheck {
    pub(crate) async fn check(&self, original: &Principal) -> Result<Principal, Status> {
        use crate::auth::authenticator::Authentication;
        let outcome = self
            .chain
            .authenticate(&self.headers, &self.path)
            .await
            .map_err(|e| e.status)?;
        let Authentication::Accepted(principal) = outcome else {
            return Err(Status::unauthenticated(
                "discovery credential is no longer valid",
            ));
        };
        if principal_key(&principal)? != principal_key(original)? {
            return Err(Status::unauthenticated("discovery identity changed"));
        }
        if let (Some(policy), Principal::User(user)) = (&self.policy, &principal) {
            policy
                .check(&user.identity, &self.path)
                .map_err(|e| e.status)?;
        }
        Ok(principal)
    }
}

async fn authorize(
    state: &ServerState,
    principal: &Principal,
    workspace: &str,
) -> Result<(), Status> {
    if !matches!(principal, Principal::User(_) | Principal::Operator(_)) {
        return Err(Status::permission_denied(
            "service discovery requires a user/API identity",
        ));
    }
    authorize_workspace(
        &state.store,
        &state.admin_role,
        principal,
        workspace,
        MinWorkspaceRole::User,
    )
    .await?;
    super::workspace::resolve_workspace(state.store.as_ref(), workspace)
        .await?
        .ensure_active()?;
    Ok(())
}

fn require_enabled(state: &ServerState) -> Result<(), Status> {
    if !state.config.supervisor_app_listener.enabled {
        return Err(Status::failed_precondition(
            "service discovery requires the supervisor app listener to be enabled",
        ));
    }
    Ok(())
}

pub async fn get_snapshot(
    state: &Arc<ServerState>,
    request: Request<GetServiceRouteSnapshotRequest>,
) -> Result<Response<GetServiceRouteSnapshotResponse>, Status> {
    let mut principal = super::extract_principal(&request)?;
    require_enabled(state)?;
    let workspace = selected_workspace_name(request.get_ref().workspace_scope.as_ref())?;
    authorize(state, &principal, workspace).await?;
    let _permits = state
        .discovery
        .admit(&principal, &[workspace.to_string()], false)?;
    let snapshot = cached_snapshot(state, workspace).await?;
    if let Some(recheck) = request.extensions().get::<BearerRecheck>() {
        principal = recheck.check(&principal).await?;
    }
    authorize(state, &principal, workspace).await?;
    Ok(Response::new(GetServiceRouteSnapshotResponse {
        snapshot: Some(snapshot),
    }))
}

pub async fn watch(
    state: &Arc<ServerState>,
    request: Request<WatchServiceRoutesRequest>,
) -> Result<Response<RouteWatchStream>, Status> {
    let mut principal = super::extract_principal(&request)?;
    require_enabled(state)?;
    let workspace =
        selected_workspace_name(request.get_ref().workspace_scope.as_ref())?.to_string();
    authorize(state, &principal, &workspace).await?;
    let shares = state
        .discovery
        .admit(&principal, std::slice::from_ref(&workspace), true)?;
    let recheck = request.extensions().get::<BearerRecheck>().cloned();
    let permit = state
        .discovery_watches
        .clone()
        .try_acquire_owned()
        .map_err(|_| Status::resource_exhausted("too many service discovery watches"))?;
    let initial = cached_snapshot(state, &workspace).await?;
    if let Some(recheck) = &recheck {
        principal = recheck.check(&principal).await?;
    }
    authorize(state, &principal, &workspace).await?;
    let mut revision = initial.revision.clone();
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tx.try_send(Ok(WatchServiceRoutesResponse {
        snapshot: Some(initial),
    }))
    .map_err(|_| Status::cancelled("discovery client closed"))?;
    let state = state.clone();
    tokio::spawn(async move {
        let _permit = permit;
        let _shares = shares;
        let run = async {
            let mut interval = tokio::time::interval(REFRESH_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                tokio::select! {
                    () = tx.closed() => return,
                    _ = interval.tick() => {}
                }
                let refresh = async {
                    authorize(&state, &principal, &workspace).await?;
                    let snapshot = cached_snapshot(&state, &workspace).await?;
                    if let Some(recheck) = &recheck {
                        principal = recheck.check(&principal).await?;
                    }
                    authorize(&state, &principal, &workspace).await?;
                    Ok::<_, Status>(snapshot)
                };
                let result = tokio::select! {
                    () = tx.closed() => return,
                    result = refresh => result,
                };
                let message = match result {
                    Ok(next) if next.revision == revision => continue,
                    Ok(next) => {
                        revision.clone_from(&next.revision);
                        Ok(WatchServiceRoutesResponse {
                            snapshot: Some(next),
                        })
                    }
                    Err(error) => Err(error),
                };
                let failed = message.is_err();
                let sent = tokio::select! {
                    () = tx.closed() => return,
                    result = tokio::time::timeout(SEND_TIMEOUT, tx.send(message)) => result,
                };
                if failed || !matches!(sent, Ok(Ok(()))) {
                    return;
                }
            }
        };
        let _ = tokio::time::timeout(WATCH_LIFETIME, run).await;
    });
    Ok(Response::new(ReceiverStream::new(rx)))
}

async fn records(state: &ServerState, workspace: &str) -> Result<Vec<ObjectRecord>, Status> {
    let mut records = Vec::new();
    let mut cursor: Option<ObjectCursor> = None;
    let mut bytes = 0usize;
    loop {
        let page = state
            .store
            .list_after(OBJECT_TYPE, workspace, cursor.as_ref(), 128)
            .await
            .map_err(|_| Status::unavailable("service installation storage unavailable"))?;
        for record in &page {
            bytes = bytes.saturating_add(record.payload.len());
            if bytes > MAX_BYTES || records.len() + page.len() > MAX_RECORDS {
                return Err(Status::resource_exhausted(
                    "service discovery collection limit exceeded",
                ));
            }
        }
        let full = page.len() == 128;
        cursor = page.last().map(ObjectCursor::from);
        records.extend(page);
        if !full {
            break;
        }
    }
    Ok(records)
}

pub async fn snapshot(
    state: &ServerState,
    workspace: &str,
) -> Result<ServiceRouteSnapshot, Status> {
    tokio::time::timeout(SNAPSHOT_TIMEOUT, collect(state, workspace))
        .await
        .map_err(|_| Status::unavailable("service discovery collection timed out"))?
}

async fn collect(state: &ServerState, workspace: &str) -> Result<ServiceRouteSnapshot, Status> {
    // A bounded per-installation validated view, not a cross-resource transaction.
    // Lease renewals must not invalidate an otherwise current installation.
    let before = records(state, workspace).await?;
    let mut routes = Vec::new();
    for object in &before {
        let installation: Installation = serde_json::from_slice(&object.payload)
            .map_err(|_| Status::internal("invalid service installation record"))?;
        let Some(installed_routes) = current_routes(state, &installation).await? else {
            continue;
        };
        let sandbox = state
            .store
            .get_message::<Sandbox>(&installation.sandbox_id)
            .await
            .map_err(|_| Status::unavailable("sandbox storage unavailable"))?
            .ok_or_else(|| Status::unavailable("sandbox changed during discovery"))?;
        if sandbox.object_workspace() != workspace {
            return Err(Status::internal("installation workspace mismatch"));
        }
        for (bytes, route) in installation.routes.iter().zip(installed_routes) {
            let label = crate::service_routing::service_route_readable_label(
                workspace,
                sandbox.object_name(),
                &route.name,
            );
            let hostname = format!("{label}.{}", installation.service_domain);
            let version = installation_version(&installation, bytes)?;
            routes.push(DiscoveredServiceRoute {
                workspace: workspace.to_string(),
                sandbox: sandbox.object_name().to_string(),
                name: route.name,
                hostname,
                endpoint: Some(ServiceRouteEndpoint {
                    host: installation.host.clone(),
                    port: installation.port,
                }),
                installation_version: version,
                declaration_revision: route.resource_version,
                expires_at: Some(
                    openshell_core::time::timestamp_from_millis(installation.expires_at_ms)
                        .map_err(|_| Status::internal("invalid installation expiry"))?,
                ),
            });
            if routes.len() > MAX_ROUTES {
                return Err(Status::resource_exhausted(
                    "too many discovered service routes",
                ));
            }
        }
    }
    finish_snapshot(routes)
}

fn route_is_live(route: &DiscoveredServiceRoute) -> bool {
    route
        .expires_at
        .as_ref()
        .and_then(|t| openshell_core::time::timestamp_to_millis(t).ok())
        .is_some_and(|t| t > current_time_ms())
}

fn finish_snapshot(
    mut routes: Vec<DiscoveredServiceRoute>,
) -> Result<ServiceRouteSnapshot, Status> {
    if routes.len() > MAX_ROUTES {
        return Err(Status::resource_exhausted(
            "too many discovered service routes",
        ));
    }
    routes.retain(route_is_live);
    routes.sort_by(|a, b| {
        (&a.workspace, &a.sandbox, &a.name).cmp(&(&b.workspace, &b.sandbox, &b.name))
    });
    let mut snapshot = ServiceRouteSnapshot {
        routes,
        revision: String::new(),
    };
    let bytes = snapshot.encode_to_vec();
    if bytes.len() > MAX_BYTES - 128 {
        return Err(Status::resource_exhausted(
            "service discovery response too large",
        ));
    }
    snapshot.revision = hex::encode(
        openshell_crypto::sha256(&bytes)
            .map_err(|_| Status::internal("snapshot fingerprint failed"))?,
    );
    Ok(snapshot)
}

fn installation_version(installation: &Installation, bytes: &[u8]) -> Result<String, Status> {
    let identity = serde_json::to_vec(&(
        "openshell-installation-v1",
        &installation.session_id,
        &installation.supervisor_instance_id,
        installation.connection_epoch,
        installation.ownership_epoch,
        &installation.pool_route,
        &installation.runtime_identity,
        &installation.configuration_instance_id,
        installation.config_revision,
        &installation.service_domain,
        &installation.host,
        installation.port,
        bytes,
    ))
    .map_err(|_| Status::internal("installation identity encoding failed"))?;
    let version = openshell_crypto::sha256(&identity)
        .map_err(|_| Status::internal("installation fingerprint failed"))?;
    Ok(hex::encode(version))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::service_advertisement::{accept, test_support::installed_fixture};
    use crate::grpc::test_support::authed_request;
    use tokio_stream::StreamExt as _;

    fn request() -> GetServiceRouteSnapshotRequest {
        GetServiceRouteSnapshotRequest {
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
        }
    }

    #[tokio::test]
    async fn disabled_listener_rejects_discovery_without_allocating_a_watch() {
        let (mut state, owner, report) = installed_fixture().await;
        // Persist a route first: disabling must reject discovery even with stored evidence.
        accept(&state, &owner, &report, current_time_ms() + 10_000)
            .await
            .unwrap();
        Arc::get_mut(&mut state)
            .unwrap()
            .config
            .supervisor_app_listener
            .enabled = false;
        let permits = state.discovery_watches.available_permits();
        let error = get_snapshot(&state, authed_request(request()))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(error.message().contains("app listener"));
        let error = watch(
            &state,
            authed_request(WatchServiceRoutesRequest {
                workspace_scope: request().workspace_scope,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(error.message().contains("app listener"));
        assert_eq!(state.discovery_watches.available_permits(), permits);
    }

    #[tokio::test]
    async fn snapshot_is_shared_between_gateway_states_and_rejects_expired_or_replaced_owners() {
        let (state, owner, report) = installed_fixture().await;
        accept(&state, &owner, &report, current_time_ms() + 10_000)
            .await
            .unwrap();
        let snapshot_a = get_snapshot(&state, authed_request(request()))
            .await
            .unwrap()
            .into_inner()
            .snapshot
            .unwrap();
        assert_eq!(snapshot_a.routes.len(), 1);
        let route = &snapshot_a.routes[0];
        assert_eq!(route.hostname, "default--demo--web.services.example.com");
        let mut routing_config = state.config.clone();
        routing_config.service_routing.base_domains = vec!["services.example.com".into()];
        let served = crate::service_routing::endpoint_url(
            &routing_config,
            &route.workspace,
            &route.sandbox,
            &route.name,
        )
        .unwrap();
        assert_eq!(
            url::Url::parse(&served).unwrap().host_str(),
            Some(route.hostname.as_str())
        );

        assert_eq!(route.endpoint.as_ref().unwrap().port, 9443);
        let compute = crate::compute::new_test_runtime(state.store.clone()).await;
        let mut replica = ServerState::new(
            state.config.clone(),
            state.store.clone(),
            compute,
            crate::sandbox_index::SandboxIndex::new(),
            crate::sandbox_watch::SandboxWatchBus::new(),
            crate::tracing_bus::TracingLogBus::new(),
            Arc::new(crate::supervisor_session::SupervisorSessionRegistry::new()),
            None,
        );
        replica.admin_role = state.admin_role.clone();
        replica.provider_profile_sources = state.provider_profile_sources.clone();
        let replica = Arc::new(replica);
        let snapshot_b = get_snapshot(&replica, authed_request(request()))
            .await
            .unwrap()
            .into_inner()
            .snapshot
            .unwrap();
        assert_eq!(snapshot_a, snapshot_b);
        crate::supervisor_owner::SupervisorOwnerIndex::new(
            state.store.clone(),
            crate::supervisor_owner::OWNER_TTL,
        )
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
        assert!(snapshot(&state, "default").await.unwrap().routes.is_empty());
        assert!(
            snapshot(&replica, "default")
                .await
                .unwrap()
                .routes
                .is_empty()
        );
    }

    #[tokio::test]
    async fn watch_reports_lease_only_renewal_then_withdrawal_and_releases_its_slot() {
        let (state, owner, mut report) = installed_fixture().await;
        accept(&state, &owner, &report, current_time_ms() + 10_000)
            .await
            .unwrap();
        let mut stream = watch(
            &state,
            authed_request(WatchServiceRoutesRequest {
                workspace_scope: request().workspace_scope,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        let first = stream.next().await.unwrap().unwrap().snapshot.unwrap();
        assert_eq!(state.discovery_watches.available_permits(), 31);
        report.lease_sequence = 2;
        accept(&state, &owner, &report, current_time_ms() + 14_000)
            .await
            .unwrap();
        let renewed = tokio::time::timeout(Duration::from_secs(3), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .snapshot
            .unwrap();
        assert_ne!(first.revision, renewed.revision);
        assert_eq!(
            first.routes[0].installation_version,
            renewed.routes[0].installation_version
        );
        assert_ne!(first.routes[0].expires_at, renewed.routes[0].expires_at);
        report.lease_sequence = 3;
        report.routes.clear();
        accept(&state, &owner, &report, current_time_ms() + 14_000)
            .await
            .unwrap();
        let withdrawn = tokio::time::timeout(Duration::from_secs(3), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .snapshot
            .unwrap();
        assert!(withdrawn.routes.is_empty());
        drop(stream);
        tokio::time::timeout(Duration::from_secs(2), async {
            while state.discovery_watches.available_permits() != 32 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn explicit_workspace_and_membership_are_required_and_watch_capacity_is_bounded() {
        let (state, _, _) = installed_fixture().await;
        assert_eq!(
            get_snapshot(
                &state,
                authed_request(GetServiceRouteSnapshotRequest::default())
            )
            .await
            .unwrap_err()
            .code(),
            tonic::Code::InvalidArgument
        );
        assert!(
            get_snapshot(
                &state,
                authed_request(GetServiceRouteSnapshotRequest {
                    workspace_scope: Some(openshell_core::proto::all_workspaces_selector())
                })
            )
            .await
            .is_err()
        );
        let mut outsider = authed_request(request());
        if let Some(Principal::User(user)) = outsider.extensions_mut().get_mut::<Principal>() {
            user.identity.roles = vec!["openshell-user".into()];
            user.identity.subject = "outsider".into();
        }
        assert_eq!(
            get_snapshot(&state, outsider).await.unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
        let mut anonymous = Request::new(request());
        anonymous.extensions_mut().insert(Principal::Anonymous);
        assert_eq!(
            get_snapshot(&state, anonymous).await.unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
        let _all = state
            .discovery_watches
            .clone()
            .acquire_many_owned(32)
            .await
            .unwrap();
        let error = watch(
            &state,
            authed_request(WatchServiceRoutesRequest {
                workspace_scope: request().workspace_scope,
            }),
        )
        .await
        .expect_err("capacity denied");
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
    }

    #[tokio::test]
    async fn watch_terminates_when_workspace_membership_is_revoked() {
        use openshell_core::proto::{ObjectMeta, WorkspaceMember, WorkspaceRole};
        let (state, _, _) = installed_fixture().await;
        let member = WorkspaceMember {
            metadata: Some(ObjectMeta {
                id: "discovery-member".into(),
                name: "discovery-reader".into(),
                workspace: "default".into(),
                ..Default::default()
            }),
            principal_subject: "discovery-reader".into(),
            role: WorkspaceRole::User.into(),
        };
        state.store.put_message(&member).await.unwrap();
        let mut request = authed_request(WatchServiceRoutesRequest {
            workspace_scope: request().workspace_scope,
        });
        if let Some(Principal::User(user)) = request.extensions_mut().get_mut::<Principal>() {
            user.identity.roles = vec!["openshell-user".into()];
            user.identity.subject = "discovery-reader".into();
        }
        let mut stream = watch(&state, request).await.unwrap().into_inner();
        assert!(stream.next().await.unwrap().is_ok());
        state
            .store
            .delete("workspace_member", "discovery-member")
            .await
            .unwrap();
        let error = tokio::time::timeout(Duration::from_secs(3), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
        assert!(stream.next().await.is_none());
        assert_eq!(state.discovery_watches.available_permits(), 32);
    }

    #[tokio::test]
    async fn quiet_watch_ends_at_lifetime_and_releases_capacity() {
        let (state, _, _) = installed_fixture().await;
        let mut stream = watch(
            &state,
            authed_request(WatchServiceRoutesRequest {
                workspace_scope: request().workspace_scope,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(stream.next().await.unwrap().is_ok());
        tokio::task::yield_now().await;
        tokio::time::pause();
        tokio::time::advance(WATCH_LIFETIME).await;
        assert!(
            tokio::time::timeout(WATCH_LIFETIME + REFRESH_INTERVAL, stream.next())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(state.discovery_watches.available_permits(), 32);
    }

    #[tokio::test]
    async fn collection_overflow_corruption_and_storage_failure_are_errors_not_empty_views() {
        let (state, _, _) = installed_fixture().await;
        state
            .store
            .put_if(
                OBJECT_TYPE,
                "broken",
                "broken",
                "default",
                b"not-json",
                None,
                crate::persistence::WriteCondition::MustCreate,
            )
            .await
            .unwrap();
        assert_eq!(
            snapshot(&state, "default").await.unwrap_err().code(),
            tonic::Code::Internal
        );
        state.store.delete(OBJECT_TYPE, "broken").await.unwrap();
        let bytes = vec![b'x'; MAX_BYTES + 1];
        state
            .store
            .put_if(
                OBJECT_TYPE,
                "oversized",
                "oversized",
                "default",
                &bytes,
                None,
                crate::persistence::WriteCondition::MustCreate,
            )
            .await
            .unwrap();
        assert_eq!(
            snapshot(&state, "default").await.unwrap_err().code(),
            tonic::Code::ResourceExhausted
        );
        state.store.delete(OBJECT_TYPE, "oversized").await.unwrap();
        state.store.close().await;
        assert_eq!(
            snapshot(&state, "default").await.unwrap_err().code(),
            tonic::Code::Unavailable
        );
    }
    fn user(subject: &str) -> Principal {
        let mut request = authed_request(());
        let Principal::User(mut user) = request.extensions_mut().remove::<Principal>().unwrap()
        else {
            panic!("user")
        };
        user.identity.subject = subject.into();
        Principal::User(user)
    }

    fn discovered() -> DiscoveredServiceRoute {
        DiscoveredServiceRoute {
            workspace: "default".into(),
            sandbox: "demo".into(),
            name: "web".into(),
            hostname: "default--demo--web.services.example.com".into(),
            expires_at: Some(
                openshell_core::time::timestamp_from_millis(current_time_ms() + 60_000).unwrap(),
            ),
            ..Default::default()
        }
    }

    #[test]
    fn route_and_wire_size_limits_reject_partial_views() {
        assert_eq!(
            finish_snapshot(vec![discovered(); MAX_ROUTES])
                .unwrap()
                .routes
                .len(),
            MAX_ROUTES
        );
        assert_eq!(
            finish_snapshot(vec![discovered(); MAX_ROUTES + 1])
                .unwrap_err()
                .code(),
            tonic::Code::ResourceExhausted
        );
        let mut route = discovered();
        route.hostname = "a".repeat(MAX_BYTES);
        assert_eq!(
            finish_snapshot(vec![route]).unwrap_err().code(),
            tonic::Code::ResourceExhausted
        );
    }

    #[tokio::test]
    async fn identity_fingerprint_changes_for_every_identity_input_but_not_renewal() {
        let (state, owner, report) = installed_fixture().await;
        accept(&state, &owner, &report, current_time_ms() + 10_000)
            .await
            .unwrap();
        let object = state
            .store
            .get(OBJECT_TYPE, "service-installation:sandbox")
            .await
            .unwrap()
            .unwrap();
        let installation: Installation = serde_json::from_slice(&object.payload).unwrap();
        let bytes = &installation.routes[0];
        let original = installation_version(&installation, bytes).unwrap();
        let mutations: &[fn(&mut Installation)] = &[
            |i| i.session_id.push('x'),
            |i| i.supervisor_instance_id.push('x'),
            |i| i.connection_epoch += 1,
            |i| i.ownership_epoch += 1,
            |i| i.pool_route.push('x'),
            |i| i.runtime_identity.push('x'),
            |i| i.configuration_instance_id.push('x'),
            |i| i.config_revision += 1,
            |i| i.service_domain.push('x'),
            |i| i.host.push('x'),
            |i| i.port += 1,
        ];
        for (index, mutate) in mutations.iter().enumerate() {
            let mut changed = installation.clone();
            mutate(&mut changed);
            assert_ne!(
                installation_version(&changed, bytes).unwrap(),
                original,
                "input {index}"
            );
        }
        let mut changed_bytes = bytes.clone();
        changed_bytes.push(0);
        assert_ne!(
            installation_version(&installation, &changed_bytes).unwrap(),
            original
        );
        let mut renewed = installation.clone();
        renewed.sequence += 1;
        renewed.expires_at_ms += 1000;
        assert_eq!(installation_version(&renewed, bytes).unwrap(), original);
    }

    #[tokio::test]
    async fn snapshot_cache_shares_collection_and_refreshes_after_a_tick() {
        let (state, owner, report) = installed_fixture().await;
        accept(&state, &owner, &report, current_time_ms() + 10_000)
            .await
            .unwrap();
        let first = cached_snapshot(&state, "default").await.unwrap();
        assert_eq!(first.routes.len(), 1);
        let busy = state
            .discovery
            .collections
            .clone()
            .acquire_many_owned(u32::try_from(MAX_COLLECTIONS).unwrap())
            .await
            .unwrap();
        let (a, b) = tokio::join!(
            cached_snapshot(&state, "default"),
            cached_snapshot(&state, "default")
        );
        assert_eq!(a.unwrap(), first);
        assert_eq!(b.unwrap(), first);
        assert_eq!(
            cached_snapshot(&state, "other").await.unwrap_err().code(),
            tonic::Code::ResourceExhausted
        );
        drop(busy);
        state
            .store
            .delete(OBJECT_TYPE, "service-installation:sandbox")
            .await
            .unwrap();
        tokio::time::sleep(REFRESH_INTERVAL).await;
        assert!(
            cached_snapshot(&state, "default")
                .await
                .unwrap()
                .routes
                .is_empty()
        );
    }

    #[tokio::test]
    async fn expired_cached_routes_are_never_returned() {
        let (state, _, _) = installed_fixture().await;
        let slot = state.discovery.slot("default").await.unwrap();
        let mut route = discovered();
        route.expires_at =
            Some(openshell_core::time::timestamp_from_millis(current_time_ms() - 1).unwrap());
        *slot.lock().await = Some((
            tokio::time::Instant::now(),
            Ok(ServiceRouteSnapshot {
                routes: vec![route],
                revision: "old".into(),
            }),
        ));
        assert!(
            cached_snapshot(&state, "default")
                .await
                .unwrap()
                .routes
                .is_empty()
        );
    }

    #[test]
    fn admission_bounds_each_principal_workspace_and_unary_pool_and_releases_capacity() {
        let state = DiscoveryState::default();
        let a = vec!["a".into()];
        let b = vec!["b".into()];
        let mut watches = Vec::new();
        for n in 0..4 {
            for _ in 0..4 {
                watches.push(state.admit(&user(&format!("u{n}")), &a, true).unwrap());
            }
        }
        assert_eq!(
            state.admit(&user("u0"), &b, true).unwrap_err().code(),
            tonic::Code::ResourceExhausted
        );
        assert_eq!(
            state.admit(&user("other"), &a, true).unwrap_err().code(),
            tonic::Code::ResourceExhausted
        );
        assert!(state.admit(&user("other"), &b, true).is_ok());
        drop(watches);
        assert!(state.admit(&user("u0"), &a, true).is_ok());
        let mut unary = Vec::new();
        for n in 0..MAX_UNARY {
            unary.push(
                state
                    .admit(&user(&format!("u{n}")), &[format!("w{n}")], false)
                    .unwrap(),
            );
        }
        assert_eq!(
            state.admit(&user("extra"), &b, false).unwrap_err().code(),
            tonic::Code::ResourceExhausted
        );
        drop(unary);
        assert!(state.admit(&user("extra"), &b, false).is_ok());
        assert!(state.shares.lock().unwrap().len() <= 4);
    }

    #[tokio::test]
    async fn collection_survives_concurrent_lease_renewals() {
        use crate::persistence::WriteCondition;
        let (state, owner, report) = installed_fixture().await;
        accept(&state, &owner, &report, current_time_ms() + 60_000)
            .await
            .unwrap();
        let record = state
            .store
            .get(OBJECT_TYPE, "service-installation:sandbox")
            .await
            .unwrap()
            .unwrap();
        // A scan of 50 installation records remains valid while their lease
        // resource versions change. Every record uses the live fixture's authority.
        for n in 0..50 {
            state
                .store
                .put_if(
                    OBJECT_TYPE,
                    &format!("renewal-{n:03}"),
                    &format!("renewal-{n:03}"),
                    "default",
                    &record.payload,
                    None,
                    WriteCondition::MustCreate,
                )
                .await
                .unwrap();
        }
        let (stop, mut stopped) = tokio::sync::watch::channel(false);
        let writes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let renew_state = state.clone();
        let count = writes.clone();
        let renew = tokio::spawn(async move {
            loop {
                for n in 0..50 {
                    let id = format!("renewal-{n:03}");
                    let record = renew_state
                        .store
                        .get(OBJECT_TYPE, &id)
                        .await
                        .unwrap()
                        .unwrap();
                    renew_state
                        .store
                        .put_if(
                            OBJECT_TYPE,
                            &id,
                            &id,
                            "default",
                            &record.payload,
                            None,
                            WriteCondition::MatchResourceVersion(record.resource_version),
                        )
                        .await
                        .unwrap();
                    count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                tokio::select! { _=stopped.changed()=>break, ()=tokio::time::sleep(Duration::from_millis(1))=>{} }
            }
        });
        for _ in 0..3 {
            assert_eq!(snapshot(&state, "default").await.unwrap().routes.len(), 51);
        }
        stop.send(true).unwrap();
        renew.await.unwrap();
        assert!(writes.load(std::sync::atomic::Ordering::Relaxed) > 50);
    }

    #[tokio::test]
    async fn watch_ends_when_its_bearer_expires_or_is_revoked() {
        use crate::auth::authenticator::{
            AuthFailureReason, AuthMechanism, AuthRejection, Authentication, Authenticator,
            AuthenticatorChain,
        };
        struct Credential {
            valid: Arc<std::sync::atomic::AtomicBool>,
            principal: Principal,
            reason: AuthFailureReason,
        }
        #[async_trait::async_trait]
        impl Authenticator for Credential {
            async fn authenticate(
                &self,
                _: &http::HeaderMap,
                _: &str,
            ) -> Result<Authentication, AuthRejection> {
                if self.valid.load(std::sync::atomic::Ordering::Relaxed) {
                    Ok(Authentication::Accepted(self.principal.clone()))
                } else {
                    Err(AuthRejection::new(
                        AuthMechanism::Oidc,
                        self.reason,
                        Status::unauthenticated("expired or revoked"),
                    ))
                }
            }
        }
        for reason in [
            AuthFailureReason::ExpiredCredential,
            AuthFailureReason::StaleIdentity,
        ] {
            let (state, _, _) = installed_fixture().await;
            let mut req = authed_request(WatchServiceRoutesRequest {
                workspace_scope: request().workspace_scope,
            });
            let principal = req.extensions().get::<Principal>().unwrap().clone();
            let valid = Arc::new(std::sync::atomic::AtomicBool::new(true));
            let recheck = BearerRecheck {
                chain: AuthenticatorChain::new(vec![Arc::new(Credential {
                    valid: valid.clone(),
                    principal: principal.clone(),
                    reason,
                })]),
                headers: http::HeaderMap::new(),
                policy: None,
                path: "/openshell.v1.ServiceDiscovery/WatchServiceRoutes".into(),
            };
            recheck.check(&principal).await.unwrap();
            req.extensions_mut().insert(recheck);
            let mut stream = watch(&state, req).await.unwrap().into_inner();
            assert!(stream.next().await.unwrap().is_ok());
            valid.store(false, std::sync::atomic::Ordering::Relaxed);
            let error = tokio::time::timeout(Duration::from_secs(3), stream.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap_err();
            assert_eq!(error.code(), tonic::Code::Unauthenticated);
            assert!(stream.next().await.is_none());
            assert_eq!(state.discovery_watches.available_permits(), 32);
            assert!(
                state
                    .discovery
                    .admit(&principal, &["default".into()], true)
                    .is_ok()
            );
        }
    }

    #[tokio::test]
    async fn record_count_limit_is_enforced_before_decoding() {
        let (state, _, _) = installed_fixture().await;
        for n in 0..=MAX_RECORDS {
            let id = format!("record-{n}");
            state
                .store
                .put_if(
                    OBJECT_TYPE,
                    &id,
                    &id,
                    "default",
                    b"{}",
                    None,
                    crate::persistence::WriteCondition::MustCreate,
                )
                .await
                .unwrap();
        }
        assert_eq!(
            snapshot(&state, "default").await.unwrap_err().code(),
            tonic::Code::ResourceExhausted
        );
    }

    #[tokio::test]
    async fn separate_discovery_service_serves_generated_clients_without_management_stubs() {
        use openshell_core::proto::{
            service_discovery_client::ServiceDiscoveryClient,
            service_discovery_server::ServiceDiscoveryServer,
        };
        let (state, owner, report) = installed_fixture().await;
        accept(&state, &owner, &report, current_time_ms() + 10_000)
            .await
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let service = ServiceDiscoveryServer::with_interceptor(
            super::super::OpenShellService::new(state),
            |mut req: Request<()>| {
                req.extensions_mut().insert(user("client"));
                Ok(req)
            },
        );
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        let _ = stopped.await;
                    },
                )
                .await
                .unwrap();
        });
        let mut client = ServiceDiscoveryClient::connect(format!("http://{address}"))
            .await
            .unwrap();
        let response = client
            .get_service_route_snapshot(request())
            .await
            .unwrap()
            .into_inner()
            .snapshot
            .unwrap();
        assert_eq!(
            response.routes[0].hostname,
            "default--demo--web.services.example.com"
        );
        let mut stream = client
            .watch_service_routes(WatchServiceRoutesRequest {
                workspace_scope: request().workspace_scope,
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            stream.message().await.unwrap().unwrap().snapshot.unwrap(),
            response
        );
        drop(stream);
        drop(client);
        stop.send(()).unwrap();
        server.await.unwrap();
        let pool =
            prost_reflect::DescriptorPool::decode(openshell_core::FILE_DESCRIPTOR_SET).unwrap();
        assert!(
            pool.get_service_by_name("openshell.v1.OpenShell")
                .unwrap()
                .methods()
                .all(|method| !matches!(
                    method.name(),
                    "GetServiceRouteSnapshot" | "WatchServiceRoutes"
                ))
        );
    }
    #[tokio::test]
    async fn watch_reauthorizes_the_refreshed_identity_instead_of_retaining_old_admin_roles() {
        use crate::auth::authenticator::{
            AuthRejection, Authentication, Authenticator, AuthenticatorChain,
        };
        struct MutableIdentity(Arc<std::sync::Mutex<Principal>>);
        #[async_trait::async_trait]
        impl Authenticator for MutableIdentity {
            async fn authenticate(
                &self,
                _: &http::HeaderMap,
                _: &str,
            ) -> Result<Authentication, AuthRejection> {
                Ok(Authentication::Accepted(self.0.lock().unwrap().clone()))
            }
        }
        let (state, _, _) = installed_fixture().await;
        let mut req = authed_request(WatchServiceRoutesRequest {
            workspace_scope: request().workspace_scope,
        });
        let identity = Arc::new(std::sync::Mutex::new(
            req.extensions().get::<Principal>().unwrap().clone(),
        ));
        req.extensions_mut().insert(BearerRecheck {
            chain: AuthenticatorChain::new(vec![Arc::new(MutableIdentity(identity.clone()))]),
            headers: http::HeaderMap::new(),
            policy: None,
            path: "/openshell.v1.ServiceDiscovery/WatchServiceRoutes".into(),
        });
        let mut stream = watch(&state, req).await.unwrap().into_inner();
        assert!(stream.next().await.unwrap().is_ok());
        if let Principal::User(user) = &mut *identity.lock().unwrap() {
            user.identity.roles = vec!["openshell-user".into()];
        }
        let error = tokio::time::timeout(Duration::from_secs(3), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
    }
}
