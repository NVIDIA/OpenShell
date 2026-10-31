// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded, full-replacement workspace views of accepted app installations.

use std::sync::Arc;
use std::time::Duration;

use openshell_core::proto::{
    DiscoveredServiceRoute, GetServiceRouteSnapshotRequest, GetServiceRouteSnapshotResponse,
    Sandbox, SandboxServiceRoute, ServiceRouteEndpoint, ServiceRouteSnapshot,
    WatchServiceRoutesRequest, WatchServiceRoutesResponse,
};
use openshell_core::{ObjectName, ObjectWorkspace};
use prost::Message as _;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use super::service_advertisement::{Installation, OBJECT_TYPE, is_current};
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

pub async fn get_snapshot(
    state: &Arc<ServerState>,
    request: Request<GetServiceRouteSnapshotRequest>,
) -> Result<Response<GetServiceRouteSnapshotResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let workspace = selected_workspace_name(request.get_ref().workspace_scope.as_ref())?;
    authorize(state, &principal, workspace).await?;
    Ok(Response::new(GetServiceRouteSnapshotResponse {
        snapshot: Some(snapshot(state, workspace).await?),
    }))
}

pub async fn watch(
    state: &Arc<ServerState>,
    request: Request<WatchServiceRoutesRequest>,
) -> Result<Response<RouteWatchStream>, Status> {
    let principal = super::extract_principal(&request)?;
    let workspace =
        selected_workspace_name(request.get_ref().workspace_scope.as_ref())?.to_string();
    authorize(state, &principal, &workspace).await?;
    let permit = state
        .discovery_watches
        .clone()
        .try_acquire_owned()
        .map_err(|_| Status::resource_exhausted("too many service discovery watches"))?;
    let initial = snapshot(state, &workspace).await?;
    let mut revision = initial.revision.clone();
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tx.try_send(Ok(WatchServiceRoutesResponse {
        snapshot: Some(initial),
    }))
    .map_err(|_| Status::cancelled("discovery client closed"))?;
    let state = state.clone();
    tokio::spawn(async move {
        let _permit = permit;
        let deadline = tokio::time::Instant::now() + WATCH_LIFETIME;
        let mut interval = tokio::time::interval(REFRESH_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            tokio::select! {
                () = tx.closed() => return,
                () = tokio::time::sleep_until(deadline) => return,
                _ = interval.tick() => {}
            }
            let refresh = async {
                authorize(&state, &principal, &workspace).await?;
                snapshot(&state, &workspace).await
            };
            let result = tokio::select! {
                () = tx.closed() => return,
                () = tokio::time::sleep_until(deadline) => return,
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
                () = tokio::time::sleep_until(deadline) => return,
                result = tokio::time::timeout(SEND_TIMEOUT, tx.send(message)) => result,
            };
            if failed || !matches!(sent, Ok(Ok(()))) {
                return;
            }
        }
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
    // Verify the installation collection did not change across the scan.
    // This is a bounded verified view, not a cross-resource transaction.
    for _ in 0..2 {
        let before = records(state, workspace).await?;
        let mut routes = Vec::new();
        for object in &before {
            let installation: Installation = serde_json::from_slice(&object.payload)
                .map_err(|_| Status::internal("invalid service installation record"))?;
            if !is_current(state, &installation).await? {
                continue;
            }
            let sandbox = state
                .store
                .get_message::<Sandbox>(&installation.sandbox_id)
                .await
                .map_err(|_| Status::unavailable("sandbox storage unavailable"))?
                .ok_or_else(|| Status::unavailable("sandbox changed during discovery"))?;
            if sandbox.object_workspace() != workspace {
                return Err(Status::internal("installation workspace mismatch"));
            }
            for bytes in &installation.routes {
                let route = SandboxServiceRoute::decode(bytes.as_slice())
                    .map_err(|_| Status::internal("invalid installed service route"))?;
                let hostname = if route.application_hostname.is_empty() {
                    // Legacy reports can only be current against legacy configuration.
                    state.config.supervisor_app_listener.service_hostname(
                        workspace,
                        sandbox.object_name(),
                        &route.name,
                        state.config.service_routing_discriminator(),
                    )
                } else {
                    route.application_hostname.clone()
                };
                let label = hostname
                    .strip_suffix(&format!(".{}", installation.service_domain))
                    .ok_or_else(|| Status::internal("installed hostname domain mismatch"))?;
                if label.is_empty() || label.len() > 63 || label.contains('.') {
                    return Err(Status::failed_precondition(
                        "service hostname exceeds DNS label limit",
                    ));
                }
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
                routes.push(DiscoveredServiceRoute {
                    workspace: workspace.to_string(),
                    sandbox: sandbox.object_name().to_string(),
                    name: route.name,
                    hostname,
                    endpoint: Some(ServiceRouteEndpoint {
                        host: installation.host.clone(),
                        port: installation.port,
                    }),
                    installation_version: hex::encode(version),
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
        let after = records(state, workspace).await?;
        if before
            .iter()
            .map(|r| (&r.id, r.resource_version))
            .ne(after.iter().map(|r| (&r.id, r.resource_version)))
        {
            continue;
        }
        routes.retain(|route| {
            route
                .expires_at
                .as_ref()
                .and_then(|t| openshell_core::time::timestamp_to_millis(t).ok())
                .is_some_and(|t| t > current_time_ms())
        });
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
        return Ok(snapshot);
    }
    Err(Status::unavailable(
        "service installations changed during collection; retry snapshot",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::service_advertisement::{accept, tests::installed_fixture};
    use crate::grpc::test_support::authed_request;
    use tokio_stream::StreamExt as _;

    fn request() -> GetServiceRouteSnapshotRequest {
        GetServiceRouteSnapshotRequest {
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
        }
    }

    #[tokio::test]
    async fn hashed_urls_discovery_and_installed_routes_use_the_same_gateway_identity() {
        use super::super::service_advertisement::tests::installed_fixture_for_gateway;
        use openshell_core::config::ServiceHostnameFormat;
        let (mut state, owner, report) =
            installed_fixture_for_gateway("gateway-a", ServiceHostnameFormat::Hashed).await;
        Arc::get_mut(&mut state)
            .unwrap()
            .config
            .supervisor_app_listener
            .public_url = Some("https://services.example.com:10443".into());
        accept(&state, &owner, &report, current_time_ms() + 10_000)
            .await
            .unwrap();
        let first = snapshot(&state, "default").await.unwrap();
        let hostname = &first.routes[0].hostname;
        let label = crate::service_routing::service_route_hash_label(
            "gateway-a",
            "default",
            "demo",
            Some("web"),
        );
        assert_eq!(*hostname, format!("{label}.services.example.com"));
        assert_eq!(*hostname, report.routes[0].application_hostname);
        let endpoint = state
            .store
            .get_message::<openshell_core::proto::ServiceEndpoint>("endpoint")
            .await
            .unwrap()
            .unwrap();
        let mut response = openshell_core::proto::ServiceEndpointResponse {
            endpoint: Some(endpoint),
            ..Default::default()
        };
        super::super::service::refresh_response_urls(&state, &mut response);
        assert_eq!(
            response.application_url,
            format!("https://{hostname}:10443/")
        );
        assert_eq!(response.url, response.application_url);

        // A renamed installation cannot advertise a hostname it has not installed.
        Arc::get_mut(&mut state).unwrap().config.name = "gateway-b".into();
        assert!(snapshot(&state, "default").await.unwrap().routes.is_empty());
        assert_eq!(
            accept(&state, &owner, &report, current_time_ms() + 10_000)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::FailedPrecondition
        );
        let sandbox = state
            .store
            .get_message::<Sandbox>("sandbox")
            .await
            .unwrap()
            .unwrap();
        let config = super::super::policy::build_sandbox_config_snapshot(&state, &sandbox)
            .await
            .unwrap();
        let replacement = openshell_core::proto::SupervisorServiceAdvertisement {
            config_revision: config.config_revision,
            routes: config.service_routes,
            lease_sequence: report.lease_sequence + 1,
            ..report
        };
        accept(&state, &owner, &replacement, current_time_ms() + 10_000)
            .await
            .unwrap();
        let second = snapshot(&state, "default").await.unwrap();
        assert_ne!(first.routes[0].hostname, second.routes[0].hostname);
        assert_ne!(
            first.routes[0].installation_version,
            second.routes[0].installation_version
        );
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
}
