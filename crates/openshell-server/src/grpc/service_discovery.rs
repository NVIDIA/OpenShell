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
    MinWorkspaceRole, authorize_workspace, require_platform_admin, selected_workspace_name,
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

#[derive(Clone, Debug)]
enum Selection {
    Named(Vec<String>),
    All,
}

fn selection(
    scope: Option<&openshell_core::proto::WorkspaceSelector>,
    names: &[String],
) -> Result<Selection, Status> {
    if !names.is_empty() {
        if scope.is_some() || names.len() > crate::auth::discovery::MAX_WORKSPACES {
            return Err(Status::invalid_argument(
                "choose a workspace selector or up to 64 workspaces",
            ));
        }
        let mut names = names.to_vec();
        for name in &names {
            super::workspace::validate_workspace_name(name)?;
        }
        names.sort();
        if names.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(Status::invalid_argument("duplicate workspace selection"));
        }
        return Ok(Selection::Named(names));
    }
    if scope.is_some_and(|scope| {
        matches!(
            scope.selection,
            Some(openshell_core::proto::workspace_selector::Selection::AllWorkspaces(_))
        )
    }) {
        return Ok(Selection::All);
    }
    Ok(Selection::Named(vec![
        selected_workspace_name(scope)?.to_string(),
    ]))
}

async fn authorize_selection(
    state: &ServerState,
    principal: &Principal,
    selection: &Selection,
) -> Result<(), Status> {
    if let Principal::Discovery(reader) = principal {
        let grant = crate::auth::discovery::grant(
            state.config.auth.discovery_grants_file.as_deref(),
            reader,
        )
        .await?;
        match selection {
            Selection::All if !grant.all_workspaces => {
                return Err(Status::permission_denied(
                    "all-workspaces discovery grant required",
                ));
            }
            Selection::Named(names)
                if !grant.all_workspaces
                    && names.iter().any(|name| !grant.workspaces.contains(name)) =>
            {
                return Err(Status::permission_denied(
                    "workspace not granted for discovery",
                ));
            }
            _ => return Ok(()),
        }
    }
    match selection {
        Selection::All => {
            if let Principal::User(user) = principal {
                let explicit_dev = state.config.auth.allow_unauthenticated_users
                    && user.identity.provider == crate::auth::identity::IdentityProvider::LocalDev;
                if !explicit_dev && state.admin_role.is_empty() {
                    return Err(Status::permission_denied(
                        "explicit platform discovery authority required",
                    ));
                }
            }
            require_platform_admin(&state.admin_role, principal)
        }
        Selection::Named(names) => {
            for name in names {
                authorize(state, principal, name).await?;
            }
            Ok(())
        }
    }
}

async fn active_workspaces(state: &ServerState) -> Result<Vec<String>, Status> {
    let mut cursor: Option<ObjectCursor> = None;
    let mut names = Vec::new();
    let mut count = 0;
    let mut bytes = 0usize;
    loop {
        let page = state
            .store
            .list_by_type_after("workspace", cursor.as_ref(), 65)
            .await
            .map_err(|_| Status::unavailable("workspace discovery storage unavailable"))?;
        count += page.len();
        for record in &page {
            bytes = bytes.saturating_add(record.payload.len());
            if count > crate::auth::discovery::MAX_WORKSPACES || bytes > MAX_BYTES {
                return Err(Status::resource_exhausted(
                    "workspace discovery limit exceeded",
                ));
            }
            let workspace = openshell_core::proto::Workspace::decode(record.payload.as_slice())
                .map_err(|_| Status::internal("invalid workspace record"))?;
            let metadata = workspace
                .metadata
                .ok_or_else(|| Status::internal("workspace metadata missing"))?;
            if metadata.deletion_time.is_none() {
                names.push(metadata.name);
            }
        }
        cursor = page.last().map(ObjectCursor::from);
        if page.len() < 65 {
            break;
        }
    }
    names.sort();
    Ok(names)
}

async fn selection_workspaces(
    state: &ServerState,
    selection: &Selection,
) -> Result<Vec<String>, Status> {
    match selection {
        Selection::All => active_workspaces(state).await,
        Selection::Named(names) => {
            let mut active = Vec::new();
            for name in names {
                match super::workspace::resolve_workspace(state.store.as_ref(), name).await {
                    Ok(workspace) if !workspace.terminating => active.push(name.clone()),
                    Ok(_) => {}
                    Err(error) if error.code() == tonic::Code::NotFound => {}
                    Err(error) => return Err(error),
                }
            }
            Ok(active)
        }
    }
}

async fn selected_snapshot(
    state: &ServerState,
    principal: &Principal,
    selection: &Selection,
) -> Result<ServiceRouteSnapshot, Status> {
    tokio::time::timeout(SNAPSHOT_TIMEOUT, async {
        authorize_selection(state, principal, selection).await?;
        let before = selection_workspaces(state, selection).await?;
        let names = before.clone();
        let mut result = ServiceRouteSnapshot::default();
        let mut bytes = 0usize;
        for name in names {
            let part = snapshot(state, &name).await?;
            bytes = bytes.saturating_add(part.encoded_len());
            if bytes > MAX_BYTES - 128 || result.routes.len() + part.routes.len() > MAX_ROUTES {
                return Err(Status::resource_exhausted(
                    "combined discovery limit exceeded",
                ));
            }
            result.routes.extend(part.routes);
        }
        if before != selection_workspaces(state, selection).await? {
            return Err(Status::unavailable(
                "workspace set changed during discovery; retry",
            ));
        }
        // Recheck grants/membership after collection, before publishing a view.
        authorize_selection(state, principal, selection).await?;
        result.revision = hex::encode(
            openshell_crypto::sha256(&result.encode_to_vec())
                .map_err(|_| Status::internal("snapshot fingerprint failed"))?,
        );
        Ok(result)
    })
    .await
    .map_err(|_| Status::unavailable("service discovery collection timed out"))?
}

pub async fn get_snapshot(
    state: &Arc<ServerState>,
    request: Request<GetServiceRouteSnapshotRequest>,
) -> Result<Response<GetServiceRouteSnapshotResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let selection = selection(
        request.get_ref().workspace_scope.as_ref(),
        &request.get_ref().workspaces,
    )?;
    Ok(Response::new(GetServiceRouteSnapshotResponse {
        snapshot: Some(selected_snapshot(state, &principal, &selection).await?),
    }))
}

pub async fn watch(
    state: &Arc<ServerState>,
    request: Request<WatchServiceRoutesRequest>,
) -> Result<Response<RouteWatchStream>, Status> {
    let principal = super::extract_principal(&request)?;
    let selection = selection(
        request.get_ref().workspace_scope.as_ref(),
        &request.get_ref().workspaces,
    )?;
    tokio::time::timeout(
        SNAPSHOT_TIMEOUT,
        authorize_selection(state, &principal, &selection),
    )
    .await
    .map_err(|_| Status::unavailable("discovery authorization timed out"))??;
    let permit = state
        .discovery_watches
        .clone()
        .try_acquire_owned()
        .map_err(|_| Status::resource_exhausted("too many service discovery watches"))?;
    let initial = selected_snapshot(state, &principal, &selection).await?;
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
            let refresh = async { selected_snapshot(&state, &principal, &selection).await };
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
            ..Default::default()
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
                ..Default::default()
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
                    workspace_scope: Some(openshell_core::proto::all_workspaces_selector()),
                    ..Default::default()
                })
            )
            .await
            .is_ok()
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
                ..Default::default()
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
            ..Default::default()
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
                ..Default::default()
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
    async fn reader_fixture(all: bool) -> (Arc<ServerState>, Principal, tempfile::TempDir) {
        let (mut state, owner, report) = installed_fixture().await;
        accept(&state, &owner, &report, current_time_ms() + 10_000)
            .await
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        let fingerprint = "a".repeat(64);
        let grant = if all {
            serde_json::json!({"certificate_sha256":fingerprint,"all_workspaces":true})
        } else {
            serde_json::json!({"certificate_sha256":fingerprint,"workspaces":["default","team-b"]})
        };
        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({"readers":[grant]})).unwrap(),
        )
        .unwrap();
        Arc::get_mut(&mut state)
            .unwrap()
            .config
            .auth
            .discovery_grants_file = Some(path);
        let principal = Principal::Discovery(crate::auth::principal::DiscoveryPrincipal {
            certificate_sha256: fingerprint,
            expires_at_ms: current_time_ms() + 60_000,
        });
        (state, principal, dir)
    }

    fn reader_request<T>(body: T, principal: &Principal) -> Request<T> {
        let mut request = Request::new(body);
        request.extensions_mut().insert(principal.clone());
        request
    }

    #[tokio::test]
    async fn machine_selection_does_not_grant_workspace_or_application_permissions() {
        let (state, principal, _dir) = reader_fixture(false).await;
        assert!(
            get_snapshot(&state, reader_request(request(), &principal))
                .await
                .is_ok()
        );
        assert!(
            authorize_workspace(
                &state.store,
                &state.admin_role,
                &principal,
                "default",
                MinWorkspaceRole::User
            )
            .await
            .is_err()
        );
        for scope in [Selection::All, Selection::Named(vec!["not-granted".into()])] {
            assert_eq!(
                authorize_selection(&state, &principal, &scope)
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::PermissionDenied
            );
        }
        assert!(selection(request().workspace_scope.as_ref(), &["default".into()]).is_err());
        assert!(selection(None, &["default".into(), "default".into()]).is_err());
        let selected = GetServiceRouteSnapshotRequest {
            workspaces: vec!["default".into(), "team-b".into()],
            ..Default::default()
        };
        assert!(
            get_snapshot(&state, reader_request(selected, &principal))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn machine_watch_rechecks_grants_and_certificate_expiry() {
        let (state, principal, dir) = reader_fixture(true).await;
        let body = WatchServiceRoutesRequest {
            workspace_scope: Some(openshell_core::proto::all_workspaces_selector()),
            ..Default::default()
        };
        let mut stream = watch(&state, reader_request(body, &principal))
            .await
            .unwrap()
            .into_inner();
        assert!(stream.next().await.unwrap().is_ok());
        std::fs::write(dir.path().join("grants.json"), r#"{"readers":[]}"#).unwrap();
        let error = tokio::time::timeout(Duration::from_secs(3), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
        assert!(stream.next().await.is_none());
        let expired = Principal::Discovery(crate::auth::principal::DiscoveryPrincipal {
            certificate_sha256: "a".repeat(64),
            expires_at_ms: 0,
        });
        assert_eq!(
            get_snapshot(&state, reader_request(request(), &expired))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
    }

    #[tokio::test]
    async fn all_workspace_views_follow_creation_and_deletion_with_bounded_output() {
        use openshell_core::proto::{ObjectMeta, Workspace};
        let (state, principal, _dir) = reader_fixture(true).await;
        assert_eq!(
            selection_workspaces(&state, &Selection::All).await.unwrap(),
            vec!["default"]
        );
        let mut workspace = Workspace {
            metadata: Some(ObjectMeta {
                id: "team-b".into(),
                name: "team-b".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        state.store.put_message(&workspace).await.unwrap();
        assert_eq!(
            selection_workspaces(&state, &Selection::All).await.unwrap(),
            vec!["default", "team-b"]
        );
        workspace.metadata.as_mut().unwrap().deletion_time =
            Some(openshell_core::time::timestamp_from_millis(current_time_ms()).unwrap());
        state.store.put_message(&workspace).await.unwrap();
        assert_eq!(
            selection_workspaces(&state, &Selection::All).await.unwrap(),
            vec!["default"]
        );
        for n in 0..crate::auth::discovery::MAX_WORKSPACES {
            let name = format!("w-{n}");
            state
                .store
                .put_message(&Workspace {
                    metadata: Some(ObjectMeta {
                        id: name.clone(),
                        name,
                        ..Default::default()
                    }),
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        assert_eq!(
            selected_snapshot(&state, &principal, &Selection::All)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::ResourceExhausted
        );
        assert!(
            selected_snapshot(
                &state,
                &principal,
                &Selection::Named(vec!["default".into()])
            )
            .await
            .is_ok()
        );
    }
    #[tokio::test]
    async fn finite_and_platform_snapshots_combine_actual_routes_and_withdraw_deleted_workspaces() {
        use openshell_core::proto::{ObjectMeta, ServiceEndpoint, Workspace};
        let (state, principal, _dir) = reader_fixture(true).await;
        state
            .store
            .put_message(&Workspace {
                metadata: Some(ObjectMeta {
                    id: "workspace-b".into(),
                    name: "team-b".into(),
                    ..Default::default()
                }),
                ..Default::default()
            })
            .await
            .unwrap();
        let mut sandbox = state
            .store
            .get_message::<Sandbox>("sandbox")
            .await
            .unwrap()
            .unwrap();
        let meta = sandbox.metadata.as_mut().unwrap();
        meta.id = "sandbox-b".into();
        meta.workspace = "team-b".into();
        state.store.put_message(&sandbox).await.unwrap();
        let mut endpoint = state
            .store
            .get_message::<ServiceEndpoint>("endpoint")
            .await
            .unwrap()
            .unwrap();
        endpoint.sandbox_id = "sandbox-b".into();
        let meta = endpoint.metadata.as_mut().unwrap();
        meta.id = "endpoint-b".into();
        meta.workspace = "team-b".into();
        state.store.put_message(&endpoint).await.unwrap();
        let owner = crate::supervisor_owner::SupervisorOwnerIndex::new(
            state.store.clone(),
            crate::supervisor_owner::OWNER_TTL,
        )
        .publish(
            "sandbox-b",
            "session-b",
            "instance-b",
            1,
            "replica",
            "local://replica",
        )
        .await
        .unwrap();
        let config = super::super::policy::build_sandbox_config_snapshot(&state, &sandbox)
            .await
            .unwrap();
        accept(
            &state,
            &owner,
            &openshell_core::proto::SupervisorServiceAdvertisement {
                service_domain: "services.example.com".into(),
                lease_sequence: 1,
                configuration_instance_id: config.configuration_instance_id,
                config_revision: config.config_revision,
                routes: config.service_routes,
            },
            current_time_ms() + 10_000,
        )
        .await
        .unwrap();
        let selected = Selection::Named(vec!["default".into(), "team-b".into()]);
        let both = selected_snapshot(&state, &principal, &selected)
            .await
            .unwrap();
        assert_eq!(
            both.routes
                .iter()
                .map(|route| route.workspace.as_str())
                .collect::<Vec<_>>(),
            vec!["default", "team-b"]
        );
        assert_eq!(
            both,
            selected_snapshot(&state, &principal, &Selection::All)
                .await
                .unwrap()
        );
        state
            .store
            .delete("workspace", "workspace-b")
            .await
            .unwrap();
        assert_eq!(
            selected_snapshot(&state, &principal, &Selection::All)
                .await
                .unwrap()
                .routes
                .len(),
            1
        );
    }
}
