// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::grpc::test_support::{authed_request, test_server_state};
use openshell_core::proto::datamodel::v1::ObjectMeta;
use openshell_core::proto::open_shell_server::OpenShell;
use openshell_core::proto::{
    SandboxWorkloadConfig, SandboxWorkloadTemplate, SandboxWorkloadTemplateSpec, WorkspaceMember,
    WorkspaceRole,
};
use openshell_core::rpc_error::StatusExt;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tonic::Code;

fn create(name: &str) -> CreateWorkspaceRequest {
    CreateWorkspaceRequest {
        name: name.into(),
        request_id: uuid::Uuid::new_v4().to_string(),
        ..Default::default()
    }
}

pub(super) fn reason(status: &Status) -> String {
    assert!(status.get_error_details().retry_info().is_none());
    status
        .get_error_details()
        .error_info()
        .unwrap_or_else(|| panic!("missing structured reason: {status:?}"))
        .reason
        .clone()
}

pub(super) async fn state_for(store: Store) -> Arc<ServerState> {
    let store = Arc::new(store);
    crate::ensure_default_workspace(&store).await.unwrap();
    let compute = crate::compute::new_test_runtime(store.clone()).await;
    Arc::new(ServerState::new(
        openshell_core::Config::new(None).with_credential_drivers(["test-static"]),
        store,
        compute,
        crate::sandbox_index::SandboxIndex::new(),
        crate::sandbox_watch::SandboxWatchBus::new(),
        crate::tracing_bus::TracingLogBus::new(),
        Arc::new(crate::supervisor_session::SupervisorSessionRegistry::new()),
        None,
    ))
}

#[test]
fn validates_bounded_nonzero_uuid_and_normalizes_case() {
    for value in [
        "",
        "not-a-uuid",
        "00000000-0000-0000-0000-000000000000",
        "550e8400e29b41d4a716446655440000",
        "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
    ] {
        let status = validate_request_id(value).unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(
            status
                .get_error_details()
                .bad_request()
                .unwrap()
                .field_violations[0]
                .field,
            "request_id"
        );
    }
    assert_eq!(
        validate_request_id("550E8400-E29B-41D4-A716-446655440000").unwrap(),
        "550e8400-e29b-41d4-a716-446655440000"
    );
}

#[test]
fn canonical_payload_ignores_map_order_and_id_but_preserves_presence() {
    let mut first = create("canonical");
    first.labels = HashMap::from([("a".into(), "1".into()), ("b".into(), "2".into())]);
    let mut second = create("canonical");
    second.labels = HashMap::from([("b".into(), "2".into()), ("a".into(), "1".into())]);
    assert_eq!(fingerprint(&first).unwrap(), fingerprint(&second).unwrap());
    second.labels.insert("b".into(), "3".into());
    assert_ne!(fingerprint(&first).unwrap(), fingerprint(&second).unwrap());
    let mut template = CreateSandboxTemplateRequest::default();
    let absent = fingerprint(&template).unwrap();
    template.template = Some(SandboxWorkloadTemplate::default());
    assert_ne!(absent, fingerprint(&template).unwrap());
}

async fn exercise_backend(url: &str) {
    let first = state_for(Store::connect(url).await.unwrap()).await;
    let second = state_for(Store::connect(url).await.unwrap()).await;
    let req = create(&format!(
        "replay-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    ));
    let mut tasks = Vec::new();
    for i in 0..24 {
        let state = if i % 2 == 0 {
            first.clone()
        } else {
            second.clone()
        };
        let req = req.clone();
        tasks.push(tokio::spawn(async move {
            run(&state, authed_request(req)).await
        }));
    }
    let mut successes = 0;
    for task in tasks {
        match task.await.unwrap() {
            Ok(_) => successes += 1,
            Err(status) => assert_eq!(reason(&status), "REQUEST_OUTCOME_UNCERTAIN"),
        }
    }
    assert!(successes > 0);
    let original = run(&first, authed_request(req.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        first
            .store
            .count_in_workspace(Workspace::object_type(), "")
            .await
            .unwrap(),
        2
    );
    drop(first);
    drop(second);
    let restarted = state_for(Store::connect(url).await.unwrap()).await;
    let replay = run(&restarted, authed_request(req.clone())).await.unwrap();
    assert_eq!(replay.metadata().get("openshell-replayed").unwrap(), "true");
    assert_eq!(original, replay.into_inner());
    let mut mismatch = req.clone();
    mismatch.labels.insert("changed".into(), "payload".into());
    assert_eq!(
        reason(&run(&restarted, authed_request(mismatch)).await.unwrap_err()),
        "REQUEST_ID_PAYLOAD_MISMATCH"
    );

    // An old deletion replay must not delete a same-name replacement.
    let deletion = DeleteWorkspaceRequest {
        name: req.name.clone(),
        request_id: uuid::Uuid::new_v4().to_string(),
        ..Default::default()
    };
    run(&restarted, authed_request(deletion.clone()))
        .await
        .unwrap();
    let replacement = run(&restarted, authed_request(create(&req.name)))
        .await
        .unwrap()
        .into_inner();
    run(&restarted, authed_request(deletion)).await.unwrap();
    assert_eq!(
        restarted
            .store
            .get_message::<Workspace>(replacement.workspace.as_ref().unwrap().object_id())
            .await
            .unwrap(),
        replacement.workspace
    );
    assert_eq!(
        reason(&run(&restarted, authed_request(req)).await.unwrap_err()),
        "REQUEST_REPLAY_UNAVAILABLE"
    );
    exercise_expiry_and_uncertainty(&restarted).await;
    ordinary::tests::exercise_protected_backend(url).await;
}

#[tokio::test]
async fn sqlite_concurrency_restart_name_reuse_expiry_and_uncertainty() {
    let dir = tempfile::tempdir().unwrap();
    exercise_backend(&format!(
        "sqlite://{}?mode=rwc",
        dir.path().join("replay.db").display()
    ))
    .await;
}

#[tokio::test]
async fn workspace_create_request_id_is_scoped_to_each_target() {
    let state = test_server_state().await;
    let service = crate::grpc::OpenShellService::new(state.clone());
    let first = create("scope-a");
    let second = CreateWorkspaceRequest {
        name: "scope-b".into(),
        ..first.clone()
    };
    let mut originals = Vec::new();
    for req in [&first, &second] {
        let response = service
            .create_workspace(authed_request(req.clone()))
            .await
            .unwrap();
        assert!(response.metadata().get("openshell-replayed").is_none());
        let original = response.into_inner();
        assert_eq!(
            original
                .workspace
                .as_ref()
                .unwrap()
                .metadata
                .as_ref()
                .unwrap()
                .name,
            req.name
        );
        assert_eq!(
            state
                .store
                .get_message_by_name::<Workspace>("", &req.name)
                .await
                .unwrap(),
            original.workspace
        );
        originals.push(original);
    }
    assert_ne!(
        originals[0].workspace.as_ref().unwrap().object_id(),
        originals[1].workspace.as_ref().unwrap().object_id()
    );
    for (req, original) in [&first, &second].into_iter().zip(originals) {
        let replay = service
            .create_workspace(authed_request(req.clone()))
            .await
            .unwrap();
        assert_eq!(replay.metadata().get("openshell-replayed").unwrap(), "true");
        assert_eq!(replay.into_inner(), original);
        let mut mismatch = req.clone();
        mismatch.labels.insert("changed".into(), "payload".into());
        assert_eq!(
            reason(
                &service
                    .create_workspace(authed_request(mismatch))
                    .await
                    .unwrap_err()
            ),
            "REQUEST_ID_PAYLOAD_MISMATCH"
        );
    }
    let rows = state
        .store
        .list_by_type_after(OBJECT_TYPE, None, 100)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    for row in rows {
        let admission: Admission = serde_json::from_slice(&row.payload).unwrap();
        assert!(admission.workspace_id.is_none());
    }
}

#[tokio::test]
async fn workspace_delete_request_id_is_scoped_to_each_target() {
    let state = test_server_state().await;
    let service = crate::grpc::OpenShellService::new(state.clone());
    let request_id = uuid::Uuid::new_v4().to_string();
    let mut requests = Vec::new();
    for name in ["scope-a", "scope-b"] {
        service
            .create_workspace(authed_request(CreateWorkspaceRequest {
                name: name.into(),
                ..Default::default()
            }))
            .await
            .unwrap();
        requests.push(DeleteWorkspaceRequest {
            name: name.into(),
            request_id: request_id.clone(),
            ..Default::default()
        });
    }
    for req in &requests {
        let response = service
            .delete_workspace(authed_request(req.clone()))
            .await
            .unwrap();
        assert!(response.metadata().get("openshell-replayed").is_none());
        assert_eq!(
            response.get_ref().outcome,
            openshell_core::proto::DeletionOutcome::Completed as i32
        );
        assert!(
            state
                .store
                .get_message_by_name::<Workspace>("", &req.name)
                .await
                .unwrap()
                .is_none()
        );
    }
    for req in requests {
        // The target no longer exists; deletion replay must not require its UUID.
        let replay = service.delete_workspace(authed_request(req)).await.unwrap();
        assert_eq!(replay.metadata().get("openshell-replayed").unwrap(), "true");
        assert_eq!(
            replay.get_ref().outcome,
            openshell_core::proto::DeletionOutcome::Completed as i32
        );
    }
    let rows = state
        .store
        .list_by_type_after(OBJECT_TYPE, None, 100)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    for row in rows {
        let admission: Admission = serde_json::from_slice(&row.payload).unwrap();
        assert!(admission.workspace_id.is_none());
    }
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL database in OPENSHELL_REPLAY_TEST_DATABASE_URL"]
async fn postgres_concurrency_restart_name_reuse_expiry_and_uncertainty() {
    let url = std::env::var("OPENSHELL_REPLAY_TEST_DATABASE_URL")
        .expect("disposable PostgreSQL database URL");
    assert!(url.starts_with("postgres"));
    let schema = format!("replay_{}", uuid::Uuid::new_v4().simple());
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
        .execute(&pool)
        .await
        .unwrap();
    let mut scoped = url::Url::parse(&url).unwrap();
    scoped
        .query_pairs_mut()
        .append_pair("options", &format!("-csearch_path={schema}"));
    exercise_backend(scoped.as_str()).await;
    // Only the randomly named schema owned by this test is removed.
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
        .execute(&pool)
        .await
        .unwrap();
}

async fn exercise_expiry_and_uncertainty(state: &Arc<ServerState>) {
    let req = create("expired-result");
    run(state, authed_request(req.clone())).await.unwrap();
    let hash = fingerprint(&req).unwrap();
    let rows = state
        .store
        .list_by_type_after(OBJECT_TYPE, None, 100)
        .await
        .unwrap();
    let row = rows
        .into_iter()
        .find(|row| {
            serde_json::from_slice::<Admission>(&row.payload)
                .unwrap()
                .payload_hash
                == hash
        })
        .unwrap();
    let mut expired: Admission = serde_json::from_slice(&row.payload).unwrap();
    expired.completed_at_ms = Some(current_time_ms() - SUCCESS_TTL_MS);
    state
        .store
        .put_if(
            OBJECT_TYPE,
            &row.id,
            &row.name,
            &row.workspace,
            &serde_json::to_vec(&expired).unwrap(),
            None,
            WriteCondition::MatchResourceVersion(row.resource_version),
        )
        .await
        .unwrap();
    let expired_row = state
        .store
        .get(OBJECT_TYPE, &row.id)
        .await
        .unwrap()
        .unwrap();
    // Expiry admits a fresh attempt, which sees the existing resource. The
    // resulting error remains unresolved even if the original resource is removed.
    assert_eq!(
        run(state, authed_request(req.clone()))
            .await
            .unwrap_err()
            .code(),
        Code::AlreadyExists
    );
    assert!(
        !state
            .store
            .delete_if(OBJECT_TYPE, &expired_row.id, expired_row.resource_version)
            .await
            .unwrap()
    );
    let pending = state
        .store
        .get_by_name(OBJECT_TYPE, &row.workspace, &row.name)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(pending.id, expired_row.id);
    let mut admission: Admission = serde_json::from_slice(&pending.payload).unwrap();
    admission.completed_at_ms = Some(0); // Even an old timestamp cannot expire an unresolved record.
    state
        .store
        .put_if(
            OBJECT_TYPE,
            &pending.id,
            &pending.name,
            &pending.workspace,
            &serde_json::to_vec(&admission).unwrap(),
            None,
            WriteCondition::MatchResourceVersion(pending.resource_version),
        )
        .await
        .unwrap();
    state
        .store
        .delete_by_name(Workspace::object_type(), "", &req.name)
        .await
        .unwrap();
    assert_eq!(
        reason(&run(state, authed_request(req)).await.unwrap_err()),
        "REQUEST_OUTCOME_UNCERTAIN"
    );
    assert!(!prune_expired(&state.store, &row.workspace).await.unwrap());
}

#[tokio::test]
async fn replays_reauthorize_membership_and_admin_grants() {
    let mut state = test_server_state().await;
    Arc::get_mut(&mut state).unwrap().admin_role = "openshell-admin".into();
    let req = AddWorkspaceMemberRequest {
        workspace: "default".into(),
        principal_subject: "member".into(),
        role: WorkspaceRole::Admin.into(),
        request_id: uuid::Uuid::new_v4().to_string(),
    };
    run(&state, authed_request(req.clone())).await.unwrap();
    let mut downgraded = authed_request(req.clone());
    let Principal::User(user) = downgraded.extensions_mut().get_mut::<Principal>().unwrap() else {
        unreachable!()
    };
    user.identity.roles.clear();
    let caller = WorkspaceMember {
        metadata: Some(ObjectMeta {
            id: "caller".into(),
            name: "dev-user".into(),
            workspace: "default".into(),
            ..Default::default()
        }),
        principal_subject: "dev-user".into(),
        role: WorkspaceRole::Admin.into(),
    };
    state.store.put_message(&caller).await.unwrap();
    assert_eq!(
        run(&state, downgraded).await.unwrap_err().code(),
        Code::PermissionDenied
    );
    let remove = RemoveWorkspaceMemberRequest {
        workspace: "default".into(),
        principal_subject: "missing".into(),
        allow_missing: true,
        request_id: uuid::Uuid::new_v4().to_string(),
    };
    let member_request = |req| {
        let mut request = authed_request(req);
        if let Principal::User(user) = request.extensions_mut().get_mut::<Principal>().unwrap() {
            user.identity.roles.clear();
        }
        request
    };
    run(&state, member_request(remove.clone())).await.unwrap();
    state
        .store
        .delete(WorkspaceMember::object_type(), "caller")
        .await
        .unwrap();
    assert_eq!(
        run(&state, member_request(remove))
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
}

#[tokio::test]
async fn template_replay_stores_only_reference_and_checks_original_version() {
    let state = test_server_state().await;
    // Delete is also routed through the public dispatch adapter.
    let req = DeleteSandboxTemplateRequest {
        name: "missing".into(),
        workspace: "default".to_string(),
        allow_missing: true,
        request_id: uuid::Uuid::new_v4().to_string(),
    };
    let service = crate::grpc::OpenShellService::new(state.clone());
    service
        .delete_sandbox_template(authed_request(req.clone()))
        .await
        .unwrap();
    assert_eq!(
        service
            .delete_sandbox_template(authed_request(req))
            .await
            .unwrap()
            .metadata()
            .get("openshell-replayed")
            .unwrap(),
        "true"
    );
    let req = CreateSandboxTemplateRequest {
        template: Some(SandboxWorkloadTemplate {
            metadata: Some(ObjectMeta {
                name: "template".into(),
                annotations: HashMap::from([("private".into(), "sensitive-template-value".into())]),
                ..Default::default()
            }),
            spec: Some(SandboxWorkloadTemplateSpec {
                workload: Some(SandboxWorkloadConfig {
                    image: "registry.example.com/agent:latest".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        }),
        workspace: "default".to_string(),
        request_id: uuid::Uuid::new_v4().to_string(),
    };
    let created = run(&state, authed_request(req.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        created,
        run(&state, authed_request(req.clone()))
            .await
            .unwrap()
            .into_inner()
    );
    for row in state
        .store
        .list_by_type_after(OBJECT_TYPE, None, 100)
        .await
        .unwrap()
    {
        assert!(
            !String::from_utf8(row.payload)
                .unwrap()
                .contains("sensitive-template-value")
        );
    }
    let original = created.template.unwrap();
    state
        .store
        .update_message_cas::<SandboxWorkloadTemplate, _>(
            original.object_id(),
            original.get_resource_version(),
            |changed| {
                changed.metadata.as_mut().unwrap().annotations.clear();
            },
        )
        .await
        .unwrap();
    assert_eq!(
        reason(&run(&state, authed_request(req)).await.unwrap_err()),
        "REQUEST_REPLAY_UNAVAILABLE"
    );
}

#[derive(Clone, PartialEq, Message)]
struct ControlledCreate {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(string, tag = "3")]
    request_id: String,
}

#[derive(Default)]
struct Control {
    started: tokio::sync::Notify,
    proceed: tokio::sync::Notify,
    calls: AtomicUsize,
    fail_after_effect: bool,
}

#[tonic::async_trait]
impl Mutation for ControlledCreate {
    type Output = CreateWorkspaceResponse;
    const METHOD: &'static str = "CreateWorkspace";
    fn request_id(&self) -> &str {
        &self.request_id
    }
    async fn authorize(&self, state: &ServerState, principal: &Principal) -> Result<Scope, Status> {
        // Fault-injected execution must use the real adapter's admission key.
        CreateWorkspaceRequest {
            name: self.name.clone(),
            ..Default::default()
        }
        .authorize(state, principal)
        .await
    }
    async fn execute(
        state: &Arc<ServerState>,
        request: Request<Self>,
    ) -> Result<Response<Self::Output>, Status> {
        let control = request.extensions().get::<Arc<Control>>().unwrap().clone();
        control.calls.fetch_add(1, Ordering::SeqCst);
        control.started.notify_one();
        control.proceed.notified().await;
        let req = request.into_inner();
        let response = workspace::handle_create_workspace(
            state,
            Request::new(CreateWorkspaceRequest {
                name: req.name,
                request_id: req.request_id,
                ..Default::default()
            }),
        )
        .await?;
        if control.fail_after_effect {
            return Err(Status::internal("simulated interruption after effect"));
        }
        Ok(response)
    }
    fn capture(response: &Response<Self::Output>) -> Result<Success, Status> {
        resource_success(response.get_ref().workspace.as_ref())
    }
    async fn restore(store: &Store, success: Success) -> Result<Self::Output, Status> {
        Ok(CreateWorkspaceResponse {
            workspace: Some(restore_resource(store, success).await?),
        })
    }
}

#[tokio::test]
async fn cancellation_keeps_owned_work_and_duplicate_cannot_take_over() {
    let state = test_server_state().await;
    let control = Arc::new(Control::default());
    let req = create("cancelled-client");
    let mut request = authed_request(ControlledCreate {
        name: req.name.clone(),
        request_id: req.request_id.clone(),
    });
    request.extensions_mut().insert(control.clone());
    let worker_state = state.clone();
    let caller = tokio::spawn(async move { run(&worker_state, request).await });
    tokio::time::timeout(Duration::from_secs(5), control.started.notified())
        .await
        .unwrap();
    caller.abort();
    assert_eq!(
        reason(&run(&state, authed_request(req.clone())).await.unwrap_err()),
        "REQUEST_OUTCOME_UNCERTAIN"
    );
    control.proceed.notify_one();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if run(&state, authed_request(req.clone())).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(control.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn quota_fails_closed_but_replays_and_expired_success_cleanup_still_work() {
    let state = test_server_state().await;
    let req = create("quota-replay");
    run(&state, authed_request(req.clone())).await.unwrap();
    let original = state
        .store
        .list_by_type_after(OBJECT_TYPE, None, 1)
        .await
        .unwrap()
        .remove(0);
    let pending = Admission {
        protection: None,
        format_version: 1,
        payload_hash: "unused".into(),
        workspace_id: None,
        success: None,
        completed_at_ms: None,
    };
    let payload = serde_json::to_vec(&pending).unwrap();
    for i in 1..MAX_ADMISSIONS_PER_CALLER - 1 {
        let id = format!("quota-{i}");
        state
            .store
            .create_if_workspace_count_below(
                OBJECT_TYPE,
                &id,
                &id,
                &original.workspace,
                &payload,
                None,
                u64::from(MAX_ADMISSIONS_PER_CALLER),
            )
            .await
            .unwrap()
            .unwrap();
    }
    let (left, right) = tokio::join!(
        run(&state, authed_request(create("quota-race-a"))),
        run(&state, authed_request(create("quota-race-b")))
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    assert_eq!(
        left.err().or_else(|| right.err()).unwrap().code(),
        Code::ResourceExhausted
    );
    let new_req = create("quota-new");
    assert_eq!(
        run(&state, authed_request(new_req.clone()))
            .await
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    assert!(
        state
            .store
            .get_message_by_name::<Workspace>("", &new_req.name)
            .await
            .unwrap()
            .is_none()
    );
    run(&state, authed_request(req)).await.unwrap();
    let mut expired: Admission = serde_json::from_slice(&original.payload).unwrap();
    expired.completed_at_ms = Some(0);
    state
        .store
        .put_if(
            OBJECT_TYPE,
            &original.id,
            &original.name,
            &original.workspace,
            &serde_json::to_vec(&expired).unwrap(),
            None,
            WriteCondition::MatchResourceVersion(original.resource_version),
        )
        .await
        .unwrap();
    run(&state, authed_request(new_req)).await.unwrap();
    assert_eq!(
        state
            .store
            .count_in_workspace(OBJECT_TYPE, &original.workspace)
            .await
            .unwrap(),
        u64::from(MAX_ADMISSIONS_PER_CALLER)
    );
    assert!(
        state
            .store
            .get(OBJECT_TYPE, "quota-1")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn workspace_replacement_blocks_replay_without_reexecuting_member_removal() {
    let state = test_server_state().await;
    let workspace_req = create("workspace-reuse");
    run(&state, authed_request(workspace_req.clone()))
        .await
        .unwrap();
    let member = AddWorkspaceMemberRequest {
        workspace: workspace_req.name.clone(),
        principal_subject: "member".into(),
        role: WorkspaceRole::User.into(),
        ..Default::default()
    };
    run(&state, authed_request(member.clone())).await.unwrap();
    let remove = RemoveWorkspaceMemberRequest {
        workspace: workspace_req.name.clone(),
        principal_subject: "member".into(),
        request_id: uuid::Uuid::new_v4().to_string(),
        ..Default::default()
    };
    run(&state, authed_request(remove.clone())).await.unwrap();
    run(
        &state,
        authed_request(DeleteWorkspaceRequest {
            name: workspace_req.name.clone(),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    run(&state, authed_request(create(&workspace_req.name)))
        .await
        .unwrap();
    let replacement = run(&state, authed_request(member))
        .await
        .unwrap()
        .into_inner()
        .member
        .unwrap();
    assert_eq!(
        reason(&run(&state, authed_request(remove)).await.unwrap_err()),
        "REQUEST_REPLAY_UNAVAILABLE"
    );
    assert!(
        state
            .store
            .get_message::<WorkspaceMember>(replacement.object_id())
            .await
            .unwrap()
            .is_some()
    );
}

#[test]
fn replay_allowlist_remains_outside_interception_and_ids_have_reviewed_wire_tags() {
    for (method, tag) in [
        ("CreateWorkspace", 3),
        ("DeleteWorkspace", 3),
        ("AddWorkspaceMember", 4),
        ("RemoveWorkspaceMember", 4),
        ("CreateSandboxTemplate", 3),
        ("DeleteSandboxTemplate", 4),
    ] {
        assert!(!openshell_gateway_interceptors::routes::INTERCEPTABLE_METHODS.contains(&method));
        let descriptor = DESCRIPTORS
            .get_message_by_name(&format!("openshell.v1.{method}Request"))
            .unwrap();
        let field = descriptor.get_field_by_name("request_id").unwrap();
        assert_eq!(field.number(), tag);
        assert_eq!(field.kind(), prost_reflect::Kind::String);
    }
}

#[tokio::test]
async fn unrelated_oidc_configuration_does_not_reset_mtls_admission_identity() {
    let mut state = test_server_state().await;
    let req = DeleteSandboxTemplateRequest {
        name: "mtls-template".into(),
        workspace: "default".to_string(),
        allow_missing: true,
        request_id: "550e8400-e29b-41d4-a716-446655440000".into(),
    };
    let mtls_request = |req| {
        let mut request = authed_request(req);
        if let Principal::User(user) = request.extensions_mut().get_mut::<Principal>().unwrap() {
            user.identity.provider = IdentityProvider::Mtls;
        }
        request
    };
    run(&state, mtls_request(req.clone())).await.unwrap();
    let row = state
        .store
        .list_by_type_after(OBJECT_TYPE, None, 1)
        .await
        .unwrap()
        .remove(0);
    assert_eq!(
        row.workspace,
        "_mutation/63247cf7f072797edfb9ca3c4290683b41ccaaae23712042f315de35a54067ce"
    );
    assert_eq!(
        row.name,
        "ecfb83c89c4be0bd1b67aee42c7049243af89db2df01d762b880e155694ca028"
    );
    let template = SandboxWorkloadTemplate {
        metadata: Some(ObjectMeta {
            id: "mtls-replacement".into(),
            name: req.name.clone(),
            workspace: "default".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    state.store.put_message(&template).await.unwrap();
    Arc::get_mut(&mut state).unwrap().config.oidc = Some(openshell_core::OidcConfig {
        issuer: "https://new.example.com".into(),
        dangerously_allow_insecure_http: false,
        jwks_allowed_origins: Vec::new(),
        audience: "openshell-cli".into(),
        jwks_ttl_secs: 300,
        roles_claim: String::new(),
        admin_role: String::new(),
        user_role: String::new(),
        scopes_claim: String::new(),
    });
    run(&state, mtls_request(req.clone())).await.unwrap();
    assert!(
        state
            .store
            .get_message::<SandboxWorkloadTemplate>(template.object_id())
            .await
            .unwrap()
            .is_some()
    );
    // Same textual subject/UUID from a different provider is a separate caller.
    run(&state, authed_request(req)).await.unwrap();
    assert!(
        state
            .store
            .get_message::<SandboxWorkloadTemplate>(template.object_id())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn restart_after_effect_without_success_persistence_never_reexecutes() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite://{}?mode=rwc",
        dir.path().join("interrupted.db").display()
    );
    let state = state_for(Store::connect(&url).await.unwrap()).await;
    let req = create("interrupted-effect");
    let control = Arc::new(Control {
        fail_after_effect: true,
        ..Default::default()
    });
    control.proceed.notify_one();
    let mut request = authed_request(ControlledCreate {
        name: req.name.clone(),
        request_id: req.request_id.clone(),
    });
    request.extensions_mut().insert(control.clone());
    assert_eq!(
        run(&state, request).await.unwrap_err().code(),
        Code::Internal
    );
    let original: Workspace = state
        .store
        .get_message_by_name("", &req.name)
        .await
        .unwrap()
        .unwrap();
    drop(state);
    let restarted = state_for(Store::connect(&url).await.unwrap()).await;
    assert_eq!(
        reason(
            &run(&restarted, authed_request(req.clone()))
                .await
                .unwrap_err()
        ),
        "REQUEST_OUTCOME_UNCERTAIN"
    );
    assert_eq!(control.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        restarted
            .store
            .get_message_by_name::<Workspace>("", &req.name)
            .await
            .unwrap()
            .unwrap(),
        original
    );
}
