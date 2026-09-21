// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::grpc::mutation_replay::tests::{reason, state_for};
use crate::grpc::mutation_replay::{
    Admission, AuthorizationBarrier, Completion, OBJECT_TYPE, OriginalMutation, SUCCESS_TTL_MS,
    fingerprint, run,
};
use crate::grpc::test_support::authed_request;
use crate::persistence::{ObjectType, WriteCondition, current_time_ms};
use openshell_core::proto::datamodel::v1::ObjectMeta;
use openshell_core::proto::{
    GatewayMessage, Sandbox, SandboxPhase, SandboxStatus, gateway_message,
};
use openshell_core::{ObjectId, ObjectName};
use prost::Message;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::StreamExt;

type ExecClient =
    openshell_core::proto::open_shell_client::OpenShellClient<tonic::transport::Channel>;

async fn wire_client(
    state: Arc<ServerState>,
    barrier: Option<Arc<AuthorizationBarrier>>,
    original: Option<OriginalMutation>,
) -> (ExecClient, tokio::task::JoinHandle<()>) {
    use crate::grpc::OpenShellService;
    use openshell_core::proto::open_shell_server::OpenShellServer;
    use tokio_stream::wrappers::TcpListenerStream;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let principal = authed_request(())
        .extensions()
        .get::<Principal>()
        .unwrap()
        .clone();
    let service = OpenShellServer::with_interceptor(
        OpenShellService::new(state),
        move |mut request: Request<()>| {
            request.extensions_mut().insert(principal.clone());
            if let Some(barrier) = &barrier {
                request.extensions_mut().insert(barrier.clone());
            }
            if let Some(original) = &original {
                request.extensions_mut().insert(original.clone());
            }
            Ok(request)
        },
    );
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let client = ExecClient::connect(format!("http://{address}"))
        .await
        .unwrap();
    (client, server)
}

fn interactive_start(req: ExecSandboxRequest) -> ExecSandboxInput {
    ExecSandboxInput {
        payload: Some(exec_sandbox_input::Payload::Start(req)),
    }
}

fn original_exec(req: ExecSandboxRequest, interactive: bool) -> OriginalMutation {
    OriginalMutation(if interactive {
        interactive_start(req).encode_to_vec()
    } else {
        req.encode_to_vec()
    })
}

async fn exec_rpc(
    client: &mut ExecClient,
    req: ExecSandboxRequest,
    interactive: bool,
) -> Result<Response<tonic::Streaming<ExecSandboxEvent>>, Status> {
    if interactive {
        client
            .exec_sandbox_interactive(tokio_stream::iter([interactive_start(req)]))
            .await
    } else {
        client.exec_sandbox(req).await
    }
}

async fn setup(url: &str, directory: &tempfile::TempDir) -> Arc<ServerState> {
    let mut state = state_for(Store::connect(url).await.unwrap()).await;
    let key = directory.path().join("key");
    std::fs::write(&key, b"exec-test-only-key").unwrap();
    let state_mut = Arc::get_mut(&mut state).unwrap();
    state_mut.admin_role = "openshell-admin".into();
    state_mut.config.gateway_jwt = Some(openshell_core::config::GatewayJwtConfig {
        signing_key_path: key,
        public_key_path: directory.path().join("public"),
        kid_path: directory.path().join("kid"),
        gateway_id: "test".into(),
        ttl_secs: None,
    });
    state
}

async fn request(state: &ServerState) -> ExecSandboxRequest {
    let sandbox = Sandbox {
        metadata: Some(ObjectMeta {
            id: uuid::Uuid::new_v4().to_string(),
            name: "exec-admission".into(),
            workspace: "default".into(),
            ..Default::default()
        }),
        status: Some(SandboxStatus {
            phase: SandboxPhase::Ready.into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    state.store.put_message(&sandbox).await.unwrap();
    ExecSandboxRequest {
        sandbox: sandbox.object_name().into(),
        workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
        request_id: uuid::Uuid::new_v4().to_string(),
        command: vec!["echo".into(), "secret-command-argument".into()],
        stdin: b"secret-stdin".to_vec(),
        environment: [("PRIVATE".into(), "secret-environment".into())].into(),
        ..Default::default()
    }
}

async fn sandbox_id(state: &ServerState, req: &ExecSandboxRequest) -> String {
    state
        .store
        .get_message_by_name::<Sandbox>("default", &req.sandbox)
        .await
        .unwrap()
        .unwrap()
        .object_id()
        .into()
}

fn register(state: &ServerState, id: &str) -> mpsc::Receiver<GatewayMessage> {
    let (tx, rx) = mpsc::channel(64);
    let (shutdown, _) = oneshot::channel();
    state
        .supervisor_sessions
        .register(id.into(), "session".into(), tx, shutdown);
    rx
}

async fn receive_relay(state: &ServerState, messages: &mut mpsc::Receiver<GatewayMessage>) {
    let message = tokio::time::timeout(std::time::Duration::from_secs(2), messages.recv())
        .await
        .unwrap()
        .unwrap();
    let Some(gateway_message::Payload::RelayOpen(open)) = message.payload else {
        panic!("expected relay open")
    };
    // No SSH transport in these admission tests. Release the detached producer.
    state
        .supervisor_sessions
        .fail_pending_relay(&open.channel_id, "test relay ended".into());
}

async fn completion(state: &ServerState) -> Completion {
    let rows = state
        .store
        .list_by_type_after(OBJECT_TYPE, None, 100)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    let row = rows.into_iter().next().unwrap();
    Completion {
        store: state.store.clone(),
        claim_id: row.id,
        key: row.name,
        bucket: row.workspace,
        version: row.resource_version,
        admission: row.payload,
    }
}

#[test]
fn interactive_fingerprint_uses_start_schema_and_ignores_request_id() {
    let mut req = ExecSandboxRequest {
        request_id: uuid::Uuid::new_v4().to_string(),
        command: vec!["echo".into()],
        ..Default::default()
    };
    let first = fingerprint(&req).unwrap();
    req.request_id = uuid::Uuid::new_v4().to_string();
    let input = ExecSandboxInput {
        payload: Some(exec_sandbox_input::Payload::Start(req.clone())),
    };
    assert_eq!(first, fingerprint(&input).unwrap());
    assert_ne!(ExecSandboxRequest::METHOD, ExecSandboxInput::METHOD);
    req.stdin.push(42);
    assert_ne!(first, fingerprint(&req).unwrap());
    assert_eq!(
        ExecSandboxInput::default()
            .canonical_message()
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
}

#[tokio::test]
async fn concurrent_exec_claims_open_one_relay_and_store_no_secrets() {
    let directory = tempfile::tempdir().unwrap();
    let state = setup("sqlite::memory:", &directory).await;
    let req = request(&state).await;
    let mut messages = register(&state, &sandbox_id(&state, &req).await);
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let state = state.clone();
        let req = req.clone();
        tasks.push(tokio::spawn(async move {
            run(&state, authed_request(req)).await
        }));
    }
    let mut admitted = 0;
    for task in tasks {
        match task.await.unwrap() {
            Ok(_) => admitted += 1,
            Err(status) => assert_eq!(reason(&status), "REQUEST_OUTCOME_UNCERTAIN"),
        }
    }
    assert_eq!(admitted, 1);
    receive_relay(&state, &mut messages).await;
    assert!(messages.try_recv().is_err());
    let pending = completion(&state).await;
    let text = String::from_utf8(pending.admission).unwrap();
    for secret in [
        "secret-command-argument",
        "secret-stdin",
        "secret-environment",
        &fingerprint(&req).unwrap(),
    ] {
        assert!(!text.contains(secret));
    }
    let mut changed = req.clone();
    changed.command.push("different".into());
    assert_eq!(
        reason(&run(&state, authed_request(changed)).await.unwrap_err()),
        "REQUEST_ID_PAYLOAD_MISMATCH"
    );
}

#[tokio::test]
async fn confirmed_exit_including_nonzero_and_124_finalizes_before_output_delivery() {
    for code in [0, 7, 124] {
        let directory = tempfile::tempdir().unwrap();
        let state = setup("sqlite::memory:", &directory).await;
        let req = request(&state).await;
        let mut messages = register(&state, &sandbox_id(&state, &req).await);
        drop(run(&state, authed_request(req.clone())).await.unwrap());
        receive_relay(&state, &mut messages).await;
        let owner = completion(&state).await;
        assert_eq!(
            sandbox::wait_for_exec_terminal(async { Ok(code) }, None, Some(owner.clone()))
                .await
                .unwrap(),
            Some(code)
        );
        assert_eq!(
            reason(&run(&state, authed_request(req)).await.unwrap_err()),
            "REQUEST_STREAM_UNAVAILABLE"
        );
        assert!(
            owner.stream_terminal().await.is_err(),
            "CAS rejects a second finalization"
        );
        let row = completion(&state).await;
        let admission: Admission = serde_json::from_slice(&row.admission).unwrap();
        assert!(matches!(admission.success, Some(Success::StreamTerminal)));
        assert!(admission.completed_at_ms.is_some());
    }
}

#[tokio::test]
async fn timeout_and_lost_exit_status_never_finalize_or_expire_pending_launches() {
    let directory = tempfile::tempdir().unwrap();
    let state = setup("sqlite::memory:", &directory).await;
    let req = request(&state).await;
    let mut messages = register(&state, &sandbox_id(&state, &req).await);
    drop(run(&state, authed_request(req.clone())).await.unwrap());
    receive_relay(&state, &mut messages).await;
    let owner = completion(&state).await;
    for execution_timeout in [
        std::time::Duration::ZERO,
        std::time::Duration::from_nanos(1),
        std::time::Duration::from_secs(1),
    ] {
        assert_eq!(
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                sandbox::wait_for_exec_terminal(
                    std::future::pending(),
                    Some(execution_timeout),
                    Some(owner.clone()),
                ),
            )
            .await
            .expect("a present timeout must not wait indefinitely")
            .unwrap(),
            None
        );
    }
    assert!(
        sandbox::wait_for_exec_terminal(
            async { Err(Status::unavailable("lost exit")) },
            None,
            Some(owner.clone())
        )
        .await
        .is_err()
    );
    let mut admission: Admission = serde_json::from_slice(&owner.admission).unwrap();
    assert!(admission.success.is_none());
    admission.completed_at_ms = Some(current_time_ms() - SUCCESS_TTL_MS - 1);
    state
        .store
        .put_if(
            OBJECT_TYPE,
            &owner.claim_id,
            &owner.key,
            &owner.bucket,
            &serde_json::to_vec(&admission).unwrap(),
            None,
            WriteCondition::MatchResourceVersion(owner.version),
        )
        .await
        .unwrap();
    // A real exit cannot be exposed as confirmed if the finalizer loses its CAS.
    let status = sandbox::wait_for_exec_terminal(async { Ok(0) }, None, Some(owner))
        .await
        .unwrap_err();
    assert_eq!(reason(&status), "REQUEST_OUTCOME_UNCERTAIN");
    assert_eq!(
        reason(&run(&state, authed_request(req)).await.unwrap_err()),
        "REQUEST_OUTCOME_UNCERTAIN"
    );
    assert!(messages.try_recv().is_err());
}

#[tokio::test]
async fn cancellation_before_admission_does_nothing_and_after_admission_keeps_owner() {
    let directory = tempfile::tempdir().unwrap();
    let state = setup("sqlite::memory:", &directory).await;
    let req = request(&state).await;
    drop(run(&state, authed_request(req.clone())));
    assert!(
        state
            .store
            .list_by_type_after(OBJECT_TYPE, None, 100)
            .await
            .unwrap()
            .is_empty()
    );
    let task_state = state.clone();
    let task_req = req.clone();
    let task = tokio::spawn(async move { run(&task_state, authed_request(task_req)).await });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while state
            .store
            .list_by_type_after(OBJECT_TYPE, None, 100)
            .await
            .unwrap()
            .is_empty()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    task.abort();
    let mut messages = register(&state, &sandbox_id(&state, &req).await);
    receive_relay(&state, &mut messages).await;
    assert_eq!(
        reason(&run(&state, authed_request(req)).await.unwrap_err()),
        "REQUEST_OUTCOME_UNCERTAIN"
    );
    assert!(messages.try_recv().is_err());
}

#[tokio::test]
async fn exec_restart_preserves_pending_and_terminal_fences_and_reauthorizes() {
    let directory = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite://{}?mode=rwc",
        directory.path().join("store.db").display()
    );
    let state = setup(&url, &directory).await;
    let req = request(&state).await;
    let mut messages = register(&state, &sandbox_id(&state, &req).await);
    let mut output = run(&state, authed_request(req.clone()))
        .await
        .unwrap()
        .into_inner();
    receive_relay(&state, &mut messages).await;
    assert!(output.next().await.unwrap().is_err());
    assert!(output.next().await.is_none());
    drop(output);
    drop(messages);
    drop(state);
    let state = setup(&url, &directory).await;
    assert_eq!(
        reason(&run(&state, authed_request(req.clone())).await.unwrap_err()),
        "REQUEST_OUTCOME_UNCERTAIN"
    );
    completion(&state).await.stream_terminal().await.unwrap();
    drop(state);
    let state = setup(&url, &directory).await;
    let mut sandbox: Sandbox = state
        .store
        .get_message_by_name("default", &req.sandbox)
        .await
        .unwrap()
        .unwrap();
    sandbox.status.as_mut().unwrap().phase = SandboxPhase::Stopped.into();
    state.store.put_message(&sandbox).await.unwrap();
    assert_eq!(
        reason(&run(&state, authed_request(req.clone())).await.unwrap_err()),
        "REQUEST_STREAM_UNAVAILABLE"
    );
    let mut unauthorized = authed_request(req.clone());
    if let Principal::User(user) = unauthorized
        .extensions_mut()
        .get_mut::<Principal>()
        .unwrap()
    {
        user.identity.roles.clear();
    }
    assert_eq!(
        run(&state, unauthorized).await.unwrap_err().code(),
        tonic::Code::NotFound
    );
    state
        .store
        .delete(Sandbox::object_type(), sandbox.object_id())
        .await
        .unwrap();
    assert_eq!(
        run(&state, authed_request(req)).await.unwrap_err().code(),
        tonic::Code::NotFound
    );
}

#[tokio::test]
async fn noninteractive_rejects_replacement_between_authorizations() {
    replacement_between_authorizations(false).await;
}

#[tokio::test]
async fn interactive_rejects_replacement_between_authorizations() {
    replacement_between_authorizations(true).await;
}

async fn replacement_between_authorizations(interactive: bool) {
    // A payload-only transformation must not be mistaken for redirection.
    for change_command in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let state = setup("sqlite::memory:", &directory).await;
        let mut req = request(&state).await;
        let original = change_command.then(|| original_exec(req.clone(), interactive));
        if change_command {
            req.command.push("transformed-argument".into());
        }
        let id = sandbox_id(&state, &req).await;
        let mut old_messages = register(&state, &id);
        let barrier = Arc::new(AuthorizationBarrier::default());
        let (mut client, server) =
            wire_client(state.clone(), Some(barrier.clone()), original).await;
        let call = tokio::spawn(async move { exec_rpc(&mut client, req, interactive).await });
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            barrier.resolved.notified(),
        )
        .await
        .unwrap();

        let mut replacement: Sandbox = state.store.get_message(&id).await.unwrap().unwrap();
        state
            .store
            .delete(Sandbox::object_type(), &id)
            .await
            .unwrap();
        replacement.metadata.as_mut().unwrap().id = uuid::Uuid::new_v4().to_string();
        state.store.put_message(&replacement).await.unwrap();
        let mut replacement_messages = register(&state, replacement.object_id());
        barrier.resume.notify_one();

        let status = tokio::time::timeout(std::time::Duration::from_secs(5), call)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(reason(&status), "REQUEST_REPLAY_UNAVAILABLE");
        assert!(old_messages.try_recv().is_err());
        assert!(replacement_messages.try_recv().is_err());
        assert!(
            state
                .store
                .list_by_type_after(OBJECT_TYPE, None, 100)
                .await
                .unwrap()
                .is_empty()
        );
        server.abort();
    }
}

#[tokio::test]
async fn exec_transformations_preserve_unchanged_targets_and_explicit_redirection() {
    use openshell_core::proto::Workspace;

    for interactive in [false, true] {
        for redirect in ["command-only", "sandbox", "workspace"] {
            let directory = tempfile::tempdir().unwrap();
            let state = setup("sqlite::memory:", &directory).await;
            let mut req = request(&state).await;
            let original = original_exec(req.clone(), interactive);
            let original_id = sandbox_id(&state, &req).await;
            let mut target: Sandbox = state
                .store
                .get_message(&original_id)
                .await
                .unwrap()
                .unwrap();
            req.command.push("transformed-argument".into());
            if redirect != "command-only" {
                target.metadata.as_mut().unwrap().id = uuid::Uuid::new_v4().to_string();
                if redirect == "sandbox" {
                    req.sandbox = "redirected".into();
                    target.metadata.as_mut().unwrap().name = req.sandbox.clone();
                } else {
                    let workspace = Workspace {
                        metadata: Some(ObjectMeta {
                            id: uuid::Uuid::new_v4().to_string(),
                            name: "redirected".into(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    };
                    state.store.put_message(&workspace).await.unwrap();
                    target.metadata.as_mut().unwrap().workspace = "redirected".into();
                    req.workspace_scope =
                        Some(openshell_core::proto::workspace_selector("redirected"));
                }
                state.store.put_message(&target).await.unwrap();
            }
            let mut messages = register(&state, target.object_id());
            let (mut client, server) = wire_client(state.clone(), None, Some(original)).await;
            drop(exec_rpc(&mut client, req, interactive).await.unwrap());
            receive_relay(&state, &mut messages).await;
            let owner = completion(&state).await;
            let admission: Admission = serde_json::from_slice(&owner.admission).unwrap();
            assert_eq!(admission.target_id.as_deref(), Some(original_id.as_str()));
            owner.ensure_target(target.object_id()).unwrap();
            if redirect != "command-only" {
                assert!(owner.ensure_target(&original_id).is_err());
            }
            server.abort();
        }
    }
}

#[tokio::test]
async fn replacement_cannot_reuse_an_exec_claim_or_receive_its_admitted_launch() {
    for terminal in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let state = setup("sqlite::memory:", &directory).await;
        let req = request(&state).await;
        let id = sandbox_id(&state, &req).await;
        let mut messages = register(&state, &id);
        drop(run(&state, authed_request(req.clone())).await.unwrap());
        receive_relay(&state, &mut messages).await;
        let owner = completion(&state).await;
        owner.ensure_target(&id).unwrap();
        if terminal {
            owner.stream_terminal().await.unwrap();
        }
        let mut replacement: Sandbox = state.store.get_message(&id).await.unwrap().unwrap();
        state
            .store
            .delete(Sandbox::object_type(), &id)
            .await
            .unwrap();
        replacement.metadata.as_mut().unwrap().id = uuid::Uuid::new_v4().to_string();
        state.store.put_message(&replacement).await.unwrap();
        let mut replacement_messages = register(&state, replacement.object_id());

        assert_eq!(
            reason(&run(&state, authed_request(req.clone())).await.unwrap_err()),
            "REQUEST_REPLAY_UNAVAILABLE"
        );
        // Simulate replacement after admission, before the owner resolves its
        // public name again. The original claim must not launch on the new ID.
        let mut admitted = authed_request(req);
        admitted.extensions_mut().insert(owner);
        assert_eq!(
            reason(
                &sandbox::handle_exec_sandbox(&state, admitted)
                    .await
                    .unwrap_err()
            ),
            "REQUEST_OUTCOME_UNCERTAIN"
        );
        assert!(replacement_messages.try_recv().is_err());
    }
}

#[tokio::test]
async fn interactive_wire_start_is_admitted_under_its_own_method_namespace() {
    use crate::grpc::OpenShellService;
    use openshell_core::proto::{
        open_shell_client::OpenShellClient, open_shell_server::OpenShellServer,
    };
    use tokio_stream::wrappers::TcpListenerStream;
    let directory = tempfile::tempdir().unwrap();
    let state = setup("sqlite::memory:", &directory).await;
    let req = request(&state).await;
    let mut messages = register(&state, &sandbox_id(&state, &req).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let principal = authed_request(())
        .extensions()
        .get::<Principal>()
        .unwrap()
        .clone();
    let service = OpenShellServer::with_interceptor(
        OpenShellService::new(state.clone()),
        move |mut request: Request<()>| {
            request.extensions_mut().insert(principal.clone());
            Ok(request)
        },
    );
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let mut client = OpenShellClient::connect(format!("http://{address}"))
        .await
        .unwrap();
    let start = ExecSandboxInput {
        payload: Some(exec_sandbox_input::Payload::Start(req.clone())),
    };
    let output = client
        .exec_sandbox_interactive(tokio_stream::iter([start.clone()]))
        .await
        .unwrap();
    receive_relay(&state, &mut messages).await;
    let owner = completion(&state).await;
    assert_eq!(
        reason(
            &client
                .exec_sandbox_interactive(tokio_stream::iter([start.clone()]))
                .await
                .unwrap_err()
        ),
        "REQUEST_OUTCOME_UNCERTAIN"
    );
    owner.stream_terminal().await.unwrap();
    assert_eq!(
        reason(
            &client
                .exec_sandbox_interactive(tokio_stream::iter([start.clone()]))
                .await
                .unwrap_err()
        ),
        "REQUEST_STREAM_UNAVAILABLE"
    );
    // The same UUID belongs to a different RPC namespace, not another stdin stream.
    drop(client.exec_sandbox(req.clone()).await.unwrap());
    receive_relay(&state, &mut messages).await;
    assert_eq!(
        state
            .store
            .list_by_type_after(OBJECT_TYPE, None, 100)
            .await
            .unwrap()
            .len(),
        2
    );
    let id = sandbox_id(&state, &req).await;
    let mut replacement: Sandbox = state.store.get_message(&id).await.unwrap().unwrap();
    state
        .store
        .delete(Sandbox::object_type(), &id)
        .await
        .unwrap();
    replacement.metadata.as_mut().unwrap().id = uuid::Uuid::new_v4().to_string();
    state.store.put_message(&replacement).await.unwrap();
    let mut replacement_messages = register(&state, replacement.object_id());
    assert_eq!(
        reason(
            &client
                .exec_sandbox_interactive(tokio_stream::iter([start]))
                .await
                .unwrap_err()
        ),
        "REQUEST_REPLAY_UNAVAILABLE"
    );
    assert_eq!(
        reason(&client.exec_sandbox(req).await.unwrap_err()),
        "REQUEST_REPLAY_UNAVAILABLE"
    );
    assert!(replacement_messages.try_recv().is_err());
    drop(output);
    server.abort();
}
