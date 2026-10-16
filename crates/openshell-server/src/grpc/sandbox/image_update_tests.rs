// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::grpc::test_support::{authed_request, test_server_state};
use crate::test_support::{FakeComputeDriver, FakeComputeDriverCall};
use openshell_core::proto::UpdateSandboxRequest;
use openshell_core::proto::compute::v1::GetCapabilitiesResponse;
use openshell_core::proto::datamodel::v1::ObjectMeta;
use openshell_core::proto::sandbox_updates_client::SandboxUpdatesClient;
use tonic::Code;

struct RunningService(tokio::task::JoinHandle<()>);

impl Drop for RunningService {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn wire_client(
    state: Arc<ServerState>,
) -> (
    SandboxUpdatesClient<tonic::transport::Channel>,
    RunningService,
) {
    use crate::multiplex::MultiplexService;
    use openshell_core::proto::open_shell_client::OpenShellClient;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    // Use the production gateway multiplexer, not a standalone tonic server:
    // this proves registration, routing and principal injection on the same
    // listener as the unchanged OpenShell service.
    let server = RunningService(tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let service = MultiplexService::new(state.clone());
            connections.spawn(async move { service.serve(stream).await.unwrap() });
        }
    }));
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    OpenShellClient::new(channel.clone())
        .health(openshell_core::proto::HealthRequest {})
        .await
        .unwrap();
    (SandboxUpdatesClient::new(channel), server)
}

#[test]
fn image_updates_have_their_own_authenticated_workspace_scoped_service() {
    use crate::auth::method_authz::{AuthMode, lookup};
    use crate::grpc::mutation_replay::Mutation;

    let path = "/openshell.v1.SandboxUpdates/UpdateSandbox";
    let authorization = lookup(path).expect("new service must participate in gateway auth");
    assert_eq!(authorization.auth_mode, AuthMode::Bearer);
    assert_eq!(authorization.scope.as_deref(), Some("sandbox:write"));
    assert_eq!(authorization.workspace_role.as_deref(), Some("user"));
    assert!(lookup("/openshell.v1.OpenShell/UpdateSandbox").is_none());
    assert_eq!(<UpdateSandboxRequest as Mutation>::REPLAY_METHOD, path);
}

fn request() -> UpdateSandboxRequest {
    UpdateSandboxRequest {
        workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
        name: "image-update".into(),
        image: "example/workload:new".into(),
        expected_resource_version: 1,
        request_id: String::new(),
    }
}

#[test]
fn image_only_request_requires_target_image_and_conditional_version() {
    let valid = request();
    validate_image_update_request(&valid).unwrap();
    for image in ["", "  ", "example/workload:tag\n", "bad image", "a\0b"] {
        assert_eq!(
            validate_image_update_request(&UpdateSandboxRequest {
                image: image.into(),
                ..valid.clone()
            })
            .unwrap_err()
            .code(),
            Code::InvalidArgument
        );
    }
    assert!(
        validate_image_update_request(&UpdateSandboxRequest {
            image: "a".repeat(super::super::MAX_TEMPLATE_STRING_LEN + 1),
            ..valid.clone()
        })
        .is_err()
    );
    assert!(
        validate_image_update_request(&UpdateSandboxRequest {
            name: String::new(),
            ..valid.clone()
        })
        .is_err()
    );
    assert!(
        validate_image_update_request(&UpdateSandboxRequest {
            expected_resource_version: 0,
            ..valid
        })
        .is_err()
    );
}

async fn state() -> (Arc<ServerState>, Arc<FakeComputeDriver>, Sandbox) {
    let mut state = test_server_state().await;
    Arc::get_mut(&mut state)
        .unwrap()
        .config
        .enable_sandbox_image_updates = true;
    let driver = Arc::new(
        FakeComputeDriver::new().with_capabilities(GetCapabilitiesResponse {
            driver_name: "image-test".into(),
            default_image: "example/workload:old".into(),
            extension: Some(openshell_core::extension_protocol::extension_metadata(
                openshell_core::extension_protocol::ExtensionFamily::Compute,
                "openshell/image-test",
                "test",
                [openshell_core::extension_protocol::COMPUTE_UPDATE_SANDBOX_IMAGE.into()],
            )),
            ..Default::default()
        }),
    );
    let compute = crate::compute::ComputeRuntime::from_driver(
        "image-test".into(),
        driver.clone(),
        None,
        state.store.clone(),
        crate::sandbox_index::SandboxIndex::new(),
        crate::sandbox_watch::SandboxWatchBus::new(),
        crate::tracing_bus::TracingLogBus::new(),
        Arc::new(crate::supervisor_session::SupervisorSessionRegistry::new()),
    )
    .await
    .unwrap()
    .with_image_update_driver(Some(driver.clone()))
    .with_sandbox_image_updates(true);
    Arc::get_mut(&mut state).unwrap().compute = compute;
    let mut sandbox = Sandbox {
        metadata: Some(ObjectMeta {
            id: "stable-sandbox-id".into(),
            name: "image-update".into(),
            workspace: "default".into(),
            ..Default::default()
        }),
        spec: Some(SandboxSpec {
            template: Some(SandboxTemplate {
                image: "example/workload:old".into(),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    sandbox.set_phase(SandboxPhase::Stopped as i32);
    state.store.put_message(&sandbox).await.unwrap();
    let sandbox = state
        .store
        .get_message::<Sandbox>(sandbox.object_id())
        .await
        .unwrap()
        .unwrap();
    (state, driver, sandbox)
}

#[tokio::test]
async fn public_image_update_checks_workspace_and_missing_resource() {
    let (state, driver, sandbox) = state().await;
    let mut req = request();
    req.expected_resource_version = sandbox.get_resource_version();
    req.workspace_scope = None;
    assert_eq!(
        handle_update_sandbox(&state, authed_request(req.clone()))
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    req.workspace_scope = Some(openshell_core::proto::workspace_selector("default"));
    req.name = "missing-sandbox".into();
    assert_eq!(
        handle_update_sandbox(&state, authed_request(req))
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
    assert!(
        !driver
            .calls()
            .iter()
            .any(|call| matches!(call, FakeComputeDriverCall::UpdateSandboxImage { .. }))
    );
}

#[tokio::test]
async fn public_image_update_replays_without_reapplying_or_touching_same_name_replacement() {
    let (mut state, driver, sandbox) = state().await;
    let directory = tempfile::tempdir().unwrap();
    let key = directory.path().join("private-key");
    std::fs::write(&key, b"test-only stable private fingerprint material").unwrap();
    Arc::get_mut(&mut state).unwrap().config.gateway_jwt =
        Some(openshell_core::config::GatewayJwtConfig {
            signing_key_path: key,
            public_key_path: directory.path().join("public"),
            kid_path: directory.path().join("kid"),
            gateway_id: "test".into(),
            ttl_secs: None,
        });
    let (mut client, _server) = wire_client(state.clone()).await;
    let req = UpdateSandboxRequest {
        expected_resource_version: sandbox.get_resource_version(),
        request_id: uuid::Uuid::new_v4().to_string(),
        ..request()
    };
    let updated = client
        .update_sandbox(req.clone())
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();
    assert_eq!(updated.object_id(), sandbox.object_id());
    assert_eq!(
        updated
            .spec
            .as_ref()
            .unwrap()
            .template
            .as_ref()
            .unwrap()
            .image,
        req.image
    );
    let replay = client.update_sandbox(req.clone()).await.unwrap();
    assert_eq!(replay.metadata().get("openshell-replayed").unwrap(), "true");
    assert_eq!(replay.get_ref().sandbox.as_ref().unwrap(), &updated);
    assert_eq!(driver.calls().iter().filter(|call| matches!(call, FakeComputeDriverCall::UpdateSandboxImage { request } if !request.validate_only)).count(), 1);
    let changed = UpdateSandboxRequest {
        image: "example/workload:other".into(),
        ..req.clone()
    };
    assert_eq!(
        client.update_sandbox(changed).await.unwrap_err().code(),
        Code::FailedPrecondition
    );
    state
        .store
        .delete(Sandbox::object_type(), sandbox.object_id())
        .await
        .unwrap();
    let mut replacement = sandbox.clone();
    let metadata = replacement.metadata.as_mut().unwrap();
    metadata.id = "replacement-sandbox-id".into();
    metadata.resource_version = 0;
    state.store.put_message(&replacement).await.unwrap();
    assert_eq!(
        client.update_sandbox(req).await.unwrap_err().code(),
        Code::FailedPrecondition
    );
    let replacement = state
        .store
        .get_message::<Sandbox>(replacement.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(replacement.spec, sandbox.spec);
    assert_eq!(driver.calls().iter().filter(|call| matches!(call, FakeComputeDriverCall::UpdateSandboxImage { request } if !request.validate_only)).count(), 1);
}
