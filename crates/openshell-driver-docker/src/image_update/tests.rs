// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::tests::{
    runtime_config, test_driver_with_config, test_launch_authentication, test_sandbox,
    test_workload_identity,
};
use crate::workspace::tests::{docker_api, fixture_for};
use bollard::models::Volume;

mod live;

type Reply = (&'static str, String, u16, serde_json::Value);

struct Fixture {
    source: ContainerInspectResponse,
    volume: Volume,
    config: DockerDriverRuntimeConfig,
    request: UpdateSandboxConfigurationRequest,
    directory: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let unique = openshell_core::SandboxSessionId::new().to_string();
        let mut sandbox = test_sandbox();
        sandbox.id = unique.clone();
        sandbox.workspace = "synthetic-update".into();
        let mut config = runtime_config();
        config.sandbox_namespace = format!("image-update-test-{unique}");
        config.workspace_storage = workspace::Storage::Persistent;
        let (mut source, volume, config) = fixture_for(sandbox.clone(), config);
        let labels = source.config.as_mut().unwrap().labels.as_mut().unwrap();
        labels.insert(LABEL_SANDBOX_NAME.into(), sandbox.name.clone());
        labels.insert(LABEL_MANAGED_BY.into(), LABEL_MANAGED_BY_VALUE.into());
        labels.insert(
            LABEL_ISOLATION_ROLE.into(),
            LABEL_ISOLATION_ROLE_SANDBOX.into(),
        );
        labels.insert(
            LABEL_ISOLATION_BACKEND.into(),
            LABEL_ISOLATION_BACKEND_OPEN_SHELL.into(),
        );
        source.id = Some("container-A".into());
        source.name = Some(format!("/openshell-fixture-{unique}"));
        source.image = Some("sha256:immutable".into());
        let original_config = source.config.as_mut().unwrap();
        original_config.image = Some("sha256:immutable".into());
        original_config.working_dir = Some("/".into());
        original_config.entrypoint = Some(vec![SANDBOX_BINARY_PATH.into()]);
        original_config.cmd = Some(vec![
            "--bootstrap".into(),
            BOUNDARY_CONFIG_MOUNT_PATH.into(),
        ]);
        original_config.env = Some(vec![
            format!("{}=debug", openshell_core::sandbox_env::LOG_LEVEL),
            format!("{}=false", openshell_core::sandbox_env::TELEMETRY_ENABLED),
            "PATH=/original-image/path".into(),
        ]);
        source.host_config = Some(serde_json::from_value(serde_json::json!({
            "NetworkMode":"none", "CapDrop":["ALL"], "SecurityOpt":["no-new-privileges:true"],
            "GroupAdd":["1236"], "Mounts":[{"Type":"volume", "Source":volume.name, "Target":"/sandbox", "ReadOnly":false, "VolumeOptions":{"NoCopy":true}}]
        })).unwrap());
        source.state = Some(serde_json::from_value(serde_json::json!({"Status":"exited", "Running":false, "Paused":false, "Restarting":false})).unwrap());
        source.network_settings =
            Some(serde_json::from_value(serde_json::json!({"Networks":{}})).unwrap());
        let authentication =
            decode_docker_launch_authentication(&test_launch_authentication()).unwrap();
        let tls = generate_sandbox_tls_material(authentication.supervisor.session_id).unwrap();
        let mut provisioned = isolation::DockerBoundarySpec {
            boundary_id: sandbox.id.clone(),
            generation: authentication.supervisor.runtime_generation.to_string(),
            session_id: authentication.supervisor.session_id,
            session_rotation: authentication.supervisor.session_rotation,
            auth_epoch: authentication.supervisor.auth_epoch,
            gateway_id: authentication.gateway_id,
            verification_keys: gateway_verification_keys(&authentication.verification_keys)
                .unwrap(),
            container_id: "container-A".into(),
            image_identity: "sha256:immutable".into(),
            gpu_requested: false,
            listener_socket: BOUNDARY_SOCKET_MOUNT_PATH.into(),
            control_socket: BOUNDARY_SOCKET_MOUNT_PATH.into(),
            sandbox_tls: SandboxTlsServerConfig {
                certificate_chain_path: BOUNDARY_CERTIFICATE_MOUNT_PATH.into(),
                private_key_path: BOUNDARY_PRIVATE_KEY_MOUNT_PATH.into(),
            },
            supervisor_tls: SandboxTlsClientConfig {
                server_name: tls.server_name,
                trust_anchor_pem: tls.trust_anchor_pem,
            },
            host_gateway_ip: None,
            workload_identity: test_workload_identity(),
            child_env: HashMap::new(),
        }
        .provision()
        .unwrap();
        let directory = prepare_docker_boundary_state_dir(&sandbox, &config).unwrap();
        let record =
            workspace::record_bytes(&sandbox.id, &config, &volume, &test_workload_identity())
                .unwrap();
        durable_write(&directory.join(workspace::RECORD_FILE), &record).unwrap();
        let claim = String::from_utf8(record).unwrap();
        for claims in [
            &mut provisioned.boundary_config.resource_claims,
            &mut provisioned.runtime_descriptor.resource_claims,
        ] {
            claims.insert(workspace::RECORD_CLAIM.into(), claim.clone());
        }
        durable_write(
            &directory.join(BOUNDARY_CONFIG_FILE),
            &provisioned.boundary_config.encode().unwrap(),
        )
        .unwrap();
        durable_write(
            &directory.join(RUNTIME_DESCRIPTOR_FILE),
            &serde_json::to_vec(&provisioned.runtime_descriptor).unwrap(),
        )
        .unwrap();
        Self {
            source,
            volume,
            config,
            directory,
            request: UpdateSandboxConfigurationRequest {
                preconditions: Some(SandboxUpdatePreconditions {
                    sandbox_id: sandbox.id,
                    name: sandbox.name,
                    image: "corrected-image".into(),
                    expected_image: "old-image".into(),
                    expected_runtime_identity: String::new(),
                    operation_id: openshell_core::SandboxSessionId::new().to_string(),
                    validate_only: false,
                    revision: 1,
                }),
                ..Default::default()
            },
        }
    }

    fn p(&self) -> &SandboxUpdatePreconditions {
        self.request.preconditions.as_ref().unwrap()
    }
    fn volume_reply(&self) -> Reply {
        (
            "GET",
            format!("/volumes/{}", self.volume.name),
            200,
            serde_json::to_value(&self.volume).unwrap(),
        )
    }
    fn source_reply(&self) -> Reply {
        (
            "GET",
            "/containers/container-A/json".into(),
            200,
            serde_json::to_value(&self.source).unwrap(),
        )
    }
    fn preflight(&self) -> Vec<Reply> {
        vec![
            self.source_reply(),
            self.volume_reply(),
            (
                "GET",
                "/images/old-image/json".into(),
                200,
                serde_json::json!({"Id":"sha256:immutable"}),
            ),
            (
                "GET",
                "/images/corrected-image/json".into(),
                200,
                serde_json::json!({"Id":"sha256:corrected", "Config":{"WorkingDir":"/sandbox", "User":"1234:1235"}}),
            ),
        ]
    }
    fn start_replies(&self, running: bool) -> Vec<Reply> {
        let mut target = self.target();
        let state = if running { "running" } else { "exited" };
        target.state.as_mut().unwrap().running = Some(running);
        target.state.as_mut().unwrap().status = Some(if running {
            ContainerStateStatusEnum::RUNNING
        } else {
            ContainerStateStatusEnum::EXITED
        });
        vec![
            (
                "GET",
                String::new(),
                200,
                serde_json::json!([{
                    "Id":"container-B", "Names":[target.name], "State":state,
                    "Labels":target.config.as_ref().unwrap().labels
                }]),
            ),
            (
                "GET",
                "/containers/container-B/json".into(),
                200,
                serde_json::to_value(target).unwrap(),
            ),
            self.volume_reply(),
        ]
    }
    fn target(&self) -> ContainerInspectResponse {
        let mut target = self.source.clone();
        target.id = Some("container-B".into());
        target.image = Some("sha256:corrected".into());
        let config = target.config.as_mut().unwrap();
        config.image = Some("sha256:corrected".into());
        config
            .env
            .as_mut()
            .unwrap()
            .retain(|value| !value.starts_with("PATH="));
        config
            .env
            .as_mut()
            .unwrap()
            .push("PATH=/corrected-image/path".into());
        config
            .labels
            .as_mut()
            .unwrap()
            .insert(OPERATION_LABEL.into(), self.p().operation_id.clone());
        config
            .labels
            .as_mut()
            .unwrap()
            .insert(REVISION_LABEL.into(), self.p().revision.to_string());
        target.state.as_mut().unwrap().status = Some(ContainerStateStatusEnum::CREATED);
        target
    }
    fn target_reply(&self, lookup: &str) -> Reply {
        (
            "GET",
            format!("/containers/{lookup}/json"),
            200,
            serde_json::to_value(self.target()).unwrap(),
        )
    }
    fn name(&self) -> &str {
        self.source
            .name
            .as_deref()
            .unwrap()
            .strip_prefix('/')
            .unwrap()
    }
    fn after_create(&self) -> Vec<Reply> {
        vec![
            self.target_reply("container-B"),
            self.volume_reply(),
            self.target_reply("container-B"),
            self.volume_reply(),
        ]
    }
    fn create_reply(&self, status: u16) -> Reply {
        (
            "POST",
            format!("/containers/create?name={}&platform=", self.name()),
            status,
            if status == 201 {
                serde_json::json!({"Id":"container-B", "Warnings":[]})
            } else {
                serde_json::json!({"message":"synthetic creation interruption"})
            },
        )
    }
    fn missing(id: &str) -> Reply {
        (
            "GET",
            format!("/containers/{id}/json"),
            404,
            serde_json::json!({"message":"not found"}),
        )
    }
    fn apply_replies(&self) -> Vec<Reply> {
        let mut replies = self.preflight();
        replies.extend([
            self.source_reply(),
            self.volume_reply(),
            (
                "DELETE",
                "/containers/container-A".into(),
                204,
                serde_json::Value::Null,
            ),
            Self::missing(self.name()),
            self.create_reply(201),
        ]);
        replies.extend(self.after_create());
        replies
    }
    async fn call(
        &self,
        replies: Vec<Reply>,
        request: &UpdateSandboxConfigurationRequest,
    ) -> (Result<(), Status>, Vec<serde_json::Value>) {
        let (docker, server) = docker_api(replies).await;
        let mut driver = test_driver_with_config(self.config.clone());
        driver.docker = Arc::new(docker);
        let result = Box::pin(driver.update_workload_image(request)).await;
        (result, server.await.unwrap())
    }

    async fn grpc_call(
        &self,
        config: DockerDriverRuntimeConfig,
        replies: Vec<Reply>,
        request: UpdateSandboxConfigurationRequest,
    ) -> Result<(), Status> {
        use openshell_core::proto::compute::v1::{
            compute_driver_configuration_updates_client::ComputeDriverConfigurationUpdatesClient,
            compute_driver_configuration_updates_server::ComputeDriverConfigurationUpdatesServer,
        };
        let (docker, api) = docker_api(replies).await;
        let mut driver = test_driver_with_config(config);
        driver.docker = Arc::new(docker);
        let service = ComputeDriverService::new_in_process(driver);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown, stopped) = oneshot::channel();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(ComputeDriverConfigurationUpdatesServer::new(service))
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        let _ = stopped.await;
                    },
                )
                .await
                .unwrap();
        });
        let mut client =
            ComputeDriverConfigurationUpdatesClient::connect(format!("http://{address}"))
                .await
                .unwrap();
        let result = client
            .update_sandbox_configuration(request)
            .await
            .map(|_| ());
        let _ = shutdown.send(());
        server.await.unwrap();
        api.await.unwrap();
        result
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
        if let Some(parent) = self.directory.parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }
}

#[tokio::test]
async fn persistent_update_requires_the_private_workspace_record() {
    for mutation in ["missing", "invalid", "foreign-namespace", "foreign-uid"] {
        let fixture = Fixture::new();
        let path = fixture.directory.join(workspace::RECORD_FILE);
        match mutation {
            "missing" => std::fs::remove_file(&path).unwrap(),
            "invalid" => std::fs::write(&path, "not-json").unwrap(),
            _ => {
                let mut record: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                if mutation == "foreign-namespace" {
                    record["namespace"] = "foreign".into();
                } else {
                    record["uid"] = 2000.into();
                }
                std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
            }
        }
        let (result, requests) = fixture
            .call(vec![fixture.source_reply()], &fixture.request)
            .await;
        assert_eq!(result.unwrap_err().code(), tonic::Code::FailedPrecondition);
        assert_eq!(requests.len(), 1);
        assert!(
            read(&fixture.config, &fixture.p().sandbox_id)
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
async fn replay_requires_storage_authority_before_any_docker_action() {
    for mutation in ["missing", "changed"] {
        let fixture = Fixture::new();
        let (docker, server) = docker_api(fixture.preflight()).await;
        let mut driver = test_driver_with_config(fixture.config.clone());
        driver.docker = Arc::new(docker);
        let intent = driver.prepare_image_update(fixture.p()).await.unwrap();
        server.await.unwrap();
        save(&fixture.config, &intent).unwrap();
        let checkpoint =
            std::fs::read(path(&fixture.config, &fixture.p().sandbox_id).unwrap()).unwrap();
        let record = fixture.directory.join(workspace::RECORD_FILE);
        if mutation == "missing" {
            std::fs::remove_file(&record).unwrap();
        } else {
            let mut value: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&record).unwrap()).unwrap();
            value["uid"] = 2000.into();
            std::fs::write(&record, serde_json::to_vec(&value).unwrap()).unwrap();
        }
        let (result, requests) = fixture.call(vec![], &fixture.request).await;
        assert_eq!(result.unwrap_err().code(), tonic::Code::FailedPrecondition);
        assert!(requests.is_empty());
        assert_eq!(
            std::fs::read(path(&fixture.config, &fixture.p().sandbox_id).unwrap()).unwrap(),
            checkpoint
        );
    }
}

#[tokio::test]
async fn incompatible_target_identity_is_rejected_before_checkpoint_or_deletion() {
    // Symbolic and implicit identities require account lookup. The initial
    // updater rejects those representations rather than assuming that the
    // source identity can execute a different image's application.
    for user in [
        "2000:2000",
        "1234:2000",
        "other:other",
        "1234:other",
        "1234",
        "",
    ] {
        let fixture = Fixture::new();
        let bootstrap = std::fs::read(fixture.directory.join(BOUNDARY_CONFIG_FILE)).unwrap();
        let descriptor = std::fs::read(fixture.directory.join(RUNTIME_DESCRIPTOR_FILE)).unwrap();
        let mut replies = fixture.preflight();
        replies.last_mut().unwrap().3["Config"]["User"] = user.into();
        let (result, requests) = fixture.call(replies, &fixture.request).await;
        assert!(
            matches!(result, Err(ref error) if error.code() == tonic::Code::FailedPrecondition),
            "accepted target USER {user:?}"
        );
        // The fake endpoint accepts only the four read-only preflight calls.
        assert_eq!(requests.len(), 4);
        assert!(
            read(&fixture.config, &fixture.p().sandbox_id)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            std::fs::read(fixture.directory.join(BOUNDARY_CONFIG_FILE)).unwrap(),
            bootstrap
        );
        assert_eq!(
            std::fs::read(fixture.directory.join(RUNTIME_DESCRIPTOR_FILE)).unwrap(),
            descriptor
        );
    }
}

#[tokio::test]
async fn validation_only_checks_original_without_writing_an_intent_or_replacing() {
    let fixture = Fixture::new();
    let mut request = fixture.request.clone();
    request.preconditions.as_mut().unwrap().validate_only = true;
    let original = std::fs::read(fixture.directory.join(RUNTIME_DESCRIPTOR_FILE)).unwrap();
    let mut replies = fixture.preflight();
    replies.extend([fixture.source_reply(), fixture.volume_reply()]);
    fixture.call(replies, &request).await.0.unwrap();
    assert!(
        read(&fixture.config, &fixture.p().sandbox_id)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        std::fs::read(fixture.directory.join(RUNTIME_DESCRIPTOR_FILE)).unwrap(),
        original
    );
}

#[tokio::test]
async fn image_replacement_keeps_native_and_volume_identity_and_publishes_new_evidence() {
    let fixture = Fixture::new();
    let (result, requests) = fixture
        .call(fixture.apply_replies(), &fixture.request)
        .await;
    result.unwrap();
    let intent = read(&fixture.config, &fixture.p().sandbox_id)
        .unwrap()
        .unwrap();
    assert!(intent.phase == Phase::Applied);
    assert_eq!(intent.sandbox_id, fixture.p().sandbox_id);
    assert_eq!(intent.target_container.as_deref(), Some("container-B"));
    assert_eq!(requests[8]["Image"], "sha256:corrected");
    assert!(
        !requests[8]["Env"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value.as_str().unwrap().starts_with("PATH="))
    );
    let descriptor: SandboxRuntimeDescriptor = serde_json::from_slice(
        &std::fs::read(fixture.directory.join(RUNTIME_DESCRIPTOR_FILE)).unwrap(),
    )
    .unwrap();
    assert_eq!(
        descriptor.resource_claims["docker.container_id"],
        "container-B"
    );
    assert_eq!(
        descriptor.resource_claims["docker.image_identity"],
        "sha256:corrected"
    );
    assert_eq!(
        descriptor.resource_claims[workspace::RECORD_CLAIM],
        workspace::record_claim(&fixture.p().sandbox_id, &fixture.config)
            .unwrap()
            .unwrap()
    );
}

#[tokio::test]
async fn running_original_refuses_before_volume_read_or_checkpoint() {
    let mut fixture = Fixture::new();
    fixture.source.state.as_mut().unwrap().running = Some(true);
    fixture.source.state.as_mut().unwrap().status = Some(ContainerStateStatusEnum::RUNNING);
    let error = fixture
        .call(vec![fixture.source_reply()], &fixture.request)
        .await
        .0
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert!(
        read(&fixture.config, &fixture.p().sandbox_id)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn failed_target_creation_recovers_same_operation_in_a_fresh_driver() {
    let fixture = Fixture::new();
    let mut replies = fixture.preflight();
    replies.extend([
        fixture.source_reply(),
        fixture.volume_reply(),
        (
            "DELETE",
            "/containers/container-A".into(),
            204,
            serde_json::Value::Null,
        ),
        Fixture::missing(fixture.name()),
        fixture.create_reply(500),
    ]);
    assert_eq!(
        fixture
            .call(replies, &fixture.request)
            .await
            .0
            .unwrap_err()
            .code(),
        tonic::Code::Unavailable
    );
    let before = read(&fixture.config, &fixture.p().sandbox_id)
        .unwrap()
        .unwrap();
    assert!(before.phase == Phase::Prepared);
    let mut recovery = vec![
        Fixture::missing("container-A"),
        Fixture::missing(fixture.name()),
        fixture.create_reply(201),
    ];
    recovery.extend(fixture.after_create());
    fixture.call(recovery, &fixture.request).await.0.unwrap();
    let applied = read(&fixture.config, &fixture.p().sandbox_id)
        .unwrap()
        .unwrap();
    assert!(applied.phase == Phase::Applied);
    assert_eq!(applied.operation_id, before.operation_id);
    fixture
        .call(
            vec![fixture.target_reply("container-B"), fixture.volume_reply()],
            &fixture.request,
        )
        .await
        .0
        .unwrap();
}

#[tokio::test]
async fn target_created_before_checkpoint_is_reconciled_without_another_create() {
    let fixture = Fixture::new();
    let (docker, server) = docker_api(fixture.preflight()).await;
    let mut driver = test_driver_with_config(fixture.config.clone());
    driver.docker = Arc::new(docker);
    let intent = driver.prepare_image_update(fixture.p()).await.unwrap();
    server.await.unwrap();
    save(&fixture.config, &intent).unwrap();
    let mut replies = vec![
        Fixture::missing("container-A"),
        fixture.target_reply(fixture.name()),
        fixture.volume_reply(),
    ];
    replies.extend([fixture.target_reply("container-B"), fixture.volume_reply()]);
    fixture.call(replies, &fixture.request).await.0.unwrap();
    assert!(
        read(&fixture.config, &fixture.p().sandbox_id)
            .unwrap()
            .unwrap()
            .phase
            == Phase::Applied
    );
}

#[test]
fn request_validation_rejects_paths_unsupported_mutations_and_foreign_compute_identity() {
    let fixture = Fixture::new();
    let mut request = fixture.request.clone();
    request.preconditions.as_mut().unwrap().sandbox_id = "../foreign".into();
    assert!(validate_request(&request).is_err());
    request = fixture.request.clone();
    request
        .preconditions
        .as_mut()
        .unwrap()
        .expected_runtime_identity = "foreign".into();
    assert!(validate_request(&request).is_err());
    request = fixture.request.clone();
    request.environment =
        Some(openshell_core::proto::compute::v1::SandboxEnvironmentUpdate::default());
    assert_eq!(
        validate_request(&request).unwrap_err().code(),
        tonic::Code::Unimplemented
    );
}

#[tokio::test]
async fn interrupted_boundary_publication_is_repaired_from_the_same_native_intent() {
    let fixture = Fixture::new();
    fixture
        .call(fixture.apply_replies(), &fixture.request)
        .await
        .0
        .unwrap();
    let mut intent = read(&fixture.config, &fixture.p().sandbox_id)
        .unwrap()
        .unwrap();
    intent.phase = Phase::Replaced;
    save(&fixture.config, &intent).unwrap();
    durable_write(
        &fixture.directory.join(BOUNDARY_CONFIG_FILE),
        b"{incomplete",
    )
    .unwrap();
    fixture
        .call(
            vec![fixture.target_reply("container-B"), fixture.volume_reply()],
            &fixture.request,
        )
        .await
        .0
        .unwrap();
    let applied = read(&fixture.config, &fixture.p().sandbox_id)
        .unwrap()
        .unwrap();
    assert!(applied.phase == Phase::Applied);
    verify_published_boundary(&applied, &fixture.config).unwrap();
    assert_eq!(applied.operation_id, intent.operation_id);
}

#[tokio::test]
async fn same_name_target_with_another_operation_is_not_adopted() {
    let fixture = Fixture::new();
    let (docker, server) = docker_api(fixture.preflight()).await;
    let mut driver = test_driver_with_config(fixture.config.clone());
    driver.docker = Arc::new(docker);
    let intent = driver.prepare_image_update(fixture.p()).await.unwrap();
    server.await.unwrap();
    save(&fixture.config, &intent).unwrap();
    let mut foreign = fixture.target();
    foreign
        .config
        .as_mut()
        .unwrap()
        .labels
        .as_mut()
        .unwrap()
        .insert(OPERATION_LABEL.into(), "foreign-operation".into());
    let replies = vec![
        Fixture::missing("container-A"),
        (
            "GET",
            format!("/containers/{}/json", fixture.name()),
            200,
            serde_json::to_value(foreign).unwrap(),
        ),
        fixture.volume_reply(),
    ];
    let error = fixture.call(replies, &fixture.request).await.0.unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert!(
        read(&fixture.config, &fixture.p().sandbox_id)
            .unwrap()
            .unwrap()
            .phase
            == Phase::Prepared
    );
    assert_eq!(
        std::fs::read(fixture.directory.join(RUNTIME_DESCRIPTOR_FILE)).unwrap(),
        intent.original_descriptor
    );
}

#[tokio::test]
async fn conflicting_replay_refuses_before_docker_or_checkpoint_writes() {
    let fixture = Fixture::new();
    fixture
        .call(fixture.apply_replies(), &fixture.request)
        .await
        .0
        .unwrap();
    let checkpoint =
        std::fs::read(path(&fixture.config, &fixture.p().sandbox_id).unwrap()).unwrap();
    let mut conflicting = fixture.request.clone();
    conflicting.preconditions.as_mut().unwrap().operation_id =
        openshell_core::SandboxSessionId::new().to_string();
    let error = fixture.call(vec![], &conflicting).await.0.unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        std::fs::read(path(&fixture.config, &fixture.p().sandbox_id).unwrap()).unwrap(),
        checkpoint
    );
}

#[tokio::test]
async fn replacement_cannot_substitute_another_persistent_volume_record() {
    let fixture = Fixture::new();
    let (docker, server) = docker_api(fixture.preflight()).await;
    let mut driver = test_driver_with_config(fixture.config.clone());
    driver.docker = Arc::new(docker);
    let intent = driver.prepare_image_update(fixture.p()).await.unwrap();
    server.await.unwrap();
    let mut target = fixture.target();
    verify_replacement(&target, &intent).unwrap();
    target
        .host_config
        .as_mut()
        .unwrap()
        .mounts
        .as_mut()
        .unwrap()[0]
        .source = Some("foreign-volume".into());
    assert_eq!(
        verify_replacement(&target, &intent).unwrap_err().code(),
        tonic::Code::FailedPrecondition
    );
}

#[tokio::test]
async fn pending_update_survives_driver_restart_and_blocks_start_by_id_or_name() {
    let fixture = Fixture::new();
    let (docker, server) = docker_api(fixture.preflight()).await;
    let mut driver = test_driver_with_config(fixture.config.clone());
    driver.docker = Arc::new(docker);
    let intent = driver.prepare_image_update(fixture.p()).await.unwrap();
    server.await.unwrap();
    save(&fixture.config, &intent).unwrap();
    let snapshots = pending_snapshots(&fixture.config).unwrap();
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].id, fixture.p().sandbox_id);
    assert_eq!(
        snapshots[0].status.as_ref().unwrap().conditions[0].reason,
        openshell_core::driver_utils::CONDITION_STOPPED
    );
    assert_eq!(
        pending_ids(&fixture.config).unwrap(),
        vec![fixture.p().sandbox_id.clone()]
    );
    let (docker, server) = docker_api(vec![]).await;
    let mut reopened = test_driver_with_config(fixture.config.clone());
    reopened.docker = Arc::new(docker);
    let observed = reopened
        .get_sandbox_snapshot("", &fixture.p().name)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(observed.id, fixture.p().sandbox_id);
    for id in [fixture.p().sandbox_id.as_str(), ""] {
        let error = Box::pin(reopened.start_sandbox(
            id,
            &fixture.p().name,
            "generation-2",
            &test_launch_authentication(),
            None,
        ))
        .await
        .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    }
    server.await.unwrap();
    assert!(
        read(&fixture.config, &fixture.p().sandbox_id)
            .unwrap()
            .unwrap()
            .phase
            == Phase::Prepared
    );
}

#[tokio::test]
async fn completed_update_clears_pending_inventory_and_keeps_start_bound_to_target() {
    let fixture = Fixture::new();
    fixture
        .call(fixture.apply_replies(), &fixture.request)
        .await
        .0
        .unwrap();
    assert!(pending_ids(&fixture.config).unwrap().is_empty());
    assert!(
        pending_snapshot(&fixture.config, &fixture.p().sandbox_id, &fixture.p().name)
            .unwrap()
            .is_none()
    );
    require_settled(&fixture.config, &fixture.p().sandbox_id).unwrap();
    let mut target = fixture.target();
    validate_committed_resource(
        &fixture.config,
        &fixture.p().sandbox_id,
        &target,
        LaunchValidation::Complete,
    )
    .unwrap();
    target.id = Some("same-name-foreign-container".into());
    assert!(
        validate_committed_resource(
            &fixture.config,
            &fixture.p().sandbox_id,
            &target,
            LaunchValidation::Complete
        )
        .is_err()
    );
}

#[tokio::test]
async fn stopped_start_repairs_interrupted_launch_rotation_before_staging() {
    let fixture = Fixture::new();
    fixture
        .call(fixture.apply_replies(), &fixture.request)
        .await
        .0
        .unwrap();
    let descriptor_path = fixture.directory.join(RUNTIME_DESCRIPTOR_FILE);
    let previous_descriptor = std::fs::read(&descriptor_path).unwrap();
    let mut interrupted =
        decode_docker_launch_authentication(&test_launch_authentication()).unwrap();
    interrupted.supervisor.runtime_generation =
        openshell_core::sandbox_generation::SandboxGenerationId::parse("generation-interrupted")
            .unwrap();
    let interrupted_authentication = serde_json::to_vec(&interrupted).unwrap();
    refresh_docker_boundary_authentication(
        &fixture.p().sandbox_id,
        &fixture.config,
        &interrupted_authentication,
    )
    .await
    .unwrap();
    // Model exit after bootstrap publication but before descriptor publication.
    std::fs::write(&descriptor_path, previous_descriptor).unwrap();
    let intent = read(&fixture.config, &fixture.p().sandbox_id)
        .unwrap()
        .unwrap();
    assert!(verify_published_boundary(&intent, &fixture.config).is_err());

    let (docker, server) = docker_api(fixture.start_replies(false)).await;
    let mut driver = test_driver_with_config(fixture.config.clone());
    driver.docker = Arc::new(docker);
    let mut authentication =
        decode_docker_launch_authentication(&test_launch_authentication()).unwrap();
    authentication.supervisor.runtime_generation =
        openshell_core::sandbox_generation::SandboxGenerationId::parse("generation-retry").unwrap();
    let encoded = serde_json::to_vec(&authentication).unwrap();
    let error = Box::pin(driver.start_sandbox(
        &fixture.p().sandbox_id,
        &fixture.p().name,
        "generation-retry",
        &encoded,
        None,
    ))
    .await
    .unwrap_err();
    server.await.unwrap();
    // Deliberately omit the workspace-root staging input: reaching this gate
    // proves the real Start path repaired publication, without starting a fake
    // workload or requiring a supervisor process in this unit test.
    assert!(error.message().contains("workspace for restart"), "{error}");
    verify_published_boundary(&intent, &fixture.config).unwrap();
    let repaired = read_docker_runtime_descriptor(&fixture.p().sandbox_id, &fixture.config)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(repaired.generation, "generation-retry");
    assert_eq!(repaired.session_id, authentication.supervisor.session_id);
    assert_eq!(
        repaired.resource_claims["docker.container_id"],
        "container-B"
    );
    assert_eq!(
        repaired.resource_claims["docker.image_identity"],
        "sha256:corrected"
    );
}

#[tokio::test]
async fn interrupted_launch_pair_requires_stopped_workload_and_fresh_authentication() {
    for (running, fresh_authentication, inspected_running) in [
        (true, true, true),
        (false, false, false),
        (false, true, true),
    ] {
        let fixture = Fixture::new();
        fixture
            .call(fixture.apply_replies(), &fixture.request)
            .await
            .0
            .unwrap();
        let descriptor_path = fixture.directory.join(RUNTIME_DESCRIPTOR_FILE);
        let previous_descriptor = std::fs::read(&descriptor_path).unwrap();
        refresh_docker_boundary_authentication(
            &fixture.p().sandbox_id,
            &fixture.config,
            &test_launch_authentication(),
        )
        .await
        .unwrap();
        std::fs::write(&descriptor_path, &previous_descriptor).unwrap();
        let previous_bootstrap =
            std::fs::read(fixture.directory.join(BOUNDARY_CONFIG_FILE)).unwrap();
        let mut replies = fixture.start_replies(running);
        if inspected_running {
            replies[1].3["State"]["Running"] = true.into();
            replies[1].3["State"]["Status"] = "running".into();
        }
        let (docker, server) = docker_api(replies).await;
        let mut driver = test_driver_with_config(fixture.config.clone());
        driver.docker = Arc::new(docker);
        let authentication = if fresh_authentication {
            test_launch_authentication()
        } else {
            Vec::new()
        };
        let error = Box::pin(driver.start_sandbox(
            &fixture.p().sandbox_id,
            &fixture.p().name,
            "generation-1",
            &authentication,
            None,
        ))
        .await
        .unwrap_err();
        server.await.unwrap();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(
            error.message().contains(if !running && inspected_running {
                "verifiably stopped"
            } else {
                "runtime evidence is inconsistent"
            }),
            "{error}"
        );
        assert_eq!(
            std::fs::read(&descriptor_path).unwrap(),
            previous_descriptor
        );
        assert_eq!(
            std::fs::read(fixture.directory.join(BOUNDARY_CONFIG_FILE)).unwrap(),
            previous_bootstrap
        );
    }
}

#[tokio::test]
async fn launch_repair_never_adopts_changed_immutable_bindings() {
    let fixture = Fixture::new();
    fixture
        .call(fixture.apply_replies(), &fixture.request)
        .await
        .0
        .unwrap();
    for filename in [BOUNDARY_CONFIG_FILE, RUNTIME_DESCRIPTOR_FILE] {
        let path = fixture.directory.join(filename);
        let original = std::fs::read(&path).unwrap();
        for (pointer, foreign) in [
            ("/boundary_id", serde_json::json!("foreign-sandbox")),
            (
                "/resource_claims/docker.container_id",
                serde_json::json!("foreign-container"),
            ),
            (
                "/resource_claims/docker.image_identity",
                serde_json::json!("sha256:foreign"),
            ),
            ("/workload_identity/uid", serde_json::json!(2000)),
            ("/workload_identity/gid", serde_json::json!(2000)),
        ] {
            let mut changed: serde_json::Value = serde_json::from_slice(&original).unwrap();
            *changed.pointer_mut(pointer).unwrap() = foreign;
            let changed = serde_json::to_vec(&changed).unwrap();
            std::fs::write(&path, &changed).unwrap();
            let mut replies = fixture.start_replies(false);
            if filename == RUNTIME_DESCRIPTOR_FILE
                && matches!(
                    pointer,
                    "/boundary_id" | "/workload_identity/uid" | "/workload_identity/gid"
                )
            {
                replies.pop(); // The protected record rejects before volume access.
            }
            let (docker, server) = docker_api(replies).await;
            let mut driver = test_driver_with_config(fixture.config.clone());
            driver.docker = Arc::new(docker);
            let error = Box::pin(driver.start_sandbox(
                &fixture.p().sandbox_id,
                &fixture.p().name,
                "generation-1",
                &test_launch_authentication(),
                None,
            ))
            .await
            .unwrap_err();
            server.await.unwrap();
            assert_eq!(error.code(), tonic::Code::FailedPrecondition);
            assert_eq!(std::fs::read(&path).unwrap(), changed);
        }
        std::fs::write(path, original).unwrap();
    }
    // Native container/image/workspace substitutions must also fail before
    // credential publication, independently of the private file checks.
    for (pointer, foreign) in [
        ("/Id", "foreign-container"),
        ("/Image", "sha256:foreign"),
        ("/HostConfig/Mounts/0/Source", "foreign-workspace"),
    ] {
        let mut target = serde_json::to_value(fixture.target()).unwrap();
        *target.pointer_mut(pointer).unwrap() = foreign.into();
        let target: ContainerInspectResponse = serde_json::from_value(target).unwrap();
        assert!(
            validate_committed_resource(
                &fixture.config,
                &fixture.p().sandbox_id,
                &target,
                LaunchValidation::BeforeStoppedRotation
            )
            .is_err()
        );
    }
}

async fn prepared_fixture() -> Fixture {
    let fixture = Fixture::new();
    let (docker, server) = docker_api(fixture.preflight()).await;
    let mut driver = test_driver_with_config(fixture.config.clone());
    driver.docker = Arc::new(docker);
    let intent = driver.prepare_image_update(fixture.p()).await.unwrap();
    server.await.unwrap();
    save(&fixture.config, &intent).unwrap();
    fixture
}

#[tokio::test]
async fn startup_cleanup_and_stop_preserve_pending_update_without_a_workload() {
    let fixture = prepared_fixture().await;
    let mut channel = fixture.volume.clone();
    channel.name = docker_channel_volume_name_by_id(&fixture.p().sandbox_id, &fixture.config);
    channel.labels.remove(workspace::ROLE_LABEL);
    // All three list operations are read-only. Any removal during startup or
    // Stop would fail the fixture's next expected method.
    let replies = vec![
        ("GET", String::new(), 200, serde_json::json!([])),
        ("GET", String::new(), 200, serde_json::json!([])),
        (
            "GET",
            String::new(),
            200,
            serde_json::json!({"Volumes":[fixture.volume, channel]}),
        ),
        ("GET", String::new(), 200, serde_json::json!([])),
        ("GET", String::new(), 200, serde_json::json!([])),
    ];
    let (docker, server) = docker_api(replies).await;
    let mut reopened = test_driver_with_config(fixture.config.clone());
    reopened.docker = Arc::new(docker);
    reopened
        .reconcile_runtime_resources_at_startup()
        .await
        .unwrap();
    ComputeDriver::stop_sandbox(
        &reopened,
        Request::new(StopSandboxRequest {
            sandbox_id: String::new(),
            name: fixture.p().name.clone(),
        }),
    )
    .await
    .unwrap();
    server.await.unwrap();
    assert_eq!(
        pending_ids(&fixture.config).unwrap(),
        vec![fixture.p().sandbox_id.clone()]
    );
    assert!(fixture.directory.join(RUNTIME_DESCRIPTOR_FILE).is_file());
}

#[tokio::test]
async fn explicit_delete_clears_pending_gap_and_reports_the_deleted_native_resource() {
    let fixture = prepared_fixture().await;
    let mut replies = vec![
        ("GET", String::new(), 200, serde_json::json!([])),
        ("GET", String::new(), 200, serde_json::json!([])),
        fixture.volume_reply(),
        (
            "DELETE",
            format!("/volumes/{}", fixture.volume.name),
            204,
            serde_json::Value::Null,
        ),
    ];
    for name in [
        docker_channel_volume_name_by_id(&fixture.p().sandbox_id, &fixture.config),
        docker_supervisor_volume_name_by_id(&fixture.p().sandbox_id, &fixture.config),
        docker_control_volume_name_by_id(&fixture.p().sandbox_id, &fixture.config),
    ] {
        replies.push((
            "DELETE",
            format!("/volumes/{name}"),
            204,
            serde_json::Value::Null,
        ));
    }
    let (docker, server) = docker_api(replies).await;
    let mut reopened = test_driver_with_config(fixture.config.clone());
    reopened.docker = Arc::new(docker);
    let response = ComputeDriver::delete_sandbox(
        &reopened,
        Request::new(DeleteSandboxRequest {
            sandbox_id: String::new(),
            name: fixture.p().name.clone(),
        }),
    )
    .await
    .unwrap()
    .into_inner();
    server.await.unwrap();
    assert!(response.deleted);
    assert!(pending_ids(&fixture.config).unwrap().is_empty());
    assert!(!fixture.directory.exists());
}

#[tokio::test]
async fn optional_rpc_remains_disabled_without_persistent_storage() {
    let fixture = Fixture::new();
    let mut config = fixture.config.clone();
    config.workspace_storage = workspace::Storage::WritableLayer;
    let capability = openshell_core::extension_protocol::COMPUTE_UPDATE_SANDBOX_CONFIGURATION;
    let advertised = test_driver_with_config(config.clone())
        .capabilities()
        .extension
        .unwrap()
        .supported_capabilities;
    assert!(!advertised.iter().any(|value| value == capability));
    let error = fixture
        .grpc_call(config, vec![], fixture.request.clone())
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::Unimplemented);
    assert!(
        read(&fixture.config, &fixture.p().sandbox_id)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn optional_rpc_uses_the_existing_preflight_contract_when_enabled() {
    let fixture = Fixture::new();
    let capability = openshell_core::extension_protocol::COMPUTE_UPDATE_SANDBOX_CONFIGURATION;
    let advertised = test_driver_with_config(fixture.config.clone())
        .capabilities()
        .extension
        .unwrap()
        .supported_capabilities;
    assert!(advertised.iter().any(|value| value == capability));
    let mut request = fixture.request.clone();
    request.preconditions.as_mut().unwrap().validate_only = true;
    let mut replies = fixture.preflight();
    replies.extend([fixture.source_reply(), fixture.volume_reply()]);
    fixture
        .grpc_call(fixture.config.clone(), replies, request)
        .await
        .unwrap();
    assert!(
        read(&fixture.config, &fixture.p().sandbox_id)
            .unwrap()
            .is_none()
    );
}
