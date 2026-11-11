// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::tests::{
    runtime_config, test_driver_with_config, test_launch_authentication, test_sandbox,
    test_workload_identity,
};
use crate::workspace::tests::{docker_api, fixture_for};
use bollard::models::Volume;

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
        let provisioned = isolation::DockerBoundarySpec {
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
    let record =
        fixture.target().config.unwrap().labels.unwrap()[workspace::IDENTITY_LABEL].clone();
    assert_eq!(
        intent.body.labels.unwrap()[workspace::IDENTITY_LABEL],
        record
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
        .config
        .as_mut()
        .unwrap()
        .labels
        .as_mut()
        .unwrap()
        .insert(workspace::IDENTITY_LABEL.into(), "foreign-volume".into());
    assert_eq!(
        verify_replacement(&target, &intent).unwrap_err().code(),
        tonic::Code::FailedPrecondition
    );
}
