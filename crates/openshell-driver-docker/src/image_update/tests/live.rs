// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Opt-in real-Docker driver integration; not gateway/supervisor protocol E2E.
//! See the crate README for image preparation and invocation.

use super::*;
use std::process::Command;

struct Resources {
    container: String,
    volume: String,
    sandbox: String,
}

impl Drop for Resources {
    fn drop(&mut self) {
        // No force, broad selectors, or removal of unverified resources, even
        // when an assertion fails halfway through replacement.
        for (kind, name, label_path) in [
            ("container", &self.container, ".Config.Labels"),
            ("volume", &self.volume, ".Labels"),
        ] {
            let format = format!("{{{{index {label_path} \"{LABEL_SANDBOX_ID}\"}}}}");
            let owned = Command::new("docker")
                .args([kind, "inspect", "--format", &format, name])
                .output()
                .is_ok_and(|output| {
                    output.status.success()
                        && String::from_utf8_lossy(&output.stdout).trim() == self.sandbox
                });
            if owned {
                let removed = Command::new("docker").args([kind, "rm", name]).output();
                if !removed.is_ok_and(|output| output.status.success()) {
                    eprintln!("live Docker test could not remove its owned {kind} {name}");
                }
            }
        }
    }
}

fn archived_file(docker_id: &str, path: &str) -> Vec<u8> {
    let output = Command::new("docker")
        .args(["cp", &format!("{docker_id}:{path}"), "-"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let mut archive = tar::Archive::new(output.stdout.as_slice());
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(
        &mut archive.entries().unwrap().next().unwrap().unwrap(),
        &mut bytes,
    )
    .unwrap();
    bytes
}

#[tokio::test]
#[ignore = "requires a live Docker daemon and the four prepared test images; see README"]
async fn live_stopped_image_replacement_retains_data_and_recovers_a_deleted_source() {
    let images: Vec<String> = ["A", "B", "BAD", "SYMBOLIC"]
        .into_iter()
        .map(|suffix| {
            std::env::var(format!("OPENSHELL_DOCKER_UPDATE_IMAGE_{suffix}"))
                .expect("prepare live test images first")
        })
        .collect();
    let docker = Arc::new(Docker::connect_with_local_defaults().unwrap());
    docker.ping().await.unwrap();
    let mut fixture = Fixture::new();
    let resources = Resources {
        container: fixture.name().into(),
        volume: fixture.volume.name.clone(),
        sandbox: fixture.p().sandbox_id.clone(),
    };
    assert!(
        matches!(docker.inspect_volume(&resources.volume).await, Err(ref error) if is_not_found_error(error))
    );
    let volume = docker
        .create_volume(VolumeCreateRequest {
            name: Some(resources.volume.clone()),
            driver: Some("local".into()),
            labels: Some(fixture.volume.labels.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
    let mut body: ContainerCreateBody =
        serde_json::from_value(serde_json::to_value(&fixture.source.config).unwrap()).unwrap();
    body.host_config = fixture.source.host_config.clone();
    body.image = Some(images[0].clone());
    body.labels.as_mut().unwrap().insert(
        workspace::IDENTITY_LABEL.into(),
        docker_volume_identity(&volume).to_string(),
    );
    let source_id = docker
        .create_container(
            Some(
                CreateContainerOptionsBuilder::default()
                    .name(&resources.container)
                    .build(),
            ),
            body,
        )
        .await
        .unwrap()
        .id;
    let source = docker.inspect_container(&source_id, None).await.unwrap();
    for filename in [BOUNDARY_CONFIG_FILE, RUNTIME_DESCRIPTOR_FILE] {
        let path = fixture.directory.join(filename);
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        value["resource_claims"]["docker.container_id"] = source_id.clone().into();
        value["resource_claims"]["docker.image_identity"] = source.image.clone().unwrap().into();
        value["workload_identity"]["resource_digest"] = source.image.clone().unwrap().into();
        value["provisioning_evidence"] = serde_json::to_value(
            isolation::provisioning_evidence(&source_id, value["generation"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        durable_write(&path, &serde_json::to_vec(&value).unwrap()).unwrap();
    }
    let mut archive = tar::Builder::new(Vec::new());
    let marker = b"retained workspace and session proof\n";
    let mut header = tar::Header::new_gnu();
    header.set_size(marker.len() as u64);
    header.set_mode(0o600);
    header.set_uid(1234);
    header.set_gid(1235);
    header.set_cksum();
    archive
        .append_data(&mut header, "retained-session.txt", marker.as_slice())
        .unwrap();
    docker
        .upload_to_container(
            &source_id,
            Some(
                UploadToContainerOptionsBuilder::default()
                    .path("/sandbox")
                    .copy_uidgid("true")
                    .build(),
            ),
            bollard::body_full(Bytes::from(archive.into_inner().unwrap())),
        )
        .await
        .unwrap();
    let mut driver = test_driver_with_config(fixture.config.clone());
    driver.docker = docker.clone();
    fixture
        .request
        .preconditions
        .as_mut()
        .unwrap()
        .expected_image = images[0].clone();
    for rejected_image in &images[2..] {
        fixture.request.preconditions.as_mut().unwrap().image = rejected_image.clone();
        let error = Box::pin(driver.update_workload_image(&fixture.request))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(error.message().contains("matching numeric"), "{error}");
        assert!(read(&fixture.config, &resources.sandbox).unwrap().is_none());
        assert_eq!(
            docker
                .inspect_container(&source_id, None)
                .await
                .unwrap()
                .id
                .as_deref(),
            Some(source_id.as_str())
        );
    }
    fixture.request.preconditions.as_mut().unwrap().image = images[1].clone();
    Box::pin(driver.update_workload_image(&fixture.request))
        .await
        .unwrap();
    let intent = read(&fixture.config, &resources.sandbox).unwrap().unwrap();
    assert!(intent.phase == Phase::Applied);
    let first_target = intent.target_container.clone().unwrap();
    assert_ne!(first_target, source_id);
    let target = docker.inspect_container(&first_target, None).await.unwrap();
    assert_eq!(target.state.as_ref().unwrap().running, Some(false));
    assert_eq!(
        target.config.as_ref().unwrap().user.as_deref(),
        Some("1234:1235")
    );
    assert_eq!(
        target.config.as_ref().unwrap().labels.as_ref().unwrap()[LABEL_SANDBOX_ID],
        resources.sandbox
    );
    assert_eq!(
        archived_file(&first_target, "/sandbox/retained-session.txt"),
        marker
    );
    assert_eq!(archived_file(&first_target, "/app/version"), b"B\n");
    // Reopen the driver and replay: no second replacement of the applied target.
    let mut reopened = test_driver_with_config(fixture.config.clone());
    reopened.docker = docker.clone();
    Box::pin(reopened.update_workload_image(&fixture.request))
        .await
        .unwrap();
    assert_eq!(
        read(&fixture.config, &resources.sandbox)
            .unwrap()
            .unwrap()
            .target_container
            .as_deref(),
        Some(first_target.as_str())
    );

    // Inject exit after an accepted update has removed its stopped source.
    let p = fixture.request.preconditions.as_mut().unwrap();
    p.expected_image = images[1].clone();
    p.image = images[0].clone();
    p.revision = 2;
    p.operation_id = openshell_core::SandboxSessionId::new().to_string();
    let pending = reopened.prepare_image_update(fixture.p()).await.unwrap();
    save(&fixture.config, &pending).unwrap();
    docker.remove_container(&first_target, None).await.unwrap();
    assert!(require_settled(&fixture.config, &resources.sandbox).is_err());
    let mut recovered = test_driver_with_config(fixture.config.clone());
    recovered.docker = docker.clone();
    Box::pin(recovered.update_workload_image(&fixture.request))
        .await
        .unwrap();
    let applied = read(&fixture.config, &resources.sandbox).unwrap().unwrap();
    let final_target = applied.target_container.as_ref().unwrap();
    assert!(applied.phase == Phase::Applied);
    assert_eq!(
        archived_file(final_target, "/sandbox/retained-session.txt"),
        marker
    );
    assert_eq!(archived_file(final_target, "/app/version"), b"A\n");
    assert_eq!(
        docker
            .inspect_volume(&resources.volume)
            .await
            .unwrap()
            .created_at,
        volume.created_at
    );
    validate_committed_resource(
        &fixture.config,
        &resources.sandbox,
        &docker.inspect_container(final_target, None).await.unwrap(),
        LaunchValidation::Complete,
    )
    .unwrap();
    // Explicitly remove only this stopped test workload and its admitted volume.
    docker.remove_container(final_target, None).await.unwrap();
    docker
        .remove_volume(
            &resources.volume,
            None::<bollard::query_parameters::RemoveVolumeOptions>,
        )
        .await
        .unwrap();
}
