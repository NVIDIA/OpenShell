// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Opt-in workspace storage, separate from disposable runtime/channel volumes.

use super::{
    DockerDriverRuntimeConfig, DockerImageMetadata, DriverSandbox, LABEL_ISOLATION_BACKEND,
    LABEL_ISOLATION_BACKEND_OPEN_SHELL, LABEL_MANAGED_BY, LABEL_MANAGED_BY_VALUE, LABEL_SANDBOX_ID,
    LABEL_SANDBOX_NAMESPACE, LABEL_SANDBOX_WORKSPACE, docker_channel_volume_name_by_id,
    docker_volume_identity, driver_mounts, is_not_found_error, remove_docker_volume,
};
use bollard::Docker;
use bollard::models::{
    ContainerInspectResponse, Mount, MountTypeEnum, MountVolumeOptions, Volume, VolumeCreateRequest,
};
use openshell_isolation_interface::contract::ResolvedWorkloadIdentity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tonic::Status;

pub const ROLE_LABEL: &str = "openshell.ai/storage-role";
pub const ROLE: &str = "workspace";
pub const RECORD_FILE: &str = "workspace-storage.json";
pub const RECORD_CLAIM: &str = "docker.workspace_storage";
const MAX_RECORD_BYTES: u64 = 16 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    namespace: String,
    sandbox_id: String,
    uid: u32,
    gid: u32,
    volume_identity: serde_json::Value,
}

pub fn record_path(id: &str, config: &DockerDriverRuntimeConfig) -> Result<PathBuf, Status> {
    Ok(super::docker_boundary_state_dir_by_id(id, config)?.join(RECORD_FILE))
}

pub fn record_bytes(
    id: &str,
    config: &DockerDriverRuntimeConfig,
    volume: &Volume,
    identity: &ResolvedWorkloadIdentity,
) -> Result<Vec<u8>, Status> {
    serde_json::to_vec(&Record {
        version: 1,
        namespace: config.sandbox_namespace.clone(),
        sandbox_id: id.into(),
        uid: identity.uid,
        gid: identity.gid,
        volume_identity: docker_volume_identity(volume),
    })
    .map_err(|_| Status::internal("encode private Docker workspace record"))
}

fn read_record(id: &str, config: &DockerDriverRuntimeConfig) -> Result<Option<Record>, Status> {
    let path = record_path(id, config)?;
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return Err(Status::failed_precondition(
                "private Docker workspace record cannot be read",
            ));
        }
    };
    if !metadata.is_file() || metadata.len() > MAX_RECORD_BYTES {
        return Err(Status::failed_precondition(
            "private Docker workspace record must be a bounded regular file",
        ));
    }
    let record: Record = serde_json::from_slice(&std::fs::read(path).map_err(|_| {
        Status::failed_precondition("private Docker workspace record cannot be read")
    })?)
    .map_err(|_| Status::failed_precondition("private Docker workspace record is invalid"))?;
    if record.version != 1
        || record.namespace != config.sandbox_namespace
        || record.sandbox_id != id
        || record.uid == 0
        || record.gid == 0
        || record
            .volume_identity
            .get("name")
            .and_then(serde_json::Value::as_str)
            != Some(volume_name(id, config).as_str())
    {
        return Err(Status::failed_precondition(
            "private Docker workspace record belongs to another resource",
        ));
    }
    Ok(Some(record))
}

pub fn record_claim(
    id: &str,
    config: &DockerDriverRuntimeConfig,
) -> Result<Option<String>, Status> {
    read_record(id, config)?
        .map(|record| {
            serde_json::to_string(&record)
                .map_err(|_| Status::internal("encode private Docker workspace claim"))
        })
        .transpose()
}

async fn load_record(
    id: &str,
    config: &DockerDriverRuntimeConfig,
) -> Result<Option<Record>, Status> {
    let record = read_record(id, config)?;
    let descriptor = super::read_docker_runtime_descriptor(id, config).await?;
    let claim = descriptor
        .as_ref()
        .and_then(|descriptor| descriptor.resource_claims.get(RECORD_CLAIM));
    match (&record, claim) {
        (None, None) => return Ok(None), // Legacy container: labels are caller data.
        (None, Some(_)) => {
            return Err(Status::failed_precondition(
                "private Docker workspace record is missing",
            ));
        }
        (Some(record), Some(claim)) => {
            if serde_json::to_string(record)
                .map_err(|_| Status::internal("encode private Docker workspace claim"))?
                != *claim
            {
                return Err(Status::failed_precondition(
                    "private Docker workspace record and descriptor disagree",
                ));
            }
        }
        (Some(_), None) if descriptor.is_some() => {
            return Err(Status::failed_precondition(
                "Docker descriptor lacks its private workspace claim",
            ));
        }
        (Some(_), None) => {} // Fresh create: record precedes container/descriptor.
    }
    if let (Some(record), Some(descriptor)) = (&record, descriptor)
        && (descriptor.boundary_id != id
            || descriptor.workload_identity.uid != record.uid
            || descriptor.workload_identity.gid != record.gid)
    {
        return Err(Status::failed_precondition(
            "private Docker workspace runtime identity changed",
        ));
    }
    Ok(record)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Storage {
    WritableLayer,
    Persistent,
}

const UID_LABEL: &str = "openshell.ai/workspace-uid";
const GID_LABEL: &str = "openshell.ai/workspace-gid";

fn volume_name(sandbox_id: &str, config: &DockerDriverRuntimeConfig) -> String {
    docker_channel_volume_name_by_id(sandbox_id, config).replacen(
        "openshell-channel-",
        "openshell-workspace-",
        1,
    )
}

pub fn mount(
    sandbox: &DriverSandbox,
    config: &DockerDriverRuntimeConfig,
    image: &DockerImageMetadata,
) -> Result<Option<Mount>, Status> {
    if config.workspace_storage != Storage::Persistent {
        return Ok(None);
    }
    let root = driver_mounts::resolve_oci_workspace_root(&image.working_dir)
        .map_err(Status::failed_precondition)?;
    if root != driver_mounts::DEFAULT_WORKSPACE_ROOT {
        return Err(Status::failed_precondition(
            "persistent Docker workspaces currently require /sandbox",
        ));
    }
    if image
        .volumes
        .iter()
        .any(|target| Path::new(target).starts_with(&root) || Path::new(&root).starts_with(target))
    {
        return Err(Status::failed_precondition(
            "image-declared volumes overlap the persistent Docker workspace",
        ));
    }
    Ok(Some(Mount {
        target: Some(root),
        source: Some(volume_name(&sandbox.id, config)),
        typ: Some(MountTypeEnum::VOLUME),
        read_only: Some(false),
        volume_options: Some(MountVolumeOptions {
            no_copy: Some(true),
            ..Default::default()
        }),
        ..Default::default()
    }))
}

fn ownership_labels(
    sandbox_id: &str,
    config: &DockerDriverRuntimeConfig,
) -> HashMap<String, String> {
    HashMap::from([
        (LABEL_MANAGED_BY.into(), LABEL_MANAGED_BY_VALUE.into()),
        (LABEL_SANDBOX_ID.into(), sandbox_id.into()),
        (
            LABEL_SANDBOX_NAMESPACE.into(),
            config.sandbox_namespace.clone(),
        ),
        (
            LABEL_ISOLATION_BACKEND.into(),
            LABEL_ISOLATION_BACKEND_OPEN_SHELL.into(),
        ),
        (ROLE_LABEL.into(), ROLE.into()),
    ])
}

fn validate_volume(
    volume: &Volume,
    sandbox_id: &str,
    config: &DockerDriverRuntimeConfig,
) -> Result<(), Status> {
    if volume.name != volume_name(sandbox_id, config)
        || volume.driver != "local"
        || !volume.options.is_empty()
        || ownership_labels(sandbox_id, config)
            .iter()
            .any(|(key, value)| volume.labels.get(key) != Some(value))
    {
        return Err(Status::failed_precondition(
            "persistent Docker workspace ownership changed",
        ));
    }
    Ok(())
}

pub async fn prepare(
    docker: &Docker,
    sandbox: &DriverSandbox,
    config: &DockerDriverRuntimeConfig,
    image: &DockerImageMetadata,
    identity: &ResolvedWorkloadIdentity,
) -> Result<Option<Volume>, Status> {
    if mount(sandbox, config, image)?.is_none() {
        return Ok(None);
    }
    if read_record(&sandbox.id, config)?.is_some() {
        return Err(Status::failed_precondition(
            "persistent Docker workspace is already recorded; explicit recovery or removal is required",
        ));
    }
    let name = volume_name(&sandbox.id, config);
    // Initial creation must not adopt an existing data volume. Recovery/update
    // will use the recorded volume identity, rather than this creation path.
    match docker.inspect_volume(&name).await {
        Ok(_) => {
            return Err(Status::failed_precondition(
                "persistent Docker workspace already exists; explicit recovery or removal is required",
            ));
        }
        Err(error) if is_not_found_error(&error) => {}
        Err(error) => {
            return Err(Status::unavailable(format!(
                "inspect persistent Docker workspace: {error}"
            )));
        }
    }
    let mut labels = ownership_labels(&sandbox.id, config);
    labels.insert(LABEL_SANDBOX_WORKSPACE.into(), sandbox.workspace.clone());
    labels.insert(UID_LABEL.into(), identity.uid.to_string());
    labels.insert(GID_LABEL.into(), identity.gid.to_string());
    let volume = docker
        .create_volume(VolumeCreateRequest {
            name: Some(name),
            driver: Some("local".into()),
            labels: Some(labels.clone()),
            ..Default::default()
        })
        .await
        .map_err(|error| {
            Status::unavailable(format!("create persistent Docker workspace: {error}"))
        })?;
    validate_volume(&volume, &sandbox.id, config)?;
    if labels
        .iter()
        .any(|(key, value)| volume.labels.get(key) != Some(value))
    {
        return Err(Status::failed_precondition(
            "persistent Docker workspace initialization identity changed",
        ));
    }
    super::prepare_docker_boundary_state_dir(sandbox, config)?;
    let bytes = record_bytes(&sandbox.id, config, &volume, identity)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(Status::failed_precondition(
            "private Docker workspace record exceeds its bound",
        ));
    }
    super::image_update::durable_write(&record_path(&sandbox.id, config)?, &bytes)?;
    Ok(Some(volume))
}

fn validate_attachment(
    container: &ContainerInspectResponse,
    volume: &Volume,
    recorded: &serde_json::Value,
    config: &DockerDriverRuntimeConfig,
) -> Result<(), Status> {
    let labels = container
        .config
        .as_ref()
        .and_then(|config| config.labels.as_ref())
        .ok_or_else(|| {
            Status::failed_precondition("persistent Docker workspace lacks sandbox ownership")
        })?;
    let id = labels
        .get(LABEL_SANDBOX_ID)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            Status::failed_precondition("persistent Docker workspace lacks sandbox ID")
        })?;
    validate_volume(volume, id, config)?;
    let matching_mounts = container
        .mounts
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|mount| mount.destination.as_deref() == Some(driver_mounts::DEFAULT_WORKSPACE_ROOT))
        .collect::<Vec<_>>();
    let user = container
        .config
        .as_ref()
        .and_then(|config| config.user.as_deref());
    let expected_user = match (volume.labels.get(UID_LABEL), volume.labels.get(GID_LABEL)) {
        (Some(uid), Some(gid)) => format!("{uid}:{gid}"),
        _ => {
            return Err(Status::failed_precondition(
                "persistent Docker workspace lacks workload identity",
            ));
        }
    };
    if labels.get(LABEL_SANDBOX_NAMESPACE) != Some(&config.sandbox_namespace)
        || labels.get(LABEL_SANDBOX_WORKSPACE) != volume.labels.get(LABEL_SANDBOX_WORKSPACE)
        || user != Some(expected_user.as_str())
        || *recorded != docker_volume_identity(volume)
        || matching_mounts.len() != 1
        || matching_mounts[0].typ != Some(bollard::models::MountPointTypeEnum::VOLUME)
        || matching_mounts[0].name.as_deref() != Some(volume.name.as_str())
        || matching_mounts[0].rw != Some(true)
    {
        return Err(Status::failed_precondition(
            "persistent Docker workspace attachment or identity changed",
        ));
    }
    Ok(())
}

pub async fn admit(
    docker: &Docker,
    container: &ContainerInspectResponse,
    config: &DockerDriverRuntimeConfig,
) -> Result<bool, Status> {
    let Some(id) = container
        .config
        .as_ref()
        .and_then(|config| config.labels.as_ref())
        .and_then(|labels| labels.get(LABEL_SANDBOX_ID))
        .filter(|id| !id.is_empty())
    else {
        return Ok(false);
    };
    let Some(record) = load_record(id, config).await? else {
        return Ok(false);
    };
    if container
        .config
        .as_ref()
        .and_then(|value| value.user.as_deref())
        != Some(format!("{}:{}", record.uid, record.gid).as_str())
    {
        return Err(Status::failed_precondition(
            "persistent Docker workspace workload identity changed",
        ));
    }
    let name = volume_name(id, config);
    let volume = docker.inspect_volume(&name).await.map_err(|error| {
        Status::unavailable(format!("inspect retained Docker workspace: {error}"))
    })?;
    validate_attachment(container, &volume, &record.volume_identity, config)?;
    Ok(true)
}

pub async fn remove(
    docker: &Docker,
    sandbox_id: &str,
    config: &DockerDriverRuntimeConfig,
) -> Result<(), Status> {
    let Some(record) = load_record(sandbox_id, config).await? else {
        return Ok(());
    };
    let name = volume_name(sandbox_id, config);
    let volume = match docker.inspect_volume(&name).await {
        Ok(volume) => volume,
        Err(error) if is_not_found_error(&error) => return Ok(()),
        Err(error) => {
            return Err(Status::unavailable(format!(
                "inspect Docker workspace for removal: {error}"
            )));
        }
    };
    validate_volume(&volume, sandbox_id, config)?;
    if docker_volume_identity(&volume) != record.volume_identity {
        return Err(Status::failed_precondition(
            "persistent Docker workspace identity changed before removal",
        ));
    }
    // Docker refuses removal while another container still uses the volume.
    remove_docker_volume(docker, &name).await
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::tests::{
        runtime_config, test_driver_with_config, test_sandbox, test_workload_identity,
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    // Exercise the real Bollard request/response path, without a Docker engine.
    pub async fn docker_api(
        replies: Vec<(&'static str, String, u16, serde_json::Value)>,
    ) -> (Docker, tokio::task::JoinHandle<Vec<serde_json::Value>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for (method, suffix, status, response) in replies {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let (header_end, body_size) = loop {
                    let mut buffer = [0_u8; 4096];
                    let count = stream.read(&mut buffer).await.unwrap();
                    assert!(count > 0, "incomplete Docker request");
                    bytes.extend_from_slice(&buffer[..count]);
                    assert!(bytes.len() < 65536, "oversized Docker request");
                    if let Some(end) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&bytes[..end]).unwrap();
                        let size = headers
                            .lines()
                            .find_map(|line| {
                                let (key, value) = line.split_once(':')?;
                                key.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        break (end + 4, size);
                    }
                };
                while bytes.len() < header_end + body_size {
                    let mut buffer = [0_u8; 4096];
                    let count = stream.read(&mut buffer).await.unwrap();
                    assert!(count > 0);
                    bytes.extend_from_slice(&buffer[..count]);
                }
                let request_line = std::str::from_utf8(&bytes[..header_end])
                    .unwrap()
                    .lines()
                    .next()
                    .unwrap();
                let fields = request_line.split_whitespace().collect::<Vec<_>>();
                assert_eq!(fields[0], method);
                assert!(
                    fields[1].ends_with(&suffix),
                    "unexpected path: {}",
                    fields[1]
                );
                requests.push(if body_size == 0 {
                    serde_json::Value::Null
                } else {
                    serde_json::from_slice(&bytes[header_end..header_end + body_size]).unwrap()
                });
                let body = response.to_string();
                let reply = format!(
                    "HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(reply.as_bytes()).await.unwrap();
            }
            requests
        });
        (
            Docker::connect_with_http(&endpoint, 2, bollard::API_DEFAULT_VERSION).unwrap(),
            task,
        )
    }

    fn fixture() -> (ContainerInspectResponse, Volume, DockerDriverRuntimeConfig) {
        let mut config = runtime_config();
        config.sandbox_namespace =
            format!("workspace-test-{}", openshell_core::SandboxSessionId::new());
        fixture_for(test_sandbox(), config)
    }

    fn save_fixture_record(volume: &Volume, config: &DockerDriverRuntimeConfig) -> PathBuf {
        let sandbox = test_sandbox();
        let directory = super::super::prepare_docker_boundary_state_dir(&sandbox, config).unwrap();
        super::super::image_update::durable_write(
            &directory.join(RECORD_FILE),
            &record_bytes(&sandbox.id, config, volume, &test_workload_identity()).unwrap(),
        )
        .unwrap();
        directory
    }

    pub fn fixture_for(
        sandbox: DriverSandbox,
        config: DockerDriverRuntimeConfig,
    ) -> (ContainerInspectResponse, Volume, DockerDriverRuntimeConfig) {
        let identity = test_workload_identity();
        let mut labels = ownership_labels(&sandbox.id, &config);
        labels.insert(LABEL_SANDBOX_WORKSPACE.into(), sandbox.workspace.clone());
        labels.insert(UID_LABEL.into(), identity.uid.to_string());
        labels.insert(GID_LABEL.into(), identity.gid.to_string());
        let volume: Volume = serde_json::from_value(serde_json::json!({
            "Name": volume_name(&sandbox.id, &config), "Driver": "local", "Options": {},
            "Labels": labels, "Mountpoint": "/synthetic/workspace", "Scope": "local", "CreatedAt": "2026-11-10T00:00:00Z"
        })).unwrap();
        let labels = HashMap::from([
            (LABEL_SANDBOX_ID.to_string(), sandbox.id),
            (
                LABEL_SANDBOX_NAMESPACE.to_string(),
                config.sandbox_namespace.clone(),
            ),
            (LABEL_SANDBOX_WORKSPACE.to_string(), sandbox.workspace),
        ]);
        let container = serde_json::from_value(serde_json::json!({
            "Config": {"Labels": labels, "User": format!("{}:{}", identity.uid, identity.gid)},
            "Mounts": [{"Type": "volume", "Name": volume.name, "Destination": "/sandbox", "RW": true}]
        })).unwrap();
        (container, volume, config)
    }

    #[tokio::test]
    async fn legacy_workspace_labels_are_not_a_driver_storage_record() {
        // These keys were previously accepted as arbitrary template labels.
        // Their values, even persistent-v1 or invalid JSON, must not turn an
        // existing writable-layer container into a driver-owned volume claim.
        for labels in [
            serde_json::json!({"openshell.ai/workspace-storage":"persistent-v1"}),
            serde_json::json!({"openshell.ai/workspace-volume-identity":"not-json"}),
            serde_json::json!({"openshell.ai/workspace-storage":"persistent-v1", "openshell.ai/workspace-volume-identity":"not-json"}),
            serde_json::json!({"openshell.ai/docker-workspace-storage":"persistent-v1", "openshell.ai/docker-workspace-volume-identity":"not-json"}),
        ] {
            let mut labels = labels;
            labels[LABEL_SANDBOX_ID] = "sbx-123".into();
            let container =
                serde_json::from_value(serde_json::json!({"Config":{"Labels":labels}})).unwrap();
            let (_, _, config) = fixture();
            let (docker, server) = docker_api(vec![]).await;
            assert!(!admit(&docker, &container, &config).await.unwrap());
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn legacy_removal_never_probes_or_removes_an_unrecorded_workspace() {
        let (_, _, config) = fixture();
        let (docker, server) = docker_api(vec![]).await;
        remove(&docker, "sbx-123", &config).await.unwrap();
        assert!(server.await.unwrap().is_empty());
    }

    #[test]
    fn failed_creation_keeps_storage_authority_until_explicit_deletion() {
        let (_, volume, config) = fixture();
        let sandbox = test_sandbox();
        let directory = save_fixture_record(&volume, &config);
        super::super::cleanup_failed_docker_boundary_state(&sandbox, &config);
        assert!(record_claim(&sandbox.id, &config).unwrap().is_some());
        super::super::cleanup_docker_boundary_state(&sandbox, &config);
        assert!(!directory.exists());

        let directory = super::super::prepare_docker_boundary_state_dir(&sandbox, &config).unwrap();
        super::super::cleanup_failed_docker_boundary_state(&sandbox, &config);
        assert!(!directory.exists());
    }

    #[test]
    fn retained_workspace_requires_original_volume_identity() {
        let (container, mut volume, config) = fixture();
        let recorded = docker_volume_identity(&volume);
        validate_attachment(&container, &volume, &recorded, &config).unwrap();
        volume.created_at = Some("2026-11-11T00:00:00Z".into());
        assert!(validate_attachment(&container, &volume, &recorded, &config).is_err());
    }

    #[test]
    fn retained_workspace_rejects_foreign_backing_and_workload_user() {
        let (mut container, mut volume, config) = fixture();
        let recorded = docker_volume_identity(&volume);
        container.config.as_mut().unwrap().user = Some("2000:2000".into());
        assert!(validate_attachment(&container, &volume, &recorded, &config).is_err());
        volume
            .options
            .insert("device".into(), "/private/foreign".into());
        assert!(validate_volume(&volume, "sbx-123", &config).is_err());
    }

    #[test]
    fn retained_workspace_rejects_unrecorded_mount_and_foreign_namespace() {
        let (mut container, mut volume, config) = fixture();
        let recorded = docker_volume_identity(&volume);
        volume
            .labels
            .insert(LABEL_SANDBOX_NAMESPACE.into(), "foreign".into());
        assert!(validate_volume(&volume, "sbx-123", &config).is_err());
        container.mounts = None;
        assert!(validate_attachment(&container, &volume, &recorded, &config).is_err());
    }

    #[tokio::test]
    async fn legacy_custom_workspace_mount_keeps_existing_admission_path() {
        let container = serde_json::from_value(serde_json::json!({
            "Config": {"Labels": {}, "WorkingDir": "/project"},
            "Mounts": [{"Type":"volume", "Name":"external-data", "Destination":"/sandbox", "RW":true}]
        })).unwrap();
        let (docker, server) = docker_api(vec![]).await;
        assert!(!admit(&docker, &container, &runtime_config()).await.unwrap());
        server.await.unwrap();
    }

    #[test]
    fn persistent_layout_is_opt_in_and_rejects_custom_workdir_and_nested_image_volume() {
        let sandbox = test_sandbox();
        let mut config = runtime_config();
        let mut image = DockerImageMetadata {
            id: "image".into(),
            user: "1000:1000".into(),
            working_dir: "/sandbox".into(),
            volumes: vec![],
        };
        assert!(mount(&sandbox, &config, &image).unwrap().is_none());
        config.workspace_storage = Storage::Persistent;
        let persistent = mount(&sandbox, &config, &image).unwrap().unwrap();
        assert_eq!(persistent.volume_options.unwrap().no_copy, Some(true));
        image.working_dir = "/custom".into();
        assert!(mount(&sandbox, &config, &image).is_err());
        image.working_dir = "/sandbox".into();
        image.volumes.push("/sandbox/cache".into());
        assert!(mount(&sandbox, &config, &image).is_err());
    }

    #[tokio::test]
    async fn creation_refuses_existing_data_without_relabeling_it() {
        let (_, volume, mut config) = fixture();
        config.workspace_storage = Storage::Persistent;
        let path = format!("/volumes/{}", volume.name);
        let (docker, server) = docker_api(vec![(
            "GET",
            path,
            200,
            serde_json::to_value(&volume).unwrap(),
        )])
        .await;
        let image = DockerImageMetadata {
            id: "image".into(),
            user: "1234:1235".into(),
            working_dir: "/sandbox".into(),
            volumes: vec![],
        };
        let error = prepare(
            &docker,
            &test_sandbox(),
            &config,
            &image,
            &test_workload_identity(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert_eq!(server.await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn creation_records_only_fresh_owned_workspace_storage() {
        let (_, volume, mut config) = fixture();
        config.workspace_storage = Storage::Persistent;
        let path = format!("/volumes/{}", volume.name);
        let (docker, server) = docker_api(vec![
            ("GET", path, 404, serde_json::json!({"message":"not found"})),
            (
                "POST",
                "/volumes/create".into(),
                201,
                serde_json::to_value(&volume).unwrap(),
            ),
        ])
        .await;
        let image = DockerImageMetadata {
            id: "image".into(),
            user: "1234:1235".into(),
            working_dir: "/sandbox".into(),
            volumes: vec![],
        };
        let created = prepare(
            &docker,
            &test_sandbox(),
            &config,
            &image,
            &test_workload_identity(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            docker_volume_identity(&created),
            docker_volume_identity(&volume)
        );
        let requests = server.await.unwrap();
        assert_eq!(requests[1]["Name"], volume.name);
        assert_eq!(requests[1]["Driver"], "local");
        assert_eq!(requests[1]["Labels"][ROLE_LABEL], ROLE);
        assert!(record_claim("sbx-123", &config).unwrap().is_some());
        std::fs::remove_dir_all(record_path("sbx-123", &config).unwrap().parent().unwrap())
            .unwrap();
    }

    #[tokio::test]
    async fn disabling_external_admission_does_not_adopt_recreated_workspace_volume() {
        let (container, mut volume, config) = fixture();
        assert!(config.allow_driver_config && !config.resource_admission.enabled);
        let directory = save_fixture_record(&volume, &config);
        volume.created_at = Some("2026-11-11T00:00:00Z".into());
        let (docker, server) = docker_api(vec![(
            "GET",
            format!("/volumes/{}", volume.name),
            200,
            serde_json::to_value(&volume).unwrap(),
        )])
        .await;
        let mut driver = test_driver_with_config(config);
        driver.docker = std::sync::Arc::new(docker);
        let error = driver
            .admit_container_resources(&container)
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        server.await.unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn removal_checks_ownership_and_never_forces_an_in_use_volume() {
        let (_, mut volume, config) = fixture();
        let original = volume.clone();
        let directory = save_fixture_record(&volume, &config);
        volume
            .labels
            .insert(LABEL_SANDBOX_NAMESPACE.into(), "foreign".into());
        let path = format!("/volumes/{}", volume.name);
        let (docker, server) = docker_api(vec![(
            "GET",
            path.clone(),
            200,
            serde_json::to_value(&volume).unwrap(),
        )])
        .await;
        assert_eq!(
            remove(&docker, "sbx-123", &config)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::FailedPrecondition
        );
        server.await.unwrap();
        let volume = original;
        let (docker, server) = docker_api(vec![
            (
                "GET",
                path.clone(),
                200,
                serde_json::to_value(&volume).unwrap(),
            ),
            (
                "DELETE",
                path,
                409,
                serde_json::json!({"message":"volume in use"}),
            ),
        ])
        .await;
        assert!(remove(&docker, "sbx-123", &config).await.is_err());
        server.await.unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }
}
