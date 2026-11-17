// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Stopped workload replacement. The gateway remains the accepted-operation owner.

use super::*;
use bollard::models::ContainerInspectResponse;
use openshell_core::proto::compute::v1::{
    SandboxUpdatePreconditions, UpdateSandboxConfigurationRequest,
};
use serde::{Deserialize, Serialize};
use std::io::Write as _;

const RECORD_FILE: &str = "workload-image-update.json";
const OPERATION_LABEL: &str = "openshell.ai/workload-image-operation";
const REVISION_LABEL: &str = "openshell.ai/workload-image-revision";
const MAX_RECORD_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Prepared,
    Replaced,
    Applied,
}

// No Debug implementation: the immutable create input can contain private
// environment/configuration. It never enters logs or public status.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    version: u32,
    namespace: String,
    sandbox_id: String,
    sandbox_name: String,
    operation_id: String,
    revision: u64,
    previous_image: String,
    image: String,
    image_id: String,
    original_container: String,
    container_name: String,
    target_container: Option<String>,
    body: ContainerCreateBody,
    original_bootstrap: Vec<u8>,
    original_descriptor: Vec<u8>,
    phase: Phase,
}

fn invalid(message: &'static str) -> Status {
    Status::failed_precondition(message)
}

fn validate_request(
    request: &UpdateSandboxConfigurationRequest,
) -> Result<&SandboxUpdatePreconditions, Status> {
    let p = request
        .preconditions
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("update preconditions are required"))?;
    if p.sandbox_id.is_empty()
        || p.sandbox_id.len() > 128
        || !p
            .sandbox_id
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || matches!(v, b'-' | b'_'))
        || p.name.is_empty()
        || p.name.len() > 256
        || p.image.is_empty()
        || p.image.len() > 4096
        || p.expected_image.is_empty()
        || p.expected_image.len() > 4096
        || p.revision == 0
    {
        return Err(Status::invalid_argument(
            "invalid Docker image-update preconditions",
        ));
    }
    let operation = p.operation_id.as_bytes();
    if operation.len() != 36
        || operation.iter().enumerate().any(|(i, v)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                *v != b'-'
            } else {
                !v.is_ascii_hexdigit()
            }
        })
    {
        return Err(Status::invalid_argument(
            "image-update operation ID must be a UUID",
        ));
    }
    if request.main_process.is_some() || request.environment.is_some() {
        return Err(Status::unimplemented(
            "the initial Docker updater supports image-only workload changes",
        ));
    }
    // Docker's pinned contract does not authenticate compute credentials or
    // publish that optional identity. The private native descriptor, exact
    // container ID and recorded persistent-volume identity anchor this update.
    if !p.expected_runtime_identity.is_empty() {
        return Err(invalid(
            "Docker image update does not recognize the supplied compute runtime identity",
        ));
    }
    Ok(p)
}

fn path(config: &DockerDriverRuntimeConfig, id: &str) -> Result<PathBuf, Status> {
    Ok(docker_boundary_state_dir_by_id(id, config)?.join(RECORD_FILE))
}

fn read(config: &DockerDriverRuntimeConfig, id: &str) -> Result<Option<Intent>, Status> {
    let path = path(config, id)?;
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(invalid("Docker image-update record cannot be read")),
    };
    if !metadata.is_file() || metadata.len() > MAX_RECORD_BYTES as u64 {
        return Err(invalid(
            "Docker image-update record is not a bounded regular file",
        ));
    }
    let intent: Intent = serde_json::from_slice(
        &std::fs::read(path).map_err(|_| invalid("Docker image-update record cannot be read"))?,
    )
    .map_err(|_| invalid("Docker image-update record is invalid"))?;
    if intent.version != 1
        || intent.sandbox_id != id
        || intent.namespace != config.sandbox_namespace
    {
        return Err(invalid(
            "Docker image-update record belongs to another native resource",
        ));
    }
    Ok(Some(intent))
}

fn durable_write(path: &Path, contents: &[u8]) -> Result<(), Status> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("Docker image-update state directory is missing"))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|_| Status::internal("create private Docker image-update checkpoint"))?;
    temporary
        .write_all(contents)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|_| Status::internal("flush Docker image-update checkpoint"))?;
    temporary
        .persist(path)
        .map_err(|_| Status::internal("publish Docker image-update checkpoint"))?;
    std::fs::File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|_| Status::internal("flush Docker image-update directory"))
}

fn save(config: &DockerDriverRuntimeConfig, intent: &Intent) -> Result<(), Status> {
    let bytes = serde_json::to_vec(intent)
        .map_err(|_| Status::internal("encode Docker image-update checkpoint"))?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(invalid("Docker image-update checkpoint exceeds its bound"));
    }
    durable_write(&path(config, &intent.sandbox_id)?, &bytes)
}

fn same_request(intent: &Intent, p: &SandboxUpdatePreconditions) -> bool {
    (intent.sandbox_id.as_str(), intent.sandbox_name.as_str())
        == (p.sandbox_id.as_str(), p.name.as_str())
        && intent.operation_id == p.operation_id
        && intent.revision == p.revision
        && intent.previous_image == p.expected_image
        && intent.image == p.image
}

fn require_stopped(container: &ContainerInspectResponse) -> Result<(), Status> {
    if container.state.as_ref().is_none_or(|state| {
        state.running != Some(false)
            || state.paused != Some(false)
            || state.restarting != Some(false)
            || !matches!(
                state.status,
                Some(ContainerStateStatusEnum::CREATED | ContainerStateStatusEnum::EXITED)
            )
    }) {
        return Err(invalid(
            "Docker workload must be verifiably stopped before image replacement",
        ));
    }
    validate_docker_outer_fence(container)?;
    let host = container
        .host_config
        .as_ref()
        .ok_or_else(|| invalid("Docker workload launch fence is missing"))?;
    if host.privileged == Some(true)
        || host
            .cap_add
            .as_ref()
            .is_some_and(|values| !values.is_empty())
        || host
            .cap_drop
            .as_ref()
            .is_none_or(|values| !values.iter().any(|value| value.eq_ignore_ascii_case("all")))
        || host.security_opt.as_ref().is_none_or(|values| {
            !values.iter().any(|value| {
                matches!(
                    value.as_str(),
                    "no-new-privileges" | "no-new-privileges:true"
                )
            })
        })
        || host.auto_remove == Some(true)
    {
        return Err(invalid("Docker workload launch fence changed"));
    }
    Ok(())
}

fn verify_replacement(container: &ContainerInspectResponse, intent: &Intent) -> Result<(), Status> {
    let actual = container
        .config
        .as_ref()
        .ok_or_else(|| invalid("Docker replacement configuration is missing"))?;
    let expected = &intent.body;
    if container.image.as_ref() != Some(&intent.image_id)
        || actual.user != expected.user
        || actual.entrypoint != expected.entrypoint
        || actual.cmd != expected.cmd
        || actual.working_dir != expected.working_dir
        || intent
            .target_container
            .as_ref()
            .is_some_and(|id| container.id.as_ref() != Some(id))
        || expected.labels.as_ref().is_none_or(|labels| {
            labels.iter().any(|(key, value)| {
                actual.labels.as_ref().and_then(|labels| labels.get(key)) != Some(value)
            })
        })
    {
        return Err(invalid(
            "Docker replacement does not match the accepted immutable input",
        ));
    }
    for entry in expected.env.as_deref().unwrap_or_default() {
        let (key, _) = entry
            .split_once('=')
            .ok_or_else(|| invalid("Docker bootstrap environment is invalid"))?;
        let matches = actual
            .env
            .as_deref()
            .unwrap_or_default()
            .iter()
            .filter(|value| value.split_once('=').is_some_and(|(name, _)| name == key))
            .collect::<Vec<_>>();
        if matches.len() != 1 || matches[0] != entry {
            return Err(invalid("Docker replacement bootstrap environment changed"));
        }
    }
    let original_host = serde_json::to_value(&expected.host_config)
        .map_err(|_| invalid("accepted Docker launch fence is invalid"))?;
    let actual_host = serde_json::to_value(&container.host_config)
        .map_err(|_| invalid("Docker replacement launch fence is invalid"))?;
    for key in [
        "NetworkMode",
        "CapDrop",
        "CapAdd",
        "Privileged",
        "SecurityOpt",
        "ReadonlyRootfs",
        "Binds",
        "Mounts",
        "GroupAdd",
        "Devices",
        "DeviceRequests",
        "PidMode",
        "UsernsMode",
        "IpcMode",
        "VolumesFrom",
        "AutoRemove",
        "Sysctls",
        "Tmpfs",
        "Dns",
        "DnsSearch",
        "ExtraHosts",
        "Memory",
        "NanoCpus",
        "PidsLimit",
    ] {
        if original_host[key] != actual_host[key] {
            return Err(invalid("Docker replacement launch settings changed"));
        }
    }
    Ok(())
}

fn read_published_boundary(
    intent: &Intent,
    config: &DockerDriverRuntimeConfig,
) -> Result<(BoundaryConfig, SandboxRuntimeDescriptor), Status> {
    let directory = docker_boundary_state_dir_by_id(&intent.sandbox_id, config)?;
    let bootstrap: BoundaryConfig = serde_json::from_slice(
        &std::fs::read(directory.join(BOUNDARY_CONFIG_FILE))
            .map_err(|_| invalid("replacement Docker bootstrap is unavailable"))?,
    )
    .map_err(|_| invalid("replacement Docker bootstrap is invalid"))?;
    let descriptor: SandboxRuntimeDescriptor = serde_json::from_slice(
        &std::fs::read(directory.join(RUNTIME_DESCRIPTOR_FILE))
            .map_err(|_| invalid("replacement Docker descriptor is unavailable"))?,
    )
    .map_err(|_| invalid("replacement Docker descriptor is invalid"))?;
    Ok((bootstrap, descriptor))
}

fn verify_boundary_resource_bindings(
    intent: &Intent,
    bootstrap: &BoundaryConfig,
    descriptor: &SandboxRuntimeDescriptor,
) -> Result<(), Status> {
    let target = intent
        .target_container
        .as_ref()
        .ok_or_else(|| invalid("Docker replacement target is missing"))?;
    let (_, expected) = decode_boundary(intent, target)?;
    let expected: SandboxRuntimeDescriptor = serde_json::from_slice(&expected)
        .map_err(|_| invalid("accepted Docker descriptor is invalid"))?;
    // A launch can be interrupted between these files' atomic writes. Each
    // must still identify the accepted resource, even when their launch-scoped
    // generation/session differ. Only stopped Start with fresh auth repairs it.
    for (id, generation, claims, identity, evidence) in [
        (
            &bootstrap.boundary_id,
            &bootstrap.generation,
            &bootstrap.resource_claims,
            &bootstrap.workload_identity,
            &bootstrap.provisioning_evidence,
        ),
        (
            &descriptor.boundary_id,
            &descriptor.generation,
            &descriptor.resource_claims,
            &descriptor.workload_identity,
            &descriptor.provisioning_evidence,
        ),
    ] {
        if id != &intent.sandbox_id
            || claims != &expected.resource_claims
            || identity != &expected.workload_identity
            || evidence
                != &isolation::provisioning_evidence(target, generation)
                    .map_err(|_| invalid("replacement Docker evidence is invalid"))?
        {
            return Err(invalid("replacement Docker resource bindings changed"));
        }
    }
    Ok(())
}

fn verify_published_boundary(
    intent: &Intent,
    config: &DockerDriverRuntimeConfig,
) -> Result<(), Status> {
    let (bootstrap, descriptor) = read_published_boundary(intent, config)?;
    verify_boundary_resource_bindings(intent, &bootstrap, &descriptor)?;
    if bootstrap.generation != descriptor.generation
        || bootstrap.session_id != descriptor.session_id
        || bootstrap.provisioning_evidence != descriptor.provisioning_evidence
    {
        return Err(invalid(
            "replacement Docker runtime evidence is inconsistent",
        ));
    }
    Ok(())
}

fn require_owner(
    container: &ContainerInspectResponse,
    p: &SandboxUpdatePreconditions,
    config: &DockerDriverRuntimeConfig,
) -> Result<(), Status> {
    let labels = container
        .config
        .as_ref()
        .and_then(|value| value.labels.as_ref())
        .ok_or_else(|| invalid("Docker image update lacks native ownership metadata"))?;
    for (key, value) in [
        (LABEL_MANAGED_BY, LABEL_MANAGED_BY_VALUE),
        (LABEL_SANDBOX_NAMESPACE, config.sandbox_namespace.as_str()),
        (LABEL_SANDBOX_ID, p.sandbox_id.as_str()),
        (LABEL_SANDBOX_NAME, p.name.as_str()),
        (LABEL_ISOLATION_ROLE, LABEL_ISOLATION_ROLE_SANDBOX),
        (workspace::MODE_LABEL, workspace::PERSISTENT_MODE),
    ] {
        if labels.get(key).map(String::as_str) != Some(value) {
            return Err(invalid(
                "Docker image update refused a changed resource owner or storage layout",
            ));
        }
    }
    if !labels.contains_key(workspace::IDENTITY_LABEL) {
        return Err(invalid(
            "Docker image update requires recorded persistent storage",
        ));
    }
    require_stopped(container)
}

fn decode_boundary(intent: &Intent, target_id: &str) -> Result<(Vec<u8>, Vec<u8>), Status> {
    let mut bootstrap: BoundaryConfig = serde_json::from_slice(&intent.original_bootstrap)
        .map_err(|_| invalid("saved Docker bootstrap is invalid"))?;
    let mut descriptor: SandboxRuntimeDescriptor =
        serde_json::from_slice(&intent.original_descriptor)
            .map_err(|_| invalid("saved Docker runtime descriptor is invalid"))?;
    if bootstrap.boundary_id != intent.sandbox_id
        || descriptor.boundary_id != intent.sandbox_id
        || bootstrap.generation != descriptor.generation
        || bootstrap.resource_claims.get("docker.container_id") != Some(&intent.original_container)
        || descriptor.resource_claims != bootstrap.resource_claims
        || descriptor.workload_identity != bootstrap.workload_identity
    {
        return Err(invalid(
            "Docker runtime evidence does not identify the original workload",
        ));
    }
    let identity = &descriptor.workload_identity;
    let identity = ResolvedWorkloadIdentity::new(
        identity.uid,
        identity.gid,
        identity.supplementary_gids.clone(),
        identity.source.clone(),
        intent.image_id.clone(),
    )
    .map_err(|_| invalid("Docker workload identity cannot be retained"))?;
    let evidence = isolation::provisioning_evidence(target_id, &bootstrap.generation)
        .map_err(|_| invalid("Docker replacement provisioning evidence is invalid"))?;
    for claims in [
        &mut bootstrap.resource_claims,
        &mut descriptor.resource_claims,
    ] {
        claims.insert("docker.container_id".into(), target_id.into());
        claims.insert("docker.image_identity".into(), intent.image_id.clone());
    }
    bootstrap.workload_identity = identity.clone();
    descriptor.workload_identity = identity;
    bootstrap.provisioning_evidence = evidence.clone();
    descriptor.provisioning_evidence = evidence;
    Ok((
        bootstrap
            .encode()
            .map_err(|_| Status::internal("encode replacement bootstrap"))?,
        serde_json::to_vec(&descriptor)
            .map_err(|_| Status::internal("encode replacement descriptor"))?,
    ))
}

impl DockerComputeDriver {
    /// Stopped image-only mutation for explicitly enabled persistent workspaces.
    /// The gateway owns acceptance, retries and public lifecycle state.
    pub async fn update_workload_image(
        &self,
        request: &UpdateSandboxConfigurationRequest,
    ) -> Result<(), Status> {
        let p = validate_request(request)?;
        if self.config.workspace_storage != workspace::Storage::Persistent {
            return Err(Status::unimplemented(
                "Docker persistent workspace image updates are not enabled",
            ));
        }
        self.verify_network_trust()?;
        let _guard = self
            .image_update_gates
            .gate_for(&p.sandbox_id)
            .lock_owned()
            .await;
        let previous = read(&self.config, &p.sandbox_id)?;
        let mut intent = match previous {
            Some(intent) if same_request(&intent, p) => intent,
            Some(intent) if intent.phase != Phase::Applied || intent.revision >= p.revision => {
                return Err(invalid(
                    "a conflicting or newer Docker image update is already recorded",
                ));
            }
            _ => Box::pin(self.prepare_image_update(p)).await?,
        };
        if p.validate_only {
            return self.validate_update_resource(&intent, p).await;
        }
        if intent.phase == Phase::Applied {
            return self.validate_update_resource(&intent, p).await;
        }
        save(&self.config, &intent)?;
        Box::pin(self.replace_image_container(&mut intent, p)).await
    }

    async fn prepare_image_update(&self, p: &SandboxUpdatePreconditions) -> Result<Intent, Status> {
        let directory = docker_boundary_state_dir_by_id(&p.sandbox_id, &self.config)?;
        let descriptor_bytes = std::fs::read(directory.join(RUNTIME_DESCRIPTOR_FILE))
            .map_err(|_| invalid("Docker image update requires the original native descriptor"))?;
        let descriptor: SandboxRuntimeDescriptor = serde_json::from_slice(&descriptor_bytes)
            .map_err(|_| invalid("Docker native descriptor is invalid"))?;
        if descriptor.boundary_id != p.sandbox_id {
            return Err(invalid(
                "Docker native descriptor belongs to another sandbox",
            ));
        }
        let source_id = descriptor
            .resource_claims
            .get("docker.container_id")
            .ok_or_else(|| invalid("Docker native descriptor lacks its container identity"))?;
        let source = self
            .docker
            .inspect_container(source_id, None)
            .await
            .map_err(|_| invalid("the original Docker workload is unavailable"))?;
        if source.id.as_ref() != Some(source_id) {
            return Err(invalid(
                "Docker inspection did not return the original immutable container ID",
            ));
        }
        require_owner(&source, p, &self.config)?;
        self.admit_container_resources(&source).await?;
        let original_image = self
            .docker
            .inspect_image(&p.expected_image)
            .await
            .map_err(|_| invalid("the expected original Docker image must be present locally"))?;
        if original_image.id != source.image
            || descriptor.resource_claims.get("docker.image_identity") != source.image.as_ref()
        {
            return Err(invalid(
                "Docker workload image no longer matches the expected original",
            ));
        }
        let target = self.docker.inspect_image(&p.image).await.map_err(|_| {
            invalid("the target Docker image must be prepared locally before update")
        })?;
        let image_id = target
            .id
            .ok_or_else(|| invalid("target Docker image lacks immutable identity"))?;
        let image_config = target
            .config
            .ok_or_else(|| invalid("target Docker image lacks configuration"))?;
        if driver_mounts::resolve_oci_workspace_root(
            image_config.working_dir.as_deref().unwrap_or_default(),
        )
        .map_err(Status::failed_precondition)?
            != "/sandbox"
            || image_config
                .volumes
                .as_ref()
                .is_some_and(|volumes| !volumes.is_empty())
        {
            return Err(invalid(
                "target Docker image requires an unsupported workspace or image volume layout",
            ));
        }
        let source_config = source
            .config
            .as_ref()
            .ok_or_else(|| invalid("Docker workload configuration is missing"))?;
        if source_config
            .volumes
            .as_ref()
            .is_some_and(|volumes| !volumes.is_empty())
        {
            return Err(invalid(
                "original Docker image has anonymous-volume state outside the initial update layout",
            ));
        }
        let expected_user = format!(
            "{}:{}",
            descriptor.workload_identity.uid, descriptor.workload_identity.gid
        );
        if source_config.user.as_deref() != Some(expected_user.as_str()) {
            return Err(invalid(
                "Docker native descriptor and workload user disagree",
            ));
        }
        // The update RPC carries no identity-policy override. Admit only an
        // explicit numeric USER matching the recorded non-root identity;
        // symbolic or implicit users need image account resolution, which the
        // initial image-only updater does not perform.
        let target_identity = image_config.user.as_deref().and_then(|user| {
            let (uid, gid) = user.split_once(':')?;
            if uid.is_empty()
                || gid.is_empty()
                || !uid
                    .bytes()
                    .chain(gid.bytes())
                    .all(|byte| byte.is_ascii_digit())
            {
                return None;
            }
            Some((uid.parse::<u32>().ok()?, gid.parse::<u32>().ok()?))
        });
        if target_identity
            != Some((
                descriptor.workload_identity.uid,
                descriptor.workload_identity.gid,
            ))
        {
            return Err(invalid(
                "target Docker image must declare matching numeric non-root UID:GID",
            ));
        }
        let mut body: ContainerCreateBody = serde_json::from_value(
            serde_json::to_value(source_config)
                .map_err(|_| invalid("Docker workload configuration cannot be retained"))?,
        )
        .map_err(|_| invalid("Docker workload configuration cannot be retained"))?;
        body.host_config.clone_from(&source.host_config);
        body.image = Some(image_id.clone());
        // Let the new image supply PATH and other image defaults. Only the
        // driver-owned bootstrap environment belongs to the container spec.
        body.env = Some(
            source_config
                .env
                .as_deref()
                .unwrap_or_default()
                .iter()
                .filter(|entry| {
                    entry.split_once('=').is_some_and(|(name, _)| {
                        matches!(
                            name,
                            openshell_core::sandbox_env::LOG_LEVEL
                                | openshell_core::sandbox_env::TELEMETRY_ENABLED
                        )
                    })
                })
                .cloned()
                .collect(),
        );
        let labels = body
            .labels
            .as_mut()
            .ok_or_else(|| invalid("Docker workload labels are missing"))?;
        labels.insert(OPERATION_LABEL.into(), p.operation_id.clone());
        labels.insert(REVISION_LABEL.into(), p.revision.to_string());
        let container_name = source
            .name
            .as_deref()
            .and_then(|name| name.strip_prefix('/'))
            .filter(|name| !name.is_empty())
            .ok_or_else(|| invalid("Docker workload canonical name is missing"))?
            .to_string();
        let original_bootstrap = std::fs::read(directory.join(BOUNDARY_CONFIG_FILE))
            .map_err(|_| invalid("original Docker bootstrap is unavailable"))?;
        let intent = Intent {
            version: 1,
            namespace: self.config.sandbox_namespace.clone(),
            sandbox_id: p.sandbox_id.clone(),
            sandbox_name: p.name.clone(),
            operation_id: p.operation_id.clone(),
            revision: p.revision,
            previous_image: p.expected_image.clone(),
            image: p.image.clone(),
            image_id,
            original_container: source_id.clone(),
            container_name,
            target_container: None,
            body,
            original_bootstrap,
            original_descriptor: descriptor_bytes,
            phase: Phase::Prepared,
        };
        // Validate both halves before accepting any destructive Docker action.
        let _ = decode_boundary(&intent, "validation-only-target")?;
        Ok(intent)
    }

    async fn validate_update_resource(
        &self,
        intent: &Intent,
        p: &SandboxUpdatePreconditions,
    ) -> Result<(), Status> {
        let id = intent
            .target_container
            .as_ref()
            .unwrap_or(&intent.original_container);
        let container = self
            .docker
            .inspect_container(id, None)
            .await
            .map_err(|_| invalid("recorded Docker update resource is unavailable"))?;
        require_owner(&container, p, &self.config)?;
        self.admit_container_resources(&container).await?;
        if intent.phase != Phase::Prepared {
            verify_replacement(&container, intent)?;
        }
        if intent.phase == Phase::Applied {
            verify_published_boundary(intent, &self.config)?;
        }
        Ok(())
    }

    async fn replace_image_container(
        &self,
        intent: &mut Intent,
        p: &SandboxUpdatePreconditions,
    ) -> Result<(), Status> {
        if intent.phase == Phase::Prepared {
            match self
                .docker
                .inspect_container(&intent.original_container, None)
                .await
            {
                Ok(source) => {
                    require_owner(&source, p, &self.config)?;
                    self.admit_container_resources(&source).await?;
                    if source.image.as_ref()
                        != serde_json::from_slice::<SandboxRuntimeDescriptor>(
                            &intent.original_descriptor,
                        )
                        .map_err(|_| invalid("original Docker descriptor changed"))?
                        .resource_claims
                        .get("docker.image_identity")
                    {
                        return Err(invalid(
                            "original Docker image changed after update acceptance",
                        ));
                    }
                    // No force and no volume-removal flag. The gateway owns the
                    // stopped lifecycle and user data remains in its volume.
                    self.docker
                        .remove_container(&intent.original_container, None)
                        .await
                        .map_err(|_| {
                            Status::unavailable(
                                "remove stopped Docker workload; retry the accepted update",
                            )
                        })?;
                }
                Err(error) if is_not_found_error(&error) => {}
                Err(_) => {
                    return Err(Status::unavailable(
                        "inspect original Docker workload during update",
                    ));
                }
            }
            let target = match self
                .docker
                .inspect_container(&intent.container_name, None)
                .await
            {
                Ok(target) => target,
                Err(error) if is_not_found_error(&error) => {
                    let created = self
                        .docker
                        .create_container(
                            Some(
                                CreateContainerOptionsBuilder::default()
                                    .name(&intent.container_name)
                                    .build(),
                            ),
                            intent.body.clone(),
                        )
                        .await
                        .map_err(|_| {
                            Status::unavailable(
                                "create corrected Docker workload; retry the accepted update",
                            )
                        })?;
                    let target = self
                        .docker
                        .inspect_container(&created.id, None)
                        .await
                        .map_err(|_| Status::unavailable("inspect corrected Docker workload"))?;
                    if target.id.as_ref() != Some(&created.id) {
                        return Err(invalid(
                            "Docker replacement inspection returned another container",
                        ));
                    }
                    target
                }
                Err(_) => return Err(Status::unavailable("inspect pending Docker replacement")),
            };
            require_owner(&target, p, &self.config)?;
            self.admit_container_resources(&target).await?;
            verify_replacement(&target, intent)?;
            let labels = target
                .config
                .as_ref()
                .and_then(|value| value.labels.as_ref())
                .ok_or_else(|| invalid("replacement ownership is missing"))?;
            if target.image.as_ref() != Some(&intent.image_id)
                || labels.get(OPERATION_LABEL) != Some(&intent.operation_id)
                || labels.get(REVISION_LABEL) != Some(&intent.revision.to_string())
                || target.state.as_ref().and_then(|value| value.status)
                    != Some(ContainerStateStatusEnum::CREATED)
            {
                return Err(invalid(
                    "Docker replacement does not match the accepted operation",
                ));
            }
            intent.target_container =
                Some(target.id.ok_or_else(|| {
                    invalid("Docker replacement lacks its immutable container ID")
                })?);
            intent.phase = Phase::Replaced;
            save(&self.config, intent)?;
        }
        self.validate_update_resource(intent, p).await?;
        let target = intent
            .target_container
            .as_ref()
            .ok_or_else(|| invalid("Docker replacement checkpoint lacks its target"))?;
        let (bootstrap, descriptor) = decode_boundary(intent, target)?;
        let directory = docker_boundary_state_dir_by_id(&intent.sandbox_id, &self.config)?;
        durable_write(&directory.join(BOUNDARY_CONFIG_FILE), &bootstrap)?;
        durable_write(&directory.join(RUNTIME_DESCRIPTOR_FILE), &descriptor)?;
        verify_published_boundary(intent, &self.config)?;
        intent.phase = Phase::Applied;
        save(&self.config, intent)
    }
}

/// Same weak per-resource lock pattern as the Kubernetes driver. This is a
/// driver mutex, not another lifecycle controller or endpoint service.
#[derive(Default)]
pub struct Gates {
    values: std::sync::Mutex<HashMap<String, std::sync::Weak<Mutex<()>>>>,
}

impl Gates {
    pub fn gate_for(&self, id: &str) -> Arc<Mutex<()>> {
        let mut values = self
            .values
            .lock()
            .expect("Docker image-update gate poisoned");
        values.retain(|_, value| value.strong_count() > 0);
        if let Some(value) = values.get(id).and_then(std::sync::Weak::upgrade) {
            return value;
        }
        let gate = Arc::new(Mutex::new(()));
        values.insert(id.into(), Arc::downgrade(&gate));
        gate
    }
}

fn record_ids(config: &DockerDriverRuntimeConfig) -> Result<Vec<String>, Status> {
    let sample = docker_boundary_state_dir_by_id("discovery", config)?;
    let root = sample
        .parent()
        .ok_or_else(|| invalid("Docker native state root is missing"))?;
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(invalid("Docker pending update inventory cannot be read")),
    };
    let mut ids = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| invalid("Docker pending update inventory is incomplete"))?;
        if !entry
            .file_type()
            .map_err(|_| invalid("Docker native state type is unavailable"))?
            .is_dir()
        {
            continue;
        }
        let Some(id) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if valid_native_id(&id)
            && read(config, &id)?.is_some_and(|intent| intent.phase != Phase::Applied)
        {
            ids.push(id);
        }
    }
    Ok(ids)
}

fn valid_native_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || matches!(v, b'-' | b'_'))
}

fn snapshot(intent: &Intent) -> DriverSandbox {
    pending_sandbox_snapshot(
        &DriverSandbox {
            id: intent.sandbox_id.clone(),
            name: intent.sandbox_name.clone(),
            namespace: intent.namespace.clone(),
            workspace: intent
                .body
                .labels
                .as_ref()
                .and_then(|labels| labels.get(LABEL_SANDBOX_WORKSPACE))
                .cloned()
                .unwrap_or_default(),
            ..Default::default()
        },
        &intent.namespace,
        DriverCondition {
            r#type: "Ready".into(),
            status: "False".into(),
            reason: openshell_core::driver_utils::CONDITION_STOPPED.into(),
            message: "Stopped; an accepted workload image update awaits recovery".into(),
            transition_time: None,
        },
        false,
    )
}

pub fn pending_ids(config: &DockerDriverRuntimeConfig) -> Result<Vec<String>, Status> {
    record_ids(config)
}

pub fn pending_snapshots(config: &DockerDriverRuntimeConfig) -> Result<Vec<DriverSandbox>, Status> {
    record_ids(config)?
        .iter()
        .map(|id| {
            read(config, id)?
                .map(|intent| snapshot(&intent))
                .ok_or_else(|| invalid("Docker pending update changed during observation"))
        })
        .collect()
}

pub fn pending_snapshot(
    config: &DockerDriverRuntimeConfig,
    id: &str,
    name: &str,
) -> Result<Option<DriverSandbox>, Status> {
    if !id.is_empty() {
        if !valid_native_id(id) {
            return Ok(None);
        }
        let Some(intent) = read(config, id)? else {
            return Ok(None);
        };
        if !name.is_empty() && name != intent.sandbox_name {
            return Err(invalid(
                "Docker update name does not match its native identity",
            ));
        }
        return Ok((intent.phase != Phase::Applied).then(|| snapshot(&intent)));
    }
    let matches = pending_snapshots(config)?
        .into_iter()
        .filter(|value| value.name == name)
        .collect::<Vec<_>>();
    match matches.len() {
        0 => Ok(None),
        1 => Ok(matches.into_iter().next()),
        _ => Err(invalid(
            "Docker pending update name is ambiguous; use its native ID",
        )),
    }
}

pub fn require_settled(config: &DockerDriverRuntimeConfig, id: &str) -> Result<(), Status> {
    if valid_native_id(id) && read(config, id)?.is_some_and(|intent| intent.phase != Phase::Applied)
    {
        return Err(invalid(
            "resume the accepted Docker image update before starting the workload",
        ));
    }
    Ok(())
}

pub enum LaunchValidation {
    Complete,
    BeforeStoppedRotation,
}

pub fn validate_committed_resource(
    config: &DockerDriverRuntimeConfig,
    id: &str,
    container: &ContainerInspectResponse,
    validation: LaunchValidation,
) -> Result<(), Status> {
    if !valid_native_id(id) {
        return Ok(());
    }
    if let Some(intent) = read(config, id)? {
        if intent.phase != Phase::Applied {
            return Err(invalid("Docker image update is not settled"));
        }
        verify_replacement(container, &intent)?;
        match validation {
            LaunchValidation::Complete => return verify_published_boundary(&intent, config),
            // Use the fresh inspect, not just the earlier list response, to
            // prove that credentials are rotated only on a stopped workload.
            LaunchValidation::BeforeStoppedRotation => require_stopped(container)?,
        }
        let (bootstrap, descriptor) = read_published_boundary(&intent, config)?;
        verify_boundary_resource_bindings(&intent, &bootstrap, &descriptor)?;
    }
    Ok(())
}

/// Enforce launch-pair consistency before using credentials or starting any
/// process. Resource bindings must also be checked before credential rotation.
pub fn validate_committed_boundary(
    config: &DockerDriverRuntimeConfig,
    id: &str,
) -> Result<(), Status> {
    if valid_native_id(id)
        && let Some(intent) = read(config, id)?
    {
        if intent.phase != Phase::Applied {
            return Err(invalid("Docker image update is not settled"));
        }
        verify_published_boundary(&intent, config)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
