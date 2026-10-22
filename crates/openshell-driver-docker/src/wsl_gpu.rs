// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Explicit Docker Desktop WSL NVIDIA injection. Never infer all-GPU consent
//! from the ordinary one-GPU resource request or a failed CDI selection.
use super::{BoundaryConfig, DockerSandboxDriverConfig, GpuResourceRequirements};
use bollard::models::{ContainerInspectResponse, DeviceRequest, SystemInfo};
use tonic::Status;

pub const SELECTION_CLAIM: &str = "docker.nvidia_wsl_gpus";

#[derive(Debug, Clone, Copy, serde::Deserialize)]
pub enum AllGpus {
    #[serde(rename = "all")]
    All,
}

pub fn supported_daemon(info: &SystemInfo) -> bool {
    info.operating_system
        .as_deref()
        .is_some_and(|os| os.eq_ignore_ascii_case("Docker Desktop"))
        && super::docker_info_reports_wsl2(info)
}

pub fn validate_request(
    gpu: Option<&GpuResourceRequirements>,
    config: &DockerSandboxDriverConfig,
    supported: bool,
) -> Result<(), Status> {
    if !supported {
        return Err(Status::failed_precondition(
            "nvidia_wsl_gpus requires a Docker Desktop WSL2 daemon",
        ));
    }
    if config.cdi_devices.is_some() || gpu.is_none() || gpu.is_some_and(|gpu| gpu.count.is_some()) {
        return Err(Status::invalid_argument(
            "nvidia_wsl_gpus=all requires a GPU request without count or cdi_devices; it explicitly grants all GPUs",
        ));
    }
    Ok(())
}

pub fn device_request() -> DeviceRequest {
    DeviceRequest {
        driver: Some("nvidia".into()),
        count: Some(-1),
        capabilities: Some(vec![vec!["gpu".into()]]),
        ..Default::default()
    }
}

pub fn admit_request(container: &ContainerInspectResponse, expected: bool) -> Result<(), Status> {
    let requests = container
        .host_config
        .as_ref()
        .and_then(|host| host.device_requests.as_deref())
        .unwrap_or_default();
    if expected {
        let valid = requests.len() == 1
            && requests[0].driver.as_deref() == Some("nvidia")
            && requests[0].count == Some(-1)
            && requests[0].device_ids.as_ref().is_none_or(Vec::is_empty)
            && requests[0]
                .options
                .as_ref()
                .is_none_or(std::collections::HashMap::is_empty)
            && requests[0].capabilities.as_ref() == device_request().capabilities.as_ref();
        if !valid {
            return Err(Status::failed_precondition(
                "Docker NVIDIA request differs from protected all-GPU selection",
            ));
        }
    } else if requests
        .iter()
        .any(|request| request.driver.as_deref() != Some("cdi"))
    {
        return Err(Status::failed_precondition(
            "unrecorded non-CDI Docker GPU request",
        ));
    }
    Ok(())
}

pub fn admit_persisted(
    container: &ContainerInspectResponse,
    boundary: &BoundaryConfig,
) -> Result<(), Status> {
    let selection = boundary.resource_claims.get(SELECTION_CLAIM);
    if selection.is_some_and(|value| value != "all") {
        return Err(Status::failed_precondition(
            "unsupported protected WSL GPU selection",
        ));
    }
    if selection.is_some()
        && (boundary.cdi_context.is_some()
            || boundary
                .resource_claims
                .get("docker.container_id")
                .map(String::as_str)
                != container.id.as_deref()
            || boundary
                .resource_claims
                .get(openshell_sandbox_backend::GPU_RESOURCE_CLAIM)
                .map(String::as_str)
                != Some("true"))
    {
        return Err(Status::failed_precondition(
            "WSL GPU selection is not bound to this GPU workload",
        ));
    }
    admit_request(container, selection.is_some())
}
