// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Operator-owned trusted workload initialization registry.

use crate::config_file::TrustedWorkloadInitFileConfig;
use openshell_core::proto::TrustedWorkloadInitRequest;
use openshell_core::proto::compute::v1::TrustedWorkloadInitPlan;
use openshell_core::trusted_workload_init::{
    MAX_PAYLOAD_BYTES, RESERVED_WRITABLE_TREES, encode_envelope, validate_plan,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use tonic::Status;

const MAX_CONTRACT_ID_BYTES: usize = 128;
const MAX_COMMAND_ARGS: usize = 64;
const MAX_COMMAND_ARG_BYTES: usize = 4096;
const MAX_WRITABLE_PATHS: usize = 32;
const MAX_TIMEOUT_SECONDS: u32 = 300;

#[derive(Debug, Clone)]
struct Registration {
    contract_id: String,
    images: BTreeSet<String>,
    command: Vec<String>,
    max_payload_bytes: usize,
    timeout_seconds: u32,
    writable_paths: Vec<PathBuf>,
    capabilities: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct TrustedWorkloadInitRegistry {
    registrations: BTreeMap<String, Registration>,
}

impl TrustedWorkloadInitRegistry {
    pub fn from_config(configs: &[TrustedWorkloadInitFileConfig]) -> Result<Self, String> {
        let mut registrations = BTreeMap::new();
        for config in configs {
            let registration = Registration::try_from(config)?;
            let contract_id = registration.contract_id.clone();
            if registrations
                .insert(contract_id.clone(), registration)
                .is_some()
            {
                return Err(format!(
                    "duplicate trusted workload initialization contract '{contract_id}'"
                ));
            }
        }
        Ok(Self { registrations })
    }

    pub fn resolve(
        &self,
        request: &TrustedWorkloadInitRequest,
        image: &str,
    ) -> Result<TrustedWorkloadInitPlan, Status> {
        validate_contract_id(&request.contract_id).map_err(Status::invalid_argument)?;
        let registration = self
            .registrations
            .get(&request.contract_id)
            .ok_or_else(|| {
                Status::failed_precondition(format!(
                    "trusted workload initialization contract '{}' is not registered",
                    request.contract_id
                ))
            })?;

        if !registration.images.contains(image) {
            return Err(Status::failed_precondition(format!(
                "trusted workload initialization contract '{}' does not authorize image '{}'",
                request.contract_id, image
            )));
        }
        if request.payload.len() > registration.max_payload_bytes {
            return Err(Status::invalid_argument(format!(
                "trusted workload initialization payload exceeds contract limit ({} > {})",
                request.payload.len(),
                registration.max_payload_bytes
            )));
        }

        let payload_sha256 = hex::encode(Sha256::digest(&request.payload));
        Ok(TrustedWorkloadInitPlan {
            contract_id: registration.contract_id.clone(),
            payload: request.payload.clone(),
            payload_sha256,
            command: registration.command.clone(),
            timeout_seconds: registration.timeout_seconds,
            writable_paths: registration
                .writable_paths
                .iter()
                .map(|path| path.display().to_string())
                .collect(),
            image: image.to_string(),
            capabilities: registration.capabilities.clone(),
        })
    }
}

impl TryFrom<&TrustedWorkloadInitFileConfig> for Registration {
    type Error = String;

    fn try_from(config: &TrustedWorkloadInitFileConfig) -> Result<Self, Self::Error> {
        validate_contract_id(&config.contract_id)?;
        if config.images.is_empty() {
            return Err(format!(
                "contract '{}' must authorize at least one immutable image",
                config.contract_id
            ));
        }
        let mut images = BTreeSet::new();
        for image in &config.images {
            validate_immutable_image(image)
                .map_err(|error| format!("contract '{}': {error}", config.contract_id))?;
            if !images.insert(image.clone()) {
                return Err(format!(
                    "contract '{}' repeats image '{}'",
                    config.contract_id, image
                ));
            }
        }

        validate_command(&config.contract_id, &config.command)?;
        if config.max_payload_bytes == 0 || config.max_payload_bytes > MAX_PAYLOAD_BYTES {
            return Err(format!(
                "contract '{}' max_payload_bytes must be between 1 and {MAX_PAYLOAD_BYTES}",
                config.contract_id
            ));
        }
        if config.timeout_seconds == 0 || config.timeout_seconds > MAX_TIMEOUT_SECONDS {
            return Err(format!(
                "contract '{}' timeout_seconds must be between 1 and {MAX_TIMEOUT_SECONDS}",
                config.contract_id
            ));
        }
        if config.writable_paths.is_empty() || config.writable_paths.len() > MAX_WRITABLE_PATHS {
            return Err(format!(
                "contract '{}' writable_paths must contain between 1 and {MAX_WRITABLE_PATHS} entries",
                config.contract_id
            ));
        }
        let mut writable_paths = Vec::with_capacity(config.writable_paths.len());
        let mut unique_paths = BTreeSet::new();
        for path in &config.writable_paths {
            validate_writable_path(path)
                .map_err(|error| format!("contract '{}': {error}", config.contract_id))?;
            if !unique_paths.insert(path.clone()) {
                return Err(format!(
                    "contract '{}' repeats writable path '{}'",
                    config.contract_id,
                    path.display()
                ));
            }
            writable_paths.push(path.clone());
        }
        let capabilities = validate_capabilities(&config.contract_id, &config.capabilities)?;

        let registration = Self {
            contract_id: config.contract_id.clone(),
            images,
            command: config.command.clone(),
            max_payload_bytes: config.max_payload_bytes,
            timeout_seconds: config.timeout_seconds,
            writable_paths,
            capabilities,
        };
        validate_registration_envelope(&registration)?;
        Ok(registration)
    }
}

fn validate_registration_envelope(registration: &Registration) -> Result<(), String> {
    let image = registration
        .images
        .iter()
        .max_by_key(|image| image.len())
        .expect("registration images were validated as non-empty");
    let payload = vec![0; registration.max_payload_bytes];
    let plan = TrustedWorkloadInitPlan {
        contract_id: registration.contract_id.clone(),
        payload_sha256: hex::encode(Sha256::digest(&payload)),
        payload,
        command: registration.command.clone(),
        timeout_seconds: registration.timeout_seconds,
        writable_paths: registration
            .writable_paths
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        image: image.clone(),
        capabilities: registration.capabilities.clone(),
    };
    validate_plan(&plan, image)
        .map_err(|error| format!("contract '{}': {error}", registration.contract_id))?;
    encode_envelope(
        &"s".repeat(128),
        &plan,
        &format!("sha256:{}", "a".repeat(64)),
    )
    .map(|_| ())
    .map_err(|error| format!("contract '{}': {error}", registration.contract_id))
}

fn validate_contract_id(contract_id: &str) -> Result<(), String> {
    if contract_id.is_empty() || contract_id.len() > MAX_CONTRACT_ID_BYTES {
        return Err(format!(
            "contract_id must contain between 1 and {MAX_CONTRACT_ID_BYTES} bytes"
        ));
    }
    if !contract_id.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
    }) {
        return Err(format!(
            "contract_id '{contract_id}' must contain only lowercase ASCII letters, digits, '.', '-', or '_'"
        ));
    }
    Ok(())
}

fn validate_immutable_image(image: &str) -> Result<(), String> {
    let digest = if let Some(digest) = image.strip_prefix("sha256:") {
        digest
    } else if let Some((name, digest)) = image.rsplit_once("@sha256:") {
        if name.is_empty() {
            return Err(format!(
                "image '{image}' must be an exact sha256 digest reference or immutable image ID"
            ));
        }
        digest
    } else {
        return Err(format!(
            "image '{image}' must be an exact sha256 digest reference or immutable image ID"
        ));
    };
    if digest.len() != 64
        || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        || image.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(format!(
            "image '{image}' must be an exact sha256 digest reference or immutable image ID"
        ));
    }
    Ok(())
}

fn validate_command(contract_id: &str, command: &[String]) -> Result<(), String> {
    if command.is_empty() || command.len() > MAX_COMMAND_ARGS {
        return Err(format!(
            "contract '{contract_id}' command must contain between 1 and {MAX_COMMAND_ARGS} argv entries"
        ));
    }
    if !Path::new(&command[0]).is_absolute() {
        return Err(format!(
            "contract '{contract_id}' command executable must be an absolute path"
        ));
    }
    let executable = Path::new(&command[0]);
    for reserved in RESERVED_WRITABLE_TREES {
        if executable == Path::new(reserved) || executable.starts_with(reserved) {
            return Err(format!(
                "contract '{contract_id}' command executable overlaps supervisor-owned path '{reserved}'"
            ));
        }
    }
    if command
        .iter()
        .any(|arg| arg.is_empty() || arg.len() > MAX_COMMAND_ARG_BYTES || arg.contains('\0'))
    {
        return Err(format!(
            "contract '{contract_id}' command contains an empty, oversized, or NUL-bearing argv entry"
        ));
    }
    Ok(())
}

fn validate_writable_path(path: &Path) -> Result<(), String> {
    let raw = path.to_string_lossy();
    if !path.is_absolute()
        || raw == "/"
        || raw.ends_with('/')
        || raw.contains("//")
        || raw
            .split('/')
            .any(|component| component == "." || component == "..")
    {
        return Err(format!(
            "writable path '{}' must be a normalized absolute path below /",
            path.display()
        ));
    }
    for reserved in RESERVED_WRITABLE_TREES {
        let reserved = Path::new(reserved);
        if path.starts_with(reserved) || reserved.starts_with(path) {
            return Err(format!(
                "writable path '{}' overlaps supervisor-owned path '{}'",
                path.display(),
                reserved.display()
            ));
        }
    }
    Ok(())
}

fn validate_capabilities(
    contract_id: &str,
    capabilities: &[String],
) -> Result<Vec<String>, String> {
    const ALLOWED: [&str; 2] = ["CHOWN", "FOWNER"];
    let mut unique = BTreeSet::new();
    for capability in capabilities {
        if !ALLOWED.contains(&capability.as_str()) {
            return Err(format!(
                "contract '{contract_id}' capability '{capability}' is not allowed; trusted initializers may request only CHOWN and FOWNER"
            ));
        }
        if !unique.insert(capability.clone()) {
            return Err(format!(
                "contract '{contract_id}' repeats capability '{capability}'"
            ));
        }
    }
    Ok(unique.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> TrustedWorkloadInitFileConfig {
        TrustedWorkloadInitFileConfig {
            contract_id: "nemoclaw.managed-startup.v1".to_string(),
            images: vec![format!(
                "registry.example/nemoclaw@sha256:{}",
                "a".repeat(64)
            )],
            command: vec!["/usr/local/bin/nemoclaw-managed-init".to_string()],
            max_payload_bytes: 4096,
            timeout_seconds: 60,
            writable_paths: vec![PathBuf::from("/etc/nemoclaw"), PathBuf::from("/sandbox")],
            capabilities: vec!["CHOWN".to_string(), "FOWNER".to_string()],
        }
    }

    #[test]
    fn resolves_registered_contract_without_caller_owned_execution_fields() {
        let registry = TrustedWorkloadInitRegistry::from_config(&[config()]).unwrap();
        let image = format!("registry.example/nemoclaw@sha256:{}", "a".repeat(64));
        let plan = registry
            .resolve(
                &TrustedWorkloadInitRequest {
                    contract_id: "nemoclaw.managed-startup.v1".to_string(),
                    payload: b"profile".to_vec(),
                },
                &image,
            )
            .unwrap();

        assert_eq!(
            plan.command,
            ["/usr/local/bin/nemoclaw-managed-init".to_string()]
        );
        assert_eq!(plan.image, image);
        assert_eq!(plan.payload_sha256.len(), 64);
    }

    #[test]
    fn rejects_mutable_image_and_supervisor_write_path() {
        let mut mutable = config();
        mutable.images = vec!["registry.example/nemoclaw:latest".to_string()];
        assert!(TrustedWorkloadInitRegistry::from_config(&[mutable]).is_err());

        let mut reserved = config();
        reserved.writable_paths = vec![PathBuf::from("/etc/openshell/auth")];
        assert!(TrustedWorkloadInitRegistry::from_config(&[reserved]).is_err());

        let mut reserved_parent = config();
        reserved_parent.writable_paths = vec![PathBuf::from("/var/lib")];
        assert!(TrustedWorkloadInitRegistry::from_config(&[reserved_parent]).is_err());

        let mut executable_parent = config();
        executable_parent.writable_paths = vec![PathBuf::from("/usr/local")];
        assert!(TrustedWorkloadInitRegistry::from_config(&[executable_parent]).is_err());
    }
}
