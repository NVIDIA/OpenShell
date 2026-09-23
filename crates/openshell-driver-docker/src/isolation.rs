// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Docker provisioning for the shared authenticated boundary protocol.
//!
//! Docker owns only container placement, the protected socket, and immutable OCI resource
//! claims. Lifecycle, process, network, identity, and wire behavior live in
//! `openshell-isolation-interface` and `openshell-sandbox`.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::path::PathBuf;

use openshell_isolation_interface::contract::{
    BackendError, OuterFenceGuarantee, OuterFenceGuarantees, ResolvedWorkloadIdentity,
};
use openshell_sandbox_backend::GPU_RESOURCE_CLAIM;
use openshell_sandbox_backend::boundary_protocol::{
    BoundaryConfig, BoundaryListener, GatewayVerificationKey, SandboxRuntimeDescriptor,
    SandboxTlsClientConfig, SandboxTlsServerConfig, SandboxTransport,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DockerFenceWireFormat {
    LegacyDriverFence,
    OuterFence,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "backend", rename_all = "kebab-case", deny_unknown_fields)]
enum LegacyDriverFenceEvidence {
    Docker {
        container_id: String,
        network_mode: String,
        unexpected_networks: Vec<String>,
    },
}

#[derive(Serialize)]
struct DockerOuterFenceEvidence<'a> {
    container_id: &'a str,
    network_mode: &'a str,
    unexpected_networks: &'a [String],
}

impl DockerOuterFenceEvidence<'_> {
    fn project(&self, generation: &str) -> Result<OuterFenceGuarantees, BackendError> {
        if self.container_id.is_empty() {
            return Err(BackendError::Descriptor(
                "Docker outer fence evidence is incomplete".to_string(),
            ));
        }
        let mut established = Vec::new();
        if self.network_mode == "none" {
            // With no container network namespace attachment, workload egress
            // remains denied both after revocation and if the supervisor exits.
            established.extend([
                OuterFenceGuarantee::DefaultDenyEgress,
                OuterFenceGuarantee::RevocationVerified,
                OuterFenceGuarantee::ControllerLossFailsClosed,
            ]);
        }
        if self.unexpected_networks.is_empty() {
            established.push(OuterFenceGuarantee::NoUnmanagedEgressPath);
        }
        let encoded = serde_json::to_vec(self).map_err(|error| {
            BackendError::Descriptor(format!("encode Docker outer fence evidence: {error}"))
        })?;
        let projection =
            OuterFenceGuarantees::from_enforcement_evidence(generation, established, &encoded)?;
        projection.validate(generation)?;
        Ok(projection)
    }
}

fn decode_fence_compatible<T: DeserializeOwned>(
    encoded: &[u8],
    description: &str,
) -> Result<(T, DockerFenceWireFormat), BackendError> {
    let mut value: serde_json::Value = serde_json::from_slice(encoded)
        .map_err(|error| BackendError::Descriptor(format!("decode {description}: {error}")))?;
    let object = value.as_object_mut().ok_or_else(|| {
        BackendError::Descriptor(format!("decode {description}: expected a JSON object"))
    })?;
    let format = match (
        object.contains_key("driver_fence"),
        object.contains_key("outer_fence"),
    ) {
        (false, true) => DockerFenceWireFormat::OuterFence,
        (true, false) => {
            let generation = object
                .get("generation")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    BackendError::Descriptor(format!(
                        "decode {description}: legacy bootstrap generation is missing"
                    ))
                })?
                .to_string();
            let legacy: LegacyDriverFenceEvidence =
                serde_json::from_value(object.remove("driver_fence").expect("checked above"))
                    .map_err(|error| {
                        BackendError::Descriptor(format!(
                            "decode {description} legacy driver fence: {error}"
                        ))
                    })?;
            let LegacyDriverFenceEvidence::Docker {
                container_id,
                network_mode,
                unexpected_networks,
            } = legacy;
            let projection = DockerOuterFenceEvidence {
                container_id: &container_id,
                network_mode: &network_mode,
                unexpected_networks: &unexpected_networks,
            }
            .project(&generation)?;
            object.insert(
                "outer_fence".to_string(),
                serde_json::to_value(projection).map_err(|error| {
                    BackendError::Descriptor(format!("encode migrated Docker outer fence: {error}"))
                })?,
            );
            DockerFenceWireFormat::LegacyDriverFence
        }
        _ => {
            return Err(BackendError::Descriptor(format!(
                "decode {description}: expected exactly one of driver_fence or outer_fence"
            )));
        }
    };
    serde_json::from_value(value)
        .map(|decoded| (decoded, format))
        .map_err(|error| BackendError::Descriptor(format!("decode {description}: {error}")))
}

pub fn decode_boundary_config_compatible(
    encoded: &[u8],
) -> Result<(BoundaryConfig, DockerFenceWireFormat), BackendError> {
    decode_fence_compatible(encoded, "Docker boundary config")
}

pub fn decode_runtime_descriptor_compatible(
    encoded: &[u8],
) -> Result<(SandboxRuntimeDescriptor, DockerFenceWireFormat), BackendError> {
    decode_fence_compatible(encoded, "Docker runtime descriptor")
}

fn encode_fence_compatible<T: Serialize>(
    value: &T,
    format: DockerFenceWireFormat,
    description: &str,
) -> Result<Vec<u8>, BackendError> {
    let mut value = serde_json::to_value(value)
        .map_err(|error| BackendError::Descriptor(format!("encode {description}: {error}")))?;
    if format == DockerFenceWireFormat::LegacyDriverFence {
        let object = value.as_object_mut().ok_or_else(|| {
            BackendError::Descriptor(format!("encode {description}: expected a JSON object"))
        })?;
        let container_id = object
            .get("resource_claims")
            .and_then(serde_json::Value::as_object)
            .and_then(|claims| claims.get("docker.container_id"))
            .and_then(serde_json::Value::as_str)
            .filter(|container_id| !container_id.is_empty())
            .ok_or_else(|| {
                BackendError::Descriptor(format!(
                    "encode {description}: Docker container resource claim is missing"
                ))
            })?
            .to_string();
        if object.remove("outer_fence").is_none() {
            return Err(BackendError::Descriptor(format!(
                "encode {description}: outer fence projection is missing"
            )));
        }
        object.insert(
            "driver_fence".to_string(),
            serde_json::to_value(LegacyDriverFenceEvidence::Docker {
                container_id,
                network_mode: "none".to_string(),
                unexpected_networks: Vec::new(),
            })
            .map_err(|error| {
                BackendError::Descriptor(format!(
                    "encode {description} legacy driver fence: {error}"
                ))
            })?,
        );
    }
    serde_json::to_vec(&value)
        .map_err(|error| BackendError::Descriptor(format!("encode {description}: {error}")))
}

pub fn encode_boundary_config_compatible(
    config: &BoundaryConfig,
    format: DockerFenceWireFormat,
) -> Result<Vec<u8>, BackendError> {
    encode_fence_compatible(config, format, "Docker boundary config")
}

pub fn encode_runtime_descriptor_compatible(
    descriptor: &SandboxRuntimeDescriptor,
    format: DockerFenceWireFormat,
) -> Result<Vec<u8>, BackendError> {
    encode_fence_compatible(descriptor, format, "Docker runtime descriptor")
}

/// Driver-owned inputs that bind one Docker container to one boundary.
pub struct DockerBoundarySpec {
    pub boundary_id: String,
    pub generation: String,
    pub session_id: openshell_core::SandboxSessionId,
    pub session_rotation: openshell_core::jwt::SessionRotation,
    pub auth_epoch: openshell_core::jwt::CredentialEpoch,
    pub gateway_id: String,
    pub verification_keys: Vec<GatewayVerificationKey>,
    pub container_id: String,
    pub image_identity: String,
    pub gpu_requested: bool,
    pub listener_socket: PathBuf,
    pub control_socket: PathBuf,
    pub sandbox_tls: SandboxTlsServerConfig,
    pub supervisor_tls: SandboxTlsClientConfig,
    pub host_gateway_ip: Option<IpAddr>,
    pub workload_identity: ResolvedWorkloadIdentity,
    pub child_env: HashMap<String, String>,
}

/// Protected container config and matching host descriptor.
pub struct DockerBoundaryProvisioning {
    pub boundary_config: BoundaryConfig,
    pub runtime_descriptor: SandboxRuntimeDescriptor,
}

impl DockerBoundarySpec {
    /// Produce both sides of the common protocol from the same immutable
    /// Docker coordinates so attach cannot bind a different container.
    pub fn provision(self) -> Result<DockerBoundaryProvisioning, BackendError> {
        let mut resource_claims = BTreeMap::from([
            ("docker.container_id".to_string(), self.container_id),
            ("docker.image_identity".to_string(), self.image_identity),
        ]);
        if self.gpu_requested {
            resource_claims.insert(GPU_RESOURCE_CLAIM.to_string(), "true".to_string());
        }
        let unexpected_networks = Vec::new();
        let outer_fence = DockerOuterFenceEvidence {
            container_id: &resource_claims["docker.container_id"],
            network_mode: "none",
            unexpected_networks: &unexpected_networks,
        }
        .project(&self.generation)?;
        Ok(DockerBoundaryProvisioning {
            boundary_config: BoundaryConfig {
                boundary_id: self.boundary_id.clone(),
                generation: self.generation.clone(),
                session_id: self.session_id,
                session_rotation: self.session_rotation,
                auth_epoch: self.auth_epoch,
                gateway_id: self.gateway_id,
                verification_keys: self.verification_keys,
                listener: BoundaryListener::Unix {
                    socket_path: self.listener_socket,
                    tls: self.sandbox_tls,
                },
                resource_claims: resource_claims.clone(),
                resource_claim_files: BTreeMap::new(),
                workload_identity: self.workload_identity.clone(),
                outer_fence: outer_fence.clone(),
                child_env: self.child_env,
            },
            runtime_descriptor: SandboxRuntimeDescriptor {
                boundary_id: self.boundary_id,
                generation: self.generation,
                session_id: self.session_id,
                workload_identity: self.workload_identity,
                transport: SandboxTransport::Unix {
                    socket_path: self.control_socket,
                },
                tls: self.supervisor_tls,
                host_gateway_ip: self.host_gateway_ip,
                resource_claims,
                outer_fence,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provisioning() -> DockerBoundaryProvisioning {
        let session_id = openshell_core::SandboxSessionId::new();
        let tls =
            openshell_sandbox_backend::boundary_protocol::generate_sandbox_tls_material(session_id)
                .unwrap();
        DockerBoundarySpec {
            boundary_id: "sandbox-1".to_string(),
            generation: "generation-1".to_string(),
            session_id,
            session_rotation: openshell_core::jwt::SessionRotation::new(1).unwrap(),
            auth_epoch: openshell_core::jwt::CredentialEpoch::new(1).unwrap(),
            gateway_id: "gateway-1".to_string(),
            verification_keys: vec![GatewayVerificationKey {
                key_id: "key-1".to_string(),
                public_key_pem: "public-key".to_string(),
            }],
            container_id: "sha256:container".to_string(),
            image_identity: "sha256:image".to_string(),
            gpu_requested: true,
            listener_socket: PathBuf::from("/run/openshell/boundary/control.sock"),
            control_socket: PathBuf::from("/host/control.sock"),
            sandbox_tls: SandboxTlsServerConfig {
                certificate_chain_path: PathBuf::from("/run/openshell/boundary/server.crt"),
                private_key_path: PathBuf::from("/run/openshell/boundary/server.key"),
            },
            supervisor_tls: SandboxTlsClientConfig {
                server_name: tls.server_name,
                trust_anchor_pem: tls.trust_anchor_pem,
            },
            host_gateway_ip: Some(IpAddr::from([127, 0, 0, 1])),
            workload_identity: ResolvedWorkloadIdentity::new(
                1000,
                1000,
                Vec::new(),
                "image".to_string(),
                "sha256:image".to_string(),
            )
            .unwrap(),
            child_env: HashMap::new(),
        }
        .provision()
        .unwrap()
    }

    #[test]
    fn outer_fence_projection_rejects_each_missing_native_fact() {
        let unexpected_networks = vec!["bridge".to_string()];
        for evidence in [
            DockerOuterFenceEvidence {
                container_id: "",
                network_mode: "none",
                unexpected_networks: &[],
            },
            DockerOuterFenceEvidence {
                container_id: "container",
                network_mode: "bridge",
                unexpected_networks: &[],
            },
            DockerOuterFenceEvidence {
                container_id: "container",
                network_mode: "none",
                unexpected_networks: &unexpected_networks,
            },
        ] {
            assert!(evidence.project("generation-1").is_err());
        }
    }

    #[test]
    fn provisioning_binds_container_and_image_claims() {
        let provisioned = provisioning();

        assert_eq!(
            provisioned.boundary_config.resource_claims,
            provisioned.runtime_descriptor.resource_claims
        );
        assert_eq!(
            provisioned.runtime_descriptor.resource_claims["docker.container_id"],
            "sha256:container"
        );
        assert_eq!(
            provisioned.runtime_descriptor.resource_claims[GPU_RESOURCE_CLAIM],
            "true"
        );
        assert_eq!(
            provisioned.boundary_config.outer_fence,
            provisioned.runtime_descriptor.outer_fence
        );
        assert!(
            provisioned
                .runtime_descriptor
                .outer_fence
                .validate("generation-1")
                .is_ok()
        );
    }

    #[test]
    fn legacy_driver_fence_round_trips_through_current_projection() {
        let provisioned = provisioning();
        let boundary = encode_boundary_config_compatible(
            &provisioned.boundary_config,
            DockerFenceWireFormat::LegacyDriverFence,
        )
        .unwrap();
        let descriptor = encode_runtime_descriptor_compatible(
            &provisioned.runtime_descriptor,
            DockerFenceWireFormat::LegacyDriverFence,
        )
        .unwrap();
        for encoded in [&boundary, &descriptor] {
            let value: serde_json::Value = serde_json::from_slice(encoded).unwrap();
            assert!(value.get("outer_fence").is_none());
            assert_eq!(value["driver_fence"]["backend"], "docker");
            assert_eq!(value["driver_fence"]["container_id"], "sha256:container");
        }
        let (decoded_boundary, boundary_format) =
            decode_boundary_config_compatible(&boundary).unwrap();
        let (decoded_descriptor, descriptor_format) =
            decode_runtime_descriptor_compatible(&descriptor).unwrap();
        assert_eq!(boundary_format, DockerFenceWireFormat::LegacyDriverFence);
        assert_eq!(descriptor_format, DockerFenceWireFormat::LegacyDriverFence);
        assert_eq!(decoded_boundary.outer_fence, decoded_descriptor.outer_fence);
        assert_eq!(
            decoded_boundary.outer_fence,
            provisioned.boundary_config.outer_fence
        );
    }
}
