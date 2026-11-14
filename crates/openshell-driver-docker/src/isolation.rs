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

use openshell_core::jwt::{LaunchBinding, LaunchTls, LaunchVerificationKey};
use openshell_isolation_interface::contract::{
    BackendError, ProvisioningEvidence, ResolvedWorkloadIdentity,
};
use openshell_sandbox_backend::GPU_RESOURCE_CLAIM;
use openshell_sandbox_backend::boundary_protocol::{
    BoundaryConfig, BoundaryListener, GatewayVerificationKey, SandboxRuntimeDescriptor,
    SandboxTlsClientConfig, SandboxTlsServerConfig, SandboxTransport,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct DockerOuterFenceEvidence<'a> {
    container_id: &'a str,
    network_mode: &'static str,
    unexpected_networks: &'a [String],
}

impl DockerOuterFenceEvidence<'_> {
    fn project(&self, generation: &str) -> Result<ProvisioningEvidence, BackendError> {
        if self.container_id.is_empty()
            || self.network_mode != "none"
            || !self.unexpected_networks.is_empty()
        {
            return Err(BackendError::Descriptor(
                "Docker provisioning evidence is incomplete".to_string(),
            ));
        }
        let encoded = serde_json::to_vec(self).map_err(|error| {
            BackendError::Descriptor(format!("encode Docker outer fence evidence: {error}"))
        })?;
        let projection = ProvisioningEvidence::from_enforcement_evidence(generation, &encoded)?;
        projection.validate(generation)?;
        Ok(projection)
    }
}

/// Bind the validated container fence to the generation being launched.
pub fn provisioning_evidence(
    container_id: &str,
    generation: &str,
) -> Result<ProvisioningEvidence, BackendError> {
    DockerOuterFenceEvidence {
        container_id,
        network_mode: "none",
        unexpected_networks: &[],
    }
    .project(generation)
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

/// Current layout of [`DockerBoundaryState`]. Bump it for a change an older
/// driver cannot read, and keep reading the versions still in use.
pub const DOCKER_BOUNDARY_STATE_VERSION: u32 = 1;

/// What the driver remembers about one boundary between launches.
///
/// This record is private to the Docker driver. It is not a contract document
/// and promises nothing to any other component: the driver writes it, reads it
/// back, and generates the contract documents from it for every launch, so it
/// never parses a document it (or an older driver) wrote earlier. It holds the
/// fields of [`DockerBoundarySpec`] as plain values, so its encoding does not
/// depend on the contract types' own encodings. It contains secrets (the
/// workload environment) and is stored with the other owner-only files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DockerBoundaryState {
    /// Layout version of this record; see [`DOCKER_BOUNDARY_STATE_VERSION`].
    pub version: u32,
    pub boundary_id: String,
    /// Generation, session, rotation, epoch, gateway identity, verification
    /// keys, and the supervisor's TLS server name and trust anchor.
    pub launch: LaunchBinding,
    pub container_id: String,
    pub image_identity: String,
    pub gpu_requested: bool,
    pub listener_socket: PathBuf,
    pub control_socket: PathBuf,
    pub sandbox_tls_certificate_path: PathBuf,
    pub sandbox_tls_private_key_path: PathBuf,
    pub host_gateway_ip: Option<IpAddr>,
    pub workload_identity: StoredIdentity,
    pub child_env: BTreeMap<String, String>,
}

/// Plain-value workload identity. Validated again when the record is turned
/// back into a [`DockerBoundarySpec`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredIdentity {
    pub uid: u32,
    pub gid: u32,
    pub supplementary_gids: Vec<u32>,
    pub source: String,
    pub resource_digest: String,
}

impl From<&ResolvedWorkloadIdentity> for StoredIdentity {
    fn from(identity: &ResolvedWorkloadIdentity) -> Self {
        Self {
            uid: identity.uid,
            gid: identity.gid,
            supplementary_gids: identity.supplementary_gids.clone(),
            source: identity.source.clone(),
            resource_digest: identity.resource_digest.clone(),
        }
    }
}

impl DockerBoundaryState {
    /// The record of the boundary that `spec` provisions.
    pub fn from_spec(spec: &DockerBoundarySpec) -> Self {
        Self {
            version: DOCKER_BOUNDARY_STATE_VERSION,
            boundary_id: spec.boundary_id.clone(),
            launch: LaunchBinding {
                session_id: spec.session_id,
                generation: spec.generation.clone(),
                session_rotation: spec.session_rotation,
                auth_epoch: spec.auth_epoch,
                gateway_id: spec.gateway_id.clone(),
                verification_keys: spec
                    .verification_keys
                    .iter()
                    .map(|key| LaunchVerificationKey {
                        key_id: key.key_id.clone(),
                        public_key_pem: key.public_key_pem.clone(),
                    })
                    .collect(),
                supervisor_tls: LaunchTls {
                    server_name: spec.supervisor_tls.server_name.clone(),
                    trust_anchor_pem: spec.supervisor_tls.trust_anchor_pem.clone(),
                },
            },
            container_id: spec.container_id.clone(),
            image_identity: spec.image_identity.clone(),
            gpu_requested: spec.gpu_requested,
            listener_socket: spec.listener_socket.clone(),
            control_socket: spec.control_socket.clone(),
            sandbox_tls_certificate_path: spec.sandbox_tls.certificate_chain_path.clone(),
            sandbox_tls_private_key_path: spec.sandbox_tls.private_key_path.clone(),
            host_gateway_ip: spec.host_gateway_ip,
            workload_identity: (&spec.workload_identity).into(),
            child_env: spec
                .child_env
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        }
    }

    /// The inputs that produce this boundary's documents.
    pub fn spec(&self) -> Result<DockerBoundarySpec, BackendError> {
        let identity = &self.workload_identity;
        Ok(DockerBoundarySpec {
            boundary_id: self.boundary_id.clone(),
            generation: self.launch.generation.clone(),
            session_id: self.launch.session_id,
            session_rotation: self.launch.session_rotation,
            auth_epoch: self.launch.auth_epoch,
            gateway_id: self.launch.gateway_id.clone(),
            verification_keys: self
                .launch
                .verification_keys
                .iter()
                .map(|key| GatewayVerificationKey {
                    key_id: key.key_id.clone(),
                    public_key_pem: key.public_key_pem.clone(),
                })
                .collect(),
            container_id: self.container_id.clone(),
            image_identity: self.image_identity.clone(),
            gpu_requested: self.gpu_requested,
            listener_socket: self.listener_socket.clone(),
            control_socket: self.control_socket.clone(),
            sandbox_tls: SandboxTlsServerConfig {
                certificate_chain_path: self.sandbox_tls_certificate_path.clone(),
                private_key_path: self.sandbox_tls_private_key_path.clone(),
            },
            supervisor_tls: SandboxTlsClientConfig {
                server_name: self.launch.supervisor_tls.server_name.clone(),
                trust_anchor_pem: self.launch.supervisor_tls.trust_anchor_pem.clone(),
            },
            host_gateway_ip: self.host_gateway_ip,
            workload_identity: ResolvedWorkloadIdentity::new(
                identity.uid,
                identity.gid,
                identity.supplementary_gids.clone(),
                identity.source.clone(),
                identity.resource_digest.clone(),
            )?,
            child_env: self
                .child_env
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        })
    }

    /// Both documents for the current state of the boundary.
    pub fn provision(&self) -> Result<DockerBoundaryProvisioning, BackendError> {
        self.spec()?.provision()
    }

    /// The record of a boundary that an older driver left as documents only.
    ///
    /// Older drivers kept the contract documents themselves as their state and
    /// edited them in place. This reads that layout so such a sandbox can
    /// restart; the caller then keeps the record and never reads the documents
    /// again. Only the runtime-initiated Unix listener and transport, the only
    /// kind Docker provisions, are accepted.
    pub fn from_documents(
        boundary: &BoundaryConfig,
        descriptor: &SandboxRuntimeDescriptor,
    ) -> Result<Self, BackendError> {
        let BoundaryListener::RuntimeInitiatedUnix {
            socket_path: listener_socket,
            tls,
        } = &boundary.listener
        else {
            return Err(BackendError::Descriptor(
                "the Docker sandbox was provisioned with an unsupported listener".to_string(),
            ));
        };
        let SandboxTransport::RuntimeInitiatedUnix {
            socket_path: control_socket,
        } = &descriptor.transport
        else {
            return Err(BackendError::Descriptor(
                "the Docker sandbox was provisioned with an unsupported transport".to_string(),
            ));
        };
        let claim = |name: &str| {
            boundary.resource_claims.get(name).cloned().ok_or_else(|| {
                BackendError::Descriptor(format!("the Docker sandbox is missing the {name} claim"))
            })
        };
        Ok(Self {
            version: DOCKER_BOUNDARY_STATE_VERSION,
            boundary_id: boundary.boundary_id.clone(),
            launch: LaunchBinding {
                session_id: boundary.session_id,
                generation: boundary.generation.clone(),
                session_rotation: boundary.session_rotation,
                auth_epoch: boundary.auth_epoch,
                gateway_id: boundary.gateway_id.clone(),
                verification_keys: boundary
                    .verification_keys
                    .iter()
                    .map(|key| LaunchVerificationKey {
                        key_id: key.key_id.clone(),
                        public_key_pem: key.public_key_pem.clone(),
                    })
                    .collect(),
                supervisor_tls: LaunchTls {
                    server_name: descriptor.tls.server_name.clone(),
                    trust_anchor_pem: descriptor.tls.trust_anchor_pem.clone(),
                },
            },
            container_id: claim("docker.container_id")?,
            image_identity: claim("docker.image_identity")?,
            gpu_requested: boundary.resource_claims.contains_key(GPU_RESOURCE_CLAIM),
            listener_socket: listener_socket.clone(),
            control_socket: control_socket.clone(),
            sandbox_tls_certificate_path: tls.certificate_chain_path.clone(),
            sandbox_tls_private_key_path: tls.private_key_path.clone(),
            host_gateway_ip: descriptor.host_gateway_ip,
            workload_identity: (&boundary.workload_identity).into(),
            child_env: boundary
                .child_env
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        })
    }
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
        let provisioning_evidence =
            provisioning_evidence(&resource_claims["docker.container_id"], &self.generation)?;
        Ok(DockerBoundaryProvisioning {
            boundary_config: BoundaryConfig {
                boundary_id: self.boundary_id.clone(),
                generation: self.generation.clone(),
                session_id: self.session_id,
                session_rotation: self.session_rotation,
                auth_epoch: self.auth_epoch,
                gateway_id: self.gateway_id,
                verification_keys: self.verification_keys,
                listener: BoundaryListener::RuntimeInitiatedUnix {
                    socket_path: self.listener_socket,
                    tls: self.sandbox_tls,
                },
                resource_claims: resource_claims.clone(),
                resource_claim_files: BTreeMap::new(),
                workload_identity: self.workload_identity.clone(),
                provisioning_evidence: provisioning_evidence.clone(),
                child_env: self.child_env,
            },
            runtime_descriptor: SandboxRuntimeDescriptor {
                boundary_id: self.boundary_id,
                generation: self.generation,
                session_id: self.session_id,
                workload_identity: self.workload_identity,
                transport: SandboxTransport::RuntimeInitiatedUnix {
                    socket_path: self.control_socket,
                },
                tls: self.supervisor_tls,
                host_gateway_ip: self.host_gateway_ip,
                resource_claims,
                provisioning_evidence,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let session_id = openshell_core::SandboxSessionId::new();
        let tls =
            openshell_sandbox_backend::boundary_protocol::generate_sandbox_tls_material(session_id)
                .unwrap();
        let provisioned = DockerBoundarySpec {
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
        .unwrap();

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
            provisioned.boundary_config.provisioning_evidence,
            provisioned.runtime_descriptor.provisioning_evidence
        );
        assert!(
            provisioned
                .runtime_descriptor
                .provisioning_evidence
                .validate("generation-1")
                .is_ok()
        );
    }

    #[test]
    fn state_round_trips_and_regenerates_the_same_documents() {
        let session_id = openshell_core::SandboxSessionId::new();
        let tls =
            openshell_sandbox_backend::boundary_protocol::generate_sandbox_tls_material(session_id)
                .unwrap();
        let spec = || DockerBoundarySpec {
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
                server_name: tls.server_name.clone(),
                trust_anchor_pem: tls.trust_anchor_pem.clone(),
            },
            host_gateway_ip: Some(IpAddr::from([127, 0, 0, 1])),
            workload_identity: ResolvedWorkloadIdentity::new(
                1000,
                1000,
                vec![2000],
                "image".to_string(),
                "sha256:image".to_string(),
            )
            .unwrap(),
            child_env: HashMap::from([("PATH".to_string(), "/bin".to_string())]),
        };
        let state = DockerBoundaryState::from_spec(&spec());
        let stored: DockerBoundaryState =
            serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
        assert_eq!(stored, state);
        let direct = spec().provision().unwrap();
        let regenerated = stored.provision().unwrap();
        assert_eq!(
            serde_json::to_value(&regenerated.boundary_config).unwrap(),
            serde_json::to_value(&direct.boundary_config).unwrap()
        );
        assert_eq!(regenerated.runtime_descriptor, direct.runtime_descriptor);
    }

    #[test]
    fn state_with_an_invalid_identity_does_not_provision() {
        let mut state = DockerBoundaryState::from_spec(&spec_for_identity());
        state.workload_identity.uid = 0;
        assert!(state.provision().is_err());
    }

    fn spec_for_identity() -> DockerBoundarySpec {
        let session_id = openshell_core::SandboxSessionId::new();
        DockerBoundarySpec {
            boundary_id: "sandbox-1".to_string(),
            generation: "generation-1".to_string(),
            session_id,
            session_rotation: openshell_core::jwt::SessionRotation::new(1).unwrap(),
            auth_epoch: openshell_core::jwt::CredentialEpoch::new(1).unwrap(),
            gateway_id: "gateway-1".to_string(),
            verification_keys: Vec::new(),
            container_id: "c".to_string(),
            image_identity: "i".to_string(),
            gpu_requested: false,
            listener_socket: PathBuf::from("/s"),
            control_socket: PathBuf::from("/s"),
            sandbox_tls: SandboxTlsServerConfig {
                certificate_chain_path: PathBuf::from("/c"),
                private_key_path: PathBuf::from("/k"),
            },
            supervisor_tls: SandboxTlsClientConfig {
                server_name: "n".to_string(),
                trust_anchor_pem: "a".to_string(),
            },
            host_gateway_ip: None,
            workload_identity: ResolvedWorkloadIdentity::new(
                1000,
                1000,
                Vec::new(),
                "image".to_string(),
                "d".to_string(),
            )
            .unwrap(),
            child_env: HashMap::new(),
        }
    }
}
