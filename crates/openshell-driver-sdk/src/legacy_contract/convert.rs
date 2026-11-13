// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Conversions between the legacy Rust documents and the messages of
//! `sandbox_runtime.proto`.
//!
//! A driver that writes both formats builds the legacy value as it does today
//! and converts it with `From`; a reader of the new format converts back with
//! `TryFrom`, which applies the validation the legacy readers apply later. The
//! conversions are exact: a value converted to a message and back is equal to
//! the original.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

use super::boundary::{
    BoundaryConfig, BoundaryListener, GatewayVerificationKey, SandboxRuntimeDescriptor,
    SandboxTlsClientConfig, SandboxTlsServerConfig, SandboxTransport,
};
use super::identity::{ProvisioningEvidence, ResolvedWorkloadIdentity, Sha256Digest};
use crate::jwt::{CredentialEpoch, SessionRotation};
use crate::proto::compute::v1 as compute;
use crate::proto::sandbox_runtime::v1 as pb;
use crate::sandbox_session::SandboxSessionId;

/// The contract version these conversions implement.
pub const CONTRACT_VERSION: &str = "1.0";

/// Why a message is not a valid legacy document. The text never quotes field
/// values, which include credentials.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ContractConversionError(String);

impl ContractConversionError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

type Result<T> = std::result::Result<T, ContractConversionError>;

/// Accept an absent version, or a version this implementation reads.
fn check_version(version: &str, required: bool) -> Result<()> {
    if version.is_empty() {
        return if required {
            Err(ContractConversionError::new("contract_version is required"))
        } else {
            Ok(())
        };
    }
    let mut parts = version.split('.');
    let supported = parts.next() == Some("1")
        && parts.next().is_some_and(|minor| minor == "0")
        && parts.next().is_none();
    if supported {
        Ok(())
    } else {
        Err(ContractConversionError::new(
            "unsupported contract_version; this reader implements 1.0",
        ))
    }
}

fn socket_address(value: &str) -> Result<SocketAddr> {
    SocketAddr::from_str(value)
        .map_err(|_| ContractConversionError::new("an address is not a socket address"))
}

fn path_string(path: &std::path::Path) -> String {
    path.to_string_lossy().into_owned()
}

// ---------------------------------------------------------------------------
// Endpoints, transports and listeners
// ---------------------------------------------------------------------------

fn unix_endpoint(path: &std::path::Path) -> pb::endpoint::Kind {
    pb::endpoint::Kind::Unix(pb::UnixEndpoint {
        socket_path: path_string(path),
    })
}

fn tcp_endpoint(authority: &str, addresses: Vec<String>) -> pb::endpoint::Kind {
    pb::endpoint::Kind::Tcp(pb::TcpEndpoint {
        authority: authority.to_string(),
        addresses,
    })
}

fn vsock_endpoint(cid: Option<u32>, port: u32) -> pb::endpoint::Kind {
    pb::endpoint::Kind::Vsock(pb::VsockEndpoint { cid, port })
}

fn initiator(value: i32) -> Result<pb::ConnectionInitiator> {
    match pb::ConnectionInitiator::try_from(value) {
        Ok(kind @ (pb::ConnectionInitiator::Supervisor | pb::ConnectionInitiator::Runtime)) => {
            Ok(kind)
        }
        _ => Err(ContractConversionError::new(
            "initiator must be SUPERVISOR or RUNTIME",
        )),
    }
}

fn endpoint_kind(endpoint: Option<pb::Endpoint>) -> Result<pb::endpoint::Kind> {
    endpoint
        .and_then(|endpoint| endpoint.kind)
        .ok_or_else(|| ContractConversionError::new("an endpoint is required"))
}

fn required_cid(cid: Option<u32>) -> Result<u32> {
    cid.ok_or_else(|| ContractConversionError::new("a vsock endpoint requires a cid here"))
}

impl From<&SandboxTransport> for pb::SandboxTransport {
    fn from(transport: &SandboxTransport) -> Self {
        use pb::ConnectionInitiator::{Runtime, Supervisor};
        let (who, kind, route) = match transport {
            SandboxTransport::Unix { socket_path } => {
                (Supervisor, unix_endpoint(socket_path), None)
            }
            SandboxTransport::Tcp {
                authority,
                addresses,
            } => (
                Supervisor,
                tcp_endpoint(
                    authority,
                    addresses.iter().map(ToString::to_string).collect(),
                ),
                None,
            ),
            SandboxTransport::Vsock { guest_cid, port } => {
                (Supervisor, vsock_endpoint(Some(*guest_cid), *port), None)
            }
            SandboxTransport::RuntimeInitiatedTcp {
                authority,
                listen_address,
            } => (
                Runtime,
                tcp_endpoint(authority, vec![listen_address.to_string()]),
                None,
            ),
            SandboxTransport::RuntimeInitiatedUnix { socket_path } => {
                (Runtime, unix_endpoint(socket_path), None)
            }
            SandboxTransport::RuntimeInitiatedVsock { guest_cid, port } => {
                (Runtime, vsock_endpoint(Some(*guest_cid), *port), None)
            }
            SandboxTransport::RuntimeInitiatedRouted { authority, route } => (
                Runtime,
                tcp_endpoint(authority, Vec::new()),
                Some(route.clone()),
            ),
        };
        Self {
            initiator: who as i32,
            endpoint: Some(pb::Endpoint { kind: Some(kind) }),
            route,
        }
    }
}

impl TryFrom<pb::SandboxTransport> for SandboxTransport {
    type Error = ContractConversionError;

    fn try_from(value: pb::SandboxTransport) -> Result<Self> {
        use pb::ConnectionInitiator::{Runtime, Supervisor};
        use pb::endpoint::Kind;
        let who = initiator(value.initiator)?;
        let kind = endpoint_kind(value.endpoint)?;
        match (who, kind, value.route) {
            (Supervisor, Kind::Unix(unix), None) => Ok(Self::Unix {
                socket_path: PathBuf::from(unix.socket_path),
            }),
            (Supervisor, Kind::Tcp(tcp), None) => Ok(Self::Tcp {
                authority: tcp.authority,
                addresses: tcp
                    .addresses
                    .iter()
                    .map(|address| socket_address(address))
                    .collect::<Result<_>>()?,
            }),
            (Supervisor, Kind::Vsock(vsock), None) => Ok(Self::Vsock {
                guest_cid: required_cid(vsock.cid)?,
                port: vsock.port,
            }),
            (Runtime, Kind::Tcp(tcp), Some(route)) => {
                if !tcp.addresses.is_empty() {
                    return Err(ContractConversionError::new(
                        "a routed transport has no addresses",
                    ));
                }
                Ok(Self::RuntimeInitiatedRouted {
                    authority: tcp.authority,
                    route,
                })
            }
            (Runtime, Kind::Tcp(tcp), None) => {
                let [listen_address] = tcp.addresses.as_slice() else {
                    return Err(ContractConversionError::new(
                        "a runtime-initiated TCP transport has exactly one address",
                    ));
                };
                Ok(Self::RuntimeInitiatedTcp {
                    authority: tcp.authority,
                    listen_address: socket_address(listen_address)?,
                })
            }
            (Runtime, Kind::Unix(unix), None) => Ok(Self::RuntimeInitiatedUnix {
                socket_path: PathBuf::from(unix.socket_path),
            }),
            (Runtime, Kind::Vsock(vsock), None) => Ok(Self::RuntimeInitiatedVsock {
                guest_cid: required_cid(vsock.cid)?,
                port: vsock.port,
            }),
            _ => Err(ContractConversionError::new(
                "this initiator, endpoint and route combination is not a transport",
            )),
        }
    }
}

impl From<&SandboxTlsServerConfig> for pb::TlsServerConfig {
    fn from(tls: &SandboxTlsServerConfig) -> Self {
        Self {
            certificate_chain_path: path_string(&tls.certificate_chain_path),
            private_key_path: path_string(&tls.private_key_path),
        }
    }
}

impl From<pb::TlsServerConfig> for SandboxTlsServerConfig {
    fn from(tls: pb::TlsServerConfig) -> Self {
        Self {
            certificate_chain_path: PathBuf::from(tls.certificate_chain_path),
            private_key_path: PathBuf::from(tls.private_key_path),
        }
    }
}

impl From<&SandboxTlsClientConfig> for pb::TlsClientConfig {
    fn from(tls: &SandboxTlsClientConfig) -> Self {
        Self {
            server_name: tls.server_name.clone(),
            trust_anchor_pem: tls.trust_anchor_pem.clone(),
        }
    }
}

impl From<pb::TlsClientConfig> for SandboxTlsClientConfig {
    fn from(tls: pb::TlsClientConfig) -> Self {
        Self {
            server_name: tls.server_name,
            trust_anchor_pem: tls.trust_anchor_pem,
        }
    }
}

impl From<&GatewayVerificationKey> for pb::GatewayVerificationKey {
    fn from(key: &GatewayVerificationKey) -> Self {
        Self {
            key_id: key.key_id.clone(),
            public_key_pem: key.public_key_pem.clone(),
        }
    }
}

impl From<pb::GatewayVerificationKey> for GatewayVerificationKey {
    fn from(key: pb::GatewayVerificationKey) -> Self {
        Self {
            key_id: key.key_id,
            public_key_pem: key.public_key_pem,
        }
    }
}

impl From<&BoundaryListener> for pb::BoundaryListener {
    fn from(listener: &BoundaryListener) -> Self {
        use pb::ConnectionInitiator::{Runtime, Supervisor};
        let (who, kind, tls, route) = match listener {
            BoundaryListener::Unix { socket_path, tls } => {
                (Supervisor, unix_endpoint(socket_path), tls, None)
            }
            BoundaryListener::TlsTcp { address, tls } => (
                Supervisor,
                tcp_endpoint("", vec![address.to_string()]),
                tls,
                None,
            ),
            BoundaryListener::Vsock { control_port, tls } => {
                (Supervisor, vsock_endpoint(None, *control_port), tls, None)
            }
            BoundaryListener::RuntimeInitiatedTlsTcp {
                authority,
                addresses,
                tls,
                route,
            } => (
                Runtime,
                tcp_endpoint(
                    authority,
                    addresses.iter().map(ToString::to_string).collect(),
                ),
                tls,
                route.clone(),
            ),
            BoundaryListener::RuntimeInitiatedUnix { socket_path, tls } => {
                (Runtime, unix_endpoint(socket_path), tls, None)
            }
            BoundaryListener::RuntimeInitiatedVsock { host_port, tls } => {
                (Runtime, vsock_endpoint(None, *host_port), tls, None)
            }
        };
        Self {
            initiator: who as i32,
            endpoint: Some(pb::Endpoint { kind: Some(kind) }),
            tls: Some(tls.into()),
            route,
        }
    }
}

impl TryFrom<pb::BoundaryListener> for BoundaryListener {
    type Error = ContractConversionError;

    fn try_from(value: pb::BoundaryListener) -> Result<Self> {
        use pb::ConnectionInitiator::{Runtime, Supervisor};
        use pb::endpoint::Kind;
        let who = initiator(value.initiator)?;
        let kind = endpoint_kind(value.endpoint)?;
        let tls: SandboxTlsServerConfig = value
            .tls
            .ok_or_else(|| ContractConversionError::new("a listener requires TLS files"))?
            .into();
        match (who, kind, value.route) {
            (Supervisor, Kind::Unix(unix), None) => Ok(Self::Unix {
                socket_path: PathBuf::from(unix.socket_path),
                tls,
            }),
            (Supervisor, Kind::Tcp(tcp), None) => {
                let [address] = tcp.addresses.as_slice() else {
                    return Err(ContractConversionError::new(
                        "a TCP listener binds exactly one address",
                    ));
                };
                Ok(Self::TlsTcp {
                    address: socket_address(address)?,
                    tls,
                })
            }
            (Supervisor, Kind::Vsock(vsock), None) => Ok(Self::Vsock {
                control_port: vsock.port,
                tls,
            }),
            (Runtime, Kind::Tcp(tcp), route) => Ok(Self::RuntimeInitiatedTlsTcp {
                authority: tcp.authority,
                addresses: tcp
                    .addresses
                    .iter()
                    .map(|address| socket_address(address))
                    .collect::<Result<_>>()?,
                tls,
                route,
            }),
            (Runtime, Kind::Unix(unix), None) => Ok(Self::RuntimeInitiatedUnix {
                socket_path: PathBuf::from(unix.socket_path),
                tls,
            }),
            (Runtime, Kind::Vsock(vsock), None) => Ok(Self::RuntimeInitiatedVsock {
                host_port: vsock.port,
                tls,
            }),
            _ => Err(ContractConversionError::new(
                "this initiator, endpoint and route combination is not a listener",
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Identity, evidence and claims (the messages of compute_driver.proto)
// ---------------------------------------------------------------------------

fn identity_to_pb(identity: &ResolvedWorkloadIdentity) -> compute::ResolvedWorkloadIdentity {
    compute::ResolvedWorkloadIdentity {
        uid: identity.uid,
        gid: identity.gid,
        supplementary_gids: identity.supplementary_gids.clone(),
        source: identity.source.clone(),
        resource_digest: identity.resource_digest.clone(),
    }
}

fn identity_from_pb(
    identity: Option<compute::ResolvedWorkloadIdentity>,
) -> Result<ResolvedWorkloadIdentity> {
    let identity =
        identity.ok_or_else(|| ContractConversionError::new("a workload identity is required"))?;
    ResolvedWorkloadIdentity::new(
        identity.uid,
        identity.gid,
        identity.supplementary_gids,
        identity.source,
        identity.resource_digest,
    )
    .map_err(|error| ContractConversionError::new(error.to_string()))
}

fn fence_to_pb(
    evidence: &ProvisioningEvidence,
    claims: &BTreeMap<String, String>,
) -> compute::DriverFenceEvidence {
    compute::DriverFenceEvidence {
        generation: evidence.generation.clone(),
        evidence_digest: evidence.evidence_digest.to_string(),
        resource_claims: claims
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    }
}

fn fence_from_pb(
    fence: Option<compute::DriverFenceEvidence>,
) -> Result<(ProvisioningEvidence, BTreeMap<String, String>)> {
    let fence = fence.ok_or_else(|| ContractConversionError::new("fence evidence is required"))?;
    let evidence_digest = Sha256Digest::from_str(&fence.evidence_digest)
        .map_err(|_| ContractConversionError::new("evidence_digest is not a SHA-256 digest"))?;
    Ok((
        ProvisioningEvidence {
            generation: fence.generation,
            evidence_digest,
        },
        fence.resource_claims.into_iter().collect(),
    ))
}

fn session_id(value: &str) -> Result<SandboxSessionId> {
    value
        .parse()
        .map_err(|_| ContractConversionError::new("session_id is not a canonical UUID"))
}

// ---------------------------------------------------------------------------
// Runtime descriptor and boundary configuration
// ---------------------------------------------------------------------------

impl From<&SandboxRuntimeDescriptor> for pb::SandboxRuntimeDescriptor {
    fn from(descriptor: &SandboxRuntimeDescriptor) -> Self {
        Self {
            contract_version: CONTRACT_VERSION.to_string(),
            boundary_id: descriptor.boundary_id.clone(),
            generation: descriptor.generation.clone(),
            session_id: descriptor.session_id.to_string(),
            workload_identity: Some(identity_to_pb(&descriptor.workload_identity)),
            transport: Some((&descriptor.transport).into()),
            tls: Some((&descriptor.tls).into()),
            host_gateway_ip: descriptor.host_gateway_ip.map(|ip| ip.to_string()),
            fence_evidence: Some(fence_to_pb(
                &descriptor.provisioning_evidence,
                &descriptor.resource_claims,
            )),
        }
    }
}

impl TryFrom<pb::SandboxRuntimeDescriptor> for SandboxRuntimeDescriptor {
    type Error = ContractConversionError;

    fn try_from(value: pb::SandboxRuntimeDescriptor) -> Result<Self> {
        check_version(&value.contract_version, true)?;
        let (provisioning_evidence, resource_claims) = fence_from_pb(value.fence_evidence)?;
        Ok(Self {
            boundary_id: value.boundary_id,
            generation: value.generation,
            session_id: session_id(&value.session_id)?,
            workload_identity: identity_from_pb(value.workload_identity)?,
            transport: value
                .transport
                .ok_or_else(|| ContractConversionError::new("a transport is required"))?
                .try_into()?,
            tls: value
                .tls
                .ok_or_else(|| ContractConversionError::new("TLS authentication is required"))?
                .into(),
            host_gateway_ip: value
                .host_gateway_ip
                .map(|ip| {
                    IpAddr::from_str(&ip).map_err(|_| {
                        ContractConversionError::new("host_gateway_ip is not an IP address")
                    })
                })
                .transpose()?,
            resource_claims,
            provisioning_evidence,
        })
    }
}

impl From<&BoundaryConfig> for pb::BoundaryConfig {
    fn from(config: &BoundaryConfig) -> Self {
        Self {
            contract_version: CONTRACT_VERSION.to_string(),
            boundary_id: config.boundary_id.clone(),
            generation: config.generation.clone(),
            session_id: config.session_id.to_string(),
            trust: Some(pb::GatewayTrust {
                gateway_id: config.gateway_id.clone(),
                verification_keys: config.verification_keys.iter().map(Into::into).collect(),
                session_rotation: config.session_rotation.get(),
                auth_epoch: config.auth_epoch.get(),
            }),
            listener: Some((&config.listener).into()),
            workload_identity: Some(identity_to_pb(&config.workload_identity)),
            fence_evidence: Some(fence_to_pb(
                &config.provisioning_evidence,
                &config.resource_claims,
            )),
            resource_claim_files: config
                .resource_claim_files
                .iter()
                .map(|(key, path)| (key.clone(), path_string(path)))
                .collect(),
            child_env: config
                .child_env
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        }
    }
}

impl TryFrom<pb::BoundaryConfig> for BoundaryConfig {
    type Error = ContractConversionError;

    fn try_from(value: pb::BoundaryConfig) -> Result<Self> {
        check_version(&value.contract_version, true)?;
        let trust = value
            .trust
            .ok_or_else(|| ContractConversionError::new("gateway trust is required"))?;
        let (provisioning_evidence, resource_claims) = fence_from_pb(value.fence_evidence)?;
        Ok(Self {
            boundary_id: value.boundary_id,
            generation: value.generation,
            session_id: session_id(&value.session_id)?,
            session_rotation: SessionRotation::new(trust.session_rotation)
                .map_err(|_| ContractConversionError::new("session_rotation must be nonzero"))?,
            auth_epoch: CredentialEpoch::new(trust.auth_epoch)
                .map_err(|_| ContractConversionError::new("auth_epoch must be nonzero"))?,
            gateway_id: trust.gateway_id,
            verification_keys: trust
                .verification_keys
                .into_iter()
                .map(Into::into)
                .collect(),
            listener: value
                .listener
                .ok_or_else(|| ContractConversionError::new("a listener is required"))?
                .try_into()?,
            resource_claims,
            resource_claim_files: value
                .resource_claim_files
                .into_iter()
                .map(|(key, path)| (key, PathBuf::from(path)))
                .collect(),
            workload_identity: identity_from_pb(value.workload_identity)?,
            provisioning_evidence,
            child_env: value.child_env.into_iter().collect::<HashMap<_, _>>(),
        })
    }
}
