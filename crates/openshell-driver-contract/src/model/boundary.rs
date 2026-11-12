// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The documents a compute driver hands to the supervisor and the sandbox
//! boundary: the runtime descriptor, the boundary bootstrap configuration, and
//! the transport, listener and TLS types they contain.

use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::BUILTIN_BACKEND_NAME;
use super::identity::{
    BackendDescriptor, BackendError, ProvisioningEvidence, ResolvedWorkloadIdentity,
};
use super::sandbox_session::SandboxSessionId;

/// Shortest accepted route handle, in bytes.
pub const MIN_ROUTE_HANDLE_LEN: usize = 16;
/// Longest accepted route handle, in bytes.
pub const MAX_ROUTE_HANDLE_LEN: usize = 64;

/// Generate a fresh opaque route handle for one runtime generation.
#[must_use]
pub fn new_route_handle() -> String {
    format!("rt-{}", uuid::Uuid::new_v4().simple())
}

/// Validate an opaque route handle: 16 to 64 lowercase ASCII letters, digits,
/// or hyphens.
pub fn validate_route_handle(handle: &str) -> Result<(), BackendError> {
    let valid = (MIN_ROUTE_HANDLE_LEN..=MAX_ROUTE_HANDLE_LEN).contains(&handle.len())
        && handle
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if valid {
        Ok(())
    } else {
        Err(BackendError::Descriptor(
            "runtime route handle must be 16 to 64 lowercase letters, digits, or hyphens"
                .to_string(),
        ))
    }
}

/// Backend-owned transport for a driver-provisioned runtime. The serialized
/// variants preserve existing runtime descriptors independently of operator
/// endpoint registration in core.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SandboxTransport {
    Unix {
        socket_path: PathBuf,
    },
    Tcp {
        /// Logical HTTP authority used for routing.
        authority: String,
        /// Concrete connection candidates pinned by the operator or driver.
        addresses: Vec<std::net::SocketAddr>,
    },
    Vsock {
        guest_cid: u32,
        port: u32,
    },
    /// The supervisor accepts a connection from its sandbox runtime. TLS and
    /// gRPC roles stay unchanged.
    RuntimeInitiatedTcp {
        authority: String,
        listen_address: std::net::SocketAddr,
    },
    RuntimeInitiatedUnix {
        socket_path: PathBuf,
    },
    RuntimeInitiatedVsock {
        guest_cid: u32,
        port: u32,
    },
    /// The runtime dials a supervisor shared by several sandbox instances and
    /// names this instance's opaque route handle before the pinned TLS
    /// handshake.
    /// Only a host that owns the shared listener can serve this transport.
    RuntimeInitiatedRouted {
        authority: String,
        route: String,
    },
}

impl SandboxTransport {
    pub fn validate(&self) -> Result<(), &'static str> {
        let valid = match self {
            Self::Unix { socket_path } | Self::RuntimeInitiatedUnix { socket_path } => {
                super::paths::is_posix_absolute(socket_path)
            }
            Self::Tcp {
                authority,
                addresses,
            } => {
                !authority.is_empty()
                    && !addresses.is_empty()
                    && addresses
                        .iter()
                        .all(|address| address.port() != 0 && !address.ip().is_unspecified())
            }
            Self::RuntimeInitiatedTcp {
                authority,
                listen_address,
            } => !authority.is_empty() && listen_address.port() != 0,
            Self::Vsock { guest_cid, port } | Self::RuntimeInitiatedVsock { guest_cid, port } => {
                *guest_cid >= 3 && *guest_cid != u32::MAX && *port != 0 && *port != u32::MAX
            }
            Self::RuntimeInitiatedRouted { authority, route } => {
                !authority.is_empty() && validate_route_handle(route).is_ok()
            }
        };
        if valid {
            Ok(())
        } else {
            Err("invalid boundary control transport endpoint")
        }
    }
}

/// Supervisor-side, generation-pinned TLS server authentication.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxTlsClientConfig {
    pub server_name: String,
    pub trust_anchor_pem: String,
}

impl fmt::Debug for SandboxTlsClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SandboxTlsClientConfig")
            .field("server_name", &self.server_name)
            .field("trust_anchor_pem", &"<redacted>")
            .finish()
    }
}

/// Sandbox-side TLS server files staged by the compute driver.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxTlsServerConfig {
    pub certificate_chain_path: PathBuf,
    pub private_key_path: PathBuf,
}

/// Fresh, server-only TLS material for one sandbox session.
#[derive(Clone)]
pub struct SandboxTlsMaterial {
    pub server_name: String,
    pub trust_anchor_pem: String,
    pub certificate_chain_pem: String,
    pub private_key_pem: String,
}

impl fmt::Debug for SandboxTlsMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SandboxTlsMaterial")
            .field("server_name", &self.server_name)
            .field("trust_anchor_pem", &"<redacted>")
            .field("certificate_chain_pem", &"<redacted>")
            .field("private_key_pem", &"<redacted>")
            .finish()
    }
}

/// Boundary-side listener provisioned by a compute driver.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum BoundaryListener {
    /// TLS over a private Unix socket shared with the host supervisor.
    Unix {
        socket_path: PathBuf,
        tls: SandboxTlsServerConfig,
    },
    /// TLS over TCP. An unspecified IP is valid for the sandbox bind.
    TlsTcp {
        address: std::net::SocketAddr,
        tls: SandboxTlsServerConfig,
    },
    /// TLS over guest `AF_VSOCK`.
    Vsock {
        control_port: u32,
        tls: SandboxTlsServerConfig,
    },
    /// The boundary dials the supervisor's listener and serves TLS and gRPC
    /// over that outbound connection. Only driver-resolved addresses are used.
    RuntimeInitiatedTlsTcp {
        /// Stable logical Service authority, for diagnostics.
        authority: String,
        /// Driver-resolved supervisor endpoints, tried in order.
        addresses: Vec<std::net::SocketAddr>,
        tls: SandboxTlsServerConfig,
        /// Route handle sent before TLS to a supervisor shared by several
        /// sandbox instances. Absent for a dedicated supervisor.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        route: Option<String>,
    },
    /// Dial the supervisor over the driver's protected shared Unix socket.
    RuntimeInitiatedUnix {
        socket_path: PathBuf,
        tls: SandboxTlsServerConfig,
    },
    /// Dial the host supervisor through the VM's vsock device.
    RuntimeInitiatedVsock {
        host_port: u32,
        tls: SandboxTlsServerConfig,
    },
}

/// Public verification key staged in the sandbox's immutable auth bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayVerificationKey {
    pub key_id: String,
    pub public_key_pem: String,
}

/// Protected runtime descriptor consumed by `openshell-supervisor`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxRuntimeDescriptor {
    /// Stable identity of the boundary, normally the sandbox ID.
    pub boundary_id: String,
    /// Immutable driver-owned workload generation.
    pub generation: String,
    /// Fresh gateway-issued identity for this exact launch.
    pub session_id: SandboxSessionId,
    /// Immutable numeric identity already applied to the sandbox workload.
    pub workload_identity: ResolvedWorkloadIdentity,
    /// Driver-provisioned byte-stream endpoint.
    pub transport: SandboxTransport,
    /// Per-generation pinned TLS server identity.
    pub tls: SandboxTlsClientConfig,
    /// Trusted dial target for well-known host-gateway aliases, when the
    /// network supervisor cannot use the boundary's resolver view.
    #[serde(default)]
    pub host_gateway_ip: Option<std::net::IpAddr>,
    /// Driver-specific immutable resource coordinates bound at attach (for
    /// example pod UID, VM generation, or container ID).
    #[serde(default)]
    pub resource_claims: std::collections::BTreeMap<String, String>,
    /// Backend-neutral projection of the validated outer network fence.
    pub provisioning_evidence: ProvisioningEvidence,
}

impl fmt::Debug for SandboxRuntimeDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SandboxRuntimeDescriptor")
            .field("boundary_id", &self.boundary_id)
            .field("generation", &self.generation)
            .field("session_id", &self.session_id)
            .field("transport", &self.transport)
            .field("tls", &self.tls)
            .field("host_gateway_ip", &self.host_gateway_ip)
            .field("resource_claims", &self.resource_claims)
            .field("provisioning_evidence", &self.provisioning_evidence)
            .finish()
    }
}

impl SandboxRuntimeDescriptor {
    /// Encode this runtime configuration for the `openshell-sandbox` backend.
    pub fn backend_descriptor(&self) -> Result<BackendDescriptor, BackendError> {
        let payload = serde_json::to_vec(self).map_err(|error| {
            BackendError::Descriptor(format!("encode runtime descriptor: {error}"))
        })?;
        Ok(BackendDescriptor {
            backend_name: BUILTIN_BACKEND_NAME.to_string(),
            payload,
        })
    }
}

/// Protected bootstrap configuration consumed by `openshell-sandbox`.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryConfig {
    /// Stable identity expected in every authenticated request.
    pub boundary_id: String,
    /// Immutable driver-owned workload generation.
    pub generation: String,
    /// Fresh gateway-issued identity for this exact launch.
    pub session_id: SandboxSessionId,
    /// Monotonic signed supervisor replacement within this generation.
    pub session_rotation: super::session_values::SessionRotation,
    /// Durable authorization epoch required in every Sandbox Protocol JWT.
    pub auth_epoch: super::session_values::CredentialEpoch,
    /// Gateway identity expected in Sandbox Protocol JWTs.
    pub gateway_id: String,
    /// Immutable current and staged-next gateway verification keys.
    pub verification_keys: Vec<GatewayVerificationKey>,
    /// Driver-provisioned listener.
    pub listener: BoundaryListener,
    /// Immutable coordinates the boundary requires from the control-side
    /// runtime descriptor before accepting attachment.
    #[serde(default)]
    pub resource_claims: std::collections::BTreeMap<String, String>,
    /// Driver-provisioned, read-only runtime evidence for resource claims.
    ///
    /// Each entry maps a claim key to an absolute file whose trimmed contents
    /// must equal the corresponding value in `resource_claims` before the
    /// boundary opens its listener. Kubernetes uses this to bind a one-use
    /// bootstrap bundle to the admitted workload Pod UID exposed by the
    /// Downward API. Other drivers may leave the map empty.
    #[serde(default)]
    pub resource_claim_files: std::collections::BTreeMap<String, PathBuf>,
    /// Exact identity already applied by the runtime to the sandbox process.
    pub workload_identity: ResolvedWorkloadIdentity,
    /// Backend-neutral projection of the validated outer network fence.
    pub provisioning_evidence: ProvisioningEvidence,
    /// Driver-resolved environment exposed only to workload processes.
    #[serde(default)]
    pub child_env: std::collections::HashMap<String, String>,
}

impl fmt::Debug for BoundaryConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundaryConfig")
            .field("boundary_id", &self.boundary_id)
            .field("generation", &self.generation)
            .field("session_id", &self.session_id)
            .field("session_rotation", &self.session_rotation)
            .field("auth_epoch", &self.auth_epoch)
            .field("gateway_id", &self.gateway_id)
            .field(
                "verification_key_ids",
                &self
                    .verification_keys
                    .iter()
                    .map(|key| key.key_id.as_str())
                    .collect::<Vec<_>>(),
            )
            .field("listener", &self.listener)
            .field("resource_claims", &self.resource_claims)
            .field("resource_claim_files", &self.resource_claim_files)
            .field("workload_identity", &self.workload_identity)
            .field("provisioning_evidence", &self.provisioning_evidence)
            .field("child_env_keys", &self.child_env.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl BoundaryConfig {
    /// Serialize the protected driver-owned boundary configuration.
    pub fn encode(&self) -> Result<Vec<u8>, BackendError> {
        serde_json::to_vec(self)
            .map_err(|error| BackendError::Descriptor(format!("encode boundary config: {error}")))
    }
}
