// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Operator-owned routes for external isolation backends.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Reserved selection for drivers that launch the built-in sandbox runtime.
pub const BUILTIN_BACKEND_NAME: &str = "openshell-sandbox";

/// Trusted byte-stream endpoint. Generation-specific TLS is supplied by the driver.
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
        addresses: Vec<SocketAddr>,
    },
    Vsock {
        guest_cid: u32,
        port: u32,
    },
}

impl SandboxTransport {
    pub fn validate(&self) -> Result<(), &'static str> {
        let valid = match self {
            Self::Unix { socket_path } => socket_path.is_absolute(),
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
            Self::Vsock { guest_cid, port } => {
                *guest_cid >= 3 && *guest_cid != u32::MAX && *port != 0 && *port != u32::MAX
            }
        };
        if valid {
            Ok(())
        } else {
            Err("invalid boundary control transport endpoint")
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendRegistration {
    pub name: String,
    pub endpoint: SandboxTransport,
}

pub fn validate_backend_name(name: &str) -> Result<(), &'static str> {
    if name == BUILTIN_BACKEND_NAME
        || name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err("invalid or reserved delegated backend name");
    }
    Ok(())
}

/// Validate every entry, including unused registrations.
pub fn validate_registrations(registrations: &[BackendRegistration]) -> Result<(), &'static str> {
    let mut names = BTreeSet::new();
    for registration in registrations {
        validate_backend_name(&registration.name)?;
        if !names.insert(&registration.name) {
            return Err("duplicate isolation backend registration");
        }
        registration.endpoint.validate()?;
    }
    Ok(())
}

impl TryFrom<&BackendRegistration> for crate::proto::compute::v1::IsolationBackendRegistration {
    type Error = &'static str;

    fn try_from(registration: &BackendRegistration) -> Result<Self, Self::Error> {
        use crate::proto::compute::v1::{
            IsolationBackendTcpEndpoint, IsolationBackendVsockEndpoint,
            isolation_backend_registration::Endpoint,
        };
        validate_backend_name(&registration.name)?;
        registration.endpoint.validate()?;
        let endpoint = match &registration.endpoint {
            SandboxTransport::Unix { socket_path } => Endpoint::UnixSocketPath(
                socket_path
                    .to_str()
                    .ok_or("isolation backend Unix path must be UTF-8")?
                    .into(),
            ),
            SandboxTransport::Tcp {
                authority,
                addresses,
            } => Endpoint::Tcp(IsolationBackendTcpEndpoint {
                authority: authority.clone(),
                addresses: addresses.iter().map(ToString::to_string).collect(),
            }),
            SandboxTransport::Vsock { guest_cid, port } => {
                Endpoint::Vsock(IsolationBackendVsockEndpoint {
                    guest_cid: *guest_cid,
                    port: *port,
                })
            }
        };
        Ok(Self {
            name: registration.name.clone(),
            endpoint: Some(endpoint),
        })
    }
}

impl TryFrom<&crate::proto::compute::v1::IsolationBackendRegistration> for BackendRegistration {
    type Error = &'static str;

    fn try_from(
        registration: &crate::proto::compute::v1::IsolationBackendRegistration,
    ) -> Result<Self, Self::Error> {
        use crate::proto::compute::v1::isolation_backend_registration::Endpoint;
        let endpoint = match registration
            .endpoint
            .as_ref()
            .ok_or("isolation backend endpoint is missing")?
        {
            Endpoint::UnixSocketPath(path) => SandboxTransport::Unix {
                socket_path: path.into(),
            },
            Endpoint::Tcp(tcp) => SandboxTransport::Tcp {
                authority: tcp.authority.clone(),
                addresses: tcp
                    .addresses
                    .iter()
                    .map(|address| {
                        address
                            .parse()
                            .map_err(|_| "invalid isolation backend TCP address")
                    })
                    .collect::<Result<_, _>>()?,
            },
            Endpoint::Vsock(vsock) => SandboxTransport::Vsock {
                guest_cid: vsock.guest_cid,
                port: vsock.port,
            },
        };
        validate_backend_name(&registration.name)?;
        endpoint.validate()?;
        Ok(Self {
            name: registration.name.clone(),
            endpoint,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::compute::v1::IsolationBackendRegistration;

    #[test]
    fn operator_routes_survive_compute_protocol_and_supervisor_json() {
        for endpoint in [
            SandboxTransport::Unix {
                socket_path: "/run/backend.sock".into(),
            },
            SandboxTransport::Tcp {
                authority: "backend.example:443".into(),
                addresses: vec![
                    "127.0.0.1:47000".parse().unwrap(),
                    "[::1]:47000".parse().unwrap(),
                ],
            },
            SandboxTransport::Vsock {
                guest_cid: 3,
                port: 47000,
            },
        ] {
            let original = BackendRegistration {
                name: "agent-substrate".into(),
                endpoint,
            };
            let wire = IsolationBackendRegistration::try_from(&original).unwrap();
            let decoded = BackendRegistration::try_from(&wire).unwrap();
            assert_eq!(decoded, original);
            let json = serde_json::to_string(&decoded).unwrap();
            assert_eq!(
                serde_json::from_str::<BackendRegistration>(&json).unwrap(),
                original
            );
        }
    }
}
