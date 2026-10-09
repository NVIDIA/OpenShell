// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! MXC registration and audit interpretation over the shared Sandbox Protocol.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use openshell_isolation_interface::contract::{
    BackendError, BoundBoundary, BoundaryDuplexStream, IsolationBackend, SandboxContext,
    VerifiedBackendDescriptor,
};
use openshell_sandbox_backend::{
    BoundaryTransportConnector,
    boundary_protocol::{SandboxRuntimeDescriptor, SandboxTransport},
};

/// The Windows relay establishes control outward from MXC; preserve that
/// direction without embedding supervision or policy in the compute driver.
#[derive(Debug, Default)]
pub struct MxcReverseTcpConnector {
    listener: tokio::sync::Mutex<Option<Arc<tokio::net::TcpListener>>>,
}

#[async_trait]
impl BoundaryTransportConnector for MxcReverseTcpConnector {
    async fn connect(
        &self,
        descriptor: &SandboxRuntimeDescriptor,
    ) -> Result<BoundaryDuplexStream, BackendError> {
        if descriptor
            .resource_claims
            .get("mxc.control_transport")
            .map(String::as_str)
            != Some("reverse_tcp")
        {
            return Err(BackendError::Descriptor(
                "MXC reverse control provisioning is required".into(),
            ));
        }
        let SandboxTransport::Tcp { addresses, .. } = &descriptor.transport else {
            return Err(BackendError::Descriptor(
                "MXC reverse control requires TCP".into(),
            ));
        };
        let [address] = addresses.as_slice() else {
            return Err(BackendError::Descriptor(
                "MXC reverse control requires one address".into(),
            ));
        };
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err(BackendError::Descriptor(
                "MXC reverse control requires a concrete loopback endpoint".into(),
            ));
        }
        let listener = {
            let mut current = self.listener.lock().await;
            if let Some(listener) = current.as_ref() {
                if listener
                    .local_addr()
                    .map_err(|e| BackendError::Unavailable(e.to_string()))?
                    != *address
                {
                    return Err(BackendError::Descriptor(
                        "MXC reverse control endpoint changed".into(),
                    ));
                }
                listener.clone()
            } else {
                let listener =
                    Arc::new(tokio::net::TcpListener::bind(address).await.map_err(|e| {
                        BackendError::Unavailable(format!("bind MXC reverse control: {e}"))
                    })?);
                *current = Some(listener.clone());
                listener
            }
        };
        let (stream, _) =
            tokio::time::timeout(std::time::Duration::from_secs(30), listener.accept())
                .await
                .map_err(|_| {
                    BackendError::Unavailable("MXC reverse control accept timed out".into())
                })?
                .map_err(|e| {
                    BackendError::Unavailable(format!("accept MXC reverse control: {e}"))
                })?;
        openshell_core::net::set_tcp_nodelay_best_effort(&stream);
        // TLS peer verification and JWT authentication remain shared and mandatory.
        Ok(Box::new(stream))
    }
}

/// The host-side MXC isolation backend. The compute driver owns provisioning;
/// this backend owns attachment and interpretation of Windows confirmation.
#[derive(Debug)]
pub struct MxcRuntimeBackend {
    transport: openshell_sandbox_backend::OpenShellRuntimeBackend,
}

impl MxcRuntimeBackend {
    /// Compose authenticated transport with the MXC-specific evidence validator.
    #[must_use]
    pub fn new(
        ca_file_paths: Arc<Mutex<Option<(PathBuf, PathBuf)>>>,
        provider_credentials: openshell_core::provider_credentials::ProviderCredentialState,
        sandbox_bearer: openshell_core::jwt::SessionBearerTokenSlot,
        connector: Arc<dyn BoundaryTransportConnector>,
    ) -> Self {
        Self {
            transport: openshell_sandbox_backend::OpenShellRuntimeBackend::new(
                ca_file_paths,
                provider_credentials,
                sandbox_bearer,
            )
            .with_audit_validator(Arc::new(crate::audit::MxcBoundaryAuditValidator))
            .with_transport_connector(connector),
        }
    }
}

#[async_trait]
impl IsolationBackend for MxcRuntimeBackend {
    fn backend_name(&self) -> &str {
        crate::BACKEND_NAME
    }

    async fn attach(
        &self,
        descriptor: VerifiedBackendDescriptor,
        sandbox: SandboxContext,
    ) -> Result<Box<dyn BoundBoundary>, BackendError> {
        if descriptor.backend_name() != crate::BACKEND_NAME {
            return Err(BackendError::Descriptor(
                "MXC backend requires MXC admission".into(),
            ));
        }
        // Keep shared validation of session, generation, identity, resource
        // claims, TLS and outer-fence guarantees; only native audit differs.
        self.transport.attach(descriptor, sandbox).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_isolation_interface::contract::{BackendDescriptor, BackendRegistry};

    fn backend() -> Arc<MxcRuntimeBackend> {
        Arc::new(MxcRuntimeBackend::new(
            Arc::new(Mutex::new(None)),
            openshell_core::provider_credentials::ProviderCredentialState::from_environment(
                0,
                std::collections::HashMap::default(),
                std::collections::HashMap::default(),
                std::collections::HashMap::default(),
            ),
            openshell_core::jwt::SessionBearerTokenSlot::empty(),
            Arc::new(MxcReverseTcpConnector::default()),
        ))
    }

    #[test]
    fn registry_requires_exact_mxc_admission_and_never_falls_back() {
        let mut registry = BackendRegistry::new();
        registry.register(backend()).unwrap();
        let descriptor = || BackendDescriptor {
            backend_name: crate::BACKEND_NAME.into(),
            payload: Vec::new(),
        };
        let (selected, verified) = registry.resolve(descriptor(), crate::BACKEND_NAME).unwrap();
        assert_eq!(selected.backend_name(), "openshell-mxc");
        assert_eq!(verified.backend_name(), selected.backend_name());
        assert!(matches!(
            registry.resolve(descriptor(), "openshell-sandbox"),
            Err(BackendError::Descriptor(_))
        ));
        assert!(matches!(
            registry.resolve(
                BackendDescriptor {
                    backend_name: "openshell-sandbox".into(),
                    payload: Vec::new(),
                },
                "openshell-sandbox"
            ),
            Err(BackendError::NotRegistered(_))
        ));
    }

    #[test]
    fn duplicate_mxc_backend_registration_is_rejected() {
        let mut registry = BackendRegistry::new();
        registry.register(backend()).unwrap();
        assert!(matches!(
            registry.register(backend()),
            Err(BackendError::Descriptor(_))
        ));
    }

    #[tokio::test]
    async fn reverse_connector_reuses_listener_and_rejects_endpoint_changes() {
        use openshell_isolation_interface::contract::{
            OuterFenceGuarantees, ResolvedWorkloadIdentity,
        };
        use openshell_sandbox_backend::boundary_protocol::SandboxTlsClientConfig;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        let descriptor = SandboxRuntimeDescriptor {
            boundary_id: "test".into(),
            generation: "test".into(),
            session_id: "550e8400-e29b-41d4-a716-446655440000".parse().unwrap(),
            workload_identity: ResolvedWorkloadIdentity::new(
                1,
                1,
                Vec::new(),
                "test".into(),
                "test".into(),
            )
            .unwrap(),
            transport: SandboxTransport::Tcp {
                authority: address.to_string(),
                addresses: vec![address],
            },
            tls: SandboxTlsClientConfig {
                server_name: "test".into(),
                trust_anchor_pem: "test".into(),
            },
            host_gateway_ip: None,
            resource_claims: std::collections::BTreeMap::from([(
                "mxc.control_transport".into(),
                "reverse_tcp".into(),
            )]),
            outer_fence: OuterFenceGuarantees::from_enforcement_evidence("test", [], b"test")
                .unwrap(),
        };
        let connector = Arc::new(MxcReverseTcpConnector::default());
        for _ in 0..2 {
            let host_connector = connector.clone();
            let host_descriptor = descriptor.clone();
            let host =
                tokio::spawn(
                    async move { host_connector.connect(&host_descriptor).await.unwrap() },
                );
            let mut peer = tokio::time::timeout(std::time::Duration::from_secs(3), async {
                loop {
                    if let Ok(stream) = tokio::net::TcpStream::connect(address).await {
                        break stream;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            let mut stream = host.await.unwrap();
            peer.write_all(b"hello").await.unwrap();
            let mut received = [0; 5];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(&received, b"hello");
        }
        let mut other = descriptor.clone();
        let SandboxTransport::Tcp { addresses, .. } = &mut other.transport else {
            unreachable!()
        };
        addresses[0] = "127.0.0.1:1".parse().unwrap();
        assert!(matches!(
            connector.connect(&other).await,
            Err(BackendError::Descriptor(_))
        ));
        other.resource_claims.clear();
        assert!(matches!(
            connector.connect(&other).await,
            Err(BackendError::Descriptor(_))
        ));
    }
}
