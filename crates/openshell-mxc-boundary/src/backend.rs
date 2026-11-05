// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! MXC registration and audit interpretation over the shared Sandbox Protocol.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use openshell_isolation_interface::contract::{BackendError, BoundaryDuplexStream};
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
pub struct MxcRuntimeBackend;

impl MxcRuntimeBackend {
    /// Compose the concrete RPC client with MXC transport and audit validation.
    pub fn client(
        descriptor: SandboxRuntimeDescriptor,
        ca_file_paths: Arc<Mutex<Option<(PathBuf, PathBuf)>>>,
        provider_credentials: openshell_core::provider_credentials::ProviderCredentialState,
        sandbox_bearer: openshell_core::jwt::SessionBearerTokenSlot,
        connector: Arc<dyn BoundaryTransportConnector>,
    ) -> Result<openshell_sandbox_backend::OpenShellRuntimeBackend, BackendError> {
        let payload = descriptor.backend_descriptor()?.payload;
        Ok(
            openshell_sandbox_backend::OpenShellRuntimeBackend::registered(
                crate::BACKEND_NAME.to_string(),
                descriptor,
                payload,
                ca_file_paths,
                provider_credentials,
                sandbox_bearer,
            )?
            .with_transport(openshell_sandbox_backend::BoundaryTransport::connector(
                connector,
            ))
            .with_audit_validator(|evidence| {
                crate::audit::MxcBoundaryAuditValidator.validate(evidence)
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn reverse_connector_reuses_listener_and_rejects_endpoint_changes() {
        use openshell_isolation_interface::contract::{
            ProvisioningEvidence, ResolvedWorkloadIdentity,
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
            provisioning_evidence: ProvisioningEvidence::from_enforcement_evidence("test", b"test")
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
