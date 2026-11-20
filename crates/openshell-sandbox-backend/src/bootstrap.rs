// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Experimental, version-locked boundary bootstrap over a dedicated TLS channel.
//! The supervisor stages one immutable launch; only its bootstrap JWT may fetch it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use openshell_core::jwt::{
    SessionJwtVerifier, SessionTokenProfile, SessionVerificationKey, SystemJwtClock,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::boundary_protocol::BoundaryConfig;

pub const PORT: u16 = 5502;
pub const SERVER_FILE: &str = "boundary-bootstrap-server.json";
pub const TOKEN_ENV: &str = "OPENSHELL_BOUNDARY_BOOTSTRAP_TOKEN";
pub const ADDRESS_ENV: &str = "OPENSHELL_BOUNDARY_BOOTSTRAP_ADDRESS";
pub const CA_ENV: &str = "OPENSHELL_BOUNDARY_BOOTSTRAP_CA";
pub const SERVER_NAME_ENV: &str = "OPENSHELL_BOUNDARY_BOOTSTRAP_SERVER_NAME";
pub const ENV_KEYS: [(&str, &str); 4] = [
    (TOKEN_ENV, "bootstrap-token"),
    (ADDRESS_ENV, "bootstrap-address"),
    (CA_ENV, "bootstrap-ca"),
    (SERVER_NAME_ENV, "bootstrap-server-name"),
];
const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_TOKEN_BYTES: usize = 8192;
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);

/// Trusted supervisor-only input, mounted through its existing Secret.
/// Deliberately has no Debug implementation: it includes workload secrets.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapServerConfig {
    pub listen: SocketAddr,
    pub config: BoundaryConfig,
    pub verification_key: SessionVerificationKey,
    pub token_id: String,
    pub certificate_pem: String,
    pub private_key_pem: String,
}

/// Starts before normal admission, avoiding a dependency on sandbox readiness.
/// Dropping the returned handle stops the listener and all pending exchanges.
pub async fn serve(config: BootstrapServerConfig) -> Result<BootstrapServer, String> {
    let verifier = SessionJwtVerifier::new(
        &config.config.gateway_id,
        SessionTokenProfile::BoundaryBootstrap,
        [config.verification_key],
        Arc::new(SystemJwtClock),
    )
    .map_err(|_| "invalid bootstrap verification key")?;
    let certs = CertificateDer::pem_slice_iter(config.certificate_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "invalid bootstrap TLS certificate")?;
    let key = PrivateKeyDer::from_pem_slice(config.private_key_pem.as_bytes())
        .map_err(|_| "invalid bootstrap TLS key")?;
    let tls = openshell_crypto::tls::try_server_builder()
        .map_err(|_| "bootstrap TLS provider unavailable")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| "invalid bootstrap TLS identity")?;
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .map_err(|error| format!("bind bootstrap listener: {error}"))?;
    let address = listener.local_addr().map_err(|error| error.to_string())?;
    let response = serde_json::to_vec(&config.config).map_err(|_| "encode boundary bootstrap")?;
    if response.len() > MAX_CONFIG_BYTES {
        return Err("boundary bootstrap exceeds 1 MiB".into());
    }
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let task = tokio::spawn(async move {
        // One exchange at a time keeps retries and acknowledgment serialized.
        // Every connection, including its TLS handshake, has a bounded lifetime.
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            openshell_core::net::set_tcp_nodelay_best_effort(&stream);
            let exchange = async {
                let mut stream = acceptor.accept(stream).await.map_err(|_| ())?;
                let token = read_frame(&mut stream, MAX_TOKEN_BYTES)
                    .await
                    .map_err(|_| ())?;
                let token = std::str::from_utf8(&token).map_err(|_| ())?;
                let identity = verifier.verify(token).map_err(|_| ())?;
                if identity.token_id.to_string() != config.token_id
                    || identity.sandbox_id.to_string() != config.config.boundary_id
                    || identity.runtime_generation.to_string() != config.config.generation
                    || identity.auth_epoch != config.config.auth_epoch
                {
                    return Err(());
                }
                write_frame(&mut stream, &response).await.map_err(|_| ())?;
                // A dropped response can be fetched again. Successful receipt
                // retires the listener for the lifetime of this supervisor.
                if stream.read_u8().await.map_err(|_| ())? != 1 {
                    return Err(());
                }
                Ok::<_, ()>(())
            };
            if matches!(
                tokio::time::timeout(EXCHANGE_TIMEOUT, exchange).await,
                Ok(Ok(()))
            ) {
                break;
            }
        }
    });
    Ok(BootstrapServer { address, task })
}

pub struct BootstrapServer {
    pub address: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for BootstrapServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Fetch configuration without writing it to disk. Endpoint, trust and token
/// are protected launch inputs; a bootstrap failure never falls back to a file.
pub async fn fetch(
    address: SocketAddr,
    server_name: String,
    ca_pem: &str,
    token: &str,
) -> Result<BoundaryConfig, String> {
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
        return Err("invalid bootstrap token length".into());
    }
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        roots
            .add(cert.map_err(|_| "invalid bootstrap CA")?)
            .map_err(|_| "invalid bootstrap CA")?;
    }
    if roots.is_empty() {
        return Err("bootstrap CA is empty".into());
    }
    let tls = openshell_crypto::tls::try_client_builder()
        .map_err(|_| "bootstrap TLS provider unavailable")?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls));
    let name = ServerName::try_from(server_name).map_err(|_| "invalid bootstrap server name")?;
    // Covers service/pod startup races; each exchange is independently bounded.
    tokio::time::timeout(Duration::from_mins(2), async {
        loop {
            let exchange = async {
                let stream = openshell_core::net::connect_tcp_nodelay_best_effort(address)
                    .await
                    .map_err(|_| "connect bootstrap supervisor")?;
                let mut stream = connector
                    .connect(name.clone(), stream)
                    .await
                    .map_err(|_| "authenticate bootstrap supervisor")?;
                write_frame(&mut stream, token.as_bytes())
                    .await
                    .map_err(|_| "send bootstrap token")?;
                let response = read_frame(&mut stream, MAX_CONFIG_BYTES)
                    .await
                    .map_err(|_| "receive boundary bootstrap")?;
                let config =
                    serde_json::from_slice(&response).map_err(|_| "decode boundary bootstrap")?;
                stream
                    .write_u8(1)
                    .await
                    .map_err(|_| "acknowledge boundary bootstrap")?;
                stream
                    .flush()
                    .await
                    .map_err(|_| "flush bootstrap acknowledgment")?;
                Ok::<BoundaryConfig, &str>(config)
            };
            if let Ok(Ok(config)) = tokio::time::timeout(EXCHANGE_TIMEOUT, exchange).await {
                return config;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .map_err(|_| "boundary bootstrap timed out".to_string())
}

async fn write_frame(stream: &mut (impl AsyncWrite + Unpin), bytes: &[u8]) -> std::io::Result<()> {
    stream
        .write_u32(u32::try_from(bytes.len()).map_err(std::io::Error::other)?)
        .await?;
    stream.write_all(bytes).await?;
    stream.flush().await
}

async fn read_frame(
    stream: &mut (impl AsyncRead + Unpin),
    limit: usize,
) -> std::io::Result<Vec<u8>> {
    let length = stream.read_u32().await? as usize;
    if length > limit {
        return Err(std::io::Error::other("bootstrap frame exceeds limit"));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary_protocol::{
        BoundaryListener, SandboxTlsServerConfig, generate_sandbox_tls_material,
    };
    use openshell_core::jwt::{
        CredentialEpoch, SandboxId, SandboxRuntimeIdentity, SessionJwtIssuer, SessionRotation,
    };
    use openshell_isolation_interface::contract::{ProvisioningEvidence, ResolvedWorkloadIdentity};

    struct Fixture {
        server: BootstrapServerConfig,
        token: String,
        ca: String,
        name: String,
        issuer: SessionJwtIssuer,
        identity: SandboxRuntimeIdentity,
    }

    fn fixture() -> Fixture {
        let session_id = openshell_core::SandboxSessionId::new();
        let tls = generate_sandbox_tls_material(session_id).unwrap();
        let key = openshell_crypto::pki::generate_jwt_keypair().unwrap();
        let issuer = SessionJwtIssuer::from_ed25519_pem(
            key.serialize_pem().unwrap().as_bytes(),
            "bootstrap",
            "test",
            None,
            Arc::new(SystemJwtClock),
        )
        .unwrap();
        let identity = SandboxRuntimeIdentity {
            sandbox_id: SandboxId::parse("test").unwrap(),
            runtime_generation: openshell_core::sandbox_generation::SandboxGenerationId::parse(
                "generation-1",
            )
            .unwrap(),
            auth_epoch: CredentialEpoch::new(1).unwrap(),
        };
        let token = issuer.mint_boundary_bootstrap(&identity).unwrap();
        Fixture {
            token: token.token.expose_secret().into(),
            ca: tls.trust_anchor_pem,
            name: tls.server_name,
            server: BootstrapServerConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                verification_key: SessionVerificationKey {
                    key_id: "bootstrap".into(),
                    public_key_pem: key.public_key_pem().into_bytes(),
                },
                token_id: token.token_id.to_string(),
                certificate_pem: tls.certificate_chain_pem,
                private_key_pem: tls.private_key_pem,
                config: BoundaryConfig {
                    boundary_id: "test".into(),
                    generation: "generation-1".into(),
                    session_id,
                    session_rotation: SessionRotation::new(1).unwrap(),
                    auth_epoch: identity.auth_epoch,
                    gateway_id: "test".into(),
                    verification_keys: vec![],
                    listener: BoundaryListener::TlsTcp {
                        address: "127.0.0.1:5500".parse().unwrap(),
                        tls: SandboxTlsServerConfig {
                            certificate_chain_path: "/unused/tls.crt".into(),
                            private_key_path: "/unused/tls.key".into(),
                        },
                    },
                    workload_identity: ResolvedWorkloadIdentity::new(
                        1000,
                        1000,
                        vec![],
                        "test".into(),
                        "test".into(),
                    )
                    .unwrap(),
                    provisioning_evidence: ProvisioningEvidence::from_enforcement_evidence(
                        "generation-1",
                        b"test",
                    )
                    .unwrap(),
                    resource_claims: std::collections::BTreeMap::default(),
                    resource_claim_files: std::collections::BTreeMap::default(),
                    child_env: [("BOOTSTRAP_TEST_SECRET".into(), "private-value".into())].into(),
                },
            },
            issuer,
            identity,
        }
    }

    async fn connect(
        address: SocketAddr,
        ca: &str,
        name: &str,
    ) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(ca.as_bytes()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let tls = openshell_crypto::tls::client_builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tokio_rustls::TlsConnector::from(Arc::new(tls))
            .connect(
                ServerName::try_from(name.to_owned()).unwrap(),
                openshell_core::net::connect_tcp_nodelay_best_effort(address)
                    .await
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn bootstrap_retries_lost_response_then_retires_after_ack() {
        let f = fixture();
        let mut server = serve(f.server).await.unwrap();
        let mut stream = connect(server.address, &f.ca, &f.name).await;
        write_frame(&mut stream, f.token.as_bytes()).await.unwrap();
        let response = read_frame(&mut stream, MAX_CONFIG_BYTES).await.unwrap();
        let config: BoundaryConfig = serde_json::from_slice(&response).unwrap();
        assert_eq!(config.child_env["BOOTSTRAP_TEST_SECRET"], "private-value");
        drop(stream); // Simulate a response lost before acknowledgment.
        let config = fetch(server.address, f.name, &f.ca, &f.token)
            .await
            .unwrap();
        assert_eq!(config.generation, "generation-1");
        tokio::time::timeout(Duration::from_secs(2), &mut server.task)
            .await
            .unwrap()
            .unwrap();
        assert!(
            openshell_core::net::connect_tcp_nodelay_best_effort(server.address)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn bootstrap_rejects_normal_bearers_and_other_launches_without_consuming_config() {
        let f = fixture();
        let normal = f.issuer.mint_pair(&f.identity).unwrap();
        let mut other = f.identity.clone();
        other.runtime_generation =
            openshell_core::sandbox_generation::SandboxGenerationId::parse("generation-2").unwrap();
        let other = f.issuer.mint_boundary_bootstrap(&other).unwrap();
        let server = serve(f.server).await.unwrap();
        for token in [
            normal.gateway.token.expose_secret(),
            normal.sandbox.token.expose_secret(),
            other.token.expose_secret(),
            "invalid",
        ] {
            let mut stream = connect(server.address, &f.ca, &f.name).await;
            write_frame(&mut stream, token.as_bytes()).await.unwrap();
            assert!(read_frame(&mut stream, MAX_CONFIG_BYTES).await.is_err());
        }
        assert!(fetch(server.address, f.name, &f.ca, &f.token).await.is_ok());
    }

    #[tokio::test]
    async fn bootstrap_pins_tls_trust_and_bounds_token_lifetime() {
        use openshell_core::jwt::JwtClock;
        struct FutureClock;
        impl JwtClock for FutureClock {
            fn now_unix_seconds(&self) -> i64 {
                SystemJwtClock.now_unix_seconds() + 1800
            }
        }
        let f = fixture();
        let expired = SessionJwtVerifier::new(
            "test",
            SessionTokenProfile::BoundaryBootstrap,
            [f.server.verification_key.clone()],
            Arc::new(FutureClock),
        )
        .unwrap();
        assert!(expired.verify(&f.token).is_err());
        let normal = SessionJwtVerifier::new(
            "test",
            SessionTokenProfile::Sandbox,
            [f.server.verification_key.clone()],
            Arc::new(SystemJwtClock),
        )
        .unwrap();
        assert!(normal.verify(&f.token).is_err());
        let server = serve(f.server).await.unwrap();
        let tls = openshell_crypto::tls::client_builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let socket = openshell_core::net::connect_tcp_nodelay_best_effort(server.address)
            .await
            .unwrap();
        assert!(
            tokio_rustls::TlsConnector::from(Arc::new(tls))
                .connect(ServerName::try_from(f.name.clone()).unwrap(), socket)
                .await
                .is_err()
        );
        assert!(fetch(server.address, f.name, &f.ca, &f.token).await.is_ok());
    }

    #[tokio::test]
    async fn bootstrap_bounds_frame_before_allocation() {
        let (mut writer, mut reader) = tokio::io::duplex(4);
        writer.write_u32(u32::MAX).await.unwrap();
        assert!(read_frame(&mut reader, MAX_CONFIG_BYTES).await.is_err());
    }
}
