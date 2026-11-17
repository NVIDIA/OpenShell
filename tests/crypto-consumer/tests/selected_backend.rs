// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_crypto::{
    Capabilities, CryptoBackend, CryptoContext, CryptoError, Digest, FipsState, ProtocolBackend,
    aead, pki,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

static TLS_CALLS: AtomicUsize = AtomicUsize::new(0);
static JWT_CALLS: AtomicUsize = AtomicUsize::new(0);

// Test-only host adapter. Unsupported operations fail rather than falling back.
struct ConsumerBackend;
impl CryptoBackend for ConsumerBackend {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            backend: "consumer-test",
            provider_version: None,
            fips: FipsState::NotVerified,
            primitives: &[],
            key_algorithms: &[],
        }
    }
    fn fill_random(&self, _: &mut [u8]) -> Result<(), CryptoError> {
        Err(CryptoError::Random)
    }
    fn sha256_digest(&self) -> Result<Box<dyn Digest>, CryptoError> {
        Err(CryptoError::Operation)
    }
    fn seal(&self, _: &[u8; 32], _: &[u8], _: &[u8]) -> Result<aead::Sealed, CryptoError> {
        Err(CryptoError::Operation)
    }
    fn open(&self, _: &[u8; 32], _: &[u8], _: &[u8; 12], _: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::Authentication)
    }
}
impl ProtocolBackend for ConsumerBackend {
    fn tls_provider(&self) -> rustls::crypto::CryptoProvider {
        TLS_CALLS.fetch_add(1, Ordering::SeqCst);
        rustls::crypto::ring::default_provider()
    }
    fn jwt_provider(&self) -> &'static jsonwebtoken::crypto::CryptoProvider {
        JWT_CALLS.fetch_add(1, Ordering::SeqCst);
        &jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER
    }
    fn generate_keypair(
        &self,
        _: &'static rcgen::SignatureAlgorithm,
    ) -> Result<pki::KeyPair, rcgen::Error> {
        Err(rcgen::Error::RemoteKeyError)
    }
    fn import_keypair_der(&self, _: &[u8]) -> Result<pki::KeyPair, rcgen::Error> {
        Err(rcgen::Error::RemoteKeyError)
    }
    fn import_keypair_pem(&self, _: &str) -> Result<pki::KeyPair, rcgen::Error> {
        Err(rcgen::Error::RemoteKeyError)
    }
}

async fn sdk_tls(trusted: bool) {
    // rcgen must continue using the consumer's Ring implementation.
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![certified.cert.der().clone()], key.into())
    .unwrap();
    server.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        openshell_core::net::set_tcp_nodelay_best_effort(&socket);
        if let Ok(tls) = acceptor.accept(socket).await {
            let mut connection = h2::server::handshake(tls).await.unwrap();
            while connection.accept().await.is_some() {}
        }
    });
    let mut config = openshell_sdk::ClientConfig::new(format!("https://localhost:{port}"));
    config.ca_cert = Some(
        (if trusted {
            certified.cert.pem()
        } else {
            rcgen::generate_simple_self_signed(vec!["localhost".into()])
                .unwrap()
                .cert
                .pem()
        })
        .into_bytes(),
    );
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        openshell_sdk::transport::build_channel(&config),
    )
    .await
    .unwrap();
    assert_eq!(
        result.is_ok(),
        trusted,
        "SDK must enforce the configured CA: {result:?}"
    );
    task.abort();
    let _ = task.await;
}

struct Clock;
impl openshell_core::jwt::JwtClock for Clock {
    fn now_unix_seconds(&self) -> i64 {
        1_900_000_000
    }
}

fn core_jwt() {
    use openshell_core::jwt::*;
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let issuer = SessionJwtIssuer::from_ed25519_pem(
        key.serialize_pem().as_bytes(),
        "current",
        "test",
        Some(DEFAULT_SESSION_TOKEN_TTL),
        Arc::new(Clock),
    )
    .unwrap();
    let verifier = SessionJwtVerifier::new(
        "test",
        SessionTokenProfile::Gateway,
        [SessionVerificationKey {
            key_id: "current".into(),
            public_key_pem: key.public_key_pem().into_bytes(),
        }],
        Arc::new(Clock),
    )
    .unwrap();
    let identity = SandboxRuntimeIdentity {
        sandbox_id: SandboxId::parse("sandbox-a").unwrap(),
        runtime_generation: openshell_core::sandbox_generation::SandboxGenerationId::parse(
            "generation-1",
        )
        .unwrap(),
        auth_epoch: CredentialEpoch::new(1).unwrap(),
    };
    let pair = issuer.mint_pair(&identity).unwrap();
    assert_eq!(
        verifier
            .verify(pair.gateway.token.expose_secret())
            .unwrap()
            .sandbox_id,
        identity.sandbox_id
    );
    assert!(verifier.verify(pair.sandbox.token.expose_secret()).is_err());
    assert!(JWT_CALLS.load(Ordering::SeqCst) > 0);
}

#[tokio::test]
async fn libraries_use_the_consumers_context() {
    assert!(rustls::crypto::CryptoProvider::get_default().is_none());
    openshell_crypto::install_default_context(CryptoContext::new(Box::new(ConsumerBackend)))
        .unwrap();
    // Run SDK TLS first: Rustls must not silently auto-select from Cargo features.
    sdk_tls(true).await;
    assert!(TLS_CALLS.load(Ordering::SeqCst) > 0);
    sdk_tls(false).await;
    let _ = openshell_sdk::oidc::http_client(false);
    core_jwt();
    let policy = openshell_policy::restrictive_default_policy();
    let yaml = openshell_policy::serialize_sandbox_policy(&policy).unwrap();
    openshell_policy::parse_sandbox_policy(&yaml).unwrap();
    assert_eq!(
        openshell_crypto::random_bytes::<8>(),
        Err(CryptoError::Random)
    );
}
