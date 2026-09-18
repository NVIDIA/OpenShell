// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "aws-lc")]

use openshell_crypto::{
    Capabilities, CryptoBackend, CryptoContext, CryptoError, Digest, ProtocolBackend, aead::Sealed,
};
use std::sync::{
    LazyLock,
    atomic::{AtomicUsize, Ordering},
};

static JWT_SIGNERS: AtomicUsize = AtomicUsize::new(0);
static JWT_VERIFIERS: AtomicUsize = AtomicUsize::new(0);
static DIGEST_FAILURE: AtomicUsize = AtomicUsize::new(0);
static DIGEST_UPDATES: AtomicUsize = AtomicUsize::new(0);
static DIGEST_FINISHES: AtomicUsize = AtomicUsize::new(0);

struct FailingDigest(usize);
impl Digest for FailingDigest {
    fn update(&mut self, _: &[u8]) -> Result<(), CryptoError> {
        DIGEST_UPDATES.fetch_add(1, Ordering::SeqCst);
        if self.0 == 2 {
            Err(CryptoError::Operation)
        } else {
            Ok(())
        }
    }

    fn finish(self: Box<Self>) -> Result<[u8; 32], CryptoError> {
        DIGEST_FINISHES.fetch_add(1, Ordering::SeqCst);
        assert_eq!(self.0, 3, "must not finalize after an update failure");
        Err(CryptoError::Operation)
    }
}

static JWT_PROVIDER: LazyLock<jsonwebtoken::crypto::CryptoProvider> = LazyLock::new(|| {
    let mut provider = CryptoContext::default().backend().jwt_provider().clone();
    provider.signer_factory = |algorithm, key| {
        JWT_SIGNERS.fetch_add(1, Ordering::SeqCst);
        (CryptoContext::default()
            .backend()
            .jwt_provider()
            .signer_factory)(algorithm, key)
    };
    provider.verifier_factory = |algorithm, key| {
        JWT_VERIFIERS.fetch_add(1, Ordering::SeqCst);
        (CryptoContext::default()
            .backend()
            .jwt_provider()
            .verifier_factory)(algorithm, key)
    };
    provider
});

struct TestBackend(CryptoContext);
impl CryptoBackend for TestBackend {
    fn capabilities(&self) -> Capabilities {
        let mut capabilities = self.0.backend().capabilities();
        capabilities.backend = "test";
        capabilities
    }
    fn fill_random(&self, bytes: &mut [u8]) -> Result<(), CryptoError> {
        bytes.fill(0x55);
        Ok(())
    }
    fn sha256_digest(&self) -> Result<Box<dyn Digest>, CryptoError> {
        match DIGEST_FAILURE.load(Ordering::SeqCst) {
            0 => self.0.backend().sha256_digest(),
            1 => Err(CryptoError::Operation),
            stage => Ok(Box::new(FailingDigest(stage))),
        }
    }
    fn seal(&self, _: &[u8; 32], _: &[u8], _: &[u8]) -> Result<Sealed, CryptoError> {
        Err(CryptoError::Random)
    }
    fn open(&self, _: &[u8; 32], _: &[u8], _: &[u8; 12], _: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::Authentication)
    }
}
impl ProtocolBackend for TestBackend {
    fn tls_provider(&self) -> rustls::crypto::CryptoProvider {
        let mut provider = self.0.backend().tls_provider();
        provider.cipher_suites.truncate(1);
        provider
    }
    fn generate_keypair(
        &self,
        _: &'static rcgen::SignatureAlgorithm,
    ) -> Result<openshell_crypto::pki::KeyPair, rcgen::Error> {
        Err(rcgen::Error::KeyGenerationUnavailable)
    }
    fn import_keypair_pem(&self, _: &str) -> Result<openshell_crypto::pki::KeyPair, rcgen::Error> {
        Err(rcgen::Error::KeyGenerationUnavailable)
    }
    fn import_keypair_der(&self, _: &[u8]) -> Result<openshell_crypto::pki::KeyPair, rcgen::Error> {
        Err(rcgen::Error::KeyGenerationUnavailable)
    }
    fn jwt_provider(&self) -> &'static jsonwebtoken::crypto::CryptoProvider {
        &JWT_PROVIDER
    }
}

#[test]
fn selected_context_controls_application_adapters_and_cannot_be_replaced() {
    // Reproduce dependency initialization before explicit context selection.
    let _ = rustls::ClientConfig::builder();
    let host = rustls::crypto::CryptoProvider::get_default()
        .unwrap()
        .clone();
    let context = CryptoContext::new(Box::new(TestBackend(CryptoContext::default())));
    openshell_crypto::install_default_context(context.clone()).unwrap();
    openshell_crypto::install_default_context(context).unwrap();
    assert_eq!(openshell_crypto::random_bytes::<8>().unwrap(), [0x55; 8]);
    assert_eq!(
        openshell_crypto::aead::seal(&[0; 32], b"", b""),
        Err(CryptoError::Random)
    );
    assert!(openshell_crypto::pki::generate_keypair().is_err());
    // Exercise each fallible stage through the public helper. No failed stage
    // may be retried with the default backend or followed by another operation.
    for (stage, updates, finishes) in [(1, 0, 0), (2, 1, 0), (3, 1, 1)] {
        DIGEST_FAILURE.store(stage, Ordering::SeqCst);
        DIGEST_UPDATES.store(0, Ordering::SeqCst);
        DIGEST_FINISHES.store(0, Ordering::SeqCst);
        assert_eq!(
            openshell_crypto::sha256(b"abc"),
            Err(CryptoError::Operation)
        );
        assert_eq!(DIGEST_UPDATES.load(Ordering::SeqCst), updates);
        assert_eq!(DIGEST_FINISHES.load(Ordering::SeqCst), finishes);
    }
    DIGEST_FAILURE.store(0, Ordering::SeqCst);
    // A plain round trip could pass with the default backend. Instrument both
    // factories to prove that JWT operations use the selected context instead.
    let claims = serde_json::json!({"sub": "sandbox", "exp": 4_000_000_000_u64});
    let token = openshell_crypto::jwt::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(b"test-context-secret"),
    )
    .unwrap();
    assert_eq!(JWT_SIGNERS.load(Ordering::SeqCst), 1);
    let decoded = openshell_crypto::jwt::decode::<serde_json::Value>(
        &token,
        &jsonwebtoken::DecodingKey::from_secret(b"test-context-secret"),
        &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256),
    )
    .unwrap();
    assert_eq!(decoded.claims, claims);
    assert_eq!(JWT_VERIFIERS.load(Ordering::SeqCst), 1);
    assert_eq!(
        openshell_crypto::tls::configuration_provider()
            .cipher_suites
            .len(),
        1
    );
    assert!(std::sync::Arc::ptr_eq(
        openshell_crypto::tls::ensure_default_provider(),
        &host
    ));
    let key = CryptoContext::default()
        .backend()
        .generate_keypair(&rcgen::PKCS_ECDSA_P256_SHA256)
        .unwrap();
    let cert = openshell_crypto::pki::self_signed(
        rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap(),
        &key,
    )
    .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let client = openshell_crypto::tls::client_builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server = openshell_crypto::tls::server_builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der().unwrap()).into(),
        )
        .unwrap();
    assert_eq!(client.crypto_provider().cipher_suites.len(), 1);
    assert_eq!(server.crypto_provider().cipher_suites.len(), 1);
    let suite = client.crypto_provider().cipher_suites[0].suite();
    let mut client =
        rustls::ClientConnection::new(std::sync::Arc::new(client), "localhost".try_into().unwrap())
            .unwrap();
    let mut server = rustls::ServerConnection::new(std::sync::Arc::new(server)).unwrap();
    for _ in 0..10 {
        let mut wire = Vec::new();
        client.write_tls(&mut wire).unwrap();
        server.read_tls(&mut wire.as_slice()).unwrap();
        server.process_new_packets().unwrap();
        wire.clear();
        server.write_tls(&mut wire).unwrap();
        client.read_tls(&mut wire.as_slice()).unwrap();
        client.process_new_packets().unwrap();
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
    }
    assert!(!client.is_handshaking() && !server.is_handshaking());
    assert_eq!(client.negotiated_cipher_suite().unwrap().suite(), suite);
    assert_eq!(
        openshell_crypto::default_context()
            .verify_posture(false)
            .unwrap()
            .backend,
        "test"
    );
    assert_eq!(
        openshell_crypto::install_default_context(CryptoContext::default()),
        Err(CryptoError::ProviderConflict)
    );
}
