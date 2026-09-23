// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_crypto::{
    Capabilities, CryptoBackend, CryptoContext, CryptoError, Digest, ProtocolBackend, aead, pki,
};
use openshell_sandbox_backend::boundary_protocol::{FrameError, Request, RequestEnvelope};
use std::sync::atomic::{AtomicUsize, Ordering};

static FAILURE: AtomicUsize = AtomicUsize::new(0);
struct Backend(CryptoContext);
struct FailingDigest;
impl Digest for FailingDigest {
    fn update(&mut self, _: &[u8]) -> Result<(), CryptoError> {
        if FAILURE.load(Ordering::SeqCst) == 2 {
            Err(CryptoError::Operation)
        } else {
            Ok(())
        }
    }
    fn finish(self: Box<Self>) -> Result<[u8; 32], CryptoError> {
        assert_eq!(
            FAILURE.load(Ordering::SeqCst),
            3,
            "must not finalize a failed update"
        );
        Err(CryptoError::Operation)
    }
}
impl CryptoBackend for Backend {
    fn capabilities(&self) -> Capabilities {
        self.0.backend().capabilities()
    }
    fn fill_random(&self, bytes: &mut [u8]) -> Result<(), CryptoError> {
        if FAILURE.load(Ordering::SeqCst) == 4 {
            Err(CryptoError::Random)
        } else {
            self.0.backend().fill_random(bytes)
        }
    }
    fn sha256_digest(&self) -> Result<Box<dyn Digest>, CryptoError> {
        match FAILURE.load(Ordering::SeqCst) {
            0 | 4 => self.0.backend().sha256_digest(),
            1 => Err(CryptoError::Operation),
            _ => Ok(Box::new(FailingDigest)),
        }
    }
    fn seal(&self, _: &[u8; 32], _: &[u8], _: &[u8]) -> Result<aead::Sealed, CryptoError> {
        unreachable!()
    }
    fn open(&self, _: &[u8; 32], _: &[u8], _: &[u8; 12], _: &[u8]) -> Result<Vec<u8>, CryptoError> {
        unreachable!()
    }
}
impl ProtocolBackend for Backend {
    fn tls_provider(&self) -> rustls::crypto::CryptoProvider {
        self.0.backend().tls_provider()
    }
    fn jwt_provider(&self) -> &'static jsonwebtoken::crypto::CryptoProvider {
        self.0.backend().jwt_provider()
    }
    fn generate_keypair(
        &self,
        _: &'static rcgen::SignatureAlgorithm,
    ) -> Result<pki::KeyPair, rcgen::Error> {
        unreachable!()
    }
    fn import_keypair_pem(&self, _: &str) -> Result<pki::KeyPair, rcgen::Error> {
        unreachable!()
    }
    fn import_keypair_der(&self, _: &[u8]) -> Result<pki::KeyPair, rcgen::Error> {
        unreachable!()
    }
}

#[test]
fn request_envelope_uses_selected_digest_and_rejects_backend_failures() {
    // Separate executable prevents process-global backend state leaking to other tests.
    openshell_crypto::install_default_context(CryptoContext::new(Box::new(Backend(
        CryptoContext::default(),
    ))))
    .unwrap();
    let request = || Request::Terminate {
        process_id: "test".into(),
    };
    let envelope = RequestEnvelope::new(request()).unwrap();
    assert_eq!(
        envelope.payload_digest,
        "12fa19027b624b79dacb71a241331c6b7a961ae5c8a5084df3559c097cf8ad76"
    );
    for stage in 1..=3 {
        FAILURE.store(stage, Ordering::SeqCst);
        assert!(matches!(
            RequestEnvelope::new(request()),
            Err(FrameError::Crypto(CryptoError::Operation))
        ));
        assert!(matches!(
            envelope.validate_payload_digest(),
            Err(FrameError::Crypto(CryptoError::Operation))
        ));
    }
    FAILURE.store(4, Ordering::SeqCst);
    assert!(matches!(
        RequestEnvelope::new(request()),
        Err(FrameError::Crypto(CryptoError::Random))
    ));
}
