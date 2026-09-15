// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_crypto::{
    Capabilities, CryptoBackend, CryptoContext, CryptoError, Digest, ProtocolBackend, aead::Sealed,
};

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
    fn sha256_digest(&self) -> Box<dyn Digest> {
        self.0.backend().sha256_digest()
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
    ) -> Result<rcgen::KeyPair, rcgen::Error> {
        Err(rcgen::Error::KeyGenerationUnavailable)
    }
    fn jwt_provider(&self) -> &'static jsonwebtoken::crypto::CryptoProvider {
        self.0.backend().jwt_provider()
    }
}

#[test]
fn selected_context_controls_application_adapters_and_cannot_be_replaced() {
    let context = CryptoContext::new(Box::new(TestBackend(CryptoContext::default())));
    openshell_crypto::install_default_context(context.clone()).unwrap();
    openshell_crypto::install_default_context(context).unwrap();
    assert_eq!(openshell_crypto::random_bytes::<8>().unwrap(), [0x55; 8]);
    assert_eq!(
        openshell_crypto::aead::seal(&[0; 32], b"", b""),
        Err(CryptoError::Random)
    );
    assert!(openshell_crypto::pki::generate_keypair().is_err());
    assert_eq!(
        openshell_crypto::tls::ensure_default_provider()
            .cipher_suites
            .len(),
        1
    );
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
