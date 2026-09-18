// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The sole production backend. Backend-specific imports belong here.

use crate::{Capabilities, CryptoBackend, CryptoError, Digest, FipsState, ProtocolBackend};
use aws_lc_rs::{
    aead, digest,
    rand::{SecureRandom, SystemRandom},
};

pub struct AwsLc;
struct Sha256(digest::Context);

impl Digest for Sha256 {
    fn update(&mut self, bytes: &[u8]) -> Result<(), CryptoError> {
        self.0.update(bytes);
        Ok(())
    }
    fn finish(self: Box<Self>) -> Result<[u8; 32], CryptoError> {
        let mut output = [0; 32];
        output.copy_from_slice(self.0.finish().as_ref());
        Ok(output)
    }
}

impl CryptoBackend for AwsLc {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            backend: "aws-lc",
            provider_version: None,
            fips: FipsState::NotVerified,
            primitives: &["CSPRNG", "SHA-256", "AES-256-GCM"],
            key_algorithms: &[
                "ECDSA-P256-SHA256",
                "ECDSA-P384-SHA384",
                "ECDSA-P521-SHA512",
                "Ed25519",
            ],
        }
    }
    fn fill_random(&self, output: &mut [u8]) -> Result<(), CryptoError> {
        SystemRandom::new()
            .fill(output)
            .map_err(|_| CryptoError::Random)
    }
    fn sha256_digest(&self) -> Result<Box<dyn Digest>, CryptoError> {
        Ok(Box::new(Sha256(digest::Context::new(&digest::SHA256))))
    }
    fn seal(
        &self,
        key: &[u8; 32],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<crate::aead::Sealed, CryptoError> {
        let mut nonce = [0; 12];
        self.fill_random(&mut nonce)?;
        let mut ciphertext = plaintext.to_vec();
        key_handle(key)?
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad),
                &mut ciphertext,
            )
            .map_err(|_| CryptoError::Operation)?;
        Ok(crate::aead::Sealed { nonce, ciphertext })
    }
    fn open(
        &self,
        key: &[u8; 32],
        aad: &[u8],
        nonce: &[u8; 12],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut buffer = ciphertext.to_vec();
        let len = key_handle(key)?
            .open_in_place(
                aead::Nonce::assume_unique_for_key(*nonce),
                aead::Aad::from(aad),
                &mut buffer,
            )
            .map_err(|_| CryptoError::Authentication)?
            .len();
        buffer.truncate(len);
        Ok(buffer)
    }
}

fn key_handle(key: &[u8; 32]) -> Result<aead::LessSafeKey, CryptoError> {
    aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map(aead::LessSafeKey::new)
        .map_err(|_| CryptoError::Operation)
}

impl ProtocolBackend for AwsLc {
    fn tls_provider(&self) -> rustls::crypto::CryptoProvider {
        rustls::crypto::aws_lc_rs::default_provider()
    }
    fn generate_keypair(
        &self,
        algorithm: &'static rcgen::SignatureAlgorithm,
    ) -> Result<crate::pki::KeyPair, rcgen::Error> {
        wrap_key(rcgen::KeyPair::generate_for(algorithm)?)
    }
    fn import_keypair_pem(&self, pem: &str) -> Result<crate::pki::KeyPair, rcgen::Error> {
        wrap_key(rcgen::KeyPair::from_pem(pem)?)
    }
    fn import_keypair_der(&self, der: &[u8]) -> Result<crate::pki::KeyPair, rcgen::Error> {
        wrap_key(rcgen::KeyPair::try_from(der)?)
    }
    fn jwt_provider(&self) -> &'static jsonwebtoken::crypto::CryptoProvider {
        &jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER
    }
}

struct Key {
    material: rcgen::KeyPair,
    signer: Box<dyn rustls::sign::Signer>,
}
fn wrap_key(mut material: rcgen::KeyPair) -> Result<crate::pki::KeyPair, rcgen::Error> {
    use aws_lc_rs::{
        encoding::{AsDer, Pkcs8V1Der},
        signature,
    };
    use rustls::{SignatureScheme, pki_types::PrivateKeyDer};
    // rcgen retains the input encoding on import. Normalize traditional RSA/EC
    // inputs before exposing the facade's PKCS#8 export contract.
    let input = material.serialize_der();
    let normalized = match PrivateKeyDer::try_from(input.as_slice())
        .map_err(|_| rcgen::Error::CouldNotParseKeyPair)?
    {
        PrivateKeyDer::Pkcs1(_) => {
            let key = signature::RsaKeyPair::from_der(&input)
                .map_err(|_| rcgen::Error::CouldNotParseKeyPair)?;
            let encoded: Pkcs8V1Der<'static> =
                key.as_der().map_err(|_| rcgen::Error::RemoteKeyError)?;
            Some(encoded.as_ref().to_vec())
        }
        PrivateKeyDer::Sec1(_) => {
            let algorithm = match material.algorithm() {
                a if a == &rcgen::PKCS_ECDSA_P256_SHA256 => {
                    &signature::ECDSA_P256_SHA256_ASN1_SIGNING
                }
                a if a == &rcgen::PKCS_ECDSA_P384_SHA384 => {
                    &signature::ECDSA_P384_SHA384_ASN1_SIGNING
                }
                a if a == &rcgen::PKCS_ECDSA_P521_SHA512 => {
                    &signature::ECDSA_P521_SHA512_ASN1_SIGNING
                }
                _ => return Err(rcgen::Error::UnsupportedSignatureAlgorithm),
            };
            let key = signature::EcdsaKeyPair::from_private_key_der(algorithm, &input)
                .map_err(|_| rcgen::Error::CouldNotParseKeyPair)?;
            Some(
                key.to_pkcs8v1()
                    .map_err(|_| rcgen::Error::RemoteKeyError)?
                    .as_ref()
                    .to_vec(),
            )
        }
        PrivateKeyDer::Pkcs8(_) => None,
        _ => return Err(rcgen::Error::CouldNotParseKeyPair),
    };
    if let Some(der) = normalized {
        material = rcgen::KeyPair::try_from(der.as_slice())?;
    }
    let scheme = match material.algorithm() {
        a if a == &rcgen::PKCS_ED25519 => SignatureScheme::ED25519,
        a if a == &rcgen::PKCS_ECDSA_P256_SHA256 => SignatureScheme::ECDSA_NISTP256_SHA256,
        a if a == &rcgen::PKCS_ECDSA_P384_SHA384 => SignatureScheme::ECDSA_NISTP384_SHA384,
        a if a == &rcgen::PKCS_ECDSA_P521_SHA512 => SignatureScheme::ECDSA_NISTP521_SHA512,
        a if a == &rcgen::PKCS_RSA_SHA256 => SignatureScheme::RSA_PKCS1_SHA256,
        a if a == &rcgen::PKCS_RSA_SHA384 => SignatureScheme::RSA_PKCS1_SHA384,
        a if a == &rcgen::PKCS_RSA_SHA512 => SignatureScheme::RSA_PKCS1_SHA512,
        _ => return Err(rcgen::Error::UnsupportedSignatureAlgorithm),
    };
    let der = rustls::pki_types::PrivatePkcs8KeyDer::from(material.serialize_der());
    let signer = rustls::crypto::aws_lc_rs::sign::any_supported_type(&der.into())
        .map_err(|_| rcgen::Error::RemoteKeyError)?
        .choose_scheme(&[scheme])
        .ok_or(rcgen::Error::UnsupportedSignatureAlgorithm)?;
    crate::pki::KeyPair::new(Box::new(Key { material, signer }))
}
impl crate::pki::SigningKey for Key {
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        self.material.algorithm()
    }
    fn public_key_raw(&self) -> &[u8] {
        self.material.public_key_raw()
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.signer
            .sign(message)
            .map_err(|_| rcgen::Error::RemoteKeyError)
    }
    fn export_pkcs8_der(&self) -> Result<Vec<u8>, rcgen::Error> {
        Ok(self.material.serialize_der())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::ServerCertVerifier as _;
    #[test]
    fn exported_keys_round_trip_and_sign_certificates() {
        for algorithm in [
            &rcgen::PKCS_ECDSA_P256_SHA256,
            &rcgen::PKCS_ECDSA_P384_SHA384,
            &rcgen::PKCS_ED25519,
            &rcgen::PKCS_ECDSA_P521_SHA512,
        ] {
            let native = rcgen::KeyPair::generate_for(algorithm).unwrap();
            let native_pem = native.serialize_pem();
            let key = wrap_key(native).unwrap();
            assert_eq!(key.serialize_pem().unwrap(), native_pem);
            let der = key.serialize_der().unwrap();
            let pem = key.serialize_pem().unwrap();
            let imported = AwsLc.import_keypair_pem(&pem).unwrap();
            let imported_der = AwsLc.import_keypair_der(&der).unwrap();
            assert_eq!(imported.public_key_der(), key.public_key_der());
            assert_eq!(imported_der.serialize_der().unwrap(), der);
            assert_eq!(imported.serialize_pem().unwrap(), pem);
            let cert = crate::pki::self_signed(
                rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap(),
                &imported,
            )
            .unwrap();
            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert.der().clone()).unwrap();
            let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
                std::sync::Arc::new(roots),
                std::sync::Arc::new(AwsLc.tls_provider()),
            )
            .build()
            .unwrap();
            verifier
                .verify_server_cert(
                    cert.der(),
                    &[],
                    &"localhost".try_into().unwrap(),
                    &[],
                    rustls::pki_types::UnixTime::now(),
                )
                .unwrap();
        }
    }
    #[test]
    fn imports_traditional_ec_keys_and_exports_pkcs8() {
        use aws_lc_rs::{encoding::AsDer, signature};
        let native =
            signature::EcdsaKeyPair::generate(&signature::ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
        let sec1 = native.private_key().as_der().unwrap();
        let encoded = pem::encode(&pem::Pem::new("EC PRIVATE KEY", sec1.as_ref()));
        let imported = AwsLc.import_keypair_pem(&encoded).unwrap();
        let exported = imported.serialize_der().unwrap();
        assert!(matches!(
            rustls::pki_types::PrivateKeyDer::try_from(exported.as_slice()).unwrap(),
            rustls::pki_types::PrivateKeyDer::Pkcs8(_)
        ));
        let reimported = AwsLc.import_keypair_der(&exported).unwrap();
        assert_eq!(imported.public_key_der(), reimported.public_key_der());
    }
    #[test]
    fn encryption_output_matches_the_previous_ciphertext_layout() {
        for plaintext in [b"".as_slice(), b"credential plaintext".as_slice()] {
            let key = [0x11; 32];
            let aad = b"record identity";
            let sealed = crate::aead::seal(&key, aad, plaintext).unwrap();
            // Independent legacy API invocation, using the returned random nonce.
            // This checks encryption bytes, not a round-trip through our decryptor.
            let legacy =
                aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &key).unwrap());
            let mut expected = plaintext.to_vec();
            legacy
                .seal_in_place_append_tag(
                    aead::Nonce::assume_unique_for_key(sealed.nonce),
                    aead::Aad::from(aad),
                    &mut expected,
                )
                .unwrap();
            assert_eq!(sealed.ciphertext, expected);
        }
    }
}
