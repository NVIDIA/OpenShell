// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Opt-in OpenSSL implementation using the process's default library context.
//! Provider configuration belongs to the embedding process, not this backend.

use crate::{
    Capabilities, CryptoBackend, CryptoError, Digest, FipsState, ProtocolBackend, aead::Sealed, pki,
};
use openssl::{
    bn::BigNumContext,
    ec::PointConversionForm,
    hash::{Hasher, MessageDigest},
    nid::Nid,
    pkey::{Id, PKey, Private},
    pkey_ctx::PkeyCtx,
    sign::Signer,
    symm::{Cipher, Crypter, Mode},
};
use zeroize::Zeroizing;

mod jwt;

/// System-OpenSSL backend for explicit [`crate::CryptoContext`] selection.
///
/// Uses OpenSSL's default library context and configuration. It does not load
/// providers, override property queries, or attest a FIPS module. Select before
/// initializing crypto-dependent libraries; changing provider configuration while
/// operations are active is unsupported. The `openssl` feature does not change
/// the AWS-LC default or redirect dependency-owned transports.
#[derive(Debug, Default, Clone, Copy)]
pub struct OpenSsl;

struct Sha256(Hasher);
impl Digest for Sha256 {
    fn update(&mut self, bytes: &[u8]) -> Result<(), CryptoError> {
        self.0.update(bytes).map_err(|_| CryptoError::Operation)
    }
    fn finish(mut self: Box<Self>) -> Result<[u8; 32], CryptoError> {
        self.0
            .finish()
            .map_err(|_| CryptoError::Operation)?
            .as_ref()
            .try_into()
            .map_err(|_| CryptoError::Operation)
    }
}

impl CryptoBackend for OpenSsl {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            backend: "openssl",
            // The library version is not the identity/version of the provider
            // module that performed an operation in the default context.
            provider_version: None,
            fips: FipsState::NotVerified,
            primitives: &["CSPRNG", "SHA-256", "AES-256-GCM"],
            key_algorithms: &["ECDSA-P256-SHA256", "ECDSA-P384-SHA384", "Ed25519", "RSA"],
        }
    }
    fn fill_random(&self, output: &mut [u8]) -> Result<(), CryptoError> {
        for chunk in output.chunks_mut(1024 * 1024) {
            openssl::rand::rand_bytes(chunk).map_err(|_| CryptoError::Random)?;
        }
        Ok(())
    }
    fn sha256_digest(&self) -> Result<Box<dyn Digest>, CryptoError> {
        Ok(Box::new(Sha256(
            Hasher::new(MessageDigest::sha256()).map_err(|_| CryptoError::Operation)?,
        )))
    }
    fn seal(&self, key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Sealed, CryptoError> {
        let mut nonce = [0; 12];
        self.fill_random(&mut nonce)?;
        let mut tag = [0; 16];
        let mut crypter = Crypter::new(Cipher::aes_256_gcm(), Mode::Encrypt, key, Some(&nonce))
            .map_err(|_| CryptoError::Operation)?;
        update_aad(&mut crypter, aad)?;
        // Retain room for the tag after truncating the encryption output.
        let capacity = output_size(plaintext.len())?
            .checked_add(tag.len())
            .ok_or(CryptoError::Operation)?;
        let mut ciphertext = vec![0; capacity];
        let written = update_data(&mut crypter, plaintext, &mut ciphertext)?;
        let final_len = crypter
            .finalize(&mut ciphertext[written..])
            .map_err(|_| CryptoError::Operation)?;
        ciphertext.truncate(written + final_len);
        crypter
            .get_tag(&mut tag)
            .map_err(|_| CryptoError::Operation)?;
        ciphertext.extend_from_slice(&tag);
        Ok(Sealed { nonce, ciphertext })
    }
    fn open(
        &self,
        key: &[u8; 32],
        aad: &[u8],
        nonce: &[u8; 12],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let split = ciphertext
            .len()
            .checked_sub(16)
            .ok_or(CryptoError::Authentication)?;
        let (data, tag) = ciphertext.split_at(split);
        let mut crypter = Crypter::new(Cipher::aes_256_gcm(), Mode::Decrypt, key, Some(nonce))
            .map_err(|_| CryptoError::Operation)?;
        update_aad(&mut crypter, aad)?;
        crypter.set_tag(tag).map_err(|_| CryptoError::Operation)?;
        // EVP writes tentative plaintext before authenticating. Clear it on every
        // failure path and return it only after finalization verifies the tag.
        let mut plaintext = Zeroizing::new(vec![0; output_size(data.len())?]);
        let written = update_data(&mut crypter, data, &mut plaintext)?;
        // EVP finalization has no portable provider-independent classification
        // for bad tags versus late provider failures. Treat all finalization
        // failures as authentication failures; never release tentative plaintext.
        let final_len = crypter
            .finalize(&mut plaintext[written..])
            .map_err(|_| CryptoError::Authentication)?;
        plaintext.truncate(written + final_len);
        Ok(std::mem::take(&mut *plaintext))
    }
}

fn output_size(len: usize) -> Result<usize, CryptoError> {
    len.checked_add(Cipher::aes_256_gcm().block_size())
        .ok_or(CryptoError::Operation)
}

fn update_aad(crypter: &mut Crypter, aad: &[u8]) -> Result<(), CryptoError> {
    for chunk in aad.chunks(1024 * 1024) {
        crypter
            .aad_update(chunk)
            .map_err(|_| CryptoError::Operation)?;
    }
    Ok(())
}

fn update_data(
    crypter: &mut Crypter,
    data: &[u8],
    output: &mut [u8],
) -> Result<usize, CryptoError> {
    let mut written = 0;
    // OpenSSL's update APIs use signed-int lengths. Bound both input and output
    // slices rather than allowing the Rust bindings to panic on large records.
    for chunk in data.chunks(1024 * 1024) {
        let end = written + output_size(chunk.len())?;
        written += crypter
            .update(chunk, &mut output[written..end])
            .map_err(|_| CryptoError::Operation)?;
    }
    Ok(written)
}

fn key_error(_: openssl::error::ErrorStack) -> rcgen::Error {
    rcgen::Error::RemoteKeyError
}

struct Key {
    inner: PKey<Private>,
    algorithm: &'static rcgen::SignatureAlgorithm,
    public: Vec<u8>,
}

impl Key {
    fn wrap(
        inner: PKey<Private>,
        algorithm: &'static rcgen::SignatureAlgorithm,
    ) -> Result<pki::KeyPair, rcgen::Error> {
        let public = match inner.id() {
            Id::ED25519 => inner.raw_public_key().map_err(key_error)?,
            Id::EC => {
                let ec = inner.ec_key().map_err(key_error)?;
                // Decoding a key does not validate its scalar, public point, or
                // their consistency. Reject invalid material before exposing it
                // to certificate construction or signing.
                ec.check_key().map_err(key_error)?;
                let mut ctx = BigNumContext::new().map_err(key_error)?;
                ec.public_key()
                    .to_bytes(ec.group(), PointConversionForm::UNCOMPRESSED, &mut ctx)
                    .map_err(key_error)?
            }
            Id::RSA => {
                // Preserve AWS-LC's 2048–8192-bit range for certificate keys on PEM
                // and PKCS#8 DER imports, before exposing a signing key.
                if !(2048..=8192).contains(&inner.bits()) {
                    return Err(rcgen::Error::CouldNotParseKeyPair);
                }
                let rsa = inner.rsa().map_err(key_error)?;
                // Decoding and size checks do not establish consistency of the
                // private exponent, primes, and CRT parameters. Signing may
                // still succeed through CRT even when the private exponent is wrong.
                if !matches!(rsa.check_key(), Ok(true)) {
                    return Err(rcgen::Error::CouldNotParseKeyPair);
                }
                rsa.public_key_to_der_pkcs1().map_err(key_error)?
            }
            _ => return Err(rcgen::Error::UnsupportedSignatureAlgorithm),
        };
        pki::KeyPair::new(Box::new(Self {
            inner,
            algorithm,
            public,
        }))
    }
    fn import(inner: PKey<Private>) -> Result<pki::KeyPair, rcgen::Error> {
        let algorithm = match inner.id() {
            Id::ED25519 => &rcgen::PKCS_ED25519,
            Id::RSA => &rcgen::PKCS_RSA_SHA256,
            Id::EC => match inner.ec_key().map_err(key_error)?.group().curve_name() {
                Some(Nid::X9_62_PRIME256V1) => &rcgen::PKCS_ECDSA_P256_SHA256,
                Some(Nid::SECP384R1) => &rcgen::PKCS_ECDSA_P384_SHA384,
                _ => return Err(rcgen::Error::UnsupportedSignatureAlgorithm),
            },
            _ => return Err(rcgen::Error::UnsupportedSignatureAlgorithm),
        };
        Self::wrap(inner, algorithm)
    }
}

impl pki::SigningKey for Key {
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        self.algorithm
    }
    fn public_key_raw(&self) -> &[u8] {
        &self.public
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let mut signer = if self.algorithm == &rcgen::PKCS_ED25519 {
            Signer::new_without_digest(&self.inner)
        } else {
            let digest = if self.algorithm == &rcgen::PKCS_ECDSA_P384_SHA384
                || self.algorithm == &rcgen::PKCS_RSA_SHA384
            {
                MessageDigest::sha384()
            } else if self.algorithm == &rcgen::PKCS_RSA_SHA512 {
                MessageDigest::sha512()
            } else if self.algorithm == &rcgen::PKCS_ECDSA_P256_SHA256
                || self.algorithm == &rcgen::PKCS_RSA_SHA256
            {
                MessageDigest::sha256()
            } else {
                return Err(rcgen::Error::UnsupportedSignatureAlgorithm);
            };
            Signer::new(digest, &self.inner)
        }
        .map_err(key_error)?;
        signer.sign_oneshot_to_vec(message).map_err(key_error)
    }
    fn export_pkcs8_der(&self) -> Result<Vec<u8>, rcgen::Error> {
        self.inner.private_key_to_pkcs8().map_err(key_error)
    }
}

impl OpenSsl {
    fn generate(
        algorithm: &'static rcgen::SignatureAlgorithm,
    ) -> Result<PKey<Private>, rcgen::Error> {
        if algorithm == &rcgen::PKCS_ED25519 {
            let mut context = PkeyCtx::new_id(Id::ED25519).map_err(key_error)?;
            context.keygen_init().map_err(key_error)?;
            return context.keygen().map_err(key_error);
        }
        if [
            &rcgen::PKCS_RSA_SHA256,
            &rcgen::PKCS_RSA_SHA384,
            &rcgen::PKCS_RSA_SHA512,
        ]
        .contains(&algorithm)
        {
            let mut context = PkeyCtx::new_id(Id::RSA).map_err(key_error)?;
            context.keygen_init().map_err(key_error)?;
            context.set_rsa_keygen_bits(2048).map_err(key_error)?;
            return context.keygen().map_err(key_error);
        }
        let curve = if algorithm == &rcgen::PKCS_ECDSA_P256_SHA256 {
            Nid::X9_62_PRIME256V1
        } else if algorithm == &rcgen::PKCS_ECDSA_P384_SHA384 {
            Nid::SECP384R1
        } else {
            return Err(rcgen::Error::UnsupportedSignatureAlgorithm);
        };
        let mut context = PkeyCtx::new_id(Id::EC).map_err(key_error)?;
        context.keygen_init().map_err(key_error)?;
        context
            .set_ec_paramgen_curve_nid(curve)
            .map_err(key_error)?;
        context.keygen().map_err(key_error)
    }
}

impl ProtocolBackend for OpenSsl {
    fn tls_provider(&self) -> rustls::crypto::CryptoProvider {
        rustls_openssl::default_provider()
    }
    fn generate_keypair(
        &self,
        algorithm: &'static rcgen::SignatureAlgorithm,
    ) -> Result<pki::KeyPair, rcgen::Error> {
        Key::wrap(Self::generate(algorithm)?, algorithm)
    }
    fn import_keypair_pem(&self, pem: &str) -> Result<pki::KeyPair, rcgen::Error> {
        // The default OpenSSL callback prompts on the controlling terminal.
        // This API has no passphrase contract: reject encrypted input without
        // terminal I/O, including input encrypted with an empty passphrase.
        let mut password_requested = false;
        let key = PKey::private_key_from_pem_callback(pem.as_bytes(), |_| {
            password_requested = true;
            Ok(0)
        });
        if password_requested {
            return Err(rcgen::Error::CouldNotParseKeyPair);
        }
        Key::import(key.map_err(key_error)?)
    }
    fn import_keypair_der(&self, der: &[u8]) -> Result<pki::KeyPair, rcgen::Error> {
        Key::import(PKey::private_key_from_pkcs8(der).map_err(key_error)?)
    }
    fn jwt_provider(&self) -> &'static jsonwebtoken::crypto::CryptoProvider {
        jwt::provider()
    }
}

#[cfg(all(test, feature = "aws-lc"))]
mod tests {
    use super::*;
    use crate::pki::SigningKey;

    #[test]
    fn signing_rejects_an_unmapped_algorithm() {
        // Exercise signing directly: generation/import currently reject P-521,
        // but extending those paths must not silently select SHA-256 here.
        let mut context = PkeyCtx::new_id(Id::EC).unwrap();
        context.keygen_init().unwrap();
        context.set_ec_paramgen_curve_nid(Nid::SECP521R1).unwrap();
        let key = Key {
            inner: context.keygen().unwrap(),
            algorithm: &rcgen::PKCS_ECDSA_P521_SHA512,
            public: Vec::new(),
        };
        assert!(matches!(
            key.sign(b"certificate contents"),
            Err(rcgen::Error::UnsupportedSignatureAlgorithm)
        ));
    }
}
