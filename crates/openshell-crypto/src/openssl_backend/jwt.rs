// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Compatibility checks around the jsonwebtoken 10 OpenSSL adapter.

use std::sync::OnceLock;

use jsonwebtoken::{
    Algorithm, AlgorithmFamily, DecodingKey, DecodingKeyKind, EncodingKey,
    crypto::{CryptoProvider, JwtSigner, JwtVerifier},
    errors::{ErrorKind, Result},
    jwk::EllipticCurve,
    signature::{Error, Signer, Verifier},
};
use openssl::{
    bn::{BigNum, BigNumContext},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private, Public},
    rsa::{Padding, Rsa},
    sign::{RsaPssSaltlen, Signer as OpenSslSigner, Verifier as OpenSslVerifier},
};

pub(super) fn provider() -> &'static CryptoProvider {
    static PROVIDER: OnceLock<CryptoProvider> = OnceLock::new();
    PROVIDER.get_or_init(|| {
        let mut provider = jsonwebtoken_openssl::DEFAULT_PROVIDER.clone();
        provider.signer_factory = signer;
        provider.verifier_factory = verifier;
        provider.jwk_utils.extract_ec_public_key_coordinates = ec_coordinates;
        provider
    })
}

fn parse_ec_key(algorithm: Algorithm, der: &[u8]) -> Result<PKey<Private>> {
    let expected = match algorithm {
        Algorithm::ES256 => Nid::X9_62_PRIME256V1,
        Algorithm::ES384 => Nid::SECP384R1,
        _ => return Err(ErrorKind::InvalidAlgorithm.into()),
    };
    let key = PKey::private_key_from_der(der).map_err(|_| ErrorKind::InvalidEcdsaKey)?;
    let ec = key.ec_key().map_err(|_| ErrorKind::InvalidEcdsaKey)?;
    if ec.group().curve_name() != Some(expected) {
        return Err(ErrorKind::InvalidEcdsaKey.into());
    }
    ec.check_key().map_err(|_| ErrorKind::InvalidEcdsaKey)?;
    Ok(key)
}

// Signature required by jsonwebtoken's provider factory.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn signer(algorithm: &Algorithm, key: &EncodingKey) -> Result<Box<dyn JwtSigner>> {
    if matches!(algorithm, Algorithm::ES256 | Algorithm::ES384) {
        if key.family() != AlgorithmFamily::Ec {
            return Err(ErrorKind::InvalidKeyFormat.into());
        }
        let key = parse_ec_key(*algorithm, key.inner())?;
        let (digest, width) = match algorithm {
            Algorithm::ES256 => (MessageDigest::sha256(), 32),
            Algorithm::ES384 => (MessageDigest::sha384(), 48),
            _ => return Err(ErrorKind::InvalidAlgorithm.into()),
        };
        return Ok(Box::new(EcSigner {
            key,
            algorithm: *algorithm,
            digest,
            width,
        }));
    }
    if let Some((digest, padding)) = rsa_parameters(*algorithm) {
        if key.family() != AlgorithmFamily::Rsa {
            return Err(ErrorKind::InvalidKeyFormat.into());
        }
        let key =
            PKey::private_key_from_der(key.inner()).map_err(|_| ErrorKind::InvalidKeyFormat)?;
        check_rsa_key(&key)?;
        // Public-component checks are insufficient for signing keys. Keep this
        // private-key validation out of the public verifier path.
        if !matches!(key.rsa().and_then(|rsa| rsa.check_key()), Ok(true)) {
            return Err(ErrorKind::InvalidKeyFormat.into());
        }
        return Ok(Box::new(RsaSigner {
            key,
            algorithm: *algorithm,
            digest,
            padding,
        }));
    }
    (jsonwebtoken_openssl::DEFAULT_PROVIDER.signer_factory)(algorithm, key)
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn verifier(algorithm: &Algorithm, key: &DecodingKey) -> Result<Box<dyn JwtVerifier>> {
    if let Some((digest, padding)) = rsa_parameters(*algorithm) {
        let key = rsa_public_key(key)?;
        check_rsa_key(&key)?;
        return Ok(Box::new(RsaVerifier {
            key,
            algorithm: *algorithm,
            digest,
            padding,
        }));
    }
    let inner = (jsonwebtoken_openssl::DEFAULT_PROVIDER.verifier_factory)(algorithm, key)?;
    let expected = match algorithm {
        Algorithm::HS256 => 32,
        Algorithm::HS384 => 48,
        Algorithm::HS512 => 64,
        _ => return Ok(inner),
    };
    Ok(Box::new(HmacVerifier { inner, expected }))
}

fn rsa_public_key(key: &DecodingKey) -> Result<PKey<Public>> {
    if key.family() != AlgorithmFamily::Rsa {
        return Err(ErrorKind::InvalidKeyFormat.into());
    }
    let rsa = match key.kind() {
        DecodingKeyKind::SecretOrDer(der) => Rsa::public_key_from_der_pkcs1(der),
        DecodingKeyKind::RsaModulusExponent { n, e } => Rsa::from_public_components(
            BigNum::from_slice(n).map_err(|_| ErrorKind::InvalidKeyFormat)?,
            BigNum::from_slice(e).map_err(|_| ErrorKind::InvalidKeyFormat)?,
        ),
    }
    .map_err(|_| ErrorKind::InvalidKeyFormat)?;
    PKey::from_rsa(rsa).map_err(|_| ErrorKind::InvalidKeyFormat.into())
}

struct HmacVerifier {
    inner: Box<dyn JwtVerifier>,
    expected: usize,
}

impl Verifier<Vec<u8>> for HmacVerifier {
    fn verify(&self, message: &[u8], signature: &Vec<u8>) -> std::result::Result<(), Error> {
        // The underlying constant-time comparison requires equal lengths.
        // Signature length is public; reject malformed input before comparison.
        if signature.len() != self.expected {
            return Err(Error::new());
        }
        self.inner.verify(message, signature)
    }
}

impl JwtVerifier for HmacVerifier {
    fn algorithm(&self) -> Algorithm {
        self.inner.algorithm()
    }
}

fn rsa_parameters(algorithm: Algorithm) -> Option<(MessageDigest, Padding)> {
    match algorithm {
        Algorithm::RS256 => Some((MessageDigest::sha256(), Padding::PKCS1)),
        Algorithm::RS384 => Some((MessageDigest::sha384(), Padding::PKCS1)),
        Algorithm::RS512 => Some((MessageDigest::sha512(), Padding::PKCS1)),
        Algorithm::PS256 => Some((MessageDigest::sha256(), Padding::PKCS1_PSS)),
        Algorithm::PS384 => Some((MessageDigest::sha384(), Padding::PKCS1_PSS)),
        Algorithm::PS512 => Some((MessageDigest::sha512(), Padding::PKCS1_PSS)),
        _ => None,
    }
}

fn check_rsa_key<T: openssl::pkey::HasPublic>(key: &PKey<T>) -> Result<()> {
    if key.id() != openssl::pkey::Id::RSA || !(2048..=8192).contains(&key.bits()) {
        return Err(ErrorKind::InvalidKeyFormat.into());
    }
    let rsa = key.rsa().map_err(|_| ErrorKind::InvalidKeyFormat)?;
    // Match AWS-LC's signature-key bounds: a positive odd modulus and an odd
    // public exponent greater than one, at most 33 bits. OpenSSL's component
    // constructors only assemble a key; they do not enforce these constraints.
    if rsa.n().is_negative()
        || !rsa.n().is_odd()
        || rsa.e().is_negative()
        || !rsa.e().is_odd()
        || !(2..=33).contains(&rsa.e().num_bits())
    {
        return Err(ErrorKind::InvalidKeyFormat.into());
    }
    Ok(())
}

struct RsaSigner {
    key: PKey<Private>,
    algorithm: Algorithm,
    digest: MessageDigest,
    padding: Padding,
}

impl Signer<Vec<u8>> for RsaSigner {
    fn try_sign(&self, message: &[u8]) -> std::result::Result<Vec<u8>, Error> {
        let mut signer = OpenSslSigner::new(self.digest, &self.key).map_err(Error::from_source)?;
        signer
            .set_rsa_padding(self.padding)
            .map_err(Error::from_source)?;
        if self.padding == Padding::PKCS1_PSS {
            signer
                .set_rsa_mgf1_md(self.digest)
                .map_err(Error::from_source)?;
            // JOSE requires salt length equal to the digest length (RFC 7518 3.5).
            signer
                .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
                .map_err(Error::from_source)?;
        }
        signer
            .sign_oneshot_to_vec(message)
            .map_err(Error::from_source)
    }
}

impl JwtSigner for RsaSigner {
    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

struct RsaVerifier {
    key: PKey<Public>,
    algorithm: Algorithm,
    digest: MessageDigest,
    padding: Padding,
}

impl Verifier<Vec<u8>> for RsaVerifier {
    fn verify(&self, message: &[u8], signature: &Vec<u8>) -> std::result::Result<(), Error> {
        let mut verifier =
            OpenSslVerifier::new(self.digest, &self.key).map_err(Error::from_source)?;
        verifier
            .set_rsa_padding(self.padding)
            .map_err(Error::from_source)?;
        if self.padding == Padding::PKCS1_PSS {
            verifier
                .set_rsa_mgf1_md(self.digest)
                .map_err(Error::from_source)?;
            verifier
                .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
                .map_err(Error::from_source)?;
        }
        if verifier
            .verify_oneshot(signature, message)
            .map_err(Error::from_source)?
        {
            Ok(())
        } else {
            Err(Error::new())
        }
    }
}

impl JwtVerifier for RsaVerifier {
    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

// Keep the validated key rather than asking the upstream factory to parse it again.
struct EcSigner {
    key: PKey<Private>,
    algorithm: Algorithm,
    digest: MessageDigest,
    width: i32,
}

impl Signer<Vec<u8>> for EcSigner {
    fn try_sign(&self, message: &[u8]) -> std::result::Result<Vec<u8>, Error> {
        let mut signer = OpenSslSigner::new(self.digest, &self.key).map_err(Error::from_source)?;
        let der = signer
            .sign_oneshot_to_vec(message)
            .map_err(Error::from_source)?;
        // JOSE uses fixed-width r || s, whereas OpenSSL returns an ASN.1 sequence.
        let signature = EcdsaSig::from_der(&der).map_err(Error::from_source)?;
        let mut raw = signature
            .r()
            .to_vec_padded(self.width)
            .map_err(Error::from_source)?;
        raw.extend(
            signature
                .s()
                .to_vec_padded(self.width)
                .map_err(Error::from_source)?,
        );
        Ok(raw)
    }
}

impl JwtSigner for EcSigner {
    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

fn ec_coordinates(der: &[u8], algorithm: Algorithm) -> Result<(EllipticCurve, Vec<u8>, Vec<u8>)> {
    let key = parse_ec_key(algorithm, der)?;
    let ec = key.ec_key().map_err(|_| ErrorKind::InvalidEcdsaKey)?;
    let (curve, width) = match algorithm {
        Algorithm::ES256 => (EllipticCurve::P256, 32),
        Algorithm::ES384 => (EllipticCurve::P384, 48),
        _ => return Err(ErrorKind::InvalidAlgorithm.into()),
    };
    let mut x = BigNum::new().map_err(Error::from_source)?;
    let mut y = BigNum::new().map_err(Error::from_source)?;
    let mut context = BigNumContext::new().map_err(Error::from_source)?;
    ec.public_key()
        .affine_coordinates_gfp(ec.group(), &mut x, &mut y, &mut context)
        .map_err(|_| ErrorKind::InvalidEcdsaKey)?;
    // JWK coordinates have fixed width, including leading zeros (RFC 7518 6.2.1).
    Ok((
        curve,
        x.to_vec_padded(width).map_err(Error::from_source)?,
        y.to_vec_padded(width).map_err(Error::from_source)?,
    ))
}
