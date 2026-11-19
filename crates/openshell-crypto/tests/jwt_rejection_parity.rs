// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(all(feature = "aws-lc", feature = "openssl"))]

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, crypto::CryptoProvider};
use openshell_crypto::{CryptoContext, OpenSsl, ProtocolBackend};
use openssl::{hash::MessageDigest, pkey::PKey, rsa::Padding, sign::RsaPssSaltlen};

const MESSAGE: &[u8] = b"header.claims";
const RSA_ALGORITHMS: [Algorithm; 6] = [
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
];

fn providers() -> [(&'static str, &'static CryptoProvider); 2] {
    [
        ("aws-lc", CryptoContext::default().backend().jwt_provider()),
        ("openssl", OpenSsl.jwt_provider()),
    ]
}

// AWS-LC defers some checks until the operation; OpenSSL checks at construction.
// Assert rejection by each provider, not just equality (both accepting is a bug).
fn reject_signing(case: &str, algorithm: Algorithm, key: &EncodingKey) {
    for (name, provider) in providers() {
        let accepted = (provider.signer_factory)(&algorithm, key)
            .is_ok_and(|signer| signer.try_sign(MESSAGE).is_ok());
        assert!(!accepted, "{name} accepted {case} for {algorithm:?}");
    }
}

fn reject_verification(case: &str, algorithm: Algorithm, key: &DecodingKey, signature: &Vec<u8>) {
    for (name, provider) in providers() {
        let accepted = (provider.verifier_factory)(&algorithm, key)
            .is_ok_and(|verifier| verifier.verify(MESSAGE, signature).is_ok());
        assert!(!accepted, "{name} accepted {case} for {algorithm:?}");
    }
}

#[test]
fn malformed_keys_are_rejected_by_both_backends() {
    for der in [&[][..], &[0x30, 0x03, 0x02, 0x01][..]] {
        for algorithm in RSA_ALGORITHMS {
            reject_signing(
                "malformed RSA DER",
                algorithm,
                &EncodingKey::from_rsa_der(der),
            );
            reject_verification(
                "malformed RSA DER",
                algorithm,
                &DecodingKey::from_rsa_der(der),
                &vec![0; 256],
            );
        }
        for algorithm in [Algorithm::ES256, Algorithm::ES384] {
            reject_signing(
                "malformed EC DER",
                algorithm,
                &EncodingKey::from_ec_der(der),
            );
            reject_verification(
                "malformed EC public key",
                algorithm,
                &DecodingKey::from_ec_der(der),
                &vec![0; 64],
            );
        }
        reject_signing(
            "malformed Ed25519 DER",
            Algorithm::EdDSA,
            &EncodingKey::from_ed_der(der),
        );
        reject_verification(
            "malformed Ed25519 public key",
            Algorithm::EdDSA,
            &DecodingKey::from_ed_der(der),
            &vec![0; 64],
        );
    }

    let rsa = openssl::rsa::Rsa::generate(1024).unwrap();
    let encoding = EncodingKey::from_rsa_der(&rsa.private_key_to_der().unwrap());
    let decoding = DecodingKey::from_rsa_der(&rsa.public_key_to_der_pkcs1().unwrap());
    // Use a real signature so failure cannot be attributed only to garbage bytes.
    let native = PKey::from_rsa(rsa).unwrap();
    for (algorithm, digest) in [
        (Algorithm::RS256, MessageDigest::sha256()),
        (Algorithm::RS384, MessageDigest::sha384()),
        (Algorithm::RS512, MessageDigest::sha512()),
    ] {
        let mut signer = openssl::sign::Signer::new(digest, &native).unwrap();
        let signature = signer.sign_oneshot_to_vec(MESSAGE).unwrap();
        reject_verification("undersized RSA key", algorithm, &decoding, &signature);
    }
    for algorithm in RSA_ALGORITHMS {
        reject_signing("undersized RSA key", algorithm, &encoding);
    }

    for (curve, algorithm, wrong_algorithm) in [
        (
            &rcgen::PKCS_ECDSA_P256_SHA256,
            Algorithm::ES256,
            Algorithm::ES384,
        ),
        (
            &rcgen::PKCS_ECDSA_P384_SHA384,
            Algorithm::ES384,
            Algorithm::ES256,
        ),
    ] {
        let key = OpenSsl.generate_keypair(curve).unwrap();
        let encoding = EncodingKey::from_ec_pem(key.serialize_pem().unwrap().as_bytes()).unwrap();
        reject_signing("mismatched EC curve", wrong_algorithm, &encoding);
        let decoding = DecodingKey::from_ec_pem(key.public_key_pem().as_bytes()).unwrap();
        let signer = (OpenSsl.jwt_provider().signer_factory)(&algorithm, &encoding).unwrap();
        let signature = signer.try_sign(MESSAGE).unwrap();
        reject_verification(
            "mismatched EC curve",
            wrong_algorithm,
            &decoding,
            &signature,
        );
    }
}

#[test]
fn malformed_signatures_are_rejected_by_both_backends() {
    for (key_algorithm, algorithms) in [
        (&rcgen::PKCS_RSA_SHA256, &RSA_ALGORITHMS[..]),
        (&rcgen::PKCS_ECDSA_P256_SHA256, &[Algorithm::ES256][..]),
        (&rcgen::PKCS_ECDSA_P384_SHA384, &[Algorithm::ES384][..]),
        (&rcgen::PKCS_ED25519, &[Algorithm::EdDSA][..]),
    ] {
        let key = OpenSsl.generate_keypair(key_algorithm).unwrap();
        let private = key.serialize_pem().unwrap();
        let public = key.public_key_pem();
        let (encoding, decoding) = match algorithms[0] {
            Algorithm::RS256 => (
                EncodingKey::from_rsa_pem(private.as_bytes()).unwrap(),
                DecodingKey::from_rsa_pem(public.as_bytes()).unwrap(),
            ),
            Algorithm::EdDSA => (
                EncodingKey::from_ed_pem(private.as_bytes()).unwrap(),
                DecodingKey::from_ed_pem(public.as_bytes()).unwrap(),
            ),
            _ => (
                EncodingKey::from_ec_pem(private.as_bytes()).unwrap(),
                DecodingKey::from_ec_pem(public.as_bytes()).unwrap(),
            ),
        };
        for &algorithm in algorithms {
            check_signatures(algorithm, &encoding, &decoding);
        }
    }
    for algorithm in [Algorithm::HS256, Algorithm::HS384, Algorithm::HS512] {
        check_signatures(
            algorithm,
            &EncodingKey::from_secret(b"parity-test-key"),
            &DecodingKey::from_secret(b"parity-test-key"),
        );
    }
}

fn check_signatures(algorithm: Algorithm, encoding: &EncodingKey, decoding: &DecodingKey) {
    for (producer, provider) in providers() {
        let signer = (provider.signer_factory)(&algorithm, encoding).unwrap();
        let signature = signer.try_sign(MESSAGE).unwrap();
        // Positive controls ensure the fixtures work with both providers.
        for (consumer, provider) in providers() {
            let verifier = (provider.verifier_factory)(&algorithm, decoding).unwrap();
            assert!(
                verifier.verify(MESSAGE, &signature).is_ok(),
                "{producer} -> {consumer}: {algorithm:?}"
            );
            assert!(verifier.verify(b"changed.claims", &signature).is_err());
        }
        let mut extended = signature.clone();
        extended.push(0);
        let mut tampered = signature.clone();
        tampered[0] ^= 1;
        for (case, invalid) in [
            ("empty signature", vec![]),
            (
                "truncated signature",
                signature[..signature.len() - 1].to_vec(),
            ),
            ("extended signature", extended),
            ("tampered signature", tampered),
        ] {
            reject_verification(case, algorithm, decoding, &invalid);
        }
    }
}

#[test]
fn non_jose_pss_salt_is_rejected_by_both_backends() {
    let key = OpenSsl.generate_keypair(&rcgen::PKCS_RSA_SHA256).unwrap();
    let native = PKey::private_key_from_pkcs8(&key.serialize_der().unwrap()).unwrap();
    let decoding = DecodingKey::from_rsa_pem(key.public_key_pem().as_bytes()).unwrap();
    for (algorithm, digest) in [
        (Algorithm::PS256, MessageDigest::sha256()),
        (Algorithm::PS384, MessageDigest::sha384()),
        (Algorithm::PS512, MessageDigest::sha512()),
    ] {
        let digest_len = i32::try_from(digest.size()).unwrap();
        for salt_len in [0, digest_len - 1, digest_len + 1] {
            let mut signer = openssl::sign::Signer::new(digest, &native).unwrap();
            signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
            signer.set_rsa_mgf1_md(digest).unwrap();
            signer
                .set_rsa_pss_saltlen(RsaPssSaltlen::custom(salt_len))
                .unwrap();
            let signature = signer.sign_oneshot_to_vec(MESSAGE).unwrap();
            reject_verification("non-JOSE PSS salt length", algorithm, &decoding, &signature);
        }
    }
}
