// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "openssl")]

mod common;

use common::{handshake, init_openssl};
#[cfg(feature = "aws-lc")]
use openshell_crypto::CryptoContext;
use openshell_crypto::OpenSsl;
use openshell_crypto::{CryptoBackend, CryptoError, ProtocolBackend, aead, jwt, pki, tls};
use std::io::{Read, Write};

#[test]
fn primitives_and_posture() {
    init_openssl();
    assert_eq!(
        openshell_crypto::sha256(b"abc").unwrap(),
        [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad
        ]
    );
    let mut digest = openshell_crypto::sha256_digest().unwrap();
    digest.update(b"a").unwrap();
    digest.update(b"bc").unwrap();
    assert_eq!(
        digest.finish().unwrap(),
        openshell_crypto::sha256(b"abc").unwrap()
    );
    assert_ne!(
        openshell_crypto::random_bytes::<32>().unwrap(),
        openshell_crypto::random_bytes::<32>().unwrap()
    );
    let context = openshell_crypto::default_context();
    let caps = context.verify_posture(false).unwrap();
    assert_eq!(caps.backend, "openssl");
    assert_eq!(caps.provider_version, None);
    assert_eq!(caps.fips, openshell_crypto::FipsState::NotVerified);
    assert_eq!(
        context.verify_posture(true),
        Err(CryptoError::UnsupportedPosture)
    );
}

#[test]
fn aead_compatibility_and_rejection() {
    init_openssl();
    // NIST AES-256-GCM empty-message vector: ciphertext consists only of the tag.
    let tag = [
        0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73,
        0x8b,
    ];
    assert_eq!(aead::open(&[0; 32], b"", &[0; 12], &tag).unwrap(), b"");
    for plain in [b"".as_slice(), b"credential-value"] {
        let sealed = aead::seal(&[7; 32], b"record-id", plain).unwrap();
        assert_eq!(sealed.ciphertext.len(), plain.len() + 16);
        assert_eq!(
            aead::open(&[7; 32], b"record-id", &sealed.nonce, &sealed.ciphertext).unwrap(),
            plain
        );
        assert_eq!(
            aead::open(&[8; 32], b"record-id", &sealed.nonce, &sealed.ciphertext),
            Err(CryptoError::Authentication)
        );
        assert_eq!(
            aead::open(&[7; 32], b"wrong-id", &sealed.nonce, &sealed.ciphertext),
            Err(CryptoError::Authentication)
        );
        let mut damaged = sealed.ciphertext.clone();
        damaged[0] ^= 1;
        assert_eq!(
            aead::open(&[7; 32], b"record-id", &sealed.nonce, &damaged),
            Err(CryptoError::Authentication)
        );
        let mut nonce = sealed.nonce;
        nonce[0] ^= 1;
        assert_eq!(
            aead::open(&[7; 32], b"record-id", &nonce, &sealed.ciphertext),
            Err(CryptoError::Authentication)
        );
        let mut damaged_tag = sealed.ciphertext.clone();
        *damaged_tag.last_mut().unwrap() ^= 1;
        assert_eq!(
            aead::open(&[7; 32], b"record-id", &sealed.nonce, &damaged_tag),
            Err(CryptoError::Authentication)
        );
    }
    assert_eq!(
        aead::open(&[0; 32], b"", &[0; 12], &[0; 15]),
        Err(CryptoError::Authentication)
    );
}

#[test]
fn aead_handles_multiple_update_chunks() {
    let plaintext = vec![0xab; 2 * 1024 * 1024 + 17];
    let aad = vec![0xcd; 1024 * 1024 + 1];
    let sealed = OpenSsl.seal(&[7; 32], &aad, &plaintext).unwrap();
    assert_eq!(
        OpenSsl
            .open(&[7; 32], &aad, &sealed.nonce, &sealed.ciphertext)
            .unwrap(),
        plaintext
    );
    #[cfg(feature = "aws-lc")]
    assert_eq!(
        CryptoContext::default()
            .backend()
            .open(&[7; 32], &aad, &sealed.nonce, &sealed.ciphertext)
            .unwrap(),
        plaintext
    );
}

#[test]
fn jwt_rejects_mismatched_curve_and_pss_salt() {
    init_openssl();
    let key = OpenSsl
        .generate_keypair(&rcgen::PKCS_ECDSA_P256_SHA256)
        .unwrap();
    let encoding =
        jsonwebtoken::EncodingKey::from_ec_pem(key.serialize_pem().unwrap().as_bytes()).unwrap();
    assert!(
        jwt::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES384),
            &serde_json::json!({"exp":4_000_000_000_u64}),
            &encoding
        )
        .is_err()
    );
    let key = OpenSsl.generate_keypair(&rcgen::PKCS_RSA_SHA256).unwrap();
    let native =
        openssl::pkey::PKey::private_key_from_pkcs8(&key.serialize_der().unwrap()).unwrap();
    let decoding =
        jsonwebtoken::DecodingKey::from_rsa_pem(key.public_key_pem().as_bytes()).unwrap();
    let message = b"header.claims";
    for (algorithm, digest) in [
        (
            jsonwebtoken::Algorithm::PS256,
            openssl::hash::MessageDigest::sha256(),
        ),
        (
            jsonwebtoken::Algorithm::PS384,
            openssl::hash::MessageDigest::sha384(),
        ),
        (
            jsonwebtoken::Algorithm::PS512,
            openssl::hash::MessageDigest::sha512(),
        ),
    ] {
        let mut signer = openssl::sign::Signer::new(digest, &native).unwrap();
        signer
            .set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)
            .unwrap();
        signer
            .set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::custom(0))
            .unwrap();
        let signature = signer.sign_oneshot_to_vec(message).unwrap();
        let verifier = (OpenSsl.jwt_provider().verifier_factory)(&algorithm, &decoding).unwrap();
        assert!(verifier.verify(message, &signature).is_err());
    }
}

#[test]
fn jwt_rejects_rsa_keys_below_the_existing_minimum() {
    let rsa = openssl::rsa::Rsa::generate(1024).unwrap();
    let encoding = jsonwebtoken::EncodingKey::from_rsa_der(&rsa.private_key_to_der().unwrap());
    let decoding = jsonwebtoken::DecodingKey::from_rsa_der(&rsa.public_key_to_der_pkcs1().unwrap());
    for algorithm in [
        jsonwebtoken::Algorithm::RS256,
        jsonwebtoken::Algorithm::RS384,
        jsonwebtoken::Algorithm::RS512,
        jsonwebtoken::Algorithm::PS256,
        jsonwebtoken::Algorithm::PS384,
        jsonwebtoken::Algorithm::PS512,
    ] {
        assert!((OpenSsl.jwt_provider().signer_factory)(&algorithm, &encoding).is_err());
        assert!((OpenSsl.jwt_provider().verifier_factory)(&algorithm, &decoding).is_err());
    }
}

#[test]
fn jwk_coordinates_preserve_leading_zeros() {
    use openssl::{
        bn::{BigNum, BigNumContext},
        ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
        nid::Nid,
        pkey::PKey,
    };
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let mut context = BigNumContext::new().unwrap();
    // Deterministic test keys. Find a coordinate with a leading zero to exercise
    // fixed-width JWK encoding; normal random-key tests rarely cover this case.
    for scalar in 1..=1024 {
        let private = BigNum::from_u32(scalar).unwrap();
        let mut public = EcPoint::new(&group).unwrap();
        public
            .mul_generator2(&group, &private, &mut context)
            .unwrap();
        let raw = public
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut context)
            .unwrap();
        if raw[1] != 0 && raw[33] != 0 {
            continue;
        }
        let key =
            PKey::from_ec_key(EcKey::from_private_components(&group, &private, &public).unwrap())
                .unwrap();
        let der = key.private_key_to_der().unwrap();
        let (curve, x, y) = (OpenSsl
            .jwt_provider()
            .jwk_utils
            .extract_ec_public_key_coordinates)(
            &der, jsonwebtoken::Algorithm::ES256
        )
        .unwrap();
        assert_eq!(curve, jsonwebtoken::jwk::EllipticCurve::P256);
        assert_eq!(x, raw[1..33]);
        assert_eq!(y, raw[33..]);
        assert!(
            (OpenSsl
                .jwt_provider()
                .jwk_utils
                .extract_ec_public_key_coordinates)(
                &der, jsonwebtoken::Algorithm::ES384
            )
            .is_err()
        );
        return;
    }
    panic!("deterministic fixture range must include a leading-zero coordinate");
}

#[test]
fn backend_owned_keys_and_certificates() {
    init_openssl();
    for alg in [
        &rcgen::PKCS_ECDSA_P256_SHA256,
        &rcgen::PKCS_ECDSA_P384_SHA384,
        &rcgen::PKCS_ED25519,
        &rcgen::PKCS_RSA_SHA256,
        &rcgen::PKCS_RSA_SHA384,
        &rcgen::PKCS_RSA_SHA512,
    ] {
        let key = pki::generate_keypair_for(alg).unwrap();
        let der = key.serialize_der().unwrap();
        let from_der = pki::KeyPair::from_pkcs8_der(&der).unwrap();
        let from_pem = pki::KeyPair::from_pem(&key.serialize_pem().unwrap()).unwrap();
        for imported in [&key, &from_der, &from_pem] {
            assert_eq!(key.public_key_der(), imported.public_key_der());
            let cert = pki::self_signed(
                rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap(),
                imported,
            )
            .unwrap();
            let x509 = openssl::x509::X509::from_der(cert.der()).unwrap();
            assert!(x509.verify(&x509.public_key().unwrap()).unwrap());
        }
    }
    assert!(pki::KeyPair::from_pkcs8_der(b"invalid key").is_err());
    assert!(pki::KeyPair::from_pem("invalid key").is_err());
}

#[test]
fn jwt_algorithms_and_claims_validation() {
    use jsonwebtoken::{
        Algorithm, DecodingKey, EncodingKey, Header, Validation, errors::ErrorKind,
    };
    init_openssl();
    let claims = serde_json::json!({"sub":"sandbox", "iss":"gateway", "aud":"sandbox", "exp":4_000_000_000_u64});
    let mut keys = vec![(
        Algorithm::HS256,
        EncodingKey::from_secret(b"backend-test-secret"),
        DecodingKey::from_secret(b"backend-test-secret"),
    )];
    for (alg, key_alg) in [
        (Algorithm::EdDSA, &rcgen::PKCS_ED25519),
        (Algorithm::ES256, &rcgen::PKCS_ECDSA_P256_SHA256),
        (Algorithm::RS256, &rcgen::PKCS_RSA_SHA256),
    ] {
        let key = pki::generate_keypair_for(key_alg).unwrap();
        let private = key.serialize_pem().unwrap();
        let public = key.public_key_pem();
        let pair = match alg {
            Algorithm::EdDSA => (
                EncodingKey::from_ed_pem(private.as_bytes()).unwrap(),
                DecodingKey::from_ed_pem(public.as_bytes()).unwrap(),
            ),
            Algorithm::ES256 => (
                EncodingKey::from_ec_pem(private.as_bytes()).unwrap(),
                DecodingKey::from_ec_pem(public.as_bytes()).unwrap(),
            ),
            _ => (
                EncodingKey::from_rsa_pem(private.as_bytes()).unwrap(),
                DecodingKey::from_rsa_pem(public.as_bytes()).unwrap(),
            ),
        };
        keys.push((alg, pair.0, pair.1));
    }
    for (alg, private, public) in keys {
        let token = jwt::encode(&Header::new(alg), &claims, &private).unwrap();
        let mut validation = Validation::new(alg);
        validation.set_issuer(&["gateway"]);
        validation.set_audience(&["sandbox"]);
        assert_eq!(
            jwt::decode::<serde_json::Value>(&token, &public, &validation)
                .unwrap()
                .claims,
            claims
        );
        let mut tampered = token.clone().into_bytes();
        let signature_start = tampered.iter().rposition(|b| *b == b'.').unwrap() + 1;
        tampered[signature_start] = if tampered[signature_start] == b'A' {
            b'B'
        } else {
            b'A'
        };
        assert_eq!(
            jwt::decode::<serde_json::Value>(&tampered, &public, &validation)
                .unwrap_err()
                .kind(),
            &ErrorKind::InvalidSignature
        );
        validation.set_issuer(&["wrong"]);
        assert_eq!(
            jwt::decode::<serde_json::Value>(&token, &public, &validation)
                .unwrap_err()
                .kind(),
            &ErrorKind::InvalidIssuer
        );
        validation.set_issuer(&["gateway"]);
        validation.set_audience(&["wrong"]);
        assert_eq!(
            jwt::decode::<serde_json::Value>(&token, &public, &validation)
                .unwrap_err()
                .kind(),
            &ErrorKind::InvalidAudience
        );
        validation.set_audience(&["sandbox"]);
        let expired =
            serde_json::json!({"sub":"sandbox", "iss":"gateway", "aud":"sandbox", "exp":1});
        let token = jwt::encode(&Header::new(alg), &expired, &private).unwrap();
        assert_eq!(
            jwt::decode::<serde_json::Value>(&token, &public, &validation)
                .unwrap_err()
                .kind(),
            &ErrorKind::ExpiredSignature
        );
    }
}

#[test]
fn tls13_handshake_and_application_data() {
    init_openssl();
    let pki::CertifiedKey { cert, key_pair } =
        pki::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let client = tls::client_builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server = tls::server_builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der().unwrap()).into(),
        )
        .unwrap();
    let (mut client, mut server) = handshake(client, server, "localhost").unwrap();
    assert_eq!(
        client.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    assert_eq!(
        client.negotiated_cipher_suite().unwrap().suite(),
        rustls::CipherSuite::TLS13_AES_256_GCM_SHA384
    );
    client.writer().write_all(b"openssl transport").unwrap();
    let mut wire = Vec::new();
    client.write_tls(&mut wire).unwrap();
    server.read_tls(&mut wire.as_slice()).unwrap();
    server.process_new_packets().unwrap();
    let mut received = [0; 17];
    server.reader().read_exact(&mut received).unwrap();
    assert_eq!(&received, b"openssl transport");
}

#[test]
fn imported_ca_signs_with_openssl() {
    init_openssl();
    let key = pki::generate_keypair().unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let ca = pki::self_signed(params, &key).unwrap();
    let pem = key.serialize_pem().unwrap();
    let issuer = pki::issuer_from_der(ca.der(), pki::KeyPair::from_pem(&pem).unwrap()).unwrap();
    let leaf_key = pki::generate_keypair().unwrap();
    let leaf = pki::signed_by_issuer(
        rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap(),
        &leaf_key,
        &issuer,
    )
    .unwrap();
    let ca = openssl::x509::X509::from_der(ca.der()).unwrap();
    let leaf = openssl::x509::X509::from_der(leaf.der()).unwrap();
    assert!(leaf.verify(&ca.public_key().unwrap()).unwrap());
    assert_eq!(
        leaf.issuer_name().to_der().unwrap(),
        ca.subject_name().to_der().unwrap()
    );
}

#[test]
fn malformed_hmac_signatures_are_rejected() {
    init_openssl();
    for algorithm in [
        jsonwebtoken::Algorithm::HS256,
        jsonwebtoken::Algorithm::HS384,
        jsonwebtoken::Algorithm::HS512,
    ] {
        let token = jwt::encode(
            &jsonwebtoken::Header::new(algorithm),
            &serde_json::json!({"exp":4_000_000_000_u64}),
            &jsonwebtoken::EncodingKey::from_secret(b"test-key"),
        )
        .unwrap();
        let (message, _) = token.rsplit_once('.').unwrap();
        for signature in ["", "AA", &"A".repeat(100)] {
            assert_eq!(
                jwt::decode::<serde_json::Value>(
                    format!("{message}.{signature}"),
                    &jsonwebtoken::DecodingKey::from_secret(b"test-key"),
                    &jsonwebtoken::Validation::new(algorithm),
                )
                .unwrap_err()
                .kind(),
                &jsonwebtoken::errors::ErrorKind::InvalidSignature
            );
        }
    }
}

#[test]
#[cfg(feature = "aws-lc")]
fn backends_preserve_ciphertext_keys_and_jwt_signatures() {
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
    init_openssl();
    let aws = CryptoContext::default();
    assert_eq!(aws.backend().capabilities().backend, "aws-lc");
    let openssl: &dyn ProtocolBackend = &OpenSsl;
    for (producer, consumer) in [(aws.backend(), openssl), (openssl, aws.backend())] {
        let sealed = producer
            .seal(&[42; 32], b"record-id", b"persisted credential")
            .unwrap();
        assert_eq!(
            consumer
                .open(&[42; 32], b"record-id", &sealed.nonce, &sealed.ciphertext)
                .unwrap(),
            b"persisted credential"
        );
        for (key_algorithm, algorithms) in [
            (&rcgen::PKCS_ED25519, &[Algorithm::EdDSA][..]),
            (&rcgen::PKCS_ECDSA_P256_SHA256, &[Algorithm::ES256][..]),
            (&rcgen::PKCS_ECDSA_P384_SHA384, &[Algorithm::ES384][..]),
        ] {
            let key = producer.generate_keypair(key_algorithm).unwrap();
            let imported = consumer
                .import_keypair_der(&key.serialize_der().unwrap())
                .unwrap();
            assert_eq!(imported.public_key_der(), key.public_key_der());
            let private = key.serialize_pem().unwrap();
            let public = key.public_key_pem();
            let (encoding, decoding) = if algorithms[0] == Algorithm::EdDSA {
                (
                    EncodingKey::from_ed_pem(private.as_bytes()).unwrap(),
                    DecodingKey::from_ed_pem(public.as_bytes()).unwrap(),
                )
            } else {
                (
                    EncodingKey::from_ec_pem(private.as_bytes()).unwrap(),
                    DecodingKey::from_ec_pem(public.as_bytes()).unwrap(),
                )
            };
            for algorithm in algorithms {
                check_signature(producer, consumer, *algorithm, &encoding, &decoding);
            }
        }
        let key = OpenSsl.generate_keypair(&rcgen::PKCS_RSA_SHA256).unwrap();
        let imported = consumer
            .import_keypair_der(&key.serialize_der().unwrap())
            .unwrap();
        assert_eq!(imported.public_key_der(), key.public_key_der());
        let encoding = EncodingKey::from_rsa_pem(key.serialize_pem().unwrap().as_bytes()).unwrap();
        let decoding = DecodingKey::from_rsa_pem(key.public_key_pem().as_bytes()).unwrap();
        for algorithm in [
            Algorithm::RS256,
            Algorithm::RS384,
            Algorithm::RS512,
            Algorithm::PS256,
            Algorithm::PS384,
            Algorithm::PS512,
        ] {
            check_signature(producer, consumer, algorithm, &encoding, &decoding);
        }
        for algorithm in [Algorithm::HS256, Algorithm::HS384, Algorithm::HS512] {
            check_signature(
                producer,
                consumer,
                algorithm,
                &EncodingKey::from_secret(b"compatibility key"),
                &DecodingKey::from_secret(b"compatibility key"),
            );
        }
    }
}

#[cfg(feature = "aws-lc")]
fn check_signature(
    producer: &dyn ProtocolBackend,
    consumer: &dyn ProtocolBackend,
    algorithm: jsonwebtoken::Algorithm,
    encoding: &jsonwebtoken::EncodingKey,
    decoding: &jsonwebtoken::DecodingKey,
) {
    let signer = (producer.jwt_provider().signer_factory)(&algorithm, encoding).unwrap();
    let verifier = (consumer.jwt_provider().verifier_factory)(&algorithm, decoding).unwrap();
    let signature = signer.try_sign(b"header.claims").unwrap();
    verifier
        .verify(b"header.claims", &signature)
        .unwrap_or_else(|error| {
            panic!(
                "{} -> {} {algorithm:?}: {error}",
                producer.capabilities().backend,
                consumer.capabilities().backend
            )
        });
    assert!(verifier.verify(b"wrong.claims", &signature).is_err());
}
