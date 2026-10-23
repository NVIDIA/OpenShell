// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "openssl")]

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
use openshell_crypto::{OpenSsl, ProtocolBackend};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::PKey,
    rsa::Rsa,
};

#[test]
fn jwt_rejects_invalid_rsa_public_components() {
    let provider = OpenSsl.jwt_provider();
    let valid = Rsa::generate(2048).unwrap();
    let mut oversized_exponent = BigNum::new().unwrap();
    oversized_exponent.set_bit(33).unwrap();
    oversized_exponent.add_word(1).unwrap();
    for exponent in [
        BigNum::from_u32(0).unwrap(),
        BigNum::from_u32(1).unwrap(),
        BigNum::from_u32(2).unwrap(),
        BigNum::from_u32(65536).unwrap(),
        oversized_exponent,
    ] {
        // Both JWK components and DER reach the adapter; parsing alone accepts
        // these values and must not be mistaken for RSA public-key validation.
        let key = Rsa::from_public_components(valid.n().to_owned().unwrap(), exponent).unwrap();
        let der = key.public_key_to_der_pkcs1().unwrap();
        let keys = [
            DecodingKey::from_rsa_raw_components(&key.n().to_vec(), &key.e().to_vec()),
            DecodingKey::from_rsa_der(&der),
        ];
        for algorithm in [
            Algorithm::RS256,
            Algorithm::RS384,
            Algorithm::RS512,
            Algorithm::PS256,
            Algorithm::PS384,
            Algorithm::PS512,
        ] {
            for key in &keys {
                assert!(
                    (provider.verifier_factory)(&algorithm, key).is_err(),
                    "invalid RSA exponent accepted for {algorithm:?}"
                );
            }
        }
    }

    let mut even_modulus = valid.n().to_owned().unwrap();
    even_modulus.sub_word(1).unwrap();
    let invalid = DecodingKey::from_rsa_raw_components(&even_modulus.to_vec(), &valid.e().to_vec());
    for algorithm in [Algorithm::RS256, Algorithm::PS256] {
        assert!((provider.verifier_factory)(&algorithm, &invalid).is_err());
    }

    // Preserve non-FIPS compatibility, including the historically valid e=3.
    for exponent in [3, 65537] {
        let key = DecodingKey::from_rsa_raw_components(
            &valid.n().to_vec(),
            &BigNum::from_u32(exponent).unwrap().to_vec(),
        );
        for algorithm in [Algorithm::RS256, Algorithm::PS256] {
            assert!((provider.verifier_factory)(&algorithm, &key).is_ok());
        }
    }
}

#[test]
fn pki_and_jwt_reject_inconsistent_ec_private_keys() {
    let provider = OpenSsl.jwt_provider();
    for (curve, algorithm) in [
        (Nid::X9_62_PRIME256V1, Algorithm::ES256),
        (Nid::SECP384R1, Algorithm::ES384),
    ] {
        let group = EcGroup::from_curve_name(curve).unwrap();
        let valid = EcKey::generate(&group).unwrap();
        let other = EcKey::generate(&group).unwrap();
        let mut order = BigNum::new().unwrap();
        group
            .order(&mut order, &mut BigNumContext::new().unwrap())
            .unwrap();
        let invalid_keys = [
            EcKey::from_private_components(&group, valid.private_key(), other.public_key())
                .unwrap(),
            EcKey::from_private_components(
                &group,
                &BigNum::from_u32(0).unwrap(),
                valid.public_key(),
            )
            .unwrap(),
            EcKey::from_private_components(&group, &order, valid.public_key()).unwrap(),
        ];
        for ec in invalid_keys {
            assert!(ec.check_key().is_err());
            let sec1 = ec.private_key_to_der().unwrap();
            let key = PKey::from_ec_key(ec).unwrap();
            let pkcs8 = key.private_key_to_pkcs8().unwrap();
            let pem = String::from_utf8(key.private_key_to_pem_pkcs8().unwrap()).unwrap();
            // These are parseable encodings of invalid key material.
            assert!(PKey::private_key_from_pkcs8(&pkcs8).is_ok());
            assert!(OpenSsl.import_keypair_der(&pkcs8).is_err());
            assert!(OpenSsl.import_keypair_pem(&pem).is_err());
            assert!(
                (provider.signer_factory)(&algorithm, &EncodingKey::from_ec_der(&sec1)).is_err()
            );
            assert!(
                (provider.jwk_utils.extract_ec_public_key_coordinates)(&sec1, algorithm).is_err()
            );
        }

        let sec1 = valid.private_key_to_der().unwrap();
        let key = PKey::from_ec_key(valid).unwrap();
        assert!(
            OpenSsl
                .import_keypair_der(&key.private_key_to_pkcs8().unwrap())
                .is_ok()
        );
        assert!((provider.signer_factory)(&algorithm, &EncodingKey::from_ec_der(&sec1)).is_ok());
    }
}

#[test]
fn pki_enforces_rsa_minimum_size_for_pem_and_pkcs8() {
    // Certificate construction uses the facade for its random serial number.
    openshell_crypto::install_default_context(openshell_crypto::CryptoContext::new(Box::new(
        OpenSsl,
    )))
    .unwrap();
    #[cfg(feature = "aws-lc")]
    let aws = openshell_crypto::CryptoContext::default();
    let backends: &[&dyn ProtocolBackend] = &[
        &OpenSsl,
        #[cfg(feature = "aws-lc")]
        aws.backend(),
    ];
    for bits in [1024, 2048] {
        let rsa = Rsa::generate(bits).unwrap();
        let traditional_pem = String::from_utf8(rsa.private_key_to_pem().unwrap()).unwrap();
        let native = PKey::from_rsa(rsa).unwrap();
        let der = native.private_key_to_pkcs8().unwrap();
        let pem = String::from_utf8(native.private_key_to_pem_pkcs8().unwrap()).unwrap();
        for backend in backends {
            for (format, imported) in [
                ("PKCS#8 DER", backend.import_keypair_der(&der)),
                ("PKCS#8 PEM", backend.import_keypair_pem(&pem)),
                ("PKCS#1 PEM", backend.import_keypair_pem(&traditional_pem)),
            ] {
                if bits < 2048 {
                    assert!(
                        imported.is_err(),
                        "{} accepted a {bits}-bit RSA key from {format}",
                        backend.capabilities().backend
                    );
                } else {
                    let key = imported.unwrap();
                    assert_eq!(key.public_key_der(), native.public_key_to_der().unwrap());
                    let certificate = openshell_crypto::pki::self_signed(
                        rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap(),
                        &key,
                    )
                    .unwrap();
                    let x509 = openssl::x509::X509::from_der(certificate.der()).unwrap();
                    assert!(x509.verify(&native).unwrap());
                }
            }
        }
    }
}

#[test]
fn pki_rejects_oversized_rsa_imports() {
    // A parseable oversized modulus isolates the size gate without expensive
    // 8193-bit prime generation. This synthetic key is not a consistent RSA pair.
    let seed = Rsa::generate(2048).unwrap();
    let mut modulus = seed.n().to_owned().unwrap();
    modulus.set_bit(8192).unwrap();
    let oversized = Rsa::from_private_components(
        modulus,
        seed.e().to_owned().unwrap(),
        seed.d().to_owned().unwrap(),
        seed.p().unwrap().to_owned().unwrap(),
        seed.q().unwrap().to_owned().unwrap(),
        seed.dmp1().unwrap().to_owned().unwrap(),
        seed.dmq1().unwrap().to_owned().unwrap(),
        seed.iqmp().unwrap().to_owned().unwrap(),
    )
    .unwrap();
    let traditional_pem = String::from_utf8(oversized.private_key_to_pem().unwrap()).unwrap();
    let native = PKey::from_rsa(oversized).unwrap();
    assert_eq!(native.bits(), 8193);
    let der = native.private_key_to_pkcs8().unwrap();
    let pem = String::from_utf8(native.private_key_to_pem_pkcs8().unwrap()).unwrap();
    assert!(PKey::private_key_from_pkcs8(&der).is_ok());
    assert!(PKey::private_key_from_pem(pem.as_bytes()).is_ok());
    assert!(OpenSsl.import_keypair_der(&der).is_err());
    assert!(OpenSsl.import_keypair_pem(&pem).is_err());
    assert!(OpenSsl.import_keypair_pem(&traditional_pem).is_err());
}

#[test]
fn pki_and_jwt_reject_inconsistent_rsa_private_keys() {
    let valid = Rsa::generate(2048).unwrap();
    #[cfg(feature = "aws-lc")]
    let aws = openshell_crypto::CryptoContext::default();
    let backends: &[&dyn ProtocolBackend] = &[
        &OpenSsl,
        #[cfg(feature = "aws-lc")]
        aws.backend(),
    ];
    for component in 0..4 {
        let mut private = [
            valid.d().to_owned().unwrap(),
            valid.dmp1().unwrap().to_owned().unwrap(),
            valid.dmq1().unwrap().to_owned().unwrap(),
            valid.iqmp().unwrap().to_owned().unwrap(),
        ];
        private[component].add_word(2).unwrap();
        let [
            private_exponent,
            first_exponent,
            second_exponent,
            coefficient,
        ] = private;
        let malformed = Rsa::from_private_components(
            valid.n().to_owned().unwrap(),
            valid.e().to_owned().unwrap(),
            private_exponent,
            valid.p().unwrap().to_owned().unwrap(),
            valid.q().unwrap().to_owned().unwrap(),
            first_exponent,
            second_exponent,
            coefficient,
        )
        .unwrap();
        assert!(!matches!(malformed.check_key(), Ok(true)));
        let pkcs1 = malformed.private_key_to_der().unwrap();
        let traditional_pem = String::from_utf8(malformed.private_key_to_pem().unwrap()).unwrap();
        let native = PKey::from_rsa(malformed).unwrap();
        let der = native.private_key_to_pkcs8().unwrap();
        let pem = String::from_utf8(native.private_key_to_pem_pkcs8().unwrap()).unwrap();
        // Parsing succeeds; consistency validation must reject these keys.
        assert!(PKey::private_key_from_pkcs8(&der).is_ok());
        assert!(PKey::private_key_from_pem(pem.as_bytes()).is_ok());
        for backend in backends {
            for imported in [
                backend.import_keypair_der(&der),
                backend.import_keypair_pem(&pem),
                backend.import_keypair_pem(&traditional_pem),
            ] {
                assert!(
                    imported.is_err(),
                    "{} accepted corrupted RSA component {component}",
                    backend.capabilities().backend
                );
            }
            for encoding in [
                EncodingKey::from_rsa_der(&pkcs1),
                EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
            ] {
                for algorithm in [
                    Algorithm::RS256,
                    Algorithm::RS384,
                    Algorithm::RS512,
                    Algorithm::PS256,
                    Algorithm::PS384,
                    Algorithm::PS512,
                ] {
                    let signer = (backend.jwt_provider().signer_factory)(&algorithm, &encoding);
                    // OpenSSL validates at construction; AWS-LC may defer it
                    // until signing. Neither may successfully use the key.
                    if backend.capabilities().backend == "openssl" {
                        assert!(
                            signer.is_err(),
                            "OpenSSL accepted corrupted RSA component {component} for {algorithm:?}"
                        );
                    } else {
                        assert!(
                            !signer.is_ok_and(|signer| signer.try_sign(b"header.claims").is_ok()),
                            "AWS-LC signed with corrupted RSA component {component} for {algorithm:?}"
                        );
                    }
                }
            }
        }
    }
}
