// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "openssl")]

mod common;

use common::{handshake, init_openssl};
use openshell_crypto::{OpenSsl, ProtocolBackend, pki, tls};
use std::sync::Arc;

#[test]
fn native_tls_library_is_available_for_linkage_check() {
    // The backend uses Rustls for TLS and libcrypto for primitives. Exercise
    // libssl explicitly so Linux's --as-needed linker retains both native
    // libraries for CI's dynamic-linkage assertion on this test executable.
    let _context = openssl::ssl::SslContext::builder(openssl::ssl::SslMethod::tls())
        .unwrap()
        .build();
}

fn leaf(
    ca: &pki::Certificate,
    ca_key: &pki::KeyPair,
    usage: rcgen::ExtendedKeyUsagePurpose,
) -> pki::CertifiedKey {
    let key_pair = pki::generate_keypair().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    params.extended_key_usages = vec![usage];
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    let cert = pki::signed_by(params, &key_pair, ca, ca_key).unwrap();
    pki::CertifiedKey { cert, key_pair }
}

#[test]
fn tls12_and_tls13_enforce_server_and_client_authentication() {
    init_openssl();
    // An explicit empty protocol policy must not be replaced with defaults.
    assert!(tls::try_client_builder_with_protocol_versions(&[]).is_err());
    assert!(tls::try_server_builder_with_protocol_versions(&[]).is_err());
    assert!(std::ptr::eq(
        tls::configuration_provider().secure_random,
        OpenSsl.tls_provider().secure_random
    ));
    let ca_key = pki::generate_keypair().unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let ca = pki::self_signed(params, &ca_key).unwrap();
    let server_key = leaf(&ca, &ca_key, rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    let client_key = leaf(&ca, &ca_key, rcgen::ExtendedKeyUsagePurpose::ClientAuth);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots.clone()),
            tls::configuration_provider(),
        )
        .build()
        .unwrap();
        let server = tls::try_server_builder_with_protocol_versions(&[version])
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![server_key.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(
                    server_key.key_pair.serialize_der().unwrap(),
                )
                .into(),
            )
            .unwrap();
        let client = tls::try_client_builder_with_protocol_versions(&[version])
            .unwrap()
            .with_root_certificates(roots.clone())
            .with_client_auth_cert(
                vec![client_key.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(
                    client_key.key_pair.serialize_der().unwrap(),
                )
                .into(),
            )
            .unwrap();
        handshake(client.clone(), server.clone(), "localhost").unwrap();
        assert!(matches!(
            handshake(client, server.clone(), "wrong.example"),
            Err(rustls::Error::InvalidCertificate(_))
        ));
        let anonymous = tls::try_client_builder_with_protocol_versions(&[version])
            .unwrap()
            .with_root_certificates(roots.clone())
            .with_no_client_auth();
        assert!(matches!(
            handshake(anonymous, server.clone(), "localhost"),
            Err(rustls::Error::NoCertificatesPresented)
        ));
        let untrusted = tls::try_client_builder_with_protocol_versions(&[version])
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        assert!(matches!(
            handshake(untrusted, server.clone(), "localhost"),
            Err(rustls::Error::InvalidCertificate(_))
        ));
        let stranger = pki::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let unauthorized = tls::try_client_builder_with_protocol_versions(&[version])
            .unwrap()
            .with_root_certificates(roots.clone())
            .with_client_auth_cert(
                vec![stranger.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(
                    stranger.key_pair.serialize_der().unwrap(),
                )
                .into(),
            )
            .unwrap();
        assert!(matches!(
            handshake(unauthorized, server, "localhost"),
            Err(rustls::Error::InvalidCertificate(_))
        ));
    }
}
