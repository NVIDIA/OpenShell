// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! TLS certificate generation helpers for e2e tests.
//!
//! Wraps rcgen to produce a CA + server cert (valid for localhost/127.0.0.1)
//! + client cert, all as PEM strings, in a single call.

pub use rcgen::{Certificate, KeyPair};
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa};

/// PEM-encoded certificate material generated for one test run.
pub struct TestCerts {
    pub ca_cert: Certificate,
    pub ca_key: KeyPair,
    pub ca_pem: String,
    pub server_cert_pem: String,
    pub server_key_pem: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,
}

/// Generate a fresh CA, server cert, and client cert.
///
/// Server cert is valid for both `localhost` and `127.0.0.1` so the TUI
/// can connect to `https://127.0.0.1:<port>` without a hostname mismatch.
pub fn generate_test_certs() -> TestCerts {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let server_key = KeyPair::generate().unwrap();
    let mut server_params =
        CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server_params.signed_by(&server_key, &ca_cert, &ca_key).unwrap();

    let client_key = KeyPair::generate().unwrap();
    let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = client_params.signed_by(&client_key, &ca_cert, &ca_key).unwrap();

    TestCerts {
        ca_pem: ca_cert.pem(),
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
        client_cert_pem: client_cert.pem(),
        client_key_pem: client_key.serialize_pem(),
        ca_cert,
        ca_key,
    }
}

/// Install the rustls ring crypto provider as the process default.
///
/// Must be called before any in-process TLS. Safe to call multiple times.
pub fn install_rustls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
