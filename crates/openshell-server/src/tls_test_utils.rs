// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared test helpers for TLS-related tests.

use std::fs::File;
use std::io::Write;
use std::path::Path;

use rcgen::{CertificateParams, IsCa, KeyPair};

/// Install the default rustls crypto provider.
///
/// Must be called once at the start of any test that exercises TLS handshakes.
/// Multiple calls are harmless (subsequent calls return an error, ignored).
pub fn install_rustls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Write bytes to a file inside `dir`, panicking on failure.
pub fn write_test_file(dir: &Path, name: &str, data: &[u8]) {
    let path = dir.join(name);
    File::create(&path)
        .and_then(|mut file| file.write_all(data))
        .expect("failed to write test file");
}

/// Generate a self-signed CA certificate and a `localhost` server certificate,
/// writing them as PEM files into `dir`.
///
/// Returns the CA certificate and keypair so callers can sign additional
/// server or client certificates.
///
/// Files written:
/// - `ca.pem`
/// - `server-cert.pem`
/// - `server-key.pem`
pub fn generate_test_certs_with_ca(dir: &Path) -> (rcgen::Certificate, KeyPair) {
    let mut ca_params =
        CertificateParams::new(Vec::<String>::new()).expect("failed to create CA params");
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "test-ca");
    let ca_key = KeyPair::generate().expect("failed to generate CA key");
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .expect("failed to sign CA cert");

    let server_params = CertificateParams::new(vec!["localhost".to_string()])
        .expect("failed to create server params");
    let server_key = KeyPair::generate().expect("failed to generate server key");
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .expect("failed to sign server cert");

    write_test_file(dir, "ca.pem", ca_cert.pem().as_bytes());
    write_test_file(dir, "server-cert.pem", server_cert.pem().as_bytes());
    write_test_file(dir, "server-key.pem", server_key.serialize_pem().as_bytes());

    (ca_cert, ca_key)
}
