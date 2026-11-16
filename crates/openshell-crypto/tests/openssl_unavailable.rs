// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "openssl")]

use openshell_crypto::{CryptoBackend, CryptoContext, CryptoError, OpenSsl, ProtocolBackend, tls};
use std::{
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[test]
fn unavailable_provider_fails_without_fallback() {
    // OpenSSL reads configuration once. Exercise failure in a fresh process,
    // without changing the test runner's environment or process-global state.
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "unavailable_provider_child",
            "--nocapture",
        ])
        .env("OPENSHELL_TEST_UNAVAILABLE", "1")
        .env(
            "OPENSSL_CONF",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/openssl-unavailable.cnf"
            ),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            // The child may have exited since try_wait; still reap it below.
            let _ = child.kill();
            let result = child.wait_with_output().unwrap();
            panic!(
                "unavailable-provider child exceeded the 10-second deadline\n{}\n{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("1 passed"));
}

#[test]
#[ignore = "run in a subprocess with deliberately unavailable OpenSSL algorithms"]
fn unavailable_provider_child() {
    assert_eq!(std::env::var("OPENSHELL_TEST_UNAVAILABLE").unwrap(), "1");
    openshell_crypto::install_default_context(CryptoContext::new(Box::new(OpenSsl))).unwrap();
    assert_eq!(
        openshell_crypto::sha256(b"message"),
        Err(CryptoError::Operation)
    );
    assert_eq!(
        openshell_crypto::random_bytes::<32>(),
        Err(CryptoError::Random)
    );
    assert_eq!(
        OpenSsl.seal(&[0; 32], b"", b"plaintext").unwrap_err(),
        CryptoError::Random
    );
    // A full-length tag reaches cipher initialization: unavailable AES is an
    // operational error, not a corrupt stored credential.
    assert_eq!(
        OpenSsl.open(&[0; 32], b"", &[0; 12], &[0; 16]),
        Err(CryptoError::Operation)
    );
    for algorithm in [
        &rcgen::PKCS_ECDSA_P256_SHA256,
        &rcgen::PKCS_ECDSA_P384_SHA384,
        &rcgen::PKCS_ED25519,
        &rcgen::PKCS_RSA_SHA256,
    ] {
        assert!(OpenSsl.generate_keypair(algorithm).is_err());
    }
    assert!(
        openshell_crypto::jwt::encode(
            &jsonwebtoken::Header::default(),
            &serde_json::json!({"exp":4_000_000_000_u64}),
            &jsonwebtoken::EncodingKey::from_secret(b"test-only-key"),
        )
        .is_err()
    );
    // Exercise the same facade builders as production callers: a provider with
    // no usable ciphers must return an error, not panic or fall back to AWS-LC.
    assert!(OpenSsl.tls_provider().cipher_suites.is_empty());
    let errors = [
        tls::try_client_builder().unwrap_err(),
        tls::try_server_builder().unwrap_err(),
        tls::try_client_builder_with_protocol_versions(&[&rustls::version::TLS13]).unwrap_err(),
        tls::try_server_builder_with_protocol_versions(&[&rustls::version::TLS13]).unwrap_err(),
    ];
    for error in errors {
        assert!(
            matches!(error, rustls::Error::General(ref message) if message == "no usable cipher suites configured")
        );
    }
}
