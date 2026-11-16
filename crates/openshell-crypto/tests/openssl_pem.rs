// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "openssl")]

use openshell_crypto::{OpenSsl, ProtocolBackend};
use openssl::{ec::EcGroup, ec::EcKey, nid::Nid, pkey::PKey, rsa::Rsa, symm::Cipher};
use std::{
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[test]
fn encrypted_pem_is_rejected_without_prompting() {
    // Isolate terminal I/O and bound execution: reverting to OpenSSL's default
    // callback must fail the test, whether a controlling terminal exists or not.
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "pem_import_child", "--nocapture"])
        .env("OPENSHELL_TEST_PEM_IMPORT", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("PEM import did not finish without interactive input");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let result = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(result.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("1 passed"), "{stdout}");
    assert!(stderr.is_empty(), "PEM import wrote to stderr: {stderr}");
}

#[test]
#[ignore = "run by the parent with an input deadline and captured diagnostics"]
fn pem_import_child() {
    assert_eq!(std::env::var("OPENSHELL_TEST_PEM_IMPORT").unwrap(), "1");
    let ec = EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap();
    let rsa = Rsa::generate(2048).unwrap();
    let keys = [
        PKey::from_ec_key(ec.clone()).unwrap(),
        PKey::from_rsa(rsa.clone()).unwrap(),
    ];
    for key in &keys {
        let pem = key.private_key_to_pem_pkcs8().unwrap();
        let imported = OpenSsl
            .import_keypair_pem(std::str::from_utf8(&pem).unwrap())
            .unwrap();
        assert_eq!(imported.public_key_der(), key.public_key_to_der().unwrap());
    }
    // Both the generic PKCS#8 and traditional PEM loaders can request passwords.
    for password in [b"test-only-passphrase".as_slice(), b""] {
        let mut encrypted = keys
            .iter()
            .map(|key| {
                key.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), password)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        encrypted.push(
            ec.private_key_to_pem_passphrase(Cipher::aes_256_cbc(), password)
                .unwrap(),
        );
        encrypted.push(
            rsa.private_key_to_pem_passphrase(Cipher::aes_256_cbc(), password)
                .unwrap(),
        );
        for pem in encrypted {
            assert!(
                OpenSsl
                    .import_keypair_pem(std::str::from_utf8(&pem).unwrap())
                    .is_err(),
                "encrypted PEM must be rejected, including with an empty passphrase"
            );
        }
    }
    assert!(OpenSsl.import_keypair_pem("invalid key").is_err());
}
