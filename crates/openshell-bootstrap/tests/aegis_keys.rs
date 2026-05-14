// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the AEGIS gateway keypair lifecycle.

use openshell_bootstrap::aegis_keys::{load_or_generate, publish_public_key, rotate};
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey};
use tempfile::TempDir;

#[test]
fn load_or_generate_creates_new_keys_when_storage_is_empty() {
    let dir = TempDir::new().unwrap();
    let material = load_or_generate(dir.path()).expect("generate");

    assert!(material.private_key_pem.contains("BEGIN PRIVATE KEY"));
    assert!(material.public_key_pem.contains("BEGIN PUBLIC KEY"));
    assert!(!material.public_key_spki_der.is_empty());
    assert_eq!(material.fingerprint_sha256.len(), 32);

    assert!(dir.path().join("aegis-private.pem").exists());
    assert!(dir.path().join("aegis-public.pem").exists());
}

#[test]
fn load_or_generate_is_idempotent() {
    let dir = TempDir::new().unwrap();
    let first = load_or_generate(dir.path()).expect("first");
    let second = load_or_generate(dir.path()).expect("second");

    assert_eq!(first.private_key_pem, second.private_key_pem);
    assert_eq!(first.public_key_pem, second.public_key_pem);
    assert_eq!(first.public_key_spki_der, second.public_key_spki_der);
    assert_eq!(first.fingerprint_sha256, second.fingerprint_sha256);
}

#[test]
fn rotate_replaces_existing_keypair() {
    let dir = TempDir::new().unwrap();
    let original = load_or_generate(dir.path()).expect("initial");
    let rotated = rotate(dir.path()).expect("rotate");

    assert_ne!(
        original.fingerprint_sha256, rotated.fingerprint_sha256,
        "rotated keypair should have a different fingerprint"
    );
    assert_ne!(original.private_key_pem, rotated.private_key_pem);
    assert_ne!(original.public_key_pem, rotated.public_key_pem);

    // After rotation, load_or_generate should return the rotated material.
    let reloaded = load_or_generate(dir.path()).expect("reload");
    assert_eq!(reloaded.fingerprint_sha256, rotated.fingerprint_sha256);
}

#[test]
fn sign_and_verify_round_trip() {
    let dir = TempDir::new().unwrap();
    let material = load_or_generate(dir.path()).expect("generate");

    let signing_secret = p256::SecretKey::from_pkcs8_pem(&material.private_key_pem)
        .expect("parse private key");
    let signing_key = SigningKey::from(signing_secret);

    let verifying_public = p256::PublicKey::from_public_key_pem(&material.public_key_pem)
        .expect("parse public key");
    let verifying_key = VerifyingKey::from(verifying_public);

    let message = b"aegis ticket round-trip canary";
    let signature: Signature = signing_key.sign(message);

    verifying_key
        .verify(message, &signature)
        .expect("signature should verify against derived public key");

    // Tampered message must not verify.
    let tampered = b"aegis ticket round-trip canary!";
    assert!(verifying_key.verify(tampered, &signature).is_err());
}

#[test]
fn publish_public_key_writes_at_least_one_path() {
    let dir = TempDir::new().unwrap();
    let material = load_or_generate(dir.path()).expect("generate");

    // Steer the publish targets into the tempdir so we don't pollute the
    // host's %TEMP% / %ProgramData% / $XDG_RUNTIME_DIR.
    let publish_root = dir.path().join("publish");
    std::fs::create_dir_all(&publish_root).unwrap();

    // Set every env var the publisher reads on any platform; the cfg in
    // the module decides which subset is consulted.
    let prev_tmp = std::env::var_os("TEMP");
    let prev_pd = std::env::var_os("ProgramData");
    let prev_xdg = std::env::var_os("XDG_RUNTIME_DIR");
    let prev_tmpdir = std::env::var_os("TMPDIR");

    // SAFETY: these env mutations are only safe because the test process
    // serializes within a single test binary; cargo runs integration
    // tests in separate processes per file. The publish test owns this
    // file so no other test mutates these vars concurrently.
    unsafe {
        std::env::set_var("TEMP", &publish_root);
        std::env::set_var("ProgramData", &publish_root);
        std::env::set_var("XDG_RUNTIME_DIR", &publish_root);
        std::env::set_var("TMPDIR", &publish_root);
    }

    let written = publish_public_key(&material).expect("publish");
    assert!(!written.is_empty(), "expected at least one published path");
    for path in &written {
        let content = std::fs::read_to_string(path).expect("read published pubkey");
        assert_eq!(content, material.public_key_pem);
    }

    unsafe {
        match prev_tmp {
            Some(v) => std::env::set_var("TEMP", v),
            None => std::env::remove_var("TEMP"),
        }
        match prev_pd {
            Some(v) => std::env::set_var("ProgramData", v),
            None => std::env::remove_var("ProgramData"),
        }
        match prev_xdg {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
        match prev_tmpdir {
            Some(v) => std::env::set_var("TMPDIR", v),
            None => std::env::remove_var("TMPDIR"),
        }
    }
}
