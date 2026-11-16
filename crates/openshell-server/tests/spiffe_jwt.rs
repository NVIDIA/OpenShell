// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rcgen::PublicKeyData as _;
use serde_json::json;
use spiffe::{JwtBundle, JwtBundleSet, JwtSvid, TrustDomain};

#[test]
fn spiffe_verifies_signed_jwt_svids_with_the_selected_crypto_backend() {
    let key = openshell_crypto::pki::generate_keypair().unwrap();
    let public_key = key.der_bytes();
    let jwks = json!({
        "keys": [{
            "kty": "EC",
            "kid": "test-key",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(&public_key[1..33]),
            "y": URL_SAFE_NO_PAD.encode(&public_key[33..65]),
        }],
    });
    let mut bundles = JwtBundleSet::new();
    bundles.add_bundle(
        JwtBundle::from_jwt_authorities(
            TrustDomain::new("example.org").unwrap(),
            &serde_json::to_vec(&jwks).unwrap(),
        )
        .unwrap(),
    );

    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some("test-key".into());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut claims = json!({
        "sub": "spiffe://example.org/supervisor",
        "aud": ["openshell"],
        "exp": now + 300,
    });
    let signing_key = EncodingKey::from_ec_pem(key.serialize_pem().unwrap().as_bytes()).unwrap();
    let token = openshell_crypto::jwt::encode(&header, &claims, &signing_key).unwrap();

    let svid = JwtSvid::parse_and_validate(&token, &bundles, &["openshell"]).unwrap();
    assert_eq!(
        svid.spiffe_id().to_string(),
        "spiffe://example.org/supervisor"
    );
    assert!(JwtSvid::parse_and_validate(&token, &bundles, &["another-audience"]).is_err());

    let untrusted_key = openshell_crypto::pki::generate_keypair().unwrap();
    let untrusted_key =
        EncodingKey::from_ec_pem(untrusted_key.serialize_pem().unwrap().as_bytes()).unwrap();
    let forged = openshell_crypto::jwt::encode(&header, &claims, &untrusted_key).unwrap();
    assert!(JwtSvid::parse_and_validate(&forged, &bundles, &["openshell"]).is_err());

    claims["exp"] = json!(now - 300);
    let expired = openshell_crypto::jwt::encode(&header, &claims, &signing_key).unwrap();
    assert!(JwtSvid::parse_and_validate(&expired, &bundles, &["openshell"]).is_err());
}
