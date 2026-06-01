// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Manual smoke test: exercise `openshell_sdk::oidc::{discover, refresh_token}`
//! against a live OIDC issuer (Keycloak in our case).
//!
//! Driven by `scripts/openshell-sdk-oidc-smoke.sh`, which fetches an initial
//! refresh token via the password grant and then runs this example.
//!
//! Env:
//!   OPENSHELL_OIDC_ISSUER         — e.g. http://localhost:8180/realms/openshell
//!   OPENSHELL_OIDC_CLIENT_ID      — e.g. openshell-cli
//!   OPENSHELL_OIDC_REFRESH_TOKEN  — refresh token from the issuer

use openshell_sdk::oidc::{RefreshTokenInput, discover, refresh_token};
use std::env;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), String> {
    let issuer = env("OPENSHELL_OIDC_ISSUER")?;
    let client_id = env("OPENSHELL_OIDC_CLIENT_ID")?;
    let refresh = env("OPENSHELL_OIDC_REFRESH_TOKEN")?;

    println!("    issuer    = {issuer}");
    println!("    client_id = {client_id}");

    println!("==> discover({issuer})");
    let discovery = discover(&issuer, false)
        .await
        .map_err(|e| format!("discover failed: {e}"))?;
    require(
        !discovery.token_endpoint.is_empty(),
        "token_endpoint should be non-empty",
    )?;
    require(
        !discovery.authorization_endpoint.is_empty(),
        "authorization_endpoint should be non-empty",
    )?;
    println!("    authorization_endpoint = {}", discovery.authorization_endpoint);
    println!("    token_endpoint         = {}", discovery.token_endpoint);

    println!("==> discover() accepts a trailing slash on the issuer");
    let trailing = format!("{}/", issuer.trim_end_matches('/'));
    discover(&trailing, false)
        .await
        .map_err(|e| format!("trailing-slash issuer should normalize: {e}"))?;

    println!("==> refresh_token() against the live token endpoint");
    let input = RefreshTokenInput::new(refresh.clone(), &issuer, &client_id);
    let output = refresh_token(&input)
        .await
        .map_err(|e| format!("refresh_token failed: {e}"))?;

    require(!output.access_token.is_empty(), "access_token should be non-empty")?;
    require(
        output.access_token.split('.').count() == 3,
        "access_token should look like a JWT (header.payload.signature)",
    )?;
    let preview: String = output.access_token.chars().take(24).collect();
    println!(
        "    access_token  = {preview}... ({} bytes)",
        output.access_token.len()
    );
    println!(
        "    refresh_token = {}",
        if output.refresh_token.is_some() {
            "<rotated by server>"
        } else {
            "<unchanged>"
        }
    );
    println!("    expires_at    = {:?}", output.expires_at);

    println!("==> ok");
    Ok(())
}

fn env(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("{name} is required"))
}

fn require(cond: bool, msg: &str) -> Result<(), String> {
    if cond { Ok(()) } else { Err(msg.to_string()) }
}
