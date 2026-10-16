// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-podman")]

#[path = "support/provider_refresh_handles.rs"]
mod support;

const PROVIDER_NAME: &str = "e2e-github-app-refresh-handle";
const PROFILE_ID: &str = "e2e-github-app-refresh-handle";

#[tokio::test]
async fn github_app_survives_rotations_and_reconfigure_revokes() -> Result<(), String> {
    let key = std::process::Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
        ])
        .output()
        .map_err(|error| format!("generate test app key: {error}"))?;
    if !key.status.success() {
        return Err("openssl could not generate the test GitHub App key".into());
    }
    let key = String::from_utf8(key.stdout).map_err(|error| error.to_string())?;
    support::exercise_refresh_handles(Some(&key)).await
}
