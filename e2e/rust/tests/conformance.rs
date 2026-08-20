// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Run the shared driver-agnostic conformance baseline against the gateway
//! registered by the surrounding e2e environment.

use miette::Result;
use openshell_e2e::conformance::ConnectionOptions;
use std::path::PathBuf;

#[tokio::test]
async fn gateway_conformance() -> Result<()> {
    let gateway_endpoint = required_env("OPENSHELL_GATEWAY_ENDPOINT")?;

    openshell_e2e::conformance::conformance_run(
        &gateway_endpoint,
        &ConnectionOptions {
            tls_ca: optional_env("OPENSHELL_CONFORMANCE_TLS_CA").map(PathBuf::from),
            tls_cert: optional_env("OPENSHELL_CONFORMANCE_TLS_CERT").map(PathBuf::from),
            tls_key: optional_env("OPENSHELL_CONFORMANCE_TLS_KEY").map(PathBuf::from),
        },
        None,
        conformance_timeout(),
        "table",
    )
    .await
}

fn optional_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn required_env(name: &str) -> Result<String> {
    optional_env(name).ok_or_else(|| miette::miette!("{name} must be set by the e2e harness"))
}

fn conformance_timeout() -> u64 {
    std::env::var("OPENSHELL_CONFORMANCE_TIMEOUT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(300)
}
