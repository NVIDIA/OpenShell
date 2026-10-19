// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cloudflare gateway registration behavior that needs no external network.

mod common;

use common::{run, run_isolated};

#[test]
fn gateway_add_creates_cloudflare_metadata_and_selects_gateway() {
    let config_dir = tempfile::tempdir().expect("create user config dir");
    let system_dir = tempfile::tempdir().expect("create system config dir");

    let output = run(
        config_dir.path(),
        system_dir.path(),
        &[
            "gateway",
            "add",
            "https://my-gateway.example.com",
            "--name",
            "test-cf-gw",
        ],
    );
    assert_eq!(output.code, 0, "gateway add:\n{}", output.combined);

    let metadata_path = config_dir
        .path()
        .join("openshell/gateways/test-cf-gw/metadata.json");
    let metadata: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&metadata_path).expect("read Cloudflare gateway metadata"),
    )
    .expect("parse Cloudflare gateway metadata");
    assert_eq!(metadata["auth_mode"], "cloudflare_jwt");
    assert_eq!(
        metadata["gateway_endpoint"],
        "https://my-gateway.example.com"
    );
    assert_eq!(metadata["name"], "test-cf-gw");
    assert_eq!(metadata["is_remote"], true);

    let active = std::fs::read_to_string(config_dir.path().join("openshell/active_gateway"))
        .expect("read active gateway");
    assert_eq!(active.trim(), "test-cf-gw");
    assert!(
        output.combined.contains("test-cf-gw") && output.combined.contains("added"),
        "{}",
        output.combined
    );
}

#[test]
fn gateway_add_derives_cloudflare_name_from_hostname() {
    let config_dir = tempfile::tempdir().expect("create user config dir");
    let system_dir = tempfile::tempdir().expect("create system config dir");

    let output = run(
        config_dir.path(),
        system_dir.path(),
        &["gateway", "add", "https://my-special-gateway.brevlab.com"],
    );
    assert_eq!(output.code, 0, "gateway add:\n{}", output.combined);
    assert!(
        config_dir
            .path()
            .join("openshell/gateways/my-special-gateway.brevlab.com/metadata.json")
            .exists()
    );
}

#[test]
fn ssh_gateway_shorthand_conflicts_with_local_type() {
    let local = run_isolated(&["gateway", "add", "ssh://user@host:8080", "--local"]);
    assert_ne!(local.code, 0, "ssh:// with --local should fail");
}

#[test]
fn ssh_gateway_shorthand_conflicts_with_explicit_remote() {
    let remote = run_isolated(&[
        "gateway",
        "add",
        "ssh://user@host:8080",
        "--remote",
        "user@host",
    ]);
    assert_ne!(remote.code, 0, "ssh:// with --remote should fail");
}

#[test]
fn ssh_gateway_shorthand_requires_port() {
    let output = run_isolated(&["gateway", "add", "ssh://user@host"]);
    assert_ne!(output.code, 0, "ssh:// without port should fail");
    assert!(output.combined.contains("port"), "{}", output.combined);
}
