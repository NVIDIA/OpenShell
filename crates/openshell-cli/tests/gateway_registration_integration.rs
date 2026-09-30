// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway registration and configuration behavior that needs no live gateway.

mod common;

use std::path::Path;

use common::{run, run_isolated};

fn write_gateway_metadata(
    root: &Path,
    name: &str,
    endpoint: &str,
    gateway_port: u16,
    is_remote: bool,
    auth_mode: &str,
) {
    let gateway_dir = root.join("gateways").join(name);
    std::fs::create_dir_all(&gateway_dir).expect("create gateway dir");
    let metadata = serde_json::json!({
        "name": name,
        "gateway_endpoint": endpoint,
        "gateway_port": gateway_port,
        "is_remote": is_remote,
        "auth_mode": auth_mode,
    });
    std::fs::write(
        gateway_dir.join("metadata.json"),
        serde_json::to_vec_pretty(&metadata).expect("serialize gateway metadata"),
    )
    .expect("write gateway metadata");
}

fn write_user_gateway_metadata(
    config_dir: &Path,
    name: &str,
    endpoint: &str,
    gateway_port: u16,
    is_remote: bool,
    auth_mode: &str,
) {
    write_gateway_metadata(
        &config_dir.join("openshell"),
        name,
        endpoint,
        gateway_port,
        is_remote,
        auth_mode,
    );
}

fn write_active_gateway(config_dir: &Path, name: &str) {
    let active_path = config_dir.join("openshell").join("active_gateway");
    std::fs::create_dir_all(active_path.parent().expect("active gateway parent"))
        .expect("create active gateway parent");
    std::fs::write(active_path, format!("{name}\n")).expect("write active gateway");
}

fn seed_gateway_sources(config_dir: &Path, system_dir: &Path) {
    write_user_gateway_metadata(
        config_dir,
        "alpha",
        "https://alpha.example.com",
        443,
        true,
        "cloudflare_jwt",
    );
    write_gateway_metadata(
        system_dir,
        "beta",
        "http://127.0.0.1:17670",
        17670,
        false,
        "plaintext",
    );
}

#[test]
fn status_without_gateway_prints_registration_hint() {
    let output = run_isolated(&["status"]);
    assert_eq!(
        output.code, 0,
        "status without a gateway should succeed:\n{}",
        output.combined
    );
    assert!(output.combined.contains("No gateway configured"));
    assert!(
        output.combined.contains("openshell gateway add <endpoint>"),
        "{}",
        output.combined
    );
}

#[test]
fn gateway_list_table_shows_user_and_system_sources() {
    let config_dir = tempfile::tempdir().expect("create user config dir");
    let system_dir = tempfile::tempdir().expect("create system config dir");
    seed_gateway_sources(config_dir.path(), system_dir.path());
    write_active_gateway(config_dir.path(), "alpha");

    let output = run(config_dir.path(), system_dir.path(), &["gateway", "list"]);
    assert_eq!(output.code, 0, "gateway list:\n{}", output.combined);
    assert!(output.combined.contains("SOURCE"), "{}", output.combined);

    let alpha = output
        .combined
        .lines()
        .find(|line| line.contains("alpha"))
        .expect("find alpha row");
    assert!(alpha.contains("user"), "{}", output.combined);

    let beta = output
        .combined
        .lines()
        .find(|line| line.contains("beta"))
        .expect("find beta row");
    assert!(beta.contains("system"), "{}", output.combined);
}

#[test]
fn gateway_list_json_includes_user_and_system_sources() {
    let config_dir = tempfile::tempdir().expect("create user config dir");
    let system_dir = tempfile::tempdir().expect("create system config dir");
    seed_gateway_sources(config_dir.path(), system_dir.path());

    let output = run(
        config_dir.path(),
        system_dir.path(),
        &["gateway", "list", "-o", "json"],
    );
    assert_eq!(output.code, 0, "gateway list -o json:\n{}", output.combined);

    let items: serde_json::Value =
        serde_json::from_str(&output.stdout).expect("parse gateway list JSON");
    let items = items.as_array().expect("gateway list JSON array");
    assert_eq!(items.len(), 2);
    assert_eq!(
        items.iter().find(|item| item["name"] == "alpha").unwrap()["source"],
        "user"
    );
    assert_eq!(
        items.iter().find(|item| item["name"] == "beta").unwrap()["source"],
        "system"
    );
}

#[test]
fn user_registration_can_shadow_system_gateway() {
    let config_dir = tempfile::tempdir().expect("create user config dir");
    let system_dir = tempfile::tempdir().expect("create system config dir");
    write_gateway_metadata(
        system_dir.path(),
        "beta",
        "http://127.0.0.1:17670",
        17670,
        false,
        "plaintext",
    );

    let added = run(
        config_dir.path(),
        system_dir.path(),
        &["gateway", "add", "http://127.0.0.1:17671", "--name", "beta"],
    );
    assert_eq!(added.code, 0, "gateway add:\n{}", added.combined);

    let listed = run(
        config_dir.path(),
        system_dir.path(),
        &["gateway", "list", "-o", "json"],
    );
    let items: serde_json::Value =
        serde_json::from_str(&listed.stdout).expect("parse gateway list JSON");
    let beta = items
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["name"] == "beta")
        .unwrap();
    assert_eq!(beta["source"], "user");
    assert_eq!(beta["endpoint"], "http://127.0.0.1:17671");
}

#[test]
fn gateway_remove_rejects_system_registration_and_preserves_it() {
    let config_dir = tempfile::tempdir().expect("create user config dir");
    let system_dir = tempfile::tempdir().expect("create system config dir");
    write_gateway_metadata(
        system_dir.path(),
        "beta",
        "http://127.0.0.1:17670",
        17670,
        false,
        "plaintext",
    );

    let removed = run(
        config_dir.path(),
        system_dir.path(),
        &["gateway", "remove", "beta"],
    );
    assert_ne!(removed.code, 0, "system gateway removal should fail");
    let normalized = removed
        .combined
        .replace(['│', '×'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        normalized.contains("installed by the system and cannot be removed from user config"),
        "{}",
        removed.combined
    );

    let listed = run(
        config_dir.path(),
        system_dir.path(),
        &["gateway", "list", "-o", "json"],
    );
    let items: serde_json::Value =
        serde_json::from_str(&listed.stdout).expect("parse gateway list JSON");
    let beta = items
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["name"] == "beta")
        .unwrap();
    assert_eq!(beta["source"], "system");
    assert_eq!(beta["endpoint"], "http://127.0.0.1:17670");
}

#[test]
fn gateway_add_rejects_duplicate_user_name() {
    let config_dir = tempfile::tempdir().expect("create user config dir");
    let system_dir = tempfile::tempdir().expect("create system config dir");

    let first = run(
        config_dir.path(),
        system_dir.path(),
        &["gateway", "add", "http://127.0.0.1:1", "--name", "my-gw"],
    );
    assert_eq!(first.code, 0, "first gateway add:\n{}", first.combined);

    let duplicate = run(
        config_dir.path(),
        system_dir.path(),
        &["gateway", "add", "http://127.0.0.1:2", "--name", "my-gw"],
    );
    assert_ne!(duplicate.code, 0, "duplicate gateway add should fail");
    assert!(
        duplicate.combined.contains("already exists"),
        "{}",
        duplicate.combined
    );
}
