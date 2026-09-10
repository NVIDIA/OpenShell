// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

const DEAD_PID: u32 = u32::MAX;

fn run_forward_list(config_dir: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_openshell"));
    for (key, _) in std::env::vars().filter(|(key, _)| key.starts_with("OPENSHELL_")) {
        command.env_remove(key);
    }
    command
        .args(["forward", "list"])
        .args(args)
        .env("XDG_CONFIG_HOME", config_dir)
        .env("HOME", config_dir)
        .output()
        .expect("run openshell forward list")
}

fn write_dead_forward(config_dir: &Path) {
    let forward_dir = config_dir.join("openshell/forwards");
    fs::create_dir_all(&forward_dir).expect("create forward directory");
    fs::write(
        forward_dir.join("my-sandbox-8443.pid"),
        format!("{DEAD_PID}\tsandbox-id\t0.0.0.0"),
    )
    .expect("write forward PID record");
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "forward list failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn forward_list_json_emits_machine_readable_records() {
    let config_dir = tempfile::tempdir().expect("create config directory");
    write_dead_forward(config_dir.path());

    let output = run_forward_list(config_dir.path(), &["--output", "json"]);
    assert_success(&output);
    assert!(
        output.stderr.is_empty(),
        "structured output wrote to stderr"
    );
    assert!(
        !output.stdout.contains(&0x1b),
        "JSON contained ANSI escapes"
    );

    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout should contain only JSON");
    assert_eq!(
        value,
        serde_json::json!([{
            "sandbox": "my-sandbox",
            "bind_address": "0.0.0.0",
            "port": 8443,
            "pid": DEAD_PID,
            "alive": false,
        }])
    );
}

#[test]
fn forward_list_yaml_emits_equivalent_records() {
    let config_dir = tempfile::tempdir().expect("create config directory");
    write_dead_forward(config_dir.path());

    let output = run_forward_list(config_dir.path(), &["-o", "yaml"]);
    assert_success(&output);
    assert!(
        output.stderr.is_empty(),
        "structured output wrote to stderr"
    );
    assert!(
        !output.stdout.contains(&0x1b),
        "YAML contained ANSI escapes"
    );

    let value: serde_json::Value =
        serde_yml::from_slice(&output.stdout).expect("stdout should contain only YAML");
    assert_eq!(
        value,
        serde_json::json!([{
            "sandbox": "my-sandbox",
            "bind_address": "0.0.0.0",
            "port": 8443,
            "pid": DEAD_PID,
            "alive": false,
        }])
    );
}

#[test]
fn forward_list_structured_output_emits_empty_collections() {
    let config_dir = tempfile::tempdir().expect("create config directory");

    for format in ["json", "yaml"] {
        let output = run_forward_list(config_dir.path(), &["--output", format]);
        assert_success(&output);
        assert!(output.stderr.is_empty(), "{format} output wrote to stderr");

        let value: serde_json::Value = match format {
            "json" => serde_json::from_slice(&output.stdout).expect("parse empty JSON collection"),
            "yaml" => serde_yml::from_slice(&output.stdout).expect("parse empty YAML collection"),
            _ => unreachable!(),
        };
        assert_eq!(value, serde_json::json!([]));
    }
}

#[test]
fn forward_list_table_output_keeps_existing_columns() {
    let config_dir = tempfile::tempdir().expect("create config directory");
    write_dead_forward(config_dir.path());

    let output = run_forward_list(config_dir.path(), &[]);
    assert_success(&output);
    assert!(output.stderr.is_empty(), "table output wrote to stderr");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let rows: Vec<Vec<&str>> = stdout
        .lines()
        .map(|line| line.split_whitespace().collect())
        .collect();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0], vec!["SANDBOX", "BIND", "PORT", "PID", "STATUS"]);
    assert_eq!(
        &rows[1][..4],
        ["my-sandbox", "0.0.0.0", "8443", "4294967295"]
    );
    assert!(rows[1][4].contains("dead"));
}

#[test]
fn forward_list_help_documents_output_flag() {
    let config_dir = tempfile::tempdir().expect("create config directory");
    let output = run_forward_list(config_dir.path(), &["--help"]);
    assert_success(&output);

    let stdout = String::from_utf8(output.stdout).expect("help should be UTF-8");
    assert!(stdout.contains("-o, --output <OUTPUT>"), "{stdout}");
    assert!(stdout.contains("[default: table]"), "{stdout}");
    assert!(
        stdout.contains("possible values: table, yaml, json"),
        "{stdout}"
    );
}
