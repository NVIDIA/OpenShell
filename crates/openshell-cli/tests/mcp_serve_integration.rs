// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `openshell mcp serve` writes nothing but JSON-RPC messages to stdout, even
//! with verbose logging and no usable gateway.

use std::io::Write;
use std::process::{Command, Stdio};

fn serve(extra_args: &[&str], envs: &[(&str, &str)]) -> (Vec<String>, String) {
    let config_dir = tempfile::tempdir().unwrap();
    let system_dir = tempfile::tempdir().unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_openshell"));
    command
        .args(extra_args)
        .args(["mcp", "serve"])
        .env("XDG_CONFIG_HOME", config_dir.path())
        .env("HOME", config_dir.path())
        .env("OPENSHELL_SYSTEM_GATEWAY_DIR", system_dir.path())
        .env("OPENSHELL_NO_BROWSER", "1")
        .env_remove("OPENSHELL_GATEWAY")
        .env_remove("OPENSHELL_GATEWAY_ENDPOINT")
        .env_remove("RUST_LOG")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in envs {
        command.env(name, value);
    }
    let mut child = command.spawn().expect("run openshell mcp serve");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            concat!(
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#,
                "\n",
                r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
                "\n",
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
                "\n",
            )
            .as_bytes(),
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    (stdout.lines().map(str::to_string).collect(), stderr)
}

fn assert_only_json_rpc(lines: &[String], stderr: &str) {
    assert_eq!(lines.len(), 2, "stdout: {lines:?}\nstderr: {stderr}");
    for line in lines {
        let message: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|_| panic!("not JSON-RPC: {line}"));
        assert_eq!(message["jsonrpc"], "2.0", "{line}");
    }
}

#[test]
fn without_a_gateway_every_call_gets_a_json_rpc_error() {
    let (lines, stderr) = serve(&["-vvv"], &[]);
    assert_only_json_rpc(&lines, &stderr);
    assert!(lines[0].contains("No active gateway"), "{lines:?}");
}

#[test]
fn with_an_unreachable_gateway_logs_stay_on_stderr() {
    let (lines, stderr) = serve(&["-vvv", "--gateway-endpoint", "http://127.0.0.1:9"], &[]);
    assert_only_json_rpc(&lines, &stderr);
    assert!(lines[0].contains("cannot reach the gateway"), "{lines:?}");
}
