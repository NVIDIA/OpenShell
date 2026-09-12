// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
#[cfg(unix)]
use std::process::Stdio;
use std::process::{Command, Output};
#[cfg(unix)]
use std::thread;
#[cfg(unix)]
use std::time::Duration;

use serde_json::Value;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_openshell-prover"))
        .args(args)
        .output()
        .expect("run openshell-prover")
}

fn check_json(candidate: &str, maximum: &str) -> Output {
    run(&[
        "check",
        fixture(candidate).to_str().expect("UTF-8 fixture path"),
        "--maximum",
        fixture(maximum).to_str().expect("UTF-8 fixture path"),
        "--output",
        "json",
    ])
}

#[test]
fn help_and_version_succeed() {
    for args in [
        &["--help"][..],
        &["--version"][..],
        &["check", "--help"][..],
    ] {
        let output = run(args);
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.stdout.is_empty());
    }
}

#[test]
fn bare_invocation_shows_help() {
    let output = run(&[]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Usage:"));
}

#[test]
fn contained_policy_returns_stable_json_and_zero() {
    let output = check_json("candidate-contained.yaml", "maximum.yaml");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let value: Value = serde_json::from_slice(&output.stdout).expect("single JSON object");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["check"], "maximum_boundary");
    assert_eq!(value["result"], "within_max");
    assert_eq!(value["exit_code"], 0);
    assert_eq!(
        value["scope"],
        serde_json::json!({
            "model_version": "maximum-boundary-v1",
            "policy_version": 1,
            "domains": ["filesystem", "network_l4", "network_rest"]
        })
    );
    assert!(value["counterexample"].is_null());
}

#[test]
fn exceeding_policy_returns_counterexample_and_one() {
    let output = check_json("candidate-exceeds.yaml", "maximum-no-write.yaml");
    assert_eq!(
        output.status.code(),
        Some(1),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("single JSON object");
    assert_eq!(value["result"], "exceeds_max");
    assert_eq!(value["exit_code"], 1);
    assert_eq!(value["counterexample"]["domain"], "filesystem");
}

#[test]
fn unsupported_policy_returns_reason_and_three() {
    let output = check_json("unsupported.yaml", "maximum.yaml");
    assert_eq!(
        output.status.code(),
        Some(3),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("single JSON object");
    assert_eq!(value["result"], "unsupported");
    assert_eq!(value["exit_code"], 3);
    assert!(value["reason_code"].is_string());
    assert!(value["reason"].is_string());
}

#[test]
fn underscore_host_exceeds_an_empty_maximum() {
    let output = check_json("candidate-underscore-host.yaml", "maximum-empty.yaml");
    assert_eq!(
        output.status.code(),
        Some(1),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("single JSON object");
    assert_eq!(value["result"], "exceeds_max");
    assert_eq!(value["counterexample"]["host"], "api_internal.example.com");
}

#[test]
fn non_ascii_network_literals_are_unsupported_in_both_inputs() {
    for (candidate, maximum, input_label) in [
        (
            "candidate-unicode-network-selector.yaml",
            "maximum-empty.yaml",
            "candidate",
        ),
        (
            "maximum-empty.yaml",
            "candidate-unicode-network-selector.yaml",
            "maximum",
        ),
    ] {
        let output = check_json(candidate, maximum);
        assert_eq!(
            output.status.code(),
            Some(3),
            "{input_label} stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value = serde_json::from_slice(&output.stdout).expect("single JSON object");
        assert_eq!(value["result"], "unsupported");
        assert_eq!(value["reason_code"], "unsupported_policy_shape");
        assert!(
            value["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains(input_label) && reason.contains("non-ASCII")),
            "{value}"
        );
    }

    let output = run(&[
        "check",
        fixture("candidate-unicode-network-selector.yaml")
            .to_str()
            .unwrap(),
        "--maximum",
        fixture("maximum-empty.yaml").to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout).expect("UTF-8 text output");
    assert!(text.contains("result: unsupported"), "{text}");
    assert!(text.contains("candidate policy"), "{text}");
    assert!(text.contains("non-ASCII"), "{text}");
}

#[test]
fn embedded_nul_network_literal_is_unsupported_without_panicking() {
    let path = std::env::temp_dir().join(format!(
        "openshell-prover-nul-selector-{}.yaml",
        std::process::id()
    ));
    fs::write(
        &path,
        "version: 1\nnetwork_policies:\n  n:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        rules: [{ allow: { method: \"G\\0ET\", path: '/**' } }]\n    binaries: [{ path: /usr/bin/curl }]\n",
    )
    .expect("write NUL selector policy");
    let output = run(&[
        "check",
        path.to_str().expect("UTF-8 temporary path"),
        "--maximum",
        fixture("maximum-empty.yaml").to_str().unwrap(),
        "--output",
        "json",
    ]);
    fs::remove_file(path).expect("remove NUL selector policy");

    assert_eq!(output.status.code(), Some(3));
    assert!(output.stderr.is_empty());
    let value: Value = serde_json::from_slice(&output.stdout).expect("single JSON object");
    assert_eq!(value["result"], "unsupported");
    assert_eq!(value["reason_code"], "unsupported_policy_shape");
    assert!(value["reason"].as_str().unwrap().contains("NUL"));
}

#[test]
fn resource_exhaustion_is_inconclusive_and_returns_three() {
    let path = std::env::temp_dir().join(format!(
        "openshell-prover-resource-limit-{}.yaml",
        std::process::id()
    ));
    let mut source = String::from("version: 1\nnetwork_policies:\n");
    for index in 0..=1_024 {
        writeln!(source, "  rule-{index}: {{}}").unwrap();
    }
    fs::write(&path, source).expect("write resource-limit policy");

    let output = run(&[
        "check",
        path.to_str().expect("UTF-8 temporary path"),
        "--maximum",
        fixture("maximum.yaml").to_str().unwrap(),
        "--output",
        "json",
    ]);
    fs::remove_file(path).expect("remove resource-limit policy");

    assert_eq!(output.status.code(), Some(3));
    let value: Value = serde_json::from_slice(&output.stdout).expect("single JSON object");
    assert_eq!(value["result"], "inconclusive");
    assert_eq!(value["reason_code"], "resource_limit");
}

#[test]
fn invalid_json_mode_input_uses_error_envelope_and_two() {
    let output = check_json("invalid.yaml", "maximum.yaml");
    assert_eq!(
        output.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("single JSON object");
    assert_eq!(value["result"], "error");
    assert_eq!(value["exit_code"], 2);
    assert_eq!(value["reason_code"], "invalid_input");
}

#[test]
fn missing_json_mode_input_uses_error_envelope_and_two() {
    let output = run(&[
        "check",
        fixture("does-not-exist.yaml").to_str().unwrap(),
        "--maximum",
        fixture("maximum.yaml").to_str().unwrap(),
        "--output",
        "json",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let value: Value = serde_json::from_slice(&output.stdout).expect("single JSON object");
    assert_eq!(value["result"], "error");
    assert_eq!(value["reason_code"], "invalid_input");
    assert!(value["reason"].as_str().unwrap().contains("cannot open"));
}

#[test]
fn usage_errors_return_two() {
    let output = run(&["check"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("required"));
}

#[test]
fn timeout_must_be_positive() {
    let output = run(&[
        "check",
        fixture("candidate-contained.yaml").to_str().unwrap(),
        "--maximum",
        fixture("maximum.yaml").to_str().unwrap(),
        "--timeout",
        "0ms",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("positive"));
}

#[test]
fn text_diagnostics_escape_terminal_controls() {
    let output = run(&[
        "check",
        "missing\u{1b}[31m.yaml",
        "--maximum",
        fixture("maximum.yaml").to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(!output.stderr.contains(&0x1b));
    assert!(String::from_utf8_lossy(&output.stderr).contains("\\u{1b}"));
}

#[cfg(unix)]
#[test]
fn fifo_input_is_rejected_without_blocking() {
    use std::time::Instant;

    let path = std::env::temp_dir().join(format!("openshell-prover-fifo-{}", std::process::id()));
    nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRUSR).expect("create FIFO fixture");

    let mut child = Command::new(env!("CARGO_BIN_EXE_openshell-prover"))
        .args([
            "check",
            path.to_str().expect("UTF-8 temporary path"),
            "--maximum",
            fixture("maximum.yaml").to_str().unwrap(),
            "--output",
            "json",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start prover with FIFO input");

    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if child.try_wait().expect("poll prover").is_some() {
            break;
        }
        if Instant::now() >= deadline {
            child.kill().expect("terminate blocked prover");
            let _ = child.wait();
            fs::remove_file(&path).expect("remove FIFO fixture");
            panic!("prover blocked while opening a FIFO input");
        }
        thread::sleep(Duration::from_millis(10));
    }

    let output = child.wait_with_output().expect("collect prover output");
    fs::remove_file(path).expect("remove FIFO fixture");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let value: Value = serde_json::from_slice(&output.stdout).expect("single JSON object");
    assert_eq!(value["result"], "error");
    assert_eq!(value["reason_code"], "invalid_input");
    assert!(
        value["reason"]
            .as_str()
            .expect("string reason")
            .contains("not a regular file")
    );
}

#[cfg(unix)]
#[test]
fn sigint_interrupts_the_check_with_exit_130() {
    let directory = std::env::temp_dir().join(format!(
        "openshell-prover-cancellation-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).unwrap();
    let policy = |paths: Vec<String>| {
        serde_json::json!({
            "version": 1,
            "network_policies": {"many": {
                "binaries": [{"path": "/usr/bin/curl"}],
                "endpoints": [{"host": "api.example.com", "port": 443,
                    "protocol": "rest", "enforcement": "enforce",
                    "rules": paths.into_iter().map(|path| serde_json::json!({
                        "allow": {"method": "GET", "path": path}
                    })).collect::<Vec<_>>()
                }]
            }}
        })
    };
    let candidate = directory.join("candidate.yaml");
    let maximum = directory.join("maximum.yaml");
    fs::write(
        &candidate,
        policy(vec!["/route*/**/tail*".into()]).to_string(),
    )
    .unwrap();
    fs::write(
        &maximum,
        policy(
            (0..300)
                .map(|index| format!("/route{index}/**/tail*"))
                .collect(),
        )
        .to_string(),
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_openshell-prover"))
        .args([
            "check",
            candidate.to_str().expect("UTF-8 temporary path"),
            "--maximum",
            maximum.to_str().expect("UTF-8 temporary path"),
            "--output",
            "json",
            "--timeout",
            "10s",
        ])
        .stdout(Stdio::piped())
        .spawn()
        .expect("start cancellable prover");
    // Different policies force a real solve; an identical pair can exit via
    // the equality shortcut before SIGINT ever exercises Z3's signal handling.
    thread::sleep(Duration::from_millis(500));
    assert!(
        child.try_wait().unwrap().is_none(),
        "fixture must still be solving when interrupted"
    );
    let signal = Command::new("kill")
        .args(["-s", "INT", &child.id().to_string()])
        .status()
        .expect("send SIGINT");
    assert!(signal.success());
    let output = child.wait_with_output().expect("wait for cancelled prover");
    assert_eq!(output.status.code(), Some(130));
    let value: Value =
        serde_json::from_slice(&output.stdout).expect("structured cancellation JSON");
    assert_eq!(value["result"], "inconclusive");
    assert_eq!(value["reason_code"], "cancelled");
    assert_eq!(value["exit_code"], 130);
    fs::remove_dir_all(directory).expect("remove cancellation policies");
}

#[cfg(unix)]
#[test]
fn symlink_descendants_require_sandbox_path_resolution() {
    let directory =
        std::env::temp_dir().join(format!("openshell-prover-symlink-{}", std::process::id()));
    let safe = directory.join("safe");
    let outside = directory.join("outside");
    fs::create_dir_all(&safe).unwrap();
    fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, safe.join("link")).unwrap();
    for access in ["read_only", "read_write"] {
        let candidate = directory.join("candidate.yaml");
        let maximum = directory.join("maximum.yaml");
        for (file, path) in [(&candidate, safe.join("link")), (&maximum, safe.clone())] {
            fs::write(
                file,
                serde_json::json!({"version": 1, "filesystem_policy": {access: [path]}})
                    .to_string(),
            )
            .unwrap();
        }
        let output = run(&[
            "check",
            candidate.to_str().unwrap(),
            "--maximum",
            maximum.to_str().unwrap(),
            "--output",
            "json",
        ]);
        assert_eq!(output.status.code(), Some(3));
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["result"], "unsupported");
        assert_eq!(value["reason_code"], "unresolved_filesystem_path");
    }
    fs::remove_dir_all(directory).unwrap();
}
