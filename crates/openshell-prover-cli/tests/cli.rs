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

fn check_json(candidate: &str, boundary: &str) -> Output {
    run(&[
        "check",
        fixture(candidate).to_str().expect("UTF-8 fixture path"),
        "--boundary",
        fixture(boundary).to_str().expect("UTF-8 fixture path"),
        "--output",
        "json",
    ])
}

#[test]
fn query_containment_and_counterexample_are_exposed_in_cli() {
    let within = check_json("query-upload.yaml", "query-any.yaml");
    assert_eq!(
        within.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&within.stdout)
    );
    let denied = check_json("query-receive.yaml", "query-upload.yaml");
    assert_eq!(
        denied.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&denied.stdout)
    );
    let value: Value = serde_json::from_slice(&denied.stdout).unwrap();
    assert_eq!(
        value["counterexample"]["query_params"]["service"],
        serde_json::json!(["git-receive-pack"])
    );
    let text = run(&[
        "check",
        fixture("query-receive.yaml").to_str().unwrap(),
        "--boundary",
        fixture("query-upload.yaml").to_str().unwrap(),
    ]);
    assert_eq!(text.status.code(), Some(1));
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(
        text.contains("query_params=") && text.contains("git-receive-pack"),
        "{text}"
    );
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
    let output = check_json("candidate-contained.yaml", "boundary.yaml");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let value: Value = serde_json::from_slice(&output.stdout).expect("single JSON object");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["check"], "boundary");
    assert_eq!(value["result"], "within_boundary");
    assert_eq!(value["exit_code"], 0);
    assert_eq!(
        value["coverage"],
        serde_json::json!({
            "domains": ["filesystem", "network_l4", "network_rest", "process", "landlock"]
        })
    );
    assert!(value.get("scope").is_none());
    assert!(value["counterexample"].is_null());
}

#[test]
fn contained_policy_returns_stable_text_coverage_and_zero() {
    let output = run(&[
        "check",
        fixture("candidate-contained.yaml")
            .to_str()
            .expect("UTF-8 fixture path"),
        "--boundary",
        fixture("boundary.yaml")
            .to_str()
            .expect("UTF-8 fixture path"),
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8(output.stdout).expect("UTF-8 text output"),
        "result: within_boundary\ncoverage: domains=filesystem,network_l4,network_rest,process,landlock\n"
    );
}

#[test]
fn exceeding_policy_returns_counterexample_and_one() {
    let output = check_json("candidate-exceeds.yaml", "boundary-no-write.yaml");
    assert_eq!(
        output.status.code(),
        Some(1),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("single JSON object");
    assert_eq!(value["result"], "exceeds_boundary");
    assert_eq!(value["exit_code"], 1);
    assert_eq!(value["counterexample"]["domain"], "filesystem");
}

#[test]
fn counterexamples_have_stable_json_shapes() {
    for (candidate, boundary, expected) in [
        (
            "candidate-process-root.yaml",
            "boundary-execution.yaml",
            serde_json::json!({
                "domain": "process",
                "field": "run_as_user",
                "boundary": "sandbox",
                "candidate": "root"
            }),
        ),
        (
            "candidate-landlock-best-effort.yaml",
            "boundary-execution.yaml",
            serde_json::json!({
                "domain": "landlock",
                "boundary": "hard_requirement",
                "candidate": "best_effort"
            }),
        ),
        (
            "candidate-ipv6.yaml",
            "boundary-empty.yaml",
            serde_json::json!({
                "domain": "network",
                "binary": null,
                "ancestor_binary": null,
                "binary_identity_required": false,
                "host": "api.example.com",
                "destination_ip": "2001:db8::",
                "trusted_gateway": false,
                "port": 443,
                "protocol": "l4",
                "method": null,
                "path": null
            }),
        ),
    ] {
        let output = check_json(candidate, boundary);
        assert_eq!(
            output.status.code(),
            Some(1),
            "candidate={candidate}, stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value = serde_json::from_slice(&output.stdout).expect("single JSON object");
        assert_eq!(value["counterexample"], expected, "candidate={candidate}");
    }
}

#[test]
fn unsupported_policy_returns_reason_and_three() {
    let output = check_json("unsupported.yaml", "boundary.yaml");
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
fn unsupported_network_surfaces_fail_closed_at_the_cli_boundary() {
    let cases = [
        (
            "l4",
            "        path: /v1\n",
            "mixes REST controls into L4 authority",
        ),
        (
            "rest",
            "        protocol: rest\n        enforcement: log\n        access: full\n",
            "uses REST without enforced inspection",
        ),
        (
            "graphql",
            "        protocol: rest\n        enforcement: enforce\n        access: full\n        persisted_queries: allow-list\n",
            "uses authority outside the initial model",
        ),
        (
            "json-rpc",
            "        protocol: rest\n        enforcement: enforce\n        access: full\n        json_rpc: {}\n",
            "uses authority outside the initial model",
        ),
        (
            "mcp",
            "        protocol: mcp\n        enforcement: enforce\n        access: full\n        mcp: {}\n",
            "uses authority outside the initial model",
        ),
    ];

    for (surface, endpoint_fields, expected_reason) in cases {
        let path = std::env::temp_dir().join(format!(
            "openshell-prover-unsupported-{surface}-{}.yaml",
            std::process::id()
        ));
        fs::write(
            &path,
            format!(
                "version: 1\nnetwork_policies:\n  n:\n    endpoints:\n      - host: api.example.com\n        port: 443\n{endpoint_fields}    binaries: [{{ path: /usr/bin/curl }}]\n"
            ),
        )
        .expect("write unsupported surface policy");

        let output = run(&[
            "check",
            path.to_str().expect("UTF-8 temporary path"),
            "--boundary",
            fixture("boundary-empty.yaml").to_str().unwrap(),
            "--output",
            "json",
        ]);
        fs::remove_file(path).expect("remove unsupported surface policy");

        assert_eq!(
            output.status.code(),
            Some(3),
            "{surface} stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value = serde_json::from_slice(&output.stdout).expect("single JSON object");
        assert_eq!(value["result"], "unsupported", "{surface}: {value}");
        assert_eq!(
            value["reason_code"], "unsupported_policy_shape",
            "{surface}: {value}"
        );
        assert!(
            value["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains(expected_reason)),
            "{surface}: {value}"
        );
    }
}

#[test]
fn canonical_schema_errors_fail_closed_in_both_inputs() {
    let cases = [
        "version: 1\nmetadata: { policy_id: boundary }\n",
        "version: 1\nfilesystem_policy: null\n",
        "version: 1\nnetwork_policies:\n  n:\n    endpoints: [{ host: api.example.com, port: 443, review: { required: true } }]\n",
        "version: 1\nnetwork_policies:\n  n:\n    endpoints: [{ rules: [{ allow: { method: GET, review: {} } }] }]\n",
        "version: 1\nnetwork_policies:\n  n:\n    endpoints: [{ credential_binding: { provider: demo, future: true } }]\n",
        "version: 1\nnetwork_policies:\n  n:\n    endpoints: [{ protocol: rest, mcp: {} }]\n",
        r#"{"version":1,"version":1}"#,
        r#"{"version":1,"future_authority":true}"#,
    ];
    let path = std::env::temp_dir().join(format!(
        "openshell-prover-schema-errors-{}.yaml",
        std::process::id()
    ));
    let empty = fixture("boundary-empty.yaml");
    for source in cases {
        fs::write(&path, source).expect("write invalid authored policy");
        for (candidate, boundary) in [(&path, &empty), (&empty, &path)] {
            let output = run(&[
                "check",
                candidate.to_str().unwrap(),
                "--boundary",
                boundary.to_str().unwrap(),
                "--output",
                "json",
            ]);
            assert_eq!(output.status.code(), Some(2), "source={source}");
            assert!(output.stderr.is_empty());
            let value: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(value["result"], "error");
            assert_eq!(value["reason_code"], "invalid_input");
            assert!(value["counterexample"].is_null());
        }
    }
    fs::remove_file(path).expect("remove invalid authored policy");
}

#[test]
fn underscore_host_exceeds_an_empty_boundary() {
    let output = check_json("candidate-underscore-host.yaml", "boundary-empty.yaml");
    assert_eq!(
        output.status.code(),
        Some(1),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("single JSON object");
    assert_eq!(value["result"], "exceeds_boundary");
    assert_eq!(value["counterexample"]["host"], "api_internal.example.com");
}

#[test]
fn non_ascii_network_literals_are_unsupported_in_both_inputs() {
    for (candidate, boundary, input_label) in [
        (
            "candidate-unicode-network-selector.yaml",
            "boundary-empty.yaml",
            "candidate",
        ),
        (
            "boundary-empty.yaml",
            "candidate-unicode-network-selector.yaml",
            "boundary",
        ),
    ] {
        let output = check_json(candidate, boundary);
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
        "--boundary",
        fixture("boundary-empty.yaml").to_str().unwrap(),
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
        "--boundary",
        fixture("boundary-empty.yaml").to_str().unwrap(),
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
fn over_limit_mixed_protocol_policy_is_rejected_before_shape_validation() {
    let path = std::env::temp_dir().join(format!(
        "openshell-prover-resource-limit-{}.yaml",
        std::process::id()
    ));
    let mut source = String::from("version: 1\nnetwork_policies:\n  mixed:\n    endpoints:\n");
    for index in 0..2_500 {
        writeln!(
            source,
            "      - {{ host: l4-{index}.example.com, port: 443 }}"
        )
        .unwrap();
    }
    for index in 0..2_500 {
        let host = if index == 2_499 {
            "l4-0.example.com".to_owned()
        } else {
            format!("rest-{index}.example.com")
        };
        writeln!(
            source,
            "      - {{ host: {host}, port: 443, protocol: rest, enforcement: enforce, access: read-only }}"
        )
        .unwrap();
    }
    fs::write(&path, source).expect("write resource-limit policy");

    let output = run(&[
        "check",
        path.to_str().expect("UTF-8 temporary path"),
        "--boundary",
        fixture("boundary.yaml").to_str().unwrap(),
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
    let output = check_json("invalid.yaml", "boundary.yaml");
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
        "--boundary",
        fixture("boundary.yaml").to_str().unwrap(),
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
fn removed_maximum_option_is_rejected() {
    let output = run(&[
        "check",
        fixture("candidate-contained.yaml").to_str().unwrap(),
        "--maximum",
        fixture("boundary.yaml").to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unexpected argument '--maximum'"),
        "{stderr}"
    );
}

#[test]
fn timeout_must_be_positive() {
    let output = run(&[
        "check",
        fixture("candidate-contained.yaml").to_str().unwrap(),
        "--boundary",
        fixture("boundary.yaml").to_str().unwrap(),
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
        "--boundary",
        fixture("boundary.yaml").to_str().unwrap(),
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
            "--boundary",
            fixture("boundary.yaml").to_str().unwrap(),
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
    let boundary = directory.join("boundary.yaml");
    fs::write(
        &candidate,
        policy(vec!["/route*/**/tail*".into()]).to_string(),
    )
    .unwrap();
    fs::write(
        &boundary,
        policy(
            (0..300)
                .map(|index| format!("/route{index}/**/tail*"))
                // Cover the bounded concrete-witness sample so this fixture
                // still exercises interruption of the unrestricted solver.
                .chain(std::iter::once("/routea/**/tail*".to_owned()))
                .collect(),
        )
        .to_string(),
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_openshell-prover"))
        .args([
            "check",
            candidate.to_str().expect("UTF-8 temporary path"),
            "--boundary",
            boundary.to_str().expect("UTF-8 temporary path"),
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
        let boundary = directory.join("boundary.yaml");
        for (file, path) in [(&candidate, safe.join("link")), (&boundary, safe.clone())] {
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
            "--boundary",
            boundary.to_str().unwrap(),
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
