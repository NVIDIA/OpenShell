// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

mod common;

#[test]
fn policy_lint_runs_offline_and_reports_file_errors() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("policy.yaml");
    let path = file.to_str().unwrap();
    let cases = [
        (
            "version: 1\n",
            true,
            vec!["Policy is valid (offline)", "Gateway checks"],
        ),
        ("process: {}\n", false, vec!["version"]),
        ("version: 1\nunknown: true\n", false, vec!["unknown"]),
        (
            "version: 1\nprocess:\n  run_as_user: '0'\n  run_as_group: root\nfilesystem_policy:\n  read_write: [relative, /]\n",
            false,
            vec![
                "run_as_user",
                "run_as_group",
                "path must be absolute",
                "overly broad",
            ],
        ),
        (
            "version: 1\nnetwork_policies:\n  _provider_private:\n    endpoints: []\n",
            false,
            vec!["reserved '_provider_'", "--base"],
        ),
        (
            "version: 1\nnetwork_policies:\n  bound:\n    endpoints:\n      - host: example.com\n        port: 443\n        credential_binding: {provider: ' '}\n",
            false,
            vec!["credential_binding.provider"],
        ),
        (
            "version: 1\nprocess:\n  run_as_user: '0'\nnetwork_middlewares:\n  redact:\n    middleware: openshell/regex\n    order: 1\n    endpoints: {include: [example.com]}\n    config: {mode: allow}\n",
            false,
            vec!["mode: redact", "run_as_user"],
        ),
        (
            "version: 1\nnetwork_policies:\n  conflict:\n    endpoints:\n      - {host: example.com, port: 443}\n      - {host: example.com, port: 443, tls: skip}\n",
            false,
            vec!["overlap", "conflicting"],
        ),
    ];
    for (yaml, valid, messages) in cases {
        std::fs::write(&file, yaml).unwrap();
        for args in [
            vec!["policy", "lint", path],
            vec![
                "--gateway-endpoint",
                "http://127.0.0.1:1",
                "policy",
                "lint",
                path,
            ],
        ] {
            let output = common::run_isolated(&args);
            assert_eq!(output.code == 0, valid, "{yaml}\n{}", output.combined);
            assert!(
                !output.combined.contains("failed to connect"),
                "{}",
                output.combined
            );
            for message in &messages {
                assert!(
                    output.combined.contains(message),
                    "expected {message}: {}",
                    output.combined
                );
            }
        }
    }
    std::fs::write(
        &file,
        format!(
            "version: 1\nnetwork_policies:\n  large:\n    name: {}\n",
            "x".repeat(openshell_policy::MAX_AUTHORED_POLICY_SIZE)
        ),
    )
    .unwrap();
    let oversized = common::run_isolated(&["policy", "lint", path]);
    assert_ne!(oversized.code, 0);
    assert!(
        oversized
            .combined
            .contains("policy serialized size exceeds maximum"),
        "{}",
        oversized.combined
    );
    let missing = dir.path().join("missing.yaml");
    assert_ne!(
        common::run_isolated(&["policy", "lint", missing.to_str().unwrap()]).code,
        0
    );
}
