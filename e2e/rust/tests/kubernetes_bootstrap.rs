// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-kubernetes")]

use openshell_e2e::harness::{cli::run_cli, sandbox::SandboxGuard};

async fn workload_secret(name: &str) -> String {
    let namespace =
        std::env::var("OPENSHELL_E2E_SANDBOX_NAMESPACE").unwrap_or_else(|_| "openshell".into());
    let mut command = tokio::process::Command::new("kubectl");
    if let Ok(context) = std::env::var("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE") {
        command.args(["--context", &context]);
    }
    let output = command
        .args([
            "-n",
            &namespace,
            "get",
            "sandboxes.agents.x-k8s.io",
            "-l",
            &format!("openshell.ai/sandbox-name={name}"),
            "-o",
            "json",
        ])
        .output()
        .await
        .unwrap();
    assert!(output.status.success());
    let list: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let containers = list["items"][0]["spec"]["podTemplate"]["spec"]["containers"]
        .as_array()
        .unwrap();
    let agent = containers
        .iter()
        .find(|container| container["name"] == "agent")
        .unwrap();
    assert_eq!(agent["command"][1], "--bootstrap-remote");
    let reference = agent["env"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == "OPENSHELL_BOUNDARY_BOOTSTRAP_TOKEN")
        .unwrap();
    let secret = reference["valueFrom"]["secretKeyRef"]["name"]
        .as_str()
        .unwrap();
    let mut command = tokio::process::Command::new("kubectl");
    if let Ok(context) = std::env::var("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE") {
        command.args(["--context", &context]);
    }
    let output = command
        .args([
            "-n",
            &namespace,
            "get",
            "secret",
            secret,
            "-o",
            "go-template={{range $key, $value := .data}}{{$key}}{{\"\\n\"}}{{end}}",
        ])
        .output()
        .await
        .unwrap();
    assert!(output.status.success());
    let keys = String::from_utf8(output.stdout).unwrap();
    assert!(keys.lines().any(|key| key == "bootstrap-token"));
    assert!(!keys.lines().any(|key| key == "boundary.json"));
    secret.to_string()
}

#[tokio::test]
async fn token_bootstrap_starts_and_restarts_without_a_boundary_config_file() {
    if std::env::var("OPENSHELL_E2E_BOOTSTRAP_OVER_WIRE").as_deref() != Ok("1") {
        return;
    }
    let mut sandbox = SandboxGuard::create(&[])
        .await
        .expect("create token-bootstrapped sandbox");
    let first_secret = workload_secret(&sandbox.name).await;
    let check = [
        "sh",
        "-c",
        "test ! -e /.openshell/state/bootstrap/boundary.json && test -z \"${OPENSHELL_BOUNDARY_BOOTSTRAP_TOKEN+x}\" && echo bootstrap-ok",
    ];
    assert!(sandbox.exec(&check).await.unwrap().contains("bootstrap-ok"));
    for operation in ["stop", "start"] {
        let (output, code) = run_cli(&["sandbox", operation, &sandbox.name]).await;
        assert_eq!(code, 0, "{operation}: {output}");
    }
    assert_ne!(first_secret, workload_secret(&sandbox.name).await);
    assert!(sandbox.exec(&check).await.unwrap().contains("bootstrap-ok"));
    sandbox.cleanup().await;
}
