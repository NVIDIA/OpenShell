// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Lightweight Kubernetes helpers for e2e tests.
//!
//! These helpers intentionally shell out to `kubectl` so the e2e crate does not
//! need a Kubernetes client dependency. They inherit `KUBECONFIG` and, when
//! present, `OPENSHELL_E2E_KUBE_CONTEXT` from the wrapper.

use std::process::Stdio;
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::process::Command;
use tokio::time::sleep;

pub async fn kubectl(args: &[&str]) -> Result<String, String> {
    let mut cmd = Command::new("kubectl");
    if let Ok(context) = std::env::var("OPENSHELL_E2E_KUBE_CONTEXT")
        && !context.trim().is_empty()
    {
        cmd.arg("--context").arg(context);
    }
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = cmd
        .output()
        .await
        .map_err(|err| format!("failed to run kubectl {args:?}: {err}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}{stderr}");

    if !output.status.success() {
        return Err(format!(
            "kubectl {args:?} failed (exit {:?}):\n{combined}",
            output.status.code()
        ));
    }

    Ok(stdout)
}

pub async fn kubectl_json(args: &[&str]) -> Result<Value, String> {
    let output = kubectl(args).await?;
    serde_json::from_str(&output)
        .map_err(|err| format!("kubectl {args:?} did not return valid JSON: {err}\n{output}"))
}

pub async fn has_crd(plural: &str, group: &str) -> bool {
    let name = format!("{plural}.{group}");
    kubectl(&["get", "crd", &name]).await.is_ok()
}

pub async fn wait_for_jsonpath(
    namespace: &str,
    kind: &str,
    name: &str,
    jsonpath: &str,
    expected: &str,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let mut last_output: Option<String>;
    let output_arg = format!("jsonpath={jsonpath}");

    loop {
        match kubectl(&["get", kind, name, "-n", namespace, "-o", &output_arg]).await {
            Ok(output) => {
                let trimmed = output.trim().to_string();
                if trimmed == expected {
                    return Ok(());
                }
                last_output = Some(trimmed);
            }
            Err(err) => last_output = Some(err),
        }

        if Instant::now() >= deadline {
            let last_output = last_output.unwrap_or_else(|| "<no kubectl attempts>".to_string());
            return Err(format!(
                "timed out after {}s waiting for {kind}/{name} jsonpath {jsonpath} to equal {expected:?}. Last output:\n{last_output}",
                timeout.as_secs()
            ));
        }
        sleep(Duration::from_secs(2)).await;
    }
}

pub async fn wait_for_resource_by_label(
    namespace: &str,
    kind: &str,
    selector: &str,
    timeout: Duration,
) -> Result<Value, String> {
    let deadline = Instant::now() + timeout;
    let mut last_output: Option<String>;

    loop {
        match kubectl_json(&["get", kind, "-n", namespace, "-l", selector, "-o", "json"]).await {
            Ok(value) if !items(&value).is_empty() => return Ok(value),
            Ok(value) => last_output = Some(value.to_string()),
            Err(err) => last_output = Some(err),
        }

        if Instant::now() >= deadline {
            let last_output = last_output.unwrap_or_else(|| "<no kubectl attempts>".to_string());
            return Err(format!(
                "timed out after {}s waiting for {kind} in namespace {namespace} with selector {selector}. Last output:\n{last_output}",
                timeout.as_secs()
            ));
        }
        sleep(Duration::from_secs(2)).await;
    }
}

pub async fn wait_for_resource_absent_by_label(
    namespace: &str,
    kind: &str,
    selector: &str,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let mut last_output: Option<String>;

    loop {
        match kubectl_json(&["get", kind, "-n", namespace, "-l", selector, "-o", "json"]).await {
            Ok(value) if items(&value).is_empty() => return Ok(()),
            Ok(value) => last_output = Some(value.to_string()),
            Err(err) if err.contains("the server doesn't have a resource type") => return Ok(()),
            Err(err) => last_output = Some(err),
        }

        if Instant::now() >= deadline {
            let last_output = last_output.unwrap_or_else(|| "<no kubectl attempts>".to_string());
            return Err(format!(
                "timed out after {}s waiting for {kind} in namespace {namespace} with selector {selector} to be absent. Last output:\n{last_output}",
                timeout.as_secs()
            ));
        }
        sleep(Duration::from_secs(2)).await;
    }
}

pub async fn delete_resource(namespace: &str, kind: &str, name: &str) -> Result<String, String> {
    kubectl(&[
        "delete",
        kind,
        name,
        "-n",
        namespace,
        "--ignore-not-found=true",
    ])
    .await
}

pub async fn dump_namespace_diagnostics(namespace: &str) {
    eprintln!("=== Kubernetes diagnostics for namespace {namespace} ===");
    for args in [
        vec![
            "get",
            "sandboxclaims.extensions.agents.x-k8s.io",
            "-n",
            namespace,
            "-o",
            "wide",
        ],
        vec![
            "get",
            "sandboxwarmpools.extensions.agents.x-k8s.io",
            "-n",
            namespace,
            "-o",
            "wide",
        ],
        vec![
            "get",
            "sandboxtemplates.extensions.agents.x-k8s.io",
            "-n",
            namespace,
            "-o",
            "wide",
        ],
        vec![
            "get",
            "sandboxes.agents.x-k8s.io",
            "-n",
            namespace,
            "-o",
            "wide",
        ],
        vec!["get", "pods", "-n", namespace, "-o", "wide"],
        vec!["get", "events", "-n", namespace, "--sort-by=.lastTimestamp"],
        vec![
            "logs",
            "-n",
            namespace,
            "-l",
            "app.kubernetes.io/instance=openshell",
            "--tail=200",
            "--all-containers",
            "--prefix",
        ],
    ] {
        eprintln!("--- kubectl {args:?} ---");
        match kubectl(&args).await {
            Ok(output) => eprintln!("{output}"),
            Err(err) => eprintln!("{err}"),
        }
    }
    eprintln!("=== end Kubernetes diagnostics ===");
}

pub fn items(value: &Value) -> &[Value] {
    value
        .get("items")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}
