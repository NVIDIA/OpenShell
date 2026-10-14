// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::helpers::{
    COMMAND_TIMEOUT, POLL_INTERVAL, READY_TIMEOUT, create_sandbox, enable_proposals,
    sandbox_bash_path,
};
use openshell_e2e_support::OpenShellRunner;
use serde_json::Value;
use std::time::Instant;
use tokio::time::sleep;

/// Read and request a rule through the sandbox-local policy HTTP API.
#[tokio::test]
async fn submits_a_rule_for_review() {
    let mut runner =
        OpenShellRunner::from_env("policy-local").expect("candidate openshell CLI is available");
    let result = async {
        runner.check_gateway_status().await?;
        let runner = &mut runner;
    let name = format!("ct-{}-pl", runner.id());
    create_sandbox(runner, &name, None).await?;
    enable_proposals(runner, &name).await?;
    let binary = sandbox_bash_path(runner, &name).await?;

    let started = Instant::now();
    let readiness_path = format!("/v1/proposals/ct-{}-readiness", runner.id());
    loop {
        match request_policy_local(runner, &name, "/v1/policy/current").await {
            Ok(response)
                if response["format"] == "yaml"
                    && response["policy_yaml"]
                        .as_str()
                        .is_some_and(|yaml| yaml.contains("version: 1")) =>
            {
                // The current-policy route is local; proposal submission also
                // needs the supervisor's workspace and gateway lookup session.
                match request_policy_local_http(runner, &name, "GET", &readiness_path, "", 404)
                    .await
                {
                    Ok(lookup) if lookup["error"] == "chunk_not_found" => break,
                    Ok(lookup) => {
                        return Err(format!(
                            "policy.local proposal lookup returned an invalid readiness response: {lookup}"
                        ));
                    }
                    Err(error) if started.elapsed() >= READY_TIMEOUT => return Err(error),
                    Err(_) => {}
                }
            }
            Ok(response) => {
                return Err(format!(
                    "policy.local returned an invalid current policy: {response}"
                ));
            }
            Err(error) => {
                if started.elapsed() >= READY_TIMEOUT {
                    return Err(error);
                }
            }
        }
        sleep(POLL_INTERVAL).await;
    }
    let denials = request_policy_local(runner, &name, "/v1/denials?last=1").await?;
    if !denials["denials"].is_array() || !denials["log_available"].is_boolean() {
        return Err(format!(
            "policy.local returned an invalid denials response: {denials}"
        ));
    }

    let rule_name = format!("conformance_local_{}", runner.id());
    let payload = serde_json::json!({
        "intent_summary": "Allow Bash to read the conformance path on example.invalid.",
        "operations": [{
            "addRule": {
                "ruleName": &rule_name,
                "rule": {
                    "name": &rule_name,
                    "endpoints": [{
                        "host": "example.invalid",
                        "port": 443,
                        "protocol": "rest",
                        "enforcement": "enforce",
                        "rules": [{"allow": {"method": "GET", "path": "/conformance"}}]
                    }],
                    "binaries": [{"path": &binary}]
                }
            }
        }]
    })
    .to_string();
    let submitted =
        request_policy_local_http(runner, &name, "POST", "/v1/proposals", &payload, 202).await?;
    let chunk_id = submitted["accepted_chunk_ids"]
        .as_array()
        .filter(|ids| ids.len() == 1)
        .and_then(|ids| ids[0].as_str())
        .filter(|id| !id.is_empty())
        .ok_or_else(|| format!("policy.local did not accept one proposal: {submitted}"))?;
    if submitted["status"] != "submitted"
        || submitted["accepted_chunks"] != 1
        || submitted["rejected_chunks"] != 0
    {
        return Err(format!("policy.local did not submit one rule: {submitted}"));
    }

    let state = request_policy_local(runner, &name, &format!("/v1/proposals/{chunk_id}")).await?;
    if state["chunk_id"] != chunk_id
        || state["rule_name"] != rule_name
        || state["binary"] != binary
        || !matches!(state["status"].as_str(), Some("pending" | "approved"))
    {
        return Err(format!("policy.local returned the wrong proposal: {state}"));
    }

    let review = runner
        .step("reviewer-inbox")
        .description("the requested rule is visible to the reviewer")
        .with_timeout(COMMAND_TIMEOUT)
        .run(&["rule", "get", &name])
        .await
        .map_err(|error| error.to_string())?;
    review.require_success()?;
    if !review.stdout().contains(&format!("Chunk: {chunk_id}"))
        || !review.stdout().contains(&format!("Rule: {rule_name}"))
    {
        return Err(review.failure_diagnostic("the submitted rule is in the reviewer inbox"));
    }
    Ok(())
    }
    .await;
    if let Err(error) = runner.finish(result).await {
        panic!("policy-local conformance story failed:\n{error}");
    }
}

async fn request_policy_local(
    runner: &OpenShellRunner,
    sandbox: &str,
    path: &str,
) -> Result<Value, String> {
    request_policy_local_http(runner, sandbox, "GET", path, "", 200).await
}

async fn request_policy_local_http(
    runner: &OpenShellRunner,
    sandbox: &str,
    method: &str,
    path: &str,
    body: &str,
    expected_status: u16,
) -> Result<Value, String> {
    let script = "method=$1; path=$2; body=$3; exec 3<>/dev/tcp/policy.local/80 || exit 1; printf '%s %s HTTP/1.1\\r\\nHost: policy.local\\r\\nContent-Type: application/json\\r\\nContent-Length: %s\\r\\nConnection: close\\r\\n\\r\\n' \"$method\" \"$path\" \"${#body}\" >&3; printf '%s' \"$body\" >&3; cat <&3";
    let result = runner
        .step(format!("policy-local-{method}{path}"))
        .description(format!(
            "{method} http://policy.local{path} succeeds from the sandbox"
        ))
        .with_timeout(COMMAND_TIMEOUT)
        .run(&[
            "sandbox",
            "exec",
            "--name",
            sandbox,
            "--no-tty",
            "--",
            "bash",
            "-c",
            script,
            "policy-local-http",
            method,
            path,
            body,
        ])
        .await
        .map_err(|error| error.to_string())?;
    result.require_success()?;
    let (headers, body) = result.stdout().split_once("\r\n\r\n").ok_or_else(|| {
        result.failure_diagnostic("a complete HTTP response with headers and JSON body")
    })?;
    if !headers.starts_with(&format!("HTTP/1.1 {expected_status} "))
        || !headers.lines().any(|line| {
            line.to_ascii_lowercase()
                .starts_with("content-type: application/json")
        })
    {
        return Err(
            result.failure_diagnostic(&format!("HTTP {expected_status} with JSON Content-Type"))
        );
    }
    serde_json::from_str(body)
        .map_err(|error| result.failure_diagnostic(&format!("valid JSON body: {error}")))
}
