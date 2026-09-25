// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Portable policy-local and mechanistic proposal checks.

use std::io::Write as _;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::Value;
use tempfile::NamedTempFile;
use tokio::time::sleep;

use crate::{OpenShellRunner, Scenario, ScenarioFuture};

const CREATE_TIMEOUT: Duration = Duration::from_mins(10);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(45);
const READY_TIMEOUT: Duration = Duration::from_mins(4);
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const PROPOSAL_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Deserialize)]
struct SandboxState {
    name: String,
    phase: String,
}

pub const POLICY_LOCAL_SCENARIO: Scenario = Scenario {
    name: "policy-local",
    description: "Read and request a rule through the sandbox-local policy HTTP API.",
    run: run_policy_local,
};

pub const MECHANISTIC_PROPOSAL_SCENARIO: Scenario = Scenario {
    name: "mechanistic-proposal",
    description: "Turn a denied transparent TCP open into a scoped policy draft.",
    run: run_mechanistic_proposal,
};

fn run_policy_local(runner: &mut OpenShellRunner) -> ScenarioFuture<'_> {
    Box::pin(async move {
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
            request_policy_local_http(runner, &name, "POST", "/v1/proposals", &payload, 202)
                .await?;
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

        let state =
            request_policy_local(runner, &name, &format!("/v1/proposals/{chunk_id}")).await?;
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
    })
}

async fn sandbox_bash_path(runner: &OpenShellRunner, name: &str) -> Result<String, String> {
    let result = runner
        .step("bash-binary")
        .description("the sandbox's Bash executable has a canonical path")
        .with_timeout(COMMAND_TIMEOUT)
        .run(&[
            "sandbox",
            "exec",
            "--name",
            name,
            "--no-tty",
            "--",
            "bash",
            "-c",
            "printf '%s\\n' \"$(readlink -f /proc/$$/exe)\"",
        ])
        .await
        .map_err(|error| error.to_string())?;
    result.require_success()?;
    let binary = result.stdout().trim();
    if !binary.starts_with('/')
        || binary.contains('\n')
        || binary.rsplit('/').next() != Some("bash")
    {
        return Err(result.failure_diagnostic("one absolute Bash executable path ending in /bash"));
    }
    Ok(binary.to_string())
}

async fn enable_proposals(runner: &OpenShellRunner, name: &str) -> Result<(), String> {
    let set = runner
        .step("enable-policy-advisor")
        .description("sandbox-scoped policy advisor setting is enabled")
        .with_timeout(COMMAND_TIMEOUT)
        .run(&[
            "settings",
            "set",
            name,
            "--key",
            "agent_policy_proposals_enabled",
            "--value",
            "true",
        ])
        .await
        .map_err(|error| error.to_string())?;
    set.require_success()?;

    let settings = runner
        .step("effective-settings")
        .description("policy advisor setting is effectively enabled")
        .with_timeout(COMMAND_TIMEOUT)
        .run(&["settings", "get", name, "--json"])
        .await
        .map_err(|error| error.to_string())?;
    settings.require_success()?;
    let value: Value = settings.json().map_err(|error| error.to_string())?;
    if value["settings"]["agent_policy_proposals_enabled"]["value"] != "true" {
        return Err(settings.failure_diagnostic(
            "effective agent_policy_proposals_enabled is true; check for a global override",
        ));
    }
    Ok(())
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

fn run_mechanistic_proposal(runner: &mut OpenShellRunner) -> ScenarioFuture<'_> {
    Box::pin(async move {
        let mut policy = NamedTempFile::new().map_err(|error| error.to_string())?;
        policy
            .write_all(
                br"version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /bin, /lib, /lib64, /proc, /dev/urandom, /app, /etc, /var/log]
  read_write: [/sandbox, /tmp, /dev/null]
landlock: { compatibility: best_effort }
network_policies: {}
",
            )
            .map_err(|error| error.to_string())?;
        let policy_path = policy
            .path()
            .to_str()
            .ok_or("temporary policy path is not UTF-8")?;
        let name = format!("ct-{}-mp", runner.id());
        create_sandbox(runner, &name, Some(policy_path)).await?;
        enable_proposals(runner, &name).await?;

        let effective = runner
            .step("effective-policy")
            .description("sandbox has no network allow rules before the probe")
            .with_timeout(COMMAND_TIMEOUT)
            .run(&["policy", "get", &name, "--full", "--output", "json"])
            .await
            .map_err(|error| error.to_string())?;
        effective.require_success()?;
        let value: Value = effective.json().map_err(|error| error.to_string())?;
        let network_rules = &value["policy"]["network_policies"];
        if !network_rules.is_null()
            && !network_rules
                .as_object()
                .is_some_and(serde_json::Map::is_empty)
        {
            return Err(effective.failure_diagnostic("effective network_policies is empty"));
        }

        let probe = runner
            .step("denied-tcp-open")
            .description("one Bash TCP open to 1.1.1.1:443 is denied by policy")
            .with_timeout(COMMAND_TIMEOUT)
            .run(&[
                "sandbox",
                "exec",
                "--name",
                &name,
                "--no-tty",
                "--",
                "bash",
                "-c",
                "printf 'BINARY=%s\\n' \"$(readlink -f /proc/$$/exe)\"; if exec 3<>/dev/tcp/1.1.1.1/443; then echo UNEXPECTED_ALLOWED; exit 1; else echo DENIED; fi",
            ])
            .await
            .map_err(|error| error.to_string())?;
        probe.require_success()?;
        let binary = probe
            .stdout()
            .lines()
            .find_map(|line| line.strip_prefix("BINARY="))
            .filter(|binary| binary.starts_with('/') && binary.rsplit('/').next() == Some("bash"))
            .ok_or_else(|| probe.failure_diagnostic("canonical Bash executable path is reported"))?
            .to_string();
        if !probe.stdout().lines().any(|line| line == "DENIED") {
            return Err(probe.failure_diagnostic("TCP open is denied before any upstream dial"));
        }

        let started = Instant::now();
        loop {
            let draft = runner
                .step("mechanistic-draft")
                .description("a single scoped mechanistic draft appears")
                .with_timeout(COMMAND_TIMEOUT)
                .run(&["rule", "get", &name])
                .await
                .map_err(|error| error.to_string())?;
            if !draft.success() {
                if started.elapsed() >= PROPOSAL_TIMEOUT {
                    return Err(draft.failure_diagnostic("the reviewer inbox is readable"));
                }
                sleep(POLL_INTERVAL).await;
                continue;
            }
            if !draft.stdout().contains("Chunk:") {
                if started.elapsed() >= PROPOSAL_TIMEOUT {
                    return Err(draft.failure_diagnostic(&format!(
                        "one mechanistic draft for 1.1.1.1:443 and {binary}; probe stderr:\n{}",
                        probe.stderr()
                    )));
                }
                sleep(POLL_INTERVAL).await;
                continue;
            }
            assert_mechanistic_draft(draft.stdout(), &binary)
                .map_err(|error| draft.failure_diagnostic(&error))?;
            return Ok(());
        }
    })
}

fn assert_mechanistic_draft(output: &str, binary: &str) -> Result<(), String> {
    let fields = output.lines().map(str::trim).collect::<Vec<_>>();
    let field = |name: &str| {
        fields
            .iter()
            .find_map(|line| line.strip_prefix(name).map(str::trim))
    };
    if fields
        .iter()
        .filter(|line| line.starts_with("Chunk:"))
        .count()
        != 1
        || !matches!(field("Status:"), Some("pending" | "approved"))
        || field("Rule:") != Some("allow_1_1_1_1_443")
        || field("Binary:") != Some(binary)
        || field("Binaries:") != Some(binary)
        || field("Endpoints:") != Some("1.1.1.1:443 [L4]")
        || !field("Rationale:").is_some_and(|value| value.contains("1.1.1.1:443"))
    {
        return Err(format!(
            "expected one pending or approved L4 mechanistic draft scoped to {binary} and 1.1.1.1:443"
        ));
    }
    Ok(())
}

async fn create_sandbox(
    runner: &mut OpenShellRunner,
    name: &str,
    policy_path: Option<&str>,
) -> Result<(), String> {
    runner.track_sandbox(name);
    let mut args = vec![
        "sandbox",
        "create",
        "--name",
        name,
        "--detach",
        "--no-tty",
        "--no-auto-providers",
    ];
    if let Some(path) = policy_path {
        args.extend(["--policy", path]);
    }
    args.extend(["--", "sh", "-c", "exec sleep infinity"]);
    let create = runner
        .step("create")
        .description(format!("sandbox '{name}' is created"))
        .with_timeout(CREATE_TIMEOUT)
        .run(&args)
        .await
        .map_err(|error| error.to_string())?;
    create.require_success()?;

    let started = Instant::now();
    loop {
        let get = runner
            .step("ready")
            .description(format!("sandbox '{name}' reaches Ready"))
            .with_timeout(COMMAND_TIMEOUT)
            .run(&["sandbox", "get", name, "--output", "json"])
            .await
            .map_err(|error| error.to_string())?;
        if get.success() {
            let state: SandboxState = get.json().map_err(|error| error.to_string())?;
            if state.name != name {
                return Err(get.failure_diagnostic("sandbox get returns the created name"));
            }
            if state.phase == "Ready" {
                return Ok(());
            }
            if state.phase == "Failed" {
                return Err(get.failure_diagnostic("sandbox reaches Ready instead of Failed"));
            }
        }
        if started.elapsed() >= READY_TIMEOUT {
            return Err(get.failure_diagnostic("sandbox reaches Ready before timeout"));
        }
        sleep(POLL_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::assert_mechanistic_draft;

    #[test]
    fn draft_assertion_rejects_unrelated_binary() {
        let draft = "Chunk: id\nStatus: pending\nRule: allow_1_1_1_1_443\nBinary: /usr/bin/sh\nRationale: Allow sh to connect to 1.1.1.1:443.\nEndpoints: 1.1.1.1:443 [L4]\nBinaries: /usr/bin/sh\n";
        assert!(assert_mechanistic_draft(draft, "/usr/bin/bash").is_err());
    }
}
