// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Conformance suite: policy-advisor.
//!
//! The sandbox's `policy.local` API and the draft policy a denied connection
//! produces. Requests to `policy.local` run inside the sandbox; settings and
//! drafts go through the gateway's gRPC API.

use std::time::{Duration, Instant};

use serde_json::Value;
use testkit::sdk::raw::proto;
use testkit::{Context, Error, Sandbox};

const READY_TIMEOUT: Duration = Duration::from_mins(4);
const PROPOSAL_TIMEOUT: Duration = Duration::from_secs(90);
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const PROPOSALS_ENABLED: &str = "agent_policy_proposals_enabled";

/// With proposals enabled, `policy.local` serves the current policy and
/// recent denials, accepts a proposed rule, reports its state, and the rule
/// reaches the reviewer's draft policy.
#[testkit::test(id = "t-p2jo0tvz")]
async fn policy_local_accepts_proposals(cx: &mut Context) -> testkit::Result {
    let sandbox = create(cx, "pl", None).await?;
    enable_proposals(&sandbox).await?;
    let binary = bash_path(&sandbox).await?;

    // The current-policy route is local; proposal lookup also needs the
    // supervisor's session with the gateway, so wait for both.
    let started = Instant::now();
    let readiness = format!("/v1/proposals/test-{}-readiness", cx.run_id());
    loop {
        let ready = async {
            let current = policy_local(&sandbox, "GET", "/v1/policy/current", "", 200).await?;
            testkit::ensure!(
                current["format"] == "yaml"
                    && current["policy_yaml"]
                        .as_str()
                        .is_some_and(|yaml| yaml.contains("version: 1")),
                "policy.local returned an invalid current policy: {current}"
            );
            let lookup = policy_local(&sandbox, "GET", &readiness, "", 404).await?;
            testkit::ensure!(
                lookup["error"] == "chunk_not_found",
                "policy.local proposal lookup returned {lookup}"
            );
            Ok(())
        }
        .await;
        match ready {
            Ok(()) => break,
            Err(error) if started.elapsed() >= READY_TIMEOUT => return Err(error),
            Err(_) => tokio::time::sleep(POLL_INTERVAL).await,
        }
    }

    let denials = policy_local(&sandbox, "GET", "/v1/denials?last=1", "", 200).await?;
    testkit::ensure!(
        denials["denials"].is_array() && denials["log_available"].is_boolean(),
        "policy.local returned an invalid denials response: {denials}"
    );

    let rule_name = format!("conformance_local_{}", cx.run_id());
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
    let submitted = policy_local(&sandbox, "POST", "/v1/proposals", &payload, 202).await?;
    let chunk_id = submitted["accepted_chunk_ids"]
        .as_array()
        .filter(|ids| ids.len() == 1)
        .and_then(|ids| ids[0].as_str())
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            Error::msg(format!(
                "policy.local did not accept one proposal: {submitted}"
            ))
        })?
        .to_string();
    testkit::ensure!(
        submitted["status"] == "submitted"
            && submitted["accepted_chunks"] == 1
            && submitted["rejected_chunks"] == 0,
        "policy.local did not submit one rule: {submitted}"
    );

    let state = policy_local(
        &sandbox,
        "GET",
        &format!("/v1/proposals/{chunk_id}"),
        "",
        200,
    )
    .await?;
    testkit::ensure!(
        state["chunk_id"] == chunk_id.as_str()
            && state["rule_name"] == rule_name.as_str()
            && state["binary"] == binary.as_str()
            && matches!(state["status"].as_str(), Some("pending" | "approved")),
        "policy.local returned the wrong proposal: {state}"
    );

    let draft = sandbox.draft_policy().await?;
    testkit::ensure!(
        draft
            .chunks
            .iter()
            .any(|chunk| chunk.id == chunk_id && chunk.rule_name == rule_name),
        "the submitted rule {rule_name} ({chunk_id}) is not in the draft policy: {:?}",
        draft
            .chunks
            .iter()
            .map(|chunk| (&chunk.id, &chunk.rule_name))
            .collect::<Vec<_>>()
    );
    Ok(())
}

/// In a sandbox with no network rules, a denied connection to an IP address
/// produces one mechanistic L4 draft rule for that endpoint and binary.
#[testkit::test(id = "t-gpw7sqdx")]
async fn denied_address_produces_draft_rule(cx: &mut Context) -> testkit::Result {
    let sandbox = create(cx, "mp", Some(no_network_policy())).await?;
    enable_proposals(&sandbox).await?;

    let config = sandbox.config().await?;
    let rules = config
        .policy
        .as_ref()
        .map(|policy| policy.network_policies.len())
        .unwrap_or_default();
    testkit::ensure!(
        rules == 0,
        "the effective policy has {rules} network rules; expected none"
    );

    let probe = sandbox
        .exec([
            "bash",
            "-c",
            "printf 'BINARY=%s\\n' \"$(readlink -f /proc/$$/exe)\"; \
             if exec 3<>/dev/tcp/1.1.1.1/443; then echo UNEXPECTED_ALLOWED; exit 1; else echo DENIED; fi",
        ])
        .await?;
    testkit::ensure!(
        probe.exit_code == 0 && probe.stdout.lines().any(|line| line == "DENIED"),
        "the connection to 1.1.1.1:443 was not denied: stdout {:?}, stderr {:?}",
        probe.stdout,
        probe.stderr
    );
    let binary = probe
        .stdout
        .lines()
        .find_map(|line| line.strip_prefix("BINARY="))
        .filter(|binary| is_bash_path(binary))
        .ok_or_else(|| Error::msg(format!("no Bash path in probe output: {:?}", probe.stdout)))?
        .to_string();

    expect_draft(
        &sandbox,
        "allow_1_1_1_1_443",
        ("1.1.1.1", 443),
        &binary,
        &probe.stderr,
    )
    .await
}

/// In a sandbox with no network rules, a denied connection to a new hostname
/// stays denied and produces one mechanistic L4 draft rule for it.
#[testkit::test(id = "t-mchrkrfm")]
async fn denied_hostname_produces_draft_rule(cx: &mut Context) -> testkit::Result {
    let sandbox = create(cx, "nh", Some(no_network_policy())).await?;
    let binary = bash_path(&sandbox).await?;

    let probe = sandbox
        .exec([
            "bash",
            "-c",
            "if exec 3<>/dev/tcp/pypi.org/80; then echo UNEXPECTED_ALLOWED; exit 1; else echo DENIED; fi",
        ])
        .await?;
    testkit::ensure!(
        probe.exit_code == 0 && probe.stdout.lines().any(|line| line == "DENIED"),
        "the connection to pypi.org:80 was not denied: stdout {:?}, stderr {:?}",
        probe.stdout,
        probe.stderr
    );

    expect_draft(
        &sandbox,
        "allow_pypi_org_80",
        ("pypi.org", 80),
        &binary,
        &probe.stderr,
    )
    .await
}

async fn create(
    cx: &Context,
    suffix: &str,
    policy: Option<proto::SandboxPolicy>,
) -> testkit::Result<Sandbox> {
    let mut builder = cx
        .sandbox(suffix)
        .command(["sh", "-c", "exec sleep infinity"]);
    if let Some(policy) = policy {
        builder = builder.policy(policy);
    }
    let sandbox = builder.create().await?;
    sandbox.wait_ready().await?;
    Ok(sandbox)
}

/// Filesystem access the tests need, and no network rules.
fn no_network_policy() -> proto::SandboxPolicy {
    let paths = |paths: &[&str]| paths.iter().map(ToString::to_string).collect();
    proto::SandboxPolicy {
        version: 1,
        filesystem: Some(proto::FilesystemPolicy {
            include_workdir: true,
            read_only: paths(&[
                "/usr",
                "/bin",
                "/lib",
                "/lib64",
                "/proc",
                "/dev/urandom",
                "/app",
                "/etc",
                "/var/log",
            ]),
            read_write: paths(&["/sandbox", "/tmp", "/dev/null"]),
        }),
        landlock: Some(proto::LandlockPolicy {
            compatibility: "best_effort".to_string(),
        }),
        ..proto::SandboxPolicy::default()
    }
}

/// Enable proposals for the sandbox and check the effective value, which a
/// global override could change.
async fn enable_proposals(sandbox: &Sandbox) -> testkit::Result {
    sandbox
        .set_setting(
            PROPOSALS_ENABLED,
            proto::setting_value::Value::BoolValue(true),
        )
        .await?;
    let config = sandbox.config().await?;
    let value = config
        .settings
        .get(PROPOSALS_ENABLED)
        .and_then(|setting| setting.value.as_ref())
        .and_then(|value| value.value.clone());
    testkit::ensure!(
        value == Some(proto::setting_value::Value::BoolValue(true)),
        "effective {PROPOSALS_ENABLED} is {value:?}; check for a global override"
    );
    Ok(())
}

async fn bash_path(sandbox: &Sandbox) -> testkit::Result<String> {
    let output = sandbox
        .exec([
            "bash",
            "-c",
            "printf '%s\\n' \"$(readlink -f /proc/$$/exe)\"",
        ])
        .await?;
    let path = output.stdout.trim();
    testkit::ensure!(
        output.exit_code == 0 && is_bash_path(path),
        "expected one absolute Bash path; got {:?}, stderr {:?}",
        output.stdout,
        output.stderr
    );
    Ok(path.to_string())
}

fn is_bash_path(path: &str) -> bool {
    path.starts_with('/') && !path.contains('\n') && path.rsplit('/').next() == Some("bash")
}

/// Send an HTTP request to `policy.local` from inside the sandbox and parse
/// the JSON body, requiring `expected_status`.
async fn policy_local(
    sandbox: &Sandbox,
    method: &str,
    path: &str,
    body: &str,
    expected_status: u16,
) -> testkit::Result<Value> {
    const SCRIPT: &str = "method=$1; path=$2; body=$3; exec 3<>/dev/tcp/policy.local/80 || exit 1; \
        printf '%s %s HTTP/1.1\\r\\nHost: policy.local\\r\\nContent-Type: application/json\\r\\nContent-Length: %s\\r\\nConnection: close\\r\\n\\r\\n' \"$method\" \"$path\" \"${#body}\" >&3; \
        printf '%s' \"$body\" >&3; cat <&3";
    let output = sandbox
        .exec([
            "bash",
            "-c",
            SCRIPT,
            "policy-local-http",
            method,
            path,
            body,
        ])
        .await?;
    testkit::ensure!(
        output.exit_code == 0,
        "{method} http://policy.local{path} exited {}; stderr: {}",
        output.exit_code,
        output.stderr
    );
    let (headers, json) = output.stdout.split_once("\r\n\r\n").ok_or_else(|| {
        Error::msg(format!(
            "{method} http://policy.local{path} returned no complete HTTP response: {:?}",
            output.stdout
        ))
    })?;
    testkit::ensure!(
        headers.starts_with(&format!("HTTP/1.1 {expected_status} "))
            && headers.lines().any(|line| {
                line.to_ascii_lowercase()
                    .starts_with("content-type: application/json")
            }),
        "{method} http://policy.local{path} did not return {expected_status} with JSON: {headers}"
    );
    serde_json::from_str(json).map_err(|error| {
        Error::msg(format!(
            "{method} http://policy.local{path} returned invalid JSON ({error}): {json}"
        ))
    })
}

/// Wait for the draft policy to contain a chunk, then require exactly one:
/// pending or approved, for `rule`, scoped to `binary` and an L4 `endpoint`.
async fn expect_draft(
    sandbox: &Sandbox,
    rule: &str,
    endpoint: (&str, u32),
    binary: &str,
    probe_stderr: &str,
) -> testkit::Result {
    let started = Instant::now();
    let chunks = loop {
        match sandbox.draft_policy().await {
            Ok(draft) if !draft.chunks.is_empty() => break draft.chunks,
            Ok(_) | Err(_) if started.elapsed() < PROPOSAL_TIMEOUT => {
                tokio::time::sleep(POLL_INTERVAL).await;
            }
            Ok(_) => {
                return Err(Error::msg(format!(
                    "no draft rule for {}:{} after {PROPOSAL_TIMEOUT:?}; probe stderr: {probe_stderr}",
                    endpoint.0, endpoint.1
                )));
            }
            Err(error) => return Err(error),
        }
    };

    testkit::ensure!(
        chunks.len() == 1,
        "expected one draft rule; got {chunks:#?}"
    );
    let chunk = &chunks[0];
    let proposed = chunk.proposed_rule.as_ref();
    let endpoints: Vec<(&str, u32, &str)> = proposed
        .map(|rule| {
            rule.endpoints
                .iter()
                .map(|e| (e.host.as_str(), e.port, e.protocol.as_str()))
                .collect()
        })
        .unwrap_or_default();
    let binaries: Vec<&str> = proposed
        .map(|rule| rule.binaries.iter().map(|b| b.path.as_str()).collect())
        .unwrap_or_default();
    testkit::ensure!(
        matches!(chunk.status.as_str(), "pending" | "approved")
            && chunk.rule_name == rule
            && chunk.binary == binary
            && binaries == [binary]
            // An empty protocol is an L4 rule.
            && endpoints == [(endpoint.0, endpoint.1, "")]
            && chunk.rationale.contains(&format!("{}:{}", endpoint.0, endpoint.1)),
        "expected one pending or approved L4 draft rule {rule} for {binary} and {}:{}; got {chunk:#?}",
        endpoint.0,
        endpoint.1
    );
    Ok(())
}
