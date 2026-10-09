// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Decision parity between YAML policies evaluated by Rego and equivalent
//! Cedar policies.
//!
//! Each scenario pairs a YAML policy with a Cedar policy written to mean the
//! same thing, and runs every [`Probe`] through both engines using the calls
//! the proxy makes. A case marked [`Expect::Same`] fails if the outcomes
//! differ. A case marked [`Expect::Diverges`] records a known difference and
//! fails if the engines start to agree, so the list stays accurate.
//!
//! `scenarios` holds hand-written scenarios. The `ported_*` modules port the
//! existing YAML decision tests that Cedar can express; each case names the
//! YAML test it ports.

mod ported_opa_a;
mod ported_opa_b;
mod ported_proxy_dns;
mod ported_relay;
mod scenarios;

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::PathBuf;

use crate::cedar_only::CedarOnlyEngine;
use crate::l7::L7RequestInfo;
use crate::l7::graphql::{GraphqlOperationInfo, GraphqlRequestInfo};
use crate::l7::jsonrpc::{JsonRpcCallInfo, JsonRpcRequestInfo, McpMethodClassification};
use crate::l7::relay::L7EvalContext;
use crate::opa::{EgressAuthorization, NetworkAction, NetworkInput, OpaEngine};

const REGO: &str = include_str!("../../data/sandbox-policy.rego");
const BINARY: &str = "/usr/bin/curl";

/// Whether both engines are expected to agree on a case.
#[derive(Debug, Clone, Copy)]
enum Expect {
    Same,
    /// A known difference, with the reason it exists.
    Diverges(&'static str),
}

/// What a case compares between the two engines.
enum Probe {
    /// One L7 request through both engines' per-tunnel `evaluate_request`.
    /// `ctx` defaults to the scenario host on port 443 and [`BINARY`].
    /// Outcome: `allow` or `deny`.
    Request {
        ctx: Option<Box<L7EvalContext>>,
        request: Box<L7RequestInfo>,
    },
    /// One connection through both engines' `authorize_egress`.
    /// Outcome: `allow` or `deny`.
    Connect(NetworkInput),
    /// Whether an allowed connection's host counts as exactly declared, which
    /// lets it resolve to a private address.
    /// Outcome: `exact`, `not-exact`, or `deny`.
    ExactHost(NetworkInput),
    /// The L7 inspection selected for an allowed connection: the distinct
    /// `protocol/enforcement` pairs of its endpoint configs.
    /// Outcome: for example `Rest/Enforce`, `none`, or `deny`.
    Inspection(NetworkInput),
    /// Whether policy DNS would resolve `name` for `port`.
    /// Outcome: `eligible` or `ineligible`.
    DnsEligible { name: String, port: u16 },
}

struct Case {
    name: &'static str,
    probe: Probe,
    expect: Expect,
}

struct Scenario<'a> {
    name: &'a str,
    /// Default host for [`Probe::Request`] cases without a `ctx`.
    host: &'a str,
    yaml: &'a str,
    cedar: &'a str,
    cases: Vec<Case>,
}

/// A request case the engines must agree on, in the scenario's default context.
fn same(name: &'static str, request: L7RequestInfo) -> Case {
    same_probe(
        name,
        Probe::Request {
            ctx: None,
            request: Box::new(request),
        },
    )
}

/// A request case recorded as a known difference.
fn diverges(name: &'static str, request: L7RequestInfo, reason: &'static str) -> Case {
    diverges_probe(
        name,
        Probe::Request {
            ctx: None,
            request: Box::new(request),
        },
        reason,
    )
}

fn same_probe(name: &'static str, probe: Probe) -> Case {
    Case {
        name,
        probe,
        expect: Expect::Same,
    }
}

fn diverges_probe(name: &'static str, probe: Probe, reason: &'static str) -> Case {
    Case {
        name,
        probe,
        expect: Expect::Diverges(reason),
    }
}

/// An L7 evaluation context for `binary` connecting to `host:port`.
fn l7_ctx(host: &str, port: u16, binary: &str) -> L7EvalContext {
    L7EvalContext {
        host: host.to_string(),
        port,
        binary_path: binary.to_string(),
        ..Default::default()
    }
}

/// A request probe with an explicit context.
fn request_in(ctx: L7EvalContext, request: L7RequestInfo) -> Probe {
    Probe::Request {
        ctx: Some(Box::new(ctx)),
        request: Box::new(request),
    }
}

/// A connection from `binary` to `host:port`, with no ancestors.
fn network(host: &str, port: u16, binary: &str) -> NetworkInput {
    network_with_ancestors(host, port, binary, &[])
}

/// A connection from `binary`, started by `ancestors`, to `host:port`.
fn network_with_ancestors(host: &str, port: u16, binary: &str, ancestors: &[&str]) -> NetworkInput {
    NetworkInput {
        host: host.to_string(),
        port,
        binary_path: PathBuf::from(binary),
        binary_sha256: String::new(),
        ancestors: ancestors.iter().map(PathBuf::from).collect(),
        cmdline_paths: Vec::new(),
    }
}

fn rest(method: &str, path: &str) -> L7RequestInfo {
    L7RequestInfo {
        action: method.to_string(),
        target: path.to_string(),
        query_params: HashMap::new(),
        graphql: None,
        jsonrpc: None,
    }
}

fn operation(operation_type: &str, name: Option<&str>, fields: &[&str]) -> GraphqlOperationInfo {
    GraphqlOperationInfo {
        operation_type: operation_type.to_string(),
        operation_name: name.map(str::to_string),
        fields: fields.iter().map(ToString::to_string).collect(),
        persisted_query: false,
        persisted_query_hash: None,
        persisted_query_id: None,
    }
}

fn graphql(operations: Vec<GraphqlOperationInfo>) -> L7RequestInfo {
    L7RequestInfo {
        graphql: Some(GraphqlRequestInfo {
            operations,
            error: None,
        }),
        ..rest("POST", "/graphql")
    }
}

fn jsonrpc_info(calls: Vec<JsonRpcCallInfo>) -> JsonRpcRequestInfo {
    JsonRpcRequestInfo {
        calls,
        is_batch: false,
        receive_stream: false,
        has_response: false,
        mcp_revision: None,
        mcp_http_metadata: None,
        error: None,
    }
}

fn call(
    method: &str,
    tool: Option<&str>,
    class: Option<McpMethodClassification>,
) -> JsonRpcCallInfo {
    let mut params = HashMap::new();
    if let Some(tool) = tool {
        params.insert("name".to_string(), tool.to_string());
    }
    JsonRpcCallInfo {
        method: method.to_string(),
        params,
        tool: tool.map(str::to_string),
        mcp_classification: class,
        is_notification: false,
    }
}

fn jsonrpc_request(path: &str, calls: Vec<JsonRpcCallInfo>) -> L7RequestInfo {
    L7RequestInfo {
        jsonrpc: Some(jsonrpc_info(calls)),
        ..rest("POST", path)
    }
}

fn mcp(method: &str, tool: Option<&str>, class: McpMethodClassification) -> L7RequestInfo {
    jsonrpc_request("/mcp", vec![call(method, tool, Some(class))])
}

/// The first line of an evaluation error, for the report.
fn error_line(error: &miette::Report) -> String {
    let text = error.to_string();
    text.lines()
        .find(|line| line.contains("error:"))
        .unwrap_or_else(|| text.lines().next().unwrap_or("evaluation error"))
        .trim()
        .to_string()
}

fn allow_or_deny(allowed: bool) -> String {
    if allowed { "allow" } else { "deny" }.to_string()
}

/// Both engines for one scenario.
struct Engines {
    opa: OpaEngine,
    cedar: CedarOnlyEngine,
}

impl Engines {
    fn load(scenario: &Scenario<'_>) -> Self {
        let opa = OpaEngine::from_strings(REGO, scenario.yaml)
            .unwrap_or_else(|error| panic!("{}: YAML policy loads: {error}", scenario.name));
        let cedar = CedarOnlyEngine::from_policy_str(scenario.cedar)
            .unwrap_or_else(|error| panic!("{}: Cedar policy loads: {error}", scenario.name));
        Self { opa, cedar }
    }

    /// Returns the `(yaml, cedar)` outcomes. Evaluation errors count as a
    /// denial, as they do in the proxy, and are noted in the report.
    fn outcomes(&self, scenario: &Scenario<'_>, probe: &Probe) -> (String, String) {
        match probe {
            Probe::Request { ctx, request } => {
                let ctx = ctx
                    .as_deref()
                    .cloned()
                    .unwrap_or_else(|| l7_ctx(scenario.host, 443, BINARY));
                let yaml = self
                    .opa
                    .clone_engine_for_tunnel(self.opa.current_generation())
                    .and_then(|tunnel| tunnel.evaluate_request(&ctx, request));
                let cedar = self
                    .cedar
                    .l7_handle(self.cedar.current_generation())
                    .evaluate_request(&ctx, request);
                (
                    request_outcome(&yaml.map(|(allowed, _)| allowed)),
                    request_outcome(&cedar.map(|(allowed, _)| allowed)),
                )
            }
            Probe::Connect(input) => (
                connect_outcome(&self.opa.authorize_egress(input)),
                connect_outcome(&self.cedar.authorize_egress(input)),
            ),
            Probe::ExactHost(input) => (
                exact_host_outcome(&self.opa.authorize_egress(input)),
                exact_host_outcome(&self.cedar.authorize_egress(input)),
            ),
            Probe::Inspection(input) => (
                inspection_outcome(&self.opa.authorize_egress(input)),
                inspection_outcome(&self.cedar.authorize_egress(input)),
            ),
            Probe::DnsEligible { name, port } => (
                dns_outcome(&self.opa.policy_dns_eligibility_snapshot(), name, *port),
                dns_outcome(&self.cedar.policy_dns_eligibility_snapshot(), name, *port),
            ),
        }
    }
}

fn request_outcome(result: &miette::Result<bool>) -> String {
    match result {
        Ok(allowed) => allow_or_deny(*allowed),
        Err(error) => format!("deny (error: {})", error_line(error)),
    }
}

fn connect_outcome(result: &miette::Result<EgressAuthorization>) -> String {
    match result {
        Ok(authorization) => {
            allow_or_deny(matches!(authorization.action, NetworkAction::Allow { .. }))
        }
        Err(error) => format!("deny (error: {})", error_line(error)),
    }
}

fn exact_host_outcome(result: &miette::Result<EgressAuthorization>) -> String {
    match result {
        Ok(authorization) if matches!(authorization.action, NetworkAction::Allow { .. }) => {
            if authorization.exact_declared_endpoint_host {
                "exact".to_string()
            } else {
                "not-exact".to_string()
            }
        }
        _ => "deny".to_string(),
    }
}

fn inspection_outcome(result: &miette::Result<EgressAuthorization>) -> String {
    match result {
        Ok(authorization) if matches!(authorization.action, NetworkAction::Allow { .. }) => {
            let mut pairs: Vec<String> = authorization
                .endpoint_configs
                .iter()
                .filter_map(crate::l7::parse_l7_config)
                .map(|config| format!("{:?}/{:?}", config.protocol, config.enforcement))
                .collect();
            pairs.sort();
            pairs.dedup();
            if pairs.is_empty() {
                "none".to_string()
            } else {
                pairs.join(",")
            }
        }
        _ => "deny".to_string(),
    }
}

fn dns_outcome(
    snapshot: &miette::Result<crate::opa::PolicyDnsEligibilitySnapshot>,
    name: &str,
    port: u16,
) -> String {
    let Ok(snapshot) = snapshot else {
        return "ineligible (error)".to_string();
    };
    let eligible = !snapshot.fail_closed
        && snapshot.endpoints.iter().any(|matched| {
            let Ok(endpoint) = serde_json::to_value(&matched.endpoint) else {
                return false;
            };
            let host = endpoint
                .get("host")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .trim_end_matches('.')
                .to_ascii_lowercase();
            let ports_match = endpoint
                .get("ports")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|ports| {
                    ports
                        .iter()
                        .any(|candidate| candidate.as_u64() == Some(u64::from(port)))
                });
            ports_match
                && !host.is_empty()
                && openshell_core::host_pattern::HostSelector::new(&[host], &[])
                    .is_ok_and(|selector| selector.matches(name))
        });
    if eligible { "eligible" } else { "ineligible" }.to_string()
}

/// Runs a scenario and returns its report rows and any failures.
fn run(scenario: &Scenario<'_>) -> (String, Vec<String>) {
    let engines = Engines::load(scenario);
    let mut report = String::new();
    let mut failures = Vec::new();
    for case in &scenario.cases {
        let (yaml, cedar) = engines.outcomes(scenario, &case.probe);
        // Compare the decision only; an evaluation error note is for the
        // report, and an error already counts as a denial.
        let decision = |outcome: &str| outcome.split(' ').next().unwrap_or_default().to_string();
        let outcome = match (case.expect, decision(&yaml) == decision(&cedar)) {
            (Expect::Same, true) => "same".to_string(),
            (Expect::Diverges(reason), false) => format!("known difference: {reason}"),
            (Expect::Same, false) => {
                failures.push(format!(
                    "{} / {}: YAML {yaml} but Cedar {cedar}",
                    scenario.name, case.name
                ));
                "MISMATCH".to_string()
            }
            (Expect::Diverges(reason), true) => {
                failures.push(format!(
                    "{} / {}: expected a difference ({reason}) but both {yaml}",
                    scenario.name, case.name
                ));
                "UNEXPECTEDLY SAME".to_string()
            }
        };
        let _ = writeln!(
            report,
            "| {} | {} | {yaml} | {cedar} | {outcome} |",
            scenario.name, case.name
        );
    }
    (report, failures)
}

fn assert_parity(scenario: &Scenario<'_>) {
    let (report, failures) = run(scenario);
    println!("| Scenario | Case | YAML | Cedar | Result |\n|---|---|---|---|---|\n{report}");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
