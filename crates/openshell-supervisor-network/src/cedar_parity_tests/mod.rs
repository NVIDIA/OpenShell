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
mod ported_phase1;
mod ported_phase2;
mod ported_phase3;
mod ported_phase4;
mod ported_phase5;
mod ported_phase6;
// Resolves real symlinks; skips where `/proc/<pid>/root` does not (non-Linux).
#[cfg(unix)]
mod ported_phase7;
mod ported_proxy_dns;
mod ported_relay;
mod scenarios;

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

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
    /// The policy DNS records an allowed connection's decision matched, as
    /// `host:ports` with `/tcp` for a native TCP record, sorted. Each must
    /// also be in the engine's DNS snapshot under the same name and index,
    /// which the transparent TCP listener relies on to correlate them.
    /// Outcome: the records joined by `;`, `none`, or `deny`, with
    /// ` (not in DNS snapshot)` when a record is missing from the snapshot.
    MatchedEndpoints(NetworkInput),
    /// Every record of the policy DNS snapshot, as for
    /// [`Probe::MatchedEndpoints`]. Record names and indices are not
    /// compared, since YAML names records by policy and Cedar does not.
    /// Outcome: the records joined by `;`, or `none`.
    DnsRecords,
    /// A transparent TCP open from `binary` to the address policy DNS
    /// answers for `name`, staged as the boundary stages it. Each engine's
    /// own policy DNS resolves `name`, with the trusted resolver answering
    /// `answers` for every name.
    /// Outcome: `dns refused: <reason>`, the denial, or
    /// `RelayReady/<dialed addresses>/<correlated|uncorrelated>`, where
    /// `correlated` means the decision names an endpoint of the mapping, as
    /// the transparent TCP listener requires.
    TransparentOpen {
        name: String,
        port: u16,
        binary: String,
        answers: Vec<IpAddr>,
    },
    /// The addresses policy DNS pins for `name` on `port` when the trusted
    /// resolver answers `answers`, after each eligible endpoint filters them.
    /// Outcome: the pinned addresses, sorted, `no mapping for port`, or
    /// `dns refused: <reason>`.
    DnsAnswers {
        name: String,
        port: u16,
        answers: Vec<IpAddr>,
    },
    /// One explicit proxy connection whose host resolved to `addresses`,
    /// checked with the destination mode the decision selects, as CONNECT
    /// and forward HTTP check it: every address must pass.
    /// Outcome: `deny` (policy), `rejected` (destination check), or
    /// `admitted`.
    Destination {
        input: NetworkInput,
        addresses: Vec<IpAddr>,
    },
    /// The token-grant owners admitted for one L7 request, selected the way
    /// the relay selects them (each JSON-RPC batch member must admit an
    /// owner). `ctx` defaults as for [`Probe::Request`].
    /// Outcome: the sorted owners, comma-separated, or `none`.
    Owners {
        ctx: Option<Box<L7EvalContext>>,
        request: Box<L7RequestInfo>,
    },
    /// The settings of an allowed connection's L7 endpoint configs that do
    /// not depend on how a policy scopes paths: protocol, enforcement, TLS
    /// mode, MCP revisions and strict tool names, encoded slashes, and body
    /// limits.
    /// Outcome: the distinct per-config summaries, sorted, `none`, or `deny`.
    Configs(NetworkInput),
    /// The TLS mode the proxy reads for an allowed connection: the `tls`
    /// field of its first endpoint config.
    /// Outcome: `Skip`, `Auto`, or `deny`.
    TlsMode(NetworkInput),
    /// One L7 request's decision and deny reason. `ctx` defaults as for
    /// [`Probe::Request`].
    /// Outcome: `allow`, or `deny: <reason>`.
    DenyReason {
        ctx: Option<Box<L7EvalContext>>,
        request: Box<L7RequestInfo>,
    },
    /// One HTTP/1 exchange through the relay the proxy runs for an allowed
    /// connection, with the endpoint configs and tunnel engine each engine
    /// supplies. See [`RelayExchange`].
    /// Outcome: `deny`, `passthrough` (no inspection), or
    /// `<status>/<forwarded|blocked>`, plus `/marker` or `/no-marker` when
    /// the exchange names a response marker.
    Relay(Box<RelayExchange>),
    /// A WebSocket upgrade and one client text message through the relay the
    /// proxy runs for an allowed connection. See [`WebSocketExchange`].
    /// Outcome: `deny`, `passthrough`, `<status>/blocked` when the upgrade
    /// is refused, or `101/message-forwarded` or `101/message-blocked`.
    WebSocket(Box<WebSocketExchange>),
}

/// One WebSocket session for [`Probe::WebSocket`].
///
/// The connection and relay mode follow [`RelayExchange`]. The upstream
/// accepts the upgrade once it receives it, then the client sends `message`
/// as one masked text frame.
struct WebSocketExchange {
    ctx: L7EvalContext,
    route_selected: bool,
    /// The raw upgrade request.
    upgrade: String,
    /// The client text message sent after the upgrade.
    message: String,
}

/// One HTTP/1 exchange for [`Probe::Relay`].
///
/// The connection is `ctx.binary_path` to `ctx.host:ctx.port`. The relay
/// mode follows the proxy: route selection when the connection has more than
/// one endpoint config or `route_selected` is set, single-config inspection
/// otherwise.
struct RelayExchange {
    /// The tunnel context. `policy_name` and `request_default_port` are
    /// filled from the connection decision.
    ctx: L7EvalContext,
    route_selected: bool,
    /// The raw request bytes. Use `Connection: close` so the relay ends.
    request: String,
    /// What the upstream answers once it receives a complete request.
    upstream_response: String,
    /// Text whose presence in the client response is part of the outcome.
    marker: Option<&'static str>,
}

/// An upstream reply with no body.
const NO_CONTENT: &str =
    "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

struct Case {
    name: Cow<'static, str>,
    probe: Probe,
    expect: Expect,
    /// The YAML outcome the ported test asserts, when the case checks it.
    yaml: Option<&'static str>,
}

impl Case {
    /// Also requires the YAML engine's outcome to be `outcome`.
    ///
    /// For a port whose YAML side loads differently from the original test,
    /// this keeps the original's assertion.
    fn asserting_yaml(self, outcome: &'static str) -> Self {
        Self {
            yaml: Some(outcome),
            ..self
        }
    }
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
fn same(name: impl Into<Cow<'static, str>>, request: L7RequestInfo) -> Case {
    same_probe(
        name,
        Probe::Request {
            ctx: None,
            request: Box::new(request),
        },
    )
}

/// A request case recorded as a known difference.
fn diverges(
    name: impl Into<Cow<'static, str>>,
    request: L7RequestInfo,
    reason: &'static str,
) -> Case {
    diverges_probe(
        name,
        Probe::Request {
            ctx: None,
            request: Box::new(request),
        },
        reason,
    )
}

fn same_probe(name: impl Into<Cow<'static, str>>, probe: Probe) -> Case {
    Case {
        name: name.into(),
        probe,
        expect: Expect::Same,
        yaml: None,
    }
}

fn diverges_probe(name: impl Into<Cow<'static, str>>, probe: Probe, reason: &'static str) -> Case {
    Case {
        name: name.into(),
        probe,
        expect: Expect::Diverges(reason),
        yaml: None,
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

/// A token-grant owner probe with an explicit context.
fn owners_in(ctx: L7EvalContext, request: L7RequestInfo) -> Probe {
    Probe::Owners {
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

/// A scenario whose network rules all come from attached providers.
///
/// Each format receives `rules` the way the gateway composes provider rules
/// into it: a YAML sandbox enforces them as network policies, and a Cedar
/// sandbox receives them as `provider_credential_rules` beside `cedar`, which
/// alone decides access. Use it for token grants, which the gateway stamps on
/// provider endpoints.
struct ProviderScenario<'a> {
    name: &'a str,
    /// Default host for [`Probe::Request`] and [`Probe::Owners`] cases without a `ctx`.
    host: &'a str,
    rules: Vec<openshell_core::proto::NetworkPolicyRule>,
    cedar: &'a str,
    cases: Vec<Case>,
}

/// A scenario whose Cedar sandbox also has endpoint settings.
///
/// `settings` is middleware file text with an `endpoint_settings` section,
/// parsed and validated as the CLI parses `--middleware`. The YAML policy
/// carries the same settings on its own endpoints.
struct SettingsScenario<'a> {
    name: &'a str,
    /// Default host for [`Probe::Request`] cases without a `ctx`.
    host: &'a str,
    yaml: &'a str,
    cedar: &'a str,
    settings: &'a str,
    cases: Vec<Case>,
}

/// Both engines for one scenario.
struct Engines {
    opa: Arc<OpaEngine>,
    cedar: Arc<CedarOnlyEngine>,
    /// The empty-policy OPA engine a Cedar sandbox builds its tunnels from.
    plumbing: OpaEngine,
}

impl Engines {
    fn load(scenario: &Scenario<'_>) -> Self {
        let opa = OpaEngine::from_strings(REGO, scenario.yaml)
            .unwrap_or_else(|error| panic!("{}: YAML policy loads: {error}", scenario.name));
        let cedar = CedarOnlyEngine::from_policy_str(scenario.cedar)
            .unwrap_or_else(|error| panic!("{}: Cedar policy loads: {error}", scenario.name));
        Self::new(opa, cedar)
    }

    fn load_providers(scenario: &ProviderScenario<'_>) -> Self {
        let rules: HashMap<_, _> = scenario
            .rules
            .iter()
            .map(|rule| (rule.name.clone(), rule.clone()))
            .collect();
        assert_eq!(rules.len(), scenario.rules.len(), "rule names are unique");
        let yaml = openshell_core::proto::SandboxPolicy {
            network_policies: rules.clone(),
            ..Default::default()
        };
        let cedar = openshell_core::proto::SandboxPolicy {
            cedar_policy_source: scenario.cedar.to_string(),
            provider_credential_rules: rules,
            ..Default::default()
        };
        let opa = OpaEngine::from_proto(&yaml)
            .unwrap_or_else(|error| panic!("{}: YAML policy loads: {error}", scenario.name));
        let cedar = CedarOnlyEngine::from_proto(&cedar)
            .unwrap_or_else(|error| panic!("{}: Cedar policy loads: {error}", scenario.name));
        Self::new(opa, cedar)
    }

    fn load_settings(scenario: &SettingsScenario<'_>) -> Self {
        let opa = OpaEngine::from_strings(REGO, scenario.yaml)
            .unwrap_or_else(|error| panic!("{}: YAML policy loads: {error}", scenario.name));
        let file = openshell_policy::parse_middleware_yaml(scenario.settings)
            .unwrap_or_else(|error| panic!("{}: settings parse: {error:?}", scenario.name));
        let policy = openshell_core::proto::SandboxPolicy {
            cedar_policy_source: scenario.cedar.to_string(),
            network_middlewares: file.network_middlewares,
            endpoint_settings: file.endpoint_settings,
            ..Default::default()
        };
        openshell_policy::validate_sandbox_policy(&policy)
            .unwrap_or_else(|errors| panic!("{}: policy validates: {errors:?}", scenario.name));
        let cedar = CedarOnlyEngine::from_proto(&policy)
            .unwrap_or_else(|error| panic!("{}: Cedar policy loads: {error}", scenario.name));
        Self::new(opa, cedar)
    }

    fn new(opa: OpaEngine, cedar: CedarOnlyEngine) -> Self {
        let plumbing =
            OpaEngine::from_strings(REGO, "network_policies: {}").expect("plumbing engine loads");
        Self {
            opa: Arc::new(opa),
            cedar: Arc::new(cedar),
            plumbing,
        }
    }

    /// Returns the `(yaml, cedar)` outcomes. Evaluation errors count as a
    /// denial, as they do in the proxy, and are noted in the report.
    fn outcomes(&self, host: &str, probe: &Probe) -> (String, String) {
        match probe {
            Probe::Request { ctx, request } => {
                let ctx = ctx
                    .as_deref()
                    .cloned()
                    .unwrap_or_else(|| l7_ctx(host, 443, BINARY));
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
            Probe::MatchedEndpoints(input) => (
                matched_endpoints_outcome(
                    &self.opa.authorize_egress(input),
                    &self.opa.policy_dns_eligibility_snapshot(),
                ),
                matched_endpoints_outcome(
                    &self.cedar.authorize_egress(input),
                    &self.cedar.policy_dns_eligibility_snapshot(),
                ),
            ),
            Probe::DnsRecords => (
                dns_records_outcome(&self.opa.policy_dns_eligibility_snapshot()),
                dns_records_outcome(&self.cedar.policy_dns_eligibility_snapshot()),
            ),
            Probe::TransparentOpen {
                name,
                port,
                binary,
                answers,
            } => {
                let open = |engine: crate::policy_engine::PolicyEngine| {
                    test_runtime().block_on(transparent_open_outcome(
                        engine, name, *port, binary, answers,
                    ))
                };
                (
                    open(Arc::clone(&self.opa).into()),
                    open(Arc::clone(&self.cedar).into()),
                )
            }
            Probe::DnsAnswers {
                name,
                port,
                answers,
            } => {
                let pinned = |engine: crate::policy_engine::PolicyEngine| {
                    test_runtime().block_on(dns_answers_outcome(engine, name, *port, answers))
                };
                (
                    pinned(Arc::clone(&self.opa).into()),
                    pinned(Arc::clone(&self.cedar).into()),
                )
            }
            Probe::Destination { input, addresses } => {
                let outcome = |engine: crate::policy_engine::PolicyEngine| {
                    crate::proxy::connect_destination_outcome_for_test(&engine, input, addresses)
                };
                (
                    outcome(Arc::clone(&self.opa).into()),
                    outcome(Arc::clone(&self.cedar).into()),
                )
            }
            Probe::Owners { ctx, request } => {
                let ctx = ctx
                    .as_deref()
                    .cloned()
                    .unwrap_or_else(|| l7_ctx(host, 443, BINARY));
                let owners = |tunnel: miette::Result<crate::opa::TunnelPolicyEngine>| {
                    tunnel.and_then(|tunnel| {
                        crate::l7::relay::admitted_token_grant_owners(&tunnel, &ctx, request)
                    })
                };
                let yaml = owners(
                    self.opa
                        .clone_engine_for_tunnel(self.opa.current_generation()),
                );
                let cedar = owners(
                    crate::policy_engine::PolicyEngine::from(Arc::clone(&self.cedar))
                        .tunnel_engine(&self.plumbing, self.cedar.current_generation()),
                );
                (owners_outcome(&yaml), owners_outcome(&cedar))
            }
            Probe::Configs(input) => (
                configs_outcome(&self.opa.authorize_egress(input)),
                configs_outcome(&self.cedar.authorize_egress(input)),
            ),
            Probe::TlsMode(input) => (
                tls_mode_outcome(&self.opa.authorize_egress(input)),
                tls_mode_outcome(&self.cedar.authorize_egress(input)),
            ),
            Probe::DenyReason { ctx, request } => {
                let ctx = ctx
                    .as_deref()
                    .cloned()
                    .unwrap_or_else(|| l7_ctx(host, 443, BINARY));
                let yaml = self
                    .opa
                    .clone_engine_for_tunnel(self.opa.current_generation())
                    .and_then(|tunnel| tunnel.evaluate_request(&ctx, request));
                let cedar = self
                    .cedar
                    .l7_handle(self.cedar.current_generation())
                    .evaluate_request(&ctx, request);
                (deny_reason_outcome(&yaml), deny_reason_outcome(&cedar))
            }
            Probe::Relay(exchange) => self.relayed(&exchange.ctx, |relay| {
                relay.run(
                    exchange.route_selected,
                    &exchange.request,
                    &exchange.upstream_response,
                    exchange.marker,
                )
            }),
            Probe::WebSocket(exchange) => self.relayed(&exchange.ctx, |relay| {
                relay.run_websocket(
                    exchange.route_selected,
                    &exchange.upgrade,
                    &exchange.message,
                )
            }),
        }
    }
}

impl Engines {
    /// Returns the `(yaml, cedar)` outcomes of `exchange` over a connection
    /// from `ctx.binary_path` to `ctx.host:ctx.port`.
    fn relayed(
        &self,
        ctx: &L7EvalContext,
        exchange: impl Fn(PreparedRelay) -> String,
    ) -> (String, String) {
        let input = network(&ctx.host, ctx.port, &ctx.binary_path);
        let yaml = PreparedRelay::prepare(
            self.opa.authorize_egress(&input),
            |generation| self.opa.clone_engine_for_tunnel(generation),
            ctx,
        )
        .map_or_else(|outcome| outcome, &exchange);
        let cedar = PreparedRelay::prepare(
            self.cedar.authorize_egress(&input),
            |generation| {
                crate::policy_engine::PolicyEngine::from(Arc::clone(&self.cedar))
                    .tunnel_engine(&self.plumbing, generation)
            },
            ctx,
        )
        .map_or_else(|outcome| outcome, &exchange);
        (yaml, cedar)
    }
}

fn configs_outcome(result: &miette::Result<EgressAuthorization>) -> String {
    match result {
        Ok(authorization) if matches!(authorization.action, NetworkAction::Allow { .. }) => {
            let mut summaries: Vec<String> = authorization
                .endpoint_configs
                .iter()
                .filter_map(crate::l7::parse_l7_config)
                .map(|config| {
                    let versions: Vec<&str> = config
                        .mcp_versions
                        .iter()
                        .map(|version| version.as_str())
                        .collect();
                    format!(
                        "{:?}/{:?}/tls={:?}/mcp=[{}]/strict={}/slash={}/jsonrpc={}/graphql={}",
                        config.protocol,
                        config.enforcement,
                        config.tls,
                        versions.join(","),
                        config.mcp_strict_tool_names,
                        config.allow_encoded_slash,
                        config.json_rpc_max_body_bytes,
                        config.graphql_max_body_bytes,
                    )
                })
                .collect();
            summaries.sort();
            summaries.dedup();
            if summaries.is_empty() {
                "none".to_string()
            } else {
                summaries.join(";")
            }
        }
        _ => "deny".to_string(),
    }
}

fn tls_mode_outcome(result: &miette::Result<EgressAuthorization>) -> String {
    match result {
        Ok(authorization) if matches!(authorization.action, NetworkAction::Allow { .. }) => {
            let mode = authorization
                .endpoint_configs
                .first()
                .map_or(crate::l7::TlsMode::Auto, crate::l7::parse_tls_mode);
            format!("{mode:?}")
        }
        _ => "deny".to_string(),
    }
}

fn deny_reason_outcome(result: &miette::Result<(bool, String)>) -> String {
    match result {
        Ok((true, _)) => "allow".to_string(),
        Ok((false, reason)) => format!("deny: {reason}"),
        Err(error) => format!("deny (error: {})", error_line(error)),
    }
}

/// An allowed, inspected connection ready to relay one exchange.
struct PreparedRelay {
    configs: Vec<crate::l7::L7EndpointConfig>,
    engine: crate::opa::TunnelPolicyEngine,
    ctx: L7EvalContext,
}

impl PreparedRelay {
    /// Prepares the relay for one engine's connection decision, or returns
    /// the outcome when the connection is denied or not inspected.
    fn prepare(
        authorization: miette::Result<EgressAuthorization>,
        tunnel: impl FnOnce(u64) -> miette::Result<crate::opa::TunnelPolicyEngine>,
        ctx: &L7EvalContext,
    ) -> Result<Self, String> {
        let authorization =
            authorization.map_err(|error| format!("deny (error: {})", error_line(&error)))?;
        let NetworkAction::Allow { matched_policy } = &authorization.action else {
            return Err("deny".to_string());
        };
        let configs: Vec<_> = authorization
            .endpoint_configs
            .iter()
            .filter_map(crate::l7::parse_l7_config)
            .collect();
        if configs.is_empty() {
            return Err("passthrough".to_string());
        }
        let engine = tunnel(authorization.generation)
            .map_err(|error| format!("deny (error: {})", error_line(&error)))?;
        Ok(Self {
            configs,
            engine,
            ctx: L7EvalContext {
                policy_name: matched_policy.clone().unwrap_or_default(),
                request_default_port: Some(ctx.port),
                ..ctx.clone()
            },
        })
    }

    /// Runs one HTTP/1 exchange; see [`Probe::Relay`] for the outcome.
    fn run(
        self,
        route_selected: bool,
        request: &str,
        upstream_response: &str,
        marker: Option<&str>,
    ) -> String {
        let Some((response, forwarded)) =
            test_runtime().block_on(run_relay(self, route_selected, request, upstream_response))
        else {
            return "timeout".to_string();
        };
        let status = response.split(' ').nth(1).unwrap_or("none");
        let delivery = if forwarded.is_empty() {
            "blocked"
        } else {
            "forwarded"
        };
        match marker {
            Some(marker) if response.contains(marker) => format!("{status}/{delivery}/marker"),
            Some(_) => format!("{status}/{delivery}/no-marker"),
            None => format!("{status}/{delivery}"),
        }
    }

    /// Runs one WebSocket session; see [`Probe::WebSocket`] for the outcome.
    fn run_websocket(self, route_selected: bool, upgrade: &str, message: &str) -> String {
        test_runtime()
            .block_on(run_websocket(self, route_selected, upgrade, message))
            .unwrap_or_else(|| "timeout".to_string())
    }

    /// Spawns the relay between `client` and `upstream`, choosing the relay
    /// mode as the proxy does.
    fn spawn(
        self,
        route_selected: bool,
        mut client: tokio::io::DuplexStream,
        mut upstream: tokio::io::DuplexStream,
    ) -> tokio::task::JoinHandle<miette::Result<()>> {
        tokio::spawn(async move {
            if route_selected || self.configs.len() > 1 {
                crate::l7::relay::relay_with_route_selection(
                    &self.configs,
                    self.engine,
                    &mut client,
                    &mut upstream,
                    &self.ctx,
                )
                .await
            } else {
                crate::l7::relay::relay_with_inspection(
                    &self.configs[0],
                    self.engine,
                    &mut client,
                    &mut upstream,
                    &self.ctx,
                )
                .await
            }
        })
    }
}

fn test_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime builds")
}

/// How long one relay step may take before the exchange counts as stuck.
const RELAY_LIMIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Relays `request` and returns the client response and the bytes the
/// upstream received, or `None` if the exchange did not finish.
async fn run_relay(
    relay: PreparedRelay,
    route_selected: bool,
    request: &str,
    upstream_response: &str,
) -> Option<(String, Vec<u8>)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut app, relay_client) = tokio::io::duplex(65536);
    let (relay_upstream, mut upstream) = tokio::io::duplex(65536);
    let relay = relay.spawn(route_selected, relay_client, relay_upstream);
    let upstream_response = upstream_response.to_string();
    let server = tokio::spawn(async move {
        let mut forwarded = Vec::new();
        let mut bytes = [0; 4096];
        let mut answered = false;
        loop {
            let Ok(count) = upstream.read(&mut bytes).await else {
                return forwarded;
            };
            if count == 0 {
                return forwarded;
            }
            forwarded.extend_from_slice(&bytes[..count]);
            if !answered && http_message_complete(&forwarded) {
                answered = true;
                if upstream
                    .write_all(upstream_response.as_bytes())
                    .await
                    .is_err()
                {
                    return forwarded;
                }
            }
        }
    });
    app.write_all(request.as_bytes()).await.ok()?;
    let mut response = Vec::new();
    let read = tokio::time::timeout(RELAY_LIMIT, async {
        let mut bytes = [0; 4096];
        loop {
            match app.read(&mut bytes).await {
                Ok(0) | Err(_) => break,
                Ok(count) => response.extend_from_slice(&bytes[..count]),
            }
            if http_message_complete(&response) {
                break;
            }
        }
    })
    .await;
    drop(app);
    read.ok()?;
    let _ = tokio::time::timeout(RELAY_LIMIT, relay).await.ok()?;
    let forwarded = tokio::time::timeout(RELAY_LIMIT, server).await.ok()?.ok()?;
    Some((String::from_utf8_lossy(&response).into_owned(), forwarded))
}

/// Runs a WebSocket upgrade and one client text message through the relay.
///
/// Returns `None` if the session did not finish.
async fn run_websocket(
    relay: PreparedRelay,
    route_selected: bool,
    upgrade: &str,
    message: &str,
) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The upstream's answer to the upgrade. The accept key is not checked.
    const SWITCHING: &str = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
        Connection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    /// What the upstream sends back once the message arrives, so the client
    /// knows it was forwarded.
    const ACK: &[u8] = b"\x81\x03ack";

    let frame = masked_text_frame(message.as_bytes());
    let (mut app, relay_client) = tokio::io::duplex(65536);
    let (relay_upstream, mut upstream) = tokio::io::duplex(65536);
    let relay = relay.spawn(route_selected, relay_client, relay_upstream);
    let expected = frame.clone();
    let server = tokio::spawn(async move {
        let mut seen = Vec::new();
        let mut bytes = [0; 4096];
        let (mut upgraded, mut acked) = (false, false);
        loop {
            let Ok(count) = upstream.read(&mut bytes).await else {
                return seen;
            };
            if count == 0 {
                return seen;
            }
            seen.extend_from_slice(&bytes[..count]);
            if !upgraded && seen.windows(4).any(|window| window == b"\r\n\r\n") {
                upgraded = true;
                if upstream.write_all(SWITCHING.as_bytes()).await.is_err() {
                    return seen;
                }
            }
            if !acked && contains(&seen, &expected) {
                acked = true;
                if upstream.write_all(ACK).await.is_err() {
                    return seen;
                }
            }
        }
    });

    app.write_all(upgrade.as_bytes()).await.ok()?;
    let mut response = Vec::new();
    let mut byte = [0; 1];
    while !response.ends_with(b"\r\n\r\n") {
        match tokio::time::timeout(RELAY_LIMIT, app.read(&mut byte)).await {
            Ok(Ok(1)) => response.push(byte[0]),
            Ok(_) => break,
            Err(_) => return None,
        }
    }
    let response = String::from_utf8_lossy(&response).into_owned();
    let status = response.split(' ').nth(1).unwrap_or("none").to_string();
    if status == "101" {
        app.write_all(&frame).await.ok()?;
        // The upstream's acknowledgement, or the relay's close and EOF.
        let mut reply = [0; 64];
        tokio::time::timeout(RELAY_LIMIT, app.read(&mut reply))
            .await
            .ok()?
            .ok()?;
    } else {
        // A refusal closes the connection after its body.
        let mut rest = Vec::new();
        let _ = tokio::time::timeout(RELAY_LIMIT, app.read_to_end(&mut rest)).await;
    }
    drop(app);
    let _ = tokio::time::timeout(RELAY_LIMIT, relay).await.ok()?;
    let seen = tokio::time::timeout(RELAY_LIMIT, server).await.ok()?.ok()?;
    Some(if status != "101" {
        format!("{status}/blocked")
    } else if contains(&seen, &frame) {
        "101/message-forwarded".to_string()
    } else {
        "101/message-blocked".to_string()
    })
}

/// Returns a client-to-server (masked) WebSocket text frame for `payload`.
fn masked_text_frame(payload: &[u8]) -> Vec<u8> {
    const MASK: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];
    let mut frame = vec![0x81];
    let length = u16::try_from(payload.len()).expect("test messages fit in a 16-bit length");
    match u8::try_from(length) {
        Ok(short) if short < 126 => frame.push(0x80 | short),
        _ => {
            frame.push(0x80 | 0x7e);
            frame.extend_from_slice(&length.to_be_bytes());
        }
    }
    frame.extend_from_slice(&MASK);
    frame.extend(
        payload
            .iter()
            .zip(MASK.iter().cycle())
            .map(|(byte, mask)| byte ^ mask),
    );
    frame
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Returns whether `bytes` hold a complete HTTP/1 message with a
/// `Content-Length` body (or none).
fn http_message_complete(bytes: &[u8]) -> bool {
    let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let header = String::from_utf8_lossy(&bytes[..header_end]);
    let length = header
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    bytes.len() >= header_end + 4 + length
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

fn owners_outcome(result: &miette::Result<std::collections::HashSet<String>>) -> String {
    match result {
        Ok(owners) if owners.is_empty() => "none".to_string(),
        Ok(owners) => {
            let mut owners: Vec<_> = owners.iter().map(String::as_str).collect();
            owners.sort_unstable();
            owners.join(",")
        }
        Err(error) => format!("none (error: {})", error_line(error)),
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

fn dns_records_outcome(
    snapshot: &miette::Result<crate::opa::PolicyDnsEligibilitySnapshot>,
) -> String {
    match snapshot {
        Ok(snapshot) => records_outcome(&snapshot.endpoints),
        Err(error) => format!("none (error: {})", error_line(error)),
    }
}

/// Summarizes endpoint records as sorted `host:ports` entries, with `/tcp`
/// for a native TCP record, joined by `;`, or `none`.
fn records_outcome(records: &[crate::opa::MatchedEndpoint]) -> String {
    let mut summaries: Vec<String> = records
        .iter()
        .map(|record| {
            let endpoint = serde_json::to_value(&record.endpoint).unwrap_or_default();
            let ports: Vec<String> = endpoint
                .get("ports")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .map(ToString::to_string)
                .collect();
            let tcp = endpoint
                .get("protocol")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|protocol| protocol.eq_ignore_ascii_case("tcp"));
            format!(
                "{}:{}{}",
                endpoint
                    .get("host")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default(),
                ports.join(","),
                if tcp { "/tcp" } else { "" }
            )
        })
        .collect();
    summaries.sort();
    if summaries.is_empty() {
        "none".to_string()
    } else {
        summaries.join(";")
    }
}

fn matched_endpoints_outcome(
    result: &miette::Result<EgressAuthorization>,
    snapshot: &miette::Result<crate::opa::PolicyDnsEligibilitySnapshot>,
) -> String {
    let authorization = match result {
        Ok(authorization) if matches!(authorization.action, NetworkAction::Allow { .. }) => {
            authorization
        }
        Ok(_) => return "deny".to_string(),
        Err(error) => return format!("deny (error: {})", error_line(error)),
    };
    let records = records_outcome(&authorization.matched_endpoints);
    let in_snapshot = snapshot.as_ref().is_ok_and(|snapshot| {
        authorization.matched_endpoints.iter().all(|matched| {
            snapshot.endpoints.iter().any(|published| {
                published.policy_name == matched.policy_name
                    && published.endpoint_index == matched.endpoint_index
                    && published.endpoint == matched.endpoint
            })
        })
    });
    if in_snapshot {
        records
    } else {
        format!("{records} (not in DNS snapshot)")
    }
}

/// The upstream address every name resolves to for [`Probe::TransparentOpen`]
/// cases that do not name their answers.
const TRANSPARENT_UPSTREAM: std::net::Ipv4Addr = std::net::Ipv4Addr::new(203, 0, 113, 8);

/// A trusted resolver that answers every name with the same addresses.
struct FixedResolver(Vec<IpAddr>);

impl crate::policy_dns::TrustedResolver for FixedResolver {
    async fn resolve(
        &self,
        _name: &crate::policy_dns::NormalizedName,
        _family: crate::policy_dns::AddressFamily,
    ) -> Result<crate::policy_dns::TrustedAnswer, crate::policy_dns::TrustedResolveError> {
        Ok(crate::policy_dns::TrustedAnswer {
            addresses: self.0.clone(),
            ttl: std::time::Duration::from_secs(30),
        })
    }
}

/// Resolves `name` through `engine`'s policy DNS, with the trusted resolver
/// answering `answers`, and returns the store holding the mapping.
async fn policy_dns_answer(
    engine: &crate::policy_engine::PolicyEngine,
    name: &str,
    answers: &[IpAddr],
) -> Result<
    (
        crate::policy_dns::SyntheticAnswer,
        Arc<crate::policy_dns::ResolvedEndpointStore>,
    ),
    String,
> {
    use crate::policy_dns::{
        AddressFamily, PolicyDnsService, ResolvedEndpointStore, StoreConfig, SyntheticPools,
    };
    use std::net::{Ipv4Addr, Ipv6Addr};

    // Like the production pools, skip the reserved sandbox-local address.
    let pools = SyntheticPools::new(
        Ipv4Addr::new(198, 18, 0, 2)..=Ipv4Addr::new(198, 18, 0, 9),
        Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, 1)..=Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, 8),
    )
    .expect("test pools are valid");
    let store = Arc::new(ResolvedEndpointStore::new(
        StoreConfig::new(pools, 16).expect("test store config is valid"),
    ));
    let dns = PolicyDnsService::new(
        engine.clone(),
        FixedResolver(answers.to_vec()),
        Arc::clone(&store),
        None,
    );
    dns.answer_query(name, AddressFamily::Ipv4, std::time::Instant::now())
        .await
        .map(|answer| (answer, store))
        .map_err(|error| format!("dns refused: {error}"))
}

/// Returns the addresses policy DNS pins for `name` on `port`; see
/// [`Probe::DnsAnswers`].
async fn dns_answers_outcome(
    engine: crate::policy_engine::PolicyEngine,
    name: &str,
    port: u16,
    answers: &[IpAddr],
) -> String {
    let (answer, store) = match policy_dns_answer(&engine, name, answers).await {
        Ok(resolved) => resolved,
        Err(refusal) => return refusal,
    };
    let Ok(mapping) = store.lookup(
        answer.address,
        port,
        answer.policy_generation,
        std::time::Instant::now(),
    ) else {
        return "no mapping for port".to_string();
    };
    let mut pinned: Vec<String> = mapping
        .pinned_addresses()
        .iter()
        .map(ToString::to_string)
        .collect();
    pinned.sort();
    pinned.join(",")
}

/// Resolves `name` through `engine`'s policy DNS and stages a transparent
/// open to the answer; see [`Probe::TransparentOpen`].
async fn transparent_open_outcome(
    engine: crate::policy_engine::PolicyEngine,
    name: &str,
    port: u16,
    binary: &str,
    answers: &[IpAddr],
) -> String {
    let (answer, store) = match policy_dns_answer(&engine, name, answers).await {
        Ok(resolved) => resolved,
        Err(refusal) => return refusal,
    };
    let destination = std::net::SocketAddr::new(answer.address, port);
    let outcome =
        crate::proxy::stage_transparent_open_for_test(&engine, &store, destination, binary).await;
    if outcome.dial_addresses.is_empty() {
        return format!("{:?}", outcome.decision);
    }
    let addresses: Vec<String> = outcome
        .dial_addresses
        .iter()
        .map(ToString::to_string)
        .collect();
    format!(
        "{:?}/{}/{}",
        outcome.decision,
        addresses.join(","),
        if outcome.correlated {
            "correlated"
        } else {
            "uncorrelated"
        }
    )
}

/// Runs a scenario's cases and returns its report rows and any failures.
fn run(name: &str, host: &str, engines: &Engines, cases: &[Case]) -> (String, Vec<String>) {
    let mut report = String::new();
    let mut failures = Vec::new();
    for case in cases {
        let (yaml, cedar) = engines.outcomes(host, &case.probe);
        // Compare the decision only; an evaluation error note is for the
        // report, and an error already counts as a denial.
        let decision = |outcome: &str| {
            outcome
                .split(" (error")
                .next()
                .unwrap_or_default()
                .to_string()
        };
        if let Some(expected) = case.yaml
            && decision(&yaml) != expected
        {
            failures.push(format!(
                "{name} / {}: the ported test asserts YAML {expected} but YAML {yaml}",
                case.name
            ));
        }
        let outcome = match (case.expect, decision(&yaml) == decision(&cedar)) {
            (Expect::Same, true) => "same".to_string(),
            (Expect::Diverges(reason), false) => format!("known difference: {reason}"),
            (Expect::Same, false) => {
                failures.push(format!(
                    "{name} / {}: YAML {yaml} but Cedar {cedar}",
                    case.name
                ));
                "MISMATCH".to_string()
            }
            (Expect::Diverges(reason), true) => {
                failures.push(format!(
                    "{name} / {}: expected a difference ({reason}) but both {yaml}",
                    case.name
                ));
                "UNEXPECTEDLY SAME".to_string()
            }
        };
        let _ = writeln!(
            report,
            "| {name} | {} | {yaml} | {cedar} | {outcome} |",
            case.name
        );
    }
    (report, failures)
}

fn assert_parity(scenario: &Scenario<'_>) {
    let engines = Engines::load(scenario);
    report_parity(run(scenario.name, scenario.host, &engines, &scenario.cases));
}

/// Runs a scenario's cases at startup, and again after each engine reloads
/// the same policy, for tests that check decisions survive a reload.
///
/// Reloading an unchanged Cedar source keeps the loaded engine, while YAML
/// rebuilds its engine; both must still agree.
fn assert_parity_across_reload(scenario: &Scenario<'_>) {
    let engines = Engines::load(scenario);
    let startup = format!("{} (startup)", scenario.name);
    let (mut report, mut failures) = run(&startup, scenario.host, &engines, &scenario.cases);
    engines
        .opa
        .reload(REGO, scenario.yaml)
        .unwrap_or_else(|error| panic!("{}: YAML policy reloads: {error}", scenario.name));
    engines
        .cedar
        .reload_from_policy_str(scenario.cedar)
        .unwrap_or_else(|error| panic!("{}: Cedar policy reloads: {error}", scenario.name));
    let reload = format!("{} (reload)", scenario.name);
    let (reloaded, reload_failures) = run(&reload, scenario.host, &engines, &scenario.cases);
    report.push_str(&reloaded);
    failures.extend(reload_failures);
    report_parity((report, failures));
}

fn assert_settings_parity(scenario: &SettingsScenario<'_>) {
    let engines = Engines::load_settings(scenario);
    report_parity(run(scenario.name, scenario.host, &engines, &scenario.cases));
}

fn assert_provider_parity(scenario: &ProviderScenario<'_>) {
    let engines = Engines::load_providers(scenario);
    report_parity(run(scenario.name, scenario.host, &engines, &scenario.cases));
}

fn report_parity((report, failures): (String, Vec<String>)) {
    println!("| Scenario | Case | YAML | Cedar | Result |\n|---|---|---|---|---|\n{report}");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
