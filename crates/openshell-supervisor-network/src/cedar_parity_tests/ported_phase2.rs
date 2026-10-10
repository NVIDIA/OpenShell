// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Ported YAML endpoint-setting tests (Cedar parity plan, phase 2).
//!
//! A YAML endpoint carries configuration such as `tls: skip`,
//! `allow_encoded_slash`, MCP revisions, and the GraphQL persisted-query
//! registry next to its rules. A Cedar sandbox gets the same configuration
//! from the `endpoint_settings` section of its middleware file
//! ([`SettingsScenario`]), and its access from the Cedar policy alone. Each
//! translation keeps the YAML endpoint's settings on a settings entry for
//! the same host and port. A YAML endpoint `path` that only scopes which
//! requests the rules apply to becomes a `context.path` condition, as in the
//! other ports; a settings entry gets a `path` only where the original
//! scopes a setting to one path of a shared `host:port`.
//!
//! The relay originals drive bytes through the L7 relay. Their ports do the
//! same with [`Probe::Relay`], using the endpoint configs and tunnel engine
//! each engine supplies, because the MCP revision and encoded-slash checks
//! the originals exercise run in the relay, outside the policy decision.

use super::ported_opa_a::{L7_TEST_CEDAR, L7_TEST_DATA};
use super::*;

use std::fmt::Write as _;

const PYTHON: &str = "/usr/bin/python3";
const NODE: &str = "/usr/bin/node";
const MCP_HOST: &str = "mcp.example.test";
const MCP_PORT: u16 = 8000;

/// The Cedar condition for a YAML binary entry with an exact path.
fn binary(path: &str) -> String {
    format!("(context.binary_path == \"{path}\" || context.ancestors.contains(\"{path}\"))")
}

/// A relay exchange from [`PYTHON`] to the MCP test endpoint.
fn mcp_exchange(
    route_selected: bool,
    request: String,
    upstream_response: &str,
    marker: Option<&'static str>,
) -> Probe {
    Probe::Relay(Box::new(RelayExchange {
        ctx: l7_ctx(MCP_HOST, MCP_PORT, PYTHON),
        route_selected,
        request,
        upstream_response: upstream_response.to_string(),
        marker,
    }))
}

/// An MCP request as the relay originals send it.
fn mcp_request(method: &str, headers: &str, body: &str) -> String {
    format!(
        "{method} /mcp HTTP/1.1\r\nHost: {MCP_HOST}:{MCP_PORT}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// A sessionless (2026-07-28) MCP body, as `sessionless_mcp_body` builds it.
fn sessionless_mcp_body(method: &str, mut params: serde_json::Value) -> String {
    params["_meta"] = serde_json::json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string()
}

/// The `mcp_api` endpoint of the MCP relay originals: tool `read_status`
/// allowed, `delete_resource` denied, under `enforcement` and `versions`.
fn mcp_tool_yaml(enforcement: &str, versions: &str) -> String {
    format!(
        r"
network_policies:
  mcp_api:
    name: mcp_api
    endpoints:
      - host: {MCP_HOST}
        port: {MCP_PORT}
        path: /mcp
        protocol: mcp
        enforcement: {enforcement}
        mcp:
          versions: {versions}
        rules:
          - allow:
              method: tools/call
              tool: read_status
        deny_rules:
          - method: tools/call
            tool: delete_resource
    binaries:
      - {{ path: {PYTHON} }}
"
    )
}

/// The Cedar translation of [`mcp_tool_yaml`].
///
/// YAML MCP endpoints implicitly admit the receive stream and response
/// frames; the second permit states that explicitly.
fn mcp_tool_cedar(enforcement_annotation: &str) -> String {
    let binary = binary(PYTHON);
    format!(
        r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"{MCP_HOST}:{MCP_PORT}")
when {{ {binary} }};
@protocol("mcp"){enforcement_annotation}
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"{MCP_HOST}:{MCP_PORT}")
when {{
    {binary}
    && context.path == "/mcp"
    && !context.jsonrpc_response
    && context.mcp_method_class == "available"
    && context.jsonrpc_method == "tools/call"
    && context.mcp_tool == "read_status"
}};{enforcement_annotation}
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"{MCP_HOST}:{MCP_PORT}")
when {{
    {binary}
    && context.path == "/mcp"
    && ((context.method == "GET" && context.jsonrpc_receive_stream)
        || context.jsonrpc_response)
}};{enforcement_annotation}
forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"{MCP_HOST}:{MCP_PORT}")
when {{ context.jsonrpc_method == "tools/call" && context.mcp_tool == "delete_resource" }};
"#
    )
}

/// The middleware file carrying [`mcp_tool_yaml`]'s MCP revisions.
fn mcp_settings(versions: &str) -> String {
    format!(
        "endpoint_settings:\n  - host: {MCP_HOST}\n    port: {MCP_PORT}\n    mcp:\n      versions: {versions}\n"
    )
}

/// The `@enforcement` annotation for a YAML enforcement mode.
fn enforcement_annotation(enforcement: &str) -> &'static str {
    if enforcement == "audit" {
        "\n@enforcement(\"audit\")"
    } else {
        ""
    }
}

// ---------------------------------------------------------------------------
// opa.rs
// ---------------------------------------------------------------------------

#[test]
fn ported_mcp_strict_tool_names_opt_out() {
    let curl = binary(BINARY);
    let cedar = format!(
        r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"mcp.example.com:443")
when {{ {curl} }};
@protocol("mcp")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"mcp.example.com:443")
when {{
    {curl}
    && context.path == "/mcp"
    && !context.jsonrpc_response
    && context.mcp_method_class == "available"
    && context.jsonrpc_method == "tools/call"
}};
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"mcp.example.com:443")
when {{
    {curl}
    && context.path == "/mcp"
    && ((context.method == "GET" && context.jsonrpc_receive_stream)
        || context.jsonrpc_response)
}};
"#
    );
    assert_settings_parity(&SettingsScenario {
        name: "opa.rs MCP strict tool names",
        host: "mcp.example.com",
        yaml: r#"
network_policies:
  mcp:
    name: mcp
    endpoints:
      - host: mcp.example.com
        port: 443
        path: /mcp
        protocol: mcp
        enforcement: enforce
        mcp:
          versions: ["2025-11-25", "2025-03-26"]
          strict_tool_names: false
        rules:
          - allow:
              method: tools/call
    binaries:
      - { path: /usr/bin/curl }
"#,
        cedar: &cedar,
        settings: r#"
endpoint_settings:
  - host: mcp.example.com
    port: 443
    mcp:
      versions: ["2025-11-25", "2025-03-26"]
      strict_tool_names: false
"#,
        cases: vec![
            same_probe(
                "opa.rs::l7_endpoint_config_preserves_mcp_strict_tool_names_opt_out",
                Probe::Configs(network("mcp.example.com", 443, BINARY)),
            )
            .asserting_yaml(
                "Mcp/Enforce/tls=Auto/mcp=[2025-03-26,2025-11-25]/strict=false/slash=false/jsonrpc=65536/graphql=65536",
            ),
        ],
    });
}

/// A hash-only persisted query, as `l7_graphql_input` describes it.
fn hash_only_query(hash: &str) -> L7RequestInfo {
    let mut operation = operation("", Some("Viewer"), &[]);
    operation.persisted_query = true;
    operation.persisted_query_hash = Some(hash.to_string());
    graphql(vec![operation])
}

/// The persisted-query settings of `graphql_api` in [`L7_TEST_DATA`].
const GRAPHQL_REGISTRY_SETTINGS: &str = r"
endpoint_settings:
  - host: api.graphql.com
    port: 443
    persisted_queries: allow_registered
    graphql_persisted_queries:
      abc123:
        operation_type: query
        operation_name: Viewer
        fields: [viewer]
";

#[test]
fn ported_graphql_persisted_query_registry() {
    assert_settings_parity(&SettingsScenario {
        name: "opa.rs GraphQL persisted queries",
        host: "api.graphql.com",
        yaml: L7_TEST_DATA,
        cedar: L7_TEST_CEDAR,
        settings: GRAPHQL_REGISTRY_SETTINGS,
        cases: vec![
            same(
                "opa.rs::l7_graphql_registered_hash_only_query_allowed",
                hash_only_query("abc123"),
            )
            .asserting_yaml("allow"),
            same(
                "opa.rs::l7_graphql_unregistered_hash_only_query_denied",
                hash_only_query("missing"),
            )
            .asserting_yaml("deny"),
            same_probe(
                "opa.rs::l7_graphql_unregistered_hash_only_query_has_deny_reason",
                Probe::DenyReason {
                    ctx: None,
                    request: Box::new(hash_only_query("missing")),
                },
            )
            .asserting_yaml("deny: GraphQL persisted query is not registered"),
        ],
    });
}

#[test]
fn graphql_persisted_query_registry_requires_allow_registered() {
    // Without `persisted_queries: allow_registered`, YAML denies every
    // hash-only query, registered or not; so must Cedar.
    assert_settings_parity(&SettingsScenario {
        name: "GraphQL persisted queries default to deny",
        host: "api.graphql.com",
        yaml: &L7_TEST_DATA.replace(
            "persisted_queries: allow_registered",
            "persisted_queries: deny",
        ),
        cedar: L7_TEST_CEDAR,
        settings: &GRAPHQL_REGISTRY_SETTINGS.replace(
            "persisted_queries: allow_registered",
            "persisted_queries: deny",
        ),
        cases: vec![
            same("registered hash, mode deny", hash_only_query("abc123")).asserting_yaml("deny"),
            same_probe(
                "registered hash, mode deny, reason",
                Probe::DenyReason {
                    ctx: None,
                    request: Box::new(hash_only_query("abc123")),
                },
            ),
        ],
    });
}

// ---------------------------------------------------------------------------
// proxy.rs
// ---------------------------------------------------------------------------

/// The handler tests' policy: the temp-dir binary glob, with `tls_line`.
fn handler_yaml(tls_line: &str) -> String {
    format!(
        r#"network_policies:
  test_allow:
    name: test_allow
    endpoints:
      - {{ host: "203.0.113.10", port: 443{tls_line} }}
    binaries:
      - {{ path: "/tmp/openshell-connect-test/*" }}
"#
    )
}

const HANDLER_CEDAR: &str = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"203.0.113.10:443")
when { context.binary_path like("/tmp/openshell-connect-test/*", "/") };
"#;

const HANDLER_BINARY: &str = "/tmp/openshell-connect-test/connect-bash";

#[test]
fn ported_tls_skip_route() {
    // The originals drive a real CONNECT through the handler (Linux only)
    // and read the TLS mode from the authorization; the port checks the
    // authorization and the TLS mode the handler reads from it.
    let input = || network("203.0.113.10", 443, HANDLER_BINARY);
    let skip_yaml = handler_yaml(", tls: skip");
    assert_settings_parity(&SettingsScenario {
        name: "proxy.rs tls: skip",
        host: "203.0.113.10",
        yaml: &skip_yaml,
        cedar: HANDLER_CEDAR,
        settings: "endpoint_settings:\n  - { host: \"203.0.113.10\", port: 443, tls: skip }\n",
        cases: vec![
            same_probe(
                "proxy.rs::connect_handler_tls_skip_route_is_not_refused/allowed",
                Probe::Connect(input()),
            )
            .asserting_yaml("allow"),
            same_probe(
                "proxy.rs::connect_handler_tls_skip_route_is_not_refused/tls mode",
                Probe::TlsMode(input()),
            )
            .asserting_yaml("Skip"),
            same_probe(
                "proxy.rs::handler_test_policy_allows_glob_binary_and_reads_tls_mode/tls: skip",
                Probe::TlsMode(input()),
            )
            .asserting_yaml("Skip"),
            same_probe(
                "proxy.rs::connect_handler_tls_skip_route_is_not_refused/no inspection",
                Probe::Inspection(input()),
            ),
        ],
    });
    let auto_yaml = handler_yaml("");
    assert_settings_parity(&SettingsScenario {
        name: "proxy.rs terminating endpoint",
        host: "203.0.113.10",
        yaml: &auto_yaml,
        cedar: HANDLER_CEDAR,
        settings: "",
        cases: vec![
            same_probe(
                "proxy.rs::handler_test_policy_allows_glob_binary_and_reads_tls_mode/terminating",
                Probe::TlsMode(input()),
            )
            .asserting_yaml("Auto"),
        ],
    });
}

// ---------------------------------------------------------------------------
// relay.rs: MCP revisions
// ---------------------------------------------------------------------------

#[test]
fn ported_mcp_march_batches_authorize_every_member() {
    let call = |id: u32, name: &str| {
        serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": name, "arguments": {}}
        })
    };
    let allowed = call(1, "read_status");
    let denied = call(2, "delete_resource");
    let malformed = serde_json::json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": 7, "arguments": {}}
    });
    let batches = [
        (
            "allowed",
            serde_json::json!([allowed, call(2, "read_status")]),
            false,
            false,
        ),
        (
            "deny last",
            serde_json::json!([allowed, denied]),
            true,
            false,
        ),
        (
            "deny first",
            serde_json::json!([denied, allowed]),
            true,
            false,
        ),
        (
            "malformed last",
            serde_json::json!([allowed, malformed]),
            false,
            true,
        ),
    ];
    let versions = r#"["2025-03-26"]"#;
    for enforcement in ["enforce", "audit"] {
        let yaml = mcp_tool_yaml(enforcement, versions);
        let cedar = mcp_tool_cedar(enforcement_annotation(enforcement));
        let settings = mcp_settings(versions);
        let mut cases = Vec::new();
        for route_selected in [false, true] {
            for (case, members, policy_denied, malformed) in &batches {
                // Audit forwards policy denials, but never malformed MCP.
                let forwarded = !*malformed && (!*policy_denied || enforcement == "audit");
                let expected = if *malformed {
                    "400/blocked/marker"
                } else if forwarded {
                    "204/forwarded/no-marker"
                } else {
                    "403/blocked/no-marker"
                };
                let name = format!(
                    "relay.rs::mcp_march_batches_authorize_every_member_before_forwarding/{enforcement}/{case}/route_selected={route_selected}"
                );
                cases.push(
                    same_probe(
                        name,
                        mcp_exchange(
                            route_selected,
                            mcp_request(
                                "POST",
                                "MCP-Protocol-Version: 2025-03-26\r\n",
                                &members.to_string(),
                            ),
                            NO_CONTENT,
                            Some("invalid_mcp_request"),
                        ),
                    )
                    .asserting_yaml(expected),
                );
            }
        }
        assert_settings_parity(&SettingsScenario {
            name: &format!("relay.rs MCP 2025-03-26 batches {enforcement}"),
            host: MCP_HOST,
            yaml: &yaml,
            cedar: &cedar,
            settings: &settings,
            cases,
        });
    }
}

#[test]
fn ported_mcp_tool_rewrites_obey_policy_with_matching_metadata() {
    // The original rewrites the tool call with a middleware stage and checks
    // that the relay judges the rewritten request. Middleware does not depend
    // on the policy engine, so the port sends the rewritten request itself
    // and checks the decision and the revision checks the relay applies to
    // it. An enforced denial is a 403 here and a middleware failure in the
    // original.
    for (version, configured) in [
        ("2025-06-18", r#"["2025-06-18"]"#),
        ("2025-11-25", r#"["2025-11-25"]"#),
        ("2026-07-28", r#"["2026-07-28"]"#),
        ("2025-11-25", r#"["2025-11-25", "2026-07-28"]"#),
        ("2026-07-28", r#"["2025-11-25", "2026-07-28"]"#),
    ] {
        let sessionless = version == "2026-07-28";
        for enforcement in ["enforce", "audit"] {
            let yaml = mcp_tool_yaml(enforcement, configured);
            let cedar = mcp_tool_cedar(enforcement_annotation(enforcement));
            let settings = mcp_settings(configured);
            let mut cases = Vec::new();
            for route_selected in [false, true] {
                for tool in ["read_status", "delete_resource"] {
                    let params =
                        serde_json::json!({"name": tool, "arguments": {"rewritten": true}});
                    let body = if sessionless {
                        sessionless_mcp_body("tools/call", params)
                    } else {
                        serde_json::json!({
                            "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params
                        })
                        .to_string()
                    };
                    let mut headers = format!("MCP-Protocol-Version: {version}\r\n");
                    if sessionless {
                        let _ = write!(headers, "Mcp-Method: tools/call\r\nMcp-Name: {tool}\r\n");
                    }
                    let expected = if tool == "delete_resource" && enforcement == "enforce" {
                        "403/blocked"
                    } else {
                        "204/forwarded"
                    };
                    let name = format!(
                        "relay.rs::mcp_middleware_tool_rewrites_obey_policy_with_matching_metadata/{version} of {configured}/{enforcement}/{tool}/route_selected={route_selected}"
                    );
                    cases.push(
                        same_probe(
                            name,
                            mcp_exchange(
                                route_selected,
                                mcp_request("POST", &headers, &body),
                                NO_CONTENT,
                                None,
                            ),
                        )
                        .asserting_yaml(expected),
                    );
                }
            }
            assert_settings_parity(&SettingsScenario {
                name: &format!("relay.rs MCP rewrites {version} of {configured} {enforcement}"),
                host: MCP_HOST,
                yaml: &yaml,
                cedar: &cedar,
                settings: &settings,
                cases,
            });
        }
    }
}

/// The sessionless endpoint of `mcp_sessionless_test_relay_context`.
const SESSIONLESS_YAML: &str = r#"
network_policies:
  mcp_api:
    name: mcp_api
    endpoints:
      - host: mcp.example.test
        port: 8000
        path: /mcp
        protocol: mcp
        enforcement: enforce
        mcp:
          versions: ["2026-07-28"]
          allow_all_known_mcp_methods: true
        rules:
          - allow: {}
          - allow:
              method: vendor/inspect
        deny_rules:
          - method: tools/call
            tool: blocked
    binaries:
      - { path: /usr/bin/python3 }
"#;

/// The Cedar translation of [`SESSIONLESS_YAML`]. `allow: {}` with
/// `allow_all_known_mcp_methods` admits every known MCP method.
fn sessionless_cedar() -> String {
    let binary = binary(PYTHON);
    format!(
        r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"{MCP_HOST}:{MCP_PORT}")
when {{ {binary} }};
@protocol("mcp")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"{MCP_HOST}:{MCP_PORT}")
when {{
    {binary}
    && context.path == "/mcp"
    && !context.jsonrpc_response
    && (context.mcp_method_class == "available"
        || context.jsonrpc_method == "vendor/inspect")
}};
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"{MCP_HOST}:{MCP_PORT}")
when {{
    {binary}
    && context.path == "/mcp"
    && ((context.method == "GET" && context.jsonrpc_receive_stream)
        || context.jsonrpc_response)
}};
forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"{MCP_HOST}:{MCP_PORT}")
when {{ context.jsonrpc_method == "tools/call" && context.mcp_tool == "blocked" }};
"#
    )
}

#[test]
fn ported_mcp_sessionless_relays() {
    let mut cases = Vec::new();
    for route_selected in [false, true] {
        for (method, params, name, response_body) in [
            (
                "server/discover",
                serde_json::json!({}),
                None,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}",
            ),
            (
                "tools/call",
                serde_json::json!({"name": "echo", "arguments": {}}),
                Some("echo"),
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}",
            ),
            (
                "vendor/inspect",
                serde_json::json!({}),
                None,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}",
            ),
            (
                "subscriptions/listen",
                serde_json::json!({"notifications": {"toolsListChanged": true}}),
                None,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n",
            ),
        ] {
            let mut headers =
                format!("MCP-Protocol-Version: 2026-07-28\r\nMcp-Method: {method}\r\n");
            if let Some(name) = name {
                let _ = write!(headers, "Mcp-Name: {name}\r\n");
            }
            let content_type = if method == "subscriptions/listen" {
                "text/event-stream"
            } else {
                "application/json"
            };
            let upstream = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
                response_body.len()
            );
            let name = format!(
                "relay.rs::mcp_sessionless_relays_discovery_tools_extensions_and_subscription_sse/{method}/route_selected={route_selected}"
            );
            cases.push(
                same_probe(
                    name,
                    mcp_exchange(
                        route_selected,
                        mcp_request("POST", &headers, &sessionless_mcp_body(method, params)),
                        &upstream,
                        Some(response_body),
                    ),
                )
                .asserting_yaml("200/forwarded/marker"),
            );
        }
        for (method, params, header_method, name, expected) in [
            (
                "tools/list",
                serde_json::json!({}),
                "server/discover",
                None,
                "400/blocked",
            ),
            (
                "tools/call",
                serde_json::json!({"name": "echo"}),
                "tools/call",
                None,
                "400/blocked",
            ),
            (
                "tools/call",
                serde_json::json!({"name": "blocked"}),
                "tools/call",
                Some("blocked"),
                "403/blocked",
            ),
            (
                "vendor/unlisted",
                serde_json::json!({}),
                "vendor/unlisted",
                None,
                "403/blocked",
            ),
        ] {
            let mut headers =
                format!("MCP-Protocol-Version: 2026-07-28\r\nMcp-Method: {header_method}\r\n");
            if let Some(name) = name {
                let _ = write!(headers, "Mcp-Name: {name}\r\n");
            }
            let name = format!(
                "relay.rs::mcp_sessionless_relays_apply_metadata_and_method_policy/{method} as {header_method}/route_selected={route_selected}"
            );
            cases.push(
                same_probe(
                    name,
                    mcp_exchange(
                        route_selected,
                        mcp_request("POST", &headers, &sessionless_mcp_body(method, params)),
                        NO_CONTENT,
                        None,
                    ),
                )
                .asserting_yaml(expected),
            );
        }
    }
    let cedar = sessionless_cedar();
    assert_settings_parity(&SettingsScenario {
        name: "relay.rs MCP sessionless",
        host: MCP_HOST,
        yaml: SESSIONLESS_YAML,
        cedar: &cedar,
        settings: &mcp_settings(r#"["2026-07-28"]"#),
        cases,
    });
}

#[test]
fn mcp_revision_outside_the_settings_is_rejected() {
    // Control for the ports above: without the revision settings, a Cedar
    // MCP endpoint keeps the pinned default, so a request at a revision the
    // YAML endpoint allows is rejected by Cedar's relay alone.
    let body = sessionless_mcp_body(
        "tools/call",
        serde_json::json!({"name": "read_status", "arguments": {}}),
    );
    let headers =
        "MCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/call\r\nMcp-Name: read_status\r\n";
    let yaml = mcp_tool_yaml("enforce", r#"["2026-07-28"]"#);
    let cedar = mcp_tool_cedar("");
    assert_settings_parity(&SettingsScenario {
        name: "MCP revision without settings",
        host: MCP_HOST,
        yaml: &yaml,
        cedar: &cedar,
        settings: "",
        cases: vec![diverges_probe(
            "2026-07-28 request without mcp.versions settings",
            mcp_exchange(false, mcp_request("POST", headers, &body), NO_CONTENT, None),
            "the Cedar endpoint has no endpoint settings, so it allows only the default MCP revision",
        )
        .asserting_yaml("204/forwarded")],
    });
}

// ---------------------------------------------------------------------------
// relay.rs: per-path encoded slashes
// ---------------------------------------------------------------------------

/// `ENCODED_SLASH_SCOPING_POLICY`: GET on `/repos/**` and `/admin/**` of one
/// `host:port`, with only `/repos/**` opting into encoded slashes.
const ENCODED_SLASH_YAML: &str = r#"
network_policies:
  route_api:
    name: route_api
    endpoints:
      - host: gateway.example.test
        port: 443
        path: /repos/**
        protocol: rest
        enforcement: enforce
        allow_encoded_slash: true
        rules:
          - allow:
              method: GET
              path: "/repos/**"
      - host: gateway.example.test
        port: 443
        path: /admin/**
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/admin/**"
    binaries:
      - { path: /usr/bin/node }
"#;

fn encoded_slash_cedar() -> String {
    let binary = binary(NODE);
    format!(
        r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"gateway.example.test:443")
when {{ {binary} }};
@protocol("rest")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"gateway.example.test:443")
when {{
    {binary}
    && ["GET", "HEAD"].contains(context.method)
    && (context.path like("/repos/**", "/") || context.path like("/admin/**", "/"))
}};
"#
    )
}

const ENCODED_SLASH_SETTINGS: &str = r"
endpoint_settings:
  - host: gateway.example.test
    port: 443
    path: /repos/**
    allow_encoded_slash: true
";

/// A GET of `target` on the route-selection endpoint, in `ctx`.
fn encoded_slash_exchange(ctx: L7EvalContext, target: &str) -> Probe {
    Probe::Relay(Box::new(RelayExchange {
        ctx,
        route_selected: true,
        request: format!(
            "GET {target} HTTP/1.1\r\nHost: gateway.example.test\r\nConnection: close\r\n\r\n"
        ),
        upstream_response: NO_CONTENT.to_string(),
        marker: Some("not allowed on this endpoint"),
    }))
}

#[test]
fn ported_route_selected_encoded_slash_scoping() {
    let ctx = l7_ctx("gateway.example.test", 443, NODE);
    let (child_env, resolver) = openshell_core::secrets::SecretResolver::from_provider_env(
        std::iter::once(("TOKEN".to_string(), "real-token".to_string())).collect(),
    );
    let placeholder = child_env.get("TOKEN").expect("placeholder env").clone();
    let resolver_ctx = L7EvalContext {
        secret_resolver: resolver.map(Arc::new),
        ..ctx.clone()
    };
    let cedar = encoded_slash_cedar();
    assert_settings_parity(&SettingsScenario {
        name: "relay.rs encoded slash scoping",
        host: "gateway.example.test",
        yaml: ENCODED_SLASH_YAML,
        cedar: &cedar,
        settings: ENCODED_SLASH_SETTINGS,
        cases: vec![
            same_probe(
                "relay.rs::route_selected_encoded_slash_optin_does_not_leak_to_other_endpoints",
                encoded_slash_exchange(ctx.clone(), "/admin/x%2Fy"),
            )
            .asserting_yaml("403/blocked/marker"),
            same_probe(
                "relay.rs::route_selected_encoded_slash_check_survives_credential_redaction",
                encoded_slash_exchange(resolver_ctx, &format!("/admin/{placeholder}%2Fx")),
            )
            .asserting_yaml("403/blocked/marker"),
            same_probe(
                "relay.rs::route_selected_encoded_slash_still_allowed_on_opted_in_endpoint",
                encoded_slash_exchange(ctx.clone(), "/repos/group%2Fproject"),
            )
            .asserting_yaml("204/forwarded/no-marker"),
            // Positive control without an encoded slash on the endpoint that
            // did not opt in.
            same_probe(
                "control: unencoded admin path",
                encoded_slash_exchange(ctx, "/admin/x"),
            )
            .asserting_yaml("204/forwarded/no-marker"),
        ],
    });
}
