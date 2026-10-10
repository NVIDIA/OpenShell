// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Ported YAML tests for query parameter matchers (Cedar parity plan,
//! phase 4).
//!
//! A YAML `query` matcher on key `k` becomes
//! `context.query.hasTag("k") && context.query.getTag("k") like "<glob>"`,
//! and an `any` matcher an `||` of such `like`s. Rego matches query values
//! with `glob.match(pattern, [], value)`, whose empty delimiter list means
//! `.`, so `*` stays within one `.`-separated segment: the translation is
//! Cedar's `like` with a `.` delimiter, which agrees for the `*`-only
//! patterns these tests use. Each YAML allow rule becomes its own
//! `permit`, since Cedar allows a request with repeated keys only when one
//! `permit` allows every combination of values, as one YAML rule must match
//! every value. A YAML deny rule becomes a `forbid`, which denies when one
//! combination matches, as a deny rule fires on one matching value per key.

use super::ported_opa_a::{L7_TEST_CEDAR, L7_TEST_DATA};
use super::ported_phase1::{self as phase1, GET};
use super::*;

use crate::l7::jsonrpc::McpMethodClassification::Available;

/// The Cedar condition for a YAML binary entry with an exact path.
fn binary(path: &str) -> String {
    phase1::binary(path)
}

/// The Cedar condition for the YAML query matcher `key: pattern`.
fn query_glob(key: &str, pattern: &str) -> String {
    format!(
        r#"(context.query.hasTag("{key}") && context.query.getTag("{key}") like("{pattern}", "."))"#
    )
}

/// The Cedar condition for the YAML query matcher `key: {any: patterns}`.
fn query_any(key: &str, patterns: &[&str]) -> String {
    let alternatives = patterns
        .iter()
        .map(|pattern| format!(r#"context.query.getTag("{key}") like("{pattern}", ".")"#))
        .collect::<Vec<_>>()
        .join(" || ");
    format!(r#"(context.query.hasTag("{key}") && ({alternatives}))"#)
}

/// A request for `method target` with `query`, as the request parser
/// decodes it.
fn with_query(method: &str, target: &str, query: &[(&str, &[&str])]) -> L7RequestInfo {
    L7RequestInfo {
        query_params: query
            .iter()
            .map(|(key, values)| {
                (
                    (*key).to_string(),
                    values.iter().map(ToString::to_string).collect(),
                )
            })
            .collect(),
        ..rest(method, target)
    }
}

/// A request probe for `host:port` from [`BINARY`].
fn at(host: &str, port: u16, request: L7RequestInfo) -> Probe {
    request_in(l7_ctx(host, port, BINARY), request)
}

/// One HTTP/1 `GET target` through the relay to `host:port`, answered by
/// the upstream with no content.
fn relay_get(host: &str, port: u16, target: &str) -> Probe {
    Probe::Relay(Box::new(RelayExchange {
        ctx: l7_ctx(host, port, BINARY),
        route_selected: false,
        request: format!(
            "GET {target} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
        ),
        upstream_response: NO_CONTENT.to_string(),
        marker: None,
    }))
}

// ---------------------------------------------------------------------------
// opa.rs: `query_api` in `L7_TEST_DATA`
// ---------------------------------------------------------------------------

/// The Cedar translation of `query_api` in [`L7_TEST_DATA`], which
/// `L7_TEST_CEDAR` leaves out. Each YAML rule is its own `permit`.
fn query_api_cedar() -> String {
    let curl = binary(BINARY);
    format!(
        r#"
// query_api
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.query.com:8080")
when {{ {curl} }};
@protocol("rest")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.query.com:8080")
when {{
    {curl} && {GET} && context.path == "/download"
    && {download}
}};
@protocol("rest")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.query.com:8080")
when {{
    {curl} && {GET} && context.path == "/search"
    && {search}
}};
"#,
        download = query_glob("tag", "foo-*"),
        search = query_any("tag", &["foo-*", "bar-*"]),
    )
}

#[test]
fn ported_l7_test_data_query_api() {
    let api = |target: &str, query: &[(&str, &[&str])]| {
        at("api.query.com", 8080, with_query("GET", target, query))
    };
    let over_cap: Vec<String> = (0..=openshell_policy_cedar::MAX_QUERY_COMBINATIONS)
        .map(|value| format!("foo-{value}"))
        .collect();
    let over_cap: Vec<&str> = over_cap.iter().map(String::as_str).collect();
    assert_parity(&Scenario {
        name: "opa.rs L7_TEST_DATA query_api",
        host: "api.query.com",
        yaml: L7_TEST_DATA,
        cedar: &format!("{L7_TEST_CEDAR}{}", query_api_cedar()),
        cases: vec![
            same_probe(
                "opa.rs::l7_query_glob_allows_matching_duplicate_values",
                api(
                    "/download",
                    &[("tag", &["foo-a", "foo-b"]), ("extra", &["ignored"])],
                ),
            )
            .asserting_yaml("allow"),
            same_probe(
                "opa.rs::l7_query_glob_denies_on_mismatched_duplicate_value",
                api("/download", &[("tag", &["foo-a", "evil"])]),
            )
            .asserting_yaml("deny"),
            same_probe(
                "opa.rs::l7_query_any_allows_if_every_value_matches_any_pattern",
                api("/search", &[("tag", &["foo-a", "bar-b"])]),
            )
            .asserting_yaml("allow"),
            same_probe(
                "opa.rs::l7_query_missing_required_key_denied",
                api("/download", &[]),
            )
            .asserting_yaml("deny"),
            // The original sets `graphql` and `jsonrpc` to null in the Rego
            // input; a parsed REST request carries neither.
            same_probe(
                "opa.rs::l7_rest_request_ignores_null_jsonrpc_metadata",
                api("/download", &[("tag", &["foo-a"])]),
            )
            .asserting_yaml("allow"),
            same_probe(
                "query_api/a glob star stays within one dot-separated segment",
                api("/download", &[("tag", &["foo-a.b"])]),
            )
            .asserting_yaml("deny"),
            same_probe(
                "query_api/any denies a value matching no pattern",
                api("/search", &[("tag", &["foo-a", "baz"])]),
            )
            .asserting_yaml("deny"),
            same_probe(
                "query_api/relay decodes and forwards matching values",
                relay_get("api.query.com", 8080, "/download?tag=foo-a&t%61g=foo%2Db"),
            )
            .asserting_yaml("204/forwarded"),
            same_probe(
                "query_api/relay blocks a mismatched repeated value",
                relay_get("api.query.com", 8080, "/download?tag=foo-a&tag=evil"),
            )
            .asserting_yaml("403/blocked"),
            diverges_probe(
                "query_api/repeated values over the combination cap",
                api("/download", &[("tag", &over_cap)]),
                "Cedar evaluates at most MAX_QUERY_COMBINATIONS value combinations per \
                 request and denies a request with more; YAML checks every value",
            )
            .asserting_yaml("allow"),
        ],
    });
}

// ---------------------------------------------------------------------------
// opa.rs: `deny_with_query` in `L7_DENY_TEST_DATA`
// ---------------------------------------------------------------------------

#[test]
fn ported_l7_deny_rule_with_query() {
    let admin = |query: &[(&str, &[&str])]| with_query("POST", "/admin/settings", query);
    let curl = binary(BINARY);
    assert_parity(&Scenario {
        name: "opa.rs L7_DENY_TEST_DATA deny_with_query",
        host: "api.restricted.com",
        yaml: r#"
network_policies:
  deny_with_query:
    name: deny_with_query
    endpoints:
      - host: api.restricted.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: full
        deny_rules:
          - method: POST
            path: "/admin/**"
            query:
              force: "true"
    binaries:
      - { path: /usr/bin/curl }
"#,
        cedar: &format!(
            r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.restricted.com:443")
when {{ {curl} }};
@protocol("rest")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.restricted.com:443")
when {{ {curl} }};
forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.restricted.com:443")
when {{
    context.method == "POST" && context.path like("/admin/**", "/")
    && {force}
}};
"#,
            force = query_glob("force", "true"),
        ),
        cases: vec![
            same(
                "opa.rs::l7_deny_rule_with_query_blocks_matching_params",
                admin(&[("force", &["true"])]),
            )
            .asserting_yaml("deny"),
            same(
                "opa.rs::l7_deny_rule_with_query_allows_non_matching_params",
                admin(&[("force", &["false"])]),
            )
            .asserting_yaml("allow"),
            same(
                "opa.rs::l7_deny_rule_with_query_blocks_when_any_value_matches",
                admin(&[("force", &["true", "false"])]),
            )
            .asserting_yaml("deny"),
            same(
                "opa.rs::l7_deny_rule_without_matching_query_key_allows",
                rest("POST", "/admin/settings"),
            )
            .asserting_yaml("allow"),
            same(
                "deny_with_query/a dotted value does not match the literal",
                admin(&[("force", &["true.x"])]),
            )
            .asserting_yaml("allow"),
            same(
                "deny_with_query/the deny rule needs its path",
                with_query("POST", "/settings", &[("force", &["true"])]),
            )
            .asserting_yaml("allow"),
        ],
    });
}

// ---------------------------------------------------------------------------
// opa.rs: query matchers loaded from protobuf
// ---------------------------------------------------------------------------

/// The original builds the policy as protobuf with an `L7QueryMatcher`
/// whose `glob` is `foo-*`; the YAML here is the same policy.
#[test]
fn ported_l7_query_rules_from_proto() {
    let curl = binary(BINARY);
    let download = |values: &[&str]| {
        at(
            "api.proto.com",
            8080,
            with_query("GET", "/download", &[("tag", values)]),
        )
    };
    assert_parity(&Scenario {
        name: "opa.rs query_proto",
        host: "api.proto.com",
        yaml: r#"
network_policies:
  query_proto:
    name: query_proto
    endpoints:
      - host: api.proto.com
        port: 8080
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: /download
              query:
                tag: {glob: "foo-*"}
    binaries:
      - { path: /usr/bin/curl }
"#,
        cedar: &format!(
            r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.proto.com:8080")
when {{ {curl} }};
@protocol("rest")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.proto.com:8080")
when {{ {curl} && {GET} && context.path == "/download" && {tag} }};
"#,
            tag = query_glob("tag", "foo-*"),
        ),
        cases: vec![
            same_probe(
                "opa.rs::l7_query_rules_from_proto_are_enforced/allow",
                download(&["foo-a"]),
            )
            .asserting_yaml("allow"),
            same_probe(
                "opa.rs::l7_query_rules_from_proto_are_enforced/deny",
                download(&["evil"]),
            )
            .asserting_yaml("deny"),
        ],
    });
}

// ---------------------------------------------------------------------------
// opa.rs: matchers that survive a reload
// ---------------------------------------------------------------------------

/// The REST half of the original: a query allow matcher and a narrower query
/// deny matcher on the same endpoint. The original also marks the endpoint
/// `provider_credentialed` and `advisor_proposed`, provenance with no Cedar
/// counterpart that does not affect decisions.
#[test]
fn ported_yaml_and_proto_matchers_rest_query() {
    let host = "matchers.parity.test";
    let curl = binary(BINARY);
    let name = |value: &str| with_query("GET", "/", &[("name", &[value])]);
    assert_parity_across_reload(&Scenario {
        name: "opa.rs matchers rest",
        host,
        yaml: r#"
network_policies:
  matchers:
    name: matchers
    endpoints:
      - host: matchers.parity.test
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: /**
              query: {name: "read_*"}
        deny_rules:
          - method: GET
            path: /**
            query: {name: "read_sec*"}
    binaries:
      - {path: /usr/bin/curl}
"#,
        cedar: &format!(
            r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"{host}:443")
when {{ {curl} }};
@protocol("rest")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"{host}:443")
when {{ {curl} && {GET} && context.path like("/**", "/") && {allow} }};
forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"{host}:443")
when {{ {GET} && context.path like("/**", "/") && {deny} }};
"#,
            allow = query_glob("name", "read_*"),
            deny = query_glob("name", "read_sec*"),
        ),
        cases: vec![
            same(
                "opa.rs::yaml_and_proto_matchers_retain_decisions_and_provenance_across_reload/rest allow",
                name("read_status"),
            )
            .asserting_yaml("allow"),
            same(
                "opa.rs::yaml_and_proto_matchers_retain_decisions_and_provenance_across_reload/rest deny",
                name("read_secret"),
            )
            .asserting_yaml("deny"),
        ],
    });
}

/// The MCP half of the original: a `params` allow matcher on the tool name
/// and an `any` deny matcher. Provenance is left out as for REST.
#[test]
fn ported_yaml_and_proto_matchers_mcp_params() {
    let host = "matchers.parity.test";
    let curl = binary(BINARY);
    let tool =
        |name: &str| jsonrpc_request("/", vec![call("tools/call", Some(name), Some(Available))]);
    let endpoint = format!("{host}:443");
    assert_parity_across_reload(&Scenario {
        name: "opa.rs matchers mcp",
        host,
        yaml: r#"
network_policies:
  matchers:
    name: matchers
    endpoints:
      - host: matchers.parity.test
        port: 443
        protocol: mcp
        enforcement: enforce
        rules:
          - allow:
              method: tools/call
              params: {name: "read_*"}
        deny_rules:
          - method: tools/call
            params: {name: {any: [read_secret, read_private]}}
    binaries:
      - {path: /usr/bin/curl}
"#,
        cedar: &format!(
            r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"{endpoint}")
when {{ {curl} }};
@protocol("mcp")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"{endpoint}")
when {{
    {curl}
    && !context.jsonrpc_response
    && context.mcp_method_class == "available"
    && context.jsonrpc_method == "tools/call"
    && context.mcp_tool like("read_*", ".")
}};
forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"{endpoint}")
when {{
    context.jsonrpc_method == "tools/call"
    && (context.mcp_tool like("read_secret", ".") || context.mcp_tool like("read_private", "."))
}};
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"{endpoint}")
when {{
    {curl}
    && ((context.method == "GET" && context.jsonrpc_receive_stream) || context.jsonrpc_response)
}};
"#
        ),
        cases: vec![
            same(
                "opa.rs::yaml_and_proto_matchers_retain_decisions_and_provenance_across_reload/mcp allow",
                tool("read_status"),
            )
            .asserting_yaml("allow"),
            same(
                "opa.rs::yaml_and_proto_matchers_retain_decisions_and_provenance_across_reload/mcp deny",
                tool("read_secret"),
            )
            .asserting_yaml("deny"),
            same("matchers mcp/deny any second pattern", tool("read_private"))
                .asserting_yaml("deny"),
            same(
                "matchers mcp/a glob star stays within one dot-separated segment",
                tool("read_a.b"),
            )
            .asserting_yaml("deny"),
        ],
    });
}

/// The original's empty scalar matcher: a deny rule on `name=""`.
#[test]
fn ported_yaml_empty_query_matcher() {
    let host = "empty.parity.test";
    let curl = binary(BINARY);
    let name = |value: &str| with_query("GET", "/", &[("name", &[value])]);
    assert_parity_across_reload(&Scenario {
        name: "opa.rs empty_query",
        host,
        yaml: r#"
network_policies:
  empty_query:
    name: empty_query
    endpoints:
      - host: empty.parity.test
        port: 443
        protocol: rest
        enforcement: enforce
        access: full
        deny_rules:
          - method: GET
            path: /**
            query: {name: ""}
    binaries:
      - {path: /usr/bin/curl}
"#,
        cedar: &format!(
            r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"{host}:443")
when {{ {curl} }};
@protocol("rest")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"{host}:443")
when {{ {curl} }};
forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"{host}:443")
when {{ {GET} && context.path like("/**", "/") && {empty} }};
"#,
            empty = query_glob("name", ""),
        ),
        cases: vec![
            same(
                "opa.rs::yaml_empty_query_matcher_retains_deny_semantics_across_reload/empty",
                name(""),
            )
            .asserting_yaml("deny"),
            same(
                "opa.rs::yaml_empty_query_matcher_retains_deny_semantics_across_reload/present",
                name("present"),
            )
            .asserting_yaml("allow"),
        ],
    });
}

// ---------------------------------------------------------------------------
// Query matchers on an audit endpoint
// ---------------------------------------------------------------------------

/// A YAML `enforcement: audit` endpoint with a query matcher, and its Cedar
/// translation with `@enforcement("audit")`: both deny a mismatched repeated
/// value, and the relay logs and forwards it.
#[test]
fn query_matchers_on_an_audit_endpoint() {
    let host = "audit.query.test";
    let curl = binary(BINARY);
    let download = |values: &[&str]| with_query("GET", "/download", &[("tag", values)]);
    assert_parity(&Scenario {
        name: "query audit endpoint",
        host,
        yaml: r#"
network_policies:
  audit_query:
    name: audit_query
    endpoints:
      - host: audit.query.test
        port: 443
        protocol: rest
        enforcement: audit
        rules:
          - allow:
              method: GET
              path: /download
              query: {tag: "foo-*"}
    binaries:
      - {path: /usr/bin/curl}
"#,
        cedar: &format!(
            r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"{host}:443")
when {{ {curl} }};
@protocol("rest")
@enforcement("audit")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"{host}:443")
when {{ {curl} && {GET} && context.path == "/download" && {tag} }};
"#,
            tag = query_glob("tag", "foo-*"),
        ),
        cases: vec![
            same("allowed values", download(&["foo-a", "foo-b"])).asserting_yaml("allow"),
            same("a mismatched value", download(&["foo-a", "evil"])).asserting_yaml("deny"),
            same_probe(
                "the relay forwards the audit denial",
                relay_get(host, 443, "/download?tag=foo-a&tag=evil"),
            )
            .asserting_yaml("204/forwarded"),
        ],
    });
}
