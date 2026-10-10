// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Ported YAML token-grant owner tests (Cedar parity plan, phase 1).
//!
//! The gateway stamps each provider endpoint with the owner of its token
//! grants. A YAML sandbox enforces provider rules as network policies; a Cedar
//! sandbox receives them as `provider_credential_rules` and gets its access
//! from the Cedar policy alone. Each scenario here hands the original test's
//! rules to both engines that way ([`ProviderScenario`]), and the Cedar
//! policy translates the same rules into the access they grant.
//!
//! The originals mostly drive bytes through the relay or forward proxy with a
//! scripted grant resolver. Each port checks the owner set the relay selects
//! for the request (`Owners`) and, where the original asserts it, the
//! forwarding decision. Grant resolution, caching, header replacement, and
//! credential-installation guards run after owner selection and do not
//! depend on the policy engine, so they are not ported.
//!
//! An endpoint without `enforcement` defaults to audit for YAML, so the
//! translations of such endpoints mark their Cedar policies
//! `@enforcement("audit")`. A YAML `GET` rule also allows `HEAD`.

use super::ported_relay::{batch_call, graphql_body, jsonrpc_body, mcp_body};
use super::*;

use openshell_core::proto::{
    L7Allow, L7DenyRule, L7QueryMatcher, L7Rule, McpOptions, NetworkBinary, NetworkEndpoint,
    NetworkEnforcementMode, NetworkPolicyRule,
};

pub(super) const HOST: &str = "api.example.test";
pub(super) const PORT: u16 = 8080;
const OTHER_CLIENT: &str = "/usr/bin/other-client";
const NODE: &str = "/usr/bin/node";

/// The Cedar condition for a YAML binary entry with an exact path.
pub(super) fn binary(path: &str) -> String {
    format!("(context.binary_path == \"{path}\" || context.ancestors.contains(\"{path}\"))")
}

/// The Cedar condition for a YAML REST rule allowing `GET` (and so `HEAD`).
pub(super) const GET: &str = r#"["GET", "HEAD"].contains(context.method)"#;

/// A `NetworkConnect` permit for the test endpoint under `condition`.
pub(super) fn connect(condition: &str) -> String {
    format!(
        r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"{HOST}:{PORT}")
when {{ {condition} }};
"#
    )
}

/// An `HttpRequest` policy on the test endpoint, with `annotations` before it.
pub(super) fn http(annotations: &str, effect: &str, condition: &str) -> String {
    format!(
        r#"
{annotations}
{effect} (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"{HOST}:{PORT}")
when {{ {condition} }};
"#
    )
}

/// A network policy named `name` for `binaries`.
fn policy(name: &str, binaries: &[&str], endpoints: Vec<NetworkEndpoint>) -> NetworkPolicyRule {
    NetworkPolicyRule {
        name: name.to_string(),
        endpoints,
        binaries: binaries
            .iter()
            .map(|path| NetworkBinary {
                path: (*path).to_string(),
            })
            .collect(),
    }
}

fn allow(method: &str, path: &str) -> L7Rule {
    L7Rule {
        allow: Some(L7Allow {
            method: method.to_string(),
            path: path.to_string(),
            ..Default::default()
        }),
    }
}

/// An endpoint on the test host stamped with `owner` (none when empty).
fn endpoint(owner: &str, path: &str, protocol: &str, rules: Vec<L7Rule>) -> NetworkEndpoint {
    NetworkEndpoint {
        host: HOST.to_string(),
        port: u32::from(PORT),
        path: path.to_string(),
        protocol: protocol.to_string(),
        token_grant_owner: owner.to_string(),
        rules,
        ..Default::default()
    }
}

/// A REST endpoint whose one rule allows `method` on its own `path`, as
/// `opa.rs::token_grant_owner_endpoint` builds it.
fn rest_route(owner: &str, path: &str, method: &str) -> NetworkEndpoint {
    endpoint(owner, path, "rest", vec![allow(method, path)])
}

/// [`rest_route`] with enforcement set, as the relay fixture's `route` builds it.
fn enforced(mut endpoint: NetworkEndpoint, mode: NetworkEnforcementMode) -> NetworkEndpoint {
    endpoint.enforcement = mode as i32;
    endpoint
}

/// The relay fixture's one-endpoint policy per route, named after its owner.
fn route_policy(owner: &str, binary: &str, endpoint: NetworkEndpoint) -> NetworkPolicyRule {
    policy(owner, &[binary], vec![endpoint])
}

/// An owner probe for [`BINARY`] on the test endpoint.
pub(super) fn owners(request: L7RequestInfo) -> Probe {
    owners_in(l7_ctx(HOST, PORT, BINARY), request)
}

/// A request probe for [`BINARY`] on the test endpoint.
pub(super) fn request(request: L7RequestInfo) -> Probe {
    request_in(l7_ctx(HOST, PORT, BINARY), request)
}

/// A request whose raw target the relay canonicalizes before policy, as
/// `l7/rest.rs` does: dot segments and percent-encoding are resolved and the
/// query is parsed into parameters.
fn canonical(method: &str, raw_target: &str) -> L7RequestInfo {
    let (path, query) = crate::l7::path::canonicalize_request_target(
        raw_target,
        &crate::l7::path::CanonicalizeOptions::default(),
    )
    .expect("canonical target");
    let query_params = query
        .as_deref()
        .map(|query| crate::l7::rest::parse_query_params(query).expect("query parses"))
        .unwrap_or_default();
    L7RequestInfo {
        query_params,
        ..rest(method, &path.path)
    }
}

// ---------------------------------------------------------------------------
// opa.rs
// ---------------------------------------------------------------------------

#[test]
fn ported_owners_require_exact_endpoint_admission() {
    let mut cedar = connect(&format!("{} || {}", binary(BINARY), binary(OTHER_CLIENT)));
    cedar.push_str(&http(
        r#"@enforcement("audit")"#,
        "permit",
        &format!(
            r#"({curl} && (({GET} && context.path like("/a/**", "/"))
                || (context.method == "POST" && context.path like("/a/private/**", "/"))))
            || ({other} && {GET} && context.path like("/a/**", "/"))"#,
            curl = binary(BINARY),
            other = binary(OTHER_CLIENT),
        ),
    ));
    assert_provider_parity(&ProviderScenario {
        name: "exact endpoint admission",
        host: HOST,
        rules: vec![
            policy(
                "allowed",
                &[BINARY],
                vec![
                    rest_route("owner-broad", "/a/**", "GET"),
                    rest_route("owner-narrow", "/a/private/**", "POST"),
                ],
            ),
            policy(
                "other_binary",
                &[OTHER_CLIENT],
                vec![rest_route("owner-other", "/a/**", "GET")],
            ),
        ],
        cedar: &cedar,
        cases: vec![
            same_probe(
                "opa.rs::l7_token_grant_owners_require_exact_endpoint_admission/GET forwarded",
                request(rest("GET", "/a/private/item")),
            )
            .asserting_yaml("allow"),
            same_probe(
                "opa.rs::l7_token_grant_owners_require_exact_endpoint_admission/GET owner",
                owners(rest("GET", "/a/private/item")),
            )
            .asserting_yaml("owner-broad"),
            same_probe(
                "opa.rs::l7_token_grant_owners_require_exact_endpoint_admission/POST forwarded",
                request(rest("POST", "/a/private/item")),
            )
            .asserting_yaml("allow"),
            same_probe(
                "opa.rs::l7_token_grant_owners_require_exact_endpoint_admission/POST owner",
                owners(rest("POST", "/a/private/item")),
            )
            .asserting_yaml("owner-narrow"),
        ],
    });
}

#[test]
fn ported_owners_preserve_union_allow_and_global_deny() {
    let mut broad = rest_route("owner-z", "/a/**", "GET");
    broad.deny_rules = vec![L7DenyRule {
        method: "GET".to_string(),
        path: "/a/private/blocked".to_string(),
        ..Default::default()
    }];
    let curl = binary(BINARY);
    let mut cedar = connect(&curl);
    // The narrow endpoints' rules are covered by the broad one.
    cedar.push_str(&http(
        r#"@enforcement("audit")"#,
        "permit",
        &format!(r#"{curl} && {GET} && context.path like("/a/**", "/")"#),
    ));
    cedar.push_str(&http(
        r#"@enforcement("audit")"#,
        "forbid",
        &format!(r#"{curl} && {GET} && context.path == "/a/private/blocked""#),
    ));
    assert_provider_parity(&ProviderScenario {
        name: "union allow and global deny",
        host: HOST,
        rules: vec![
            policy("broad", &[BINARY], vec![broad]),
            policy(
                "narrow",
                &[BINARY],
                vec![
                    rest_route("owner-a", "/a/private/**", "GET"),
                    rest_route("owner-z", "/a/private/**", "GET"),
                ],
            ),
        ],
        cedar: &cedar,
        cases: vec![
            same_probe(
                "opa.rs::l7_token_grant_owners_preserve_union_allow_and_global_deny/allowed",
                request(rest("GET", "/a/private/item")),
            )
            .asserting_yaml("allow"),
            same_probe(
                "opa.rs::l7_token_grant_owners_preserve_union_allow_and_global_deny/union",
                owners(rest("GET", "/a/private/item")),
            )
            .asserting_yaml("owner-a,owner-z"),
            same_probe(
                "opa.rs::l7_token_grant_owners_preserve_union_allow_and_global_deny/denied",
                request(rest("GET", "/a/private/blocked")),
            )
            .asserting_yaml("deny"),
            same_probe(
                "opa.rs::l7_token_grant_owners_preserve_union_allow_and_global_deny/deny admits none",
                owners(rest("GET", "/a/private/blocked")),
            )
            .asserting_yaml("none"),
        ],
    });
}

#[test]
fn ported_owners_preserve_binary_and_query_restrictions() {
    let mut endpoint = rest_route("owner", "/a/**", "GET");
    endpoint.rules[0]
        .allow
        .as_mut()
        .expect("allow rule")
        .query
        .insert(
            "team".to_string(),
            L7QueryMatcher {
                glob: "prod-*".to_string(),
                ..Default::default()
            },
        );
    // Cedar cannot yet match query parameters (plan phase 4), so the access
    // translation omits the query restriction. The provider rule still
    // carries it, and owner admission checks it.
    let glob = r#"context.binary_path like("/opt/tools/*", "/")"#;
    let mut cedar = connect(glob);
    cedar.push_str(&http(
        r#"@enforcement("audit")"#,
        "permit",
        &format!(r#"{glob} && {GET} && context.path like("/a/**", "/")"#),
    ));
    let query = |values: &[&str]| {
        let mut request = rest("GET", "/a/item");
        request.query_params = HashMap::from([(
            "team".to_string(),
            values.iter().map(ToString::to_string).collect(),
        )]);
        request
    };
    let mut argv = l7_ctx(HOST, PORT, BINARY);
    argv.cmdline_paths = vec!["/opt/tools/client".to_string()];
    let mut ancestor = argv.clone();
    ancestor.ancestors = vec!["/opt/tools/client".to_string()];
    assert_provider_parity(&ProviderScenario {
        name: "binary and query restrictions",
        host: HOST,
        rules: vec![policy("owner", &["/opt/tools/*"], vec![endpoint])],
        cedar: &cedar,
        cases: vec![
            same_probe(
                "opa.rs::l7_token_grant_owners_preserve_binary_and_query_restrictions/argv",
                owners_in(argv, query(&["prod-east"])),
            )
            .asserting_yaml("none"),
            diverges_probe(
                "opa.rs::l7_token_grant_owners_preserve_binary_and_query_restrictions/ancestor",
                owners_in(ancestor.clone(), query(&["prod-east"])),
                "a YAML binary glob also matches ancestors; Cedar cannot match a glob against \
                 the members of context.ancestors, so Cedar denies the request and admits no \
                 owner (Cedar admits fewer owners, never more)",
            )
            .asserting_yaml("owner"),
            same_probe(
                "opa.rs::l7_token_grant_owners_preserve_binary_and_query_restrictions/every query value",
                owners_in(ancestor, query(&["prod-east", "dev"])),
            )
            .asserting_yaml("none"),
            // Positive control: the calling binary itself matches the glob,
            // which Cedar can express.
            same_probe(
                "binary and query restrictions/calling binary matches the glob",
                owners_in(
                    l7_ctx(HOST, PORT, "/opt/tools/client"),
                    query(&["prod-east"]),
                ),
            )
            .asserting_yaml("owner"),
        ],
    });
}

#[test]
fn ported_owners_exclude_audit_denial_and_missing_metadata() {
    // The original also stamps a non-string owner (42) in raw Rego data. A
    // gateway-stamped owner is a proto string, so that case cannot reach
    // either engine and is not ported; an empty owner is the proto form of
    // a missing one.
    let mut audit = rest_route("owner-audit", "/a/**", "GET");
    audit.enforcement = NetworkEnforcementMode::Audit as i32;
    let curl = binary(BINARY);
    let mut cedar = connect(&curl);
    cedar.push_str(&http(
        r#"@enforcement("audit")"#,
        "permit",
        &format!(
            r#"{curl} && {GET} && (context.path like("/a/**", "/")
                || context.path like("/b/**", "/") || context.path like("/d/**", "/"))"#
        ),
    ));
    assert_provider_parity(&ProviderScenario {
        name: "audit denial and missing owner metadata",
        host: HOST,
        rules: vec![policy(
            "owner",
            &[BINARY],
            vec![
                audit,
                rest_route("", "/b/**", "GET"),
                rest_route("", "/d/**", "GET"),
            ],
        )],
        cedar: &cedar,
        cases: vec![
            same_probe(
                "opa.rs::l7_token_grant_owners_exclude_audit_denial_and_missing_metadata/audit denied",
                request(rest("POST", "/a/item")),
            )
            .asserting_yaml("deny"),
            same_probe(
                "opa.rs::l7_token_grant_owners_exclude_audit_denial_and_missing_metadata/audit denial admits none",
                owners(rest("POST", "/a/item")),
            )
            .asserting_yaml("none"),
            same_probe(
                "audit denial and missing owner metadata/audit allow admits its owner",
                owners(rest("GET", "/a/item")),
            )
            .asserting_yaml("owner-audit"),
            same_probe(
                "audit denial and missing owner metadata/inspection",
                Probe::Inspection(network(HOST, PORT, BINARY)),
            )
            .asserting_yaml("Rest/Audit"),
            same_probe(
                "opa.rs::l7_token_grant_owners_exclude_audit_denial_and_missing_metadata/missing forwarded",
                request(rest("GET", "/b/item")),
            )
            .asserting_yaml("allow"),
            same_probe(
                "opa.rs::l7_token_grant_owners_exclude_audit_denial_and_missing_metadata/missing",
                owners(rest("GET", "/b/item")),
            )
            .asserting_yaml("none"),
            same_probe(
                "opa.rs::l7_token_grant_owners_exclude_audit_denial_and_missing_metadata/empty forwarded",
                request(rest("GET", "/d/item")),
            )
            .asserting_yaml("allow"),
            same_probe(
                "opa.rs::l7_token_grant_owners_exclude_audit_denial_and_missing_metadata/empty",
                owners(rest("GET", "/d/item")),
            )
            .asserting_yaml("none"),
        ],
    });
}

#[test]
fn ported_owners_preserve_proto_identity() {
    let curl = binary(BINARY);
    let mut cedar = connect(&curl);
    cedar.push_str(&http(
        r#"@enforcement("audit")"#,
        "permit",
        &format!(r#"{curl} && {GET} && context.path like("/a/**", "/")"#),
    ));
    assert_provider_parity(&ProviderScenario {
        name: "proto owner identity",
        host: HOST,
        rules: vec![policy(
            "owner",
            &[BINARY],
            vec![rest_route("gateway-stamped-owner", "/a/**", "GET")],
        )],
        cedar: &cedar,
        cases: vec![
            same_probe(
                "opa.rs::l7_token_grant_owners_preserve_proto_identity/forwarded",
                request(rest("GET", "/a/item")),
            )
            .asserting_yaml("allow"),
            same_probe(
                "opa.rs::l7_token_grant_owners_preserve_proto_identity",
                owners(rest("GET", "/a/item")),
            )
            .asserting_yaml("gateway-stamped-owner"),
        ],
    });
}

// ---------------------------------------------------------------------------
// l7/relay/token_grant_ownership_tests.rs
// ---------------------------------------------------------------------------

/// The relay fixture's enforced REST route for `owner` on `path`.
fn relay_route(owner: &str, path: &str, method: &str) -> NetworkEndpoint {
    enforced(
        rest_route(owner, path, method),
        NetworkEnforcementMode::Enforce,
    )
}

/// The Cedar policy for enforced curl REST routes `(method condition, path glob)`.
fn relay_cedar(routes: &[(&str, &str)]) -> String {
    let curl = binary(BINARY);
    let routes = routes
        .iter()
        .map(|(method, path)| format!(r#"({method} && context.path like("{path}", "/"))"#))
        .collect::<Vec<_>>()
        .join(" || ");
    let mut cedar = connect(&curl);
    cedar.push_str(&http("", "permit", &format!("{curl} && ({routes})")));
    cedar
}

/// The `native_protocol_fixture` routes for `protocol`: the native route,
/// and with `multiple_routes` the unrelated REST route on `/other/**`.
///
/// The variants with the unrelated route need a protocol per path, so their
/// Cedar policies carry `@path`; `ported_phase3` ports them.
pub(super) fn native_scenario(
    protocol: &str,
    multiple_routes: bool,
) -> (Vec<NetworkPolicyRule>, String) {
    let path = if multiple_routes {
        r#"@path("/native")"#
    } else {
        ""
    };
    let curl = binary(BINARY);
    let (rule, condition) = match protocol {
        "graphql" => (
            L7Allow {
                operation_type: "query".to_string(),
                fields: vec!["echo".to_string()],
                ..Default::default()
            },
            r#"context.graphql_operation_type == "query"
                && context.graphql_fields.containsAny(["echo"])
                && ["echo"].containsAll(context.graphql_fields)"#
                .to_string(),
        ),
        "json-rpc" => (
            L7Allow {
                method: "echo".to_string(),
                ..Default::default()
            },
            r#"!context.jsonrpc_response && context.jsonrpc_method == "echo""#.to_string(),
        ),
        "mcp" => (
            L7Allow {
                method: "tools/call".to_string(),
                params: HashMap::from([(
                    "name".to_string(),
                    L7QueryMatcher {
                        glob: "echo".to_string(),
                        ..Default::default()
                    },
                )]),
                ..Default::default()
            },
            r#"!context.jsonrpc_response
                && context.mcp_method_class == "available"
                && context.jsonrpc_method == "tools/call"
                && context.mcp_tool == "echo""#
                .to_string(),
        ),
        _ => panic!("unsupported fixture protocol"),
    };
    let mut native = enforced(
        endpoint(
            "native",
            "/native",
            protocol,
            vec![L7Rule { allow: Some(rule) }],
        ),
        NetworkEnforcementMode::Enforce,
    );
    if protocol == "mcp" {
        native.mcp = Some(McpOptions {
            versions: vec!["2025-11-25".to_string()],
            ..Default::default()
        });
    }
    let mut cedar = connect(&curl);
    cedar.push_str(&http(
        &format!("{path} @protocol(\"{protocol}\")"),
        "permit",
        &format!(r#"{curl} && context.path == "/native" && {condition}"#),
    ));
    if protocol == "mcp" {
        // A YAML MCP endpoint also allows its receive stream and client
        // response frames on the endpoint path.
        cedar.push_str(&http(
            path,
            "permit",
            &format!(
                r#"{curl} && context.path == "/native"
                    && ((context.method == "GET" && context.jsonrpc_receive_stream)
                        || context.jsonrpc_response)"#
            ),
        ));
    }
    let mut rules = vec![route_policy("native", BINARY, native)];
    if multiple_routes {
        rules.push(route_policy(
            "unrelated",
            BINARY,
            relay_route("unrelated", "/other/**", "GET"),
        ));
        cedar.push_str(&http(
            r#"@path("/other/**")"#,
            "permit",
            &format!(r#"{curl} && {GET} && context.path like("/other/**", "/")"#),
        ));
    }
    (rules, cedar)
}

/// The relay's parsed request for `native_protocol_body(protocol, operation)`.
pub(super) fn native_request(protocol: &str, operation: &str) -> L7RequestInfo {
    match protocol {
        "graphql" => graphql_body(
            "/native",
            &serde_json::json!({"query": format!("query {{ {operation} }}")}),
        ),
        "json-rpc" => jsonrpc_body(
            "POST",
            "/native",
            &serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": operation}).to_string(),
        ),
        "mcp" => mcp_body(
            "POST",
            "/native",
            &serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": operation, "arguments": {}}
            })
            .to_string(),
        ),
        _ => panic!("unsupported fixture protocol"),
    }
}

#[test]
fn ported_native_protocol_grants() {
    const PRESERVE: &str = "relay/token_grant_ownership_tests.rs::native_protocol_grants_preserve_auth_when_an_unrelated_route_is_added";
    const DENIALS: &str = "relay/token_grant_ownership_tests.rs::native_protocol_denials_do_not_resolve_grants_or_forward_bytes";
    const MISSING: &str = "relay/token_grant_ownership_tests.rs::missing_grant_owner_metadata_rejects_only_matching_requests";
    for protocol in ["graphql", "json-rpc", "mcp"] {
        let (rules, cedar) = native_scenario(protocol, false);
        let mut cases = vec![
            same_probe(PRESERVE, request(native_request(protocol, "echo"))).asserting_yaml("allow"),
            same_probe(PRESERVE, owners(native_request(protocol, "echo"))).asserting_yaml("native"),
            same_probe(DENIALS, request(native_request(protocol, "blocked")))
                .asserting_yaml("deny"),
            same_probe(DENIALS, owners(native_request(protocol, "blocked"))).asserting_yaml("none"),
        ];
        if protocol == "mcp" {
            // The original installs an extra grant without owner metadata;
            // which grant is rejected is decided after owner selection.
            cases.push(
                same_probe(MISSING, owners(native_request(protocol, "echo")))
                    .asserting_yaml("native"),
            );
        }
        assert_provider_parity(&ProviderScenario {
            name: protocol,
            host: HOST,
            rules,
            cedar: &cedar,
            cases,
        });
    }
}

#[test]
fn ported_route_selected_grants() {
    const CANONICAL: &str = "relay/token_grant_ownership_tests.rs::grant_selection_uses_canonical_path_and_ignores_query_selector_text";
    const ABA: &str = "relay/token_grant_ownership_tests.rs::route_selected_grants_follow_a_b_a_on_one_connection";
    // `grant_selection_uses_canonical_path...` declares only route `a`; route
    // `b` does not match its request path, so one scenario serves both.
    assert_provider_parity(&ProviderScenario {
        name: "route-selected grants",
        host: HOST,
        rules: vec![
            route_policy("a", BINARY, relay_route("a", "/a/**", "GET")),
            route_policy("b", BINARY, relay_route("b", "/b/**", "GET")),
        ],
        cedar: &relay_cedar(&[(GET, "/a/**"), (GET, "/b/**")]),
        cases: vec![
            same_probe(
                CANONICAL,
                request(canonical("GET", "/outside/../a/%69tem?next=/b/item")),
            )
            .asserting_yaml("allow"),
            same_probe(
                CANONICAL,
                owners(canonical("GET", "/outside/../a/%69tem?next=/b/item")),
            )
            .asserting_yaml("a"),
            same_probe(ABA, owners(canonical("GET", "/a/first"))).asserting_yaml("a"),
            same_probe(ABA, owners(canonical("GET", "/a/../b/%69tem?next=/a/item")))
                .asserting_yaml("b"),
            same_probe(ABA, owners(canonical("GET", "/a/third"))).asserting_yaml("a"),
        ],
    });
}

#[test]
fn ported_overlapping_get_and_post_routes() {
    const BROADER: &str = "relay/token_grant_ownership_tests.rs::broader_get_allow_does_not_authorize_narrow_post_owner";
    const OVERLAPPING: &str = "relay/token_grant_ownership_tests.rs::overlapping_get_and_post_select_their_admitted_owner_on_one_connection";
    assert_provider_parity(&ProviderScenario {
        name: "overlapping GET and POST routes",
        host: HOST,
        rules: vec![
            route_policy("broad", BINARY, relay_route("broad", "/a/**", "GET")),
            route_policy(
                "narrow",
                BINARY,
                relay_route("narrow", "/a/private/**", "POST"),
            ),
        ],
        cedar: &relay_cedar(&[
            (GET, "/a/**"),
            (r#"context.method == "POST""#, "/a/private/**"),
        ]),
        cases: vec![
            same_probe(BROADER, request(rest("GET", "/a/private/item"))).asserting_yaml("allow"),
            same_probe(BROADER, owners(rest("GET", "/a/private/item"))).asserting_yaml("broad"),
            same_probe(OVERLAPPING, owners(rest("POST", "/a/private/item")))
                .asserting_yaml("narrow"),
            same_probe(OVERLAPPING, request(rest("POST", "/a/private/item")))
                .asserting_yaml("allow"),
        ],
    });
}

#[test]
fn ported_equal_selector_does_not_authorize_another_binarys_grant() {
    const NAME: &str = "relay/token_grant_ownership_tests.rs::equal_selector_does_not_authorize_another_binarys_grant";
    let curl = binary(BINARY);
    let other = binary(OTHER_CLIENT);
    let mut cedar = connect(&format!("{curl} || {other}"));
    cedar.push_str(&http(
        "",
        "permit",
        &format!(r#"({curl} || {other}) && {GET} && context.path like("/a/**", "/")"#),
    ));
    assert_provider_parity(&ProviderScenario {
        name: "equal selector, other binary",
        host: HOST,
        rules: vec![
            route_policy("allowed", BINARY, relay_route("allowed", "/a/**", "GET")),
            route_policy("owner", OTHER_CLIENT, relay_route("owner", "/a/**", "GET")),
        ],
        cedar: &cedar,
        cases: vec![
            same_probe(NAME, request(rest("GET", "/a/item"))).asserting_yaml("allow"),
            same_probe(NAME, owners(rest("GET", "/a/item"))).asserting_yaml("allowed"),
            // Positive control: the owning binary is admitted its own grant.
            same_probe(
                "equal selector, other binary/owning binary",
                owners_in(l7_ctx(HOST, PORT, OTHER_CLIENT), rest("GET", "/a/item")),
            )
            .asserting_yaml("owner"),
        ],
    });
}

#[test]
fn ported_denials_admit_no_grant() {
    const ENFORCED: &str =
        "relay/token_grant_ownership_tests.rs::enforced_denial_mints_nothing_and_forwards_no_bytes";
    const AUDIT: &str =
        "relay/token_grant_ownership_tests.rs::audit_denial_does_not_authorize_a_grant";
    for (mode, annotation, inspection, name) in [
        (
            NetworkEnforcementMode::Enforce,
            "",
            "Rest/Enforce",
            ENFORCED,
        ),
        (
            NetworkEnforcementMode::Audit,
            r#"@enforcement("audit")"#,
            "Rest/Audit",
            AUDIT,
        ),
    ] {
        let curl = binary(BINARY);
        let mut cedar = connect(&curl);
        cedar.push_str(&http(
            annotation,
            "permit",
            &format!(r#"{curl} && {GET} && context.path like("/a/**", "/")"#),
        ));
        assert_provider_parity(&ProviderScenario {
            name: inspection,
            host: HOST,
            rules: vec![route_policy(
                "a",
                BINARY,
                enforced(rest_route("a", "/a/**", "GET"), mode),
            )],
            cedar: &cedar,
            cases: vec![
                // The relay forwards an audit denial and rejects an enforced
                // one; the inspection decides which.
                same_probe(name, Probe::Inspection(network(HOST, PORT, BINARY)))
                    .asserting_yaml(inspection),
                same_probe(name, request(rest("POST", "/a/item"))).asserting_yaml("deny"),
                same_probe(name, owners(rest("POST", "/a/item"))).asserting_yaml("none"),
                // Positive control: an allowed request admits the owner.
                same_probe(
                    "denials admit no grant/allowed request",
                    owners(rest("GET", "/a/item")),
                )
                .asserting_yaml("a"),
            ],
        });
    }
}

/// A JSON-RPC endpoint on `path` allowing `methods`, as the body tests build it.
fn jsonrpc_route(owner: &str, path: &str, methods: &[&str]) -> NetworkEndpoint {
    enforced(
        endpoint(
            owner,
            path,
            "json-rpc",
            methods
                .iter()
                .map(|method| L7Rule {
                    allow: Some(L7Allow {
                        method: (*method).to_string(),
                        ..Default::default()
                    }),
                })
                .collect(),
        ),
        NetworkEnforcementMode::Enforce,
    )
}

#[test]
fn ported_jsonrpc_batch_requires_one_owner_to_admit_every_member() {
    const NAME: &str = "relay/token_grant_ownership_tests.rs::jsonrpc_batch_requires_one_owner_to_admit_every_member";
    let batch = jsonrpc_body(
        "POST",
        "/rpc",
        r#"[{"jsonrpc":"2.0","id":1,"method":"readFirst"},{"jsonrpc":"2.0","id":2,"method":"readSecond"}]"#,
    );
    let curl = binary(BINARY);
    let mut cedar = connect(&curl);
    cedar.push_str(&http(
        r#"@protocol("json-rpc")"#,
        "permit",
        &format!(
            r#"{curl} && context.path == "/rpc" && !context.jsonrpc_response
                && ["readFirst", "readSecond"].contains(context.jsonrpc_method)"#
        ),
    ));
    for (shared_owner, expected) in [(false, "none"), (true, "shared")] {
        let mut endpoints = vec![
            jsonrpc_route("first", "/rpc", &["readFirst"]),
            jsonrpc_route("second", "/rpc", &["readSecond"]),
        ];
        if shared_owner {
            endpoints.push(jsonrpc_route(
                "shared",
                "/rpc",
                &["readFirst", "readSecond"],
            ));
        }
        assert_provider_parity(&ProviderScenario {
            name: expected,
            host: HOST,
            rules: vec![policy("body_api", &[BINARY], endpoints)],
            cedar: &cedar,
            cases: vec![
                same_probe(NAME, request(batch_call(&batch, 0))).asserting_yaml("allow"),
                same_probe(NAME, request(batch_call(&batch, 1))).asserting_yaml("allow"),
                same_probe(NAME, owners(batch.clone())).asserting_yaml(expected),
                // Positive control: one member alone admits its own owner.
                same_probe(
                    "JSON-RPC batch/first member alone",
                    owners(batch_call(&batch, 0)),
                )
                .asserting_yaml(if shared_owner {
                    "first,shared"
                } else {
                    "first"
                }),
            ],
        });
    }
}

#[test]
fn ported_transformed_jsonrpc_body_selects_final_operation_owner() {
    const NAME: &str = "relay/token_grant_ownership_tests.rs::transformed_jsonrpc_body_selects_final_operation_owner";
    let curl = binary(BINARY);
    let mut cedar = connect(&curl);
    cedar.push_str(&http(
        r#"@protocol("json-rpc")"#,
        "permit",
        &format!(
            r#"{curl} && !context.jsonrpc_response
                && ((context.path == "/api/rpc" && context.jsonrpc_method == "readOriginal")
                    || (context.path like("/api/**", "/")
                        && context.jsonrpc_method == "readTransformed"))"#
        ),
    ));
    // The relay recomputes owners for the body it will send, so the
    // transformed body is probed as its own request.
    let original = jsonrpc_body(
        "POST",
        "/api/rpc",
        r#"{"jsonrpc":"2.0","id":1,"method":"readOriginal"}"#,
    );
    let transformed = jsonrpc_body(
        "POST",
        "/api/rpc",
        r#"{"jsonrpc":"2.0","id":1,"method":"readTransformed"}"#,
    );
    assert_provider_parity(&ProviderScenario {
        name: "transformed JSON-RPC body",
        host: HOST,
        rules: vec![policy(
            "body_api",
            &[BINARY],
            vec![
                jsonrpc_route("original", "/api/rpc", &["readOriginal"]),
                jsonrpc_route("transformed", "/api/**", &["readTransformed"]),
            ],
        )],
        cedar: &cedar,
        cases: vec![
            same_probe(NAME, request(original.clone())).asserting_yaml("allow"),
            same_probe(NAME, owners(original)).asserting_yaml("original"),
            same_probe(NAME, request(transformed.clone())).asserting_yaml("allow"),
            same_probe(NAME, owners(transformed)).asserting_yaml("transformed"),
        ],
    });
}

// ---------------------------------------------------------------------------
// proxy/tests/token_grants.rs
// ---------------------------------------------------------------------------

#[test]
fn ported_forward_inspection_owner_selection() {
    const SELECTS: &str = "proxy/tests/token_grants.rs::forward_inspection_selects_only_the_owner_admitting_the_request";
    const RETAINS: &str = "proxy/tests/token_grants.rs::forward_inspection_retains_installation_through_guarded_write";
    let node = binary(NODE);
    let mut cedar = connect(&node);
    cedar.push_str(&http(
        r#"@enforcement("audit")"#,
        "permit",
        &format!(
            r#"{node} && (({GET} && context.path like("/v1/**", "/"))
                || (context.method == "POST" && context.path == "/v1/projects"))"#
        ),
    ));
    let ctx = l7_ctx(HOST, PORT, NODE);
    assert_provider_parity(&ProviderScenario {
        name: "forward inspection",
        host: HOST,
        rules: vec![policy(
            "rest_api",
            &[NODE],
            vec![
                rest_route("other-owner", "/v1/**", "GET"),
                endpoint(
                    "test-owner",
                    "/v1/projects",
                    "rest",
                    vec![allow("POST", "/v1/projects")],
                ),
            ],
        )],
        cedar: &cedar,
        cases: vec![
            same_probe(
                SELECTS,
                request_in(ctx.clone(), rest("GET", "/v1/projects")),
            )
            .asserting_yaml("allow"),
            same_probe(SELECTS, owners_in(ctx.clone(), rest("GET", "/v1/projects")))
                .asserting_yaml("other-owner"),
            same_probe(
                SELECTS,
                request_in(ctx.clone(), rest("POST", "/v1/projects")),
            )
            .asserting_yaml("allow"),
            same_probe(
                SELECTS,
                owners_in(ctx.clone(), rest("POST", "/v1/projects")),
            )
            .asserting_yaml("test-owner"),
            same_probe(RETAINS, owners_in(ctx, rest("POST", "/v1/projects")))
                .asserting_yaml("test-owner"),
        ],
    });
}

// ---------------------------------------------------------------------------
// proxy.rs
// ---------------------------------------------------------------------------

/// The forward-proxy grant tests run without an inspected endpoint: an
/// uninspected forward request keeps selector-based credentials, with no
/// owner decision, and the grant itself is resolved without the policy
/// engine. What the policy decides is that the connection is allowed and not
/// inspected, which is what these cases compare.
#[test]
fn ported_forward_proxy_uninspected_grants() {
    assert_parity(&Scenario {
        name: "uninspected forward request",
        host: HOST,
        yaml: r"
network_policies:
  rest_api:
    name: rest_api
    endpoints:
      - { host: api.example.test, port: 8080 }
    binaries:
      - { path: /usr/bin/curl }
",
        cedar: &connect(&binary(BINARY)),
        cases: [
            "proxy.rs::forward_proxy_injects_token_grant_before_rewriting_request",
            "proxy.rs::forward_proxy_injects_token_exchange_before_rewriting_request",
            "proxy.rs::forward_proxy_token_grant_failure_returns_error_before_rewrite",
            "proxy.rs::forward_proxy_token_exchange_failure_returns_error_before_rewrite",
        ]
        .into_iter()
        .flat_map(|name| {
            [
                same_probe(name, Probe::Connect(network(HOST, PORT, BINARY)))
                    .asserting_yaml("allow"),
                same_probe(name, Probe::Inspection(network(HOST, PORT, BINARY)))
                    .asserting_yaml("none"),
            ]
        })
        .collect(),
    });
}
