// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Ported YAML decision tests from `opa.rs`, first half.
//!
//! Each case is named after the `opa.rs` test it ports. A YAML binary entry
//! also matches an ancestor of the calling process, so an exact binary is
//! translated as `context.binary_path == B || context.ancestors.contains(B)`.
//! Cedar cannot glob over the members of a set, so a glob binary only checks
//! `context.binary_path`; no ported glob case sets ancestors.
//!
//! A YAML MCP endpoint also allows its receive stream and client response
//! frames on the endpoint path, so every MCP translation adds the explicit
//! permit the Cedar docs require for those.

use std::fmt::Write as _;

use super::*;

/// A request probe for `host:port` from [`BINARY`].
fn at(host: &str, port: u16, request: L7RequestInfo) -> Probe {
    request_in(l7_ctx(host, port, BINARY), request)
}

/// A connection that also carries `/proc/<pid>/cmdline` paths.
fn with_cmdline(mut input: NetworkInput, cmdline_paths: &[&str]) -> NetworkInput {
    input.cmdline_paths = cmdline_paths.iter().map(PathBuf::from).collect();
    input
}

/// A single generic JSON-RPC call posted to `path`.
fn rpc(path: &str, method: &str) -> L7RequestInfo {
    jsonrpc_request(path, vec![call(method, None, None)])
}

/// A generic JSON-RPC call whose params are visible to policy.
fn rpc_with_params(path: &str, method: &str, params: &[(&str, &str)]) -> L7RequestInfo {
    let mut call = call(method, None, None);
    call.params = params
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect();
    jsonrpc_request(path, vec![call])
}

/// An MCP `tools/call` whose params carry `name` plus extra arguments.
fn mcp_tool_call(tool: &str, arguments: &[(&str, &str)]) -> L7RequestInfo {
    let mut call = call(
        "tools/call",
        Some(tool),
        Some(McpMethodClassification::Available),
    );
    for (key, value) in arguments {
        call.params.insert((*key).to_string(), (*value).to_string());
    }
    jsonrpc_request("/mcp", vec![call])
}

/// A bodyless `method` request that carries JSON-RPC metadata with no call.
fn jsonrpc_frame(
    method: &str,
    path: &str,
    receive_stream: bool,
    has_response: bool,
) -> L7RequestInfo {
    L7RequestInfo {
        jsonrpc: Some(JsonRpcRequestInfo {
            receive_stream,
            has_response,
            ..jsonrpc_info(Vec::new())
        }),
        ..rest(method, path)
    }
}

/// An MCP request the parser rejected with an inspection error.
///
/// The parser rejects a method that is unavailable in the selected revision
/// with an inspection error before policy runs, which is how both engines
/// receive it. That error cannot be built outside the parser, so this uses
/// the error the parser returns for a call sent before a revision is
/// selected; both engines treat every inspection error alike.
fn mcp_rejected(method: &str) -> L7RequestInfo {
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}"}}"#);
    let info = crate::l7::jsonrpc::parse_jsonrpc_body(
        body.as_bytes(),
        crate::l7::jsonrpc::JsonRpcInspectionMode::Mcp,
    );
    assert!(info.error.is_some(), "the parser rejects `{method}`");
    L7RequestInfo {
        jsonrpc: Some(info),
        ..rest("POST", "/mcp")
    }
}

/// The Cedar condition for a YAML binary entry with an exact path.
fn binary(path: &str) -> String {
    format!("(context.binary_path == \"{path}\" || context.ancestors.contains(\"{path}\"))")
}

/// The Cedar condition for a YAML binary entry with a glob path.
fn binary_glob(pattern: &str) -> String {
    format!("context.binary_path like(\"{pattern}\", \"/\")")
}

/// A `NetworkConnect` permit for `host:port` under `condition`.
fn connect_permit(cedar: &mut String, endpoint: &str, condition: &str) {
    let _ = write!(
        cedar,
        r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"{endpoint}")
when {{ {condition} }};
"#
    );
}

/// The MCP receive-stream and response-frame permit for `endpoint` and `path`.
fn mcp_frames_permit(endpoint: &str, path: &str, condition: &str) -> String {
    format!(
        r#"
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"{endpoint}")
when {{
    {condition}
    && context.path == "{path}"
    && ((context.method == "GET" && context.jsonrpc_receive_stream) || context.jsonrpc_response)
}};
"#
    )
}

// ---------------------------------------------------------------------------
// testdata/sandbox-policy.yaml (`test_engine()`)
// ---------------------------------------------------------------------------

const DEFAULT_FIXTURE_YAML: &str = include_str!("../../testdata/sandbox-policy.yaml");

/// The distinct `host:443` endpoints of the default fixture (15 endpoints,
/// `github.com` declared twice).
const DEFAULT_FIXTURE_HOSTS: [(&str, &str); 14] = [
    (
        "opa.rs::policy_dns_snapshot_accepts_the_default_multi_policy_shape/api.anthropic.com",
        "api.anthropic.com",
    ),
    (
        "opa.rs::policy_dns_snapshot_accepts_the_default_multi_policy_shape/statsig.anthropic.com",
        "statsig.anthropic.com",
    ),
    (
        "opa.rs::policy_dns_snapshot_accepts_the_default_multi_policy_shape/github.com",
        "github.com",
    ),
    (
        "opa.rs::policy_dns_snapshot_accepts_the_default_multi_policy_shape/api.github.com",
        "api.github.com",
    ),
    (
        "opa.rs::policy_dns_snapshot_accepts_the_default_multi_policy_shape/api.githubcopilot.com",
        "api.githubcopilot.com",
    ),
    (
        "opa.rs::policy_dns_snapshot_accepts_the_default_multi_policy_shape/api.individual.githubcopilot.com",
        "api.individual.githubcopilot.com",
    ),
    (
        "opa.rs::policy_dns_snapshot_accepts_the_default_multi_policy_shape/api.business.githubcopilot.com",
        "api.business.githubcopilot.com",
    ),
    (
        "opa.rs::policy_dns_snapshot_accepts_the_default_multi_policy_shape/api.enterprise.githubcopilot.com",
        "api.enterprise.githubcopilot.com",
    ),
    (
        "opa.rs::policy_dns_snapshot_accepts_the_default_multi_policy_shape/copilot-proxy.githubusercontent.com",
        "copilot-proxy.githubusercontent.com",
    ),
    (
        "opa.rs::policy_dns_snapshot_accepts_the_default_multi_policy_shape/copilot-telemetry.githubusercontent.com",
        "copilot-telemetry.githubusercontent.com",
    ),
    (
        "opa.rs::policy_dns_snapshot_accepts_the_default_multi_policy_shape/default.exp-tas.com",
        "default.exp-tas.com",
    ),
    (
        "opa.rs::policy_dns_snapshot_accepts_the_default_multi_policy_shape/origin-tracker.githubusercontent.com",
        "origin-tracker.githubusercontent.com",
    ),
    (
        "opa.rs::policy_dns_snapshot_accepts_the_default_multi_policy_shape/release-assets.githubusercontent.com",
        "release-assets.githubusercontent.com",
    ),
    (
        "opa.rs::policy_dns_snapshot_accepts_the_default_multi_policy_shape/gitlab.com",
        "gitlab.com",
    ),
];

/// The Cedar translation of `testdata/sandbox-policy.yaml`.
fn default_fixture_cedar() -> String {
    let mut cedar = String::new();

    // claude_code
    let claude_code = format!(
        "{} || {}",
        binary("/usr/local/bin/claude"),
        binary("/usr/bin/node")
    );
    for endpoint in ["api.anthropic.com:443", "statsig.anthropic.com:443"] {
        connect_permit(&mut cedar, endpoint, &claude_code);
    }

    // github_ssh_over_https: a REST endpoint; a YAML GET rule also allows HEAD.
    let git = binary("/usr/bin/git");
    connect_permit(&mut cedar, "github.com:443", &git);
    let _ = write!(
        cedar,
        r#"
@protocol("rest")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"github.com:443")
when {{
    {git}
    && ((["GET", "HEAD"].contains(context.method) && context.path like("/**/info/refs*", "/"))
        || (context.method == "POST" && context.path like("/**/git-upload-pack", "/")))
}};
"#
    );

    // copilot
    let copilot = [
        binary_glob("/usr/lib/node_modules/@github/copilot/node_modules/@github/**/copilot"),
        binary("/usr/local/bin/copilot"),
        binary_glob("/home/*/.local/bin/copilot"),
        binary("/usr/bin/node"),
    ]
    .join(" || ");
    for (_, host) in &DEFAULT_FIXTURE_HOSTS[2..13] {
        connect_permit(&mut cedar, &format!("{host}:443"), &copilot);
    }

    // gitlab
    connect_permit(&mut cedar, "gitlab.com:443", &binary("/usr/bin/glab"));
    cedar
}

#[test]
fn ported_default_fixture_connections() {
    let cedar = default_fixture_cedar();
    let mut cases = vec![
        same_probe(
            "opa.rs::allowed_binary_and_endpoint",
            Probe::Connect(with_cmdline(
                network("api.anthropic.com", 443, "/usr/bin/node"),
                &["/usr/local/bin/claude"],
            )),
        ),
        same_probe(
            "opa.rs::from_strings_and_from_files_produce_same_results",
            Probe::Connect(with_cmdline(
                network("api.anthropic.com", 443, "/usr/bin/node"),
                &["/usr/local/bin/claude"],
            )),
        ),
        same_probe(
            "opa.rs::wrong_binary_denied",
            Probe::Connect(network("api.anthropic.com", 443, "/usr/bin/python3")),
        ),
        same_probe(
            "opa.rs::wrong_endpoint_denied",
            Probe::Connect(network("evil.example.com", 443, "/usr/bin/node")),
        ),
        same_probe(
            "opa.rs::unknown_binary_default_deny",
            Probe::Connect(network("api.anthropic.com", 443, "/tmp/malicious")),
        ),
        same_probe(
            "opa.rs::github_policy_allows_git",
            Probe::Connect(network("github.com", 443, "/usr/bin/git")),
        ),
        same_probe(
            "opa.rs::case_insensitive_host_matching",
            Probe::Connect(with_cmdline(
                network("API.ANTHROPIC.COM", 443, "/usr/bin/node"),
                &["/usr/local/bin/claude"],
            )),
        ),
        same_probe(
            "opa.rs::wrong_port_denied",
            Probe::Connect(network("api.anthropic.com", 80, "/usr/bin/node")),
        ),
        same_probe(
            "opa.rs::ancestor_binary_allowed",
            Probe::Connect(network_with_ancestors(
                "github.com",
                443,
                "/usr/bin/python3",
                &["/usr/bin/git"],
            )),
        ),
        same_probe(
            "opa.rs::no_ancestor_match_denied",
            Probe::Connect(network_with_ancestors(
                "github.com",
                443,
                "/usr/bin/python3",
                &["/usr/bin/bash"],
            )),
        ),
        same_probe(
            "opa.rs::deep_ancestor_chain_matches",
            Probe::Connect(network_with_ancestors(
                "github.com",
                443,
                "/usr/bin/python3",
                &["/usr/bin/sh", "/usr/bin/git"],
            )),
        ),
        same_probe(
            "opa.rs::empty_ancestors_falls_back_to_direct",
            Probe::Connect(network("api.anthropic.com", 443, "/usr/local/bin/claude")),
        ),
    ];
    // The YAML test counts 15 snapshot endpoints; this checks that each
    // declared host is eligible, and that an undeclared one is not.
    cases.extend(DEFAULT_FIXTURE_HOSTS.iter().map(|(name, host)| {
        same_probe(
            *name,
            Probe::DnsEligible {
                name: (*host).to_string(),
                port: 443,
            },
        )
    }));
    cases.push(same_probe(
        "opa.rs::policy_dns_snapshot_accepts_the_default_multi_policy_shape/undeclared",
        Probe::DnsEligible {
            name: "evil.example.com".to_string(),
            port: 443,
        },
    ));
    assert_parity(&Scenario {
        name: "opa.rs default fixture",
        host: "github.com",
        yaml: DEFAULT_FIXTURE_YAML,
        cedar: &cedar,
        cases,
    });
}

/// The network policies of `opa.rs::test_proto()`, as YAML.
#[test]
fn ported_from_proto_fixture() {
    let claude = binary("/usr/local/bin/claude");
    let mut cedar = String::new();
    connect_permit(&mut cedar, "api.anthropic.com:443", &claude);
    connect_permit(&mut cedar, "statsig.anthropic.com:443", &claude);
    connect_permit(&mut cedar, "gitlab.com:443", &binary("/usr/bin/glab"));
    assert_parity(&Scenario {
        name: "opa.rs test_proto",
        host: "api.anthropic.com",
        yaml: r"
network_policies:
  claude_code:
    name: claude_code
    endpoints:
      - { host: api.anthropic.com, port: 443 }
      - { host: statsig.anthropic.com, port: 443 }
    binaries:
      - { path: /usr/local/bin/claude }
  gitlab:
    name: gitlab
    endpoints:
      - { host: gitlab.com, port: 443 }
    binaries:
      - { path: /usr/bin/glab }
",
        cedar: &cedar,
        cases: vec![
            same_probe(
                "opa.rs::from_proto_allows_matching_request",
                Probe::Connect(network("api.anthropic.com", 443, "/usr/local/bin/claude")),
            ),
            same_probe(
                "opa.rs::from_proto_denies_unmatched_request",
                Probe::Connect(network("evil.example.com", 443, "/usr/bin/curl")),
            ),
        ],
    });
}

// ---------------------------------------------------------------------------
// Binary globs and cmdline paths
// ---------------------------------------------------------------------------

#[test]
fn ported_binary_glob_usr_bin() {
    let mut cedar = String::new();
    connect_permit(&mut cedar, "example.com:443", &binary_glob("/usr/bin/*"));
    assert_parity(&Scenario {
        name: "opa.rs glob /usr/bin/*",
        host: "example.com",
        yaml: r#"
network_policies:
  glob_test:
    name: glob_test
    endpoints:
      - { host: example.com, port: 443 }
    binaries:
      - { path: "/usr/bin/*" }
"#,
        cedar: &cedar,
        cases: vec![
            same_probe(
                "opa.rs::glob_pattern_matches_binary",
                Probe::Connect(network("example.com", 443, "/usr/bin/node")),
            ),
            same_probe(
                "opa.rs::glob_pattern_no_cross_segment",
                Probe::Connect(network("example.com", 443, "/usr/bin/subdir/node")),
            ),
        ],
    });
}

#[test]
fn ported_binary_glob_usr_local_bin() {
    let mut cedar = String::new();
    connect_permit(
        &mut cedar,
        "example.com:443",
        &binary_glob("/usr/local/bin/*"),
    );
    assert_parity(&Scenario {
        name: "opa.rs glob /usr/local/bin/*",
        host: "example.com",
        yaml: r#"
network_policies:
  glob_test:
    name: glob_test
    endpoints:
      - { host: example.com, port: 443 }
    binaries:
      - { path: "/usr/local/bin/*" }
"#,
        cedar: &cedar,
        cases: vec![same_probe(
            "opa.rs::cmdline_glob_pattern_does_not_grant_access",
            Probe::Connect(with_cmdline(
                network("example.com", 443, "/usr/bin/node"),
                &["/usr/local/bin/claude"],
            )),
        )],
    });
}

#[test]
fn ported_cmdline_paths() {
    let mut cedar = String::new();
    connect_permit(
        &mut cedar,
        "example.com:443",
        &binary("/usr/local/bin/my-tool"),
    );
    assert_parity(&Scenario {
        name: "opa.rs cmdline paths",
        host: "example.com",
        yaml: r"
network_policies:
  script_test:
    name: script_test
    endpoints:
      - { host: example.com, port: 443 }
    binaries:
      - { path: /usr/local/bin/my-tool }
",
        cedar: &cedar,
        cases: vec![
            same_probe(
                "opa.rs::cmdline_path_does_not_grant_access",
                Probe::Connect(with_cmdline(
                    network_with_ancestors("example.com", 443, "/usr/bin/node", &["/usr/bin/bash"]),
                    &["/usr/local/bin/my-tool"],
                )),
            ),
            same_probe(
                "control: declared binary connects",
                Probe::Connect(network("example.com", 443, "/usr/local/bin/my-tool")),
            ),
            same_probe(
                "opa.rs::cmdline_path_no_match_denied",
                Probe::Connect(with_cmdline(
                    network_with_ancestors("example.com", 443, "/usr/bin/node", &["/usr/bin/bash"]),
                    &["/usr/bin/node", "/tmp/script.js"],
                )),
            ),
        ],
    });
}

#[test]
fn ported_wildcard_host() {
    assert_parity(&Scenario {
        name: "opa.rs wildcard host",
        host: "sub.example.com",
        yaml: r#"
network_policies:
  wildcard_test:
    name: wildcard_test
    endpoints:
      - host: "*.example.com"
        port: 443
    binaries:
      - path: /usr/bin/test
"#,
        cedar: r#"
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {
    resource.host like("*.example.com", ".")
    && resource.port == 443
    && (context.binary_path == "/usr/bin/test" || context.ancestors.contains("/usr/bin/test"))
};
"#,
        cases: vec![same_probe(
            "opa.rs::wildcard_host_percent_encoded_dot_no_match",
            Probe::Connect(network("evil%2eexample.com", 443, "/usr/bin/test")),
        )],
    });
}

// ---------------------------------------------------------------------------
// L7_TEST_DATA (`l7_engine()`)
// ---------------------------------------------------------------------------

pub(super) const L7_TEST_DATA: &str = r#"
network_policies:
  rest_api:
    name: rest_api
    endpoints:
      - host: api.example.com
        port: 8080
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/repos/**"
          - allow:
              method: POST
              path: "/repos/*/issues"
    binaries:
      - { path: /usr/bin/curl }
  readonly_api:
    name: readonly_api
    endpoints:
      - host: api.readonly.com
        port: 8080
        protocol: rest
        enforcement: enforce
        access: read-only
    binaries:
      - { path: /usr/bin/curl }
  full_api:
    name: full_api
    endpoints:
      - host: api.full.com
        port: 8080
        protocol: rest
        enforcement: audit
        access: full
    binaries:
      - { path: /usr/bin/curl }
  query_api:
    name: query_api
    endpoints:
      - host: api.query.com
        port: 8080
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/download"
              query:
                tag: "foo-*"
          - allow:
              method: GET
              path: "/search"
              query:
                tag:
                  any: ["foo-*", "bar-*"]
    binaries:
      - { path: /usr/bin/curl }
  graphql_api:
    name: graphql_api
    endpoints:
      - host: api.graphql.com
        port: 443
        protocol: graphql
        enforcement: enforce
        persisted_queries: allow_registered
        graphql_persisted_queries:
          abc123:
            operation_type: query
            operation_name: Viewer
            fields: [viewer]
        rules:
          - allow:
              operation_type: query
              fields: [viewer, repository]
          - allow:
              operation_type: mutation
              operation_name: Issue*
              fields: [createIssue, deleteRepository]
        deny_rules:
          - operation_type: mutation
            fields: [deleteRepository]
    binaries:
      - { path: /usr/bin/curl }
  graphql_readonly:
    name: graphql_readonly
    endpoints:
      - host: gql.readonly.com
        port: 443
        protocol: graphql
        enforcement: enforce
        access: read-only
    binaries:
      - { path: /usr/bin/curl }
  graphql_ws:
    name: graphql_ws
    endpoints:
      - host: realtime.graphql.com
        ports: [443]
        path: "/graphql"
        protocol: websocket
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/graphql"
          - allow:
              operation_type: query
              fields: [viewer]
          - allow:
              operation_type: subscription
              fields: [messageAdded]
        deny_rules:
          - operation_type: mutation
    binaries:
      - { path: /usr/bin/curl }
  l4_only:
    name: l4_only
    endpoints:
      - { host: l4only.example.com, port: 443 }
      - { host: explicit-tcp.example.com, port: 443, protocol: tcp }
    binaries:
      - { path: /usr/bin/curl }
filesystem_policy:
  include_workdir: true
  read_only: []
  read_write: []
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox
"#;

/// The Cedar translation of [`L7_TEST_DATA`].
///
/// `ported_phase4` translates `query_api` (query matchers) and
/// `ported_phase3` translates `graphql_ws` (GraphQL over WebSocket)
/// separately. The persisted-query registry of `graphql_api` is an endpoint
/// setting, not policy; `ported_phase2` supplies it with the middleware file.
pub(super) const L7_TEST_CEDAR: &str = r#"
// rest_api
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:8080")
when { context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl") };
@protocol("rest")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:8080")
when {
    (context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl"))
    && ((["GET", "HEAD"].contains(context.method) && context.path like("/repos/**", "/"))
        || (context.method == "POST" && context.path like("/repos/*/issues", "/")))
};

// readonly_api
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.readonly.com:8080")
when { context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl") };
@protocol("rest")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.readonly.com:8080")
when {
    (context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl"))
    && ["GET", "HEAD", "OPTIONS"].contains(context.method)
};

// full_api
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.full.com:8080")
when { context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl") };
@protocol("rest")
@enforcement("audit")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.full.com:8080")
when { context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl") };

// graphql_api
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.graphql.com:443")
when { context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl") };
@protocol("graphql")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.graphql.com:443")
when {
    (context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl"))
    && ((context.graphql_operation_type == "query"
         && context.graphql_fields.containsAny(["viewer", "repository"])
         && ["viewer", "repository"].containsAll(context.graphql_fields))
        || (context.graphql_operation_type == "mutation"
            && context.graphql_operation_name like "Issue*"
            && context.graphql_fields.containsAny(["createIssue", "deleteRepository"])
            && ["createIssue", "deleteRepository"].containsAll(context.graphql_fields)))
};
forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.graphql.com:443")
when {
    context.graphql_operation_type == "mutation"
    && context.graphql_fields.containsAny(["deleteRepository"])
};

// graphql_readonly
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"gql.readonly.com:443")
when { context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl") };
@protocol("graphql")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"gql.readonly.com:443")
when {
    (context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl"))
    && context.graphql_operation_type == "query"
};

// l4_only
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"l4only.example.com:443")
when { context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl") };
@transport("tcp")
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"explicit-tcp.example.com:443")
when { context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl") };
"#;

const FULL_PRESET_METHODS: [(&str, &str); 7] = [
    ("opa.rs::l7_full_preset_allows_everything/GET", "GET"),
    ("opa.rs::l7_full_preset_allows_everything/POST", "POST"),
    ("opa.rs::l7_full_preset_allows_everything/PUT", "PUT"),
    ("opa.rs::l7_full_preset_allows_everything/DELETE", "DELETE"),
    ("opa.rs::l7_full_preset_allows_everything/PATCH", "PATCH"),
    (
        "opa.rs::l7_full_preset_allows_everything/OPTIONS",
        "OPTIONS",
    ),
    ("opa.rs::l7_full_preset_allows_everything/HEAD", "HEAD"),
];

#[test]
fn ported_l7_test_data() {
    let api = |method: &str, path: &str| at("api.example.com", 8080, rest(method, path));
    let readonly = |method: &str| at("api.readonly.com", 8080, rest(method, "/anything"));
    let parse_error = L7RequestInfo {
        graphql: Some(GraphqlRequestInfo {
            operations: Vec::new(),
            error: Some("GraphQL document parse error".to_string()),
        }),
        ..rest("POST", "/graphql")
    };
    let mut cases = vec![
        same_probe(
            "opa.rs::l7_get_allowed_by_rules",
            api("GET", "/repos/myorg/foo"),
        ),
        same_probe(
            "opa.rs::l7_post_allowed_by_rules",
            api("POST", "/repos/myorg/issues"),
        ),
        same_probe(
            "opa.rs::l7_delete_denied_by_rules",
            api("DELETE", "/repos/myorg/foo"),
        ),
        same_probe(
            "opa.rs::l7_deny_reason_populated",
            api("DELETE", "/repos/myorg/foo"),
        ),
        same_probe(
            "opa.rs::l7_get_wrong_path_denied",
            api("GET", "/admin/settings"),
        ),
        same_probe(
            "opa.rs::l7_method_matching_case_insensitive",
            api("get", "/repos/myorg/foo"),
        ),
        same_probe(
            "opa.rs::l7_path_glob_matching",
            api("GET", "/repos/org/repo"),
        ),
        same_probe(
            "opa.rs::l7_wrong_binary_denied_even_with_matching_rules",
            request_in(
                l7_ctx("api.example.com", 8080, "/usr/bin/python3"),
                rest("GET", "/repos/myorg/foo"),
            ),
        ),
        same_probe(
            "opa.rs::l7_endpoint_config_returned_for_l7_endpoint",
            Probe::Inspection(network("api.example.com", 8080, BINARY)),
        ),
        same_probe("opa.rs::l7_readonly_preset_allows_get", readonly("GET")),
        same_probe("opa.rs::l7_readonly_preset_allows_head", readonly("HEAD")),
        same_probe(
            "opa.rs::l7_readonly_preset_allows_options",
            readonly("OPTIONS"),
        ),
        same_probe("opa.rs::l7_readonly_preset_denies_post", readonly("POST")),
        same_probe(
            "opa.rs::l7_readonly_preset_denies_delete",
            readonly("DELETE"),
        ),
        same(
            "opa.rs::l7_graphql_query_allowed_by_field_rule",
            graphql(vec![operation(
                "query",
                Some("RepoLookup"),
                &["repository"],
            )]),
        ),
        same(
            "opa.rs::l7_graphql_unlisted_field_denied",
            graphql(vec![operation("query", None, &["viewer", "adminAuditLog"])]),
        ),
        same(
            "opa.rs::l7_graphql_batch_denied_if_any_operation_unallowed",
            graphql(vec![
                operation("query", None, &["viewer"]),
                operation("mutation", Some("DeleteRepo"), &["deleteRepository"]),
            ]),
        ),
        same(
            "opa.rs::l7_graphql_deny_rule_takes_precedence",
            graphql(vec![operation(
                "mutation",
                Some("IssueDelete"),
                &["deleteRepository"],
            )]),
        ),
        same("opa.rs::l7_graphql_parse_error_denied", parse_error),
        same_probe(
            "opa.rs::l7_graphql_readonly_access_allows_query_and_denies_mutation/query",
            at(
                "gql.readonly.com",
                443,
                graphql(vec![operation("query", None, &["viewer"])]),
            ),
        ),
        same_probe(
            "opa.rs::l7_graphql_readonly_access_allows_query_and_denies_mutation/mutation",
            at(
                "gql.readonly.com",
                443,
                graphql(vec![operation("mutation", None, &["createIssue"])]),
            ),
        ),
        same_probe(
            "opa.rs::l7_no_request_on_l4_only_endpoint",
            at("l4only.example.com", 443, rest("GET", "/anything")),
        ),
    ];
    cases.extend(FULL_PRESET_METHODS.iter().map(|(name, method)| {
        same_probe(*name, at("api.full.com", 8080, rest(method, "/any/path")))
    }));
    assert_parity(&Scenario {
        name: "opa.rs L7_TEST_DATA",
        host: "api.graphql.com",
        yaml: L7_TEST_DATA,
        cedar: L7_TEST_CEDAR,
        cases,
    });
}

// ---------------------------------------------------------------------------
// Single-policy REST fixtures
// ---------------------------------------------------------------------------

#[test]
fn ported_relaxed_binary_identity_proto() {
    // The YAML test loads the policy with binary identity relaxed and an empty
    // binary path. The harness loads both engines with binary identity
    // required, and Cedar has no relaxed mode, so this ports the policy's
    // decisions for the declared binary.
    assert_parity(&Scenario {
        name: "opa.rs relaxed identity proto",
        host: "host.k3d.internal",
        yaml: r#"
network_policies:
  test_l7:
    name: test_l7
    endpoints:
      - host: host.k3d.internal
        port: 56123
        protocol: rest
        enforcement: enforce
        allowed_ips: ["192.168.0.0/16"]
        rules:
          - allow:
              method: GET
              path: /allowed
    binaries:
      - { path: /usr/bin/curl }
"#,
        cedar: r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"host.k3d.internal:56123")
when { context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl") };
@protocol("rest")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"host.k3d.internal:56123")
when {
    (context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl"))
    && ["GET", "HEAD"].contains(context.method)
    && context.path == "/allowed"
};
"#,
        cases: vec![
            same_probe(
                "opa.rs::relaxed_binary_identity_preserves_matched_policy_and_l7_for_proto/connect",
                Probe::Connect(network("host.k3d.internal", 56123, BINARY)),
            ),
            same_probe(
                "opa.rs::relaxed_binary_identity_preserves_matched_policy_and_l7_for_proto/request",
                at("host.k3d.internal", 56123, rest("GET", "/allowed")),
            ),
        ],
    });
}

#[test]
fn ported_github_git_transport() {
    assert_parity(&Scenario {
        name: "opa.rs github git transport",
        host: "github.com",
        yaml: r#"
network_policies:
  github:
    name: github
    endpoints:
      - host: github.com
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow: { method: GET, path: "**" }
          - allow: { method: HEAD, path: "**" }
          - allow: { method: OPTIONS, path: "**" }
          - allow: { method: POST, path: "/**/git-upload-pack" }
    binaries:
      - { path: /usr/bin/curl }
"#,
        cedar: r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"github.com:443")
when { context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl") };
@protocol("rest")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"github.com:443")
when {
    (context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl"))
    && ((["GET", "HEAD", "OPTIONS"].contains(context.method) && context.path like("**", "/"))
        || (context.method == "POST" && context.path like("/**/git-upload-pack", "/")))
};
"#,
        cases: vec![
            same(
                "opa.rs::l7_github_git_transport_allows_clone_blocks_push/info-refs",
                rest("GET", "/NVIDIA/OpenShell.git/info/refs"),
            ),
            same(
                "opa.rs::l7_github_git_transport_allows_clone_blocks_push/upload-pack",
                rest("POST", "/NVIDIA/OpenShell.git/git-upload-pack"),
            ),
            same(
                "opa.rs::l7_github_git_transport_allows_clone_blocks_push/receive-pack",
                rest("POST", "/NVIDIA/OpenShell.git/git-receive-pack"),
            ),
        ],
    });
}

// ---------------------------------------------------------------------------
// JSON-RPC fixtures
// ---------------------------------------------------------------------------

/// A YAML policy for one JSON-RPC endpoint at `host:8000` on `/rpc`.
fn jsonrpc_yaml(name: &str, host: &str, rules: &str) -> String {
    format!(
        r"
network_policies:
  {name}:
    name: {name}
    endpoints:
      - host: {host}
        port: 8000
        path: /rpc
        protocol: json-rpc
        enforcement: enforce
{rules}
    binaries:
      - {{ path: /usr/bin/curl }}
"
    )
}

/// The Cedar translation of a JSON-RPC endpoint at `host:8000` on `/rpc`.
///
/// `allow` is the condition on the call; `deny`, when present, is the
/// condition of a `forbid`.
fn jsonrpc_cedar(host: &str, allow: &str, deny: Option<&str>) -> String {
    let curl = binary("/usr/bin/curl");
    let mut cedar = String::new();
    connect_permit(&mut cedar, &format!("{host}:8000"), &curl);
    let _ = write!(
        cedar,
        r#"
@protocol("json-rpc")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"{host}:8000")
when {{
    {curl}
    && context.path == "/rpc"
    && !context.jsonrpc_response
    && {allow}
}};
"#
    );
    if let Some(deny) = deny {
        let _ = write!(
            cedar,
            r#"
forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"{host}:8000")
when {{ {deny} }};
"#
        );
    }
    cedar
}

const ALLOW_INITIALIZE: &str =
    "        rules:\n          - allow:\n              method: initialize";

#[test]
fn ported_jsonrpc_method_from_proto() {
    let host = "jsonrpc.proto.com";
    assert_parity(&Scenario {
        name: "opa.rs jsonrpc_proto",
        host,
        yaml: &jsonrpc_yaml("jsonrpc_proto", host, ALLOW_INITIALIZE),
        cedar: &jsonrpc_cedar(host, r#"context.jsonrpc_method == "initialize""#, None),
        cases: vec![
            same_probe(
                "opa.rs::l7_method_from_proto_is_enforced/initialize",
                at(host, 8000, rpc("/rpc", "initialize")),
            ),
            same_probe(
                "opa.rs::l7_method_from_proto_is_enforced/reports.list",
                at(host, 8000, rpc("/rpc", "reports.list")),
            ),
        ],
    });
}

#[test]
fn ported_jsonrpc_receive_stream() {
    let host = "jsonrpc.stream.test";
    assert_parity(&Scenario {
        name: "opa.rs jsonrpc_stream",
        host,
        yaml: &jsonrpc_yaml("jsonrpc_stream", host, ALLOW_INITIALIZE),
        cedar: &jsonrpc_cedar(host, r#"context.jsonrpc_method == "initialize""#, None),
        cases: vec![
            same_probe(
                "opa.rs::l7_jsonrpc_receive_stream_get_is_denied_for_matching_endpoint/rpc",
                at(host, 8000, jsonrpc_frame("GET", "/rpc", true, false)),
            ),
            same_probe(
                "opa.rs::l7_jsonrpc_receive_stream_get_is_denied_for_matching_endpoint/other",
                at(host, 8000, jsonrpc_frame("GET", "/other", true, false)),
            ),
            same_probe(
                "opa.rs::l7_jsonrpc_receive_stream_get_is_denied_for_matching_endpoint/bodyless",
                at(host, 8000, jsonrpc_frame("GET", "/rpc", false, false)),
            ),
            same_probe(
                "opa.rs::l7_jsonrpc_receive_stream_get_is_denied_for_matching_endpoint/null-metadata",
                at("mcp.stream.test", 8000, rest("GET", "/mcp")),
            ),
            same_probe(
                "control: listed call is allowed",
                at(host, 8000, rpc("/rpc", "initialize")),
            ),
        ],
    });
}

#[test]
fn ported_jsonrpc_response_post() {
    let host = "jsonrpc.response.test";
    let mixed = L7RequestInfo {
        jsonrpc: Some(JsonRpcRequestInfo {
            has_response: true,
            ..jsonrpc_info(vec![call("initialize", None, None)])
        }),
        ..rest("POST", "/rpc")
    };
    assert_parity(&Scenario {
        name: "opa.rs jsonrpc_response",
        host,
        yaml: &jsonrpc_yaml("jsonrpc_response", host, ALLOW_INITIALIZE),
        cedar: &jsonrpc_cedar(host, r#"context.jsonrpc_method == "initialize""#, None),
        cases: vec![
            same_probe(
                "opa.rs::l7_jsonrpc_response_post_is_denied_for_matching_endpoint/response",
                at(host, 8000, jsonrpc_frame("POST", "/rpc", false, true)),
            ),
            same_probe(
                "opa.rs::l7_jsonrpc_response_post_is_denied_for_matching_endpoint/mixed",
                at(host, 8000, mixed),
            ),
            same_probe(
                "opa.rs::l7_jsonrpc_response_post_is_denied_for_matching_endpoint/other",
                at(host, 8000, jsonrpc_frame("POST", "/other", false, true)),
            ),
            same_probe(
                "control: listed call is allowed",
                at(host, 8000, rpc("/rpc", "initialize")),
            ),
        ],
    });
}

#[test]
fn ported_jsonrpc_unlisted_method() {
    let host = "jsonrpc.methods.test";
    assert_parity(&Scenario {
        name: "opa.rs jsonrpc_methods",
        host,
        yaml: &jsonrpc_yaml("jsonrpc_methods", host, ALLOW_INITIALIZE),
        cedar: &jsonrpc_cedar(host, r#"context.jsonrpc_method == "initialize""#, None),
        cases: vec![same_probe(
            "opa.rs::l7_jsonrpc_unlisted_method_is_denied",
            at(host, 8000, rpc("/rpc", "reports.progress")),
        )],
    });
}

#[test]
fn ported_jsonrpc_method_rules_require_post() {
    let host = "jsonrpc.post.test";
    let with_method = |method: &str| L7RequestInfo {
        action: method.to_string(),
        ..rpc("/rpc", "initialize")
    };
    assert_parity(&Scenario {
        name: "opa.rs jsonrpc_post",
        host,
        yaml: &jsonrpc_yaml(
            "jsonrpc_post",
            host,
            "        rules:\n          - allow:\n              method: initialize\n        deny_rules:\n          - method: reports.archive",
        ),
        cedar: &jsonrpc_cedar(
            host,
            r#"context.jsonrpc_method == "initialize""#,
            Some(r#"context.jsonrpc_method == "reports.archive""#),
        ),
        cases: vec![
            same_probe(
                "opa.rs::l7_method_rules_require_post/POST",
                at(host, 8000, with_method("POST")),
            ),
            same_probe(
                "opa.rs::l7_method_rules_require_post/PUT",
                at(host, 8000, with_method("PUT")),
            ),
            same_probe(
                "opa.rs::l7_method_rules_require_post/GET",
                at(host, 8000, with_method("GET")),
            ),
        ],
    });
}

#[test]
fn ported_jsonrpc_request_params() {
    let host = "jsonrpc.params.test";
    let search = |params: &[(&str, &str)]| {
        at(
            host,
            8000,
            rpc_with_params("/rpc", "reports.search", params),
        )
    };
    assert_parity(&Scenario {
        name: "opa.rs jsonrpc_params",
        host,
        yaml: &jsonrpc_yaml(
            "jsonrpc_params",
            host,
            "        rules:\n          - allow:\n              method: reports.search\n        deny_rules:\n          - method: reports.archive",
        ),
        cedar: &jsonrpc_cedar(
            host,
            r#"context.jsonrpc_method == "reports.search""#,
            Some(r#"context.jsonrpc_method == "reports.archive""#),
        ),
        cases: vec![
            same_probe(
                "opa.rs::l7_jsonrpc_request_params_do_not_affect_method_policy/query",
                search(&[("query", "quarterly")]),
            ),
            same_probe(
                "opa.rs::l7_jsonrpc_request_params_do_not_affect_method_policy/scope",
                search(&[("query", "quarterly"), ("filters.scope", "workspace/main")]),
            ),
            same_probe(
                "opa.rs::l7_jsonrpc_request_params_do_not_affect_method_policy/blocked",
                search(&[("query", "blocked")]),
            ),
            same_probe(
                "opa.rs::l7_jsonrpc_request_params_do_not_affect_method_policy/blocked-args",
                search(&[("query", "blocked"), ("filters.reason", "test")]),
            ),
        ],
    });
}

#[test]
fn ported_jsonrpc_allow_all() {
    let host = "jsonrpc.allow-all.test";
    assert_parity(&Scenario {
        name: "opa.rs jsonrpc_allow_all",
        host,
        yaml: &jsonrpc_yaml(
            "jsonrpc_allow_all",
            host,
            "        rules:\n          - allow:\n              method: \"*\"",
        ),
        cedar: &jsonrpc_cedar(host, "true", None),
        cases: vec![
            same_probe(
                "opa.rs::l7_jsonrpc_allow_all_still_allows_any_method/initialize",
                at(host, 8000, rpc("/rpc", "initialize")),
            ),
            same_probe(
                "opa.rs::l7_jsonrpc_allow_all_still_allows_any_method/reports.archive",
                at(host, 8000, rpc("/rpc", "reports.archive")),
            ),
        ],
    });
}

#[test]
fn ported_jsonrpc_null_metadata() {
    let host = "jsonrpc.null.test";
    assert_parity(&Scenario {
        name: "opa.rs jsonrpc_null",
        host,
        yaml: &jsonrpc_yaml(
            "jsonrpc_null",
            host,
            "        rules:\n          - allow:\n              method: reports.list",
        ),
        cedar: &jsonrpc_cedar(host, r#"context.jsonrpc_method == "reports.list""#, None),
        cases: vec![same_probe(
            "opa.rs::l7_jsonrpc_null_metadata_non_matches_without_opa_error",
            at(host, 8000, rest("POST", "/rpc")),
        )],
    });
}

// ---------------------------------------------------------------------------
// MCP fixtures
// ---------------------------------------------------------------------------

/// A YAML MCP endpoint at `host:8000` on `/mcp`, as a list item.
fn mcp_endpoint_yaml(host: &str, body: &str) -> String {
    format!(
        r"      - host: {host}
        port: 8000
        path: /mcp
        protocol: mcp
        enforcement: enforce
{body}
"
    )
}

/// A YAML policy for one MCP endpoint at `host:8000` on `/mcp`.
fn mcp_yaml(name: &str, host: &str, body: &str) -> String {
    format!(
        r"
network_policies:
  {name}:
    name: {name}
    endpoints:
{endpoint}    binaries:
      - {{ path: /usr/bin/curl }}
",
        endpoint = mcp_endpoint_yaml(host, body)
    )
}

/// The Cedar translation of an MCP endpoint at `host:8000` on `/mcp`.
///
/// `allow` is the condition on the call; `deny`, when present, is the
/// condition of a `forbid`.
fn mcp_cedar(host: &str, allow: &str, deny: Option<&str>) -> String {
    let curl = binary("/usr/bin/curl");
    let endpoint = format!("{host}:8000");
    let mut cedar = String::new();
    connect_permit(&mut cedar, &endpoint, &curl);
    let _ = write!(
        cedar,
        r#"
@protocol("mcp")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"{endpoint}")
when {{
    {curl}
    && context.path == "/mcp"
    && !context.jsonrpc_response
    && {allow}
}};
"#
    );
    cedar.push_str(&mcp_frames_permit(&endpoint, "/mcp", &curl));
    if let Some(deny) = deny {
        let _ = write!(
            cedar,
            r#"
forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"{endpoint}")
when {{ {deny} }};
"#
        );
    }
    cedar
}

const MCP_ALLOW_INITIALIZE: &str =
    r#"context.mcp_method_class == "available" && context.jsonrpc_method == "initialize""#;

#[test]
fn ported_mcp_tool_params_from_proto() {
    let host = "mcp.proto.com";
    assert_parity(&Scenario {
        name: "opa.rs mcp_proto",
        host,
        yaml: &mcp_yaml(
            "mcp_proto",
            host,
            "        rules:\n          - allow:\n              method: tools/call\n              tool:\n                any: [read_status, \"submit_*\"]",
        ),
        cedar: &mcp_cedar(
            host,
            r#"context.mcp_method_class == "available"
    && context.jsonrpc_method == "tools/call"
    && (context.mcp_tool == "read_status" || context.mcp_tool like("submit_*", "."))"#,
            None,
        ),
        cases: vec![
            same_probe(
                "opa.rs::l7_mcp_tool_params_from_proto_are_enforced/read_status",
                at(host, 8000, mcp_tool_call("read_status", &[])),
            ),
            same_probe(
                "opa.rs::l7_mcp_tool_params_from_proto_are_enforced/blocked_action",
                at(host, 8000, mcp_tool_call("blocked_action", &[])),
            ),
        ],
    });
}

#[test]
fn ported_mcp_receive_stream() {
    let host = "mcp.stream.test";
    assert_parity(&Scenario {
        name: "opa.rs mcp_stream",
        host,
        yaml: &mcp_yaml("mcp_stream", host, ALLOW_INITIALIZE),
        cedar: &mcp_cedar(host, MCP_ALLOW_INITIALIZE, None),
        cases: vec![
            same_probe(
                "opa.rs::l7_mcp_receive_stream_get_is_allowed_for_matching_endpoint/mcp",
                at(host, 8000, jsonrpc_frame("GET", "/mcp", true, false)),
            ),
            same_probe(
                "opa.rs::l7_mcp_receive_stream_get_is_allowed_for_matching_endpoint/other",
                at(host, 8000, jsonrpc_frame("GET", "/other", true, false)),
            ),
        ],
    });
}

#[test]
fn ported_mcp_response_post() {
    let host = "mcp.response.test";
    assert_parity(&Scenario {
        name: "opa.rs mcp_response",
        host,
        yaml: &mcp_yaml("mcp_response", host, ALLOW_INITIALIZE),
        cedar: &mcp_cedar(host, MCP_ALLOW_INITIALIZE, None),
        cases: vec![
            same_probe(
                "opa.rs::l7_mcp_response_post_is_allowed_for_matching_endpoint/mcp",
                at(host, 8000, jsonrpc_frame("POST", "/mcp", false, true)),
            ),
            same_probe(
                "opa.rs::l7_mcp_response_post_is_allowed_for_matching_endpoint/other",
                at(host, 8000, jsonrpc_frame("POST", "/other", false, true)),
            ),
        ],
    });
}

#[test]
fn ported_mcp_rules_filter_tools_call() {
    let host = "mcp.params.test";
    assert_parity(&Scenario {
        name: "opa.rs mcp_params",
        host,
        yaml: &mcp_yaml(
            "mcp_params",
            host,
            "        mcp:\n          max_body_bytes: 131072\n        rules:\n          - allow:\n              method: tools/call\n              tool:\n                any: [read_status, submit_*]\n        deny_rules:\n          - method: tools/call\n            tool: blocked_action",
        ),
        cedar: &mcp_cedar(
            host,
            r#"context.mcp_method_class == "available"
    && context.jsonrpc_method == "tools/call"
    && (context.mcp_tool == "read_status" || context.mcp_tool like("submit_*", "."))"#,
            Some(
                r#"context.jsonrpc_method == "tools/call" && context.mcp_tool == "blocked_action""#,
            ),
        ),
        cases: vec![
            same_probe(
                "opa.rs::l7_mcp_rules_filter_tools_call/read_status",
                at(
                    host,
                    8000,
                    mcp_tool_call("read_status", &[("arguments.scope", "workspace/main")]),
                ),
            ),
            same_probe(
                "opa.rs::l7_mcp_rules_filter_tools_call/read_status-other-args",
                at(
                    host,
                    8000,
                    mcp_tool_call("read_status", &[("arguments.scope", "workspace/other")]),
                ),
            ),
            same_probe(
                "opa.rs::l7_mcp_rules_filter_tools_call/submit_report",
                at(host, 8000, mcp_tool_call("submit_report", &[])),
            ),
            same_probe(
                "opa.rs::l7_mcp_rules_filter_tools_call/blocked_action",
                at(host, 8000, mcp_tool_call("blocked_action", &[])),
            ),
            same_probe(
                "opa.rs::l7_mcp_rules_filter_tools_call/unmatched-tool",
                at(
                    host,
                    8000,
                    mcp_tool_call(
                        "private_tool_name",
                        &[("arguments.secret", "private-value")],
                    ),
                ),
            ),
            same_probe(
                "opa.rs::l7_mcp_rules_filter_tools_call/tools-list",
                at(
                    host,
                    8000,
                    mcp("tools/list", None, McpMethodClassification::Available),
                ),
            ),
        ],
    });
}

#[test]
fn ported_mcp_method_profile_allows_all_tools() {
    let host = "mcp.default.test";
    assert_parity(&Scenario {
        name: "opa.rs mcp_default",
        host,
        yaml: &mcp_yaml(
            "mcp_default",
            host,
            "        mcp:\n          allow_all_known_mcp_methods: true",
        ),
        cedar: &mcp_cedar(host, r#"context.mcp_method_class == "available""#, None),
        cases: vec![
            same_probe(
                "opa.rs::l7_mcp_method_profile_allows_all_tools/tools-call",
                at(
                    host,
                    8000,
                    mcp_tool_call("any_tool", &[("arguments.scope", "workspace/other")]),
                ),
            ),
            same_probe(
                "opa.rs::l7_mcp_method_profile_allows_all_tools/tools-list",
                at(
                    host,
                    8000,
                    mcp("tools/list", None, McpMethodClassification::Available),
                ),
            ),
            same_probe(
                "opa.rs::l7_mcp_method_profile_allows_all_tools/extension",
                at(
                    host,
                    8000,
                    mcp(
                        "vendor/private_method_name",
                        None,
                        McpMethodClassification::Extension,
                    ),
                ),
            ),
        ],
    });
}

#[test]
fn ported_mcp_extension_requires_an_exact_method_literal() {
    let exact = "mcp.extension-exact.test";
    let wildcard = "mcp.extension-wildcard.test";
    let denied = "mcp.extension-denied.test";
    let yaml = format!(
        r"
network_policies:
  exact_extension:
    name: exact_extension
    endpoints:
{exact_endpoint}    binaries:
      - {{ path: /usr/bin/curl }}
  wildcard_extension:
    name: wildcard_extension
    endpoints:
{wildcard_endpoint}    binaries:
      - {{ path: /usr/bin/curl }}
  denied_extension:
    name: denied_extension
    endpoints:
{denied_endpoint}    binaries:
      - {{ path: /usr/bin/curl }}
",
        exact_endpoint = mcp_endpoint_yaml(
            exact,
            "        rules:\n          - allow:\n              method: tools/vendor"
        ),
        wildcard_endpoint = mcp_endpoint_yaml(
            wildcard,
            "        rules:\n          - allow:\n              method: tools/*"
        ),
        denied_endpoint = mcp_endpoint_yaml(
            denied,
            "        rules:\n          - allow:\n              method: tools/vendor\n        deny_rules:\n          - method: tools/*"
        ),
    );
    // An exact method allows that method whatever its class; a method glob
    // only matches core methods of the selected revision.
    let cedar = [
        mcp_cedar(exact, r#"context.jsonrpc_method == "tools/vendor""#, None),
        mcp_cedar(
            wildcard,
            r#"context.mcp_method_class == "available" && context.jsonrpc_method like("tools/*", "/")"#,
            None,
        ),
        mcp_cedar(
            denied,
            r#"context.jsonrpc_method == "tools/vendor""#,
            Some(r#"context.jsonrpc_method like("tools/*", "/")"#),
        ),
    ]
    .concat();
    let extension = || mcp("tools/vendor", None, McpMethodClassification::Extension);
    assert_parity(&Scenario {
        name: "opa.rs mcp extensions",
        host: exact,
        yaml: &yaml,
        cedar: &cedar,
        cases: vec![
            same_probe(
                "opa.rs::l7_mcp_extension_requires_an_exact_method_literal/exact",
                at(exact, 8000, extension()),
            ),
            same_probe(
                "opa.rs::l7_mcp_extension_requires_an_exact_method_literal/unavailable",
                at(exact, 8000, mcp_rejected("tools/vendor")),
            ),
            same_probe(
                "opa.rs::l7_mcp_extension_requires_an_exact_method_literal/wildcard",
                at(wildcard, 8000, extension()),
            ),
            same_probe(
                "opa.rs::l7_mcp_extension_requires_an_exact_method_literal/denied",
                at(denied, 8000, extension()),
            ),
        ],
    });
}

#[test]
fn ported_mcp_null_params() {
    let host = "mcp.null-params.test";
    assert_parity(&Scenario {
        name: "opa.rs mcp_null_params",
        host,
        yaml: &mcp_yaml(
            "mcp_null_params",
            host,
            "        rules:\n          - allow:\n              method: tools/call\n              tool: read_status",
        ),
        cedar: &mcp_cedar(
            host,
            r#"context.mcp_method_class == "available"
    && context.jsonrpc_method == "tools/call"
    && context.mcp_tool == "read_status""#,
            None,
        ),
        cases: vec![same_probe(
            "opa.rs::l7_mcp_null_params_non_matches_without_opa_error",
            at(
                host,
                8000,
                mcp("tools/call", None, McpMethodClassification::Available),
            ),
        )],
    });
}
