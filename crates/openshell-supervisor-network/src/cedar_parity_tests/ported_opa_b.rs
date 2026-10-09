// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Ported YAML decision tests from `opa.rs`: network actions, L7 deny rules,
//! multi-port and wildcard hosts, symlink-expanded binaries, and HEAD
//! handling.
//!
//! YAML binary rules also match a process's ancestors, so each Cedar
//! translation of an exact binary path checks `context.ancestors` too.
//! A YAML `GET` rule also allows `HEAD`, so the Cedar translation lists
//! `HEAD` explicitly.

use super::*;

/// A Cedar condition matching YAML exact `binaries` against the calling
/// binary or any of its ancestors.
fn binaries(paths: &[&str]) -> String {
    let list = paths
        .iter()
        .map(|path| format!("\"{path}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!("([{list}].contains(context.binary_path) || context.ancestors.containsAny([{list}]))")
}

/// A `NetworkConnect` permit for one exact endpoint.
fn connect(endpoint: &str, condition: &str) -> String {
    format!(
        "permit (principal, action == Sandbox::Action::\"NetworkConnect\",\n        \
         resource == Sandbox::NetworkEndpoint::\"{endpoint}\")\nwhen {{ {condition} }};\n"
    )
}

/// `PROVIDER_ENDPOINT_TEST_DATA` from `opa.rs`.
const PROVIDER_ENDPOINT_YAML: &str = r"
network_policies:
  claude_code:
    name: claude_code
    endpoints:
      - { host: api.anthropic.com, port: 443 }
    binaries:
      - { path: /usr/local/bin/claude }
  gitlab:
    name: gitlab
    endpoints:
      - { host: gitlab.com, port: 443 }
    binaries:
      - { path: /usr/bin/glab }
";

#[test]
fn ported_provider_endpoint_network_actions() {
    let cedar = connect(
        "api.anthropic.com:443",
        &binaries(&["/usr/local/bin/claude"]),
    ) + &connect("gitlab.com:443", &binaries(&["/usr/bin/glab"]));
    assert_parity(&Scenario {
        name: "provider endpoints",
        host: "api.anthropic.com",
        yaml: PROVIDER_ENDPOINT_YAML,
        cedar: &cedar,
        cases: vec![
            same_probe(
                "opa.rs::explicitly_allowed_endpoint_binary_returns_allow",
                Probe::Connect(network("api.anthropic.com", 443, "/usr/local/bin/claude")),
            ),
            same_probe(
                "opa.rs::unknown_endpoint_returns_deny",
                Probe::Connect(network("api.openai.com", 443, "/usr/bin/python3")),
            ),
            same_probe(
                "opa.rs::endpoint_in_policy_binary_not_allowed_returns_deny",
                Probe::Connect(network("api.anthropic.com", 443, "/usr/bin/python3")),
            ),
        ],
    });
}

#[test]
fn ported_other_endpoint_network_actions() {
    let cedar = connect("gitlab.com:443", &binaries(&["/usr/bin/glab"]));
    assert_parity(&Scenario {
        name: "other endpoint",
        host: "gitlab.com",
        yaml: r"
network_policies:
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
                "opa.rs::unknown_endpoint_with_other_policy_returns_deny",
                Probe::Connect(network("api.openai.com", 443, "/usr/bin/python3")),
            ),
            same_probe(
                "opa.rs::endpoint_in_policy_binary_not_allowed_with_other_policy_returns_deny",
                Probe::Connect(network("gitlab.com", 443, "/usr/bin/python3")),
            ),
            same_probe(
                "control: declared binary connects",
                Probe::Connect(network("gitlab.com", 443, "/usr/bin/glab")),
            ),
        ],
    });
}

/// The original test loads `PROVIDER_ENDPOINT_TEST_DATA` with binary
/// identity not required. The harness always requires it, so the YAML here
/// matches every binary with the `/**` glob instead, which makes the same
/// decisions. The Cedar policy has no binary condition.
#[test]
fn ported_relaxed_binary_identity() {
    assert_parity(&Scenario {
        name: "relaxed binary identity",
        host: "api.anthropic.com",
        yaml: r#"
network_policies:
  claude_code:
    name: claude_code
    endpoints:
      - { host: api.anthropic.com, port: 443 }
    binaries:
      - { path: "/**" }
  gitlab:
    name: gitlab
    endpoints:
      - { host: gitlab.com, port: 443 }
    binaries:
      - { path: "/**" }
"#,
        cedar: r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.anthropic.com:443");
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"gitlab.com:443");
"#,
        cases: vec![
            same_probe(
                "opa.rs::relaxed_binary_identity_allows_declared_endpoint_without_binary_match",
                Probe::Connect(network("api.anthropic.com", 443, "/tmp/unlisted-agent")),
            ),
            same_probe(
                "opa.rs::relaxed_binary_identity_allows_declared_endpoint_without_binary_match / exact host",
                Probe::ExactHost(network("api.anthropic.com", 443, "/tmp/unlisted-agent")),
            ),
            same_probe(
                "opa.rs::relaxed_binary_identity_allows_declared_endpoint_without_binary_match / undeclared",
                Probe::Connect(network("api.openai.com", 443, "/tmp/unlisted-agent")),
            ),
        ],
    });
}

/// `test_proto()` from `opa.rs`, written as YAML.
#[test]
fn ported_from_proto_network_actions() {
    let claude = binaries(&["/usr/local/bin/claude"]);
    let cedar = connect("api.anthropic.com:443", &claude)
        + &connect("statsig.anthropic.com:443", &claude)
        + &connect("gitlab.com:443", &binaries(&["/usr/bin/glab"]));
    assert_parity(&Scenario {
        name: "test_proto",
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
                "opa.rs::from_proto_explicitly_allowed_returns_allow",
                Probe::Connect(network("api.anthropic.com", 443, "/usr/local/bin/claude")),
            ),
            same_probe(
                "opa.rs::from_proto_unknown_endpoint_returns_deny",
                Probe::Connect(network("api.openai.com", 443, "/usr/bin/python3")),
            ),
        ],
    });
}

/// The network policies of `testdata/sandbox-policy.yaml`.
const DEV_POLICY_YAML: &str = r#"
network_policies:
  claude_code:
    name: claude_code
    endpoints:
      - { host: api.anthropic.com, port: 443 }
      - { host: statsig.anthropic.com, port: 443 }
    binaries:
      - { path: /usr/local/bin/claude }
      - { path: /usr/bin/node }
  github_ssh_over_https:
    name: github-ssh-over-https
    endpoints:
      - host: github.com
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/**/info/refs*"
          - allow:
              method: POST
              path: "/**/git-upload-pack"
    binaries:
      - { path: /usr/bin/git }
  copilot:
    name: copilot
    endpoints:
      - { host: github.com, port: 443 }
      - { host: api.github.com, port: 443 }
      - { host: api.githubcopilot.com, port: 443 }
      - { host: api.individual.githubcopilot.com, port: 443 }
      - { host: api.business.githubcopilot.com, port: 443 }
      - { host: api.enterprise.githubcopilot.com, port: 443 }
      - { host: copilot-proxy.githubusercontent.com, port: 443 }
      - { host: copilot-telemetry.githubusercontent.com, port: 443 }
      - { host: default.exp-tas.com, port: 443 }
      - { host: origin-tracker.githubusercontent.com, port: 443 }
      - { host: release-assets.githubusercontent.com, port: 443 }
    binaries:
      - { path: "/usr/lib/node_modules/@github/copilot/node_modules/@github/**/copilot" }
      - { path: /usr/local/bin/copilot }
      - { path: "/home/*/.local/bin/copilot" }
      - { path: /usr/bin/node }
  gitlab:
    name: gitlab
    endpoints:
      - { host: gitlab.com, port: 443 }
    binaries:
      - { path: /usr/bin/glab }
"#;

/// The Cedar translation of [`DEV_POLICY_YAML`]. Cedar has no quantifier
/// over set elements, so copilot's glob binaries match the calling binary
/// only, not its ancestors.
fn dev_policy_cedar() -> String {
    let claude = binaries(&["/usr/local/bin/claude", "/usr/bin/node"]);
    let git = binaries(&["/usr/bin/git"]);
    let copilot = format!(
        "context.binary_path like(\"/usr/lib/node_modules/@github/copilot/node_modules/@github/**/copilot\", \"/\") \
         || context.binary_path like(\"/home/*/.local/bin/copilot\", \"/\") || {}",
        binaries(&["/usr/local/bin/copilot", "/usr/bin/node"])
    );
    let mut cedar = connect("api.anthropic.com:443", &claude)
        + &connect("statsig.anthropic.com:443", &claude)
        + &connect("github.com:443", &git)
        + &format!(
            r#"@protocol("rest")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"github.com:443")
when {{
    {git}
    && ((["GET", "HEAD"].contains(context.method) && context.path like("/**/info/refs*", "/"))
        || (context.method == "POST" && context.path like("/**/git-upload-pack", "/")))
}};
"#
        );
    for host in [
        "github.com",
        "api.github.com",
        "api.githubcopilot.com",
        "api.individual.githubcopilot.com",
        "api.business.githubcopilot.com",
        "api.enterprise.githubcopilot.com",
        "copilot-proxy.githubusercontent.com",
        "copilot-telemetry.githubusercontent.com",
        "default.exp-tas.com",
        "origin-tracker.githubusercontent.com",
        "release-assets.githubusercontent.com",
    ] {
        cedar += &connect(&format!("{host}:443"), &copilot);
    }
    cedar + &connect("gitlab.com:443", &binaries(&["/usr/bin/glab"]))
}

#[test]
fn ported_dev_policy_network_actions() {
    let cedar = dev_policy_cedar();
    assert_parity(&Scenario {
        name: "dev policy",
        host: "api.anthropic.com",
        yaml: DEV_POLICY_YAML,
        cedar: &cedar,
        cases: vec![
            same_probe(
                "opa.rs::network_action_with_dev_policy / claude",
                Probe::Connect(network("api.anthropic.com", 443, "/usr/local/bin/claude")),
            ),
            same_probe(
                "opa.rs::network_action_with_dev_policy / git",
                Probe::Connect(network("github.com", 443, "/usr/bin/git")),
            ),
            // The original also checks the Rego deny reason text, which is
            // out of scope; only the denial is compared.
            same_probe(
                "opa.rs::deny_reason_includes_symlink_hint",
                Probe::Connect(network("api.anthropic.com", 443, "/usr/bin/python3.11")),
            ),
            same_probe(
                "opa.rs::deny_reason_collapses_endpoint_misses",
                Probe::Connect(network(
                    "not-configured.example.com",
                    443,
                    "/usr/local/bin/claude",
                )),
            ),
        ],
    });
}

/// `L7_DENY_TEST_DATA` from `opa.rs`, without the `deny_with_query` policy,
/// whose query-parameter deny rule Cedar cannot express.
#[test]
fn ported_l7_deny_rules() {
    assert_parity(&Scenario {
        name: "L7 deny rules",
        host: "api.github.com",
        yaml: r#"
network_policies:
  github_api:
    name: github_api
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-write
        deny_rules:
          - method: POST
            path: "/repos/*/pulls/*/reviews"
          - method: PUT
            path: "/repos/*/branches/*/protection"
          - method: "*"
            path: "/repos/*/rulesets"
    binaries:
      - { path: /usr/bin/curl }
"#,
        cedar: r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.github.com:443")
when { context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl") };
@protocol("rest")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.github.com:443")
when {
    (context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl"))
    && ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"].contains(context.method)
};
forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.github.com:443")
when { context.method == "POST" && context.path like("/repos/*/pulls/*/reviews", "/") };
forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.github.com:443")
when { context.method == "PUT" && context.path like("/repos/*/branches/*/protection", "/") };
forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.github.com:443")
when { context.path like("/repos/*/rulesets", "/") };
"#,
        cases: vec![
            same(
                "opa.rs::l7_deny_rule_blocks_allowed_method_path",
                rest("POST", "/repos/myorg/pulls/123/reviews"),
            ),
            same(
                "opa.rs::l7_deny_rule_allows_non_matching_requests",
                rest("GET", "/repos/myorg/issues"),
            ),
            same(
                "opa.rs::l7_deny_rule_allows_same_method_different_path",
                rest("POST", "/repos/myorg/issues"),
            ),
            same(
                "opa.rs::l7_deny_rule_blocks_wildcard_method",
                rest("GET", "/repos/myorg/rulesets"),
            ),
            same(
                "opa.rs::l7_deny_rule_blocks_put_protection",
                rest("PUT", "/repos/myorg/branches/main/protection"),
            ),
            // The original checks the deny reason text; only the denial is
            // compared.
            same(
                "opa.rs::l7_deny_reason_populated_when_deny_rule_matches",
                rest("POST", "/repos/myorg/pulls/123/reviews"),
            ),
        ],
    });
}

/// `OVERLAPPING_L7_TEST_DATA` from `opa.rs`. The second policy's `tls: skip`
/// and `allowed_ips` do not affect request decisions.
#[test]
fn ported_overlapping_l7_policies() {
    let ctx = || l7_ctx("192.168.1.100", 8567, BINARY);
    assert_parity(&Scenario {
        name: "overlapping L7 policies",
        host: "192.168.1.100",
        yaml: r#"
network_policies:
  test_server:
    name: test_server
    endpoints:
      - host: 192.168.1.100
        port: 8567
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "**"
    binaries:
      - { path: /usr/bin/curl }
  allow_192_168_1_100_8567:
    name: allow_192_168_1_100_8567
    endpoints:
      - host: 192.168.1.100
        port: 8567
        protocol: rest
        enforcement: enforce
        tls: skip
        allowed_ips:
          - 192.168.1.100
        rules:
          - allow:
              method: GET
              path: "**"
    binaries:
      - { path: /usr/bin/curl }
"#,
        cedar: r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"192.168.1.100:8567")
when { context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl") };
@protocol("rest")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"192.168.1.100:8567")
when {
    (context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl"))
    && ["GET", "HEAD"].contains(context.method)
};
"#,
        cases: vec![
            same_probe(
                "opa.rs::l7_overlapping_policies_allow_request_does_not_crash",
                request_in(ctx(), rest("GET", "/test")),
            ),
            same_probe(
                "opa.rs::l7_overlapping_policies_deny_request_does_not_crash",
                request_in(ctx(), rest("DELETE", "/test")),
            ),
        ],
    });
}

/// The `rest_api` and `l4_only` policies of `L7_TEST_DATA` from `opa.rs`.
/// The other policies there use query matchers, persisted GraphQL queries,
/// and WebSocket rules, which Cedar cannot express, and no case here
/// reaches them.
#[test]
fn ported_l7_test_data_rest_and_l4() {
    let ctx = || l7_ctx("api.example.com", 8080, BINARY);
    assert_parity(&Scenario {
        name: "L7 test data",
        host: "api.example.com",
        yaml: r#"
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
  l4_only:
    name: l4_only
    endpoints:
      - { host: l4only.example.com, port: 443 }
      - { host: explicit-tcp.example.com, port: 443, protocol: tcp }
    binaries:
      - { path: /usr/bin/curl }
"#,
        cedar: r#"
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
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"l4only.example.com:443")
when { context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl") };
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"explicit-tcp.example.com:443")
when { context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl") };
"#,
        cases: vec![
            same_probe(
                "opa.rs::l7_endpoint_config_none_for_l4_only",
                Probe::Inspection(network("l4only.example.com", 443, BINARY)),
            ),
            same_probe(
                "opa.rs::l7_head_allowed_where_get_is_allowed",
                request_in(ctx(), rest("HEAD", "/repos/myorg/foo")),
            ),
            same_probe(
                "opa.rs::l7_options_not_implicitly_allowed_by_get",
                request_in(ctx(), rest("OPTIONS", "/repos/myorg/foo")),
            ),
        ],
    });
}

#[test]
fn ported_l7_head_denied_when_only_post_allowed() {
    assert_parity(&Scenario {
        name: "POST-only endpoint",
        host: "h.test",
        yaml: "network_policies:\n  p:\n    name: p\n    endpoints:\n      - host: h.test\n        port: 80\n        protocol: rest\n        enforcement: enforce\n        rules:\n          - allow: {method: POST, path: \"/\"}\n    binaries:\n      - {path: /usr/bin/curl}\n",
        cedar: r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"h.test:80")
when { context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl") };
@protocol("rest")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"h.test:80")
when {
    (context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl"))
    && context.method == "POST" && context.path == "/"
};
"#,
        cases: vec![same_probe(
            "opa.rs::l7_head_denied_when_only_post_allowed",
            request_in(l7_ctx("h.test", 80, BINARY), rest("HEAD", "/")),
        )],
    });
}

#[test]
fn ported_l7_head_blocked_by_deny_rule_targeting_get() {
    assert_parity(&Scenario {
        name: "deny rule on GET",
        host: "h.test",
        yaml: "network_policies:\n  p:\n    name: p\n    endpoints:\n      - host: h.test\n        port: 80\n        protocol: rest\n        enforcement: enforce\n        access: full\n        deny_rules:\n          - method: GET\n            path: \"/protected\"\n    binaries:\n      - {path: /usr/bin/curl}\n",
        cedar: r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"h.test:80")
when { context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl") };
@protocol("rest")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"h.test:80")
when { context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl") };
forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"h.test:80")
when { ["GET", "HEAD"].contains(context.method) && context.path == "/protected" };
"#,
        cases: vec![same_probe(
            "opa.rs::l7_head_blocked_by_deny_rule_targeting_get",
            request_in(l7_ctx("h.test", 80, BINARY), rest("HEAD", "/protected")),
        )],
    });
}

/// The `public_api` and `wildcard_api` policies of `ALLOWED_IPS_TEST_DATA`
/// from `opa.rs`. The other policies there use `allowed_ips`, which Cedar
/// cannot express, and no case here reaches them.
#[test]
fn ported_exact_declared_endpoint_host() {
    assert_parity(&Scenario {
        name: "exact declared host",
        host: "api.github.com",
        yaml: r#"
network_policies:
  public_api:
    name: public_api
    endpoints:
      - { host: api.github.com, port: 443 }
    binaries:
      - { path: /usr/bin/curl }
  wildcard_api:
    name: wildcard_api
    endpoints:
      - { host: "*.corp.net", port: 443 }
    binaries:
      - { path: /usr/bin/curl }
"#,
        cedar: r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.github.com:443")
when { context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl") };
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {
    resource.host like("*.corp.net", ".")
    && resource.port == 443
    && (context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl"))
};
"#,
        cases: vec![
            same_probe(
                "opa.rs::exact_declared_endpoint_host_true_for_l4_host_only / no L7 config",
                Probe::Inspection(network("api.github.com", 443, BINARY)),
            ),
            same_probe(
                "opa.rs::exact_declared_endpoint_host_true_for_l4_host_only",
                Probe::ExactHost(network("api.github.com", 443, BINARY)),
            ),
            same_probe(
                "opa.rs::exact_declared_endpoint_host_false_for_wildcard_host / allowed",
                Probe::Connect(network("api.corp.net", 443, BINARY)),
            ),
            same_probe(
                "opa.rs::exact_declared_endpoint_host_false_for_wildcard_host",
                Probe::ExactHost(network("api.corp.net", 443, BINARY)),
            ),
        ],
    });
}

/// The multi-port YAML tests, and `from_proto_multi_port_allows_matching`,
/// whose proto policy is the same endpoint written as YAML.
#[test]
fn ported_multi_port_endpoint() {
    assert_parity(&Scenario {
        name: "multi-port endpoint",
        host: "api.example.com",
        yaml: r"
network_policies:
  multi:
    name: multi
    endpoints:
      - { host: api.example.com, ports: [443, 8443] }
    binaries:
      - { path: /usr/bin/curl }
",
        cedar: r#"
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {
    resource.host == "api.example.com"
    && [443, 8443].contains(resource.port)
    && (context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl"))
};
"#,
        cases: vec![
            same_probe(
                "opa.rs::multi_port_endpoint_matches_first_port",
                Probe::Connect(network("api.example.com", 443, BINARY)),
            ),
            same_probe(
                "opa.rs::multi_port_endpoint_matches_second_port",
                Probe::Connect(network("api.example.com", 8443, BINARY)),
            ),
            same_probe(
                "opa.rs::multi_port_endpoint_rejects_unlisted_port",
                Probe::Connect(network("api.example.com", 80, BINARY)),
            ),
            same_probe(
                "opa.rs::from_proto_multi_port_allows_matching / 443",
                Probe::Connect(network("api.example.com", 443, BINARY)),
            ),
            same_probe(
                "opa.rs::from_proto_multi_port_allows_matching / 8443",
                Probe::Connect(network("api.example.com", 8443, BINARY)),
            ),
            same_probe(
                "opa.rs::from_proto_multi_port_allows_matching / 80",
                Probe::Connect(network("api.example.com", 80, BINARY)),
            ),
        ],
    });
}

#[test]
fn ported_single_port_backwards_compat() {
    assert_parity(&Scenario {
        name: "single port",
        host: "api.example.com",
        yaml: r"
network_policies:
  compat:
    name: compat
    endpoints:
      - { host: api.example.com, port: 443 }
    binaries:
      - { path: /usr/bin/curl }
",
        cedar: r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl") };
"#,
        cases: vec![
            same_probe(
                "opa.rs::single_port_backwards_compat / 443",
                Probe::Connect(network("api.example.com", 443, BINARY)),
            ),
            same_probe(
                "opa.rs::single_port_backwards_compat / 80",
                Probe::Connect(network("api.example.com", 80, BINARY)),
            ),
        ],
    });
}

/// A scenario for the wildcard-host tests, whose request cases default to
/// `api.example.com`.
fn wildcard_scenario<'a>(
    name: &'a str,
    yaml: &'a str,
    cedar: &'a str,
    cases: Vec<Case>,
) -> Scenario<'a> {
    Scenario {
        name,
        host: "api.example.com",
        yaml,
        cedar,
        cases,
    }
}

const WILDCARD_CEDAR: &str = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {
    resource.host like("*.example.com", ".")
    && resource.port == 443
    && (context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl"))
};
"#;

#[test]
fn ported_wildcard_host() {
    assert_parity(&wildcard_scenario(
        "wildcard host",
        r#"
network_policies:
  wildcard:
    name: wildcard
    endpoints:
      - { host: "*.example.com", port: 443 }
    binaries:
      - { path: /usr/bin/curl }
"#,
        WILDCARD_CEDAR,
        vec![
            same_probe(
                "opa.rs::wildcard_host_matches_subdomain",
                Probe::Connect(network("api.example.com", 443, BINARY)),
            ),
            same_probe(
                "opa.rs::wildcard_host_rejects_deep_subdomain",
                Probe::Connect(network("deep.sub.example.com", 443, BINARY)),
            ),
            same_probe(
                "opa.rs::wildcard_host_rejects_exact_domain",
                Probe::Connect(network("example.com", 443, BINARY)),
            ),
            same_probe(
                "opa.rs::wildcard_host_plus_port",
                Probe::Connect(network("api.example.com", 80, BINARY)),
            ),
        ],
    ));
}

/// Cedar endpoint hosts are lowercase, so the Cedar translation of
/// `*.EXAMPLE.COM` writes the pattern in lowercase.
#[test]
fn ported_wildcard_host_case_insensitive() {
    assert_parity(&wildcard_scenario(
        "uppercase wildcard host",
        r#"
network_policies:
  wildcard:
    name: wildcard
    endpoints:
      - { host: "*.EXAMPLE.COM", port: 443 }
    binaries:
      - { path: /usr/bin/curl }
"#,
        WILDCARD_CEDAR,
        vec![same_probe(
            "opa.rs::wildcard_host_case_insensitive",
            Probe::Connect(network("api.example.com", 443, BINARY)),
        )],
    ));
}

#[test]
fn ported_wildcard_host_intra_label() {
    assert_parity(&wildcard_scenario(
        "intra-label wildcard",
        r#"
network_policies:
  intra_label:
    name: intra_label
    endpoints:
      - { host: "*-aiplatform.googleapis.com", port: 443 }
    binaries:
      - { path: /usr/bin/curl }
"#,
        r#"
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {
    resource.host like("*-aiplatform.googleapis.com", ".")
    && resource.port == 443
    && (context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl"))
};
"#,
        vec![
            same_probe(
                "opa.rs::wildcard_host_intra_label_matches",
                Probe::Connect(network(
                    "us-central1-aiplatform.googleapis.com",
                    443,
                    BINARY,
                )),
            ),
            same_probe(
                "opa.rs::wildcard_host_intra_label_does_not_cross_dot",
                Probe::Connect(network(
                    "us-central1.aiplatform.googleapis.com",
                    443,
                    BINARY,
                )),
            ),
        ],
    ));
}

#[test]
fn ported_wildcard_host_middle_label() {
    assert_parity(&wildcard_scenario(
        "middle-label wildcard",
        r#"
network_policies:
  s3:
    name: s3
    endpoints:
      - { host: "*.s3.*.amazonaws.com", port: 443 }
    binaries:
      - { path: /usr/bin/curl }
"#,
        r#"
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {
    resource.host like("*.s3.*.amazonaws.com", ".")
    && resource.port == 443
    && (context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl"))
};
"#,
        vec![
            same_probe(
                "opa.rs::wildcard_host_middle_label_matches_one_region_label",
                Probe::Connect(network("my-bucket.s3.us-east-1.amazonaws.com", 443, BINARY)),
            ),
            same_probe(
                "opa.rs::wildcard_host_middle_label_does_not_match_missing_bucket_label",
                Probe::Connect(network("s3.us-east-1.amazonaws.com", 443, BINARY)),
            ),
            same_probe(
                "opa.rs::wildcard_host_middle_label_does_not_skip_dualstack_label",
                Probe::Connect(network(
                    "my-bucket.s3.dualstack.us-east-1.amazonaws.com",
                    443,
                    BINARY,
                )),
            ),
        ],
    ));
}

#[test]
fn ported_wildcard_host_multi_port() {
    assert_parity(&wildcard_scenario(
        "wildcard host, multiple ports",
        r#"
network_policies:
  wildcard:
    name: wildcard
    endpoints:
      - { host: "*.example.com", ports: [443, 8443] }
    binaries:
      - { path: /usr/bin/curl }
"#,
        r#"
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {
    resource.host like("*.example.com", ".")
    && [443, 8443].contains(resource.port)
    && (context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl"))
};
"#,
        vec![same_probe(
            "opa.rs::wildcard_host_multi_port",
            Probe::Connect(network("api.example.com", 8443, BINARY)),
        )],
    ));
}

/// Cedar rejects an `HttpRequest` policy that does not name one endpoint in
/// its scope, so a YAML L7 rule on a wildcard host can only be translated
/// for the hosts the case uses.
const WILDCARD_L7_CEDAR_CONNECT: &str = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {
    resource.host like("*.example.com", ".")
    && resource.port == 8080
    && (context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl"))
};
"#;

#[test]
fn ported_wildcard_host_l7_rules_apply() {
    let cedar = WILDCARD_L7_CEDAR_CONNECT.to_string()
        + r#"
@protocol("rest")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:8080")
when {
    (context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl"))
    && ["GET", "HEAD"].contains(context.method)
    && context.path like("/api/**", "/")
};
"#;
    let ctx = || l7_ctx("api.example.com", 8080, BINARY);
    assert_parity(&wildcard_scenario(
        "wildcard host with L7 rules",
        r#"
network_policies:
  wildcard_l7:
    name: wildcard_l7
    endpoints:
      - host: "*.example.com"
        port: 8080
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/api/**"
    binaries:
      - { path: /usr/bin/curl }
"#,
        &cedar,
        vec![
            same_probe(
                "opa.rs::wildcard_host_l7_rules_apply / GET",
                request_in(ctx(), rest("GET", "/api/foo")),
            ),
            same_probe(
                "opa.rs::wildcard_host_l7_rules_apply / DELETE",
                request_in(ctx(), rest("DELETE", "/api/foo")),
            ),
        ],
    ));
}

#[test]
fn ported_wildcard_host_l7_endpoint_config_returned() {
    let cedar = WILDCARD_L7_CEDAR_CONNECT.to_string()
        + r#"
@protocol("rest")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:8080")
when {
    (context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl"))
    && ["GET", "HEAD"].contains(context.method)
};
"#;
    assert_parity(&wildcard_scenario(
        "wildcard host endpoint config",
        r#"
network_policies:
  wildcard_l7:
    name: wildcard_l7
    endpoints:
      - host: "*.example.com"
        port: 8080
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "**"
    binaries:
      - { path: /usr/bin/curl }
"#,
        &cedar,
        vec![
            same_probe(
                "opa.rs::wildcard_host_l7_endpoint_config_returned",
                Probe::Inspection(network("api.example.com", 8080, BINARY)),
            ),
            diverges_probe(
                "opa.rs::wildcard_host_l7_endpoint_config_returned / other subdomain",
                Probe::Inspection(network("other.example.com", 8080, BINARY)),
                "YAML inspects every host matching a wildcard L7 endpoint; a Cedar \
                 HttpRequest policy must name one exact endpoint, so other matching \
                 hosts connect uninspected",
            ),
        ],
    ));
}

/// Cedar rejects an `HttpRequest` policy without one endpoint in its scope,
/// so the multi-port YAML endpoint becomes one policy per port.
#[test]
fn ported_l7_multi_port_request_evaluation() {
    assert_parity(&Scenario {
        name: "multi-port L7 endpoint",
        host: "api.example.com",
        yaml: r#"
network_policies:
  multi_l7:
    name: multi_l7
    endpoints:
      - host: api.example.com
        ports: [8080, 9090]
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "**"
    binaries:
      - { path: /usr/bin/curl }
"#,
        cedar: r#"
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {
    resource.host == "api.example.com"
    && [8080, 9090].contains(resource.port)
    && (context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl"))
};
@protocol("rest")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:8080")
when {
    (context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl"))
    && ["GET", "HEAD"].contains(context.method)
};
@protocol("rest")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:9090")
when {
    (context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl"))
    && ["GET", "HEAD"].contains(context.method)
};
"#,
        cases: vec![
            same_probe(
                "opa.rs::l7_multi_port_request_evaluation / 8080",
                request_in(
                    l7_ctx("api.example.com", 8080, BINARY),
                    rest("GET", "/anything"),
                ),
            ),
            same_probe(
                "opa.rs::l7_multi_port_request_evaluation / 9090",
                request_in(
                    l7_ctx("api.example.com", 9090, BINARY),
                    rest("GET", "/anything"),
                ),
            ),
        ],
    });
}

#[test]
fn ported_symlink_expanded_binaries() {
    let cedar = connect(
        "pypi.org:443",
        &binaries(&["/usr/bin/python3", "/usr/bin/python3.11"]),
    );
    assert_parity(&Scenario {
        name: "symlink-expanded binaries",
        host: "pypi.org",
        yaml: r"
network_policies:
  python_policy:
    name: python_policy
    endpoints:
      - { host: pypi.org, port: 443 }
    binaries:
      - { path: /usr/bin/python3 }
      - { path: /usr/bin/python3.11 }
",
        cedar: &cedar,
        cases: vec![
            same_probe(
                "opa.rs::symlink_expanded_binary_allows_resolved_path",
                Probe::Connect(network("pypi.org", 443, "/usr/bin/python3.11")),
            ),
            same_probe(
                "opa.rs::symlink_expanded_binary_still_allows_original_path",
                Probe::Connect(network("pypi.org", 443, "/usr/bin/python3")),
            ),
            same_probe(
                "opa.rs::symlink_expanded_binary_does_not_weaken_security",
                Probe::Connect(network("pypi.org", 443, "/usr/bin/curl")),
            ),
            same_probe(
                "opa.rs::symlink_expansion_works_with_ancestors",
                Probe::Connect(network_with_ancestors(
                    "pypi.org",
                    443,
                    "/usr/bin/curl",
                    &["/usr/bin/python3.11"],
                )),
            ),
        ],
    });
}
