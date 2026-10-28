// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Ported proxy, destination, and policy DNS decision tests.
//!
//! Many of the original tests assert outcomes that come from fixed checks
//! applied after the policy decision: always-blocked loopback and link-local
//! addresses, blocked control-plane ports, binary digest pinning, trusted
//! gateway configuration, and the policy DNS store's observation records.
//! Those checks do not depend on the policy engine. These ports cover only the
//! policy-dependent part: whether the connection is allowed, whether its host
//! counts as exactly declared (which admits private addresses), and whether
//! policy DNS considers the name eligible.

use super::*;

/// A YAML and Cedar policy allowing `binary` to reach one exactly named
/// `host:port`, as the original tests' single-endpoint fixtures do.
fn single_exact_endpoint(host: &str, port: u16, binary: &str) -> (String, String) {
    let yaml = format!(
        r#"
network_policies:
  allowed:
    name: allowed
    endpoints:
      - {{ host: "{host}", port: {port} }}
    binaries:
      - {{ path: {binary} }}
"#
    );
    let cedar = format!(
        r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"{host}:{port}")
when {{ context.binary_path == "{binary}" }};
"#
    );
    (yaml, cedar)
}

/// Runs a scenario over [`single_exact_endpoint`].
fn assert_single_exact_endpoint(name: &str, host: &str, port: u16, cases: Vec<Case>) {
    let (yaml, cedar) = single_exact_endpoint(host, port, BINARY);
    assert_parity(&Scenario {
        name,
        host,
        yaml: &yaml,
        cedar: &cedar,
        cases,
    });
}

/// The redactor rewrites the allowed JSON-RPC method to `[REDACTED]`; the
/// re-evaluation of the rewritten request must deny it.
#[test]
fn ported_jsonrpc_reevaluation_after_redaction() {
    const NODE: &str = "/usr/bin/node";
    let ctx = || l7_ctx("api.example.test", 80, NODE);
    let call_to = |method: &str| jsonrpc_request("/rpc", vec![call(method, None, None)]);
    assert_parity(&Scenario {
        name: "Forward middleware re-evaluation",
        host: "api.example.test",
        yaml: r"
network_policies:
  jsonrpc_api:
    name: jsonrpc_api
    endpoints:
      - host: api.example.test
        port: 80
        path: /rpc
        protocol: json-rpc
        enforcement: enforce
        rules:
          - allow:
              method: sk-ABCDEFGHIJKLMNOP
    binaries:
      - { path: /usr/bin/node }
",
        cedar: r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.test:80")
when { context.binary_path == "/usr/bin/node" };
@protocol("json-rpc")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.test:80")
when {
    context.binary_path == "/usr/bin/node"
    && context.path == "/rpc"
    && !context.jsonrpc_response
    && context.jsonrpc_method == "sk-ABCDEFGHIJKLMNOP"
};
"#,
        cases: vec![
            same_probe(
                "proxy.rs::forward_middleware_pipeline_denies_policy_invalid_transformation inspection",
                Probe::Inspection(network("api.example.test", 80, NODE)),
            ),
            same_probe(
                "proxy.rs::forward_middleware_pipeline_denies_policy_invalid_transformation original",
                request_in(ctx(), call_to("sk-ABCDEFGHIJKLMNOP")),
            ),
            same_probe(
                "proxy.rs::forward_middleware_pipeline_denies_policy_invalid_transformation redacted",
                request_in(ctx(), call_to("[REDACTED]")),
            ),
        ],
    });
}

/// `POLICY_DNS_OPEN_POLICY` from `proxy.rs`. The rejection of an
/// observation-only record as an invalid destination is a store check and is
/// not covered; the policy part is that pypi.org:80 is allowed and eligible
/// while unknown.example is denied and ineligible.
#[test]
fn ported_staged_transparent_open_policy_dns() {
    assert_parity(&Scenario {
        name: "Staged transparent open",
        host: "pypi.org",
        yaml: r"
network_policies:
  database:
    name: database
    endpoints:
      - { host: db.example, port: 5432, protocol: tcp }
    binaries: [{ path: /usr/bin/curl }]
  pypi:
    name: pypi
    endpoints:
      - { host: pypi.org, port: 80 }
    binaries: [{ path: /usr/bin/curl }]
filesystem_policy: { include_workdir: true, read_only: [], read_write: [] }
landlock: { compatibility: best_effort }
process: { run_as_user: sandbox, run_as_group: sandbox }
",
        cedar: r#"
@transport("tcp")
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"db.example:5432")
when { context.binary_path == "/usr/bin/curl" };
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"pypi.org:80")
when { context.binary_path == "/usr/bin/curl" };
"#,
        cases: vec![
            same_probe(
                "proxy.rs::staged_transparent_open_never_relays_an_observation_that_policy_allows connect",
                Probe::Connect(network("pypi.org", 80, BINARY)),
            ),
            same_probe(
                "proxy.rs::staged_transparent_open_never_relays_an_observation_that_policy_allows dns",
                Probe::DnsEligible {
                    name: "pypi.org".to_string(),
                    port: 80,
                },
            ),
            same_probe(
                "proxy.rs::staged_transparent_open_proposes_a_denied_observation_hostname connect",
                Probe::Connect(network("unknown.example", 443, BINARY)),
            ),
            same_probe(
                "proxy.rs::staged_transparent_open_proposes_a_denied_observation_hostname dns",
                Probe::DnsEligible {
                    name: "unknown.example".to_string(),
                    port: 443,
                },
            ),
        ],
    });
}

/// The metadata address is declared, so policy allows it; the proxy blocks it
/// afterwards as an invalid destination regardless of policy, which this
/// probe does not cover.
#[test]
fn ported_staged_transparent_open_waits_for_l4_policy() {
    assert_parity(&Scenario {
        name: "Transparent open L4 policy",
        host: "203.0.113.7",
        yaml: r"
network_policies:
  allowed:
    name: allowed
    endpoints:
      - host: 203.0.113.7
        port: 443
      - host: 169.254.169.254
        port: 80
    binaries:
      - path: /usr/bin/curl
",
        cedar: r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"203.0.113.7:443")
when { context.binary_path == "/usr/bin/curl" };
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"169.254.169.254:80")
when { context.binary_path == "/usr/bin/curl" };
"#,
        cases: vec![
            same_probe(
                "proxy.rs::staged_transparent_open_waits_for_l4_policy allowed",
                Probe::Connect(network("203.0.113.7", 443, BINARY)),
            ),
            same_probe(
                "proxy.rs::staged_transparent_open_waits_for_l4_policy metadata declared",
                Probe::Connect(network("169.254.169.254", 80, BINARY)),
            ),
            same_probe(
                "proxy.rs::staged_transparent_open_waits_for_l4_policy unlisted",
                Probe::Connect(network("203.0.113.8", 443, BINARY)),
            ),
        ],
    });
}

/// Digest pinning denies the replacement executable in both original tests;
/// pinning is engine-independent, so only the initial allow is compared.
#[test]
fn ported_supplied_identity_client() {
    const CLIENT: &str = "/sandbox/bin/client";
    assert_parity(&Scenario {
        name: "Supplied identity with L7 rules",
        host: "api.example.com",
        yaml: r"
network_policies:
  credentialed:
    name: credentialed
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow: { method: GET, path: /allowed }
    binaries:
      - path: /sandbox/bin/client
",
        cedar: r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.binary_path == "/sandbox/bin/client" };
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when {
    context.binary_path == "/sandbox/bin/client"
    && ["GET", "HEAD"].contains(context.method)
    && context.path == "/allowed"
};
"#,
        cases: vec![same_probe(
            "proxy.rs::supplied_identity_rejects_same_path_replacement",
            Probe::Connect(network("api.example.com", 443, CLIENT)),
        )],
    });

    let (yaml, cedar) = single_exact_endpoint("api.example.com", 443, CLIENT);
    assert_parity(&Scenario {
        name: "Supplied identity",
        host: "api.example.com",
        yaml: &yaml,
        cedar: &cedar,
        cases: vec![same_probe(
            "proxy.rs::supplied_identity_pin_survives_policy_reload",
            Probe::Connect(network("api.example.com", 443, CLIENT)),
        )],
    });
}

/// The policy authorizes through the launcher ancestor; the ancestor digest
/// pin that later denies is engine-independent.
#[test]
fn ported_supplied_identity_ancestor() {
    assert_parity(&Scenario {
        name: "Supplied identity ancestor",
        host: "api.example.com",
        yaml: r"
network_policies:
  allowed:
    name: allowed
    endpoints:
      - host: api.example.com
        port: 443
    binaries:
      - path: /sandbox/bin/launcher
",
        cedar: r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when {
    context.binary_path == "/sandbox/bin/launcher"
    || context.ancestors.contains("/sandbox/bin/launcher")
};
"#,
        cases: vec![
            same_probe(
                "proxy.rs::supplied_identity_rejects_replaced_authorizing_ancestor",
                Probe::Connect(network_with_ancestors(
                    "api.example.com",
                    443,
                    "/sandbox/bin/client",
                    &["/sandbox/bin/launcher"],
                )),
            ),
            same_probe(
                "proxy.rs::supplied_identity_rejects_replaced_authorizing_ancestor no ancestor",
                Probe::Connect(network("api.example.com", 443, "/sandbox/bin/client")),
            ),
        ],
    });
}

/// The original checks that an exactly declared host may resolve to a
/// private hosts-file address; the policy part is the exact-host treatment.
#[test]
fn ported_declared_endpoint_private_hosts_file() {
    assert_single_exact_endpoint(
        "Declared endpoint hosts file",
        "searxng.local",
        8080,
        vec![same_probe(
            "proxy.rs::test_declared_endpoint_private_hosts_file_resolution_allowed",
            Probe::ExactHost(network("searxng.local", 8080, BINARY)),
        )],
    );
}

/// A declared loopback endpoint is exactly declared by policy; the SSRF 403
/// comes from the always-blocked address check, which this probe does not
/// cover.
#[test]
fn ported_declared_loopback_is_exact() {
    assert_single_exact_endpoint(
        "Declared loopback 443",
        "127.0.0.1",
        443,
        vec![same_probe(
            "proxy.rs::connect_handler_returns_ssrf_403_for_internal_address_not_503",
            Probe::ExactHost(network("127.0.0.1", 443, BINARY)),
        )],
    );
    assert_single_exact_endpoint(
        "Declared loopback 80",
        "127.0.0.1",
        80,
        vec![
            same_probe(
                "proxy.rs::forward_handler_preserves_ssrf_response_and_denial_stage",
                Probe::ExactHost(network("127.0.0.1", 80, BINARY)),
            ),
            same_probe(
                "proxy/destination.rs::declared_endpoint_preserves_its_denial_classification",
                Probe::ExactHost(network("127.0.0.1", 80, BINARY)),
            ),
        ],
    );
}

/// The destination address filter tests take an `ExactDeclaredHost` plan;
/// the policy decides that mode. Dropping loopback answers and blocking
/// control-plane ports are fixed checks this probe does not cover.
#[test]
fn ported_address_filter_exact_hosts() {
    assert_single_exact_endpoint(
        "Address filter private",
        "private.example",
        443,
        vec![same_probe(
            "proxy/destination.rs::address_filter_exact_host_allows_private_but_not_always_blocked",
            Probe::ExactHost(network("private.example", 443, BINARY)),
        )],
    );
    assert_single_exact_endpoint(
        "Address filter loopback",
        "loopback.example",
        443,
        vec![same_probe(
            "proxy/destination.rs::address_filter_rejects_always_blocked_only_answer",
            Probe::ExactHost(network("loopback.example", 443, BINARY)),
        )],
    );
    assert_single_exact_endpoint(
        "Address filter control plane",
        "api.example",
        6443,
        vec![same_probe(
            "proxy/destination.rs::address_filter_rejects_control_plane_port",
            Probe::ExactHost(network("api.example", 6443, BINARY)),
        )],
    );
}

/// The destination tests that take a `DefaultPublicOnly` plan: a host matched
/// only by a glob is not exactly declared, so it gets public-only filtering.
/// The original's `mixed.example` becomes `mixed.example.com` under
/// `*.example.com`, because both engines reject a wildcard top-level domain
/// such as `*.example`.
#[test]
fn ported_address_filter_default_public_only() {
    assert_parity(&Scenario {
        name: "Address filter glob",
        host: "mixed.example.com",
        yaml: r#"
network_policies:
  allowed:
    name: allowed
    endpoints:
      - { host: "*.example.com", port: 443 }
    binaries:
      - { path: /usr/bin/curl }
"#,
        cedar: r#"
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {
    resource.host like("*.example.com", ".")
    && resource.port == 443
    && context.binary_path == "/usr/bin/curl"
};
"#,
        cases: vec![same_probe(
            "proxy/destination.rs::address_filter_retains_public_answer_from_mixed_set",
            Probe::ExactHost(network("mixed.example.com", 443, BINARY)),
        )],
    });
    assert_parity(&Scenario {
        name: "Default mode glob",
        host: "loopback.example.com",
        yaml: r#"
network_policies:
  allowed:
    name: allowed
    endpoints:
      - { host: "*.example.com", port: 80 }
    binaries:
      - { path: /usr/bin/curl }
"#,
        cedar: r#"
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {
    resource.host like("*.example.com", ".")
    && resource.port == 80
    && context.binary_path == "/usr/bin/curl"
};
"#,
        cases: vec![
            same_probe(
                "proxy/destination.rs::default_mode_classifies_loopback_as_internal_address glob host",
                Probe::ExactHost(network("loopback.example.com", 80, BINARY)),
            ),
            same_probe(
                "proxy/destination.rs::default_mode_classifies_loopback_as_internal_address literal",
                Probe::ExactHost(network("127.0.0.1", 80, BINARY)),
            ),
        ],
    });
}

/// `BASE_POLICY` from `policy_dns/mod.rs`. The tests query names in mixed case
/// or with a trailing dot; the service normalizes them before checking
/// eligibility, so the probes use the normalized name. Answer filtering
/// (dropping loopback) and observation records are not covered.
#[test]
fn ported_policy_dns_base_policy() {
    const PSQL: &str = "/usr/bin/psql";
    assert_parity(&Scenario {
        name: "Policy DNS base",
        host: "db.example",
        yaml: r"
network_policies:
  database:
    name: database
    endpoints:
      - { host: db.example, port: 5432, protocol: tcp }
    binaries: [{ path: /usr/bin/psql }]
filesystem_policy: { include_workdir: true, read_only: [], read_write: [] }
landlock: { compatibility: best_effort }
process: { run_as_user: sandbox, run_as_group: sandbox }
",
        cedar: r#"
@transport("tcp")
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"db.example:5432")
when { context.binary_path == "/usr/bin/psql" };
"#,
        cases: vec![
            same_probe(
                "policy_dns/mod.rs::eligible_name_filters_answers_and_publishes_bounded_mapping dns",
                Probe::DnsEligible {
                    name: "db.example".to_string(),
                    port: 5432,
                },
            ),
            same_probe(
                "policy_dns/mod.rs::eligible_name_filters_answers_and_publishes_bounded_mapping exact",
                Probe::ExactHost(network("db.example", 5432, PSQL)),
            ),
            same_probe(
                "policy_dns/mod.rs::stages_unknown_name_without_upstream_resolution",
                Probe::DnsEligible {
                    name: "other.example".to_string(),
                    port: 80,
                },
            ),
            same_probe(
                "policy_dns/mod.rs::unknown_name_correlates_without_authorizing_a_port",
                Probe::DnsEligible {
                    name: "pypi.org".to_string(),
                    port: 80,
                },
            ),
        ],
    });
}

/// A wildcard host is DNS eligible but not exactly declared, so its private
/// answer is rejected by public-only filtering.
#[test]
fn ported_policy_dns_wildcard() {
    assert_parity(&Scenario {
        name: "Policy DNS wildcard",
        host: "db.example.com",
        yaml: r"
network_policies:
  database:
    name: database
    endpoints:
      - { host: '*.example.com', port: 5432, protocol: tcp }
    binaries: [{ path: /usr/bin/psql }]
filesystem_policy: { include_workdir: true, read_only: [], read_write: [] }
landlock: { compatibility: best_effort }
process: { run_as_user: sandbox, run_as_group: sandbox }
",
        cedar: r#"
@transport("tcp")
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {
    resource.host like("*.example.com", ".")
    && resource.port == 5432
    && context.binary_path == "/usr/bin/psql"
};
"#,
        cases: vec![
            same_probe(
                "policy_dns/mod.rs::wildcard_is_eligible_but_uses_public_only_destination_rules dns",
                Probe::DnsEligible {
                    name: "db.example.com".to_string(),
                    port: 5432,
                },
            ),
            same_probe(
                "policy_dns/mod.rs::wildcard_is_eligible_but_uses_public_only_destination_rules exact",
                Probe::ExactHost(network("db.example.com", 5432, "/usr/bin/psql")),
            ),
        ],
    });
}

/// `HOST_GATEWAY_POLICY` from `policy_dns/mod.rs`, with the alias substituted.
fn gateway_alias_policies(alias: &str) -> (String, String) {
    let yaml = format!(
        r"
network_policies:
  gateway:
    name: gateway
    endpoints:
      - {{ host: {alias}, port: 8080, protocol: tcp }}
    binaries: [{{ path: /usr/bin/client }}]
filesystem_policy: {{ include_workdir: true, read_only: [], read_write: [] }}
landlock: {{ compatibility: best_effort }}
process: {{ run_as_user: sandbox, run_as_group: sandbox }}
"
    );
    let cedar = format!(
        r#"
@transport("tcp")
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"{alias}:8080")
when {{ context.binary_path == "/usr/bin/client" }};
"#
    );
    (yaml, cedar)
}

/// The trusted gateway address, its family, and its absence are gateway
/// configuration checked after eligibility; the policy part is that the
/// declared alias is eligible and exactly declared.
#[test]
fn ported_policy_dns_gateway_alias() {
    const CLIENT: &str = "/usr/bin/client";
    let (yaml, cedar) = gateway_alias_policies("host.openshell.internal");
    let dns = || Probe::DnsEligible {
        name: "host.openshell.internal".to_string(),
        port: 8080,
    };
    let exact = || Probe::ExactHost(network("host.openshell.internal", 8080, CLIENT));
    assert_parity(&Scenario {
        name: "Policy DNS gateway alias",
        host: "host.openshell.internal",
        yaml: &yaml,
        cedar: &cedar,
        cases: vec![
            same_probe(
                "policy_dns/mod.rs::reserved_gateway_alias_pins_only_the_exact_trusted_address dns",
                dns(),
            ),
            same_probe(
                "policy_dns/mod.rs::reserved_gateway_alias_pins_only_the_exact_trusted_address exact",
                exact(),
            ),
            same_probe(
                "policy_dns/mod.rs::reserved_gateway_alias_accepts_an_exact_private_backend_gateway dns",
                dns(),
            ),
            same_probe(
                "policy_dns/mod.rs::reserved_gateway_alias_accepts_an_exact_private_backend_gateway exact",
                exact(),
            ),
            same_probe(
                "policy_dns/mod.rs::reserved_gateway_alias_rejects_wrong_address_family_without_resolver_fallback",
                dns(),
            ),
        ],
    });

    for alias in [
        "host.openshell.internal",
        "host.containers.internal",
        "host.docker.internal",
    ] {
        let (yaml, cedar) = gateway_alias_policies(alias);
        assert_parity(&Scenario {
            name: alias,
            host: alias,
            yaml: &yaml,
            cedar: &cedar,
            cases: vec![same_probe(
                "policy_dns/mod.rs::reserved_gateway_alias_without_trusted_address_never_queries_resolver",
                Probe::DnsEligible {
                    name: alias.to_string(),
                    port: 8080,
                },
            )],
        });
    }
}
