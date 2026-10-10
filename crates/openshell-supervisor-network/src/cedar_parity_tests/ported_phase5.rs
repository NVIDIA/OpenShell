// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Ported YAML tests for native TCP endpoints (Cedar parity plan, phase 5).
//!
//! A YAML endpoint with `protocol: tcp` becomes a `NetworkConnect` permit
//! annotated `@transport("tcp")`. Both are plain L4 connections without an
//! endpoint config, and both publish a policy DNS record marked
//! `protocol: tcp`. YAML names a record by its policy and endpoint index and
//! Cedar by its position among the `cedar` records, so the probes compare
//! records by host, ports, and transport, and check that each engine's
//! connection decisions name records of its own DNS snapshot.

use super::ported_opa_a::{L7_TEST_CEDAR, L7_TEST_DATA};
use super::*;

/// A transparent open of `name:port` from `binary`.
fn transparent_open(name: &str, port: u16, binary: &str) -> Probe {
    Probe::TransparentOpen {
        name: name.to_string(),
        port,
        binary: binary.to_string(),
        answers: vec![TRANSPARENT_UPSTREAM.into()],
    }
}

fn dns(name: &str, port: u16) -> Probe {
    Probe::DnsEligible {
        name: name.to_string(),
        port,
    }
}

// ---------------------------------------------------------------------------
// opa.rs::egress_authorization_preserves_explicit_tcp_endpoint_identity
// ---------------------------------------------------------------------------

#[test]
fn ported_explicit_tcp_endpoint_identity() {
    const CLIENT: &str = "/usr/bin/client";
    const NAME: &str = "opa.rs::egress_authorization_preserves_explicit_tcp_endpoint_identity";
    let input = || network("database.example.com", 5432, CLIENT);
    assert_parity(&Scenario {
        name: "Explicit TCP endpoint identity",
        host: "database.example.com",
        yaml: r"
network_policies:
  native_tcp:
    name: native_tcp
    endpoints:
      - host: database.example.com
        port: 5432
        protocol: tcp
    binaries:
      - path: /usr/bin/client
filesystem_policy:
  include_workdir: true
  read_only: []
  read_write: []
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox
",
        cedar: r#"
@transport("tcp")
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"database.example.com:5432")
when { context.binary_path == "/usr/bin/client" };
"#,
        cases: vec![
            same_probe(format!("{NAME} configs"), Probe::Inspection(input()))
                .asserting_yaml("none"),
            same_probe(format!("{NAME} matched"), Probe::MatchedEndpoints(input()))
                .asserting_yaml("database.example.com:5432/tcp"),
            same_probe(
                format!("{NAME} other binary"),
                Probe::MatchedEndpoints(network("database.example.com", 5432, BINARY)),
            )
            .asserting_yaml("deny"),
        ],
    });
}

// ---------------------------------------------------------------------------
// opa.rs::explicit_tcp_authorizes_as_l4_without_endpoint_config
// ---------------------------------------------------------------------------

/// `L7_TEST_CEDAR` marks `explicit-tcp.example.com:443` with
/// `@transport("tcp")`.
#[test]
fn ported_explicit_tcp_authorizes_as_l4() {
    const NAME: &str = "opa.rs::explicit_tcp_authorizes_as_l4_without_endpoint_config";
    let input = || network("explicit-tcp.example.com", 443, BINARY);
    assert_parity(&Scenario {
        name: "opa.rs L7_TEST_DATA explicit TCP",
        host: "explicit-tcp.example.com",
        yaml: L7_TEST_DATA,
        cedar: L7_TEST_CEDAR,
        cases: vec![
            same_probe(format!("{NAME} allow"), Probe::Connect(input())).asserting_yaml("allow"),
            same_probe(format!("{NAME} config"), Probe::Inspection(input())).asserting_yaml("none"),
            same_probe(format!("{NAME} exact"), Probe::ExactHost(input())).asserting_yaml("exact"),
            same_probe(format!("{NAME} matched"), Probe::MatchedEndpoints(input()))
                .asserting_yaml("explicit-tcp.example.com:443/tcp"),
            // The plain L4 endpoint beside it is not native TCP.
            same_probe(
                format!("{NAME} plain L4 control"),
                Probe::MatchedEndpoints(network("l4only.example.com", 443, BINARY)),
            )
            .asserting_yaml("l4only.example.com:443"),
        ],
    });
}

// ---------------------------------------------------------------------------
// opa.rs::policy_dns_snapshot_includes_every_tcp_carried_endpoint
// ---------------------------------------------------------------------------

/// `POLICY_DNS_SNAPSHOT_DATA` from `opa.rs`.
///
/// The hostless `protocol: tcp` endpoint with `allowed_ips` has no Cedar
/// form: Cedar rejects a hostless `@transport("tcp")` permit at load, as
/// gateway validation rejects that YAML endpoint
/// (`lib.rs::validate_rejects_hostless_allowed_ips_for_explicit_tcp`). The
/// test asserts it is left out of the snapshot, which the record list and
/// the `8.8.8.8` case check on the YAML side. `access: full` on a REST
/// endpoint becomes an `HttpRequest` permit without request conditions.
/// The test's endpoint indices are YAML policy positions and are not
/// compared; each matched record must be in its engine's snapshot.
#[test]
fn ported_policy_dns_snapshot_tcp_endpoints() {
    const NAME: &str = "opa.rs::policy_dns_snapshot_includes_every_tcp_carried_endpoint";
    const PROCESS: &str = "/usr/bin/one-process";
    assert_parity_across_reload(&Scenario {
        name: "Policy DNS snapshot TCP endpoints",
        host: "web.example",
        yaml: r"
network_policies:
  dns_transport:
    name: dns_transport
    endpoints:
      - { host: resolver.example, ports: [53, 853], protocol: tcp }
      - { host: web.example, port: 443, protocol: rest, access: full }
      - { host: implicit.example, port: 443 }
      - { host: '', port: 53, protocol: tcp, allowed_ips: [8.8.8.8] }
      - { host: secondary.example, port: 5353, protocol: tcp }
    binaries:
      - { path: /usr/bin/one-process }
filesystem_policy:
  include_workdir: true
  read_only: []
  read_write: []
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox
",
        cedar: r#"
@transport("tcp")
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"resolver.example:53")
when { context.binary_path == "/usr/bin/one-process" };
@transport("tcp")
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"resolver.example:853")
when { context.binary_path == "/usr/bin/one-process" };
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"web.example:443")
when { context.binary_path == "/usr/bin/one-process" };
@protocol("rest")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"web.example:443")
when { context.binary_path == "/usr/bin/one-process" };
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"implicit.example:443")
when { context.binary_path == "/usr/bin/one-process" };
@transport("tcp")
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"secondary.example:5353")
when { context.binary_path == "/usr/bin/one-process" };
"#,
        cases: vec![
            same_probe(format!("{NAME} records"), Probe::DnsRecords).asserting_yaml(
                "implicit.example:443;resolver.example:53,853/tcp;\
                 secondary.example:5353/tcp;web.example:443",
            ),
            same_probe(format!("{NAME} resolver 53"), dns("resolver.example", 53))
                .asserting_yaml("eligible"),
            same_probe(format!("{NAME} resolver 853"), dns("resolver.example", 853))
                .asserting_yaml("eligible"),
            same_probe(format!("{NAME} web"), dns("web.example", 443)).asserting_yaml("eligible"),
            same_probe(format!("{NAME} implicit"), dns("implicit.example", 443))
                .asserting_yaml("eligible"),
            same_probe(format!("{NAME} secondary"), dns("secondary.example", 5353))
                .asserting_yaml("eligible"),
            same_probe(
                format!("{NAME} undeclared port"),
                dns("resolver.example", 443),
            )
            .asserting_yaml("ineligible"),
            same_probe(format!("{NAME} hostless excluded"), dns("8.8.8.8", 53))
                .asserting_yaml("ineligible"),
            same_probe(
                format!("{NAME} resolver matched"),
                Probe::MatchedEndpoints(network("resolver.example", 853, PROCESS)),
            )
            .asserting_yaml("resolver.example:53,853/tcp"),
            same_probe(
                format!("{NAME} web matched"),
                Probe::MatchedEndpoints(network("web.example", 443, PROCESS)),
            )
            .asserting_yaml("web.example:443"),
        ],
    });
}

// ---------------------------------------------------------------------------
// opa.rs::yaml_and_proto_sql_and_l4_policies_have_config_and_decision_parity
// ---------------------------------------------------------------------------

/// SQL commands are not inspected in either format: the proxy does not
/// enforce YAML SQL rules, and Cedar rejects `@protocol("sql")`. Only the
/// TCP and L4 parts of the test are ported: each endpoint allows the
/// connection and denies an unlisted host, and the `tcp` and plain forms
/// carry no endpoint config. The SQL variant's audit config and command
/// decisions are not ported. The YAML-against-proto comparison is a YAML
/// loader check with no Cedar counterpart.
/// Why the test's `protocol: ""` endpoint differs from its Cedar form.
const EMPTY_PROTOCOL: &str = "the test loads YAML text with an explicit `protocol: \"\"`, which \
     the Rego DNS eligibility rule reads as an unsupported protocol, so YAML leaves the endpoint \
     out of policy DNS; a gateway-delivered policy omits an empty protocol and is eligible, as \
     the Cedar endpoint is";

#[test]
fn ported_sql_and_l4_connection_parity() {
    const NAME: &str = "opa.rs::yaml_and_proto_sql_and_l4_policies_have_config_and_decision_parity";
    for (protocol, fields, annotation) in [
        (
            "sql",
            "enforcement: audit\n        rules: [{allow: {command: SELECT}}]",
            "",
        ),
        ("tcp", "", "@transport(\"tcp\")"),
        ("", "", ""),
    ] {
        let yaml = format!(
            r#"
version: 1
network_policies:
  parity:
    name: parity
    endpoints:
      - host: sql-l4.parity.test
        port: 443
        protocol: "{protocol}"
        {fields}
    binaries:
      - {{path: /usr/bin/curl}}
"#
        );
        let cedar = format!(
            r#"
{annotation}
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"sql-l4.parity.test:443")
when {{ context.binary_path == "/usr/bin/curl" }};
"#
        );
        let input = || network("sql-l4.parity.test", 443, BINARY);
        let mut cases = vec![
            same_probe(
                format!("{NAME} {protocol:?} allow"),
                Probe::Connect(input()),
            )
            .asserting_yaml("allow"),
            same_probe(
                format!("{NAME} {protocol:?} unlisted"),
                Probe::Connect(network("unlisted.parity.test", 443, BINARY)),
            )
            .asserting_yaml("deny"),
        ];
        if protocol != "sql" {
            cases.push(
                same_probe(
                    format!("{NAME} {protocol:?} config"),
                    Probe::Inspection(input()),
                )
                .asserting_yaml("none"),
            );
            let matched = format!("{NAME} {protocol:?} matched");
            cases.push(if protocol == "tcp" {
                same_probe(matched, Probe::MatchedEndpoints(input()))
                    .asserting_yaml("sql-l4.parity.test:443/tcp")
            } else {
                diverges_probe(matched, Probe::MatchedEndpoints(input()), EMPTY_PROTOCOL)
                    .asserting_yaml("sql-l4.parity.test:443 (not in DNS snapshot)")
            });
            cases.push(if protocol == "tcp" {
                same_probe(
                    format!("{NAME} {protocol:?} dns"),
                    dns("sql-l4.parity.test", 443),
                )
                .asserting_yaml("eligible")
            } else {
                diverges_probe(
                    format!("{NAME} {protocol:?} dns"),
                    dns("sql-l4.parity.test", 443),
                    EMPTY_PROTOCOL,
                )
                .asserting_yaml("ineligible")
            });
        }
        assert_parity(&Scenario {
            name: &format!("SQL and L4 parity, protocol {protocol:?}"),
            host: "sql-l4.parity.test",
            yaml: &yaml,
            cedar: &cedar,
            cases,
        });
    }
}

// ---------------------------------------------------------------------------
// proxy.rs::staged_transparent_open_dials_only_pinned_policy_dns_addresses
// ---------------------------------------------------------------------------

/// `POLICY_DNS_OPEN_POLICY` from `proxy.rs`, with `db.example` marked
/// `@transport("tcp")`.
///
/// The original publishes the mapping directly; here each engine's own
/// policy DNS publishes it from its snapshot, so the probe also checks that
/// the published mapping pins the resolved address. `correlated` checks
/// that the decision names an endpoint of the mapping, which the transparent
/// TCP listener requires and which Cedar decisions used to lack.
#[test]
fn ported_staged_transparent_open_dials_pinned_addresses() {
    const NAME: &str = "proxy.rs::staged_transparent_open_dials_only_pinned_policy_dns_addresses";
    assert_parity(&Scenario {
        name: "Staged transparent open native TCP",
        host: "db.example",
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
            same_probe(NAME, transparent_open("db.example", 5432, BINARY))
                .asserting_yaml("RelayReady/203.0.113.8:5432/correlated"),
            same_probe(
                format!("{NAME} plain L4 control"),
                transparent_open("pypi.org", 80, BINARY),
            )
            .asserting_yaml("RelayReady/203.0.113.8:80/correlated"),
            same_probe(
                format!("{NAME} other binary"),
                transparent_open("db.example", 5432, "/usr/bin/wget"),
            )
            .asserting_yaml("Denied(PolicyDenied)"),
            same_probe(
                format!("{NAME} undeclared port"),
                transparent_open("db.example", 443, BINARY),
            ),
            same_probe(
                format!("{NAME} undeclared name"),
                transparent_open("unknown.example", 5432, BINARY),
            ),
        ],
    });
}
