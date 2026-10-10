// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Ported YAML tests for `allowed_ips` (Cedar parity plan, phase 6).
//!
//! A YAML endpoint's `allowed_ips` becomes a `NetworkConnect` permit
//! condition, `context has destination_ip &&
//! context.destination_ip.isInRange(ip("..."))`, and a host-less endpoint a
//! permit with a port condition and no host. Many original tests assert the
//! `allowed_ips` list a YAML engine returns or call the proxy's address
//! checks with hand-built allowlists. Cedar has no such list, so those are
//! ported as [`Probe::Destination`] cases: the decision for a connection
//! whose host resolved to given addresses, through each engine's own
//! destination mode, and [`Probe::DnsAnswers`] cases for policy DNS answer
//! filtering. Tests that build an allowlist covering loopback, link-local,
//! or unspecified addresses keep their address and use a valid allowlist:
//! Cedar rejects such ranges when the policy loads
//! (`openshell-policy-cedar/tests/destination_ip.rs`), and the address stays
//! blocked in both formats.

use std::net::IpAddr;

use super::*;

fn ips(addresses: &[&str]) -> Vec<IpAddr> {
    addresses
        .iter()
        .map(|address| address.parse().expect("test address parses"))
        .collect()
}

/// A connection from `binary` to `host:port` whose host resolved to
/// `addresses`.
fn destination(host: &str, port: u16, binary: &str, addresses: &[&str]) -> Probe {
    Probe::Destination {
        input: network(host, port, binary),
        addresses: ips(addresses),
    }
}

fn dns_answers(name: &str, port: u16, answers: &[&str]) -> Probe {
    Probe::DnsAnswers {
        name: name.to_string(),
        port,
        answers: ips(answers),
    }
}

fn dns(name: &str, port: u16) -> Probe {
    Probe::DnsEligible {
        name: name.to_string(),
        port,
    }
}

// ---------------------------------------------------------------------------
// opa.rs ALLOWED_IPS_TEST_DATA
// ---------------------------------------------------------------------------

const ALLOWED_IPS_YAML: &str = r#"
network_policies:
  internal_api:
    name: internal_api
    endpoints:
      - host: my-service.corp.net
        port: 8080
        allowed_ips: ["10.0.5.0/24"]
    binaries:
      - { path: /usr/bin/curl }
  private_network:
    name: private_network
    endpoints:
      - port: 9443
        allowed_ips: ["172.16.0.0/12", "192.168.1.1"]
    binaries:
      - { path: /usr/bin/curl }
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
"#;

const ALLOWED_IPS_CEDAR: &str = r#"
@id("internal_api")
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"my-service.corp.net:8080")
when {
    context.binary_path == "/usr/bin/curl"
    && context has destination_ip
    && context.destination_ip.isInRange(ip("10.0.5.0/24"))
};
@id("private_network")
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {
    resource.port == 9443
    && context.binary_path == "/usr/bin/curl"
    && context has destination_ip
    && (context.destination_ip.isInRange(ip("172.16.0.0/12"))
        || context.destination_ip.isInRange(ip("192.168.1.1")))
};
@id("public_api")
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.github.com:443")
when { context.binary_path == "/usr/bin/curl" };
@id("wildcard_api")
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {
    resource.host like("*.corp.net", ".")
    && resource.port == 443
    && context.binary_path == "/usr/bin/curl"
};
"#;

/// `allowed_ips_mode*`, `exact_declared_endpoint_host_*_allowed_ips`, and
/// `egress_authorization_returns_one_generation_consistent_snapshot`.
///
/// The YAML tests read the matched endpoint's `allowed_ips` list; here the
/// destination cases check what that list admits. The snapshot test's
/// policy name, endpoint index, and generation have no Cedar counterpart
/// beyond the matched record and the decision, which are compared.
#[test]
fn ported_allowed_ips_modes() {
    const MODE1: &str = "opa.rs::allowed_ips_mode1_no_ips_returns_empty";
    const MODE2: &str = "opa.rs::allowed_ips_mode2_host_plus_ips_allows";
    const MODE2_IPS: &str = "opa.rs::allowed_ips_mode2_returns_allowed_ips";
    const MODE3: &str = "opa.rs::allowed_ips_mode3_hostless_allows_any_domain";
    const MODE3_IPS: &str = "opa.rs::allowed_ips_mode3_returns_allowed_ips";
    const MODE3_PORT: &str = "opa.rs::allowed_ips_mode3_wrong_port_denied";
    const EXACT_IPS: &str = "opa.rs::exact_declared_endpoint_host_true_for_host_with_allowed_ips";
    const HOSTLESS: &str = "opa.rs::exact_declared_endpoint_host_false_for_hostless_allowed_ips";
    const SNAPSHOT: &str =
        "opa.rs::egress_authorization_returns_one_generation_consistent_snapshot";
    let service = || network("my-service.corp.net", 8080, BINARY);
    let anything = || network("anything.example.com", 9443, BINARY);
    assert_parity(&Scenario {
        name: "allowed_ips modes",
        host: "my-service.corp.net",
        yaml: ALLOWED_IPS_YAML,
        cedar: ALLOWED_IPS_CEDAR,
        cases: vec![
            // Mode 1: a host without allowed_ips is exactly declared, so it
            // may resolve to public and private addresses.
            same_probe(
                format!("{MODE1} public"),
                destination("api.github.com", 443, BINARY, &["140.82.112.5"]),
            )
            .asserting_yaml("admitted"),
            same_probe(
                format!("{MODE1} private"),
                destination("api.github.com", 443, BINARY, &["10.1.2.3"]),
            )
            .asserting_yaml("admitted"),
            same_probe(
                format!("{MODE1} loopback"),
                destination("api.github.com", 443, BINARY, &["127.0.0.1"]),
            )
            .asserting_yaml("rejected"),
            // Mode 2: host plus allowed_ips.
            same_probe(format!("{MODE2} allow"), Probe::Connect(service())).asserting_yaml("allow"),
            same_probe(
                format!("{MODE2} other binary"),
                Probe::Connect(network("my-service.corp.net", 8080, "/usr/bin/wget")),
            )
            .asserting_yaml("deny"),
            same_probe(
                format!("{MODE2_IPS} inside"),
                destination("my-service.corp.net", 8080, BINARY, &["10.0.5.9"]),
            )
            .asserting_yaml("admitted"),
            same_probe(
                format!("{MODE2_IPS} private outside"),
                destination("my-service.corp.net", 8080, BINARY, &["10.0.6.1"]),
            )
            .asserting_yaml("rejected"),
            same_probe(
                format!("{MODE2_IPS} public outside"),
                destination("my-service.corp.net", 8080, BINARY, &["8.8.8.8"]),
            )
            .asserting_yaml("rejected"),
            same_probe(
                format!("{MODE2_IPS} one address outside"),
                destination(
                    "my-service.corp.net",
                    8080,
                    BINARY,
                    &["10.0.5.9", "10.0.6.1"],
                ),
            )
            .asserting_yaml("rejected"),
            same_probe(
                format!("{MODE2_IPS} dns answers"),
                dns_answers("my-service.corp.net", 8080, &["10.0.6.1", "10.0.5.7"]),
            )
            .asserting_yaml("10.0.5.7"),
            // Mode 3: host-less allowed_ips match any host on the port.
            same_probe(format!("{MODE3} allow"), Probe::Connect(anything()))
                .asserting_yaml("allow"),
            same_probe(
                format!("{MODE3} range"),
                destination("anything.example.com", 9443, BINARY, &["172.20.1.1"]),
            )
            .asserting_yaml("admitted"),
            same_probe(
                format!("{MODE3_IPS} single address"),
                destination("anything.example.com", 9443, BINARY, &["192.168.1.1"]),
            )
            .asserting_yaml("admitted"),
            same_probe(
                format!("{MODE3_IPS} next address"),
                destination("anything.example.com", 9443, BINARY, &["192.168.1.2"]),
            )
            .asserting_yaml("rejected"),
            same_probe(
                format!("{MODE3_IPS} public"),
                destination("anything.example.com", 9443, BINARY, &["8.8.8.8"]),
            )
            .asserting_yaml("rejected"),
            same_probe(
                format!("{MODE3_PORT} wrong port"),
                Probe::Connect(network("anything.example.com", 12345, BINARY)),
            )
            .asserting_yaml("deny"),
            same_probe(
                format!("{MODE3} not policy DNS eligible"),
                dns("anything.example.com", 9443),
            )
            .asserting_yaml("ineligible"),
            same_probe(
                format!("{MODE3} dns refused"),
                dns_answers("anything.example.com", 9443, &["172.20.1.1"]),
            )
            // An ineligible name gets only an observation mapping, which
            // pins no address for any port.
            .asserting_yaml("no mapping for port"),
            // Exactly declared hosts.
            same_probe(EXACT_IPS, Probe::ExactHost(service())).asserting_yaml("exact"),
            same_probe(HOSTLESS, Probe::ExactHost(anything())).asserting_yaml("not-exact"),
            // The wildcard host is neither exact nor allowed private addresses.
            same_probe(
                "ALLOWED_IPS_TEST_DATA wildcard private",
                destination("api.corp.net", 443, BINARY, &["10.0.5.9"]),
            )
            .asserting_yaml("rejected"),
            same_probe(
                "ALLOWED_IPS_TEST_DATA wildcard public",
                destination("api.corp.net", 443, BINARY, &["8.8.8.8"]),
            )
            .asserting_yaml("admitted"),
            // The atomic snapshot: allow, exact host, the matched record.
            same_probe(format!("{SNAPSHOT} allow"), Probe::Connect(service()))
                .asserting_yaml("allow"),
            same_probe(format!("{SNAPSHOT} exact"), Probe::ExactHost(service()))
                .asserting_yaml("exact"),
            same_probe(
                format!("{SNAPSHOT} matched"),
                Probe::MatchedEndpoints(service()),
            )
            .asserting_yaml("my-service.corp.net:8080"),
        ],
    });
}

// ---------------------------------------------------------------------------
// opa.rs::hostless_endpoint_multi_port
// ---------------------------------------------------------------------------

#[test]
fn ported_hostless_endpoint_multi_port() {
    const NAME: &str = "opa.rs::hostless_endpoint_multi_port";
    assert_parity(&Scenario {
        name: "Host-less multi-port allowed_ips",
        host: "anything.internal",
        yaml: r#"
network_policies:
  private:
    name: private
    endpoints:
      - ports: [80, 443]
        allowed_ips: ["10.0.0.0/8"]
    binaries:
      - { path: /usr/bin/curl }
"#,
        cedar: r#"
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {
    [80, 443].contains(resource.port)
    && context.binary_path == "/usr/bin/curl"
    && context has destination_ip
    && context.destination_ip.isInRange(ip("10.0.0.0/8"))
};
"#,
        cases: vec![
            same_probe(
                format!("{NAME} port 80"),
                Probe::Connect(network("anything.internal", 80, BINARY)),
            )
            .asserting_yaml("allow"),
            same_probe(
                format!("{NAME} port 443"),
                Probe::Connect(network("anything.internal", 443, BINARY)),
            )
            .asserting_yaml("allow"),
            same_probe(
                format!("{NAME} unlisted port"),
                Probe::Connect(network("anything.internal", 8080, BINARY)),
            )
            .asserting_yaml("deny"),
            same_probe(
                format!("{NAME} in range"),
                destination("anything.internal", 443, BINARY, &["10.9.8.7"]),
            )
            .asserting_yaml("admitted"),
            same_probe(
                format!("{NAME} out of range"),
                destination("anything.internal", 443, BINARY, &["8.8.8.8"]),
            )
            .asserting_yaml("rejected"),
            same_probe(
                format!("{NAME} not exact"),
                Probe::ExactHost(network("anything.internal", 80, BINARY)),
            )
            .asserting_yaml("not-exact"),
        ],
    });
}

// ---------------------------------------------------------------------------
// opa.rs::allowed_ips_proto_round_trip
// ---------------------------------------------------------------------------

/// The YAML test builds the policy as a proto, a YAML loader path; here
/// both lists' ranges are checked by what they admit.
#[test]
fn ported_allowed_ips_proto_round_trip() {
    const NAME: &str = "opa.rs::allowed_ips_proto_round_trip";
    let policy = openshell_core::proto::SandboxPolicy {
        network_policies: HashMap::from([(
            "internal".to_string(),
            openshell_core::proto::NetworkPolicyRule {
                name: "internal".to_string(),
                endpoints: vec![openshell_core::proto::NetworkEndpoint {
                    host: "internal.corp.net".to_string(),
                    port: 8080,
                    allowed_ips: vec!["10.0.5.0/24".to_string(), "10.0.6.0/24".to_string()],
                    ..Default::default()
                }],
                binaries: vec![openshell_core::proto::NetworkBinary {
                    path: BINARY.to_string(),
                }],
            },
        )]),
        ..Default::default()
    };
    let opa = OpaEngine::from_proto(&policy).expect("YAML proto loads");
    let cedar = CedarOnlyEngine::from_policy_str(
        r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"internal.corp.net:8080")
when {
    context.binary_path == "/usr/bin/curl"
    && context has destination_ip
    && (context.destination_ip.isInRange(ip("10.0.5.0/24"))
        || context.destination_ip.isInRange(ip("10.0.6.0/24")))
};
"#,
    )
    .expect("Cedar policy loads");
    let engines = Engines::new(opa, cedar);
    let cases = [
        same_probe(
            format!("{NAME} first range"),
            destination("internal.corp.net", 8080, BINARY, &["10.0.5.3"]),
        )
        .asserting_yaml("admitted"),
        same_probe(
            format!("{NAME} second range"),
            destination("internal.corp.net", 8080, BINARY, &["10.0.6.3"]),
        )
        .asserting_yaml("admitted"),
        same_probe(
            format!("{NAME} outside"),
            destination("internal.corp.net", 8080, BINARY, &["10.0.7.3"]),
        )
        .asserting_yaml("rejected"),
    ];
    report_parity(run(
        "allowed_ips proto round trip",
        "internal.corp.net",
        &engines,
        &cases,
    ));
}

// ---------------------------------------------------------------------------
// opa.rs::credential_guard_does_not_shadow_inspected_endpoint_config
// ---------------------------------------------------------------------------

/// `access: full` without `enforcement` is an audit-only `HttpRequest`
/// permit, as YAML defaults it to audit. The inspected endpoint's
/// `tls: skip` is an endpoint setting on the Cedar
/// side. The L4 endpoint's `provider_credentialed` and
/// `allow_uninspected_credentials` come only from provider endpoints on a
/// Cedar sandbox, so the credential-guard count is not ported; provider
/// credential guards are covered by the phase 1 ports. The YAML test's
/// point, that the L4 endpoint does not shadow the inspected endpoint's
/// inspection, TLS mode, and `allowed_ips`, is checked by decision.
#[test]
fn ported_credential_guard_does_not_shadow_allowed_ips() {
    const NAME: &str = "opa.rs::credential_guard_does_not_shadow_inspected_endpoint_config";
    let input = || network("api.example.com", 443, BINARY);
    assert_settings_parity(&SettingsScenario {
        name: "Credential guard does not shadow allowed_ips",
        host: "api.example.com",
        yaml: r#"
network_policies:
  telemetry_l4:
    name: telemetry_l4
    endpoints:
      - host: api.example.com
        port: 443
        provider_credentialed: true
        allow_uninspected_credentials: true
    binaries:
      - { path: /usr/bin/curl }
  inspected_api:
    name: inspected_api
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        access: full
        tls: skip
        allowed_ips: ["10.0.5.0/24"]
    binaries:
      - { path: /usr/bin/curl }
"#,
        cedar: r#"
@id("telemetry_l4")
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.binary_path == "/usr/bin/curl" };
@id("inspected_api")
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when {
    context.binary_path == "/usr/bin/curl"
    && context has destination_ip
    && context.destination_ip.isInRange(ip("10.0.5.0/24"))
};
@protocol("rest")
@enforcement("audit")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.binary_path == "/usr/bin/curl" };
"#,
        settings: r"
endpoint_settings:
  - host: api.example.com
    port: 443
    tls: skip
",
        cases: vec![
            same_probe(format!("{NAME} inspection"), Probe::Inspection(input()))
                .asserting_yaml("Rest/Audit"),
            same_probe(format!("{NAME} tls"), Probe::TlsMode(input())).asserting_yaml("Skip"),
            same_probe(
                format!("{NAME} allowed_ips inside"),
                destination("api.example.com", 443, BINARY, &["10.0.5.3"]),
            )
            .asserting_yaml("admitted"),
            same_probe(
                format!("{NAME} allowed_ips private outside"),
                destination("api.example.com", 443, BINARY, &["10.0.6.3"]),
            )
            .asserting_yaml("rejected"),
            same_probe(
                format!("{NAME} allowed_ips public outside"),
                destination("api.example.com", 443, BINARY, &["8.8.8.8"]),
            )
            .asserting_yaml("rejected"),
        ],
    });
}

// ---------------------------------------------------------------------------
// opa.rs::overlapping_policy_outputs_are_snapshotted_independently
// ---------------------------------------------------------------------------

/// `OVERLAPPING_L7_TEST_DATA` from `opa.rs`: two policies on one IP literal
/// endpoint, the second with `tls: skip` and `allowed_ips`. The YAML test
/// asserts the per-config lists and the matched policy name; here the TLS
/// mode, the two matched records, the exact host, and the admitted address
/// are compared. The second endpoint's `tls: skip` is an endpoint setting.
#[test]
fn ported_overlapping_policy_outputs() {
    const NAME: &str = "opa.rs::overlapping_policy_outputs_are_snapshotted_independently";
    let input = || network("192.168.1.100", 8567, BINARY);
    assert_settings_parity(&SettingsScenario {
        name: "Overlapping policy outputs",
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
when { context.binary_path == "/usr/bin/curl" };
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"192.168.1.100:8567")
when {
    context.binary_path == "/usr/bin/curl"
    && context has destination_ip
    && context.destination_ip.isInRange(ip("192.168.1.100"))
};
@protocol("rest")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"192.168.1.100:8567")
when { context.binary_path == "/usr/bin/curl" && context.method == "GET" };
"#,
        settings: r"
endpoint_settings:
  - host: 192.168.1.100
    port: 8567
    tls: skip
",
        cases: vec![
            same_probe(format!("{NAME} allow"), Probe::Connect(input())).asserting_yaml("allow"),
            same_probe(format!("{NAME} matched"), Probe::MatchedEndpoints(input()))
                .asserting_yaml("192.168.1.100:8567;192.168.1.100:8567"),
            same_probe(format!("{NAME} tls"), Probe::TlsMode(input())).asserting_yaml("Skip"),
            same_probe(format!("{NAME} exact"), Probe::ExactHost(input())).asserting_yaml("exact"),
            same_probe(
                format!("{NAME} allowed_ips"),
                destination("192.168.1.100", 8567, BINARY, &["192.168.1.100"]),
            )
            .asserting_yaml("admitted"),
        ],
    });
}

// ---------------------------------------------------------------------------
// proxy.rs::supplied_identity_preserves_authorized_endpoint_metadata
// ---------------------------------------------------------------------------

/// The supplied-identity path authorizes through the same engine call for
/// both formats. `request_body_credential_rewrite` comes only from provider
/// endpoints on a Cedar sandbox and is not ported; the endpoint's
/// `allowed_ips` and inspection are.
#[test]
fn ported_supplied_identity_endpoint_metadata() {
    const NAME: &str = "proxy.rs::supplied_identity_preserves_authorized_endpoint_metadata";
    const PYTHON: &str = "/usr/bin/python3";
    assert_parity(&Scenario {
        name: "Supplied identity endpoint metadata",
        host: "api.example.com",
        yaml: r#"
network_policies:
  inspected:
    name: inspected
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        enforcement: enforce
        allowed_ips: ["192.0.2.0/24"]
        rules:
          - allow: { method: GET, path: /allowed }
    binaries:
      - path: /usr/bin/python3
"#,
        cedar: r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when {
    context.binary_path == "/usr/bin/python3"
    && context has destination_ip
    && context.destination_ip.isInRange(ip("192.0.2.0/24"))
};
@protocol("rest")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when {
    context.binary_path == "/usr/bin/python3"
    && ["GET", "HEAD"].contains(context.method)
    && context.path == "/allowed"
};
"#,
        cases: vec![
            same_probe(
                format!("{NAME} inspection"),
                Probe::Inspection(network("api.example.com", 443, PYTHON)),
            )
            .asserting_yaml("Rest/Enforce"),
            same_probe(
                format!("{NAME} allowed_ips inside"),
                destination("api.example.com", 443, PYTHON, &["192.0.2.10"]),
            )
            .asserting_yaml("admitted"),
            same_probe(
                format!("{NAME} allowed_ips outside"),
                destination("api.example.com", 443, PYTHON, &["198.51.100.10"]),
            )
            .asserting_yaml("rejected"),
        ],
    });
}

// ---------------------------------------------------------------------------
// proxy.rs address checks with allowlists
// ---------------------------------------------------------------------------

/// The proxy's `allowed_ips` address-check tests, through a policy whose
/// endpoints carry the allowlists the tests build.
///
/// - `curl` has a host-less allowlist on every port the tests use.
/// - `wget` has a host-less allowlist that excludes `10.0.0.1`.
/// - `python3` has a host glob with an allowlist and `node` the same glob
///   without one, for the hosts-file test: `/etc/hosts` is only where the
///   private address came from, so the probe supplies it directly. The
///   original's `searxng.local` becomes `searxng.home.test` so the host glob
///   is a valid YAML wildcard host.
#[test]
fn ported_proxy_allowlist_address_checks() {
    const PYTHON: &str = "/usr/bin/python3";
    const NODE: &str = "/usr/bin/node";
    const WGET: &str = "/usr/bin/wget";
    const LOOPBACK: &str = "proxy.rs::test_resolve_check_allowed_ips_blocks_loopback";
    const METADATA: &str = "proxy.rs::test_resolve_check_allowed_ips_blocks_metadata";
    const UNSPECIFIED: &str = "proxy.rs::test_resolve_check_allowed_ips_blocks_unspecified";
    const OUTSIDE: &str = "proxy.rs::test_resolve_check_allowed_ips_rejects_outside_allowlist";
    const CONTROL: &str = "proxy.rs::test_resolve_check_allowed_ips_blocks_control_plane_ports";
    const ALLOWED: &str = "proxy.rs::test_resolve_check_allowed_ips_allows_non_control_plane_ports";
    const FORWARD_ACCEPTED: &str = "proxy.rs::test_forward_private_ip_accepted_with_allowed_ips";
    const FORWARD_WRONG: &str = "proxy.rs::test_forward_private_ip_rejected_with_wrong_allowed_ips";
    const FORWARD_LOOPBACK: &str =
        "proxy.rs::test_forward_loopback_always_blocked_even_with_allowed_ips";
    const FORWARD_LINK_LOCAL: &str =
        "proxy.rs::test_forward_link_local_always_blocked_even_with_allowed_ips";
    const HOSTS_FILE: &str =
        "proxy.rs::test_resolve_from_hosts_file_contents_private_ip_requires_allowed_ips";
    assert_parity(&Scenario {
        name: "Proxy allowlist address checks",
        host: "dns.google",
        yaml: r#"
network_policies:
  allowlisted:
    name: allowlisted
    endpoints:
      - ports: [80, 443, 2379, 6443, 10250]
        allowed_ips: ["10.0.0.0/8", "8.8.8.0/24"]
    binaries:
      - { path: /usr/bin/curl }
  wrong_range:
    name: wrong_range
    endpoints:
      - ports: [80]
        allowed_ips: ["192.168.0.0/16"]
    binaries:
      - { path: /usr/bin/wget }
  hosts_file_allowlisted:
    name: hosts_file_allowlisted
    endpoints:
      - host: "*.home.test"
        port: 8080
        allowed_ips: ["192.168.1.105/32"]
    binaries:
      - { path: /usr/bin/python3 }
  hosts_file_default:
    name: hosts_file_default
    endpoints:
      - { host: "*.home.test", port: 8080 }
    binaries:
      - { path: /usr/bin/node }
"#,
        cedar: r#"
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {
    [80, 443, 2379, 6443, 10250].contains(resource.port)
    && context.binary_path == "/usr/bin/curl"
    && context has destination_ip
    && (context.destination_ip.isInRange(ip("10.0.0.0/8"))
        || context.destination_ip.isInRange(ip("8.8.8.0/24")))
};
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {
    resource.port == 80
    && context.binary_path == "/usr/bin/wget"
    && context has destination_ip
    && context.destination_ip.isInRange(ip("192.168.0.0/16"))
};
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {
    resource.host like("*.home.test", ".")
    && resource.port == 8080
    && context.binary_path == "/usr/bin/python3"
    && context has destination_ip
    && context.destination_ip.isInRange(ip("192.168.1.105/32"))
};
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {
    resource.host like("*.home.test", ".")
    && resource.port == 8080
    && context.binary_path == "/usr/bin/node"
};
"#,
        cases: vec![
            same_probe(
                LOOPBACK,
                destination("127.0.0.1", 80, BINARY, &["127.0.0.1"]),
            )
            .asserting_yaml("rejected"),
            same_probe(
                METADATA,
                destination("169.254.169.254", 80, BINARY, &["169.254.169.254"]),
            )
            .asserting_yaml("rejected"),
            same_probe(
                UNSPECIFIED,
                destination("0.0.0.0", 80, BINARY, &["0.0.0.0"]),
            )
            .asserting_yaml("rejected"),
            same_probe(
                FORWARD_LOOPBACK,
                destination("loopback.example", 80, BINARY, &["127.0.0.1"]),
            )
            .asserting_yaml("rejected"),
            same_probe(
                FORWARD_LINK_LOCAL,
                destination("metadata.example", 80, BINARY, &["169.254.169.254"]),
            )
            .asserting_yaml("rejected"),
            same_probe(
                format!("{OUTSIDE} public"),
                destination("dns.google", 443, BINARY, &["1.1.1.1"]),
            )
            .asserting_yaml("rejected"),
            same_probe(
                format!("{OUTSIDE} one of two"),
                destination("dns.google", 443, BINARY, &["8.8.8.8", "1.1.1.1"]),
            )
            .asserting_yaml("rejected"),
            same_probe(
                format!("{CONTROL} 6443"),
                destination("8.8.8.8", 6443, BINARY, &["8.8.8.8"]),
            )
            .asserting_yaml("rejected"),
            same_probe(
                format!("{CONTROL} 2379"),
                destination("8.8.8.8", 2379, BINARY, &["8.8.8.8"]),
            )
            .asserting_yaml("rejected"),
            same_probe(
                format!("{CONTROL} 10250"),
                destination("8.8.8.8", 10250, BINARY, &["8.8.8.8"]),
            )
            .asserting_yaml("rejected"),
            same_probe(ALLOWED, destination("8.8.8.8", 443, BINARY, &["8.8.8.8"]))
                .asserting_yaml("admitted"),
            same_probe(
                format!("{ALLOWED} by name"),
                destination("dns.google", 443, BINARY, &["8.8.8.8", "8.8.8.4"]),
            )
            .asserting_yaml("admitted"),
            same_probe(
                FORWARD_ACCEPTED,
                destination("10.0.0.1", 80, BINARY, &["10.0.0.1"]),
            )
            .asserting_yaml("admitted"),
            same_probe(
                FORWARD_WRONG,
                destination("10.0.0.1", 80, WGET, &["10.0.0.1"]),
            )
            .asserting_yaml("rejected"),
            same_probe(
                format!("{FORWARD_WRONG} control"),
                destination("192.168.3.4", 80, WGET, &["192.168.3.4"]),
            )
            .asserting_yaml("admitted"),
            same_probe(
                format!("{HOSTS_FILE} default"),
                destination("searxng.home.test", 8080, NODE, &["192.168.1.105"]),
            )
            .asserting_yaml("rejected"),
            same_probe(
                format!("{HOSTS_FILE} default public control"),
                destination("searxng.home.test", 8080, NODE, &["8.8.8.8"]),
            )
            .asserting_yaml("admitted"),
            same_probe(
                format!("{HOSTS_FILE} allowlisted"),
                destination("searxng.home.test", 8080, PYTHON, &["192.168.1.105"]),
            )
            .asserting_yaml("admitted"),
        ],
    });
}

// ---------------------------------------------------------------------------
// policy_dns/mod.rs and proxy/destination.rs answer filtering
// ---------------------------------------------------------------------------

/// `BASE_POLICY` from `policy_dns/mod.rs` with `allowed_ips`, and the
/// address filter test from `proxy/destination.rs` through policy DNS. Each
/// engine's policy DNS filters the trusted resolver's answers and pins the
/// rest.
#[test]
fn ported_policy_dns_allowed_ips_filtering() {
    const DNS: &str =
        "policy_dns/mod.rs::allowed_ips_filters_each_answer_without_rejecting_usable_addresses";
    const FILTER: &str = "proxy/destination.rs::address_filter_enforces_allowed_ips";
    const PSQL: &str = "/usr/bin/psql";
    let open = |binary: &str, answers: &[&str]| Probe::TransparentOpen {
        name: "db.example".to_string(),
        port: 5432,
        binary: binary.to_string(),
        answers: ips(answers),
    };
    assert_parity(&Scenario {
        name: "Policy DNS allowed_ips filtering",
        host: "db.example",
        yaml: r"
network_policies:
  database:
    name: database
    endpoints:
      - { host: db.example, port: 5432, protocol: tcp, allowed_ips: [10.2.0.0/16] }
    binaries: [{ path: /usr/bin/psql }]
  allowlisted:
    name: allowlisted
    endpoints:
      - { host: allowlisted.example, port: 443, allowed_ips: [10.2.0.0/16] }
    binaries: [{ path: /usr/bin/curl }]
filesystem_policy: { include_workdir: true, read_only: [], read_write: [] }
landlock: { compatibility: best_effort }
process: { run_as_user: sandbox, run_as_group: sandbox }
",
        cedar: r#"
@transport("tcp")
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"db.example:5432")
when {
    context.binary_path == "/usr/bin/psql"
    && context has destination_ip
    && context.destination_ip.isInRange(ip("10.2.0.0/16"))
};
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"allowlisted.example:443")
when {
    context.binary_path == "/usr/bin/curl"
    && context has destination_ip
    && context.destination_ip.isInRange(ip("10.2.0.0/16"))
};
"#,
        cases: vec![
            same_probe(
                DNS,
                dns_answers("db.example", 5432, &["10.3.4.5", "10.2.3.4"]),
            )
            .asserting_yaml("10.2.3.4"),
            same_probe(
                format!("{DNS} no usable answer"),
                dns_answers("db.example", 5432, &["10.3.4.5"]),
            )
            .asserting_yaml(
                "dns refused: no trusted resolver address passed endpoint destination policy",
            ),
            same_probe(
                format!("{DNS} transparent open"),
                open(PSQL, &["10.3.4.5", "10.2.3.4"]),
            )
            .asserting_yaml("RelayReady/10.2.3.4:5432/correlated"),
            same_probe(
                format!("{DNS} other binary"),
                open(BINARY, &["10.3.4.5", "10.2.3.4"]),
            )
            .asserting_yaml("Denied(PolicyDenied)"),
            same_probe(
                FILTER,
                dns_answers("allowlisted.example", 443, &["10.3.4.5", "10.2.3.4"]),
            )
            .asserting_yaml("10.2.3.4"),
        ],
    });
}

// ---------------------------------------------------------------------------
// proxy/destination.rs::validation_mode_precedence_is_explicit_and_stable
// ---------------------------------------------------------------------------

/// The mode precedence below the host gateway aliases, by what each mode
/// admits: `allowed_ips` over an exactly declared host, an IP literal host,
/// an exactly declared host, and the public-only default for a glob. The
/// host gateway modes take precedence the same way for both formats and are
/// not reached without a gateway; a Cedar sandbox also requires Cedar to
/// allow the gateway address (`proxy/destination.rs` unit tests).
#[test]
fn ported_validation_mode_precedence() {
    const NAME: &str = "proxy/destination.rs::validation_mode_precedence_is_explicit_and_stable";
    assert_parity(&Scenario {
        name: "Destination mode precedence",
        host: "private.example",
        yaml: r#"
network_policies:
  modes:
    name: modes
    endpoints:
      - { host: explicit.example, port: 443, allowed_ips: ["10.0.0.0/8"] }
      - { host: private.example, port: 443 }
      - { host: 10.2.3.4, port: 443 }
      - { host: "*.glob.example", port: 443 }
    binaries:
      - { path: /usr/bin/curl }
"#,
        cedar: r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"explicit.example:443")
when {
    context.binary_path == "/usr/bin/curl"
    && context has destination_ip
    && context.destination_ip.isInRange(ip("10.0.0.0/8"))
};
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"private.example:443")
when { context.binary_path == "/usr/bin/curl" };
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"10.2.3.4:443")
when { context.binary_path == "/usr/bin/curl" };
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {
    resource.host like("*.glob.example", ".")
    && resource.port == 443
    && context.binary_path == "/usr/bin/curl"
};
"#,
        cases: vec![
            same_probe(
                format!("{NAME} explicit private"),
                destination("explicit.example", 443, BINARY, &["10.1.1.1"]),
            )
            .asserting_yaml("admitted"),
            same_probe(
                format!("{NAME} explicit over exact"),
                destination("explicit.example", 443, BINARY, &["8.8.8.8"]),
            )
            .asserting_yaml("rejected"),
            same_probe(
                format!("{NAME} implicit literal"),
                destination("10.2.3.4", 443, BINARY, &["10.2.3.4"]),
            )
            .asserting_yaml("admitted"),
            same_probe(
                format!("{NAME} declared private"),
                destination("private.example", 443, BINARY, &["10.1.1.1"]),
            )
            .asserting_yaml("admitted"),
            same_probe(
                format!("{NAME} declared public"),
                destination("private.example", 443, BINARY, &["8.8.8.8"]),
            )
            .asserting_yaml("admitted"),
            same_probe(
                format!("{NAME} default private"),
                destination("a.glob.example", 443, BINARY, &["10.1.1.1"]),
            )
            .asserting_yaml("rejected"),
            same_probe(
                format!("{NAME} default public"),
                destination("a.glob.example", 443, BINARY, &["8.8.8.8"]),
            )
            .asserting_yaml("admitted"),
        ],
    });
}

// ---------------------------------------------------------------------------
// Overlapping endpoints (not a ported test)
// ---------------------------------------------------------------------------

/// Why Cedar rejects a private address YAML admits for overlapping endpoints.
const FIRST_CONFIG: &str = "YAML checks addresses against the first matching endpoint that has \
     extended config, so a host-less allowed_ips endpoint decides for a glob host whose own \
     endpoint has none; Cedar does not depend on that order and admits a private address only \
     when every allowing permit restricts the address or one names the host exactly";

/// A glob endpoint and a host-less `allowed_ips` endpoint on the same port.
///
/// YAML picks the address mode from the first matching endpoint with
/// extended config, an order Cedar cannot reproduce, so Cedar applies the
/// strictest mode of every allowing permit. Both reject a public address
/// outside the allowlist; for a private address inside it Cedar is stricter.
#[test]
fn overlapping_endpoints_never_widen_address_admission() {
    assert_parity(&Scenario {
        name: "Overlapping glob and host-less allowed_ips",
        host: "svc.corp.example",
        yaml: r#"
network_policies:
  glob:
    name: glob
    endpoints:
      - { host: "*.corp.example", port: 443 }
    binaries:
      - { path: /usr/bin/curl }
  hostless:
    name: hostless
    endpoints:
      - ports: [443]
        allowed_ips: ["10.0.0.0/8"]
    binaries:
      - { path: /usr/bin/curl }
"#,
        cedar: r#"
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {
    resource.host like("*.corp.example", ".")
    && resource.port == 443
    && context.binary_path == "/usr/bin/curl"
};
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {
    resource.port == 443
    && context.binary_path == "/usr/bin/curl"
    && context has destination_ip
    && context.destination_ip.isInRange(ip("10.0.0.0/8"))
};
"#,
        cases: vec![
            same_probe(
                "overlap public outside allowlist",
                destination("svc.corp.example", 443, BINARY, &["8.8.8.8"]),
            )
            .asserting_yaml("rejected"),
            diverges_probe(
                "overlap private inside allowlist",
                destination("svc.corp.example", 443, BINARY, &["10.1.1.1"]),
                FIRST_CONFIG,
            )
            .asserting_yaml("admitted"),
            same_probe(
                "overlap host-less only",
                destination("other.example", 443, BINARY, &["10.1.1.1"]),
            )
            .asserting_yaml("admitted"),
        ],
    });
}

// ---------------------------------------------------------------------------
// Provider allowed_ips (not a ported test)
// ---------------------------------------------------------------------------

/// Why Cedar rejects a private address a YAML provider endpoint admits.
const PROVIDERS_GRANT_NO_ACCESS: &str = "a YAML sandbox enforces provider rules as network \
     policies, so a provider endpoint's allowed_ips admit private addresses; on a Cedar sandbox \
     providers grant no access, so their allowed_ips only narrow what the Cedar policy admits, \
     and a glob permit stays public-only";

/// One provider rule for curl to `api.corp.example:443` within `10.5.0.0/16`.
fn ranged_provider_rule() -> openshell_core::proto::NetworkPolicyRule {
    openshell_core::proto::NetworkPolicyRule {
        name: "_provider_corp".to_string(),
        endpoints: vec![openshell_core::proto::NetworkEndpoint {
            host: "api.corp.example".to_string(),
            port: 443,
            allowed_ips: vec!["10.5.0.0/16".to_string()],
            provider_credentialed: true,
            ..Default::default()
        }],
        binaries: vec![openshell_core::proto::NetworkBinary {
            path: BINARY.to_string(),
        }],
    }
}

/// A credentialed provider endpoint's `allowed_ips` restrict the addresses
/// its connections reach on both formats, when Cedar names the host exactly.
#[test]
fn provider_allowed_ips_restrict_credentialed_connections() {
    assert_provider_parity(&ProviderScenario {
        name: "Provider allowed_ips with an exact Cedar permit",
        host: "api.corp.example",
        rules: vec![ranged_provider_rule()],
        cedar: r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.corp.example:443")
when { context.binary_path == "/usr/bin/curl" };
"#,
        cases: vec![
            same_probe(
                "provider range inside",
                destination("api.corp.example", 443, BINARY, &["10.5.0.1"]),
            )
            .asserting_yaml("admitted"),
            same_probe(
                "provider range outside private",
                destination("api.corp.example", 443, BINARY, &["10.6.0.1"]),
            )
            .asserting_yaml("rejected"),
            same_probe(
                "provider range outside public",
                destination("api.corp.example", 443, BINARY, &["8.8.8.8"]),
            )
            .asserting_yaml("rejected"),
            same_probe(
                "provider range mixed answers",
                destination("api.corp.example", 443, BINARY, &["10.5.0.1", "10.6.0.1"]),
            )
            .asserting_yaml("rejected"),
        ],
    });
}

/// Provider `allowed_ips` never admit a private address a Cedar glob permit
/// rejects; outside the range both formats reject.
#[test]
fn provider_allowed_ips_never_widen_cedar_admission() {
    assert_provider_parity(&ProviderScenario {
        name: "Provider allowed_ips with a glob Cedar permit",
        host: "api.corp.example",
        rules: vec![ranged_provider_rule()],
        cedar: r#"
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {
    resource.host like("*.corp.example", ".")
    && resource.port == 443
    && context.binary_path == "/usr/bin/curl"
};
"#,
        cases: vec![
            diverges_probe(
                "provider range inside, glob permit",
                destination("api.corp.example", 443, BINARY, &["10.5.0.1"]),
                PROVIDERS_GRANT_NO_ACCESS,
            )
            .asserting_yaml("admitted"),
            same_probe(
                "provider range outside, glob permit",
                destination("api.corp.example", 443, BINARY, &["8.8.8.8"]),
            )
            .asserting_yaml("rejected"),
        ],
    });
}
