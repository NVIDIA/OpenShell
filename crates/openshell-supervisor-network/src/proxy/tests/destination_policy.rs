// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

fn authorize_destination(
    declared_host: &str,
    host: &str,
    port: u16,
    allowed_ips: &[&str],
) -> EgressDecision {
    let policy = serde_json::json!({
        "network_policies": {
            "egress": {
                "name": "egress",
                "endpoints": [{
                    "host": declared_host,
                    "port": port,
                    "tls": "skip",
                    "allowed_ips": allowed_ips,
                }],
                "binaries": [{ "path": "/usr/bin/curl" }],
            },
        },
    });
    let engine = native_identity_engine(
        include_str!("../../../data/sandbox-policy.rego"),
        &policy.to_string(),
    )
    .expect("load destination policy");
    let (open, _completion) = staged_curl_open(
        "10.23.45.67:443".parse().unwrap(),
        engine.current_generation(),
    );
    let decision = authorize_supplied_identity(
        &engine,
        &BinaryIdentityCache::new(),
        EgressIntent::connect(host.to_string(), port),
        &open.binary_identity,
    );
    assert!(matches!(decision.action, NetworkAction::Allow { .. }));
    assert_eq!(decision.endpoint.exact_declared_host, declared_host == host);
    assert_eq!(
        query_allowed_ips(&decision),
        allowed_ips
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    );
    decision
}

fn accepted_addresses(
    decision: &mut EgressDecision,
    ip: IpAddr,
) -> std::result::Result<Vec<IpAddr>, DestinationDenial> {
    hydrate_destination_plan(decision, None, None)?;
    filter_resolved_addresses(
        decision.endpoint.destination.as_ref().unwrap(),
        &decision.intent.destination.host,
        decision.intent.destination.port,
        &[ip],
    )
}

#[test]
fn glob_requires_grant_for_private_literal() {
    let glob = "**.*.*";
    let host = "10.23.45.67";
    let mut decision = authorize_destination(glob, host, 443, &[]);
    let result = accepted_addresses(&mut decision, host.parse().unwrap());
    assert!(
        result.is_err(),
        "glob {glob} without allowed_ips admitted private literal {host}: {result:?}"
    );
    assert_eq!(
        result.unwrap_err().kind,
        DestinationDenialKind::InternalAddress
    );
}

#[test]
fn planner_requires_grant_for_private_ipv6_literals() {
    for (host, ip) in [
        ("fd00::1234", "fd00::1234"),
        ("[fd00::1234]", "fd00::1234"),
        ("::ffff:10.23.45.67", "::ffff:10.23.45.67"),
    ] {
        let ip = ip.parse().unwrap();
        let result = build_validation_plan(host, host, None, None, &[], false)
            .and_then(|plan| filter_resolved_addresses(&plan, host, 443, &[ip]));
        assert!(
            result.is_err(),
            "planner admitted private literal {host} without an explicit grant: {result:?}"
        );
        assert_eq!(
            result.unwrap_err().kind,
            DestinationDenialKind::InternalAddress
        );
    }
}

#[test]
fn glob_hostname_still_rejects_private_resolution() {
    let mut decision = authorize_destination("**.*.*", "fixture.example.test", 443, &[]);
    let denial = accepted_addresses(&mut decision, "10.23.45.67".parse().unwrap())
        .expect_err("a glob hostname must not admit private resolved addresses");
    assert_eq!(denial.kind, DestinationDenialKind::InternalAddress);
}

#[test]
fn preserves_explicit_private_grants_and_public_targets() {
    let private_allowlist: &[&str] = &["10.23.45.0/24"];
    let no_allowlist: &[&str] = &[];
    for (declared_host, host, allowed_ips, ip) in [
        ("10.23.45.67", "10.23.45.67", no_allowlist, "10.23.45.67"),
        (
            "fixture.example.test",
            "fixture.example.test",
            no_allowlist,
            "10.23.45.67",
        ),
        ("**.*.*", "10.23.45.67", private_allowlist, "10.23.45.67"),
        (
            "**.*.*",
            "fixture.example.test",
            private_allowlist,
            "10.23.45.67",
        ),
        ("**.*.*", "8.8.8.8", no_allowlist, "8.8.8.8"),
        ("**.*.*", "fixture.example.test", no_allowlist, "8.8.8.8"),
    ] {
        let ip: IpAddr = ip.parse().unwrap();
        let mut decision = authorize_destination(declared_host, host, 443, allowed_ips);
        assert_eq!(
            accepted_addresses(&mut decision, ip).unwrap(),
            vec![ip],
            "{declared_host} must retain its grant for {host}"
        );
    }
}

#[test]
fn explicit_allowlist_constrains_exact_and_glob_hosts() {
    for declared_host in ["10.23.45.67", "**.*.*"] {
        let mut decision =
            authorize_destination(declared_host, "10.23.45.67", 443, &["8.8.8.8/32"]);
        let denial = accepted_addresses(&mut decision, "10.23.45.67".parse().unwrap())
            .expect_err("an explicit allowlist must constrain the requested IP literal");
        assert_eq!(denial.kind, DestinationDenialKind::AllowedIps);
    }
}

#[test]
fn public_literal_keeps_control_plane_port_block() {
    let mut decision = authorize_destination("**.*.*", "8.8.8.8", 6443, &[]);
    accepted_addresses(&mut decision, "8.8.8.8".parse().unwrap())
        .expect_err("a glob-authorized public IP literal must retain the port 6443 block");
}

#[test]
fn private_grants_keep_hard_address_and_port_blocks() {
    for ip in [
        "127.0.0.1",
        "169.254.169.254",
        "0.0.0.0",
        "::1",
        "fe80::1",
        "::",
    ] {
        let mut decision =
            authorize_destination("fixture.example.test", "fixture.example.test", 443, &[]);
        accepted_addresses(&mut decision, ip.parse().unwrap())
            .expect_err("exact hostname declarations must reject always-blocked addresses");
    }
    for (declared_host, allowed_ips) in
        [("10.23.45.67", &[][..]), ("**.*.*", &["10.23.45.0/24"][..])]
    {
        let mut decision = authorize_destination(declared_host, "10.23.45.67", 6443, allowed_ips);
        accepted_addresses(&mut decision, "10.23.45.67".parse().unwrap())
            .expect_err("private grants must retain the port 6443 block");
    }
}
