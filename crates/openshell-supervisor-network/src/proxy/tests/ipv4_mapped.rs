// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! IPv4-mapped destinations must retain their IPv4 policy and DNS identity.

use super::*;

fn engine_for(host: &str) -> OpaEngine {
    native_identity_engine(
        include_str!("../../../data/sandbox-policy.rego"),
        &policy_with_native_executable_paths(&POLICY_DNS_OPEN_POLICY.replace("db.example", host)),
    )
    .unwrap()
}

async fn probe(
    destination: SocketAddr,
    store: Option<&Arc<ResolvedEndpointStore>>,
    engine: &OpaEngine,
) -> (
    Option<TransparentOpen>,
    TcpOpenDecision,
    Option<DenialEvent>,
) {
    let (open, completion) = staged_curl_open(destination, engine.current_generation());
    let (denial_tx, mut denial_rx) = mpsc::unbounded_channel();
    let accepted = preauthorize_transparent_open(
        open,
        store,
        engine,
        &BinaryIdentityCache::new(),
        None,
        None,
        false,
        Some(&denial_tx),
        None,
    )
    .await;
    let decision = completion.await.unwrap();
    assert_eq!(accepted.is_some(), decision == TcpOpenDecision::RelayReady);
    (
        accepted.and_then(|(_, _, _, transparent)| transparent),
        decision,
        denial_rx.try_recv().ok(),
    )
}

#[tokio::test]
async fn allowed_ipv4_endpoint_accepts_mapped_form() {
    let engine = engine_for("203.0.113.7");
    let store = policy_dns_test_store();
    for dns in [None, Some(&store)] {
        for destination in ["203.0.113.7:5432", "[::ffff:203.0.113.7]:5432"] {
            let (transparent, decision, denial) =
                probe(destination.parse().unwrap(), dns, &engine).await;
            assert_eq!(decision, TcpOpenDecision::RelayReady, "{destination}");
            assert_eq!(
                transparent.unwrap().destination,
                "203.0.113.7:5432".parse().unwrap()
            );
            assert!(denial.is_none());
        }
    }
}

#[tokio::test]
async fn policy_dns_recovers_hostname_for_mapped_form() {
    let engine = engine_for("db.example");
    let store = policy_dns_test_store();
    let record = publish_mapping(
        &store,
        "db.example",
        "database",
        5432,
        engine.current_generation(),
    );
    let IpAddr::V4(ipv4) = record.synthetic_address else {
        panic!("test publishes an IPv4 mapping");
    };
    for ip in [IpAddr::V4(ipv4), IpAddr::V6(ipv4.to_ipv6_mapped())] {
        let destination = SocketAddr::new(ip, 5432);
        let (transparent, decision, denial) = probe(destination, Some(&store), &engine).await;
        assert_eq!(decision, TcpOpenDecision::RelayReady, "{destination}");
        assert!(denial.is_none());
        let transparent = transparent.unwrap();
        assert_eq!(
            transparent.destination,
            SocketAddr::new(IpAddr::V4(ipv4), 5432)
        );
        let (decision, connector) = transparent.authorization.unwrap();
        assert_eq!(decision.intent.destination.host, "db.example");
        assert_eq!(connector.addrs(), &["203.0.113.8:5432".parse().unwrap()]);
    }
}

#[tokio::test]
async fn denial_reports_canonical_ipv4_host() {
    let engine = engine_for("203.0.113.7");
    let store = policy_dns_test_store();
    let mut hosts = Vec::new();
    for destination in ["203.0.113.8:5432", "[::ffff:203.0.113.8]:5432"] {
        let (_, decision, denial) =
            probe(destination.parse().unwrap(), Some(&store), &engine).await;
        assert_eq!(
            decision,
            TcpOpenDecision::Denied(TcpOpenDenial::PolicyDenied)
        );
        let denial = denial.expect("unapproved endpoint produces a policy proposal");
        assert_eq!(denial.denial_stage, "transparent_tcp_connect");
        hosts.push(denial.host);
    }
    assert_eq!(hosts, ["203.0.113.8", "203.0.113.8"]);
}

#[tokio::test]
async fn metadata_stays_blocked_in_both_forms() {
    let store = policy_dns_test_store();
    for policy_host in ["169.254.169.254", "::ffff:169.254.169.254"] {
        let engine = engine_for(policy_host);
        for destination in ["169.254.169.254:5432", "[::ffff:169.254.169.254]:5432"] {
            let (_, decision, denial) =
                probe(destination.parse().unwrap(), Some(&store), &engine).await;
            assert!(matches!(decision, TcpOpenDecision::Denied(_)));
            assert!(
                denial.is_none(),
                "blocked metadata must not become a proposal"
            );
        }
    }
}

#[tokio::test]
async fn native_ipv6_preserves_scope_and_flowinfo() {
    let engine = engine_for("2001:db8::7");
    let destination = SocketAddr::V6(std::net::SocketAddrV6::new(
        "2001:db8::7".parse().unwrap(),
        5432,
        42,
        7,
    ));
    let (transparent, decision, denial) = probe(destination, None, &engine).await;
    assert_eq!(decision, TcpOpenDecision::RelayReady);
    assert_eq!(transparent.unwrap().destination, destination);
    assert!(denial.is_none());
}
