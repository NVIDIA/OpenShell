// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! Policy DNS IPv6 egress selection in each driver's supervisor network
//! namespace.
//!
//! The supervisor reports its decision in an OCSF configuration event. Every
//! driver lane checks that `auto` read the routing tables and enabled IPv6
//! answers exactly when the namespace is IPv6-only. Lanes with a known
//! network layout pin it with `OPENSHELL_E2E_EXPECT_ROUTE_STATE`
//! (`ipv6_only`, `dual_stack`, `ipv4_only`), and lanes that configure the
//! driver's `policy_dns_ipv6_egress` set `OPENSHELL_E2E_POLICY_DNS_IPV6_EGRESS`.

use std::process::Stdio;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::sandbox::SandboxGuard;

const DECISION_PREFIX: &str = "Policy DNS IPv6 egress ";
const NAT64_MESSAGE: &str = "NAT64 prefixes for SSRF classification";

#[derive(Debug, PartialEq, Eq)]
struct Decision {
    enabled: bool,
    requested: String,
    route_state: String,
}

/// Parse `Policy DNS IPv6 egress <enabled|disabled> (requested <mode>, route
/// state <state>)` from the sandbox log.
fn parse_decision(logs: &str) -> Option<Decision> {
    let line = logs.lines().find(|line| line.contains(DECISION_PREFIX))?;
    let rest = &line[line.find(DECISION_PREFIX)? + DECISION_PREFIX.len()..];
    let (state, rest) = rest.split_once(" (requested ")?;
    let (requested, rest) = rest.split_once(", route state ")?;
    let route_state = rest.split(')').next()?;
    Some(Decision {
        enabled: match state {
            "enabled" => true,
            "disabled" => false,
            _ => return None,
        },
        requested: requested.to_string(),
        route_state: route_state.to_string(),
    })
}

async fn sandbox_logs(name: &str) -> Result<String, String> {
    let output = openshell_cmd()
        .args([
            "logs", name, "-n", "500", "--since", "5m", "--source", "sandbox",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| format!("failed to spawn openshell logs: {e}"))?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if output.status.success() {
        Ok(combined)
    } else {
        Err(format!("openshell logs failed:\n{combined}"))
    }
}

#[tokio::test]
async fn supervisor_reports_policy_dns_ipv6_egress_decision() {
    let mut guard = SandboxGuard::create(&["--", "sh", "-c", "echo ipv6-egress-ready"])
        .await
        .expect("create sandbox");

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    let logs = loop {
        let logs = sandbox_logs(&guard.name).await.expect("fetch sandbox logs");
        if parse_decision(&logs).is_some() && logs.contains(NAT64_MESSAGE) {
            break logs;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for the IPv6 egress and NAT64 events:\n{logs}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    };
    let decision = parse_decision(&logs).expect("decision event");

    let requested = std::env::var("OPENSHELL_E2E_POLICY_DNS_IPV6_EGRESS")
        .unwrap_or_else(|_| "auto".to_string());
    assert_eq!(decision.requested, requested, "{logs}");
    assert_ne!(
        decision.route_state, "route_table_unavailable",
        "supervisor could not read its routing tables:\n{logs}"
    );
    match decision.requested.as_str() {
        "auto" => assert_eq!(
            decision.enabled,
            decision.route_state == "ipv6_only",
            "auto must enable IPv6 egress only on IPv6-only namespaces: {decision:?}"
        ),
        "enabled" => assert!(decision.enabled, "{decision:?}"),
        "disabled" => assert!(!decision.enabled, "{decision:?}"),
        other => panic!("unexpected requested mode {other}"),
    }
    if let Ok(expected) = std::env::var("OPENSHELL_E2E_EXPECT_ROUTE_STATE") {
        assert_eq!(decision.route_state, expected, "{logs}");
    }

    guard.cleanup().await;
}

#[test]
fn parses_the_decision_message() {
    let line = "OCSF CONFIG:ENABLED [INFO] Policy DNS IPv6 egress disabled (requested auto, route state dual_stack)";
    assert_eq!(
        parse_decision(line),
        Some(Decision {
            enabled: false,
            requested: "auto".to_string(),
            route_state: "dual_stack".to_string(),
        })
    );
    assert_eq!(parse_decision("unrelated"), None);
}
