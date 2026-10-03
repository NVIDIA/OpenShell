// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Compile-time and behavioral coverage for the supported external API shape.

use std::time::Duration;

use openshell_prover::containment::{
    CheckDomain, CheckOptions, CheckResult, Counterexample, Protocol, ReasonCode,
    check_within_boundary, parse_policy_str,
};

fn authorize(result: &CheckResult) -> bool {
    matches!(result, CheckResult::Within(_))
}

fn result_state(result: &CheckResult) -> &'static str {
    // CheckResult is intentionally exhaustive: adding an outcome is a breaking
    // API change that requires callers to choose new fail-closed semantics.
    match result {
        CheckResult::Within(_) => "within",
        CheckResult::Exceeds(_) => "exceeds",
        CheckResult::Unsupported(_) => "unsupported",
        CheckResult::Inconclusive(_) => "inconclusive",
    }
}

fn protocol_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::L4 => "l4",
        Protocol::Rest => "rest",
        _ => "unknown",
    }
}

fn domain_name(domain: CheckDomain) -> &'static str {
    match domain {
        CheckDomain::Filesystem => "filesystem",
        CheckDomain::NetworkL4 => "network_l4",
        CheckDomain::NetworkRest => "network_rest",
        _ => "unknown",
    }
}

#[test]
fn external_callers_use_extensible_construction_and_matching_patterns() {
    let boundary = parse_policy_str(
        "version: 1\nfilesystem_policy: { read_only: [/data], include_workdir: false }\n",
    )
    .expect("boundary should parse");
    let candidate = parse_policy_str(
        "version: 1\nfilesystem_policy: { read_write: [/data], include_workdir: false }\n",
    )
    .expect("candidate should parse");

    let mut options = CheckOptions::new(Duration::from_secs(2));
    assert_eq!(options.timeout, Duration::from_secs(2));
    options.timeout = Duration::from_secs(3);
    let result = check_within_boundary(&boundary, &candidate, options);

    assert_eq!(result_state(&result), "exceeds");
    assert!(!authorize(&result));
    let CheckResult::Exceeds(evidence) = &result else {
        panic!("expected filesystem violation, got {result:?}");
    };
    assert_eq!(evidence.scope().model_version, "boundary-v1");
    assert!(
        evidence
            .scope()
            .domains
            .iter()
            .any(|domain| domain_name(*domain) == "filesystem")
    );
    match evidence.counterexample() {
        Counterexample::Filesystem { access, path, .. } => {
            assert_eq!(access.as_str(), "write");
            assert_eq!(path, "/data");
        }
        Counterexample::Network { protocol, .. } => {
            assert_ne!(protocol_name(*protocol), "unknown");
        }
        _ => panic!("unknown counterexample kinds must fail closed"),
    }
}

#[test]
fn external_callers_read_reason_evidence_and_authorize_only_within() {
    let policy = parse_policy_str(
        "version: 1\nfilesystem_policy: { read_only: [/data], include_workdir: false }\n",
    )
    .expect("policy should parse");

    let within = check_within_boundary(&policy, &policy, CheckOptions::new(Duration::from_secs(1)));
    assert!(authorize(&within));

    let inconclusive = check_within_boundary(&policy, &policy, CheckOptions::new(Duration::ZERO));
    assert!(!authorize(&inconclusive));
    let CheckResult::Inconclusive(evidence) = &inconclusive else {
        panic!("expected timeout evidence, got {inconclusive:?}");
    };
    assert_eq!(evidence.reason(), "solver timeout must be positive");
    assert_eq!(evidence.reason_code().as_str(), "solver_timeout");
    match evidence.reason_code() {
        ReasonCode::SolverTimeout => {}
        _ => panic!("unexpected reason code"),
    }
    assert_eq!(evidence.scope().policy_version, 1);
}
