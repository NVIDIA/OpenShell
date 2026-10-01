// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Rust guideline compliant 2026-09-30

//! Checks that [`compile_normalized_data`] translates the CONNECT-time
//! subset of normalized `data.sandbox.*` JSON (the same shape
//! `openshell_supervisor_network::opa::proto_to_opa_data_json` produces)
//! into Cedar decisions matching what Rego's `network_policy_for_request`
//! would compute, and correctly reports `Unsupported` instead of guessing
//! when a rule shape can't be represented.

use openshell_policy_cedar::compile::compile_normalized_data;
use openshell_policy_cedar::{CedarNetworkEngine, NetworkDecision, NetworkRequest};
use serde_json::json;

fn request(host: &str, port: u16, binary_path: &str, ancestors: &[&str]) -> NetworkRequest {
    NetworkRequest {
        user: "sandbox".to_string(),
        group: "sandbox".to_string(),
        host: host.to_string(),
        port,
        protocol: "rest".to_string(),
        binary_path: binary_path.to_string(),
        ancestors: ancestors.iter().map(ToString::to_string).collect(),
        method: String::new(),
        path: String::new(),
        command: String::new(),
    }
}

#[test]
fn empty_policy_denies_everything() {
    let compiled = compile_normalized_data(&json!({})).expect("empty data must compile");
    assert!(compiled.uncompiled.is_empty());
    let engine = CedarNetworkEngine::from_compiled(compiled).expect("engine must build");
    let decision = engine
        .evaluate_network(&request("pypi.org", 443, "/usr/bin/python3", &[]))
        .expect("request must evaluate");
    assert!(
        matches!(decision, NetworkDecision::Deny { .. }),
        "{decision:?}"
    );
}

#[test]
fn allows_exact_host_and_exact_binary() {
    let data = json!({
        "network_policies": {
            "pip": {
                "endpoints": [{"host": "pypi.org", "ports": [443]}],
                "binaries": [{"path": "/sandbox/.venv/bin/python3"}]
            }
        }
    });
    let compiled = compile_normalized_data(&data).expect("policy must compile");
    assert!(compiled.uncompiled.is_empty(), "{:?}", compiled.uncompiled);
    let engine = CedarNetworkEngine::from_compiled(compiled).expect("engine must build");

    let decision = engine
        .evaluate_network(&request("pypi.org", 443, "/sandbox/.venv/bin/python3", &[]))
        .expect("request must evaluate");
    assert!(
        matches!(decision, NetworkDecision::Allow { .. }),
        "{decision:?}"
    );

    let wrong_binary = engine
        .evaluate_network(&request("pypi.org", 443, "/usr/bin/curl", &[]))
        .expect("request must evaluate");
    assert!(
        matches!(wrong_binary, NetworkDecision::Deny { .. }),
        "{wrong_binary:?}"
    );
}

#[test]
fn host_matching_is_case_insensitive() {
    let data = json!({
        "network_policies": {
            "pip": {
                "endpoints": [{"host": "PyPI.org", "ports": [443]}],
                "binaries": [{"path": "/usr/bin/python3"}]
            }
        }
    });
    let compiled = compile_normalized_data(&data).expect("policy must compile");
    let engine = CedarNetworkEngine::from_compiled(compiled).expect("engine must build");
    let decision = engine
        .evaluate_network(&request("pypi.ORG", 443, "/usr/bin/python3", &[]))
        .expect("request must evaluate");
    assert!(
        matches!(decision, NetworkDecision::Allow { .. }),
        "{decision:?}"
    );
}

#[test]
fn allows_exact_ancestor_membership() {
    let data = json!({
        "network_policies": {
            "node": {
                "endpoints": [{"host": "registry.npmjs.org", "ports": [443]}],
                "binaries": [{"path": "/usr/bin/node"}]
            }
        }
    });
    let compiled = compile_normalized_data(&data).expect("policy must compile");
    let engine = CedarNetworkEngine::from_compiled(compiled).expect("engine must build");

    // The immediate exe is npm, but an ancestor is the allowed node binary.
    let decision = engine
        .evaluate_network(&request(
            "registry.npmjs.org",
            443,
            "/usr/bin/npm",
            &["/usr/bin/node"],
        ))
        .expect("request must evaluate");
    assert!(
        matches!(decision, NetworkDecision::Allow { .. }),
        "{decision:?}"
    );
}

#[test]
fn allows_safe_double_star_host_glob() {
    let data = json!({
        "network_policies": {
            "wildcard": {
                "endpoints": [{"host": "**.example.com", "ports": [443]}],
                "binaries": [{"path": "/usr/bin/curl"}]
            }
        }
    });
    let compiled = compile_normalized_data(&data).expect("policy must compile");
    assert!(compiled.uncompiled.is_empty(), "{:?}", compiled.uncompiled);
    let engine = CedarNetworkEngine::from_compiled(compiled).expect("engine must build");

    let decision = engine
        .evaluate_network(&request("a.b.example.com", 443, "/usr/bin/curl", &[]))
        .expect("request must evaluate");
    assert!(
        matches!(decision, NetworkDecision::Allow { .. }),
        "{decision:?}"
    );
}

#[test]
fn reports_unsupported_for_segment_unsafe_host_glob() {
    let data = json!({
        "network_policies": {
            "singlestar": {
                "endpoints": [{"host": "*.example.com", "ports": [443]}],
                "binaries": [{"path": "/usr/bin/curl"}]
            }
        }
    });
    let compiled = compile_normalized_data(&data).expect("data must parse");
    assert_eq!(compiled.uncompiled.len(), 1);
    let engine = CedarNetworkEngine::from_compiled(compiled).expect("engine must build");

    // A request the unsafe pattern would have matched must be Unsupported,
    // not a guessed Deny.
    let decision = engine
        .evaluate_network(&request("foo.example.com", 443, "/usr/bin/curl", &[]))
        .expect("request must evaluate");
    assert!(
        matches!(decision, NetworkDecision::Unsupported { .. }),
        "{decision:?}"
    );

    // A request the unsafe pattern would NOT have matched (extra label
    // crossing the "." delimiter) correctly falls through to a real Deny,
    // since no other policy covers it either.
    let unmatched = engine
        .evaluate_network(&request("a.b.example.com", 443, "/usr/bin/curl", &[]))
        .expect("request must evaluate");
    assert!(
        matches!(unmatched, NetworkDecision::Deny { .. }),
        "{unmatched:?}"
    );
}

#[test]
fn reports_unsupported_for_glob_binary_even_with_exact_host() {
    let data = json!({
        "network_policies": {
            "globbinary": {
                "endpoints": [{"host": "pypi.org", "ports": [443]}],
                "binaries": [{"path": "/sandbox/**/bin/python3"}]
            }
        }
    });
    let compiled = compile_normalized_data(&data).expect("data must parse");
    assert_eq!(compiled.uncompiled.len(), 1, "{:?}", compiled.uncompiled);
    let engine = CedarNetworkEngine::from_compiled(compiled).expect("engine must build");

    let decision = engine
        .evaluate_network(&request("pypi.org", 443, "/sandbox/venv/bin/python3", &[]))
        .expect("request must evaluate");
    assert!(
        matches!(decision, NetworkDecision::Unsupported { .. }),
        "{decision:?}"
    );
}

#[test]
fn require_binary_identity_false_skips_binary_matching() {
    let data = json!({
        "network_policies": {
            "trusted": {
                "endpoints": [{"host": "pypi.org", "ports": [443]}],
                "binaries": []
            }
        },
        "runtime": {"require_binary_identity": false}
    });
    let compiled = compile_normalized_data(&data).expect("policy must compile");
    assert!(compiled.uncompiled.is_empty(), "{:?}", compiled.uncompiled);
    let engine = CedarNetworkEngine::from_compiled(compiled).expect("engine must build");

    let decision = engine
        .evaluate_network(&request("pypi.org", 443, "/anything/at/all", &[]))
        .expect("request must evaluate");
    assert!(
        matches!(decision, NetworkDecision::Allow { .. }),
        "{decision:?}"
    );
}

#[test]
fn does_not_grant_cross_policy_combinations() {
    // Policy A allows endpoint X with binary P; policy B allows endpoint Y
    // with binary Q. Endpoint X with binary Q must stay denied - policies
    // must not be flattened into a shared global fact base.
    let data = json!({
        "network_policies": {
            "a": {
                "endpoints": [{"host": "x.example.com", "ports": [443]}],
                "binaries": [{"path": "/usr/bin/p"}]
            },
            "b": {
                "endpoints": [{"host": "y.example.com", "ports": [443]}],
                "binaries": [{"path": "/usr/bin/q"}]
            }
        }
    });
    let compiled = compile_normalized_data(&data).expect("policy must compile");
    let engine = CedarNetworkEngine::from_compiled(compiled).expect("engine must build");

    let cross = engine
        .evaluate_network(&request("x.example.com", 443, "/usr/bin/q", &[]))
        .expect("request must evaluate");
    assert!(matches!(cross, NetworkDecision::Deny { .. }), "{cross:?}");
}
