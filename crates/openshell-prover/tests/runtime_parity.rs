// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Regression tests against the network supervisor's actual Rego policy.

use openshell_prover::containment::{
    CheckOptions, CheckResult, check_within_maximum, parse_policy_str,
};
use regorus::{Engine, Value};
use serde_json::json;
use std::time::Duration;

const SANDBOX_POLICY_REGO: &str =
    include_str!("../../openshell-supervisor-network/data/sandbox-policy.rego");

fn check(maximum: &str, candidate: &str) -> CheckResult {
    let maximum = parse_policy_str(maximum).expect("maximum policy should parse");
    let candidate = parse_policy_str(candidate).expect("candidate policy should parse");
    check_within_maximum(
        &maximum,
        &candidate,
        CheckOptions {
            timeout: Duration::from_secs(5),
        },
    )
}

fn runtime_engine(policy: &str) -> Engine {
    let yaml: serde_yml::Value = serde_yml::from_str(policy).expect("valid policy YAML");
    let mut data = serde_json::to_value(yaml).expect("policy converts to JSON");
    data.as_object_mut().expect("policy is an object").insert(
        "runtime".to_owned(),
        json!({ "require_binary_identity": true }),
    );

    let mut engine = Engine::new();
    engine
        .add_policy("sandbox-policy.rego".into(), SANDBOX_POLICY_REGO.into())
        .expect("runtime Rego should compile");
    engine
        .add_data_json(&data.to_string())
        .expect("runtime policy data should load");
    engine
}

fn runtime_input(binary: &str, ancestors: &[&str], host: &str, method: &str) -> Value {
    serde_json::from_value(json!({
        "exec": {
            "path": binary,
            "ancestors": ancestors,
            "cmdline_paths": [],
        },
        "network": {
            "host": host,
            "port": 443,
        },
        "request": {
            "method": method,
            "path": "/",
            "query_params": {},
        },
    }))
    .expect("input converts to a Rego value")
}

fn eval_bool(engine: &mut Engine, input: &Value, rule: &str) -> bool {
    engine.set_input(input.clone());
    engine
        .eval_rule(rule.into())
        .expect("runtime rule should evaluate")
        == Value::from(true)
}

fn eval_array_len(engine: &mut Engine, input: &Value, rule: &str) -> usize {
    engine.set_input(input.clone());
    match engine
        .eval_rule(rule.into())
        .expect("runtime rule should evaluate")
    {
        Value::Array(values) => values.len(),
        Value::Undefined => 0,
        value => panic!("expected array from {rule}, got {value:?}"),
    }
}

#[test]
fn recursive_path_globs_preserve_zero_directory_grants_and_denies() {
    let policy = |grant: &str, deny: Option<&str>, endpoint: &str| {
        json!({
            "version": 1,
            "network_policies": {"n": {
                "binaries": [{"path": "/usr/bin/curl"}],
                "endpoints": [{
                    "host": "api.example.com", "ports": [443],
                    "protocol": "rest", "enforcement": "enforce", "path": endpoint,
                    "rules": [{"allow": {"method": "GET", "path": grant}}],
                    "deny_rules": deny.into_iter().map(|path| json!({"method": "GET", "path": path})).collect::<Vec<_>>()
                }]
            }}
        }).to_string()
    };
    for (maximum, candidate, within) in [
        (
            policy("/**", Some("/a/**/b"), ""),
            policy("/a/b", None, ""),
            false,
        ),
        (
            policy("/a/**/b", Some("/a/b"), ""),
            policy("/a/**/b", None, ""),
            false,
        ),
        (policy("/a/**/b", None, ""), policy("/a/b", None, ""), true),
        (
            policy("/**", None, "/a/**/b"),
            policy("/a/b", None, ""),
            true,
        ),
    ] {
        let input: Value = serde_json::from_value(json!({
            "exec": {"path": "/usr/bin/curl", "ancestors": [], "cmdline_paths": []},
            "network": {"host": "api.example.com", "port": 443},
            "request": {"method": "GET", "path": "/a/b", "query_params": {}}
        }))
        .unwrap();
        assert!(eval_bool(
            &mut runtime_engine(&candidate),
            &input,
            "data.openshell.sandbox.allow_request"
        ));
        assert_eq!(
            eval_bool(
                &mut runtime_engine(&maximum),
                &input,
                "data.openshell.sandbox.allow_request"
            ),
            within
        );
        let result = check(&maximum, &candidate);
        if within {
            assert!(matches!(result, CheckResult::Within(_)), "{result:?}");
        } else {
            assert!(matches!(result, CheckResult::Exceeds(_)), "{result:?}");
        }
    }
}

#[test]
fn intra_label_host_wildcard_matches_empty_suffix_at_runtime() {
    let maximum = r#"
version: 1
network_policies:
  grant:
    endpoints:
      - host: api*.example.com
        ports: [443]
        protocol: rest
        enforcement: enforce
        rules: [{ allow: { method: GET, path: "/**" } }]
    binaries: [{ path: /usr/bin/curl }]
  exact_deny:
    endpoints:
      - host: api.example.com
        ports: [443]
        protocol: rest
        enforcement: enforce
        rules: [{ allow: { method: GET, path: "/**" } }]
        deny_rules: [{ method: GET, path: "/**" }]
    binaries: [{ path: /usr/bin/curl }]
"#;
    let candidate = r#"
version: 1
network_policies:
  grant:
    endpoints:
      - host: api*.example.com
        ports: [443]
        protocol: rest
        enforcement: enforce
        rules: [{ allow: { method: GET, path: "/**" } }]
    binaries: [{ path: /usr/bin/curl }]
"#;
    let input = runtime_input("/usr/bin/curl", &[], "api.example.com", "GET");
    let mut maximum_runtime = runtime_engine(maximum);
    let mut candidate_runtime = runtime_engine(candidate);

    assert!(eval_bool(
        &mut candidate_runtime,
        &input,
        "data.openshell.sandbox.allow_request"
    ));
    assert!(!eval_bool(
        &mut maximum_runtime,
        &input,
        "data.openshell.sandbox.allow_request"
    ));
    assert!(matches!(check(maximum, candidate), CheckResult::Exceeds(_)));
}

#[test]
fn ancestor_identity_applies_to_runtime_denies() {
    let maximum = policy_with_ancestor_deny("/usr/bin/python3");
    let candidate = policy_with_ancestor_deny("/usr/bin/node");
    let input = runtime_input("/usr/bin/curl", &["/usr/bin/python3"], "example.com", "GET");
    let mut maximum_runtime = runtime_engine(&maximum);
    let mut candidate_runtime = runtime_engine(&candidate);

    assert!(eval_bool(
        &mut candidate_runtime,
        &input,
        "data.openshell.sandbox.allow_request"
    ));
    assert!(!eval_bool(
        &mut maximum_runtime,
        &input,
        "data.openshell.sandbox.allow_request"
    ));
    assert!(matches!(
        check(&maximum, &candidate),
        CheckResult::Exceeds(_)
    ));
}

fn policy_with_ancestor_deny(denied_binary: &str) -> String {
    format!(
        r#"
version: 1
network_policies:
  grant:
    endpoints:
      - host: example.com
        ports: [443]
        protocol: rest
        enforcement: enforce
        rules: [{{ allow: {{ method: GET, path: "/**" }} }}]
    binaries: [{{ path: /usr/bin/curl }}]
  deny:
    endpoints:
      - host: example.com
        ports: [443]
        protocol: rest
        enforcement: enforce
        rules: [{{ allow: {{ method: GET, path: "/**" }} }}]
        deny_rules: [{{ method: "*", path: "/**" }}]
    binaries: [{{ path: {denied_binary} }}]
"#
    )
}

#[test]
fn inspected_endpoint_restricts_an_overlapping_l4_grant() {
    let maximum = r#"
version: 1
network_policies:
  egress:
    endpoints:
      - { host: api.example.com, ports: [443] }
      - host: api.example.com
        ports: [443]
        protocol: rest
        enforcement: enforce
        rules: [{ allow: { method: GET, path: "/**" } }]
    binaries: [{ path: /usr/bin/curl }]
"#;
    let candidate = r"
version: 1
network_policies:
  egress:
    endpoints:
      - { host: api.example.com, ports: [443] }
    binaries: [{ path: /usr/bin/curl }]
";
    let input = runtime_input("/usr/bin/curl", &[], "api.example.com", "POST");
    let mut maximum_runtime = runtime_engine(maximum);
    let mut candidate_runtime = runtime_engine(candidate);

    assert_eq!(
        eval_array_len(
            &mut candidate_runtime,
            &input,
            "data.openshell.sandbox._matching_endpoint_configs"
        ),
        0
    );
    assert_eq!(
        eval_array_len(
            &mut maximum_runtime,
            &input,
            "data.openshell.sandbox._matching_endpoint_configs"
        ),
        1
    );
    assert!(!eval_bool(
        &mut maximum_runtime,
        &input,
        "data.openshell.sandbox.allow_request"
    ));
    let result = check(maximum, candidate);
    assert!(
        matches!(result, CheckResult::Unsupported(_)),
        "overlapping inspection must be rejected explicitly: {result:?}"
    );
}

#[test]
fn runtime_accepts_methods_longer_than_sixty_four_bytes() {
    let long_method = "X".repeat(65);
    let maximum = rest_method_policy("GET");
    let candidate = rest_method_policy(&long_method);
    let input = runtime_input("/usr/bin/curl", &[], "api.example.com", &long_method);
    let mut maximum_runtime = runtime_engine(&maximum);
    let mut candidate_runtime = runtime_engine(&candidate);

    assert!(eval_bool(
        &mut candidate_runtime,
        &input,
        "data.openshell.sandbox.allow_request"
    ));
    assert!(!eval_bool(
        &mut maximum_runtime,
        &input,
        "data.openshell.sandbox.allow_request"
    ));
    assert!(matches!(
        check(&maximum, &candidate),
        CheckResult::Exceeds(_)
    ));
}

fn rest_method_policy(method: &str) -> String {
    format!(
        r#"
version: 1
network_policies:
  egress:
    endpoints:
      - host: api.example.com
        ports: [443]
        protocol: rest
        enforcement: enforce
        rules: [{{ allow: {{ method: "{method}", path: "/**" }} }}]
    binaries: [{{ path: /usr/bin/curl }}]
"#
    )
}
