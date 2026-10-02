// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Checks that [`compile_l7`] translates the `rules`/`deny_rules` subset of
//! normalized `data.sandbox.*` JSON into `HttpRequest` Cedar decisions
//! matching Rego's `allow_request`/`deny_request`, and correctly reports
//! `Unsupported` instead of guessing when a rule shape can't be
//! represented.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, Entity, EntityId, EntityTypeName, EntityUid,
    PolicySet, Request, RestrictedExpression,
};
use openshell_policy_cedar::compile_l7::compile_l7;
use openshell_policy_cedar_schema::{actions, context_fields, endpoint_fields, entity_types};
use serde_json::json;

fn entity_uid(type_name: &str, id: &str) -> EntityUid {
    let type_name = EntityTypeName::from_str(type_name).unwrap();
    let entity_id = EntityId::from_str(id).unwrap();
    EntityUid::from_type_name_and_id(type_name, entity_id)
}

#[allow(clippy::too_many_arguments)]
fn evaluate(
    policies: &PolicySet,
    binary_path: &str,
    ancestors: &[&str],
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    command: &str,
    jsonrpc_method: &str,
) -> Decision {
    let schema = openshell_policy_cedar_schema::load_schema().expect("schema parses");
    let host_port = format!("{host}:{port}");
    let process_uid = entity_uid(entity_types::PROCESS, "current");
    let user_uid = entity_uid(entity_types::USER, "sandbox");
    let group_uid = entity_uid(entity_types::GROUP, "sandbox");
    let endpoint_uid = entity_uid(entity_types::NETWORK_ENDPOINT, &host_port);
    let action_uid = entity_uid(actions::ACTION_TYPE, actions::HTTP_REQUEST);

    let process = Entity::new(
        process_uid.clone(),
        HashMap::from([
            (
                "user".to_string(),
                RestrictedExpression::new_entity_uid(user_uid.clone()),
            ),
            (
                "group".to_string(),
                RestrictedExpression::new_entity_uid(group_uid.clone()),
            ),
        ]),
        HashSet::new(),
    )
    .unwrap();
    let user = Entity::new_no_attrs(user_uid, HashSet::new());
    let group = Entity::new_no_attrs(group_uid, HashSet::new());
    let endpoint = Entity::new(
        endpoint_uid.clone(),
        HashMap::from([
            (
                endpoint_fields::HOST.to_string(),
                RestrictedExpression::new_string(host.to_string()),
            ),
            (
                endpoint_fields::PORT.to_string(),
                RestrictedExpression::new_long(i64::from(port)),
            ),
            (
                endpoint_fields::PROTOCOL.to_string(),
                RestrictedExpression::new_string(String::new()),
            ),
            (
                endpoint_fields::HOST_PORT.to_string(),
                RestrictedExpression::new_string(host_port),
            ),
        ]),
        HashSet::new(),
    )
    .unwrap();
    let entities =
        Entities::from_entities([process, user, group, endpoint], Some(&schema)).unwrap();

    let context = Context::from_pairs([
        (
            context_fields::BINARY_PATH.to_string(),
            RestrictedExpression::new_string(binary_path.to_string()),
        ),
        (
            context_fields::ANCESTORS.to_string(),
            RestrictedExpression::new_set(
                ancestors
                    .iter()
                    .map(|a| RestrictedExpression::new_string((*a).to_string())),
            ),
        ),
        (
            context_fields::METHOD.to_string(),
            RestrictedExpression::new_string(method.to_string()),
        ),
        (
            context_fields::PATH.to_string(),
            RestrictedExpression::new_string(path.to_string()),
        ),
        (
            context_fields::COMMAND.to_string(),
            RestrictedExpression::new_string(command.to_string()),
        ),
        (
            context_fields::JSONRPC_METHOD.to_string(),
            RestrictedExpression::new_string(jsonrpc_method.to_string()),
        ),
    ])
    .unwrap();

    let cedar_request = Request::new(
        process_uid,
        action_uid,
        endpoint_uid,
        context,
        Some(&schema),
    )
    .unwrap();
    let response = Authorizer::new().is_authorized(&cedar_request, policies, &entities);
    response.decision()
}

fn rest_policy(method: &str, path: &str) -> serde_json::Value {
    json!({
        "network_policies": {
            "api": {
                "endpoints": [{
                    "host": "api.example.com",
                    "ports": [443],
                    "rules": [{"allow": {"method": method, "path": path}}],
                }],
                "binaries": [{"path": "/usr/bin/curl"}],
            }
        }
    })
}

#[test]
fn allows_exact_method_and_path() {
    let data = rest_policy("GET", "/v1/users");
    let compiled = compile_l7(&data).expect("data must compile");
    assert!(compiled.uncompiled.is_empty(), "{:?}", compiled.uncompiled);

    let decision = evaluate(
        &compiled.policies,
        "/usr/bin/curl",
        &[],
        "api.example.com",
        443,
        "GET",
        "/v1/users",
        "",
        "",
    );
    assert_eq!(decision, Decision::Allow);
}

#[test]
fn denies_wrong_path() {
    let data = rest_policy("GET", "/v1/users");
    let compiled = compile_l7(&data).expect("data must compile");

    let decision = evaluate(
        &compiled.policies,
        "/usr/bin/curl",
        &[],
        "api.example.com",
        443,
        "GET",
        "/v1/admin",
        "",
        "",
    );
    assert_eq!(decision, Decision::Deny);
}

#[test]
fn allows_safe_glob_path() {
    let data = rest_policy("GET", "/v1/**");
    let compiled = compile_l7(&data).expect("data must compile");
    assert!(compiled.uncompiled.is_empty(), "{:?}", compiled.uncompiled);

    let decision = evaluate(
        &compiled.policies,
        "/usr/bin/curl",
        &[],
        "api.example.com",
        443,
        "GET",
        "/v1/users/42/profile",
        "",
        "",
    );
    assert_eq!(decision, Decision::Allow);
}

#[test]
fn reports_unsupported_for_segment_unsafe_path_glob() {
    let data = rest_policy("GET", "/v1/*/profile");
    let compiled = compile_l7(&data).expect("data must parse");
    assert_eq!(compiled.uncompiled.len(), 1, "{:?}", compiled.uncompiled);
}

#[test]
fn allows_sql_command_match() {
    let data = json!({
        "network_policies": {
            "db": {
                "endpoints": [{
                    "host": "db.example.com",
                    "ports": [5432],
                    "rules": [{"allow": {"command": "SELECT"}}],
                }],
                "binaries": [{"path": "/usr/bin/psql"}],
            }
        }
    });
    let compiled = compile_l7(&data).expect("data must compile");
    assert!(compiled.uncompiled.is_empty(), "{:?}", compiled.uncompiled);

    let allowed = evaluate(
        &compiled.policies,
        "/usr/bin/psql",
        &[],
        "db.example.com",
        5432,
        "",
        "",
        "SELECT",
        "",
    );
    assert_eq!(allowed, Decision::Allow);

    let denied = evaluate(
        &compiled.policies,
        "/usr/bin/psql",
        &[],
        "db.example.com",
        5432,
        "",
        "",
        "DELETE",
        "",
    );
    assert_eq!(denied, Decision::Deny);
}

#[test]
fn allows_jsonrpc_exact_method() {
    let data = json!({
        "network_policies": {
            "rpc": {
                "endpoints": [{
                    "host": "rpc.example.com",
                    "ports": [443],
                    "protocol": "json-rpc",
                    "rules": [{"allow": {"method": "getBlock"}}],
                }],
                "binaries": [{"path": "/usr/bin/curl"}],
            }
        }
    });
    let compiled = compile_l7(&data).expect("data must compile");
    assert!(compiled.uncompiled.is_empty(), "{:?}", compiled.uncompiled);

    let allowed = evaluate(
        &compiled.policies,
        "/usr/bin/curl",
        &[],
        "rpc.example.com",
        443,
        "",
        "",
        "",
        "getBlock",
    );
    assert_eq!(allowed, Decision::Allow);

    let denied = evaluate(
        &compiled.policies,
        "/usr/bin/curl",
        &[],
        "rpc.example.com",
        443,
        "",
        "",
        "",
        "sendTransaction",
    );
    assert_eq!(denied, Decision::Deny);
}

#[test]
fn deny_rule_overrides_allow() {
    let data = json!({
        "network_policies": {
            "api": {
                "endpoints": [{
                    "host": "api.example.com",
                    "ports": [443],
                    "rules": [{"allow": {"method": "*", "path": "/**"}}],
                    "deny_rules": [{"method": "DELETE", "path": "/v1/admin/**"}],
                }],
                "binaries": [{"path": "/usr/bin/curl"}],
            }
        }
    });
    let compiled = compile_l7(&data).expect("data must compile");
    assert!(compiled.uncompiled.is_empty(), "{:?}", compiled.uncompiled);

    let allowed = evaluate(
        &compiled.policies,
        "/usr/bin/curl",
        &[],
        "api.example.com",
        443,
        "GET",
        "/v1/users",
        "",
        "",
    );
    assert_eq!(allowed, Decision::Allow);

    let denied = evaluate(
        &compiled.policies,
        "/usr/bin/curl",
        &[],
        "api.example.com",
        443,
        "DELETE",
        "/v1/admin/users/1",
        "",
        "",
    );
    assert_eq!(denied, Decision::Deny);
}

#[test]
fn reports_unsupported_for_query_matcher() {
    let data = json!({
        "network_policies": {
            "api": {
                "endpoints": [{
                    "host": "api.example.com",
                    "ports": [443],
                    "rules": [{"allow": {"method": "GET", "path": "/search", "query": {"q": "*"}}}],
                }],
                "binaries": [{"path": "/usr/bin/curl"}],
            }
        }
    });
    let compiled = compile_l7(&data).expect("data must parse");
    assert_eq!(compiled.uncompiled.len(), 1, "{:?}", compiled.uncompiled);
}

#[test]
fn reports_unsupported_for_mcp_endpoint_with_rules() {
    let data = json!({
        "network_policies": {
            "mcp": {
                "endpoints": [{
                    "host": "mcp.example.com",
                    "ports": [443],
                    "protocol": "mcp",
                    "rules": [{"allow": {"method": "tools/call"}}],
                }],
                "binaries": [{"path": "/usr/bin/curl"}],
            }
        }
    });
    let compiled = compile_l7(&data).expect("data must parse");
    assert_eq!(compiled.uncompiled.len(), 1, "{:?}", compiled.uncompiled);
}

#[test]
fn endpoint_with_no_rules_compiles_to_nothing() {
    let data = json!({
        "network_policies": {
            "plain": {
                "endpoints": [{"host": "plain.example.com", "ports": [443]}],
                "binaries": [{"path": "/usr/bin/curl"}],
            }
        }
    });
    let compiled = compile_l7(&data).expect("data must compile");
    assert!(compiled.uncompiled.is_empty(), "{:?}", compiled.uncompiled);
    assert!(compiled.policies.policies().next().is_none());
}

#[test]
fn method_rule_without_path_never_matches() {
    // Mirrors Rego: `path_matches(request.path, rule.allow.path)` is
    // undefined (and so never satisfied) when `rule.allow.path` is absent.
    let data = json!({
        "network_policies": {
            "api": {
                "endpoints": [{
                    "host": "api.example.com",
                    "ports": [443],
                    "rules": [{"allow": {"method": "GET"}}],
                }],
                "binaries": [{"path": "/usr/bin/curl"}],
            }
        }
    });
    let compiled = compile_l7(&data).expect("data must compile");
    assert!(compiled.uncompiled.is_empty(), "{:?}", compiled.uncompiled);

    let decision = evaluate(
        &compiled.policies,
        "/usr/bin/curl",
        &[],
        "api.example.com",
        443,
        "GET",
        "/anything",
        "",
        "",
    );
    assert_eq!(decision, Decision::Deny);
}
