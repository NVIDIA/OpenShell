// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Engine-neutral shaping of YAML network policy data.
//!
//! Builds the JSON form of proto network policies and normalizes it the way
//! every consumer reads it: canonical protocol names, MCP tool aliases moved
//! into `params`, and matcher leaves in object form. The Rego engine loads the
//! result as its data, and a Cedar sandbox compiles provider rules from it
//! (see `crate::cedar_provider_rules`).

use openshell_core::mcp::is_mcp_protocol;
use openshell_policy::L7Protocol as PolicyL7Protocol;

fn l7_matchers_to_json(
    matchers: &std::collections::HashMap<String, openshell_core::proto::L7QueryMatcher>,
) -> serde_json::Map<String, serde_json::Value> {
    matchers
        .iter()
        .map(|(key, matcher)| {
            let mut matcher_json = serde_json::json!({});
            if !matcher.glob.is_empty() {
                matcher_json["glob"] = matcher.glob.clone().into();
            }
            if !matcher.any.is_empty() {
                matcher_json["any"] = matcher.any.clone().into();
            }
            (key.clone(), matcher_json)
        })
        .collect()
}

/// Converts one policy endpoint into the JSON shape the L7 config parser reads.
///
/// Shared by the Rego data builder and the Cedar engine, which emits provider
/// endpoint settings for connections it allows. `policy_hash` identifies the
/// policy for MCP endpoint observation.
pub fn endpoint_policy_value(
    e: &openshell_core::proto::NetworkEndpoint,
    policy_hash: &str,
) -> serde_json::Value {
    // Normalize port/ports: ports takes precedence, then
    // single port promoted to array. Rego always sees "ports".
    let ports: Vec<u32> = if !e.ports.is_empty() {
        e.ports.clone()
    } else if e.port > 0 {
        vec![e.port]
    } else {
        vec![]
    };
    let mut ep = serde_json::json!({"host": e.host, "ports": ports});
    if !e.path.is_empty() {
        ep["path"] = e.path.clone().into();
    }
    if !e.protocol.is_empty() {
        ep["protocol"] = e.protocol.clone().into();
    }
    if e.tls != 0 {
        ep["tls"] = openshell_policy::network_tls_mode_to_str(e.tls)
            .map_or_else(|| format!("unknown({})", e.tls), str::to_owned)
            .into();
    }
    if e.enforcement != 0 {
        ep["enforcement"] = openshell_policy::network_enforcement_mode_to_str(e.enforcement)
            .map_or_else(|| format!("unknown({})", e.enforcement), str::to_owned)
            .into();
    }
    if e.access != 0 {
        ep["access"] = openshell_policy::network_access_preset_to_str(e.access)
            .map_or_else(|| format!("unknown({})", e.access), str::to_owned)
            .into();
    }
    if !e.rules.is_empty() {
        let rules: Vec<serde_json::Value> = e
            .rules
            .iter()
            .map(|r| {
                let a = r.allow.as_ref();
                let mut allow = serde_json::Map::new();
                if let Some(a) = a {
                    // Proto3 represents absent scalar selectors as empty
                    // strings. Omit them so protobuf and YAML rules expose
                    // the same selector families to runtime validation.
                    if !a.method.is_empty() {
                        allow.insert("method".to_string(), a.method.clone().into());
                    }
                    if !a.path.is_empty() {
                        allow.insert("path".to_string(), a.path.clone().into());
                    }
                    if !a.command.is_empty() {
                        allow.insert("command".to_string(), a.command.clone().into());
                    }
                    if !a.operation_type.is_empty() {
                        allow.insert(
                            "operation_type".to_string(),
                            a.operation_type.clone().into(),
                        );
                    }
                    if !a.operation_name.is_empty() {
                        allow.insert(
                            "operation_name".to_string(),
                            a.operation_name.clone().into(),
                        );
                    }
                    if !a.fields.is_empty() {
                        allow.insert("fields".to_string(), a.fields.clone().into());
                    }
                }
                let query = a.map_or_else(serde_json::Map::new, |allow| {
                    l7_matchers_to_json(&allow.query)
                });
                if !query.is_empty() {
                    allow.insert("query".to_string(), query.into());
                }
                let params = a.map_or_else(serde_json::Map::new, |allow| {
                    l7_matchers_to_json(&allow.params)
                });
                if !params.is_empty() {
                    allow.insert("params".to_string(), params.into());
                }
                serde_json::json!({ "allow": allow })
            })
            .collect();
        ep["rules"] = rules.into();
    }
    if !e.allowed_ips.is_empty() {
        ep["allowed_ips"] = e.allowed_ips.clone().into();
    }
    if e.advisor_proposed {
        ep["advisor_proposed"] = true.into();
    }
    if !e.deny_rules.is_empty() {
        let deny_rules: Vec<serde_json::Value> = e
            .deny_rules
            .iter()
            .map(|d| {
                let mut deny = serde_json::json!({});
                if !d.method.is_empty() {
                    deny["method"] = d.method.clone().into();
                }
                if !d.path.is_empty() {
                    deny["path"] = d.path.clone().into();
                }
                if !d.command.is_empty() {
                    deny["command"] = d.command.clone().into();
                }
                if !d.operation_type.is_empty() {
                    deny["operation_type"] = d.operation_type.clone().into();
                }
                if !d.operation_name.is_empty() {
                    deny["operation_name"] = d.operation_name.clone().into();
                }
                if !d.fields.is_empty() {
                    deny["fields"] = d.fields.clone().into();
                }
                let query = l7_matchers_to_json(&d.query);
                if !query.is_empty() {
                    deny["query"] = query.into();
                }
                let params = l7_matchers_to_json(&d.params);
                if !params.is_empty() {
                    deny["params"] = params.into();
                }
                deny
            })
            .collect();
        ep["deny_rules"] = deny_rules.into();
    }
    if e.allow_encoded_slash {
        ep["allow_encoded_slash"] = true.into();
    }
    if e.websocket_credential_rewrite {
        ep["websocket_credential_rewrite"] = true.into();
    }
    if e.request_body_credential_rewrite {
        ep["request_body_credential_rewrite"] = true.into();
    }
    if e.allow_uninspected_credentials {
        ep["allow_uninspected_credentials"] = true.into();
    }
    if e.provider_credentialed {
        ep["provider_credentialed"] = true.into();
    }
    if !e.token_grant_owner.is_empty() {
        // Preserve the gateway's endpoint identity so admission
        // can select its grants without reconstructing ownership
        // from overlapping host and path selectors.
        ep["token_grant_owner"] = e.token_grant_owner.clone().into();
    }
    // Every inspected protocol must bind grant reporting to the
    // policy selected before credential acquisition.
    ep["policy_hash"] = policy_hash.into();
    if is_mcp_protocol(&e.protocol) {
        // Derive endpoint identity from the policy endpoint while
        // it is still available. Request handling carries this
        // opaque value through exact path selection and never
        // recomputes identity from a concrete request host.
        ep["endpoint_id"] = openshell_core::endpoint_status::endpoint_id(e).into();
    }
    if !e.credential_signing.is_empty() {
        ep["credential_signing"] = e.credential_signing.clone().into();
    }
    if !e.signing_service.is_empty() {
        ep["signing_service"] = e.signing_service.clone().into();
    }
    if !e.signing_region.is_empty() {
        ep["signing_region"] = e.signing_region.clone().into();
    }
    if let Some(binding) = &e.credential_binding {
        ep["credential_binding"] = serde_json::json!({
            "provider": binding.provider.clone(),
        });
    }
    if !e.persisted_queries.is_empty() {
        ep["persisted_queries"] = e.persisted_queries.clone().into();
    }
    if !e.graphql_persisted_queries.is_empty() {
        let persisted: serde_json::Map<String, serde_json::Value> = e
            .graphql_persisted_queries
            .iter()
            .map(|(key, op)| {
                (
                    key.clone(),
                    serde_json::json!({
                        "operation_type": op.operation_type,
                        "operation_name": op.operation_name,
                        "fields": op.fields,
                    }),
                )
            })
            .collect();
        ep["graphql_persisted_queries"] = persisted.into();
    }
    if e.graphql_max_body_bytes > 0 {
        ep["graphql_max_body_bytes"] = e.graphql_max_body_bytes.into();
    }
    if e.json_rpc_max_body_bytes > 0 {
        ep["json_rpc_max_body_bytes"] = e.json_rpc_max_body_bytes.into();
    }
    if let Some(mcp) = &e.mcp {
        if e.protocol.eq_ignore_ascii_case("mcp") {
            ep["mcp_versions"] = mcp.versions.clone().into();
        }
        if let Some(strict_tool_names) = mcp.strict_tool_names {
            ep["mcp_strict_tool_names"] = strict_tool_names.into();
        }
        if let Some(allow_all_known_mcp_methods) = mcp.allow_all_known_mcp_methods {
            ep["mcp_allow_all_known_mcp_methods"] = allow_all_known_mcp_methods.into();
        }
    }
    ep
}

/// Converts a policy's `network_middlewares` into the JSON shape the policy
/// data carries, keyed by config name in sorted order.
///
/// Shared by the Rego data builder and the Cedar middleware state, so both
/// engines select middleware from identical configs.
pub fn network_middlewares_json(
    policy: &openshell_core::proto::SandboxPolicy,
) -> serde_json::Map<String, serde_json::Value> {
    let mut middleware_entries: Vec<_> = policy.network_middlewares.iter().collect();
    middleware_entries.sort_by_key(|(name, _)| name.as_str());
    middleware_entries
        .into_iter()
        .map(|(name, mw)| {
            let mut value = serde_json::json!({
                "middleware": mw.middleware,
                "order": mw.order,
            });
            if !mw.name.is_empty() {
                value["name"] = mw.name.clone().into();
            }
            if let Some(config) = &mw.config {
                value["config"] = openshell_core::proto_struct::struct_to_json_value(config);
            }
            if !mw.on_error.is_empty() {
                value["on_error"] = mw.on_error.clone().into();
            }
            if let Some(selector) = &mw.endpoints {
                let mut endpoints = serde_json::json!({});
                if !selector.include.is_empty() {
                    endpoints["include"] = selector.include.clone().into();
                }
                if !selector.exclude.is_empty() {
                    endpoints["exclude"] = selector.exclude.clone().into();
                }
                value["endpoints"] = endpoints;
            }
            (name.clone(), value)
        })
        .collect()
}

/// Canonicalize recognized protocol spellings before L7 validation or Rego use.
///
/// Rust parses protocol names case-insensitively, while Rego compares stable
/// wire keys. Publishing one canonical spelling keeps rule validation, typed
/// routing, and authorization on the same protocol branch.
pub fn normalize_endpoint_protocols(data: &mut serde_json::Value) {
    let Some(policies) = data
        .get_mut("network_policies")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };

    for policy in policies.values_mut() {
        let Some(endpoints) = policy
            .get_mut("endpoints")
            .and_then(serde_json::Value::as_array_mut)
        else {
            continue;
        };

        for endpoint in endpoints {
            let Some(endpoint) = endpoint.as_object_mut() else {
                continue;
            };
            let Some(protocol) = endpoint.get("protocol").and_then(serde_json::Value::as_str)
            else {
                continue;
            };
            let canonical = if protocol.eq_ignore_ascii_case("tcp") {
                Some("tcp")
            } else {
                PolicyL7Protocol::parse(protocol).map(|protocol| match protocol {
                    PolicyL7Protocol::Rest => "rest",
                    PolicyL7Protocol::Websocket => "websocket",
                    PolicyL7Protocol::Graphql => "graphql",
                    PolicyL7Protocol::Sql => "sql",
                    PolicyL7Protocol::JsonRpc => "json-rpc",
                    PolicyL7Protocol::Mcp => "mcp",
                })
            };
            if let Some(canonical) = canonical {
                endpoint.insert(
                    "protocol".to_string(),
                    serde_json::Value::String(canonical.to_string()),
                );
            }
        }
    }
}

pub fn normalize_l7_policy_rule_aliases(data: &mut serde_json::Value) {
    let Some(policies) = data
        .get_mut("network_policies")
        .and_then(|v| v.as_object_mut())
    else {
        return;
    };

    for (_name, policy) in policies.iter_mut() {
        let Some(endpoints) = policy.get_mut("endpoints").and_then(|v| v.as_array_mut()) else {
            continue;
        };

        for ep in endpoints.iter_mut() {
            let Some(ep_obj) = ep.as_object_mut() else {
                continue;
            };
            normalize_l7_rules_aliases(ep_obj);
        }
    }
}

fn normalize_l7_rules_aliases(ep: &mut serde_json::Map<String, serde_json::Value>) {
    let protocol = ep
        .get("protocol")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string();
    let mcp_allow_all_known_mcp_methods = ep
        .get("mcp_allow_all_known_mcp_methods")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if let Some(rules) = ep.get_mut("rules").and_then(|v| v.as_array_mut()) {
        for rule in rules {
            if let Some(allow) = rule
                .get_mut("allow")
                .and_then(serde_json::Value::as_object_mut)
            {
                normalize_l7_rule_aliases(allow, &protocol, mcp_allow_all_known_mcp_methods);
            } else if let Some(allow) = rule.as_object_mut() {
                normalize_l7_rule_aliases(allow, &protocol, mcp_allow_all_known_mcp_methods);
            }
        }
    }

    if let Some(denies) = ep.get_mut("deny_rules").and_then(|v| v.as_array_mut()) {
        for deny in denies {
            if let Some(deny_obj) = deny.as_object_mut() {
                normalize_l7_rule_aliases(deny_obj, &protocol, mcp_allow_all_known_mcp_methods);
            }
        }
    }
}

fn normalize_l7_rule_aliases(
    rule: &mut serde_json::Map<String, serde_json::Value>,
    protocol: &str,
    mcp_allow_all_known_mcp_methods: bool,
) {
    if protocol == "mcp" {
        let mut has_tool_selector = rule
            .get("params")
            .and_then(serde_json::Value::as_object)
            .and_then(|params| params.get("name"))
            .is_some_and(|v| !v.is_null());
        if let Some(tool) = rule.remove("tool").filter(|v| !v.is_null()) {
            let params = rule
                .entry("params".to_string())
                .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
            if let Some(params) = params.as_object_mut() {
                params.entry("name".to_string()).or_insert(tool);
                has_tool_selector = true;
            }
        }

        if mcp_allow_all_known_mcp_methods
            && rule
                .get("method")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .is_empty()
        {
            let method = if has_tool_selector { "tools/call" } else { "*" };
            rule.insert(
                "method".to_string(),
                serde_json::Value::String(method.to_string()),
            );
        }
    }

    // MCP tool aliases must move into params before matcher normalization so
    // both authored forms produce the same endpoint configuration as protobuf.
    normalize_l7_matcher_map(rule, "query");
    normalize_l7_matcher_map(rule, "params");
}

/// Normalize nonempty matcher leaves to the protobuf runtime representation.
///
/// OPA data also accepts explicit `glob` and `any` objects. Keeping those intact
/// makes normalization idempotent for already lowered data and protobuf reloads.
fn normalize_l7_matcher_map(rule: &mut serde_json::Map<String, serde_json::Value>, field: &str) {
    let Some(matchers) = rule
        .get_mut(field)
        .and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };
    for matcher in matchers.values_mut() {
        // Rego permits an empty scalar to match an empty query value, whereas
        // an empty glob object never matches. Preserve this OPA-only form.
        if matcher.as_str().is_some_and(|glob| !glob.is_empty()) {
            *matcher = serde_json::json!({ "glob": matcher.take() });
        }
    }
}
