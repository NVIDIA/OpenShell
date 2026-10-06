// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Validate raw network fields before normalization can erase malformed values.
//!
//! Raw OPA data can contain application data and lowered protocol options that
//! are not authored-policy fields. Validation uses the authored DTOs on copies;
//! the original objects retain their extra fields for Rego evaluation.

use miette::Result;
use ryno_policy_schema::{
    JsonRpcConfig, L7Allow, L7DenyRule, McpConfig, NetworkBinary, NetworkEndpoint,
    NetworkPolicyRule,
};
use serde::{Deserializer, de::DeserializeOwned};
use serde_json::{Map, Value};

/// Validate consumed fields after the parent has checked collection shapes.
///
/// Shared fields use the authored DTO types. Only the raw runtime field names
/// and matcher representation need adaptation; existing L7 validators still
/// own protocol combinations and matcher semantics.
pub(super) fn validate_network_settings(data: &Value) -> Result<()> {
    let Some(policies) = data.get("network_policies").and_then(Value::as_object) else {
        return Ok(());
    };
    for policy in policies.values() {
        let mut fields = object_copy(policy)?;
        fields.remove("endpoints");
        fields.remove("binaries");
        validate_known::<NetworkPolicyRule>(fields, "invalid network policy settings")?;

        for binary in array_entries(policy, "binaries") {
            validate_known::<NetworkBinary>(
                object_copy(binary)?,
                "invalid network binary settings",
            )?;
        }
        for endpoint in array_entries(policy, "endpoints") {
            validate_endpoint(endpoint)?;
        }
    }
    Ok(())
}

fn validate_endpoint(endpoint: &Value) -> Result<()> {
    let diagnostic = "L7 policy validation failed: invalid L7 policy configuration";
    let mut fields = object_copy(endpoint)?;
    // Rules are validated separately because raw matchers accept an explicit
    // `glob` object and allow rules also have a flattened OPA representation.
    fields.remove("rules");
    fields.remove("deny_rules");
    // The following alias-normalization stage already parses these stanzas
    // through the canonical config DTOs and owns their diagnostic category.
    fields.remove("mcp");
    fields.remove("json_rpc");
    validate_known::<NetworkEndpoint>(fields, diagnostic)?;

    validate_renamed::<JsonRpcConfig>(
        endpoint,
        &[("json_rpc_max_body_bytes", "max_body_bytes")],
        diagnostic,
    )?;
    validate_renamed::<McpConfig>(
        endpoint,
        &[
            ("mcp_versions", "versions"),
            ("mcp_strict_tool_names", "strict_tool_names"),
            (
                "mcp_allow_all_known_mcp_methods",
                "allow_all_known_mcp_methods",
            ),
        ],
        diagnostic,
    )?;

    // These values are emitted by protobuf lowering and read by network/L7
    // consumers. They have no authored DTO field, so check their wire types
    // explicitly rather than letting failed reads become runtime defaults.
    for field in ["provider_credentialed", "advisor_proposed"] {
        if endpoint.get(field).is_some_and(|value| !value.is_boolean()) {
            return Err(miette::miette!(diagnostic));
        }
    }
    for field in ["endpoint_id", "policy_hash"] {
        if endpoint.get(field).is_some_and(|value| !value.is_string()) {
            return Err(miette::miette!(diagnostic));
        }
    }

    for rule in array_entries(endpoint, "rules") {
        let mut fields = object_copy(rule.get("allow").unwrap_or(rule))?;
        adapt_matchers(&mut fields);
        validate_known::<L7Allow>(fields, diagnostic)?;
    }
    for rule in array_entries(endpoint, "deny_rules") {
        let mut fields = object_copy(rule)?;
        adapt_matchers(&mut fields);
        validate_known::<L7DenyRule>(fields, diagnostic)?;
    }
    Ok(())
}

fn array_entries<'a>(object: &'a Value, field: &str) -> &'a [Value] {
    // The parent shape validator rejects malformed present arrays before this
    // traversal. Missing arrays retain the raw loader's empty default.
    object
        .get(field)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn object_copy(value: &Value) -> Result<Map<String, Value>> {
    value.as_object().cloned().ok_or_else(|| {
        miette::miette!("L7 policy validation failed: invalid L7 policy configuration")
    })
}

fn validate_renamed<T: DeserializeOwned>(
    value: &Value,
    names: &[(&str, &str)],
    diagnostic: &'static str,
) -> Result<()> {
    let fields = names
        .iter()
        .filter_map(|(raw, authored)| {
            value
                .get(*raw)
                .map(|value| ((*authored).to_string(), value.clone()))
        })
        .collect();
    validate_known::<T>(fields, diagnostic)
}

/// Adapt only validation copies of runtime matcher leaves.
///
/// An explicit `{glob: string}` has the same type as the authored scalar
/// matcher. Leave malformed objects intact so the canonical DTO rejects them.
/// In particular, a mixed `glob`/`any` object must not lose either selector.
fn adapt_matchers(rule: &mut Map<String, Value>) {
    // The raw query validator treats null as omission. Preserve that OPA-only
    // form in installed data while omitting it from this authored-type check.
    if rule.get("query").is_some_and(Value::is_null) {
        rule.remove("query");
    }
    for field in ["query", "params"] {
        if let Some(matchers) = rule.get_mut(field).and_then(Value::as_object_mut) {
            for matcher in matchers.values_mut() {
                adapt_matcher(matcher);
            }
        }
    }
    if let Some(tool) = rule.get_mut("tool") {
        adapt_matcher(tool);
    }
}

fn adapt_matcher(matcher: &mut Value) {
    if let Some(fields) = matcher.as_object()
        && fields.len() == 1
        && let Some(glob) = fields.get("glob").filter(|value| value.is_string())
    {
        *matcher = glob.clone();
    }
}

fn validate_known<T: DeserializeOwned>(
    fields: Map<String, Value>,
    diagnostic: &'static str,
) -> Result<()> {
    T::deserialize(KnownFields(Value::Object(fields)))
        .map(|_| ())
        // Serde errors include authored values and keys. Do not retain their
        // Display, Debug, or source chain at the policy loading boundary.
        .map_err(|_| miette::miette!(diagnostic))
}

/// Use the canonical DTO's declared field list instead of duplicating it.
///
/// Unknown fields at this object belong to raw OPA data and remain untouched
/// in the installed document. Nested authored configuration still uses its
/// normal deserializer, including its own unknown-field restrictions.
struct KnownFields(Value);

impl<'de> Deserializer<'de> for KnownFields {
    type Error = serde_json::Error;

    fn deserialize_any<V: serde::de::Visitor<'de>>(
        self,
        visitor: V,
    ) -> std::result::Result<V::Value, Self::Error> {
        self.0.deserialize_any(visitor)
    }

    fn deserialize_struct<V: serde::de::Visitor<'de>>(
        mut self,
        _name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> std::result::Result<V::Value, Self::Error> {
        if let Value::Object(object) = &mut self.0 {
            object.retain(|name, _| fields.contains(&name.as_str()));
        }
        self.0.deserialize_any(visitor)
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string bytes
        byte_buf option unit unit_struct newtype_struct seq tuple tuple_struct
        map enum identifier ignored_any
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opa::{BAKED_POLICY_RULES, NetworkInput, OpaEngine};

    fn valid_policy() -> Value {
        serde_json::json!({
            "version": 1,
            "network_policies": {"private-policy-name": {
                "name": "private-policy-name",
                "endpoints": [{
                    "host": "private-policy-host.test", "port": 443,
                    "protocol": "rest", "enforcement": "enforce", "access": "full",
                    "deny_rules": [{"method": "DELETE", "path": "/**"}]
                }],
                "binaries": [{"path": "/usr/bin/curl"}]
            }}
        })
    }

    fn input(host: &str) -> NetworkInput {
        NetworkInput {
            host: host.to_string(),
            port: 443,
            binary_path: "/usr/bin/curl".into(),
            binary_sha256: String::new(),
            ancestors: Vec::new(),
            cmdline_paths: Vec::new(),
        }
    }

    #[test]
    fn raw_network_leaf_types_reject_before_startup_file_load_and_reload() {
        let valid = valid_policy();
        let source = valid.to_string();
        ryno_policy::parse_sandbox_policy(&source).expect("valid typed control");
        let active = OpaEngine::from_strings(BAKED_POLICY_RULES, &source).unwrap();
        let allowed = input("private-policy-host.test");
        let denied = input("unlisted.test");
        let generation = active.current_generation();
        let directory = tempfile::tempdir().unwrap();
        let rego_path = directory.path().join("policy.rego");
        let data_path = directory.path().join("policy.yaml");
        std::fs::write(&rego_path, BAKED_POLICY_RULES).unwrap();

        for (pointer, value) in [
            (
                "/endpoints/0/allow_encoded_slash",
                serde_json::json!("true"),
            ),
            (
                "/endpoints/0/websocket_credential_rewrite",
                serde_json::json!("true"),
            ),
            (
                "/endpoints/0/request_body_credential_rewrite",
                serde_json::json!("true"),
            ),
            (
                "/endpoints/0/allow_uninspected_credentials",
                serde_json::json!("true"),
            ),
            ("/endpoints/0/host", serde_json::json!(["private-value"])),
            ("/endpoints/0/port", serde_json::json!("443")),
            ("/endpoints/0/ports", serde_json::json!([443, "8443"])),
            ("/endpoints/0/tls", serde_json::json!(true)),
            ("/endpoints/0/protocol", serde_json::json!(false)),
            ("/endpoints/0/allowed_ips", serde_json::json!([7])),
            (
                "/endpoints/0/deny_rules/0/method",
                serde_json::json!(["DELETE"]),
            ),
            (
                "/endpoints/0/deny_rules/0/path",
                serde_json::json!(["/private-value"]),
            ),
            ("/endpoints/0/graphql_max_body_bytes", serde_json::json!(-1)),
            ("/binaries/0/path", serde_json::json!(["/private-value"])),
            ("/name", serde_json::json!(["private-value"])),
        ] {
            let mut candidate = valid.clone();
            let policy = &mut candidate["network_policies"]["private-policy-name"];
            let (parent, field) = pointer.rsplit_once('/').unwrap();
            policy.pointer_mut(parent).unwrap()[field] = value;
            let source = candidate.to_string();
            assert!(
                ryno_policy::parse_sandbox_policy(&source).is_err(),
                "{pointer}"
            );
            let startup = OpaEngine::from_strings(BAKED_POLICY_RULES, &source)
                .err()
                .expect("malformed leaf must reject at startup");
            std::fs::write(&data_path, &source).unwrap();
            let file = OpaEngine::from_files(&rego_path, &data_path)
                .err()
                .expect("malformed leaf must reject from files");
            let reload = active
                .reload(BAKED_POLICY_RULES, &source)
                .expect_err("malformed leaf must reject on reload");
            for error in [startup, file, reload] {
                for rendered in [
                    error.to_string(),
                    format!("{error:?}"),
                    format!("{error:#}"),
                ] {
                    assert!(rendered.len() <= 512, "{pointer}: {rendered}");
                    assert!(!rendered.contains("private-"), "{pointer}: {rendered}");
                }
            }
            assert_eq!(active.current_generation(), generation, "{pointer}");
            assert!(
                active.evaluate_network(&allowed).unwrap().allowed,
                "{pointer}"
            );
            assert!(
                !active.evaluate_network(&denied).unwrap().allowed,
                "{pointer}"
            );
        }
    }

    #[test]
    fn raw_network_validation_retains_runtime_forms_and_custom_data() {
        let mut data = valid_policy();
        data.as_object_mut().unwrap().remove("version");
        data["custom_rego_data"] = serde_json::json!({"private": [1, 2]});
        let endpoint = &mut data["network_policies"]["private-policy-name"]["endpoints"][0];
        endpoint["allow_encoded_slash"] = true.into();
        endpoint["provider_credentialed"] = true.into();
        endpoint["advisor_proposed"] = true.into();
        endpoint["policy_hash"] = "private-hash".into();
        endpoint["endpoint_id"] = "private-endpoint".into();
        endpoint["custom_metadata"] = serde_json::json!([null, {"extra": true}]);
        endpoint["deny_rules"][0]["query"] = serde_json::json!({
            "repo": {"glob": "private/*"}, "name": "", "org": {"any": ["one", "two"]}
        });
        let original = data.clone();
        validate_network_settings(&data).unwrap();
        assert_eq!(data, original);
        let engine = OpaEngine::from_strings(BAKED_POLICY_RULES, &data.to_string()).unwrap();
        let endpoint = engine
            .query_endpoint_config(&input("private-policy-host.test"))
            .unwrap()
            .unwrap();
        let endpoint: Value = serde_json::from_str(&endpoint.to_string()).unwrap();
        assert_eq!(endpoint["allow_encoded_slash"], true);
        assert_eq!(endpoint["provider_credentialed"], true);
        assert_eq!(endpoint["policy_hash"], "private-hash");
        assert_eq!(
            endpoint["custom_metadata"],
            original["network_policies"]["private-policy-name"]["endpoints"][0]["custom_metadata"]
        );

        let mut null_query = valid_policy();
        null_query["network_policies"]["private-policy-name"]["endpoints"][0]["deny_rules"][0]["query"] =
            Value::Null;
        OpaEngine::from_strings(BAKED_POLICY_RULES, &null_query.to_string()).unwrap();

        for protocol in ["json-rpc", "mcp"] {
            let mut data = valid_policy();
            let endpoint = &mut data["network_policies"]["private-policy-name"]["endpoints"][0];
            endpoint["protocol"] = protocol.into();
            endpoint.as_object_mut().unwrap().remove("access");
            endpoint.as_object_mut().unwrap().remove("deny_rules");
            endpoint["json_rpc_max_body_bytes"] = 4096.into();
            endpoint["rules"] = serde_json::json!([{"allow": {"method": "tools/call"}}]);
            if protocol == "mcp" {
                endpoint["mcp_versions"] = serde_json::json!(["2025-11-25"]);
                endpoint["mcp_strict_tool_names"] = false.into();
                endpoint["mcp_allow_all_known_mcp_methods"] = true.into();
                // Non-strict MCP names require an exact tool selector; glob
                // syntax is permitted only when strict names are enabled.
                endpoint["rules"][0]["allow"]["params"] =
                    serde_json::json!({"name": {"glob": "read_tool"}});
            }
            OpaEngine::from_strings(BAKED_POLICY_RULES, &data.to_string()).unwrap();
        }
    }

    #[test]
    fn raw_network_runtime_fields_and_rule_scalars_reject_malformed_values() {
        for (field, value) in [
            ("json_rpc_max_body_bytes", serde_json::json!("4096")),
            ("mcp_strict_tool_names", serde_json::json!("false")),
            ("mcp_allow_all_known_mcp_methods", Value::Null),
            ("mcp_versions", serde_json::json!([42])),
            ("provider_credentialed", serde_json::json!("false")),
            ("advisor_proposed", serde_json::json!(1)),
            ("endpoint_id", serde_json::json!(["id"])),
            ("policy_hash", serde_json::json!(false)),
        ] {
            let mut data = valid_policy();
            data["network_policies"]["private-policy-name"]["endpoints"][0][field] = value;
            assert!(
                OpaEngine::from_strings(BAKED_POLICY_RULES, &data.to_string()).is_err(),
                "{field}"
            );
        }
        for nested in [true, false] {
            for (field, value) in [
                ("method", serde_json::json!(["GET"])),
                ("path", serde_json::json!(["/**"])),
                ("command", serde_json::json!(true)),
                ("operation_name", serde_json::json!(42)),
                ("fields", serde_json::json!([42])),
                ("query", serde_json::json!({"name": {"glob": 1}})),
            ] {
                let mut data = valid_policy();
                let endpoint = &mut data["network_policies"]["private-policy-name"]["endpoints"][0];
                endpoint.as_object_mut().unwrap().remove("access");
                let mut rule = serde_json::json!({"method": "GET", "path": "/**"});
                rule[field] = value;
                endpoint["rules"] = if nested {
                    serde_json::json!([{"allow": rule}])
                } else {
                    serde_json::json!([rule])
                };
                assert!(
                    OpaEngine::from_strings(BAKED_POLICY_RULES, &data.to_string()).is_err(),
                    "{nested}: {field}"
                );
            }
        }
    }
}
