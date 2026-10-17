// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provider rules of a Cedar sandbox, compiled to Cedar for token grants.
//!
//! The gateway delivers attached providers' rules to a Cedar sandbox in
//! `provider_credential_rules`, with each endpoint stamped with the owner of
//! its token grants. This module validates and normalizes them as the YAML
//! engine would load them (protocol spellings, MCP tool aliases, access
//! presets, and symlinked binaries resolved in the sandbox), then hands them
//! to [`TokenGrantRules`], which compiles them to Cedar. No Rego is involved.

use std::collections::HashMap;

use miette::Result;
use openshell_core::proto::{NetworkPolicyRule, SandboxPolicy as ProtoSandboxPolicy};
use openshell_ocsf::{ConfigStateChangeBuilder, SeverityId, StateId, StatusId, ocsf_emit};
use openshell_policy_cedar::{
    ProviderEndpoint, ProviderPolicy, RuleMatcher, TokenGrantRules, ValueMatcher,
};
use serde_json::Value;

use crate::policy_data::{
    endpoint_policy_value, normalize_endpoint_protocols, normalize_l7_policy_rule_aliases,
};

/// Compiles provider rules for token-grant owner selection.
///
/// Returns `None` when no provider endpoint carries an owner. Binary paths
/// are resolved in the root filesystem of `entrypoint_pid` (none when it is
/// 0), as a YAML sandbox resolves them.
///
/// # Errors
///
/// Returns an error when the rules fail the validation a YAML sandbox
/// applies to them, or the generated Cedar does not load.
pub fn compile(
    rules: &HashMap<String, NetworkPolicyRule>,
    entrypoint_pid: u32,
) -> Result<Option<TokenGrantRules>> {
    let stamped = rules
        .values()
        .flat_map(|rule| &rule.endpoints)
        .any(|endpoint| !endpoint.token_grant_owner.is_empty());
    if !stamped {
        return Ok(None);
    }
    let policies = provider_policies(rules, entrypoint_pid)?;
    let compiled = TokenGrantRules::compile(&policies)
        .map_err(|e| miette::miette!("provider credential rules failed to compile: {e}"))?;
    report(&compiled);
    Ok(Some(compiled))
}

/// Validates and normalizes `rules` into the compiler's input.
fn provider_policies(
    rules: &HashMap<String, NetworkPolicyRule>,
    entrypoint_pid: u32,
) -> Result<Vec<ProviderPolicy>> {
    let policy = openshell_policy::validate_and_canonicalize_sandbox_policy(ProtoSandboxPolicy {
        network_policies: rules.clone(),
        ..Default::default()
    })
    .map_err(|error| {
        miette::miette!(
            "provider credential rules failed validation ({} violations)",
            error.violations().len()
        )
    })?;
    let ambiguities = openshell_policy::find_endpoint_ambiguities(&policy);
    if !ambiguities.is_empty() {
        return Err(miette::miette!(
            "provider credential rules have {} ambiguous endpoint selectors",
            ambiguities.len()
        ));
    }

    let network_policies: serde_json::Map<String, Value> = policy
        .network_policies
        .iter()
        .map(|(key, rule)| {
            let binaries: Vec<Value> = rule
                .binaries
                .iter()
                .flat_map(|binary| {
                    let resolved = crate::binary_resolution::resolve_policy_binary(
                        &binary.path,
                        entrypoint_pid,
                    );
                    std::iter::once(binary.path.clone()).chain(resolved)
                })
                .map(|path| serde_json::json!({ "path": path }))
                .collect();
            let endpoints: Vec<Value> = rule
                .endpoints
                .iter()
                .map(|endpoint| endpoint_policy_value(endpoint, ""))
                .collect();
            (
                key.clone(),
                serde_json::json!({ "endpoints": endpoints, "binaries": binaries }),
            )
        })
        .collect();
    let mut data = serde_json::json!({ "network_policies": network_policies });
    normalize_endpoint_protocols(&mut data);
    let (errors, _) = crate::l7::validate_l7_policies(&data);
    if !errors.is_empty() {
        return Err(miette::miette!(
            "provider credential rules have {} invalid L7 configurations",
            errors.len()
        ));
    }
    normalize_l7_policy_rule_aliases(&mut data);
    let _ = crate::l7::expand_access_presets(&mut data);

    let mut policies: Vec<ProviderPolicy> = data["network_policies"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(name, policy)| ProviderPolicy {
            name: name.clone(),
            binaries: strings(&policy["binaries"], |binary| binary["path"].as_str()),
            endpoints: policy["endpoints"]
                .as_array()
                .into_iter()
                .flatten()
                .map(provider_endpoint)
                .collect(),
        })
        .collect();
    policies.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(policies)
}

/// Collects the strings `get` reads from each element of `array`.
fn strings<'a>(array: &'a Value, get: impl Fn(&'a Value) -> Option<&'a str>) -> Vec<String> {
    array
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(get)
        .map(str::to_string)
        .collect()
}

fn text(value: &Value, key: &str) -> String {
    value[key].as_str().unwrap_or_default().to_string()
}

/// Reads one normalized endpoint as the Rego rules read it.
fn provider_endpoint(endpoint: &Value) -> ProviderEndpoint {
    ProviderEndpoint {
        host: text(endpoint, "host"),
        ports: endpoint["ports"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_u64)
            .filter_map(|port| u16::try_from(port).ok())
            .collect(),
        path: text(endpoint, "path"),
        has_allowed_ips: endpoint["allowed_ips"]
            .as_array()
            .is_some_and(|ips| !ips.is_empty()),
        protocol: text(endpoint, "protocol"),
        token_grant_owner: text(endpoint, "token_grant_owner"),
        mcp_allow_all_known_methods: endpoint["mcp_allow_all_known_mcp_methods"]
            .as_bool()
            .unwrap_or(false),
        // Rego reads an allow rule's selectors under `allow`.
        rules: endpoint["rules"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|rule| rule.get("allow"))
            .map(rule_matcher)
            .collect(),
        deny_rules: endpoint["deny_rules"]
            .as_array()
            .into_iter()
            .flatten()
            .map(rule_matcher)
            .collect(),
    }
}

fn rule_matcher(rule: &Value) -> RuleMatcher {
    let selector = |key: &str| rule.get(key).and_then(Value::as_str).map(str::to_string);
    RuleMatcher {
        method: selector("method"),
        path: selector("path"),
        command: selector("command"),
        operation_type: selector("operation_type"),
        operation_name: selector("operation_name"),
        fields: strings(&rule["fields"], Value::as_str),
        query: value_matchers(&rule["query"]),
        params: value_matchers(&rule["params"]),
    }
}

/// Reads matchers as `query_value_matches` does: a string is one glob, and
/// an object matches its non-empty `glob` or any of its `any` globs.
fn value_matchers(matchers: &Value) -> std::collections::BTreeMap<String, ValueMatcher> {
    matchers
        .as_object()
        .into_iter()
        .flatten()
        .map(|(key, matcher)| {
            let mut globs = Vec::new();
            if let Some(glob) = matcher.as_str() {
                globs.push(glob.to_string());
            }
            if let Some(glob) = matcher["glob"].as_str().filter(|glob| !glob.is_empty()) {
                globs.push(glob.to_string());
            }
            globs.extend(strings(&matcher["any"], Value::as_str));
            (key.clone(), ValueMatcher { globs })
        })
        .collect()
}

/// Reports provider selectors compiled other than exactly.
fn report(compiled: &TokenGrantRules) {
    if compiled.untranslated().is_empty() {
        return;
    }
    let notes: Vec<String> = compiled
        .untranslated()
        .iter()
        .map(ToString::to_string)
        .collect();
    let (severity, summary) = if compiled.fail_closed_reason().is_some() {
        (
            SeverityId::Medium,
            "no token grant is admitted for any request",
        )
    } else {
        (
            SeverityId::Low,
            "some token grants are admitted for fewer requests",
        )
    };
    tracing::warn!(rules = ?notes, "provider rules not translated exactly to Cedar; {summary}");
    ocsf_emit!(
        ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
            .severity(severity)
            .status(StatusId::Success)
            .state(StateId::Enabled, "provider token grants compiled")
            .unmapped("untranslated_provider_rules", serde_json::json!(notes))
            .message(format!(
                "CONFIG:TOKEN_GRANTS provider rules not translated exactly to Cedar [count:{}]; {summary}",
                notes.len()
            ))
            .build()
    );
}
