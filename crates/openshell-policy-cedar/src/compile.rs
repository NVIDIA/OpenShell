// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Rust guideline compliant 2026-09-30

//! Compiles normalized sandbox network-policy JSON into a generated Cedar
//! `PolicySet`.
//!
//! The input is the same `data.sandbox.*` shape
//! `openshell_supervisor_network::opa::proto_to_opa_data_json` produces for
//! Rego, so normalization (port/protocol handling) is never re-derived.
//! This compiler is scoped to the CONNECT-time decision
//! (`authorize_egress_intent`): host:port matching and binary/ancestor
//! matching only. L7 rules (`rules`/`deny_rules`) are a separate call site
//! and are not read here.
//!
//! Cedar has no loops/comprehensions, so it cannot test "does any element
//! of a dynamic collection match a pattern" — this makes ancestor-glob
//! matching permanently inexpressible (see [`crate::glob`]). Everything
//! else here is expressible as plain Cedar `Set` membership/glob checks.
//! This compiler generates **one Cedar policy per named network policy**
//! (not per rule), since Rego requires one common policy name to satisfy
//! both endpoint and binary matching together
//! (`sandbox-policy.rego:94-101`) — flattening all policies' allowlists
//! into one global fact base would silently allow cross-policy
//! combinations Rego never grants.
//!
//! A named policy is compiled only if every one of its endpoints has an
//! exact or segment-safe-glob host, **and** every one of its binaries is an
//! exact path. Binary globs — segment-safe or not — are always left
//! uncompiled: Rego's binary-glob rule also matches against the ancestor
//! set, and ancestor-glob can never be represented in Cedar, so a glob
//! binary pattern can never be faithfully compiled either. A named policy
//! left uncompiled for any reason is skipped entirely (not partially
//! compiled) and must be checked with [`UncompiledPolicy::matches`] before
//! trusting a Cedar `Deny` — see [`CompiledCedarPolicy`].

use std::fmt::Write as _;
use std::str::FromStr;

use cedar_policy::PolicySet;
use openshell_policy_cedar_schema::{actions, context_fields, endpoint_fields, entity_types};
use serde_json::Value;

use crate::CedarEngineError;
use crate::glob::{GlobClass, classify_glob, matches_segmented};

/// One network endpoint pattern from an authored policy: a (possibly glob)
/// host and the ports it applies to.
#[derive(Debug, Clone)]
pub struct EndpointPattern {
    /// Exact or glob host pattern, as authored.
    pub host: String,
    /// Ports this pattern applies to.
    pub ports: Vec<u16>,
}

/// A named network policy this compiler could not fully represent in
/// Cedar.
///
/// Must be checked via [`UncompiledPolicy::matches`] against every request
/// before trusting a Cedar `Deny` from [`CompiledCedarPolicy::policies`],
/// since Cedar has no knowledge of this policy's content at all — an
/// omission here would silently under-report what Rego actually allows.
#[derive(Debug, Clone)]
pub struct UncompiledPolicy {
    /// The `network_policies` key.
    pub name: String,
    /// Why this policy couldn't be compiled.
    pub reason: String,
    /// This policy's endpoint patterns, exactly as authored.
    pub endpoints: Vec<EndpointPattern>,
    /// Binary path patterns (exact or glob), as authored. Matched against
    /// both the request's binary path and its ancestor list, mirroring
    /// Rego's `binary_allowed` glob rule.
    pub binaries: Vec<String>,
}

impl UncompiledPolicy {
    /// True if `host`/`port`/`binary_path`/`ancestors` would have matched
    /// this policy under Rego's `network_policy_for_request` semantics.
    #[must_use]
    pub fn matches(&self, host: &str, port: u16, binary_path: &str, ancestors: &[String]) -> bool {
        let host_lower = host.to_lowercase();
        let endpoint_matches = self.endpoints.iter().any(|ep| {
            ep.ports.contains(&port) && matches_segmented(&ep.host.to_lowercase(), '.', &host_lower)
        });
        if !endpoint_matches {
            return false;
        }
        self.binaries.iter().any(|pattern| {
            matches_segmented(pattern, '/', binary_path)
                || ancestors.iter().any(|a| matches_segmented(pattern, '/', a))
        })
    }
}

/// Output of [`compile_normalized_data`].
#[derive(Debug)]
pub struct CompiledCedarPolicy {
    /// Generated Cedar policies for every fully-compilable named policy.
    pub policies: PolicySet,
    /// Named policies left out of `policies`. See [`UncompiledPolicy`].
    pub uncompiled: Vec<UncompiledPolicy>,
}

/// Compiles normalized `data.sandbox.*` JSON (as produced by
/// `openshell_supervisor_network::opa::proto_to_opa_data_json`) into a
/// [`CompiledCedarPolicy`].
///
/// # Errors
///
/// Returns [`CedarEngineError`] if the generated Cedar policy text fails to
/// parse. This indicates a bug in this compiler, not a caller-input error:
/// the generator only ever emits syntax it fully controls, with all values
/// escaped via [`cedar_string_literal`].
pub fn compile_normalized_data(data: &Value) -> Result<CompiledCedarPolicy, CedarEngineError> {
    let require_binary_identity = data
        .get("runtime")
        .and_then(|runtime| runtime.get("require_binary_identity"))
        .and_then(Value::as_bool)
        .unwrap_or(true);

    let empty = serde_json::Map::new();
    let network_policies = data
        .get("network_policies")
        .and_then(Value::as_object)
        .unwrap_or(&empty);

    let mut cedar_src = String::new();
    let mut uncompiled = Vec::new();

    for (name, policy) in network_policies {
        let endpoints = parse_endpoints(policy);
        let binaries = parse_binaries(policy);

        match classify_endpoints(&endpoints) {
            Some(endpoint_conditions) if binaries.iter().all(|b| is_exact(b)) => {
                write_policy(
                    &mut cedar_src,
                    name,
                    &endpoint_conditions,
                    &binaries,
                    require_binary_identity,
                );
            }
            Some(_) => uncompiled.push(UncompiledPolicy {
                name: name.clone(),
                reason: "one or more binaries is a glob pattern; binary globs also match \
                         against the ancestor list, which Cedar cannot represent"
                    .to_string(),
                endpoints,
                binaries,
            }),
            None => uncompiled.push(UncompiledPolicy {
                name: name.clone(),
                reason: "one or more endpoints has a segment-unsafe host glob (a standalone \
                         `*` not part of a `**` run)"
                    .to_string(),
                endpoints,
                binaries,
            }),
        }
    }

    let policies =
        PolicySet::from_str(&cedar_src).map_err(|e| CedarEngineError::PolicyParse(Box::new(e)))?;
    Ok(CompiledCedarPolicy {
        policies,
        uncompiled,
    })
}

fn is_exact(pattern: &str) -> bool {
    matches!(classify_glob(pattern), GlobClass::Exact(_))
}

fn parse_endpoints(policy: &Value) -> Vec<EndpointPattern> {
    policy
        .get("endpoints")
        .and_then(Value::as_array)
        .map(|endpoints| {
            endpoints
                .iter()
                .filter_map(|endpoint| {
                    let host = endpoint.get("host")?.as_str()?.to_string();
                    let ports = endpoint
                        .get("ports")
                        .and_then(Value::as_array)?
                        .iter()
                        .filter_map(Value::as_u64)
                        .filter_map(|p| u16::try_from(p).ok())
                        .collect();
                    Some(EndpointPattern { host, ports })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn parse_binaries(policy: &Value) -> Vec<String> {
    policy
        .get("binaries")
        .and_then(Value::as_array)
        .map(|binaries| {
            binaries
                .iter()
                .filter_map(|b| b.get("path")?.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// One endpoint condition ready to render into a Cedar `when` clause.
enum EndpointCondition {
    /// Combined into one `Set.contains()` check for the whole policy.
    ExactHostPort(String),
    /// One `.like()` clause per safe glob pattern.
    SafeGlobHostPort { host_pattern: String, port: u16 },
}

/// Classifies every endpoint in `endpoints`. Returns `None` if any endpoint
/// has a segment-unsafe host glob.
fn classify_endpoints(endpoints: &[EndpointPattern]) -> Option<Vec<EndpointCondition>> {
    let mut conditions = Vec::new();
    for endpoint in endpoints {
        match classify_glob(&endpoint.host) {
            GlobClass::Exact(host) => {
                let host = host.to_lowercase();
                for &port in &endpoint.ports {
                    conditions.push(EndpointCondition::ExactHostPort(format!("{host}:{port}")));
                }
            }
            GlobClass::SafeGlob(pattern) => {
                let host_pattern = pattern.to_lowercase();
                for &port in &endpoint.ports {
                    conditions.push(EndpointCondition::SafeGlobHostPort {
                        host_pattern: host_pattern.clone(),
                        port,
                    });
                }
            }
            GlobClass::Unsafe => return None,
        }
    }
    Some(conditions)
}

/// Appends one generated `permit` policy for `name` to `cedar_src`.
fn write_policy(
    cedar_src: &mut String,
    name: &str,
    endpoint_conditions: &[EndpointCondition],
    binaries: &[String],
    require_binary_identity: bool,
) {
    let exact_host_ports: Vec<&str> = endpoint_conditions
        .iter()
        .filter_map(|c| match c {
            EndpointCondition::ExactHostPort(hp) => Some(hp.as_str()),
            EndpointCondition::SafeGlobHostPort { .. } => None,
        })
        .collect();

    let mut endpoint_clauses = Vec::new();
    if !exact_host_ports.is_empty() {
        let set_literal = exact_host_ports
            .iter()
            .map(|hp| cedar_string_literal(hp))
            .collect::<Vec<_>>()
            .join(", ");
        endpoint_clauses.push(format!(
            "[{set_literal}].contains(resource.{})",
            endpoint_fields::HOST_PORT
        ));
    }
    for condition in endpoint_conditions {
        if let EndpointCondition::SafeGlobHostPort { host_pattern, port } = condition {
            endpoint_clauses.push(format!(
                "(resource.{host_field} like {pattern} && resource.{port_field} == {port})",
                host_field = endpoint_fields::HOST,
                pattern = cedar_string_literal(host_pattern),
                port_field = endpoint_fields::PORT,
            ));
        }
    }

    let binary_clause = if require_binary_identity {
        if binaries.is_empty() {
            // Rego requires at least one `policy.binaries[_]` entry to
            // match; an empty list can never satisfy `binary_allowed`.
            "false".to_string()
        } else {
            let set_literal = binaries
                .iter()
                .map(|b| cedar_string_literal(b))
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "([{set_literal}].contains(context.{binary_field}) \
                 || context.{ancestors_field}.containsAny([{set_literal}]))",
                binary_field = context_fields::BINARY_PATH,
                ancestors_field = context_fields::ANCESTORS,
            )
        }
    } else {
        "true".to_string()
    };

    let _ = writeln!(
        cedar_src,
        "// network_policies.{comment_name}\n\
         permit(\n  \
           principal is {process},\n  \
           action == {action_type}::{action_id},\n  \
           resource is {endpoint}\n\
         )\nwhen {{\n  ({endpoint_clauses}) && {binary_clause}\n}};\n",
        comment_name = name.replace(['\n', '\r'], " "),
        process = entity_types::PROCESS,
        action_type = actions::ACTION_TYPE,
        action_id = cedar_string_literal(actions::NETWORK_CONNECT),
        endpoint = entity_types::NETWORK_ENDPOINT,
        endpoint_clauses = endpoint_clauses.join(" || "),
    );
}

/// Renders `value` as an escaped Cedar string literal (`"..."`, with `\`
/// and `"` escaped).
fn cedar_string_literal(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}
