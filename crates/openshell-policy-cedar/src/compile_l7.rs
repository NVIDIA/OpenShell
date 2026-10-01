// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Rust guideline compliant 2026-10-01

//! Compiles normalized sandbox network-policy JSON's `rules`/`deny_rules`
//! (per-request L7 enforcement) into a generated Cedar `PolicySet` for the
//! `HttpRequest` action.
//!
//! Sibling to [`crate::compile`], which handles the CONNECT-time decision
//! only. Reuses its endpoint/binary classification: an L7 policy is
//! generated for a named policy only if its CONNECT-time endpoint/binary
//! shape is also compilable, since Rego's `allow_request` requires the same
//! `endpoint_allowed`/`binary_allowed` checks before consulting `rules` —
//! see `sandbox-policy.rego`'s `_policy_allows_l7`/`_policy_denies_l7`.
//!
//! In scope: REST `method`+`path` (exact or segment-safe glob), SQL
//! `command` (exact), JSON-RPC `method` (exact only — segment-safe glob
//! needs Cedar's upcoming delimiter/glob support). A rule using `query`,
//! `operation_type`/`operation_name`/`fields` (GraphQL), `tool`, or
//! `params` (MCP params), or any endpoint whose `protocol` is `"mcp"` or
//! `"graphql"`, leaves the whole named policy uncompiled — those need
//! Cedar's open-records support (query/param matchers) or full glob.match
//! semantics (MCP method aliases), neither of which exists yet. `method`/
//! `command` are compared case-sensitively: Rego case-folds via `upper()`,
//! which Cedar has no equivalent for. Authored patterns are expected in the
//! same case the runtime sends (HTTP verbs and SQL commands are already
//! uppercase off the wire), so this is a minor fidelity simplification, not
//! a coverage gap.

use std::str::FromStr;

use cedar_policy::PolicySet;
use openshell_policy_cedar_schema::{actions, context_fields, entity_types};
use serde_json::{Map, Value};

use crate::CedarEngineError;
use crate::compile::{
    cedar_string_literal, classify_endpoints, is_exact, parse_binaries, parse_endpoints,
    render_binary_clause, render_endpoint_clause,
};
use crate::glob::{GlobClass, classify_glob};

/// A named network policy this compiler could not represent for L7.
///
/// Unlike [`crate::compile::UncompiledPolicy`], this only means the
/// policy's L7 `rules`/`deny_rules` aren't compiled — its CONNECT-time
/// decision (if separately compilable) is unaffected.
#[derive(Debug, Clone)]
pub struct UncompiledL7Policy {
    /// The `network_policies` key.
    pub name: String,
    /// Why this policy's L7 rules couldn't be compiled.
    pub reason: String,
}

/// Output of [`compile_l7`].
#[derive(Debug)]
pub struct CompiledL7Policy {
    /// Generated Cedar `HttpRequest` policies for every fully-compilable
    /// named policy's L7 rules.
    pub policies: PolicySet,
    /// Named policies whose L7 rules were left out of `policies`. See
    /// [`UncompiledL7Policy`].
    pub uncompiled: Vec<UncompiledL7Policy>,
}

/// Compiles normalized `data.sandbox.*` JSON (as produced by
/// `openshell_supervisor_network::opa::proto_to_opa_data_json`) into a
/// [`CompiledL7Policy`].
///
/// # Errors
///
/// Returns [`CedarEngineError`] if the generated Cedar policy text fails to
/// parse — indicates a bug in this compiler, not a caller-input error.
pub fn compile_l7(data: &Value) -> Result<CompiledL7Policy, CedarEngineError> {
    let require_binary_identity = data
        .get("runtime")
        .and_then(|runtime| runtime.get("require_binary_identity"))
        .and_then(Value::as_bool)
        .unwrap_or(true);

    let empty = Map::new();
    let network_policies = data
        .get("network_policies")
        .and_then(Value::as_object)
        .unwrap_or(&empty);

    let mut cedar_src = String::new();
    let mut uncompiled = Vec::new();

    for (name, policy) in network_policies {
        let endpoints = parse_endpoints(policy);
        let binaries = parse_binaries(policy);

        let Some(endpoint_conditions) = classify_endpoints(&endpoints) else {
            uncompiled.push(UncompiledL7Policy {
                name: name.clone(),
                reason: "one or more endpoints has a segment-unsafe host glob".to_string(),
            });
            continue;
        };
        if !binaries.iter().all(|b| is_exact(b)) {
            uncompiled.push(UncompiledL7Policy {
                name: name.clone(),
                reason: "one or more binaries is a glob pattern".to_string(),
            });
            continue;
        }

        let empty_eps = Vec::new();
        let endpoints_json = policy
            .get("endpoints")
            .and_then(Value::as_array)
            .unwrap_or(&empty_eps);

        match compile_rule_clauses(endpoints_json) {
            Some((allow_clauses, deny_clauses)) => {
                if allow_clauses.is_empty() && deny_clauses.is_empty() {
                    // No endpoint in this policy has any `rules`/`deny_rules`
                    // configured; Rego's `request_allowed_for_endpoint`
                    // requires an explicit rule match, so an endpoint with
                    // none never grants any L7 request. Nothing to compile,
                    // and not an uncompiled case either.
                    continue;
                }
                let endpoint_clause = render_endpoint_clause(&endpoint_conditions);
                let binary_clause = render_binary_clause(&binaries, require_binary_identity);
                write_l7_policies(
                    &mut cedar_src,
                    name,
                    &endpoint_clause,
                    &binary_clause,
                    &allow_clauses,
                    &deny_clauses,
                );
            }
            None => uncompiled.push(UncompiledL7Policy {
                name: name.clone(),
                reason: "one or more rules uses a matcher Cedar cannot yet represent \
                         (query params, GraphQL operation/field, MCP tool/params) or an \
                         unsupported endpoint protocol (mcp, graphql)"
                    .to_string(),
            }),
        }
    }

    let policies =
        PolicySet::from_str(&cedar_src).map_err(|e| CedarEngineError::PolicyParse(Box::new(e)))?;
    Ok(CompiledL7Policy {
        policies,
        uncompiled,
    })
}

/// Compiles every endpoint's `rules`/`deny_rules` for one named policy into
/// Cedar `when`-clause fragments. Returns `None` if any rule or endpoint
/// uses a matcher outside this compiler's scope.
fn compile_rule_clauses(endpoints_json: &[Value]) -> Option<(Vec<String>, Vec<String>)> {
    let mut allow_clauses = Vec::new();
    let mut deny_clauses = Vec::new();

    for endpoint in endpoints_json {
        let protocol = endpoint
            .get("protocol")
            .and_then(Value::as_str)
            .unwrap_or("");
        if matches!(protocol, "mcp" | "graphql") {
            // Any rules at all on an MCP/GraphQL endpoint need matching this
            // compiler doesn't implement; a REST/SQL/JSON-RPC rule on such
            // an endpoint would be an authoring mistake Rego still honors
            // for its own protocol-specific branches, so don't guess here.
            if has_any_rules(endpoint) {
                return None;
            }
            continue;
        }

        let empty = Vec::new();
        let rules = endpoint
            .get("rules")
            .and_then(Value::as_array)
            .unwrap_or(&empty);
        for rule in rules {
            let allow = rule.get("allow");
            let clause = allow.and_then(|allow| compile_rule_clause(allow, protocol))?;
            allow_clauses.push(clause);
        }

        let deny_rules = endpoint
            .get("deny_rules")
            .and_then(Value::as_array)
            .unwrap_or(&empty);
        for rule in deny_rules {
            let clause = compile_rule_clause(rule, protocol)?;
            deny_clauses.push(clause);
        }
    }

    Some((allow_clauses, deny_clauses))
}

fn has_any_rules(endpoint: &Value) -> bool {
    endpoint
        .get("rules")
        .and_then(Value::as_array)
        .is_some_and(|r| !r.is_empty())
        || endpoint
            .get("deny_rules")
            .and_then(Value::as_array)
            .is_some_and(|r| !r.is_empty())
}

/// Keys this compiler understands on a rule object. Any other key present
/// (`query`, `operation_type`, `operation_name`, `fields`, `tool`,
/// `params`) takes the whole policy's L7 rules out of scope.
const SUPPORTED_RULE_KEYS: [&str; 3] = ["method", "path", "command"];

/// Compiles one `rules[].allow` or `deny_rules[]` object into a Cedar
/// boolean expression, or `None` if it uses an unsupported matcher.
fn compile_rule_clause(rule: &Value, protocol: &str) -> Option<String> {
    let obj = rule.as_object()?;
    if obj
        .keys()
        .any(|k| !SUPPORTED_RULE_KEYS.contains(&k.as_str()))
    {
        return None;
    }

    let mut subclauses = Vec::new();

    if let Some(command) = obj.get("command").and_then(Value::as_str) {
        subclauses.push(sql_command_clause(command));
    }

    if let Some(method) = obj.get("method").and_then(Value::as_str) {
        let path = obj.get("path").and_then(Value::as_str);
        match protocol {
            "json-rpc" => subclauses.push(jsonrpc_method_clause(method)),
            _ => match path {
                None => subclauses.push("false".to_string()),
                Some(path) => subclauses.push(rest_method_path_clause(method, path)?),
            },
        }
    }

    if subclauses.is_empty() {
        // A rule object with neither `command` nor `method` never matches
        // under Rego either (both `request_allowed_for_endpoint` branches
        // require one of them to be present).
        return Some("false".to_string());
    }
    Some(format!("({})", subclauses.join(" || ")))
}

fn sql_command_clause(command: &str) -> String {
    if command == "*" {
        return "true".to_string();
    }
    format!(
        "context.{field} == {lit}",
        field = context_fields::COMMAND,
        lit = cedar_string_literal(command)
    )
}

fn jsonrpc_method_clause(method: &str) -> String {
    if method == "*" {
        return format!(
            "context.{field} != \"\"",
            field = context_fields::JSONRPC_METHOD
        );
    }
    format!(
        "context.{field} == {lit}",
        field = context_fields::JSONRPC_METHOD,
        lit = cedar_string_literal(method)
    )
}

fn rest_method_path_clause(method: &str, path: &str) -> Option<String> {
    let method_clause = if method == "*" {
        "true".to_string()
    } else {
        format!(
            "context.{field} == {lit}",
            field = context_fields::METHOD,
            lit = cedar_string_literal(method)
        )
    };
    let path_clause = match classify_glob(path) {
        GlobClass::Exact(p) => format!(
            "context.{field} == {lit}",
            field = context_fields::PATH,
            lit = cedar_string_literal(p)
        ),
        GlobClass::SafeGlob(p) => format!(
            "context.{field} like {lit}",
            field = context_fields::PATH,
            lit = cedar_string_literal(p)
        ),
        GlobClass::Unsafe => return None,
    };
    Some(format!("({method_clause} && {path_clause})"))
}

/// Appends one generated `permit` (from `allow_clauses`) and, if
/// `deny_clauses` is non-empty, one generated `forbid` policy for `name` to
/// `cedar_src`. Cedar's `forbid`-overrides-`permit` precedence matches
/// Rego's "deny rules take precedence" rule directly.
fn write_l7_policies(
    cedar_src: &mut String,
    name: &str,
    endpoint_clause: &str,
    binary_clause: &str,
    allow_clauses: &[String],
    deny_clauses: &[String],
) {
    use std::fmt::Write as _;

    let comment_name = name.replace(['\n', '\r'], " ");
    if !allow_clauses.is_empty() {
        let _ = writeln!(
            cedar_src,
            "// network_policies.{comment_name} (L7 allow)\n\
             permit(\n  \
               principal is {process},\n  \
               action == {action_type}::{action_id},\n  \
               resource is {endpoint}\n\
             )\nwhen {{\n  {endpoint_clause} && {binary_clause} && ({rule_clauses})\n}};\n",
            process = entity_types::PROCESS,
            action_type = actions::ACTION_TYPE,
            action_id = cedar_string_literal(actions::HTTP_REQUEST),
            endpoint = entity_types::NETWORK_ENDPOINT,
            rule_clauses = allow_clauses.join(" || "),
        );
    }
    if !deny_clauses.is_empty() {
        let _ = writeln!(
            cedar_src,
            "// network_policies.{comment_name} (L7 deny)\n\
             forbid(\n  \
               principal is {process},\n  \
               action == {action_type}::{action_id},\n  \
               resource is {endpoint}\n\
             )\nwhen {{\n  {endpoint_clause} && {binary_clause} && ({rule_clauses})\n}};\n",
            process = entity_types::PROCESS,
            action_type = actions::ACTION_TYPE,
            action_id = cedar_string_literal(actions::HTTP_REQUEST),
            endpoint = entity_types::NETWORK_ENDPOINT,
            rule_clauses = deny_clauses.join(" || "),
        );
    }
}
