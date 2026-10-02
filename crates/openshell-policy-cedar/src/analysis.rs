// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Load-time checks that an authored policy set is enforced exactly as written.
//!
//! Cedar evaluates `NetworkConnect` and `HttpRequest` at request time, so any
//! condition an author writes on those actions is enforced by Cedar itself.
//! Three things are *not* decided by Cedar at request time, and are instead
//! derived from the policy text once, here:
//!
//! - **Landlock grants.** Landlock is a flat allow-list of path subtrees
//!   applied at sandbox start. Only filesystem policies whose meaning is
//!   exactly "this process may read/write these subtrees" are accepted:
//!   `permit`, an action scope of `ReadFile`/`WriteFile` only, an
//!   unconstrained principal, and paths named either as
//!   `resource in Sandbox::FilesystemPath::"/p"` in the scope, or as a `when`
//!   clause that is only an `||` of such `resource in` tests. Anything else
//!   (`forbid`, other conditions, `resource ==`, a principal constraint) is
//!   rejected, because Landlock would grant more than the policy says.
//! - **L7 inspection routing.** The proxy must decide at CONNECT time whether
//!   to inspect a connection per request. Every policy that can apply to
//!   `HttpRequest` must therefore name its endpoint literally in the scope,
//!   and every endpoint so named is inspected. An `HttpRequest` policy the
//!   proxy could not route would otherwise be silently skipped.
//! - **DNS eligibility.** Exact `NetworkConnect` endpoints named in a
//!   `permit` scope are eligible for policy DNS. Endpoints reachable only
//!   through a condition (for example `resource.host like "*.example.com"`)
//!   are not, which fails closed.
//!
//! Before any of that, the policy set is validated against the schema in
//! strict mode, so a typo such as `context.binray_path` is a load error
//! rather than a policy Cedar silently skips at request time.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use cedar_policy::{
    ActionConstraint, Effect, EntityUid, Policy, PolicySet, PrincipalConstraint,
    ResourceConstraint, Schema, ValidationMode, Validator,
};
use openshell_policy_cedar_schema::{actions, entity_types};
use serde_json::Value;

use crate::filesystem::FilesystemPolicyInput;
use crate::{AuthorizedNetworkEndpoint, CedarEngineError};

/// Annotation that declares the wire protocol of an `HttpRequest` endpoint.
///
/// Read only from policies that can apply to `HttpRequest`; see
/// [`L7Protocol`] for accepted values.
const PROTOCOL_ANNOTATION: &str = "protocol";

/// Annotation whose value, when present, names a policy in error messages.
///
/// Cedar assigns positional ids (`policy0`, `policy1`, ...) to policies
/// parsed from text, which are hard to map back to the source.
const ID_ANNOTATION: &str = "id";

/// Wire protocol the proxy parses on an L7-inspected endpoint.
///
/// Only protocols whose per-request fields the `HttpRequest` context carries
/// are accepted. SQL, GraphQL, and MCP inspection need request details the
/// Cedar schema does not expose, so they are rejected at load instead of
/// being inspected without enforcement.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum L7Protocol {
    /// HTTP/1.1 REST requests, matched on `context.method`/`context.path`.
    #[default]
    Rest,
    /// JSON-RPC requests, matched on `context.jsonrpc_method`.
    JsonRpc,
}

impl L7Protocol {
    /// Returns the protocol label the proxy's L7 config parser expects.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rest => "rest",
            Self::JsonRpc => "json-rpc",
        }
    }

    fn from_annotation(value: &str) -> Option<Self> {
        match value {
            "rest" => Some(Self::Rest),
            "json-rpc" => Some(Self::JsonRpc),
            _ => None,
        }
    }
}

impl fmt::Display for L7Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Everything derived from an authored policy set at load time.
#[derive(Debug, Clone, Default)]
pub struct PolicyAnalysis {
    /// Landlock path grants.
    pub(crate) filesystem: FilesystemPolicyInput,
    /// Exact `NetworkConnect` endpoints eligible for policy DNS, by host.
    pub(crate) dns_endpoints: Vec<AuthorizedNetworkEndpoint>,
    /// Endpoints routed into L7 inspection, keyed by `(host, port)`.
    pub(crate) l7_endpoints: BTreeMap<(String, u16), L7Protocol>,
}

/// Validates `policies` against `schema` and derives a [`PolicyAnalysis`].
///
/// # Errors
///
/// Returns [`CedarEngineError`] if the policy set fails strict schema
/// validation, contains templates, or contains a policy whose meaning this
/// crate cannot enforce exactly (see the module docs).
pub fn analyze(schema: &Schema, policies: &PolicySet) -> Result<PolicyAnalysis, CedarEngineError> {
    let validation = Validator::new(schema.clone()).validate(policies, ValidationMode::Strict);
    if !validation.validation_passed() {
        let reason = validation
            .validation_errors()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ");
        return Err(CedarEngineError::PolicyValidation { reason });
    }
    if let Some(template) = policies.templates().next() {
        return Err(CedarEngineError::UnsupportedPolicy {
            policy_id: template.id().to_string(),
            reason: "policy templates are not supported".to_string(),
        });
    }

    let mut read_only = BTreeSet::new();
    let mut read_write = BTreeSet::new();
    let mut dns_ports: BTreeMap<String, BTreeSet<u16>> = BTreeMap::new();
    let mut l7_declared: BTreeMap<(String, u16), Option<L7Protocol>> = BTreeMap::new();

    for policy in policies.policies() {
        let policy_id = display_id(policy);
        let scope = ActionScope::of(policy);
        let touches_filesystem = (scope.includes(actions::READ_FILE)
            || scope.includes(actions::WRITE_FILE))
            && resource_may_be(policy, entity_types::FILESYSTEM_PATH);
        let touches_http_request = scope.includes(actions::HTTP_REQUEST)
            && resource_may_be(policy, entity_types::NETWORK_ENDPOINT);
        let touches_network_connect = scope.includes(actions::NETWORK_CONNECT)
            && resource_may_be(policy, entity_types::NETWORK_ENDPOINT);

        let protocol_annotation = policy.annotation(PROTOCOL_ANNOTATION);
        if protocol_annotation.is_some() && !touches_http_request {
            return Err(CedarEngineError::UnsupportedPolicy {
                policy_id,
                reason: "@protocol only applies to policies on the HttpRequest action".to_string(),
            });
        }

        if touches_filesystem {
            let grant = filesystem_grant(policy, &policy_id, &scope)?;
            let target = if grant.writes {
                &mut read_write
            } else {
                &mut read_only
            };
            target.extend(grant.paths);
        }

        if touches_http_request {
            let endpoint =
                scope_endpoint(policy).ok_or_else(|| CedarEngineError::UnsupportedPolicy {
                    policy_id: policy_id.clone(),
                    reason: "a policy on the HttpRequest action must name its endpoint in the \
                             scope (resource == Sandbox::NetworkEndpoint::\"host:port\") so the \
                             proxy knows which connections to inspect"
                        .to_string(),
                })?;
            let key = parse_endpoint(&policy_id, &endpoint)?;
            let protocol = protocol_annotation
                .map(|value| {
                    L7Protocol::from_annotation(value).ok_or_else(|| {
                        CedarEngineError::UnsupportedL7Protocol {
                            policy_id: policy_id.clone(),
                            protocol: value.to_string(),
                        }
                    })
                })
                .transpose()?;
            let declared = l7_declared.entry(key).or_insert(None);
            match (*declared, protocol) {
                (Some(first), Some(second)) if first != second => {
                    return Err(CedarEngineError::ConflictingL7Protocol {
                        endpoint,
                        first: first.to_string(),
                        second: second.to_string(),
                    });
                }
                (None, Some(protocol)) => *declared = Some(protocol),
                _ => {}
            }
        }

        if touches_network_connect
            && policy.effect() == Effect::Permit
            && let Some(endpoint) = scope_endpoint(policy)
        {
            let (host, port) = parse_endpoint(&policy_id, &endpoint)?;
            dns_ports.entry(host).or_default().insert(port);
        }
    }

    Ok(PolicyAnalysis {
        filesystem: FilesystemPolicyInput {
            read_only: read_only.into_iter().collect(),
            read_write: read_write.into_iter().collect(),
        },
        dns_endpoints: dns_ports
            .into_iter()
            .map(|(host, ports)| AuthorizedNetworkEndpoint {
                host,
                ports: ports.into_iter().collect(),
            })
            .collect(),
        l7_endpoints: l7_declared
            .into_iter()
            .map(|(key, protocol)| (key, protocol.unwrap_or_default()))
            .collect(),
    })
}

/// Which `Sandbox::Action`s a policy's action scope can match.
enum ActionScope {
    /// Unconstrained `action`: every action in the schema.
    Any,
    /// The listed action ids.
    Listed(BTreeSet<String>),
}

impl ActionScope {
    fn of(policy: &Policy) -> Self {
        let ids = |uids: &[EntityUid]| {
            uids.iter()
                .filter(|uid| uid.type_name().to_string() == actions::ACTION_TYPE)
                .map(|uid| uid.id().unescaped().to_string())
                .collect()
        };
        match policy.action_constraint() {
            ActionConstraint::Any => Self::Any,
            ActionConstraint::Eq(uid) => Self::Listed(ids(&[uid])),
            ActionConstraint::In(uids) => Self::Listed(ids(&uids)),
        }
    }

    fn includes(&self, action: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Listed(ids) => ids.contains(action),
        }
    }

    /// True if every action in scope is `ReadFile` or `WriteFile`.
    fn is_filesystem_only(&self) -> bool {
        match self {
            Self::Any => false,
            Self::Listed(ids) => ids
                .iter()
                .all(|id| id == actions::READ_FILE || id == actions::WRITE_FILE),
        }
    }
}

/// True if the policy's resource scope can match an entity of `type_name`.
fn resource_may_be(policy: &Policy, type_name: &str) -> bool {
    match policy.resource_constraint() {
        ResourceConstraint::Any => true,
        ResourceConstraint::Is(entity_type) | ResourceConstraint::IsIn(entity_type, _) => {
            entity_type.to_string() == type_name
        }
        ResourceConstraint::Eq(uid) | ResourceConstraint::In(uid) => {
            uid.type_name().to_string() == type_name
        }
    }
}

/// Returns the `NetworkEndpoint` id named in the policy's resource scope.
///
/// `NetworkEndpoint` has no parent types, so `resource in E` matches exactly
/// `E`, the same as `resource == E`.
fn scope_endpoint(policy: &Policy) -> Option<String> {
    match policy.resource_constraint() {
        ResourceConstraint::Eq(uid)
        | ResourceConstraint::In(uid)
        | ResourceConstraint::IsIn(_, uid)
            if uid.type_name().to_string() == entity_types::NETWORK_ENDPOINT =>
        {
            Some(uid.id().unescaped().to_string())
        }
        _ => None,
    }
}

/// Splits a `"host:port"` endpoint id into a lowercase host and a port.
fn parse_endpoint(policy_id: &str, endpoint: &str) -> Result<(String, u16), CedarEngineError> {
    let invalid = |reason: &str| CedarEngineError::InvalidEndpoint {
        policy_id: policy_id.to_string(),
        endpoint: endpoint.to_string(),
        reason: reason.to_string(),
    };
    let (host, port) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| invalid("expected \"host:port\""))?;
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| invalid("port must be in 1..=65535"))?;
    if host.is_empty() {
        return Err(invalid("host must not be empty"));
    }
    if host.ends_with('.') {
        return Err(invalid("host must not end with '.'"));
    }
    if host != host.to_ascii_lowercase() {
        // Requests are matched against the lowercased host, so an uppercase
        // literal could never match.
        return Err(invalid("host must be lowercase"));
    }
    Ok((host.to_string(), port))
}

/// Paths and access level granted by one filesystem `permit`.
struct FilesystemGrant {
    paths: Vec<String>,
    writes: bool,
}

/// Converts one filesystem-touching policy into a Landlock grant.
///
/// # Errors
///
/// Returns [`CedarEngineError`] if the policy's meaning cannot be expressed
/// exactly as a Landlock allow-list entry.
fn filesystem_grant(
    policy: &Policy,
    policy_id: &str,
    scope: &ActionScope,
) -> Result<FilesystemGrant, CedarEngineError> {
    let unsupported = |reason: &str| CedarEngineError::UnsupportedPolicy {
        policy_id: policy_id.to_string(),
        reason: reason.to_string(),
    };
    if policy.effect() == Effect::Forbid {
        return Err(CedarEngineError::FilesystemForbidUnsupported {
            policy_id: policy_id.to_string(),
        });
    }
    if !scope.is_filesystem_only() {
        return Err(unsupported(
            "a policy that can apply to files must list only ReadFile and/or WriteFile \
             in its action scope",
        ));
    }
    let principal_unconstrained = match policy.principal_constraint() {
        PrincipalConstraint::Any => true,
        PrincipalConstraint::Is(entity_type) => entity_type.to_string() == entity_types::PROCESS,
        _ => false,
    };
    if !principal_unconstrained {
        return Err(unsupported(
            "filesystem grants apply to every sandbox process; use `principal` or \
             `principal is Sandbox::Process`",
        ));
    }

    let paths = match policy.resource_constraint() {
        ResourceConstraint::In(uid) | ResourceConstraint::IsIn(_, uid)
            if !policy.has_non_scope_constraint() =>
        {
            vec![uid.id().unescaped().to_string()]
        }
        ResourceConstraint::Eq(_) => {
            return Err(unsupported(
                "`resource ==` names one exact path, but Landlock grants the whole \
                 subtree; use `resource in Sandbox::FilesystemPath::\"/path\"`",
            ));
        }
        ResourceConstraint::Any | ResourceConstraint::Is(_) => when_clause_paths(policy)
            .ok_or_else(|| {
                unsupported(
                    "name paths in the scope (`resource in Sandbox::FilesystemPath::\"/path\"`) \
                     or in a single `when` clause that only ORs `resource in` tests",
                )
            })?,
        ResourceConstraint::In(_) | ResourceConstraint::IsIn(..) => {
            return Err(unsupported(
                "`when`/`unless` conditions on a filesystem policy cannot be enforced by \
                 Landlock",
            ));
        }
    };

    let writes = scope.includes(actions::WRITE_FILE);
    Ok(FilesystemGrant { paths, writes })
}

/// Returns the paths of a `when { resource in P1 || resource in P2 ... }` body.
///
/// Returns `None` unless the policy has exactly one condition, it is `when`,
/// and its body consists only of `||` over `resource in` tests against
/// `FilesystemPath` literals.
fn when_clause_paths(policy: &Policy) -> Option<Vec<String>> {
    let json = policy.to_json().ok()?;
    let conditions = json.get("conditions")?.as_array()?;
    let [condition] = conditions.as_slice() else {
        return None;
    };
    if condition.get("kind")?.as_str()? != "when" {
        return None;
    }
    let mut paths = Vec::new();
    collect_resource_in_paths(condition.get("body")?, &mut paths).then_some(paths)
}

/// Collects `resource in FilesystemPath::"..."` paths from an `||` tree.
///
/// Returns `false` if any node is not `||` or such a `resource in` test.
fn collect_resource_in_paths(expr: &Value, paths: &mut Vec<String>) -> bool {
    if let Some(or) = expr.get("||") {
        return match (or.get("left"), or.get("right")) {
            (Some(left), Some(right)) => {
                collect_resource_in_paths(left, paths) && collect_resource_in_paths(right, paths)
            }
            _ => false,
        };
    }
    let Some(test) = expr.get("in") else {
        return false;
    };
    let is_resource = test
        .get("left")
        .and_then(|left| left.get("Var"))
        .and_then(Value::as_str)
        == Some("resource");
    let entity = test
        .get("right")
        .and_then(|right| right.get("Value"))
        .and_then(|value| value.get("__entity"));
    let Some(entity) = entity else {
        return false;
    };
    let is_path = entity.get("type").and_then(Value::as_str) == Some(entity_types::FILESYSTEM_PATH);
    match entity.get("id").and_then(Value::as_str) {
        Some(id) if is_resource && is_path => {
            paths.push(id.to_string());
            true
        }
        _ => false,
    }
}

/// Returns the policy's `@id` annotation, or its Cedar-assigned id.
fn display_id(policy: &Policy) -> String {
    policy
        .annotation(ID_ANNOTATION)
        .map_or_else(|| policy.id().to_string(), ToString::to_string)
}
