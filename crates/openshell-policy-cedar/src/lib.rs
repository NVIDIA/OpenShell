// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cedar policy evaluation for `OpenShell` sandboxes.
//!
//! [`CedarEngine`] is the authoritative policy engine for a sandbox
//! whose policy is authored in Cedar (`SandboxPolicy.cedar_policy_source`).
//! It evaluates `NetworkConnect` and per-request `HttpRequest` decisions at
//! request time, and derives Landlock grants, L7 inspection routing, and DNS
//! eligibility from the policy text once, at construction. Construction
//! rejects any policy whose meaning those derived artifacts could not
//! enforce exactly; see [`analysis`](crate::analysis) for the accepted
//! shapes.
//!
//! The schema itself lives in `openshell-policy-cedar-schema`, the single
//! source of truth for Cedar entity/action names across every Cedar-aware
//! consumer.

mod analysis;
mod error;

pub use analysis::L7Protocol;
pub use error::CedarEngineError;

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Entities, Entity, EntityId, EntityTypeName, EntityUid, PolicySet, Request,
    RestrictedExpression, Schema,
};
use openshell_policy_cedar_schema::{actions, context_fields, endpoint_fields, entity_types};

use analysis::PolicyAnalysis;

/// Synthetic id for the single `Process` entity built per request.
///
/// Each request is evaluated on its own and never cross-references other
/// processes, so a fixed id is sufficient.
const CURRENT_PROCESS: &str = "current";

/// `Process` attribute holding the process's `User` entity.
const PROCESS_USER_ATTR: &str = "user";

/// `Process` attribute holding the process's `Group` entity.
const PROCESS_GROUP_ATTR: &str = "group";

/// One network-connect authorization request.
///
/// Mirrors the fields `openshell_supervisor_network::opa::NetworkInput`
/// supplies to the Rego engine. The schema's `method`, `path`, and `command`
/// context fields are always `""` for `NetworkConnect`, since no request has
/// been read at CONNECT time, so they are not part of this type.
#[derive(Debug, Clone)]
pub struct NetworkRequest {
    /// Sandbox process user identity (`Sandbox::User` entity id).
    pub user: String,
    /// Sandbox process group identity (`Sandbox::Group` entity id).
    pub group: String,
    /// Destination host.
    pub host: String,
    /// Destination port.
    pub port: u16,
    /// Absolute path of the binary making the connection.
    pub binary_path: String,
    /// Absolute paths of the calling process's ancestors (parent,
    /// grandparent, ...). Excludes cmdline/argv0, which is spoofable.
    pub ancestors: Vec<String>,
}

/// Outcome of evaluating a request against a Cedar policy set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// A `permit` policy matched and no `forbid` overrode it.
    Allow {
        /// Ids of the policies that contributed to the decision.
        matched_policies: Vec<String>,
    },
    /// No `permit` matched, or a `forbid` matched.
    Deny {
        /// Ids of the policies that contributed to the decision.
        matched_policies: Vec<String>,
    },
}

impl Decision {
    /// Returns `true` for [`Decision::Allow`].
    #[must_use]
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }
}

/// One per-request L7 evaluation within an already-permitted connection.
///
/// Mirrors the fields `openshell_supervisor_network::l7::relay::L7EvalContext`
/// / `L7RequestInfo` supply, narrowed to what the `Sandbox::HttpRequest`
/// Cedar action declares in its schema.
#[derive(Debug, Clone)]
pub struct L7Request {
    /// Sandbox process user identity (`Sandbox::User` entity id), same as
    /// the connection's `NetworkConnect` request. Identity doesn't change
    /// within a connection, but policies may still guard every action
    /// (including `HttpRequest`) on it, e.g. a top-level identity `forbid`.
    pub user: String,
    /// Sandbox process group identity (`Sandbox::Group` entity id).
    pub group: String,
    /// Absolute path of the binary that owns this connection.
    pub binary_path: String,
    /// Absolute paths of the connection-owning process's ancestors.
    pub ancestors: Vec<String>,
    /// Destination host (same endpoint the `NetworkConnect` matched).
    pub host: String,
    /// Destination port.
    pub port: u16,
    /// HTTP method, when known; empty string when not applicable.
    pub method: String,
    /// REST request path, when known; empty string when not applicable.
    pub path: String,
    /// SQL command verb, when known; empty string when not applicable.
    pub command: String,
    /// JSON-RPC method name, when known; empty string when not applicable.
    pub jsonrpc_method: String,
}

/// Landlock path grants derived from a Cedar policy set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilesystemGrants {
    /// Path subtrees granted read-only access.
    pub read_only: Vec<String>,
    /// Path subtrees granted read-write access.
    pub read_write: Vec<String>,
}

/// One host a Cedar policy set permits `NetworkConnect` to, with its ports.
///
/// Used for DNS eligibility, not CONNECT-time matching: only endpoints named
/// literally in a `permit` scope are included. A host reachable only through
/// a condition such as `resource.host like "*.example.com"` is not, so DNS
/// resolution for it fails closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedNetworkEndpoint {
    /// Destination host, lowercased.
    pub host: String,
    /// Ports this host is permitted on.
    pub ports: Vec<u16>,
}

/// Entity type names and ids every request needs, built once per engine.
#[derive(Debug, Clone)]
struct RequestUids {
    user_type: EntityTypeName,
    group_type: EntityTypeName,
    endpoint_type: EntityTypeName,
    process: EntityUid,
    network_connect: EntityUid,
    http_request: EntityUid,
}

impl RequestUids {
    fn new() -> Result<Self, CedarEngineError> {
        Ok(Self {
            user_type: entity_type(entity_types::USER)?,
            group_type: entity_type(entity_types::GROUP)?,
            endpoint_type: entity_type(entity_types::NETWORK_ENDPOINT)?,
            process: entity_uid(entity_types::PROCESS, CURRENT_PROCESS)?,
            network_connect: entity_uid(actions::ACTION_TYPE, actions::NETWORK_CONNECT)?,
            http_request: entity_uid(actions::ACTION_TYPE, actions::HTTP_REQUEST)?,
        })
    }
}

/// Cedar-backed sandbox policy evaluator.
///
/// Loads a Cedar schema and policy set once, validates and analyzes them,
/// then evaluates [`NetworkRequest`]s and [`L7Request`]s against them.
#[derive(Debug)]
pub struct CedarEngine {
    schema: Schema,
    policies: PolicySet,
    authorizer: Authorizer,
    analysis: PolicyAnalysis,
    uids: RequestUids,
}

impl CedarEngine {
    /// Parses and validates a policy set against the canonical sandbox schema.
    ///
    /// The schema is [`openshell_policy_cedar_schema::SANDBOX_SCHEMA_SRC`].
    ///
    /// # Errors
    ///
    /// Returns [`CedarEngineError`] if the policy set fails to parse, fails
    /// strict schema validation, or uses a shape this crate cannot enforce
    /// exactly.
    pub fn from_policy_str(policy_src: &str) -> Result<Self, CedarEngineError> {
        let schema = openshell_policy_cedar_schema::load_schema()?;
        let policies = PolicySet::from_str(policy_src)
            .map_err(|e| CedarEngineError::PolicyParse(Box::new(e)))?;
        let analysis = analysis::analyze(&schema, &policies)?;
        Ok(Self {
            schema,
            policies,
            authorizer: Authorizer::new(),
            analysis,
            uids: RequestUids::new()?,
        })
    }

    /// Returns the Landlock path grants this policy set authorizes.
    #[must_use]
    pub fn filesystem_grants(&self) -> &FilesystemGrants {
        &self.analysis.filesystem
    }

    /// Returns the exact `NetworkConnect` endpoints eligible for policy DNS.
    #[must_use]
    pub fn dns_endpoints(&self) -> &[AuthorizedNetworkEndpoint] {
        &self.analysis.dns_endpoints
    }

    /// Returns the L7 protocol to inspect `host:port` with, if any.
    ///
    /// `None` means no `HttpRequest` policy names this endpoint, so an
    /// allowed connection to it is relayed without per-request checks.
    #[must_use]
    pub fn l7_protocol(&self, host: &str, port: u16) -> Option<L7Protocol> {
        self.analysis
            .l7_endpoints
            .get(&(normalize_host(host), port))
            .copied()
    }

    /// Evaluates one network-connect request against the loaded policy set.
    ///
    /// # Errors
    ///
    /// Returns [`CedarEngineError`] if the request cannot be represented in
    /// the loaded schema, or if Cedar reports an error while evaluating any
    /// policy.
    pub fn evaluate_network(&self, request: &NetworkRequest) -> Result<Decision, CedarEngineError> {
        self.authorize(
            &self.uids.network_connect,
            &Principal {
                user: &request.user,
                group: &request.group,
            },
            &request.host,
            request.port,
            [
                (context_fields::BINARY_PATH, string(&request.binary_path)),
                (context_fields::ANCESTORS, string_set(&request.ancestors)),
                (context_fields::METHOD, string("")),
                (context_fields::PATH, string("")),
                (context_fields::COMMAND, string("")),
            ],
        )
    }

    /// Evaluates one per-request `HttpRequest` within a permitted connection.
    ///
    /// # Errors
    ///
    /// Returns [`CedarEngineError`] if the request cannot be represented in
    /// the loaded schema, or if Cedar reports an error while evaluating any
    /// policy.
    pub fn evaluate_l7(&self, request: &L7Request) -> Result<Decision, CedarEngineError> {
        self.authorize(
            &self.uids.http_request,
            &Principal {
                user: &request.user,
                group: &request.group,
            },
            &request.host,
            request.port,
            [
                (context_fields::BINARY_PATH, string(&request.binary_path)),
                (context_fields::ANCESTORS, string_set(&request.ancestors)),
                (context_fields::METHOD, string(&request.method)),
                (context_fields::PATH, string(&request.path)),
                (context_fields::COMMAND, string(&request.command)),
                (
                    context_fields::JSONRPC_METHOD,
                    string(&request.jsonrpc_method),
                ),
            ],
        )
    }

    /// Runs one authorization query.
    fn authorize<const N: usize>(
        &self,
        action: &EntityUid,
        principal: &Principal<'_>,
        host: &str,
        port: u16,
        context: [(&str, RestrictedExpression); N],
    ) -> Result<Decision, CedarEngineError> {
        let host = normalize_host(host);
        let host_port = format!("{host}:{port}");
        let protocol = self
            .analysis
            .l7_endpoints
            .get(&(host.clone(), port))
            .map_or("", |protocol| protocol.as_str());

        let user_uid = EntityUid::from_type_name_and_id(
            self.uids.user_type.clone(),
            entity_id(principal.user),
        );
        let group_uid = EntityUid::from_type_name_and_id(
            self.uids.group_type.clone(),
            entity_id(principal.group),
        );
        let endpoint_uid = EntityUid::from_type_name_and_id(
            self.uids.endpoint_type.clone(),
            entity_id(&host_port),
        );

        let process = Entity::new(
            self.uids.process.clone(),
            HashMap::from([
                (
                    PROCESS_USER_ATTR.to_string(),
                    RestrictedExpression::new_entity_uid(user_uid.clone()),
                ),
                (
                    PROCESS_GROUP_ATTR.to_string(),
                    RestrictedExpression::new_entity_uid(group_uid.clone()),
                ),
            ]),
            HashSet::new(),
        )
        .map_err(|e| CedarEngineError::EntityBuild(Box::new(e)))?;
        let user = Entity::new_no_attrs(user_uid, HashSet::new());
        let group = Entity::new_no_attrs(group_uid, HashSet::new());
        let endpoint = Entity::new(
            endpoint_uid.clone(),
            HashMap::from([
                (
                    endpoint_fields::HOST.to_string(),
                    RestrictedExpression::new_string(host),
                ),
                (
                    endpoint_fields::PORT.to_string(),
                    RestrictedExpression::new_long(i64::from(port)),
                ),
                (
                    endpoint_fields::PROTOCOL.to_string(),
                    RestrictedExpression::new_string(protocol.to_string()),
                ),
                (
                    endpoint_fields::HOST_PORT.to_string(),
                    RestrictedExpression::new_string(host_port),
                ),
            ]),
            HashSet::new(),
        )
        .map_err(|e| CedarEngineError::EntityBuild(Box::new(e)))?;

        let entities =
            Entities::from_entities([process, user, group, endpoint], Some(&self.schema))
                .map_err(|e| CedarEngineError::EntitiesBuild(Box::new(e)))?;
        let context = Context::from_pairs(
            context
                .into_iter()
                .map(|(field, value)| (field.to_string(), value)),
        )
        .map_err(|e| CedarEngineError::ContextBuild(Box::new(e)))?;
        let request = Request::new(
            self.uids.process.clone(),
            action.clone(),
            endpoint_uid,
            context,
            Some(&self.schema),
        )
        .map_err(|e| CedarEngineError::RequestBuild(Box::new(e)))?;

        let response = self
            .authorizer
            .is_authorized(&request, &self.policies, &entities);
        let errors: Vec<String> = response
            .diagnostics()
            .errors()
            .map(ToString::to_string)
            .collect();
        if !errors.is_empty() {
            return Err(CedarEngineError::Evaluation {
                reason: errors.join("; "),
            });
        }
        let matched_policies = response
            .diagnostics()
            .reason()
            .map(ToString::to_string)
            .collect();
        Ok(match response.decision() {
            cedar_policy::Decision::Allow => Decision::Allow { matched_policies },
            cedar_policy::Decision::Deny => Decision::Deny { matched_policies },
        })
    }
}

/// The user and group a request is evaluated as.
struct Principal<'a> {
    user: &'a str,
    group: &'a str,
}

fn string(value: &str) -> RestrictedExpression {
    RestrictedExpression::new_string(value.to_string())
}

fn string_set(values: &[String]) -> RestrictedExpression {
    RestrictedExpression::new_set(values.iter().map(|value| string(value)))
}

/// Lowercases `host` and strips one trailing `.`.
///
/// DNS-resolved hostnames (as published by `policy_dns` and read back via
/// `ResolvedEndpointStore::lookup`) are absolute FQDNs with a trailing dot
/// (see `NormalizedName::parse`); authored Cedar policy host literals never
/// have one. Without this, every request whose host came from a DNS
/// resolution would fail to match an otherwise-identical policy host.
/// Lowercasing is ASCII-only, matching how endpoint literals are checked at
/// load.
#[must_use]
pub fn normalize_host(host: &str) -> String {
    host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
}

fn entity_type(type_name: &str) -> Result<EntityTypeName, CedarEngineError> {
    EntityTypeName::from_str(type_name).map_err(|e| CedarEngineError::EntityTypeParse(Box::new(e)))
}

fn entity_id(id: &str) -> EntityId {
    // `EntityId::from_str` is infallible: any string is a valid entity id.
    EntityId::from_str(id).unwrap_or_else(|never| match never {})
}

/// Builds an [`EntityUid`] from a Cedar entity type name and id.
fn entity_uid(type_name: &str, id: &str) -> Result<EntityUid, CedarEngineError> {
    Ok(EntityUid::from_type_name_and_id(
        entity_type(type_name)?,
        entity_id(id),
    ))
}
