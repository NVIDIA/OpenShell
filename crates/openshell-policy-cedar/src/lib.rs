// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Rust guideline compliant 2026-09-19

//! Experimental Cedar-based policy tooling for `OpenShell`.
//!
//! Two distinct roles, scoped separately because they have different risk
//! profiles (see `architecture/plans/cedar-policy-engine-rfc-draft.md`):
//!
//! - **Network** (crate root, this module): a proof of concept exploring
//!   Cedar as an alternative to the Rego-based `OpaEngine` in
//!   `openshell-supervisor-network` — evaluating `NetworkConnect`
//!   authorization decisions against a Cedar schema and policy set instead
//!   of YAML compiled to Rego. Not wired into the gateway or supervisor.
//! - **Filesystem** ([`filesystem`]): advisory-only. Landlock remains the
//!   sole runtime enforcer of filesystem policy; this module compiles the
//!   authored allow-list into Cedar entities purely for offline
//!   inspection/verification (conflicting or redundant grants). It is never
//!   a runtime decision point and nothing depends on it at request time.
//!
//! Process/syscall policy has no authored surface to represent and is out
//! of scope entirely.
//!
//! The schema itself lives in `openshell-policy-cedar-schema`, the single
//! source of truth for Cedar entity/action names across every Cedar-aware
//! consumer.

pub mod compile;
pub mod compile_l7;
mod error;
pub mod filesystem;
pub mod glob;

pub use compile::CompiledCedarPolicy;
pub use compile_l7::CompiledL7Policy;
pub use error::CedarEngineError;

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, Entity, EntityId, EntityTypeName, EntityUid,
    PolicySet, Request, RestrictedExpression, Schema,
};
use openshell_policy_cedar_schema::{actions, context_fields, endpoint_fields, entity_types};

/// Synthetic id for the single `Process` entity built per request; this
/// proof of concept evaluates one request at a time and never
/// cross-references processes, so a fixed id is sufficient.
const CURRENT_PROCESS: &str = "current";

/// One network-connect authorization request.
///
/// Mirrors the fields `openshell_supervisor_network::opa::NetworkInput`
/// supplies to the Rego engine, narrowed to what the `Sandbox::NetworkConnect`
/// Cedar action declares in its schema.
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
    /// L7 protocol label recorded on the `NetworkEndpoint` entity (e.g. `"rest"`).
    pub protocol: String,
    /// Absolute path of the binary making the connection.
    pub binary_path: String,
    /// Absolute paths of the calling process's ancestors (parent,
    /// grandparent, ...). Excludes cmdline/argv0, which is spoofable.
    pub ancestors: Vec<String>,
    /// HTTP method, when known; empty string when not applicable.
    pub method: String,
    /// REST request path, when known; empty string when not applicable.
    pub path: String,
    /// SQL command verb, when known; empty string when not applicable.
    pub command: String,
}

/// Outcome of evaluating a [`NetworkRequest`] against a Cedar policy set.
///
/// Mirrors `openshell_supervisor_network::opa::NetworkAction` so a future
/// integration can return either engine's decision through one type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkDecision {
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
    /// The matched endpoint's policy uses a rule shape not yet translatable
    /// to Cedar (planned: a policy compiler from normalized policy data,
    /// tracked separately). Not a decision: callers must not treat this as
    /// Allow or Deny, and shadow-mode comparisons must exclude it from
    /// agreement/disagreement counting.
    Unsupported {
        /// Human-readable reason the endpoint's policy could not be compiled.
        reason: String,
    },
}

/// Cedar-backed network policy evaluator.
///
/// Loads a Cedar schema and policy set once, then evaluates
/// [`NetworkRequest`]s against them.
pub struct CedarNetworkEngine {
    schema: Schema,
    policies: PolicySet,
    authorizer: Authorizer,
    /// Named policies [`compile::compile_normalized_data`] could not
    /// represent in `policies`. Checked before trusting a Cedar `Deny`; see
    /// [`compile::UncompiledPolicy`]. Empty for engines built from
    /// hand-authored policy text ([`Self::from_cedar_str`],
    /// [`Self::from_policy_str`]).
    uncompiled: Vec<compile::UncompiledPolicy>,
}

impl CedarNetworkEngine {
    /// Parses a Cedar schema and policy set from their human-readable
    /// (`.cedarschema` / `.cedar`) syntax.
    ///
    /// # Errors
    ///
    /// Returns [`CedarEngineError`] if either input fails to parse.
    pub fn from_cedar_str(schema_src: &str, policy_src: &str) -> Result<Self, CedarEngineError> {
        let (schema, _warnings) = Schema::from_cedarschema_str(schema_src)
            .map_err(|e| CedarEngineError::SchemaParse(Box::new(e)))?;
        let policies = PolicySet::from_str(policy_src)
            .map_err(|e| CedarEngineError::PolicyParse(Box::new(e)))?;
        Ok(Self {
            schema,
            policies,
            authorizer: Authorizer::new(),
            uncompiled: Vec::new(),
        })
    }

    /// Parses a Cedar policy set against the canonical
    /// [`openshell_policy_cedar_schema::SANDBOX_SCHEMA_SRC`] schema.
    ///
    /// # Errors
    ///
    /// Returns [`CedarEngineError`] if the policy set source fails to parse.
    pub fn from_policy_str(policy_src: &str) -> Result<Self, CedarEngineError> {
        Self::from_cedar_str(
            openshell_policy_cedar_schema::SANDBOX_SCHEMA_SRC,
            policy_src,
        )
    }

    /// Builds an engine from a [`CompiledCedarPolicy`] produced by
    /// [`compile::compile_normalized_data`].
    ///
    /// # Errors
    ///
    /// Returns [`CedarEngineError`] if the canonical schema fails to parse
    /// (should not happen; the schema is fixed and tested in
    /// `openshell-policy-cedar-schema`).
    pub fn from_compiled(compiled: CompiledCedarPolicy) -> Result<Self, CedarEngineError> {
        let (schema, _warnings) =
            Schema::from_cedarschema_str(openshell_policy_cedar_schema::SANDBOX_SCHEMA_SRC)
                .map_err(|e| CedarEngineError::SchemaParse(Box::new(e)))?;
        Ok(Self {
            schema,
            policies: compiled.policies,
            authorizer: Authorizer::new(),
            uncompiled: compiled.uncompiled,
        })
    }

    /// Extracts the filesystem paths this engine's policy set permits for
    /// reading and/or writing. See [`filesystem::extract_authorized_paths`].
    ///
    /// # Errors
    ///
    /// Returns [`CedarEngineError`] if any policy `forbid`s a
    /// `FilesystemPath` — Landlock's flat allow-list can't express
    /// forbid-over-permit carve-outs.
    pub fn extract_authorized_paths(
        &self,
    ) -> Result<filesystem::FilesystemPolicyInput, CedarEngineError> {
        filesystem::extract_authorized_paths(&self.policies)
    }

    /// Evaluates one network-connect request against the loaded policy set.
    ///
    /// # Errors
    ///
    /// Returns [`CedarEngineError`] if the request cannot be represented in
    /// the loaded schema: invalid entity type names, attribute evaluation
    /// failures, or a request shape the schema rejects.
    pub fn evaluate_network(
        &self,
        request: &NetworkRequest,
    ) -> Result<NetworkDecision, CedarEngineError> {
        if let Some(uncompiled) = self.uncompiled.iter().find(|policy| {
            policy.matches(
                &request.host,
                request.port,
                &request.binary_path,
                &request.ancestors,
            )
        }) {
            return Ok(NetworkDecision::Unsupported {
                reason: format!(
                    "request matches named policy {:?}, which could not be compiled to Cedar: {}",
                    uncompiled.name, uncompiled.reason
                ),
            });
        }

        let host_lower = request.host.to_lowercase();
        let host_port = format!("{host_lower}:{}", request.port);

        let user_uid = entity_uid(entity_types::USER, &request.user)?;
        let group_uid = entity_uid(entity_types::GROUP, &request.group)?;
        let process_uid = entity_uid(entity_types::PROCESS, CURRENT_PROCESS)?;
        let endpoint_uid = entity_uid(entity_types::NETWORK_ENDPOINT, &host_port)?;
        let action_uid = entity_uid(actions::ACTION_TYPE, actions::NETWORK_CONNECT)?;

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
        .map_err(|e| CedarEngineError::EntityBuild(Box::new(e)))?;
        let user = Entity::new_no_attrs(user_uid, HashSet::new());
        let group = Entity::new_no_attrs(group_uid, HashSet::new());
        let endpoint = Entity::new(
            endpoint_uid.clone(),
            HashMap::from([
                (
                    endpoint_fields::HOST.to_string(),
                    RestrictedExpression::new_string(host_lower),
                ),
                (
                    endpoint_fields::PORT.to_string(),
                    RestrictedExpression::new_long(i64::from(request.port)),
                ),
                (
                    endpoint_fields::PROTOCOL.to_string(),
                    RestrictedExpression::new_string(request.protocol.clone()),
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

        let context = Context::from_pairs([
            (
                context_fields::BINARY_PATH.to_string(),
                RestrictedExpression::new_string(request.binary_path.clone()),
            ),
            (
                context_fields::ANCESTORS.to_string(),
                RestrictedExpression::new_set(
                    request
                        .ancestors
                        .iter()
                        .map(|a| RestrictedExpression::new_string(a.clone())),
                ),
            ),
            (
                context_fields::METHOD.to_string(),
                RestrictedExpression::new_string(request.method.clone()),
            ),
            (
                context_fields::PATH.to_string(),
                RestrictedExpression::new_string(request.path.clone()),
            ),
            (
                context_fields::COMMAND.to_string(),
                RestrictedExpression::new_string(request.command.clone()),
            ),
        ])
        .map_err(|e| CedarEngineError::ContextBuild(Box::new(e)))?;

        let cedar_request = Request::new(
            process_uid,
            action_uid,
            endpoint_uid,
            context,
            Some(&self.schema),
        )
        .map_err(|e| CedarEngineError::RequestBuild(Box::new(e)))?;

        let response = self
            .authorizer
            .is_authorized(&cedar_request, &self.policies, &entities);

        let matched_policies: Vec<String> = response
            .diagnostics()
            .reason()
            .map(ToString::to_string)
            .collect();

        Ok(match response.decision() {
            Decision::Allow => NetworkDecision::Allow { matched_policies },
            Decision::Deny => NetworkDecision::Deny { matched_policies },
        })
    }

    /// Evaluates one per-request `HttpRequest` within an already-permitted
    /// `NetworkConnect` tunnel.
    ///
    /// Unlike [`Self::evaluate_network`], there is no `uncompiled`
    /// short-circuit: this engine's `policies` may come from hand-authored
    /// `.cedar` text (which either contains `HttpRequest` policies or
    /// doesn't — nothing to compile), or from [`compile_l7::compile_l7`]
    /// (whose own `CompiledL7Policy::uncompiled` list is the caller's
    /// responsibility to check before trusting a `Deny` here, same as
    /// [`compile::UncompiledPolicy`] for CONNECT).
    ///
    /// # Errors
    ///
    /// Returns [`CedarEngineError`] if the request cannot be represented in
    /// the loaded schema.
    pub fn evaluate_l7(
        &self,
        request: &L7Request,
    ) -> Result<(bool, Vec<String>), CedarEngineError> {
        let host_lower = request.host.to_lowercase();
        let host_port = format!("{host_lower}:{}", request.port);

        let user_uid = entity_uid(entity_types::USER, &request.user)?;
        let group_uid = entity_uid(entity_types::GROUP, &request.group)?;
        let process_uid = entity_uid(entity_types::PROCESS, CURRENT_PROCESS)?;
        let endpoint_uid = entity_uid(entity_types::NETWORK_ENDPOINT, &host_port)?;
        let action_uid = entity_uid(actions::ACTION_TYPE, actions::HTTP_REQUEST)?;

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
        .map_err(|e| CedarEngineError::EntityBuild(Box::new(e)))?;
        let user = Entity::new_no_attrs(user_uid, HashSet::new());
        let group = Entity::new_no_attrs(group_uid, HashSet::new());
        let endpoint = Entity::new(
            endpoint_uid.clone(),
            HashMap::from([
                (
                    endpoint_fields::HOST.to_string(),
                    RestrictedExpression::new_string(host_lower),
                ),
                (
                    endpoint_fields::PORT.to_string(),
                    RestrictedExpression::new_long(i64::from(request.port)),
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
        .map_err(|e| CedarEngineError::EntityBuild(Box::new(e)))?;

        let entities =
            Entities::from_entities([process, user, group, endpoint], Some(&self.schema))
                .map_err(|e| CedarEngineError::EntitiesBuild(Box::new(e)))?;

        let context = Context::from_pairs([
            (
                context_fields::BINARY_PATH.to_string(),
                RestrictedExpression::new_string(request.binary_path.clone()),
            ),
            (
                context_fields::ANCESTORS.to_string(),
                RestrictedExpression::new_set(
                    request
                        .ancestors
                        .iter()
                        .map(|a| RestrictedExpression::new_string(a.clone())),
                ),
            ),
            (
                context_fields::METHOD.to_string(),
                RestrictedExpression::new_string(request.method.clone()),
            ),
            (
                context_fields::PATH.to_string(),
                RestrictedExpression::new_string(request.path.clone()),
            ),
            (
                context_fields::COMMAND.to_string(),
                RestrictedExpression::new_string(request.command.clone()),
            ),
            (
                context_fields::JSONRPC_METHOD.to_string(),
                RestrictedExpression::new_string(request.jsonrpc_method.clone()),
            ),
        ])
        .map_err(|e| CedarEngineError::ContextBuild(Box::new(e)))?;

        let cedar_request = Request::new(
            process_uid,
            action_uid,
            endpoint_uid,
            context,
            Some(&self.schema),
        )
        .map_err(|e| CedarEngineError::RequestBuild(Box::new(e)))?;

        let response = self
            .authorizer
            .is_authorized(&cedar_request, &self.policies, &entities);

        let matched_policies: Vec<String> = response
            .diagnostics()
            .reason()
            .map(ToString::to_string)
            .collect();

        Ok((response.decision() == Decision::Allow, matched_policies))
    }
}

/// One per-request L7 evaluation within an already-permitted
/// `NetworkConnect` tunnel.
///
/// Mirrors the fields `openshell_supervisor_network::l7::relay::L7EvalContext`
/// / `L7RequestInfo` supply, narrowed to what the `Sandbox::HttpRequest`
/// Cedar action declares in its schema.
#[derive(Debug, Clone)]
pub struct L7Request {
    /// Sandbox process user identity (`Sandbox::User` entity id), same as
    /// the tunnel's `NetworkConnect` request — identity doesn't change
    /// within a tunnel, but policies may still guard every action
    /// (including `HttpRequest`) on it, e.g. a top-level identity `forbid`.
    pub user: String,
    /// Sandbox process group identity (`Sandbox::Group` entity id).
    pub group: String,
    /// Absolute path of the binary that owns this tunnel.
    pub binary_path: String,
    /// Absolute paths of the tunnel-owning process's ancestors.
    pub ancestors: Vec<String>,
    /// Destination host (same endpoint the tunnel's `NetworkConnect` matched).
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

/// Builds an [`EntityUid`] from a Cedar entity type name and id.
pub(crate) fn entity_uid(type_name: &str, id: &str) -> Result<EntityUid, CedarEngineError> {
    let type_name = EntityTypeName::from_str(type_name)
        .map_err(|e| CedarEngineError::EntityTypeParse(Box::new(e)))?;
    // `EntityId::from_str` is infallible: any string is a valid entity id.
    let entity_id = EntityId::from_str(id).unwrap_or_else(|never| match never {});
    Ok(EntityUid::from_type_name_and_id(type_name, entity_id))
}
