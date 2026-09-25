// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Rust guideline compliant 2026-09-19

//! Experimental Cedar-based network policy evaluation engine for `OpenShell`.
//!
//! This crate is a proof of concept exploring Cedar as an alternative to the
//! Rego-based `OpaEngine` in `openshell-supervisor-network`: it evaluates
//! `NetworkConnect` authorization decisions against a Cedar schema and policy
//! set instead of YAML compiled to Rego. It is not wired into the gateway or
//! supervisor, and it covers network decisions only — filesystem and process
//! policy stay on the existing YAML/Landlock path.
//!
//! The schema itself lives in `openshell-policy-cedar-schema`, the single
//! source of truth for Cedar entity/action names across every Cedar-aware
//! consumer.

mod error;

pub use error::CedarEngineError;

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, Entity, EntityId, EntityTypeName, EntityUid,
    PolicySet, Request, RestrictedExpression, Schema,
};
use openshell_policy_cedar_schema::{actions, entity_types};

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
    /// `"host:port"` endpoints known to be an incomplete picture in
    /// `policies` (planned: populated by a policy compiler, tracked
    /// separately). Requests to these endpoints always evaluate to
    /// [`NetworkDecision::Unsupported`] rather than a guessed Allow/Deny.
    unsupported_endpoints: HashSet<String>,
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
            unsupported_endpoints: HashSet::new(),
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
        let endpoint_key = format!("{}:{}", request.host, request.port);
        if self.unsupported_endpoints.contains(&endpoint_key) {
            return Ok(NetworkDecision::Unsupported {
                reason: format!(
                    "policy for endpoint {endpoint_key} includes a rule shape not yet \
                     translated to Cedar"
                ),
            });
        }

        let user_uid = entity_uid(entity_types::USER, &request.user)?;
        let group_uid = entity_uid(entity_types::GROUP, &request.group)?;
        let process_uid = entity_uid(entity_types::PROCESS, CURRENT_PROCESS)?;
        let binary_uid = entity_uid(entity_types::FILESYSTEM_PATH, &request.binary_path)?;
        let endpoint_uid = entity_uid(entity_types::NETWORK_ENDPOINT, &endpoint_key)?;
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
        let binary = Entity::new_no_attrs(binary_uid.clone(), HashSet::new());
        let endpoint = Entity::new(
            endpoint_uid.clone(),
            HashMap::from([
                (
                    "host".to_string(),
                    RestrictedExpression::new_string(request.host.clone()),
                ),
                (
                    "port".to_string(),
                    RestrictedExpression::new_long(i64::from(request.port)),
                ),
                (
                    "protocol".to_string(),
                    RestrictedExpression::new_string(request.protocol.clone()),
                ),
            ]),
            HashSet::new(),
        )
        .map_err(|e| CedarEngineError::EntityBuild(Box::new(e)))?;

        let entities =
            Entities::from_entities([process, user, group, binary, endpoint], Some(&self.schema))
                .map_err(|e| CedarEngineError::EntitiesBuild(Box::new(e)))?;

        let context = Context::from_pairs([
            (
                "binary".to_string(),
                RestrictedExpression::new_entity_uid(binary_uid),
            ),
            (
                "method".to_string(),
                RestrictedExpression::new_string(request.method.clone()),
            ),
            (
                "path".to_string(),
                RestrictedExpression::new_string(request.path.clone()),
            ),
            (
                "command".to_string(),
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
}

/// Builds an [`EntityUid`] from a Cedar entity type name and id.
fn entity_uid(type_name: &str, id: &str) -> Result<EntityUid, CedarEngineError> {
    let type_name = EntityTypeName::from_str(type_name)
        .map_err(|e| CedarEngineError::EntityTypeParse(Box::new(e)))?;
    // `EntityId::from_str` is infallible: any string is a valid entity id.
    let entity_id = EntityId::from_str(id).unwrap_or_else(|never| match never {});
    Ok(EntityUid::from_type_name_and_id(type_name, entity_id))
}
