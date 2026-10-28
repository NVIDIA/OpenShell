// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-request L7 decisions of an inspected Cedar tunnel.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use miette::Result;
use openshell_ocsf::{
    ActionId, ActivityId, DispositionId, Endpoint, HttpActivityBuilder, HttpRequest, SeverityId,
    Url as OcsfUrl, ocsf_emit,
};
use openshell_policy_cedar::{CedarEngine, CedarEngineError, Decision, HttpRequestInput};

use super::routes::{RequestRoute, UNMATCHED_PATH};
use super::{LoadedPolicy, PLACEHOLDER_IDENTITY};
use crate::policy_types::GraphqlPersistedQuery;

/// Per-tunnel L7 decision handle for a Cedar-sourced sandbox.
///
/// Unlike a YAML tunnel's Rego evaluator, this needs no actual
/// per-tunnel engine clone — `Authorizer`/`PolicySet` are immutable, so
/// concurrent evaluation is just concurrent `RwLock::read()` calls, same as
/// [`super::CedarOnlyEngine::authorize_egress`]. Only `captured_generation` is
/// per-tunnel state.
#[derive(Debug)]
pub struct CedarL7TunnelEngine {
    pub(super) engine: Arc<RwLock<LoadedPolicy>>,
    pub(super) generation: Arc<AtomicU64>,
    pub(super) captured_generation: u64,
}

impl CedarL7TunnelEngine {
    /// Evaluates one L7 request and returns `(allowed, deny_reason)`.
    ///
    /// # Errors
    ///
    /// Returns an error if the tunnel's generation is stale, the engine lock
    /// is poisoned, or Cedar fails to evaluate the request.
    pub(crate) fn evaluate_request(
        &self,
        ctx: &crate::l7::relay::L7EvalContext,
        request: &crate::l7::L7RequestInfo,
    ) -> Result<(bool, String)> {
        let guard = self.read_pinned()?;
        Self::decide(&guard, ctx, request, StagedAudit::Log)
    }

    /// Returns the token-grant owners admitted for one request.
    ///
    /// Admits owner O when Cedar allows the request and a provider endpoint
    /// stamped with O admits it under that endpoint's own rules, as a YAML
    /// sandbox admits O. The provider rules are compiled to Cedar and
    /// evaluated with the request's own Cedar evaluations; they only narrow
    /// which owners qualify and never allow a request Cedar denies. A denial
    /// on a Cedar audit path admits no owner, matching a YAML audit denial.
    ///
    /// Two requests that Cedar sees differently from the Rego rules admit
    /// no owner: a JSON-RPC request whose method is not uppercase, which the
    /// Rego rules compare case-sensitively, and a hash-only GraphQL persisted
    /// query, which the Rego rules resolve through the provider endpoint's
    /// registry rather than the endpoint settings.
    ///
    /// # Errors
    ///
    /// Returns an error if the tunnel's generation is stale, the engine lock
    /// is poisoned, or an evaluation fails. Callers inject no token on error.
    pub(crate) fn admitted_token_grant_owners(
        &self,
        ctx: &crate::l7::relay::L7EvalContext,
        request: &crate::l7::L7RequestInfo,
    ) -> Result<std::collections::HashSet<String>> {
        let none = std::collections::HashSet::new;
        let guard = self.read_pinned()?;
        let Some(grants) = &guard.token_grants else {
            return Ok(none());
        };
        let Prepared::Evaluate(requests) = Self::prepare(&guard, ctx, request)? else {
            return Ok(none());
        };
        // `evaluate_request` already logged any staged audit decision for
        // this request.
        for l7_request in &requests {
            if !Self::evaluate_one(&guard.cedar, ctx, request, l7_request, StagedAudit::Skip)?.0 {
                return Ok(none());
            }
        }
        let hash_only = request
            .graphql
            .as_ref()
            .is_some_and(|graphql| graphql.operations.iter().any(needs_graphql_registry));
        let lowercase_jsonrpc =
            request.jsonrpc.is_some() && request.action != request.action.to_ascii_uppercase();
        if hash_only || lowercase_jsonrpc {
            return Ok(none());
        }
        match grants.admitted_owners(&requests) {
            Ok(owners) => Ok(owners.into_iter().collect()),
            // Too many query combinations to evaluate, or a request field
            // over the engine's length cap, admits no owner.
            Err(
                CedarEngineError::TooManyQueryCombinations { .. }
                | CedarEngineError::RequestFieldTooLong { .. },
            ) => Ok(none()),
            Err(error) => Err(miette::miette!("{error}")),
        }
    }

    /// Takes the engine read lock and checks the tunnel's pinned generation.
    ///
    /// Compared under the read lock: a reload advances the generation under
    /// the write lock, so a request is judged by the policy generation the
    /// tunnel was pinned to, never a newer one.
    fn read_pinned(&self) -> Result<std::sync::RwLockReadGuard<'_, LoadedPolicy>> {
        let guard = self
            .engine
            .read()
            .map_err(|_| miette::miette!("Cedar engine lock poisoned"))?;
        let current_generation = self.generation.load(Ordering::Acquire);
        if current_generation != self.captured_generation {
            return Err(miette::miette!(
                "L7 tunnel policy generation is stale [captured_generation:{} current_generation:{current_generation}]",
                self.captured_generation,
            ));
        }
        Ok(guard)
    }

    /// Decides one L7 request and returns `(allowed, deny_reason)`.
    ///
    /// Same as the YAML path: a GraphQL request is allowed only when every
    /// operation is allowed.
    fn decide(
        policy: &LoadedPolicy,
        ctx: &crate::l7::relay::L7EvalContext,
        request: &crate::l7::L7RequestInfo,
        staged_audit: StagedAudit,
    ) -> Result<(bool, String)> {
        let requests = match Self::prepare(policy, ctx, request)? {
            Prepared::Denied(reason) => return Ok((false, reason)),
            Prepared::Evaluate(requests) => requests,
        };
        for l7_request in &requests {
            let decision =
                Self::evaluate_one(&policy.cedar, ctx, request, l7_request, staged_audit)?;
            if !decision.0 {
                return Ok(decision);
            }
        }
        Ok(Self::decision(true))
    }

    /// Builds the Cedar evaluations of one L7 request, or the reason it is
    /// denied before evaluation.
    fn prepare(
        policy: &LoadedPolicy,
        ctx: &crate::l7::relay::L7EvalContext,
        request: &crate::l7::L7RequestInfo,
    ) -> Result<Prepared> {
        let mut base = HttpRequestInput {
            user: PLACEHOLDER_IDENTITY.to_string(),
            group: PLACEHOLDER_IDENTITY.to_string(),
            binary_path: ctx.binary_path.clone(),
            ancestors: ctx.ancestors.clone(),
            binary_aliases: policy
                .binary_aliases
                .matching(&ctx.binary_path, &ctx.ancestors)?,
            binary_globs: policy
                .binary_globs
                .matching(&ctx.binary_path, &ctx.ancestors)?,
            // The relay parsed the request as GraphQL: an operation on a
            // GraphQL path or a GraphQL-over-WebSocket client message. As
            // the Rego `is_object(request.graphql)`, this makes the routed
            // path authoritative for it.
            graphql_request: request.graphql.is_some(),
            host: ctx.host.clone(),
            port: ctx.port,
            // YAML matches methods case-insensitively, and the request parser
            // keeps the client's case, so normalize before Cedar compares.
            method: request.action.to_ascii_uppercase(),
            path: request.target.clone(),
            // Decoded by the request parser, as the Rego input receives them.
            query: request
                .query_params
                .iter()
                .map(|(key, values)| (key.clone(), values.clone()))
                .collect(),
            ..HttpRequestInput::default()
        };
        // The relay selects the endpoint config, and with it the protocol and
        // enforcement, by the most specific matching path, and denies a
        // request no inspected path matches before evaluating it. A
        // WebSocket message carries its upgrade path, so it is routed as its
        // upgrade was.
        match policy.route_request(&ctx.host, ctx.port, &request.target) {
            RequestRoute::Unmatched => return Ok(Prepared::Denied(UNMATCHED_PATH.to_string())),
            RequestRoute::Routed { endpoint_path } => base.endpoint_path = endpoint_path,
            RequestRoute::Uninspected => {}
        }

        if let Some(info) = &request.jsonrpc {
            // Same as the YAML path: a request that failed inspection is
            // never matched against policy.
            if info.error.is_some() {
                return Ok(Prepared::Denied(
                    "JSON-RPC request could not be inspected".to_string(),
                ));
            }
            // The relay splits batches into single calls before policy
            // evaluation; a batch seen here carries no single method.
            let call = if info.is_batch {
                None
            } else {
                info.calls.first()
            };
            // Same as the YAML path: calls and response frames are only ever
            // allowed in a POST, so a body carried by any other method is
            // denied before Cedar sees it. An MCP receive stream (a GET with
            // no body) is unaffected.
            if (!info.calls.is_empty() || info.has_response)
                && !request.action.eq_ignore_ascii_case("POST")
            {
                return Ok(Prepared::Denied(
                    "JSON-RPC calls and responses must be sent with POST".to_string(),
                ));
            }
            if let Some(call) = call {
                // `method` stays empty for a call so policies match on
                // `jsonrpc_method` instead, the schema's not-applicable
                // convention.
                base.method = String::new();
                base.jsonrpc_method.clone_from(&call.method);
                base.mcp_tool = call.tool.clone().unwrap_or_default();
                base.mcp_method_class = match call.mcp_classification {
                    Some(crate::l7::jsonrpc::McpMethodClassification::Available) => "available",
                    Some(crate::l7::jsonrpc::McpMethodClassification::Extension) => "extension",
                    None => "",
                }
                .to_string();
            }
            base.jsonrpc_receive_stream = info.receive_stream;
            base.jsonrpc_response = info.has_response;
        }

        let Some(graphql) = &request.graphql else {
            return Ok(Prepared::Evaluate(vec![base]));
        };
        // Same as the YAML path: a GraphQL request is allowed only when it
        // parsed into at least one operation and every operation is allowed.
        if graphql.error.is_some() || graphql.operations.is_empty() {
            return Ok(Prepared::Denied(
                "GraphQL request could not be inspected".to_string(),
            ));
        }
        // Resolve every hash-only persisted query before evaluating any
        // operation, so an unregistered one is reported as such, as in YAML.
        let registry = graphql
            .operations
            .iter()
            .any(needs_graphql_registry)
            .then(|| PersistedQueryRegistry::for_request(policy, ctx, &request.target));
        let mut operations = Vec::with_capacity(graphql.operations.len());
        for operation in &graphql.operations {
            let effective = match &registry {
                Some(registry) if needs_graphql_registry(operation) => {
                    let Some(registered) = registry.lookup(operation) else {
                        return Ok(Prepared::Denied(UNREGISTERED_PERSISTED_QUERY.to_string()));
                    };
                    registered
                }
                _ => EffectiveGraphqlOperation::parsed(operation),
            };
            operations.push(effective);
        }
        Ok(Prepared::Evaluate(
            operations
                .into_iter()
                .map(|operation| {
                    let mut l7_request = base.clone();
                    l7_request.graphql_operation_type =
                        operation.operation_type.to_ascii_lowercase();
                    l7_request.graphql_operation_name = operation.operation_name;
                    l7_request.graphql_fields = operation.fields;
                    l7_request
                })
                .collect(),
        ))
    }

    /// Evaluates one Cedar request and returns `(allowed, deny_reason)`,
    /// logging any staged audit decision when `staged_audit` asks for it.
    ///
    /// A query with too many value combinations to evaluate, or a request
    /// field over the engine's length cap, is denied with that reason.
    fn evaluate_one(
        cedar: &CedarEngine,
        ctx: &crate::l7::relay::L7EvalContext,
        request: &crate::l7::L7RequestInfo,
        l7_request: &HttpRequestInput,
        staged_audit: StagedAudit,
    ) -> Result<(bool, String)> {
        let evaluation = match cedar.evaluate_l7(l7_request) {
            Ok(evaluation) => evaluation,
            Err(
                error @ (CedarEngineError::TooManyQueryCombinations { .. }
                | CedarEngineError::RequestFieldTooLong { .. }),
            ) => {
                return Ok((false, error.to_string()));
            }
            Err(error) => return Err(miette::miette!("{error}")),
        };
        if staged_audit == StagedAudit::Log
            && let Some(staged) = &evaluation.staged
        {
            ocsf_emit!(staged_audit_event(
                ctx,
                request,
                evaluation.is_allow(),
                staged
            ));
        }
        Ok(Self::decision(evaluation.is_allow()))
    }

    /// Returns the relay's `(allowed, deny_reason)` pair.
    fn decision(allowed: bool) -> (bool, String) {
        let reason = if allowed {
            String::new()
        } else {
            "denied by Cedar HttpRequest policy".to_string()
        };
        (allowed, reason)
    }
}

/// The Cedar evaluations of one L7 request.
#[derive(Debug)]
enum Prepared {
    /// Denied before evaluation, with the reason.
    Denied(String),
    /// One evaluation per GraphQL operation, else one.
    Evaluate(Vec<HttpRequestInput>),
}

/// The deny reason for a hash-only persisted query with no registry entry,
/// the same reason YAML reports.
pub(super) const UNREGISTERED_PERSISTED_QUERY: &str = "GraphQL persisted query is not registered";

/// Returns whether a parsed operation is a hash-only persisted query.
///
/// Mirrors the Rego `graphql_operation_needs_registry`: the request named a
/// persisted query and sent no operation text, so the operation type is
/// unknown until the registry supplies it.
fn needs_graphql_registry(operation: &crate::l7::graphql::GraphqlOperationInfo) -> bool {
    operation.persisted_query && operation.operation_type.is_empty()
}

/// The GraphQL operation Cedar evaluates.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EffectiveGraphqlOperation {
    operation_type: String,
    operation_name: String,
    fields: Vec<String>,
}

impl EffectiveGraphqlOperation {
    /// The operation as the request spelled it.
    fn parsed(operation: &crate::l7::graphql::GraphqlOperationInfo) -> Self {
        Self {
            operation_type: operation.operation_type.clone(),
            operation_name: operation.operation_name.clone().unwrap_or_default(),
            fields: operation.fields.clone(),
        }
    }
}

/// The persisted-query registry of the endpoint config a request selects.
#[derive(Debug, Default)]
struct PersistedQueryRegistry {
    /// `None` unless the config sets `persisted_queries: allow_registered`.
    operations: Option<std::collections::BTreeMap<String, GraphqlPersistedQuery>>,
}

impl PersistedQueryRegistry {
    /// Reads the registry from the endpoint config the relay selects for
    /// `target`, which carries the matching `endpoint_settings`.
    fn for_request(
        policy: &LoadedPolicy,
        ctx: &crate::l7::relay::L7EvalContext,
        target: &str,
    ) -> Self {
        let Some(config) = policy.request_config(&ctx.host, ctx.port, target) else {
            return Self::default();
        };
        Self {
            operations: (config.persisted_queries == "allow_registered")
                .then_some(config.graphql_persisted_queries),
        }
    }

    /// Returns the registered operation for a hash-only persisted query.
    ///
    /// Mirrors the Rego `graphql_registered_operation`: the key is the
    /// query hash when the request has one, and the saved-query id
    /// otherwise.
    fn lookup(
        &self,
        operation: &crate::l7::graphql::GraphqlOperationInfo,
    ) -> Option<EffectiveGraphqlOperation> {
        let key = operation
            .persisted_query_hash
            .as_deref()
            .filter(|hash| !hash.is_empty())
            .or_else(|| {
                operation
                    .persisted_query_id
                    .as_deref()
                    .filter(|id| !id.is_empty())
            })?;
        let registered = self.operations.as_ref()?.get(key)?;
        Some(EffectiveGraphqlOperation {
            operation_type: registered.operation_type.clone(),
            operation_name: registered.operation_name.clone(),
            fields: registered.fields.clone(),
        })
    }
}

/// Whether an evaluation logs the decision staged policies would make.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StagedAudit {
    /// Log it; the evaluation is the request's own policy decision.
    Log,
    /// Skip it; the request's own decision already logged it.
    Skip,
}

/// Builds the event for a request whose decision staged policies would
/// change.
///
/// The request itself is decided, and logged by the relay, without them.
pub(super) fn staged_audit_event(
    ctx: &crate::l7::relay::L7EvalContext,
    request: &crate::l7::L7RequestInfo,
    allowed: bool,
    staged: &Decision,
) -> openshell_ocsf::OcsfEvent {
    let (action_id, disposition_id) = if allowed {
        (ActionId::Allowed, DispositionId::Allowed)
    } else {
        (ActionId::Denied, DispositionId::Blocked)
    };
    let (outcome, policies) = match staged {
        Decision::Allow { matched_policies } => ("allow", matched_policies),
        Decision::Deny { matched_policies } => ("deny", matched_policies),
    };
    let method = if request.action.is_empty() {
        "-"
    } else {
        request.action.as_str()
    };
    HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .activity(ActivityId::Other)
        .action(action_id)
        .disposition(disposition_id)
        .severity(SeverityId::Informational)
        .http_request(HttpRequest::new(
            method,
            OcsfUrl::new("http", &ctx.host, &request.target, ctx.port),
        ))
        .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
        .firewall_rule(&ctx.policy_name, "cedar")
        .unmapped("cedar_audit", format!("staged_{outcome}"))
        .unmapped("cedar_audit_policies", policies.join(","))
        .message(format!(
            "L7_AUDIT staged {outcome} {method} {}:{}{} policies={}",
            ctx.host,
            ctx.port,
            request.target,
            policies.join(","),
        ))
        .build()
}
