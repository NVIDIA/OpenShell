// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Typed errors for [`crate::CedarEngine`].

use miette::Diagnostic;
use thiserror::Error;

/// Errors produced while loading or evaluating a sandbox Cedar policy.
#[derive(Debug, Error, Diagnostic)]
pub enum CedarEngineError {
    /// The canonical schema failed to load. Indicates a broken build, not a
    /// caller-input error.
    #[error(transparent)]
    #[diagnostic(transparent)]
    SchemaLoad(#[from] openshell_policy_cedar_schema::CedarSchemaLoadError),

    /// The Cedar policy set source failed to parse.
    #[error("Cedar policy parse error: {0}")]
    #[diagnostic(code(openshell::policy_cedar::policy_parse))]
    PolicyParse(#[source] Box<cedar_policy::ParseErrors>),

    /// The enforced subset of a policy set could not be assembled.
    #[error("Cedar policy set error: {0}")]
    #[diagnostic(code(openshell::policy_cedar::policy_set))]
    PolicySet(#[source] Box<cedar_policy::PolicySetError>),

    /// An entity type name used to build a request did not parse (e.g.
    /// `Sandbox::Process`).
    #[error("invalid Cedar entity type name: {0}")]
    #[diagnostic(code(openshell::policy_cedar::entity_type))]
    EntityTypeParse(#[source] Box<cedar_policy::ParseErrors>),

    /// Building one of the request's Cedar entities failed attribute
    /// evaluation.
    #[error("failed to build Cedar entity: {0}")]
    #[diagnostic(code(openshell::policy_cedar::entity_build))]
    EntityBuild(#[source] Box<cedar_policy::EntityAttrEvaluationError>),

    /// Assembling the request's `Entities` store failed (duplicate ids or a
    /// schema-conformance failure).
    #[error("failed to build Cedar entities store: {0}")]
    #[diagnostic(code(openshell::policy_cedar::entities_build))]
    EntitiesBuild(#[source] Box<cedar_policy::entities_errors::EntitiesError>),

    /// Building the request `Context` failed.
    #[error("failed to build Cedar context: {0}")]
    #[diagnostic(code(openshell::policy_cedar::context_build))]
    ContextBuild(#[source] Box<cedar_policy::ContextCreationError>),

    /// The assembled `Request` was rejected by schema validation.
    #[error("Cedar request failed schema validation: {0}")]
    #[diagnostic(code(openshell::policy_cedar::request_build))]
    RequestBuild(#[source] Box<cedar_policy::RequestValidationError>),

    /// A `forbid` policy can apply to `ReadFile` or `WriteFile`.
    ///
    /// Landlock's flat allow-list cannot express forbid-over-permit
    /// carve-outs (e.g. "allow /usr except /usr/secret"), so this is rejected
    /// rather than silently dropped or guessed.
    #[error(
        "policy {policy_id:?} is a forbid that can apply to files, which a Landlock \
         allow-list cannot represent; narrow the permit instead, or limit the forbid's \
         action scope to network actions"
    )]
    #[diagnostic(code(openshell::policy_cedar::filesystem_forbid_unsupported))]
    FilesystemForbidUnsupported {
        /// The id of the offending `forbid` policy.
        policy_id: String,
    },

    /// The policy set failed strict validation against the canonical schema.
    #[error("Cedar policy failed schema validation: {reason}")]
    #[diagnostic(code(openshell::policy_cedar::policy_validation))]
    PolicyValidation {
        /// Every validation error, joined with `"; "`.
        reason: String,
    },

    /// A policy's meaning cannot be enforced exactly as written.
    #[error("policy {policy_id:?} is not supported: {reason}")]
    #[diagnostic(code(openshell::policy_cedar::unsupported_policy))]
    UnsupportedPolicy {
        /// The `@id` annotation of the policy, or its Cedar-assigned id.
        policy_id: String,
        /// What about the policy cannot be enforced, and how to fix it.
        reason: String,
    },

    /// A `NetworkEndpoint` literal in a policy scope is not `"host:port"`.
    #[error("policy {policy_id:?} names invalid endpoint {endpoint:?}: {reason}")]
    #[diagnostic(code(openshell::policy_cedar::invalid_endpoint))]
    InvalidEndpoint {
        /// The `@id` annotation of the policy, or its Cedar-assigned id.
        policy_id: String,
        /// The endpoint literal as written.
        endpoint: String,
        /// Why the literal is invalid.
        reason: String,
    },

    /// An `@protocol` annotation names a protocol Cedar cannot enforce.
    #[error(
        "policy {policy_id:?} declares @protocol({protocol:?}); supported values are \
         \"rest\", \"json-rpc\", \"mcp\", \"graphql\", \"websocket\", and \
         \"websocket-graphql\""
    )]
    #[diagnostic(code(openshell::policy_cedar::unsupported_l7_protocol))]
    UnsupportedL7Protocol {
        /// The `@id` annotation of the policy, or its Cedar-assigned id.
        policy_id: String,
        /// The annotation value as written.
        protocol: String,
    },

    /// An `@enforcement` annotation has a value other than `audit` or `enforce`.
    #[error(
        "policy {policy_id:?} declares @enforcement({enforcement:?}); supported values are \
         \"enforce\" and \"audit\""
    )]
    #[diagnostic(code(openshell::policy_cedar::unsupported_enforcement))]
    UnsupportedEnforcement {
        /// The `@id` annotation of the policy, or its Cedar-assigned id.
        policy_id: String,
        /// The annotation value as written.
        enforcement: String,
    },

    /// An `@path` annotation is not a valid endpoint path pattern.
    #[error("policy {policy_id:?} declares invalid @path({path:?}): {reason}")]
    #[diagnostic(code(openshell::policy_cedar::invalid_l7_path))]
    InvalidL7Path {
        /// The `@id` annotation of the policy, or its Cedar-assigned id.
        policy_id: String,
        /// The annotation value as written.
        path: String,
        /// Why the value is invalid.
        reason: String,
    },

    /// Two policies declare different `@protocol` values for one endpoint path.
    #[error(
        "endpoint {endpoint:?} is declared as both @protocol({first:?}) and @protocol({second:?})"
    )]
    #[diagnostic(code(openshell::policy_cedar::conflicting_l7_protocol))]
    ConflictingL7Protocol {
        /// The endpoint literal as written, followed by its `@path`, if any.
        endpoint: String,
        /// The protocol declared first.
        first: String,
        /// The conflicting protocol declared later.
        second: String,
    },

    /// Two equally specific `@path` patterns of one endpoint can match the
    /// same request but inspect it differently.
    ///
    /// The relay picks the most specific matching path, so between these two
    /// the choice would depend on their order.
    #[error(
        "endpoint {endpoint:?} declares @path({first:?}) and @path({second:?}), which are \
         equally specific and can match the same request, with a different protocol or \
         enforcement; make one path more specific or give both the same inspection"
    )]
    #[diagnostic(code(openshell::policy_cedar::ambiguous_l7_paths))]
    AmbiguousL7Paths {
        /// The endpoint, as `"host:port"`.
        endpoint: String,
        /// One of the two paths; empty for the path-less endpoint.
        first: String,
        /// The other path.
        second: String,
    },

    /// An `@transport` annotation names a transport other than `tcp`.
    #[error(
        "policy {policy_id:?} declares @transport({transport:?}); the supported value is \"tcp\""
    )]
    #[diagnostic(code(openshell::policy_cedar::unsupported_transport))]
    UnsupportedTransport {
        /// The `@id` annotation of the policy, or its Cedar-assigned id.
        policy_id: String,
        /// The annotation value as written.
        transport: String,
    },

    /// A `@transport("tcp")` permit names a host native TCP cannot reach.
    #[error("policy {policy_id:?} declares @transport(\"tcp\") for host {host:?}: {reason}")]
    #[diagnostic(code(openshell::policy_cedar::invalid_tcp_host))]
    InvalidTcpHost {
        /// The `@id` annotation of the policy, or its Cedar-assigned id.
        policy_id: String,
        /// The host as written.
        host: String,
        /// Why the host is invalid.
        reason: String,
    },

    /// A native TCP endpoint overlaps an endpoint that is not native TCP.
    #[error(
        "@transport(\"tcp\") endpoint {tcp_endpoint:?} overlaps {other_endpoint:?}, {reason}; \
         a host and port must be native TCP for every policy or for none"
    )]
    #[diagnostic(code(openshell::policy_cedar::conflicting_transport))]
    ConflictingTransport {
        /// The native TCP endpoint, as `"host:port"`; the host may be a glob.
        tcp_endpoint: String,
        /// The overlapping endpoint, as `"host:port"`; the host may be a glob.
        other_endpoint: String,
        /// How the overlapping endpoint is declared.
        reason: String,
    },

    /// A policy reads `context.destination_ip` in a form whose address
    /// ranges cannot be derived exactly.
    #[error("policy {policy_id:?} has an unsupported destination_ip condition: {reason}")]
    #[diagnostic(code(openshell::policy_cedar::invalid_destination_ip))]
    InvalidDestinationIp {
        /// The `@id` annotation of the policy, or its Cedar-assigned id.
        policy_id: String,
        /// Why the condition is rejected.
        reason: String,
    },

    /// A policy reads `context.binary_aliases` in a form whose binary paths
    /// cannot be collected exactly.
    #[error("policy {policy_id:?} has an unsupported binary_aliases condition: {reason}")]
    #[diagnostic(code(openshell::policy_cedar::invalid_binary_alias))]
    InvalidBinaryAlias {
        /// The `@id` annotation of the policy, or its Cedar-assigned id.
        policy_id: String,
        /// Why the condition is rejected.
        reason: String,
    },

    /// A request's repeated query keys have more value combinations than
    /// Cedar evaluates for one request.
    ///
    /// Each combination is a separate Cedar evaluation, so the count is
    /// capped and a request over it is denied.
    #[error(
        "request query parameters have {combinations} value combinations, more than the \
         {limit} Cedar evaluates for one request"
    )]
    #[diagnostic(code(openshell::policy_cedar::too_many_query_combinations))]
    TooManyQueryCombinations {
        /// The number of combinations, saturating at `usize::MAX`.
        combinations: usize,
        /// The cap, [`crate::MAX_QUERY_COMBINATIONS`].
        limit: usize,
    },

    /// Cedar reported errors while evaluating a request.
    ///
    /// Cedar skips a policy that errors during evaluation, which could turn
    /// an intended `forbid` into an allow, so the request is failed instead.
    #[error("Cedar policy evaluation failed: {reason}")]
    #[diagnostic(code(openshell::policy_cedar::evaluation))]
    Evaluation {
        /// Every evaluation error, joined with `"; "`.
        reason: String,
    },
}
