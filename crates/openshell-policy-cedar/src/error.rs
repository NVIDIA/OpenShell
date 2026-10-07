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
         \"rest\" and \"json-rpc\""
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

    /// Two policies declare different `@protocol` values for one endpoint.
    #[error(
        "endpoint {endpoint:?} is declared as both @protocol({first:?}) and @protocol({second:?})"
    )]
    #[diagnostic(code(openshell::policy_cedar::conflicting_l7_protocol))]
    ConflictingL7Protocol {
        /// The endpoint literal as written.
        endpoint: String,
        /// The protocol declared first.
        first: String,
        /// The conflicting protocol declared later.
        second: String,
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
