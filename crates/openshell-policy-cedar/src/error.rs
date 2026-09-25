// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Rust guideline compliant 2026-09-19

//! Typed errors for [`crate::CedarNetworkEngine`].

use miette::Diagnostic;
use thiserror::Error;

/// Errors produced while loading or evaluating Cedar policy for the sandbox
/// `NetworkConnect` action.
#[derive(Debug, Error, Diagnostic)]
pub enum CedarEngineError {
    /// The `.cedarschema` source failed to parse.
    #[error("Cedar schema parse error: {0}")]
    #[diagnostic(code(openshell::policy_cedar::schema_parse))]
    SchemaParse(#[source] Box<cedar_policy::CedarSchemaError>),

    /// The Cedar policy set source failed to parse.
    #[error("Cedar policy parse error: {0}")]
    #[diagnostic(code(openshell::policy_cedar::policy_parse))]
    PolicyParse(#[source] Box<cedar_policy::ParseErrors>),

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
}
