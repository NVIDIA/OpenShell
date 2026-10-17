// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Engine-neutral validation of a gateway-delivered sandbox policy.
//!
//! A policy is validated with [`openshell_policy`] before either engine
//! activates it, whether it is YAML or Cedar. Validation errors are rendered
//! from fixed, implementation-owned categories so authored names, paths, and
//! values never cross the supervisor's load boundary.

use miette::Result;
use openshell_core::proto::SandboxPolicy as ProtoSandboxPolicy;
use openshell_policy::PolicyViolation;

/// Maximum number of fixed categories in one policy-load error.
pub(crate) const POLICY_VALIDATION_DIAGNOSTIC_MAX_ITEMS: usize = 8;
/// Maximum byte length of one policy-load error, including its omission marker.
pub(crate) const POLICY_VALIDATION_DIAGNOSTIC_MAX_BYTES: usize = 512;

/// Validates `policy` and returns its canonical form.
///
/// Applies the same checks to every section a gateway delivers, for YAML and
/// Cedar policies alike: process identity, Landlock, filesystem paths,
/// network endpoints, middleware (names, implementations, failure modes,
/// selectors, and built-in configs), endpoint settings, and the Cedar text.
/// Protobuf cannot distinguish an omitted repeated MCP version field from an
/// empty one, so canonicalization selects the pinned default for both.
///
/// # Errors
///
/// Returns a bounded, redacted diagnostic if the policy is invalid or its
/// network endpoint selectors are ambiguous.
pub fn validate_sandbox_policy(policy: &ProtoSandboxPolicy) -> Result<ProtoSandboxPolicy> {
    let policy = openshell_policy::validate_and_canonicalize_sandbox_policy(policy.clone())
        .map_err(|error| {
            miette::miette!(render_bounded_validation_diagnostics(
                "policy validation failed",
                error
                    .violations()
                    .iter()
                    .map(redacted_policy_violation_category),
            ))
        })?;

    let ambiguities = openshell_policy::find_endpoint_ambiguities(&policy);
    if !ambiguities.is_empty() {
        return Err(miette::miette!(render_repeated_validation_diagnostic(
            "network endpoint ambiguity validation failed",
            ambiguities.len(),
            "ambiguous network endpoint selectors",
        )));
    }
    Ok(policy)
}

/// Select a fixed category without formatting authored fields or nested reasons.
/// Keep this match exhaustive so new validator variants require an explicit
/// decision before their diagnostics can cross the supervisor load boundary.
pub(crate) fn redacted_policy_violation_category(violation: &PolicyViolation) -> &'static str {
    match violation {
        PolicyViolation::InvalidProcessIdentity { .. } => "invalid process identity",
        PolicyViolation::InvalidLandlockCompatibility { .. } => "invalid Landlock compatibility",
        PolicyViolation::PathTraversal { .. }
        | PolicyViolation::RelativePath { .. }
        | PolicyViolation::OverlyBroadPath { .. }
        | PolicyViolation::FieldTooLong { .. } => "invalid filesystem path",
        PolicyViolation::TooManyPaths { .. } => "filesystem path limit exceeded",
        PolicyViolation::TldWildcard { .. }
        | PolicyViolation::TcpEndpointIpLiteral { .. }
        | PolicyViolation::InvalidTcpEndpointHost { .. }
        | PolicyViolation::InvalidHostWildcard { .. } => "invalid network endpoint host",
        PolicyViolation::MissingEndpointHost { .. }
        | PolicyViolation::MissingTcpEndpointHost { .. } => "missing network endpoint host",
        PolicyViolation::MissingEndpointPort { .. }
        | PolicyViolation::InvalidEndpointPort { .. } => "invalid network endpoint port",
        PolicyViolation::MissingSigningService { .. } => {
            "incomplete credential signing configuration"
        }
        PolicyViolation::UnknownCredentialSigning { .. } => {
            "invalid credential signing configuration"
        }
        PolicyViolation::CredentialSigningWithBodyRewrite { .. } => {
            "conflicting credential rewrite configuration"
        }
        PolicyViolation::InvalidL7Endpoint { .. } => "invalid L7 endpoint configuration",
        PolicyViolation::InvalidMiddlewareConfig { .. } => "invalid middleware configuration",
        PolicyViolation::TooManyMiddlewareConfigs { .. } => {
            "middleware configuration limit exceeded"
        }
        PolicyViolation::DuplicateMiddlewareOrder { .. } => "duplicate middleware order",
        PolicyViolation::TooManyMiddlewareSelectorPatterns { .. } => {
            "middleware selector limit exceeded"
        }
        PolicyViolation::MiddlewareTlsSkipConflict { .. } => {
            "middleware conflicts with TLS inspection"
        }
        PolicyViolation::MissingMcpVersions { .. } => "missing MCP protocol version",
        PolicyViolation::McpOptionsOnNonMcpEndpoint { .. } => "MCP options require MCP protocol",
        PolicyViolation::UnsupportedMcpVersion { .. } => "unsupported MCP protocol version",
        PolicyViolation::DuplicateMcpVersion { .. } => "duplicate MCP protocol version",
        PolicyViolation::CedarMutuallyExclusiveWithNetworkPolicies => {
            "cedar_policy_source combined with network_policies"
        }
        PolicyViolation::InvalidCedarPolicy { .. } => "invalid Cedar policy",
        PolicyViolation::EndpointSettingsRequireCedar => "endpoint settings require Cedar",
        PolicyViolation::InvalidEndpointSetting { .. } => "invalid endpoint setting",
    }
}

/// Render only fixed, implementation-owned headings and categories. Reserve
/// space for the omission marker before adding each complete item; never copy
/// or truncate a validator's payload-bearing Display, Debug, or source chain.
pub(crate) fn render_bounded_validation_diagnostics(
    heading: &'static str,
    diagnostics: impl Iterator<Item = &'static str>,
) -> String {
    const OMITTED_SUFFIX: &str = "; additional violations omitted";
    let mut rendered = heading.to_string();
    for (index, category) in diagnostics.enumerate() {
        let separator = if index == 0 { ": " } else { "; " };
        if index == POLICY_VALIDATION_DIAGNOSTIC_MAX_ITEMS
            || rendered.len() + separator.len() + category.len() + OMITTED_SUFFIX.len()
                > POLICY_VALIDATION_DIAGNOSTIC_MAX_BYTES
        {
            rendered.push_str(OMITTED_SUFFIX);
            break;
        }
        rendered.push_str(separator);
        rendered.push_str(category);
    }
    rendered
}

/// String-only validators have no safe fields to expose; retain their stage
/// and bounded item count without inspecting their authored error text.
pub(crate) fn render_repeated_validation_diagnostic(
    heading: &'static str,
    count: usize,
    category: &'static str,
) -> String {
    render_bounded_validation_diagnostics(heading, std::iter::repeat_n(category, count))
}
