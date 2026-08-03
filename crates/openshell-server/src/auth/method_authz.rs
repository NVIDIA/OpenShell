// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Aggregated auth metadata for every gRPC method.
//!
//! Delegates to the descriptor-pool-based auth table in `descriptor_authz`,
//! which reads per-method `(openshell.options.v1.authorization)` annotations
//! from the compiled `FileDescriptorSet`.

pub use super::descriptor_authz::DescriptorAuthEntry;

/// How a gRPC method is authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// No authentication required (e.g. health probes).
    Unauthenticated,
    /// Only callable by a `Principal::Sandbox` (gateway-minted sandbox JWT).
    /// See `auth/sandbox_jwt.rs`.
    Sandbox,
    /// Bearer (OIDC) authentication required.
    Bearer,
    /// Either sandbox principal or Bearer; scope and role apply on
    /// the Bearer path only.
    Dual,
}

/// Coarse role mapping. Maps to the configured `admin_role` /
/// `user_role` names at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Role {
    Admin,
    User,
}

/// Find the auth metadata for `method`, if any.
#[must_use]
pub fn lookup(method: &str) -> Option<&'static DescriptorAuthEntry> {
    super::descriptor_authz::lookup(method)
}

/// All registered RPC paths across every service.
#[cfg(test)]
pub fn all_paths() -> impl Iterator<Item = &'static str> {
    super::descriptor_authz::all_paths()
}

/// Required role for the method on the Bearer path.
#[must_use]
#[allow(dead_code)]
pub fn required_role(method: &str) -> Option<Role> {
    lookup(method).and_then(DescriptorAuthEntry::effective_role)
}

/// `true` if the method bypasses authentication entirely.
///
/// Note: this checks the per-method tables only. The prefix-based
/// bypass for gRPC reflection and health probes is layered on top by
/// `oidc::is_unauthenticated_method`.
#[must_use]
pub fn is_unauthenticated(method: &str) -> bool {
    matches!(
        lookup(method).map(|m| m.auth_mode),
        Some(AuthMode::Unauthenticated)
    )
}

/// `true` if the method is callable by a `Principal::Sandbox`
/// (`sandbox` or `dual` auth mode).
#[must_use]
pub fn is_sandbox_callable(method: &str) -> bool {
    matches!(
        lookup(method).map(|m| m.auth_mode),
        Some(AuthMode::Sandbox | AuthMode::Dual)
    )
}

/// `true` if the method is callable by a `Principal::User` (`bearer` or
/// `dual` auth mode).
///
/// Unknown methods return `true` so [`super::authz::AuthzPolicy::check`]
/// still gets a chance to evaluate role/scope and apply the
/// `openshell:all` fallback — the exhaustiveness test prevents this
/// branch from ever firing for real RPCs, but it remains as
/// defense-in-depth.
#[must_use]
pub fn is_user_callable(method: &str) -> bool {
    match lookup(method).map(|m| m.auth_mode) {
        Some(AuthMode::Sandbox | AuthMode::Unauthenticated) => false,
        Some(AuthMode::Bearer | AuthMode::Dual) | None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every RPC path in the descriptor pool is resolvable through this
    /// delegation layer.
    #[test]
    fn every_proto_rpc_has_an_annotation() {
        for path in all_paths() {
            assert!(lookup(path).is_some(), "lookup failed for path: {path}");
        }
    }

    /// No path appears more than once.
    #[test]
    fn no_duplicate_paths_across_services() {
        let mut seen: Vec<&str> = Vec::new();
        for path in all_paths() {
            assert!(!seen.contains(&path), "duplicate path: {path}");
            seen.push(path);
        }
    }

    /// User principals must be rejected for `sandbox` and `unauthenticated`
    /// methods; the auth-mode check at the router enforces this regardless
    /// of role/scope, closing the gap where a token with `openshell:all`
    /// could otherwise reach sandbox-only handlers.
    #[test]
    fn user_callable_matches_auth_mode() {
        // Bearer
        assert!(is_user_callable("/openshell.v1.OpenShell/ListSandboxes"));
        // Dual
        assert!(is_user_callable("/openshell.v1.OpenShell/GetSandboxConfig"));
        // Sandbox-only
        assert!(!is_user_callable(
            "/openshell.v1.OpenShell/ReportPolicyStatus"
        ));
        assert!(!is_user_callable("/openshell.v1.OpenShell/PushSandboxLogs"));
        assert!(!is_user_callable(
            "/openshell.v1.OpenShell/GetSandboxProviderEnvironment"
        ));
        assert!(!is_user_callable(
            "/openshell.v1.OpenShell/SubmitPolicyAnalysis"
        ));
        assert!(!is_user_callable(
            "/openshell.v1.OpenShell/ConnectSupervisor"
        ));
        assert!(!is_user_callable("/openshell.v1.OpenShell/RelayStream"));
        assert!(!is_user_callable(
            "/openshell.inference.v1.Inference/GetInferenceBundle"
        ));
        // Unauthenticated methods are not "user callable" — they're
        // intercepted before principal evaluation.
        assert!(!is_user_callable("/openshell.v1.OpenShell/Health"));
        // Unknown method falls through to AuthzPolicy::check.
        assert!(is_user_callable("/openshell.v1.OpenShell/FutureMethod"));
    }
}
