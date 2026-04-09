// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared image-name resolution for community sandbox images.
//!
//! Both the CLI and TUI need to expand bare sandbox names (e.g. `"base"`) into
//! fully-qualified container image references. This module centralises that
//! logic so every client resolves names identically.

/// Default registry prefix for community sandbox images.
///
/// Bare sandbox names are expanded to `{prefix}/{name}:latest`.
/// Override at runtime with the `OPENSHELL_COMMUNITY_REGISTRY` env var.
pub const DEFAULT_COMMUNITY_REGISTRY: &str = "ghcr.io/nvidia/openshell-community/sandboxes";

/// Resolve a user-supplied image string into a fully-qualified reference.
///
/// Resolution rules (applied in order):
/// 1. If the value contains `/`, `:`, or `.` it is treated as a complete image
///    reference and returned as-is.
/// 2. Otherwise it is treated as a community sandbox name and expanded to
///    `{registry}/{value}:latest` where `{registry}` defaults to
///    [`DEFAULT_COMMUNITY_REGISTRY`] but can be overridden via the
///    `OPENSHELL_COMMUNITY_REGISTRY` environment variable.
///
/// This function only handles image-name resolution. Dockerfile detection is
/// the responsibility of the caller (e.g. the CLI's `resolve_from()`).
pub fn resolve_community_image(value: &str) -> String {
    // Already a fully-qualified reference.
    if value.contains('/') || value.contains(':') || value.contains('.') {
        return value.to_string();
    }

    // Community sandbox shorthand → expand with registry prefix.
    let prefix = std::env::var("OPENSHELL_COMMUNITY_REGISTRY")
        .unwrap_or_else(|_| DEFAULT_COMMUNITY_REGISTRY.to_string());
    let prefix = prefix.trim_end_matches('/');
    format!("{prefix}/{value}:latest")
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;

    #[test]
    fn bare_name_expands_to_community_registry() {
        let result = resolve_community_image("base");
        assert_eq!(
            result,
            "ghcr.io/nvidia/openshell-community/sandboxes/base:latest"
        );
    }

    #[test]
    fn bare_name_with_env_override() {
        // Use a temp env override. Safety: test-only, and these env-var tests
        // are not run concurrently with other tests reading the same var.
        let key = "OPENSHELL_COMMUNITY_REGISTRY";
        let prev = std::env::var(key).ok();
        // SAFETY: single-threaded test context; no other thread reads this var.
        unsafe { std::env::set_var(key, "my-registry.example.com/sandboxes") };
        let result = resolve_community_image("python");
        assert_eq!(result, "my-registry.example.com/sandboxes/python:latest");
        // Restore.
        match prev {
            Some(v) => unsafe { std::env::set_var(key, v) },
            None => unsafe { std::env::remove_var(key) },
        }
    }

    #[test]
    fn full_reference_with_slash_passes_through() {
        let input = "ghcr.io/myorg/myimage:v1";
        assert_eq!(resolve_community_image(input), input);
    }

    #[test]
    fn reference_with_colon_passes_through() {
        let input = "myimage:latest";
        assert_eq!(resolve_community_image(input), input);
    }

    #[test]
    fn reference_with_dot_passes_through() {
        let input = "registry.example.com";
        assert_eq!(resolve_community_image(input), input);
    }

    #[test]
    fn trailing_slash_in_env_is_trimmed() {
        let key = "OPENSHELL_COMMUNITY_REGISTRY";
        let prev = std::env::var(key).ok();
        // SAFETY: single-threaded test context; no other thread reads this var.
        unsafe { std::env::set_var(key, "my-registry.example.com/sandboxes/") };
        let result = resolve_community_image("base");
        assert_eq!(result, "my-registry.example.com/sandboxes/base:latest");
        match prev {
            Some(v) => unsafe { std::env::set_var(key, v) },
            None => unsafe { std::env::remove_var(key) },
        }
    }
}
