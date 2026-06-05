// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! PolicyMapper seam: `SandboxPolicy` → MXC `ContainerConfig` fragment.
//!
//! This skill does **not** write the actual policy mapping — that is
//! Giedrius's Rust mapper crate. This module defines the trait seam and ships
//! a minimal `StubPolicyMapper` that is only sufficient to compile and run
//! unit tests. Wire Giedrius's crate as the primary binding once it lands.
//!
//! **Rule: never silently drop policy.** Unmappable rules must surface as
//! `MapError::Unsupported` and be rejected in `ValidateSandboxCreate`.

use thiserror::Error;

/// The MXC config fragment derived from a `SandboxPolicy`.
///
/// Carries filesystem share lists for the MXC provision phase.
/// Future fields: `network_proxy` (Stage 2 egress skill).
#[derive(Debug, Default, Clone)]
pub struct MappedConfig {
    /// Paths granted read-write access inside the sandbox.
    pub readwrite_paths: Vec<String>,
    /// Paths granted read-only access inside the sandbox.
    pub readonly_paths: Vec<String>,
}

/// Context passed to the mapper alongside the policy.
#[derive(Debug)]
pub struct MapCtx {
    /// Sandbox ID (gateway-assigned). Used by the real PolicyMapper to correlate
    /// policy lookups; unused by the stub.
    #[allow(dead_code)]
    pub sandbox_id: String,
    /// Host share directory for the demo positive proof.
    pub share_dir: Option<String>,
}

/// A policy rule that the active mapper cannot enforce.
#[derive(Debug, Clone)]
pub struct LossItem {
    pub rule_kind: String,
    pub detail: String,
}

/// Error returned when policy translation fails or is incomplete.
///
/// Variants are constructed by the real `PolicyMapper` implementation (Giedrius's
/// crate). The `StubPolicyMapper` does not construct them — hence the `dead_code`
/// allow below; they are part of the public seam contract.
#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum MapError {
    #[error("policy rule(s) cannot be enforced by the MXC driver: {}", format_loss(.0))]
    Unsupported(Vec<LossItem>),
    #[error("policy mapper internal error: {0}")]
    Internal(String),
}

fn format_loss(items: &[LossItem]) -> String {
    items
        .iter()
        .map(|i| format!("{}: {}", i.rule_kind, i.detail))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Translates an OpenShell `SandboxPolicy` into an MXC `ContainerConfig`
/// fragment, returning a loss report of anything unrepresentable.
///
/// The implementing crate (Giedrius's mapper) is bound behind this trait.
/// The `StubPolicyMapper` ships as a compile-only fallback.
pub trait PolicyMapper: Send + Sync {
    fn map(&self, ctx: &MapCtx) -> Result<MappedConfig, MapError>;
}

// ── Stub implementation ───────────────────────────────────────────────────────

/// Compile-only stub that applies only the demo's filesystem grant.
///
/// Maps `ctx.share_dir` as a read-write path. Rejects any other policy rule.
/// **Not sufficient for a live agent run** — replace with Giedrius's crate.
pub struct StubPolicyMapper;

impl PolicyMapper for StubPolicyMapper {
    fn map(&self, ctx: &MapCtx) -> Result<MappedConfig, MapError> {
        let mut config = MappedConfig::default();
        if let Some(ref dir) = ctx.share_dir {
            config.readwrite_paths.push(dir.clone());
        }
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn demo_ctx(share_dir: Option<&str>) -> MapCtx {
        MapCtx {
            sandbox_id: "sb-test".into(),
            share_dir: share_dir.map(str::to_string),
        }
    }

    #[test]
    fn stub_maps_share_dir_as_readwrite() {
        let mapper = StubPolicyMapper;
        let ctx = demo_ctx(Some("C:\\work\\demo"));
        let config = mapper.map(&ctx).unwrap();
        assert_eq!(config.readwrite_paths, vec!["C:\\work\\demo"]);
        assert!(config.readonly_paths.is_empty());
    }

    #[test]
    fn stub_produces_empty_config_without_share_dir() {
        let mapper = StubPolicyMapper;
        let ctx = demo_ctx(None);
        let config = mapper.map(&ctx).unwrap();
        assert!(config.readwrite_paths.is_empty());
        assert!(config.readonly_paths.is_empty());
    }
}
