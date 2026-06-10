// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! PolicyMapper seam: `SandboxPolicy` → MXC `ContainerConfig` fragment.
//!
//! This file does **not** write the actual policy mapping rules — that logic is
//! **embedded** as the [`crate::policy_map`] module (the source of truth; it was
//! the standalone `openshell-policy-mapper` crate). This file defines the trait
//! seam plus:
//!
//! - [`EmbeddedPolicyMapper`] — the **primary** impl. Calls
//!   [`crate::policy_map::map_to_mxc`] directly on the typed `SandboxPolicy`
//!   proto (no YAML bridge), extracts the MXC filesystem shares, normalizes
//!   their paths to Windows form, and rejects the create on any `error`-severity
//!   loss.
//! - [`StubPolicyMapper`] — a compile-only fallback that grants only the demo
//!   `share_dir`. Kept so the crate builds/tests without exercising the embed.
//!
//! **Rule: never silently drop policy.** Unmappable rules surface as
//! `MapError::Unsupported` and are rejected in `ValidateSandboxCreate`.

use openshell_core::proto::SandboxPolicy;
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
    /// Sandbox ID (gateway-assigned). Used as the MXC `containerId` and to
    /// correlate diagnostics.
    pub sandbox_id: String,
    /// Host share directory for the demo positive proof. Always granted
    /// read-write so `hello.txt` is visible on the host.
    pub share_dir: Option<String>,
}

/// A policy rule that the active mapper cannot enforce.
#[derive(Debug, Clone)]
pub struct LossItem {
    pub rule_kind: String,
    pub detail: String,
}

/// Error returned when policy translation fails or is incomplete.
#[derive(Debug, Error)]
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
pub trait PolicyMapper: Send + Sync {
    /// `policy` is `None` only when the gateway failed to stage one (the MXC
    /// path treats that as a hard error — the demo's whole point is enforcement).
    fn map(&self, policy: Option<&SandboxPolicy>, ctx: &MapCtx) -> Result<MappedConfig, MapError>;
}

// ── Path normalization ──────────────────────────────────────────────────────

/// Normalize forward-slash paths to Windows backslash form. Path normalization
/// lives here, in one place — the embedded mapper copies path strings through
/// unchanged.
fn normalize_path(p: &str) -> String {
    p.replace('/', "\\")
}

// ── Embedded mapper (primary impl) ──────────────────────────────────────────

/// Primary `PolicyMapper`: calls the embedded `policy_map` module (the source of
/// truth) directly on the typed `SandboxPolicy` proto.
pub struct EmbeddedPolicyMapper;

fn extract_paths(config: &serde_json::Value, key: &str) -> Vec<String> {
    config["filesystem"][key]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

impl PolicyMapper for EmbeddedPolicyMapper {
    fn map(&self, policy: Option<&SandboxPolicy>, ctx: &MapCtx) -> Result<MappedConfig, MapError> {
        let policy = policy.ok_or_else(|| {
            MapError::Internal(
                "MXC driver requires a sandbox policy, but none was staged for this sandbox"
                    .to_owned(),
            )
        })?;

        // Map directly off the typed proto. The MXC driver runs an isolation
        // session, so use that containment: its network branch yields an
        // `error` loss for any host allowlist, which is what rejects network
        // policy below.
        let opts = crate::policy_map::MxcMappingOptions {
            containment: "isolation_session".to_owned(),
            container_id: ctx.sandbox_id.clone(),
            ..Default::default()
        };
        let result = crate::policy_map::map_to_mxc(policy, &opts);

        // Reject the create on any error-severity loss. Warnings/info (e.g. the
        // filesystem default-deny note) are advisory and do not block.
        let errors: Vec<LossItem> = result
            .loss
            .iter()
            .filter(|i| i.severity == "error")
            .map(|i| LossItem {
                rule_kind: i.path.clone(),
                detail: i.message.clone(),
            })
            .collect();
        if !errors.is_empty() {
            return Err(MapError::Unsupported(errors));
        }

        // The embedded mapper copies paths verbatim; normalize them (and the
        // demo share dir) to Windows backslash form here, in one place.
        let mut readwrite: Vec<String> = extract_paths(&result.config, "readwritePaths")
            .iter()
            .map(|p| normalize_path(p))
            .collect();
        let readonly: Vec<String> = extract_paths(&result.config, "readonlyPaths")
            .iter()
            .map(|p| normalize_path(p))
            .collect();

        // Always grant the demo host-visible share read-write so the positive
        // proof artifact (`hello.txt`) appears on the host. For the demo this
        // equals the policy's read_write path, so it does not broaden access.
        if let Some(dir) = &ctx.share_dir {
            let norm = normalize_path(dir);
            if !readwrite.contains(&norm) {
                readwrite.push(norm);
            }
        }

        Ok(MappedConfig {
            readwrite_paths: readwrite,
            readonly_paths: readonly,
        })
    }
}

// ── Stub implementation (compile-only fallback) ─────────────────────────────

/// Compile-only stub that applies only the demo's filesystem grant.
///
/// Ignores the policy and maps `ctx.share_dir` as a read-write path. Kept so the
/// crate compiles/tests without exercising the embedded mapper. **Not sufficient
/// for a meaningful policy demo** — use [`EmbeddedPolicyMapper`].
///
/// Retained as a documented scaffolding fallback (see SKILL Step 7); the default
/// backend uses [`EmbeddedPolicyMapper`], so this is unused outside tests.
#[allow(dead_code)]
pub struct StubPolicyMapper;

impl PolicyMapper for StubPolicyMapper {
    fn map(&self, _policy: Option<&SandboxPolicy>, ctx: &MapCtx) -> Result<MappedConfig, MapError> {
        let mut config = MappedConfig::default();
        if let Some(ref dir) = ctx.share_dir {
            config.readwrite_paths.push(normalize_path(dir));
        }
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::FilesystemPolicy;

    fn demo_ctx(share_dir: Option<&str>) -> MapCtx {
        MapCtx {
            sandbox_id: "sb-test".into(),
            share_dir: share_dir.map(str::to_string),
        }
    }

    fn fs_policy(rw: &[&str], ro: &[&str]) -> SandboxPolicy {
        SandboxPolicy {
            filesystem: Some(FilesystemPolicy {
                include_workdir: false,
                read_only: ro.iter().map(|s| s.to_string()).collect(),
                read_write: rw.iter().map(|s| s.to_string()).collect(),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn stub_maps_share_dir_as_readwrite() {
        let mapper = StubPolicyMapper;
        let ctx = demo_ctx(Some("C:\\work\\demo"));
        let config = mapper.map(None, &ctx).unwrap();
        assert_eq!(config.readwrite_paths, vec!["C:\\work\\demo"]);
        assert!(config.readonly_paths.is_empty());
    }

    #[test]
    fn embedded_maps_policy_read_write_to_share() {
        let mapper = EmbeddedPolicyMapper;
        let policy = fs_policy(&["C:/work/openshell-mxc-demo"], &["C:/tools"]);
        let ctx = demo_ctx(Some("C:/work/openshell-mxc-demo"));
        let config = mapper.map(Some(&policy), &ctx).unwrap();
        // Forward slashes normalized to Windows backslashes by the bridge.
        assert!(
            config
                .readwrite_paths
                .contains(&"C:\\work\\openshell-mxc-demo".to_string())
        );
        assert_eq!(config.readonly_paths, vec!["C:\\tools"]);
    }

    #[test]
    fn embedded_rejects_missing_policy() {
        let mapper = EmbeddedPolicyMapper;
        let ctx = demo_ctx(Some("C:/work/demo"));
        let err = mapper.map(None, &ctx).unwrap_err();
        assert!(matches!(err, MapError::Internal(_)));
    }

    #[test]
    fn embedded_rejects_network_policy_on_isolation_session() {
        use openshell_core::proto::{NetworkEndpoint, NetworkPolicyRule};
        let mapper = EmbeddedPolicyMapper;
        let mut policy = fs_policy(&["C:/work/demo"], &[]);
        policy.network_policies.insert(
            "api".to_string(),
            NetworkPolicyRule {
                name: "api".into(),
                endpoints: vec![NetworkEndpoint {
                    host: "example.com".into(),
                    ..Default::default()
                }],
                binaries: Vec::new(),
            },
        );
        let ctx = demo_ctx(Some("C:/work/demo"));
        let err = mapper.map(Some(&policy), &ctx).unwrap_err();
        assert!(matches!(err, MapError::Unsupported(_)));
    }
}
