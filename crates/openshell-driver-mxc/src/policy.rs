// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `PolicyMapper` seam: `SandboxPolicy` → MXC `ContainerConfig` fragment.
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
//!
//! **Rule: never silently drop policy.** Unmappable rules surface as
//! `MapError::Unsupported` and are rejected by `CreateSandbox` before lifecycle side effects.

use std::net::SocketAddr;

use openshell_core::proto::SandboxPolicy;
use thiserror::Error;

/// The MXC config fragment derived from a `SandboxPolicy`.
///
/// Carries filesystem share lists for the MXC provision phase, plus the
/// Pattern-C governed-egress handoff when enabled.
#[derive(Debug, Default, Clone)]
pub struct MappedConfig {
    /// Paths granted read-write access inside the sandbox.
    pub readwrite_paths: Vec<String>,
    /// Paths granted read-only access inside the sandbox.
    pub readonly_paths: Vec<String>,
    /// Network-only policy for the host CONNECT proxy. `None` on the coarse
    /// filesystem-only path.
    pub trimmed_policy: Option<SandboxPolicy>,
    /// Loopback address MXC redirects sandbox egress to. `None` when governed
    /// egress is disabled.
    pub proxy_addr: Option<SocketAddr>,
}

/// Context passed to the mapper alongside the policy.
#[derive(Debug)]
pub struct MapCtx {
    /// Sandbox ID (gateway-assigned). Used as the MXC `containerId` and to
    /// correlate diagnostics.
    pub sandbox_id: String,
    /// Pattern-C governed-egress redirect address. When set, the embedded
    /// mapper uses `split_policy`; otherwise it uses the coarse MXC map.
    pub egress: Option<SocketAddr>,
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

/// Translates an `OpenShell` `SandboxPolicy` into an MXC `ContainerConfig`
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

        let (config, loss, trimmed_policy, proxy_addr) = if let Some(addr) = ctx.egress {
            // Pattern C: MXC handles filesystem + a proxy redirect, while the
            // host CONNECT proxy receives the network-only trimmed policy.
            let opts = crate::policy_map::MxcMappingOptions {
                containment: "processcontainer".to_owned(),
                container_id: ctx.sandbox_id.clone(),
                proxy_redirect: Some(addr),
                ..Default::default()
            };
            let result = crate::policy_map::split_policy(policy, &opts).ok_or_else(|| {
                MapError::Internal(
                    "egress proxy was enabled but no proxy address was supplied".into(),
                )
            })?;
            (
                result.mxc_config,
                result.loss,
                Some(result.proxy_policy),
                Some(addr),
            )
        } else {
            // Map directly off the typed proto. The default MXC driver path runs
            // an isolation session, so use that containment: its network branch
            // yields an `error` loss for any host allowlist, which rejects
            // network policy below.
            let opts = crate::policy_map::MxcMappingOptions {
                containment: "isolation_session".to_owned(),
                container_id: ctx.sandbox_id.clone(),
                ..Default::default()
            };
            let result = crate::policy_map::map_to_mxc(policy, &opts);
            (result.config, result.loss, None, None)
        };

        // Reject the create on any error-severity loss. Warnings/info (e.g. the
        // filesystem default-deny note) are advisory and do not block.
        let errors: Vec<LossItem> = loss
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

        // The embedded mapper copies paths verbatim; normalize them to Windows
        // backslash form here, in one place.
        let readwrite: Vec<String> = extract_paths(&config, "readwritePaths")
            .iter()
            .map(|p| normalize_path(p))
            .collect();
        let readonly: Vec<String> = extract_paths(&config, "readonlyPaths")
            .iter()
            .map(|p| normalize_path(p))
            .collect();

        Ok(MappedConfig {
            readwrite_paths: readwrite,
            readonly_paths: readonly,
            trimmed_policy,
            proxy_addr,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::FilesystemPolicy;

    fn demo_ctx() -> MapCtx {
        MapCtx {
            sandbox_id: "sb-test".into(),
            egress: None,
        }
    }

    fn fs_policy(rw: &[&str], ro: &[&str]) -> SandboxPolicy {
        SandboxPolicy {
            filesystem: Some(FilesystemPolicy {
                include_workdir: false,
                read_only: ro.iter().map(ToString::to_string).collect(),
                read_write: rw.iter().map(ToString::to_string).collect(),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn embedded_maps_policy_read_write_to_share() {
        let mapper = EmbeddedPolicyMapper;
        let policy = fs_policy(&["C:/work/openshell-mxc-demo"], &["C:/tools"]);
        let ctx = demo_ctx();
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
        let ctx = demo_ctx();
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
        let ctx = demo_ctx();
        let err = mapper.map(Some(&policy), &ctx).unwrap_err();
        assert!(matches!(err, MapError::Unsupported(_)));
    }

    #[test]
    fn embedded_split_normalizes_paths_and_returns_proxy_handoff() {
        use openshell_core::proto::{NetworkBinary, NetworkEndpoint, NetworkPolicyRule};
        let mapper = EmbeddedPolicyMapper;
        let mut policy = fs_policy(&["C:/work/demo"], &["C:/tools"]);
        policy.version = 1;
        policy.network_policies.insert(
            "api".to_string(),
            NetworkPolicyRule {
                name: "api".into(),
                endpoints: vec![NetworkEndpoint {
                    host: "example.com".into(),
                    ports: vec![443],
                    protocol: "rest".into(),
                    ..Default::default()
                }],
                binaries: vec![NetworkBinary {
                    path: "/usr/bin/curl".into(),
                    ..Default::default()
                }],
            },
        );
        let proxy_addr = "127.0.0.1:18080".parse().unwrap();
        let ctx = MapCtx {
            sandbox_id: "sb-egress".into(),

            egress: Some(proxy_addr),
        };

        let config = mapper.map(Some(&policy), &ctx).unwrap();
        assert_eq!(config.readwrite_paths, vec!["C:\\work\\demo"]);
        assert_eq!(config.readonly_paths, vec!["C:\\tools"]);
        assert_eq!(config.proxy_addr, Some(proxy_addr));
        let trimmed = config.trimmed_policy.expect("trimmed policy");
        assert_eq!(trimmed.version, policy.version);
        assert_eq!(trimmed.network_policies, policy.network_policies);
        assert!(trimmed.filesystem.is_none());
    }
}
