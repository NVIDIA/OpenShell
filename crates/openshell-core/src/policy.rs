// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox policy configuration.

use crate::paths::normalize_path;
use crate::proto::{
    FilesystemPolicy as ProtoFilesystemPolicy, LandlockPolicy as ProtoLandlockPolicy,
    ProcessPolicy as ProtoProcessPolicy, SandboxPolicy as ProtoSandboxPolicy,
};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    pub version: u32,
    pub filesystem: FilesystemPolicy,
    pub network: NetworkPolicy,
    pub landlock: LandlockPolicy,
    pub process: ProcessPolicy,
}

#[derive(Debug, Clone)]
pub struct FilesystemPolicy {
    /// Read-only directory allow list.
    pub read_only: Vec<PathBuf>,

    /// Read-write directory allow list.
    pub read_write: Vec<PathBuf>,

    /// Automatically include the workdir as read-write.
    pub include_workdir: bool,
}

impl Default for FilesystemPolicy {
    fn default() -> Self {
        Self {
            read_only: Vec::new(),
            read_write: Vec::new(),
            include_workdir: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkPolicy {
    pub mode: NetworkMode,
    pub proxy: Option<ProxyPolicy>,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            mode: NetworkMode::Block,
            proxy: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub enum NetworkMode {
    #[default]
    Block,
    Proxy,
    Allow,
}

#[derive(Debug, Clone)]
pub struct ProxyPolicy {
    /// TCP address for a local HTTP proxy (loopback-only).
    pub http_addr: Option<SocketAddr>,
}

#[derive(Debug, Clone, Default)]
pub struct LandlockPolicy {
    pub compatibility: LandlockCompatibility,
}

#[derive(Debug, Clone, Default)]
pub struct ProcessPolicy {
    /// User name to run the sandboxed process as.
    pub run_as_user: Option<String>,

    /// Group name to run the sandboxed process as.
    pub run_as_group: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub enum LandlockCompatibility {
    #[default]
    BestEffort,
    HardRequirement,
}

/// Accepted `landlock.compatibility` values in their proto string form.
///
/// Single source of truth shared by YAML parsing, proto→runtime conversion,
/// and gateway policy validation so the accepted set cannot drift.
pub const LANDLOCK_COMPATIBILITY_VALUES: [&str; 2] = ["best_effort", "hard_requirement"];

/// Returns `true` if `value` is an accepted `landlock.compatibility` string.
///
/// The empty string is accepted and defaults to `best_effort`.
pub fn is_valid_landlock_compatibility(value: &str) -> bool {
    value.is_empty() || LANDLOCK_COMPATIBILITY_VALUES.contains(&value)
}

// ============================================================================
// Proto to Rust type conversions
// ============================================================================

impl TryFrom<ProtoSandboxPolicy> for SandboxPolicy {
    type Error = miette::Report;

    fn try_from(proto: ProtoSandboxPolicy) -> Result<Self, Self::Error> {
        // In cluster mode we always run with proxy networking so all egress
        // can be evaluated by OPA and `inference.local` is always addressable.
        let network = NetworkPolicy {
            mode: NetworkMode::Proxy,
            proxy: Some(ProxyPolicy { http_addr: None }),
        };

        Ok(Self {
            version: proto.version,
            filesystem: proto
                .filesystem
                .map(FilesystemPolicy::from)
                .unwrap_or_default(),
            network,
            landlock: proto
                .landlock
                .map(LandlockPolicy::try_from)
                .transpose()?
                .unwrap_or_default(),
            process: proto.process.map(ProcessPolicy::from).unwrap_or_default(),
        })
    }
}

impl From<ProtoFilesystemPolicy> for FilesystemPolicy {
    fn from(proto: ProtoFilesystemPolicy) -> Self {
        Self {
            read_only: proto
                .read_only
                .into_iter()
                .map(|p| PathBuf::from(normalize_path(&p)))
                .collect(),
            read_write: proto
                .read_write
                .into_iter()
                .map(|p| PathBuf::from(normalize_path(&p)))
                .collect(),
            include_workdir: proto.include_workdir,
        }
    }
}

impl TryFrom<ProtoLandlockPolicy> for LandlockPolicy {
    type Error = miette::Error;

    fn try_from(proto: ProtoLandlockPolicy) -> Result<Self, Self::Error> {
        let compatibility = match proto.compatibility.as_str() {
            "best_effort" | "" => LandlockCompatibility::BestEffort,
            "hard_requirement" => LandlockCompatibility::HardRequirement,
            otherwise => miette::bail!(
                "invalid landlock.compatibility {:?}; accepted: {}",
                otherwise,
                LANDLOCK_COMPATIBILITY_VALUES.join(", ")
            ),
        };
        Ok(Self { compatibility })
    }
}

impl From<ProtoProcessPolicy> for ProcessPolicy {
    fn from(proto: ProtoProcessPolicy) -> Self {
        Self {
            run_as_user: if proto.run_as_user.is_empty() {
                None
            } else {
                Some(proto.run_as_user)
            },
            run_as_group: if proto.run_as_group.is_empty() {
                None
            } else {
                Some(proto.run_as_group)
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_from_maps_known_compatibility_values() {
        for (input, expected) in [
            ("", LandlockCompatibility::BestEffort),
            ("best_effort", LandlockCompatibility::BestEffort),
            ("hard_requirement", LandlockCompatibility::HardRequirement),
        ] {
            let proto = ProtoLandlockPolicy {
                compatibility: input.into(),
            };
            let policy = LandlockPolicy::try_from(proto).expect("should convert");
            assert_eq!(
                std::mem::discriminant(&policy.compatibility),
                std::mem::discriminant(&expected),
                "input {input:?} mapped to unexpected variant",
            );
        }
    }

    #[test]
    fn try_from_rejects_invalid_compatibility() {
        let proto = ProtoLandlockPolicy {
            compatibility: "hard-requirement".into(),
        };
        let err = LandlockPolicy::try_from(proto).expect_err("should reject");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("best_effort") && msg.contains("hard_requirement"),
            "error should list accepted values, got: {msg}",
        );
    }

    #[test]
    fn is_valid_landlock_compatibility_accepts_empty_and_known() {
        assert!(is_valid_landlock_compatibility(""));
        assert!(is_valid_landlock_compatibility("best_effort"));
        assert!(is_valid_landlock_compatibility("hard_requirement"));
        assert!(!is_valid_landlock_compatibility("nope"));
        assert!(!is_valid_landlock_compatibility("BestEffort"));
    }
}
