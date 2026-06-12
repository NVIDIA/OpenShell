//! Deployment role for the BlueField compute driver.
//!
//! A single driver binary runs in one of three roles, selected at startup.
//! The role is workload-agnostic, so it lives in `bf-core` and is reused by
//! every leaf driver (`bf-vm`, a future `bf-container`, ...).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Which part of the split topology this driver instance plays.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BluefieldRole {
    /// In-process control + compute on one node (dev / single host).
    #[default]
    AllInOne,
    /// Leader: allocates VFs, programs OVS via the DPU controller, and
    /// forwards sandbox lifecycle to a downstream compute-node driver. Never
    /// binds a VF or launches a workload itself.
    ControlPlane,
    /// Follower: binds the leader-assigned VF and launches the workload.
    /// Holds no control-plane endpoint.
    ComputeNode,
}

impl BluefieldRole {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AllInOne => "all-in-one",
            Self::ControlPlane => "control-plane",
            Self::ComputeNode => "compute-node",
        }
    }

    /// True when this role allocates VFs and drives the DPU controller.
    #[must_use]
    pub fn is_control_plane(self) -> bool {
        matches!(self, Self::AllInOne | Self::ControlPlane)
    }

    /// True when this role binds a VF and launches the workload locally.
    #[must_use]
    pub fn runs_workload(self) -> bool {
        matches!(self, Self::AllInOne | Self::ComputeNode)
    }
}

impl fmt::Display for BluefieldRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for BluefieldRole {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "all-in-one" => Ok(Self::AllInOne),
            "control-plane" => Ok(Self::ControlPlane),
            "compute-node" => Ok(Self::ComputeNode),
            other => Err(format!(
                "invalid BlueField role {other:?}; expected 'all-in-one', 'control-plane', or 'compute-node'"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_str() {
        for role in [
            BluefieldRole::AllInOne,
            BluefieldRole::ControlPlane,
            BluefieldRole::ComputeNode,
        ] {
            assert_eq!(role.as_str().parse::<BluefieldRole>().unwrap(), role);
        }
    }

    #[test]
    fn default_is_all_in_one() {
        assert_eq!(BluefieldRole::default(), BluefieldRole::AllInOne);
    }

    #[test]
    fn capability_predicates() {
        assert!(BluefieldRole::ControlPlane.is_control_plane());
        assert!(!BluefieldRole::ControlPlane.runs_workload());
        assert!(BluefieldRole::ComputeNode.runs_workload());
        assert!(!BluefieldRole::ComputeNode.is_control_plane());
        assert!(BluefieldRole::AllInOne.is_control_plane());
        assert!(BluefieldRole::AllInOne.runs_workload());
    }

    #[test]
    fn rejects_unknown_role() {
        let err = "leader".parse::<BluefieldRole>().unwrap_err();
        assert!(err.contains("invalid BlueField role"));
    }
}
