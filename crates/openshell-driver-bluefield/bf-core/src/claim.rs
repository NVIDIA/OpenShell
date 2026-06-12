//! Runtime-neutral BlueField resource claims.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkMode {
    #[default]
    ProxyOnly,
    DirectDevice,
}

impl NetworkMode {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ProxyOnly => "proxy-only",
            Self::DirectDevice => "direct-device",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "proxy" | "proxy-only" | "proxy_only" => Some(Self::ProxyOnly),
            "direct" | "direct-device" | "direct_device" | "vf" | "sriov" => {
                Some(Self::DirectDevice)
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageMode {
    #[default]
    None,
    Workspace,
    VmDisk,
}

impl StorageMode {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Workspace => "workspace",
            Self::VmDisk => "vm-disk",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "none" | "disabled" => Some(Self::None),
            "workspace" | "workspaces" => Some(Self::Workspace),
            "vm-disk" | "vm_disk" | "vmdisk" => Some(Self::VmDisk),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpuClaim {
    pub claim_id: String,
    pub sandbox_id: String,
    pub runtime: String,
    pub network_mode: NetworkMode,
    pub storage_mode: StorageMode,
    pub attachment_id: Option<String>,
    pub lease_generation: u64,
    pub node: Option<String>,
    pub workload_identity: Option<String>,
    pub policy_hash: Option<String>,
}

impl DpuClaim {
    #[must_use]
    pub fn new(
        claim_id: impl Into<String>,
        sandbox_id: impl Into<String>,
        runtime: impl Into<String>,
        network_mode: NetworkMode,
        storage_mode: StorageMode,
    ) -> Self {
        Self {
            claim_id: claim_id.into(),
            sandbox_id: sandbox_id.into(),
            runtime: runtime.into(),
            network_mode,
            storage_mode,
            attachment_id: None,
            lease_generation: 0,
            node: None,
            workload_identity: None,
            policy_hash: None,
        }
    }
}
