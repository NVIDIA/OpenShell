//! Sandbox policy configuration.

use navigator_core::proto::{
    self, FilesystemPolicy as ProtoFilesystemPolicy, LandlockCompatibility as ProtoLandlockCompat,
    LandlockPolicy as ProtoLandlockPolicy, NetworkMode as ProtoNetworkMode,
    NetworkPolicy as ProtoNetworkPolicy, ProcessPolicy as ProtoProcessPolicy,
    SandboxPolicy as ProtoSandboxPolicy,
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

// ============================================================================
// Proto to Rust type conversions
// ============================================================================

impl TryFrom<ProtoSandboxPolicy> for SandboxPolicy {
    type Error = miette::Report;

    fn try_from(proto: ProtoSandboxPolicy) -> Result<Self, Self::Error> {
        Ok(Self {
            version: proto.version,
            filesystem: proto
                .filesystem
                .map(FilesystemPolicy::from)
                .unwrap_or_default(),
            network: proto
                .network
                .map(NetworkPolicy::try_from)
                .transpose()?
                .unwrap_or_default(),
            landlock: proto.landlock.map(LandlockPolicy::from).unwrap_or_default(),
            process: proto.process.map(ProcessPolicy::from).unwrap_or_default(),
        })
    }
}

impl From<ProtoFilesystemPolicy> for FilesystemPolicy {
    fn from(proto: ProtoFilesystemPolicy) -> Self {
        Self {
            read_only: proto.read_only.into_iter().map(PathBuf::from).collect(),
            read_write: proto.read_write.into_iter().map(PathBuf::from).collect(),
            include_workdir: proto.include_workdir,
        }
    }
}

impl TryFrom<ProtoNetworkPolicy> for NetworkPolicy {
    type Error = miette::Report;

    fn try_from(proto: ProtoNetworkPolicy) -> Result<Self, Self::Error> {
        let mode = match proto::NetworkMode::try_from(proto.mode) {
            Ok(ProtoNetworkMode::Proxy) => NetworkMode::Proxy,
            Ok(ProtoNetworkMode::Allow) => NetworkMode::Allow,
            Ok(ProtoNetworkMode::Block | ProtoNetworkMode::Unspecified) | Err(_) => {
                NetworkMode::Block
            }
        };

        let proxy = proto.proxy.map(|p| ProxyPolicy {
            http_addr: if p.http_addr.is_empty() {
                None
            } else {
                p.http_addr.parse().ok()
            },
        });

        Ok(Self { mode, proxy })
    }
}

impl From<ProtoLandlockPolicy> for LandlockPolicy {
    fn from(proto: ProtoLandlockPolicy) -> Self {
        let compatibility = match proto::LandlockCompatibility::try_from(proto.compatibility) {
            Ok(ProtoLandlockCompat::HardRequirement) => LandlockCompatibility::HardRequirement,
            _ => LandlockCompatibility::BestEffort,
        };
        Self { compatibility }
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
