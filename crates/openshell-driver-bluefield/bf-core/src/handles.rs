//! Shared BlueField handles that cross the driver, host, and DPU seam.

use serde::{Deserialize, Serialize};

/// The kind of network function backing a sandbox.
///
/// BlueField can hand a sandbox different function types depending on the
/// runtime and fabric configuration. The discovery and allocation layers are
/// kind-agnostic; this discriminant lets a consumer (and the attach mechanism)
/// know which kind a slot represents.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FunctionKind {
    /// SR-IOV virtual function (the `bf-vm` passthrough path).
    #[default]
    Vf,
    /// Scalable Function (e.g. container/Kubernetes adapters via `mlnx-sf`).
    Sf,
}

impl FunctionKind {
    /// Stable wire/label string for this kind.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vf => "vf",
            Self::Sf => "sf",
        }
    }

    /// Parse a [`FunctionKind`] from its wire/label string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "vf" => Some(Self::Vf),
            "sf" => Some(Self::Sf),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionSlot {
    pub id: String,
    pub host_bdf: String,
    pub kind: FunctionKind,
    pub pf: Option<String>,
    /// Identity index within the parent PF. `vf_index` for a VF, `sf_num` for
    /// an SF, function index for a virtio-net device.
    pub index: Option<u32>,
    pub representor: Option<String>,
    pub ovs_port: Option<String>,
    pub datapath_address: Option<String>,
    pub mac: Option<String>,
}

impl FunctionSlot {
    #[must_use]
    pub fn new(id: impl Into<String>, host_bdf: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            host_bdf: host_bdf.into(),
            kind: FunctionKind::Vf,
            pf: None,
            index: None,
            representor: None,
            ovs_port: None,
            datapath_address: None,
            mac: None,
        }
    }

    #[must_use]
    pub fn with_kind(mut self, kind: FunctionKind) -> Self {
        self.kind = kind;
        self
    }

    #[must_use]
    pub fn with_pf(mut self, pf: impl Into<String>) -> Self {
        self.pf = Some(pf.into());
        self
    }

    #[must_use]
    pub fn with_index(mut self, index: u32) -> Self {
        self.index = Some(index);
        self
    }

    #[must_use]
    pub fn with_representor(mut self, representor: impl Into<String>) -> Self {
        self.representor = Some(representor.into());
        self
    }

    #[must_use]
    pub fn with_ovs_port(mut self, ovs_port: impl Into<String>) -> Self {
        self.ovs_port = Some(ovs_port.into());
        self
    }

    #[must_use]
    pub fn with_datapath_address(mut self, address: impl Into<String>) -> Self {
        self.datapath_address = Some(address.into());
        self
    }

    #[must_use]
    pub fn with_mac(mut self, mac: impl Into<String>) -> Self {
        self.mac = Some(mac.into());
        self
    }

    #[must_use]
    pub fn net_function(&self) -> Option<NetFunction> {
        match (&self.pf, self.index) {
            (Some(pf), Some(idx)) => Some(NetFunction::new(pf.clone(), idx).with_kind(self.kind)),
            _ => None,
        }
    }
}

/// A reference to a single network function: `(kind, pf, index)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetFunction {
    pub kind: FunctionKind,
    pub pf: String,
    pub index: u32,
}

impl NetFunction {
    #[must_use]
    pub fn new(pf: impl Into<String>, index: u32) -> Self {
        Self {
            kind: FunctionKind::Vf,
            pf: pf.into(),
            index,
        }
    }

    #[must_use]
    pub fn with_kind(mut self, kind: FunctionKind) -> Self {
        self.kind = kind;
        self
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ProxyPlacement {
    #[default]
    None,
    Dpu,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachSpec {
    pub sandbox_id: String,
    pub function: NetFunction,
    pub host_bdf: String,
    pub representor: Option<String>,
    pub endpoint_ip: Option<String>,
    pub mac: Option<String>,
    pub openshell_endpoint: Option<String>,
    pub sandbox_token: Option<String>,
}
