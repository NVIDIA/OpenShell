//! Shared BlueField handles that cross the driver, host, and DPU seam.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VfSlot {
    pub id: String,
    pub host_bdf: String,
    pub pf: Option<String>,
    pub vf_index: Option<u32>,
    pub representor: Option<String>,
    pub ovs_port: Option<String>,
    pub guest_datapath_address: Option<String>,
    pub guest_mac: Option<String>,
}

impl VfSlot {
    #[must_use]
    pub fn new(id: impl Into<String>, host_bdf: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            host_bdf: host_bdf.into(),
            pf: None,
            vf_index: None,
            representor: None,
            ovs_port: None,
            guest_datapath_address: None,
            guest_mac: None,
        }
    }

    #[must_use]
    pub fn with_pf(mut self, pf: impl Into<String>) -> Self {
        self.pf = Some(pf.into());
        self
    }

    #[must_use]
    pub fn with_vf_index(mut self, vf_index: u32) -> Self {
        self.vf_index = Some(vf_index);
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
    pub fn with_guest_datapath_address(mut self, address: impl Into<String>) -> Self {
        self.guest_datapath_address = Some(address.into());
        self
    }

    #[must_use]
    pub fn with_guest_mac(mut self, mac: impl Into<String>) -> Self {
        self.guest_mac = Some(mac.into());
        self
    }

    #[must_use]
    pub fn vf_ref(&self) -> Option<VfRef> {
        match (&self.pf, self.vf_index) {
            (Some(pf), Some(idx)) => Some(VfRef::new(pf.clone(), idx)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VfRef {
    pub pf: String,
    pub vf_index: u32,
}

impl VfRef {
    #[must_use]
    pub fn new(pf: impl Into<String>, vf_index: u32) -> Self {
        Self {
            pf: pf.into(),
            vf_index,
        }
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
    pub vf: VfRef,
    pub host_bdf: String,
    pub representor: Option<String>,
    pub guest_ip: Option<String>,
    pub guest_mac: Option<String>,
    pub openshell_endpoint: Option<String>,
    pub sandbox_token: Option<String>,
}
