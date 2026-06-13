// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Network-function inventory discovery.
//!
//! Replaces hand-fed function slots with discovery behind a trait, so the same
//! extension works in both topologies and is unit-testable against a mock
//! `/sys` (no hardware):
//!
//! - [`StaticFunctionInventory`] — an explicit slot list (pinned setups, tests).
//! - [`SysfsVfInventory`] — **host** side: enumerates a PF's VFs from
//!   `/sys/bus/pci/devices/<pf>/virtfn<N>` to get each VF's BDF + index.
//! - [`SysfsRepresentorInventory`] — **DPU** side: enumerates switchdev
//!   representor netdevs and reads `phys_port_name` (`pfXvfY`) to map a VF
//!   coordinate to its representor / OVS port.
//!
//! Other function kinds (SF, virtio-net) plug in as additional implementations
//! of [`FunctionInventory`] without changing the allocation layer.
//!
//! The two sides agree on a [`NetFunction`] = `(kind, pf, index)`. The host uses
//! the PF's PCI BDF as the `pf` key; the DPU uses the e-switch PF index. Mapping
//! one to the other on a given deployment is a config concern (the host PF
//! BDF that backs `pf0`), kept out of this mechanical discovery layer.

use std::path::PathBuf;

use bf_core::{FunctionSlot, NetFunction};
use openshell_vfio::SysfsRoot;

/// Error surface for inventory discovery.
#[derive(Debug, Clone)]
pub enum InventoryError {
    Discovery(String),
}

impl core::fmt::Display for InventoryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Discovery(m) => write!(f, "function discovery failed: {m}"),
        }
    }
}

impl std::error::Error for InventoryError {}

pub type InventoryResult<T> = Result<T, InventoryError>;

/// Source of the function slots a [`super::pool::FunctionPool`] hands to
/// sandboxes.
pub trait FunctionInventory: core::fmt::Debug + Send + Sync {
    /// Enumerate all function slots this inventory knows about.
    fn discover(&self) -> InventoryResult<Vec<FunctionSlot>>;

    /// Resolve the representor for a function coordinate. Defaults to a scan of
    /// [`discover`](Self::discover); sysfs impls may override for efficiency.
    fn resolve_representor(&self, function: &NetFunction) -> InventoryResult<Option<String>> {
        Ok(self
            .discover()?
            .into_iter()
            .find(|s| {
                s.pf.as_deref() == Some(function.pf.as_str()) && s.index == Some(function.index)
            })
            .and_then(|s| s.representor))
    }
}

/// Explicit, hand-fed inventory. Equivalent to the original `FunctionPool::new`
/// behavior; ideal for tests and pinned deployments.
#[derive(Debug, Default, Clone)]
pub struct StaticFunctionInventory {
    slots: Vec<FunctionSlot>,
}

impl StaticFunctionInventory {
    #[must_use]
    pub fn new(slots: impl IntoIterator<Item = FunctionSlot>) -> Self {
        Self {
            slots: slots.into_iter().collect(),
        }
    }
}

impl FunctionInventory for StaticFunctionInventory {
    fn discover(&self) -> InventoryResult<Vec<FunctionSlot>> {
        Ok(self.slots.clone())
    }
}

/// Host-side inventory: enumerates SR-IOV VFs of one or more PFs from sysfs.
#[derive(Debug)]
pub struct SysfsVfInventory {
    sysfs: SysfsRoot,
    /// PF PCI BDFs whose VFs are available to sandboxes.
    pfs: Vec<String>,
    /// Safety cap on the per-PF `virtfn<N>` scan.
    max_vfs: u32,
}

impl SysfsVfInventory {
    #[must_use]
    pub fn new(sysfs: SysfsRoot, pfs: impl IntoIterator<Item = String>) -> Self {
        Self {
            sysfs,
            pfs: pfs.into_iter().collect(),
            max_vfs: 256,
        }
    }
}

impl FunctionInventory for SysfsVfInventory {
    fn discover(&self) -> InventoryResult<Vec<FunctionSlot>> {
        let mut slots = Vec::new();
        for pf in &self.pfs {
            let pf_dir = self.sysfs.pci_device(pf);
            for index in 0..self.max_vfs {
                let link = pf_dir.join(format!("virtfn{index}"));
                // `symlink_metadata` so a dangling/!exists link stops the scan
                // without following into a missing target.
                if link.symlink_metadata().is_err() {
                    break;
                }
                let target = std::fs::read_link(&link).map_err(|e| {
                    InventoryError::Discovery(format!("read_link {}: {e}", link.display()))
                })?;
                let vf_bdf = target
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or_else(|| {
                        InventoryError::Discovery(format!(
                            "virtfn target has no bdf: {}",
                            target.display()
                        ))
                    })?
                    .to_string();
                let mut slot = FunctionSlot::new(vf_bdf.clone(), vf_bdf.clone())
                    .with_pf(pf.clone())
                    .with_index(index);
                if let Some(mac) = read_vf_mac(&self.sysfs, &vf_bdf) {
                    slot = slot.with_mac(mac);
                }
                slots.push(slot);
            }
        }
        Ok(slots)
    }
}

fn read_vf_mac(sysfs: &SysfsRoot, vf_bdf: &str) -> Option<String> {
    let net_dir = sysfs.pci_device(vf_bdf).join("net");
    let entries = std::fs::read_dir(net_dir).ok()?;
    let mut ifaces = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    ifaces.sort();
    for iface in ifaces {
        let Ok(address) = std::fs::read_to_string(iface.join("address")) else {
            continue;
        };
        let address = address.trim();
        if !address.is_empty() {
            return Some(address.to_ascii_lowercase());
        }
    }
    None
}

/// DPU-side inventory: maps VF coordinates to switchdev representor netdevs by
/// reading `phys_port_name` under the net sysfs tree.
#[derive(Debug)]
pub struct SysfsRepresentorInventory {
    /// Base of the net sysfs tree (default `/sys/class/net`).
    net_sysfs: PathBuf,
}

impl Default for SysfsRepresentorInventory {
    fn default() -> Self {
        Self {
            net_sysfs: PathBuf::from("/sys/class/net"),
        }
    }
}

impl SysfsRepresentorInventory {
    #[must_use]
    pub fn new(net_sysfs: impl Into<PathBuf>) -> Self {
        Self {
            net_sysfs: net_sysfs.into(),
        }
    }
}

/// Parse a switchdev VF-representor `phys_port_name` (e.g. `pf0vf3`) into a
/// `(pf_index, vf_index)`. Returns `None` for non-VF ports (uplinks, PFs).
fn parse_phys_port_name(s: &str) -> Option<(u32, u32)> {
    let s = s.trim();
    let pf_pos = s.find("pf")?;
    let after_pf = &s[pf_pos + 2..];
    let vf_pos = after_pf.find("vf")?;
    let pf_num: u32 = after_pf[..vf_pos].parse().ok()?;
    let vf_num: u32 = after_pf[vf_pos + 2..].parse().ok()?;
    Some((pf_num, vf_num))
}

impl FunctionInventory for SysfsRepresentorInventory {
    fn discover(&self) -> InventoryResult<Vec<FunctionSlot>> {
        let mut slots = Vec::new();
        let entries = std::fs::read_dir(&self.net_sysfs).map_err(|e| {
            InventoryError::Discovery(format!("read_dir {}: {e}", self.net_sysfs.display()))
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| InventoryError::Discovery(e.to_string()))?;
            let ifname = entry.file_name().to_string_lossy().into_owned();
            let ppn_path = entry.path().join("phys_port_name");
            let Ok(ppn) = std::fs::read_to_string(&ppn_path) else {
                continue;
            };
            let Some((pf_index, vf_index)) = parse_phys_port_name(&ppn) else {
                continue;
            };
            slots.push(
                FunctionSlot::new(ifname.clone(), String::new())
                    .with_pf(pf_index.to_string())
                    .with_index(vf_index)
                    .with_representor(ifname.clone())
                    .with_ovs_port(ifname),
            );
        }
        Ok(slots)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_sysfs_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("openshell-{name}-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn sysfs_vf_inventory_reads_mac_from_vf_netdev() {
        let root = temp_sysfs_root("vf-mac");
        let devices = root.join("bus/pci/devices");
        let pf = devices.join("0000:03:00.0");
        let vf = devices.join("0000:03:00.2");
        std::fs::create_dir_all(&pf).unwrap();
        std::fs::create_dir_all(vf.join("net/enp3s0v0")).unwrap();
        std::fs::write(vf.join("net/enp3s0v0/address"), "86:7F:6E:5B:E0:7B\n").unwrap();
        symlink("../0000:03:00.2", pf.join("virtfn0")).unwrap();

        let inventory = SysfsVfInventory::new(SysfsRoot::new(&root), ["0000:03:00.0".to_string()]);
        let slots = inventory.discover().unwrap();

        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].host_bdf, "0000:03:00.2");
        assert_eq!(slots[0].index, Some(0));
        assert_eq!(slots[0].mac.as_deref(), Some("86:7f:6e:5b:e0:7b"));

        std::fs::remove_dir_all(root).unwrap();
    }
}
