// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_vfio::{
    GpuBindGuard, GpuBindState, GpuBinding, GpuInfo, SysfsRoot, prepare_gpu_for_passthrough,
    probe_host_nvidia_vfio_readiness, reconcile_stale_bindings, validate_bdf,
};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

/// Tracks available GPUs and their assignment to sandboxes.
pub struct GpuInventory {
    slots: Vec<GpuSlot>,
    sysfs: SysfsRoot,
    state_path: PathBuf,
}

struct GpuSlot {
    info: GpuInfo,
    assigned_to: Option<String>,
    bind_guard: Option<GpuBindGuard>,
}

impl GpuInventory {
    pub fn new(sysfs: SysfsRoot, state_dir: &Path) -> Self {
        let state_path = state_dir.join("gpu-bindings.json");

        let restored = reconcile_stale_bindings(&sysfs, &state_path);
        for bdf in &restored {
            tracing::info!(bdf = %bdf, "restored stale GPU binding from previous crash");
        }

        let gpus = probe_host_nvidia_vfio_readiness(&sysfs);
        let slots = gpus
            .into_iter()
            .map(|info| GpuSlot {
                info,
                assigned_to: None,
                bind_guard: None,
            })
            .collect();

        Self {
            slots,
            sysfs,
            state_path,
        }
    }

    pub fn gpu_count(&self) -> u32 {
        self.slots.len() as u32
    }

    pub fn available_count(&self) -> u32 {
        self.slots
            .iter()
            .filter(|s| s.assigned_to.is_none())
            .count() as u32
    }

    /// Assign a GPU to a sandbox. Returns the assignment details including BDF.
    pub fn assign(&mut self, sandbox_id: &str, gpu_device: &str) -> Result<GpuAssignment, String> {
        let slot_idx = if gpu_device.is_empty() {
            self.slots
                .iter()
                .position(|s| s.assigned_to.is_none())
                .ok_or_else(|| "all GPUs are currently assigned to other sandboxes".to_string())?
        } else if let Ok(idx) = gpu_device.parse::<usize>() {
            if idx >= self.slots.len() {
                return Err(format!(
                    "GPU index {idx} out of range (have {} GPUs)",
                    self.slots.len()
                ));
            }
            if self.slots[idx].assigned_to.is_some() {
                return Err(format!(
                    "GPU at index {idx} ({}) is already assigned to another sandbox",
                    self.slots[idx].info.bdf
                ));
            }
            idx
        } else {
            validate_bdf(gpu_device).map_err(|e| e.to_string())?;
            let idx = self
                .slots
                .iter()
                .position(|s| s.info.bdf == gpu_device)
                .ok_or_else(|| format!("GPU {gpu_device} not found in inventory"))?;
            if self.slots[idx].assigned_to.is_some() {
                return Err(format!(
                    "GPU {gpu_device} is already assigned to another sandbox"
                ));
            }
            idx
        };

        let bdf = self.slots[slot_idx].info.bdf.clone();
        let guard = prepare_gpu_for_passthrough(&self.sysfs, &bdf)
            .map_err(|e| format!("failed to prepare GPU {bdf} for passthrough: {e}"))?;

        self.slots[slot_idx].assigned_to = Some(sandbox_id.to_string());
        self.slots[slot_idx].bind_guard = Some(guard);
        self.persist_state();

        Ok(GpuAssignment {
            bdf,
            name: self.slots[slot_idx].info.name.clone(),
            iommu_group: self.slots[slot_idx].info.iommu_group,
        })
    }

    /// Release a GPU assignment. The `GpuBindGuard` is dropped, restoring the GPU.
    pub fn release(&mut self, sandbox_id: &str) {
        if let Some(slot) = self
            .slots
            .iter_mut()
            .find(|s| s.assigned_to.as_deref() == Some(sandbox_id))
        {
            let bdf = slot.info.bdf.clone();
            slot.assigned_to = None;
            slot.bind_guard.take();
            self.persist_state();
            tracing::info!(bdf = %bdf, sandbox_id = %sandbox_id, "released GPU assignment");
        }
    }

    fn persist_state(&self) {
        let bindings: Vec<GpuBinding> = self
            .slots
            .iter()
            .filter_map(|s| {
                s.assigned_to.as_ref().map(|id| GpuBinding {
                    bdf: s.info.bdf.clone(),
                    sandbox_id: id.clone(),
                    bound_at_ms: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_millis() as i64),
                })
            })
            .collect();
        let state = GpuBindState { bindings };
        if let Err(err) = state.save(&self.state_path) {
            tracing::warn!(error = %err, "failed to persist GPU bind state");
        }
    }
}

pub struct GpuAssignment {
    pub bdf: String,
    pub name: String,
    pub iommu_group: u32,
}

// ---------------------------------------------------------------------------
// Subnet allocation for per-sandbox TAP networking
// ---------------------------------------------------------------------------

/// Allocates /30 subnets from a pool for per-sandbox TAP networking.
pub struct SubnetAllocator {
    base: Ipv4Addr,
    prefix_len: u8,
    next_offset: u32,
    allocated: HashMap<String, SubnetAllocation>,
}

pub struct SubnetAllocation {
    pub host_ip: Ipv4Addr,
    pub guest_ip: Ipv4Addr,
    pub prefix_len: u8,
    pub offset: u32,
}

static NEXT_VSOCK_CID: AtomicU32 = AtomicU32::new(3);

impl SubnetAllocator {
    pub fn new(base: Ipv4Addr, prefix_len: u8) -> Self {
        Self {
            base,
            prefix_len,
            next_offset: 0,
            allocated: HashMap::new(),
        }
    }

    pub fn allocate(&mut self, sandbox_id: &str) -> Result<SubnetAllocation, String> {
        let pool_size = 1u32 << (32 - self.prefix_len);
        let max_subnets = pool_size / 4;

        if self.allocated.len() as u32 >= max_subnets {
            return Err("subnet pool exhausted".to_string());
        }

        while self
            .allocated
            .values()
            .any(|a| a.offset == self.next_offset)
        {
            self.next_offset = (self.next_offset + 1) % max_subnets;
        }

        let base_u32 = u32::from(self.base);
        let subnet_base = base_u32 + (self.next_offset * 4);
        let host_ip = Ipv4Addr::from(subnet_base + 1);
        let guest_ip = Ipv4Addr::from(subnet_base + 2);

        let allocation = SubnetAllocation {
            host_ip,
            guest_ip,
            prefix_len: 30,
            offset: self.next_offset,
        };

        self.allocated.insert(sandbox_id.to_string(), allocation);
        self.next_offset = (self.next_offset + 1) % max_subnets;

        let alloc = &self.allocated[sandbox_id];
        Ok(SubnetAllocation {
            host_ip: alloc.host_ip,
            guest_ip: alloc.guest_ip,
            prefix_len: alloc.prefix_len,
            offset: alloc.offset,
        })
    }

    pub fn release(&mut self, sandbox_id: &str) {
        self.allocated.remove(sandbox_id);
    }
}

pub fn allocate_vsock_cid() -> u32 {
    NEXT_VSOCK_CID.fetch_add(1, Ordering::Relaxed)
}

/// Generate a locally-administered MAC from sandbox ID using FNV-1a.
pub fn mac_from_sandbox_id(sandbox_id: &str) -> [u8; 6] {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in sandbox_id.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let bytes = hash.to_le_bytes();
    let mut mac = [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]];
    mac[0] = (mac[0] & 0xFE) | 0x02;
    mac
}

/// TAP device name from sandbox ID (fits `IFNAMSIZ=16`).
pub fn tap_device_name(sandbox_id: &str) -> String {
    let end = sandbox_id.len().min(8);
    let end = sandbox_id.floor_char_boundary(end);
    let prefix = &sandbox_id[..end];
    format!("vmtap-{prefix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnet_allocator_assigns_sequential_blocks() {
        let mut alloc = SubnetAllocator::new(Ipv4Addr::new(10, 0, 128, 0), 17);

        let s1 = alloc.allocate("sandbox-1").unwrap();
        assert_eq!(s1.host_ip, Ipv4Addr::new(10, 0, 128, 1));
        assert_eq!(s1.guest_ip, Ipv4Addr::new(10, 0, 128, 2));
        assert_eq!(s1.prefix_len, 30);

        let s2 = alloc.allocate("sandbox-2").unwrap();
        assert_eq!(s2.host_ip, Ipv4Addr::new(10, 0, 128, 5));
        assert_eq!(s2.guest_ip, Ipv4Addr::new(10, 0, 128, 6));
    }

    #[test]
    fn subnet_allocator_recycles_after_release() {
        let mut alloc = SubnetAllocator::new(Ipv4Addr::new(10, 0, 128, 0), 17);

        let _s1 = alloc.allocate("sandbox-1").unwrap();
        let _s2 = alloc.allocate("sandbox-2").unwrap();
        alloc.release("sandbox-1");

        let s3 = alloc.allocate("sandbox-3").unwrap();
        assert_eq!(s3.host_ip, Ipv4Addr::new(10, 0, 128, 9));
    }

    #[test]
    fn tap_device_name_truncates_long_ids() {
        assert_eq!(tap_device_name("abc"), "vmtap-abc");
        assert_eq!(tap_device_name("abcdefghijklmnop"), "vmtap-abcdefgh");
    }

    #[test]
    fn mac_from_sandbox_id_sets_locally_administered_bit() {
        let mac = mac_from_sandbox_id("sandbox-123");
        assert_eq!(mac[0] & 0x02, 0x02, "locally-administered bit must be set");
        assert_eq!(mac[0] & 0x01, 0x00, "multicast bit must be clear");
    }

    #[test]
    fn mac_from_sandbox_id_deterministic() {
        let mac1 = mac_from_sandbox_id("sandbox-x");
        let mac2 = mac_from_sandbox_id("sandbox-x");
        assert_eq!(mac1, mac2);

        let mac3 = mac_from_sandbox_id("sandbox-y");
        assert_ne!(mac1, mac3);
    }

    #[test]
    fn vsock_cid_increments() {
        let cid1 = allocate_vsock_cid();
        let cid2 = allocate_vsock_cid();
        assert_eq!(cid2, cid1 + 1);
    }
}
