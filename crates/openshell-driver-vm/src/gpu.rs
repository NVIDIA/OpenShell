// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_vfio::{
    GpuBindGuard, GpuBindState, GpuBinding, GpuInfo, SysfsRoot, prepare_gpu_for_passthrough,
    probe_host_nvidia_vfio_readiness, reconcile_stale_bindings, validate_bdf,
};
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
        u32::try_from(self.slots.len()).unwrap_or(u32::MAX)
    }

    pub fn available_count(&self) -> u32 {
        u32::try_from(
            self.slots
                .iter()
                .filter(|s| s.assigned_to.is_none())
                .count(),
        )
        .unwrap_or(u32::MAX)
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
                        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX)),
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

static NEXT_VSOCK_CID: AtomicU32 = AtomicU32::new(3);

pub fn allocate_vsock_cid() -> u32 {
    NEXT_VSOCK_CID.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vsock_cid_increments() {
        let cid1 = allocate_vsock_cid();
        let cid2 = allocate_vsock_cid();
        assert_eq!(cid2, cid1 + 1);
    }
}
