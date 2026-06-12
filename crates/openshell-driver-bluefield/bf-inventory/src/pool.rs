// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! VF slot pool. In-memory claim/release of BlueField VFs to sandboxes.

use std::collections::HashMap;
use std::sync::Mutex;

pub use bf_core::VfSlot;

/// Inventory of VF slots with per-sandbox claim tracking.
#[derive(Debug, Default)]
pub struct VfPool {
    slots: Vec<VfSlot>,
    /// sandbox_id -> slot index.
    claims: Mutex<HashMap<String, usize>>,
}

impl VfPool {
    #[must_use]
    pub fn new(slots: impl IntoIterator<Item = VfSlot>) -> Self {
        Self {
            slots: slots.into_iter().collect(),
            claims: Mutex::new(HashMap::new()),
        }
    }

    /// Build a pool from a [`VfInventory`](super::inventory::VfInventory),
    /// discovering the available slots at startup instead of hand-feeding them.
    pub fn from_inventory(
        inventory: &dyn crate::inventory::VfInventory,
    ) -> Result<Self, crate::inventory::VfError> {
        Ok(Self::new(inventory.discover()?))
    }

    /// Claim a free slot for `sandbox_id`. Idempotent: a sandbox that already
    /// holds a slot gets the same one back. Returns `None` when exhausted.
    pub fn claim(&self, sandbox_id: &str) -> Option<VfSlot> {
        let mut claims = self.claims.lock().expect("vf pool claims lock poisoned");
        if let Some(&idx) = claims.get(sandbox_id) {
            return self.slots.get(idx).cloned();
        }
        let used: std::collections::HashSet<usize> = claims.values().copied().collect();
        let free = (0..self.slots.len()).find(|idx| !used.contains(idx))?;
        claims.insert(sandbox_id.to_string(), free);
        self.slots.get(free).cloned()
    }

    /// Claim a specific host BDF for `sandbox_id`. Idempotent for an existing
    /// matching claim and fails if another sandbox owns the slot.
    pub fn claim_by_host_bdf(&self, sandbox_id: &str, host_bdf: &str) -> Option<VfSlot> {
        let mut claims = self.claims.lock().expect("vf pool claims lock poisoned");
        let idx = self
            .slots
            .iter()
            .position(|slot| slot.host_bdf == host_bdf)?;
        if let Some(&existing_idx) = claims.get(sandbox_id) {
            return (existing_idx == idx)
                .then(|| self.slots.get(idx).cloned())
                .flatten();
        }
        if claims.values().any(|&claimed_idx| claimed_idx == idx) {
            return None;
        }
        claims.insert(sandbox_id.to_string(), idx);
        self.slots.get(idx).cloned()
    }

    /// Return the slot with the given host BDF.
    #[must_use]
    pub fn slot_by_host_bdf(&self, host_bdf: &str) -> Option<VfSlot> {
        self.slots
            .iter()
            .find(|slot| slot.host_bdf == host_bdf)
            .cloned()
    }

    /// Release the slot held by `sandbox_id`, if any.
    pub fn release(&self, sandbox_id: &str) {
        self.claims
            .lock()
            .expect("vf pool claims lock poisoned")
            .remove(sandbox_id);
    }
}

#[cfg(test)]
mod tests {
    use super::{VfPool, VfSlot};

    #[test]
    fn claim_is_idempotent_per_sandbox() {
        let pool = VfPool::new([VfSlot::new("vf0", "0000:03:00.2")]);
        let a = pool.claim("sandbox-1").unwrap();
        let b = pool.claim("sandbox-1").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_sandboxes_get_distinct_slots_and_release_frees() {
        let pool = VfPool::new([
            VfSlot::new("vf0", "0000:03:00.2"),
            VfSlot::new("vf1", "0000:03:00.3"),
        ]);
        let s1 = pool.claim("sandbox-1").unwrap();
        let s2 = pool.claim("sandbox-2").unwrap();
        assert_ne!(s1.id, s2.id);
        assert!(pool.claim("sandbox-3").is_none(), "pool exhausted");

        pool.release("sandbox-1");
        let s3 = pool.claim("sandbox-3").unwrap();
        assert_eq!(s3.id, s1.id);
    }

    #[test]
    fn claim_by_host_bdf_reuses_matching_restore_slot() {
        let pool = VfPool::new([
            VfSlot::new("vf0", "0000:03:00.2"),
            VfSlot::new("vf1", "0000:03:00.3"),
        ]);

        let restored = pool.claim_by_host_bdf("sandbox-1", "0000:03:00.3").unwrap();
        assert_eq!(restored.id, "vf1");
        assert_eq!(
            pool.claim_by_host_bdf("sandbox-1", "0000:03:00.3")
                .unwrap()
                .id,
            "vf1"
        );
        assert!(
            pool.claim_by_host_bdf("sandbox-2", "0000:03:00.3")
                .is_none(),
            "claimed restore slot is not reused by another sandbox"
        );
    }
}
