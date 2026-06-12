// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Host VF slot discovery and BlueField-specific slot preparation.

use std::collections::HashSet;

use bf_inventory::{SysfsVfInventory, VfInventory, VfSlot};
use openshell_vfio::SysfsRoot;

use crate::config::BluefieldDriverConfig;
use crate::host_pf::resolve_host_pf;

pub(crate) struct HostSlotConfig<'a> {
    reserved_vf_indexes: &'a [u32],
    pf_key: Option<&'a str>,
    egress_cidr_pool: &'a [String],
}

impl<'a> From<&'a BluefieldDriverConfig> for HostSlotConfig<'a> {
    fn from(config: &'a BluefieldDriverConfig) -> Self {
        Self {
            reserved_vf_indexes: &config.reserved_vf_indexes,
            pf_key: config.pf_key.as_deref().filter(|value| !value.is_empty()),
            egress_cidr_pool: &config.egress_cidr_pool,
        }
    }
}

pub(crate) fn resolve_host_pf_bdf(config: &BluefieldDriverConfig) -> Result<String, String> {
    let resolved = resolve_host_pf(config.host_pf.as_deref(), std::path::Path::new("/sys"))?;
    Ok(resolved.bdf)
}

/// Discover the local VF slots for `host_pf` and apply the operator's
/// reservations, PF-key rewrite, and egress-pool addressing. Shared by every
/// host-side role so the local pool is built identically.
pub(crate) fn prepare_host_slots(
    config: HostSlotConfig<'_>,
    sysfs: &SysfsRoot,
    host_pf: &str,
) -> Result<Vec<VfSlot>, String> {
    let inventory = SysfsVfInventory::new(sysfs.clone(), [host_pf.to_string()]);
    let mut slots = inventory
        .discover()
        .map_err(|err| format!("discover BlueField VFs for host PF {host_pf}: {err}"))?;
    apply_slot_config(&config, &mut slots)?;
    if slots.is_empty() {
        return Err(format!("BlueField host PF {host_pf} has no discovered VFs"));
    }
    Ok(slots)
}

fn apply_slot_config(config: &HostSlotConfig<'_>, slots: &mut Vec<VfSlot>) -> Result<(), String> {
    if !config.reserved_vf_indexes.is_empty() {
        let reserved: HashSet<u32> = config.reserved_vf_indexes.iter().copied().collect();
        slots.retain(|slot| match slot.vf_index {
            Some(index) => !reserved.contains(&index),
            None => true,
        });
    }
    if let Some(pf_key) = config.pf_key {
        for slot in slots.iter_mut() {
            slot.pf = Some(pf_key.to_string());
        }
    }
    if !config.egress_cidr_pool.is_empty() {
        if config.egress_cidr_pool.len() < slots.len() {
            return Err(format!(
                "BlueField egress pool has {} addresses for {} usable VFs",
                config.egress_cidr_pool.len(),
                slots.len()
            ));
        }
        for (slot, address) in slots.iter_mut().zip(config.egress_cidr_pool.iter()) {
            slot.guest_datapath_address = Some(address.clone());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{HostSlotConfig, apply_slot_config};
    use bf_inventory::VfSlot;

    #[test]
    fn applies_reserved_indexes_pf_key_and_egress_pool() {
        let mut slots = vec![
            VfSlot::new("vf0", "0000:03:00.2")
                .with_pf("p0")
                .with_vf_index(0),
            VfSlot::new("vf1", "0000:03:00.3")
                .with_pf("p0")
                .with_vf_index(1),
        ];
        let egress_pool = vec!["10.0.120.61/22".to_string()];
        let config = HostSlotConfig {
            reserved_vf_indexes: &[0],
            pf_key: Some("bf-a"),
            egress_cidr_pool: &egress_pool,
        };

        apply_slot_config(&config, &mut slots).unwrap();

        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].host_bdf, "0000:03:00.3");
        assert_eq!(slots[0].pf.as_deref(), Some("bf-a"));
        assert_eq!(
            slots[0].guest_datapath_address.as_deref(),
            Some("10.0.120.61/22")
        );
    }

    #[test]
    fn rejects_egress_pool_shorter_than_usable_slots() {
        let mut slots = vec![
            VfSlot::new("vf0", "0000:03:00.2").with_vf_index(0),
            VfSlot::new("vf1", "0000:03:00.3").with_vf_index(1),
        ];
        let egress_pool = vec!["10.0.120.61/22".to_string()];
        let config = HostSlotConfig {
            reserved_vf_indexes: &[],
            pf_key: None,
            egress_cidr_pool: &egress_pool,
        };

        let err = apply_slot_config(&config, &mut slots).unwrap_err();

        assert!(err.contains("egress pool has 1 addresses for 2 usable VFs"));
    }
}
