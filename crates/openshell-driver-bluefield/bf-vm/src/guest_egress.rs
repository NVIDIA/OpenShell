// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Guest VF egress wiring: the `OPENSHELL_VM_DATA_*` env contract and the
//! guest-init drop-in that consumes it.

use crate::lifecycle::GuestInitDropin;

use bf_inventory::FunctionSlot;

const ENV_EGRESS: &str = "OPENSHELL_VM_DATA_EGRESS";
const ENV_IP_MODE: &str = "OPENSHELL_VM_DATA_IP_MODE";
const ENV_IP: &str = "OPENSHELL_VM_DATA_IP";
const ENV_GATEWAY: &str = "OPENSHELL_VM_DATA_GW";
const ENV_MAC: &str = "OPENSHELL_VM_DATA_MAC";
const EGRESS_EXTERNAL_VF: &str = "external-vf";
const IP_MODE_STATIC: &str = "static";
const DROPIN_SCRIPT: &[u8] = include_bytes!("../scripts/guest-egress-dropin.sh");

/// Static egress parameters for a sandbox's data-path VF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestEgress {
    pub address_cidr: String,
    pub gateway: String,
}

impl GuestEgress {
    /// Build the `OPENSHELL_VM_DATA_*` env vars the guest-init drop-in reads.
    /// A per-slot `datapath_address` overrides `address_cidr`.
    #[must_use]
    pub fn env(&self, slot: &FunctionSlot) -> Vec<String> {
        GuestEgressEnv::for_slot(self, slot).to_env()
    }
}

/// Concrete guest-init environment for one sandbox function.
#[derive(Debug, Clone, PartialEq, Eq)]
struct GuestEgressEnv {
    address_cidr: String,
    gateway: String,
    mac: Option<String>,
}

impl GuestEgressEnv {
    #[must_use]
    fn for_slot(egress: &GuestEgress, slot: &FunctionSlot) -> Self {
        let address = slot
            .datapath_address
            .as_deref()
            .unwrap_or(&egress.address_cidr);
        Self {
            address_cidr: address.to_string(),
            gateway: egress.gateway.clone(),
            mac: slot.mac.clone(),
        }
    }

    #[must_use]
    fn to_env(&self) -> Vec<String> {
        let mut env = vec![
            format!("{ENV_EGRESS}={EGRESS_EXTERNAL_VF}"),
            format!("{ENV_IP_MODE}={IP_MODE_STATIC}"),
            format!("{}={}", ENV_IP, self.address_cidr),
            format!("{}={}", ENV_GATEWAY, self.gateway),
        ];
        if let Some(mac) = self.mac.as_deref() {
            env.push(format!("{ENV_MAC}={mac}"));
        }
        env
    }
}

/// Name of the guest-init drop-in this extension injects. Sorted late so it
/// runs after base network setup.
pub const DROPIN_NAME: &str = "50-bluefield-vf-egress.sh";

/// Build the guest-init drop-in that configures the VF NIC from the
/// `OPENSHELL_VM_DATA_*` env. The TAP interface remains directly connected to
/// the gateway host address, while default egress moves to the BlueField VF.
#[must_use]
pub fn dropin() -> GuestInitDropin {
    GuestInitDropin::new(DROPIN_NAME, DROPIN_SCRIPT.to_vec())
}

#[cfg(test)]
mod tests {
    use super::GuestEgress;
    use bf_inventory::FunctionSlot;

    #[test]
    fn env_contract_uses_default_address_without_dns_or_mac() {
        let egress = GuestEgress {
            address_cidr: "10.0.120.10/22".to_string(),
            gateway: "10.0.120.254".to_string(),
        };
        let slot = FunctionSlot::new("vf0", "0000:03:00.2");
        let env = egress.env(&slot);
        assert_eq!(
            env,
            vec![
                "OPENSHELL_VM_DATA_EGRESS=external-vf",
                "OPENSHELL_VM_DATA_IP_MODE=static",
                "OPENSHELL_VM_DATA_IP=10.0.120.10/22",
                "OPENSHELL_VM_DATA_GW=10.0.120.254",
            ]
        );
    }

    #[test]
    fn env_contract_uses_slot_address_override_and_optional_mac() {
        let egress = GuestEgress {
            address_cidr: "10.0.120.10/22".to_string(),
            gateway: "10.0.120.254".to_string(),
        };
        let slot = FunctionSlot::new("vf0", "0000:03:00.2").with_datapath_address("10.0.120.61/22");
        let slot = slot.with_mac("02:bf:64:04:00:10");
        let env = egress.env(&slot);
        assert_eq!(
            env,
            vec![
                "OPENSHELL_VM_DATA_EGRESS=external-vf",
                "OPENSHELL_VM_DATA_IP_MODE=static",
                "OPENSHELL_VM_DATA_IP=10.0.120.61/22",
                "OPENSHELL_VM_DATA_GW=10.0.120.254",
                "OPENSHELL_VM_DATA_MAC=02:bf:64:04:00:10",
            ]
        );
    }

    #[test]
    fn dropin_script_is_reviewable_and_configures_static_vf_egress() {
        let dropin = super::dropin();
        let script = String::from_utf8(dropin.contents).expect("drop-in is utf8");
        assert!(script.contains("OPENSHELL_VM_DATA_IP"));
        assert!(script.contains("OPENSHELL_VM_DATA_GW"));
        assert!(script.contains("0x15b3"));
        assert!(script.contains("OPENSHELL_VM_DATA_MAC"));
        assert!(script.contains("find_bluefield_vf()"));
        assert!(script.contains("configure_static_ip()"));
        assert!(script.contains("configure_resolv_conf()"));
        assert!(script.contains("remove_inherited_default_routes()"));
        assert!(script.contains("verify_vf_default_route()"));
        assert!(script.contains("main \"$@\""));
        assert!(script.contains("ip link set dev \"${vf_nic}\" address"));
        assert!(script.contains("ip addr add"));
        assert!(script.contains("ip route del default"));
        assert!(script.contains("ip route replace default"));
        assert!(script.contains("ip route get \"${OPENSHELL_VM_DATA_GW}\""));
        assert!(script.contains("dev ${vf_nic}"));
        assert!(!script.contains("OPENSHELL_VM_DATA_DNS"));
        assert!(script.contains("resolv.conf"));
        assert!(script.contains("DPU-side policy"));
    }
}
