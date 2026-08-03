// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Thin VM-driver-specific wrapper over the shared `openshell-nft-ruleset`
//! generator. The generic ruleset shape (NAT + default-deny forward/input
//! scoped to the gateway port) lives in `openshell-nft-ruleset` so the
//! oci driver can reuse it for veth-based networking without pulling in
//! the VM driver's `bollard`/`oci-client`/libkrun dependencies.
//!
//! The table prefix `openshell_vm` is preserved so existing deployments see
//! no change in the nftables tables this driver creates, and so the VM and
//! oci drivers can never collide on a table name if both manage
//! interfaces on the same host.

const TABLE_PREFIX: &str = "openshell_vm";

/// Return the nftables table name for a TAP device.
pub fn teardown_table_name(device: &str) -> String {
    openshell_nft_ruleset::teardown_table_name(TABLE_PREFIX, device)
}

/// Generate the nftables ruleset for VM TAP networking.
pub fn generate_tap_ruleset(tap_device: &str, subnet: &str, gateway_port: u16) -> String {
    openshell_nft_ruleset::generate_ruleset(TABLE_PREFIX, tap_device, subnet, gateway_port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_tap_setup_ruleset() {
        let ruleset = generate_tap_ruleset("vmtap-abcd", "10.0.128.0/30", 8080);
        assert!(ruleset.contains("table ip openshell_vm_vmtap_abcd {"));
        assert!(ruleset.contains("type nat hook postrouting priority 100; policy accept;"));
        assert!(ruleset.contains("ip saddr 10.0.128.0/30 masquerade"));
        assert!(ruleset.contains("type filter hook forward priority 0; policy accept;"));
        assert!(ruleset.contains("iifname \"vmtap-abcd\" accept"));
        assert!(ruleset.contains("oifname \"vmtap-abcd\" ct state related,established accept"));
        assert!(ruleset.contains("oifname \"vmtap-abcd\" drop"));
        assert!(ruleset.contains("type filter hook input priority 0; policy accept;"));
        assert!(ruleset.contains("iifname \"vmtap-abcd\" tcp dport 8080 accept"));
    }

    #[test]
    fn table_name_sanitizes_device_name() {
        let ruleset = generate_tap_ruleset("vmtap-abc-123", "10.0.128.0/30", 8080);
        assert!(ruleset.contains("table ip openshell_vm_vmtap_abc_123 {"));
    }

    #[test]
    fn teardown_command_targets_correct_table() {
        let cmd = teardown_table_name("vmtap-abcd");
        assert_eq!(cmd, "openshell_vm_vmtap_abcd");
    }
}
