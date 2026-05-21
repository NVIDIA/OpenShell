// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Write;

/// Sanitize a TAP device name for use as an nftables table name suffix.
/// Assumes device names match `vmtap-[a-f0-9]+` (driver-controlled).
fn sanitize_table_name(device: &str) -> String {
    device.replace('-', "_")
}

/// Return the nftables table name for a TAP device.
pub fn teardown_table_name(device: &str) -> String {
    format!("openshell_vm_{}", sanitize_table_name(device))
}

/// Generate the nftables ruleset for VM TAP networking.
pub fn generate_tap_ruleset(tap_device: &str, subnet: &str, gateway_port: u16) -> String {
    let table_name = teardown_table_name(tap_device);
    let mut ruleset = String::with_capacity(512);

    writeln!(ruleset, "table ip {table_name} {{").unwrap();
    writeln!(ruleset, "    chain postrouting {{").unwrap();
    writeln!(
        ruleset,
        "        type nat hook postrouting priority 100; policy accept;"
    )
    .unwrap();
    writeln!(ruleset, "        ip saddr {subnet} masquerade").unwrap();
    writeln!(ruleset, "    }}").unwrap();
    writeln!(ruleset, "    chain forward {{").unwrap();
    writeln!(
        ruleset,
        "        type filter hook forward priority 0; policy accept;"
    )
    .unwrap();
    writeln!(ruleset, "        iifname \"{tap_device}\" accept").unwrap();
    writeln!(
        ruleset,
        "        oifname \"{tap_device}\" ct state related,established accept"
    )
    .unwrap();
    writeln!(ruleset, "        oifname \"{tap_device}\" drop").unwrap();
    writeln!(ruleset, "    }}").unwrap();
    writeln!(ruleset, "    chain input {{").unwrap();
    writeln!(
        ruleset,
        "        type filter hook input priority 0; policy accept;"
    )
    .unwrap();
    writeln!(
        ruleset,
        "        iifname \"{tap_device}\" tcp dport {gateway_port} accept"
    )
    .unwrap();
    writeln!(ruleset, "        iifname \"{tap_device}\" drop").unwrap();
    writeln!(ruleset, "    }}").unwrap();
    writeln!(ruleset, "}}").unwrap();

    ruleset
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
