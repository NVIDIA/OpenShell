// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared nftables ruleset generation for per-sandbox network isolation.
//!
//! This crate contains pure, dependency-free string generation only. Callers
//! own actually invoking `nft` (typically via `nft -f -` on stdin) and
//! managing the lifecycle of the host-side network interface (TAP device for
//! the VM driver, veth pair for the oci driver).
//!
//! The generated ruleset is intentionally minimal and symmetric across
//! backends:
//! - `postrouting`: NAT (masquerade) traffic leaving the sandbox subnet.
//! - `forward`: default-deny; only allow traffic initiated by the sandbox
//!   interface and its related/established return traffic.
//! - `input`: default-deny; only allow the sandbox to reach the gateway's
//!   listen port on the host.

use std::fmt::Write;

/// Sanitize an interface name for use as an nftables table name suffix.
/// Assumes interface names are driver-controlled and contain only
/// alphanumerics and hyphens (e.g. `vmtap-<hex>`, `oshveth-<hex>`).
fn sanitize_table_name(interface: &str) -> String {
    interface.replace('-', "_")
}

/// Return the nftables table name for a given table prefix and interface.
///
/// The prefix namespaces tables per-backend (e.g. `openshell_vm`,
/// `openshell_oci`) so that two drivers managing interfaces on the same
/// host can never collide on a table name, even if (implausibly) they picked
/// the same interface name.
#[must_use]
pub fn teardown_table_name(table_prefix: &str, interface: &str) -> String {
    format!("{table_prefix}_{}", sanitize_table_name(interface))
}

/// Generate the nftables ruleset scoping a sandbox's network interface.
///
/// `table_prefix` should be a short, driver-unique identifier (for example
/// `openshell_vm` or `openshell_oci`). `interface` is the host-side
/// interface for this sandbox (a TAP device or the host end of a veth pair).
/// `subnet` is the sandbox's point-to-point or bridge subnet in CIDR form.
/// `gateway_port` is the only TCP port on the host the sandbox is allowed to
/// reach.
#[must_use]
pub fn generate_ruleset(
    table_prefix: &str,
    interface: &str,
    subnet: &str,
    gateway_port: u16,
) -> String {
    let table_name = teardown_table_name(table_prefix, interface);
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
    writeln!(ruleset, "        iifname \"{interface}\" accept").unwrap();
    writeln!(
        ruleset,
        "        oifname \"{interface}\" ct state related,established accept"
    )
    .unwrap();
    writeln!(ruleset, "        oifname \"{interface}\" drop").unwrap();
    writeln!(ruleset, "    }}").unwrap();
    writeln!(ruleset, "    chain input {{").unwrap();
    writeln!(
        ruleset,
        "        type filter hook input priority 0; policy accept;"
    )
    .unwrap();
    writeln!(
        ruleset,
        "        iifname \"{interface}\" tcp dport {gateway_port} accept"
    )
    .unwrap();
    writeln!(ruleset, "        iifname \"{interface}\" drop").unwrap();
    writeln!(ruleset, "    }}").unwrap();
    writeln!(ruleset, "}}").unwrap();

    ruleset
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_setup_ruleset() {
        let ruleset = generate_ruleset("openshell_vm", "vmtap-abcd", "10.0.128.0/30", 8080);
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
    fn table_name_sanitizes_interface_name() {
        let ruleset = generate_ruleset("openshell_vm", "vmtap-abc-123", "10.0.128.0/30", 8080);
        assert!(ruleset.contains("table ip openshell_vm_vmtap_abc_123 {"));
    }

    #[test]
    fn teardown_command_targets_correct_table() {
        let cmd = teardown_table_name("openshell_vm", "vmtap-abcd");
        assert_eq!(cmd, "openshell_vm_vmtap_abcd");
    }

    #[test]
    fn different_prefixes_never_collide_on_the_same_interface_name() {
        let vm_table = teardown_table_name("openshell_vm", "shared-iface");
        let oci_table = teardown_table_name("openshell_oci", "shared-iface");
        assert_ne!(vm_table, oci_table);
    }
}
