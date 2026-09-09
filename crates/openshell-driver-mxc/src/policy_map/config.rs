// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! MXC `ContainerConfig` defaults and backend-specific behavior.

use openshell_core::proto::SandboxPolicy;
use serde_json::{Value, json};

use super::loss::{LossItem, add_loss};

/// Placeholder command written into `process.commandLine` when the caller does
/// not supply a real workload command.
pub const DEFAULT_COMMAND: &str = "sh -lc \"echo OpenShell policy mapped to MXC; replace process.commandLine before running a real workload\"";

/// Default MXC schema version emitted in `version`.
pub const DEFAULT_MXC_VERSION: &str = "0.7.0-alpha";

/// Default MXC containment backend for the coarse mapping.
pub const DEFAULT_CONTAINMENT: &str = "bubblewrap";

/// Select a default `network.enforcementMode` for the backend, or `None` to
/// omit the field (backends that derive enforcement from host lists / proxy).
pub fn default_enforcement_mode(
    containment: &str,
    allowed_hosts: &[String],
) -> Option<&'static str> {
    if allowed_hosts.is_empty() {
        return None;
    }
    match containment {
        "processcontainer" | "process" => Some("both"),
        "wslc" | "seatbelt" | "microvm" | "vm" | "windows_sandbox" => None,
        // lxc, bubblewrap, hyperlight, and anything else default to firewall.
        _ => Some("firewall"),
    }
}

/// Backend-specific advisory about how filesystem default-deny differs from
/// `OpenShell` Landlock.
pub fn filesystem_default_deny_message(containment: &str) -> String {
    match containment {
        "bubblewrap" => "Bubblewrap policy is not strict OpenShell filesystem parity: MXC \
            may bind host root read-only and overlay policy mounts."
            .to_owned(),
        "lxc" => "LXC exposes the container rootfs and bind-mounts selected host \
            paths; this is not identical to OpenShell Landlock."
            .to_owned(),
        "wslc" => "WSLC mounts selected Windows paths, but default-deny behavior is \
            runner/backend specific."
            .to_owned(),
        "seatbelt" => "Seatbelt starts from a deny-default profile with baseline system \
            allowances, not OpenShell Landlock."
            .to_owned(),
        _ => "MXC filesystem behavior is backend-specific and not equivalent to \
            OpenShell Landlock by construction."
            .to_owned(),
    }
}

/// Add backend-specific config blocks (and reject unsupported backends).
pub fn add_backend_specific_config(
    config: &mut Value,
    containment: &str,
    allowed_hosts: &[String],
    items: &mut Vec<LossItem>,
) {
    match containment {
        "processcontainer" | "process" if !allowed_hosts.is_empty() => {
            config["processContainer"] = json!({ "capabilities": ["internetClient"] });
        }
        "lxc" => {
            config["lxc"] = json!({ "distribution": "alpine", "release": "3.20" });
        }
        backend @ ("windows_sandbox" | "isolation_session" | "vm") if !allowed_hosts.is_empty() => {
            add_loss(
                items,
                "containment",
                "error",
                &format!("{backend} is not a v0 target for OpenShell network policy mapping."),
                "OpenShell network policy",
                "MXC network behavior is unsupported or unknown for this backend.",
            );
        }
        "microvm" if !allowed_hosts.is_empty() => {
            add_loss(
                items,
                "containment",
                "error",
                "microvm network policy enforcement is not defined for this mapper.",
                "OpenShell network policy",
                "MXC network behavior is unsupported or unknown for microvm.",
            );
        }
        _ => {}
    }
}

/// Add a backend-specific advisory about host-allowlist fidelity. Only fires
/// when the source policy declares network rules.
pub fn add_backend_network_loss(
    policy: &SandboxPolicy,
    containment: &str,
    items: &mut Vec<LossItem>,
) {
    if policy.network_policies.is_empty() {
        return;
    }
    match containment {
        "seatbelt" => add_loss(
            items,
            "network_policies",
            "error",
            "MXC Seatbelt cannot faithfully enforce arbitrary allowedHosts.",
            "host allowlist",
            "Seatbelt allowlists can broaden to allow-all outbound.",
        ),
        "processcontainer" | "process" => add_loss(
            items,
            "network_policies",
            "warning",
            "Windows ProcessContainer host allowlists are possible but fragile.",
            "host allowlist",
            "Review firewall/capability behavior before treating this as parity.",
        ),
        "wslc" => add_loss(
            items,
            "network_policies",
            "warning",
            "WSLC host filtering relies on bridged networking plus in-container iptables.",
            "host allowlist",
            "Backend privileges and runner behavior determine parity.",
        ),
        "vm" | "windows_sandbox" => add_loss(
            items,
            "network_policies",
            "error",
            "MXC Windows Sandbox / vm cannot faithfully enforce arbitrary allowedHosts.",
            "host allowlist",
            "Network policy enforcement is unsupported or unknown for this backend.",
        ),
        _ => {}
    }
}
