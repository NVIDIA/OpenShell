// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! MXC `ContainerConfig` defaults and backend-specific behavior.

use openshell_core::proto::SandboxPolicy;
use serde_json::{Value, json};

use super::loss::{LossItem, add_loss};
use crate::mxc::MXC_SCHEMA_VERSION;

/// Placeholder command written into `process.commandLine` when the caller does
/// not supply a real workload command.
pub const DEFAULT_COMMAND: &str = "sh -lc \"echo OpenShell policy mapped to MXC; replace process.commandLine before running a real workload\"";

/// Stable MXC schema used by every mapper output.
pub const DEFAULT_MXC_VERSION: &str = MXC_SCHEMA_VERSION;

/// Default MXC containment backend for the coarse mapping.
pub const DEFAULT_CONTAINMENT: &str = "bubblewrap";

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
    has_direct_egress: bool,
    items: &mut Vec<LossItem>,
) {
    match containment {
        "processcontainer" | "process" if has_direct_egress => {
            config["processContainer"] = json!({ "capabilities": ["internetClient"] });
        }
        "lxc" => {
            config["lxc"] = json!({ "distribution": "alpine", "release": "3.20" });
        }
        backend @ ("windows_sandbox" | "isolation_session" | "vm") if has_direct_egress => {
            add_loss(
                items,
                "containment",
                "error",
                &format!(
                    "MXC 1.0 `{backend}` cannot enforce this direct directional egress policy."
                ),
                "OpenShell network policy",
                "The mapping must be rejected instead of sending an unenforceable network grant.",
            );
        }
        "microvm" | "hyperlight" if has_direct_egress => {
            add_loss(
                items,
                "containment",
                "error",
                "This experimental containment backend is outside the stable MXC 1.0 contract.",
                "OpenShell network policy",
                "The stable-schema mapping must be rejected.",
            );
        }
        _ => {}
    }
}

/// Reject direct network mapping on stable-schema backends that cannot enforce
/// the generated directional policy. Only fires when the source policy declares
/// network rules.
pub fn add_backend_network_loss(
    policy: &SandboxPolicy,
    containment: &str,
    items: &mut Vec<LossItem>,
) {
    if policy.network_policies.is_empty() {
        return;
    }
    match containment {
        "isolation_session" | "vm" | "windows_sandbox" | "microvm" | "hyperlight" => add_loss(
            items,
            "network_policies",
            "error",
            "The selected backend cannot enforce stable MXC 1.0 directional egress rules for this mapping.",
            "directional network policy",
            "The caller must reject the mapping or use governed ProcessContainer egress.",
        ),
        _ => {}
    }
}
