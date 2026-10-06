// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Loss-report model shared by the coarse map and the governed-egress split.

use std::collections::HashSet;

use serde::Serialize;

/// A single mapping observation: something that could not be represented in
/// MXC, was delegated elsewhere, or is informational.
///
/// `severity` is one of `"error"`, `"warning"`, or `"info"`. `"error"` marks a
/// semantic broadening or an unsupported parity gap; `"warning"` marks lost
/// information that does not obviously broaden access; `"info"` is advisory.
#[derive(Clone, Debug, Serialize)]
pub struct LossItem {
    pub path: String,
    pub severity: String,
    pub message: String,
    pub ryno_feature: String,
    pub mxc_impact: String,
}

/// MXC capabilities that have no `Ryno` *policy* equivalent. Surfaced in the
/// loss report so reviewers understand the mapping is not symmetric.
pub const RYNO_SUPERSET_GAPS: &[&str] = &[
    "MXC UI policy has no Ryno policy equivalent: ui.disable, ui.clipboard, and ui.injection.",
    "MXC lifecycle fields have no Ryno policy equivalent: destroyOnExit, preservePolicy, phase, and sandboxId.",
    "MXC backend selection and backend-specific blocks are outside Ryno policy YAML.",
    "MXC process command, cwd, env, and timeout are runtime config fields, not Ryno policy fields.",
    "MXC explicit deniedPaths are not expressible in current Ryno policy YAML, which relies on default-deny filesystem behavior instead.",
    "MXC fallback.allowDaclMutation (host DACL mutation consent) has no Ryno policy equivalent.",
    "MXC network.allowLocalNetwork (inbound bind/listen permission) has no Ryno policy equivalent.",
    "MXC network.proxy configuration has no Ryno policy equivalent.",
    "MXC experimental backend blocks (windows_sandbox, wslc, seatbelt, isolation_session) are outside Ryno policy YAML.",
];

pub fn add_loss(
    items: &mut Vec<LossItem>,
    path: &str,
    severity: &str,
    message: &str,
    ryno_feature: &str,
    mxc_impact: &str,
) {
    items.push(LossItem {
        path: path.to_owned(),
        severity: severity.to_owned(),
        message: message.to_owned(),
        ryno_feature: ryno_feature.to_owned(),
        mxc_impact: mxc_impact.to_owned(),
    });
}

/// Distinct `Ryno` features that were lost or degraded, in first-seen order.
pub fn summarize_missing_mxc(items: &[LossItem]) -> Vec<String> {
    let mut seen: HashSet<&str> = HashSet::new();
    let mut summary = Vec::new();
    for item in items {
        if (item.severity == "error" || item.severity == "warning")
            && seen.insert(item.ryno_feature.as_str())
        {
            summary.push(item.ryno_feature.clone());
        }
    }
    summary
}
