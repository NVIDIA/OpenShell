// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Linux sandbox implementation using Landlock and seccomp.

mod landlock;
pub mod netns;
mod seccomp;

use crate::policy::SandboxPolicy;
use miette::Result;
use std::path::PathBuf;
use std::sync::Once;

/// Opaque handle to a prepared-but-not-yet-enforced sandbox.
/// Holds the Landlock ruleset with PathFds opened as root.
pub struct PreparedSandbox {
    landlock: Option<landlock::PreparedRuleset>,
    policy: SandboxPolicy,
}

/// Phase 1: Prepare sandbox restrictions **as root** (before `drop_privileges`).
///
/// Opens Landlock PathFds while the process still has root privileges,
/// ensuring paths like mode-700 directories are accessible.
pub fn prepare(policy: &SandboxPolicy, workdir: Option<&str>) -> Result<PreparedSandbox> {
    let landlock = landlock::prepare(policy, workdir)?;
    Ok(PreparedSandbox {
        landlock,
        policy: policy.clone(),
    })
}

/// Phase 2: Enforce prepared sandbox restrictions (after `drop_privileges`).
///
/// Calls `restrict_self()` for Landlock and applies seccomp filters.
/// Neither operation requires root privileges.
pub fn enforce(prepared: PreparedSandbox) -> Result<()> {
    if let Some(ruleset) = prepared.landlock {
        landlock::enforce(ruleset)?;
    }
    seccomp::apply(&prepared.policy)?;
    Ok(())
}

/// Legacy single-phase apply. Kept for backward compatibility.
/// New callers should use [`prepare`] + [`enforce`] for correct privilege ordering.
pub fn apply(policy: &SandboxPolicy, workdir: Option<&str>) -> Result<()> {
    landlock::apply(policy, workdir)?;
    seccomp::apply(policy)?;
    Ok(())
}

/// Probe Landlock availability and emit OCSF logs from the parent process.
///
/// This must be called **before** `pre_exec` / `fork()` so that the OCSF events
/// are emitted through the parent's tracing subscriber (the child process after
/// fork does not have a working tracing pipeline).
pub fn log_sandbox_readiness(policy: &SandboxPolicy, workdir: Option<&str>) {
    static PROBED: Once = Once::new();
    let mut already_probed = true;
    PROBED.call_once(|| already_probed = false);
    if already_probed {
        return;
    }

    let mut read_write = policy.filesystem.read_write.clone();
    let read_only = &policy.filesystem.read_only;

    if policy.filesystem.include_workdir {
        if let Some(dir) = workdir {
            let workdir_path = PathBuf::from(dir);
            if !read_write.contains(&workdir_path) {
                read_write.push(workdir_path);
            }
        }
    }

    let total_paths = read_only.len() + read_write.len();

    if total_paths == 0 {
        openshell_ocsf::ocsf_emit!(
            openshell_ocsf::ConfigStateChangeBuilder::new(crate::ocsf_ctx())
                .severity(openshell_ocsf::SeverityId::Informational)
                .status(openshell_ocsf::StatusId::Success)
                .state(openshell_ocsf::StateId::Other, "skipped")
                .message("Landlock filesystem sandbox skipped: no paths configured".to_string())
                .build()
        );
        return;
    }

    let availability = landlock::probe_availability();
    match &availability {
        landlock::LandlockAvailability::Available { abi } => {
            openshell_ocsf::ocsf_emit!(
                openshell_ocsf::ConfigStateChangeBuilder::new(crate::ocsf_ctx())
                    .severity(openshell_ocsf::SeverityId::Informational)
                    .status(openshell_ocsf::StatusId::Success)
                    .state(openshell_ocsf::StateId::Enabled, "probed")
                    .message(format!(
                        "Landlock filesystem sandbox available \
                         [abi:v{abi} compat:{:?} ro:{} rw:{}]",
                        policy.landlock.compatibility,
                        read_only.len(),
                        read_write.len(),
                    ))
                    .build()
            );
        }
        _ => {
            // Landlock is NOT available — this is the critical log that was
            // previously invisible because it only fired inside pre_exec.
            let is_best_effort = matches!(
                policy.landlock.compatibility,
                crate::policy::LandlockCompatibility::BestEffort
            );
            let (desc, msg) = if is_best_effort {
                (
                    format!(
                        "Sandbox will run WITHOUT filesystem restrictions: {availability}. \
                         Policy requests {total_paths} path rule(s) \
                         (ro:{} rw:{}) but Landlock cannot enforce them. \
                         Set landlock.compatibility to 'hard_requirement' to make this fatal.",
                        read_only.len(),
                        read_write.len(),
                    ),
                    format!(
                        "Landlock filesystem sandbox unavailable (best_effort, degraded): {availability}"
                    ),
                )
            } else {
                (
                    format!(
                        "Landlock is unavailable: {availability}. \
                         Policy requires {total_paths} path rule(s) \
                         (ro:{} rw:{}) with hard_requirement — sandbox startup will fail.",
                        read_only.len(),
                        read_write.len(),
                    ),
                    format!(
                        "Landlock filesystem sandbox unavailable (hard_requirement, will fail): {availability}"
                    ),
                )
            };
            openshell_ocsf::ocsf_emit!(
                openshell_ocsf::DetectionFindingBuilder::new(crate::ocsf_ctx())
                    .activity(openshell_ocsf::ActivityId::Open)
                    .severity(openshell_ocsf::SeverityId::High)
                    .confidence(openshell_ocsf::ConfidenceId::High)
                    .is_alert(true)
                    .finding_info(
                        openshell_ocsf::FindingInfo::new(
                            "landlock-unavailable",
                            "Landlock Filesystem Sandbox Unavailable",
                        )
                        .with_desc(&desc),
                    )
                    .message(msg)
                    .build()
            );
        }
    }
}
