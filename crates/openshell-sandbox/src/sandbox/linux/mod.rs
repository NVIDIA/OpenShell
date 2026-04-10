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
                        .with_desc(&format!(
                            "Sandbox will run WITHOUT filesystem restrictions: {availability}. \
                             Policy requests {total_paths} path rule(s) \
                             (ro:{} rw:{}, compat:{:?}) but Landlock cannot enforce them. \
                             Set landlock.compatibility to 'hard_requirement' to make this fatal.",
                            read_only.len(),
                            read_write.len(),
                            policy.landlock.compatibility,
                        )),
                    )
                    .message(format!(
                        "Landlock filesystem sandbox unavailable: {availability}"
                    ))
                    .build()
            );
        }
    }
}
