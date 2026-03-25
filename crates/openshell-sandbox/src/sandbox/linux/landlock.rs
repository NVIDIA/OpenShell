// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Landlock filesystem sandboxing.

use crate::policy::{LandlockCompatibility, SandboxPolicy};
use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr,
};
use miette::{IntoDiagnostic, Result};
use std::path::PathBuf;
use tracing::{debug, info, warn};

pub fn apply(policy: &SandboxPolicy, workdir: Option<&str>) -> Result<()> {
    let read_only = policy.filesystem.read_only.clone();
    let mut read_write = policy.filesystem.read_write.clone();

    if policy.filesystem.include_workdir
        && let Some(dir) = workdir
    {
        let workdir_path = PathBuf::from(dir);
        if !read_write.contains(&workdir_path) {
            read_write.push(workdir_path);
        }
    }

    if read_only.is_empty() && read_write.is_empty() {
        return Ok(());
    }

    let abi = ABI::V2;
    info!(
        abi = ?abi,
        compatibility = ?policy.landlock.compatibility,
        read_only_paths = read_only.len(),
        read_write_paths = read_write.len(),
        "Applying Landlock filesystem sandbox"
    );

    let result: Result<()> = (|| {
        let access_all = AccessFs::from_all(abi);
        let access_read = AccessFs::from_read(abi);

        let mut ruleset = Ruleset::default();
        ruleset = ruleset
            .set_compatibility(compat_level(&policy.landlock.compatibility))
            .handle_access(access_all)
            .into_diagnostic()?;

        let mut ruleset = ruleset.create().into_diagnostic()?;

        for path in read_only {
            debug!(path = %path.display(), "Landlock allow read-only");
            ruleset = ruleset
                .add_rule(PathBeneath::new(
                    PathFd::new(path).into_diagnostic()?,
                    access_read,
                ))
                .into_diagnostic()?;
        }

        for path in read_write {
            debug!(path = %path.display(), "Landlock allow read-write");
            ruleset = ruleset
                .add_rule(PathBeneath::new(
                    PathFd::new(path).into_diagnostic()?,
                    access_all,
                ))
                .into_diagnostic()?;
        }

        ruleset.restrict_self().into_diagnostic()?;
        Ok(())
    })();

    if let Err(err) = result {
        if matches!(
            policy.landlock.compatibility,
            LandlockCompatibility::BestEffort
        ) {
            warn!(
                error = %err,
                "Landlock filesystem sandbox is UNAVAILABLE — running WITHOUT filesystem restrictions. \
                 Set landlock.compatibility to 'hard_requirement' to make this a fatal error."
            );
            return Ok(());
        }
        return Err(err);
    }

    Ok(())
}

fn compat_level(level: &LandlockCompatibility) -> CompatLevel {
    match level {
        LandlockCompatibility::BestEffort => CompatLevel::BestEffort,
        LandlockCompatibility::HardRequirement => CompatLevel::HardRequirement,
    }
}
