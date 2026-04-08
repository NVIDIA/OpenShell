// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Landlock filesystem sandboxing.

use crate::policy::{LandlockCompatibility, SandboxPolicy};
use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, PathFdError, Ruleset,
    RulesetAttr, RulesetCreatedAttr,
};
use miette::{IntoDiagnostic, Result};
use std::path::{Path, PathBuf};
use tracing::debug;

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

    let total_paths = read_only.len() + read_write.len();
    let abi = ABI::V2;
    openshell_ocsf::ocsf_emit!(
        openshell_ocsf::ConfigStateChangeBuilder::new(crate::ocsf_ctx())
            .severity(openshell_ocsf::SeverityId::Informational)
            .status(openshell_ocsf::StatusId::Success)
            .state(openshell_ocsf::StateId::Enabled, "applying")
            .message(format!(
                "Applying Landlock filesystem sandbox [abi:{abi:?} compat:{:?} ro:{} rw:{}]",
                policy.landlock.compatibility,
                read_only.len(),
                read_write.len(),
            ))
            .build()
    );

    let compatibility = &policy.landlock.compatibility;

    let result: Result<()> = (|| {
        let access_all = AccessFs::from_all(abi);
        let access_read = AccessFs::from_read(abi);

        let mut ruleset = Ruleset::default();
        ruleset = ruleset
            .set_compatibility(compat_level(compatibility))
            .handle_access(access_all)
            .into_diagnostic()?;

        let mut ruleset = ruleset.create().into_diagnostic()?;
        let mut rules_applied: usize = 0;

        for path in &read_only {
            if let Some(path_fd) = try_open_path(path, compatibility)? {
                debug!(path = %path.display(), "Landlock allow read-only");
                ruleset = ruleset
                    .add_rule(PathBeneath::new(path_fd, access_read))
                    .into_diagnostic()?;
                rules_applied += 1;
            }
        }

        for path in &read_write {
            if let Some(path_fd) = try_open_path(path, compatibility)? {
                debug!(path = %path.display(), "Landlock allow read-write");
                ruleset = ruleset
                    .add_rule(PathBeneath::new(path_fd, access_all))
                    .into_diagnostic()?;
                rules_applied += 1;
            }
        }

        if rules_applied == 0 {
            return Err(miette::miette!(
                "Landlock ruleset has zero valid paths — all {} path(s) failed to open. \
                 Refusing to apply an empty ruleset that would block all filesystem access.",
                total_paths,
            ));
        }

        let skipped = total_paths - rules_applied;
        openshell_ocsf::ocsf_emit!(
            openshell_ocsf::ConfigStateChangeBuilder::new(crate::ocsf_ctx())
                .severity(openshell_ocsf::SeverityId::Informational)
                .status(openshell_ocsf::StatusId::Success)
                .state(openshell_ocsf::StateId::Enabled, "built")
                .message(format!(
                    "Landlock ruleset built [rules_applied:{rules_applied} skipped:{skipped}]"
                ))
                .build()
        );

        ruleset.restrict_self().into_diagnostic()?;
        Ok(())
    })();

    if let Err(err) = result {
        if matches!(compatibility, LandlockCompatibility::BestEffort) {
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
                            "Running WITHOUT filesystem restrictions: {err}. \
                             Set landlock.compatibility to 'hard_requirement' to make this fatal."
                        )),
                    )
                    .message(format!("Landlock filesystem sandbox unavailable: {err}"))
                    .build()
            );
            return Ok(());
        }
        return Err(err);
    }

    Ok(())
}

/// Attempt to open a path for Landlock rule creation.
///
/// In `BestEffort` mode, inaccessible paths (missing, permission denied, symlink
/// loops, etc.) are skipped with a warning and `Ok(None)` is returned so the
/// caller can continue building the ruleset from the remaining valid paths.
///
/// In `HardRequirement` mode, any failure is fatal — the caller propagates the
/// error, which ultimately aborts sandbox startup.
fn try_open_path(path: &Path, compatibility: &LandlockCompatibility) -> Result<Option<PathFd>> {
    match PathFd::new(path) {
        Ok(fd) => Ok(Some(fd)),
        Err(err) => {
            let reason = classify_path_fd_error(&err);
            let is_not_found = matches!(
                &err,
                PathFdError::OpenCall { source, .. }
                    if source.kind() == std::io::ErrorKind::NotFound
            );
            match compatibility {
                LandlockCompatibility::BestEffort => {
                    // NotFound is expected for stale baseline paths (e.g.
                    // /app baked into the server-stored policy but absent
                    // in this container image).  Log at debug! to avoid
                    // polluting SSH exec stdout — the pre_exec hook
                    // inherits the tracing subscriber whose writer targets
                    // fd 1 (the pipe/PTY).
                    //
                    // Other errors (permission denied, symlink loops, etc.)
                    // are genuinely unexpected and logged at warn!.
                    if is_not_found {
                        debug!(
                            path = %path.display(),
                            reason,
                            "Skipping non-existent Landlock path (best-effort mode)"
                        );
                    } else {
                        openshell_ocsf::ocsf_emit!(
                            openshell_ocsf::ConfigStateChangeBuilder::new(crate::ocsf_ctx())
                                .severity(openshell_ocsf::SeverityId::Medium)
                                .status(openshell_ocsf::StatusId::Failure)
                                .state(openshell_ocsf::StateId::Other, "degraded")
                                .message(format!(
                                    "Skipping inaccessible Landlock path (best-effort) [path:{} error:{err}]",
                                    path.display()
                                ))
                                .build()
                        );
                    }
                    Ok(None)
                }
                LandlockCompatibility::HardRequirement => Err(miette::miette!(
                    "Landlock path unavailable in hard_requirement mode: {} ({}): {}",
                    path.display(),
                    reason,
                    err,
                )),
            }
        }
    }
}

/// Classify a [`PathFdError`] into a human-readable reason.
///
/// `PathFd::new()` wraps `open(path, O_PATH | O_CLOEXEC)` which can fail for
/// several reasons beyond simple non-existence. The `PathFdError::OpenCall`
/// variant wraps the underlying `std::io::Error`.
fn classify_path_fd_error(err: &PathFdError) -> &'static str {
    match err {
        PathFdError::OpenCall { source, .. } => classify_io_error(source),
        // PathFdError is #[non_exhaustive], handle future variants gracefully.
        _ => "unexpected error",
    }
}

/// Classify a `std::io::Error` into a human-readable reason string.
fn classify_io_error(err: &std::io::Error) -> &'static str {
    match err.kind() {
        std::io::ErrorKind::NotFound => "path does not exist",
        std::io::ErrorKind::PermissionDenied => "permission denied",
        _ => match err.raw_os_error() {
            Some(40) => "too many symlink levels",           // ELOOP
            Some(36) => "path name too long",                // ENAMETOOLONG
            Some(20) => "path component is not a directory", // ENOTDIR
            _ => "unexpected error",
        },
    }
}

fn compat_level(level: &LandlockCompatibility) -> CompatLevel {
    match level {
        LandlockCompatibility::BestEffort => CompatLevel::BestEffort,
        LandlockCompatibility::HardRequirement => CompatLevel::HardRequirement,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_open_path_best_effort_returns_none_for_missing_path() {
        let result = try_open_path(
            &PathBuf::from("/nonexistent/openshell/test/path"),
            &LandlockCompatibility::BestEffort,
        );
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn try_open_path_hard_requirement_errors_for_missing_path() {
        let result = try_open_path(
            &PathBuf::from("/nonexistent/openshell/test/path"),
            &LandlockCompatibility::HardRequirement,
        );
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("hard_requirement"),
            "error should mention hard_requirement mode: {err_msg}"
        );
        assert!(
            err_msg.contains("does not exist"),
            "error should include the classified reason: {err_msg}"
        );
    }

    #[test]
    fn try_open_path_succeeds_for_existing_path() {
        let dir = tempfile::tempdir().unwrap();
        let result = try_open_path(dir.path(), &LandlockCompatibility::BestEffort);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn classify_not_found() {
        let err = std::io::Error::from_raw_os_error(libc::ENOENT);
        assert_eq!(classify_io_error(&err), "path does not exist");
    }

    #[test]
    fn classify_permission_denied() {
        let err = std::io::Error::from_raw_os_error(libc::EACCES);
        assert_eq!(classify_io_error(&err), "permission denied");
    }

    #[test]
    fn classify_symlink_loop() {
        let err = std::io::Error::from_raw_os_error(libc::ELOOP);
        assert_eq!(classify_io_error(&err), "too many symlink levels");
    }

    #[test]
    fn classify_name_too_long() {
        let err = std::io::Error::from_raw_os_error(libc::ENAMETOOLONG);
        assert_eq!(classify_io_error(&err), "path name too long");
    }

    #[test]
    fn classify_not_a_directory() {
        let err = std::io::Error::from_raw_os_error(libc::ENOTDIR);
        assert_eq!(classify_io_error(&err), "path component is not a directory");
    }

    #[test]
    fn classify_unknown_error() {
        let err = std::io::Error::from_raw_os_error(libc::EIO);
        assert_eq!(classify_io_error(&err), "unexpected error");
    }

    #[test]
    fn classify_path_fd_error_extracts_io_error() {
        // Use PathFd::new on a non-existent path to get a real PathFdError
        // (the OpenCall variant is #[non_exhaustive] and can't be constructed directly).
        let err = PathFd::new("/nonexistent/openshell/classify/test").unwrap_err();
        assert_eq!(classify_path_fd_error(&err), "path does not exist");
    }
}
