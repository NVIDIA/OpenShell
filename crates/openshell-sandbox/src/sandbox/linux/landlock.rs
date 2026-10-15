// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Landlock filesystem sandboxing.

use landlock::{
    ABI, Access, AccessFs, BitFlags, CompatLevel, Compatible, PathBeneath, PathFd, PathFdError,
    Ruleset, RulesetAttr, RulesetCreatedAttr,
};
use miette::{IntoDiagnostic, Result};
use openshell_core::policy::{LandlockCompatibility, SandboxPolicy};
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use tracing::debug;

/// Result of probing the kernel for Landlock support.
#[derive(Debug)]
pub enum LandlockAvailability {
    /// Landlock is available with the given ABI version.
    Available { abi: i32 },
    /// Kernel does not implement Landlock (ENOSYS).
    NotImplemented,
    /// Landlock is compiled in but not enabled at boot (EOPNOTSUPP).
    NotEnabled,
    /// Landlock syscall is blocked, likely by a container seccomp profile (EPERM).
    Blocked,
    /// Unexpected error from the probe syscall.
    Unknown(i32),
}

impl std::fmt::Display for LandlockAvailability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Available { abi } => write!(f, "available (ABI v{abi})"),
            Self::NotImplemented => {
                write!(f, "not implemented (kernel lacks CONFIG_SECURITY_LANDLOCK)")
            }
            Self::NotEnabled => write!(
                f,
                "not enabled (Landlock built into kernel but not in active LSM list)"
            ),
            Self::Blocked => write!(
                f,
                "blocked (container seccomp profile denies Landlock syscalls)"
            ),
            Self::Unknown(errno) => write!(f, "unexpected probe error (errno {errno})"),
        }
    }
}

/// Probe the kernel for Landlock support by issuing the `landlock_create_ruleset`
/// syscall with the version-check flag.
///
/// This is safe to call from the parent process and does not create any file
/// descriptors or modify process state.
pub fn probe_availability() -> LandlockAvailability {
    match crate::linux::landlock::abi_version() {
        Ok(abi) => LandlockAvailability::Available {
            abi: i32::try_from(abi).unwrap_or(i32::MAX),
        },
        Err(error) => match error.raw_os_error().unwrap_or(0) {
            libc::ENOSYS => LandlockAvailability::NotImplemented,
            libc::EOPNOTSUPP => LandlockAvailability::NotEnabled,
            libc::EPERM => LandlockAvailability::Blocked,
            other => LandlockAvailability::Unknown(other),
        },
    }
}

/// Lowest Landlock ABI the mandatory baseline accepts (matches [`ABI::V3`]).
/// ABI v3, introduced in Linux 6.2, adds pathname truncation.
const REQUIRED_ABI: i32 = 3;

fn check_abi(availability: &LandlockAvailability) -> Result<u32> {
    match availability {
        LandlockAvailability::Available { abi } if *abi >= REQUIRED_ABI => Ok(abi.unsigned_abs()),
        _ => Err(miette::miette!(
            "Landlock ABI v{REQUIRED_ABI} or newer (Linux 6.2+) is required, but Landlock is {availability}"
        )),
    }
}

/// Probe the kernel and fail, naming the required and detected ABI, unless it
/// supports the mandatory baseline. Returns the detected ABI.
pub fn require_abi() -> Result<u32> {
    check_abi(&probe_availability())
}

/// A prepared Landlock ruleset ready to be enforced via `restrict_self()`.
///
/// Path FDs are opened before enforcement. The capability-free launch path
/// prepares the baseline and user rules as the workload identity, then calls
/// [`enforce`] in the child before exec. `restrict_self()` does not require
/// elevated privileges.
pub struct PreparedRuleset {
    ruleset: landlock::RulesetCreated,
    compatibility: LandlockCompatibility,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathOpenMode {
    Privileged,
    CurrentUser,
}

/// Phase 1: Open `PathFds` and build the Landlock ruleset with strict path opening.
///
/// Opens configured paths as the calling identity. Inaccessible paths fail in
/// hard-requirement mode and are skipped in best-effort mode. Unlike
/// [`prepare_current_user`], this does not always omit inaccessible paths.
///
/// Returns `None` if there are no filesystem paths to restrict (no-op).
/// Returns `Some(PreparedRuleset)` on success, or an error.
pub fn prepare(policy: &SandboxPolicy, workdir: Option<&str>) -> Result<Option<PreparedRuleset>> {
    prepare_with_path_open_mode(policy, workdir, PathOpenMode::Privileged, None)
}

/// Phase 1 for already-unprivileged workloads.
///
/// The sandbox boundary starts as the workload UID, so Landlock path FDs are
/// opened as the same UID that will run the workload.
/// Paths this UID cannot open are already unavailable to the workload; omit
/// them from the allowlist and let the resulting ruleset deny everything else.
pub fn prepare_current_user(
    policy: &SandboxPolicy,
    workdir: Option<&str>,
    launch_context: &crate::launch::WorkloadLaunchContext,
) -> Result<Option<PreparedRuleset>> {
    prepare_with_path_open_mode(
        policy,
        workdir,
        PathOpenMode::CurrentUser,
        launch_context.cdi_requirements.as_ref(),
    )
}

/// Build the mandatory same-UID self-protection baseline.
///
/// Landlock is allow-list only. Granting `/` would also grant the protected
/// `/.openshell` subtree, so enumerate the root's children and omit that one
/// hierarchy. Entries the final UID cannot open are already inaccessible and
/// are safely omitted by [`PathOpenMode::CurrentUser`].
pub fn prepare_capability_free_baseline() -> Result<PreparedRuleset> {
    prepare_capability_free_baseline_at(Path::new("/"))
}

fn prepare_capability_free_baseline_at(root: &Path) -> Result<PreparedRuleset> {
    // Unlike optional filesystem policy, self-protection must cover pathname
    // truncation as well as opens. Never silently downgrade this ABI requirement.
    require_abi()?;
    let abi = ABI::V3;
    let access = AccessFs::from_all(abi);
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(access)
        .into_diagnostic()?
        .create()
        .into_diagnostic()?;
    let mut usable_entries = 0;
    // Consume the lazy iterator directly so each path descriptor is added and
    // dropped before the next root entry is opened. Images can contain
    // thousands of root entries while the boundary has a 1,024-FD limit.
    for entry in capability_free_baseline_entries(root)? {
        let (_, fd) = entry?;
        usable_entries += 1;
        let allowed = access_for_path_fd(&fd, access, abi)?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, allowed))
            .into_diagnostic()?;
    }
    if usable_entries == 0 {
        return Err(miette::miette!(
            "capability-free Landlock baseline found no usable root entries"
        ));
    }
    Ok(PreparedRuleset {
        ruleset,
        compatibility: LandlockCompatibility::HardRequirement,
    })
}

fn capability_free_baseline_entries(
    root: &Path,
) -> Result<impl Iterator<Item = Result<(PathBuf, OwnedFd)>>> {
    use rustix::fs::{Mode, OFlags, open, openat};
    const PRIVATE_ROOT: &str = ".openshell";

    let root_fd = open(
        root,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .into_diagnostic()?;
    // The reserved root itself must not redirect private child mounts into an
    // allowed subtree. Pin and validate it independently of the public entries.
    // Absence is allowed for qualification before driver bootstrap is staged.
    let _private_root = match openat(
        &root_fd,
        PRIVATE_ROOT,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => Some(fd),
        Err(rustix::io::Errno::NOENT) => None,
        Err(error) => {
            return Err(miette::miette!(
                "private sandbox root must be a real directory: {error}"
            ));
        }
    };
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(root).into_diagnostic()? {
        let entry = entry.into_diagnostic()?;
        if entry.file_name() == PRIVATE_ROOT {
            continue;
        }
        entries.push((entry.path(), entry.file_name()));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(entries.into_iter().filter_map(move |(path, file_name)| {
        // Open relative to the pinned root and classify this exact descriptor.
        // O_PATH|O_NOFOLLOW opens a symlink itself, never its target. A root
        // alias to `/` or `/.openshell` therefore cannot broaden the allowlist.
        let fd = match openat(
            &root_fd,
            file_name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT | rustix::io::Errno::ACCESS) => return None,
            Err(error) => return Some(Err(error).into_diagnostic()),
        };
        let stat = match rustix::fs::fstat(&fd) {
            Ok(stat) => stat,
            Err(error) => return Some(Err(error).into_diagnostic()),
        };
        if rustix::fs::FileType::from_raw_mode(stat.st_mode) == rustix::fs::FileType::Symlink {
            return None;
        }
        Some(Ok((path, fd)))
    }))
}

/// CDI targets require enforcement, so they override a best-effort policy.
fn effective_compatibility<'a>(
    policy: &'a SandboxPolicy,
    cdi_paths: &super::super::cdi_paths::CdiPaths,
) -> &'a LandlockCompatibility {
    if cdi_paths.is_empty() {
        &policy.landlock.compatibility
    } else {
        &LandlockCompatibility::HardRequirement
    }
}

/// Effective compatibility for a workload launch, for logging before preparation.
pub(super) fn launch_compatibility<'a>(
    policy: &'a SandboxPolicy,
    launch_context: &crate::launch::WorkloadLaunchContext,
) -> &'a LandlockCompatibility {
    let cdi_paths = launch_context
        .cdi_requirements
        .as_ref()
        .map(super::super::cdi_paths::CdiPaths::new)
        .unwrap_or_default();
    effective_compatibility(policy, &cdi_paths)
}

fn prepare_with_path_open_mode(
    policy: &SandboxPolicy,
    workdir: Option<&str>,
    path_open_mode: PathOpenMode,
    cdi_requirements: Option<&crate::launch::CdiDerivedRequirements>,
) -> Result<Option<PreparedRuleset>> {
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

    // Keep only path requirements; CDI descriptors are opened and consumed
    // sequentially when building rules, including validation-only targets.
    let cdi_paths = cdi_requirements
        .map(super::super::cdi_paths::CdiPaths::new)
        .unwrap_or_default();

    if read_only.is_empty() && read_write.is_empty() && cdi_paths.is_empty() {
        return Ok(None);
    }

    // CDI target preparation and enforcement cannot fall back to an
    // unrestricted launch. This does not change authored path opening:
    // missing or inaccessible authored paths retain the policy's mode.
    let compatibility = effective_compatibility(policy, &cdi_paths);

    // Probe first: kernels without Landlock (e.g. gVisor's sentry returns
    // ENOSYS) would otherwise log misleading "Applying"+"Built" events.
    let availability = probe_availability();
    if !matches!(availability, LandlockAvailability::Available { .. }) {
        match compatibility {
            LandlockCompatibility::BestEffort => {
                openshell_ocsf::ocsf_emit!(
                    openshell_ocsf::DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
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
                                "Running WITHOUT filesystem restrictions: Landlock is {availability}. \
                                 Set landlock.compatibility to 'hard_requirement' to make this fatal."
                            )),
                        )
                        .message(format!(
                            "Landlock filesystem sandbox unavailable: {availability}"
                        ))
                        .build()
                );
                return Ok(None);
            }
            LandlockCompatibility::HardRequirement => {
                return Err(miette::miette!(
                    "Landlock unavailable in hard_requirement mode: {availability}"
                ));
            }
        }
    }

    let total_paths = read_only.len() + read_write.len();
    // Read-only policy must also deny pathname truncation. The mandatory
    // baseline already qualifies ABI v3; optional best-effort policy keeps its
    // independent compatibility behavior for other callers.
    let abi = ABI::V3;
    openshell_ocsf::ocsf_emit!(
        openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
            .severity(openshell_ocsf::SeverityId::Informational)
            .status(openshell_ocsf::StatusId::Success)
            .state(openshell_ocsf::StateId::Enabled, "applying")
            .message(format!(
                "Applying Landlock filesystem sandbox [abi:{abi:?} compat:{:?} ro:{} rw:{}]",
                compatibility,
                read_only.len(),
                read_write.len(),
            ))
            .build()
    );

    let result: Result<PreparedRuleset> = (|| {
        let access_all = AccessFs::from_all(abi);
        let access_read = AccessFs::from_read(abi);

        let mut ruleset = Ruleset::default();
        ruleset = ruleset
            .set_compatibility(compat_level(compatibility))
            .handle_access(access_all)
            .into_diagnostic()?;

        let ruleset = ruleset.create().into_diagnostic()?;
        let (mut ruleset, mut rules_applied) = cdi_paths.process_validated(
            (ruleset, 0_usize),
            // Use a direct O_PATH open for CDI objects. PathFd uses std
            // OpenOptions, whose musl opener cannot open Unix socket inodes.
            |path| {
                rustix::fs::open(
                    path,
                    rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .into_diagnostic()
            },
            |(ruleset, count), path, fd| {
                // A covered CDI target still needs validation, but no extra
                // rule. Match exact policy entries without reopening the path.
                let access = if read_write.iter().any(|allowed| allowed == path) {
                    Some(access_all)
                } else if read_only.iter().any(|allowed| allowed == path) {
                    Some(access_read)
                } else {
                    None
                };
                let Some(access) = access else {
                    return Ok((ruleset, count));
                };
                let allowed_access = access_for_path_fd(fd, access, abi)?;
                debug!(path = %path.display(), "Landlock allow validated CDI target");
                Ok((
                    ruleset
                        .add_rule(PathBeneath::new(fd, allowed_access))
                        .into_diagnostic()?,
                    count + 1,
                ))
            },
        )?;

        for path in &read_only {
            if cdi_paths.contains(path) {
                continue;
            }
            if let Some(path_fd) =
                try_open_path(path, &policy.landlock.compatibility, path_open_mode)?
            {
                let allowed_access = access_for_path_fd(&path_fd, access_read, abi)?;
                debug!(path = %path.display(), "Landlock allow read-only");
                ruleset = ruleset
                    .add_rule(PathBeneath::new(path_fd, allowed_access))
                    .into_diagnostic()?;
                rules_applied += 1;
            }
        }

        for path in &read_write {
            if cdi_paths.contains(path) {
                continue;
            }
            if let Some(path_fd) =
                try_open_path(path, &policy.landlock.compatibility, path_open_mode)?
            {
                let allowed_access = access_for_path_fd(&path_fd, access_all, abi)?;
                debug!(path = %path.display(), "Landlock allow read-write");
                ruleset = ruleset
                    .add_rule(PathBeneath::new(path_fd, allowed_access))
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
            openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                .severity(openshell_ocsf::SeverityId::Informational)
                .status(openshell_ocsf::StatusId::Success)
                .state(openshell_ocsf::StateId::Enabled, "built")
                .message(format!(
                    "Landlock ruleset built [rules_applied:{rules_applied} skipped:{skipped}]"
                ))
                .build()
        );

        Ok(PreparedRuleset {
            ruleset,
            compatibility: compatibility.clone(),
        })
    })();

    match result {
        Ok(prepared) => Ok(Some(prepared)),
        Err(err) => {
            if matches!(compatibility, LandlockCompatibility::BestEffort) {
                openshell_ocsf::ocsf_emit!(
                    openshell_ocsf::DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
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
                Ok(None)
            } else {
                Err(err)
            }
        }
    }
}

/// Phase 2: Enforce a prepared Landlock ruleset by calling `restrict_self()`.
///
/// The capability-free launch path calls this in the child before exec, already
/// running as the workload identity. `restrict_self()` does not require root;
/// it restricts the calling thread and its future children.
///
/// Respects the same `best_effort` / `hard_requirement` compatibility as
/// [`prepare`]: if `restrict_self()` fails and the policy is `best_effort`,
/// the error is logged and the sandbox continues without Landlock.
pub fn enforce(prepared: PreparedRuleset) -> Result<()> {
    let result = prepared.ruleset.restrict_self().into_diagnostic();
    if let Err(err) = result {
        if matches!(prepared.compatibility, LandlockCompatibility::BestEffort) {
            openshell_ocsf::ocsf_emit!(
                openshell_ocsf::DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
                    .activity(openshell_ocsf::ActivityId::Open)
                    .severity(openshell_ocsf::SeverityId::High)
                    .confidence(openshell_ocsf::ConfidenceId::High)
                    .is_alert(true)
                    .finding_info(
                        openshell_ocsf::FindingInfo::new(
                            "landlock-enforce-failed",
                            "Landlock restrict_self Failed",
                        )
                        .with_desc(&format!(
                            "Ruleset was prepared but restrict_self() failed: {err}. \
                             Running WITHOUT filesystem restrictions. \
                             Set landlock.compatibility to 'hard_requirement' to make this fatal."
                        )),
                    )
                    .message(format!(
                        "Landlock restrict_self failed (best_effort): {err}"
                    ))
                    .build()
            );
            return Ok(());
        }
        return Err(err);
    }
    Ok(())
}

/// Tailor a rule's access mask to the inode referenced by its already-open FD.
///
/// Landlock directory-only rights such as `ReadDir` are invalid for regular
/// files and device nodes in hard-requirement mode. Classifying through the
/// same `PathFd` used by the rule avoids a pathname TOCTOU race.
fn access_for_path_fd(
    path_fd: &impl AsFd,
    requested_access: BitFlags<AccessFs>,
    abi: ABI,
) -> Result<BitFlags<AccessFs>> {
    let stat = rustix::fs::fstat(path_fd.as_fd()).into_diagnostic()?;
    Ok(match rustix::fs::FileType::from_raw_mode(stat.st_mode) {
        rustix::fs::FileType::Directory => requested_access,
        _ => requested_access & AccessFs::from_file(abi),
    })
}

/// Attempt to open a path for Landlock rule creation.
///
/// In `BestEffort` mode, inaccessible paths (missing, permission denied, symlink
/// loops, etc.) are skipped with a warning and `Ok(None)` is returned so the
/// caller can continue building the ruleset from the remaining valid paths.
///
/// In `HardRequirement` mode, any failure is fatal — the caller propagates the
/// error, which ultimately aborts sandbox startup.
fn try_open_path(
    path: &Path,
    compatibility: &LandlockCompatibility,
    path_open_mode: PathOpenMode,
) -> Result<Option<PathFd>> {
    match PathFd::new(path) {
        Ok(fd) => Ok(Some(fd)),
        Err(err) => {
            let reason = classify_path_fd_error(&err);
            let is_not_found = matches!(
                &err,
                PathFdError::OpenCall { source, .. }
                    if source.kind() == std::io::ErrorKind::NotFound
            );
            if matches!(path_open_mode, PathOpenMode::CurrentUser) {
                if is_not_found {
                    debug!(
                        path = %path.display(),
                        reason,
                        "Skipping non-existent Landlock path for current user"
                    );
                } else {
                    openshell_ocsf::ocsf_emit!(
                        openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                            .severity(openshell_ocsf::SeverityId::Informational)
                            .status(openshell_ocsf::StatusId::Success)
                            .state(openshell_ocsf::StateId::Other, "already-denied")
                            .message(format!(
                                "Skipping inaccessible Landlock path for current user [path:{} error:{err}]",
                                path.display()
                            ))
                            .build()
                    );
                }
                return Ok(None);
            }
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
                            openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
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
    use openshell_core::policy::{FilesystemPolicy, LandlockPolicy, NetworkPolicy, ProcessPolicy};

    fn hard_requirement_policy(read_only: Vec<PathBuf>, read_write: Vec<PathBuf>) -> SandboxPolicy {
        SandboxPolicy {
            version: 1,
            filesystem: FilesystemPolicy {
                read_only,
                read_write,
                include_workdir: false,
            },
            network: NetworkPolicy::default(),
            landlock: LandlockPolicy {
                compatibility: LandlockCompatibility::HardRequirement,
            },
            process: ProcessPolicy::default(),
        }
    }

    #[test]
    fn cdi_targets_make_the_logged_compatibility_a_hard_requirement() {
        let mut policy = hard_requirement_policy(vec![], vec![]);
        policy.landlock.compatibility = LandlockCompatibility::BestEffort;
        let without_cdi = crate::launch::WorkloadLaunchContext::default();
        assert!(matches!(
            launch_compatibility(&policy, &without_cdi),
            LandlockCompatibility::BestEffort
        ));
        let empty_cdi = crate::launch::WorkloadLaunchContext {
            cdi_requirements: Some(crate::launch::CdiDerivedRequirements::default()),
        };
        assert!(matches!(
            launch_compatibility(&policy, &empty_cdi),
            LandlockCompatibility::BestEffort
        ));
        let with_cdi = crate::launch::WorkloadLaunchContext {
            cdi_requirements: Some(crate::launch::CdiDerivedRequirements {
                device_node_paths: vec!["/dev/null".into()],
                ..Default::default()
            }),
        };
        assert!(matches!(
            launch_compatibility(&policy, &with_cdi),
            LandlockCompatibility::HardRequirement
        ));
    }

    #[test]
    fn cdi_preserves_authored_path_compatibility() {
        if let Err(error) = require_abi() {
            assert!(
                std::env::var_os("OPENSHELL_TEST_REQUIRE_LANDLOCK").is_none(),
                "{error}"
            );
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let library = directory.path().join("lib");
        std::fs::create_dir(&library).unwrap();
        let missing = directory.path().join("absent-from-image");
        let requirements = crate::launch::CdiDerivedRequirements {
            read_only_paths: vec![library.to_string_lossy().into_owned()],
            ..Default::default()
        };
        let mut policy = hard_requirement_policy(vec![library.clone(), missing], vec![]);
        policy.landlock.compatibility = LandlockCompatibility::BestEffort;
        let prepared = prepare_with_path_open_mode(
            &policy,
            None,
            PathOpenMode::Privileged,
            Some(&requirements),
        )
        .unwrap()
        .unwrap();
        assert!(matches!(
            prepared.compatibility,
            LandlockCompatibility::HardRequirement
        ));
        policy.landlock.compatibility = LandlockCompatibility::HardRequirement;
        assert!(
            prepare_with_path_open_mode(
                &policy,
                None,
                PathOpenMode::Privileged,
                Some(&requirements),
            )
            .is_err()
        );
        policy.landlock.compatibility = LandlockCompatibility::BestEffort;
        std::fs::remove_dir(&library).unwrap();
        assert!(
            prepare_with_path_open_mode(
                &policy,
                None,
                PathOpenMode::Privileged,
                Some(&requirements),
            )
            .is_err(),
            "missing CDI targets remain fatal"
        );
    }

    #[test]
    fn cdi_socket_communication_does_not_grant_parent_file_access() {
        use std::io::{Read, Write};

        let availability = probe_availability();
        if !matches!(availability, LandlockAvailability::Available { abi } if abi >= 3) {
            assert!(
                std::env::var_os("OPENSHELL_TEST_REQUIRE_LANDLOCK").is_none(),
                "Landlock ABI v3 required: {availability}"
            );
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("socket");
        let sibling = temp.path().join("secret");
        std::fs::write(&sibling, b"secret").unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&target).unwrap();
        let allowed = temp.path().join("allowed");
        std::fs::write(&allowed, b"allowed").unwrap();
        let policy = hard_requirement_policy(vec![allowed], vec![]);
        let launch_context = crate::launch::WorkloadLaunchContext {
            cdi_requirements: Some(crate::launch::CdiDerivedRequirements {
                socket_paths: vec![target.to_string_lossy().into_owned()],
                ..Default::default()
            }),
        };
        std::thread::spawn(move || {
            let prepared = prepare_current_user(&policy, None, &launch_context)
                .unwrap()
                .unwrap();
            enforce(prepared).unwrap();
            let mut stream = std::os::unix::net::UnixStream::connect(&target).unwrap();
            stream.write_all(b"ping").unwrap();
            assert_eq!(
                std::fs::read(&sibling).unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
            assert_eq!(
                std::fs::write(&sibling, b"changed").unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
        })
        .join()
        .unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        let mut message = [0; 4];
        stream.read_exact(&mut message).unwrap();
        assert_eq!(&message, b"ping");
    }

    #[test]
    fn cdi_ipc_directory_grants_pipe_access_without_widening_siblings() {
        use rustix::fs::{Mode, OFlags, StatVfsMountFlags, mkfifoat, statvfs};
        let availability = probe_availability();
        if !matches!(availability, LandlockAvailability::Available { abi } if abi >= 3) {
            assert!(
                std::env::var_os("OPENSHELL_TEST_REQUIRE_LANDLOCK").is_none(),
                "Landlock ABI v3 required: {availability}"
            );
            return;
        }
        // IPC directories must be on a nosuid,nodev,noexec mount, as the
        // container /dev/shm normally is.
        let shm = Path::new("/dev/shm");
        let required =
            StatVfsMountFlags::NOSUID | StatVfsMountFlags::NODEV | StatVfsMountFlags::NOEXEC;
        if !shm.is_dir() || !statvfs(shm).unwrap().f_flag.contains(required) {
            return;
        }
        let pipes = tempfile::tempdir_in(shm).unwrap();
        let control = pipes.path().join("control");
        mkfifoat(rustix::fs::CWD, &control, Mode::from_bits_truncate(0o600)).unwrap();
        let outside = tempfile::tempdir().unwrap();
        let sibling = outside.path().join("secret");
        std::fs::write(&sibling, b"secret").unwrap();
        // Policy enrichment adds the exact IPC directory as read-write.
        let policy = hard_requirement_policy(vec![], vec![pipes.path().to_path_buf()]);
        let launch_context = crate::launch::WorkloadLaunchContext {
            cdi_requirements: Some(crate::launch::CdiDerivedRequirements {
                ipc_directory_paths: vec![pipes.path().to_string_lossy().into_owned()],
                ..Default::default()
            }),
        };
        let client = pipes.path().join("client");
        std::thread::spawn(move || {
            let prepared = prepare_current_user(&policy, None, &launch_context)
                .unwrap()
                .unwrap();
            enforce(prepared).unwrap();
            // Opening a FIFO read-write needs no peer and requires write access.
            rustix::fs::open(&control, OFlags::RDWR | OFlags::CLOEXEC, Mode::empty()).unwrap();
            std::fs::write(&client, b"client").unwrap();
            assert_eq!(
                std::fs::read(&sibling).unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
        })
        .join()
        .unwrap();
    }

    #[test]
    fn cdi_rules_remain_pinned_after_symlink_swap() {
        let availability = probe_availability();
        if !matches!(availability, LandlockAvailability::Available { abi } if abi >= 3) {
            assert!(
                std::env::var_os("OPENSHELL_TEST_REQUIRE_LANDLOCK").is_none(),
                "Landlock ABI v3 required for this regression: {availability}"
            );
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let library = temp.path().join("lib");
        let alias = temp.path().join("alias");
        std::fs::create_dir(&library).unwrap();
        std::fs::write(library.join("sentinel"), b"allowed").unwrap();
        std::os::unix::fs::symlink(&library, &alias).unwrap();
        let mut policy = hard_requirement_policy(vec![alias.clone()], vec![]);
        policy.landlock.compatibility = LandlockCompatibility::BestEffort;
        let launch_context = crate::launch::WorkloadLaunchContext {
            cdi_requirements: Some(crate::launch::CdiDerivedRequirements {
                read_only_paths: vec![alias.to_string_lossy().into_owned()],
                ..Default::default()
            }),
        };
        std::thread::spawn(move || {
            let prepared = prepare_current_user(&policy, None, &launch_context)
                .unwrap()
                .unwrap();
            std::fs::remove_file(&alias).unwrap();
            std::os::unix::fs::symlink("/", &alias).unwrap();
            // Later exec preparation must validate the swapped target afresh.
            assert!(prepare_current_user(&policy, None, &launch_context).is_err());
            enforce(prepared).unwrap();
            assert_eq!(std::fs::read(library.join("sentinel")).unwrap(), b"allowed");
            for path in [PathBuf::from("/etc/hosts"), alias.join("etc/hosts")] {
                assert_eq!(
                    std::fs::read(path).unwrap_err().kind(),
                    std::io::ErrorKind::PermissionDenied
                );
            }
        })
        .join()
        .unwrap();
    }

    #[test]
    fn cdi_alias_validation_is_fatal_in_best_effort_mode() {
        let temp = tempfile::tempdir().unwrap();
        let alias = temp.path().join("lib");
        std::os::unix::fs::symlink("/", &alias).unwrap();
        let mut policy = hard_requirement_policy(vec![alias.clone()], vec![]);
        policy.landlock.compatibility = LandlockCompatibility::BestEffort;
        let launch_context = crate::launch::WorkloadLaunchContext {
            cdi_requirements: Some(crate::launch::CdiDerivedRequirements {
                read_only_paths: vec![alias.to_string_lossy().into_owned()],
                ..Default::default()
            }),
        };
        assert!(prepare_current_user(&policy, None, &launch_context).is_err());
    }

    #[test]
    fn cdi_targets_covered_by_authored_ancestors_are_still_validated() {
        if !matches!(probe_availability(), LandlockAvailability::Available { .. }) {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let alias = temp.path().join("lib");
        std::os::unix::fs::symlink("/", &alias).unwrap();
        let policy = hard_requirement_policy(vec![temp.path().to_path_buf()], vec![]);
        let launch_context = crate::launch::WorkloadLaunchContext {
            cdi_requirements: Some(crate::launch::CdiDerivedRequirements {
                read_only_paths: vec![alias.to_string_lossy().into_owned()],
                ..Default::default()
            }),
        };
        let Err(error) = prepare_current_user(&policy, None, &launch_context) else {
            panic!("covered CDI target must be validated");
        };
        assert!(error.to_string().contains("broad root"));
    }

    #[test]
    fn cdi_missing_path_is_fatal_in_current_user_mode() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("missing");
        let mut policy = hard_requirement_policy(vec![path.clone()], vec![]);
        policy.landlock.compatibility = LandlockCompatibility::BestEffort;
        let launch_context = crate::launch::WorkloadLaunchContext {
            cdi_requirements: Some(crate::launch::CdiDerivedRequirements {
                read_only_paths: vec![path.to_string_lossy().into_owned()],
                ..Default::default()
            }),
        };
        assert!(prepare_current_user(&policy, None, &launch_context).is_err());
    }

    #[test]
    fn cdi_writable_mounts_reject_authored_write_grants_at_enforcement() {
        let temp = tempfile::tempdir().unwrap();
        let allowed = temp.path().join("allowed");
        let cache = allowed.join("cache");
        std::fs::create_dir_all(&cache).unwrap();
        let file = cache.join("cache.db");
        std::fs::write(&file, b"original").unwrap();
        for path in [cache, file] {
            for grant in [allowed.clone(), path.clone()] {
                let policy = hard_requirement_policy(vec![temp.path().into()], vec![grant]);
                // Check both a persisted writable requirement and mount metadata
                // alone, so neither representation can bypass enforcement.
                for explicit_requirement in [false, true] {
                    let launch_context = crate::launch::WorkloadLaunchContext {
                        cdi_requirements: Some(crate::launch::CdiDerivedRequirements {
                            read_write_mount_paths: if explicit_requirement {
                                vec![path.to_string_lossy().into_owned()]
                            } else {
                                Vec::new()
                            },
                            mounts: vec![crate::launch::CdiMountRequirement {
                                path: path.to_string_lossy().into_owned(),
                                read_only: false,
                            }],
                            ..Default::default()
                        }),
                    };
                    let error = prepare_current_user(&policy, None, &launch_context)
                        .err()
                        .unwrap();
                    assert!(error.to_string().contains("CDI writable mount"));
                }
            }
        }
    }

    #[test]
    fn prepare_hard_requirement_accepts_device_paths() {
        if !matches!(probe_availability(), LandlockAvailability::Available { .. }) {
            return;
        }

        let policy = hard_requirement_policy(
            vec![PathBuf::from("/tmp"), PathBuf::from("/dev/urandom")],
            vec![PathBuf::from("/dev/null")],
        );

        let result = prepare(&policy, None);
        if let Err(err) = result {
            panic!("hard_requirement should accept mixed directory and device paths: {err}");
        }
    }

    #[test]
    fn capability_free_baseline_omits_only_private_root() {
        let root = tempfile::tempdir().unwrap();
        for name in ["bin", "etc", "sandbox", ".openshell"] {
            std::fs::create_dir(root.path().join(name)).unwrap();
        }

        std::os::unix::fs::symlink(root.path(), root.path().join("root-alias")).unwrap();
        std::os::unix::fs::symlink(
            root.path().join(".openshell"),
            root.path().join("private-alias"),
        )
        .unwrap();
        let paths: Vec<_> = capability_free_baseline_entries(root.path())
            .unwrap()
            .map(|entry| entry.unwrap().0)
            .collect();
        assert_eq!(
            paths,
            ["bin", "etc", "sandbox"]
                .map(|name| root.path().join(name))
                .to_vec()
        );
    }

    #[test]
    fn capability_free_baseline_rejects_private_root_redirect() {
        let root = tempfile::tempdir().unwrap();
        let public = root.path().join("public");
        let private = root.path().join(".openshell");
        std::fs::create_dir(&public).unwrap();
        std::fs::write(public.join("secret"), b"private mount contents").unwrap();
        std::os::unix::fs::symlink(&public, &private).unwrap();
        assert!(capability_free_baseline_entries(root.path()).is_err());
        std::fs::remove_file(&private).unwrap();
        std::fs::write(&private, b"not a directory").unwrap();
        assert!(capability_free_baseline_entries(root.path()).is_err());
    }

    #[test]
    fn capability_free_baseline_prepares_under_low_descriptor_limit() {
        const CHILD_MARKER: &str = "OPENSHELL_TEST_LANDLOCK_FD_LIMIT_CHILD";

        if !matches!(probe_availability(), LandlockAvailability::Available { abi } if abi >= 3) {
            return;
        }

        // Descriptor limits are process-wide. Isolate this test from the other
        // tests' sockets and files, and lower the limit only in the child.
        if std::env::var_os(CHILD_MARKER).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "sandbox::linux::landlock::tests::capability_free_baseline_prepares_under_low_descriptor_limit",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD_MARKER, "1")
                .output()
                .expect("run isolated Landlock descriptor-limit test");
            assert!(
                output.status.success(),
                "isolated Landlock descriptor-limit test failed: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
            return;
        }

        let root = tempfile::tempdir().unwrap();
        for index in 0..128 {
            std::fs::write(root.path().join(format!("entry-{index:03}")), b"public").unwrap();
        }
        std::fs::create_dir(root.path().join(".openshell")).unwrap();

        // More entries than available descriptors forces the production path
        // to release each entry after adding its rule instead of collecting FDs.
        nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_NOFILE, 64, 64)
            .expect("lower child descriptor limit");
        let _prepared = prepare_capability_free_baseline_at(root.path())
            .expect("prepare 128 baseline entries with a 64-descriptor limit");
    }

    #[test]
    fn capability_free_baseline_denies_alias_reads_and_path_truncation() {
        if !matches!(probe_availability(), LandlockAvailability::Available { abi } if abi >= 3) {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let public = root.path().join("public");
        let private = root.path().join(".openshell");
        std::fs::create_dir(&public).unwrap();
        std::fs::create_dir(&private).unwrap();
        std::fs::write(public.join("sentinel"), b"allowed").unwrap();
        std::fs::write(private.join("secret"), b"protected").unwrap();
        let spec = root
            .path()
            .join(openshell_core::cdi::cdi_spec_mount_path(0).trim_start_matches('/'))
            .join("other-vendor.yaml");
        std::fs::create_dir_all(spec.parent().unwrap()).unwrap();
        std::fs::write(&spec, b"trusted runtime CDI metadata").unwrap();
        std::os::unix::fs::symlink(root.path(), root.path().join("root-alias")).unwrap();
        std::os::unix::fs::symlink(&private, root.path().join("private-alias")).unwrap();
        let path = root.path().to_path_buf();
        std::thread::spawn(move || {
            let authored = prepare(&hard_requirement_policy(vec![path.clone()], vec![]), None)
                .unwrap()
                .unwrap();
            enforce(prepare_capability_free_baseline_at(&path).unwrap()).unwrap();
            enforce(authored).unwrap();
            assert_eq!(
                std::fs::read(&spec).unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
            assert_eq!(
                std::fs::read(path.join("public/sentinel")).unwrap(),
                b"allowed"
            );
            for name in [
                ".openshell/secret",
                "root-alias/.openshell/secret",
                "private-alias/secret",
                ".openshell/cdi-specs/0/other-vendor.yaml",
                "private-alias/cdi-specs/0/other-vendor.yaml",
            ] {
                let target = path.join(name);
                assert_eq!(
                    std::fs::read(&target).unwrap_err().kind(),
                    std::io::ErrorKind::PermissionDenied
                );
                let target = std::ffi::CString::new(target.as_os_str().as_encoded_bytes()).unwrap();
                // SAFETY: target is a live, NUL-terminated path. The syscall
                // tests pathname truncation without opening a file first.
                #[allow(unsafe_code)]
                let result = unsafe { libc::truncate(target.as_ptr(), 0) };
                assert_eq!(result, -1);
                assert_eq!(
                    std::io::Error::last_os_error().kind(),
                    std::io::ErrorKind::PermissionDenied
                );
            }
            let policy = hard_requirement_policy(vec![path.join("public")], Vec::new());
            enforce(
                prepare_current_user(
                    &policy,
                    None,
                    &crate::launch::WorkloadLaunchContext::default(),
                )
                .unwrap()
                .unwrap(),
            )
            .unwrap();
            let read_only =
                std::ffi::CString::new(path.join("public/sentinel").as_os_str().as_encoded_bytes())
                    .unwrap();
            // SAFETY: live NUL-terminated pathname; optional read-only policy
            // must handle truncation independently of the protected baseline.
            #[allow(unsafe_code)]
            let truncated = unsafe { libc::truncate(read_only.as_ptr(), 0) };
            assert_eq!(truncated, -1);
            assert_eq!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::PermissionDenied
            );
        })
        .join()
        .unwrap();
        assert_eq!(std::fs::read(private.join("secret")).unwrap(), b"protected");
    }
    fn tailored_access(path: &Path, requested_access: BitFlags<AccessFs>) -> BitFlags<AccessFs> {
        let path_fd = PathFd::new(path).unwrap();
        access_for_path_fd(&path_fd, requested_access, ABI::V2).unwrap()
    }

    #[test]
    fn access_for_path_fd_preserves_directory_access() {
        let dir = tempfile::tempdir().unwrap();
        let requested_access = AccessFs::from_all(ABI::V2);

        assert_eq!(
            tailored_access(dir.path(), requested_access),
            requested_access
        );
    }

    #[test]
    fn access_for_path_fd_limits_regular_file_access() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let requested_access = AccessFs::from_all(ABI::V2);

        assert_eq!(
            tailored_access(file.path(), requested_access),
            requested_access & AccessFs::from_file(ABI::V2)
        );
    }

    #[test]
    fn access_for_path_fd_limits_character_device_access() {
        let requested_read = AccessFs::from_read(ABI::V2);
        let requested_write = AccessFs::from_all(ABI::V2);

        assert_eq!(
            tailored_access(Path::new("/dev/urandom"), requested_read),
            requested_read & AccessFs::from_file(ABI::V2)
        );
        assert_eq!(
            tailored_access(Path::new("/dev/null"), requested_write),
            requested_write & AccessFs::from_file(ABI::V2)
        );
    }

    #[test]
    fn access_for_path_fd_classifies_symlink_target() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("link");
        std::fs::File::create(&target).unwrap();
        symlink(&target, &link).unwrap();

        let requested_access = AccessFs::from_all(ABI::V2);
        assert_eq!(
            tailored_access(&link, requested_access),
            requested_access & AccessFs::from_file(ABI::V2)
        );
    }

    #[test]
    fn try_open_path_best_effort_returns_none_for_missing_path() {
        let result = try_open_path(
            &PathBuf::from("/nonexistent/openshell/test/path"),
            &LandlockCompatibility::BestEffort,
            PathOpenMode::Privileged,
        );
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn try_open_path_hard_requirement_errors_for_missing_path() {
        let result = try_open_path(
            &PathBuf::from("/nonexistent/openshell/test/path"),
            &LandlockCompatibility::HardRequirement,
            PathOpenMode::Privileged,
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
        let result = try_open_path(
            dir.path(),
            &LandlockCompatibility::BestEffort,
            PathOpenMode::Privileged,
        );
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn try_open_path_current_user_skips_missing_path_in_hard_requirement() {
        let result = try_open_path(
            &PathBuf::from("/nonexistent/openshell/test/path"),
            &LandlockCompatibility::HardRequirement,
            PathOpenMode::CurrentUser,
        );
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
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

    #[test]
    fn probe_availability_returns_a_result() {
        // The probe should not panic regardless of whether Landlock is available.
        // On Linux hosts with Landlock, this returns Available; on Docker Desktop
        // linuxkit or older kernels, it returns NotImplemented/NotEnabled/Blocked.
        let result = probe_availability();
        let display = format!("{result}");
        assert!(
            !display.is_empty(),
            "probe_availability Display should produce output"
        );
        // Verify the Debug impl works too.
        let debug = format!("{result:?}");
        assert!(
            !debug.is_empty(),
            "probe_availability Debug should produce output"
        );
    }

    #[test]
    fn check_abi_accepts_the_required_abi_or_newer() {
        for abi in [REQUIRED_ABI, REQUIRED_ABI + 4] {
            let detected = check_abi(&LandlockAvailability::Available { abi }).unwrap();
            assert_eq!(detected, abi.unsigned_abs());
        }
    }

    #[test]
    fn check_abi_names_the_required_and_detected_abi() {
        let err = check_abi(&LandlockAvailability::Available { abi: 2 })
            .unwrap_err()
            .to_string();
        assert!(err.contains("ABI v3 or newer"), "{err}");
        assert!(err.contains("ABI v2"), "{err}");
    }

    #[test]
    fn check_abi_rejects_unavailable_landlock() {
        for availability in [
            LandlockAvailability::NotImplemented,
            LandlockAvailability::NotEnabled,
            LandlockAvailability::Blocked,
            LandlockAvailability::Unknown(libc::EIO),
        ] {
            let err = check_abi(&availability).unwrap_err().to_string();
            assert!(err.contains("ABI v3 or newer"), "{err}");
            assert!(err.contains(&availability.to_string()), "{err}");
        }
    }
}
