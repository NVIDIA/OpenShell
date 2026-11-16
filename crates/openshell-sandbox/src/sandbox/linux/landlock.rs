// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Landlock filesystem sandboxing.

#[cfg(test)]
use landlock::PathFd;
use landlock::{
    ABI, Access, AccessFs, BitFlags, CompatLevel, Compatible, PathBeneath, Ruleset, RulesetAttr,
    RulesetCreatedAttr,
};
use miette::{IntoDiagnostic, Result};
use openshell_core::policy::{LandlockCompatibility, SandboxPolicy};
use std::collections::VecDeque;
use std::ffi::OsString;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::path::Component;
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
    prepare_with_path_open_mode(policy, workdir, PathOpenMode::Privileged)
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
) -> Result<Option<PreparedRuleset>> {
    prepare_with_path_open_mode(policy, workdir, PathOpenMode::CurrentUser)
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
    // allowed subtree. Validate it eagerly and independently of the public
    // entries: when present it must be a real directory. The descriptor only
    // backs this check and is dropped before any per-entry descriptor is
    // opened; exclusion during enumeration is by name plus O_NOFOLLOW.
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

fn prepare_with_path_open_mode(
    policy: &SandboxPolicy,
    workdir: Option<&str>,
    path_open_mode: PathOpenMode,
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

    if read_only.is_empty() && read_write.is_empty() {
        return Ok(None);
    }

    let compatibility = &policy.landlock.compatibility;

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
                policy.landlock.compatibility,
                read_only.len(),
                read_write.len(),
            ))
            .build()
    );

    // Path admission is independent of kernel compatibility. In particular, an
    // unsafe policy anchor must never reach the best-effort ruleset fallback.
    let read_only = open_policy_paths(&read_only, compatibility, path_open_mode)?;
    let read_write = open_policy_paths(&read_write, compatibility, path_open_mode)?;
    let rules_applied = read_only.len() + read_write.len();
    if rules_applied == 0 {
        return Err(miette::miette!(
            "Landlock ruleset has zero valid paths — all {} path(s) failed to open. \
             Refusing to continue without filesystem restrictions.",
            total_paths,
        ));
    }

    let result: Result<PreparedRuleset> = (|| {
        let access_all = AccessFs::from_all(abi);
        let access_read = AccessFs::from_read(abi);

        let mut ruleset = Ruleset::default();
        ruleset = ruleset
            .set_compatibility(compat_level(compatibility))
            .handle_access(access_all)
            .into_diagnostic()?;

        let mut ruleset = ruleset.create().into_diagnostic()?;
        for (path, path_fd) in read_only {
            let allowed_access = access_for_path_fd(&path_fd, access_read, abi)?;
            debug!(path = %path.display(), "Landlock allow read-only");
            ruleset = ruleset
                .add_rule(PathBeneath::new(path_fd, allowed_access))
                .into_diagnostic()?;
        }

        for (path, path_fd) in read_write {
            let allowed_access = access_for_path_fd(&path_fd, access_all, abi)?;
            debug!(path = %path.display(), "Landlock allow read-write");
            ruleset = ruleset
                .add_rule(PathBeneath::new(path_fd, allowed_access))
                .into_diagnostic()?;
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

/// A path-opening failure that must not be confused with compatibility errors.
#[derive(Debug)]
enum PolicyPathError {
    Io(std::io::Error),
    UnsafeSymlink,
}

impl From<rustix::io::Errno> for PolicyPathError {
    fn from(error: rustix::io::Errno) -> Self {
        Self::Io(error.into())
    }
}

/// Whether a directory's entries can be changed by this workload identity.
/// Ownership counts even without current write permission: owners can chmod.
/// An unrecognized access-check failure is conservatively treated as mutable.
fn workload_can_modify_directory(directory: &OwnedFd) -> Result<bool, PolicyPathError> {
    use rustix::fs::{Access, AtFlags, accessat, fstat};
    let stat = fstat(directory)?;
    if stat.st_uid == rustix::process::geteuid().as_raw() {
        return Ok(true);
    }
    // A read-only image mount is also immutable to the capability-free
    // workload. Unknown failures remain untrusted rather than granting access.
    Ok(!matches!(
        accessat(directory, ".", Access::WRITE_OK, AtFlags::EACCESS),
        Err(rustix::io::Errno::ACCESS | rustix::io::Errno::ROFS)
    ))
}

fn path_components(path: &Path) -> VecDeque<OsString> {
    path.components()
        .filter_map(|component| match component {
            Component::RootDir | Component::CurDir => None,
            Component::ParentDir => Some(OsString::from("..")),
            Component::Normal(name) => Some(name.to_owned()),
            Component::Prefix(_) => unreachable!("Linux paths have no prefix"),
        })
        .collect()
}

/// Resolve policy anchors through pinned descriptors, following only symlinks
/// beneath directories the workload cannot modify. This preserves immutable
/// image aliases while refusing mutable aliases at every path component.
fn open_policy_path(path: &Path) -> Result<OwnedFd, PolicyPathError> {
    use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat, readlinkat};
    if !path.is_absolute() {
        return Err(PolicyPathError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Landlock policy paths must be absolute",
        )));
    }
    let flags = OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = open("/", flags | OFlags::DIRECTORY, Mode::empty())?;
    let mut mutable_ancestor = workload_can_modify_directory(&directory)?;
    let mut pending = path_components(path);
    let mut symlinks = 0;
    while let Some(component) = pending.pop_front() {
        let fd = openat(&directory, &component, flags, Mode::empty())?;
        match FileType::from_raw_mode(fstat(&fd)?.st_mode) {
            FileType::Symlink => {
                // A non-writable immediate parent is insufficient: an ancestor
                // may allow renaming that parent or replacing its entire tree.
                if mutable_ancestor {
                    return Err(PolicyPathError::UnsafeSymlink);
                }
                symlinks += 1;
                if symlinks > 40 {
                    return Err(rustix::io::Errno::LOOP.into());
                }
                // Empty-path readlinkat reads the opened link, not a possibly
                // replaced directory entry. Magic links are never opened.
                let target = PathBuf::from(OsString::from_vec(
                    readlinkat(&fd, "", Vec::new())?.into_bytes(),
                ));
                if target.is_absolute() {
                    directory = open("/", flags | OFlags::DIRECTORY, Mode::empty())?;
                    mutable_ancestor |= workload_can_modify_directory(&directory)?;
                }
                let mut target_components = path_components(&target);
                target_components.append(&mut pending);
                pending = target_components;
            }
            FileType::Directory => {
                mutable_ancestor |= workload_can_modify_directory(&fd)?;
                directory = fd;
            }
            _ if pending.is_empty() => return Ok(fd),
            _ => return Err(rustix::io::Errno::NOTDIR.into()),
        }
    }
    Ok(directory)
}

fn open_policy_paths(
    paths: &[PathBuf],
    compatibility: &LandlockCompatibility,
    path_open_mode: PathOpenMode,
) -> Result<Vec<(PathBuf, OwnedFd)>> {
    let mut opened = Vec::new();
    for path in paths {
        if let Some(fd) = try_open_path(path, compatibility, path_open_mode)? {
            opened.push((path.clone(), fd));
        }
    }
    Ok(opened)
}

/// Attempt to open a path for Landlock rule creation.
///
/// Mutable symlink traversal is always fatal. In `BestEffort` mode, ordinary
/// inaccessible paths are skipped with `Ok(None)` so the caller can continue
/// building the ruleset from the remaining valid paths.
///
/// In `HardRequirement` mode, any failure is fatal — the caller propagates the
/// error, which ultimately aborts sandbox startup.
fn try_open_path(
    path: &Path,
    compatibility: &LandlockCompatibility,
    path_open_mode: PathOpenMode,
) -> Result<Option<OwnedFd>> {
    match open_policy_path(path) {
        Ok(fd) => Ok(Some(fd)),
        Err(PolicyPathError::UnsafeSymlink) => Err(miette::miette!(
            "Landlock policy path traverses a symlink beneath a workload-modifiable directory: {}",
            path.display()
        )),
        Err(PolicyPathError::Io(err)) => {
            let reason = classify_io_error(&err);
            let is_not_found = err.kind() == std::io::ErrorKind::NotFound;
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
        std::os::unix::fs::symlink(root.path(), root.path().join("root-alias")).unwrap();
        std::os::unix::fs::symlink(&private, root.path().join("private-alias")).unwrap();
        let path = root.path().to_path_buf();
        std::thread::spawn(move || {
            enforce(prepare_capability_free_baseline_at(&path).unwrap()).unwrap();
            assert_eq!(
                std::fs::read(path.join("public/sentinel")).unwrap(),
                b"allowed"
            );
            for name in [
                ".openshell/secret",
                "root-alias/.openshell/secret",
                "private-alias/secret",
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
            enforce(prepare_current_user(&policy, None).unwrap().unwrap()).unwrap();
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
    fn policy_path_rejects_mutable_symlink_in_every_compatibility_mode() {
        let root = tempfile::tempdir().unwrap();
        let link = root.path().join("workspace");
        std::os::unix::fs::symlink("/", &link).unwrap();
        for compatibility in [
            LandlockCompatibility::BestEffort,
            LandlockCompatibility::HardRequirement,
        ] {
            for mode in [PathOpenMode::CurrentUser, PathOpenMode::Privileged] {
                let error = try_open_path(&link, &compatibility, mode).unwrap_err();
                assert!(error.to_string().contains("workload-modifiable"));
            }
        }
    }

    #[test]
    fn policy_path_rejects_mutable_ancestor_symlink() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir(outside.path().join("nested")).unwrap();
        let link = root.path().join("workspace");
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();
        assert!(matches!(
            open_policy_path(&link.join("nested")),
            Err(PolicyPathError::UnsafeSymlink)
        ));
    }

    #[test]
    fn policy_path_owned_readonly_directory_is_mutable() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        let fd = rustix::fs::open(
            root.path(),
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        assert!(workload_can_modify_directory(&fd).unwrap());
        // Restore permissions for TempDir cleanup.
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn policy_path_descriptor_stays_on_admitted_inode_after_replacement() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let fd = open_policy_path(&workspace).unwrap();
        let admitted = rustix::fs::fstat(&fd).unwrap();
        std::fs::remove_dir(&workspace).unwrap();
        std::os::unix::fs::symlink("/", &workspace).unwrap();
        let retained = rustix::fs::fstat(&fd).unwrap();
        assert_eq!(
            (retained.st_dev, retained.st_ino),
            (admitted.st_dev, admitted.st_ino)
        );
        assert!(matches!(
            open_policy_path(&workspace),
            Err(PolicyPathError::UnsafeSymlink)
        ));
    }

    #[test]
    fn policy_path_rejects_relative_paths() {
        assert!(matches!(
            open_policy_path(Path::new("workspace")),
            Err(PolicyPathError::Io(_))
        ));
    }

    #[test]
    fn policy_path_trusted_image_aliases_and_mutable_ancestry() {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::process::CommandExt;
        // Exercise the actual DAC check as an unprivileged workload. Root owns
        // every containing system directory and is not an admitted workload UID.
        if rustix::process::geteuid().is_root() {
            let fixture = tempfile::tempdir().unwrap();
            std::fs::set_permissions(fixture.path(), std::fs::Permissions::from_mode(0o777))
                .unwrap();
            let immutable = fixture.path().join("immutable");
            std::fs::create_dir(&immutable).unwrap();
            std::os::unix::fs::symlink("/", immutable.join("alias")).unwrap();
            std::fs::set_permissions(&immutable, std::fs::Permissions::from_mode(0o555)).unwrap();
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command.args([
                "--exact",
                "sandbox::linux::landlock::tests::policy_path_trusted_image_aliases_and_mutable_ancestry",
                "--nocapture",
            ]).env("OPENSHELL_LANDLOCK_MUTABLE_ANCESTRY", immutable.join("alias"));
            // SAFETY: these credential operations execute only in the forked
            // test child before exec and do not change the test runner identity.
            #[allow(unsafe_code)]
            unsafe {
                command.pre_exec(|| {
                    if libc::setgroups(0, std::ptr::null()) != 0
                        || libc::setgid(65534) != 0
                        || libc::setuid(65534) != 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let status = command.status().unwrap();
            std::fs::set_permissions(&immutable, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert!(status.success());
            return;
        }
        for alias in ["/bin", "/lib"] {
            if std::fs::symlink_metadata(alias).is_ok() {
                open_policy_path(Path::new(alias)).unwrap();
            }
        }
        if let Some(path) = std::env::var_os("OPENSHELL_LANDLOCK_MUTABLE_ANCESTRY") {
            assert!(matches!(
                open_policy_path(Path::new(&path)),
                Err(PolicyPathError::UnsafeSymlink)
            ));
        }
    }

    #[test]
    fn prepare_mutable_policy_anchor_never_uses_best_effort_fallback() {
        if !matches!(probe_availability(), LandlockAvailability::Available { .. }) {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let link = root.path().join("workspace");
        std::os::unix::fs::symlink("/", &link).unwrap();
        for compatibility in [
            LandlockCompatibility::BestEffort,
            LandlockCompatibility::HardRequirement,
        ] {
            for mode in [PathOpenMode::CurrentUser, PathOpenMode::Privileged] {
                let mut policy =
                    hard_requirement_policy(vec![root.path().to_path_buf()], vec![link.clone()]);
                policy.landlock.compatibility = compatibility.clone();
                let error = prepare_with_path_open_mode(&policy, None, mode)
                    .err()
                    .expect("unsafe anchor must abort preparation");
                assert!(error.to_string().contains("workload-modifiable"));
            }
        }
    }

    #[test]
    fn prepare_zero_usable_paths_never_uses_best_effort_fallback() {
        if !matches!(probe_availability(), LandlockAvailability::Available { .. }) {
            return;
        }
        let mut policy = hard_requirement_policy(
            vec![],
            vec![PathBuf::from("/nonexistent/openshell/test/path")],
        );
        policy.landlock.compatibility = LandlockCompatibility::BestEffort;
        let error = prepare_current_user(&policy, None)
            .err()
            .expect("empty allowlist must fail closed");
        assert!(error.to_string().contains("zero valid paths"));
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
