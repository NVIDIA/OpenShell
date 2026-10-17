// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Resolution of policy binary paths through a sandbox's root filesystem.
//!
//! Policies name binaries by the path a user writes (e.g. `/usr/bin/python3`),
//! while the kernel reports the canonical executable (e.g.
//! `/usr/bin/python3.11`). Both policy engines resolve each authored path
//! through `/proc/<pid>/root/` with [`resolve_policy_binary`] once the
//! entrypoint process is known: YAML adds the target as another binary
//! entry, and Cedar exposes it in `context.binary_aliases`.
//!
//! [`compile_binary_glob`] builds the matcher the Rego rules apply to a YAML
//! binary glob, which Cedar reuses for `context.binary_globs`.

#[cfg(any(target_os = "linux", test))]
use std::path::{Path, PathBuf};

/// Compiles a YAML binary glob as the Rego rules match it.
///
/// The rules call `glob.match(pattern, ["/"], path)`, which builds the glob
/// with a literal `/` separator: `*` stays within one path segment and `**`
/// spans segments only as a whole segment.
///
/// # Errors
///
/// Returns the `globset` error for a pattern that does not compile, which
/// fails Rego evaluation.
pub fn compile_binary_glob(pattern: &str) -> Result<globset::GlobMatcher, globset::Error> {
    Ok(globset::GlobBuilder::new(pattern)
        .literal_separator(true)
        .build()?
        .compile_matcher())
}

/// Normalize a path by resolving `.` and `..` components without touching
/// the filesystem. Only works correctly for absolute paths.
#[cfg(any(target_os = "linux", test))]
pub fn normalize_path(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                result.pop();
            }
            std::path::Component::CurDir => {}
            other => result.push(other),
        }
    }
    result
}

// Only the Linux resolver constructs the non-`Literal` variants; on other
// platforms the stub returns `Literal`, so the rest look dead there.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, PartialEq, Eq)]
pub enum BinaryResolution {
    /// Symlink resolved to a different canonical target — add it to policy.
    Resolved(String),
    /// Nothing to add: glob, pid 0, not a symlink, or already canonical.
    Literal,
    /// Candidate absent under an accessible process root — expected, quiet.
    Absent,
    /// The process root `/proc/<pid>/root` itself is unreachable (pid gone or
    /// denied) — actionable, and `CAP_SYS_PTRACE` guidance is relevant.
    Inaccessible(std::io::ErrorKind),
    /// The process root is reachable but the candidate path itself failed for a
    /// non-NotFound reason (a parent component is permission-denied, or the path
    /// forms a symlink loop) — actionable, but a target-path problem rather than
    /// a process-root one, so `CAP_SYS_PTRACE` guidance does not apply.
    CandidateInaccessible(std::io::ErrorKind),
    /// A component mid symlink-chain failed to resolve.
    ChainBroken(std::io::ErrorKind),
}

impl BinaryResolution {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub const fn classify_first_probe_error(kind: std::io::ErrorKind) -> Self {
        // Callers reach this only after confirming the process root is
        // reachable, so a non-NotFound failure here is specific to the
        // candidate path, not the process root.
        match kind {
            std::io::ErrorKind::NotFound => Self::Absent,
            _ => Self::CandidateInaccessible(kind),
        }
    }
}

/// Resolve a policy binary path through the container's root filesystem.
///
/// On Linux, `/proc/<pid>/root/` provides access to the container's mount
/// namespace. If the policy path is a symlink inside the container
/// (e.g., `/usr/bin/python3` → `/usr/bin/python3.11`), the canonical target is
/// returned as [`BinaryResolution::Resolved`]. The outcome is classified as:
/// - [`BinaryResolution::Literal`] — not on Linux, `entrypoint_pid` is 0
///   (container not yet started), the path contains glob characters, it is not
///   a symlink, or the resolved path equals the original.
/// - [`BinaryResolution::Absent`] — the candidate does not exist under an
///   otherwise reachable process root (expected; the caller logs it quietly).
/// - [`BinaryResolution::Inaccessible`] — `/proc/<pid>/root` itself is
///   unreachable (pid gone or access denied).
/// - [`BinaryResolution::CandidateInaccessible`] — the process root is
///   reachable but the candidate path failed for a non-NotFound reason.
/// - [`BinaryResolution::ChainBroken`] — a component mid symlink-chain failed,
///   or the chain forms a cycle / exceeds the kernel symlink limit.
#[cfg(target_os = "linux")]
pub fn resolve_binary_in_container(policy_path: &str, entrypoint_pid: u32) -> BinaryResolution {
    if policy_path.contains('*') || entrypoint_pid == 0 {
        return BinaryResolution::Literal;
    }

    // Confirm the process root itself is reachable before probing candidates.
    // A leaf `ENOENT` (absent candidate) and an unreachable process root
    // (pid gone -> `ENOENT`, or denied -> `EACCES`) are indistinguishable at
    // the leaf path, so check the root first. Any failure here is an access
    // problem, not an absent candidate, and must stay actionable.
    if let Err(e) = std::fs::metadata(format!("/proc/{entrypoint_pid}/root")) {
        return BinaryResolution::Inaccessible(e.kind());
    }

    // Walk the symlink chain inside the container filesystem using
    // read_link rather than canonicalize. canonicalize resolves
    // /proc/<pid>/root itself (a kernel pseudo-symlink to /) which
    // strips the prefix we need. read_link only reads the target of
    // the specified symlink, keeping us in the container's namespace.
    let mut resolved = PathBuf::from(policy_path);

    // Set once the walk reaches a real (non-symlink) target or a terminal
    // dead end. If the iteration cap is hit while every component is still a
    // symlink, this stays false and the chain is treated as broken.
    let mut reached_target = false;

    // Linux SYMLOOP_MAX is 40; stop before infinite loops
    for _ in 0..40 {
        let container_path = format!("/proc/{entrypoint_pid}/root{}", resolved.display());

        tracing::debug!(
            "Symlink resolution: probing container_path={container_path} for policy_path={policy_path} pid={entrypoint_pid}"
        );

        let meta = match std::fs::symlink_metadata(&container_path) {
            Ok(m) => m,
            Err(e) => {
                // First iteration is the original policy path: an absent
                // candidate (NotFound) is expected, any other error means the
                // process root itself is unreachable. Later iterations are
                // chain components, so a failure there is a broken symlink
                // chain. Classify without logging; the caller emits the log at
                // the appropriate level.
                if resolved.as_os_str() == policy_path {
                    // The up-front root check and this probe are separate
                    // syscalls; if the process exited in between, the whole
                    // `/proc/<pid>` tree is gone and the leaf probe also
                    // reports NotFound. Re-check the root so a vanished process
                    // stays classified as Inaccessible (actionable) rather than
                    // being masked as an absent candidate (quiet).
                    if e.kind() == std::io::ErrorKind::NotFound
                        && let Err(root_error) =
                            std::fs::metadata(format!("/proc/{entrypoint_pid}/root"))
                    {
                        return BinaryResolution::Inaccessible(root_error.kind());
                    }
                    return BinaryResolution::classify_first_probe_error(e.kind());
                }
                return BinaryResolution::ChainBroken(e.kind());
            }
        };

        if !meta.file_type().is_symlink() {
            // Reached a non-symlink — this is the final resolved target
            reached_target = true;
            break;
        }

        let target = match std::fs::read_link(&container_path) {
            Ok(t) => t,
            // A symlink whose target can't be read is a broken chain; the
            // caller logs it.
            Err(e) => return BinaryResolution::ChainBroken(e.kind()),
        };

        if target.is_absolute() {
            resolved = target;
        } else if let Some(parent) = resolved.parent() {
            // Relative symlink: resolve against the containing directory
            // e.g., /usr/bin/python3 -> python3.11 becomes /usr/bin/python3.11
            resolved = normalize_path(&parent.join(&target));
        } else {
            // No parent to resolve a relative target against — terminal.
            reached_target = true;
            break;
        }
    }

    if !reached_target {
        // The cap was exhausted while following symlinks. Linux SYMLOOP_MAX is
        // 40, so a chain of exactly 40 symlinks ending at a real file is still
        // valid — after the 40th hop `resolved` may already point at that file.
        // Inspect it once more without following another link: a non-symlink is
        // the valid final target (fall through to the Literal/Resolved logic
        // below), while another symlink (or an error) is a genuine cycle
        // (a -> b -> a) or a chain deeper than the kernel allows. read_link
        // resolves one hop at a time, so the kernel never surfaces ELOOP; treat
        // those as a broken chain so the caller logs it and matches literally.
        let container_path = format!("/proc/{entrypoint_pid}/root{}", resolved.display());

        match std::fs::symlink_metadata(&container_path) {
            Ok(meta) if !meta.file_type().is_symlink() => {}
            Ok(_) => {
                return BinaryResolution::ChainBroken(
                    std::io::Error::from_raw_os_error(libc::ELOOP).kind(),
                );
            }
            Err(e) => return BinaryResolution::ChainBroken(e.kind()),
        }
    }

    let resolved_str = resolved.to_string_lossy().into_owned();

    if resolved_str == policy_path {
        BinaryResolution::Literal
    } else {
        // The caller logs the resolution at info level.
        BinaryResolution::Resolved(resolved_str)
    }
}

#[cfg(not(target_os = "linux"))]
pub fn resolve_binary_in_container(_policy_path: &str, _entrypoint_pid: u32) -> BinaryResolution {
    BinaryResolution::Literal
}

/// Resolves a policy binary path through the container's root filesystem
/// and logs the outcome.
///
/// Returns the canonical target when `policy_path` is a symlink inside the
/// container that resolves to a different path, which YAML adds as another
/// binary entry; see [`resolve_binary_in_container`]. A Cedar sandbox
/// resolves the paths its policies test in `context.binary_aliases` with
/// this same function.
pub fn resolve_policy_binary(policy_path: &str, entrypoint_pid: u32) -> Option<String> {
    match resolve_binary_in_container(policy_path, entrypoint_pid) {
        BinaryResolution::Resolved(resolved) => {
            tracing::info!(
                "Resolved policy binary symlink: original={policy_path} resolved={resolved} pid={entrypoint_pid}"
            );
            return Some(resolved);
        }
        BinaryResolution::Absent => {
            tracing::debug!(
                "Policy binary candidate not present in container: path={policy_path} pid={entrypoint_pid}. Matched literally."
            );
        }
        BinaryResolution::Inaccessible(kind) => {
            tracing::warn!(
                "Cannot access container filesystem for symlink resolution: path={policy_path} pid={entrypoint_pid} \
                error_kind={kind:?}. Binary paths in policy will be matched literally. \
                If this binary is a symlink (e.g., /usr/bin/python3 -> python3.11), \
                use the canonical path instead, or run with CAP_SYS_PTRACE."
            );
        }
        BinaryResolution::CandidateInaccessible(kind) => {
            tracing::warn!(
                "Cannot access policy binary candidate path: path={policy_path} pid={entrypoint_pid} \
                error_kind={kind:?}. Binary path will be matched literally. \
                A parent component is permission-denied or the path forms a symlink loop; \
                the process root itself is reachable."
            );
        }
        BinaryResolution::ChainBroken(kind) => {
            tracing::warn!(
                "Symlink chain broken during resolution: path={policy_path} pid={entrypoint_pid} error_kind={kind:?}. \
                Matched by original path only."
            );
        }
        BinaryResolution::Literal => {}
    }
    None
}
