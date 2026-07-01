// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared validation helpers for driver-config mounts.

use std::collections::HashSet;
use std::path::Path;

/// `SELinux` relabelling mode for bind mounts.
///
/// On hosts with `SELinux` enabled (e.g. Fedora, RHEL) a bind-mounted path
/// must be relabelled so the container process can access it.
///
/// * `shared` (`:z`) — the label is shared across all containers that mount
///   the same path.  Safe when multiple sandboxes read the same data set.
/// * `private` (`:Z`) — the label is private to *this* container.  The host
///   directory becomes inaccessible to other containers (and potentially to
///   the host) until the container is removed.  Use only when exclusive
///   ownership is acceptable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelinuxLabel {
    /// Shared `SELinux` label (`:z`).
    Shared,
    /// Private `SELinux` label (`:Z`).
    Private,
}

const RESERVED_MOUNT_TARGETS: &[&str] = &[
    "/opt/openshell",
    "/etc/openshell",
    "/etc/openshell-tls",
    "/run/netns",
];

/// Validate a non-empty driver mount source.
pub fn validate_mount_source(source: &str, field: &str) -> Result<(), String> {
    if source.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if source != source.trim() {
        return Err(format!("{field} must not contain surrounding whitespace"));
    }
    if source.as_bytes().contains(&0) {
        return Err(format!("{field} must not contain NUL bytes"));
    }
    Ok(())
}

/// Validate a bind mount source as an absolute host path.
pub fn validate_absolute_mount_source(source: &str, field: &str) -> Result<(), String> {
    validate_mount_source(source, field)?;
    if !Path::new(source).is_absolute() {
        return Err(format!("{field} must be an absolute host path"));
    }
    Ok(())
}

/// Validate a relative subpath inside a runtime-managed mount source.
pub fn validate_mount_subpath(subpath: &str) -> Result<(), String> {
    if subpath.is_empty() {
        return Err("mount subpath must not be empty".to_string());
    }
    if subpath != subpath.trim() {
        return Err("mount subpath must not contain surrounding whitespace".to_string());
    }
    if subpath.as_bytes().contains(&0) {
        return Err("mount subpath must not contain NUL bytes".to_string());
    }
    let path = Path::new(subpath);
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err("mount subpath must be relative and must not contain '..'".to_string());
    }
    Ok(())
}

/// Validate a container-side mount target for user-supplied driver mounts.
pub fn validate_container_mount_target(target: &str) -> Result<(), String> {
    if target.is_empty() {
        return Err("mount target must not be empty".to_string());
    }
    if target != target.trim() {
        return Err("mount target must not contain surrounding whitespace".to_string());
    }
    if target.as_bytes().contains(&0) {
        return Err("mount target must not contain NUL bytes".to_string());
    }
    if !target.starts_with('/') {
        return Err("mount target must be an absolute container path".to_string());
    }
    let path = Path::new(target);
    if path == Path::new("/") {
        return Err("mount target must not be the container root".to_string());
    }
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err("mount target must not contain '..'".to_string());
    }
    if path == Path::new("/sandbox") {
        return Err("mount target '/sandbox' is reserved for the OpenShell workspace".to_string());
    }
    for reserved in RESERVED_MOUNT_TARGETS {
        if path_is_or_under(path, Path::new(reserved)) {
            return Err(format!(
                "mount target '{target}' conflicts with reserved OpenShell path '{reserved}'"
            ));
        }
    }
    Ok(())
}

/// Normalize a validated container-side mount target for semantic comparison.
pub fn normalize_mount_target(target: &str) -> String {
    if target == "/" {
        return target.to_string();
    }
    target.trim_end_matches('/').to_string()
}

/// Return true when `path` is exactly `parent` or is contained below it.
pub fn path_is_or_under(path: &Path, parent: &Path) -> bool {
    path == parent || path.starts_with(parent)
}

/// Validate that already-normalized driver mount targets are unique.
pub fn validate_unique_mount_targets<'a>(
    targets: impl IntoIterator<Item = &'a str>,
    driver_name: &str,
) -> Result<(), String> {
    let mut seen = HashSet::new();
    for target in targets {
        if !seen.insert(target) {
            return Err(format!(
                "duplicate {driver_name} driver_config mount target '{target}'"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_target_allows_paths_under_workspace() {
        validate_container_mount_target("/sandbox/work/").unwrap();
        assert_eq!(normalize_mount_target("/sandbox/work/"), "/sandbox/work");
    }

    #[test]
    fn container_target_rejects_workspace_root_only() {
        let err = validate_container_mount_target("/sandbox/").unwrap_err();

        assert!(err.contains("reserved for the OpenShell workspace"));
    }

    #[test]
    fn container_target_rejects_reserved_openshell_tls_legacy_path() {
        let err = validate_container_mount_target("/etc/openshell-tls/client").unwrap_err();

        assert!(err.contains("/etc/openshell-tls"));
    }

    #[test]
    fn container_target_rejects_reserved_openshell_tree() {
        let err = validate_container_mount_target("/etc/openshell/tls/client").unwrap_err();

        assert!(err.contains("/etc/openshell"));
    }

    #[test]
    fn container_target_does_not_prefix_match_unrelated_paths() {
        validate_container_mount_target("/etc/openshell-tools").unwrap();
    }

    #[test]
    fn path_is_or_under_matches_boundaries() {
        assert!(path_is_or_under(
            Path::new("/sandbox"),
            Path::new("/sandbox")
        ));
        assert!(path_is_or_under(
            Path::new("/sandbox/work"),
            Path::new("/sandbox")
        ));
        assert!(!path_is_or_under(
            Path::new("/sandbox-work"),
            Path::new("/sandbox")
        ));
    }

    #[test]
    fn unique_mount_targets_rejects_duplicates() {
        let err =
            validate_unique_mount_targets(["/sandbox/work", "/sandbox/work"], "test").unwrap_err();

        assert_eq!(
            err,
            "duplicate test driver_config mount target '/sandbox/work'"
        );
    }

    #[test]
    fn mount_subpath_must_be_relative_without_parent_dirs() {
        assert!(validate_mount_subpath("project/a").is_ok());
        assert!(validate_mount_subpath(" project/a ").is_err());
        assert!(validate_mount_subpath("/project").is_err());
        assert!(validate_mount_subpath("../project").is_err());
    }

    #[test]
    fn mount_values_reject_surrounding_whitespace() {
        assert_eq!(
            validate_mount_source(" volume ", "volume source").unwrap_err(),
            "volume source must not contain surrounding whitespace"
        );
        assert_eq!(
            validate_absolute_mount_source(" /host/path", "bind source").unwrap_err(),
            "bind source must not contain surrounding whitespace"
        );
        assert_eq!(
            validate_container_mount_target("/sandbox/work ").unwrap_err(),
            "mount target must not contain surrounding whitespace"
        );
    }
}
