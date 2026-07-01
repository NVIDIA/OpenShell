// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared validation helpers for driver-config mounts.

use std::collections::HashSet;
use std::path::Path;

const RESERVED_MOUNT_TARGETS: &[&str] = &[
    "/opt/openshell",
    "/etc/openshell",
    "/etc/openshell-tls",
    "/run/netns",
];

/// Validate a non-empty driver mount source.
pub fn validate_mount_source(source: &str, field: &str) -> Result<String, String> {
    let source = source.trim();
    if source.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if source.as_bytes().contains(&0) {
        return Err(format!("{field} must not contain NUL bytes"));
    }
    Ok(source.to_string())
}

/// Validate a bind mount source as an absolute host path.
pub fn validate_absolute_mount_source(source: &str, field: &str) -> Result<String, String> {
    let source = validate_mount_source(source, field)?;
    if !Path::new(&source).is_absolute() {
        return Err(format!("{field} must be an absolute host path"));
    }
    Ok(source)
}

/// Validate a relative subpath inside a runtime-managed mount source.
pub fn validate_mount_subpath(subpath: &str) -> Result<String, String> {
    let subpath = subpath.trim();
    if subpath.is_empty() {
        return Err("mount subpath must not be empty".to_string());
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
    Ok(subpath.to_string())
}

/// Validate a container-side mount target for user-supplied driver mounts.
pub fn validate_container_mount_target(target: &str) -> Result<String, String> {
    let target = normalize_container_mount_target(target);
    if target.is_empty() {
        return Err("mount target must not be empty".to_string());
    }
    if target.as_bytes().contains(&0) {
        return Err("mount target must not contain NUL bytes".to_string());
    }
    if !target.starts_with('/') {
        return Err("mount target must be an absolute container path".to_string());
    }
    if target == "/" {
        return Err("mount target must not be the container root".to_string());
    }
    let path = Path::new(&target);
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err("mount target must not contain '..'".to_string());
    }
    if target == "/sandbox" {
        return Err("mount target '/sandbox' is reserved for the OpenShell workspace".to_string());
    }
    for reserved in RESERVED_MOUNT_TARGETS {
        if path_is_or_under(&target, reserved) {
            return Err(format!(
                "mount target '{target}' conflicts with reserved OpenShell path '{reserved}'"
            ));
        }
    }
    Ok(target)
}

fn normalize_container_mount_target(target: &str) -> String {
    let target = target.trim();
    if target == "/" {
        return target.to_string();
    }
    target.trim_end_matches('/').to_string()
}

/// Return true when `path` is exactly `parent` or is contained below it.
pub fn path_is_or_under(path: &str, parent: &str) -> bool {
    path == parent
        || path
            .strip_prefix(parent)
            .is_some_and(|rest| rest.starts_with('/'))
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
        assert_eq!(
            validate_container_mount_target("/sandbox/work/").unwrap(),
            "/sandbox/work"
        );
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
        assert_eq!(
            validate_container_mount_target("/etc/openshell-tools").unwrap(),
            "/etc/openshell-tools"
        );
    }

    #[test]
    fn path_is_or_under_matches_boundaries() {
        assert!(path_is_or_under("/sandbox", "/sandbox"));
        assert!(path_is_or_under("/sandbox/work", "/sandbox"));
        assert!(!path_is_or_under("/sandbox-work", "/sandbox"));
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
        assert_eq!(validate_mount_subpath(" project/a ").unwrap(), "project/a");
        assert!(validate_mount_subpath("/project").is_err());
        assert!(validate_mount_subpath("../project").is_err());
    }
}
