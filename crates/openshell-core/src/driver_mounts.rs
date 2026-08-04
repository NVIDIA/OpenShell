// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared validation helpers for driver-config mounts.

use std::path::Path;

use crate::container_paths::{CONTROL_ROOTS, OCI_RUNTIME_MOUNT_ROOTS};

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

/// Compatibility workspace used when an OCI image has no usable working
/// directory and by drivers whose workspace remains fixed.
pub const DEFAULT_WORKSPACE_ROOT: &str = "/sandbox";

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
///
/// Workspace collisions depend on the inspected image's resolved working
/// directory and are checked separately by `validate_workspace_mount_target`.
pub fn validate_container_mount_target(target: &str) -> Result<(), String> {
    let normalized = normalize_absolute_container_path(target, "mount target")?;
    let path = Path::new(&normalized);
    for reserved in CONTROL_ROOTS {
        let reserved = Path::new(reserved);
        if paths_overlap(path, reserved) {
            return Err(format!(
                "mount target '{target}' conflicts with reserved OpenShell path '{}'",
                reserved.display()
            ));
        }
    }
    Ok(())
}

/// Resolve an OCI image working directory to the internal workspace root used
/// by local container drivers.
///
/// Empty declarations and `/` use the compatibility fallback. Non-empty
/// declarations must already be normalized absolute paths so the inspected
/// value and the path passed to the supervisor cannot be interpreted
/// differently.
pub fn resolve_oci_workspace_root(working_dir: &str) -> Result<String, String> {
    if working_dir.is_empty() || working_dir == "/" {
        return Ok(DEFAULT_WORKSPACE_ROOT.to_string());
    }
    let workspace_root = normalize_absolute_container_path(working_dir, "OCI WorkingDir")?;
    for runtime_path in OCI_RUNTIME_MOUNT_ROOTS {
        validate_workspace_reserved_path(&workspace_root, runtime_path, "OCI runtime mount")?;
    }
    for control_path in CONTROL_ROOTS {
        validate_workspace_control_path(&workspace_root, control_path)?;
    }

    Ok(workspace_root)
}

fn normalize_absolute_container_path(value: &str, field: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if value != value.trim() {
        return Err(format!("{field} must not contain surrounding whitespace"));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{field} must not contain control characters"));
    }
    if !value.starts_with('/') {
        return Err(format!("{field} must be an absolute container path"));
    }

    let segments = value.split('/').skip(1).collect::<Vec<_>>();
    let has_internal_empty_segment = segments
        .iter()
        .take(segments.len().saturating_sub(1))
        .any(|segment| segment.is_empty());
    if has_internal_empty_segment || segments.contains(&".") || segments.contains(&"..") {
        return Err(format!(
            "{field} must be normalized without empty, '.', or '..' path segments"
        ));
    }

    let normalized = value.trim_end_matches('/');
    if normalized.is_empty() {
        return Err(format!("{field} must not be the container root"));
    }
    Ok(normalized.to_string())
}

/// Reject a workspace that contains or is contained by an `OpenShell` control
/// path. Drivers use this for runtime-configured paths such as the SSH socket.
pub fn validate_workspace_control_path(
    workspace_root: &str,
    control_path: &str,
) -> Result<(), String> {
    validate_workspace_reserved_path(workspace_root, control_path, "OpenShell control path")
}

fn validate_workspace_reserved_path(
    workspace_root: &str,
    reserved_path: &str,
    description: &str,
) -> Result<(), String> {
    let normalized_workspace = normalize_absolute_container_path(workspace_root, "OCI WorkingDir")?;
    let normalized_reserved = normalize_absolute_container_path(reserved_path, description)?;
    let workspace = Path::new(&normalized_workspace);
    let reserved = Path::new(&normalized_reserved);
    if paths_overlap(workspace, reserved) {
        return Err(format!(
            "OCI WorkingDir '{workspace_root}' conflicts with {description} '{reserved_path}'"
        ));
    }
    Ok(())
}

/// Reject a mount that contains or is contained by a runtime-configured
/// `OpenShell` control path, such as the sandbox SSH socket.
pub fn validate_mount_control_path(target: &str, control_path: &str) -> Result<(), String> {
    let normalized_target = normalize_absolute_container_path(target, "mount target")?;
    let normalized_control =
        normalize_absolute_container_path(control_path, "OpenShell control path")?;
    if paths_overlap(
        Path::new(&normalized_target),
        Path::new(&normalized_control),
    ) {
        return Err(format!(
            "mount target '{target}' conflicts with OpenShell control path '{control_path}'"
        ));
    }
    Ok(())
}

/// Reject a user-supplied mount that would replace or contain the resolved
/// workspace root. Mounts below the workspace remain valid.
pub fn validate_workspace_mount_target(target: &str, workspace_root: &str) -> Result<(), String> {
    let normalized_target = normalize_mount_target(target);
    if path_is_or_under(Path::new(workspace_root), Path::new(&normalized_target)) {
        return Err(format!(
            "mount target '{target}' is reserved for the OpenShell workspace"
        ));
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

fn paths_overlap(left: &Path, right: &Path) -> bool {
    path_is_or_under(left, right) || path_is_or_under(right, left)
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
    fn container_target_workspace_reservation_is_dynamic() {
        validate_container_mount_target("/sandbox/").unwrap();
        validate_workspace_mount_target("/sandbox/", "/sandbox").unwrap_err();
        validate_workspace_mount_target("/workspace/", "/sandbox").unwrap();
        validate_workspace_mount_target("/workspace/cache", "/workspace").unwrap();
        validate_workspace_mount_target("/workspace", "/workspace/project").unwrap_err();
        validate_workspace_mount_target("/workspace-other", "/workspace/project").unwrap();
    }

    #[test]
    fn oci_workspace_root_uses_fallback_and_accepts_normalized_absolute_paths() {
        assert_eq!(resolve_oci_workspace_root("").unwrap(), "/sandbox");
        assert_eq!(resolve_oci_workspace_root("/").unwrap(), "/sandbox");
        assert_eq!(
            resolve_oci_workspace_root("/workspace/project/").unwrap(),
            "/workspace/project"
        );
        assert_eq!(
            resolve_oci_workspace_root("/workspace with spaces").unwrap(),
            "/workspace with spaces"
        );
    }

    #[test]
    fn oci_workspace_root_rejects_relative_and_malformed_paths() {
        for invalid in [
            "workspace",
            "./workspace",
            "/workspace/../etc",
            "/workspace/./project",
            "/workspace//project",
            "/workspace\0project",
            "/workspace ",
            "/workspace\nproject",
        ] {
            assert!(
                resolve_oci_workspace_root(invalid).is_err(),
                "expected '{invalid}' to be rejected"
            );
        }
    }

    #[test]
    fn oci_workspace_root_rejects_runtime_and_openshell_control_path_collisions() {
        for invalid in [
            "/proc",
            "/proc/self",
            "/sys",
            "/sys/fs/cgroup",
            "/dev",
            "/dev/shm",
            "/etc",
            "/opt",
            "/opt/openshell",
            "/opt/openshell/bin/project",
            "/etc/openshell/tls/client",
            "/etc/openshell/auth",
            "/etc/openshell/skills",
            "/etc/openshell-tls",
            "/run",
            "/run/openshell/cache",
            "/run/openshell-sidecar/control.sock",
            "/run/netns/project",
            "/var/run/netns/project",
        ] {
            assert!(
                resolve_oci_workspace_root(invalid).is_err(),
                "expected control-path workspace '{invalid}' to be rejected"
            );
        }

        for valid in [
            "/app",
            "/etc/project",
            "/home/app",
            "/opt/app",
            "/usr/bin/project",
            "/usr/src/app",
            "/var/lib/app",
            "/var/app/current",
            "/var/task",
            "/var/www/app",
            "/processor",
            "/system",
            "/device",
        ] {
            assert_eq!(
                resolve_oci_workspace_root(valid).unwrap(),
                valid,
                "expected application workspace '{valid}' to remain valid"
            );
        }
    }

    #[test]
    fn container_target_rejects_reserved_openshell_tls_legacy_path() {
        let err = validate_container_mount_target("/etc/openshell-tls/proxy/client").unwrap_err();

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
        validate_container_mount_target("/run/openshell-tools").unwrap();
    }

    #[test]
    fn mount_target_rejects_runtime_configured_control_path_overlap() {
        for target in ["/custom", "/custom/ssh.sock", "/custom/ssh.sock/cache"] {
            assert!(
                validate_mount_control_path(target, "/custom/ssh.sock").is_err(),
                "expected '{target}' to conflict with the configured control path"
            );
        }
        validate_mount_control_path("/custom-other", "/custom/ssh.sock").unwrap();
    }

    #[test]
    fn workspace_rejects_malformed_runtime_control_paths() {
        for control_path in [
            "workspace/ssh.sock",
            "/workspace/../run/ssh.sock",
            "/workspace//ssh.sock",
            "",
        ] {
            assert!(
                validate_workspace_control_path("/workspace", control_path).is_err(),
                "expected malformed control path '{control_path}' to be rejected"
            );
        }
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
    #[test]
    fn mount_target_rejects_internal_empty_or_dot_segments() {
        assert_eq!(
            validate_container_mount_target("/sandbox/work//tmp").unwrap_err(),
            "mount target must be normalized without empty, '.', or '..' path segments"
        );
        assert_eq!(
            validate_container_mount_target("/sandbox/work/./tmp").unwrap_err(),
            "mount target must be normalized without empty, '.', or '..' path segments"
        );
        assert_eq!(
            validate_container_mount_target("/sandbox/work/../../tmp").unwrap_err(),
            "mount target must be normalized without empty, '.', or '..' path segments"
        );
        validate_container_mount_target("/sandbox/work/").unwrap();
    }
}
