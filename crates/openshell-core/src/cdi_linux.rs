// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Linux implementation of CDI policy resolution.

use super::{CDI_CONTEXT_VERSION, CdiContext, CdiDerivedRequirements, CdiError, CdiSpecDirectory};
use crate::paths::normalize_path;
use container_device_interface::{
    cache::{Cache, with_auto_refresh},
    container_edits::ContainerEdits as UpstreamContainerEdits,
    spec_dirs::with_spec_dirs,
};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;
use std::hash::BuildHasher;
use std::os::unix::fs::FileTypeExt;
use std::path::{Component, Path};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CdiPathKind {
    File,
    Directory,
    CharacterDevice,
    BlockDevice,
    Other,
}

impl fmt::Display for CdiPathKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File => f.write_str("file"),
            Self::Directory => f.write_str("directory"),
            Self::CharacterDevice => f.write_str("character device"),
            Self::BlockDevice => f.write_str("block device"),
            Self::Other => f.write_str("other"),
        }
    }
}

// Temporary view over upstream-resolved CDI edits. The Rust CDI crate currently
// keeps some spec-model fields crate-private even though they are serialized and
// public in specs-go, so OpenShell serializes the merged upstream model and
// decodes only the policy-relevant fields here.
#[derive(Debug, Default, Deserialize)]
struct CdiContainerEdits {
    #[serde(default, rename = "deviceNodes")]
    device_nodes: Vec<CdiDeviceNode>,
    #[serde(default)]
    mounts: Vec<CdiMount>,
    #[serde(default, rename = "additionalGids")]
    additional_gids: Vec<u32>,
}

#[derive(Debug, Deserialize)]
struct CdiDeviceNode {
    path: String,
}

#[derive(Debug, Deserialize)]
struct CdiMount {
    #[serde(rename = "containerPath")]
    container_path: String,
    #[serde(default)]
    options: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CdiAccess {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Default)]
struct RequirementAccumulator {
    device_node_paths: BTreeSet<String>,
    mount_paths: BTreeMap<String, CdiAccess>,
    additional_gids: BTreeSet<u32>,
}

impl RequirementAccumulator {
    fn add_device_node<F>(&mut self, path: String, path_kind: &F) -> Result<(), CdiError>
    where
        F: Fn(&str) -> Option<CdiPathKind>,
    {
        let kind = path_kind(&path);
        if !matches!(
            kind,
            Some(CdiPathKind::CharacterDevice | CdiPathKind::BlockDevice)
        ) {
            return Err(CdiError::DeviceNodeNotDevice {
                path,
                kind: kind.map_or_else(|| "missing".to_string(), |kind| kind.to_string()),
            });
        }
        match self.mount_paths.get(&path).copied() {
            Some(CdiAccess::ReadOnly) => Err(CdiError::ConflictingAccess { path }),
            Some(CdiAccess::ReadWrite) | None => {
                self.device_node_paths.insert(path);
                Ok(())
            }
        }
    }

    fn add_mount(&mut self, path: String, access: CdiAccess) -> Result<(), CdiError> {
        if access == CdiAccess::ReadOnly && self.device_node_paths.contains(&path) {
            return Err(CdiError::ConflictingAccess { path });
        }
        match self.mount_paths.get(&path).copied() {
            Some(existing) if existing != access => Err(CdiError::ConflictingAccess { path }),
            Some(_) => Ok(()),
            None => {
                self.mount_paths.insert(path, access);
                Ok(())
            }
        }
    }

    fn add_gid(&mut self, gid: u32) {
        if gid == 0 {
            tracing::debug!("Skipping CDI additionalGids entry for root GID 0");
            return;
        }
        self.additional_gids.insert(gid);
    }

    fn validate_writable_mounts<F>(
        &self,
        normalized_writable_file_allowlist: &HashSet<String>,
        path_kind: &F,
    ) -> Result<(), CdiError>
    where
        F: Fn(&str) -> Option<CdiPathKind>,
    {
        for (path, access) in &self.mount_paths {
            if *access != CdiAccess::ReadWrite {
                continue;
            }
            if !normalized_writable_file_allowlist.contains(path) {
                return Err(CdiError::WritableMountNotAllowed { path: path.clone() });
            }
            let kind = path_kind(path);
            if kind != Some(CdiPathKind::File) {
                return Err(CdiError::WritableMountNotFile {
                    path: path.clone(),
                    kind: kind.map_or_else(|| "missing".to_string(), |kind| kind.to_string()),
                });
            }
        }
        Ok(())
    }

    fn build(self) -> CdiDerivedRequirements {
        let mut read_only_mount_paths = Vec::new();
        let mut read_write_mount_paths = Vec::new();
        for (path, access) in self.mount_paths {
            match access {
                CdiAccess::ReadOnly => read_only_mount_paths.push(path),
                CdiAccess::ReadWrite => read_write_mount_paths.push(path),
            }
        }
        CdiDerivedRequirements {
            device_node_paths: self.device_node_paths.into_iter().collect(),
            read_only_mount_paths,
            read_write_mount_paths,
            additional_gids: self.additional_gids.into_iter().collect(),
        }
    }
}

pub fn resolve_cdi_context<S: BuildHasher>(
    context: &CdiContext,
    writable_file_allowlist: &HashSet<String, S>,
) -> Result<CdiDerivedRequirements, CdiError> {
    resolve_cdi_context_with_path_kind(context, writable_file_allowlist, filesystem_path_kind)
}

fn resolve_cdi_context_with_path_kind<F, S>(
    context: &CdiContext,
    writable_file_allowlist: &HashSet<String, S>,
    path_kind: F,
) -> Result<CdiDerivedRequirements, CdiError>
where
    F: Fn(&str) -> Option<CdiPathKind>,
    S: BuildHasher,
{
    validate_context(context)?;
    let selected_devices = selected_cdi_devices(&context.selected_devices);
    if selected_devices.is_empty() || context.spec_dirs.is_empty() {
        return Ok(CdiDerivedRequirements::default());
    }

    let normalized_allowlist = writable_file_allowlist
        .iter()
        .map(|path| normalize_path(path))
        .collect::<HashSet<_>>();

    let edits = resolve_container_edits(context, &selected_devices)?;
    let mut accumulator = RequirementAccumulator::default();
    accumulate_requirements(&edits, &normalized_allowlist, &path_kind, &mut accumulator)?;
    Ok(accumulator.build())
}

fn validate_context(context: &CdiContext) -> Result<(), CdiError> {
    if context.version != CDI_CONTEXT_VERSION {
        return Err(CdiError::UnsupportedContextVersion(context.version));
    }
    for spec_dir in &context.spec_dirs {
        validate_absolute_no_parent(&spec_dir.path).map_err(|reason| CdiError::UnsafeSpecDir {
            path: spec_dir.path.clone(),
            diagnostic_source: spec_dir.source.clone(),
            reason,
        })?;
    }
    Ok(())
}

fn selected_cdi_devices(device_ids: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut parsed = Vec::new();
    for raw in device_ids {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        if seen.insert(raw.to_string()) {
            parsed.push(raw.to_string());
        }
    }
    parsed
}

fn resolve_container_edits(
    context: &CdiContext,
    selected_devices: &[String],
) -> Result<CdiContainerEdits, CdiError> {
    let (mut cache, refresh_error) = build_cache(&context.spec_dirs);
    let mut merged = UpstreamContainerEdits::new();
    let mut applied_specs = BTreeSet::new();

    for device_id in selected_devices {
        let device = cache
            .get_device(device_id)
            .cloned()
            .ok_or_else(|| missing_device_error(device_id, refresh_error.as_deref()))?;
        let mut spec = device.get_spec();
        let spec_path = spec.get_path();
        if applied_specs.insert(spec_path)
            && let Some(spec_edits) = spec.edits()
        {
            merged
                .append(spec_edits)
                .map_err(|err| CdiError::EditMerge {
                    device: device_id.clone(),
                    error: err.to_string(),
                })?;
        }
        merged
            .append(device.edits())
            .map_err(|err| CdiError::EditMerge {
                device: device_id.clone(),
                error: err.to_string(),
            })?;
    }

    let value = serde_json::to_value(&merged.container_edits)
        .map_err(|source| CdiError::EditEncode { source })?;
    serde_json::from_value(value).map_err(|source| CdiError::EditDecode { source })
}

fn missing_device_error(device: &str, refresh_error: Option<&str>) -> CdiError {
    refresh_error.map_or_else(
        || CdiError::MissingDevice(device.to_string()),
        |refresh_error| CdiError::MissingDeviceAfterRefresh {
            device: device.to_string(),
            refresh_error: refresh_error.to_string(),
        },
    )
}

fn build_cache(spec_dirs: &[CdiSpecDirectory]) -> (Cache, Option<String>) {
    let spec_dir_paths = spec_dirs
        .iter()
        .map(|spec_dir| spec_dir.path.as_str())
        .collect::<Vec<_>>();
    let mut cache = Cache::default();
    cache.configure(vec![
        with_spec_dirs(&spec_dir_paths),
        with_auto_refresh(false),
    ]);
    let refresh_error = cache.refresh().err().map(|err| {
        tracing::debug!(
            error = %err,
            "Ignoring CDI cache refresh error; requested device lookup will determine availability"
        );
        err.to_string()
    });
    (cache, refresh_error)
}

fn accumulate_requirements<F>(
    edits: &CdiContainerEdits,
    normalized_writable_file_allowlist: &HashSet<String>,
    path_kind: &F,
    accumulator: &mut RequirementAccumulator,
) -> Result<(), CdiError>
where
    F: Fn(&str) -> Option<CdiPathKind>,
{
    for device_node in &edits.device_nodes {
        let path = normalize_policy_path(&device_node.path)?;
        accumulator.add_device_node(path, path_kind)?;
    }

    for mount in &edits.mounts {
        let path = normalize_policy_path(&mount.container_path)?;
        let access = mount_access(&path, &mount.options)?;
        accumulator.add_mount(path, access)?;
    }

    for gid in &edits.additional_gids {
        accumulator.add_gid(*gid);
    }

    accumulator.validate_writable_mounts(normalized_writable_file_allowlist, path_kind)?;
    Ok(())
}

fn mount_access(path: &str, options: &[String]) -> Result<CdiAccess, CdiError> {
    let read_only_requested = options
        .iter()
        .any(|option| option.eq_ignore_ascii_case("ro"));
    let read_write_requested = options
        .iter()
        .any(|option| option.eq_ignore_ascii_case("rw"));
    // CDI mount options are stringly typed and runtime-specific normalization
    // can differ. Treat simultaneous ro/rw as malformed instead of guessing
    // which option a later mount syscall would effectively apply.
    if read_only_requested && read_write_requested {
        return Err(CdiError::ConflictingMountOptions {
            path: path.to_string(),
        });
    }
    if read_write_requested {
        Ok(CdiAccess::ReadWrite)
    } else {
        Ok(CdiAccess::ReadOnly)
    }
}

fn normalize_policy_path(path: &str) -> Result<String, CdiError> {
    validate_absolute_no_parent(path).map_err(|reason| CdiError::UnsafePolicyPath {
        path: path.to_string(),
        reason,
    })?;
    let normalized = normalize_path(path);
    if matches!(
        normalized.as_str(),
        "/" | "/dev" | "/proc" | "/sys" | "/run" | "/usr"
    ) {
        return Err(CdiError::UnsafePolicyPath {
            path: path.to_string(),
            reason: "broad root path is not allowed",
        });
    }
    Ok(normalized)
}

fn validate_absolute_no_parent(path: &str) -> Result<(), &'static str> {
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err("path must be absolute");
    }
    for component in path.components() {
        match component {
            Component::ParentDir => return Err("path must not contain '..'"),
            Component::Prefix(_) => return Err("path must be a Unix-style absolute path"),
            Component::CurDir => return Err("path must be normalized"),
            Component::RootDir | Component::Normal(_) => {}
        }
    }
    Ok(())
}

fn filesystem_path_kind(path: &str) -> Option<CdiPathKind> {
    let metadata = std::fs::metadata(path).ok()?;
    let file_type = metadata.file_type();
    if file_type.is_char_device() {
        return Some(CdiPathKind::CharacterDevice);
    }
    if file_type.is_block_device() {
        return Some(CdiPathKind::BlockDevice);
    }
    if file_type.is_file() {
        Some(CdiPathKind::File)
    } else if file_type.is_dir() {
        Some(CdiPathKind::Directory)
    } else {
        Some(CdiPathKind::Other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_spec(dir: &Path, name: &str, yaml: &str) {
        std::fs::write(dir.join(name), yaml).unwrap();
    }

    fn context(dir: &Path, selected_devices: &[&str]) -> CdiContext {
        CdiContext::new(
            selected_devices
                .iter()
                .map(|device| (*device).to_string())
                .collect(),
            vec![CdiSpecDirectory::new(
                dir.to_string_lossy().into_owned(),
                "/host/cdi",
            )],
        )
    }

    fn resolve_with_kind(
        context: &CdiContext,
        writable: &[&str],
        kind: impl Fn(&str) -> Option<CdiPathKind>,
    ) -> Result<CdiDerivedRequirements, CdiError> {
        let writable_file_allowlist: HashSet<String> =
            writable.iter().map(|path| (*path).to_string()).collect();
        resolve_cdi_context_with_path_kind(context, &writable_file_allowlist, kind)
    }

    fn always_missing(_: &str) -> Option<CdiPathKind> {
        None
    }

    fn fake_device_node(path: &str) -> Option<CdiPathKind> {
        path.starts_with("/dev/")
            .then_some(CdiPathKind::CharacterDevice)
    }

    #[test]
    fn resolves_native_single_device_requirements() {
        let dir = tempfile::tempdir().unwrap();
        write_spec(
            dir.path(),
            "nvidia.yaml",
            r#"
cdiVersion: 0.6.0
kind: nvidia.com/gpu
devices:
  - name: "0"
    containerEdits:
      deviceNodes:
        - path: /dev/nvidiactl
        - path: /dev/nvidia0
      mounts:
        - hostPath: /host/libcuda.so.1
          containerPath: /usr/local/cuda/lib64/libcuda.so.1
"#,
        );

        let requirements = resolve_with_kind(
            &context(dir.path(), &["nvidia.com/gpu=0"]),
            &[],
            fake_device_node,
        )
        .unwrap();

        assert_eq!(
            requirements.device_node_paths,
            vec!["/dev/nvidia0", "/dev/nvidiactl"]
        );
        assert_eq!(
            requirements.read_only_mount_paths,
            vec!["/usr/local/cuda/lib64/libcuda.so.1"]
        );
    }

    #[test]
    fn resolves_native_all_device_requirements() {
        let dir = tempfile::tempdir().unwrap();
        write_spec(
            dir.path(),
            "nvidia.yaml",
            r"
cdiVersion: 1.1.0
kind: nvidia.com/gpu
devices:
  - name: all
    containerEdits:
      deviceNodes:
        - path: /dev/nvidiactl
        - path: /dev/nvidia0
        - path: /dev/nvidia1
",
        );

        let requirements = resolve_with_kind(
            &context(dir.path(), &["nvidia.com/gpu=all"]),
            &[],
            fake_device_node,
        )
        .unwrap();

        assert_eq!(
            requirements.device_node_paths,
            vec!["/dev/nvidia0", "/dev/nvidia1", "/dev/nvidiactl"]
        );
    }

    #[test]
    fn resolves_wsl_shape_requirements() {
        let dir = tempfile::tempdir().unwrap();
        write_spec(
            dir.path(),
            "wsl.yaml",
            r"
cdiVersion: 1.1.0
kind: nvidia.com/gpu
devices:
  - name: all
    containerEdits:
      deviceNodes:
        - path: /dev/dxg
      mounts:
        - hostPath: /host/wsl/lib/libcuda.so.1
          containerPath: /usr/lib/wsl/lib/libcuda.so.1
",
        );

        let requirements = resolve_with_kind(
            &context(dir.path(), &["nvidia.com/gpu=all"]),
            &[],
            fake_device_node,
        )
        .unwrap();

        assert_eq!(requirements.device_node_paths, vec!["/dev/dxg"]);
        assert_eq!(
            requirements.read_only_mount_paths,
            vec!["/usr/lib/wsl/lib/libcuda.so.1"]
        );
    }

    #[test]
    fn resolves_tegra_shape_requirements_and_gids() {
        let dir = tempfile::tempdir().unwrap();
        write_spec(
            dir.path(),
            "tegra.yaml",
            r#"
cdiVersion: 1.1.0
kind: nvidia.com/gpu
containerEdits:
  additionalGids: [44]
devices:
  - name: "0"
    containerEdits:
      deviceNodes:
        - path: /dev/nvmap
        - path: /dev/nvhost-gpu
"#,
        );

        let requirements = resolve_with_kind(
            &context(dir.path(), &["nvidia.com/gpu=0"]),
            &[],
            fake_device_node,
        )
        .unwrap();

        assert_eq!(requirements.additional_gids, vec![44]);
        assert_eq!(
            requirements.device_node_paths,
            vec!["/dev/nvhost-gpu", "/dev/nvmap"]
        );
    }

    #[test]
    fn accepts_writable_single_file_mount_with_explicit_policy_opt_in() {
        let dir = tempfile::tempdir().unwrap();
        write_spec(
            dir.path(),
            "rw-file.yaml",
            r#"
cdiVersion: 1.1.0
kind: nvidia.com/gpu
devices:
  - name: "0"
    containerEdits:
      mounts:
        - hostPath: /host/nvidia/cache.db
          containerPath: /opt/nvidia/cache.db
          options: [rw]
"#,
        );

        let requirements = resolve_with_kind(
            &context(dir.path(), &["nvidia.com/gpu=0"]),
            &["/opt/nvidia/cache.db"],
            |path| (path == "/opt/nvidia/cache.db").then_some(CdiPathKind::File),
        )
        .unwrap();

        assert_eq!(
            requirements.read_write_mount_paths,
            vec!["/opt/nvidia/cache.db"]
        );
    }

    #[test]
    fn rejects_writable_directory_mount() {
        let dir = tempfile::tempdir().unwrap();
        write_spec(
            dir.path(),
            "rw-dir.yaml",
            r#"
cdiVersion: 1.1.0
kind: nvidia.com/gpu
devices:
  - name: "0"
    containerEdits:
      mounts:
        - hostPath: /host/nvidia/cache
          containerPath: /opt/nvidia/cache
          options: [rw]
"#,
        );

        let err = resolve_with_kind(
            &context(dir.path(), &["nvidia.com/gpu=0"]),
            &["/opt/nvidia/cache"],
            |path| (path == "/opt/nvidia/cache").then_some(CdiPathKind::Directory),
        )
        .unwrap_err();

        assert!(matches!(err, CdiError::WritableMountNotFile { .. }));
    }

    #[test]
    fn rejects_missing_selected_device() {
        let dir = tempfile::tempdir().unwrap();
        write_spec(
            dir.path(),
            "nvidia.yaml",
            r#"
cdiVersion: 1.1.0
kind: nvidia.com/gpu
devices:
  - name: "0"
    containerEdits:
      env:
        - OPEN_SHELL_TEST=1
"#,
        );

        let err = resolve_with_kind(
            &context(dir.path(), &["nvidia.com/gpu=1"]),
            &[],
            always_missing,
        )
        .unwrap_err();

        assert!(matches!(err, CdiError::MissingDevice(device) if device == "nvidia.com/gpu=1"));
    }

    #[test]
    fn reports_refresh_errors_when_requested_device_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        write_spec(dir.path(), "broken.yaml", "kind: [");

        let err = resolve_with_kind(
            &context(dir.path(), &["nvidia.com/gpu=0"]),
            &[],
            fake_device_node,
        )
        .unwrap_err();

        assert!(
            matches!(err, CdiError::MissingDeviceAfterRefresh { device, refresh_error }
                if device == "nvidia.com/gpu=0" && !refresh_error.is_empty())
        );
    }

    #[test]
    fn empty_selection_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let requirements = resolve_with_kind(&context(dir.path(), &[]), &[], always_missing)
            .expect("empty selection should resolve to empty requirements");

        assert_eq!(requirements, CdiDerivedRequirements::default());
    }

    #[test]
    fn empty_spec_dirs_are_noop() {
        let context = CdiContext::new(vec!["nvidia.com/gpu=0".to_string()], Vec::new());

        let requirements = resolve_with_kind(&context, &[], always_missing)
            .expect("empty spec dirs should resolve to empty requirements");

        assert_eq!(requirements, CdiDerivedRequirements::default());
    }

    #[test]
    fn defers_device_id_shape_to_upstream_resolution() {
        let dir = tempfile::tempdir().unwrap();
        write_spec(
            dir.path(),
            "nvidia.yaml",
            r#"
cdiVersion: 1.1.0
kind: nvidia.com/gpu
devices:
  - name: "0"
    containerEdits:
      env:
        - OPEN_SHELL_TEST=1
"#,
        );

        let err = resolve_with_kind(&context(dir.path(), &["not-a-cdi-id"]), &[], always_missing)
            .unwrap_err();

        assert!(matches!(err, CdiError::MissingDevice(device) if device == "not-a-cdi-id"));
    }

    #[test]
    fn rejects_unsafe_policy_paths() {
        for path in [
            "relative", "/dev", "/proc", "/sys", "/run", "/usr", "/a/../b",
        ] {
            let dir = tempfile::tempdir().unwrap();
            write_spec(
                dir.path(),
                "unsafe.yaml",
                &format!(
                    r#"
cdiVersion: 1.1.0
kind: nvidia.com/gpu
devices:
  - name: "0"
    containerEdits:
      deviceNodes:
        - path: {path}
"#
                ),
            );

            let err = resolve_with_kind(
                &context(dir.path(), &["nvidia.com/gpu=0"]),
                &[],
                always_missing,
            )
            .unwrap_err();

            assert!(
                matches!(err, CdiError::UnsafePolicyPath { .. }),
                "expected unsafe path error for {path}, got {err:?}"
            );
        }
    }

    #[test]
    fn rejects_duplicate_access_conflicts() {
        let dir = tempfile::tempdir().unwrap();
        write_spec(
            dir.path(),
            "conflict.yaml",
            r#"
cdiVersion: 1.1.0
kind: nvidia.com/gpu
devices:
  - name: "0"
    containerEdits:
      deviceNodes:
        - path: /dev/nvidia0
      mounts:
        - hostPath: /host/dev/nvidia0
          containerPath: /dev/nvidia0
          options: [ro]
"#,
        );

        let err = resolve_with_kind(
            &context(dir.path(), &["nvidia.com/gpu=0"]),
            &[],
            fake_device_node,
        )
        .unwrap_err();

        assert!(matches!(err, CdiError::ConflictingAccess { .. }));
    }

    #[test]
    fn skips_root_additional_gid() {
        let dir = tempfile::tempdir().unwrap();
        write_spec(
            dir.path(),
            "root-gid.yaml",
            r#"
cdiVersion: 1.1.0
kind: nvidia.com/gpu
devices:
  - name: "0"
    containerEdits:
      additionalGids: [0, 44]
"#,
        );

        let requirements = resolve_with_kind(
            &context(dir.path(), &["nvidia.com/gpu=0"]),
            &[],
            always_missing,
        )
        .unwrap();

        assert_eq!(requirements.additional_gids, vec![44]);
    }

    #[test]
    fn rejects_device_node_that_is_not_device() {
        let dir = tempfile::tempdir().unwrap();
        write_spec(
            dir.path(),
            "regular-file-node.yaml",
            r#"
cdiVersion: 1.1.0
kind: nvidia.com/gpu
devices:
  - name: "0"
    containerEdits:
      deviceNodes:
        - path: /opt/nvidia/not-a-device
"#,
        );

        let err = resolve_with_kind(&context(dir.path(), &["nvidia.com/gpu=0"]), &[], |path| {
            (path == "/opt/nvidia/not-a-device").then_some(CdiPathKind::File)
        })
        .unwrap_err();

        assert!(matches!(err, CdiError::DeviceNodeNotDevice { .. }));
    }
}
