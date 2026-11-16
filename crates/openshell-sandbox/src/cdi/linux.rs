// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Linux implementation of CDI policy resolution.

use super::{
    CDI_CONTEXT_VERSION, CdiContext, CdiDerivedRequirements, CdiError, CdiMountRequirement,
    CdiSpecDirectory, shared_library_parent,
};
use container_device_interface::{
    cache::{Cache, with_auto_refresh},
    container_edits::ContainerEdits as UpstreamContainerEdits,
    spec_dirs::with_spec_dirs,
};
use openshell_core::paths::normalize_path;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;
use std::path::{Component, Path};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CdiPathKind {
    File,
    Directory,
    CharacterDevice,
    BlockDevice,
    Socket,
    Other,
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
    socket_paths: BTreeSet<String>,
    ipc_directory_paths: BTreeSet<String>,
    additional_gids: BTreeSet<u32>,
}

impl RequirementAccumulator {
    fn add_device_node(&mut self, path: String) -> Result<(), CdiError> {
        if self.socket_paths.contains(&path) || self.ipc_directory_paths.contains(&path) {
            return Err(CdiError::ConflictingAccess { path });
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
        if self.socket_paths.contains(&path)
            || self.ipc_directory_paths.contains(&path)
            || (access == CdiAccess::ReadOnly && self.device_node_paths.contains(&path))
        {
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

    fn add_socket(&mut self, path: String) -> Result<(), CdiError> {
        if self.device_node_paths.contains(&path)
            || self.mount_paths.contains_key(&path)
            || self.ipc_directory_paths.contains(&path)
        {
            return Err(CdiError::ConflictingAccess { path });
        }
        self.socket_paths.insert(path);
        Ok(())
    }

    fn add_ipc_directory(&mut self, path: String) -> Result<(), CdiError> {
        if self.device_node_paths.contains(&path)
            || self.mount_paths.contains_key(&path)
            || self.socket_paths.contains(&path)
        {
            return Err(CdiError::ConflictingAccess { path });
        }
        self.ipc_directory_paths.insert(path);
        Ok(())
    }

    fn add_gid(&mut self, gid: u32) -> Result<(), CdiError> {
        if gid == 0 {
            return Err(CdiError::RootAdditionalGid);
        }
        self.additional_gids.insert(gid);
        Ok(())
    }

    fn build(self) -> Result<CdiDerivedRequirements, CdiError> {
        let mut read_only_paths = BTreeSet::new();
        let mut read_write_mount_paths = Vec::new();
        let mut mounts = Vec::new();
        for (path, access) in self.mount_paths {
            mounts.push(CdiMountRequirement {
                path: path.clone(),
                read_only: access == CdiAccess::ReadOnly,
            });
            match access {
                CdiAccess::ReadOnly => {
                    let expanded = shared_library_parent(&path).unwrap_or(path);
                    read_only_paths.insert(normalize_policy_path(&expanded)?);
                }
                CdiAccess::ReadWrite => read_write_mount_paths.push(path),
            }
        }
        Ok(CdiDerivedRequirements {
            device_node_paths: self.device_node_paths.into_iter().collect(),
            socket_paths: self.socket_paths.into_iter().collect(),
            read_only_paths: read_only_paths.into_iter().collect(),
            read_write_mount_paths,
            ipc_directory_paths: self.ipc_directory_paths.into_iter().collect(),
            additional_gids: self.additional_gids.into_iter().collect(),
            mounts,
        })
    }
}

/// Facts observed in the workload namespace, independent of spec mount options.
#[derive(Debug, Clone, Copy)]
struct CdiMountState {
    kind: CdiPathKind,
    access: CdiAccess,
}

pub fn resolve_cdi_context(context: &CdiContext) -> Result<CdiDerivedRequirements, CdiError> {
    let mut table = None;
    resolve_cdi_context_with_mount_inspector(context, |path| inspect_cdi_mount(path, &mut table))
}

/// Use the production resolver with injectable workload mount observations.
/// Only the OS inspection is replaced in hardware-fixture tests.
fn resolve_cdi_context_with_mount_inspector(
    context: &CdiContext,
    mut inspect_mount: impl FnMut(&str) -> Result<CdiMountState, CdiError>,
) -> Result<CdiDerivedRequirements, CdiError> {
    validate_context(context)?;
    let selected_devices = selected_cdi_devices(&context.selected_devices);
    if selected_devices.is_empty() || context.spec_dirs.is_empty() {
        return Ok(CdiDerivedRequirements::default());
    }
    let edits = resolve_container_edits(context, &selected_devices)?;
    let mut accumulator = RequirementAccumulator::default();
    for node in &edits.device_nodes {
        accumulator.add_device_node(normalize_policy_path(&node.path)?)?;
    }
    for mount in &edits.mounts {
        let path = normalize_policy_path(&mount.container_path)?;
        validate_mount_options(&path, &mount.options)?;
        let state = inspect_mount(&path)?;
        if state.kind == CdiPathKind::Socket {
            accumulator.add_socket(path)?;
        } else if is_ipc_directory(&path, state) {
            validate_ipc_directory_options(&path, &mount.options)?;
            accumulator.add_ipc_directory(path)?;
        } else {
            accumulator.add_mount(path, state.access)?;
        }
    }
    for gid in &edits.additional_gids {
        accumulator.add_gid(*gid)?;
    }
    accumulator.build()
}

/// A workload-local mount snapshot, reused for all original directory mounts.
/// Expanded shared-library parents are not inspected as original mounts.
pub struct CdiMountTable {
    mounts: Vec<(std::path::PathBuf, bool)>,
}

/// Decode the octal escapes mountinfo uses for space, tab, newline and
/// backslash in a single pass, so an escaped backslash is never re-decoded.
fn decode_mountinfo_path(field: &str) -> String {
    let mut decoded = String::with_capacity(field.len());
    let mut rest = field;
    while let Some(index) = rest.find('\\') {
        decoded.push_str(&rest[..index]);
        let escape = rest.get(index + 1..index + 4);
        match escape {
            Some("040") => decoded.push(' '),
            Some("011") => decoded.push('\t'),
            Some("012") => decoded.push('\n'),
            Some("134") => decoded.push('\\'),
            _ => {
                decoded.push('\\');
                rest = &rest[index + 1..];
                continue;
            }
        }
        rest = &rest[index + 4..];
    }
    decoded.push_str(rest);
    decoded
}

impl CdiMountTable {
    pub fn read() -> Result<Self, CdiError> {
        let text = std::fs::read_to_string("/proc/self/mountinfo")
            .map_err(|error| mount_inspection("/proc/self/mountinfo", error))?;
        Self::parse(&text)
    }

    fn parse(text: &str) -> Result<Self, CdiError> {
        let mut mounts = Vec::new();
        for line in text.lines() {
            // The mount source may be empty, so split on the separator rather
            // than counting whitespace-delimited fields. Paths are escaped and
            // never contain a literal " - ".
            let malformed = || mount_inspection("/proc/self/mountinfo", "malformed mount record");
            let (head, tail) = line.split_once(" - ").ok_or_else(malformed)?;
            let fields = head.split(' ').collect::<Vec<_>>();
            let tail = tail.split(' ').collect::<Vec<_>>();
            if fields.len() < 6 || tail.len() != 3 || fields[..6].iter().any(|f| f.is_empty()) {
                return Err(malformed());
            }
            let path = decode_mountinfo_path(fields[4]);
            if !Path::new(&path).is_absolute() {
                return Err(mount_inspection(
                    "/proc/self/mountinfo",
                    "relative mount point",
                ));
            }
            let read_only = fields[5].split(',').any(|option| option == "ro")
                || tail[2].split(',').any(|option| option == "ro");
            if !read_only && !fields[5].split(',').any(|option| option == "rw") {
                return Err(mount_inspection(
                    "/proc/self/mountinfo",
                    "missing mount access flags",
                ));
            }
            mounts.push((path.into(), read_only));
        }
        if mounts.is_empty() {
            return Err(mount_inspection(
                "/proc/self/mountinfo",
                "empty mount table",
            ));
        }
        Ok(Self { mounts })
    }

    /// Inspect the same object descriptor that will anchor a Landlock rule.
    pub fn read_only<F: std::os::fd::AsFd>(&self, path: &str, fd: &F) -> Result<bool, CdiError> {
        use rustix::fs::{FileType, StatVfsMountFlags, fstat, fstatvfs};
        use std::os::fd::AsRawFd;
        let flags = fstatvfs(fd).map_err(|error| mount_inspection(path, error))?;
        if !flags.f_flag.contains(StatVfsMountFlags::RDONLY) {
            return Ok(false);
        }
        let stat = fstat(fd).map_err(|error| mount_inspection(path, error))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
            return Ok(true);
        }
        let resolved = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_fd().as_raw_fd()))
            .map_err(|error| mount_inspection(path, error))?;
        if resolved
            .as_os_str()
            .as_encoded_bytes()
            .ends_with(b" (deleted)")
        {
            return Err(mount_inspection(path, "directory was removed"));
        }
        Ok(!self.mounts.iter().any(|(mount, read_only)| {
            mount != &resolved && mount.starts_with(&resolved) && !read_only
        }))
    }
}

fn mount_inspection(path: &str, error: impl fmt::Display) -> CdiError {
    CdiError::MountInspection {
        path: path.into(),
        error: error.to_string(),
    }
}

fn inspect_cdi_mount(
    path: &str,
    table: &mut Option<CdiMountTable>,
) -> Result<CdiMountState, CdiError> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| mount_inspection(path, error))?;
    let stat = rustix::fs::fstat(&fd).map_err(|error| mount_inspection(path, error))?;
    let kind = match rustix::fs::FileType::from_raw_mode(stat.st_mode) {
        rustix::fs::FileType::RegularFile => CdiPathKind::File,
        rustix::fs::FileType::Directory => CdiPathKind::Directory,
        rustix::fs::FileType::CharacterDevice => CdiPathKind::CharacterDevice,
        rustix::fs::FileType::BlockDevice => CdiPathKind::BlockDevice,
        rustix::fs::FileType::Socket => CdiPathKind::Socket,
        _ => CdiPathKind::Other,
    };
    // Sockets are exact validation targets, without filesystem-access grants.
    let access = if kind == CdiPathKind::Socket {
        CdiAccess::ReadOnly
    } else {
        if table.is_none() {
            *table = Some(CdiMountTable::read()?);
        }
        if table
            .as_ref()
            .expect("mount table initialized")
            .read_only(path, &fd)?
        {
            CdiAccess::ReadOnly
        } else {
            CdiAccess::ReadWrite
        }
    };
    Ok(CdiMountState { kind, access })
}

/// Ordinary writable CDI mounts need dedicated host-write authorization, which
/// is not currently supported. Authored filesystem grants cannot authorize them.
pub fn validate_cdi_requirements(requirements: &CdiDerivedRequirements) -> Result<(), CdiError> {
    if let Some(path) = requirements.read_write_mount_paths.first() {
        return Err(CdiError::WritableMountNotAllowed { path: path.clone() });
    }
    Ok(())
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

/// A writable directory at a known IPC destination is an IPC directory rather
/// than an ordinary writable mount. Read-only mounts there stay ordinary.
fn is_ipc_directory(path: &str, state: CdiMountState) -> bool {
    state.kind == CdiPathKind::Directory
        && state.access == CdiAccess::ReadWrite
        && super::CDI_IPC_DIRECTORIES.contains(&path)
}

fn validate_ipc_directory_options(path: &str, options: &[String]) -> Result<(), CdiError> {
    let complete = super::CDI_IPC_DIRECTORY_MOUNT_OPTIONS
        .iter()
        .all(|required| {
            options
                .iter()
                .any(|option| option.eq_ignore_ascii_case(required))
        });
    if complete {
        Ok(())
    } else {
        Err(CdiError::UnsafeIpcDirectory {
            path: path.to_string(),
        })
    }
}

fn validate_mount_options(path: &str, options: &[String]) -> Result<(), CdiError> {
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
    Ok(())
}

fn normalize_policy_path(path: &str) -> Result<String, CdiError> {
    validate_absolute_no_parent(path).map_err(|reason| CdiError::UnsafePolicyPath {
        path: path.to_string(),
        reason,
    })?;
    let normalized = normalize_path(path);
    if super::FORBIDDEN_CDI_ROOTS.contains(&normalized.as_str()) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_resolution_keeps_socket_destinations_exact_without_file_grants() {
        let directory = tempfile::tempdir().unwrap();
        let specs = directory.path().join("specs");
        std::fs::create_dir(&specs).unwrap();
        for name in [
            "persistenced/socket",
            "fabricmanager/socket",
            "libdaemon.so.1",
        ] {
            let target = directory.path().join(name);
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            let _listener = std::os::unix::net::UnixListener::bind(&target).unwrap();
            for options in ["[]", "[ro, bind]", "[rw, rbind]"] {
                write_spec(
                    &specs,
                    "socket.yaml",
                    &format!(
                        "cdiVersion: 0.7.0\nkind: example.com/device\ndevices:\n  - name: test\n    containerEdits:\n      mounts:\n        - hostPath: /host/socket\n          containerPath: {}\n          options: {}\n",
                        target.display(),
                        options,
                    ),
                );
                let requirements =
                    resolve_cdi_context(&context(&specs, &["example.com/device=test"])).unwrap();
                assert_eq!(requirements.socket_paths, vec![target.to_string_lossy()]);
                assert!(requirements.read_only_paths.is_empty());
                assert!(requirements.read_write_mount_paths.is_empty());
                assert!(requirements.mounts.is_empty());
                validate_cdi_requirements(&requirements).unwrap();
            }
        }
    }

    #[test]
    fn runtime_resolution_classifies_a_mount_without_access_options() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("runtime.json");
        std::fs::write(&target, "{}").unwrap();
        let specs = directory.path().join("specs");
        std::fs::create_dir(&specs).unwrap();
        write_spec(
            &specs,
            "runtime.yaml",
            &format!(
                "cdiVersion: 0.7.0\nkind: example.com/device\ndevices:\n  - name: test\n    containerEdits:\n      mounts:\n        - hostPath: /host/runtime.json\n          containerPath: {}\n",
                target.display()
            ),
        );
        let requirements =
            resolve_cdi_context(&context(&specs, &["example.com/device=test"])).unwrap();
        assert_eq!(
            requirements.read_write_mount_paths,
            vec![target.to_string_lossy()]
        );
        assert!(requirements.read_only_paths.is_empty());
    }

    #[test]
    fn effective_mount_flags_override_omitted_bind_and_ro_options() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("runtime.json");
        std::fs::write(&target, "{}").unwrap();
        for options in [vec![], vec!["bind"], vec!["rbind"], vec!["ro"]] {
            let path = target.to_string_lossy().into_owned();
            let requirements =
                resolve_cdi_context(&runtime_mount_context(directory.path(), &path, &options))
                    .unwrap();
            assert_eq!(requirements.read_write_mount_paths, vec![path.clone()]);
            assert!(requirements.read_only_paths.is_empty());
            assert!(matches!(
                validate_cdi_requirements(&requirements),
                Err(CdiError::WritableMountNotAllowed { .. })
            ));
        }
    }

    #[test]
    #[ignore = "requires a Linux container with read-only sysfs"]
    fn effective_read_only_mount_needs_no_explicit_ro_option() {
        let path = "/sys/kernel/uevent_seqnum";
        let directory = tempfile::tempdir().unwrap();
        let requirements =
            resolve_cdi_context(&runtime_mount_context(directory.path(), path, &[])).unwrap();
        assert_eq!(requirements.read_only_paths, vec![path]);
        assert!(requirements.read_write_mount_paths.is_empty());
    }

    #[test]
    fn mount_table_accepts_empty_sources_and_optional_fields() {
        let table = CdiMountTable::parse(concat!(
            "1 0 0:1 / / rw shared:1 master:2 - overlay overlay rw,lowerdir=/l\n",
            "2 1 0:2 / /usr/lib/x86_64-linux-gnu/libcuda.so.1 ro,nosuid - ext4  rw\n",
            "3 1 0:3 / /run/nvidia\\040dir rw - tmpfs tmpfs ro\n",
            "4 1 0:4 / /odd\\134040 rw - tmpfs tmpfs rw\n",
        ))
        .unwrap();
        assert_eq!(
            table.mounts,
            vec![
                ("/".into(), false),
                ("/usr/lib/x86_64-linux-gnu/libcuda.so.1".into(), true),
                ("/run/nvidia dir".into(), true),
                ("/odd\\040".into(), false),
            ]
        );
    }

    #[test]
    fn mount_table_rejects_malformed_records() {
        for text in [
            "",
            "malformed",
            "1 0 0:1 / / rw overlay overlay rw",
            "1 0 0:1 / / rw - overlay overlay",
            "1 0 0:1 / relative rw - tmpfs tmpfs rw",
            "1 0 0:1 / / nosuid - tmpfs tmpfs nosuid",
        ] {
            assert!(CdiMountTable::parse(text).is_err(), "{text:?}");
        }
    }

    #[test]
    #[ignore = "requires a Linux container with read-only sysfs"]
    fn original_directory_mounts_reject_writable_descendants_and_resolve_aliases() {
        let directory = tempfile::tempdir().unwrap();
        let alias = directory.path().join("alias");
        std::os::unix::fs::symlink("/sys/kernel", &alias).unwrap();
        let fd =
            rustix::fs::open(&alias, rustix::fs::OFlags::PATH, rustix::fs::Mode::empty()).unwrap();
        let table = CdiMountTable::parse(
            "1 0 0:1 / /sys ro - sysfs sysfs ro\n2 1 0:2 / /sys/kernel/debug rw - tmpfs tmpfs rw\n",
        )
        .unwrap();
        assert!(!table.read_only(alias.to_str().unwrap(), &fd).unwrap());
        let table = CdiMountTable::parse("1 0 0:1 / /sys ro - sysfs sysfs ro\n2 1 0:2 / /sys/kernel/debug ro - tmpfs tmpfs ro\n3 0 0:3 / /sys/kernel-other rw - tmpfs tmpfs rw\n").unwrap();
        assert!(table.read_only(alias.to_str().unwrap(), &fd).unwrap());
        assert!(CdiMountTable::parse("malformed").is_err());
        assert!(CdiMountTable::parse("").is_err());
    }

    #[test]
    fn effective_writable_directory_is_rejected_and_missing_mount_fails() {
        let directory = tempfile::tempdir().unwrap();
        for path in [
            directory.path().to_string_lossy().into_owned(),
            directory
                .path()
                .join("missing")
                .to_string_lossy()
                .into_owned(),
        ] {
            let context = runtime_mount_context(directory.path(), &path, &["ro"]);
            if Path::new(&path).exists() {
                let requirements = resolve_cdi_context(&context).unwrap();
                assert!(matches!(
                    validate_cdi_requirements(&requirements),
                    Err(CdiError::WritableMountNotAllowed { .. })
                ));
            } else {
                assert!(matches!(
                    resolve_cdi_context(&context),
                    Err(CdiError::MountInspection { .. })
                ));
            }
        }
    }

    /// Options the NVIDIA Container Toolkit applies to IPC mounts.
    const TOOLKIT_IPC_OPTIONS: &[&str] = &["nosuid", "nodev", "rbind", "rprivate", "noexec"];

    #[test]
    fn writable_mps_pipe_directory_is_an_ipc_directory() {
        let directory = tempfile::tempdir().unwrap();
        let context =
            runtime_mount_context(directory.path(), "/tmp/nvidia-mps", TOOLKIT_IPC_OPTIONS);
        let requirements = resolve_with_kind_and_access(&context, CdiAccess::ReadWrite, |_| {
            Some(CdiPathKind::Directory)
        })
        .unwrap();
        assert_eq!(requirements.ipc_directory_paths, vec!["/tmp/nvidia-mps"]);
        assert!(requirements.read_write_mount_paths.is_empty());
        assert!(requirements.read_only_paths.is_empty());
        assert!(requirements.mounts.is_empty());
    }

    #[test]
    fn mps_pipe_directory_requires_restrictive_spec_options() {
        let directory = tempfile::tempdir().unwrap();
        for missing in ["nosuid", "nodev", "noexec"] {
            let options = TOOLKIT_IPC_OPTIONS
                .iter()
                .copied()
                .filter(|option| *option != missing)
                .collect::<Vec<_>>();
            let context = runtime_mount_context(directory.path(), "/tmp/nvidia-mps", &options);
            assert!(
                matches!(
                    resolve_with_kind_and_access(&context, CdiAccess::ReadWrite, |_| {
                        Some(CdiPathKind::Directory)
                    }),
                    Err(CdiError::UnsafeIpcDirectory { .. })
                ),
                "missing {missing}"
            );
        }
    }

    #[test]
    fn ipc_directory_exception_is_limited_to_writable_mps_directories() {
        let directory = tempfile::tempdir().unwrap();
        // A read-only MPS mount stays an ordinary read-only mount.
        let context =
            runtime_mount_context(directory.path(), "/tmp/nvidia-mps", TOOLKIT_IPC_OPTIONS);
        let requirements = resolve_with_kind_and_access(&context, CdiAccess::ReadOnly, |_| {
            Some(CdiPathKind::Directory)
        })
        .unwrap();
        assert!(requirements.ipc_directory_paths.is_empty());
        assert_eq!(requirements.read_only_paths, vec!["/tmp/nvidia-mps"]);
        // A writable file at the MPS path, or a writable directory elsewhere,
        // remains an unsupported writable mount.
        for (path, kind) in [
            ("/tmp/nvidia-mps", CdiPathKind::File),
            ("/tmp/nvidia-mps-other", CdiPathKind::Directory),
            ("/var/run/nvidia-mps", CdiPathKind::Directory),
        ] {
            let context = runtime_mount_context(directory.path(), path, TOOLKIT_IPC_OPTIONS);
            assert!(
                matches!(
                    resolve_with_kind_and_access(&context, CdiAccess::ReadWrite, |_| Some(kind)),
                    Err(CdiError::WritableMountNotAllowed { .. })
                ),
                "{path}"
            );
        }
    }

    #[test]
    fn ipc_directory_conflicts_with_other_cdi_uses_of_the_same_path() {
        let mut accumulator = RequirementAccumulator::default();
        accumulator
            .add_ipc_directory("/tmp/nvidia-mps".into())
            .unwrap();
        assert!(
            accumulator
                .add_device_node("/tmp/nvidia-mps".into())
                .is_err()
        );
        assert!(accumulator.add_socket("/tmp/nvidia-mps".into()).is_err());
        assert!(
            accumulator
                .add_mount("/tmp/nvidia-mps".into(), CdiAccess::ReadOnly)
                .is_err()
        );
        let mut accumulator = RequirementAccumulator::default();
        accumulator
            .add_mount("/tmp/nvidia-mps".into(), CdiAccess::ReadOnly)
            .unwrap();
        assert!(
            accumulator
                .add_ipc_directory("/tmp/nvidia-mps".into())
                .is_err()
        );
    }

    #[test]
    fn writable_cdi_mounts_are_rejected() {
        // Authored write grants cannot authorize them; enforcement covers that
        // in the Landlock tests.
        for path in ["/opt/nvidia/cache.db", "/opt/nvidia/cache"] {
            let requirements = CdiDerivedRequirements {
                read_write_mount_paths: vec![path.into()],
                ..Default::default()
            };
            assert!(matches!(
                validate_cdi_requirements(&requirements),
                Err(CdiError::WritableMountNotAllowed { .. })
            ));
        }
    }

    #[test]
    fn rejects_broad_shared_library_parents() {
        for parent in ["", "/dev", "/proc", "/sys", "/run", "/usr"] {
            let mut accumulator = RequirementAccumulator::default();
            accumulator
                .add_mount(format!("{parent}/libexample.so.1"), CdiAccess::ReadOnly)
                .unwrap();
            assert!(matches!(
                accumulator.build(),
                Err(CdiError::UnsafePolicyPath { .. })
            ));
        }
    }

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
        kind: impl Fn(&str) -> Option<CdiPathKind>,
    ) -> Result<CdiDerivedRequirements, CdiError> {
        resolve_with_kind_and_access(context, CdiAccess::ReadOnly, kind)
    }

    fn resolve_with_kind_and_access(
        context: &CdiContext,
        access: CdiAccess,
        kind: impl Fn(&str) -> Option<CdiPathKind>,
    ) -> Result<CdiDerivedRequirements, CdiError> {
        let requirements = resolve_cdi_context_with_mount_inspector(context, |path| {
            let kind = kind(path).ok_or_else(|| mount_inspection(path, "missing fixture mount"))?;
            Ok(CdiMountState { kind, access })
        })?;
        validate_cdi_requirements(&requirements)?;
        Ok(requirements)
    }

    fn fixture_mount_state(path: &str) -> CdiMountState {
        // These captured NVIDIA layouts model ordinary mounts as effectively
        // read-only and the persistenced endpoint as a Unix socket. Neither
        // observation is inferred from ro/rw strings in the specs.
        CdiMountState {
            kind: if path == "/run/nvidia-persistenced/socket" {
                CdiPathKind::Socket
            } else {
                CdiPathKind::File
            },
            access: CdiAccess::ReadOnly,
        }
    }

    fn resolve_fixture(context: &CdiContext) -> Result<CdiDerivedRequirements, CdiError> {
        resolve_cdi_context_with_mount_inspector(context, |path| Ok(fixture_mount_state(path)))
    }

    fn runtime_mount_context(dir: &Path, path: &str, options: &[&str]) -> CdiContext {
        let specs = dir.join("specs");
        std::fs::create_dir_all(&specs).unwrap();
        let spec = serde_json::json!({
            "cdiVersion": "1.1.0", "kind": "example.com/device",
            "devices": [{"name": "test", "containerEdits": {"mounts": [{
                "hostPath": "/host/mount", "containerPath": path, "options": options
            }]}}]
        });
        write_spec(&specs, "runtime.json", &spec.to_string());
        context(&specs, &["example.com/device=test"])
    }

    fn always_missing(_: &str) -> Option<CdiPathKind> {
        None
    }

    fn fake_device_node(path: &str) -> Option<CdiPathKind> {
        path.starts_with("/dev/")
            .then_some(CdiPathKind::CharacterDevice)
    }

    #[derive(serde::Serialize)]
    struct CdiRequirementsBaseline<'a> {
        device_node_paths: &'a [String],
        socket_paths: &'a [String],
        read_only_paths: &'a [String],
        read_write_mount_paths: &'a [String],
        ipc_directory_paths: &'a [String],
        additional_gids: &'a [u32],
    }

    fn assert_cdi_spec_matches_derived_requirements_baseline(spec: &str, expected: &str) {
        let dir = tempfile::tempdir().unwrap();
        write_spec(dir.path(), "nvidia.yaml", spec);

        let requirements = resolve_fixture(&context(dir.path(), &["nvidia.com/gpu=all"])).unwrap();
        let baseline = CdiRequirementsBaseline {
            device_node_paths: &requirements.device_node_paths,
            socket_paths: &requirements.socket_paths,
            read_only_paths: &requirements.read_only_paths,
            read_write_mount_paths: &requirements.read_write_mount_paths,
            ipc_directory_paths: &requirements.ipc_directory_paths,
            additional_gids: &requirements.additional_gids,
        };
        let generated = serde_json::to_string_pretty(&baseline).unwrap() + "\n";

        assert_eq!(generated, expected);
    }

    #[test]
    fn orin_cdi_spec_matches_derived_requirements_baseline() {
        assert_cdi_spec_matches_derived_requirements_baseline(
            include_str!("../../testdata/cdi/orin-nvidia.yaml"),
            include_str!("../../testdata/cdi/orin-nvidia-policy-baseline.json"),
        );
    }

    #[test]
    fn spark_cdi_spec_matches_derived_requirements_baseline() {
        assert_cdi_spec_matches_derived_requirements_baseline(
            include_str!("../../testdata/cdi/spark-nvidia.yaml"),
            include_str!("../../testdata/cdi/spark-nvidia-policy-baseline.json"),
        );
    }

    #[test]
    fn multi_gpu_cdi_spec_matches_derived_requirements_baseline() {
        assert_cdi_spec_matches_derived_requirements_baseline(
            include_str!("../../testdata/cdi/multi-gpu-nvidia.yaml"),
            include_str!("../../testdata/cdi/multi-gpu-nvidia-policy-baseline.json"),
        );
    }

    #[test]
    fn fixture_resolution_uses_mount_state_instead_of_spec_options() {
        let directory = tempfile::tempdir().unwrap();
        for (options, access) in [
            (vec![], CdiAccess::ReadOnly),
            (vec!["rw"], CdiAccess::ReadOnly),
            (vec!["ro"], CdiAccess::ReadWrite),
        ] {
            let context =
                runtime_mount_context(directory.path(), "/opt/nvidia/runtime.json", &options);
            let requirements = resolve_cdi_context_with_mount_inspector(&context, |_| {
                Ok(CdiMountState {
                    kind: CdiPathKind::File,
                    access,
                })
            })
            .unwrap();
            if access == CdiAccess::ReadOnly {
                assert_eq!(
                    requirements.read_only_paths,
                    vec!["/opt/nvidia/runtime.json"]
                );
                assert!(requirements.read_write_mount_paths.is_empty());
            } else {
                assert_eq!(
                    requirements.read_write_mount_paths,
                    vec!["/opt/nvidia/runtime.json"]
                );
                assert!(requirements.read_only_paths.is_empty());
            }
        }
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

        let requirements = resolve_fixture(&context(dir.path(), &["nvidia.com/gpu=0"])).unwrap();

        assert_eq!(
            requirements.device_node_paths,
            vec!["/dev/nvidia0", "/dev/nvidiactl"]
        );
        assert_eq!(requirements.read_only_paths, vec!["/usr/local/cuda/lib64"]);
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

        let requirements = resolve_fixture(&context(dir.path(), &["nvidia.com/gpu=all"])).unwrap();

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

        let requirements = resolve_fixture(&context(dir.path(), &["nvidia.com/gpu=all"])).unwrap();

        assert_eq!(requirements.device_node_paths, vec!["/dev/dxg"]);
        assert_eq!(requirements.read_only_paths, vec!["/usr/lib/wsl/lib"]);
    }

    #[test]
    fn resolves_supported_shared_library_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        write_spec(
            dir.path(),
            "libraries.yaml",
            r#"
cdiVersion: 1.1.0
kind: nvidia.com/gpu
devices:
  - name: "0"
    containerEdits:
      mounts:
        - hostPath: /host/lib/libcuda.so
          containerPath: /opt/nvidia/lib/libcuda.so
        - hostPath: /host/lib/libnvidia-ml.so.1
          containerPath: /opt/nvidia/lib/libnvidia-ml.so.1
        - hostPath: /host/lib/libnvidia-encode.so.9
          containerPath: /opt/nvidia/encode/libnvidia-encode.so.9
        - hostPath: /host/lib/libnvidia-eglcore.so.540.5.0
          containerPath: /opt/nvidia/versioned/libnvidia-eglcore.so.540.5.0
        - hostPath: /host/lib/libunsupported.so.debug
          containerPath: /opt/nvidia/debug/libunsupported.so.debug
        - hostPath: /host/lib/libunsupported.so.1beta
          containerPath: /opt/nvidia/debug/libunsupported.so.1beta
        - hostPath: /host/config/ld.so.conf
          containerPath: /etc/nvidia/ld.so.conf
        - hostPath: /host/bin/nvidia-smi
          containerPath: /usr/bin/nvidia-smi
        - hostPath: /host/config/runtime.json
          containerPath: /etc/nvidia/runtime.json
"#,
        );

        let requirements = resolve_fixture(&context(dir.path(), &["nvidia.com/gpu=0"])).unwrap();

        assert_eq!(
            requirements.read_only_paths,
            vec![
                "/etc/nvidia/ld.so.conf",
                "/etc/nvidia/runtime.json",
                "/opt/nvidia/debug/libunsupported.so.1beta",
                "/opt/nvidia/debug/libunsupported.so.debug",
                "/opt/nvidia/encode",
                "/opt/nvidia/lib",
                "/opt/nvidia/versioned",
                "/usr/bin/nvidia-smi",
            ]
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

        let requirements = resolve_fixture(&context(dir.path(), &["nvidia.com/gpu=0"])).unwrap();

        assert_eq!(requirements.additional_gids, vec![44]);
        assert_eq!(
            requirements.device_node_paths,
            vec!["/dev/nvhost-gpu", "/dev/nvmap"]
        );
    }

    #[test]
    fn rejects_writable_single_file_mount_with_exact_filesystem_grant() {
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

        let result = resolve_with_kind_and_access(
            &context(dir.path(), &["nvidia.com/gpu=0"]),
            CdiAccess::ReadWrite,
            |path| (path == "/opt/nvidia/cache.db").then_some(CdiPathKind::File),
        );
        assert!(matches!(
            result,
            Err(CdiError::WritableMountNotAllowed { .. })
        ));
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

        let err = resolve_with_kind(&context(dir.path(), &["nvidia.com/gpu=1"]), always_missing)
            .unwrap_err();

        assert!(matches!(err, CdiError::MissingDevice(device) if device == "nvidia.com/gpu=1"));
    }

    #[test]
    fn reports_refresh_errors_when_requested_device_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        write_spec(dir.path(), "broken.yaml", "kind: [");

        let err = resolve_with_kind(
            &context(dir.path(), &["nvidia.com/gpu=0"]),
            fake_device_node,
        )
        .unwrap_err();

        assert!(
            matches!(err, CdiError::MissingDeviceAfterRefresh { device, refresh_error }
                if device == "nvidia.com/gpu=0" && !refresh_error.is_empty())
        );
    }

    #[test]
    fn rejects_duplicate_cdi_device_names() {
        let dir = tempfile::tempdir().unwrap();
        for (name, value) in [("first.yaml", "FIRST"), ("second.yaml", "SECOND")] {
            write_spec(
                dir.path(),
                name,
                &format!(
                    r#"
cdiVersion: 1.1.0
kind: nvidia.com/gpu
devices:
  - name: "0"
    containerEdits:
      env:
        - OPEN_SHELL_TEST={value}
"#
                ),
            );
        }

        let err = resolve_with_kind(&context(dir.path(), &["nvidia.com/gpu=0"]), always_missing)
            .unwrap_err();

        assert!(
            matches!(err, CdiError::MissingDeviceAfterRefresh { device, refresh_error }
                if device == "nvidia.com/gpu=0"
                    && refresh_error.contains("conflicting device nvidia.com/gpu=0"))
        );
    }

    #[test]
    fn empty_selection_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let requirements = resolve_with_kind(&context(dir.path(), &[]), always_missing)
            .expect("empty selection should resolve to empty requirements");

        assert_eq!(requirements, CdiDerivedRequirements::default());
    }

    #[test]
    fn empty_spec_dirs_are_noop() {
        let context = CdiContext::new(vec!["nvidia.com/gpu=0".to_string()], Vec::new());

        let requirements = resolve_with_kind(&context, always_missing)
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

        let err =
            resolve_with_kind(&context(dir.path(), &["not-a-cdi-id"]), always_missing).unwrap_err();

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

            let err =
                resolve_with_kind(&context(dir.path(), &["nvidia.com/gpu=0"]), always_missing)
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
            fake_device_node,
        )
        .unwrap_err();

        assert!(matches!(err, CdiError::ConflictingAccess { .. }));
    }

    #[test]
    fn rejects_root_additional_gid() {
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

        let err = resolve_with_kind(&context(dir.path(), &["nvidia.com/gpu=0"]), always_missing)
            .unwrap_err();

        assert!(matches!(err, CdiError::RootAdditionalGid));
    }
}
