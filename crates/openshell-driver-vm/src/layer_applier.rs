// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Applies extracted OCI layers to a VM root filesystem.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs;
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt as _;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

pub fn apply_layer_dir_to_rootfs(layer_root: &Path, rootfs: &Path) -> Result<(), String> {
    LayerApplier::new(rootfs)?.apply(layer_root)
}

/// Owns all filesystem mutations performed while merging an extracted OCI
/// layer into a rootfs.
///
/// Keeping the mutation boundary here makes the distinction between symlinks
/// supplied by the current layer and directory symlinks retained from lower
/// layers explicit. The latter are followed only through a
/// [`DirectoryMergePlan::FollowLowerLayerSymlink`] decision.
struct LayerApplier {
    rootfs: PathBuf,
    #[cfg(unix)]
    root_dir: rustix::fd::OwnedFd,
}

#[cfg(not(unix))]
#[derive(Debug)]
enum DirectoryMergePlan {
    CreateDirectory { path: PathBuf },
    MergeDirectory { path: PathBuf },
    FollowLowerLayerSymlink { target: PathBuf },
    ReplaceLowerLayerEntry { path: PathBuf },
}

#[cfg(not(unix))]
impl DirectoryMergePlan {
    fn path(&self) -> &Path {
        match self {
            Self::CreateDirectory { path }
            | Self::MergeDirectory { path }
            | Self::ReplaceLowerLayerEntry { path } => path,
            Self::FollowLowerLayerSymlink { target, .. } => target,
        }
    }

    fn applies_directory_metadata(&self) -> bool {
        !matches!(self, Self::FollowLowerLayerSymlink { .. })
    }
}

#[cfg(unix)]
struct ResolvedDirectory {
    fd: rustix::fd::OwnedFd,
    components: Vec<OsString>,
}

#[cfg(unix)]
enum DirectoryMergePlan {
    CreateDirectory,
    MergeDirectory(ResolvedDirectory),
    FollowLowerLayerSymlink(ResolvedDirectory),
    ReplaceLowerLayerEntry,
}

impl LayerApplier {
    fn new(rootfs: &Path) -> Result<Self, String> {
        fs::create_dir_all(rootfs).map_err(|err| format!("create {}: {err}", rootfs.display()))?;
        let rootfs = fs::canonicalize(rootfs)
            .map_err(|err| format!("canonicalize rootfs {}: {err}", rootfs.display()))?;
        #[cfg(unix)]
        let root_dir = rustix::fs::open(
            &rootfs,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|err| format!("open rootfs {}: {err}", rootfs.display()))?;
        Ok(Self {
            rootfs,
            #[cfg(unix)]
            root_dir,
        })
    }

    fn apply(&self, layer_root: &Path) -> Result<(), String> {
        #[cfg(unix)]
        {
            let root = ResolvedDirectory {
                fd: self.open_root_dir()?,
                components: Vec::new(),
            };
            self.merge_directory(layer_root, &root)
        }
        #[cfg(not(unix))]
        {
            self.merge_directory(layer_root, &self.rootfs)
        }
    }

    #[cfg(not(unix))]
    fn merge_directory(&self, source_dir: &Path, target_dir: &Path) -> Result<(), String> {
        fs::create_dir_all(target_dir)
            .map_err(|err| format!("create {}: {err}", target_dir.display()))?;

        let mut entries = fs::read_dir(source_dir)
            .map_err(|err| format!("read {}: {err}", source_dir.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| format!("read {}: {err}", source_dir.display()))?;
        entries.sort_by_key(fs::DirEntry::file_name);

        if entries
            .iter()
            .any(|entry| entry.file_name().to_string_lossy() == ".wh..wh..opq")
        {
            self.clear_directory_contents(target_dir)?;
        }

        for entry in entries {
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();
            if name == ".wh..wh..opq" {
                continue;
            }
            if let Some(hidden_name) = name.strip_prefix(".wh.") {
                self.remove_path_if_exists(&target_dir.join(hidden_name))?;
                continue;
            }

            let source_path = entry.path();
            let dest_path = target_dir.join(&file_name);
            let metadata = fs::symlink_metadata(&source_path)
                .map_err(|err| format!("stat {}: {err}", source_path.display()))?;
            let file_type = metadata.file_type();

            if file_type.is_dir() {
                let plan = self.plan_directory_merge(&dest_path)?;
                if matches!(plan, DirectoryMergePlan::ReplaceLowerLayerEntry { .. }) {
                    self.remove_path_if_exists(plan.path())?;
                }
                fs::create_dir_all(plan.path())
                    .map_err(|err| format!("create {}: {err}", plan.path().display()))?;
                self.merge_directory(&source_path, plan.path())?;
                if plan.applies_directory_metadata() {
                    fs::set_permissions(plan.path(), metadata.permissions())
                        .map_err(|err| format!("chmod {}: {err}", plan.path().display()))?;
                }
            } else if file_type.is_file() {
                self.remove_path_if_exists(&dest_path)?;
                if let Some(parent) = dest_path.parent() {
                    fs::create_dir_all(parent)
                        .map_err(|err| format!("create {}: {err}", parent.display()))?;
                }
                fs::copy(&source_path, &dest_path).map_err(|err| {
                    format!(
                        "copy {} to {}: {err}",
                        source_path.display(),
                        dest_path.display()
                    )
                })?;
                fs::set_permissions(&dest_path, metadata.permissions())
                    .map_err(|err| format!("chmod {}: {err}", dest_path.display()))?;
            } else if file_type.is_symlink() {
                self.copy_symlink(&source_path, &dest_path)?;
            } else {
                return Err(format!(
                    "unsupported layer entry type at {}",
                    source_path.display()
                ));
            }
        }

        Ok(())
    }

    #[cfg(unix)]
    fn merge_directory(
        &self,
        source_dir: &Path,
        target_dir: &ResolvedDirectory,
    ) -> Result<(), String> {
        let mut entries = fs::read_dir(source_dir)
            .map_err(|err| format!("read {}: {err}", source_dir.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| format!("read {}: {err}", source_dir.display()))?;
        entries.sort_by_key(fs::DirEntry::file_name);

        if entries
            .iter()
            .any(|entry| entry.file_name().to_string_lossy() == ".wh..wh..opq")
        {
            self.clear_directory_contents(target_dir)?;
        }

        for entry in entries {
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();
            if name == ".wh..wh..opq" {
                continue;
            }
            if let Some(hidden_name) = name.strip_prefix(".wh.") {
                self.remove_entry(target_dir, std::ffi::OsStr::new(hidden_name))?;
                continue;
            }

            let source_path = entry.path();
            let metadata = fs::symlink_metadata(&source_path)
                .map_err(|err| format!("stat {}: {err}", source_path.display()))?;
            let file_type = metadata.file_type();

            if file_type.is_dir() {
                let plan = self.plan_directory_merge(target_dir, &file_name)?;
                let apply_metadata =
                    !matches!(plan, DirectoryMergePlan::FollowLowerLayerSymlink(_));
                let child = match plan {
                    DirectoryMergePlan::CreateDirectory => {
                        self.create_child_directory(target_dir, &file_name)?
                    }
                    DirectoryMergePlan::MergeDirectory(directory)
                    | DirectoryMergePlan::FollowLowerLayerSymlink(directory) => directory,
                    DirectoryMergePlan::ReplaceLowerLayerEntry => {
                        self.remove_entry(target_dir, &file_name)?;
                        self.create_child_directory(target_dir, &file_name)?
                    }
                };
                self.merge_directory(&source_path, &child)?;
                if apply_metadata {
                    rustix::fs::fchmod(&child.fd, Self::mode_from_metadata(&metadata)).map_err(
                        |err| format!("chmod {}: {err}", self.directory_path(&child).display()),
                    )?;
                }
            } else if file_type.is_file() {
                self.copy_file(&source_path, target_dir, &file_name, &metadata)?;
            } else if file_type.is_symlink() {
                self.copy_symlink(&source_path, target_dir, &file_name)?;
            } else {
                return Err(format!(
                    "unsupported layer entry type at {}",
                    source_path.display()
                ));
            }
        }

        Ok(())
    }

    #[cfg(unix)]
    fn plan_directory_merge(
        &self,
        parent: &ResolvedDirectory,
        name: &std::ffi::OsStr,
    ) -> Result<DirectoryMergePlan, String> {
        let entry_path = self.entry_path(parent, name);
        let stat = match rustix::fs::statat(&parent.fd, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        {
            Ok(stat) => stat,
            Err(rustix::io::Errno::NOENT) => return Ok(DirectoryMergePlan::CreateDirectory),
            Err(err) => return Err(format!("stat {}: {err}", entry_path.display())),
        };
        let file_type = rustix::fs::FileType::from_raw_mode(stat.st_mode);
        if file_type.is_dir() {
            return self
                .open_child_directory(parent, name)
                .map(DirectoryMergePlan::MergeDirectory);
        }
        if file_type.is_symlink() {
            let mut components = parent.components.clone();
            components.push(name.to_os_string());
            if let Some(directory) = self.resolve_directory(&components)? {
                return Ok(DirectoryMergePlan::FollowLowerLayerSymlink(directory));
            }
        }
        Ok(DirectoryMergePlan::ReplaceLowerLayerEntry)
    }

    #[cfg(unix)]
    fn open_root_dir(&self) -> Result<rustix::fd::OwnedFd, String> {
        rustix::fs::openat(
            &self.root_dir,
            ".",
            Self::directory_open_flags(),
            rustix::fs::Mode::empty(),
        )
        .map_err(|err| format!("open rootfs {}: {err}", self.rootfs.display()))
    }

    #[cfg(unix)]
    fn open_child_directory(
        &self,
        parent: &ResolvedDirectory,
        name: &std::ffi::OsStr,
    ) -> Result<ResolvedDirectory, String> {
        let path = self.entry_path(parent, name);
        let fd = rustix::fs::openat(
            &parent.fd,
            name,
            Self::directory_open_flags(),
            rustix::fs::Mode::empty(),
        )
        .map_err(|err| format!("open directory {}: {err}", path.display()))?;
        let mut components = parent.components.clone();
        components.push(name.to_os_string());
        Ok(ResolvedDirectory { fd, components })
    }

    #[cfg(unix)]
    fn create_child_directory(
        &self,
        parent: &ResolvedDirectory,
        name: &std::ffi::OsStr,
    ) -> Result<ResolvedDirectory, String> {
        let path = self.entry_path(parent, name);
        rustix::fs::mkdirat(&parent.fd, name, rustix::fs::Mode::from_raw_mode(0o700))
            .map_err(|err| format!("create {}: {err}", path.display()))?;
        self.open_child_directory(parent, name)
    }

    #[cfg(unix)]
    fn resolve_directory(
        &self,
        components: &[OsString],
    ) -> Result<Option<ResolvedDirectory>, String> {
        const MAX_SYMLINKS: usize = 40;

        let requested = components
            .iter()
            .fold(self.rootfs.clone(), |path, component| path.join(component));
        let mut pending = components
            .iter()
            .cloned()
            .map(RootfsPathComponent::Normal)
            .collect::<VecDeque<_>>();
        let mut resolved = Vec::<OsString>::new();
        let mut stack = vec![self.open_root_dir()?];
        let mut symlinks = 0_usize;

        while let Some(component) = pending.pop_front() {
            match component {
                RootfsPathComponent::Parent => {
                    if resolved.pop().is_none() {
                        return Err(format!(
                            "layer destination {} escapes rootfs {}",
                            requested.display(),
                            self.rootfs.display()
                        ));
                    }
                    stack.pop();
                }
                RootfsPathComponent::Normal(name) => {
                    let parent = stack.last().expect("root directory handle remains");
                    let candidate = resolved
                        .iter()
                        .fold(self.rootfs.clone(), |path, component| path.join(component))
                        .join(&name);
                    let stat = match rustix::fs::statat(
                        parent,
                        &name,
                        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                    ) {
                        Ok(stat) => stat,
                        Err(rustix::io::Errno::NOENT | rustix::io::Errno::NOTDIR) => {
                            return Ok(None);
                        }
                        Err(err) => return Err(format!("stat {}: {err}", candidate.display())),
                    };
                    let file_type = rustix::fs::FileType::from_raw_mode(stat.st_mode);
                    if file_type.is_symlink() {
                        symlinks += 1;
                        if symlinks > MAX_SYMLINKS {
                            return Err(format!(
                                "too many symlinks while resolving layer destination {}",
                                requested.display()
                            ));
                        }
                        let target = rustix::fs::readlinkat(parent, &name, Vec::new())
                            .map_err(|err| format!("readlink {}: {err}", candidate.display()))?;
                        let target = Path::new(std::ffi::OsStr::from_bytes(target.to_bytes()));
                        if target.is_absolute() {
                            return Err(format!(
                                "absolute symlink {} -> {} cannot be traversed while applying a layer",
                                candidate.display(),
                                target.display()
                            ));
                        }
                        let mut target_components = rootfs_path_components(target)?;
                        target_components.append(&mut pending);
                        pending = target_components;
                    } else if file_type.is_dir() {
                        let fd = rustix::fs::openat(
                            parent,
                            &name,
                            Self::directory_open_flags(),
                            rustix::fs::Mode::empty(),
                        )
                        .map_err(|err| format!("open directory {}: {err}", candidate.display()))?;
                        resolved.push(name);
                        stack.push(fd);
                    } else {
                        return Ok(None);
                    }
                }
            }
        }

        let fd = stack.pop().expect("resolved directory handle remains");
        Ok(Some(ResolvedDirectory {
            fd,
            components: resolved,
        }))
    }

    #[cfg(unix)]
    fn copy_file(
        &self,
        source_path: &Path,
        parent: &ResolvedDirectory,
        name: &std::ffi::OsStr,
        metadata: &fs::Metadata,
    ) -> Result<(), String> {
        self.remove_entry(parent, name)?;
        let path = self.entry_path(parent, name);
        let mut source = fs::File::open(source_path)
            .map_err(|err| format!("open {}: {err}", source_path.display()))?;
        let fd = rustix::fs::openat(
            &parent.fd,
            name,
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_raw_mode(0o600),
        )
        .map_err(|err| format!("create {}: {err}", path.display()))?;
        let mut destination = fs::File::from(fd);
        std::io::copy(&mut source, &mut destination).map_err(|err| {
            format!(
                "copy {} to {}: {err}",
                source_path.display(),
                path.display()
            )
        })?;
        destination
            .flush()
            .map_err(|err| format!("flush {}: {err}", path.display()))?;
        rustix::fs::fchmod(&destination, Self::mode_from_metadata(metadata))
            .map_err(|err| format!("chmod {}: {err}", path.display()))
    }

    #[cfg(unix)]
    fn clear_directory_contents(&self, directory: &ResolvedDirectory) -> Result<(), String> {
        let mut stream = rustix::fs::Dir::read_from(&directory.fd)
            .map_err(|err| format!("read {}: {err}", self.directory_path(directory).display()))?;
        let mut names = Vec::new();
        for entry in &mut stream {
            let entry = entry.map_err(|err| {
                format!("read {}: {err}", self.directory_path(directory).display())
            })?;
            let name = entry.file_name().to_bytes();
            if name != b"." && name != b".." {
                names.push(std::ffi::OsStr::from_bytes(name).to_os_string());
            }
        }
        for name in names {
            self.remove_entry(directory, &name)?;
        }
        Ok(())
    }

    #[cfg(unix)]
    fn remove_entry(
        &self,
        parent: &ResolvedDirectory,
        name: &std::ffi::OsStr,
    ) -> Result<(), String> {
        let path = self.entry_path(parent, name);
        let stat = match rustix::fs::statat(&parent.fd, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        {
            Ok(stat) => stat,
            Err(rustix::io::Errno::NOENT) => return Ok(()),
            Err(err) => return Err(format!("stat {}: {err}", path.display())),
        };
        if rustix::fs::FileType::from_raw_mode(stat.st_mode).is_dir() {
            let directory = self.open_child_directory(parent, name)?;
            self.clear_directory_contents(&directory)?;
            rustix::fs::unlinkat(&parent.fd, name, rustix::fs::AtFlags::REMOVEDIR)
                .map_err(|err| format!("remove {}: {err}", path.display()))
        } else {
            rustix::fs::unlinkat(&parent.fd, name, rustix::fs::AtFlags::empty())
                .map_err(|err| format!("remove {}: {err}", path.display()))
        }
    }

    #[cfg(unix)]
    fn copy_symlink(
        &self,
        source_path: &Path,
        parent: &ResolvedDirectory,
        name: &std::ffi::OsStr,
    ) -> Result<(), String> {
        let target = fs::read_link(source_path)
            .map_err(|err| format!("readlink {}: {err}", source_path.display()))?;
        self.remove_entry(parent, name)?;
        let path = self.entry_path(parent, name);
        rustix::fs::symlinkat(&target, &parent.fd, name)
            .map_err(|err| format!("symlink {} to {}: {err}", target.display(), path.display()))
    }

    #[cfg(unix)]
    fn directory_open_flags() -> rustix::fs::OFlags {
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC
    }

    #[cfg(unix)]
    fn mode_from_metadata(metadata: &fs::Metadata) -> rustix::fs::Mode {
        let raw = metadata.permissions().mode();
        let mut mode = rustix::fs::Mode::empty();
        for (bit, flag) in [
            (0o4000, rustix::fs::Mode::SUID),
            (0o2000, rustix::fs::Mode::SGID),
            (0o1000, rustix::fs::Mode::SVTX),
            (0o0400, rustix::fs::Mode::RUSR),
            (0o0200, rustix::fs::Mode::WUSR),
            (0o0100, rustix::fs::Mode::XUSR),
            (0o0040, rustix::fs::Mode::RGRP),
            (0o0020, rustix::fs::Mode::WGRP),
            (0o0010, rustix::fs::Mode::XGRP),
            (0o0004, rustix::fs::Mode::ROTH),
            (0o0002, rustix::fs::Mode::WOTH),
            (0o0001, rustix::fs::Mode::XOTH),
        ] {
            if raw & bit != 0 {
                mode |= flag;
            }
        }
        mode
    }

    #[cfg(unix)]
    fn directory_path(&self, directory: &ResolvedDirectory) -> PathBuf {
        directory
            .components
            .iter()
            .fold(self.rootfs.clone(), |path, component| path.join(component))
    }

    #[cfg(unix)]
    fn entry_path(&self, parent: &ResolvedDirectory, name: &std::ffi::OsStr) -> PathBuf {
        self.directory_path(parent).join(name)
    }

    #[cfg(not(unix))]
    fn plan_directory_merge(&self, path: &Path) -> Result<DirectoryMergePlan, String> {
        self.ensure_rootfs_destination(path)?;
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(DirectoryMergePlan::CreateDirectory {
                    path: path.to_path_buf(),
                });
            }
            Err(err) => return Err(format!("stat {}: {err}", path.display())),
        };
        if metadata.file_type().is_dir() {
            return Ok(DirectoryMergePlan::MergeDirectory {
                path: path.to_path_buf(),
            });
        }
        if metadata.file_type().is_symlink() {
            let target = self.resolve_path_beneath_rootfs(path)?;
            match fs::metadata(&target) {
                Ok(metadata) if metadata.file_type().is_dir() => {
                    return Ok(DirectoryMergePlan::FollowLowerLayerSymlink { target });
                }
                Ok(_) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(format!("stat {}: {err}", target.display())),
            }
        }
        Ok(DirectoryMergePlan::ReplaceLowerLayerEntry {
            path: path.to_path_buf(),
        })
    }

    #[cfg(not(unix))]
    fn clear_directory_contents(&self, dir: &Path) -> Result<(), String> {
        if !dir.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(dir).map_err(|err| format!("read {}: {err}", dir.display()))? {
            let entry = entry.map_err(|err| format!("read {}: {err}", dir.display()))?;
            self.remove_path_if_exists(&entry.path())?;
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn remove_path_if_exists(&self, path: &Path) -> Result<(), String> {
        self.ensure_rootfs_destination(path)?;
        let Ok(metadata) = fs::symlink_metadata(path) else {
            return Ok(());
        };
        if metadata.file_type().is_dir() {
            fs::remove_dir_all(path).map_err(|err| format!("remove {}: {err}", path.display()))
        } else {
            fs::remove_file(path).map_err(|err| format!("remove {}: {err}", path.display()))
        }
    }

    #[cfg(not(unix))]
    fn ensure_rootfs_destination(&self, path: &Path) -> Result<(), String> {
        path.strip_prefix(&self.rootfs).map(|_| ()).map_err(|_| {
            format!(
                "layer destination {} is outside rootfs {}",
                path.display(),
                self.rootfs.display()
            )
        })
    }

    #[cfg(not(unix))]
    fn resolve_path_beneath_rootfs(&self, path: &Path) -> Result<PathBuf, String> {
        const MAX_SYMLINKS: usize = 40;

        // A symlink from an earlier OCI layer has container path semantics,
        // not ambient access to the host filesystem. Resolve it component by
        // component without following it, and reject targets that leave the
        // private image staging root before a later layer performs any
        // filesystem operation.
        let relative = path.strip_prefix(&self.rootfs).map_err(|_| {
            format!(
                "layer destination {} is outside rootfs {}",
                path.display(),
                self.rootfs.display()
            )
        })?;
        let mut pending = rootfs_path_components(relative)?;
        let mut resolved = Vec::<OsString>::new();
        let mut symlinks = 0_usize;

        while let Some(component) = pending.pop_front() {
            match component {
                RootfsPathComponent::Parent => {
                    if resolved.pop().is_none() {
                        return Err(format!(
                            "layer destination {} escapes rootfs {}",
                            path.display(),
                            self.rootfs.display()
                        ));
                    }
                }
                RootfsPathComponent::Normal(name) => {
                    let candidate = resolved
                        .iter()
                        .fold(self.rootfs.clone(), |path, component| path.join(component))
                        .join(&name);
                    match fs::symlink_metadata(&candidate) {
                        Ok(metadata) if metadata.file_type().is_symlink() => {
                            symlinks += 1;
                            if symlinks > MAX_SYMLINKS {
                                return Err(format!(
                                    "too many symlinks while resolving layer destination {}",
                                    path.display()
                                ));
                            }
                            let target = fs::read_link(&candidate).map_err(|err| {
                                format!("readlink {}: {err}", candidate.display())
                            })?;
                            if target.is_absolute() {
                                return Err(format!(
                                    "absolute symlink {} -> {} cannot be traversed while applying a layer",
                                    candidate.display(),
                                    target.display()
                                ));
                            }
                            let mut target_components = rootfs_path_components(&target)?;
                            target_components.append(&mut pending);
                            pending = target_components;
                        }
                        Ok(_) => resolved.push(name),
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                            resolved.push(name);
                        }
                        Err(err) => return Err(format!("stat {}: {err}", candidate.display())),
                    }
                }
            }
        }

        Ok(resolved
            .into_iter()
            .fold(self.rootfs.clone(), |path, component| path.join(component)))
    }

    #[cfg(not(unix))]
    fn copy_symlink(&self, _source_path: &Path, _dest_path: &Path) -> Result<(), String> {
        Err("symlink layers are only supported on Unix hosts".to_string())
    }
}

#[derive(Debug)]
enum RootfsPathComponent {
    Parent,
    Normal(OsString),
}

fn rootfs_path_components(path: &Path) -> Result<VecDeque<RootfsPathComponent>, String> {
    path.components()
        .filter_map(|component| match component {
            Component::CurDir => None,
            Component::ParentDir => Some(Ok(RootfsPathComponent::Parent)),
            Component::Normal(name) => Some(Ok(RootfsPathComponent::Normal(name.to_os_string()))),
            Component::RootDir | Component::Prefix(_) => Some(Err(format!(
                "absolute symlink target {} cannot be traversed while applying a layer",
                path.display()
            ))),
        })
        .collect()
}

#[cfg(all(test, unix))]
mod tests {
    use super::{DirectoryMergePlan, LayerApplier, ResolvedDirectory};
    use std::ffi::OsStr;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn keeps_using_opened_directory_after_path_replacement() {
        let base = tempdir().unwrap();
        let rootfs = base.path().join("rootfs");
        let upper = base.path().join("upper");
        let outside = base.path().join("outside");
        fs::create_dir_all(rootfs.join("pivot")).unwrap();
        fs::create_dir_all(&upper).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(rootfs.join("pivot/victim"), "inside").unwrap();
        fs::write(outside.join("victim"), "outside").unwrap();
        fs::write(upper.join(".wh..wh..opq"), "").unwrap();
        fs::write(upper.join("payload"), "payload").unwrap();

        let applier = LayerApplier::new(&rootfs).unwrap();
        let root = ResolvedDirectory {
            fd: applier.open_root_dir().unwrap(),
            components: Vec::new(),
        };
        let DirectoryMergePlan::MergeDirectory(opened) = applier
            .plan_directory_merge(&root, OsStr::new("pivot"))
            .unwrap()
        else {
            panic!("expected an existing directory merge");
        };

        fs::rename(rootfs.join("pivot"), rootfs.join("detached")).unwrap();
        std::os::unix::fs::symlink(&outside, rootfs.join("pivot")).unwrap();
        applier.merge_directory(&upper, &opened).unwrap();

        assert_eq!(
            fs::read_to_string(outside.join("victim")).unwrap(),
            "outside"
        );
        assert!(!outside.join("payload").exists());
        assert_eq!(
            fs::read_to_string(rootfs.join("detached/payload")).unwrap(),
            "payload"
        );
        assert!(!rootfs.join("detached/victim").exists());
    }
}
