// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Validate CDI objects using the descriptors that will anchor Landlock rules.

use std::collections::BTreeMap;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};

use crate::launch::CdiDerivedRequirements;
use miette::{IntoDiagnostic, Result};
use rustix::fs::{FileType, fstat};

/// Deduplicated CDI paths and their combined validation requirements.
/// Stores no descriptors; target handles live only through validation and use.
#[derive(Default)]
pub(super) struct CdiPaths {
    paths: BTreeMap<PathBuf, TargetRequirements>,
}

// Each flag is an independent constraint; duplicate CDI uses of one path must
// all hold, so they are not collapsed into a single kind.
#[allow(clippy::struct_excessive_bools)]
#[derive(Default)]
struct TargetRequirements {
    device: bool,
    socket: bool,
    ipc_directory: bool,
    writable_mount: bool,
    mount_read_only: Option<bool>,
}

impl CdiPaths {
    pub(super) fn new(requirements: &CdiDerivedRequirements) -> Self {
        let mut paths = BTreeMap::<PathBuf, TargetRequirements>::new();
        for path in &requirements.read_only_paths {
            paths.entry(path.into()).or_default();
        }
        for path in &requirements.socket_paths {
            paths.entry(path.into()).or_default().socket = true;
        }
        for path in &requirements.device_node_paths {
            paths.entry(path.into()).or_default().device = true;
        }
        for path in &requirements.ipc_directory_paths {
            paths.entry(path.into()).or_default().ipc_directory = true;
        }
        for path in &requirements.read_write_mount_paths {
            paths.entry(path.into()).or_default().writable_mount = true;
        }
        for mount in &requirements.mounts {
            paths
                .entry((&mount.path).into())
                .or_default()
                .mount_read_only = Some(mount.read_only);
        }
        Self { paths }
    }

    pub(super) fn contains(&self, path: &Path) -> bool {
        self.paths.contains_key(path)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    /// Open, validate and consume one target at a time, including targets
    /// covered by authored ancestors. `apply` must install any matching rules
    /// using the supplied descriptor before this function closes it.
    /// Sockets are validated without inserting ordinary filesystem rules.
    /// Symlinks remain supported: validation applies to the opened object,
    /// without a canonicalize/reopen race.
    pub(super) fn process_validated<F: AsFd, S>(
        &self,
        mut state: S,
        mut open: impl FnMut(&Path) -> Result<F>,
        mut apply: impl FnMut(S, &Path, &F) -> Result<S>,
    ) -> Result<S> {
        if self.is_empty() {
            return Ok(state);
        }
        // Retain only root identities. Each root descriptor closes immediately.
        let mut broad_roots = Vec::new();
        for root in crate::cdi::FORBIDDEN_CDI_ROOTS {
            match open(Path::new(root)) {
                Ok(fd) => broad_roots.push(fstat(&fd).into_diagnostic()?),
                Err(_) if !Path::new(root).exists() => {}
                Err(error) => return Err(error),
            }
        }
        #[cfg(target_os = "linux")]
        let mount_table = self
            .paths
            .values()
            .any(|target| target.mount_read_only.is_some())
            .then(crate::cdi::CdiMountTable::read)
            .transpose()
            .into_diagnostic()?;
        for (path, requirements) in &self.paths {
            let fd = open(path)?;
            let stat = fstat(&fd).into_diagnostic()?;
            if broad_roots
                .iter()
                .any(|root| root.st_dev == stat.st_dev && root.st_ino == stat.st_ino)
            {
                return Err(miette::miette!(
                    "CDI path '{}' resolves to a forbidden broad root",
                    path.display()
                ));
            }
            let kind = FileType::from_raw_mode(stat.st_mode);
            if requirements.socket && kind != FileType::Socket {
                return Err(miette::miette!(
                    "CDI socket '{}' is not a Unix socket",
                    path.display()
                ));
            }
            if requirements.device
                && !matches!(kind, FileType::CharacterDevice | FileType::BlockDevice)
            {
                return Err(miette::miette!(
                    "CDI device '{}' is not a character or block device",
                    path.display()
                ));
            }
            if requirements.ipc_directory {
                validate_ipc_directory(path, &fd, kind)?;
            }
            if requirements.writable_mount || requirements.mount_read_only == Some(false) {
                return Err(miette::miette!(
                    "CDI writable mount '{}' is unsupported: ordinary host-backed file and directory mounts must be read-only",
                    path.display()
                ));
            }
            #[cfg(target_os = "linux")]
            if let Some(expected) = requirements.mount_read_only {
                let actual = mount_table
                    .as_ref()
                    .expect("mount table loaded")
                    .read_only(&path.to_string_lossy(), &fd)
                    .into_diagnostic()?;
                if actual != expected {
                    return Err(miette::miette!(
                        "CDI mount '{}' changed effective access before enforcement",
                        path.display()
                    ));
                }
            }
            if !requirements.socket {
                state = apply(state, path, &fd)?;
            }
            // The descriptor closes before the next target is opened. Landlock
            // retains its object reference after successful rule insertion.
        }
        Ok(state)
    }
}

/// IPC directories are writable host mounts, so require the kernel to report
/// the same restrictive flags the spec requested on the opened directory.
fn validate_ipc_directory<F: AsFd>(path: &Path, fd: &F, kind: FileType) -> Result<()> {
    if kind != FileType::Directory {
        return Err(miette::miette!(
            "CDI IPC directory '{}' is not a directory",
            path.display()
        ));
    }
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{StatVfsMountFlags, fstatvfs};
        let required =
            StatVfsMountFlags::NOSUID | StatVfsMountFlags::NODEV | StatVfsMountFlags::NOEXEC;
        let flags = fstatvfs(fd).into_diagnostic()?.f_flag;
        if !flags.contains(required) {
            return Err(miette::miette!(
                "CDI IPC directory '{}' must be mounted with nosuid, nodev and noexec",
                path.display()
            ));
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = fd;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::os::unix::fs::symlink;

    fn open(path: &Path) -> Result<File> {
        File::open(path).into_diagnostic()
    }

    fn validate(
        requirements: &CdiDerivedRequirements,
        open: impl FnMut(&Path) -> Result<File>,
    ) -> Result<()> {
        CdiPaths::new(requirements).process_validated((), open, |(), _, _| Ok(()))
    }

    fn read_only(path: &Path) -> CdiDerivedRequirements {
        CdiDerivedRequirements {
            read_only_paths: vec![path.to_string_lossy().into_owned()],
            ..Default::default()
        }
    }

    struct TrackedFd {
        file: File,
        live: std::rc::Rc<std::cell::Cell<usize>>,
    }

    impl AsFd for TrackedFd {
        fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
            self.file.as_fd()
        }
    }

    impl Drop for TrackedFd {
        fn drop(&mut self) {
            self.live.set(self.live.get() - 1);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn socket_targets_are_exact_and_revalidated_without_filesystem_rules() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("socket");
        let _listener = std::os::unix::net::UnixListener::bind(&target).unwrap();
        let requirements = CdiDerivedRequirements {
            socket_paths: vec![target.to_string_lossy().into_owned()],
            ..Default::default()
        };
        let paths = CdiPaths::new(&requirements);
        assert!(paths.contains(&target));
        assert!(!paths.contains(temp.path()));
        let open_socket = |path: &Path| {
            rustix::fs::open(
                path,
                rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .into_diagnostic()
        };
        paths
            .process_validated((), open_socket, |(), _, _| {
                panic!("socket must not add a filesystem rule")
            })
            .unwrap();
        std::fs::remove_file(&target).unwrap();
        std::fs::write(&target, "replacement").unwrap();
        assert!(
            paths
                .process_validated((), open_socket, |(), _, _| Ok(()))
                .unwrap_err()
                .to_string()
                .contains("not a Unix socket")
        );
    }

    #[test]
    fn deduplicates_paths_and_keeps_one_descriptor_live() {
        let temp = tempfile::tempdir().unwrap();
        let mut requirements = CdiDerivedRequirements::default();
        for index in 0..512 {
            let path = temp.path().join(format!("file-{index}"));
            std::fs::write(&path, "").unwrap();
            let path = path.to_string_lossy().into_owned();
            requirements.read_only_paths.extend([path.clone(), path]);
        }
        let paths = CdiPaths::new(&requirements);
        assert!(paths.contains(&temp.path().join("file-0")));
        let live = std::rc::Rc::new(std::cell::Cell::new(0));
        let processed = paths
            .process_validated(
                0,
                |path| {
                    // No earlier target (or root) descriptor may survive this open.
                    assert_eq!(live.get(), 0);
                    let file = open(path)?;
                    live.set(live.get() + 1);
                    Ok(TrackedFd {
                        file,
                        live: std::rc::Rc::clone(&live),
                    })
                },
                |count, _, fd| {
                    assert_eq!(live.get(), 1);
                    assert_eq!(
                        FileType::from_raw_mode(fstat(fd).unwrap().st_mode),
                        FileType::RegularFile
                    );
                    Ok(count + 1)
                },
            )
            .unwrap();
        assert_eq!(processed, 512);
        assert_eq!(live.get(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rechecks_effective_mount_access_on_the_consumed_descriptor() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        std::fs::write(&target, "").unwrap();
        let requirements = CdiDerivedRequirements {
            mounts: vec![crate::launch::CdiMountRequirement {
                path: target.to_string_lossy().into_owned(),
                read_only: true,
            }],
            ..Default::default()
        };
        let error = validate(&requirements, open).unwrap_err();
        assert!(error.to_string().contains("changed effective access"));
    }

    #[test]
    fn retains_all_constraints_for_duplicate_paths() {
        let requirements = CdiDerivedRequirements {
            read_only_paths: vec!["/dev/null".into()],
            device_node_paths: vec!["/dev/null".into()],
            read_write_mount_paths: vec!["/dev/null".into()],
            ..Default::default()
        };
        // Valid as a device but invalid as an ordinary writable mount.
        let error = validate(&requirements, open).unwrap_err();
        assert!(error.to_string().contains("CDI writable mount"));
    }

    #[test]
    fn closes_descriptor_when_consumer_fails() {
        let temp = tempfile::tempdir().unwrap();
        let live = std::rc::Rc::new(std::cell::Cell::new(0));
        let paths = CdiPaths::new(&read_only(temp.path()));
        let result = paths.process_validated(
            (),
            |path| {
                assert_eq!(live.get(), 0);
                let file = open(path)?;
                live.set(live.get() + 1);
                Ok(TrackedFd {
                    file,
                    live: std::rc::Rc::clone(&live),
                })
            },
            |(), _, _| Err(miette::miette!("rule insertion failed")),
        );
        assert!(result.is_err());
        assert_eq!(live.get(), 0);
    }

    #[test]
    fn rejects_symlink_aliases_to_broad_roots() {
        let temp = tempfile::tempdir().unwrap();
        let alias = temp.path().join("library-parent");
        for root in crate::cdi::FORBIDDEN_CDI_ROOTS {
            if !Path::new(root).exists() {
                continue;
            }
            symlink(root, &alias).unwrap();
            assert!(
                validate(&read_only(&alias), open)
                    .unwrap_err()
                    .to_string()
                    .contains("broad root")
            );
            std::fs::remove_file(&alias).unwrap();
        }
    }

    #[test]
    fn allows_library_directory_symlinks() {
        let temp = tempfile::tempdir().unwrap();
        let library = temp.path().join("lib");
        std::fs::create_dir(&library).unwrap();
        let alias = temp.path().join("alias");
        symlink(&library, &alias).unwrap();
        assert!(validate(&read_only(&alias), open).is_ok());
    }

    #[test]
    fn validates_types_on_opened_objects() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("fake-device");
        std::fs::write(&file, "").unwrap();
        let requirements = CdiDerivedRequirements {
            device_node_paths: vec![file.to_string_lossy().into_owned()],
            ..Default::default()
        };
        assert!(validate(&requirements, open).is_err());
        let requirements = CdiDerivedRequirements {
            read_write_mount_paths: vec![temp.path().to_string_lossy().into_owned()],
            ..Default::default()
        };
        assert!(validate(&requirements, open).is_err());
        let requirements = CdiDerivedRequirements {
            read_write_mount_paths: vec![file.to_string_lossy().into_owned()],
            ..Default::default()
        };
        assert!(validate(&requirements, open).is_err());
        // Read-only targets still have to exist when enforcement opens them.
        let missing = temp.path().join("missing");
        assert!(validate(&read_only(&missing), open).is_err());
        let requirements = CdiDerivedRequirements {
            device_node_paths: vec!["/dev/null".into()],
            ..Default::default()
        };
        assert!(validate(&requirements, open).is_ok());
    }

    fn ipc_directory(path: &Path) -> CdiDerivedRequirements {
        CdiDerivedRequirements {
            ipc_directory_paths: vec![path.to_string_lossy().into_owned()],
            ..Default::default()
        }
    }

    #[test]
    fn ipc_directories_must_be_directories() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("nvidia-mps");
        std::fs::write(&file, "").unwrap();
        let error = validate(&ipc_directory(&file), open).unwrap_err();
        assert!(error.to_string().contains("not a directory"), "{error}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ipc_directories_require_effective_nosuid_nodev_noexec() {
        use rustix::fs::{StatVfsMountFlags, statvfs};
        let required =
            StatVfsMountFlags::NOSUID | StatVfsMountFlags::NODEV | StatVfsMountFlags::NOEXEC;
        let temp = tempfile::tempdir().unwrap();
        let result = validate(&ipc_directory(temp.path()), open);
        if statvfs(temp.path()).unwrap().f_flag.contains(required) {
            result.unwrap();
        } else {
            let error = result.unwrap_err();
            assert!(
                error.to_string().contains("nosuid, nodev and noexec"),
                "{error}"
            );
        }
        // Container /dev/shm is normally mounted nosuid,nodev,noexec.
        let shm = Path::new("/dev/shm");
        if shm.is_dir() && statvfs(shm).unwrap().f_flag.contains(required) {
            let pipes = tempfile::tempdir_in(shm).unwrap();
            validate(&ipc_directory(pipes.path()), open).unwrap();
        }
    }

    #[test]
    fn pins_target_across_swap_and_revalidates_next_launch() {
        let temp = tempfile::tempdir().unwrap();
        let library = temp.path().join("lib");
        std::fs::create_dir(&library).unwrap();
        let alias = temp.path().join("alias");
        symlink(&library, &alias).unwrap();
        let requirements = read_only(&alias);
        let expected = fstat(File::open(&library).unwrap()).unwrap();
        let pinned = CdiPaths::new(&requirements)
            .process_validated(
                None,
                |path| {
                    let fd = open(path)?;
                    if path == alias {
                        std::fs::remove_file(&alias).unwrap();
                        symlink("/", &alias).unwrap();
                    }
                    Ok(fd)
                },
                |_, path, fd| {
                    assert_eq!(path, alias);
                    Ok(Some(fstat(fd).unwrap()))
                },
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            (pinned.st_dev, pinned.st_ino),
            (expected.st_dev, expected.st_ino)
        );
        // Exec clones preserve provenance and prepare fresh rules, so the new
        // alias must be rejected rather than using earlier pathname validation.
        assert!(validate(&requirements, open).is_err());
    }
}
