// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Preloadable peer-address shim for legacy seccomp listeners.
//!
//! See `src/accept_shim.c` and this crate's README for why the shim exists.
//! The compiled object is embedded here so the sandbox can materialize it
//! into a workload whose image it does not control.

/// File name used when the shim is materialized into a workload.
pub const FILE_NAME: &str = "accept_shim.so";

/// Environment variable the workload's dynamic loader reads.
pub const PRELOAD_ENV: &str = "LD_PRELOAD";

/// The compiled shared object for this build's target architecture.
#[cfg(target_os = "linux")]
pub const SHIM_OBJECT: &[u8] = include_bytes!(env!("OPENSHELL_ACCEPT_SHIM"));

/// Directory the shim is materialized into inside the workload.
///
/// This deliberately sits outside the driver-owned `/.openshell` hierarchy,
/// which the capability-free Landlock baseline never exposes to a workload.
/// The dynamic loader must be able to open and map the object, so it also has
/// to live outside the `noexec` tmpfs mounts that carry supervisor material.
pub const RUNTIME_DIR: &str = "/run/openshell-compat";

/// Materialize an object into `directory` as a read-only executable file.
///
/// The target rootfs is writable by the workload, so every component is
/// checked for symlink redirection and the file is created with `O_NOFOLLOW`
/// before being renamed into place. The shim is a compatibility aid rather
/// than a security control — a workload can always decline to load it — but
/// installing it must still never write through a path the workload chose.
#[cfg(unix)]
pub fn install_object_at(
    directory: &std::path::Path,
    contents: &[u8],
) -> Result<std::path::PathBuf, String> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    match std::fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(format!(
                "shim directory is a symlink: {}",
                directory.display()
            ));
        }
        Ok(metadata) if !metadata.is_dir() => {
            return Err(format!(
                "shim directory is not a directory: {}",
                directory.display()
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(directory).map_err(|error| {
                format!("create shim directory {}: {error}", directory.display())
            })?;
        }
        Err(error) => {
            return Err(format!(
                "inspect shim directory {}: {error}",
                directory.display()
            ));
        }
    }
    // Writable for the install itself; tightened to read-only below. The
    // sandbox is not necessarily root, so the owner write bit is required
    // here even on a freshly created directory.
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o755))
        .map_err(|error| format!("set shim directory permissions: {error}"))?;

    let path = directory.join(FILE_NAME);
    if let Ok(metadata) = std::fs::symlink_metadata(&path)
        && metadata.file_type().is_symlink()
    {
        return Err(format!("shim path is a symlink: {}", path.display()));
    }

    let temporary = path.with_extension("tmp");
    if let Ok(metadata) = std::fs::symlink_metadata(&temporary) {
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(format!(
                "refusing unsafe temporary shim path: {}",
                temporary.display()
            ));
        }
        std::fs::remove_file(&temporary)
            .map_err(|error| format!("remove stale temporary shim: {error}"))?;
    }

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o555)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|error| format!("create temporary shim: {error}"))?;
    if let Err(error) = file
        .write_all(contents)
        .and_then(|()| file.sync_all())
        .and_then(|()| file.set_permissions(std::fs::Permissions::from_mode(0o555)))
        .and_then(|()| std::fs::rename(&temporary, &path))
    {
        let _ = std::fs::remove_file(&temporary);
        return Err(format!("install shim: {error}"));
    }
    // Traversable and readable by every workload identity, writable by none.
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o555))
        .map_err(|error| format!("seal shim directory permissions: {error}"))?;
    Ok(path)
}

/// Materialize the embedded shim into [`RUNTIME_DIR`].
#[cfg(target_os = "linux")]
pub fn install_shim() -> Result<std::path::PathBuf, String> {
    install_object_at(std::path::Path::new(RUNTIME_DIR), SHIM_OBJECT)
}

/// Compose an `LD_PRELOAD` value that keeps any workload-supplied entries.
///
/// The shim is placed first so it wins symbol resolution, and an existing
/// value is preserved rather than replaced: a workload that relies on its own
/// preload must keep working.
#[must_use]
pub fn compose_preload(shim_path: &str, existing: Option<&str>) -> String {
    match existing.map(str::trim).filter(|value| !value.is_empty()) {
        Some(existing) if preload_contains(existing, shim_path) => existing.to_string(),
        Some(existing) => format!("{shim_path}:{existing}"),
        None => shim_path.to_string(),
    }
}

/// Whether an `LD_PRELOAD` value already lists a path.
///
/// The loader separates entries by colon or whitespace, so both are honored.
fn preload_contains(value: &str, path: &str) -> bool {
    value
        .split([':', ' ', '\t'])
        .any(|entry| !entry.is_empty() && entry == path)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    /// The object is produced by a C compiler chosen at build time, so a
    /// misresolved cross-compiler yields a host-architecture object that the
    /// workload's loader rejects with a message that reads like a policy
    /// denial. Pin the shape of what actually got embedded.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_embedded_object_is_a_shared_object_for_the_build_target() {
        let expected_machine: u16 = if cfg!(target_arch = "x86_64") {
            0x3e // EM_X86_64
        } else if cfg!(target_arch = "aarch64") {
            0xb7 // EM_AARCH64
        } else {
            panic!("unsupported architecture for the accept shim");
        };

        let header = SHIM_OBJECT;
        assert!(header.len() > 20, "object is too short to be an ELF file");
        assert_eq!(&header[0..4], b"\x7fELF", "not an ELF object");
        assert_eq!(header[4], 2, "expected ELFCLASS64");
        assert_eq!(header[5], 1, "expected little-endian ELF");
        assert_eq!(
            u16::from_le_bytes([header[16], header[17]]),
            3,
            "expected ET_DYN; a non-shared object cannot be preloaded"
        );
        assert_eq!(
            u16::from_le_bytes([header[18], header[19]]),
            expected_machine,
            "object architecture does not match the build target"
        );
    }

    #[cfg(unix)]
    fn scratch_dir(name: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!("openshell-accept-shim-{name}"));
        let _ = std::fs::remove_dir_all(&base);
        base
    }

    #[test]
    #[cfg(unix)]
    fn installing_creates_a_read_only_executable_object() {
        let directory = scratch_dir("install");
        let installed = install_object_at(&directory, b"shim-bytes").expect("install");

        assert_eq!(installed, directory.join(FILE_NAME));
        assert_eq!(std::fs::read(&installed).expect("read"), b"shim-bytes");
        // The workload must be able to map it executable but never rewrite it.
        let mode = std::fs::metadata(&installed)
            .expect("stat")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o555);
    }

    #[test]
    #[cfg(unix)]
    fn installing_twice_replaces_the_previous_object() {
        // A sandbox restart re-materializes into a directory that may already
        // hold a previous generation of the shim.
        let directory = scratch_dir("reinstall");
        install_object_at(&directory, b"old").expect("first install");
        let installed = install_object_at(&directory, b"new").expect("second install");

        assert_eq!(std::fs::read(&installed).expect("read"), b"new");
        assert_eq!(
            std::fs::metadata(&installed)
                .expect("stat")
                .permissions()
                .mode()
                & 0o777,
            0o555
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_symlinked_directory_is_refused() {
        // The directory lives on a workload-writable rootfs, so a redirect
        // must never be followed into a path the workload chose.
        let base = scratch_dir("symlink-dir");
        std::fs::create_dir_all(base.join("real")).expect("create real");
        let link = base.join("link");
        std::os::unix::fs::symlink(base.join("real"), &link).expect("symlink");

        let error = install_object_at(&link, b"shim-bytes").expect_err("must refuse");
        assert!(error.contains("symlink"), "unexpected error: {error}");
    }

    #[test]
    #[cfg(unix)]
    fn a_symlinked_target_file_is_refused() {
        let directory = scratch_dir("symlink-file");
        std::fs::create_dir_all(&directory).expect("create");
        let target = directory.join("elsewhere");
        std::fs::write(&target, b"victim").expect("write victim");
        std::os::unix::fs::symlink(&target, directory.join(FILE_NAME)).expect("symlink");

        let error = install_object_at(&directory, b"shim-bytes").expect_err("must refuse");
        assert!(error.contains("symlink"), "unexpected error: {error}");
        assert_eq!(std::fs::read(&target).expect("read"), b"victim");
    }

    #[test]
    fn preload_is_the_only_entry_when_the_workload_set_none() {
        assert_eq!(compose_preload("/run/shim.so", None), "/run/shim.so");
        assert_eq!(compose_preload("/run/shim.so", Some("")), "/run/shim.so");
        assert_eq!(compose_preload("/run/shim.so", Some("   ")), "/run/shim.so");
    }

    #[test]
    fn workload_supplied_preloads_are_kept_after_the_shim() {
        assert_eq!(
            compose_preload("/run/shim.so", Some("/opt/jemalloc.so")),
            "/run/shim.so:/opt/jemalloc.so"
        );
        assert_eq!(
            compose_preload("/run/shim.so", Some("/a.so:/b.so")),
            "/run/shim.so:/a.so:/b.so"
        );
    }

    #[test]
    fn an_already_listed_shim_is_not_added_twice() {
        // Children re-inherit the composed value; repeated spawns must not
        // grow LD_PRELOAD without bound.
        assert_eq!(
            compose_preload("/run/shim.so", Some("/run/shim.so")),
            "/run/shim.so"
        );
        assert_eq!(
            compose_preload("/run/shim.so", Some("/run/shim.so:/b.so")),
            "/run/shim.so:/b.so"
        );
        assert_eq!(
            compose_preload("/run/shim.so", Some("/a.so /run/shim.so")),
            "/a.so /run/shim.so"
        );
    }

    #[test]
    fn a_path_that_merely_shares_a_prefix_is_not_treated_as_present() {
        assert_eq!(
            compose_preload("/run/shim.so", Some("/run/shim.so.bak")),
            "/run/shim.so:/run/shim.so.bak"
        );
    }
}
