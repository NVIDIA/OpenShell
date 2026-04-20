// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Helpers for per-sandbox state disks and host-to-guest import sockets
//! used by the OCI container execution path.

#![allow(unsafe_code)]

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

/// Default raw state disk size when the driver has not been given an override.
/// Sparse-allocated; only actual writes consume space.
pub const DEFAULT_STATE_DISK_SIZE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// libkrun block ID the guest init script uses to locate the state disk.
pub const STATE_DISK_BLOCK_ID: &str = "sandbox-state";

/// vsock port used for one-shot OCI payload import.
pub const IMPORT_VSOCK_PORT: u32 = 10778;

/// Layout of per-sandbox state-disk and import-socket paths.
#[derive(Debug, Clone)]
pub struct SandboxStatePaths {
    /// Raw sparse disk image attached to the VM.
    pub state_disk: PathBuf,
    /// Host Unix socket bridged to the guest on [`IMPORT_VSOCK_PORT`].
    pub import_socket: PathBuf,
}

impl SandboxStatePaths {
    #[must_use]
    pub fn for_state_dir(state_dir: &Path) -> Self {
        Self {
            state_disk: state_dir.join("sandbox-state.raw"),
            import_socket: state_dir.join("oci-import.sock"),
        }
    }
}

/// Create (or grow to size) the sparse raw state disk image.
pub fn ensure_state_disk(path: &Path, size_bytes: u64) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;

    let current = file.metadata()?.len();
    if current < size_bytes {
        file.set_len(size_bytes)?;
    }
    Ok(())
}

/// Prepare the import-socket parent directory and remove any stale socket file.
///
/// The parent directory is created with `0700`. If it already exists, it must
/// not be a symlink and must be owned by the current uid, otherwise we refuse
/// to use it — a tampered path would let an unprivileged user substitute the
/// socket before the VM connects to it.
pub fn prepare_import_socket_dir(socket_path: &Path) -> io::Result<()> {
    let parent = socket_path
        .parent()
        .ok_or_else(|| io::Error::other("import socket path has no parent directory"))?;

    if parent.exists() {
        let meta = parent.symlink_metadata()?;
        if meta.file_type().is_symlink() {
            return Err(io::Error::other(format!(
                "import socket directory {} is a symlink; refusing to use it",
                parent.display()
            )));
        }
        check_owner_and_mode(parent, &meta)?;
    } else {
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }

    match fs::remove_file(socket_path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

/// Verify that `path` is owned by the current uid and has a mode of `0o700`
/// or stricter. Returns an error if either check fails.
pub fn verify_import_socket_path(path: &Path) -> io::Result<()> {
    let meta = path.symlink_metadata()?;
    if meta.file_type().is_symlink() {
        return Err(io::Error::other(format!(
            "import socket path {} is a symlink; refusing to use it",
            path.display()
        )));
    }
    check_owner(path, &meta)?;

    if let Some(parent) = path.parent() {
        let parent_meta = parent.symlink_metadata()?;
        if parent_meta.file_type().is_symlink() {
            return Err(io::Error::other(format!(
                "import socket directory {} is a symlink; refusing to use it",
                parent.display()
            )));
        }
        check_owner_and_mode(parent, &parent_meta)?;
    }
    Ok(())
}

#[cfg(unix)]
fn check_owner_and_mode(path: &Path, meta: &fs::Metadata) -> io::Result<()> {
    check_owner(path, meta)?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(io::Error::other(format!(
            "import socket directory {} has permissions {:o}; expected 0700",
            path.display(),
            mode
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_owner_and_mode(_path: &Path, _meta: &fs::Metadata) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn check_owner(path: &Path, meta: &fs::Metadata) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let uid = unsafe { libc::getuid() };
    if meta.uid() != uid {
        return Err(io::Error::other(format!(
            "{} is owned by uid {} but we are uid {}",
            path.display(),
            meta.uid(),
            uid
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_owner(_path: &Path, _meta: &fs::Metadata) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let suffix = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "openshell-state-disk-test-{}-{nanos}-{suffix}",
            std::process::id()
        ))
    }

    #[test]
    fn sandbox_state_paths_places_files_inside_state_dir() {
        let paths = SandboxStatePaths::for_state_dir(Path::new("/srv/state/abc"));
        assert_eq!(
            paths.state_disk,
            Path::new("/srv/state/abc/sandbox-state.raw")
        );
        assert_eq!(
            paths.import_socket,
            Path::new("/srv/state/abc/oci-import.sock")
        );
    }

    #[test]
    fn ensure_state_disk_creates_sparse_file_of_requested_size() {
        let dir = unique_temp_dir();
        let disk = dir.join("state.raw");
        ensure_state_disk(&disk, 1024 * 1024).expect("create disk");
        let meta = fs::metadata(&disk).expect("stat disk");
        assert_eq!(meta.len(), 1024 * 1024);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_state_disk_grows_but_does_not_shrink() {
        let dir = unique_temp_dir();
        let disk = dir.join("state.raw");
        ensure_state_disk(&disk, 4096).expect("initial");
        ensure_state_disk(&disk, 8192).expect("grow");
        assert_eq!(fs::metadata(&disk).unwrap().len(), 8192);
        ensure_state_disk(&disk, 2048).expect("shrink noop");
        assert_eq!(fs::metadata(&disk).unwrap().len(), 8192);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn prepare_import_socket_dir_creates_0700_dir_when_absent() {
        let base = unique_temp_dir();
        let sock = base.join("oci-import.sock");
        prepare_import_socket_dir(&sock).expect("prepare");
        let meta = fs::metadata(&base).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn prepare_import_socket_dir_removes_stale_socket_file() {
        let base = unique_temp_dir();
        fs::create_dir_all(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        let sock = base.join("oci-import.sock");
        fs::write(&sock, b"stale").unwrap();

        prepare_import_socket_dir(&sock).expect("prepare");
        assert!(!sock.exists(), "stale socket should be removed");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn prepare_import_socket_dir_rejects_world_writable_dir() {
        let base = unique_temp_dir();
        fs::create_dir_all(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o755)).unwrap();
        let sock = base.join("oci-import.sock");
        let err = prepare_import_socket_dir(&sock).expect_err("loose dir should be rejected");
        assert!(err.to_string().contains("permissions"));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn verify_import_socket_path_rejects_symlink() {
        let base = unique_temp_dir();
        fs::create_dir_all(&base).unwrap();
        let target = base.join("real.sock");
        fs::write(&target, b"").unwrap();
        let link = base.join("oci-import.sock");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err =
            verify_import_socket_path(&link).expect_err("symlinked socket should be rejected");
        assert!(err.to_string().contains("symlink"));
        let _ = fs::remove_dir_all(&base);
    }
}
