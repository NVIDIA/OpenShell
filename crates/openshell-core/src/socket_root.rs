// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Short private directories for Unix domain sockets.
//!
//! `sun_path` is 104 bytes on macOS, so a socket under a deep state directory
//! can fail to bind. Sockets that do not need to persist live in a short,
//! random, owner-only directory under `/tmp` instead.

use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

const ALLOC_RETRIES: usize = 16;

/// macOS `sun_path` is 104 bytes including the NUL terminator.
pub const MAX_SUN_PATH_LEN: usize = 103;

/// Create `/tmp/os-<euid>-<128-bit hex>` with mode `0700` and return it with
/// an open directory handle.
///
/// `/tmp` is hardcoded because macOS `TMPDIR` is already about 50 bytes long.
pub fn allocate() -> io::Result<(PathBuf, OwnedFd)> {
    let uid = rustix::process::geteuid().as_raw();
    allocate_in(Path::new("/tmp"), || {
        let random =
            u128::from_ne_bytes(openshell_crypto::random_bytes::<16>().map_err(io::Error::other)?);
        Ok(format!("os-{uid}-{random:032x}"))
    })
}

/// Create a new `0700` directory named by `gen_name` under `base`.
///
/// A name that already exists is never inspected or reused: a fresh name is
/// generated instead, so a pre-created entry cannot redirect the socket.
pub fn allocate_in(
    base: &Path,
    mut gen_name: impl FnMut() -> io::Result<String>,
) -> io::Result<(PathBuf, OwnedFd)> {
    for _ in 0..ALLOC_RETRIES {
        let root = base.join(gen_name()?);
        match rustix::fs::mkdir(&root, rustix::fs::Mode::from_raw_mode(0o700)) {
            Ok(()) => {
                let fd = rustix::fs::open(
                    &root,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::NOFOLLOW,
                    rustix::fs::Mode::empty(),
                )
                .map_err(io::Error::from)?;
                return Ok((root, fd));
            }
            Err(rustix::io::Errno::EXIST) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!(
            "failed to allocate socket root under {} after {ALLOC_RETRIES} attempts",
            base.display()
        ),
    ))
}

/// Reject a socket path that cannot be bound, naming the path, its length,
/// and the limit.
pub fn check_path_len(path: &Path) -> io::Result<()> {
    let len = path.as_os_str().len();
    if len > MAX_SUN_PATH_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "socket path {} is {len} bytes, over the {MAX_SUN_PATH_LEN} byte sun_path limit",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn allocate_returns_private_distinct_roots_that_fit_sun_path() {
        let (root_a, _fd_a) = allocate().unwrap();
        let (root_b, _fd_b) = allocate().unwrap();
        assert_ne!(root_a, root_b);
        for root in [&root_a, &root_b] {
            let mode = std::fs::metadata(root).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
            check_path_len(&root.join("compute-driver.sock")).unwrap();
            let _ = std::fs::remove_dir(root);
        }
    }

    #[test]
    fn worst_case_root_fits_macos_sun_path() {
        let worst_root = "/tmp/os-4294967295-00000000000000000000000000000000";
        let socket = Path::new(worst_root).join("compute-driver.sock");
        check_path_len(&socket).unwrap();
    }

    #[test]
    fn allocate_in_returns_distinct_roots() {
        let tmp = tempfile::tempdir().unwrap();
        let mut counter = 0u64;
        let mut name = || {
            counter += 1;
            Ok(format!("root-{counter}"))
        };
        let (root_a, _fd_a) = allocate_in(tmp.path(), &mut name).unwrap();
        let (root_b, _fd_b) = allocate_in(tmp.path(), &mut name).unwrap();
        assert_ne!(root_a, root_b);
    }

    #[test]
    fn allocate_in_retries_on_occupied_name() {
        let tmp = tempfile::tempdir().unwrap();
        let victim = tmp.path().join("victim");
        std::fs::create_dir(&victim).unwrap();
        let original_mode = std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777;

        // attempt-0: symlink to victim directory
        std::os::unix::fs::symlink(&victim, tmp.path().join("attempt-0")).unwrap();
        // attempt-1: existing directory (simulates foreign-owned pre-creation)
        std::fs::create_dir(tmp.path().join("attempt-1")).unwrap();

        let call_count = AtomicUsize::new(0);
        let (root, _fd) = allocate_in(tmp.path(), || {
            let n = call_count.fetch_add(1, Ordering::SeqCst);
            Ok(format!("attempt-{n}"))
        })
        .expect("should succeed after retries");

        assert_eq!(root, tmp.path().join("attempt-2"));
        assert_eq!(call_count.load(Ordering::SeqCst), 3);
        assert!(
            tmp.path()
                .join("attempt-0")
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink(),
            "pre-created symlink must not be removed"
        );
        assert!(
            tmp.path().join("attempt-1").exists(),
            "pre-created directory must not be removed"
        );
        let after_mode = std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            original_mode, after_mode,
            "victim directory permissions must not change"
        );
    }

    #[test]
    fn allocate_in_propagates_name_generation_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let err = allocate_in(tmp.path(), || {
            Err(io::Error::other(openshell_crypto::CryptoError::Random))
        })
        .expect_err("entropy failure must stop allocation");
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
    }

    #[test]
    fn allocate_in_exhaustion_returns_error() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("blocked")).unwrap();

        let err = allocate_in(tmp.path(), || Ok("blocked".to_string()))
            .expect_err("should fail when all names are occupied");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn check_path_len_names_path_length_and_limit() {
        let long = PathBuf::from(format!("/tmp/{}", "x".repeat(MAX_SUN_PATH_LEN)));
        let err = check_path_len(&long).expect_err("over-long path must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let message = err.to_string();
        assert!(message.contains(long.to_str().unwrap()), "{message}");
        assert!(message.contains(&format!("{} bytes", long.as_os_str().len())));
        assert!(message.contains(&MAX_SUN_PATH_LEN.to_string()), "{message}");
    }
}
