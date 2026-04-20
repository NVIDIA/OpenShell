// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Build a read-only squashfs image from a flattened rootfs tree.
//!
//! Shell out to `mksquashfs`. The binary is expected to ship with the VM
//! runtime bundle under `<runtime-dir>/mksquashfs`; callers pass an explicit
//! path so the build is reproducible and does not depend on `$PATH`.

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Options for building a squashfs image.
#[derive(Debug, Clone)]
pub struct BuildOptions {
    /// Path to the `mksquashfs` binary.
    pub mksquashfs: PathBuf,
    /// Compression algorithm passed via `-comp`.
    pub compression: Compression,
    /// Optional extra flags forwarded verbatim (e.g. `-no-xattrs`).
    pub extra_args: Vec<String>,
}

impl BuildOptions {
    #[must_use]
    pub fn with_binary(mksquashfs: PathBuf) -> Self {
        Self {
            mksquashfs,
            compression: Compression::Zstd,
            extra_args: Vec::new(),
        }
    }
}

/// Compression algorithm for squashfs builds. `zstd` is the default; it has
/// the best decompression-speed-vs-ratio tradeoff for cold-start latency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    Zstd,
    Gzip,
    Xz,
}

impl Compression {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Zstd => "zstd",
            Self::Gzip => "gzip",
            Self::Xz => "xz",
        }
    }
}

/// Build a squashfs image from `source_dir` into `dest` using `options`.
///
/// Returns an `io::Error` if the `mksquashfs` binary is missing or exits
/// non-zero. Callers are responsible for placing the result in the cache
/// via [`super::cache::CacheLayout::install_fs_image`].
pub fn build(source_dir: &Path, dest: &Path, options: &BuildOptions) -> io::Result<()> {
    if !options.mksquashfs.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "mksquashfs binary not found at {}",
                options.mksquashfs.display()
            ),
        ));
    }
    if !source_dir.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("source tree not found at {}", source_dir.display()),
        ));
    }

    if dest.exists() {
        std::fs::remove_file(dest)?;
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut cmd = Command::new(&options.mksquashfs);
    cmd.arg(source_dir)
        .arg(dest)
        .arg("-noappend")
        .arg("-quiet")
        .arg("-comp")
        .arg(options.compression.as_str());
    for arg in &options.extra_args {
        cmd.arg(arg);
    }
    cmd.stdin(Stdio::null());

    let output = cmd.output().map_err(|err| {
        io::Error::other(format!(
            "spawn mksquashfs {}: {err}",
            options.mksquashfs.display()
        ))
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::other(format!(
            "mksquashfs failed (status {}): {}",
            output.status,
            stderr.trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_fails_when_mksquashfs_is_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("src");
        std::fs::create_dir_all(&source).unwrap();
        let dest = tmp.path().join("out.squashfs");

        let options = BuildOptions::with_binary(tmp.path().join("missing-mksquashfs"));
        let err = build(&source, &dest, &options).expect_err("missing binary should fail");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn build_fails_when_source_tree_is_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let fake_bin = tmp.path().join("mksquashfs");
        std::fs::write(&fake_bin, "").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&fake_bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let options = BuildOptions::with_binary(fake_bin);
        let err = build(
            &tmp.path().join("missing-src"),
            &tmp.path().join("out.squashfs"),
            &options,
        )
        .expect_err("missing source should fail");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn compression_tag_matches_mksquashfs_flag_values() {
        assert_eq!(Compression::Zstd.as_str(), "zstd");
        assert_eq!(Compression::Gzip.as_str(), "gzip");
        assert_eq!(Compression::Xz.as_str(), "xz");
    }
}
