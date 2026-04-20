// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Apply OCI image layers in order into a flat rootfs tree, honoring whiteouts.
//!
//! OCI whiteout convention (see image-spec):
//! - A file named `.wh.<name>` in a layer means "delete <name>" from the tree.
//! - A file named `.wh..wh..opq` in a directory means "opaque directory" —
//!   delete all existing children of that directory before applying this
//!   layer's additions.

use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

const OPAQUE_MARKER: &str = ".wh..wh..opq";
const WHITEOUT_PREFIX: &str = ".wh.";

/// Apply a single gzip-compressed OCI layer tar stream into `dest`.
///
/// Whiteouts are honored against the existing contents of `dest`; the
/// markers themselves are never materialized.
pub fn apply_layer<R: Read>(dest: &Path, layer_reader: R) -> io::Result<()> {
    let gz = flate2::read::GzDecoder::new(layer_reader);
    apply_tar_stream(dest, gz)
}

/// Apply a layer whose bytes are in memory, dispatching on OCI media type.
///
/// Supports `tar` (uncompressed) and `tar+gzip`. Other encodings
/// (`tar+zstd`, `tar+bzip2`) are rejected — OCI v1.1 allows them but common
/// registries still use gzip.
pub fn apply_layer_bytes(dest: &Path, media_type: &str, bytes: &[u8]) -> io::Result<()> {
    let base = media_type.split(';').next().unwrap_or(media_type).trim();
    if base.ends_with("+gzip") || base.ends_with(".gzip") || base.ends_with(".tar.gzip") {
        apply_layer(dest, bytes)
    } else if base.ends_with(".tar") || base.ends_with("+tar") || base == "application/x-tar" {
        apply_tar_stream(dest, bytes)
    } else if base.ends_with("+zstd") {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported layer media type (zstd not supported in v1): {media_type}"),
        ))
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown layer media type: {media_type}"),
        ))
    }
}

/// Apply an uncompressed tar stream. Exposed for tests that build synthetic
/// layers in memory.
pub fn apply_tar_stream<R: Read>(dest: &Path, tar_reader: R) -> io::Result<()> {
    let mut archive = tar::Archive::new(tar_reader);
    archive.set_preserve_permissions(true);
    archive.set_preserve_mtime(true);
    archive.set_unpack_xattrs(false);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let entry_path = entry.path()?.into_owned();
        let Some(rel) = sanitize_relative(&entry_path) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("layer tar contains unsafe path: {}", entry_path.display()),
            ));
        };

        let Some(file_name) = rel.file_name().and_then(|n| n.to_str()) else {
            // skip entries we cannot reason about (e.g. `.` top-level)
            continue;
        };

        if file_name == OPAQUE_MARKER {
            let parent = rel.parent().unwrap_or(Path::new(""));
            clear_directory(&dest.join(parent))?;
            continue;
        }

        if let Some(target_name) = file_name.strip_prefix(WHITEOUT_PREFIX) {
            let parent = rel.parent().unwrap_or(Path::new(""));
            let target = dest.join(parent).join(target_name);
            remove_any(&target)?;
            continue;
        }

        let dest_path = dest.join(&rel);
        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent)?;
        }
        entry.unpack(&dest_path)?;
    }

    Ok(())
}

/// Reject absolute, parent-escaping, or root-component paths in layer tars.
fn sanitize_relative(path: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) | Component::ParentDir => return None,
        }
    }
    if out.as_os_str().is_empty() {
        return None;
    }
    Some(out)
}

fn clear_directory(path: &Path) -> io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        remove_any(&entry.path())?;
    }
    Ok(())
}

fn remove_any(path: &Path) -> io::Result<()> {
    match path.symlink_metadata() {
        Ok(meta) => {
            if meta.file_type().is_dir() {
                fs::remove_dir_all(path)
            } else {
                fs::remove_file(path)
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Build an in-memory tar stream from a list of (path, contents) pairs.
    /// Directories are created implicitly when their children have paths.
    fn build_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);
            for (path, contents) in entries {
                if path.ends_with('/') {
                    let mut header = tar::Header::new_gnu();
                    header.set_path(path).unwrap();
                    header.set_size(0);
                    header.set_mode(0o755);
                    header.set_entry_type(tar::EntryType::Directory);
                    header.set_cksum();
                    builder.append(&header, io::empty()).unwrap();
                } else {
                    let mut header = tar::Header::new_gnu();
                    header.set_path(path).unwrap();
                    header.set_size(contents.len() as u64);
                    header.set_mode(0o644);
                    header.set_entry_type(tar::EntryType::Regular);
                    header.set_cksum();
                    builder.append(&header, *contents).unwrap();
                }
            }
            builder.finish().unwrap();
        }
        buf
    }

    #[test]
    fn whiteout_removes_file_from_lower_layer() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        let lower = build_tar(&[("app/", b""), ("app/a.txt", b"a"), ("app/b.txt", b"b")]);
        apply_tar_stream(root, lower.as_slice()).unwrap();
        assert!(root.join("app/a.txt").exists());

        let upper = build_tar(&[("app/.wh.a.txt", b"")]);
        apply_tar_stream(root, upper.as_slice()).unwrap();

        assert!(!root.join("app/a.txt").exists(), "whiteout should remove a");
        assert!(root.join("app/b.txt").exists(), "b should still exist");
        assert!(
            !root.join("app/.wh.a.txt").exists(),
            "marker should not be materialized"
        );
    }

    #[test]
    fn opaque_whiteout_clears_directory_before_additions() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        let lower = build_tar(&[
            ("data/", b""),
            ("data/keep.txt", b"lower"),
            ("data/gone.txt", b"lower"),
        ]);
        apply_tar_stream(root, lower.as_slice()).unwrap();

        let upper = build_tar(&[
            ("data/", b""),
            ("data/.wh..wh..opq", b""),
            ("data/new.txt", b"upper"),
        ]);
        apply_tar_stream(root, upper.as_slice()).unwrap();

        assert!(!root.join("data/keep.txt").exists());
        assert!(!root.join("data/gone.txt").exists());
        assert!(root.join("data/new.txt").exists());
        assert_eq!(
            fs::read_to_string(root.join("data/new.txt")).unwrap(),
            "upper"
        );
    }

    #[test]
    fn whiteout_removes_directory_recursively() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        let lower = build_tar(&[
            ("dir/", b""),
            ("dir/a.txt", b"a"),
            ("dir/sub/", b""),
            ("dir/sub/b.txt", b"b"),
        ]);
        apply_tar_stream(root, lower.as_slice()).unwrap();

        let upper = build_tar(&[(".wh.dir", b"")]);
        apply_tar_stream(root, upper.as_slice()).unwrap();

        assert!(!root.join("dir").exists());
    }

    #[test]
    fn layers_apply_in_order_with_later_overwriting_earlier() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        apply_tar_stream(root, build_tar(&[("x.txt", b"v1")]).as_slice()).unwrap();
        apply_tar_stream(root, build_tar(&[("x.txt", b"v2")]).as_slice()).unwrap();
        assert_eq!(fs::read_to_string(root.join("x.txt")).unwrap(), "v2");
    }

    #[test]
    fn sanitize_relative_rejects_absolute_paths() {
        assert!(sanitize_relative(Path::new("/etc/passwd")).is_none());
    }

    #[test]
    fn sanitize_relative_rejects_parent_traversal() {
        assert!(sanitize_relative(Path::new("../escape.txt")).is_none());
        assert!(sanitize_relative(Path::new("a/../../etc/passwd")).is_none());
    }

    #[test]
    fn sanitize_relative_strips_curdir_and_keeps_clean_paths() {
        assert_eq!(
            sanitize_relative(Path::new("./etc/hosts")).unwrap(),
            PathBuf::from("etc/hosts")
        );
        assert_eq!(
            sanitize_relative(Path::new("app/bin/sh")).unwrap(),
            PathBuf::from("app/bin/sh")
        );
    }

    #[test]
    fn sanitize_relative_rejects_empty_and_root_only_paths() {
        assert!(sanitize_relative(Path::new("")).is_none());
        assert!(sanitize_relative(Path::new("/")).is_none());
    }

    #[test]
    fn apply_layer_bytes_dispatches_on_media_type() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        let tarball = build_tar(&[("plain.txt", b"v")]);
        apply_layer_bytes(root, "application/vnd.oci.image.layer.v1.tar", &tarball).unwrap();
        assert!(root.join("plain.txt").exists());

        let mut gz = Vec::new();
        {
            let mut enc = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::fast());
            enc.write_all(&build_tar(&[("gz.txt", b"v")])).unwrap();
            enc.finish().unwrap();
        }
        apply_layer_bytes(root, "application/vnd.oci.image.layer.v1.tar+gzip", &gz).unwrap();
        assert!(root.join("gz.txt").exists());
    }

    #[test]
    fn apply_layer_bytes_rejects_zstd_in_v1() {
        let tmp = tempfile::tempdir().unwrap();
        let err = apply_layer_bytes(
            tmp.path(),
            "application/vnd.oci.image.layer.v1.tar+zstd",
            b"",
        )
        .expect_err("zstd should be rejected");
        assert!(err.to_string().contains("zstd"));
    }

    #[test]
    fn apply_layer_bytes_rejects_unknown_media_type() {
        let tmp = tempfile::tempdir().unwrap();
        let err = apply_layer_bytes(tmp.path(), "application/bogus", b"")
            .expect_err("unknown media type should fail");
        assert!(err.to_string().contains("unknown"));
    }

    #[test]
    fn apply_layer_handles_gzip_streams() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let tarball = build_tar(&[("hello.txt", b"world")]);
        let mut gz = Vec::new();
        {
            let mut enc = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::fast());
            enc.write_all(&tarball).unwrap();
            enc.finish().unwrap();
        }
        apply_layer(root, gz.as_slice()).unwrap();
        assert_eq!(fs::read_to_string(root.join("hello.txt")).unwrap(), "world");
    }
}
