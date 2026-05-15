// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::path::{Path, PathBuf};

const PROTO_REL: &str = "../../proto";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- Git-derived version ---
    // Compute a version from `git describe` for local builds. In Docker/CI
    // builds where .git is absent, this silently does nothing and the binary
    // falls back to CARGO_PKG_VERSION (which is already sed-patched by the
    // build pipeline).
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs/tags");

    if let Some(version) = git_version() {
        println!("cargo:rustc-env=OPENSHELL_GIT_VERSION={version}");
    }

    // --- Protobuf compilation ---
    // Re-run when anything under proto/ changes (including newly added .proto files).
    println!("cargo:rerun-if-changed={PROTO_REL}");
    // Use bundled protoc from protobuf-src.  The system protoc (from apt-get)
    // does not bundle the well-known type includes (google/protobuf/struct.proto
    // etc.), so we must use protobuf-src which ships both the binary and the
    // include tree.
    // SAFETY: This is run at build time in a single-threaded build script context.
    // No other threads are reading environment variables concurrently.
    #[allow(unsafe_code)]
    unsafe {
        env::set_var("PROTOC", protobuf_src::protoc());
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let proto_root = manifest_dir.join(PROTO_REL);

    let mut proto_files = Vec::new();
    collect_proto_files(&proto_root, &mut proto_files)?;
    proto_files.sort();

    // Configure tonic-build
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&proto_files, &[proto_root.as_path()])?;

    Ok(())
}

fn collect_proto_files(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_proto_files(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "proto") {
            out.push(path);
        }
    }
    Ok(())
}

/// Derive a version string from `git describe --tags`.
///
/// Implements the "guess-next-dev" convention used by the release pipeline
/// (`setuptools-scm`): when there are commits past the last tag, the patch
/// version is bumped and `-dev.<N>+g<sha>` is appended.
///
/// Examples:
///   on tag v0.0.3          → "0.0.3"
///   3 commits past v0.0.3  → "0.0.4-dev.3+g2bf9969"
///
/// Returns `None` when git is unavailable or the repo has no matching tags.
fn git_version() -> Option<String> {
    // Match numeric release tags only (e.g. `v0.0.29`). The bare glob `v*`
    // also matches non-release tags like `vm-dev` or `vm-prod`; when one of
    // those lands on the same commit as a release tag, `git describe` picks
    // it and the resulting version string collapses to `m-dev` after the
    // leading `v` is stripped below. Requiring a digit after `v` excludes
    // those development tags without losing any release tag.
    let output = std::process::Command::new("git")
        .args(["describe", "--tags", "--long", "--match", "v[0-9]*"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let desc = String::from_utf8(output.stdout).ok()?;
    let desc = desc.trim();
    let desc = desc.strip_prefix('v').unwrap_or(desc);

    // `git describe --long` format: <tag>-<N>-g<sha>
    // Split from the right to handle tags that contain hyphens.
    let (rest, sha) = desc.rsplit_once('-')?;
    let (tag, commits_str) = rest.rsplit_once('-')?;
    let commits: u32 = commits_str.parse().ok()?;

    if commits == 0 {
        // Exactly on a tag — use the tag version as-is.
        return Some(tag.to_string());
    }

    // Bump patch version (guess-next-dev scheme).
    let mut parts = tag.splitn(3, '.');
    let major = parts.next()?;
    let minor = parts.next()?;
    let patch: u32 = parts.next()?.parse().ok()?;

    Some(format!("{major}.{minor}.{}-dev.{commits}+{sha}", patch + 1))
}
