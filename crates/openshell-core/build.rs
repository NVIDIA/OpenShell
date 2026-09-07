// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::path::{Path, PathBuf};

mod build_version;

const PROTO_REL: &str = "../../proto";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- Git-derived version ---
    // Compute a version from tags and commit metadata for local builds. In
    // Docker/CI builds where .git is absent, this silently does nothing and
    // the binary falls back to CARGO_PKG_VERSION (which is already sed-patched
    // by the build pipeline).
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/logs/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs/tags");
    println!("cargo:rerun-if-changed=../../.git/packed-refs");

    if let Some(version) = git_version() {
        println!("cargo:rustc-env=OPENSHELL_GIT_VERSION={version}");
    }

    // --- Protobuf compilation ---
    // Re-run when anything under proto/ changes (including newly added .proto files).
    println!("cargo:rerun-if-changed={PROTO_REL}");
    // Use a vendored protoc binary and include tree. System protoc installs
    // often omit the well-known type includes (google/protobuf/struct.proto,
    // etc.), and protobuf-src requires autotools/sh which breaks MSVC builds.
    // SAFETY: This is run at build time in a single-threaded build script context.
    // No other threads are reading environment variables concurrently.
    #[allow(unsafe_code)]
    unsafe {
        env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
        env::set_var("PROTOC_INCLUDE", protoc_bin_vendored::include_path()?);
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let proto_root = manifest_dir.join(PROTO_REL);
    let mut proto_files = Vec::new();
    collect_proto_files(&proto_root, &mut proto_files)?;
    proto_files.sort();

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let descriptor_path = out_dir.join("openshell_descriptor.bin");

    // Configure tonic/prost protobuf code generation.
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .include_file("openshell.rs")
        // Emit a binary FileDescriptorSet so the server can enumerate every
        // RPC at runtime (used by the per-handler auth exhaustiveness test).
        .file_descriptor_set_path(&descriptor_path)
        .compile_protos(&proto_files, &[proto_root])?;

    println!(
        "cargo:rustc-env=OPENSHELL_DESCRIPTOR_PATH={}",
        descriptor_path.display()
    );

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

/// Derive the release or development version from git metadata.
///
/// Implements the "guess-next-dev" convention used by the release pipeline
/// (`tasks/scripts/release.py`): exact stable and prerelease tags retain their
/// version. Otherwise, the latest merged stable release gets a patch bump and
/// `-dev.<N>+g<sha>` is appended.
///
/// Examples:
///   on tag v0.1.0-pre.1    → "0.1.0-pre.1"
///   3 commits past v0.0.3  → "0.0.4-dev.3+g2bf9969ab"
///
/// Returns `None` when git metadata cannot be read.
fn git_version() -> Option<String> {
    let exact_tags = git_output(&["tag", "--points-at", "HEAD"])?;
    if let Some(version) = build_version::exact_release_version(exact_tags.lines()) {
        return Some(version);
    }

    let merged_tags = git_output(&["tag", "--merged", "HEAD", "--list", "v*.*.*"])?;
    let latest_tag = build_version::latest_stable_tag(merged_tags.lines());
    let revision_range = latest_tag
        .as_deref()
        .map_or_else(|| "HEAD".to_string(), |tag| format!("{tag}..HEAD"));
    let distance = git_output(&["rev-list", "--count", &revision_range])?
        .parse()
        .ok()?;
    let sha = git_output(&["rev-parse", "--short=9", "HEAD"])?;

    build_version::next_dev_version(latest_tag.as_deref(), distance, &sha)
}

fn git_output(args: &[&str]) -> Option<String> {
    let output = std::process::Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|output| output.trim().to_string())
}
