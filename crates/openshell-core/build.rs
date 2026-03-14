// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::env;

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
    // Use bundled protoc from protobuf-src
    // SAFETY: This is run at build time in a single-threaded build script context.
    // No other threads are reading environment variables concurrently.
    #[allow(unsafe_code)]
    unsafe {
        env::set_var("PROTOC", protobuf_src::protoc());
    }

    let proto_files = [
        "../../proto/openshell.proto",
        "../../proto/datamodel.proto",
        "../../proto/sandbox.proto",
        "../../proto/inference.proto",
        "../../proto/test.proto",
    ];

    // Configure tonic-build
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&proto_files, &["../../proto"])?;

    // Tell cargo to rerun if the proto file changes
    for proto_file in proto_files {
        println!("cargo:rerun-if-changed={proto_file}");
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
    let output = std::process::Command::new("git")
        .args(["describe", "--tags", "--long", "--match", "v*"])
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
