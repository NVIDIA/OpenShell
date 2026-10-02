// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::path::{Path, PathBuf};

#[path = "build_support/git.rs"]
mod git;

const PROTO_REL: &str = "../../proto";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- Git-derived version ---
    // Compute a version from tags and commit metadata for local builds. In
    // Docker/CI builds where .git is absent, this silently does nothing and
    // the binary falls back to CARGO_PKG_VERSION (which is already sed-patched
    // by the build pipeline).
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    git::emit_rerun_if_changed(&manifest_dir);
    if let Some(version) = git::version(&manifest_dir) {
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
