// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::path::{Path, PathBuf};

mod build_git;
mod build_version;

const PROTO_REL: &str = "../../proto";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A caller-supplied PROTOC (for example a distro package's system
    // compiler) is used as-is and prost resolves its own includes. Without it,
    // use the vendored compiler and include tree.
    println!("cargo:rerun-if-env-changed=PROTOC");
    println!("cargo:rerun-if-env-changed=PROTOC_INCLUDE");
    let use_vendored_protoc = env::var_os("PROTOC").is_none();

    // In vendored mode, preserve the vendored include-tree guarantee even when
    // the caller has PROTOC_INCLUDE set: prost validates that ambient path
    // independently of explicit includes. Re-enter with a child-only
    // environment override.
    if use_vendored_protoc && env::var_os("PROTOC_INCLUDE").is_some() {
        let status = std::process::Command::new(env::current_exe()?)
            .env_remove("PROTOC_INCLUDE")
            .status()?;
        if !status.success() {
            return Err(format!("vendored protobuf build failed: {status}").into());
        }
        return Ok(());
    }

    // --- Git-derived version ---
    // Compute a version from tags and commit metadata for local builds. In
    // Docker/CI builds where .git is absent, this silently does nothing and
    // the binary falls back to CARGO_PKG_VERSION (which is already sed-patched
    // by the build pipeline).
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    build_git::emit_rerun_if_changed(&manifest_dir);
    if let Some(version) = build_git::version(&manifest_dir) {
        println!("cargo:rustc-env=OPENSHELL_GIT_VERSION={version}");
    }

    // --- Protobuf compilation ---
    // Re-run when anything under proto/ changes (including newly added .proto files).
    println!("cargo:rerun-if-changed={PROTO_REL}");
    // Configure the vendored compiler and well-known includes without changing
    // the build process environment. With a caller-supplied PROTOC, leave both
    // to prost.
    let mut proto_config = tonic_prost_build::Config::new();
    // Keep optional grant evidence off sandbox lifecycle futures' stacks.
    proto_config.boxed(".openshell.v1.SandboxStatus.last_token_grant_failure");
    let proto_include = if use_vendored_protoc {
        proto_config.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
        Some(protoc_bin_vendored::include_path()?)
    } else {
        None
    };

    let proto_root = manifest_dir.join(PROTO_REL);
    let mut proto_files = Vec::new();
    collect_proto_files(&proto_root, &mut proto_files)?;
    proto_files.sort();

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let descriptor_path = out_dir.join("openshell_descriptor.bin");
    let mut include_dirs = vec![proto_root];
    include_dirs.extend(proto_include);

    // Configure tonic/prost protobuf code generation.
    tonic_prost_build::configure()
        .btree_map(".openshell.sandbox.protocol.v1")
        .build_server(true)
        .build_client(true)
        .include_file("openshell.rs")
        // Emit a binary FileDescriptorSet so the server can enumerate every
        // RPC at runtime (used by the per-handler auth exhaustiveness test).
        .file_descriptor_set_path(&descriptor_path)
        .compile_with_config(proto_config, &proto_files, &include_dirs)?;

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
