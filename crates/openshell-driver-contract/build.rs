// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::path::PathBuf;

const PROTO_REL: &str = "../../proto";

/// `sandbox_runtime.proto` and its only import, `options.proto`.
const PROTO_FILES: &[&str] = &["options.proto", "sandbox_runtime.proto"];

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

    println!("cargo:rerun-if-changed={PROTO_REL}");
    let mut proto_config = tonic_prost_build::Config::new();
    // Map fields of the documents are written to files, so they must encode in
    // a fixed order.
    proto_config.btree_map([".openshell.sandbox.runtime.v1"]);
    let proto_include = if use_vendored_protoc {
        proto_config.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
        Some(protoc_bin_vendored::include_path()?)
    } else {
        None
    };

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let proto_root = manifest_dir.join(PROTO_REL);
    let proto_files: Vec<PathBuf> = PROTO_FILES.iter().map(|f| proto_root.join(f)).collect();

    let mut include_dirs = vec![proto_root];
    include_dirs.extend(proto_include);
    let descriptor_path =
        PathBuf::from(env::var("OUT_DIR")?).join("openshell_driver_contract_descriptor.bin");

    tonic_prost_build::configure()
        .build_server(false)
        .build_client(false)
        .include_file("openshell.rs")
        .file_descriptor_set_path(&descriptor_path)
        .compile_with_config(proto_config, &proto_files, &include_dirs)?;

    println!(
        "cargo:rustc-env=OPENSHELL_DRIVER_CONTRACT_DESCRIPTOR_PATH={}",
        descriptor_path.display()
    );

    Ok(())
}
