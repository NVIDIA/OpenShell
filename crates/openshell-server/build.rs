// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Preserve the vendored include-tree guarantee even when the caller has
    // PROTOC_INCLUDE set: prost validates that ambient path independently of
    // explicit includes. Re-enter with a child-only environment override.
    if env::var_os("PROTOC_INCLUDE").is_some() {
        let status = std::process::Command::new(env::current_exe()?)
            .env_remove("PROTOC_INCLUDE")
            .status()?;
        if !status.success() {
            return Err(format!("vendored protobuf build failed: {status}").into());
        }
        return Ok(());
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let storage_proto_dir = manifest_dir.join("proto");
    let public_proto_dir = manifest_dir.join("../../proto");
    let storage_proto = storage_proto_dir.join("storage.proto");

    println!("cargo:rerun-if-changed={}", storage_proto.display());
    for imported_proto in [
        "datamodel.proto",
        "openshell.proto",
        "options.proto",
        "sandbox.proto",
    ] {
        println!(
            "cargo:rerun-if-changed={}",
            public_proto_dir.join(imported_proto).display()
        );
    }

    // Configure the vendored compiler and well-known includes without changing
    // the build process environment.
    let mut proto_config = tonic_prost_build::Config::new();
    proto_config.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    let proto_include = protoc_bin_vendored::include_path()?;

    let descriptor_path = PathBuf::from(env::var("OUT_DIR")?).join("storage_descriptor.bin");
    tonic_prost_build::configure()
        .build_server(false)
        .build_client(false)
        .extern_path(".openshell.v1", "::openshell_core::proto")
        .extern_path(
            ".openshell.datamodel.v1",
            "::openshell_core::proto::datamodel::v1",
        )
        .extern_path(
            ".openshell.sandbox.v1",
            "::openshell_core::proto::sandbox::v1",
        )
        .file_descriptor_set_path(&descriptor_path)
        .compile_with_config(
            proto_config,
            &[storage_proto],
            &[storage_proto_dir, public_proto_dir, proto_include],
        )?;

    Ok(())
}
