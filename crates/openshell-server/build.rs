// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    // SAFETY: Build scripts run in their own single-threaded process.
    #[allow(unsafe_code)]
    unsafe {
        env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
        env::set_var("PROTOC_INCLUDE", protoc_bin_vendored::include_path()?);
    }

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
        .compile_protos(&[storage_proto], &[storage_proto_dir, public_proto_dir])?;

    Ok(())
}
