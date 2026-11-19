// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::path::PathBuf;

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

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let storage_proto_dir = manifest_dir.join("proto");
    let public_proto_dir = manifest_dir.join("../../proto");
    let storage_proto = storage_proto_dir.join("storage.proto");
    let image_proto = storage_proto_dir.join("sandbox_image.proto");
    let secret_proto = storage_proto_dir.join("workspace_secret.proto");

    println!("cargo:rerun-if-changed={}", storage_proto.display());
    println!("cargo:rerun-if-changed={}", image_proto.display());
    println!("cargo:rerun-if-changed={}", secret_proto.display());
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
    // the build process environment. With a caller-supplied PROTOC, leave both
    // to prost.
    let mut proto_config = tonic_prost_build::Config::new();
    let proto_include = if use_vendored_protoc {
        proto_config.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
        Some(protoc_bin_vendored::include_path()?)
    } else {
        None
    };

    let descriptor_path = PathBuf::from(env::var("OUT_DIR")?).join("storage_descriptor.bin");
    let mut include_dirs = vec![storage_proto_dir, public_proto_dir.clone()];
    include_dirs.extend(proto_include);
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
            &[storage_proto, image_proto, secret_proto],
            &include_dirs,
        )?;

    if env::var_os("CARGO_FEATURE_TEST_SUPPORT").is_some() {
        let output = PathBuf::from(env::var("OUT_DIR")?).join("test_grpc");
        std::fs::create_dir_all(&output)?;
        let mut config = tonic_prost_build::Config::new();
        if use_vendored_protoc {
            config.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
        }
        // Only test fixtures get default UNIMPLEMENTED handlers. Keep the
        // production trait exhaustive and reuse its existing wire types.
        tonic_prost_build::configure()
            .build_client(false)
            .build_server(true)
            .generate_default_stubs(true)
            .extern_path(".openshell.v1", "::openshell_core::proto")
            .extern_path(
                ".openshell.datamodel.v1",
                "::openshell_core::proto::datamodel::v1",
            )
            .extern_path(
                ".openshell.sandbox.v1",
                "::openshell_core::proto::sandbox::v1",
            )
            .out_dir(output)
            .compile_with_config(
                config,
                &[public_proto_dir.join("openshell.proto")],
                &include_dirs,
            )?;
    }

    Ok(())
}
