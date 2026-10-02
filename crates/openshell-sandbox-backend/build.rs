// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Preserve the vendored include-tree guarantee even when the caller has
    // PROTOC_INCLUDE set: prost validates that ambient path independently of
    // explicit includes. Re-enter with a child-only environment override.
    if std::env::var_os("PROTOC_INCLUDE").is_some() {
        let status = std::process::Command::new(std::env::current_exe()?)
            .env_remove("PROTOC_INCLUDE")
            .status()?;
        if !status.success() {
            return Err(format!("vendored protobuf build failed: {status}").into());
        }
        return Ok(());
    }

    println!("cargo:rerun-if-changed=proto/openshell_sandbox.proto");

    // Configure the vendored compiler and well-known includes without changing
    // the build process environment.
    let mut proto_config = tonic_prost_build::Config::new();
    proto_config.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    let proto_include = protoc_bin_vendored::include_path()?;

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_with_config(
            proto_config,
            &[std::path::PathBuf::from("proto/openshell_sandbox.proto")],
            &[std::path::PathBuf::from("proto"), proto_include],
        )?;
    Ok(())
}
