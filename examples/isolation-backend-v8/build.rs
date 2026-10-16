// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = tonic_prost_build::Config::new();
    config.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    tonic_prost_build::configure()
        .btree_map(".openshell.sandbox.protocol.v1")
        .compile_with_config(
            config,
            &[
                "../../proto/isolation_backend.proto",
                "../../proto/sandbox_protocol.proto",
            ],
            &["../../proto"],
        )?;
    println!("cargo:rerun-if-changed=../../proto");
    Ok(())
}
