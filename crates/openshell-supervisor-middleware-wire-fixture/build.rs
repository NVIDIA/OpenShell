// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::path::PathBuf;

const PROTO_ROOT: &str = "proto/v0.1.2";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed={PROTO_ROOT}");
    // SAFETY: build scripts run single-threaded; nothing else reads the
    // environment concurrently.
    #[allow(unsafe_code)]
    unsafe {
        env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
        env::set_var("PROTOC_INCLUDE", protoc_bin_vendored::include_path()?);
    }

    let proto_root = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?).join(PROTO_ROOT);
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .include_file("v0_1_2.rs")
        .compile_protos(
            &[
                proto_root.join("extension.proto"),
                proto_root.join("supervisor_middleware.proto"),
            ],
            &[proto_root],
        )?;
    Ok(())
}
