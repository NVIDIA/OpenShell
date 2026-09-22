// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::path::PathBuf;

const PROTO_ROOT: &str = "../../proto";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let proto_root = manifest_dir.join(PROTO_ROOT);
    let policy_proto = proto_root.join("policy.proto");

    println!("cargo:rerun-if-changed={}", policy_proto.display());

    // SAFETY: Build scripts run in their own single-threaded process.
    #[allow(unsafe_code)]
    unsafe {
        env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
        env::set_var("PROTOC_INCLUDE", protoc_bin_vendored::include_path()?);
    }

    tonic_prost_build::configure()
        .build_server(false)
        .build_client(false)
        .file_descriptor_set_path(PathBuf::from(env::var("OUT_DIR")?).join("policy_descriptor.bin"))
        .compile_protos(&[policy_proto], &[proto_root])?;

    Ok(())
}
