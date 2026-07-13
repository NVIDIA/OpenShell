// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::path::{Path, PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use the bundled protoc from protobuf-src unless the environment already
    // provides one. The system protoc (from apt-get) does not bundle the
    // well-known type includes (google/protobuf/struct.proto etc.), so plain
    // cargo builds compile protoc from source; Bazel injects a prebuilt
    // hermetic protoc via $PROTOC instead.
    #[cfg(feature = "vendored-protoc")]
    if env::var_os("PROTOC").is_none() {
        // SAFETY: This is run at build time in a single-threaded build script
        // context. No other threads are reading environment variables
        // concurrently.
        #[allow(unsafe_code)]
        unsafe {
            env::set_var("PROTOC", protobuf_src::protoc());
        }
    }

    // The proto tree location is injected by the build system: cargo sets it
    // via [env] in .cargo/config.toml, Bazel via build_script_env.
    let proto_root = PathBuf::from(env::var("OPENSHELL_PROTO_DIR").map_err(
        |_| "OPENSHELL_PROTO_DIR is not set (cargo: .cargo/config.toml [env]; bazel: build_script_env)",
    )?);

    // Re-run when anything under proto/ changes (including newly added .proto files).
    println!("cargo:rerun-if-changed={}", proto_root.display());

    // Extra include root for protoc, used when it cannot resolve the
    // google/protobuf well-known types relative to its own binary (Bazel
    // builds a bare protoc with no include tree next to it).
    let mut includes = vec![proto_root.clone()];
    if let Ok(include) = env::var("PROTOC_INCLUDE") {
        includes.push(PathBuf::from(include));
    }

    let mut proto_files = Vec::new();
    collect_proto_files(&proto_root, &mut proto_files)?;
    proto_files.sort();

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let descriptor_path = out_dir.join("openshell_descriptor.bin");

    // Configure tonic/prost protobuf code generation.
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        // Emit a binary FileDescriptorSet so the server can enumerate every
        // RPC at runtime (used by the per-handler auth exhaustiveness test).
        .file_descriptor_set_path(&descriptor_path)
        .compile_protos(&proto_files, &includes)?;

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
