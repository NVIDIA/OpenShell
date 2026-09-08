// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Build script for openshell-driver-vm.
//!
//! This crate embeds the sandbox supervisor plus the minimal libkrun runtime
//! artifacts it needs to boot VMs without a separate VM runtime binary.

use std::path::{Path, PathBuf};
use std::{env, fs};

fn main() {
    println!("cargo:rerun-if-env-changed=OPENSHELL_VM_RUNTIME_COMPRESSED_DIR");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let workspace_root =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"))
            .parent()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .expect("workspace root not found");
    let default_compressed_dir = workspace_root.join("target/vm-runtime-compressed");

    let compressed_dir =
        env::var("OPENSHELL_VM_RUNTIME_COMPRESSED_DIR").map_or_else(
            |_| default_compressed_dir.clone(),
            PathBuf::from,
        );

    if compressed_dir.is_dir() {
        println!("cargo:rerun-if-changed={}", compressed_dir.display());
        for name in &[
            "libkrun.so.zst",
            "libkrunfw.so.5.zst",
            "libkrun.dylib.zst",
            "libkrunfw.5.dylib.zst",
            "gvproxy.zst",
            "openshell-sandbox.zst",
            "umoci.zst",
        ] {
            println!("cargo:rerun-if-changed={}/{name}", compressed_dir.display());
        }
    }

    let (libkrun_name, libkrunfw_name) = match target_os.as_str() {
        "macos" => ("libkrun.dylib", "libkrunfw.5.dylib"),
        "linux" => ("libkrun.so", "libkrunfw.so.5"),
        _ => {
            println!("cargo:warning=VM runtime not available for {target_os}-{target_arch}");
            generate_stub_resources(
                &out_dir,
                &["libkrun", "libkrunfw", "openshell-sandbox.zst", "umoci.zst"],
            );
            return;
        }
    };

    if !compressed_dir.is_dir() {
        generate_stub_resources(
            &out_dir,
            &[
                &format!("{libkrun_name}.zst"),
                &format!("{libkrunfw_name}.zst"),
                "gvproxy.zst",
                "openshell-sandbox.zst",
                "umoci.zst",
            ],
        );
        return;
    }

    let files = [
        (format!("{libkrun_name}.zst"), format!("{libkrun_name}.zst")),
        (
            format!("{libkrunfw_name}.zst"),
            format!("{libkrunfw_name}.zst"),
        ),
        ("gvproxy.zst".to_string(), "gvproxy.zst".to_string()),
        (
            "openshell-sandbox.zst".to_string(),
            "openshell-sandbox.zst".to_string(),
        ),
        ("umoci.zst".to_string(), "umoci.zst".to_string()),
    ];

    for (src_name, _) in &files {
        let src_path = compressed_dir.join(src_name);
        let metadata = fs::metadata(&src_path).unwrap_or_else(|e| {
            panic!(
                "Required compressed artifact unavailable: {}: {e}",
                src_path.display()
            )
        });
        assert!(
            metadata.is_file(),
            "Required compressed artifact is not a file: {}",
            src_path.display()
        );
        assert!(
            metadata.len() != 0,
            "Required compressed artifact is empty: {}",
            src_path.display()
        );
    }

    for (src_name, dst_name) in &files {
        let src_path = compressed_dir.join(src_name);
        let dst_path = out_dir.join(dst_name);

        if dst_path.exists() {
            let _ = fs::remove_file(&dst_path);
        }
        fs::copy(&src_path, &dst_path).unwrap_or_else(|e| {
            panic!(
                "Failed to copy {} to {}: {}",
                src_path.display(),
                dst_path.display(),
                e
            )
        });
        let size = fs::metadata(&dst_path).map_or(0, |m| m.len());
        println!("cargo:warning=Embedded {src_name}: {size} bytes");
    }
}

fn generate_stub_resources(out_dir: &Path, names: &[&str]) {
    for name in names {
        let path = out_dir.join(name);
        if !path.exists() {
            fs::write(&path, b"")
                .unwrap_or_else(|e| panic!("Failed to write stub {}: {}", path.display(), e));
        }
    }
}
