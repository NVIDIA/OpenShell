// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Build script for openshell-vm.
//!
//! This script copies pre-compressed VM runtime artifacts (libkrun, libkrunfw,
//! gvproxy) to `OUT_DIR` for embedding via `include_bytes!()`.
//!
//! The compressed artifacts are expected to be prepared by:
//!   `mise run vm:setup` (one-time) then `mise run vm:build`
//!
//! Environment:
//!   `OPENSHELL_VM_RUNTIME_COMPRESSED_DIR` - Path to compressed artifacts

use std::path::PathBuf;
use std::{env, fs};

fn main() {
    println!("cargo:rerun-if-env-changed=OPENSHELL_VM_RUNTIME_COMPRESSED_DIR");

    // Re-run if any compressed artifact changes.
    if let Ok(dir) = env::var("OPENSHELL_VM_RUNTIME_COMPRESSED_DIR") {
        println!("cargo:rerun-if-changed={dir}");
        for name in &[
            "libkrun.so.zst",
            "libkrunfw.so.5.zst",
            "libkrun.dylib.zst",
            "libkrunfw.5.dylib.zst",
            "gvproxy.zst",
            "rootfs.tar.zst",
        ] {
            println!("cargo:rerun-if-changed={dir}/{name}");
        }
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    // Determine platform-specific file names
    let (libkrun_name, libkrunfw_name) = match target_os.as_str() {
        "macos" => ("libkrun.dylib", "libkrunfw.5.dylib"),
        "linux" => ("libkrun.so", "libkrunfw.so.5"),
        _ => {
            println!("cargo:warning=VM runtime not available for {target_os}-{target_arch}");
            generate_stub_resources(&out_dir);
            return;
        }
    };

    // Check for pre-compressed artifacts from mise task
    let compressed_dir = if let Ok(dir) = env::var("OPENSHELL_VM_RUNTIME_COMPRESSED_DIR") {
        PathBuf::from(dir)
    } else {
        println!("cargo:warning=OPENSHELL_VM_RUNTIME_COMPRESSED_DIR not set");
        println!("cargo:warning=Run: mise run vm:setup");
        generate_stub_resources(&out_dir);
        return;
    };

    if !compressed_dir.is_dir() {
        println!(
            "cargo:warning=Compressed runtime dir not found: {}",
            compressed_dir.display()
        );
        println!("cargo:warning=Run: mise run vm:setup");
        generate_stub_resources(&out_dir);
        return;
    }

    // Copy compressed files to OUT_DIR
    let files = [
        (format!("{libkrun_name}.zst"), format!("{libkrun_name}.zst")),
        (
            format!("{libkrunfw_name}.zst"),
            format!("{libkrunfw_name}.zst"),
        ),
        ("gvproxy.zst".to_string(), "gvproxy.zst".to_string()),
        ("rootfs.tar.zst".to_string(), "rootfs.tar.zst".to_string()),
    ];

    let mut all_found = true;
    for (src_name, dst_name) in &files {
        let src_path = compressed_dir.join(src_name);
        let dst_path = out_dir.join(dst_name);

        if src_path.exists() {
            // Remove existing file first (may be read-only from previous build)
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
            let size = fs::metadata(&dst_path).map(|m| m.len()).unwrap_or(0);
            println!("cargo:warning=Embedded {src_name}: {size} bytes");
        } else {
            println!(
                "cargo:warning=Missing compressed artifact: {}",
                src_path.display()
            );
            all_found = false;
        }
    }

    if !all_found {
        println!("cargo:warning=Some artifacts missing. Run: mise run vm:setup");
        generate_stub_resources(&out_dir);
    }
}

/// Generate stub (empty) resource files so the build can complete.
/// The embedded module will fail at runtime if these stubs are used.
fn generate_stub_resources(out_dir: &PathBuf) {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    let (libkrun_name, libkrunfw_name) = match target_os.as_str() {
        "macos" => ("libkrun.dylib", "libkrunfw.5.dylib"),
        _ => ("libkrun.so", "libkrunfw.so.5"),
    };

    let stubs = [
        format!("{libkrun_name}.zst"),
        format!("{libkrunfw_name}.zst"),
        "gvproxy.zst".to_string(),
        "rootfs.tar.zst".to_string(),
    ];

    for name in &stubs {
        let path = out_dir.join(name);
        if !path.exists() {
            // Write an empty file as a stub
            fs::write(&path, b"")
                .unwrap_or_else(|e| panic!("Failed to write stub {}: {}", path.display(), e));
        }
    }
}
