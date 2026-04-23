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

use std::path::{Path, PathBuf};
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
            "rootfs-gpu.tar.zst",
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

    // Copy compressed files to OUT_DIR.
    // Core artifacts are required; rootfs has two variants (base and GPU) and
    // the presence of either one is sufficient.
    let core_files = [
        (format!("{libkrun_name}.zst"), format!("{libkrun_name}.zst")),
        (
            format!("{libkrunfw_name}.zst"),
            format!("{libkrunfw_name}.zst"),
        ),
        ("gvproxy.zst".to_string(), "gvproxy.zst".to_string()),
    ];

    let mut all_found = true;
    let mut total_embedded_size: u64 = 0;

    let copy_artifact = |src_name: &str,
                         dst_name: &str,
                         compressed_dir: &Path,
                         out_dir: &Path,
                         total: &mut u64|
     -> bool {
        let src_path = compressed_dir.join(src_name);
        let dst_path = out_dir.join(dst_name);
        if src_path.exists() {
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
            *total += size;
            println!("cargo:warning=Embedded {src_name}: {size} bytes");
            true
        } else {
            false
        }
    };

    for (src_name, dst_name) in &core_files {
        if !copy_artifact(
            src_name,
            dst_name,
            &compressed_dir,
            &out_dir,
            &mut total_embedded_size,
        ) {
            println!(
                "cargo:warning=Missing compressed artifact: {}",
                compressed_dir.join(src_name).display()
            );
            all_found = false;
        }
    }

    // Rootfs: accept either the base rootfs or the GPU rootfs (or both).
    let has_base = copy_artifact(
        "rootfs.tar.zst",
        "rootfs.tar.zst",
        &compressed_dir,
        &out_dir,
        &mut total_embedded_size,
    );
    let has_gpu = copy_artifact(
        "rootfs-gpu.tar.zst",
        "rootfs-gpu.tar.zst",
        &compressed_dir,
        &out_dir,
        &mut total_embedded_size,
    );
    if !has_base && !has_gpu {
        println!(
            "cargo:warning=Missing rootfs artifact: neither rootfs.tar.zst nor rootfs-gpu.tar.zst found in {}",
            compressed_dir.display()
        );
    } else if !has_base {
        println!(
            "cargo:warning=Only rootfs-gpu.tar.zst found (base rootfs.tar.zst absent). \
             This is fine for GPU-only builds; run `mise run vm:setup` to get the base rootfs."
        );
    } else if !has_gpu {
        println!(
            "cargo:warning=Only rootfs.tar.zst found (GPU rootfs-gpu.tar.zst absent). \
             This is fine for non-GPU builds; run `mise run vm:rootfs -- --gpu` to get the GPU rootfs."
        );
    }

    // Write empty stubs for any missing rootfs variant so that
    // `include_bytes!()` in embedded.rs always resolves. The embedded module
    // treats zero-length slices as "not available".
    for (found, name) in [
        (has_base, "rootfs.tar.zst"),
        (has_gpu, "rootfs-gpu.tar.zst"),
    ] {
        if !found {
            let stub = out_dir.join(name);
            if !stub.exists() {
                fs::write(&stub, b"")
                    .unwrap_or_else(|e| panic!("Failed to write stub {name}: {e}"));
            }
        }
    }

    if !all_found {
        println!("cargo:warning=Some artifacts missing. Run: mise run vm:setup");
        generate_stub_resources(&out_dir);
    }

    // Warn when total embedded data approaches the x86_64 small code model limit.
    // The default code model uses R_X86_64_PC32 (±2 GiB) relocations; embedding
    // blobs that push .rodata past 2 GiB will cause linker failures unless
    // RUSTFLAGS="-C code-model=large" is set. The vm:build task does this
    // automatically, but direct cargo invocations may not.
    const LARGE_BLOB_THRESHOLD: u64 = 1_800_000_000; // ~1.8 GiB
    if target_arch == "x86_64" && total_embedded_size > LARGE_BLOB_THRESHOLD {
        println!(
            "cargo:warning=Total embedded data is {total_embedded_size} bytes ({:.1} GiB).",
            total_embedded_size as f64 / (1024.0 * 1024.0 * 1024.0)
        );
        println!("cargo:warning=This exceeds the x86_64 small code model limit (~2 GiB).");
        println!(
            "cargo:warning=Ensure RUSTFLAGS includes '-C code-model=large' or use `mise run vm:build`."
        );
    }
}

/// Generate stub (empty) resource files so the build can complete.
/// The embedded module will fail at runtime if these stubs are used.
fn generate_stub_resources(out_dir: &Path) {
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
        "rootfs-gpu.tar.zst".to_string(),
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
