// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Build script for openshell-driver-vm.
//!
//! This crate embeds the sandbox supervisor plus the minimal libkrun runtime
//! artifacts it needs to boot VMs without depending on the openshell-vm binary
//! or crate.

use std::path::PathBuf;
use std::{env, fs};

fn main() {
    println!("cargo:rerun-if-env-changed=OPENSHELL_VM_RUNTIME_COMPRESSED_DIR");

    if let Ok(dir) = env::var("OPENSHELL_VM_RUNTIME_COMPRESSED_DIR") {
        println!("cargo:rerun-if-changed={dir}");
        for name in &[
            "libkrun.so.zst",
            "libkrunfw.so.5.zst",
            "libkrun.dylib.zst",
            "libkrunfw.5.dylib.zst",
            "gvproxy.zst",
            "openshell-sandbox.zst",
        ] {
            println!("cargo:rerun-if-changed={dir}/{name}");
        }
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    let (libkrun_name, libkrunfw_name) = match target_os.as_str() {
        "macos" => ("libkrun.dylib", "libkrunfw.5.dylib"),
        "linux" => ("libkrun.so", "libkrunfw.so.5"),
        _ => {
            println!("cargo:warning=VM runtime not available for {target_os}-{target_arch}");
            generate_stub_resources(&out_dir, &["libkrun", "libkrunfw", "openshell-sandbox.zst"]);
            return;
        }
    };

    let compressed_dir = if let Ok(dir) = env::var("OPENSHELL_VM_RUNTIME_COMPRESSED_DIR") {
        PathBuf::from(dir)
    } else {
        println!("cargo:warning=OPENSHELL_VM_RUNTIME_COMPRESSED_DIR not set");
        println!("cargo:warning=Run: mise run vm:setup && mise run vm:supervisor");
        generate_stub_resources(
            &out_dir,
            &[
                &format!("{libkrun_name}.zst"),
                &format!("{libkrunfw_name}.zst"),
                "gvproxy.zst",
                "openshell-sandbox.zst",
            ],
        );
        return;
    };

    if !compressed_dir.is_dir() {
        println!(
            "cargo:warning=Compressed runtime dir not found: {}",
            compressed_dir.display()
        );
        println!("cargo:warning=Run: mise run vm:setup && mise run vm:supervisor");
        generate_stub_resources(
            &out_dir,
            &[
                &format!("{libkrun_name}.zst"),
                &format!("{libkrunfw_name}.zst"),
                "gvproxy.zst",
                "openshell-sandbox.zst",
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
    ];

    let mut all_found = true;
    for (src_name, dst_name) in &files {
        let src_path = compressed_dir.join(src_name);
        let dst_path = out_dir.join(dst_name);

        if !src_path.exists() {
            println!(
                "cargo:warning=Missing compressed artifact: {}",
                src_path.display()
            );
            all_found = false;
            continue;
        }

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
    }

    if !all_found {
        println!(
            "cargo:warning=Some artifacts missing. Run: mise run vm:setup && mise run vm:supervisor"
        );
        generate_stub_resources(
            &out_dir,
            &[
                &format!("{libkrun_name}.zst"),
                &format!("{libkrunfw_name}.zst"),
                "gvproxy.zst",
                "openshell-sandbox.zst",
            ],
        );
    }
}

fn generate_stub_resources(out_dir: &PathBuf, names: &[&str]) {
    for name in names {
        let path = out_dir.join(name);
        if !path.exists() {
            fs::write(&path, b"")
                .unwrap_or_else(|e| panic!("Failed to write stub {}: {}", path.display(), e));
        }
    }
}
