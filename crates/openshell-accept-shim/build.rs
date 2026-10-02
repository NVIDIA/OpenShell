// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Compile the preloadable peer-address shim for Linux workload targets.
//!
//! The object is deliberately freestanding: `-nostdlib` keeps any `DT_NEEDED`
//! entry out of the result so a single per-architecture build loads under both
//! glibc and musl. `-fPIC` without text relocations also keeps `SELinux` from
//! requiring `execmod` on the materialized file.

use std::path::{Path, PathBuf};
use std::process::Command;

const SOURCE: &str = "src/accept_shim.c";

fn main() {
    println!("cargo:rerun-if-changed={SOURCE}");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "linux" {
        // Other hosts still build and lint the workspace; the shim is only
        // ever loaded inside a Linux workload.
        return;
    }

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let object = out_dir.join("accept_shim.so");

    let mut command = compiler_command();
    command
        .args([
            "-shared",
            "-fPIC",
            "-O2",
            "-nostdlib",
            "-fno-stack-protector",
            // Undefined `__errno_location` is resolved from the workload's
            // own libc at load time, so do not demand definitions here.
            "-Wall",
            "-Wextra",
            "-Werror",
            SOURCE,
            "-o",
        ])
        .arg(&object);

    let status = command
        .status()
        .unwrap_or_else(|error| panic!("run C compiler {command:?}: {error}"));
    assert!(status.success(), "compile {SOURCE}: {status}");

    println!("cargo:rerun-if-changed=tests/fixtures/cancellation.c");
    let helper = out_dir.join("cancellation");
    let status = compiler_command()
        .args([
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pthread",
            "-lc",
            "tests/fixtures/cancellation.c",
            "-o",
        ])
        .arg(&helper)
        .status()
        .expect("compile cancellation helper");
    assert!(status.success(), "compile cancellation helper: {status}");
    println!(
        "cargo:rustc-env=OPENSHELL_CANCELLATION_HELPER={}",
        helper.display()
    );

    println!("cargo:rerun-if-changed=tests/fixtures/other_preload.c");
    let other = out_dir.join("other_preload.so");
    let status = compiler_command()
        .args([
            "-shared",
            "-fPIC",
            "-nostdlib",
            "tests/fixtures/other_preload.c",
            "-o",
        ])
        .arg(&other)
        .status()
        .expect("compile other preload fixture");
    assert!(status.success(), "compile other preload fixture: {status}");
    println!(
        "cargo:rustc-env=OPENSHELL_OTHER_PRELOAD={}",
        other.display()
    );

    verify_object_architecture(&object);

    println!("cargo:rustc-env=OPENSHELL_ACCEPT_SHIM={}", object.display());
}

/// Build the C compiler invocation for the target being compiled.
///
/// Resolution is delegated to the `cc` crate so the standard overrides
/// (`CC_<target>`, `TARGET_CC`, `CC`) and the per-target wrappers that
/// cross-build drivers such as `cargo-zigbuild` install are all honored.
/// Guessing a cross prefix instead would pick a binary that is frequently
/// absent on the build host.
fn compiler_command() -> Command {
    match cc::Build::new().try_get_compiler() {
        Ok(compiler) => compiler.to_command(),
        Err(error) => panic!("locate a C compiler for the shim: {error}"),
    }
}

/// Fail the build when the emitted object does not match the Rust target.
///
/// A host compiler reached through a misconfigured `CC` produces a valid
/// object for the wrong architecture. The workload's loader then reports
/// `cannot open shared object file`, which is indistinguishable from a
/// sandbox policy denial, so catch the mismatch here instead.
fn verify_object_architecture(object: &Path) {
    let expected: u16 = match std::env::var("CARGO_CFG_TARGET_ARCH")
        .unwrap_or_default()
        .as_str()
    {
        "x86_64" => 0x3e,  // EM_X86_64
        "aarch64" => 0xb7, // EM_AARCH64
        other => panic!("unsupported architecture for the accept shim: {other}"),
    };

    let bytes = std::fs::read(object).expect("read the compiled shim");
    assert!(bytes.len() > 20, "compiled shim is not an ELF object");
    assert_eq!(
        &bytes[0..4],
        b"\x7fELF",
        "compiled shim is not an ELF object"
    );
    let machine = u16::from_le_bytes([bytes[18], bytes[19]]);
    assert_eq!(
        machine, expected,
        "compiled shim targets ELF machine {machine:#x}, expected {expected:#x}"
    );
}
