// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The Cargo and binary metadata nextest reads instead of building the suite.

use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::path::Path;

use serde_json::json;

pub fn write(dir: &Path, package: &str, binary: &str) -> io::Result<()> {
    let exe = std::env::current_exe()?;
    fs::create_dir_all(dir)?;
    let dir = dir.canonicalize()?;
    let manifest = dir.join("Cargo.toml");
    let target = dir.join("target");
    let package_id = format!("{package} 0.0.0");
    let binary_id = format!("{package}::bin/{binary}");

    // The manifest identifies the workspace. Nextest reads the JSON rather
    // than invoking Cargo, and the only test target is the running binary.
    let cargo = json!({
        "packages": [{
            "name": package, "version": "0.0.0", "id": package_id,
            "manifest_path": manifest,
            "authors": [], "categories": [], "keywords": [],
            "dependencies": [], "features": {},
            "targets": [{
                "name": binary, "kind": ["bin"], "crate_types": ["bin"],
                "src_path": exe, "edition": "2024", "test": true
            }],
            "edition": "2024"
        }],
        "workspace_members": [package_id],
        "workspace_default_members": [package_id],
        "target_directory": target,
        "workspace_root": dir,
        "version": 1
    });
    // Omitting platforms lets nextest use its own native target when rustc
    // isn't installed. The executable is already runnable on this machine.
    let binaries = json!({
        "rust-build-meta": {
            "target-directory": target,
            "base-output-directories": [],
            "non-test-binaries": {},
            "linked-paths": []
        },
        "rust-binaries": {
            binary_id.clone(): {
                "binary-id": binary_id, "binary-name": binary,
                "package-id": package_id, "kind": "bin",
                "binary-path": exe, "build-platform": "target"
            }
        }
    });
    let create = |name| {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(name))
    };
    writeln!(
        create("Cargo.toml")?,
        "[package]\nname = {package:?}\nversion = \"0.0.0\""
    )?;
    serde_json::to_writer(create("cargo-metadata.json")?, &cargo)?;
    serde_json::to_writer(create("binaries-metadata.json")?, &binaries)?;
    Ok(())
}
