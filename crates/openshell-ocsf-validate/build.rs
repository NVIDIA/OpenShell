// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Write as _;
use std::path::PathBuf;

fn main() {
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("schemas");
    println!("cargo:rerun-if-changed={}", root.display());

    let mut files = Vec::new();
    for dir in std::fs::read_dir(&root).unwrap() {
        let dir = dir.unwrap().path();
        let Some(version) = dir
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix('v'))
            .map(str::to_string)
        else {
            continue;
        };
        if !dir.is_dir() {
            continue;
        }
        for file in std::fs::read_dir(&dir).unwrap() {
            let path = file.unwrap().path();
            if path.extension().is_some_and(|ext| ext == "json") {
                files.push((version.clone(), path));
            }
        }
    }
    files.sort();

    let mut table = String::from("&[\n");
    for (version, path) in files {
        let name = path.file_stem().unwrap().to_str().unwrap();
        writeln!(
            table,
            "    ({version:?}, {name:?}, include_str!({:?})),",
            path.display().to_string()
        )
        .unwrap();
    }
    table.push(']');

    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("schemas.rs");
    std::fs::write(out, table).unwrap();
}
