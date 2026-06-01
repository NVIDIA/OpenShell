// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_os = "windows")]
fn main() {
    eprintln!("openshell-sandbox supervisor is not available on Windows");
    std::process::exit(1);
}

#[cfg(not(target_os = "windows"))]
include!("main_unix.rs");
