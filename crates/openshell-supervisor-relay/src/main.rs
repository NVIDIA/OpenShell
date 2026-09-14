// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Entry point for `openshell-supervisor-relay`.
//!
//! This is an MXC/AppContainer helper -- it only does anything useful on
//! Windows (see `imp.rs` for the real implementation and its module docs).
//! The implementation is technically portable (no Windows-specific APIs),
//! but per the `openshell-driver-mxc` platform pattern, it's gated behind
//! `cfg(target_os = "windows")` so a generic `cargo build --workspace` on
//! Linux/macOS doesn't compile the full relay implementation (and its
//! tokio/tungstenite dependency tree) for a binary those platforms never
//! run. Non-Windows builds get this minimal stub instead, purely so
//! workspace membership (`members = ["crates/*"]`) keeps working everywhere.

#[cfg(target_os = "windows")]
mod imp;

#[cfg(target_os = "windows")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    imp::run().await
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!(
        "openshell-supervisor-relay is a Windows-only MXC ProcessContainer/AppContainer helper; \
         it is not usable on this platform."
    );
    std::process::exit(1);
}
