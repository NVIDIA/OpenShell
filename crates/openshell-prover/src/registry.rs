// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Registry of embedded data files (API descriptors, etc.).
//!
//! The built-in registry is embedded at compile time via `include_dir!`.
//! A filesystem override can be provided at runtime for custom registries.

use include_dir::{Dir, include_dir};

static EMBEDDED_REGISTRY: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/registry");

/// Accessor for the embedded registry (used by credentials module for API descriptors).
pub fn embedded_registry() -> &'static Dir<'static> {
    &EMBEDDED_REGISTRY
}
