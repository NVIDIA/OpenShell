// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Concrete implementations of [`crate::lifecycle::LifecycleExtension`].
//!
//! The framework itself — the trait, registry, launch plan, descriptor,
//! and backend-feature resolver — lives in [`crate::lifecycle`]. This
//! module is the conventional home for concrete extensions that
//! implement the trait.
//!
//! # Conventions for a new extension
//!
//! - Each extension lives in its own submodule:
//!   `crates/openshell-driver-vm/src/extensions/<name>/mod.rs`.
//! - The submodule exposes a single public type
//!   `<Name>Extension` (e.g. `VfioPassthroughExtension`) that
//!   implements [`crate::lifecycle::LifecycleExtension`].
//! - Helpers (pool allocators, guest env builders, on-disk state
//!   layouts) live alongside the extension in private modules within
//!   the same directory.
//! - The extension's [`crate::lifecycle::LifecycleExtension::name`]
//!   must match `<name>` (kebab-case ASCII). The driver creates
//!   per-extension state at
//!   `<sandbox_state_dir>/extensions/<name>/` for hooks to use.
//! - Re-export the extension type from this `mod.rs` so callers can
//!   write `use openshell_driver_vm::extensions::VfioPassthroughExtension;`.
//!
//! New extension types are wired into a running driver by registering
//! them with [`crate::lifecycle::LifecycleExtensionRegistry`] and passing
//! the registry to [`crate::VmDriver::new_with_extensions`].
