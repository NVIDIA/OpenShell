// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `BlueField` compute driver package marker.
//!
//! The `bf-*` crates under this directory are private implementation crates.
//! They are workspace members for build and review boundaries, but this marker
//! crate intentionally re-exports nothing.

pub const DRIVER_NAME: &str = "bluefield";
