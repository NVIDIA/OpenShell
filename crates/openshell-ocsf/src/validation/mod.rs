// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Schema validation utilities for testing OCSF events against vendored schemas.
//!
//! These utilities are gated behind `#[cfg(test)]` — they are only available
//! in test builds.

pub mod schema;

pub use schema::{load_class_schema, validate_enum_value, validate_required_fields};
