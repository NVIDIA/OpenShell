// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Schema validation utilities for testing OCSF events against vendored schemas.
//!
//! Available in this crate's tests or through the `test-support` feature for
//! producer regression tests.

mod embedded;
pub mod schema;

pub use schema::{
    load_class_schema, load_class_schema_for_version, validate_enum_value, validate_required_fields,
};
