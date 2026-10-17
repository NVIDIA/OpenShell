// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Typed error for [`crate::load_schema`] and [`crate::declared_attributes`].

use std::error::Error as StdError;

use miette::Diagnostic;
use thiserror::Error;

/// The embedded [`crate::SANDBOX_SCHEMA_SRC`] failed to parse or to convert.
///
/// This should only happen if this crate ships a broken schema; it is not a
/// caller-input error.
#[derive(Debug, Error, Diagnostic)]
#[error("Cedar schema parse error: {0}")]
#[diagnostic(code(openshell::policy_cedar_schema::parse))]
pub struct CedarSchemaLoadError(#[source] Box<dyn StdError + Send + Sync + 'static>);

impl CedarSchemaLoadError {
    pub(crate) fn new(source: impl StdError + Send + Sync + 'static) -> Self {
        Self(Box::new(source))
    }
}
