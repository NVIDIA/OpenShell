// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Navigator Core - shared library for Navigator components.
//!
//! This crate provides:
//! - Protocol buffer definitions and generated code
//! - Configuration management
//! - Common error types

pub mod config;
pub mod error;
pub mod inference;
pub mod proto;

pub use config::{Config, TlsConfig};
pub use error::{Error, Result};
