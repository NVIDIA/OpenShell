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

pub use config::Config;
pub use error::{Error, Result};
