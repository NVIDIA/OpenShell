// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared support for `OpenShell` end-to-end test suites.
//!
//! End-to-end suites test a running `OpenShell` system through the Rust SDK.
//! Each test is an `async fn` marked `#[testkit::test]`:
//!
//! ```ignore
//! use testkit::Context;
//!
//! /// A long-running sandbox becomes ready, runs exec, and is gone after delete.
//! #[testkit::test]
//! async fn long_running_exec_delete(cx: &mut Context) -> testkit::Result {
//!     let sandbox = cx.sandbox("lr").command(["sleep", "infinity"]).create().await?;
//!     sandbox.wait_ready().await?;
//!     // ...
//!     Ok(())
//! }
//! ```
//!
//! Tests find the gateway the same way the `openshell` CLI does (see
//! [`gateway`]).
//!
//! `#[testkit::test]` also registers each test, so a binary that calls
//! [`main`] is a test program that lists, runs, and reports its tests without
//! Cargo (see [`program`]).

mod cleanup;
mod cli;
mod context;
mod error;
pub mod gateway;
mod image;
mod poll;
pub mod program;
mod ready;
mod registry;
mod run;

pub use cleanup::CLEANUP_TIMEOUT;
pub use cli::{BIN_ENV, CLI_TIMEOUT, Cli, CliOutput};
pub use context::{
    Context, DELETE_TIMEOUT, EXEC_TIMEOUT, ExecOutput, READY_TIMEOUT, STOP_TIMEOUT, Sandbox,
    SandboxBuilder,
};
pub use error::{Error, Result, ResultExt};
pub use gateway::Gateway;
pub use image::{BASE_IMAGE_ENV, DEFAULT_BASE_IMAGE, base_image};
pub use openshell_sdk as sdk;
pub use poll::{Poll, poll_until};
pub use program::main;
pub use ready::check as check_ready;
pub use registry::Test;
pub use run::{TestInfo, run};
pub use testkit_macros::test;

#[doc(hidden)]
pub mod __private {
    pub use crate::registry::TESTS;
    pub use linkme;
    pub use tokio;
}
