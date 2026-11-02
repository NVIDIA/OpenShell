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

mod cli;
mod context;
mod error;
pub mod gateway;
mod poll;
mod run;

pub use cli::{BIN_ENV, CLI_TIMEOUT, Cli, CliOutput};
pub use context::{
    Context, DELETE_TIMEOUT, EXEC_TIMEOUT, ExecOutput, READY_TIMEOUT, STOP_TIMEOUT, Sandbox,
    SandboxBuilder,
};
pub use error::{Error, Result, ResultExt};
pub use gateway::Gateway;
pub use openshell_sdk as sdk;
pub use poll::{Poll, poll_until};
pub use run::{TestInfo, run};
pub use testkit_macros::test;

#[doc(hidden)]
pub mod __private {
    pub use tokio;
}
