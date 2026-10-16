// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared support for `OpenShell` end-to-end test suites.
//!
//! The suites under `tests/suites/` (conformance and the other families) test
//! a running `OpenShell` system through the Rust SDK. Each test is an
//! `async fn` marked `#[testkit::test]`:
//!
//! ```ignore
//! use testkit::Context;
//!
//! /// A long-running sandbox becomes ready, runs exec, and is gone after delete.
//! #[testkit::test(id = "t-3tfdx240")]
//! async fn long_running_exec_delete(cx: &mut Context) -> testkit::Result {
//!     let sandbox = cx.sandbox("lr").command(["sleep", "infinity"]).create().await?;
//!     sandbox.wait_ready().await?;
//!     // ...
//!     Ok(())
//! }
//! ```
//!
//! Tests read the system under test from the target file named by
//! `OPENSHELL_TEST_TARGET` (see [`target`]).

mod cli;
mod context;
mod error;
mod poll;
mod run;
pub mod target;

pub use cli::{CLI_TIMEOUT, Cli, CliOutput};
pub use context::{
    Context, DELETE_TIMEOUT, EXEC_TIMEOUT, ExecOutput, READY_TIMEOUT, STOP_TIMEOUT, Sandbox,
    SandboxBuilder,
};
pub use error::{Error, Result, ResultExt};
pub use openshell_sdk as sdk;
pub use poll::{Poll, poll_until};
pub use run::{TestInfo, run};
pub use target::{Capability, Target};
pub use testkit_macros::test;

#[doc(hidden)]
pub mod __private {
    pub use tokio;
}
