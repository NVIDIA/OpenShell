// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Wait until the gateway is ready for tests.
//!
//! Usage: `testkit-ready [TIMEOUT_SECS]` (default 60), with the gateway
//! selected as for tests. Run it once per environment before the test
//! binaries; exits non-zero with the last error if the gateway is not healthy
//! in time, or if the CLI does not reach it.

use std::process::ExitCode;
use std::time::Duration;

use testkit::{Cli, Gateway};

const DEFAULT_TIMEOUT_SECS: u64 = 60;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let timeout = match std::env::args().nth(1).map(|arg| arg.parse::<u64>()) {
        None => DEFAULT_TIMEOUT_SECS,
        Some(Ok(secs)) => secs,
        Some(Err(error)) => {
            eprintln!("testkit-ready: invalid timeout: {error}");
            return ExitCode::from(2);
        }
    };
    let result = async {
        let gateway = Gateway::from_env()?;
        eprintln!("testkit-ready: {}", gateway.describe());
        let health = gateway.wait_ready(Duration::from_secs(timeout)).await?;
        Cli::from_env(&gateway).check_connected().await?;
        testkit::Result::Ok(health)
    }
    .await;
    match result {
        Ok(health) => {
            eprintln!(
                "testkit-ready: gateway {} is healthy and the CLI reaches it",
                health.version
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("testkit-ready: {error}");
            ExitCode::FAILURE
        }
    }
}
