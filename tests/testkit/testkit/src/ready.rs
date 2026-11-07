// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Waiting until the gateway is ready for tests.

use std::time::Duration;

use crate::cli::Cli;
use crate::gateway::Gateway;

/// Wait until the gateway selected as for tests is healthy and the CLI
/// reports it connected, logging to stderr as `program`. Returns whether it
/// is ready; if not, the last error has been logged.
pub async fn check(program: &str, timeout: Duration) -> bool {
    let result = async {
        let gateway = Gateway::from_env()?;
        eprintln!("{program}: {}", gateway.describe());
        let health = gateway.wait_ready(timeout).await?;
        Cli::from_env(&gateway).check_connected().await?;
        crate::Result::Ok(health)
    }
    .await;
    match result {
        Ok(health) => {
            eprintln!(
                "{program}: gateway {} is healthy and the CLI reaches it",
                health.version
            );
            true
        }
        Err(error) => {
            eprintln!("{program}: {error}");
            false
        }
    }
}
