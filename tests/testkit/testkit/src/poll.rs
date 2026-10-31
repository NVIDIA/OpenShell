// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Waiting for observable state.

use std::time::{Duration, Instant};

use crate::error::{Error, Result};

/// The outcome of one observation.
pub enum Poll<T> {
    /// The condition holds.
    Ready(T),
    /// Not yet; the string describes what was observed, for the timeout report.
    Pending(String),
}

/// Observe until the condition holds or `timeout` elapses.
///
/// An error from `observe` fails immediately. On timeout, the error reports
/// the last observation.
pub async fn poll_until<T>(
    what: &str,
    timeout: Duration,
    interval: Duration,
    mut observe: impl AsyncFnMut() -> Result<Poll<T>>,
) -> Result<T> {
    let started = Instant::now();
    loop {
        match observe().await? {
            Poll::Ready(value) => return Ok(value),
            Poll::Pending(observation) if started.elapsed() >= timeout => {
                return Err(Error::msg(format!(
                    "timed out after {timeout:?} waiting for {what}; last observation: {observation}"
                )));
            }
            Poll::Pending(_) => tokio::time::sleep(interval).await,
        }
    }
}
