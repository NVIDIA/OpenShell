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

/// Fail unless `future` finishes within `timeout`. For a deadline shorter
/// than the step's own, such as one that must fit inside the runner's kill.
pub async fn with_deadline<T>(
    timeout: Duration,
    what: &str,
    future: impl Future<Output = Result<T>>,
) -> Result<T> {
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| Error::msg(format!("{what} did not finish within {timeout:?}")))?
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
