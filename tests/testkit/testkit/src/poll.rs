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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn returns_when_ready() {
        let mut calls = 0;
        let value = poll_until(
            "three calls",
            Duration::from_secs(5),
            Duration::ZERO,
            async || {
                calls += 1;
                Ok(if calls == 3 {
                    Poll::Ready(calls)
                } else {
                    Poll::Pending(format!("call {calls}"))
                })
            },
        )
        .await
        .unwrap();
        assert_eq!(value, 3);
    }

    #[tokio::test]
    async fn reports_last_observation_on_timeout() {
        let err = poll_until::<()>("never", Duration::ZERO, Duration::ZERO, async || {
            Ok(Poll::Pending("still waiting".to_string()))
        })
        .await
        .unwrap_err();
        assert!(err.to_string().contains("waiting for never"), "{err}");
        assert!(err.to_string().contains("still waiting"), "{err}");
    }

    #[tokio::test]
    async fn fails_fast_on_error() {
        let err = poll_until::<()>(
            "error",
            Duration::from_mins(1),
            Duration::ZERO,
            async || Err(Error::msg("broken")),
        )
        .await
        .unwrap_err();
        assert_eq!(err.to_string(), "broken");
    }
}
