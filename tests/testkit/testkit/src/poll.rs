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
    what: &str,
    timeout: Duration,
    future: impl Future<Output = Result<T>>,
) -> Result<T> {
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| Error::msg(format!("{what} did not finish within {timeout:?}")))?
}

/// Observe until the condition holds or `timeout` elapses.
///
/// An error from `observe` fails immediately. The deadline also covers an
/// observation in flight, so one that hangs, such as a request that never
/// answers, fails with the last completed observation instead of outliving
/// the wait. On timeout, the error reports that observation.
pub async fn poll_until<T>(
    what: &str,
    timeout: Duration,
    interval: Duration,
    mut observe: impl AsyncFnMut() -> Result<Poll<T>>,
) -> Result<T> {
    let timeout = crate::budget::cap(timeout);
    let started = Instant::now();
    let mut last = String::from("none completed");
    loop {
        let left = timeout.saturating_sub(started.elapsed());
        let timed_out = || {
            Error::msg(format!(
                "timed out after {timeout:?} waiting for {what}; last observation: {last}"
            ))
        };
        if left.is_zero() {
            return Err(timed_out());
        }
        match tokio::time::timeout(left, observe()).await {
            Err(_) => return Err(timed_out()),
            Ok(observed) => match observed? {
                Poll::Ready(value) => return Ok(value),
                Poll::Pending(observation) => last = observation,
            },
        }
        let left = timeout.saturating_sub(started.elapsed());
        tokio::time::sleep(interval.min(left)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_hung_observation_times_out_with_the_last_completed_one() {
        let mut calls = 0;
        let started = Instant::now();
        let error = poll_until(
            "the thing",
            Duration::from_millis(300),
            Duration::from_millis(10),
            async || {
                calls += 1;
                if calls > 1 {
                    std::future::pending::<()>().await;
                }
                Ok(Poll::<()>::Pending("not yet".into()))
            },
        )
        .await
        .unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(5));
        let message = error.to_string();
        assert!(message.contains("waiting for the thing"), "{message}");
        assert!(message.contains("last observation: not yet"), "{message}");
    }

    #[tokio::test]
    async fn the_retry_sleep_does_not_pass_the_deadline() {
        let started = Instant::now();
        let error = poll_until(
            "the thing",
            Duration::from_millis(200),
            Duration::from_secs(30),
            async || Ok(Poll::<()>::Pending("not yet".into())),
        )
        .await
        .unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(error.to_string().contains("last observation: not yet"));
    }

    #[tokio::test]
    async fn a_ready_observation_returns_its_value() {
        let value = poll_until(
            "the thing",
            Duration::from_secs(1),
            Duration::from_millis(10),
            async || Ok(Poll::Ready(7)),
        )
        .await
        .unwrap();
        assert_eq!(value, 7);
    }
}
