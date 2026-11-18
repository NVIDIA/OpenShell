// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Client-side retry of sandbox creation while the gateway is saturated.
//!
//! A create is retried only for `MUTATION_LOCK_TIMEOUT`, or for a same-name
//! `SANDBOX_DELETING` conflict after an earlier attempt failed. Every other
//! error is returned as is.

use std::future::Future;
use std::time::Duration;

use rand::Rng;
use tokio::time::Instant;
use tonic::Status;

use crate::rpc_error::{MUTATION_LOCK_TIMEOUT, SANDBOX_DELETING, decode_details, has_reason};

const DEFAULT_MAX_ELAPSED: Duration = Duration::from_mins(1);
const FALLBACK_DELAY: Duration = Duration::from_secs(1);

/// Retry budget for sandbox creation.
#[derive(Clone, Copy, Debug)]
pub struct RetryPolicy {
    max_elapsed: Duration,
}

impl RetryPolicy {
    /// Retry lock contention for up to 60 seconds.
    #[must_use]
    pub const fn lock_contention() -> Self {
        Self {
            max_elapsed: DEFAULT_MAX_ELAPSED,
        }
    }

    /// Never retry.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            max_elapsed: Duration::ZERO,
        }
    }

    /// Stop retrying once this much time has passed since the first attempt.
    #[must_use]
    pub const fn max_elapsed(mut self, max_elapsed: Duration) -> Self {
        self.max_elapsed = max_elapsed;
        self
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::lock_contention()
    }
}

/// Server-requested minimum wait if `status` is retryable.
///
/// `after_failure` is true once an earlier attempt of the same create failed.
fn retry_floor(status: &Status, after_failure: bool) -> Option<Duration> {
    let retryable = match status.code() {
        tonic::Code::Unavailable => has_reason(status, MUTATION_LOCK_TIMEOUT),
        tonic::Code::AlreadyExists => after_failure && has_reason(status, SANDBOX_DELETING),
        _ => false,
    };
    retryable.then(|| {
        decode_details(status)
            .and_then(|details| details.retry_info()?.retry_delay)
            .unwrap_or(FALLBACK_DELAY)
    })
}

/// Whether `status` is a lock-contention timeout that a retry may clear.
#[must_use]
pub fn is_lock_contention(status: &Status) -> bool {
    status.code() == tonic::Code::Unavailable && has_reason(status, MUTATION_LOCK_TIMEOUT)
}

/// Add up to 50% of `floor` so concurrent callers do not retry in lockstep.
fn with_jitter(floor: Duration) -> Duration {
    floor + floor.mul_f64(rand::rng().random_range(0.0..=0.5))
}

/// Run `op`, retrying per `policy`. `status_of` extracts the gRPC status from
/// the caller's error type; `on_retry` receives the wait and the next attempt number.
///
/// # Errors
///
/// Returns the last error once the budget is spent or the error is not retryable.
pub async fn retry_create<T, E, F, Fut>(
    policy: RetryPolicy,
    mut op: F,
    status_of: impl Fn(&E) -> Option<&Status>,
    mut on_retry: impl FnMut(Duration, u32),
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let started = Instant::now();
    let mut attempt = 1;
    loop {
        let error = match op().await {
            Ok(value) => return Ok(value),
            Err(error) => error,
        };
        let Some(floor) = status_of(&error).and_then(|s| retry_floor(s, attempt > 1)) else {
            return Err(error);
        };
        let wait = with_jitter(floor);
        if started.elapsed() + wait > policy.max_elapsed {
            return Err(error);
        }
        attempt += 1;
        on_retry(wait, attempt);
        tokio::time::sleep(wait).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc_error::{already_exists_transient, unavailable};
    use std::sync::Mutex;

    fn lock_timeout(delay: Duration) -> Status {
        unavailable(MUTATION_LOCK_TIMEOUT, "busy", delay)
    }

    fn deleting() -> Status {
        already_exists_transient(SANDBOX_DELETING, "being deleted", FALLBACK_DELAY)
    }

    async fn run(
        policy: RetryPolicy,
        mut results: Vec<Result<u32, Status>>,
    ) -> (Result<u32, Status>, Vec<Duration>) {
        results.reverse();
        let results = Mutex::new(results);
        let waits = Mutex::new(Vec::new());
        let result = retry_create(
            policy,
            || {
                let next = results
                    .lock()
                    .unwrap()
                    .pop()
                    .expect("unexpected extra attempt");
                async move { next }
            },
            |status: &Status| Some(status),
            |wait, _| waits.lock().unwrap().push(wait),
        )
        .await;
        (result, waits.into_inner().unwrap())
    }

    #[tokio::test(start_paused = true)]
    async fn waits_at_least_the_server_delay_between_attempts() {
        let floor = Duration::from_secs(2);
        let (result, waits) = run(
            RetryPolicy::lock_contention(),
            vec![Err(lock_timeout(floor)), Err(lock_timeout(floor)), Ok(7)],
        )
        .await;
        assert_eq!(result.unwrap(), 7);
        assert_eq!(waits.len(), 2);
        assert!(waits.iter().all(|w| *w >= floor && *w <= floor * 2));
    }

    #[tokio::test(start_paused = true)]
    async fn stops_when_the_budget_is_spent() {
        let policy = RetryPolicy::lock_contention().max_elapsed(Duration::from_secs(3));
        let one = Duration::from_secs(1);
        let (result, waits) = run(policy, vec![Err(lock_timeout(one)); 4]).await;
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unavailable);
        assert!(!waits.is_empty() && waits.len() < 3, "{waits:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn none_never_retries() {
        let (result, waits) =
            run(RetryPolicy::none(), vec![Err(lock_timeout(FALLBACK_DELAY))]).await;
        assert!(result.is_err());
        assert!(waits.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn other_errors_are_not_retried() {
        for status in [
            Status::unavailable("down"),
            unavailable("DATABASE_UNAVAILABLE", "db", FALLBACK_DELAY),
            Status::already_exists("taken"),
            Status::internal("boom"),
        ] {
            let (result, waits) = run(RetryPolicy::lock_contention(), vec![Err(status)]).await;
            assert!(result.is_err());
            assert!(waits.is_empty());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn deleting_conflict_waits_for_cleanup_only_after_a_failed_attempt() {
        let (result, waits) = run(RetryPolicy::lock_contention(), vec![Err(deleting())]).await;
        assert_eq!(result.unwrap_err().code(), tonic::Code::AlreadyExists);
        assert!(waits.is_empty());

        let (result, waits) = run(
            RetryPolicy::lock_contention(),
            vec![
                Err(lock_timeout(FALLBACK_DELAY)),
                Err(deleting()),
                Err(deleting()),
                Ok(1),
            ],
        )
        .await;
        assert_eq!(result.unwrap(), 1);
        assert_eq!(waits.len(), 3);
    }

    #[test]
    fn lock_contention_is_classified_by_reason_not_code() {
        assert!(is_lock_contention(&lock_timeout(FALLBACK_DELAY)));
        assert!(!is_lock_contention(&Status::unavailable("busy")));
    }
}
