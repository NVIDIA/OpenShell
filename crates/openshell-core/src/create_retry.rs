// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Retry policy for sandbox creates that lose the gateway mutation lock.
//!
//! The gateway rejects a create with `UNAVAILABLE` and
//! [`MUTATION_LOCK_TIMEOUT`](crate::rpc_error::MUTATION_LOCK_TIMEOUT) when a
//! concurrent mutation holds the sandbox record past the lock budget, and
//! `RetryInfo` carries the minimum delay before another attempt.
//!
//! The module is pure: it takes decoded observations and returns a decision.
//! Clock, sleeping, and transport stay with the caller, so the SDK and the CLI
//! drive their loops from the same policy and cannot drift.
//!
//! A named create can also surface `AlreadyExists` while the previous sandbox
//! with that name is still being deleted. [`plan_already_exists`] decides
//! between waiting, retrying the create, and stopping for each observed phase.

use std::time::Duration;

/// Delay used when the gateway omits `RetryInfo`.
pub const DEFAULT_RETRY_DELAY: Duration = Duration::from_secs(1);

/// Upper bound on the jitter added to each retry delay.
pub const MAX_RETRY_JITTER: Duration = Duration::from_millis(500);

/// Ceiling of the exponential retry-delay floor.
pub const MAX_RETRY_DELAY: Duration = Duration::from_secs(10);

/// Ceiling of the exponential cleanup-wait floor.
pub const MAX_CLEANUP_WAIT_DELAY: Duration = Duration::from_secs(5);

/// Create sends one retrying call may make, including the first.
///
/// The cap bounds how long a retrying create can re-enter the gateway's
/// mutation-lock wait, which holds a lock-pool connection for its whole
/// budget. The wall-clock budget alone does not bound that share.
pub const MAX_CREATE_ATTEMPTS: u32 = 5;

/// Consecutive `NotFound` observations that may drive a create retry.
pub const MAX_NOT_FOUND_RETRIES: u32 = 3;

/// Decision for the next create attempt after a mutation-lock timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryPlan {
    /// Sleep for the given duration, then send the create again.
    Sleep(Duration),
    /// Stop retrying and surface the last error.
    Stop,
}

/// Plan the next create attempt after a mutation-lock timeout.
///
/// `server_delay` is the decoded `RetryInfo` delay; an absent or zero delay
/// falls back to [`DEFAULT_RETRY_DELAY`]. `attempt` counts the create attempts
/// made so far, including the one that just failed: the plan stops once that
/// count reaches [`MAX_CREATE_ATTEMPTS`], so a retrying create cannot keep
/// re-entering the gateway's lock wait on the wall-clock budget alone. The
/// delay floor doubles per retry starting from the server delay, capped at
/// [`MAX_RETRY_DELAY`]. `seed` decorrelates concurrent clients: callers derive
/// one per client instance and keep it stable across attempts. The jitter stays
/// within `min(MAX_RETRY_JITTER, delay / 2)`.
///
/// The sleep includes the jitter. A sleep that does not fit in
/// `remaining_budget` stops instead of overrunning the caller's deadline.
#[must_use]
pub fn plan_retry(
    server_delay: Option<Duration>,
    attempt: u32,
    seed: u64,
    remaining_budget: Duration,
) -> RetryPlan {
    if attempt >= MAX_CREATE_ATTEMPTS {
        return RetryPlan::Stop;
    }
    let delay = backoff_floor(
        retry_delay_floor(server_delay),
        attempt.saturating_sub(1),
        MAX_RETRY_DELAY,
    );
    let sleep = delay.saturating_add(jitter(seed, attempt, delay));
    if sleep <= remaining_budget {
        RetryPlan::Sleep(sleep)
    } else {
        RetryPlan::Stop
    }
}

/// Phase observed for the sandbox that already holds a requested name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupPhase {
    /// The holder is being deleted; the name frees when cleanup finishes.
    Deleting,
    /// The holder is still being created. Its name is not free yet, but a
    /// failed create compensates its record, so the conflict may resolve.
    Provisioning,
    /// The holder is not visible to this caller: the record is gone or hidden.
    NotFound,
    /// The holder is live and keeps the name.
    Live,
}

/// Decision for a named create that failed with `AlreadyExists`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlreadyExistsPlan {
    /// Wait for the holder's deletion, then observe its phase again.
    Wait(Duration),
    /// Send the create again immediately; the name may already be free.
    RetryCreate,
    /// Stop retrying and surface the conflict.
    Stop,
}

/// Plan the next step for a named create that hit `AlreadyExists`.
///
/// `not_found_retries` counts the consecutive `NotFound` observations that
/// already drove a create retry. `attempts_made` counts every create attempt
/// so far, including the one that hit the conflict; a retry that would exceed
/// [`MAX_CREATE_ATTEMPTS`] stops instead.
///
/// A `Deleting` holder keeps the name until cleanup finishes, so the plan waits
/// one poll interval: the decoded server delay, defaulting to
/// [`DEFAULT_RETRY_DELAY`], doubled per consecutive wait up to
/// [`MAX_CLEANUP_WAIT_DELAY`], plus jitter derived from `wait_attempt` and
/// `seed`. A `Provisioning` holder is waited out the same way: its record is
/// not a live sandbox yet, and a failed create compensates it, so the name can
/// still free. `NotFound` never waits, because either the record is gone (the
/// retry can win) or it is invisible to this principal (waiting will not
/// reveal it); the retry is capped at [`MAX_NOT_FOUND_RETRIES`] so an invisible
/// holder fails fast. A live holder keeps the name, including a holder that was
/// `Deleting` and came back live: both are terminal conflicts.
#[must_use]
pub fn plan_already_exists(
    observed: CleanupPhase,
    not_found_retries: u32,
    poll_delay: Option<Duration>,
    wait_attempt: u32,
    attempts_made: u32,
    seed: u64,
) -> AlreadyExistsPlan {
    match observed {
        CleanupPhase::Deleting | CleanupPhase::Provisioning => {
            AlreadyExistsPlan::Wait(cleanup_wait_delay(poll_delay, wait_attempt, seed))
        }
        CleanupPhase::NotFound
            if not_found_retries < MAX_NOT_FOUND_RETRIES && attempts_made < MAX_CREATE_ATTEMPTS =>
        {
            AlreadyExistsPlan::RetryCreate
        }
        CleanupPhase::NotFound | CleanupPhase::Live => AlreadyExistsPlan::Stop,
    }
}

/// Delay before the next `AlreadyExists` phase poll.
///
/// `wait_attempt` counts the consecutive waits already spent on this conflict:
/// the floor doubles from `poll_delay` (defaulting to [`DEFAULT_RETRY_DELAY`])
/// per wait, capped at [`MAX_CLEANUP_WAIT_DELAY`], and jitter of at most
/// `min(MAX_RETRY_JITTER, delay / 2)` spreads contending clients.
#[must_use]
pub fn cleanup_wait_delay(poll_delay: Option<Duration>, wait_attempt: u32, seed: u64) -> Duration {
    let delay = backoff_floor(
        retry_delay_floor(poll_delay),
        wait_attempt,
        MAX_CLEANUP_WAIT_DELAY,
    );
    delay.saturating_add(jitter(seed, wait_attempt, delay))
}

/// Suffix appended to a create failure that ended the retry loop.
///
/// Names the create attempt count and, when supplied, the original mutation
/// lock timeout. Both client loops share the format so they cannot drift.
#[must_use]
pub fn retry_stopped_suffix(attempts: u32, lock_timeout: Option<&str>) -> String {
    use std::fmt::Write as _;

    let plural = if attempts == 1 { "" } else { "s" };
    let mut suffix = format!(" (create retry stopped after {attempts} create attempt{plural}");
    if let Some(message) = lock_timeout {
        let _ = write!(suffix, "; last mutation lock timeout: {message}");
    }
    suffix.push(')');
    suffix
}

/// Delay floor shared by retries and cleanup polls.
fn retry_delay_floor(server_delay: Option<Duration>) -> Duration {
    server_delay
        .filter(|delay| !delay.is_zero())
        .unwrap_or(DEFAULT_RETRY_DELAY)
}

/// `base * 2^step`, capped at `cap` but never below `base`.
///
/// A server-supplied delay is a minimum the client promised to honor, so a
/// delay above the ceiling stays binding instead of being silently shortened.
fn backoff_floor(base: Duration, step: u32, cap: Duration) -> Duration {
    let factor = 1_u32 << step.min(31);
    base.saturating_mul(factor).min(cap.max(base))
}

/// Jitter for one attempt, capped at `min(MAX_RETRY_JITTER, delay / 2)`.
fn jitter(seed: u64, attempt: u32, delay: Duration) -> Duration {
    let bound = (delay / 2).min(MAX_RETRY_JITTER);
    let bound_nanos = u64::try_from(bound.as_nanos()).unwrap_or(u64::MAX);
    if bound_nanos == 0 {
        return Duration::ZERO;
    }
    Duration::from_nanos(mix(seed ^ mix(u64::from(attempt))) % bound_nanos)
}

/// `SplitMix64` finalizer: deterministic mixing without a dependency.
fn mix(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9E37_79B9_7F4A_7C15);
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn sleep_of(plan: RetryPlan) -> Duration {
        match plan {
            RetryPlan::Sleep(sleep) => sleep,
            RetryPlan::Stop => panic!("expected a retry sleep, got a terminal plan"),
        }
    }

    #[test]
    fn absent_delay_uses_the_one_second_floor() {
        let sleep = sleep_of(plan_retry(None, 0, 7, Duration::from_mins(1)));
        assert!(sleep >= DEFAULT_RETRY_DELAY);
        assert!(sleep <= DEFAULT_RETRY_DELAY + MAX_RETRY_JITTER);
    }

    #[test]
    fn zero_delay_uses_the_one_second_floor() {
        let sleep = sleep_of(plan_retry(
            Some(Duration::ZERO),
            0,
            7,
            Duration::from_mins(1),
        ));
        assert!(sleep >= DEFAULT_RETRY_DELAY);
    }

    #[test]
    fn server_delay_is_the_floor_and_short_delays_cap_jitter_at_half() {
        let delay = Duration::from_millis(200);
        let sleep = sleep_of(plan_retry(Some(delay), 0, 7, Duration::from_mins(1)));
        assert!(sleep >= delay);
        assert!(sleep <= delay + delay / 2);
    }

    #[test]
    fn jitter_is_capped_at_the_maximum() {
        let delay = Duration::from_secs(10);
        let seed = 7;
        let attempt = 0;
        assert!(jitter(seed, attempt, delay) <= MAX_RETRY_JITTER);
        let sleep = sleep_of(plan_retry(
            Some(delay),
            attempt,
            seed,
            Duration::from_mins(1),
        ));
        assert!(sleep <= delay + MAX_RETRY_JITTER);
    }

    #[test]
    fn a_sleep_that_exceeds_the_remaining_budget_stops() {
        assert_eq!(
            plan_retry(None, 0, 7, Duration::ZERO),
            RetryPlan::Stop,
            "a zero budget cannot cover the delay floor"
        );
        let sleep = sleep_of(plan_retry(None, 0, 7, Duration::from_mins(1)));
        assert_eq!(plan_retry(None, 0, 7, sleep), RetryPlan::Sleep(sleep));
        let just_short = sleep.checked_sub(Duration::from_nanos(1)).unwrap();
        assert_eq!(plan_retry(None, 0, 7, just_short), RetryPlan::Stop);
    }

    #[test]
    fn retry_delay_floor_doubles_per_attempt_and_caps() {
        let delay = Duration::from_millis(200);
        for (attempt, floor) in [
            (1, Duration::from_millis(200)),
            (2, Duration::from_millis(400)),
            (3, Duration::from_millis(800)),
            (4, Duration::from_millis(1600)),
        ] {
            let sleep = sleep_of(plan_retry(Some(delay), attempt, 7, Duration::from_mins(1)));
            assert!(sleep >= floor, "attempt {attempt}: {sleep:?} < {floor:?}");
            assert!(
                sleep <= floor + floor / 2,
                "attempt {attempt}: {sleep:?} exceeds the jitter bound of {floor:?}"
            );
        }
        // A four-second server delay doubles past the ten-second ceiling.
        let capped = sleep_of(plan_retry(
            Some(Duration::from_secs(4)),
            4,
            7,
            Duration::from_mins(1),
        ));
        assert!(
            capped <= MAX_RETRY_DELAY + MAX_RETRY_JITTER,
            "the floor must stop at {MAX_RETRY_DELAY:?}: {capped:?}"
        );
    }

    #[test]
    fn a_server_delay_above_the_ceiling_stays_binding() {
        let server_delay = Duration::from_secs(30);
        // The documented contract is "retry after at least the supplied delay",
        // so the ten-second ceiling must never shorten a larger server minimum.
        assert_eq!(
            plan_retry(Some(server_delay), 1, 7, Duration::from_secs(20)),
            RetryPlan::Stop,
            "a twenty-second budget cannot cover a thirty-second server minimum"
        );
        let sleep = sleep_of(plan_retry(Some(server_delay), 1, 7, Duration::from_mins(1)));
        assert!(
            sleep >= server_delay,
            "the floor must not drop below the server minimum: {sleep:?}"
        );
    }

    #[test]
    fn a_cleanup_poll_delay_above_the_ceiling_stays_binding() {
        let poll_delay = Duration::from_secs(30);
        let AlreadyExistsPlan::Wait(delay) =
            plan_already_exists(CleanupPhase::Deleting, 0, Some(poll_delay), 1, 1, 7)
        else {
            panic!("a deleting holder must wait");
        };
        assert!(
            delay >= poll_delay,
            "the cleanup wait must not drop below the server poll delay: {delay:?}"
        );
    }

    #[test]
    fn attempt_cap_stops_the_retry() {
        let budget = Duration::from_mins(1);
        assert!(matches!(
            plan_retry(None, MAX_CREATE_ATTEMPTS - 1, 7, budget),
            RetryPlan::Sleep(_)
        ));
        assert_eq!(
            plan_retry(None, MAX_CREATE_ATTEMPTS, 7, budget),
            RetryPlan::Stop,
            "a create that already spent the attempt cap must not retry"
        );
    }

    #[test]
    fn distinct_seeds_decorrelate_jitter_at_the_same_attempt() {
        let delay = Duration::from_secs(1);
        let jitters: BTreeSet<Duration> = (0..16).map(|seed| jitter(seed, 0, delay)).collect();
        assert!(
            jitters.len() > 1,
            "every seed produced the same jitter: {jitters:?}"
        );
    }

    #[test]
    fn deleting_holder_waits_back_off_and_stay_jittered() {
        // No server poll delay: the one-second floor doubles per wait and
        // stops at five seconds.
        for (wait_attempt, floor) in [
            (0, Duration::from_secs(1)),
            (1, Duration::from_secs(2)),
            (2, Duration::from_secs(4)),
            (3, MAX_CLEANUP_WAIT_DELAY),
            (8, MAX_CLEANUP_WAIT_DELAY),
        ] {
            let AlreadyExistsPlan::Wait(delay) =
                plan_already_exists(CleanupPhase::Deleting, 0, None, wait_attempt, 1, 7)
            else {
                panic!("a deleting holder must wait");
            };
            assert!(
                delay >= floor,
                "wait {wait_attempt}: {delay:?} is below the {floor:?} floor"
            );
            assert!(
                delay <= floor + floor / 2,
                "wait {wait_attempt}: {delay:?} exceeds the jitter bound of {floor:?}"
            );
        }

        let poll = Duration::from_millis(250);
        let AlreadyExistsPlan::Wait(first) =
            plan_already_exists(CleanupPhase::Deleting, 0, Some(poll), 0, 1, 7)
        else {
            panic!("a deleting holder must wait");
        };
        assert!(first >= poll && first <= poll + poll / 2);
        let AlreadyExistsPlan::Wait(zero_floor) =
            plan_already_exists(CleanupPhase::Deleting, 0, Some(Duration::ZERO), 0, 1, 7)
        else {
            panic!("a deleting holder must wait");
        };
        assert!(zero_floor >= DEFAULT_RETRY_DELAY);
    }

    #[test]
    fn cleanup_wait_jitter_decorrelates_seeds() {
        let waits: BTreeSet<Duration> = (0..16)
            .map(|seed| cleanup_wait_delay(None, 0, seed))
            .collect();
        assert!(
            waits.len() > 1,
            "every seed produced the same cleanup wait: {waits:?}"
        );
    }

    #[test]
    fn provisioning_holder_is_waited_out() {
        // A holder that is still creating is not a live sandbox yet: a failed
        // create compensates its record, so the wait must continue instead of
        // stopping on a spurious conflict.
        let AlreadyExistsPlan::Wait(delay) =
            plan_already_exists(CleanupPhase::Provisioning, 0, None, 0, 1, 7)
        else {
            panic!("a provisioning holder must be waited out");
        };
        assert!(delay >= DEFAULT_RETRY_DELAY);
        assert!(delay <= DEFAULT_RETRY_DELAY + MAX_RETRY_JITTER);
        // Once the record disappears, the create may be sent again.
        assert_eq!(
            plan_already_exists(CleanupPhase::NotFound, 0, None, 1, 1, 7),
            AlreadyExistsPlan::RetryCreate
        );
    }

    #[test]
    fn not_found_retries_the_create_and_is_capped() {
        for retries in 0..MAX_NOT_FOUND_RETRIES {
            assert_eq!(
                plan_already_exists(CleanupPhase::NotFound, retries, None, 0, 1, 7),
                AlreadyExistsPlan::RetryCreate,
                "NotFound retry {retries} should resend the create"
            );
        }
        assert_eq!(
            plan_already_exists(CleanupPhase::NotFound, MAX_NOT_FOUND_RETRIES, None, 0, 1, 7),
            AlreadyExistsPlan::Stop
        );
    }

    #[test]
    fn attempt_cap_stops_a_not_found_retry() {
        assert_eq!(
            plan_already_exists(CleanupPhase::NotFound, 0, None, 0, MAX_CREATE_ATTEMPTS, 7,),
            AlreadyExistsPlan::Stop,
            "a retry that would exceed the attempt cap must stop"
        );
    }

    #[test]
    fn live_holder_is_terminal_including_a_deleting_to_live_flip() {
        assert_eq!(
            plan_already_exists(CleanupPhase::Live, 0, None, 0, 1, 7),
            AlreadyExistsPlan::Stop
        );
        let deleting = plan_already_exists(CleanupPhase::Deleting, 0, None, 0, 1, 7);
        assert!(matches!(deleting, AlreadyExistsPlan::Wait(_)));
        // The same create polls a Deleting holder, then sees it live again:
        // the deletion was abandoned and the name stays taken.
        let after_flip = plan_already_exists(CleanupPhase::Live, 0, None, 1, 1, 7);
        assert_eq!(after_flip, AlreadyExistsPlan::Stop);
    }

    #[test]
    fn retry_stopped_suffix_names_attempts_and_the_cause() {
        assert_eq!(
            retry_stopped_suffix(2, Some("gateway busy")),
            " (create retry stopped after 2 create attempts; last mutation lock timeout: gateway busy)"
        );
        assert_eq!(
            retry_stopped_suffix(1, None),
            " (create retry stopped after 1 create attempt)"
        );
    }
}
