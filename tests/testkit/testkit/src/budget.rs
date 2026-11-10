// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The time one test may take, so a stuck step fails with its own error
//! before whoever runs the tests stops the test with a generic timeout.
//!
//! The runner exports the limit it enforces in [`TIMEOUT_ENV`]. Without it,
//! as when a test runs under plain `cargo test`, nothing is capped and each
//! step keeps its own timeout.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// The per-test limit the runner enforces, in seconds.
pub const TIMEOUT_ENV: &str = "OPENSHELL_TEST_TIMEOUT_SECS";

/// How long before the limit a step gives up, so its error is reported and
/// the test cleans up before the runner stops it.
const MARGIN: Duration = Duration::from_secs(5);

/// The least a step is given, so it still reports a timeout of its own.
const FLOOR: Duration = Duration::from_secs(1);

/// Set once the test body is over: cleanup needs its own timeouts, because it
/// is most needed when the budget ran out.
static RELEASED: AtomicBool = AtomicBool::new(false);

static DEADLINE: OnceLock<Option<Instant>> = OnceLock::new();

/// Start the clock for the current test. Call once, when the test starts.
pub(crate) fn start() {
    DEADLINE.get_or_init(|| deadline_from(std::env::var(TIMEOUT_ENV).ok().as_deref()));
}

/// Stop capping, for cleanup.
pub(crate) fn release() {
    RELEASED.store(true, Ordering::Relaxed);
}

fn deadline_from(value: Option<&str>) -> Option<Instant> {
    let secs: u64 = value?.trim().parse().ok().filter(|secs| *secs > 0)?;
    Instant::now().checked_add(Duration::from_secs(secs).saturating_sub(MARGIN))
}

/// `timeout`, or the time left in the test's budget if that is less.
pub(crate) fn cap(timeout: Duration) -> Duration {
    if RELEASED.load(Ordering::Relaxed) {
        return timeout;
    }
    cap_at(timeout, DEADLINE.get().copied().flatten())
}

fn cap_at(timeout: Duration, deadline: Option<Instant>) -> Duration {
    match deadline {
        Some(deadline) => timeout.min(
            deadline
                .saturating_duration_since(Instant::now())
                .max(FLOOR),
        ),
        None => timeout,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_limit_leaves_the_timeout_alone() {
        assert_eq!(deadline_from(None), None);
        assert_eq!(deadline_from(Some("soon")), None);
        assert_eq!(deadline_from(Some("0")), None);
        assert_eq!(
            cap_at(Duration::from_secs(300), None),
            Duration::from_secs(300)
        );
    }

    #[test]
    fn a_step_gets_no_more_than_the_time_left() {
        let deadline = deadline_from(Some("120")).unwrap();
        let capped = cap_at(Duration::from_secs(300), Some(deadline));
        assert!(capped <= Duration::from_secs(115), "{capped:?}");
        assert!(capped > Duration::from_secs(100), "{capped:?}");
        // A short step keeps its own timeout.
        assert_eq!(
            cap_at(Duration::from_secs(10), Some(deadline)),
            Duration::from_secs(10)
        );
    }

    #[test]
    fn an_exhausted_budget_still_leaves_a_floor() {
        let passed = Instant::now();
        assert_eq!(cap_at(Duration::from_secs(300), Some(passed)), FLOOR);
    }
}
