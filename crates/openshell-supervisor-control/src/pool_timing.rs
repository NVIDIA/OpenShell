// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Timing contract between a supervisor pool's hosts and the gateway.
//!
//! The gateway replica that serves a member's stream refreshes the member's
//! durable record; a record older than [`MEMBER_TTL`] is dead, and any replica
//! then takes the member's instances over. A healthy member whose serving
//! replica stops answering without resetting the connection (frozen, or
//! partitioned from the member only) must therefore notice the silence,
//! reconnect through the gateway Service to a replica that answers, and be
//! refreshed there before its record expires. [`reconnect_budget`] is that
//! worst case; it stays well inside [`MEMBER_TTL`] even when the first
//! [`COVERED_UNANSWERED_ATTEMPTS`] attempts reach the unresponsive replica
//! again. A member cut off from every replica still expires after
//! [`MEMBER_TTL`], so a true partition fails over as before.
//!
//! Conversely, a replica stops refreshing a member that died without closing
//! its stream once the stream has been silent for
//! [`GATEWAY_SILENCE_TIMEOUT`], so the member's record expires and its
//! instances move well inside the runtime's recovery deadline.

use std::time::Duration;

/// Age after which a member's durable record means the member is dead.
pub const MEMBER_TTL: Duration = Duration::from_secs(15);
/// Interval at which a gateway replica refreshes the records of the members
/// it serves, independently of its reconciliation passes. A member that
/// attaches or announces leaving is refreshed at once.
pub const MEMBER_REFRESH_INTERVAL: Duration = Duration::from_secs(2);
/// Interval of heartbeats in both directions on a pool member's stream.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
/// Silence after which a gateway replica closes a pool member's stream and
/// stops refreshing its record. Also bounds queueing one message to the
/// member, so a member that stops reading is dropped as soon.
pub const GATEWAY_SILENCE_TIMEOUT: Duration = Duration::from_secs(5);
/// Silence after which a pool host abandons its stream and reconnects.
pub const HOST_SILENCE_TIMEOUT: Duration = Duration::from_secs(3);
/// How often a pool host checks its stream for silence.
pub const HOST_SILENCE_CHECK: Duration = Duration::from_millis(250);
/// Bound on one pool host attempt to connect and be accepted.
///
/// It applies to the first attempts after a stream is lost. Later attempts
/// get the host's ordinary bound, so a slow but responsive gateway is still
/// reached.
pub const HOST_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(1);
/// First pool host reconnect backoff; it doubles up to
/// [`HOST_RECONNECT_BACKOFF_MAX`].
pub const HOST_RECONNECT_BACKOFF_MIN: Duration = Duration::from_millis(100);
/// Longest pool host reconnect backoff, before jitter.
pub const HOST_RECONNECT_BACKOFF_MAX: Duration = Duration::from_millis(400);
/// Jitter added to a pool host backoff, at most this fraction of it.
pub const HOST_RECONNECT_JITTER: f64 = 0.5;
/// Attempts after a lost stream that use [`HOST_ATTEMPT_TIMEOUT`] and that
/// [`reconnect_budget`] allows to reach an unresponsive replica again.
pub const COVERED_UNANSWERED_ATTEMPTS: u32 = 3;
/// Bound on the gateway writing one member's record. A replica writes the
/// records of all the members it serves at once, so one refresh round takes
/// no longer either.
pub const RECORD_WRITE_BOUND: Duration = Duration::from_millis(500);

/// Longest pool host backoff before attempt `attempt` (1-based) after a lost
/// stream, jitter included.
#[must_use]
pub fn host_backoff_bound(attempt: u32) -> Duration {
    let doubled = HOST_RECONNECT_BACKOFF_MIN
        .saturating_mul(1_u32 << attempt.saturating_sub(1).min(16))
        .min(HOST_RECONNECT_BACKOFF_MAX);
    doubled.mul_f64(1.0 + HOST_RECONNECT_JITTER)
}

/// Worst case from a member's serving replica going unresponsive to another
/// replica refreshing the member's record.
///
/// The first `unanswered` attempts reach the unresponsive replica again. The
/// sum is the record's age when the replica stopped, silence detection, each
/// unanswered attempt and its backoff, the answered attempt, and two refresh
/// rounds on the answering replica: one already in flight when the member
/// attaches, and the one the attach starts.
#[must_use]
pub fn reconnect_budget(unanswered: u32) -> Duration {
    let mut budget = MEMBER_REFRESH_INTERVAL + HOST_SILENCE_TIMEOUT + HOST_SILENCE_CHECK;
    for attempt in 1..=unanswered {
        budget += HOST_ATTEMPT_TIMEOUT + host_backoff_bound(attempt);
    }
    budget + HOST_ATTEMPT_TIMEOUT + RECORD_WRITE_BOUND * 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_member_reconnects_well_before_its_record_expires() {
        let budget = reconnect_budget(COVERED_UNANSWERED_ATTEMPTS);
        // At least a fifth of the TTL is left after the covered worst case.
        assert!(
            budget + MEMBER_TTL / 5 <= MEMBER_TTL,
            "reconnect budget {budget:?} leaves too little of the {MEMBER_TTL:?} TTL"
        );
        // Heartbeats are frequent enough that silence means several were
        // missed, and the runtime's recovery deadline outlasts expiry,
        // takeover, and a replacement's start.
        assert!(HOST_SILENCE_TIMEOUT >= HEARTBEAT_INTERVAL * 3);
        assert!(GATEWAY_SILENCE_TIMEOUT >= HEARTBEAT_INTERVAL * 3);
        // A member that died without closing its stream: the stream goes
        // silent, its record's last refresh ages out, and a pass takes its
        // instances over, all within half the runtime's recovery deadline.
        assert!(
            (GATEWAY_SILENCE_TIMEOUT
                + MEMBER_REFRESH_INTERVAL
                + MEMBER_TTL
                + MEMBER_REFRESH_INTERVAL)
                * 2
                < Duration::from_secs(u64::from(crate::controller::POOL_RECOVERY_TIMEOUT_SECS))
        );
        assert!(
            MEMBER_TTL * 2
                < Duration::from_secs(u64::from(crate::controller::POOL_RECOVERY_TIMEOUT_SECS))
        );
        assert!(
            GATEWAY_SILENCE_TIMEOUT
                + MEMBER_REFRESH_INTERVAL
                + MEMBER_TTL
                + MEMBER_REFRESH_INTERVAL
                + Duration::from_secs(5)
                <= Duration::from_secs(u64::from(
                    *crate::controller::POOL_RECOVERY_TIMEOUT_RANGE.start()
                ))
        );
        assert!(
            crate::controller::POOL_RECOVERY_TIMEOUT_RANGE
                .contains(&crate::controller::POOL_RECOVERY_TIMEOUT_SECS)
        );
        assert_eq!(host_backoff_bound(1), Duration::from_millis(150));
        assert_eq!(host_backoff_bound(10), Duration::from_millis(600));
    }
}
