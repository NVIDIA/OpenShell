// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cross-component anonymous network activity event type.
//!
//! `ActivityEvent` is emitted by the supervisor's networking proxy and by
//! the supervisor's bypass monitor on every observed connection attempt
//! (allowed or denied). It is consumed by the orchestrator-side
//! `ActivityAggregator` which counts events, sanitizes deny groups, and
//! periodically flushes anonymous summaries to the gateway.
//!
//! It lives in `openshell-core` because both supervisor leaves
//! (`openshell-supervisor-network` and `openshell-supervisor-process`)
//! produce it and need a shared type without depending on each other.

use tokio::sync::mpsc;

/// Channel capacity for the per-sandbox activity event queue.
pub const ACTIVITY_EVENT_QUEUE_CAPACITY: usize = 1024;

/// A single anonymous network activity event.
#[derive(Debug, Clone)]
pub struct ActivityEvent {
    /// Whether the action was denied.
    pub denied: bool,
    /// The deny group label (e.g. `connect_policy`, `l7_policy`, `bypass`).
    /// Static so producers cannot leak per-request data into the channel.
    pub deny_group: &'static str,
}

/// Shorthand for the producer side of the activity channel.
pub type ActivitySender = mpsc::Sender<ActivityEvent>;

/// Non-blocking emit. Drops the event if the queue is full.
/// Returns whether the event was enqueued.
pub fn try_record_activity(tx: &ActivitySender, denied: bool, deny_group: &'static str) -> bool {
    tx.try_send(ActivityEvent { denied, deny_group }).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activity_send_drops_when_queue_is_full() {
        let (tx, _rx) = mpsc::channel(1);
        assert!(try_record_activity(&tx, false, "unknown"));
        assert!(!try_record_activity(&tx, true, "connect_policy"));
    }
}
