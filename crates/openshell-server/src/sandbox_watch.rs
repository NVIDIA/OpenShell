// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! In-memory buses to support sandbox watch streaming.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use openshell_core::proto::SandboxStreamWarning;
use tokio::sync::broadcast;

/// Broadcast bus of sandbox updates keyed by sandbox id.
///
/// Producers call [`SandboxWatchBus::notify`] whenever the persisted sandbox record changes.
/// Consumers can subscribe per-id to drive streaming updates without polling.
#[derive(Debug, Clone)]
pub struct SandboxWatchBus {
    inner: Arc<Mutex<HashMap<String, broadcast::Sender<()>>>>,
}

impl SandboxWatchBus {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Private method to register sandbox in the `SandboxWatchBus` registry if it does not exist.
    fn sender_for(&self, sandbox_id: &str) -> broadcast::Sender<()> {
        let mut inner = self.inner.lock().expect("sandbox watch bus lock poisoned");
        inner
            .entry(sandbox_id.to_string())
            .or_insert_with(|| {
                // Small buffer; lag is handled best-effort by the stream.
                let (tx, _rx) = broadcast::channel(128);
                tx
            })
            .clone()
    }

    /// Notify watchers that the sandbox record has changed.
    pub fn notify(&self, sandbox_id: &str) {
        let tx = self.sender_for(sandbox_id);
        let _ = tx.send(());
    }

    /// Subscribe to sandbox updates.
    pub fn subscribe(&self, sandbox_id: &str) -> broadcast::Receiver<()> {
        self.sender_for(sandbox_id).subscribe()
    }

    /// Remove the bus entry for the given sandbox id.
    ///
    /// This drops the broadcast sender, closing any active receivers with
    /// `RecvError::Closed`.
    pub fn remove(&self, sandbox_id: &str) {
        let mut inner = self.inner.lock().expect("sandbox watch bus lock poisoned");
        inner.remove(sandbox_id);
    }
}

/// Build the warning payload emitted when a watch broadcast receiver lags.
///
/// Broadcast lag is recoverable: the receiver skips ahead to the oldest
/// surviving message, so the stream continues after surfacing this warning
/// instead of terminating.
pub fn lag_warning(n: u64) -> SandboxStreamWarning {
    SandboxStreamWarning {
        message: format!("watch stream lagged; dropped {n} messages"),
    }
}

/// Wrap [`lag_warning`] in a `SandboxStreamEvent` ready to send on the stream.
pub fn lag_warning_event(n: u64) -> openshell_core::proto::SandboxStreamEvent {
    use openshell_core::proto::sandbox_stream_event::Payload;
    openshell_core::proto::SandboxStreamEvent {
        payload: Some(Payload::Warning(lag_warning(n))),
        // Warnings are not part of the resumable log/platform sequence.
        cursor: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_watch_bus_remove_cleans_up() {
        let bus = SandboxWatchBus::new();
        let sandbox_id = "sb-1";

        let mut rx = bus.subscribe(sandbox_id);

        // Notify and receive
        bus.notify(sandbox_id);
        assert!(rx.try_recv().is_ok());

        // Remove
        bus.remove(sandbox_id);

        // Receiver should be closed
        match rx.try_recv() {
            Err(broadcast::error::TryRecvError::Closed) => {} // expected
            other => panic!("expected Closed, got {other:?}"),
        }
    }

    #[test]
    fn sandbox_watch_bus_subscribe_after_remove_creates_fresh_channel() {
        let bus = SandboxWatchBus::new();
        let sandbox_id = "sb-2";

        let _old_rx = bus.subscribe(sandbox_id);
        bus.remove(sandbox_id);

        // New subscription should work
        let mut new_rx = bus.subscribe(sandbox_id);
        bus.notify(sandbox_id);
        assert!(new_rx.try_recv().is_ok());
    }

    #[test]
    fn sandbox_watch_bus_remove_nonexistent_is_noop() {
        let bus = SandboxWatchBus::new();
        // Should not panic
        bus.remove("nonexistent");
    }

    #[test]
    fn lag_warning_reports_dropped_count() {
        let warning = lag_warning(7);
        assert!(
            warning.message.contains('7'),
            "message: {}",
            warning.message
        );
        assert!(
            warning.message.contains("lagged"),
            "message: {}",
            warning.message
        );
    }

    #[test]
    fn lag_warning_event_wraps_warning_payload() {
        use openshell_core::proto::sandbox_stream_event::Payload;
        let evt = lag_warning_event(3);
        match evt.payload {
            Some(Payload::Warning(w)) => assert!(w.message.contains('3')),
            other => panic!("expected Warning payload, got {other:?}"),
        }
    }

    // Broadcast lag is recoverable at the tokio layer: after `Lagged`, the same
    // receiver keeps yielding the oldest surviving messages instead of closing.
    #[tokio::test]
    async fn lagged_receiver_recovers_after_lag() {
        const N: usize = 4;
        let (tx, mut rx) = broadcast::channel(N);
        for _ in 0..=N {
            let _ = tx.send(());
        }

        let err = rx.recv().await.expect_err("expected Lagged");
        assert!(matches!(err, broadcast::error::RecvError::Lagged(_)));

        // The receiver is still usable: after lag it resumes at the oldest
        // surviving message instead of closing.
        assert!(rx.recv().await.is_ok(), "receiver should recover after lag");
    }
}
