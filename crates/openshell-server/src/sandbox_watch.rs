// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! In-memory buses to support sandbox watch streaming.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;
use tonic::Status;

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
}

/// Helper to translate broadcast lag into a gRPC status.
pub fn broadcast_to_status(err: broadcast::error::RecvError) -> Status {
    match err {
        broadcast::error::RecvError::Closed => Status::cancelled("stream closed"),
        broadcast::error::RecvError::Lagged(n) => {
            Status::resource_exhausted(format!("watch stream lagged; dropped {n} messages"))
        }
    }
}
