// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! In-memory buses to support sandbox watch streaming.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{broadcast, watch};
use tonic::Status;

use crate::persistence::Store;
use openshell_core::proto::Sandbox;

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

    fn active_sandbox_ids(&self) -> HashSet<String> {
        self.inner
            .lock()
            .expect("sandbox watch bus lock poisoned")
            .iter()
            .filter(|(_, sender)| sender.receiver_count() > 0)
            .map(|(sandbox_id, _)| sandbox_id.clone())
            .collect()
    }
}

/// Poll persisted sandbox resource versions once per gateway and notify the
/// existing in-memory watch bus when another replica changes a record.
///
/// The poller performs at most one lookup per actively watched sandbox per
/// interval, regardless of how many clients are watching that sandbox.
pub fn spawn_store_poller(
    store: Arc<Store>,
    bus: SandboxWatchBus,
    interval: Duration,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let mut known_versions: HashMap<String, Option<u64>> = HashMap::new();
        let mut timer = tokio::time::interval(interval);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = timer.tick() => {
                    let active = bus.active_sandbox_ids();
                    known_versions.retain(|sandbox_id, _| active.contains(sandbox_id));

                    for sandbox_id in active {
                        let current = match store.get_message::<Sandbox>(&sandbox_id).await {
                            Ok(sandbox) => sandbox.map(|sandbox| {
                                sandbox.metadata.as_ref().map_or(0, |metadata| metadata.resource_version)
                            }),
                            Err(err) => {
                                tracing::warn!(
                                    sandbox_id,
                                    error = %err,
                                    "sandbox watch poller: failed to read persisted sandbox"
                                );
                                continue;
                            }
                        };

                        let changed = known_versions
                            .insert(sandbox_id.clone(), current)
                            .is_none_or(|previous| previous != current);
                        if changed {
                            bus.notify(&sandbox_id);
                        }
                    }
                }
            }
        }
    });
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

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::datamodel::v1::ObjectMeta;

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

    #[tokio::test]
    async fn shared_store_poller_notifies_remote_resource_version_change() {
        let store = Arc::new(crate::persistence::test_store().await);
        let bus = SandboxWatchBus::new();
        let sandbox = Sandbox {
            metadata: Some(ObjectMeta {
                id: "sb-1".to_string(),
                name: "sandbox-a".to_string(),
                workspace: "default".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        store.put_message(&sandbox).await.unwrap();

        let mut rx = bus.subscribe("sb-1");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        spawn_store_poller(store.clone(), bus, Duration::from_millis(10), shutdown_rx);

        tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("poller should publish its initial observation")
            .unwrap();

        store
            .update_message_cas::<Sandbox, _>("sb-1", 0, |stored| {
                stored.set_phase(1);
            })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("poller should observe a remote store update")
            .unwrap();

        shutdown_tx.send(true).unwrap();
    }
}
