// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Frees the log and event buffers a replica holds for deleted sandboxes.
//!
//! Delete cleanup runs only on the replica that served the delete or ran the
//! driver watch. Any other replica that buffered the sandbox's logs or events
//! keeps them until this sweeper sees the record is gone. Each replica checks
//! only its own idle buffers, in batched primary-key lookups, so the cost
//! scales with local state rather than with fleet size or replica count.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use openshell_core::proto::Sandbox;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::persistence::{ObjectType, PersistenceResult, Store};
use crate::tracing_bus::TracingLogBus;

/// How often each replica sweeps its buffers.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Buffers active more recently than this are not checked. A sandbox that is
/// still publishing almost certainly still exists. Watched buffers are checked
/// too, and closing one ends its watch streams.
pub const MIN_IDLE: Duration = Duration::from_mins(2);

/// Spawn the sweeper. Only multi-replica deployments need it: a single replica
/// runs every delete cleanup itself.
pub fn spawn(store: Arc<Store>, bus: TracingLogBus, mut shutdown_rx: watch::Receiver<bool>) {
    tokio::spawn(async move {
        let mut suspects = HashSet::new();
        let mut timer = tokio::time::interval(SWEEP_INTERVAL);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = timer.tick() => {
                    match sweep_once(&store, &bus, MIN_IDLE, &mut suspects).await {
                        Ok(0) => {}
                        Ok(closed) => info!(closed, "freed log and event buffers of deleted sandboxes"),
                        Err(err) => warn!(error = %err, "bus sweeper: failed to check sandbox records"),
                    }
                }
            }
        }
    });
}

/// Run one sweep and return how many sandboxes were closed.
///
/// A sandbox is closed only when its record is missing on two sweeps in a
/// row; `suspects` carries the ids missing on the previous one. A store error
/// closes nothing and leaves `suspects` unchanged.
pub async fn sweep_once(
    store: &Store,
    bus: &TracingLogBus,
    min_idle: Duration,
    suspects: &mut HashSet<String>,
) -> PersistenceResult<usize> {
    let idle = bus.idle_sandbox_ids(min_idle);
    let existing = store.existing_ids(Sandbox::object_type(), &idle).await?;

    let mut closed = 0;
    let mut missing = HashSet::new();
    for sandbox_id in idle {
        if existing.contains(&sandbox_id) {
            continue;
        }
        if suspects.contains(&sandbox_id) {
            bus.close(&sandbox_id);
            closed += 1;
        } else {
            missing.insert(sandbox_id);
        }
    }
    *suspects = missing;
    Ok(closed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::test_postgres::TestSchema;
    use openshell_core::proto::{SandboxLogLine, SandboxStreamEvent};

    async fn put_sandbox(store: &Store, sandbox_id: &str) {
        store
            .put(
                Sandbox::object_type(),
                sandbox_id,
                sandbox_id,
                "default",
                b"payload",
                None,
            )
            .await
            .unwrap();
    }

    fn publish_log(bus: &TracingLogBus, sandbox_id: &str) {
        bus.publish_external(SandboxLogLine {
            sandbox_id: sandbox_id.to_string(),
            message: "line".to_string(),
            ..Default::default()
        });
    }

    fn publish_event(bus: &TracingLogBus, sandbox_id: &str) {
        bus.platform_event_bus
            .publish(sandbox_id, SandboxStreamEvent::default());
    }

    #[tokio::test]
    async fn deleted_sandbox_is_freed_on_another_replica() {
        let store = crate::persistence::test_store().await;
        deleted_sandbox_is_freed_on_another_replica_on(&store, &store).await;
    }

    #[tokio::test]
    #[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
    async fn postgres_deleted_sandbox_is_freed_on_another_replica() {
        let schema = TestSchema::create("bus_sweeper").await;
        let owner = schema.connect_store().await;
        let other = schema.connect_store().await;
        deleted_sandbox_is_freed_on_another_replica_on(&owner, &other).await;
        schema.drop_schema().await;
    }

    /// `owner` serves the delete; `other` is a replica that buffered the
    /// sandbox but never runs its delete cleanup.
    async fn deleted_sandbox_is_freed_on_another_replica_on(owner: &Store, other: &Store) {
        put_sandbox(owner, "sb-live").await;
        put_sandbox(owner, "sb-gone").await;
        let bus = TracingLogBus::new();
        publish_log(&bus, "sb-live");
        publish_log(&bus, "sb-gone");
        publish_event(&bus, "sb-gone");

        owner
            .delete(Sandbox::object_type(), "sb-gone")
            .await
            .unwrap();

        let mut suspects = HashSet::new();
        let first = sweep_once(other, &bus, Duration::ZERO, &mut suspects).await;
        assert_eq!(first.unwrap(), 0, "first miss only marks a suspect");
        assert!(!bus.is_closed("sb-gone"));

        let second = sweep_once(other, &bus, Duration::ZERO, &mut suspects).await;
        assert_eq!(second.unwrap(), 1);
        assert!(bus.is_closed("sb-gone"));
        assert!(bus.tail("sb-gone", 10).is_empty());
        assert!(bus.platform_event_bus.tail("sb-gone", 10).is_empty());

        assert!(!bus.is_closed("sb-live"));
        assert_eq!(bus.tail("sb-live", 10).len(), 1);
    }

    #[tokio::test]
    async fn recently_active_buffers_are_not_checked() {
        let store = crate::persistence::test_store().await;
        let bus = TracingLogBus::new();
        publish_log(&bus, "sb-gone");
        let mut suspects = HashSet::new();

        for _ in 0..2 {
            let swept = sweep_once(&store, &bus, Duration::from_hours(1), &mut suspects).await;
            assert_eq!(swept.unwrap(), 0);
        }
        assert!(!bus.is_closed("sb-gone"));
    }

    #[tokio::test]
    async fn watched_buffers_of_deleted_sandbox_are_freed() {
        let store = crate::persistence::test_store().await;
        let bus = TracingLogBus::new();
        publish_log(&bus, "sb-gone");
        let mut log_rx = bus.subscribe("sb-gone");

        let mut suspects = HashSet::new();
        for expected in [0, 1] {
            let swept = sweep_once(&store, &bus, Duration::ZERO, &mut suspects).await;
            assert_eq!(swept.unwrap(), expected);
        }

        assert!(bus.is_closed("sb-gone"));
        assert!(matches!(
            log_rx.recv().await,
            Err(tokio::sync::broadcast::error::RecvError::Closed)
        ));
    }

    #[tokio::test]
    async fn store_failure_frees_nothing() {
        let store = crate::persistence::test_store().await;
        let bus = TracingLogBus::new();
        publish_log(&bus, "sb-gone");
        let mut suspects = HashSet::from(["sb-gone".to_string()]);

        store.close().await;
        let swept = sweep_once(&store, &bus, Duration::ZERO, &mut suspects).await;

        assert!(swept.is_err());
        assert!(!bus.is_closed("sb-gone"));
        assert_eq!(bus.tail("sb-gone", 10).len(), 1);
        assert!(suspects.contains("sb-gone"));
    }
}
