// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Capture openshell-server tracing logs for streaming over gRPC.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use openshell_core::proto::{SandboxLogLine, SandboxStreamEvent};
use openshell_ocsf::OCSF_TARGET;
use tokio::sync::broadcast;
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

/// Bus that publishes server log lines keyed by sandbox id.
#[derive(Debug, Clone)]
pub struct TracingLogBus {
    inner: Arc<Mutex<Inner>>,
    pub(crate) platform_event_bus: PlatformEventBus,
}

#[derive(Debug)]
struct Inner {
    per_id: HashMap<String, broadcast::Sender<SandboxStreamEvent>>,
    tails: HashMap<String, VecDeque<SandboxStreamEvent>>,
    /// Recently removed sandbox ids, in eviction order.
    removed: VecDeque<String>,
    removed_set: HashSet<String>,
}

impl Default for TracingLogBus {
    fn default() -> Self {
        Self::new()
    }
}

impl TracingLogBus {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                per_id: HashMap::new(),
                tails: HashMap::new(),
                removed: VecDeque::new(),
                removed_set: HashSet::new(),
            })),
            platform_event_bus: PlatformEventBus::new(),
        }
    }

    pub(crate) fn layer<S: Subscriber>(&self) -> impl Layer<S> {
        SandboxLogLayer {
            bus: self.clone(),
            default_tail: Self::DEFAULT_TAIL,
        }
    }

    pub fn subscribe(&self, sandbox_id: &str) -> broadcast::Receiver<SandboxStreamEvent> {
        let mut inner = self.inner.lock().expect("tracing bus lock poisoned");
        if inner.removed_set.contains(sandbox_id) {
            let (tx, rx) = broadcast::channel(1);
            drop(tx);
            return rx;
        }
        inner
            .per_id
            .entry(sandbox_id.to_string())
            .or_insert_with(|| {
                let (tx, _rx) = broadcast::channel(1024);
                tx
            })
            .subscribe()
    }

    /// Remove all bus entries for the given sandbox id.
    ///
    /// This drops the broadcast sender (closing any active receivers with
    /// `RecvError::Closed`) and frees the tail buffer.
    pub fn remove(&self, sandbox_id: &str) {
        let mut inner = self.inner.lock().expect("tracing bus lock poisoned");
        inner.per_id.remove(sandbox_id);
        inner.tails.remove(sandbox_id);

        if inner.removed_set.insert(sandbox_id.to_string()) {
            inner.removed.push_back(sandbox_id.to_string());
            while inner.removed.len() > Self::MAX_REMEMBERED_REMOVALS {
                if let Some(evicted) = inner.removed.pop_front() {
                    inner.removed_set.remove(&evicted);
                }
            }
        }
    }

    pub fn tail(&self, sandbox_id: &str, max: usize) -> Vec<SandboxStreamEvent> {
        let inner = self.inner.lock().expect("tracing bus lock poisoned");
        inner
            .tails
            .get(sandbox_id)
            .map(|d| d.iter().rev().take(max).cloned().collect::<Vec<_>>())
            .unwrap_or_default()
            .into_iter()
            .rev()
            .collect()
    }

    /// Publish a log line from an external source (e.g., sandbox push).
    ///
    /// Injects the line into the same broadcast channel and tail buffer
    /// used by the tracing layer, so it appears in `WatchSandbox` and
    /// `GetSandboxLogs` transparently.
    pub fn publish_external(&self, log: SandboxLogLine) {
        if log.sandbox_id.is_empty() {
            return;
        }
        let evt = SandboxStreamEvent {
            payload: Some(openshell_core::proto::sandbox_stream_event::Payload::Log(
                log.clone(),
            )),
        };
        self.publish(&log.sandbox_id, evt, Self::DEFAULT_TAIL);
    }

    /// Default tail buffer capacity (lines per sandbox).
    const DEFAULT_TAIL: usize = 2000;

    /// Number of `(sender, tail)` entries currently held, for leak assertions.
    #[cfg(test)]
    fn entry_counts(&self) -> (usize, usize) {
        let inner = self.inner.lock().expect("tracing bus lock poisoned");
        (inner.per_id.len(), inner.tails.len())
    }

    /// Maximum number of removed sandbox ids to retain.
    ///
    /// This bounds memory; after eviction, a very late publisher may create a
    /// fresh entry for that id.
    const MAX_REMEMBERED_REMOVALS: usize = 1024;

    fn publish(&self, sandbox_id: &str, event: SandboxStreamEvent, tail_cap: usize) {
        let mut inner = self.inner.lock().expect("tracing bus lock poisoned");
        if inner.removed_set.contains(sandbox_id) {
            return;
        }

        let tx = inner
            .per_id
            .entry(sandbox_id.to_string())
            .or_insert_with(|| {
                let (tx, _rx) = broadcast::channel(1024);
                tx
            })
            .clone();

        let deque = inner.tails.entry(sandbox_id.to_string()).or_default();
        deque.push_back(event.clone());
        while deque.len() > tail_cap {
            deque.pop_front();
        }
        drop(inner);

        let _ = tx.send(event);
    }
}

#[derive(Debug, Clone)]
struct SandboxLogLayer {
    bus: TracingLogBus,
    default_tail: usize,
}

impl<S> Layer<S> for SandboxLogLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        // OCSF tracing events carry no fields; the payload arrives out of band
        // through a thread-local.
        let (visitor_sandbox_id, visitor_message) = if meta.target() == OCSF_TARGET {
            openshell_ocsf::clone_current_event().map_or((None, None), |ocsf_event| {
                (
                    ocsf_event.base().metadata.uid.clone(),
                    Some(ocsf_event.format_shorthand()),
                )
            })
        } else {
            let mut visitor = LogVisitor::default();
            event.record(&mut visitor);
            (visitor.sandbox_id, visitor.message)
        };

        // An empty id means no sandbox association; publishing would allocate a
        // bucket nothing can subscribe to.
        let Some(sandbox_id) = visitor_sandbox_id.filter(|id| !id.is_empty()) else {
            return;
        };

        let msg = visitor_message.unwrap_or_else(|| meta.name().to_string());
        let level = display_level(meta.target(), &meta.level().to_string());

        let ts = openshell_core::time::now_ms();
        let log = SandboxLogLine {
            sandbox_id: sandbox_id.clone(),
            timestamp_ms: ts,
            level,
            target: meta.target().to_string(),
            message: msg,
            source: "gateway".to_string(),
            fields: HashMap::new(),
        };
        let evt = SandboxStreamEvent {
            payload: Some(openshell_core::proto::sandbox_stream_event::Payload::Log(
                log,
            )),
        };
        self.bus.publish(&sandbox_id, evt, self.default_tail);
    }
}

#[derive(Debug, Default)]
struct LogVisitor {
    sandbox_id: Option<String>,
    message: Option<String>,
}

impl tracing::field::Visit for LogVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        match field.name() {
            "sandbox_id" => self.sandbox_id = Some(value.to_string()),
            "message" => self.message = Some(value.to_string()),
            _ => {}
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "sandbox_id" => self.sandbox_id = Some(format!("{value:?}")),
            "message" => self.message = Some(format!("{value:?}")),
            _ => {}
        }
    }
}

fn display_level(target: &str, level: &str) -> String {
    if target == OCSF_TARGET {
        "OCSF".to_string()
    } else {
        level.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_log_event(sandbox_id: &str, message: &str) -> SandboxLogLine {
        SandboxLogLine {
            sandbox_id: sandbox_id.to_string(),
            timestamp_ms: 1000,
            level: "INFO".to_string(),
            target: "test".to_string(),
            message: message.to_string(),
            source: "gateway".to_string(),
            fields: HashMap::new(),
        }
    }

    #[test]
    fn tracing_log_bus_remove_cleans_up_all_maps() {
        let bus = TracingLogBus::new();
        let sandbox_id = "sb-1";

        // Create entries via subscribe and publish
        let _rx = bus.subscribe(sandbox_id);
        bus.publish_external(make_log_event(sandbox_id, "hello"));

        // Verify entries exist
        assert_eq!(bus.tail(sandbox_id, 10).len(), 1);

        // Remove
        bus.remove(sandbox_id);

        // Verify entries are gone
        assert!(bus.tail(sandbox_id, 10).is_empty());
    }

    #[test]
    fn subscribe_after_remove_does_not_reactivate_the_bus() {
        let bus = TracingLogBus::new();
        let sandbox_id = "sb-2";

        bus.publish_external(make_log_event(sandbox_id, "old message"));
        bus.remove(sandbox_id);

        let mut rx = bus.subscribe(sandbox_id);
        bus.publish_external(make_log_event(sandbox_id, "late message"));

        assert_eq!(bus.entry_counts(), (0, 0));
        assert!(bus.tail(sandbox_id, 10).is_empty());
        assert!(matches!(
            rx.try_recv(),
            Err(broadcast::error::TryRecvError::Closed)
        ));
    }

    #[test]
    fn tracing_log_bus_remove_closes_active_receivers() {
        let bus = TracingLogBus::new();
        let sandbox_id = "sb-3";

        let mut rx = bus.subscribe(sandbox_id);

        // Remove drops the sender
        bus.remove(sandbox_id);

        // Existing receiver should get Closed error
        match rx.try_recv() {
            Err(broadcast::error::TryRecvError::Closed) => {} // expected
            other => panic!("expected Closed, got {other:?}"),
        }
    }

    #[test]
    fn tracing_log_bus_remove_nonexistent_is_noop() {
        let bus = TracingLogBus::new();
        // Should not panic
        bus.remove("nonexistent");
    }

    #[test]
    fn publish_after_remove_does_not_resurrect_the_bus_entry() {
        let bus = TracingLogBus::new();
        let sandbox_id = "sb-torn-down";

        bus.publish_external(make_log_event(sandbox_id, "before teardown"));
        assert_eq!(bus.entry_counts(), (1, 1));

        bus.remove(sandbox_id);
        assert_eq!(bus.entry_counts(), (0, 0));

        bus.publish_external(make_log_event(sandbox_id, "late line"));
        assert_eq!(bus.entry_counts(), (0, 0));
        assert!(bus.tail(sandbox_id, 10).is_empty());
    }

    fn ocsf_ctx(sandbox_id: &str) -> openshell_ocsf::SandboxContext {
        openshell_ocsf::SandboxContext {
            sandbox_id: sandbox_id.to_string(),
            sandbox_name: "gw".to_string(),
            container_image: "openshell/gateway".to_string(),
            hostname: "openshell-gateway".to_string(),
            product_version: "0.0.0".to_string(),
            proxy_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            proxy_port: 0,
        }
    }

    /// Run `f` with the bus layer installed as the active subscriber.
    fn with_bus_layer(bus: &TracingLogBus, f: impl FnOnce()) {
        use tracing_subscriber::layer::SubscriberExt;
        let subscriber = tracing_subscriber::registry().with(bus.layer());
        tracing::subscriber::with_default(subscriber, f);
    }

    fn log_message(event: &SandboxStreamEvent) -> &SandboxLogLine {
        match event.payload {
            Some(openshell_core::proto::sandbox_stream_event::Payload::Log(ref log)) => log,
            _ => panic!("expected a log payload"),
        }
    }

    #[test]
    fn ocsf_emit_events_reach_the_bus_with_shorthand_and_sandbox_id() {
        use openshell_ocsf::{
            ActionId, ActivityId, DispositionId, Endpoint, NetworkActivityBuilder, SeverityId,
            StatusId, ocsf_emit,
        };

        let bus = TracingLogBus::new();
        let event = NetworkActivityBuilder::new(&ocsf_ctx("sb-emit"))
            .activity(ActivityId::Open)
            .action(ActionId::Denied)
            .disposition(DispositionId::Blocked)
            .severity(SeverityId::Medium)
            .status(StatusId::Failure)
            .dst_endpoint(Endpoint::from_domain("blocked.example.com", 443))
            .message("CONNECT denied blocked.example.com:443")
            .build();
        let expected_message = event.format_shorthand();

        with_bus_layer(&bus, || ocsf_emit!(event));

        let tail = bus.tail("sb-emit", 10);
        assert_eq!(tail.len(), 1, "ocsf_emit! event should reach the bus");
        let log = log_message(&tail[0]);
        assert_eq!(log.sandbox_id, "sb-emit");
        assert_eq!(log.message, expected_message);
        assert_eq!(log.level, "OCSF");
        assert_eq!(log.target, OCSF_TARGET);
        assert_eq!(log.source, "gateway");
    }

    #[test]
    fn ocsf_emit_events_without_a_sandbox_are_skipped() {
        use openshell_ocsf::{ActivityId, AppLifecycleBuilder, SeverityId, ocsf_emit};

        let bus = TracingLogBus::new();
        let event = AppLifecycleBuilder::new(&ocsf_ctx(""))
            .activity(ActivityId::Open)
            .severity(SeverityId::Informational)
            .message("gateway TLS reloaded")
            .build();

        with_bus_layer(&bus, || ocsf_emit!(event));

        assert_eq!(bus.entry_counts(), (0, 0));
    }

    #[test]
    fn non_ocsf_events_still_use_the_sandbox_id_field() {
        let bus = TracingLogBus::new();
        with_bus_layer(&bus, || {
            tracing::info!(sandbox_id = "sb-plain", "plain gateway line");
        });

        let tail = bus.tail("sb-plain", 10);
        assert_eq!(tail.len(), 1);
        let log = log_message(&tail[0]);
        assert_eq!(log.message, "plain gateway line");
        assert_eq!(log.level, "INFO");
    }

    #[test]
    fn removal_tombstones_are_bounded() {
        let bus = TracingLogBus::new();
        let overflow = TracingLogBus::MAX_REMEMBERED_REMOVALS + 10;
        for i in 0..overflow {
            bus.remove(&format!("sb-{i}"));
        }

        let inner = bus.inner.lock().unwrap();
        assert_eq!(inner.removed.len(), TracingLogBus::MAX_REMEMBERED_REMOVALS);
        assert_eq!(
            inner.removed_set.len(),
            TracingLogBus::MAX_REMEMBERED_REMOVALS
        );
        assert!(!inner.removed_set.contains("sb-0"));
        assert!(inner.removed_set.contains(&format!("sb-{}", overflow - 1)));
    }

    #[test]
    fn publish_external_ignores_an_empty_sandbox_id() {
        let bus = TracingLogBus::new();
        bus.publish_external(make_log_event("", "no sandbox association"));

        assert_eq!(bus.entry_counts(), (0, 0));
        assert!(bus.tail("", 10).is_empty());
    }

    #[test]
    fn publish_external_still_accepts_a_real_sandbox_id() {
        let bus = TracingLogBus::new();
        bus.publish_external(make_log_event("sb-real", "hello"));
        assert_eq!(bus.tail("sb-real", 10).len(), 1);
    }

    #[test]
    fn display_level_maps_ocsf_target_to_ocsf() {
        assert_eq!(display_level(OCSF_TARGET, "INFO"), "OCSF");
        assert_eq!(display_level("openshell_server", "WARN"), "WARN");
    }

    #[test]
    fn platform_event_bus_remove_cleans_up() {
        let bus = PlatformEventBus::new();
        let sandbox_id = "sb-4";

        let mut rx = bus.subscribe(sandbox_id);

        // Publish an event
        let evt = SandboxStreamEvent { payload: None };
        bus.publish(sandbox_id, evt);
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
    fn platform_event_bus_subscribe_after_remove_creates_fresh_channel() {
        let bus = PlatformEventBus::new();
        let sandbox_id = "sb-5";

        let _old_rx = bus.subscribe(sandbox_id);
        bus.remove(sandbox_id);

        // New subscription should work
        let mut new_rx = bus.subscribe(sandbox_id);
        let evt = SandboxStreamEvent { payload: None };
        bus.publish(sandbox_id, evt);
        assert!(new_rx.try_recv().is_ok());
    }

    #[test]
    fn platform_event_bus_remove_nonexistent_is_noop() {
        let bus = PlatformEventBus::new();
        // Should not panic
        bus.remove("nonexistent");
    }

    #[test]
    fn platform_event_bus_tail_returns_buffered_events() {
        use openshell_core::proto::{PlatformEvent, sandbox_stream_event};

        let bus = PlatformEventBus::new();
        let sandbox_id = "sb-6";

        // Publish some events
        for i in 0..5 {
            let evt = SandboxStreamEvent {
                payload: Some(sandbox_stream_event::Payload::Event(PlatformEvent {
                    timestamp_ms: i,
                    source: "test".to_string(),
                    r#type: "Normal".to_string(),
                    reason: format!("Event{i}"),
                    message: format!("Message {i}"),
                    metadata: HashMap::new(),
                })),
            };
            bus.publish(sandbox_id, evt);
        }

        // Tail should return all events in order
        let events = bus.tail(sandbox_id, 10);
        assert_eq!(events.len(), 5);

        // Verify order (oldest first)
        for (i, evt) in events.iter().enumerate() {
            if let Some(sandbox_stream_event::Payload::Event(ref e)) = evt.payload {
                assert_eq!(e.reason, format!("Event{i}"));
            } else {
                panic!("expected Event payload");
            }
        }

        // Tail with smaller max should return most recent events
        let events = bus.tail(sandbox_id, 2);
        assert_eq!(events.len(), 2);
        if let Some(sandbox_stream_event::Payload::Event(ref e)) = events[0].payload {
            assert_eq!(e.reason, "Event3");
        }
        if let Some(sandbox_stream_event::Payload::Event(ref e)) = events[1].payload {
            assert_eq!(e.reason, "Event4");
        }
    }

    #[test]
    fn platform_event_bus_tail_empty_sandbox() {
        let bus = PlatformEventBus::new();
        let events = bus.tail("nonexistent", 10);
        assert!(events.is_empty());
    }

    #[test]
    fn platform_event_bus_remove_clears_tail() {
        let bus = PlatformEventBus::new();
        let sandbox_id = "sb-7";

        let evt = SandboxStreamEvent { payload: None };
        bus.publish(sandbox_id, evt);
        assert_eq!(bus.tail(sandbox_id, 10).len(), 1);

        bus.remove(sandbox_id);
        assert!(bus.tail(sandbox_id, 10).is_empty());
    }
}

/// Separate bus for platform event stream events.
///
/// This keeps platform events isolated from tracing capture.
#[derive(Debug, Clone)]
pub(crate) struct PlatformEventBus {
    inner: Arc<Mutex<PlatformEventBusInner>>,
}

#[derive(Debug)]
struct PlatformEventBusInner {
    senders: HashMap<String, broadcast::Sender<SandboxStreamEvent>>,
    tails: HashMap<String, VecDeque<SandboxStreamEvent>>,
}

impl PlatformEventBus {
    /// Default tail buffer capacity (events per sandbox).
    /// Platform events are infrequent (typically 5-10 per sandbox lifecycle).
    const DEFAULT_TAIL: usize = 50;

    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(PlatformEventBusInner {
                senders: HashMap::new(),
                tails: HashMap::new(),
            })),
        }
    }

    fn sender_for(&self, sandbox_id: &str) -> broadcast::Sender<SandboxStreamEvent> {
        let mut inner = self.inner.lock().expect("platform event bus lock poisoned");
        inner
            .senders
            .entry(sandbox_id.to_string())
            .or_insert_with(|| {
                let (tx, _rx) = broadcast::channel(1024);
                tx
            })
            .clone()
    }

    pub(crate) fn subscribe(&self, sandbox_id: &str) -> broadcast::Receiver<SandboxStreamEvent> {
        self.sender_for(sandbox_id).subscribe()
    }

    pub(crate) fn publish(&self, sandbox_id: &str, event: SandboxStreamEvent) {
        let tx = self.sender_for(sandbox_id);
        let _ = tx.send(event.clone());

        let mut inner = self.inner.lock().expect("platform event bus lock poisoned");
        let deque = inner.tails.entry(sandbox_id.to_string()).or_default();
        deque.push_back(event);
        while deque.len() > Self::DEFAULT_TAIL {
            deque.pop_front();
        }
    }

    /// Return buffered platform events for replay to late subscribers.
    pub(crate) fn tail(&self, sandbox_id: &str, max: usize) -> Vec<SandboxStreamEvent> {
        let inner = self.inner.lock().expect("platform event bus lock poisoned");
        inner
            .tails
            .get(sandbox_id)
            .map(|d| d.iter().rev().take(max).cloned().collect::<Vec<_>>())
            .unwrap_or_default()
            .into_iter()
            .rev()
            .collect()
    }

    /// Remove the bus entry for the given sandbox id.
    ///
    /// This drops the broadcast sender, closing any active receivers,
    /// and frees the tail buffer.
    pub(crate) fn remove(&self, sandbox_id: &str) {
        let mut inner = self.inner.lock().expect("platform event bus lock poisoned");
        inner.senders.remove(sandbox_id);
        inner.tails.remove(sandbox_id);
    }
}
