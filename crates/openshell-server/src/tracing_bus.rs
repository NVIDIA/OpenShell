// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Capture openshell-server tracing logs for streaming over gRPC.

use std::collections::{HashMap, VecDeque};
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
    seq: SeqAllocator,
}

#[derive(Debug, Clone)]
struct Inner {
    per_id: HashMap<String, PerSandbox>,
}

#[derive(Debug, Clone)]
struct PerSandbox {
    sender: broadcast::Sender<SandboxStreamEvent>,
    tail: VecDeque<(u64, SandboxStreamEvent)>,
    /// Highest seq this bus has evicted from `tail`. 0 = nothing trimmed.
    ///
    /// Under the shared cursor space each bus's tail is non-contiguous in the
    /// global seq (the other bus owns the missing seqs), so a resume gap can
    /// only be judged by what *this* bus actually dropped.
    last_trimmed_seq: u64,
}

impl PerSandbox {
    fn new() -> Self {
        let (tx, _rx) = broadcast::channel(1024);
        Self {
            sender: tx,
            tail: VecDeque::new(),
            last_trimmed_seq: 0,
        }
    }
}

/// The requested resume cursor is older than the oldest buffered event;
/// the events between them were trimmed and cannot be replayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResumeGap {
    pub requested_after: u64,
    pub oldest_available: u64,
}

/// Per-sandbox monotonic sequence allocator.
///
/// Shared across the resumable buses (`TracingLogBus`, `PlatformEventBus`) so
/// cursors are unique and strictly ordered within a single sandbox's merged
/// stream. Stamping at publish time keeps tail cursors stable across client
/// reconnects, which is what a single `resume_after_cursor` needs.
#[derive(Debug, Clone, Default)]
struct SeqAllocator {
    inner: Arc<Mutex<HashMap<String, u64>>>,
}

impl SeqAllocator {
    /// Return the next sequence number for this sandbox.
    ///
    /// Seq starts at 1 so the proto default `resume_after_cursor` (0) means
    /// "from the beginning" without skipping event 1.
    fn next(&self, sandbox_id: &str) -> u64 {
        let mut counters = self.inner.lock().expect("seq allocator lock poisoned");
        let counter = counters.entry(sandbox_id.to_string()).or_insert(1);
        let seq = *counter;
        *counter += 1;
        seq
    }

    /// Drop the counter for a sandbox once its buses are torn down.
    fn remove(&self, sandbox_id: &str) {
        self.inner
            .lock()
            .expect("seq allocator lock poisoned")
            .remove(sandbox_id);
    }
}

fn tail_after_impl(
    tail: &VecDeque<(u64, SandboxStreamEvent)>,
    last_trimmed_seq: u64,
    after_seq: u64,
) -> Result<Vec<SandboxStreamEvent>, ResumeGap> {
    // Gap iff this bus dropped an event the client still needs, i.e. the
    // highest seq we evicted is newer than the client's position. Judged only
    // on this bus's own evictions — the other bus owns the seqs missing here.
    if after_seq < last_trimmed_seq {
        return Err(ResumeGap {
            requested_after: after_seq,
            oldest_available: last_trimmed_seq + 1,
        });
    }

    // Skippable events (seq <= after_seq) are the oldest, at the front, so a
    // take-while would stop before reaching the wanted ones. Filter the whole
    // tail instead; order is preserved and caught-up yields an empty vec.
    let res: Vec<SandboxStreamEvent> = tail
        .iter()
        .filter(|(seq, _)| *seq > after_seq)
        .map(|(_, event)| event.clone())
        .collect();

    Ok(res)
}

impl Default for TracingLogBus {
    fn default() -> Self {
        Self::new()
    }
}

impl TracingLogBus {
    #[must_use]
    pub fn new() -> Self {
        // One allocator, shared with the platform event bus so both draw from
        // a single per-sandbox cursor space.
        let seq = SeqAllocator::default();
        Self {
            inner: Arc::new(Mutex::new(Inner {
                per_id: HashMap::new(),
            })),
            platform_event_bus: PlatformEventBus::new(seq.clone()),
            seq,
        }
    }

    pub(crate) fn layer<S: Subscriber>(&self) -> impl Layer<S> {
        SandboxLogLayer {
            bus: self.clone(),
            default_tail: Self::DEFAULT_TAIL,
        }
    }

    fn sender_for(&self, sandbox_id: &str) -> broadcast::Sender<SandboxStreamEvent> {
        let mut inner = self.inner.lock().expect("tracing bus lock poisoned");
        inner
            .per_id
            .entry(sandbox_id.to_string())
            .or_insert_with(PerSandbox::new)
            .sender
            .clone()
    }

    pub fn subscribe(&self, sandbox_id: &str) -> broadcast::Receiver<SandboxStreamEvent> {
        self.sender_for(sandbox_id).subscribe()
    }

    /// Remove all bus entries for the given sandbox id, including the platform
    /// event bus that shares this bus's cursor allocator.
    ///
    /// This drops the broadcast senders (closing any active receivers with
    /// `RecvError::Closed`) and frees the tail buffers. Both per-sandbox maps
    /// are cleared before the shared `SeqAllocator` entry is reset, so the
    /// allocator is never reset while either map can still accept a publish that
    /// references it.
    pub fn remove(&self, sandbox_id: &str) {
        {
            let mut inner = self.inner.lock().expect("tracing bus lock poisoned");
            inner.per_id.remove(sandbox_id);
        }
        self.platform_event_bus.remove(sandbox_id);
        self.seq.remove(sandbox_id);
    }

    pub fn tail(&self, sandbox_id: &str, max: usize) -> Vec<SandboxStreamEvent> {
        let inner = self.inner.lock().expect("tracing bus lock poisoned");
        inner
            .per_id
            .get(sandbox_id)
            .map(|d| {
                d.tail
                    .iter()
                    .rev()
                    .take(max)
                    .map(|(_seq, event)| event.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
            .into_iter()
            .rev()
            .collect::<Vec<SandboxStreamEvent>>()
    }

    pub fn tail_after(
        &self,
        sandbox_id: &str,
        after_seq: u64,
    ) -> Result<Vec<SandboxStreamEvent>, ResumeGap> {
        let inner = self.inner.lock().expect("tracing bus lock poisoned");
        inner.per_id.get(sandbox_id).map_or_else(
            || Ok(Vec::new()),
            |per| tail_after_impl(&per.tail, per.last_trimmed_seq, after_seq),
        )
    }

    /// Publish a log line from an external source (e.g., sandbox push).
    ///
    /// Injects the line into the same broadcast channel and tail buffer
    /// used by the tracing layer, so it appears in `WatchSandbox` and
    /// `GetSandboxLogs` transparently.
    pub fn publish_external(&self, log: SandboxLogLine) {
        let evt = SandboxStreamEvent {
            payload: Some(openshell_core::proto::sandbox_stream_event::Payload::Log(
                log.clone(),
            )),
            // Placeholder: publish() stamps the real cursor from next_seq.
            cursor: 0,
        };
        self.publish(&log.sandbox_id, evt, Self::DEFAULT_TAIL);
    }

    /// Default tail buffer capacity (lines per sandbox).
    const DEFAULT_TAIL: usize = 2000;

    fn publish(&self, sandbox_id: &str, mut event: SandboxStreamEvent, tail_cap: usize) {
        // Allocate the cursor first; next() takes and releases its own lock
        // before we lock `inner`, so the two locks are never nested.
        let seq = self.seq.next(sandbox_id);
        event.cursor = seq;

        let mut inner = self.inner.lock().expect("tracing bus lock poisoned");
        let per = inner
            .per_id
            .entry(sandbox_id.to_string())
            .or_insert_with(PerSandbox::new);

        let _ = per.sender.send(event.clone());
        per.tail.push_back((seq, event));
        while per.tail.len() > tail_cap {
            if let Some((trimmed, _)) = per.tail.pop_front() {
                per.last_trimmed_seq = trimmed;
            }
        }
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
        let mut visitor = LogVisitor::default();
        event.record(&mut visitor);

        let Some(sandbox_id) = visitor.sandbox_id else {
            return;
        };

        let msg = visitor.message.unwrap_or_else(|| meta.name().to_string());
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
            // Placeholder: publish() stamps the real cursor from next_seq.
            cursor: 0,
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

    /// Build a stream event carrying `seq` in its cursor for assertion.
    fn stream_event(seq: u64) -> SandboxStreamEvent {
        SandboxStreamEvent {
            payload: Some(openshell_core::proto::sandbox_stream_event::Payload::Log(
                make_log_event("sb", &seq.to_string()),
            )),
            cursor: seq,
        }
    }

    /// Build a contiguous tail with seqs `lo..=hi`.
    fn tail_of(lo: u64, hi: u64) -> VecDeque<(u64, SandboxStreamEvent)> {
        (lo..=hi).map(|s| (s, stream_event(s))).collect()
    }

    /// Extract cursors from a run of events, in order.
    fn cursors(events: &[SandboxStreamEvent]) -> Vec<u64> {
        events.iter().map(|e| e.cursor).collect()
    }

    #[test]
    fn tail_after_impl_empty_tail_returns_empty() {
        let tail = VecDeque::new();
        // Nothing trimmed (last_trimmed_seq = 0): any cursor is serviceable.
        assert_eq!(tail_after_impl(&tail, 0, 0).unwrap(), Vec::new());
        assert_eq!(tail_after_impl(&tail, 0, 42).unwrap(), Vec::new());
    }

    #[test]
    fn tail_after_impl_from_zero_returns_all() {
        let tail = tail_of(1, 5);
        let events = tail_after_impl(&tail, 0, 0).expect("serviceable");
        assert_eq!(cursors(&events), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn tail_after_impl_mid_range_returns_newer_in_order() {
        let tail = tail_of(1, 5);
        let events = tail_after_impl(&tail, 0, 3).expect("serviceable");
        assert_eq!(cursors(&events), vec![4, 5]);
    }

    #[test]
    fn tail_after_impl_caught_up_returns_empty() {
        let tail = tail_of(1, 5);
        // Cursor at the newest seq: nothing newer, but not a gap.
        assert_eq!(tail_after_impl(&tail, 0, 5).expect("ok"), Vec::new());
    }

    #[test]
    fn tail_after_impl_future_cursor_returns_empty() {
        let tail = tail_of(1, 5);
        // Cursor beyond newest (client claims to have seen more than exists):
        // still serviceable, just nothing to send.
        assert_eq!(tail_after_impl(&tail, 0, 99).expect("ok"), Vec::new());
    }

    #[test]
    fn tail_after_impl_boundary_at_last_trimmed_is_serviceable() {
        // Bus trimmed up to seq 2, retains 3..=5. Client saw exactly 2, so
        // nothing they still need was dropped.
        let tail = tail_of(3, 5);
        let events = tail_after_impl(&tail, 2, 2).expect("serviceable");
        assert_eq!(cursors(&events), vec![3, 4, 5]);
    }

    #[test]
    fn tail_after_impl_gap_returns_err() {
        // Bus trimmed up to seq 2, retains 3..=5. Client wants everything after
        // 1, but seq 2 was evicted and cannot be replayed.
        let tail = tail_of(3, 5);
        let err = tail_after_impl(&tail, 2, 1).expect_err("gap");
        assert_eq!(
            err,
            ResumeGap {
                requested_after: 1,
                oldest_available: 3,
            }
        );
    }

    #[test]
    fn tail_after_impl_non_contiguous_tail_no_false_gap() {
        // Simulate the shared cursor space: this bus only owns seqs 2 and 4
        // (the other bus owns 1 and 3), and never trimmed. Resuming from 0 must
        // not report a gap just because seq 1 is absent here.
        let tail: VecDeque<(u64, SandboxStreamEvent)> =
            [(2, stream_event(2)), (4, stream_event(4))]
                .into_iter()
                .collect();
        let events = tail_after_impl(&tail, 0, 0).expect("no gap");
        assert_eq!(cursors(&events), vec![2, 4]);
    }

    #[test]
    fn tracing_log_bus_tail_after_serviceable_and_missing() {
        let bus = TracingLogBus::new();
        let sandbox_id = "sb-ta";
        for _ in 0..3 {
            bus.publish_external(make_log_event(sandbox_id, "line"));
        }
        // Cursors start at 1, so three publishes are seqs 1,2,3.
        assert_eq!(
            cursors(&bus.tail_after(sandbox_id, 0).unwrap()),
            vec![1, 2, 3]
        );
        assert_eq!(cursors(&bus.tail_after(sandbox_id, 2).unwrap()), vec![3]);
        // Unknown sandbox: no entry, nothing buffered, no gap.
        assert_eq!(bus.tail_after("nope", 5).unwrap(), Vec::new());
    }

    #[test]
    fn platform_event_bus_tail_after_serviceable() {
        let bus = TracingLogBus::new();
        let platform = &bus.platform_event_bus;
        let sandbox_id = "sb-pe";
        for _ in 0..3 {
            platform.publish(sandbox_id, stream_event(0));
        }
        // Shared allocator, but only the platform bus published here, so its
        // seqs are 1,2,3.
        assert_eq!(
            cursors(&platform.tail_after(sandbox_id, 0).unwrap()),
            vec![1, 2, 3]
        );
        assert_eq!(
            cursors(&platform.tail_after(sandbox_id, 1).unwrap()),
            vec![2, 3]
        );
    }

    #[test]
    fn shared_allocator_interleaves_cursors_across_buses() {
        let bus = TracingLogBus::new();
        let sandbox_id = "sb-mix";
        // Interleave log and platform publishes; the shared allocator gives
        // each a unique, increasing cursor in one merged space.
        bus.publish_external(make_log_event(sandbox_id, "a")); // seq 1
        bus.platform_event_bus.publish(sandbox_id, stream_event(0)); // seq 2
        bus.publish_external(make_log_event(sandbox_id, "b")); // seq 3

        let logs = cursors(&bus.tail_after(sandbox_id, 0).unwrap());
        let events = cursors(&bus.platform_event_bus.tail_after(sandbox_id, 0).unwrap());
        assert_eq!(logs, vec![1, 3]);
        assert_eq!(events, vec![2]);
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
    fn tracing_log_bus_subscribe_after_remove_creates_fresh_channel() {
        let bus = TracingLogBus::new();
        let sandbox_id = "sb-2";

        // Create and remove
        bus.publish_external(make_log_event(sandbox_id, "old message"));
        bus.remove(sandbox_id);

        // Subscribe again — should get a fresh channel with no history
        let mut rx = bus.subscribe(sandbox_id);
        assert!(bus.tail(sandbox_id, 10).is_empty());

        // New publish should reach the new subscriber
        bus.publish_external(make_log_event(sandbox_id, "new message"));
        let evt = rx.try_recv().expect("should receive new event");
        assert!(evt.payload.is_some());
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
    fn display_level_maps_ocsf_target_to_ocsf() {
        assert_eq!(display_level(OCSF_TARGET, "INFO"), "OCSF");
        assert_eq!(display_level("openshell_server", "WARN"), "WARN");
    }

    #[test]
    fn platform_event_bus_remove_cleans_up() {
        let bus = PlatformEventBus::new(SeqAllocator::default());
        let sandbox_id = "sb-4";

        let mut rx = bus.subscribe(sandbox_id);

        // Publish an event
        let evt = SandboxStreamEvent {
            payload: None,
            cursor: 0,
        };
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
        let bus = PlatformEventBus::new(SeqAllocator::default());
        let sandbox_id = "sb-5";

        let _old_rx = bus.subscribe(sandbox_id);
        bus.remove(sandbox_id);

        // New subscription should work
        let mut new_rx = bus.subscribe(sandbox_id);
        let evt = SandboxStreamEvent {
            payload: None,
            cursor: 0,
        };
        bus.publish(sandbox_id, evt);
        assert!(new_rx.try_recv().is_ok());
    }

    #[test]
    fn platform_event_bus_remove_nonexistent_is_noop() {
        let bus = PlatformEventBus::new(SeqAllocator::default());
        // Should not panic
        bus.remove("nonexistent");
    }

    #[test]
    fn platform_event_bus_tail_returns_buffered_events() {
        use openshell_core::proto::{PlatformEvent, sandbox_stream_event};

        let bus = PlatformEventBus::new(SeqAllocator::default());
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
                cursor: 0,
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
        let bus = PlatformEventBus::new(SeqAllocator::default());
        let events = bus.tail("nonexistent", 10);
        assert!(events.is_empty());
    }

    #[test]
    fn platform_event_bus_remove_clears_tail() {
        let bus = PlatformEventBus::new(SeqAllocator::default());
        let sandbox_id = "sb-7";

        let evt = SandboxStreamEvent {
            payload: None,
            cursor: 0,
        };
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
    inner: Arc<Mutex<Inner>>,
    seq: SeqAllocator,
}

impl PlatformEventBus {
    /// Default tail buffer capacity (events per sandbox).
    /// Platform events are infrequent (typically 5-10 per sandbox lifecycle).
    const DEFAULT_TAIL: usize = 50;

    /// Build a platform event bus sharing `seq` with its owning `TracingLogBus`
    /// so both stamp cursors from the same per-sandbox sequence.
    fn new(seq: SeqAllocator) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                per_id: HashMap::new(),
            })),
            seq,
        }
    }

    fn sender_for(&self, sandbox_id: &str) -> broadcast::Sender<SandboxStreamEvent> {
        let mut inner = self.inner.lock().expect("platform event bus lock poisoned");
        inner
            .per_id
            .entry(sandbox_id.to_string())
            .or_insert_with(PerSandbox::new)
            .sender
            .clone()
    }

    pub(crate) fn subscribe(&self, sandbox_id: &str) -> broadcast::Receiver<SandboxStreamEvent> {
        self.sender_for(sandbox_id).subscribe()
    }

    pub(crate) fn publish(&self, sandbox_id: &str, mut event: SandboxStreamEvent) {
        // Allocate before locking `inner` (same non-nested lock order as
        // TracingLogBus::publish).
        let seq = self.seq.next(sandbox_id);
        event.cursor = seq;

        let mut inner = self.inner.lock().expect("platform event bus lock poisoned");
        let per = inner
            .per_id
            .entry(sandbox_id.to_string())
            .or_insert_with(PerSandbox::new);

        let _ = per.sender.send(event.clone());
        per.tail.push_back((seq, event));
        while per.tail.len() > Self::DEFAULT_TAIL {
            if let Some((trimmed, _)) = per.tail.pop_front() {
                per.last_trimmed_seq = trimmed;
            }
        }
    }

    /// Return buffered platform events for replay to late subscribers.
    pub(crate) fn tail(&self, sandbox_id: &str, max: usize) -> Vec<SandboxStreamEvent> {
        let inner = self.inner.lock().expect("platform event bus lock poisoned");
        inner
            .per_id
            .get(sandbox_id)
            .map(|d| {
                d.tail
                    .iter()
                    .rev()
                    .take(max)
                    .map(|(_seq, event)| event.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
            .into_iter()
            .rev()
            .collect()
    }

    pub(crate) fn tail_after(
        &self,
        sandbox_id: &str,
        after_seq: u64,
    ) -> Result<Vec<SandboxStreamEvent>, ResumeGap> {
        let inner = self.inner.lock().expect("platform event bus lock poisoned");
        inner.per_id.get(sandbox_id).map_or_else(
            || Ok(Vec::new()),
            |per| tail_after_impl(&per.tail, per.last_trimmed_seq, after_seq),
        )
    }

    /// Remove the bus entry for the given sandbox id.
    ///
    /// This drops the broadcast sender, closing any active receivers,
    /// and frees the tail buffer.
    pub(crate) fn remove(&self, sandbox_id: &str) {
        let mut inner = self.inner.lock().expect("platform event bus lock poisoned");
        inner.per_id.remove(sandbox_id);
    }
}
