// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Capture openshell-server tracing logs for streaming over gRPC.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

use openshell_core::proto::{SandboxLogLine, SandboxStreamEvent};
use openshell_ocsf::OCSF_TARGET;
use tokio::sync::broadcast;
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use uuid::Uuid;

use crate::watch_cursor::WatchCursor;

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

/// A buffered or broadcast stream event paired with its raw sequence number.
///
/// The wire `SandboxStreamEvent.cursor` is an opaque token; ordering decisions
/// must not depend on its encoding. Carrying the seq alongside keeps every
/// comparison on the watch path numeric, so no consumer parses the token to
/// decide whether an event has already been delivered.
#[derive(Debug, Clone)]
pub(crate) struct CursoredEvent {
    pub(crate) seq: u64,
    pub(crate) event: SandboxStreamEvent,
}

#[derive(Debug, Clone)]
struct PerSandbox {
    sender: broadcast::Sender<CursoredEvent>,
    tail: VecDeque<CursoredEvent>,
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

/// One sandbox's cursor space: an identity plus its running sequence.
///
/// The epoch is what makes a cursor verifiable. Sequence numbers restart at 1
/// whenever a space is recreated, so a bare number from a previous space can
/// look like a valid position in the current one. Minting a fresh epoch with
/// the entry means every reset produces a distinguishable space, and a resume
/// cursor can be checked against the identity that issued it rather than
/// against a plausible range.
#[derive(Debug, Clone)]
struct CursorSpace {
    epoch: Uuid,
    next: u64,
}

/// Identity and extent of a sandbox's current cursor space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CursorSpaceInfo {
    pub(crate) epoch: Uuid,
    /// Highest sequence issued so far. `0` means nothing published yet.
    pub(crate) highest_seq: u64,
}

/// Per-sandbox monotonic sequence allocator.
///
/// Shared across the resumable buses (`TracingLogBus`, `PlatformEventBus`) so
/// cursors are unique and strictly ordered within a single sandbox's merged
/// stream. Stamping at publish time keeps tail cursors stable across client
/// reconnects, which is what a single `resume_after_cursor` needs.
#[derive(Debug, Clone, Default)]
struct SeqAllocator {
    inner: Arc<Mutex<HashMap<String, CursorSpace>>>,
}

impl SeqAllocator {
    /// Lock the cursor space.
    ///
    /// Publication and teardown each hold this guard across their bus-map
    /// mutation, which is what keeps cursors monotonic. Allocating and then
    /// releasing would let a teardown reset the counter in between, so the
    /// in-flight event lands in a freshly recreated entry carrying a cursor from
    /// the old space while the next publish restarts at 1.
    ///
    /// The lock order is always allocator -> bus map. No path takes a bus map
    /// lock and then reaches for the allocator, so the nesting cannot deadlock.
    fn lock(&self) -> MutexGuard<'_, HashMap<String, CursorSpace>> {
        self.inner.lock().expect("seq allocator lock poisoned")
    }

    /// Take the next `(epoch, seq)` for this sandbox from a locked space.
    ///
    /// Seq starts at 1 so an empty `resume_after_cursor` means "from the
    /// beginning" without skipping event 1.
    ///
    /// The epoch is minted on the vacant path only — once per cursor space, not
    /// once per publish — so generating it under the allocator lock costs
    /// nothing on the hot path.
    fn next_locked(spaces: &mut HashMap<String, CursorSpace>, sandbox_id: &str) -> (Uuid, u64) {
        let space = spaces
            .entry(sandbox_id.to_string())
            .or_insert_with(|| CursorSpace {
                epoch: Uuid::new_v4(),
                next: 1,
            });
        let seq = space.next;
        space.next += 1;
        (space.epoch, seq)
    }

    /// Identity and extent of this sandbox's space, or `None` when no event has
    /// been published into it.
    ///
    /// A resume cursor is validated against this: a different epoch means the
    /// cursor belongs to a space that no longer exists, and `None` means there
    /// is no space to resume into at all. An empty `tail_after` result is not
    /// on its own proof that a cursor is still valid.
    fn space(&self, sandbox_id: &str) -> Option<CursorSpaceInfo> {
        self.lock().get(sandbox_id).map(|space| CursorSpaceInfo {
            epoch: space.epoch,
            highest_seq: space.next.saturating_sub(1),
        })
    }
}

fn tail_after_impl(
    tail: &VecDeque<CursoredEvent>,
    last_trimmed_seq: u64,
    after_seq: u64,
) -> Result<Vec<CursoredEvent>, ResumeGap> {
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
    let res: Vec<CursoredEvent> = tail
        .iter()
        .filter(|cursored| cursored.seq > after_seq)
        .cloned()
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

    fn sender_for(&self, sandbox_id: &str) -> broadcast::Sender<CursoredEvent> {
        let mut inner = self.inner.lock().expect("tracing bus lock poisoned");
        inner
            .per_id
            .entry(sandbox_id.to_string())
            .or_insert_with(PerSandbox::new)
            .sender
            .clone()
    }

    pub(crate) fn subscribe(&self, sandbox_id: &str) -> broadcast::Receiver<CursoredEvent> {
        self.sender_for(sandbox_id).subscribe()
    }

    /// Remove all bus entries for the given sandbox id, including the platform
    /// event bus that shares this bus's cursor allocator.
    ///
    /// This drops the broadcast senders (closing any active receivers with
    /// `RecvError::Closed`) and frees the tail buffers.
    ///
    /// The whole sequence runs under the cursor-space lock, so it is atomic
    /// against publication on either bus. Clearing the maps first is not enough
    /// on its own: a publisher that had already allocated a cursor would insert
    /// it into a recreated entry after the maps were cleared, and the next
    /// publisher would restart at 1 behind it.
    ///
    /// Dropping the allocator entry retires the epoch with it, so the next
    /// publish mints a new one. Cursors handed out before this call are
    /// therefore rejected on resume rather than mistaken for positions in the
    /// replacement space. Both broadcast senders are dropped here too, so a
    /// stream that was live across the reset ends rather than silently
    /// continuing into a different space.
    pub fn remove(&self, sandbox_id: &str) {
        let mut spaces = self.seq.lock();
        {
            let mut inner = self.inner.lock().expect("tracing bus lock poisoned");
            inner.per_id.remove(sandbox_id);
        }
        // Takes only the platform bus map lock; never reaches for `spaces`.
        self.platform_event_bus.remove(sandbox_id);
        spaces.remove(sandbox_id);
    }

    pub(crate) fn tail(&self, sandbox_id: &str, max: usize) -> Vec<CursoredEvent> {
        let inner = self.inner.lock().expect("tracing bus lock poisoned");
        inner
            .per_id
            .get(sandbox_id)
            .map(|d| d.tail.iter().rev().take(max).cloned().collect::<Vec<_>>())
            .unwrap_or_default()
            .into_iter()
            .rev()
            .collect::<Vec<CursoredEvent>>()
    }

    /// Identity and extent of this sandbox's current cursor space.
    ///
    /// `None` means nothing has been published for the sandbox, so there is no
    /// space to resume into. Takes only the allocator lock, never the bus map,
    /// so it cannot invert the documented allocator -> bus map order.
    pub(crate) fn cursor_space(&self, sandbox_id: &str) -> Option<CursorSpaceInfo> {
        self.seq.space(sandbox_id)
    }

    pub(crate) fn tail_after(
        &self,
        sandbox_id: &str,
        after_seq: u64,
    ) -> Result<Vec<CursoredEvent>, ResumeGap> {
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
            // Placeholder: publish() stamps the real cursor from the sandbox
            // cursor space.
            cursor: String::new(),
        };
        self.publish(&log.sandbox_id, evt, Self::DEFAULT_TAIL);
    }

    /// Default tail buffer capacity (lines per sandbox).
    const DEFAULT_TAIL: usize = 2000;

    fn publish(&self, sandbox_id: &str, mut event: SandboxStreamEvent, tail_cap: usize) {
        // Hold the cursor space across the tail insert so a teardown cannot
        // reset the counter between allocation and insertion. Lock order is
        // allocator -> bus map, matching `remove`.
        let mut spaces = self.seq.lock();
        let (epoch, seq) = SeqAllocator::next_locked(&mut spaces, sandbox_id);
        event.cursor = WatchCursor::new(epoch, seq).encode();

        let mut inner = self.inner.lock().expect("tracing bus lock poisoned");
        let per = inner
            .per_id
            .entry(sandbox_id.to_string())
            .or_insert_with(PerSandbox::new);

        let cursored = CursoredEvent { seq, event };
        let _ = per.sender.send(cursored.clone());
        per.tail.push_back(cursored);
        while per.tail.len() > tail_cap {
            if let Some(trimmed) = per.tail.pop_front() {
                per.last_trimmed_seq = trimmed.seq;
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
            event_time: openshell_core::time::timestamp_from_millis(ts).ok(),
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
            // Placeholder: publish() stamps the real cursor from the sandbox
            // cursor space.
            cursor: String::new(),
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
            event_time: openshell_core::time::timestamp_from_millis(1000).ok(),
            level: "INFO".to_string(),
            target: "test".to_string(),
            message: message.to_string(),
            source: "gateway".to_string(),
            fields: HashMap::new(),
        }
    }

    /// Fixed epoch for hand-built events, so encoded cursors are deterministic.
    fn test_epoch() -> Uuid {
        Uuid::parse_str("11111111-1111-4111-8111-111111111111").expect("valid uuid")
    }

    /// Build a stream event carrying `seq` in its cursor for assertion.
    fn stream_event(seq: u64) -> SandboxStreamEvent {
        SandboxStreamEvent {
            payload: Some(openshell_core::proto::sandbox_stream_event::Payload::Log(
                make_log_event("sb", &seq.to_string()),
            )),
            cursor: WatchCursor::new(test_epoch(), seq).encode(),
        }
    }

    /// Build a buffered event stamped at `seq`.
    fn cursored(seq: u64) -> CursoredEvent {
        CursoredEvent {
            seq,
            event: stream_event(seq),
        }
    }

    /// Build a contiguous tail with seqs `lo..=hi`.
    fn tail_of(lo: u64, hi: u64) -> VecDeque<CursoredEvent> {
        (lo..=hi).map(cursored).collect()
    }

    /// Extract seqs from a run of buffered events, in order.
    fn cursors(events: &[CursoredEvent]) -> Vec<u64> {
        events.iter().map(|c| c.seq).collect()
    }

    #[test]
    fn tail_after_impl_empty_tail_returns_empty() {
        let tail = VecDeque::new();
        // Nothing trimmed (last_trimmed_seq = 0): any cursor is serviceable.
        assert!(tail_after_impl(&tail, 0, 0).unwrap().is_empty());
        assert!(tail_after_impl(&tail, 0, 42).unwrap().is_empty());
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
        assert!(tail_after_impl(&tail, 0, 5).expect("ok").is_empty());
    }

    #[test]
    fn tail_after_impl_future_cursor_returns_empty() {
        let tail = tail_of(1, 5);
        // Cursor beyond newest (client claims to have seen more than exists):
        // still serviceable, just nothing to send.
        assert!(tail_after_impl(&tail, 0, 99).expect("ok").is_empty());
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
        let tail: VecDeque<CursoredEvent> = [cursored(2), cursored(4)].into_iter().collect();
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
        assert!(bus.tail_after("nope", 5).unwrap().is_empty());
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
    fn cursor_space_is_absent_until_first_publish() {
        let bus = TracingLogBus::new();
        let sandbox_id = "sb-epoch-lazy";

        assert_eq!(bus.cursor_space(sandbox_id), None);

        // Subscribing must not mint a space. `sender_for` touches only the bus
        // map, never the allocator -- and the watch handler subscribes before
        // it validates the resume cursor. If a subscription could manufacture
        // an epoch, a client resuming against a torn-down sandbox would create
        // the very space its stale cursor is then checked against.
        let _log_rx = bus.subscribe(sandbox_id);
        let _platform_rx = bus.platform_event_bus.subscribe(sandbox_id);
        assert_eq!(bus.cursor_space(sandbox_id), None);

        bus.publish_external(make_log_event(sandbox_id, "first"));
        let space = bus.cursor_space(sandbox_id).expect("space after publish");
        assert_eq!(space.highest_seq, 1);
    }

    #[test]
    fn publish_after_remove_starts_a_new_epoch() {
        // The defect this whole mechanism exists for: teardown restarts seqs at
        // 1, so a cursor from before the reset is numerically indistinguishable
        // from a position in the new space. A fresh epoch makes it distinct.
        let bus = TracingLogBus::new();
        let sandbox_id = "sb-epoch-reset";

        bus.publish_external(make_log_event(sandbox_id, "a"));
        bus.publish_external(make_log_event(sandbox_id, "b"));
        let before = bus.cursor_space(sandbox_id).expect("space exists");
        assert_eq!(before.highest_seq, 2);

        bus.remove(sandbox_id);
        assert_eq!(bus.cursor_space(sandbox_id), None);

        bus.publish_external(make_log_event(sandbox_id, "c"));
        let after = bus.cursor_space(sandbox_id).expect("space recreated");

        assert_ne!(before.epoch, after.epoch, "teardown must retire the epoch");
        // Seq alone cannot tell the spaces apart -- that is the point.
        assert_eq!(after.highest_seq, 1);
    }

    #[test]
    fn log_and_platform_publishes_share_one_epoch() {
        // Both buses draw from one allocator, so a cursor observed on either
        // resumes both. Separate epochs would make a merged resume impossible.
        let bus = TracingLogBus::new();
        let sandbox_id = "sb-epoch-shared";

        bus.publish_external(make_log_event(sandbox_id, "a"));
        let after_log = bus.cursor_space(sandbox_id).expect("space exists");

        bus.platform_event_bus.publish(sandbox_id, stream_event(0));
        let after_platform = bus.cursor_space(sandbox_id).expect("space exists");

        assert_eq!(after_log.epoch, after_platform.epoch);
        assert_eq!(after_platform.highest_seq, 2);

        let log_cursor = &bus.tail(sandbox_id, 10)[0].event.cursor;
        let platform_cursor = &bus.platform_event_bus.tail(sandbox_id, 10)[0].event.cursor;
        assert_eq!(
            WatchCursor::parse(log_cursor).expect("valid").epoch,
            WatchCursor::parse(platform_cursor).expect("valid").epoch,
        );
    }

    #[test]
    fn concurrent_publish_and_remove_keeps_cursors_in_one_ascending_space() {
        // Teardown retires the cursor space while both buses can still accept a
        // publish. Unless the whole sequence is atomic against publication, a
        // publisher that allocated before the reset inserts its old cursor into
        // a recreated entry, and the next publisher restarts at 1 behind it --
        // leaving a tail whose cursors go backwards, or worse, one that mixes
        // two epochs.
        //
        // Both halves matter. Resume validation trusts that every cursor in a
        // tail belongs to the epoch `cursor_space` reports, so a mixed tail
        // would let a cursor pass the epoch check and still address the wrong
        // events.
        let bus = TracingLogBus::new();
        let sandbox_id = "sb-race";
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let barrier = Arc::new(std::sync::Barrier::new(5));

        let publishers: Vec<_> = (0..4)
            .map(|_| {
                let bus = bus.clone();
                let stop = Arc::clone(&stop);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        bus.publish_external(make_log_event(sandbox_id, "x"));
                    }
                })
            })
            .collect();

        barrier.wait();
        // Interleave teardown with in-flight publication. Each observation is a
        // sample of the tail mid-race; a non-monotonic one means an event was
        // stamped from a cursor space that no longer existed when it landed.
        for _ in 0..20_000 {
            bus.remove(sandbox_id);
            let observed: Vec<WatchCursor> = bus
                .tail(sandbox_id, usize::MAX)
                .iter()
                .map(|c| WatchCursor::parse(&c.event.cursor).expect("bus stamps valid cursors"))
                .collect();
            assert!(
                observed
                    .windows(2)
                    .all(|w| w[0].epoch == w[1].epoch && w[0].seq < w[1].seq),
                "tail must stay in one epoch with strictly ascending seqs, got {observed:?}"
            );
        }

        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for publisher in publishers {
            publisher.join().expect("publisher thread panicked");
        }
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
        assert!(evt.event.payload.is_some());
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
            cursor: String::new(),
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
            cursor: String::new(),
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
                    event_time: openshell_core::time::timestamp_from_millis(i).ok(),
                    source: "test".to_string(),
                    r#type: "Normal".to_string(),
                    reason: format!("Event{i}"),
                    message: format!("Message {i}"),
                    metadata: HashMap::new(),
                })),
                cursor: String::new(),
            };
            bus.publish(sandbox_id, evt);
        }

        // Tail should return all events in order
        let events = bus.tail(sandbox_id, 10);
        assert_eq!(events.len(), 5);

        // Verify order (oldest first)
        for (i, cursored) in events.iter().enumerate() {
            if let Some(sandbox_stream_event::Payload::Event(ref e)) = cursored.event.payload {
                assert_eq!(e.reason, format!("Event{i}"));
            } else {
                panic!("expected Event payload");
            }
        }

        // Tail with smaller max should return most recent events
        let events = bus.tail(sandbox_id, 2);
        assert_eq!(events.len(), 2);
        if let Some(sandbox_stream_event::Payload::Event(ref e)) = events[0].event.payload {
            assert_eq!(e.reason, "Event3");
        }
        if let Some(sandbox_stream_event::Payload::Event(ref e)) = events[1].event.payload {
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
            cursor: String::new(),
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

    fn sender_for(&self, sandbox_id: &str) -> broadcast::Sender<CursoredEvent> {
        let mut inner = self.inner.lock().expect("platform event bus lock poisoned");
        inner
            .per_id
            .entry(sandbox_id.to_string())
            .or_insert_with(PerSandbox::new)
            .sender
            .clone()
    }

    pub(crate) fn subscribe(&self, sandbox_id: &str) -> broadcast::Receiver<CursoredEvent> {
        self.sender_for(sandbox_id).subscribe()
    }

    pub(crate) fn publish(&self, sandbox_id: &str, mut event: SandboxStreamEvent) {
        // Hold the cursor space across the tail insert (same allocator -> map
        // lock order as `TracingLogBus::publish`), so teardown cannot reset the
        // counter underneath an in-flight publish.
        let mut spaces = self.seq.lock();
        let (epoch, seq) = SeqAllocator::next_locked(&mut spaces, sandbox_id);
        event.cursor = WatchCursor::new(epoch, seq).encode();

        let mut inner = self.inner.lock().expect("platform event bus lock poisoned");
        let per = inner
            .per_id
            .entry(sandbox_id.to_string())
            .or_insert_with(PerSandbox::new);

        let cursored = CursoredEvent { seq, event };
        let _ = per.sender.send(cursored.clone());
        per.tail.push_back(cursored);
        while per.tail.len() > Self::DEFAULT_TAIL {
            if let Some(trimmed) = per.tail.pop_front() {
                per.last_trimmed_seq = trimmed.seq;
            }
        }
    }

    /// Return buffered platform events for replay to late subscribers.
    pub(crate) fn tail(&self, sandbox_id: &str, max: usize) -> Vec<CursoredEvent> {
        let inner = self.inner.lock().expect("platform event bus lock poisoned");
        inner
            .per_id
            .get(sandbox_id)
            .map(|d| d.tail.iter().rev().take(max).cloned().collect::<Vec<_>>())
            .unwrap_or_default()
            .into_iter()
            .rev()
            .collect()
    }

    pub(crate) fn tail_after(
        &self,
        sandbox_id: &str,
        after_seq: u64,
    ) -> Result<Vec<CursoredEvent>, ResumeGap> {
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
