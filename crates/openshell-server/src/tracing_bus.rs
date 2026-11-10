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
    #[cfg(test)]
    hooks: SnapshotHooks,
}

#[derive(Debug, Clone)]
struct Inner {
    per_id: HashMap<String, PerSandbox>,
}

/// Result of a resumable-source replay read: the events after the requested
/// cursor, or the gap that made them unreplayable.
pub(crate) type ReplayResult = Result<Vec<CursoredEvent>, ResumeGap>;

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

/// Split a tail into what a bounded request returns and the coverage floor
/// that bound leaves behind.
///
/// `max` may return fewer events than the tail currently retains; the ones
/// excluded are the oldest, at the front. The floor is the *newest* excluded
/// event's seq: this bus returned every event it retains above the floor and
/// none at or below it. `0` means `max` covered everything currently
/// retained, so there's nothing this call withheld.
///
/// Because the excluded set is a prefix of this bus's retained deque, the
/// floor is the only boundary a caller needs: an event from any followed
/// source with a seq above the floor is safe to hand out as far as this bus
/// is concerned, and one at or below it may sit next to an event this bus
/// withheld. Excluding events below the delivered window is ordinary tail
/// truncation, the same as a single-source `log_tail_lines`.
///
/// This is what lets a caller answer "is a cursor from this batch safe to
/// resume from," which `tail_after`'s eviction-only gap check can't: a
/// shallow request and a bus eviction both withhold events, but only the
/// eviction leaves a trace in `last_trimmed_seq`.
///
/// `keep_after` exempts the newest events from `max`: every retained event
/// with a seq above it is returned regardless of depth. The watch handler
/// passes the high-water mark it recorded when it subscribed, so an event
/// published while the stream was opening -- one that is also queued on the
/// live receiver, where the snapshot's cutoff will suppress it -- is always
/// delivered in the batch rather than trimmed as history. The returned set is
/// still a suffix of the tail, so the floor keeps its meaning, and it never
/// exceeds `keep_after`.
fn tail_with_floor_impl(
    tail: &VecDeque<CursoredEvent>,
    max: usize,
    keep_after: u64,
) -> (Vec<CursoredEvent>, u64) {
    let first_unseen = tail.partition_point(|cursored| cursored.seq <= keep_after);
    let excluded = tail.len().saturating_sub(max).min(first_unseen);
    let floor = excluded
        .checked_sub(1)
        .and_then(|newest_excluded| tail.get(newest_excluded))
        .map_or(0, |cursored| cursored.seq);
    let events = tail.iter().skip(excluded).cloned().collect();
    (events, floor)
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
            #[cfg(test)]
            hooks: SnapshotHooks::default(),
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

    /// Validate a resume cursor's epoch and read both resumable buses, all
    /// under one lock hold.
    ///
    /// Folding validation into the same hold as the reads is what makes this
    /// atomic against a teardown: checking the epoch first and reading after
    /// -- even via a single call that itself locks once internally -- still
    /// leaves a window between the two lock acquisitions for a `remove` plus
    /// a republish to retire the validated space and install a replacement
    /// numbered from 1. A read landing after that would apply the old
    /// space's seq to the replacement's buffers and find no gap, since
    /// `tail_after` only compares numbers. Locking the cursor space before
    /// checking the epoch -- the same lock every publish path holds across
    /// its own tail insert -- closes that window entirely, and also makes
    /// the two bus reads atomic against any publish on either bus, for the
    /// same reason.
    pub(crate) fn snapshot_after(
        &self,
        sandbox_id: &str,
        expected_epoch: Uuid,
        log_after: u64,
        platform_after: u64,
        want_log: bool,
        want_platform: bool,
    ) -> ResumeSnapshot {
        let spaces = self.seq.lock();
        let Some(space) = spaces.get(sandbox_id) else {
            return ResumeSnapshot::SpaceGone;
        };
        if space.epoch != expected_epoch {
            return ResumeSnapshot::SpaceGone;
        }
        // Right space, but ahead of anything it has issued: only a
        // fabricated cursor gets here. Reject rather than accept a cutoff no
        // event can ever exceed.
        if log_after.max(platform_after) > space.next.saturating_sub(1) {
            return ResumeSnapshot::CursorAhead;
        }

        let log = want_log.then(|| {
            let inner = self.inner.lock().expect("tracing bus lock poisoned");
            inner.per_id.get(sandbox_id).map_or_else(
                || Ok(Vec::new()),
                |per| tail_after_impl(&per.tail, per.last_trimmed_seq, log_after),
            )
        });
        #[cfg(test)]
        self.hooks.run(SnapshotPoint::BetweenReads);
        let platform = want_platform.then(|| {
            let inner = self
                .platform_event_bus
                .inner
                .lock()
                .expect("platform event bus lock poisoned");
            inner.per_id.get(sandbox_id).map_or_else(
                || Ok(Vec::new()),
                |per| tail_after_impl(&per.tail, per.last_trimmed_seq, platform_after),
            )
        });
        ResumeSnapshot::Read(log, platform)
    }

    /// Read both bounded initial tails and the space's high-water mark, all
    /// under one lock hold.
    ///
    /// `None` skips a source. Holding the cursor-space lock -- the one every
    /// publish holds across its tail insert and broadcast send -- means no
    /// publish can land between the two reads, and `highest_seq` is exactly
    /// the boundary between what these tails could see and what can only
    /// arrive live. Every event at or below it was already buffered when the
    /// tails were read, so the caller can suppress live copies at or below it
    /// without dropping anything the tails could not have covered.
    ///
    /// `subscribed_at` is the mark [`Self::subscribe_resumable`] recorded.
    /// Events above it were published after the caller's live receivers
    /// existed, so they are queued live as well as buffered here; the caller
    /// suppresses those live copies, which means this batch is their only
    /// delivery. Each source therefore returns all of them regardless of its
    /// depth (see `tail_with_floor_impl`), and reports whether its buffer
    /// already evicted any of them before the read, in which case they are
    /// lost from both paths and the caller must say so.
    ///
    /// Reads never mint a space: with none, both tails are empty and
    /// `highest_seq` is `0`.
    pub(crate) fn snapshot_tail(
        &self,
        sandbox_id: &str,
        log_max: Option<usize>,
        platform_max: Option<usize>,
        subscribed_at: u64,
    ) -> TailSnapshot {
        let spaces = self.seq.lock();
        let highest_seq = spaces
            .get(sandbox_id)
            .map_or(0, |space| space.next.saturating_sub(1));

        let read = |per: Option<&PerSandbox>, max: usize| {
            per.map_or_else(SourceTail::default, |per| {
                let (events, floor) = tail_with_floor_impl(&per.tail, max, subscribed_at);
                SourceTail {
                    events,
                    floor,
                    evicted_while_opening: per.last_trimmed_seq > subscribed_at,
                }
            })
        };

        let log = log_max.map_or_else(SourceTail::default, |max| {
            let inner = self.inner.lock().expect("tracing bus lock poisoned");
            read(inner.per_id.get(sandbox_id), max)
        });
        #[cfg(test)]
        self.hooks.run(SnapshotPoint::BetweenReads);
        let platform = platform_max.map_or_else(SourceTail::default, |max| {
            let inner = self
                .platform_event_bus
                .inner
                .lock()
                .expect("platform event bus lock poisoned");
            read(inner.per_id.get(sandbox_id), max)
        });
        drop(spaces);

        TailSnapshot {
            log,
            platform,
            highest_seq,
        }
    }

    /// Subscribe live receivers for the resumable sources and record the
    /// space's high-water mark, all under one cursor-space lock hold.
    ///
    /// Every publish holds this lock across its broadcast send, so the mark
    /// splits the space exactly: an event at or below it was sent before
    /// these receivers existed and can only be found in a buffer, and one
    /// above it is queued on them. [`Self::snapshot_tail`] uses the mark to
    /// keep every queued-and-buffered event in the initial batch.
    ///
    /// The lock order is allocator -> bus map, the same as publish. Never
    /// mints a space: with none, the mark is `0`.
    pub(crate) fn subscribe_resumable(
        &self,
        sandbox_id: &str,
        want_log: bool,
        want_platform: bool,
    ) -> ResumableSubscription {
        let spaces = self.seq.lock();
        let subscription = ResumableSubscription {
            log_rx: want_log.then(|| self.subscribe(sandbox_id)),
            platform_rx: want_platform.then(|| self.platform_event_bus.subscribe(sandbox_id)),
            subscribed_at: spaces
                .get(sandbox_id)
                .map_or(0, |space| space.next.saturating_sub(1)),
        };
        drop(spaces);
        #[cfg(test)]
        self.hooks.run(SnapshotPoint::AfterSubscribe);
        subscription
    }

    /// Install a hook that runs at each [`SnapshotPoint`], replacing any
    /// previous one. Shared by every clone of this bus.
    #[cfg(test)]
    pub(crate) fn set_snapshot_hook(&self, hook: impl FnMut(SnapshotPoint) + Send + 'static) {
        *self.hooks.0.lock().expect("snapshot hook lock poisoned") = Some(Box::new(hook));
    }

    /// Whether the cursor-space lock is held right now, by anyone.
    #[cfg(test)]
    pub(crate) fn cursor_space_locked(&self) -> bool {
        matches!(
            self.seq.inner.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        )
    }
}

/// Receivers from [`TracingLogBus::subscribe_resumable`] and the mark that
/// separates buffered-only history from events queued on them.
pub(crate) struct ResumableSubscription {
    pub(crate) log_rx: Option<broadcast::Receiver<CursoredEvent>>,
    pub(crate) platform_rx: Option<broadcast::Receiver<CursoredEvent>>,
    /// Highest seq the space had issued when the receivers subscribed; `0`
    /// with no space.
    pub(crate) subscribed_at: u64,
}

/// Points inside the snapshot paths where a test hook runs.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SnapshotPoint {
    /// After `subscribe_resumable` subscribed and released the lock.
    AfterSubscribe,
    /// Inside `snapshot_tail` or `snapshot_after`, after the log read and
    /// before the platform read, with the cursor-space lock still held.
    BetweenReads,
}

/// Test-only hook slot. Production builds carry no field at all.
#[cfg(test)]
#[derive(Clone, Default)]
#[allow(clippy::type_complexity)]
struct SnapshotHooks(Arc<Mutex<Option<Box<dyn FnMut(SnapshotPoint) + Send>>>>);

#[cfg(test)]
impl SnapshotHooks {
    fn run(&self, point: SnapshotPoint) {
        if let Some(hook) = self.0.lock().expect("snapshot hook lock poisoned").as_mut() {
            hook(point);
        }
    }
}

#[cfg(test)]
impl std::fmt::Debug for SnapshotHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SnapshotHooks")
    }
}

/// One source's part of a [`TailSnapshot`]. An unread source has no events,
/// a floor of `0`, and nothing evicted.
#[derive(Debug, Default)]
pub(crate) struct SourceTail {
    pub(crate) events: Vec<CursoredEvent>,
    /// What `tail_with_floor_impl` reports for this source.
    pub(crate) floor: u64,
    /// The buffer trimmed at least one event published after the receivers
    /// subscribed, before the snapshot could read it. Its live copy is
    /// suppressed with the rest of the batch's range, so it is lost.
    pub(crate) evicted_while_opening: bool,
}

/// What [`race_publish_between_reads`] observed from inside the snapshot.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct RaceProbe {
    /// The hook ran at all, i.e. a snapshot reached its second read.
    pub(crate) fired: bool,
    /// The cursor-space lock was held between the two reads.
    pub(crate) lock_held_between_reads: bool,
    /// The competing publisher completed while the snapshot sat between its
    /// reads. With both reads under one lock hold it cannot.
    pub(crate) publisher_finished_between_reads: bool,
    publisher: Option<std::thread::JoinHandle<()>>,
}

#[cfg(test)]
impl RaceProbe {
    /// Wait for the competing publisher to finish both publishes.
    pub(crate) fn join_publisher(&mut self) {
        if let Some(handle) = self.publisher.take() {
            handle.join().expect("publisher thread panicked");
        }
    }
}

/// Force the interleaving a snapshot must be atomic against: when the next
/// snapshot on `bus` sits between its log read and its platform read, start a
/// publisher that publishes one log line and then one platform event for
/// `sandbox_id`, and give it time to finish before letting the snapshot read
/// the platform bus.
///
/// With separate reads, the publisher completes in that pause and the platform
/// read picks up its event while the log read missed the log line published
/// just before it. With one lock hold, the publisher blocks until the snapshot
/// is done, and both events land after it. The hook records what it saw
/// rather than asserting, because it may run inside a gateway producer task
/// where a panic would surface only as a truncated stream.
///
/// The hook fires once.
#[cfg(test)]
pub(crate) fn race_publish_between_reads(
    bus: &TracingLogBus,
    sandbox_id: &str,
) -> Arc<Mutex<RaceProbe>> {
    use std::sync::mpsc;
    use std::time::Duration;

    let probe = Arc::new(Mutex::new(RaceProbe::default()));
    let hook_probe = Arc::clone(&probe);
    let publisher_bus = bus.clone();
    let lock_bus = bus.clone();
    let sandbox_id = sandbox_id.to_string();
    // Closure state, not the probe, decides whether the hook already fired:
    // a later snapshot must not touch the probe, which the test may be
    // holding while it inspects the result.
    let mut fired = false;
    bus.set_snapshot_hook(move |point| {
        if point != SnapshotPoint::BetweenReads || fired {
            return;
        }
        fired = true;
        let mut probe = hook_probe.lock().expect("race probe lock poisoned");
        probe.fired = true;
        probe.lock_held_between_reads = lock_bus.cursor_space_locked();

        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let bus = publisher_bus.clone();
        let id = sandbox_id.clone();
        probe.publisher = Some(std::thread::spawn(move || {
            started_tx.send(()).expect("hook waits for start");
            bus.publish_external(SandboxLogLine {
                sandbox_id: id.clone(),
                level: "INFO".to_string(),
                target: "race".to_string(),
                message: "raced log".to_string(),
                source: "gateway".to_string(),
                ..Default::default()
            });
            bus.platform_event_bus.publish(
                &id,
                SandboxStreamEvent {
                    payload: Some(openshell_core::proto::sandbox_stream_event::Payload::Event(
                        openshell_core::proto::PlatformEvent {
                            source: "race".to_string(),
                            r#type: "Normal".to_string(),
                            reason: "raced".to_string(),
                            message: "raced event".to_string(),
                            ..Default::default()
                        },
                    )),
                    cursor: String::new(),
                },
            );
            let _ = done_tx.send(());
        }));
        started_rx.recv().expect("publisher thread starts");
        // Long enough for an unblocked publisher to finish two publishes many
        // times over. A blocked one never does, so the correct implementation
        // always pays the full wait; a broken one fails reliably.
        probe.publisher_finished_between_reads =
            done_rx.recv_timeout(Duration::from_millis(300)).is_ok();
    });
    probe
}

/// Outcome of [`TracingLogBus::snapshot_tail`].
pub(crate) struct TailSnapshot {
    pub(crate) log: SourceTail,
    pub(crate) platform: SourceTail,
    /// Highest seq the space had issued at the lock hold; `0` with no space.
    pub(crate) highest_seq: u64,
}

/// Outcome of [`TracingLogBus::snapshot_after`].
pub(crate) enum ResumeSnapshot {
    /// No cursor space exists for this sandbox, or its epoch no longer
    /// matches the resume cursor's -- the space that issued it is gone.
    SpaceGone,
    /// The right space, but the cursor is ahead of anything it has issued.
    /// Only a fabricated cursor reaches this.
    CursorAhead,
    /// Both requested reads succeeded at the lock hold; each is
    /// independently either the replay or the gap that made it unreplayable.
    Read(Option<ReplayResult>, Option<ReplayResult>),
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

        if meta.target() == OCSF_TARGET
            && let Some(ocsf) = openshell_ocsf::clone_current_event()
        {
            // The structured bridge carries no tracing fields. Route by the
            // trusted context identity, never by request-supplied resources.
            visitor.sandbox_id = ocsf.sandbox_id().map(str::to_string);
            visitor.message = Some(ocsf.format_shorthand());
        }

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

    #[test]
    fn cross_sandbox_denials_remain_gateway_wide() {
        use crate::auth::{audit, principal::test_support};
        use tracing_subscriber::prelude::*;

        let bus = TracingLogBus::new();
        let mut receiver = bus.subscribe("sb-victim");
        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry()
            .with(bus.layer())
            .with(capture.clone());
        tracing::subscriber::with_default(subscriber, || {
            for target in ["sb-victim", "sb-nonexistent-1", "sb-nonexistent-2"] {
                audit::emit_authorization_denial_for(
                    "/openshell.v1.OpenShell/GetSandbox",
                    &audit::test_support::origin(),
                    &test_support::sandbox("sb-attacker"),
                    audit::AuthzDenial::CrossSandbox { sandbox_id: target },
                );
            }
        });

        let events = capture.json_events();
        assert_eq!(events.len(), 6, "each denial must retain both audit events");
        for event in &events {
            openshell_ocsf_validate::validate_event(event).unwrap();
        }
        for event in capture.events() {
            assert!(event.sandbox_id().is_none());
        }
        assert_eq!(events[0]["resources"][0]["uid"], "sb-victim");
        assert!(receiver.try_recv().is_err());
        assert!(bus.tail("sb-victim", 10).is_empty());
        let inner = bus.inner.lock().unwrap();
        assert_eq!(
            inner.per_id.len(),
            1,
            "only the subscribed sandbox may exist"
        );
        assert!(inner.per_id.contains_key("sb-victim"));
        drop(inner);
        assert!(
            bus.seq.lock().is_empty(),
            "denials must allocate no sandbox cursors"
        );
    }

    #[test]
    fn gateway_ocsf_reaches_sandbox_tail_and_live_stream() {
        use tracing_subscriber::prelude::*;
        let ctx = crate::gateway_ocsf::context("sb-audit", "audit");
        for event in [
            openshell_ocsf::ConfigStateChangeBuilder::new(&ctx)
                .message("policy approved")
                .build(),
            openshell_ocsf::ApiActivityBuilder::new(&ctx, "GetSandbox").build(),
            openshell_ocsf::DetectionFindingBuilder::new(&ctx).build(),
        ] {
            let bus = TracingLogBus::new();
            let mut receiver = bus.subscribe("sb-audit");
            let expected = event.format_shorthand();
            let subscriber = tracing_subscriber::registry().with(bus.layer());
            tracing::subscriber::with_default(subscriber, || {
                openshell_ocsf::ocsf_emit!(event);
                openshell_ocsf::ocsf_emit!(
                    openshell_ocsf::ConfigStateChangeBuilder::new(&crate::gateway_ocsf::context(
                        "", ""
                    ))
                    .message("gateway-wide event")
                    .build()
                );
            });
            let live = receiver
                .try_recv()
                .expect("sandbox audit event must reach live stream");
            let Some(openshell_core::proto::sandbox_stream_event::Payload::Log(log)) =
                live.event.payload
            else {
                panic!("expected log payload");
            };
            assert_eq!(log.sandbox_id, "sb-audit");
            assert_eq!(log.source, "gateway");
            assert_eq!(log.level, "OCSF");
            assert_eq!(log.message, expected);
            assert_eq!(bus.tail("sb-audit", 10).len(), 1);
            assert!(bus.tail("", 10).is_empty());
            assert!(receiver.try_recv().is_err());
        }
    }

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
    fn tail_with_floor_impl_empty_tail_returns_zero_floor() {
        let tail = VecDeque::new();
        let (events, floor) = tail_with_floor_impl(&tail, 10, u64::MAX);
        assert!(events.is_empty());
        assert_eq!(floor, 0);
    }

    #[test]
    fn tail_with_floor_impl_max_covers_everything_returns_zero_floor() {
        let tail = tail_of(1, 5);
        let (events, floor) = tail_with_floor_impl(&tail, 5, u64::MAX);
        assert_eq!(cursors(&events), vec![1, 2, 3, 4, 5]);
        assert_eq!(floor, 0);

        // Asking for more than exists is the same as asking for everything.
        let (events, floor) = tail_with_floor_impl(&tail, 99, u64::MAX);
        assert_eq!(cursors(&events), vec![1, 2, 3, 4, 5]);
        assert_eq!(floor, 0);
    }

    #[test]
    fn tail_with_floor_impl_truncated_reports_newest_excluded_seq() {
        let tail = tail_of(1, 5);
        // Newest 2 returned (4, 5); 1..=3 excluded, newest of those is 3.
        // Every returned event sits above the floor, so a bus never
        // withholds its own delivered window.
        let (events, floor) = tail_with_floor_impl(&tail, 2, u64::MAX);
        assert_eq!(cursors(&events), vec![4, 5]);
        assert_eq!(floor, 3);
        assert!(events.iter().all(|cursored| cursored.seq > floor));
    }

    #[test]
    fn tail_with_floor_impl_zero_max_excludes_everything() {
        let tail = tail_of(1, 5);
        // Nothing returned; every event is excluded, so the floor is the
        // newest of them, 5.
        let (events, floor) = tail_with_floor_impl(&tail, 0, u64::MAX);
        assert!(events.is_empty());
        assert_eq!(floor, 5);
    }

    /// The resume read is atomic against a publish on either bus. The forced
    /// interleaving publishes a log line and then a platform event while
    /// `snapshot_after` sits between its two reads. If the reads were
    /// separate, the platform read would return the event while the log read
    /// had already missed the line before it: a client handed that event's
    /// cursor would resume past the line forever. Under one lock hold the
    /// publisher waits, the replay holds neither, and both arrive live in
    /// cursor order and are replayable from the replay's last cursor.
    #[test]
    fn snapshot_after_holds_the_lock_across_a_publish_between_reads() {
        let bus = TracingLogBus::new();
        let sandbox_id = "sb-race-resume";
        bus.publish_external(make_log_event(sandbox_id, "l1")); // seq 1
        bus.platform_event_bus.publish(sandbox_id, stream_event(0)); // seq 2
        let epoch = bus.cursor_space(sandbox_id).expect("space exists").epoch;
        let sub = bus.subscribe_resumable(sandbox_id, true, true);
        let (mut log_rx, mut platform_rx) = (sub.log_rx.unwrap(), sub.platform_rx.unwrap());

        let probe = race_publish_between_reads(&bus, sandbox_id);
        let ResumeSnapshot::Read(log, platform) =
            bus.snapshot_after(sandbox_id, epoch, 0, 0, true, true)
        else {
            panic!("expected a successful read");
        };
        {
            let mut probe = probe.lock().unwrap();
            probe.join_publisher();
            assert!(probe.fired, "the hook must run between the two reads");
            assert!(probe.lock_held_between_reads, "lock released between reads");
            assert!(
                !probe.publisher_finished_between_reads,
                "a publish landed between the log read and the platform read"
            );
        }

        let log = log.expect("followed").expect("no gap");
        let platform = platform.expect("followed").expect("no gap");
        assert_eq!(cursors(&log), vec![1]);
        assert_eq!(cursors(&platform), vec![2]);

        // The raced events come live, in order, above the replay.
        assert_eq!(log_rx.try_recv().expect("raced log is live").seq, 3);
        assert_eq!(platform_rx.try_recv().expect("raced event is live").seq, 4);

        // Resuming from the replay's highest cursor recovers both.
        let ResumeSnapshot::Read(log, platform) =
            bus.snapshot_after(sandbox_id, epoch, 2, 2, true, true)
        else {
            panic!("expected a successful read");
        };
        assert_eq!(cursors(&log.unwrap().unwrap()), vec![3]);
        assert_eq!(cursors(&platform.unwrap().unwrap()), vec![4]);
    }

    /// The same forced interleaving on the initial path. Under one lock hold
    /// the raced events are newer than the snapshot's high-water mark, so the
    /// caller's cutoff lets their live copies through, in order.
    #[test]
    fn snapshot_tail_holds_the_lock_across_a_publish_between_reads() {
        let bus = TracingLogBus::new();
        let sandbox_id = "sb-race-tail";
        bus.publish_external(make_log_event(sandbox_id, "l1")); // seq 1
        bus.platform_event_bus.publish(sandbox_id, stream_event(0)); // seq 2
        let sub = bus.subscribe_resumable(sandbox_id, true, true);
        let (mut log_rx, mut platform_rx) = (sub.log_rx.unwrap(), sub.platform_rx.unwrap());

        let probe = race_publish_between_reads(&bus, sandbox_id);
        let snap = bus.snapshot_tail(sandbox_id, Some(10), Some(10), sub.subscribed_at);
        let mut probe = probe.lock().unwrap();
        probe.join_publisher();
        assert!(probe.fired, "the hook must run between the two reads");
        assert!(probe.lock_held_between_reads, "lock released between reads");
        assert!(
            !probe.publisher_finished_between_reads,
            "a publish landed between the log read and the platform read"
        );

        assert_eq!(cursors(&snap.log.events), vec![1]);
        assert_eq!(cursors(&snap.platform.events), vec![2]);
        assert_eq!(snap.highest_seq, 2);

        let live_log = log_rx.try_recv().expect("raced log is live");
        let live_event = platform_rx.try_recv().expect("raced event is live");
        assert_eq!((live_log.seq, live_event.seq), (3, 4));
        assert!(live_log.seq > snap.highest_seq && live_event.seq > snap.highest_seq);
    }

    /// `subscribe_resumable` records the mark under the lock every publish
    /// holds across its send, so an event at or below it is never queued on
    /// the new receivers and one above it always is.
    #[test]
    fn subscribe_resumable_splits_buffered_history_from_queued_events() {
        let bus = TracingLogBus::new();
        let sandbox_id = "sb-sub";
        assert_eq!(
            bus.subscribe_resumable(sandbox_id, true, true)
                .subscribed_at,
            0
        );
        assert_eq!(bus.cursor_space(sandbox_id), None, "must not mint a space");

        bus.publish_external(make_log_event(sandbox_id, "l1")); // seq 1
        let sub = bus.subscribe_resumable(sandbox_id, true, false);
        assert_eq!(sub.subscribed_at, 1);
        assert!(sub.platform_rx.is_none());
        let mut log_rx = sub.log_rx.unwrap();
        assert!(log_rx.try_recv().is_err(), "history is not queued live");

        bus.publish_external(make_log_event(sandbox_id, "l2")); // seq 2
        assert_eq!(log_rx.try_recv().unwrap().seq, 2);
    }

    /// The reviewer's example at bus level: subscribe, then platform event 1
    /// and log 2 are published before the snapshot. Both are queued live, and
    /// the caller will suppress those copies, so the snapshot must return both
    /// even though `event_tail` asked for no platform history -- and with
    /// nothing excluded, neither source reports a floor.
    #[test]
    fn snapshot_tail_keeps_events_published_after_subscribe_regardless_of_depth() {
        let bus = TracingLogBus::new();
        let sandbox_id = "sb-opening";
        let sub = bus.subscribe_resumable(sandbox_id, true, true);
        bus.platform_event_bus.publish(sandbox_id, stream_event(0)); // seq 1
        bus.publish_external(make_log_event(sandbox_id, "l2")); // seq 2

        let snap = bus.snapshot_tail(sandbox_id, Some(200), Some(0), sub.subscribed_at);
        assert_eq!(cursors(&snap.log.events), vec![2]);
        assert_eq!(cursors(&snap.platform.events), vec![1]);
        assert_eq!((snap.log.floor, snap.platform.floor), (0, 0));
        assert!(!snap.log.evicted_while_opening && !snap.platform.evicted_while_opening);
        assert_eq!(snap.highest_seq, 2);
    }

    /// The exemption covers only events after the mark: older history is
    /// still bounded by depth and still reports its floor.
    #[test]
    fn tail_with_floor_impl_exempts_only_events_after_keep_after() {
        let tail = tail_of(1, 6);
        // Depth 1 would return just 6; everything after 3 is exempt.
        let (events, floor) = tail_with_floor_impl(&tail, 1, 3);
        assert_eq!(cursors(&events), vec![4, 5, 6]);
        assert_eq!(floor, 3);

        // A depth deeper than the exempt run still reaches into history.
        let (events, floor) = tail_with_floor_impl(&tail, 4, 5);
        assert_eq!(cursors(&events), vec![3, 4, 5, 6]);
        assert_eq!(floor, 2);

        // Nothing after the mark: plain depth bound.
        let (events, floor) = tail_with_floor_impl(&tail, 0, 6);
        assert!(events.is_empty());
        assert_eq!(floor, 6);
    }

    /// If the buffer trimmed an event published after subscribe before the
    /// snapshot read it, that event is gone from both paths; the source says
    /// so for the caller to report.
    #[test]
    fn snapshot_tail_reports_eviction_of_events_published_after_subscribe() {
        let bus = TracingLogBus::new();
        let sandbox_id = "sb-opening-evict";
        bus.platform_event_bus.publish(sandbox_id, stream_event(0)); // seq 1
        let sub = bus.subscribe_resumable(sandbox_id, true, true);
        for _ in 0..=PlatformEventBus::DEFAULT_TAIL {
            bus.platform_event_bus.publish(sandbox_id, stream_event(0));
        }

        let snap = bus.snapshot_tail(sandbox_id, Some(10), Some(0), sub.subscribed_at);
        assert!(snap.platform.evicted_while_opening);
        assert!(!snap.log.evicted_while_opening);
        assert_eq!(snap.platform.events.len(), PlatformEventBus::DEFAULT_TAIL);

        // History trimmed before subscribe is ordinary truncation.
        let late = bus.subscribe_resumable(sandbox_id, true, true);
        let snap = bus.snapshot_tail(sandbox_id, Some(10), Some(0), late.subscribed_at);
        assert!(!snap.platform.evicted_while_opening);
        assert!(snap.platform.events.is_empty());
    }

    /// Baseline correctness: interleaved log/platform publishes draw from the
    /// same cursor space, and `snapshot_after` returns each source's own
    /// events under its own key, not merged or cross-contaminated.
    #[test]
    fn snapshot_after_matches_independent_tail_after_calls() {
        let bus = TracingLogBus::new();
        let sandbox_id = "sb-snap";
        bus.publish_external(make_log_event(sandbox_id, "l1")); // seq 1
        bus.platform_event_bus.publish(
            sandbox_id,
            SandboxStreamEvent {
                payload: None,
                cursor: String::new(),
            },
        ); // seq 2
        bus.publish_external(make_log_event(sandbox_id, "l2")); // seq 3
        let epoch = bus.cursor_space(sandbox_id).expect("space exists").epoch;

        let ResumeSnapshot::Read(log, platform) =
            bus.snapshot_after(sandbox_id, epoch, 0, 0, true, true)
        else {
            panic!("expected a successful read");
        };
        assert_eq!(
            cursors(&log.expect("followed").expect("no gap")),
            vec![1, 3]
        );
        assert_eq!(
            cursors(&platform.expect("followed").expect("no gap")),
            vec![2]
        );
    }

    /// A source that isn't followed isn't read at all.
    #[test]
    fn snapshot_after_skips_unfollowed_sources() {
        let bus = TracingLogBus::new();
        let sandbox_id = "sb-skip";
        bus.publish_external(make_log_event(sandbox_id, "l1"));
        let epoch = bus.cursor_space(sandbox_id).expect("space exists").epoch;

        let ResumeSnapshot::Read(log, platform) =
            bus.snapshot_after(sandbox_id, epoch, 0, 0, true, false)
        else {
            panic!("expected a successful read");
        };
        assert_eq!(log.expect("followed").expect("no gap").len(), 1);
        assert!(platform.is_none());
    }

    /// The epoch check and both bus reads happen under one lock hold, so a
    /// teardown plus republish between them can't apply a stale epoch's
    /// cursor to the replacement space's buffers.
    #[test]
    fn snapshot_after_rejects_a_cursor_from_a_retired_space() {
        let bus = TracingLogBus::new();
        let sandbox_id = "sb-retired";
        bus.publish_external(make_log_event(sandbox_id, "l1"));
        let original_epoch = bus.cursor_space(sandbox_id).expect("space exists").epoch;

        bus.remove(sandbox_id);
        bus.publish_external(make_log_event(sandbox_id, "l1-again")); // seq 1 again, new epoch

        assert!(matches!(
            bus.snapshot_after(sandbox_id, original_epoch, 0, 0, true, false),
            ResumeSnapshot::SpaceGone
        ));
    }

    /// No space at all -- an unpublished or never-existent sandbox -- is the
    /// same outcome as a retired one: there's nothing for the cursor to
    /// address.
    #[test]
    fn snapshot_after_rejects_when_no_space_exists() {
        let bus = TracingLogBus::new();
        assert!(matches!(
            bus.snapshot_after("nope", Uuid::nil(), 0, 0, true, false),
            ResumeSnapshot::SpaceGone
        ));
    }

    /// A cursor ahead of anything the space has issued -- only reachable with
    /// a fabricated token -- is rejected rather than treated as caught up.
    #[test]
    fn snapshot_after_rejects_a_cursor_ahead_of_the_space() {
        let bus = TracingLogBus::new();
        let sandbox_id = "sb-ahead";
        bus.publish_external(make_log_event(sandbox_id, "l1"));
        let epoch = bus.cursor_space(sandbox_id).expect("space exists").epoch;

        assert!(matches!(
            bus.snapshot_after(sandbox_id, epoch, 99, 0, true, false),
            ResumeSnapshot::CursorAhead
        ));
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
    fn tracing_log_bus_resume_replay_serviceable_and_missing() {
        let bus = TracingLogBus::new();
        let sandbox_id = "sb-ta";
        for _ in 0..3 {
            bus.publish_external(make_log_event(sandbox_id, "line"));
        }
        let epoch = bus.cursor_space(sandbox_id).expect("space exists").epoch;

        // Cursors start at 1, so three publishes are seqs 1,2,3.
        let ResumeSnapshot::Read(log, _) = bus.snapshot_after(sandbox_id, epoch, 0, 0, true, false)
        else {
            panic!("expected a successful read");
        };
        assert_eq!(
            cursors(&log.expect("followed").expect("no gap")),
            vec![1, 2, 3]
        );
        let ResumeSnapshot::Read(log, _) = bus.snapshot_after(sandbox_id, epoch, 2, 0, true, false)
        else {
            panic!("expected a successful read");
        };
        assert_eq!(cursors(&log.expect("followed").expect("no gap")), vec![3]);
    }

    #[test]
    fn platform_event_bus_resume_replay_serviceable() {
        let bus = TracingLogBus::new();
        let platform = &bus.platform_event_bus;
        let sandbox_id = "sb-pe";
        for _ in 0..3 {
            platform.publish(sandbox_id, stream_event(0));
        }
        let epoch = bus.cursor_space(sandbox_id).expect("space exists").epoch;

        // Shared allocator, but only the platform bus published here, so its
        // seqs are 1,2,3.
        let ResumeSnapshot::Read(_, platform_replay) =
            bus.snapshot_after(sandbox_id, epoch, 0, 0, false, true)
        else {
            panic!("expected a successful read");
        };
        assert_eq!(
            cursors(&platform_replay.expect("followed").expect("no gap")),
            vec![1, 2, 3]
        );
        let ResumeSnapshot::Read(_, platform_replay) =
            bus.snapshot_after(sandbox_id, epoch, 0, 1, false, true)
        else {
            panic!("expected a successful read");
        };
        assert_eq!(
            cursors(&platform_replay.expect("followed").expect("no gap")),
            vec![2, 3]
        );
    }

    #[test]
    fn snapshot_tail_reports_truncation() {
        let bus = TracingLogBus::new();
        let sandbox_id = "sb-floor";
        for _ in 0..5 {
            bus.publish_external(make_log_event(sandbox_id, "line"));
        }
        let snap = bus.snapshot_tail(sandbox_id, Some(2), None, u64::MAX);
        assert_eq!(cursors(&snap.log.events), vec![4, 5]);
        assert_eq!(snap.log.floor, 3);

        // Wide enough to cover everything: no floor.
        let snap = bus.snapshot_tail(sandbox_id, Some(10), None, u64::MAX);
        assert_eq!(cursors(&snap.log.events), vec![1, 2, 3, 4, 5]);
        assert_eq!(snap.log.floor, 0);
    }

    /// `highest_seq` is the space's high-water mark at the lock hold, not the
    /// newest event either window returned: events a depth excluded still
    /// count, since they were buffered when the tails were read and can only
    /// reach a live receiver as a duplicate of pre-snapshot history.
    #[test]
    fn snapshot_tail_reports_the_high_water_mark_past_excluded_events() {
        let bus = TracingLogBus::new();
        let sandbox_id = "sb-hwm";
        bus.publish_external(make_log_event(sandbox_id, "l1")); // seq 1
        bus.publish_external(make_log_event(sandbox_id, "l2")); // seq 2
        bus.platform_event_bus.publish(sandbox_id, stream_event(0)); // seq 3

        let snap = bus.snapshot_tail(sandbox_id, Some(10), Some(0), u64::MAX);
        assert_eq!(cursors(&snap.log.events), vec![1, 2]);
        assert_eq!(snap.log.floor, 0);
        assert!(snap.platform.events.is_empty());
        assert_eq!(snap.platform.floor, 3);
        assert_eq!(snap.highest_seq, 3);
    }

    /// An unread source is skipped outright; a sandbox with nothing published
    /// yields empty tails and a zero mark without minting a cursor space.
    #[test]
    fn snapshot_tail_skips_unread_sources_and_never_mints_a_space() {
        let bus = TracingLogBus::new();
        let sandbox_id = "sb-tail-skip";
        bus.publish_external(make_log_event(sandbox_id, "l1"));
        bus.platform_event_bus.publish(sandbox_id, stream_event(0));

        let snap = bus.snapshot_tail(sandbox_id, Some(10), None, u64::MAX);
        assert_eq!(cursors(&snap.log.events), vec![1]);
        assert!(snap.platform.events.is_empty());
        assert_eq!(snap.platform.floor, 0);
        assert_eq!(snap.highest_seq, 2);

        let snap = bus.snapshot_tail("nope", Some(10), Some(10), u64::MAX);
        assert!(snap.log.events.is_empty() && snap.platform.events.is_empty());
        assert_eq!(snap.highest_seq, 0);
        assert_eq!(bus.cursor_space("nope"), None);
    }

    #[test]
    fn platform_event_bus_tail_with_floor_reports_truncation() {
        let bus = TracingLogBus::new();
        let platform = &bus.platform_event_bus;
        let sandbox_id = "sb-pe-floor";
        for _ in 0..5 {
            platform.publish(sandbox_id, stream_event(0));
        }
        let (events, floor) = platform.tail_with_floor(sandbox_id, 0);
        assert!(events.is_empty());
        // Nothing returned: floor is the newest of everything excluded, 5.
        assert_eq!(floor, 5);
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
        let platform_cursor = &bus.platform_event_bus.tail_with_floor(sandbox_id, 10).0[0]
            .event
            .cursor;
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
        let (events, floor) = bus.tail_with_floor(sandbox_id, 10);
        assert_eq!(events.len(), 5);
        assert_eq!(floor, 0, "max covered everything retained");

        // Verify order (oldest first)
        for (i, cursored) in events.iter().enumerate() {
            if let Some(sandbox_stream_event::Payload::Event(ref e)) = cursored.event.payload {
                assert_eq!(e.reason, format!("Event{i}"));
            } else {
                panic!("expected Event payload");
            }
        }

        // Tail with smaller max should return most recent events
        let (events, floor) = bus.tail_with_floor(sandbox_id, 2);
        assert_eq!(events.len(), 2);
        assert_eq!(floor, 3, "newest excluded event is Event2 (seq 3)");
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
        let (events, floor) = bus.tail_with_floor("nonexistent", 10);
        assert!(events.is_empty());
        assert_eq!(floor, 0);
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
        assert_eq!(bus.tail_with_floor(sandbox_id, 10).0.len(), 1);

        bus.remove(sandbox_id);
        assert!(bus.tail_with_floor(sandbox_id, 10).0.is_empty());
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

    /// Return buffered platform events and the coverage floor `max` leaves
    /// behind. See `tail_with_floor_impl`. Production reads go through
    /// `TracingLogBus::snapshot_tail`, which holds the cursor-space lock.
    #[cfg(test)]
    pub(crate) fn tail_with_floor(
        &self,
        sandbox_id: &str,
        max: usize,
    ) -> (Vec<CursoredEvent>, u64) {
        let inner = self.inner.lock().expect("platform event bus lock poisoned");
        inner.per_id.get(sandbox_id).map_or_else(
            || (Vec::new(), 0),
            |per| tail_with_floor_impl(&per.tail, max, u64::MAX),
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
