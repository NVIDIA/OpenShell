// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Real-time ETW → OCSF audit consumer for MXC (Plane A).
//!
//! MXC does not emit its own ETW; the events we consume are produced by the OS
//! **Sandboxing** TraceLogging provider (`{f6ec123e-…}`) as a side effect of the
//! AppContainer / `processcontainer` operations MXC drives. This module runs one
//! process-wide real-time trace session, decodes events via TDH, and (in later
//! checkpoints) attributes each to an OpenShell `sandbox_id` and emits OCSF
//! through the gateway's tracing sink (`TracingLogBus`).
//!
//! Two responsibilities are kept behind a clean internal seam so a future
//! crate-extraction is a move-file, not a rewrite:
//!   1. **capture + decode** (this module's `unsafe` TDH/ETW code) → produces a
//!      neutral [`DecodedEtwEvent`]. Knows nothing about OCSF or the registry.
//!   2. **attribute + map + emit** (the `handler` closure passed to
//!      [`start_session`]) → `DecodedEtwEvent` → registry lookup → OCSF.
//!
//! Ported from MXC's reference consumer
//! (`msft-mxc/src/tools/mxc_diagnostic_console/src/etw.rs`), trimmed to Plane A
//! (Sandboxing provider only — the Kernel-General provider needs privilege our
//! service account does not have and is not required for Plane A).
//!
//! Checkpoint 2: capture + decode only. `start_session`'s handler currently just
//! logs decoded events at `debug`. Attribution + OCSF mapping land in later
//! checkpoints, without touching the capture/decode seam below.

// This module is a thin, self-contained wrapper over the Windows ETW/TDH C API,
// which is unavoidably `unsafe`. The workspace lint `unsafe_code = "warn"` is
// allowed here (and only here) rather than annotating dozens of FFI blocks; the
// unsafe surface is confined to this file behind the safe `start_session` API.
#![allow(unsafe_code)]
// Scaffold: OCSF emit/context helpers are unused until checkpoint 3.
#![allow(dead_code)]
// The following pedantic/nursery lints are inherent to decoding raw ETW records
// against Windows structs and are allowed for this FFI module only:
//   - pointer casts over the `EVENT_TRACE_PROPERTIES` / TDH buffers (the documented
//     Win32 pattern of a `Vec<u8>` backing a header struct),
//   - width/sign casts on fixed, small size/level values,
//   - GUID/brace text in doc comments.
#![allow(
    clippy::cast_ptr_alignment,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::borrow_as_ptr,
    clippy::ptr_as_ptr,
    clippy::match_same_arms,
    clippy::redundant_pub_crate,
    clippy::doc_markdown
)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, EVENT_HEADER, EVENT_HEADER_EXTENDED_DATA_ITEM,
    EVENT_PROPERTY_INFO, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW,
    EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2, OpenTraceW,
    PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE,
    ProcessTrace, StartTraceW, TRACE_EVENT_INFO, TRACE_LEVEL_VERBOSE, TdhGetEventInformation,
    WNODE_FLAG_TRACED_GUID,
};
use windows::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};
use windows::core::{GUID, PCWSTR, PWSTR};

use openshell_ocsf::{
    ActionId, ActivityId, AppLifecycleBuilder, ConfigStateChangeBuilder, DetectionFindingBuilder,
    DispositionId, EventContext, FindingInfo, LaunchTypeId, OcsfEvent, Process,
    ProcessActivityBuilder, SecurityLevelId, SeverityId, StateId, StatusId,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// OS ProcessModel/Sandboxing TraceLogging provider — the Plane-A source.
/// `{f6ec123e-314e-400b-9e0a-151365e23083}`.
pub(crate) const SANDBOXING_PROVIDER_GUID: GUID =
    GUID::from_u128(0xf6ec123e_314e_400b_9e0a_151365e23083);

/// Stable gateway-owned prefix for real-time ETW sessions (distinct from MXC's
/// diagnostic console session). The complete name also carries the gateway PID
/// and a per-start discriminator so concurrent gateways and stale sessions never
/// share an ETW controller name.
const SESSION_NAME_PREFIX: &str = "OpenShell-MXC-ETW";

/// Separates multiple backend constructions in one process even if their clocks
/// resolve to the same instant.
static SESSION_SEQUENCE: AtomicU32 = AtomicU32::new(0);

/// The Sandboxing provider normally emits only a small group of records per
/// sandbox creation. This allows several thousand records of burst headroom
/// without permitting sustained system-wide ETW activity to grow memory without
/// bound.
const EVENT_QUEUE_CAPACITY: usize = 4096;

/// A second bound covers variable-size TraceLogging payloads. Queue accounting
/// includes owned event data, extended-data descriptors, and their copied bytes.
const EVENT_QUEUE_BYTE_CAPACITY: usize = 16 * 1024 * 1024;

/// Emit the first overload warning immediately, then coalesce additional drops
/// while the consumer remains behind.
const OVERLOAD_WARNING_INTERVAL: Duration = Duration::from_secs(30);

/// `EVENT_CONTROL_CODE_ENABLE_PROVIDER`.
const EVENT_CONTROL_CODE_ENABLE_PROVIDER: u32 = 1;

/// `TdhGetEventInformation` sizing probe returns this when asking for the buffer size.
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

// TDH InType constants for property decoding.
const TDH_INTYPE_UNICODESTRING: u16 = 1;
const TDH_INTYPE_ANSISTRING: u16 = 2;
const TDH_INTYPE_INT8: u16 = 3;
const TDH_INTYPE_UINT8: u16 = 4;
const TDH_INTYPE_INT16: u16 = 5;
const TDH_INTYPE_UINT16: u16 = 6;
const TDH_INTYPE_INT32: u16 = 7;
const TDH_INTYPE_UINT32: u16 = 8;
const TDH_INTYPE_INT64: u16 = 9;
const TDH_INTYPE_UINT64: u16 = 10;
const TDH_INTYPE_FLOAT: u16 = 11;
const TDH_INTYPE_DOUBLE: u16 = 12;
const TDH_INTYPE_BOOLEAN: u16 = 13;
const TDH_INTYPE_GUID: u16 = 15;
const TDH_INTYPE_POINTER: u16 = 16;
const TDH_INTYPE_FILETIME: u16 = 17;
const TDH_INTYPE_HEXINT32: u16 = 20;
const TDH_INTYPE_HEXINT64: u16 = 21;

// ---------------------------------------------------------------------------
// Neutral decoded event (the capture/decode → attribute/map seam)
// ---------------------------------------------------------------------------

/// TraceLogging activity opcodes we care about.
const OPCODE_START: u8 = 1;
const OPCODE_STOP: u8 = 2;

/// An owned, `Send` copy of a raw ETW event record, captured in the callback so
/// the (slow) TDH decode happens off the real-time `ProcessTrace` pump thread.
///
/// Decoding inline in the callback made the pump fall behind during the
/// sandbox-create burst, and ETW silently dropped mid-burst events into
/// `RealTimeBuffersLost`. The callback now does only cheap byte copies and hands
/// off; the consumer thread reconstructs an [`EVENT_RECORD`] over these owned
/// buffers and decodes at leisure. TraceLogging events carry their schema in the
/// extended-data items, so those are deep-copied too (not just `UserData`).
struct RawEtwEvent {
    header: EVENT_HEADER,
    user_data: Vec<u8>,
    /// Extended-data item headers (their `DataPtr` is re-pointed at `ext_bufs`
    /// before decode).
    ext_items: Vec<EVENT_HEADER_EXTENDED_DATA_ITEM>,
    /// Owned backing buffers for each extended-data item, index-aligned with
    /// `ext_items`.
    ext_bufs: Vec<Vec<u8>>,
    /// Bytes reserved against [`EVENT_QUEUE_BYTE_CAPACITY`] while this record is
    /// waiting in the channel.
    queued_bytes: usize,
}

// SAFETY: every field is `Send`: `Vec` or a POD Windows struct whose
// only address-like field (`EVENT_HEADER_EXTENDED_DATA_ITEM::DataPtr`, a `u64`)
// is re-pointed at our owned buffers on the consumer thread before use. No
// borrowed kernel pointers survive the callback, so this is sound to move
// across threads.
unsafe impl Send for RawEtwEvent {}

/// A decoded ETW event, independent of OCSF and the driver registry.
///
/// Do not derive `Debug`: properties can contain raw command-line secrets. Use
/// [`DecodedEtwEvent::summary`] for sanitized diagnostic output.
#[derive(Clone)]
pub(crate) struct DecodedEtwEvent {
    /// QPC timestamp recorded by ETW when the producer emitted the event. The
    /// session uses `ClientContext = 1`, so this is on the same clock as process
    /// registration and retirement. Callback delivery time is deliberately not
    /// used: ETW may retain a record in a per-CPU buffer across PID reuse.
    pub timestamp_qpc: i64,
    /// Provider that emitted the event.
    pub provider: GUID,
    /// TraceLogging event id.
    pub event_id: u16,
    /// Event level (1=crit … 5=verbose).
    pub level: u8,
    /// Activity opcode: 1=Start, 2=Stop, 0=Info (plain event).
    pub opcode: u8,
    /// Emitting process id.
    pub process_id: u32,
    /// ETW activity id (event header) — the cross-process/cross-event correlator
    /// for payload-keyless events like `SandboxConfig`.
    pub activity_id: GUID,
    /// Event/task name from TDH, if present.
    pub event_name: Option<String>,
    /// Top-level properties as `(name, value)`; string values keep TDH's quotes.
    pub props: Vec<(String, String)>,
}

impl DecodedEtwEvent {
    /// Raw property value (may be quoted for string types), first match wins.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.props
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Property value with surrounding double-quotes trimmed (for string types).
    pub fn get_unquoted(&self, key: &str) -> Option<String> {
        self.get(key)
            .map(|v| v.trim_matches('"').to_string())
            .filter(|s| !s.is_empty())
    }

    /// The MXC sandbox identity, if this event carries a non-empty one.
    pub fn identity(&self) -> Option<String> {
        self.get_unquoted("identity")
    }

    /// The Correlation-Vector base (`<base>.<n>` → `<base>`) from `__TlgCV__` or
    /// `correlationVector`, if present. A cross-event correlator MXC stamps on
    /// most (not all) events.
    pub fn cv_base(&self) -> Option<String> {
        self.get_unquoted("__TlgCV__")
            .or_else(|| self.get_unquoted("correlationVector"))
            .map(|cv| cv.split('.').next().unwrap_or(&cv).to_string())
            .filter(|s| !s.is_empty())
    }

    /// Compact `name { k=v, k=v }` rendering for debug logging.
    ///
    /// Sensitive property values are redacted here so every logging path,
    /// including pending-buffer eviction, is safe by construction.
    pub fn summary(&self) -> String {
        let name = self.event_name.as_deref().unwrap_or("<unnamed>");
        if self.props.is_empty() {
            format!("{name} (id={})", self.event_id)
        } else {
            let joined: Vec<String> = self
                .props
                .iter()
                .map(|(key, value)| {
                    if key.eq_ignore_ascii_case("commandLine") {
                        format!("{key}=[REDACTED]")
                    } else {
                        format!("{key}={value}")
                    }
                })
                .collect();
            format!("{name} (id={}) {{ {} }}", self.event_id, joined.join(", "))
        }
    }
}

// ---------------------------------------------------------------------------
// Session handle (RAII)
// ---------------------------------------------------------------------------

/// Health of the blocking `ProcessTrace` pump, shared between the pump thread and
/// the owning [`EtwSession`] (review #4). Previously `ProcessTrace`'s result was
/// discarded, so if capture died mid-run (e.g. the session was stopped out from
/// under us) the backend had no way to know. The pump records its outcome here so
/// an *unexpected* termination is logged at ERROR and can be queried via
/// [`EtwSession::is_capture_alive`].
#[derive(Default)]
struct CaptureHealth {
    /// Set once the pump's `ProcessTrace` has returned (capture is no longer running).
    stopped: AtomicBool,
    /// Set by [`EtwSession::stop`] *before* stopping the session, so a deliberate
    /// shutdown isn't misreported as a capture failure.
    stopping: AtomicBool,
    /// The `WIN32_ERROR` code `ProcessTrace` returned (0 == `ERROR_SUCCESS`).
    /// Only meaningful once `stopped` is set.
    exit_code: AtomicU32,
    /// Records rejected by the bounded callback queue. A non-zero value means
    /// the OCSF audit trail has a coverage gap.
    dropped_events: AtomicU64,
    /// Approximate owned bytes currently waiting in the callback queue.
    queued_bytes: AtomicUsize,
    /// Largest observed value of `queued_bytes`, retained for diagnostics.
    queue_high_water_bytes: AtomicUsize,
}

struct CallbackContext {
    tx: mpsc::SyncSender<RawEtwEvent>,
    health: Arc<CaptureHealth>,
}

#[derive(Default)]
struct OverloadReporter {
    last_reported_drops: u64,
    last_warning: Option<Instant>,
}

impl OverloadReporter {
    fn report_if_due(&mut self, health: &CaptureHealth, force: bool) -> bool {
        let dropped_events = health.dropped_events.load(Ordering::Relaxed);
        if dropped_events == self.last_reported_drops {
            return false;
        }

        let now = Instant::now();
        if !force
            && self
                .last_warning
                .is_some_and(|last| now.duration_since(last) < OVERLOAD_WARNING_INTERVAL)
        {
            return false;
        }

        let dropped_since_last_warning = dropped_events - self.last_reported_drops;
        self.last_reported_drops = dropped_events;
        self.last_warning = Some(now);
        tracing::warn!(
            target: "mxc_etw",
            dropped_events,
            dropped_since_last_warning,
            queued_bytes = health.queued_bytes.load(Ordering::Relaxed),
            queue_high_water_bytes = health.queue_high_water_bytes.load(Ordering::Relaxed),
            queue_capacity_events = EVENT_QUEUE_CAPACITY,
            queue_capacity_bytes = EVENT_QUEUE_BYTE_CAPACITY,
            "MXC ETW audit queue overloaded; events were dropped and audit coverage has a gap"
        );
        true
    }
}

/// A running real-time ETW session plus its worker threads. Dropping (or calling
/// [`EtwSession::stop`]) stops the session and joins the threads.
pub(crate) struct EtwSession {
    handle: u64,
    session_name: String,
    pump_thread: Option<JoinHandle<()>>,
    consumer_thread: Option<JoinHandle<()>>,
    health: Arc<CaptureHealth>,
}

impl EtwSession {
    /// Stop the session and join worker threads. Idempotent.
    pub fn stop(&mut self) {
        // Mark the stop as expected *before* triggering it so the pump thread's
        // `ProcessTrace` return isn't logged as an unexpected capture death.
        self.health.stopping.store(true, Ordering::SeqCst);
        if self.handle != 0 {
            stop_session(self.handle, &self.session_name);
            self.handle = 0;
        }
        // ControlTraceW(STOP) makes ProcessTrace return → the pump thread ends and
        // drops the boxed Sender → the consumer thread's recv loop sees
        // `Disconnected`, does a final pending drain, and exits.
        if let Some(t) = self.pump_thread.take() {
            let _ = t.join();
        }
        if let Some(t) = self.consumer_thread.take() {
            let _ = t.join();
        }
    }

    /// Whether the `ProcessTrace` pump is still running. Returns `false` once the
    /// pump has returned — whether from a deliberate [`stop`](Self::stop) or an
    /// unexpected termination. Exposed so the backend can surface capture health
    /// in status/diagnostics (review #4).
    pub fn is_capture_alive(&self) -> bool {
        !self.health.stopped.load(Ordering::SeqCst)
    }

    /// Number of ETW records rejected by the callback queue's count or byte limit.
    pub fn dropped_event_count(&self) -> u64 {
        self.health.dropped_events.load(Ordering::Relaxed)
    }
}

impl Drop for EtwSession {
    fn drop(&mut self) {
        self.stop();
    }
}

/// A successfully-opened real-time trace, handed to the pump thread to run the
/// blocking `ProcessTrace`. Produced by [`open_trace`] on the *caller* thread so
/// an `OpenTraceW` failure is surfaced synchronously (review #4) rather than
/// dying silently on the worker after `start_session` already returned `Ok`.
///
/// SAFETY (`Send`): the contained callback-context pointer and trace handle are
/// only ever touched by the single pump thread that takes ownership of this
/// struct; the boxed context lives until that thread reclaims it after
/// `ProcessTrace` returns, and `name` (the `LoggerName` buffer `OpenTraceW`
/// referenced) is kept alive for the whole `ProcessTrace` duration.
struct OpenedTrace {
    handle: PROCESSTRACE_HANDLE,
    name: Vec<u16>,
    callback_context: *mut CallbackContext,
}
unsafe impl Send for OpenedTrace {}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Start the real-time ETW session on the Sandboxing provider. Every decoded
/// event is attributed (via `index`) and mapped to OCSF on a dedicated consumer
/// thread. The driver seeds `index` (pid → sandbox_id) as it launches sandboxes.
///
/// Returns an [`EtwSession`] that must be kept alive; dropping it stops capture.
pub(crate) fn start_session(index: Arc<Mutex<AttributionIndex>>) -> Result<EtwSession, String> {
    let session_name = new_session_name();

    let handle = start_trace_session(&session_name)?;
    enable_provider(handle, &session_name)?;

    let health = Arc::new(CaptureHealth::default());
    let consumer_health = health.clone();
    let (tx, rx) = mpsc::sync_channel::<RawEtwEvent>(EVENT_QUEUE_CAPACITY);

    let consumer_thread = std::thread::Builder::new()
        .name("etw-ocsf-consumer".into())
        .spawn(move || {
            let mut overload_reporter = OverloadReporter::default();
            // Decode off the pump thread: the callback only copies bytes, so the
            // real-time buffers drain fast and the create burst isn't dropped.
            //
            // A *timed* recv lets us also re-drive the pending buffer during a
            // lull: an event that beat the driver's `register_launch` is replayed
            // within one tick once attribution lands, without having to wait for
            // the next ETW event (which may never arrive for a lone/last sandbox).
            loop {
                match rx.recv_timeout(Duration::from_millis(200)) {
                    Ok(mut raw) => {
                        release_queue_bytes(&consumer_health, raw.queued_bytes);
                        match decode_raw(&mut raw) {
                            Some(ev) => process_event(&index, ev),
                            None => tracing::debug!(
                                target: "mxc_etw",
                                id = raw.header.EventDescriptor.Id,
                                opcode = raw.header.EventDescriptor.Opcode,
                                pid = raw.header.ProcessId,
                                "TDH decode failed for event"
                            ),
                        }
                        drain_and_emit(&index);
                        overload_reporter.report_if_due(&consumer_health, false);
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        drain_and_emit(&index);
                        overload_reporter.report_if_due(&consumer_health, false);
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        overload_reporter.report_if_due(&consumer_health, true);
                        break;
                    }
                }
            }
            // Final drain on shutdown so anything still resolvable is emitted.
            drain_and_emit(&index);
        })
        .map_err(|e| {
            stop_session(handle, &session_name);
            format!("failed to spawn ETW consumer thread: {e}")
        })?;

    // Open the trace on THIS thread (review #4): `OpenTraceW` is a quick,
    // synchronous call, so we can return its failure to the caller instead of
    // reporting the session "started" and then having the worker die silently.
    // Only the *blocking* `ProcessTrace` runs on the pump thread. On failure we
    // reclaim the boxed callback context (which disconnects the consumer's
    // channel so it exits), stop the session, and join the consumer before
    // returning `Err`.
    let callback_context = Box::into_raw(Box::new(CallbackContext {
        tx,
        health: health.clone(),
    }));
    let opened = match open_trace(&session_name, callback_context) {
        Ok(o) => o,
        Err(e) => {
            unsafe { drop(Box::from_raw(callback_context)) };
            stop_session(handle, &session_name);
            let _ = consumer_thread.join();
            return Err(e);
        }
    };

    let pump_health = health.clone();
    let pump_thread = match std::thread::Builder::new()
        .name("etw-ocsf-pump".into())
        .spawn(move || run_trace(opened, pump_health))
    {
        Ok(t) => t,
        Err(e) => {
            // The trace is open but we couldn't spawn the pump. Stop the session,
            // reclaim the boxed callback context so the consumer disconnects,
            // and join it.
            unsafe { drop(Box::from_raw(callback_context)) };
            stop_session(handle, &session_name);
            let _ = consumer_thread.join();
            return Err(format!("failed to spawn ETW pump thread: {e}"));
        }
    };

    tracing::info!(
        session = %session_name,
        "MXC ETW→OCSF consumer started (Sandboxing provider)"
    );

    Ok(EtwSession {
        handle,
        session_name,
        pump_thread: Some(pump_thread),
        consumer_thread: Some(consumer_thread),
        health,
    })
}

// ---------------------------------------------------------------------------
// Session management
// ---------------------------------------------------------------------------

fn format_session_name(process_id: u32, started_at_nanos: u128, sequence: u32) -> String {
    format!("{SESSION_NAME_PREFIX}-{process_id}-{started_at_nanos:032x}-{sequence:08x}")
}

fn new_session_name() -> String {
    let started_at_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let sequence = SESSION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format_session_name(std::process::id(), started_at_nanos, sequence)
}

fn session_name_wide(session_name: &str) -> Vec<u16> {
    session_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect()
}

fn alloc_properties_buf(session_name: &str) -> Vec<u8> {
    let props_size = size_of::<EVENT_TRACE_PROPERTIES>();
    let name_wide_len = session_name.encode_utf16().count() + 1;
    let name_bytes = name_wide_len * 2;
    let total = props_size + name_bytes + 2;

    let mut buf = vec![0u8; total];
    let props = buf.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();
    unsafe {
        (*props).Wnode.BufferSize = total as u32;
        (*props).LoggerNameOffset = props_size as u32;
        (*props).LogFileNameOffset = (props_size + name_bytes) as u32;
    }
    buf
}

fn start_trace_session(session_name: &str) -> Result<u64, String> {
    let name = session_name_wide(session_name);
    let mut buf = alloc_properties_buf(session_name);
    let props = buf.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();

    unsafe {
        (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*props).Wnode.ClientContext = 1; // QPC timestamps
        (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        // ETW uses per-processor buffers. A short sandbox-create burst can leave
        // a low-volume buffer on one CPU unflushed until the session stops,
        // intermittently dropping mid-stream events (e.g. SandboxConfig). A 1s
        // flush timer forces every per-CPU buffer to deliver promptly; the
        // buffer sizing gives headroom for the create burst.
        (*props).BufferSize = 64; // KB per buffer
        (*props).MinimumBuffers = 8;
        (*props).MaximumBuffers = 64;
        (*props).FlushTimer = 1; // seconds
    }

    let mut handle = CONTROLTRACE_HANDLE::default();
    let status = unsafe { StartTraceW(&mut handle, PCWSTR(name.as_ptr()), props) };

    if status != WIN32_ERROR(0) {
        return Err(format!(
            "StartTraceW failed: error {} (needs 'Performance Log Users' or admin)",
            status.0
        ));
    }

    Ok(handle.Value)
}

fn enable_provider(session_handle: u64, session_name: &str) -> Result<(), String> {
    let h = CONTROLTRACE_HANDLE {
        Value: session_handle,
    };

    let status = unsafe {
        EnableTraceEx2(
            h,
            &SANDBOXING_PROVIDER_GUID,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_VERBOSE as u8,
            0xFFFF_FFFF_FFFF_FFFF, // all keywords
            0,
            0,
            None,
        )
    };

    if status != WIN32_ERROR(0) {
        stop_session(session_handle, session_name);
        return Err(format!(
            "EnableTraceEx2 (Sandboxing provider) failed: error {}",
            status.0
        ));
    }

    Ok(())
}

fn stop_session(handle: u64, session_name: &str) {
    let name = session_name_wide(session_name);
    let mut buf = alloc_properties_buf(session_name);
    let props = buf.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();
    let h = CONTROLTRACE_HANDLE { Value: handle };

    unsafe {
        let status = ControlTraceW(h, PCWSTR(name.as_ptr()), props, EVENT_TRACE_CONTROL_STOP);
        // On a successful STOP the kernel fills the properties with final session
        // stats. Surface EventsLost so lossy captures are never silent (an audit
        // trail that silently drops events is worse than one that flags gaps).
        if status == WIN32_ERROR(0) {
            // EventsLost = kernel buffer overruns; RealTimeBuffersLost/LogBuffersLost
            // = the real-time delivery queue overflowing because the consumer fell
            // behind. The latter is what a slow callback causes, so surface all
            // three — an audit trail that silently drops events is worse than one
            // that flags gaps.
            let events_lost = (*props).EventsLost;
            let rt_lost = (*props).RealTimeBuffersLost;
            let log_lost = (*props).LogBuffersLost;
            if events_lost > 0 || rt_lost > 0 || log_lost > 0 {
                tracing::warn!(
                    events_lost,
                    realtime_buffers_lost = rt_lost,
                    log_buffers_lost = log_lost,
                    session = session_name,
                    "ETW session lost events (increase buffers / speed up consumer)"
                );
            } else {
                tracing::debug!(session = session_name, "ETW session stopped; 0 events lost");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ProcessTrace loop (dedicated blocking thread)
// ---------------------------------------------------------------------------

/// Open the real-time consumer with `OpenTraceW` on the **caller** thread so the
/// result is synchronous (review #4). `callback_context` is the boxed queue
/// sender + health counters; on failure the caller reclaims it (we do not drop it
/// here). On success it and the `LoggerName` buffer are handed to the returned
/// [`OpenedTrace`] so they outlive the subsequent blocking `ProcessTrace`.
#[allow(clippy::field_reassign_with_default)]
fn open_trace(
    session_name: &str,
    callback_context: *mut CallbackContext,
) -> Result<OpenedTrace, String> {
    let mut name = session_name_wide(session_name);

    let mut logfile = EVENT_TRACE_LOGFILEW::default();
    logfile.LoggerName = PWSTR(name.as_mut_ptr());
    logfile.Anonymous1.ProcessTraceMode =
        PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.Anonymous2.EventRecordCallback = Some(event_record_callback);
    logfile.Context = callback_context.cast::<c_void>();

    let handle = unsafe { OpenTraceW(&mut logfile) };
    if handle.Value == u64::MAX {
        return Err(format!(
            "ETW OpenTraceW failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(OpenedTrace {
        handle,
        name,
        callback_context,
    })
}

/// Run the blocking `ProcessTrace` pump for an already-opened trace, then clean
/// up. Owns [`OpenedTrace`] for its whole lifetime so the `LoggerName` buffer and
/// boxed callback context stay valid until `ProcessTrace` returns.
///
/// `ProcessTrace` blocks until the session stops. A deliberate stop (via
/// [`EtwSession::stop`], which sets `health.stopping`) is normal; any *other*
/// return means capture died and is recorded + logged at ERROR (review #4) so it
/// isn't silently discarded.
fn run_trace(opened: OpenedTrace, health: Arc<CaptureHealth>) {
    let OpenedTrace {
        handle,
        name,
        callback_context,
    } = opened;

    let status = unsafe { ProcessTrace(&[handle], None, None) };

    // Record the outcome before any cleanup so a health query never races a
    // still-"alive" state after the pump has actually returned.
    health.exit_code.store(status.0, Ordering::SeqCst);
    health.stopped.store(true, Ordering::SeqCst);

    let expected = health.stopping.load(Ordering::SeqCst);
    if !expected {
        // The session went away without anyone asking it to (e.g. an external
        // `logman stop`, a provider error, or a dropped trace). Surface it — the
        // OCSF audit trail is now blind until the driver is restarted.
        tracing::error!(
            target: "mxc_etw",
            code = status.0,
            "ETW ProcessTrace terminated unexpectedly; MXC OCSF capture is no longer running"
        );
    } else {
        tracing::debug!(target: "mxc_etw", code = status.0, "ETW ProcessTrace returned after stop");
    }

    unsafe {
        let _ = CloseTrace(handle);
        drop(Box::from_raw(callback_context));
    }
    // Keep the LoggerName buffer alive until ProcessTrace has fully returned.
    drop(name);
}

unsafe extern "system" fn event_record_callback(event_record: *mut EVENT_RECORD) {
    let event = unsafe { &*event_record };
    // Hot path — keep it minimal (decode runs on the consumer thread). We only
    // enabled the Sandboxing provider, but guard anyway.
    if event.EventHeader.ProviderId != SANDBOXING_PROVIDER_GUID {
        return;
    }
    // Hot path: reserve bounded queue memory, copy raw bytes, then use a
    // non-blocking send. No TDH decode or logging runs here. Overload is counted
    // atomically and reported by the consumer thread so ETW's pump never waits
    // for decoding, disk, or tracing sinks.
    let context = unsafe { &*(event.UserContext as *const CallbackContext) };
    let Some(queued_bytes) = (unsafe { raw_event_queued_bytes(event_record) }) else {
        record_queue_drop(&context.health);
        return;
    };
    if !try_reserve_queue_bytes(&context.health, queued_bytes) {
        record_queue_drop(&context.health);
        return;
    }
    let raw = unsafe { copy_raw(event_record, queued_bytes) };
    try_enqueue_raw(context, raw);
}

/// Approximate the owned memory that [`copy_raw`] will allocate, including the
/// event wrapper, vector storage, and copied ETW payloads. `None` means integer
/// overflow; callers reject that event without allocating it.
unsafe fn raw_event_queued_bytes(event_record: *const EVENT_RECORD) -> Option<usize> {
    let event = unsafe { &*event_record };
    let ext_count = event.ExtendedDataCount as usize;
    let ext_item_bytes = ext_count.checked_mul(size_of::<EVENT_HEADER_EXTENDED_DATA_ITEM>())?;
    let ext_vec_bytes = ext_count.checked_mul(size_of::<Vec<u8>>())?;
    let user_data_bytes = if event.UserData.is_null() {
        0
    } else {
        event.UserDataLength as usize
    };

    let mut bytes = size_of::<RawEtwEvent>()
        .checked_add(ext_item_bytes)?
        .checked_add(ext_vec_bytes)?
        .checked_add(user_data_bytes)?;

    if !event.ExtendedData.is_null() {
        for index in 0..ext_count {
            let item = unsafe { &*event.ExtendedData.add(index) };
            if item.DataPtr != 0 {
                bytes = bytes.checked_add(item.DataSize as usize)?;
            }
        }
    }
    Some(bytes)
}

fn try_reserve_queue_bytes(health: &CaptureHealth, event_bytes: usize) -> bool {
    if event_bytes > EVENT_QUEUE_BYTE_CAPACITY {
        return false;
    }

    match health
        .queued_bytes
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |queued| {
            queued
                .checked_add(event_bytes)
                .filter(|total| *total <= EVENT_QUEUE_BYTE_CAPACITY)
        }) {
        Ok(previous) => {
            health
                .queue_high_water_bytes
                .fetch_max(previous + event_bytes, Ordering::Relaxed);
            true
        }
        Err(_) => false,
    }
}

fn release_queue_bytes(health: &CaptureHealth, event_bytes: usize) {
    let previous = health
        .queued_bytes
        .fetch_sub(event_bytes, Ordering::Relaxed);
    debug_assert!(
        previous >= event_bytes,
        "ETW queue byte accounting underflow"
    );
}

fn record_queue_drop(health: &CaptureHealth) {
    health.dropped_events.fetch_add(1, Ordering::Relaxed);
}

fn try_enqueue_raw(context: &CallbackContext, raw: RawEtwEvent) -> bool {
    match context.tx.try_send(raw) {
        Ok(()) => true,
        Err(mpsc::TrySendError::Full(raw) | mpsc::TrySendError::Disconnected(raw)) => {
            release_queue_bytes(&context.health, raw.queued_bytes);
            record_queue_drop(&context.health);
            false
        }
    }
}

/// Deep-copy a kernel `EVENT_RECORD` into an owned, `Send` [`RawEtwEvent`].
/// Runs in the ETW callback, so it does the minimum: byte copies, no decode.
unsafe fn copy_raw(event_record: *const EVENT_RECORD, queued_bytes: usize) -> RawEtwEvent {
    let ev = unsafe { &*event_record };
    let header = ev.EventHeader;

    let ulen = ev.UserDataLength as usize;
    let user_data = if ev.UserData.is_null() || ulen == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(ev.UserData.cast::<u8>(), ulen) }.to_vec()
    };

    let ext_count = ev.ExtendedDataCount as usize;
    let mut ext_items = Vec::with_capacity(ext_count);
    let mut ext_bufs = Vec::with_capacity(ext_count);
    if !ev.ExtendedData.is_null() {
        for i in 0..ext_count {
            let item = unsafe { *ev.ExtendedData.add(i) };
            let dsize = item.DataSize as usize;
            let buf = if item.DataPtr == 0 || dsize == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(item.DataPtr as *const u8, dsize) }.to_vec()
            };
            ext_items.push(item);
            ext_bufs.push(buf);
        }
    }

    RawEtwEvent {
        header,
        user_data,
        ext_items,
        ext_bufs,
        queued_bytes,
    }
}

/// Reconstruct an [`EVENT_RECORD`] over the owned buffers and TDH-decode it.
/// Runs on the consumer thread (off the real-time pump).
#[allow(clippy::field_reassign_with_default)]
fn decode_raw(raw: &mut RawEtwEvent) -> Option<DecodedEtwEvent> {
    // Re-point each extended-data item at our owned copy (TraceLogging schema
    // lives here, so TDH must be able to read it).
    for (item, buf) in raw.ext_items.iter_mut().zip(raw.ext_bufs.iter()) {
        item.DataPtr = if buf.is_empty() {
            0
        } else {
            buf.as_ptr() as u64
        };
    }

    let mut rec = EVENT_RECORD::default();
    rec.EventHeader = raw.header;
    rec.UserDataLength = u16::try_from(raw.user_data.len()).unwrap_or(u16::MAX);
    rec.UserData = if raw.user_data.is_empty() {
        std::ptr::null_mut()
    } else {
        raw.user_data.as_ptr() as *mut c_void
    };
    rec.ExtendedDataCount = u16::try_from(raw.ext_items.len()).unwrap_or(u16::MAX);
    rec.ExtendedData = if raw.ext_items.is_empty() {
        std::ptr::null_mut()
    } else {
        raw.ext_items.as_mut_ptr()
    };

    decode_event(std::ptr::addr_of_mut!(rec))
}

// ---------------------------------------------------------------------------
// Event decoding (TDH)
// ---------------------------------------------------------------------------

/// Decode a raw event record into a neutral [`DecodedEtwEvent`] via TDH.
/// Returns `None` only when TDH decoding fails entirely.
fn decode_event(event_record: *mut EVENT_RECORD) -> Option<DecodedEtwEvent> {
    let mut buf_size: u32 = 0;
    let status = unsafe { TdhGetEventInformation(event_record, None, None, &mut buf_size) };
    if status != ERROR_INSUFFICIENT_BUFFER {
        return None;
    }

    let mut buffer = vec![0u8; buf_size as usize];
    let info_ptr = buffer.as_mut_ptr().cast::<TRACE_EVENT_INFO>();
    let status =
        unsafe { TdhGetEventInformation(event_record, None, Some(info_ptr), &mut buf_size) };
    if status != 0 {
        return None;
    }

    let info = unsafe { &*info_ptr };

    let event_name_offset = unsafe { info.Anonymous1.EventNameOffset };
    let event_name = wide_str_at(&buffer, event_name_offset)
        .or_else(|| wide_str_at(&buffer, info.TaskNameOffset))
        .filter(|s| !s.is_empty());

    let header = unsafe { &(*event_record).EventHeader };
    let props = decode_properties(&buffer, info, event_record);

    Some(DecodedEtwEvent {
        timestamp_qpc: header.TimeStamp,
        provider: header.ProviderId,
        event_id: header.EventDescriptor.Id,
        level: header.EventDescriptor.Level,
        opcode: header.EventDescriptor.Opcode,
        process_id: header.ProcessId,
        activity_id: header.ActivityId,
        event_name,
        props,
    })
}

fn decode_properties(
    info_buf: &[u8],
    info: &TRACE_EVENT_INFO,
    event_record: *mut EVENT_RECORD,
) -> Vec<(String, String)> {
    let event = unsafe { &*event_record };
    let user_data = event.UserData as *const u8;
    let user_data_len = event.UserDataLength as usize;

    if user_data.is_null() || user_data_len == 0 {
        return Vec::new();
    }

    let prop_count = info.TopLevelPropertyCount as usize;
    let mut results = Vec::with_capacity(prop_count);
    let mut offset: usize = 0;

    for i in 0..prop_count {
        let prop_info = unsafe {
            let base =
                std::ptr::addr_of!(info.EventPropertyInfoArray) as *const EVENT_PROPERTY_INFO;
            &*base.add(i)
        };

        let prop_name =
            wide_str_at(info_buf, prop_info.NameOffset).unwrap_or_else(|| format!("prop{i}"));

        // PropertyStruct flag: the header holds no data, but its child members
        // occupy space in the user-data buffer, so decode+skip each to keep
        // `offset` in sync.
        if prop_info.Flags.0 & 1 != 0 {
            let num_members =
                unsafe { prop_info.Anonymous1.structType.NumOfStructMembers } as usize;
            let start_index = unsafe { prop_info.Anonymous1.structType.StructStartIndex } as usize;

            for j in 0..num_members {
                let child_prop = unsafe {
                    let base = std::ptr::addr_of!(info.EventPropertyInfoArray)
                        as *const EVENT_PROPERTY_INFO;
                    &*base.add(start_index + j)
                };
                let child_in_type = unsafe { child_prop.Anonymous1.nonStructType.InType };
                let child_length = unsafe { child_prop.Anonymous3.length } as usize;
                let remaining = user_data_len.saturating_sub(offset);
                let data_ptr = if remaining > 0 {
                    unsafe { user_data.add(offset) }
                } else {
                    std::ptr::null()
                };
                let (_, consumed) =
                    format_property_value(child_in_type, child_length, data_ptr, remaining);
                offset += consumed;
            }

            results.push((prop_name, "<struct>".to_string()));
            continue;
        }

        let in_type = unsafe { prop_info.Anonymous1.nonStructType.InType };
        let prop_length = unsafe { prop_info.Anonymous3.length } as usize;

        let remaining = user_data_len.saturating_sub(offset);
        let data_ptr = if remaining > 0 {
            unsafe { user_data.add(offset) }
        } else {
            std::ptr::null()
        };

        let (value_str, consumed) =
            format_property_value(in_type, prop_length, data_ptr, remaining);
        offset += consumed;
        results.push((prop_name, value_str));
    }

    results
}

/// Decode a single property value, returning `(rendered, bytes_consumed)`.
fn format_property_value(
    in_type: u16,
    declared_length: usize,
    data: *const u8,
    available: usize,
) -> (String, usize) {
    if data.is_null() || available == 0 {
        return ("<no data>".to_string(), 0);
    }

    match in_type {
        TDH_INTYPE_UNICODESTRING => {
            let max_wchars = available / 2;
            let wchars = unsafe { std::slice::from_raw_parts(data.cast::<u16>(), max_wchars) };
            let len = wchars.iter().position(|&c| c == 0).unwrap_or(max_wchars);
            let s = String::from_utf16_lossy(&wchars[..len]);
            let consumed = (len + 1).min(max_wchars) * 2;
            (format!("\"{s}\""), consumed)
        }
        TDH_INTYPE_ANSISTRING => {
            let bytes = unsafe { std::slice::from_raw_parts(data, available) };
            let len = bytes.iter().position(|&b| b == 0).unwrap_or(available);
            let s = String::from_utf8_lossy(&bytes[..len]);
            let consumed = (len + 1).min(available);
            (format!("\"{s}\""), consumed)
        }
        TDH_INTYPE_INT8 if available >= 1 => ((unsafe { *data } as i8).to_string(), 1),
        TDH_INTYPE_UINT8 if available >= 1 => ((unsafe { *data }).to_string(), 1),
        TDH_INTYPE_INT16 if available >= 2 => {
            (i16::from_le_bytes(read_bytes::<2>(data)).to_string(), 2)
        }
        TDH_INTYPE_UINT16 if available >= 2 => {
            (u16::from_le_bytes(read_bytes::<2>(data)).to_string(), 2)
        }
        TDH_INTYPE_INT32 if available >= 4 => {
            (i32::from_le_bytes(read_bytes::<4>(data)).to_string(), 4)
        }
        TDH_INTYPE_UINT32 if available >= 4 => {
            (u32::from_le_bytes(read_bytes::<4>(data)).to_string(), 4)
        }
        TDH_INTYPE_INT64 if available >= 8 => {
            (i64::from_le_bytes(read_bytes::<8>(data)).to_string(), 8)
        }
        TDH_INTYPE_UINT64 if available >= 8 => {
            (u64::from_le_bytes(read_bytes::<8>(data)).to_string(), 8)
        }
        TDH_INTYPE_FLOAT if available >= 4 => (
            format!("{:.4}", f32::from_le_bytes(read_bytes::<4>(data))),
            4,
        ),
        TDH_INTYPE_DOUBLE if available >= 8 => (
            format!("{:.4}", f64::from_le_bytes(read_bytes::<8>(data))),
            8,
        ),
        TDH_INTYPE_BOOLEAN if available >= 4 => (
            (i32::from_le_bytes(read_bytes::<4>(data)) != 0).to_string(),
            4,
        ),
        TDH_INTYPE_GUID if available >= 16 => {
            let b = unsafe { std::slice::from_raw_parts(data, 16) };
            let d1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            let d2 = u16::from_le_bytes([b[4], b[5]]);
            let d3 = u16::from_le_bytes([b[6], b[7]]);
            let s = format!(
                "{{{d1:08x}-{d2:04x}-{d3:04x}-{:02x}{:02x}-\
                 {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
                b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
            );
            (s, 16)
        }
        TDH_INTYPE_HEXINT32 if available >= 4 => (
            format!("0x{:08X}", u32::from_le_bytes(read_bytes::<4>(data))),
            4,
        ),
        TDH_INTYPE_HEXINT64 if available >= 8 => (
            format!("0x{:016X}", u64::from_le_bytes(read_bytes::<8>(data))),
            8,
        ),
        TDH_INTYPE_POINTER if available >= 8 => (
            format!("0x{:016X}", u64::from_le_bytes(read_bytes::<8>(data))),
            8,
        ),
        TDH_INTYPE_FILETIME if available >= 8 => (
            format!(
                "FILETIME(0x{:016X})",
                u64::from_le_bytes(read_bytes::<8>(data))
            ),
            8,
        ),
        _ => {
            let len = if declared_length > 0 {
                declared_length.min(available)
            } else {
                available.min(32)
            };
            let bytes = unsafe { std::slice::from_raw_parts(data, len) };
            let hex: String = bytes
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(" ");
            (hex, len)
        }
    }
}

// ---------------------------------------------------------------------------
// Attribution: MXC ETW event → OpenShell sandbox_id
// ---------------------------------------------------------------------------

/// Runtime index that maps MXC's uneven ETW correlators back to an OpenShell
/// `sandbox_id`. Shared (`Arc<Mutex<_>>`) between the driver (which seeds
/// `pid → sandbox_id` as it spawns wxc-exec) and the ETW consumer thread.
///
/// Attribution chain (grounded in the live `Sandboxing` capture):
/// - **pid anchor** — the wxc-exec pid we spawn is unique and driver-owned; it
///   emits `CreateProcessInSandbox`, which also carries `identity` + CV.
/// - from there we learn `identity → sandbox_id` and (`SandboxEngineCreate`)
///   `activity_id → sandbox_id`, so the payload-keyless `SandboxConfig`
///   (no identity/CV) resolves via the ETW `ActivityId` it shares.
/// - command text never establishes ownership, and the PID anchor is retired as
///   soon as the monitored `wxc-exec` child exits.
/// An ETW event that could not yet be attributed, held so it can be replayed
/// once its sandbox's attribution is seeded.
struct PendingEvent {
    at: Instant,
    ev: DecodedEtwEvent,
}

/// Max number of unattributed events buffered at once (memory bound). The
/// create/config burst is ~10 events per sandbox, so this comfortably holds
/// many concurrent racing launches while still capping worst-case memory.
const PENDING_MAX: usize = 4096;

/// How long an unattributed event is held before being given up on. The
/// driver seeds attribution within milliseconds of spawning `wxc-exec`, so a
/// few seconds is ample; anything older is almost certainly genuinely
/// unattributable (e.g. an unrelated Sandboxing-provider consumer on the box).
const PENDING_TTL: Duration = Duration::from_secs(5);

/// Grace window for trusting a PID match for an event captured just before the
/// driver's initial registration.
/// The driver seeds `by_pid` within milliseconds of spawning `wxc-exec`, so a
/// legitimate seed event's registration lands at (or just after) the moment the
/// event was captured. A recycled PID, by contrast, requires the prior
/// `wxc-exec` to exit and a new one to spawn — far longer than this window — so
/// a registration that is newer than the captured event by more than this grace
/// is treated as a *different* (recycled) owner and the PID match is refused.
const PRE_REGISTRATION_PID_GRACE: Duration = Duration::from_secs(2);

/// Keep already-established strong correlations briefly after `wxc-exec` exits
/// so ETW records that were in flight can still be attributed. The consumer's
/// periodic pending drain prunes them after the same horizon used for late event
/// replay.
const RETIRED_CORRELATION_TTL: Duration = PENDING_TTL;

fn qpc_now() -> i64 {
    let mut value = 0;
    // QPC is available on every supported Windows version. If the call ever
    // fails, zero fails closed for generation matching instead of borrowing a
    // wall clock that is incompatible with ETW's configured timestamp source.
    let _ = unsafe { QueryPerformanceCounter(&mut value) };
    value
}

fn duration_qpc_ticks(duration: Duration) -> i64 {
    let mut frequency = 0;
    if unsafe { QueryPerformanceFrequency(&mut frequency) }.is_err() || frequency <= 0 {
        return 0;
    }
    let ticks = duration.as_nanos().saturating_mul(frequency as u128) / 1_000_000_000;
    i64::try_from(ticks).unwrap_or(i64::MAX)
}

/// A `wxc-exec` PID registration: which sandbox owns the PID and *when* it was
/// registered. The timestamp lets every resolution path reject a record that
/// was captured under an older generation of a recycled PID.
struct PidReg {
    sid: String,
    started_qpc: i64,
    /// Whether an event captured just before this registration may use the PID.
    /// A recently retired or reassigned PID makes that race ambiguous, so only
    /// its strong identity/activity/CV correlators remain eligible for
    /// resolution.
    allow_pre_registration_capture: bool,
}

struct RetiredPidReg {
    registration: PidReg,
    ended_qpc: i64,
    retired_at: Instant,
}

#[derive(Default)]
pub(crate) struct AttributionIndex {
    by_pid: HashMap<u32, PidReg>,
    by_identity: HashMap<String, String>,
    by_activity: HashMap<String, String>,
    by_cv: HashMap<String, String>,
    /// Sandboxes whose driver-owned `wxc-exec` process has exited. Their strong
    /// correlations remain authoritative only until the recorded instant plus
    /// [`RETIRED_CORRELATION_TTL`].
    retired_sandboxes: HashMap<String, Instant>,
    /// Recently retired PID generations. Their producer-time lifetime lets
    /// records delivered after process exit resolve to the correct sandbox and
    /// prevents those records from binding to a recycled PID's new owner.
    retired_pids: HashMap<u32, VecDeque<RetiredPidReg>>,
    names: HashMap<String, String>,
    /// Sandboxes for which a lifecycle [6002] row has already been emitted, so
    /// the two redundant create events don't double-count.
    lifecycle_emitted: HashSet<String>,
    /// Events that arrived before their sandbox's attribution was seeded. ETW
    /// delivers the create/config burst the instant `wxc-exec` starts, which can
    /// race the driver's `register_launch`; rather than drop those events we hold
    /// them here and replay when a later registration/cross-link resolves them.
    /// Bounded by [`PENDING_MAX`] and [`PENDING_TTL`].
    pending: VecDeque<PendingEvent>,
}

impl AttributionIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a launched sandbox. `wxc_pid` (the process we spawned) is the
    /// only initial authority anchor and remains authoritative only while that
    /// process is alive. Events resolved through it establish the strong
    /// identity/activity/CV correlations used for the rest of the create burst.
    pub fn register_launch(&mut self, sandbox_id: &str, sandbox_name: &str, wxc_pid: u32) {
        let now = Instant::now();
        let now_qpc = qpc_now();
        self.purge_expired_retirements(now);
        let previous = self.by_pid.remove(&wxc_pid);
        let allow_pre_registration_capture =
            previous.is_none() && !self.retired_pids.contains_key(&wxc_pid);

        // PID-reuse guard: if this PID still maps to a *different* sandbox, the
        // prior process exited without its monitor retiring the registration.
        // Its actual end is unknown, so do not synthesize a retired lifetime at
        // `now_qpc`: that would make a new process's pre-registration events look
        // as though they belonged to the old sandbox. Established strong
        // correlations remain available for the normal late-event horizon, but
        // PID-only events across this ambiguous generation gap fail closed.
        if let Some(previous) = previous {
            if previous.sid != sandbox_id {
                tracing::warn!(
                    target: "mxc_etw",
                    pid = wxc_pid,
                    prev = %previous.sid,
                    new = %sandbox_id,
                    "wxc-exec PID reused before prior sandbox was forgotten; rebinding attribution"
                );
                self.retired_sandboxes
                    .entry(previous.sid.clone())
                    .or_insert(now);
            } else {
                // Duplicate registration of the same live launch is idempotent.
                self.by_pid.insert(wxc_pid, previous);
                self.names
                    .insert(sandbox_id.to_string(), sandbox_name.to_string());
                return;
            }
        }
        self.by_pid.insert(
            wxc_pid,
            PidReg {
                sid: sandbox_id.to_string(),
                started_qpc: now_qpc,
                allow_pre_registration_capture,
            },
        );
        self.retired_sandboxes.remove(sandbox_id);

        self.names
            .insert(sandbox_id.to_string(), sandbox_name.to_string());
    }

    /// Retire a driver-owned PID after its monitored child exits. The exact
    /// sandbox match prevents a delayed monitor from removing a recycled PID's
    /// newer registration. Strong correlations and the bounded historical PID
    /// lifetime remain for a short late-event window so records still buffered
    /// inside ETW can be attributed after the process exits.
    pub fn retire_launch(&mut self, sandbox_id: &str, wxc_pid: u32) {
        let matches_owner = self
            .by_pid
            .get(&wxc_pid)
            .is_some_and(|registration| registration.sid == sandbox_id);
        if !matches_owner {
            return;
        }

        let now = Instant::now();
        let registration = self
            .by_pid
            .remove(&wxc_pid)
            .expect("owner match requires a live registration");
        self.retired_pids
            .entry(wxc_pid)
            .or_default()
            .push_back(RetiredPidReg {
                registration,
                ended_qpc: qpc_now(),
                retired_at: now,
            });
        if !self
            .by_pid
            .values()
            .any(|registration| registration.sid == sandbox_id)
        {
            self.retired_sandboxes.insert(sandbox_id.to_string(), now);
        }
    }

    #[cfg(test)]
    pub fn has_live_pid_for_sandbox(&self, sandbox_id: &str) -> bool {
        self.by_pid
            .values()
            .any(|registration| registration.sid == sandbox_id)
    }

    /// Drop all keys for a finished sandbox to bound memory.
    pub fn forget(&mut self, sandbox_id: &str) {
        let now = Instant::now();
        let retired_pids = self
            .by_pid
            .iter()
            .filter_map(|(pid, registration)| (registration.sid == sandbox_id).then_some(*pid))
            .collect::<Vec<_>>();
        for pid in retired_pids {
            if let Some(registration) = self.by_pid.remove(&pid) {
                self.retired_pids
                    .entry(pid)
                    .or_default()
                    .push_back(RetiredPidReg {
                        registration,
                        ended_qpc: qpc_now(),
                        retired_at: now,
                    });
            }
        }
        self.by_identity.retain(|_, v| v != sandbox_id);
        self.by_activity.retain(|_, v| v != sandbox_id);
        self.by_cv.retain(|_, v| v != sandbox_id);
        self.retired_sandboxes.remove(sandbox_id);
        self.names.remove(sandbox_id);
        self.lifecycle_emitted.remove(sandbox_id);
    }

    fn purge_expired_retirements(&mut self, now: Instant) {
        self.retired_pids.retain(|_, generations| {
            generations.retain(|generation| {
                now.checked_duration_since(generation.retired_at)
                    .is_none_or(|age| age < PENDING_TTL)
            });
            !generations.is_empty()
        });

        let expired_sandboxes = self
            .retired_sandboxes
            .iter()
            .filter_map(|(sandbox_id, retired_at)| {
                now.checked_duration_since(*retired_at)
                    .is_some_and(|age| age >= RETIRED_CORRELATION_TTL)
                    .then(|| sandbox_id.clone())
            })
            .collect::<HashSet<_>>();
        if expired_sandboxes.is_empty() {
            return;
        }

        self.by_identity
            .retain(|_, sid| !expired_sandboxes.contains(sid));
        self.by_activity
            .retain(|_, sid| !expired_sandboxes.contains(sid));
        self.by_cv.retain(|_, sid| !expired_sandboxes.contains(sid));
        self.retired_sandboxes
            .retain(|sid, _| !expired_sandboxes.contains(sid));
    }

    /// Returns `true` the first time a lifecycle row should be emitted for this
    /// sandbox. MXC emits two redundant create events (`SandboxEngineCreate` and
    /// `SandboxCreateWithPolicyEnforcement`) and ETW drops them interchangeably
    /// under load, so we anchor on whichever arrives first and dedupe here.
    fn take_lifecycle_once(&mut self, sandbox_id: &str) -> bool {
        self.lifecycle_emitted.insert(sandbox_id.to_string())
    }

    fn name_of(&self, sandbox_id: &str) -> String {
        self.names
            .get(sandbox_id)
            .cloned()
            .unwrap_or_else(|| sandbox_id.to_string())
    }

    /// Resolve an event to a `sandbox_id` via any known key, then cross-link the
    /// other keys it carries so later keyless events attribute correctly.
    ///
    /// Strong per-sandbox correlators take precedence over PID. A PID match uses
    /// ETW's producer timestamp against current and recently-retired process
    /// lifetimes. This rule applies before and after pending-buffer replay.
    fn resolve(&mut self, ev: &DecodedEtwEvent) -> Option<String> {
        self.resolve_at(ev, qpc_now())
    }

    fn resolve_at(&mut self, ev: &DecodedEtwEvent, now_qpc: i64) -> Option<String> {
        self.purge_expired_retirements(Instant::now());
        let identity = ev.identity();
        let cv = ev.cv_base();
        let activity = guid_key(&ev.activity_id);

        let sid = identity
            .as_ref()
            .and_then(|i| self.by_identity.get(i).cloned())
            .or_else(|| {
                activity
                    .as_ref()
                    .and_then(|a| self.by_activity.get(a).cloned())
            })
            .or_else(|| cv.as_ref().and_then(|c| self.by_cv.get(c).cloned()))
            .or_else(|| {
                self.retired_pids
                    .get(&ev.process_id)
                    .and_then(|generations| {
                        generations.iter().rev().find_map(|generation| {
                            let start = if generation.registration.allow_pre_registration_capture {
                                generation
                                    .registration
                                    .started_qpc
                                    .saturating_sub(duration_qpc_ticks(PRE_REGISTRATION_PID_GRACE))
                            } else {
                                generation.registration.started_qpc
                            };
                            (ev.timestamp_qpc >= start && ev.timestamp_qpc <= generation.ended_qpc)
                                .then(|| generation.registration.sid.clone())
                        })
                    })
            })
            .or_else(|| {
                self.by_pid.get(&ev.process_id).and_then(|r| {
                    // A PID is the only seed available before strong ETW keys
                    // are learned. Hold PID-only events long enough for the
                    // driver's registration to expose a reuse boundary; without
                    // this delay an event from a newly reused PID could resolve
                    // through the stale live owner before that owner is displaced.
                    let grace_ticks = duration_qpc_ticks(PRE_REGISTRATION_PID_GRACE);
                    let pid_evidence_mature =
                        grace_ticks > 0 && now_qpc.saturating_sub(ev.timestamp_qpc) >= grace_ticks;
                    if !pid_evidence_mature {
                        return None;
                    }
                    let captured_during_registration = ev.timestamp_qpc >= r.started_qpc;
                    let captured_during_seed_race = r.allow_pre_registration_capture
                        && r.started_qpc.saturating_sub(ev.timestamp_qpc)
                            <= duration_qpc_ticks(PRE_REGISTRATION_PID_GRACE);
                    if captured_during_registration || captured_during_seed_race {
                        Some(r.sid.clone())
                    } else {
                        None
                    }
                })
            })?;

        self.cross_link(&sid, identity, cv, activity);
        Some(sid)
    }

    /// Cross-link the strong keys an event carries to its resolved `sandbox_id`
    /// so later keyless events for the same sandbox attribute correctly.
    fn cross_link(
        &mut self,
        sid: &str,
        identity: Option<String>,
        cv: Option<String>,
        activity: Option<String>,
    ) {
        if let Some(i) = identity {
            self.by_identity.entry(i).or_insert_with(|| sid.to_string());
        }
        if let Some(c) = cv {
            self.by_cv.entry(c).or_insert_with(|| sid.to_string());
        }
        if let Some(a) = activity {
            self.by_activity.entry(a).or_insert_with(|| sid.to_string());
        }
    }

    /// Hold an event that didn't resolve yet, evicting expired and (if needed)
    /// oldest entries first so the buffer stays bounded.
    fn buffer_unresolved(&mut self, ev: DecodedEtwEvent) {
        let now = Instant::now();
        while let Some(front) = self.pending.front() {
            if now.duration_since(front.at) > PENDING_TTL {
                let stale = self.pending.pop_front();
                if let Some(p) = stale {
                    tracing::debug!(target: "mxc_etw", pid = p.ev.process_id, "dropping unattributed (aged out) {}", p.ev.summary());
                }
            } else {
                break;
            }
        }
        if self.pending.len() >= PENDING_MAX {
            if let Some(p) = self.pending.pop_front() {
                tracing::debug!(target: "mxc_etw", pid = p.ev.process_id, "dropping unattributed (buffer full) {}", p.ev.summary());
            }
        }
        self.pending.push_back(PendingEvent { at: now, ev });
    }

    /// Re-resolve buffered events. Returns those that now attribute (removed
    /// from the buffer, in arrival order, ready to emit) and drops any that have
    /// aged past [`PENDING_TTL`] still unresolved. Callers emit the returned
    /// events *after* releasing the index lock.
    fn drain_resolved(&mut self) -> Vec<(String, String, DecodedEtwEvent)> {
        self.drain_resolved_at(Instant::now(), qpc_now())
    }

    fn drain_resolved_at(
        &mut self,
        now: Instant,
        now_qpc: i64,
    ) -> Vec<(String, String, DecodedEtwEvent)> {
        self.purge_expired_retirements(now);
        if self.pending.is_empty() {
            return Vec::new();
        }
        let drained = std::mem::take(&mut self.pending);
        let mut ready = Vec::new();
        let mut keep = VecDeque::with_capacity(drained.len());
        for p in drained {
            if now.duration_since(p.at) > PENDING_TTL {
                tracing::debug!(target: "mxc_etw", pid = p.ev.process_id, "dropping unattributed (aged out) {}", p.ev.summary());
                continue;
            }
            match self.resolve_at(&p.ev, now_qpc) {
                Some(sid) => {
                    let name = self.name_of(&sid);
                    ready.push((sid, name, p.ev));
                }
                None => keep.push_back(p),
            }
        }
        self.pending = keep;
        ready
    }
}

/// Consumer-thread entry point: attribute one decoded event and, for the mapped
/// classes, emit an OCSF row into the gateway trail. Unmapped/unresolved events
/// are debug-logged (checkpoint-2 behaviour) so nothing is silently dropped.
fn process_event(index: &Mutex<AttributionIndex>, ev: DecodedEtwEvent) {
    // Activity STOP is the empty twin of START — never a distinct OCSF row.
    if ev.opcode == OPCODE_STOP {
        return;
    }

    let resolved = {
        let mut idx = index
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match idx.resolve(&ev) {
            Some(sid) => {
                let name = idx.name_of(&sid);
                Some((sid, name, ev))
            }
            None => {
                // Not attributable yet: ETW delivers the create/config burst the
                // instant `wxc-exec` starts, which can beat the driver's
                // `register_launch`. Hold the event for replay instead of dropping
                // it (see `drain_and_emit`).
                idx.buffer_unresolved(ev);
                None
            }
        }
    };

    if let Some((sandbox_id, sandbox_name, ev)) = resolved {
        emit_resolved(index, &sandbox_id, &sandbox_name, &ev);
    }
}

/// Re-resolve and emit any buffered events that have since become attributable.
/// Called by the consumer thread after each incoming event and on a periodic
/// tick, so a create/config burst that raced `register_launch` still lands in
/// the trail (and aged-out unresolvable events are dropped, bounded).
fn drain_and_emit(index: &Mutex<AttributionIndex>) {
    let ready = {
        let mut idx = index
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        idx.drain_resolved()
    };
    for (sandbox_id, sandbox_name, ev) in ready {
        emit_resolved(index, &sandbox_id, &sandbox_name, &ev);
    }
}

/// Map one attributed event to its OCSF class and emit it into the gateway trail.
fn emit_resolved(
    index: &Mutex<AttributionIndex>,
    sandbox_id: &str,
    sandbox_name: &str,
    ev: &DecodedEtwEvent,
) {
    // STOP twins are already filtered before buffering, so activity events
    // reaching here are STARTs.
    match ev.event_name.as_deref().unwrap_or("") {
        // Lifecycle [6002]: MXC emits two create events per sandbox —
        // `SandboxEngineCreate` and `SandboxCreateWithPolicyEnforcement` — and
        // ETW drops them interchangeably under buffer pressure (observed: one run
        // keeps the former, the next keeps the latter). Anchor on whichever
        // arrives first and dedupe so the row is emitted exactly once.
        "SandboxEngineCreate" | "SandboxCreateWithPolicyEnforcement"
            if ev.opcode == OPCODE_START =>
        {
            let first = index
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take_lifecycle_once(sandbox_id);
            if first {
                let ctx = etw_ctx(sandbox_id, sandbox_name);
                emit_ocsf(sandbox_id, map_lifecycle_create(&ctx, sandbox_name));
            }
        }
        // Process [1007]: `CreateProcessInSandbox` carries the real agent command
        // line + working directory. The activity fires once empty (probe) and
        // once with the command. Emit only the populated event, and map the
        // command to a safe executable identity rather than durable arguments.
        "CreateProcessInSandbox" if ev.opcode == OPCODE_START => {
            if let Some(cmd) = ev.get_unquoted("commandLine") {
                let ctx = etw_ctx(sandbox_id, sandbox_name);
                emit_ocsf(sandbox_id, map_process_launch(&ctx, ev, &cmd));
            } else {
                tracing::debug!(target: "mxc_etw", pid = ev.process_id, sandbox_id = %sandbox_id, "{}", ev.summary());
            }
        }
        // Process [1007]: `ProcessLaunched` is the confirmation twin of
        // `CreateProcessInSandbox` — it carries the *actual* `processId`/`threadId`
        // of the started in-sandbox process (the create event only has the request +
        // command line). We emit it as a distinct PROC row so the trail records both
        // the launch request (with executable identity) and confirmed start (with pid).
        "ProcessLaunched" => {
            let ctx = etw_ctx(sandbox_id, sandbox_name);
            emit_ocsf(sandbox_id, map_process_started(&ctx, ev));
        }
        // Config [5019]: several distinct config/hardening/setup state changes. Each
        // is a genuine audit-worthy config event; `SandboxConfig` is the richest but
        // drops intermittently, so the reliably-captured hardening events
        // (`Win32kLockdownApplied`, `ApplyUILimits`, `EnforceOsPolicy`) guarantee
        // coverage. `SandboxProxyConfigured` (network/proxy setup — the one
        // network-plane event the provider emits) and `SandboxConsoleReferencePlumbed`
        // (console-handle plumbing) are additional per-sandbox setup state changes.
        "SandboxConfig"
        | "Win32kLockdownApplied"
        | "ApplyUILimits"
        | "EnforceOsPolicy"
        | "SandboxProxyConfigured"
        | "SandboxConsoleReferencePlumbed" => {
            // Dump the raw decoded field set for config-family events at debug so we
            // can confirm the exact property names MXC emits (e.g. which key carries
            // the proxy port on `SandboxProxyConfigured`). Guarded by `debug=true`.
            tracing::debug!(target: "mxc_etw", pid = ev.process_id, sandbox_id = %sandbox_id, "{}", ev.summary());
            let ctx = etw_ctx(sandbox_id, sandbox_name);
            emit_ocsf(sandbox_id, map_config_state(&ctx, ev));
        }
        // Finding [2004]: MXC surfaces WIL error/fallback activities during
        // sandbox setup. Captured as informational (non-alert) findings so the
        // audit trail records setup anomalies without crying wolf.
        "ActivityError" | "FallbackError" => {
            let ctx = etw_ctx(sandbox_id, sandbox_name);
            emit_ocsf(sandbox_id, map_finding(&ctx, ev));
        }
        _ => {
            tracing::debug!(target: "mxc_etw", pid = ev.process_id, sandbox_id = %sandbox_id, "{}", ev.summary());
        }
    }
}

// ---------------------------------------------------------------------------
// OCSF mappers (checkpoint 3 subset: LIFECYCLE + CONFIG)
// ---------------------------------------------------------------------------

/// `SandboxCreateWithPolicyEnforcement` (START) → Application Lifecycle [6002].
fn map_lifecycle_create(ctx: &EventContext, sandbox_name: &str) -> OcsfEvent {
    AppLifecycleBuilder::new(ctx)
        .activity(ActivityId::Reset) // lifecycle label = "Start"
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .message(format!(
            "MXC sandbox '{sandbox_name}' created with policy enforcement"
        ))
        .build()
}

/// A sandbox config/hardening/setup ETW event → Device Config State Change [5019].
///
/// Handles the full family of per-sandbox config state changes the Sandboxing
/// provider emits: `SandboxConfig` (full posture snapshot), the hardening events
/// (`Win32kLockdownApplied`, `ApplyUILimits`, `EnforceOsPolicy`),
/// `SandboxProxyConfigured` (network/proxy setup) and
/// `SandboxConsoleReferencePlumbed` (console-handle plumbing). Whichever
/// config-ish fields the event carries ride along as `unmapped`, and
/// `security_level` reflects any hardening signal present.
fn map_config_state(ctx: &EventContext, ev: &DecodedEtwEvent) -> OcsfEvent {
    let flag = |k: &str| ev.get(k).map(|v| v == "1").unwrap_or(false);
    let nonzero = |k: &str| ev.get(k).map(|v| v != "0").unwrap_or(false);
    let hardened = flag("useLeastPrivilege") || flag("useAppContainer") || nonzero("agenticFlags");
    let security_level = if hardened {
        SecurityLevelId::Secure
    } else {
        SecurityLevelId::Unknown
    };

    let message = match ev.event_name.as_deref().unwrap_or("") {
        "Win32kLockdownApplied" => "MXC sandbox win32k lockdown applied".to_string(),
        "ApplyUILimits" => "MXC sandbox UI restrictions applied".to_string(),
        "EnforceOsPolicy" => "MXC sandbox OS policy enforced".to_string(),
        "SandboxConsoleReferencePlumbed" => "MXC sandbox console reference plumbed".to_string(),
        // The one network-plane event the provider emits. Empirically the OS
        // Sandboxing provider fires this event *only* when an egress proxy is
        // configured for the sandbox, but it does **not** surface the port for
        // MXC's URL-based proxy — `proxyPort` is always 0 (MXC redirects egress via
        // a `network.proxy.localhost` policy URL, not the OS built-in proxy-port
        // mechanism this field reflects). The real per-sandbox listening port is
        // recorded on the host proxy's own Network Activity [4001] "Listen" event.
        // So the presence of this event means a proxy WAS configured; only append a
        // port on the off chance a future provider/build populates it.
        "SandboxProxyConfigured" => match ev.get_unquoted("proxyPort").as_deref() {
            Some(port) if port != "0" => {
                format!("MXC sandbox proxy configured (port {port})")
            }
            _ => "MXC sandbox proxy configured".to_string(),
        },
        _ => "MXC sandbox OS policy configured".to_string(),
    };

    let mut builder = ConfigStateChangeBuilder::new(ctx)
        .state(StateId::Enabled, "configured")
        .security_level(security_level)
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .message(message);

    // Superset of config-ish fields across all event shapes; only present
    // fields are attached.
    for key in [
        "useAppContainer",
        "integrityMode",
        "integrityLevel",
        "uiRestrictions",
        "useLeastPrivilege",
        "readWritePathsCount",
        "readOnlyPathsCount",
        "capabilities",
        "agenticFlags",
        "processId",
        "proxyPort",
        "hasConsoleReference",
        "creationFlags",
    ] {
        if let Some(v) = ev.get(key) {
            builder = builder.unmapped(key, v.trim_matches('"').to_string());
        }
    }

    builder.build()
}

/// `CreateProcessInSandbox` (populated) → Process Activity [1007] "Launch".
///
/// Command arguments are intentionally omitted from both `process.cmd_line` and
/// the message because legitimate arguments may contain credentials, signed URLs,
/// or PII. The executable basename provides a useful, bounded audit identity
/// without copying the raw ETW command line into durable or streamed logs.
fn map_process_launch(ctx: &EventContext, ev: &DecodedEtwEvent, cmd_line: &str) -> OcsfEvent {
    // The created process's own pid isn't in this event (it appears later in
    // `ProcessLaunched`); the emitting pid is the sandbox host (wxc-exec).
    let executable = exe_name(cmd_line);
    let proc = Process::new(&executable, 0);
    let cwd = ev.get_unquoted("currentDirectory").unwrap_or_default();
    let cwd_suffix = if cwd.is_empty() {
        String::new()
    } else {
        format!(" (cwd: {cwd})")
    };
    ProcessActivityBuilder::new(ctx)
        .activity(ActivityId::Open) // process label = "Launch"
        .launch_type(LaunchTypeId::Spawn)
        .action(ActionId::Allowed)
        .disposition(DispositionId::Allowed)
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .process(proc)
        .actor_process(Process::new("wxc-exec", i64::from(ev.process_id)))
        .message(format!(
            "MXC sandbox launched process: {executable}{cwd_suffix}"
        ))
        .build()
}

/// `ProcessLaunched` → Process Activity [1007] "Launch" (confirmed start).
///
/// Unlike `CreateProcessInSandbox` (the request, which carries the command line
/// but not the resulting pid), this event carries the real `processId`/`threadId`
/// of the process that actually started. We give the process a distinct name
/// (`sandboxed-process`) so the shorthand row is visibly the confirmed-start twin,
/// not a duplicate of the launch-request row.
fn map_process_started(ctx: &EventContext, ev: &DecodedEtwEvent) -> OcsfEvent {
    let pid = ev
        .get("processId")
        .map(|v| v.trim_matches('"'))
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0);
    let tid = ev.get_unquoted("threadId").unwrap_or_default();
    let tid_suffix = if tid.is_empty() {
        String::new()
    } else {
        format!(", tid: {tid}")
    };
    ProcessActivityBuilder::new(ctx)
        .activity(ActivityId::Open) // process label = "Launch"
        .launch_type(LaunchTypeId::Spawn)
        .action(ActionId::Allowed)
        .disposition(DispositionId::Allowed)
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .process(Process::new("sandboxed-process", pid))
        .actor_process(Process::new("wxc-exec", i64::from(ev.process_id)))
        .message(format!(
            "MXC sandbox process started (pid: {pid}{tid_suffix})"
        ))
        .build()
}

/// `ActivityError` / `FallbackError` → Detection Finding [2004] (informational).
fn map_finding(ctx: &EventContext, ev: &DecodedEtwEvent) -> OcsfEvent {
    let kind = ev.event_name.as_deref().unwrap_or("SandboxError");
    let uid = ev
        .cv_base()
        .map(|cv| format!("{kind}:{cv}"))
        .unwrap_or_else(|| format!("{kind}:{}", ev.process_id));
    DetectionFindingBuilder::new(ctx)
        .activity(ActivityId::Open) // finding label = "Create"
        .severity(SeverityId::Informational)
        .is_alert(false)
        .finding_info(
            FindingInfo::new(&uid, &format!("MXC sandbox {kind}"))
                .with_desc("MXC emitted a WIL error/fallback activity during sandbox setup."),
        )
        .message(format!("MXC reported {kind} during sandbox setup"))
        .build()
}

/// Best-effort executable name from a command line: first whitespace-delimited
/// token, stripped of any directory prefix and surrounding quotes.
fn exe_name(cmd_line: &str) -> String {
    let first = cmd_line
        .trim()
        .split_whitespace()
        .next()
        .unwrap_or("process")
        .trim_matches('"');
    first
        .rsplit(['\\', '/'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("process")
        .to_string()
}

// ---------------------------------------------------------------------------
// OCSF emit helpers
// ---------------------------------------------------------------------------

/// Emit an OCSF event so it lands in BOTH gateway output planes from one
/// tracing event:
/// - the **routing bus** (`TracingLogBus`) picks up the `sandbox_id` + `message`
///   fields → stdout shorthand + per-sandbox gRPC stream, and
/// - the **JSONL audit layer** (`OcsfJsonlLayer`, installed in
///   `openshell-server`'s subscriber) picks up the full structured `OcsfEvent`
///   from the thread-local bridge → durable `openshell-ocsf.<date>.log`.
///
/// Before cp6 this fired a bare `tracing::info!` that never populated the
/// bridge, so the structured event was silently dropped and no JSONL was
/// written. `emit_ocsf_event_routed` does both jobs from a single dispatch.
fn emit_ocsf(sandbox_id: &str, event: OcsfEvent) {
    openshell_ocsf::emit_ocsf_event_routed(sandbox_id, event);
}

/// The gateway host's machine name, resolved once. This becomes `device.hostname`
/// in every emitted OCSF event, so the audit trail attributes activity to the
/// real box (e.g. `7F203-MXC-001`) rather than a static placeholder. `COMPUTERNAME`
/// is always set on Windows; we fall back to a sentinel only if it is somehow empty.
fn gateway_hostname() -> &'static str {
    static HOSTNAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HOSTNAME.get_or_init(|| {
        std::env::var("COMPUTERNAME")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "openshell-gateway".to_string())
    })
}

/// Build a per-event OCSF context (not the process-wide `ctx()` singleton, since
/// one gateway process hosts many sandboxes — wrinkle #1).
fn etw_ctx(sandbox_id: &str, sandbox_name: &str) -> EventContext {
    EventContext {
        sandbox_id: sandbox_id.to_string(),
        sandbox_name: sandbox_name.to_string(),
        container_image: "mxc/appcontainer".to_string(),
        hostname: gateway_hostname().to_string(),
        product_version: env!("CARGO_PKG_VERSION").to_string(),
        proxy_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        proxy_port: 0,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Stable string key for an ETW `ActivityId` GUID, or `None` for the all-zero
/// GUID (which means "no activity" and must never be used as a correlation key).
fn guid_key(g: &GUID) -> Option<String> {
    if g.data1 == 0 && g.data2 == 0 && g.data3 == 0 && g.data4 == [0u8; 8] {
        return None;
    }
    let tail: String = g.data4.iter().map(|b| format!("{b:02x}")).collect();
    Some(format!(
        "{:08x}-{:04x}-{:04x}-{tail}",
        g.data1, g.data2, g.data3
    ))
}

fn read_bytes<const N: usize>(ptr: *const u8) -> [u8; N] {
    let mut out = [0u8; N];
    unsafe {
        std::ptr::copy_nonoverlapping(ptr, out.as_mut_ptr(), N);
    }
    out
}

fn wide_str_at(buf: &[u8], offset: u32) -> Option<String> {
    let off = offset as usize;
    if off == 0 || off >= buf.len() {
        return None;
    }

    let remaining = &buf[off..];
    let max_wchars = remaining.len() / 2;
    if max_wchars == 0 {
        return None;
    }

    let wchars =
        unsafe { std::slice::from_raw_parts(remaining.as_ptr().cast::<u16>(), max_wchars) };
    let len = wchars.iter().position(|&c| c == 0).unwrap_or(max_wchars);
    if len == 0 {
        return None;
    }

    Some(String::from_utf16_lossy(&wchars[..len]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_raw_event(queued_bytes: usize) -> RawEtwEvent {
        RawEtwEvent {
            header: EVENT_HEADER::default(),
            user_data: Vec::new(),
            ext_items: Vec::new(),
            ext_bufs: Vec::new(),
            queued_bytes,
        }
    }

    #[test]
    fn stalled_consumer_keeps_callback_queue_bounded_and_counts_drops() {
        const EXTRA_EVENTS: usize = 17;
        let health = Arc::new(CaptureHealth::default());
        let (tx, _stalled_rx) = mpsc::sync_channel(EVENT_QUEUE_CAPACITY);
        let context = CallbackContext {
            tx,
            health: health.clone(),
        };
        let event_bytes = size_of::<RawEtwEvent>();

        for attempt in 0..(EVENT_QUEUE_CAPACITY + EXTRA_EVENTS) {
            assert!(try_reserve_queue_bytes(&health, event_bytes));
            let accepted = try_enqueue_raw(&context, empty_raw_event(event_bytes));
            assert_eq!(accepted, attempt < EVENT_QUEUE_CAPACITY);
        }

        assert_eq!(
            health.dropped_events.load(Ordering::Relaxed),
            EXTRA_EVENTS as u64
        );
        assert_eq!(
            health.queued_bytes.load(Ordering::Relaxed),
            EVENT_QUEUE_CAPACITY * event_bytes
        );
        assert!(health.queue_high_water_bytes.load(Ordering::Relaxed) <= EVENT_QUEUE_BYTE_CAPACITY);
    }

    #[test]
    fn event_larger_than_queue_byte_budget_is_rejected_before_copy() {
        let health = CaptureHealth::default();

        assert!(!try_reserve_queue_bytes(
            &health,
            EVENT_QUEUE_BYTE_CAPACITY + 1
        ));
        assert_eq!(health.queued_bytes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn overload_reporter_warns_immediately_then_rate_limits() {
        let health = CaptureHealth::default();
        let mut reporter = OverloadReporter::default();

        assert!(!reporter.report_if_due(&health, false));
        health.dropped_events.store(2, Ordering::Relaxed);
        assert!(reporter.report_if_due(&health, false));
        health.dropped_events.store(3, Ordering::Relaxed);
        assert!(!reporter.report_if_due(&health, false));
        assert!(reporter.report_if_due(&health, true));
        assert_eq!(reporter.last_reported_drops, 3);
    }

    #[test]
    fn gateway_processes_and_restarts_use_distinct_session_names() {
        let first_gateway = format_session_name(1001, 0x1111, 0);
        let second_gateway = format_session_name(1002, 0x1111, 0);
        let restarted_gateway = format_session_name(1001, 0x2222, 0);

        assert!(first_gateway.starts_with("OpenShell-MXC-ETW-1001-"));
        assert_ne!(first_gateway, second_gateway);
        assert_ne!(first_gateway, restarted_gateway);
        assert_eq!(
            first_gateway,
            format_session_name(1001, 0x1111, 0),
            "the controller and consumer must derive the same session name"
        );
    }

    fn mk_event(pid: u32, name: &str) -> DecodedEtwEvent {
        DecodedEtwEvent {
            timestamp_qpc: qpc_now(),
            provider: GUID::from_u128(0),
            event_id: 1,
            level: 4,
            opcode: OPCODE_START,
            process_id: pid,
            activity_id: GUID::from_u128(0),
            event_name: Some(name.to_string()),
            props: Vec::new(),
        }
    }

    fn resolve_after_pid_grace(idx: &mut AttributionIndex, ev: &DecodedEtwEvent) -> Option<String> {
        idx.resolve_at(
            ev,
            ev.timestamp_qpc
                .saturating_add(duration_qpc_ticks(PRE_REGISTRATION_PID_GRACE))
                .saturating_add(1),
        )
    }

    fn drain_after_pid_grace(idx: &mut AttributionIndex) -> Vec<(String, String, DecodedEtwEvent)> {
        idx.drain_resolved_at(
            Instant::now() + PRE_REGISTRATION_PID_GRACE,
            qpc_now()
                .saturating_add(duration_qpc_ticks(PRE_REGISTRATION_PID_GRACE))
                .saturating_add(1),
        )
    }

    #[test]
    fn process_launch_omits_command_arguments_from_audit_output() {
        const SECRET: &str = "secret-value";
        let ctx = etw_ctx("sbx-secret-test", "secret-test");
        let mut ev = mk_event(4242, "CreateProcessInSandbox");
        ev.props
            .push(("currentDirectory".into(), r#""C:\work\openshell""#.into()));

        let event = map_process_launch(&ctx, &ev, &format!("tool --token {SECRET}"));
        let json = serde_json::to_string(&event).expect("process event should serialize");
        let shorthand = event.format_shorthand();

        assert!(!json.contains(SECRET), "serialized OCSF leaked an argument");
        assert!(
            !shorthand.contains(SECRET),
            "OCSF shorthand leaked an argument"
        );
        let OcsfEvent::ProcessActivity(process_event) = event else {
            panic!("expected Process Activity event");
        };
        assert_eq!(process_event.process.name, "tool");
        assert!(process_event.process.cmd_line.is_none());
        assert_eq!(
            process_event.base.message.as_deref(),
            Some("MXC sandbox launched process: tool (cwd: C:\\work\\openshell)")
        );
    }

    #[test]
    fn decoded_event_summary_redacts_command_line() {
        const SECRET: &str = "secret-value";
        let mut ev = mk_event(4242, "CreateProcessInSandbox");
        ev.props.extend([
            ("commandLine".into(), format!(r#""tool --token {SECRET}""#)),
            ("currentDirectory".into(), r#""C:\work\openshell""#.into()),
        ]);

        let summary = ev.summary();

        assert!(
            !summary.contains(SECRET),
            "debug summary leaked an argument"
        );
        assert!(summary.contains("commandLine=[REDACTED]"));
        assert!(summary.contains(r#"currentDirectory="C:\work\openshell""#));
    }

    // Shailendra #2: the create/config burst can reach the consumer before the
    // driver's `register_launch` seeds attribution. An event that doesn't resolve
    // must be held and replayed once attribution lands — not dropped.
    #[test]
    fn buffered_event_replays_after_registration() {
        let mut idx = AttributionIndex::new();
        let ev = mk_event(1234, "SandboxConfig");

        // Arrives before registration → unresolved → buffered, not dropped.
        assert!(idx.resolve(&ev).is_none());
        idx.buffer_unresolved(ev);
        assert!(
            idx.drain_resolved().is_empty(),
            "nothing to drain pre-registration"
        );

        // Driver seeds attribution for the wxc-exec pid we spawned.
        idx.register_launch("sbx-1", "my-sandbox", 1234);

        // The buffered event now attributes and is returned for emit, in order.
        let ready = drain_after_pid_grace(&mut idx);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].0, "sbx-1");
        assert_eq!(ready[0].1, "my-sandbox");
        assert_eq!(ready[0].2.process_id, 1234);

        // And it's removed from the buffer (no double emit).
        assert!(idx.drain_resolved().is_empty());
    }

    // Genuinely unattributable events (e.g. from unrelated Sandboxing activity)
    // must never grow the buffer without bound.
    #[test]
    fn pending_buffer_is_bounded() {
        let mut idx = AttributionIndex::new();
        for pid in 0..(PENDING_MAX as u32 + 50) {
            idx.buffer_unresolved(mk_event(pid, "SandboxConfig"));
        }
        assert!(
            idx.pending.len() <= PENDING_MAX,
            "buffer exceeded PENDING_MAX"
        );
    }

    // A buffered event that resolves via a cross-linked correlator (not just the
    // pid) is also replayed: register one pid, then an event sharing only the
    // activity id resolves after the first event cross-links it.
    #[test]
    fn buffered_event_replays_via_crosslink() {
        let mut idx = AttributionIndex::new();
        idx.register_launch("sbx-9", "s9", 4321);

        // First event carries the pid + an activity id → resolves and cross-links
        // the activity id to sbx-9.
        let mut anchor = mk_event(4321, "CreateProcessInSandbox");
        anchor.activity_id = GUID::from_u128(0xABCD);
        assert_eq!(
            resolve_after_pid_grace(&mut idx, &anchor).as_deref(),
            Some("sbx-9")
        );

        // A later payload-keyless event shares only the activity id (different
        // pid) — it must now resolve via the cross-link.
        let mut keyless = mk_event(0, "SandboxConfig");
        keyless.activity_id = GUID::from_u128(0xABCD);
        assert_eq!(idx.resolve(&keyless).as_deref(), Some("sbx-9"));
    }

    // Shailendra #1 (PID reuse): if a sandbox leaked (no `forget`) and Windows
    // recycles its wxc-exec PID for a new sandbox, mature events on that PID must
    // route to the new owner, never the dead one.
    #[test]
    fn pid_reuse_rebinds_to_new_sandbox() {
        let mut idx = AttributionIndex::new();
        idx.register_launch("sbx-A", "A", 1000);
        let ev_a = mk_event(1000, "CreateProcessInSandbox");
        assert_eq!(
            resolve_after_pid_grace(&mut idx, &ev_a).as_deref(),
            Some("sbx-A")
        );

        // A leaks (delete never ran). PID 1000 is recycled for B.
        idx.register_launch("sbx-B", "B", 1000);
        idx.retire_launch("sbx-A", 1000);
        let ev_b = mk_event(1000, "CreateProcessInSandbox");
        assert_eq!(
            resolve_after_pid_grace(&mut idx, &ev_b).as_deref(),
            Some("sbx-B")
        );
    }

    #[test]
    fn displaced_live_pid_does_not_claim_new_pre_registration_event() {
        let mut idx = AttributionIndex::new();
        idx.register_launch("sbx-old", "old", 1000);

        // Windows has reused PID 1000, but the new launch registration has not
        // reached the consumer yet. The stale live owner must not immediately
        // claim the event or learn its new generation's strong identity.
        let mut queued_new = mk_event(1000, "SandboxConfig");
        queued_new
            .props
            .push(("identity".into(), "new-generation".into()));
        assert!(idx.resolve(&queued_new).is_none());
        idx.buffer_unresolved(queued_new.clone());

        idx.register_launch("sbx-new", "new", 1000);

        assert!(drain_after_pid_grace(&mut idx).is_empty());
        let mut same_identity = mk_event(0, "SandboxConfig");
        same_identity
            .props
            .push(("identity".into(), "new-generation".into()));
        assert!(
            idx.resolve(&same_identity).is_none(),
            "an ambiguous pre-registration event must not seed old-sandbox strong keys"
        );
    }

    #[test]
    fn displaced_live_pid_does_not_reassign_delayed_old_event_to_new_owner() {
        let mut idx = AttributionIndex::new();
        idx.register_launch("sbx-old", "old", 1000);
        let queued_old = mk_event(1000, "SandboxConfig");

        // The old monitor has not recorded an exact retirement boundary before
        // Windows reuses the PID. Neither side may claim records from the
        // resulting ambiguous interval using PID evidence alone.
        idx.register_launch("sbx-new", "new", 1000);
        assert!(
            resolve_after_pid_grace(&mut idx, &queued_old).is_none(),
            "a delayed old-generation event must not bind to the new owner"
        );

        let fresh_new = mk_event(1000, "SandboxConfig");
        assert_eq!(
            resolve_after_pid_grace(&mut idx, &fresh_new).as_deref(),
            Some("sbx-new")
        );
    }

    // Command text is user-controlled and may match unrelated host activity, so
    // it must never establish sandbox ownership even when currently unique.
    #[test]
    fn command_line_is_never_used_for_resolution() {
        let mut idx = AttributionIndex::new();
        idx.register_launch("sbx-1", "s1", 11);

        // An unrelated provider event carrying the exact workload command but no
        // driver-owned PID or strong correlator must remain unattributed.
        let mut only_cmd = mk_event(999, "SandboxConfig");
        only_cmd
            .props
            .push(("commandLine".into(), "\"agent --run\"".into()));
        assert!(idx.resolve(&only_cmd).is_none());
    }

    #[test]
    fn retired_pid_is_not_used_before_sandbox_deletion() {
        let mut idx = AttributionIndex::new();
        idx.register_launch("sbx-1", "s1", 11);

        let anchor = mk_event(11, "CreateProcessInSandbox");
        assert_eq!(
            resolve_after_pid_grace(&mut idx, &anchor).as_deref(),
            Some("sbx-1")
        );
        idx.retire_launch("sbx-1", 11);

        let mut stale = mk_event(11, "SandboxConfig");
        stale
            .props
            .push(("commandLine".into(), "\"agent --run\"".into()));
        assert!(
            idx.resolve(&stale).is_none(),
            "a completed wxc-exec PID and matching command text must not confer ownership"
        );
    }

    #[test]
    fn retired_strong_correlations_expire_after_late_event_window() {
        let mut idx = AttributionIndex::new();
        idx.register_launch("sbx-1", "s1", 11);

        let mut anchor = mk_event(11, "CreateProcessInSandbox");
        anchor.activity_id = GUID::from_u128(0xABCD);
        assert_eq!(
            resolve_after_pid_grace(&mut idx, &anchor).as_deref(),
            Some("sbx-1")
        );
        idx.retire_launch("sbx-1", 11);

        let mut late = mk_event(999, "SandboxConfig");
        late.activity_id = anchor.activity_id;
        assert_eq!(
            idx.resolve(&late).as_deref(),
            Some("sbx-1"),
            "an established strong correlator should cover in-flight ETW records"
        );

        idx.retired_sandboxes.insert(
            "sbx-1".into(),
            Instant::now() - RETIRED_CORRELATION_TTL - Duration::from_millis(1),
        );
        assert!(
            idx.resolve(&late).is_none(),
            "strong correlators must stop conferring ownership after the late-event window"
        );
    }

    // A record whose only key is a PID must not bind to a registration that
    // appeared well after capture. Refusing it beats misattributing it.
    #[test]
    fn pid_match_refused_when_capture_predates_registration_beyond_grace() {
        let mut idx = AttributionIndex::new();
        let mut ev = mk_event(1000, "CreateProcessInSandbox");
        ev.timestamp_qpc = qpc_now() - duration_qpc_ticks(Duration::from_secs(3));

        idx.register_launch("sbx-new", "new", 1000);

        assert!(
            idx.resolve(&ev).is_none(),
            "stale PID-only record must not bind to a newer registration"
        );
    }

    #[test]
    fn producer_timestamp_routes_delayed_record_to_original_pid_generation() {
        let mut idx = AttributionIndex::new();
        idx.register_launch("sbx-old", "old", 1000);
        // The producer emits this record while the old PID generation is live,
        // but ETW delays callback delivery until after process exit and reuse.
        let queued_old = mk_event(1000, "CreateProcessInSandbox");
        idx.retire_launch("sbx-old", 1000);
        idx.register_launch("sbx-new", "new", 1000);

        assert_eq!(
            idx.resolve(&queued_old).as_deref(),
            Some("sbx-old"),
            "a delayed record must resolve through its producer-time PID generation"
        );

        let fresh = mk_event(1000, "CreateProcessInSandbox");
        assert_eq!(
            resolve_after_pid_grace(&mut idx, &fresh).as_deref(),
            Some("sbx-new"),
            "a record captured during the new registration remains authoritative"
        );
    }

    #[test]
    fn short_lived_process_keeps_attribution_until_etw_flushes() {
        let mut idx = AttributionIndex::new();
        idx.register_launch("sbx-short", "short", 2000);
        let emitted_before_exit = mk_event(2000, "SandboxConfig");

        // The process exits before ETW's one-second flush timer delivers the
        // record to our callback.
        idx.retire_launch("sbx-short", 2000);

        assert_eq!(
            idx.resolve(&emitted_before_exit).as_deref(),
            Some("sbx-short"),
            "process exit must not discard attribution for ETW-buffered records"
        );
    }

    // The legitimate seed race is preserved: an event captured immediately
    // before the driver seeds attribution still resolves via its PID.
    #[test]
    fn pre_registration_pid_match_is_accepted_within_grace() {
        let mut idx = AttributionIndex::new();
        let ev = mk_event(1000, "CreateProcessInSandbox");
        idx.register_launch("sbx-1", "s1", 1000);
        assert_eq!(
            resolve_after_pid_grace(&mut idx, &ev).as_deref(),
            Some("sbx-1"),
            "a seed event captured at registration time must still resolve"
        );
    }

    // Command text is not an authority key for pre-registration records either.
    #[test]
    fn command_line_is_not_used_for_pre_registration_resolution() {
        let mut idx = AttributionIndex::new();
        idx.register_launch("sbx-1", "s1", 11);

        let mut only_cmd = mk_event(999, "SandboxConfig");
        only_cmd
            .props
            .push(("commandLine".into(), "\"agent --unique\"".into()));

        assert!(idx.resolve(&only_cmd).is_none());
    }
}
