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

use std::collections::{HashMap, VecDeque};
use std::ffi::c_void;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, EVENT_HEADER, EVENT_HEADER_EXTENDED_DATA_ITEM,
    EVENT_PROPERTY_INFO, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW,
    EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2, OpenTraceW,
    PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, ProcessTrace, StartTraceW,
    TRACE_EVENT_INFO, TRACE_LEVEL_VERBOSE, TdhGetEventInformation, WNODE_FLAG_TRACED_GUID,
};
use windows::core::{GUID, PCWSTR, PWSTR};

use openshell_ocsf::{
    ActionId, ActivityId, AppLifecycleBuilder, ConfigStateChangeBuilder, DetectionFindingBuilder,
    DispositionId, FindingInfo, LaunchTypeId, OcsfEvent, Process, ProcessActivityBuilder,
    SandboxContext, SecurityLevelId, SeverityId, StateId, StatusId,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// OS ProcessModel/Sandboxing TraceLogging provider — the Plane-A source.
/// `{f6ec123e-314e-400b-9e0a-151365e23083}`.
pub(crate) const SANDBOXING_PROVIDER_GUID: GUID =
    GUID::from_u128(0xf6ec123e_314e_400b_9e0a_151365e23083);

/// Our real-time session name (distinct from MXC's diagnostic console session).
const SESSION_NAME: &str = "OpenShell-MXC-ETW";

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
}

// SAFETY: every field is either a `Vec` or a POD Windows struct whose only
// address-like field (`EVENT_HEADER_EXTENDED_DATA_ITEM::DataPtr`, a `u64`) is
// re-pointed at our owned buffers on the consumer thread before use. No borrowed
// kernel pointers survive the callback, so this is sound to move across threads.
unsafe impl Send for RawEtwEvent {}

/// A decoded ETW event, independent of OCSF and the driver registry.
#[derive(Debug, Clone)]
pub(crate) struct DecodedEtwEvent {
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
    pub fn summary(&self) -> String {
        let name = self.event_name.as_deref().unwrap_or("<unnamed>");
        if self.props.is_empty() {
            format!("{name} (id={})", self.event_id)
        } else {
            let joined: Vec<String> = self.props.iter().map(|(k, v)| format!("{k}={v}")).collect();
            format!("{name} (id={}) {{ {} }}", self.event_id, joined.join(", "))
        }
    }
}

// ---------------------------------------------------------------------------
// Session handle (RAII)
// ---------------------------------------------------------------------------

/// A running real-time ETW session plus its worker threads. Dropping (or calling
/// [`EtwSession::stop`]) stops the session and joins the threads.
pub(crate) struct EtwSession {
    handle: u64,
    pump_thread: Option<JoinHandle<()>>,
    consumer_thread: Option<JoinHandle<()>>,
}

impl EtwSession {
    /// Stop the session and join worker threads. Idempotent.
    pub fn stop(&mut self) {
        if self.handle != 0 {
            stop_session(self.handle);
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
}

impl Drop for EtwSession {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Wrapper to move a raw `Sender` pointer across the thread boundary into the
/// blocking `ProcessTrace` worker. SAFETY: the boxed `Sender` lives until the
/// worker reclaims it after `ProcessTrace` returns.
struct SendPtr(*mut mpsc::Sender<RawEtwEvent>);
unsafe impl Send for SendPtr {}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Start the real-time ETW session on the Sandboxing provider. Every decoded
/// event is attributed (via `index`) and mapped to OCSF on a dedicated consumer
/// thread. The driver seeds `index` (pid → sandbox_id) as it launches sandboxes.
///
/// Returns an [`EtwSession`] that must be kept alive; dropping it stops capture.
pub(crate) fn start_session(index: Arc<Mutex<AttributionIndex>>) -> Result<EtwSession, String> {
    cleanup_stale_session();

    let handle = start_trace_session()?;
    enable_provider(handle)?;

    let (tx, rx) = mpsc::channel::<RawEtwEvent>();

    let consumer_thread = std::thread::Builder::new()
        .name("etw-ocsf-consumer".into())
        .spawn(move || {
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
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => drain_and_emit(&index),
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
            // Final drain on shutdown so anything still resolvable is emitted.
            drain_and_emit(&index);
        })
        .map_err(|e| {
            stop_session(handle);
            format!("failed to spawn ETW consumer thread: {e}")
        })?;

    let send_ptr = SendPtr(Box::into_raw(Box::new(tx)));
    let pump_thread = std::thread::Builder::new()
        .name("etw-ocsf-pump".into())
        .spawn(move || process_trace_loop(send_ptr))
        .map_err(|e| {
            stop_session(handle);
            format!("failed to spawn ETW pump thread: {e}")
        })?;

    tracing::info!(
        session = SESSION_NAME,
        "MXC ETW→OCSF consumer started (Sandboxing provider)"
    );

    Ok(EtwSession {
        handle,
        pump_thread: Some(pump_thread),
        consumer_thread: Some(consumer_thread),
    })
}

// ---------------------------------------------------------------------------
// Session management
// ---------------------------------------------------------------------------

fn session_name_wide() -> Vec<u16> {
    SESSION_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect()
}

fn alloc_properties_buf() -> Vec<u8> {
    let props_size = size_of::<EVENT_TRACE_PROPERTIES>();
    let name_wide_len = SESSION_NAME.encode_utf16().count() + 1;
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

fn start_trace_session() -> Result<u64, String> {
    let name = session_name_wide();
    let mut buf = alloc_properties_buf();
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

fn enable_provider(session_handle: u64) -> Result<(), String> {
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
        stop_session(session_handle);
        return Err(format!(
            "EnableTraceEx2 (Sandboxing provider) failed: error {}",
            status.0
        ));
    }

    Ok(())
}

fn stop_session(handle: u64) {
    let name = session_name_wide();
    let mut buf = alloc_properties_buf();
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
                    session = SESSION_NAME,
                    "ETW session lost events (increase buffers / speed up consumer)"
                );
            } else {
                tracing::debug!(session = SESSION_NAME, "ETW session stopped; 0 events lost");
            }
        }
    }
}

/// Best-effort stop of a same-named session left behind by a crashed run, so
/// `StartTraceW` doesn't fail with `ERROR_ALREADY_EXISTS`.
fn cleanup_stale_session() {
    let name = session_name_wide();
    let mut buf = alloc_properties_buf();
    let props = buf.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();

    unsafe {
        let _ = ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(name.as_ptr()),
            props,
            EVENT_TRACE_CONTROL_STOP,
        );
    }
}

// ---------------------------------------------------------------------------
// ProcessTrace loop (dedicated blocking thread)
// ---------------------------------------------------------------------------

#[allow(clippy::field_reassign_with_default)]
fn process_trace_loop(send_ptr: SendPtr) {
    let tx_ptr = send_ptr.0;
    let mut name = session_name_wide();

    let mut logfile = EVENT_TRACE_LOGFILEW::default();
    logfile.LoggerName = PWSTR(name.as_mut_ptr());
    logfile.Anonymous1.ProcessTraceMode =
        PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.Anonymous2.EventRecordCallback = Some(event_record_callback);
    logfile.Context = tx_ptr.cast::<c_void>();

    let trace_handle = unsafe { OpenTraceW(&mut logfile) };
    if trace_handle.Value == u64::MAX {
        tracing::error!(err = %std::io::Error::last_os_error(), "ETW OpenTraceW failed");
        // Reclaim the boxed Sender so the consumer thread's channel closes.
        unsafe { drop(Box::from_raw(tx_ptr)) };
        return;
    }

    let _ = unsafe { ProcessTrace(&[trace_handle], None, None) };

    unsafe {
        let _ = CloseTrace(trace_handle);
        drop(Box::from_raw(tx_ptr));
    }
}

unsafe extern "system" fn event_record_callback(event_record: *mut EVENT_RECORD) {
    let event = unsafe { &*event_record };
    // Hot path — keep it minimal (decode runs on the consumer thread). We only
    // enabled the Sandboxing provider, but guard anyway.
    if event.EventHeader.ProviderId != SANDBOXING_PROVIDER_GUID {
        return;
    }

    // Hot path: copy raw bytes only, then hand off. No TDH decode here — keeping
    // this callback cheap is what stops ETW dropping the create burst.
    let tx = unsafe { &*(event.UserContext as *const mpsc::Sender<RawEtwEvent>) };
    let raw = unsafe { copy_raw(event_record) };
    let _ = tx.send(raw);
}

/// Deep-copy a kernel `EVENT_RECORD` into an owned, `Send` [`RawEtwEvent`].
/// Runs in the ETW callback, so it does the minimum: byte copies, no decode.
unsafe fn copy_raw(event_record: *const EVENT_RECORD) -> RawEtwEvent {
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
/// - `commandLine` and a per-pid "last resolved" value are fallbacks.
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

#[derive(Default)]
pub(crate) struct AttributionIndex {
    by_pid: HashMap<u32, String>,
    by_identity: HashMap<String, String>,
    by_activity: HashMap<String, String>,
    by_cv: HashMap<String, String>,
    /// Command line → sandbox_id, but **only while that command line is unique**.
    /// The instant a second sandbox registers the same command line it is moved to
    /// [`Self::ambiguous_cmds`] and removed here, so an ambiguous command can never
    /// misroute an event. Command line is a weak, last-resort key for exactly this
    /// reason (two sandboxes commonly run the identical agent command).
    by_cmd: HashMap<String, String>,
    /// Command lines seen for more than one sandbox — never usable for resolution.
    ambiguous_cmds: std::collections::HashSet<String>,
    last_pid_sid: HashMap<u32, String>,
    names: HashMap<String, String>,
    /// Sandboxes for which a lifecycle [6002] row has already been emitted, so
    /// the two redundant create events don't double-count.
    lifecycle_emitted: std::collections::HashSet<String>,
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
    /// primary anchor — unique *while that process is alive* (Windows won't reuse
    /// a live PID). `command_line` is only a weak fallback and is dropped the
    /// moment it stops being unique (see [`Self::ambiguous_cmds`]).
    pub fn register_launch(
        &mut self,
        sandbox_id: &str,
        sandbox_name: &str,
        wxc_pid: u32,
        command_line: &str,
    ) {
        // PID-reuse guard: if this PID still maps to a *different* sandbox, the
        // prior sandbox was never `forget()`-ten (e.g. a crash skipped `delete`)
        // and Windows has recycled the number. Rebind to the new owner and drop
        // the stale per-PID "last resolved" hint so it can't misroute.
        if let Some(prev) = self.by_pid.get(&wxc_pid) {
            if prev != sandbox_id {
                tracing::warn!(
                    target: "mxc_etw",
                    pid = wxc_pid,
                    prev = %prev,
                    new = %sandbox_id,
                    "wxc-exec PID reused before prior sandbox was forgotten; rebinding attribution"
                );
            }
        }
        self.by_pid.insert(wxc_pid, sandbox_id.to_string());
        self.last_pid_sid.remove(&wxc_pid);

        // Command line is only trustworthy while unique. Promote to `by_cmd` on
        // first sight; on a second, different owner, demote to ambiguous forever.
        if !command_line.is_empty() && !self.ambiguous_cmds.contains(command_line) {
            match self.by_cmd.get(command_line) {
                Some(existing) if existing != sandbox_id => {
                    self.by_cmd.remove(command_line);
                    self.ambiguous_cmds.insert(command_line.to_string());
                }
                Some(_) => {} // same owner re-registering; keep
                None => {
                    self.by_cmd
                        .insert(command_line.to_string(), sandbox_id.to_string());
                }
            }
        }

        self.names
            .insert(sandbox_id.to_string(), sandbox_name.to_string());
    }

    /// Drop all keys for a finished sandbox to bound memory.
    pub fn forget(&mut self, sandbox_id: &str) {
        self.by_pid.retain(|_, v| v != sandbox_id);
        self.by_identity.retain(|_, v| v != sandbox_id);
        self.by_activity.retain(|_, v| v != sandbox_id);
        self.by_cv.retain(|_, v| v != sandbox_id);
        self.by_cmd.retain(|_, v| v != sandbox_id);
        self.last_pid_sid.retain(|_, v| v != sandbox_id);
        self.names.remove(sandbox_id);
        self.lifecycle_emitted.remove(sandbox_id);
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
    fn resolve(&mut self, ev: &DecodedEtwEvent) -> Option<String> {
        let identity = ev.identity();
        let cv = ev.cv_base();
        let activity = guid_key(&ev.activity_id);
        let cmd = ev.get_unquoted("commandLine");

        let sid = self
            .by_pid
            .get(&ev.process_id)
            .cloned()
            .or_else(|| {
                identity
                    .as_ref()
                    .and_then(|i| self.by_identity.get(i).cloned())
            })
            .or_else(|| {
                activity
                    .as_ref()
                    .and_then(|a| self.by_activity.get(a).cloned())
            })
            .or_else(|| cv.as_ref().and_then(|c| self.by_cv.get(c).cloned()))
            .or_else(|| cmd.as_ref().and_then(|c| self.by_cmd.get(c).cloned()))
            .or_else(|| self.last_pid_sid.get(&ev.process_id).cloned())?;

        if let Some(i) = identity {
            self.by_identity.entry(i).or_insert_with(|| sid.clone());
        }
        if let Some(c) = cv {
            self.by_cv.entry(c).or_insert_with(|| sid.clone());
        }
        if let Some(a) = activity {
            self.by_activity.entry(a).or_insert_with(|| sid.clone());
        }
        self.last_pid_sid.insert(ev.process_id, sid.clone());

        Some(sid)
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
        if self.pending.is_empty() {
            return Vec::new();
        }
        let now = Instant::now();
        let drained = std::mem::take(&mut self.pending);
        let mut ready = Vec::new();
        let mut keep = VecDeque::with_capacity(drained.len());
        for p in drained {
            if now.duration_since(p.at) > PENDING_TTL {
                tracing::debug!(target: "mxc_etw", pid = p.ev.process_id, "dropping unattributed (aged out) {}", p.ev.summary());
                continue;
            }
            match self.resolve(&p.ev) {
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
        // once with the command — only emit for the populated one.
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
        // the launch request (with cmd line) and the confirmed start (with real pid).
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
fn map_lifecycle_create(ctx: &SandboxContext, sandbox_name: &str) -> OcsfEvent {
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
fn map_config_state(ctx: &SandboxContext, ev: &DecodedEtwEvent) -> OcsfEvent {
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
        // The one network-plane event the provider emits; `proxyPort=0` means no
        // proxy was configured. Surface the port so the CONFIG row is self-describing.
        "SandboxProxyConfigured" => match ev.get_unquoted("proxyPort").as_deref() {
            Some("0") | None => "MXC sandbox proxy configured (no proxy)".to_string(),
            Some(port) => format!("MXC sandbox proxy configured (port {port})"),
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
/// PRIVACY NOTE (review item #3): `cmd_line` is copied **verbatim** from MXC's
/// ETW event into the OCSF `process.cmd_line` field. This consumer performs **no
/// privacy/secret filtering** — if a caller passes credentials, tokens, or PII on
/// the command line, they will appear **unredacted** in the durable audit trail.
/// This is deliberate (audit fidelity), so the OCSF log must be treated as
/// sensitive at rest and in transit.
///
/// Redaction is intentionally **not** done here and is owned by an upstream
/// privacy layer, not the ETW→OCSF path. Note that no general PII/secret scrubber
/// covers this field today: the only redaction that exists
/// (`openshell_core::secrets`, `${…}` → `[CREDENTIAL]`) is scoped to the network
/// proxy's HTTP-target logging, a separate egress path. If/when a general
/// audit-output PII filter lands, this field is where it must apply.
fn map_process_launch(ctx: &SandboxContext, ev: &DecodedEtwEvent, cmd_line: &str) -> OcsfEvent {
    // The created process's own pid isn't in this event (it appears later in
    // `ProcessLaunched`); the emitting pid is the sandbox host (wxc-exec).
    let proc = Process::new(&exe_name(cmd_line), 0).with_cmd_line(cmd_line);
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
            "MXC sandbox launched process: {}{cwd_suffix}",
            truncate(cmd_line, 160)
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
fn map_process_started(ctx: &SandboxContext, ev: &DecodedEtwEvent) -> OcsfEvent {
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
fn map_finding(ctx: &SandboxContext, ev: &DecodedEtwEvent) -> OcsfEvent {
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

/// Truncate at a char boundary with an ellipsis (keeps shorthand tidy).
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
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
fn etw_ctx(sandbox_id: &str, sandbox_name: &str) -> SandboxContext {
    SandboxContext {
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

    fn mk_event(pid: u32, name: &str) -> DecodedEtwEvent {
        DecodedEtwEvent {
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
        idx.register_launch("sbx-1", "my-sandbox", 1234, "agent --run");

        // The buffered event now attributes and is returned for emit, in order.
        let ready = idx.drain_resolved();
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
        idx.register_launch("sbx-9", "s9", 4321, "agent");

        // First event carries the pid + an activity id → resolves and cross-links
        // the activity id to sbx-9.
        let mut anchor = mk_event(4321, "CreateProcessInSandbox");
        anchor.activity_id = GUID::from_u128(0xABCD);
        assert_eq!(idx.resolve(&anchor).as_deref(), Some("sbx-9"));

        // A later payload-keyless event shares only the activity id (different
        // pid) — it must now resolve via the cross-link.
        let mut keyless = mk_event(0, "SandboxConfig");
        keyless.activity_id = GUID::from_u128(0xABCD);
        assert_eq!(idx.resolve(&keyless).as_deref(), Some("sbx-9"));
    }

    // Shailendra #1 (PID reuse): if a sandbox leaked (no `forget`) and Windows
    // recycles its wxc-exec PID for a new sandbox, events on that PID must route
    // to the *new* owner, never the dead one.
    #[test]
    fn pid_reuse_rebinds_to_new_sandbox() {
        let mut idx = AttributionIndex::new();
        idx.register_launch("sbx-A", "A", 1000, "agent --a");
        let ev_a = mk_event(1000, "CreateProcessInSandbox");
        assert_eq!(idx.resolve(&ev_a).as_deref(), Some("sbx-A"));

        // A leaks (delete never ran). PID 1000 is recycled for B.
        idx.register_launch("sbx-B", "B", 1000, "agent --b");
        let ev_b = mk_event(1000, "CreateProcessInSandbox");
        assert_eq!(idx.resolve(&ev_b).as_deref(), Some("sbx-B"));
    }

    // Shailendra #1 (cmd ambiguity): two sandboxes running the identical command
    // line must not let that command line resolve anything (it's ambiguous); a
    // unique command line still works as a fallback.
    #[test]
    fn duplicate_command_line_is_not_used_for_resolution() {
        let mut idx = AttributionIndex::new();
        idx.register_launch("sbx-1", "s1", 11, "agent --run");
        idx.register_launch("sbx-2", "s2", 22, "agent --run"); // same cmd → ambiguous

        // Event carrying ONLY the duplicate command line (unknown pid, no
        // identity/activity) must NOT resolve — refusing beats misrouting.
        let mut only_cmd = mk_event(999, "SandboxConfig");
        only_cmd
            .props
            .push(("commandLine".into(), "\"agent --run\"".into()));
        assert!(idx.resolve(&only_cmd).is_none());

        // A still-unique command line resolves via the fallback as before.
        idx.register_launch("sbx-3", "s3", 33, "agent --unique");
        let mut uniq = mk_event(998, "SandboxConfig");
        uniq.props
            .push(("commandLine".into(), "\"agent --unique\"".into()));
        assert_eq!(idx.resolve(&uniq).as_deref(), Some("sbx-3"));
    }
}
