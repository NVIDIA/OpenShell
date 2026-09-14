// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Request/response JSON control channel to a sandboxed process, riding
//! `wxc-exec`'s inherited stdin/stdout (STDIO passthrough) — see the
//! `openshell-supervisor-relay` crate's module docs for the protocol
//! and why this needs no `AppContainer` network capability at all: it's
//! inherited process handles, not network traffic.

use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::ChildStdin;
use tokio::sync::{Mutex, oneshot};

#[derive(Debug, thiserror::Error)]
pub enum ControlChannelError {
    #[error("control channel write failed: {0}")]
    Write(#[source] std::io::Error),
    #[error("control channel response sender dropped")]
    Dropped,
    #[error("control channel request timed out after {0:?}")]
    Timeout(Duration),
    #[error("control channel serialize failed: {0}")]
    Serialize(#[from] serde_json::Error),
}

type PendingMap = Mutex<HashMap<u64, oneshot::Sender<Value>>>;
/// Slot for one of the spawner's one-time, unsolicited events -- startup-
/// ready (see `try_route_ready`) and target-ready (see
/// `try_route_target_ready`) each get their own instance of this type.
/// Not part of `PendingMap`: neither has a correlation id or is a reply to
/// anything the driver sent. The payload is `Ok(())` for a normal fire, or
/// `Err(reason)` when the event fired but something about it was rejected
/// (currently only the "ready" event's protocol version check uses this;
/// `"target_ready"` always sends `Ok(())`).
pub type ReadySlot = Mutex<Option<oneshot::Sender<Result<(), String>>>>;

/// Wire protocol version this driver requires from
/// `openshell-supervisor-relay`'s startup `"ready"` event (see
/// `try_route_ready`). Must match that crate's own `PROTOCOL_VERSION`
/// constant -- duplicated rather than shared via a common crate, matching
/// how the rest of this wire protocol (event/op names, the auth nonce
/// encoding, etc.) is already duplicated across the two sides. Bump both
/// together whenever the control-channel protocol changes in a way an
/// out-of-sync peer can't safely ignore (e.g. the "nonce" field added to
/// "forward", or the `"target_ready"` event itself) -- an independently
/// staged, stale relay binary then fails fast with a clear error instead of
/// hanging or misbehaving against fields/events it doesn't understand.
const REQUIRED_SUPERVISOR_RELAY_PROTOCOL_VERSION: u64 = 2;

/// One control channel per sandboxed process. `request()` is safe to call
/// concurrently — each call gets its own correlation id and awaits only its
/// own response, so multiple in-flight requests (e.g. concurrent `forward`
/// calls) don't interfere with each other.
pub struct ControlChannel {
    stdin: Mutex<ChildStdin>,
    next_id: AtomicU64,
    pending: Arc<PendingMap>,
}

impl ControlChannel {
    pub fn new(stdin: ChildStdin) -> Self {
        Self {
            stdin: Mutex::new(stdin),
            next_id: AtomicU64::new(1),
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// A clonable handle to the pending-requests map, for the stdout-reader
    /// task (which owns the read side) to route responses into.
    pub fn pending_handle(&self) -> Arc<PendingMap> {
        self.pending.clone()
    }

    /// Try to parse `line` as a control-channel response and complete the
    /// matching pending request. Returns `true` if `line` was consumed this
    /// way; `false` means the caller should treat it as plain log text
    /// instead (covers wxc-exec's own banner/config-dump lines, which are
    /// never `{"id":...}`-shaped).
    pub async fn try_route_response(pending: &PendingMap, line: &str) -> bool {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            return false;
        };
        let Some(id) = value.get("id").and_then(Value::as_u64) else {
            return false;
        };
        let mut map = pending.lock().await;
        map.remove(&id).is_some_and(|tx| {
            let _ = tx.send(value);
            true
        })
    }

    /// Try to recognize `line` as the spawner's unsolicited startup-ready
    /// event (`{"event":"ready","protocol_version":N}`) -- sent once,
    /// before it's spawned anything, so the driver knows when to send the
    /// `"launch"` request carrying the real command/env (see driver.rs's
    /// launch handshake and the `openshell-supervisor-relay` crate's module
    /// docs). Unlike a query response this has no correlation id, so it
    /// can't go through `try_route_response`. Returns `true` if `line` was
    /// consumed this way (regardless of whether the version check passed --
    /// the caller distinguishes that via the channel payload).
    ///
    /// Validates `protocol_version` against
    /// `REQUIRED_SUPERVISOR_RELAY_PROTOCOL_VERSION` so an independently
    /// staged, out-of-sync relay binary (e.g. left over from an older
    /// package drop in a shared `share_dir`) fails the sandbox immediately
    /// with a clear "wrong version" error instead of hanging or misbehaving
    /// later against a "launch"/"forward" field or a `"target_ready"` event it
    /// doesn't understand. A missing field means a pre-versioning binary --
    /// also rejected, since there's no version to compare.
    pub async fn try_route_ready(ready: &ReadySlot, line: &str) -> bool {
        Self::try_route_named_event(ready, line, "ready", |value| {
            match value.get("protocol_version").and_then(Value::as_u64) {
                Some(v) if v == REQUIRED_SUPERVISOR_RELAY_PROTOCOL_VERSION => Ok(()),
                Some(v) => Err(format!(
                    "openshell-supervisor-relay reports protocol_version {v}, this driver requires {REQUIRED_SUPERVISOR_RELAY_PROTOCOL_VERSION} -- restage a matching build"
                )),
                None => Err(format!(
                    "openshell-supervisor-relay's ready event has no protocol_version field (pre-versioning binary); this driver requires {REQUIRED_SUPERVISOR_RELAY_PROTOCOL_VERSION} -- restage a matching build"
                )),
            }
        })
        .await
    }

    /// Try to recognize `line` as the spawner's unsolicited target-ready
    /// event (`{"event":"target_ready"}`) -- sent once the spawner has
    /// actually spawned the target and confirmed its configured port is
    /// accepting connections (see `wait_for_port_ready` in
    /// `openshell-supervisor-relay`). Distinct from the `"launch"`
    /// control-channel *response*, which only confirms the command/env
    /// arrived, not that the target is running: driver.rs awaits this event
    /// too before publishing the sandbox `Ready=True`, so a caller acting on
    /// `Ready` can't race a target that hasn't bound its port yet. Returns
    /// `true` if `line` was consumed this way. No version gate here -- the
    /// startup "ready" handshake above already rejected an incompatible
    /// peer long before this could fire.
    pub async fn try_route_target_ready(target_ready: &ReadySlot, line: &str) -> bool {
        Self::try_route_named_event(target_ready, line, "target_ready", |_| Ok(())).await
    }

    async fn try_route_named_event(
        slot: &ReadySlot,
        line: &str,
        event_name: &str,
        validate: impl FnOnce(&Value) -> Result<(), String>,
    ) -> bool {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            return false;
        };
        if value.get("event").and_then(|v| v.as_str()) != Some(event_name) {
            return false;
        }
        let sender = slot.lock().await.take();
        if let Some(tx) = sender {
            let _ = tx.send(validate(&value));
        }
        true
    }

    /// Fail every currently pending request with `Dropped`, e.g. when the
    /// stdout-reader task observes EOF/error on the child's stdout: once the
    /// reader is gone, no response will ever arrive for these ids, so let
    /// callers fail fast instead of sitting out their individual timeouts.
    /// Dropping each sender (rather than sending a value) is what makes the
    /// waiting `request()` call observe `ControlChannelError::Dropped`.
    pub async fn fail_all_pending(pending: &PendingMap) {
        let mut map = pending.lock().await;
        map.clear();
    }

    /// Send `{"id":N,"op":op,"data":data}` and await the correlated
    /// response, or an error on write failure, timeout, or a dropped sender
    /// (the reader task exited, e.g. the process died).
    pub async fn request(
        &self,
        op: &str,
        data: Value,
        timeout: Duration,
    ) -> Result<Value, ControlChannelError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(id, tx);

        let req = serde_json::json!({"id": id, "op": op, "data": data});
        let mut line = serde_json::to_string(&req)?;
        line.push('\n');

        let write_result = {
            let mut stdin = self.stdin.lock().await;
            match stdin.write_all(line.as_bytes()).await {
                Ok(()) => stdin.flush().await,
                Err(e) => Err(e),
            }
        };
        if let Err(e) = write_result {
            self.pending.lock().await.remove(&id);
            return Err(ControlChannelError::Write(e));
        }

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(_)) => Err(ControlChannelError::Dropped),
            Err(_) => {
                self.pending.lock().await.remove(&id);
                Err(ControlChannelError::Timeout(timeout))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_ready_slot() -> ReadySlot {
        Mutex::new(None)
    }

    fn armed_ready_slot() -> (ReadySlot, oneshot::Receiver<Result<(), String>>) {
        let (tx, rx) = oneshot::channel();
        (Mutex::new(Some(tx)), rx)
    }

    // ── try_route_response ──────────────────────────────────────────────

    #[tokio::test]
    async fn try_route_response_completes_matching_pending_id() {
        let pending: PendingMap = Mutex::new(HashMap::new());
        let (tx, rx) = oneshot::channel();
        pending.lock().await.insert(7, tx);

        let consumed =
            ControlChannel::try_route_response(&pending, r#"{"id":7,"ok":true,"data":42}"#).await;

        assert!(consumed);
        let value = rx.await.unwrap();
        assert_eq!(value["data"], 42);
        assert!(pending.lock().await.is_empty());
    }

    #[tokio::test]
    async fn try_route_response_ignores_unknown_id() {
        let pending: PendingMap = Mutex::new(HashMap::new());
        let (tx, _rx) = oneshot::channel();
        pending.lock().await.insert(1, tx);

        let consumed = ControlChannel::try_route_response(&pending, r#"{"id":99,"ok":true}"#).await;

        assert!(
            !consumed,
            "an id with no pending sender must not be consumed"
        );
        assert_eq!(
            pending.lock().await.len(),
            1,
            "the real pending entry survives"
        );
    }

    #[tokio::test]
    async fn try_route_response_ignores_non_json_and_id_less_lines() {
        let pending: PendingMap = Mutex::new(HashMap::new());

        assert!(!ControlChannel::try_route_response(&pending, "not json at all").await);
        assert!(!ControlChannel::try_route_response(&pending, r#"{"event":"ready"}"#).await);
    }

    // ── try_route_ready (protocol-version handshake) ────────────────────

    #[tokio::test]
    async fn try_route_ready_accepts_matching_protocol_version() {
        let (slot, rx) = armed_ready_slot();

        let consumed =
            ControlChannel::try_route_ready(&slot, r#"{"event":"ready","protocol_version":2}"#)
                .await;

        assert!(consumed);
        assert_eq!(rx.await.unwrap(), Ok(()));
    }

    #[tokio::test]
    async fn try_route_ready_rejects_mismatched_protocol_version() {
        let (slot, rx) = armed_ready_slot();

        let consumed =
            ControlChannel::try_route_ready(&slot, r#"{"event":"ready","protocol_version":1}"#)
                .await;

        assert!(
            consumed,
            "a recognized ready event is consumed even when rejected"
        );
        let err = rx.await.unwrap().expect_err("version 2 must be rejected");
        assert!(
            err.contains('2'),
            "error should name the offending version: {err}"
        );
        assert!(
            err.contains('1'),
            "error should name the required version: {err}"
        );
    }

    #[tokio::test]
    async fn try_route_ready_rejects_missing_protocol_version_field() {
        let (slot, rx) = armed_ready_slot();

        let consumed = ControlChannel::try_route_ready(&slot, r#"{"event":"ready"}"#).await;

        assert!(consumed);
        let err = rx
            .await
            .unwrap()
            .expect_err("a missing field must be rejected");
        assert!(
            err.contains("pre-versioning"),
            "error should call out the pre-versioning case: {err}"
        );
    }

    #[tokio::test]
    async fn try_route_ready_ignores_other_events_and_non_json() {
        let slot = empty_ready_slot();

        assert!(!ControlChannel::try_route_ready(&slot, r#"{"event":"target_ready"}"#).await);
        assert!(!ControlChannel::try_route_ready(&slot, "garbage").await);
    }

    // ── try_route_target_ready ───────────────────────────────────────────

    #[tokio::test]
    async fn try_route_target_ready_fires_ok_with_no_version_gate() {
        let (slot, rx) = armed_ready_slot();

        // No protocol_version field at all -- unlike "ready", "target_ready"
        // must not be gated on one (see the doc comment on
        // try_route_target_ready).
        let consumed =
            ControlChannel::try_route_target_ready(&slot, r#"{"event":"target_ready"}"#).await;

        assert!(consumed);
        assert_eq!(rx.await.unwrap(), Ok(()));
    }

    #[tokio::test]
    async fn try_route_target_ready_ignores_ready_event() {
        let slot = empty_ready_slot();

        // "ready" and "target_ready" must not be cross-routed into each
        // other's slot.
        let consumed = ControlChannel::try_route_target_ready(
            &slot,
            r#"{"event":"ready","protocol_version":2}"#,
        )
        .await;

        assert!(!consumed);
    }

    #[tokio::test]
    async fn try_route_named_event_is_a_safe_no_op_once_the_slot_is_already_empty() {
        let (slot, rx) = armed_ready_slot();

        assert!(ControlChannel::try_route_target_ready(&slot, r#"{"event":"target_ready"}"#).await);
        // The slot's sender was taken (and used) on the first fire. A
        // repeat of the same event on the wire is still recognized as a
        // "target_ready" line (so the caller doesn't mistake it for plain
        // log text) but must not panic just because the slot is now empty.
        let consumed_again =
            ControlChannel::try_route_target_ready(&slot, r#"{"event":"target_ready"}"#).await;

        assert!(
            consumed_again,
            "still recognized as the event, even as a no-op"
        );
        assert_eq!(
            rx.await.unwrap(),
            Ok(()),
            "only the first fire's Ok(()) was ever sent"
        );
    }

    // ── fail_all_pending ──────────────────────────────────────────────────

    #[tokio::test]
    async fn fail_all_pending_drops_every_sender() {
        let pending: PendingMap = Mutex::new(HashMap::new());
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        pending.lock().await.insert(1, tx1);
        pending.lock().await.insert(2, tx2);

        ControlChannel::fail_all_pending(&pending).await;

        assert!(pending.lock().await.is_empty());
        assert!(
            rx1.await.is_err(),
            "dropped sender must surface as a recv error"
        );
        assert!(rx2.await.is_err());
    }
}
