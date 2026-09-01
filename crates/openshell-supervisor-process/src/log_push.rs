// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Push sandbox tracing events to the `OpenShell` server via gRPC.
//!
//! A [`tracing`] layer captures log events and sends them through an mpsc
//! channel to a background task. The task batches lines and streams them to
//! the server using the `PushSandboxLogs` client-streaming RPC.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use openshell_core::grpc_client::CachedOpenShellClient;
use openshell_core::proto::{PushSandboxLogsRequest, SandboxLogLine};
use tokio::sync::mpsc;
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

/// Tracing layer that pushes log events to the `OpenShell` server.
///
/// Events are sent best-effort via `try_send` — if the channel is full the
/// event is dropped. Logging must never block the sandbox.
#[derive(Clone)]
pub struct LogPushLayer {
    sandbox_id: String,
    tx: mpsc::Sender<SandboxLogLine>,
    max_level: tracing::Level,
    drops: Arc<LogPushDrops>,
}

impl LogPushLayer {
    pub fn new(
        sandbox_id: String,
        tx: mpsc::Sender<SandboxLogLine>,
        drops: Arc<LogPushDrops>,
    ) -> Self {
        let max_level = parse_max_level(std::env::var("OPENSHELL_LOG_PUSH_LEVEL").ok().as_deref());
        Self {
            sandbox_id,
            tx,
            max_level,
            drops,
        }
    }
}

/// Counts log lines the sandbox could not deliver to the gateway.
#[derive(Debug, Default)]
pub struct LogPushDrops {
    channel_full: AtomicU64,
    backoff_overflow: AtomicU64,
    handoff_failed: AtomicU64,
    oversized: AtomicU64,
}

impl LogPushDrops {
    /// Lines dropped because the layer's channel was full.
    #[must_use]
    pub fn channel_full(&self) -> u64 {
        self.channel_full.load(Ordering::Relaxed)
    }

    /// Lines dropped because the reconnect buffer was full.
    #[must_use]
    pub fn backoff_overflow(&self) -> u64 {
        self.backoff_overflow.load(Ordering::Relaxed)
    }

    /// Lines dropped when shutdown prevented retrying a failed stream handoff.
    #[must_use]
    pub fn handoff_failed(&self) -> u64 {
        self.handoff_failed.load(Ordering::Relaxed)
    }

    /// Total lines dropped on the sandbox-to-gateway hop.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.channel_full() + self.backoff_overflow() + self.handoff_failed() + self.oversized()
    }

    /// Lines dropped because one line alone exceeds the gateway's decode limit.
    #[must_use]
    pub fn oversized(&self) -> u64 {
        self.oversized.load(Ordering::Relaxed)
    }

    fn record_channel_full(&self) {
        self.channel_full.fetch_add(1, Ordering::Relaxed);
    }

    fn record_backoff_overflow(&self) {
        self.backoff_overflow.fetch_add(1, Ordering::Relaxed);
    }

    fn record_handoff_failed(&self, count: u64) {
        self.handoff_failed.fetch_add(count, Ordering::Relaxed);
    }

    fn record_oversized(&self, count: u64) {
        self.oversized.fetch_add(count, Ordering::Relaxed);
    }
}

/// Resolve the push level filter, defaulting to `INFO` when unset or unparseable.
fn parse_max_level(raw: Option<&str>) -> tracing::Level {
    raw.and_then(|s| s.parse().ok())
        .unwrap_or(tracing::Level::INFO)
}

impl<S: Subscriber> Layer<S> for LogPushLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();

        // Filter by configured max level (default: info).
        if *meta.level() > self.max_level {
            return;
        }

        // OCSF events carry their payload in a thread-local. Send both the
        // structured event and shorthand display text: older gateways ignore
        // `ocsf_json`, so `message` remains the mixed-version fallback.
        let (msg, fields, ocsf_json) = if meta.target() == openshell_ocsf::OCSF_TARGET {
            let Some(ocsf_event) = openshell_ocsf::clone_current_event() else {
                return;
            };
            let shorthand = ocsf_event.format_shorthand();
            let Ok(json) = ocsf_event.to_json_line() else {
                return;
            };
            (
                shorthand,
                std::collections::HashMap::new(),
                json.into_bytes(),
            )
        } else {
            let mut visitor = LogVisitor::default();
            event.record(&mut visitor);
            let (msg, fields) = visitor.into_parts(meta.name());
            (msg, fields, Vec::new())
        };

        let ts = openshell_core::time::now_ms();

        let is_ocsf = meta.target() == openshell_ocsf::OCSF_TARGET;

        let log = SandboxLogLine {
            sandbox_id: self.sandbox_id.clone(),
            timestamp_ms: ts,
            level: if is_ocsf {
                "OCSF".to_string()
            } else {
                meta.level().to_string()
            },
            target: meta.target().to_string(),
            message: msg,
            source: "sandbox".to_string(),
            fields,
            ocsf_json,
        };

        // Best-effort: drop if the channel is full (don't block tracing), but
        // count the loss so it is visible rather than silent.
        if self.tx.try_send(log).is_err() {
            self.drops.record_channel_full();
        }
    }
}

/// Spawn a background task that batches and pushes log lines to the server.
///
/// Returns the channel sender, shared drop counters, and task handle.
pub fn spawn_log_push_task(
    endpoint: String,
    sandbox_id: String,
) -> (
    mpsc::Sender<SandboxLogLine>,
    Arc<LogPushDrops>,
    tokio::task::JoinHandle<()>,
) {
    let (tx, rx) = mpsc::channel::<SandboxLogLine>(1024);
    let drops = Arc::new(LogPushDrops::default());

    let handle = tokio::spawn(run_push_loop(endpoint, sandbox_id, rx, Arc::clone(&drops)));

    (tx, drops, handle)
}

/// Build a push request, stamping the running drop total for gap accounting.
fn push_request(
    sandbox_id: &str,
    logs: Vec<SandboxLogLine>,
    drops: &LogPushDrops,
) -> PushSandboxLogsRequest {
    PushSandboxLogsRequest {
        sandbox_id: sandbox_id.to_string(),
        logs,
        dropped_total: drops.total(),
    }
}

/// Keep each request clear of the gateway's 1 MiB gRPC decode cap.
///
/// Exceeding the cap does not reject one request: it kills the stream, and the
/// reconnect loop would resend the same batch forever.
const MAX_PUSH_REQUEST_BYTES: usize = 512 * 1024;

/// Bytes a request costs before any log lines.
const ENVELOPE_BYTES: usize = 64;

/// Tag and length prefix prost writes per repeated `logs` entry.
const FIELD_OVERHEAD: usize = 8;

/// Group `logs` so each group encodes below `limit`.
///
/// Returns the groups and the count of lines no request could carry.
fn split_to_fit(logs: Vec<SandboxLogLine>, limit: usize) -> (Vec<Vec<SandboxLogLine>>, u64) {
    let mut groups: Vec<Vec<SandboxLogLine>> = Vec::new();
    let mut current: Vec<SandboxLogLine> = Vec::new();
    let mut current_len = ENVELOPE_BYTES;
    let mut oversized = 0;

    for line in logs {
        let line_len = prost::Message::encoded_len(&line) + FIELD_OVERHEAD;
        if ENVELOPE_BYTES + line_len > limit {
            oversized += 1;
            continue;
        }
        if !current.is_empty() && current_len + line_len > limit {
            groups.push(std::mem::take(&mut current));
            current_len = ENVELOPE_BYTES;
        }
        current_len += line_len;
        current.push(line);
    }
    if !current.is_empty() {
        groups.push(current);
    }

    (groups, oversized)
}

/// Send `logs`, splitting to fit and counting anything undeliverable.
///
/// Returns the rejected group and any groups not yet handed off when the stream
/// is gone, preserving their original order for retry after reconnecting.
async fn send_logs(
    push_tx: &mpsc::Sender<PushSandboxLogsRequest>,
    sandbox_id: &str,
    logs: Vec<SandboxLogLine>,
    drops: &LogPushDrops,
) -> Result<(), Vec<SandboxLogLine>> {
    let (mut groups, oversized) = split_to_fit(logs, MAX_PUSH_REQUEST_BYTES);
    if oversized > 0 {
        drops.record_oversized(oversized);
        eprintln!("openshell: dropped {oversized} log line(s) too large to deliver");
        if groups.is_empty() {
            // Report the loss even when the batch has no deliverable line.
            groups.push(Vec::new());
        }
    }
    let mut groups = groups.into_iter();
    while let Some(group) = groups.next() {
        if let Err(rejected) = push_tx.send(push_request(sandbox_id, group, drops)).await {
            let mut unsent = rejected.0.logs;
            unsent.extend(groups.flatten());
            return Err(unsent);
        }
    }
    Ok(())
}

/// Account for lines that cannot be retried because the log source closed.
///
/// A rejected synthetic request used only to report oversized drops contains
/// no lines, so it must not produce a second, zero-line drop report.
fn record_shutdown_handoff_failure(unsent: &[SandboxLogLine], drops: &LogPushDrops) -> Option<u64> {
    let count = u64::try_from(unsent.len()).unwrap_or(u64::MAX);
    if count == 0 {
        return None;
    }
    drops.record_handoff_failed(count);
    Some(count)
}

/// Maximum backoff delay between reconnection attempts.
const MAX_BACKOFF: tokio::time::Duration = tokio::time::Duration::from_secs(30);
/// Initial backoff delay after a connection failure.
const INITIAL_BACKOFF: tokio::time::Duration = tokio::time::Duration::from_secs(1);

/// Request compression for sandbox log pushes.
///
/// Keep this disabled until all supported gateways accept gzip. Enabling it in
/// the same release as server-side acceptance breaks newer supervisors that
/// connect to an older gateway or an older replica during a rolling upgrade.
const fn log_push_request_compression() -> Option<tonic::codec::CompressionEncoding> {
    None
}

/// Observe why an immediately rejected handoff ended, then drain new lines
/// during the reconnect delay unless authentication made retrying futile.
async fn back_off_after_handoff_failure(
    rpc_done_rx: &mut mpsc::Receiver<bool>,
    rx: &mut mpsc::Receiver<SandboxLogLine>,
    batch: &mut Vec<SandboxLogLine>,
    delay: tokio::time::Duration,
    drops: &LogPushDrops,
) -> bool {
    let fatal_auth = rpc_done_rx.recv().await.unwrap_or(false);
    if !fatal_auth {
        drain_during_backoff(rx, batch, delay, drops).await;
    }
    fatal_auth
}

async fn run_push_loop(
    endpoint: String,
    sandbox_id: String,
    mut rx: mpsc::Receiver<SandboxLogLine>,
    drops: Arc<LogPushDrops>,
) {
    let mut batch = Vec::with_capacity(50);
    let mut backoff = INITIAL_BACKOFF;
    let mut attempt: u64 = 0;

    // Outer reconnect loop — runs for the entire sandbox lifetime.
    loop {
        attempt += 1;

        // --- Connect ---
        let client = match CachedOpenShellClient::connect(&endpoint).await {
            Ok(c) => {
                if attempt > 1 {
                    eprintln!("openshell: log push reconnected (attempt {attempt})");
                }
                backoff = INITIAL_BACKOFF;
                c
            }
            Err(e) => {
                eprintln!("openshell: log push connect failed: {e}");
                // Drain the channel during backoff so the tracing layer doesn't
                // fill while retaining the newest lines up to the buffer cap.
                drain_during_backoff(&mut rx, &mut batch, backoff, &drops).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
                continue;
            }
        };

        // --- Open the client-streaming RPC ---
        let (push_tx, push_rx) = mpsc::channel::<PushSandboxLogsRequest>(32);
        let stream = tokio_stream::wrappers::ReceiverStream::new(push_rx);

        // Spawn the gRPC streaming call. When the call ends (success or error),
        // `rpc_done_tx` fires so the batch loop below knows whether to retry.
        let (rpc_done_tx, mut rpc_done_rx) = mpsc::channel::<bool>(1);
        tokio::spawn({
            let mut nav_client = client.raw_client();
            if let Some(encoding) = log_push_request_compression() {
                nav_client = nav_client.send_compressed(encoding);
            }
            async move {
                let fatal_auth = match nav_client.push_sandbox_logs(stream).await {
                    Ok(_) => false,
                    Err(e) => {
                        let fatal_auth = e.code() == tonic::Code::Unauthenticated;
                        eprintln!("openshell: log push RPC failed: {e}");
                        fatal_auth
                    }
                };
                let _ = rpc_done_tx.send(fatal_auth).await;
            }
        });

        // --- Flush any lines buffered during reconnect ---
        if !batch.is_empty() {
            let lines = std::mem::take(&mut batch);
            if let Err(unsent) = send_logs(&push_tx, &sandbox_id, lines, &drops).await {
                // RPC died immediately. Retain the rejected requests, observe
                // fatal authentication, and drain during backoff before retry.
                batch = unsent;
                if back_off_after_handoff_failure(
                    &mut rpc_done_rx,
                    &mut rx,
                    &mut batch,
                    backoff,
                    &drops,
                )
                .await
                {
                    eprintln!("openshell: log push disabled after authentication failure");
                    return;
                }
                eprintln!("openshell: log push stream lost, reconnecting after backoff...");
                backoff = (backoff * 2).min(MAX_BACKOFF);
                continue;
            }
        }

        // --- Batch and send loop (runs until stream breaks) ---
        let flush_interval = tokio::time::Duration::from_millis(500);
        let mut timer = tokio::time::interval(flush_interval);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut fatal_auth = false;
        let stream_broken = loop {
            tokio::select! {
                line = rx.recv() => {
                    let Some(line) = line else {
                        // Tracing layer dropped — sandbox is shutting down.
                        // Flush remaining and exit entirely.
                        if !batch.is_empty() {
                            let lines = std::mem::take(&mut batch);
                            if let Err(unsent) = send_logs(&push_tx, &sandbox_id, lines, &drops).await
                                && let Some(count) = record_shutdown_handoff_failure(&unsent, &drops)
                            {
                                eprintln!(
                                    "openshell: dropped {count} log line(s) after stream handoff failed during shutdown"
                                );
                            }
                        }
                        return;
                    };
                    batch.push(line);
                    if batch.len() >= 50 {
                        let lines = std::mem::take(&mut batch);
                        if let Err(unsent) = send_logs(&push_tx, &sandbox_id, lines, &drops).await {
                            batch = unsent;
                            break true;
                        }
                    }
                }
                _ = timer.tick() => {
                    if !batch.is_empty() {
                        let lines = std::mem::take(&mut batch);
                        if let Err(unsent) = send_logs(&push_tx, &sandbox_id, lines, &drops).await {
                            batch = unsent;
                            break true;
                        }
                    }
                }
                rpc_done = rpc_done_rx.recv() => {
                    // The gRPC streaming call ended (server closed / error).
                    fatal_auth = rpc_done.unwrap_or(false);
                    break true;
                }
            }
        };

        if fatal_auth {
            eprintln!("openshell: log push disabled after authentication failure");
            return;
        }

        if stream_broken {
            eprintln!("openshell: log push stream lost, reconnecting after backoff...");
            drain_during_backoff(&mut rx, &mut batch, backoff, &drops).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }
}

/// Drain incoming log lines during a backoff delay so the tracing layer's
/// `try_send` doesn't fill up. Lines received during backoff are kept in `batch`
/// (up to a limit) so they can be sent after reconnecting.
async fn drain_during_backoff(
    rx: &mut mpsc::Receiver<SandboxLogLine>,
    batch: &mut Vec<SandboxLogLine>,
    delay: tokio::time::Duration,
    drops: &LogPushDrops,
) {
    // Keep at most 200 lines across reconnect attempts to bound memory.
    const MAX_BUFFERED: usize = 200;

    let deadline = tokio::time::Instant::now() + delay;
    loop {
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => { return; }
            line = rx.recv() => {
                match line {
                    Some(l) => {
                        if batch.len() >= MAX_BUFFERED {
                            // Prefer current sandbox activity over the oldest
                            // retry while keeping loss explicitly accounted.
                            batch.remove(0);
                            drops.record_backoff_overflow();
                        }
                        batch.push(l);
                    }
                    None => return, // channel closed, sandbox shutting down
                }
            }
        }
    }
}

#[derive(Debug, Default)]
struct LogVisitor {
    message: Option<String>,
    fields: Vec<(String, String)>,
}

impl LogVisitor {
    /// Split into message and structured fields map.
    fn into_parts(self, fallback: &str) -> (String, std::collections::HashMap<String, String>) {
        let msg = self.message.unwrap_or_else(|| fallback.to_string());
        let fields = self.fields.into_iter().collect();
        (msg, fields)
    }
}

impl tracing::field::Visit for LogVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        } else {
            self.fields
                .push((field.name().to_string(), value.to_string()));
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{value:?}"));
        } else {
            self.fields
                .push((field.name().to_string(), format!("{value:?}")));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_ocsf::{
        ActionId, ActivityId, DispositionId, Endpoint, NetworkActivityBuilder, SandboxContext,
        SeverityId, StatusId, ocsf_emit,
    };
    use tracing_subscriber::layer::SubscriberExt;

    fn ocsf_ctx() -> SandboxContext {
        SandboxContext {
            sandbox_id: "sb-test".to_string(),
            sandbox_name: "test-sandbox".to_string(),
            container_image: "openshell/sandbox:test".to_string(),
            hostname: "test-host".to_string(),
            product_version: "0.0.0".to_string(),
            proxy_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            proxy_port: 8888,
            origin: openshell_ocsf::EventOrigin::Sandbox,
        }
    }

    /// Capture lines emitted by `f` with an `INFO` level filter.
    fn capture(capacity: usize, f: impl FnOnce()) -> Vec<SandboxLogLine> {
        let (tx, mut rx) = mpsc::channel::<SandboxLogLine>(capacity);
        let layer = LogPushLayer {
            sandbox_id: "sb-test".to_string(),
            tx,
            max_level: tracing::Level::INFO,
            drops: Arc::new(LogPushDrops::default()),
        };
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, f);

        let mut out = Vec::new();
        while let Ok(line) = rx.try_recv() {
            out.push(line);
        }
        out
    }

    #[test]
    fn ocsf_events_push_the_structured_event_with_shorthand_fallback() {
        let event = NetworkActivityBuilder::new(&ocsf_ctx())
            .activity(ActivityId::Open)
            .action(ActionId::Denied)
            .disposition(DispositionId::Blocked)
            .severity(SeverityId::Medium)
            .status(StatusId::Failure)
            .dst_endpoint(Endpoint::from_domain("blocked.example.com", 443))
            .message("CONNECT denied blocked.example.com:443".to_string())
            .build();
        let expected_json = event.to_json().expect("serialize");
        let expected_shorthand = event.format_shorthand();

        let lines = capture(16, || ocsf_emit!(event));
        assert_eq!(lines.len(), 1);
        let line = &lines[0];

        assert!(
            !line.ocsf_json.is_empty(),
            "structured event should be sent"
        );
        let decoded: serde_json::Value =
            serde_json::from_slice(&line.ocsf_json).expect("payload should be valid JSON");
        assert_eq!(decoded, expected_json);

        // Older gateways ignore `ocsf_json`, so the shorthand remains in the
        // legacy message field as a mixed-version fallback.
        assert_eq!(line.message, expected_shorthand);

        // What the receiver will render must match what the sandbox would have.
        let decoded_event: openshell_ocsf::OcsfEvent =
            serde_json::from_slice(&line.ocsf_json).expect("payload should decode");
        assert_eq!(decoded_event.format_shorthand(), expected_shorthand);
    }

    #[test]
    fn remove_mixed_version_shorthand_fallback_after_2026_10_15() {
        const REMOVE_FALLBACK_AFTER_UNIX_SECS: u64 = 1_792_022_400;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_secs();

        assert!(
            now < REMOVE_FALLBACK_AFTER_UNIX_SECS,
            "remove the OCSF shorthand message fallback now that gateways predating ocsf_json are no longer supported"
        );
    }

    #[test]
    fn a_batch_that_fits_is_sent_as_one_request() {
        let logs = vec![test_line("a"), test_line("b")];

        let (groups, oversized) = split_to_fit(logs, MAX_PUSH_REQUEST_BYTES);

        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].len(), 2);
        assert_eq!(oversized, 0);
    }

    #[test]
    fn an_empty_batch_produces_no_requests() {
        let (groups, oversized) = split_to_fit(Vec::new(), MAX_PUSH_REQUEST_BYTES);

        assert!(groups.is_empty());
        assert_eq!(oversized, 0);
    }

    #[test]
    fn an_oversized_batch_is_split_rather_than_dropped() {
        // Each line carries a 1 KiB payload; a 4 KiB limit cannot hold all six.
        let logs: Vec<SandboxLogLine> = (0..6).map(|i| padded_line(i, 1024)).collect();

        let (groups, oversized) = split_to_fit(logs, 4096);

        assert!(groups.len() > 1, "the batch should have been split");
        assert_eq!(oversized, 0, "nothing should be lost to a split");
        let total: usize = groups.iter().map(Vec::len).sum();
        assert_eq!(total, 6);
    }

    #[test]
    fn every_group_encodes_below_the_limit() {
        let logs: Vec<SandboxLogLine> = (0..20).map(|i| padded_line(i, 1024)).collect();

        let (groups, _) = split_to_fit(logs, 4096);

        for group in &groups {
            let request = push_request("sb", group.clone(), &LogPushDrops::default());
            let encoded = prost::Message::encoded_len(&request);
            assert!(
                encoded <= 4096,
                "a group encoded to {encoded} bytes, over the 4096 limit"
            );
        }
    }

    #[test]
    fn splitting_preserves_line_order() {
        let logs: Vec<SandboxLogLine> = (0..6).map(|i| padded_line(i, 1024)).collect();

        let (groups, _) = split_to_fit(logs, 4096);

        let messages: Vec<String> = groups
            .into_iter()
            .flatten()
            .map(|line| line.message)
            .collect();
        let expected: Vec<String> = (0..6).map(|i| padded_line(i, 1024).message).collect();
        assert_eq!(messages, expected);
    }

    #[test]
    fn a_single_line_too_large_to_send_is_dropped_and_counted() {
        let logs = vec![test_line("small"), padded_line(1, 8192)];

        let (groups, oversized) = split_to_fit(logs, 4096);

        assert_eq!(oversized, 1);
        let kept: Vec<String> = groups
            .into_iter()
            .flatten()
            .map(|line| line.message)
            .collect();
        assert_eq!(kept, vec!["small"], "the deliverable line still goes");
    }

    #[tokio::test]
    async fn an_oversized_only_batch_reports_its_drop() {
        let (push_tx, mut push_rx) = mpsc::channel(1);
        let drops = LogPushDrops::default();

        send_logs(
            &push_tx,
            "sb",
            vec![padded_line(1, MAX_PUSH_REQUEST_BYTES)],
            &drops,
        )
        .await
        .expect("drop report should be handed off");

        let request = push_rx
            .try_recv()
            .expect("the gateway should receive the updated drop total");
        assert!(request.logs.is_empty());
        assert_eq!(request.dropped_total, 1);
    }

    #[tokio::test]
    async fn a_rejected_request_and_remaining_split_groups_are_returned_for_retry() {
        let (push_tx, mut push_rx) = mpsc::channel(1);
        let logs: Vec<SandboxLogLine> = (0..3)
            .map(|i| padded_line(i, MAX_PUSH_REQUEST_BYTES / 2 + 1))
            .collect();

        let send =
            tokio::spawn(
                async move { send_logs(&push_tx, "sb", logs, &LogPushDrops::default()).await },
            );

        let accepted = push_rx
            .recv()
            .await
            .expect("first group should be accepted");
        assert_eq!(accepted.logs.len(), 1);
        assert_eq!(
            accepted.logs[0].message,
            padded_line(0, MAX_PUSH_REQUEST_BYTES / 2 + 1).message
        );
        drop(push_rx);

        let unsent = send
            .await
            .expect("send task should finish")
            .expect_err("closed request channel should reject the next group");
        let messages: Vec<_> = unsent.into_iter().map(|line| line.message).collect();
        assert_eq!(
            messages,
            vec![
                padded_line(1, MAX_PUSH_REQUEST_BYTES / 2 + 1).message,
                padded_line(2, MAX_PUSH_REQUEST_BYTES / 2 + 1).message,
            ]
        );
    }

    #[tokio::test]
    async fn a_rejected_oversized_drop_report_is_not_reported_as_a_zero_line_drop() {
        let (push_tx, push_rx) = mpsc::channel(1);
        drop(push_rx);
        let drops = LogPushDrops::default();
        let unsent = send_logs(
            &push_tx,
            "sb",
            vec![padded_line(1, MAX_PUSH_REQUEST_BYTES)],
            &drops,
        )
        .await
        .expect_err("closed request channel should reject the drop report");

        assert!(unsent.is_empty());
        assert_eq!(record_shutdown_handoff_failure(&unsent, &drops), None);
        assert_eq!(drops.handoff_failed(), 0);
        assert_eq!(drops.oversized(), 1);
    }

    #[test]
    fn oversized_drops_join_the_running_drop_total() {
        let drops = LogPushDrops::default();
        drops.record_oversized(2);

        assert_eq!(drops.oversized(), 2);
        assert_eq!(drops.total(), 2);
    }

    #[test]
    fn push_requests_report_the_running_drop_total() {
        let drops = LogPushDrops::default();
        assert_eq!(push_request("sb", Vec::new(), &drops).dropped_total, 0);

        drops.record_channel_full();
        drops.record_backoff_overflow();
        drops.record_backoff_overflow();
        drops.record_handoff_failed(4);

        let request = push_request("sb", vec![test_line("x")], &drops);
        assert_eq!(request.dropped_total, 7);
        assert_eq!(request.sandbox_id, "sb");
        assert_eq!(request.logs.len(), 1);
    }

    #[test]
    fn log_push_requests_remain_uncompressed_for_legacy_gateways() {
        assert!(
            log_push_request_compression().is_none(),
            "supervisors must not require gzip until every supported gateway accepts it"
        );
    }

    #[test]
    fn non_ocsf_lines_carry_no_ocsf_payload() {
        let lines = capture(16, || {
            tracing::info!(target: "test_target", "plain line");
        });
        assert!(lines[0].ocsf_json.is_empty());
        assert_eq!(lines[0].message, "plain line");
    }

    #[test]
    fn ocsf_events_push_with_ocsf_level_and_no_fields() {
        let event = NetworkActivityBuilder::new(&ocsf_ctx())
            .activity(ActivityId::Open)
            .action(ActionId::Denied)
            .disposition(DispositionId::Blocked)
            .severity(SeverityId::Medium)
            .status(StatusId::Failure)
            .dst_endpoint(Endpoint::from_domain("blocked.example.com", 443))
            .message("CONNECT denied blocked.example.com:443".to_string())
            .build();
        let lines = capture(16, || ocsf_emit!(event));

        assert_eq!(lines.len(), 1);
        let line = &lines[0];
        assert_eq!(line.level, "OCSF");
        assert_eq!(line.target, openshell_ocsf::OCSF_TARGET);
        assert_eq!(line.source, "sandbox");
        assert_eq!(line.sandbox_id, "sb-test");
        assert!(line.fields.is_empty());
        assert!(line.timestamp_ms > 0);
    }

    #[test]
    fn non_ocsf_events_use_visitor_extraction() {
        let lines = capture(16, || {
            tracing::info!(target: "test_target", answer = 42, name = "widget", "hello");
        });

        assert_eq!(lines.len(), 1);
        let line = &lines[0];
        assert_eq!(line.level, "INFO");
        assert_eq!(line.target, "test_target");
        assert_eq!(line.source, "sandbox");
        assert_eq!(line.message, "hello");
        assert_eq!(line.fields.get("name").map(String::as_str), Some("widget"));
        assert_eq!(line.fields.get("answer").map(String::as_str), Some("42"));
        assert!(!line.fields.contains_key("message"));
    }

    #[test]
    fn events_without_a_message_field_fall_back_to_the_event_name() {
        let lines = capture(16, || {
            tracing::info!(target: "test_target", answer = 1);
        });

        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].message.starts_with("event "),
            "expected event-name fallback, got {:?}",
            lines[0].message
        );
    }

    #[test]
    fn events_below_the_max_level_are_filtered() {
        let lines = capture(16, || {
            tracing::debug!(target: "test_target", "debug line");
            tracing::trace!(target: "test_target", "trace line");
            tracing::info!(target: "test_target", "info line");
            tracing::warn!(target: "test_target", "warn line");
        });

        let messages: Vec<_> = lines.iter().map(|l| l.message.as_str()).collect();
        assert_eq!(messages, vec!["info line", "warn line"]);
    }

    #[test]
    fn lines_are_dropped_when_the_channel_is_full() {
        let lines = capture(2, || {
            for i in 0..3 {
                tracing::info!(target: "test_target", "line {i}");
            }
        });

        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].message, "line 0");
        assert_eq!(lines[1].message, "line 1");
    }

    #[test]
    fn lines_dropped_on_a_full_channel_are_counted() {
        use tracing_subscriber::layer::SubscriberExt;

        let (tx, _rx) = mpsc::channel::<SandboxLogLine>(2);
        let drops = Arc::new(LogPushDrops::default());
        let layer = LogPushLayer {
            sandbox_id: "sb-test".to_string(),
            tx,
            max_level: tracing::Level::INFO,
            drops: Arc::clone(&drops),
        };
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            for i in 0..5 {
                tracing::info!(target: "test_target", "line {i}");
            }
        });

        // Two fit in the channel; the other three are dropped and counted, so
        // the loss is a countable gap rather than silence.
        assert_eq!(drops.channel_full(), 3);
        assert_eq!(drops.backoff_overflow(), 0);
    }

    #[tokio::test]
    async fn lines_dropped_during_backoff_are_counted() {
        let (tx, mut rx) = mpsc::channel::<SandboxLogLine>(1024);
        for i in 0..250 {
            tx.try_send(test_line(&format!("line {i}"))).unwrap();
        }
        drop(tx);

        let drops = LogPushDrops::default();
        let mut batch = Vec::new();
        drain_during_backoff(
            &mut rx,
            &mut batch,
            tokio::time::Duration::from_secs(30),
            &drops,
        )
        .await;

        assert_eq!(batch.len(), 200);
        assert_eq!(drops.backoff_overflow(), 50);
        assert_eq!(drops.channel_full(), 0);
    }

    #[test]
    fn parse_max_level_defaults_to_info() {
        assert_eq!(parse_max_level(None), tracing::Level::INFO);
        assert_eq!(parse_max_level(Some("not-a-level")), tracing::Level::INFO);
        assert_eq!(parse_max_level(Some("debug")), tracing::Level::DEBUG);
        assert_eq!(parse_max_level(Some("TRACE")), tracing::Level::TRACE);
        assert_eq!(parse_max_level(Some("warn")), tracing::Level::WARN);
    }

    fn test_line(message: &str) -> SandboxLogLine {
        SandboxLogLine {
            sandbox_id: "sb-test".to_string(),
            timestamp_ms: 1,
            level: "INFO".to_string(),
            target: "t".to_string(),
            message: message.to_string(),
            source: "sandbox".to_string(),
            fields: std::collections::HashMap::new(),
            ocsf_json: Vec::new(),
        }
    }

    /// A line whose message is `pad` bytes long, for size-limit tests.
    fn padded_line(index: usize, pad: usize) -> SandboxLogLine {
        let mut line = test_line(&format!("line-{index}"));
        line.message = format!("line-{index}-{}", "x".repeat(pad));
        line
    }

    #[tokio::test]
    async fn drain_during_backoff_keeps_the_newest_lines_at_the_cap() {
        let (tx, mut rx) = mpsc::channel::<SandboxLogLine>(1024);
        for i in 0..250 {
            tx.try_send(test_line(&format!("line {i}"))).unwrap();
        }
        drop(tx);

        let mut batch = Vec::new();
        let drops = LogPushDrops::default();
        drain_during_backoff(
            &mut rx,
            &mut batch,
            tokio::time::Duration::from_secs(30),
            &drops,
        )
        .await;

        assert_eq!(batch.len(), 200);
        assert_eq!(batch[0].message, "line 50");
        assert_eq!(batch[199].message, "line 249");
        assert_eq!(drops.backoff_overflow(), 50);
    }

    #[tokio::test]
    async fn immediate_handoff_failure_observes_auth_failure_without_draining() {
        let (rpc_done_tx, mut rpc_done_rx) = mpsc::channel(1);
        rpc_done_tx.send(true).await.unwrap();
        drop(rpc_done_tx);

        let (tx, mut rx) = mpsc::channel(1);
        tx.send(test_line("fresh")).await.unwrap();
        drop(tx);

        let drops = LogPushDrops::default();
        let mut batch = vec![test_line("retry")];
        let fatal_auth = back_off_after_handoff_failure(
            &mut rpc_done_rx,
            &mut rx,
            &mut batch,
            tokio::time::Duration::from_secs(30),
            &drops,
        )
        .await;

        assert!(fatal_auth);
        assert_eq!(rx.try_recv().unwrap().message, "fresh");
    }

    #[tokio::test]
    async fn immediate_handoff_failure_drains_new_lines_during_backoff() {
        let (rpc_done_tx, mut rpc_done_rx) = mpsc::channel(1);
        rpc_done_tx.send(false).await.unwrap();
        drop(rpc_done_tx);

        let (tx, mut rx) = mpsc::channel(1);
        tx.send(test_line("fresh")).await.unwrap();
        drop(tx);

        let drops = LogPushDrops::default();
        let mut batch = vec![test_line("retry")];
        let fatal_auth = back_off_after_handoff_failure(
            &mut rpc_done_rx,
            &mut rx,
            &mut batch,
            tokio::time::Duration::from_secs(30),
            &drops,
        )
        .await;

        assert!(!fatal_auth);
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].message, "retry");
        assert_eq!(batch[1].message, "fresh");
    }

    #[tokio::test]
    async fn immediate_handoff_failure_waits_for_the_backoff_deadline() {
        let (rpc_done_tx, mut rpc_done_rx) = mpsc::channel(1);
        rpc_done_tx.send(false).await.unwrap();
        drop(rpc_done_tx);

        let (_input_tx, mut rx) = mpsc::channel(1);
        let drops = LogPushDrops::default();
        let mut batch = vec![test_line("retry")];

        let result = tokio::time::timeout(
            tokio::time::Duration::from_millis(10),
            back_off_after_handoff_failure(
                &mut rpc_done_rx,
                &mut rx,
                &mut batch,
                tokio::time::Duration::from_secs(1),
                &drops,
            ),
        )
        .await;

        assert!(
            result.is_err(),
            "retry must not spin before backoff elapses"
        );
    }

    #[tokio::test]
    async fn drain_during_backoff_preserves_an_existing_batch() {
        let (tx, mut rx) = mpsc::channel::<SandboxLogLine>(16);
        tx.try_send(test_line("new")).unwrap();
        drop(tx);

        let mut batch = vec![test_line("buffered")];
        let drops = LogPushDrops::default();
        drain_during_backoff(
            &mut rx,
            &mut batch,
            tokio::time::Duration::from_secs(30),
            &drops,
        )
        .await;

        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].message, "buffered");
        assert_eq!(batch[1].message, "new");
    }

    #[tokio::test]
    async fn drain_during_backoff_returns_early_when_the_channel_closes() {
        let (tx, mut rx) = mpsc::channel::<SandboxLogLine>(16);
        tx.try_send(test_line("last")).unwrap();
        drop(tx);

        let mut batch = Vec::new();
        let drops = LogPushDrops::default();
        tokio::time::timeout(
            tokio::time::Duration::from_secs(5),
            drain_during_backoff(
                &mut rx,
                &mut batch,
                tokio::time::Duration::from_secs(30),
                &drops,
            ),
        )
        .await
        .expect("closed channel should end the backoff drain");

        assert_eq!(batch.len(), 1);
    }

    #[test]
    fn log_visitor_into_parts_uses_the_fallback_only_without_a_message() {
        let visitor = LogVisitor {
            message: Some("explicit".to_string()),
            fields: vec![("k".to_string(), "v".to_string())],
        };
        let (msg, fields) = visitor.into_parts("fallback");
        assert_eq!(msg, "explicit");
        assert_eq!(fields.get("k").map(String::as_str), Some("v"));

        let (msg, fields) = LogVisitor::default().into_parts("fallback");
        assert_eq!(msg, "fallback");
        assert!(fields.is_empty());
    }
}
