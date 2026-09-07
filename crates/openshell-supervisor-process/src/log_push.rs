// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Push sandbox tracing events to the `OpenShell` server via gRPC.
//!
//! A [`tracing`] layer captures log events and sends them through an mpsc
//! channel to a background task. The task batches lines and streams them to
//! the server using the `PushSandboxLogs` client-streaming RPC.

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
}

impl LogPushLayer {
    pub fn new(sandbox_id: String, tx: mpsc::Sender<SandboxLogLine>) -> Self {
        let max_level = parse_max_level(std::env::var("OPENSHELL_LOG_PUSH_LEVEL").ok().as_deref());
        Self {
            sandbox_id,
            tx,
            max_level,
        }
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

        // OCSF events carry their payload in a thread-local; extract the
        // shorthand representation for the push message. Non-OCSF events
        // use the original visitor-based extraction.
        let (msg, fields) = if meta.target() == openshell_ocsf::OCSF_TARGET {
            if let Some(ocsf_event) = openshell_ocsf::clone_current_event() {
                (
                    ocsf_event.format_shorthand(),
                    std::collections::HashMap::new(),
                )
            } else {
                return;
            }
        } else {
            let mut visitor = LogVisitor::default();
            event.record(&mut visitor);
            visitor.into_parts(meta.name())
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
        };

        // Best-effort: drop if the channel is full (don't block tracing).
        let _ = self.tx.try_send(log);
    }
}

/// Spawn a background task that batches and pushes log lines to the server.
///
/// Returns the sender half of the channel (for the [`LogPushLayer`]) and the
/// task handle. The task runs until the sender is dropped or the gRPC stream
/// breaks.
pub fn spawn_log_push_task(
    endpoint: String,
    sandbox_id: String,
) -> (mpsc::Sender<SandboxLogLine>, tokio::task::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel::<SandboxLogLine>(1024);

    let handle = tokio::spawn(run_push_loop(endpoint, sandbox_id, rx));

    (tx, handle)
}

/// Maximum backoff delay between reconnection attempts.
const MAX_BACKOFF: tokio::time::Duration = tokio::time::Duration::from_secs(30);
/// Initial backoff delay after a connection failure.
const INITIAL_BACKOFF: tokio::time::Duration = tokio::time::Duration::from_secs(1);

async fn run_push_loop(
    endpoint: String,
    sandbox_id: String,
    mut rx: mpsc::Receiver<SandboxLogLine>,
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
                // block, but discard lines we can't deliver.
                drain_during_backoff(&mut rx, &mut batch, backoff).await;
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
            if push_tx
                .send(PushSandboxLogsRequest {
                    sandbox_id: sandbox_id.clone(),
                    logs: lines,
                })
                .await
                .is_err()
            {
                // RPC died immediately — go back to reconnect.
                backoff = INITIAL_BACKOFF;
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
                            let _ = push_tx.send(PushSandboxLogsRequest {
                                sandbox_id: sandbox_id.clone(),
                                logs: lines,
                            }).await;
                        }
                        return;
                    };
                    batch.push(line);
                    if batch.len() >= 50 {
                        let lines = std::mem::take(&mut batch);
                        if push_tx.send(PushSandboxLogsRequest {
                            sandbox_id: sandbox_id.clone(),
                            logs: lines,
                        }).await.is_err() {
                            break true;
                        }
                    }
                }
                _ = timer.tick() => {
                    if !batch.is_empty() {
                        let lines = std::mem::take(&mut batch);
                        if push_tx.send(PushSandboxLogsRequest {
                            sandbox_id: sandbox_id.clone(),
                            logs: lines,
                        }).await.is_err() {
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
            drain_during_backoff(&mut rx, &mut batch, backoff).await;
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
                        if batch.len() < MAX_BUFFERED {
                            batch.push(l);
                        }
                        // else: drop — we're over the reconnect buffer limit
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
        }
    }

    /// Capture lines emitted by `f` with an `INFO` level filter.
    fn capture(capacity: usize, f: impl FnOnce()) -> Vec<SandboxLogLine> {
        let (tx, mut rx) = mpsc::channel::<SandboxLogLine>(capacity);
        let layer = LogPushLayer {
            sandbox_id: "sb-test".to_string(),
            tx,
            max_level: tracing::Level::INFO,
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
    fn ocsf_events_push_shorthand_with_ocsf_level_and_no_fields() {
        let event = NetworkActivityBuilder::new(&ocsf_ctx())
            .activity(ActivityId::Open)
            .action(ActionId::Denied)
            .disposition(DispositionId::Blocked)
            .severity(SeverityId::Medium)
            .status(StatusId::Failure)
            .dst_endpoint(Endpoint::from_domain("blocked.example.com", 443))
            .message("CONNECT denied blocked.example.com:443".to_string())
            .build();
        let expected_shorthand = event.format_shorthand();

        let lines = capture(16, || ocsf_emit!(event));

        assert_eq!(lines.len(), 1);
        let line = &lines[0];
        assert_eq!(line.level, "OCSF");
        assert_eq!(line.target, openshell_ocsf::OCSF_TARGET);
        assert_eq!(line.source, "sandbox");
        assert_eq!(line.sandbox_id, "sb-test");
        assert_eq!(line.message, expected_shorthand);
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
        }
    }

    #[tokio::test]
    async fn drain_during_backoff_buffers_up_to_the_cap_and_drops_the_rest() {
        let (tx, mut rx) = mpsc::channel::<SandboxLogLine>(1024);
        for i in 0..250 {
            tx.try_send(test_line(&format!("line {i}"))).unwrap();
        }
        drop(tx);

        let mut batch = Vec::new();
        drain_during_backoff(&mut rx, &mut batch, tokio::time::Duration::from_secs(30)).await;

        assert_eq!(batch.len(), 200);
        assert_eq!(batch[0].message, "line 0");
        assert_eq!(batch[199].message, "line 199");
    }

    #[tokio::test]
    async fn drain_during_backoff_preserves_an_existing_batch() {
        let (tx, mut rx) = mpsc::channel::<SandboxLogLine>(16);
        tx.try_send(test_line("new")).unwrap();
        drop(tx);

        let mut batch = vec![test_line("buffered")];
        drain_during_backoff(&mut rx, &mut batch, tokio::time::Duration::from_secs(30)).await;

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
        tokio::time::timeout(
            tokio::time::Duration::from_secs(5),
            drain_during_backoff(&mut rx, &mut batch, tokio::time::Duration::from_secs(30)),
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
