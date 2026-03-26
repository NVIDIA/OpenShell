// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Push sandbox tracing events to the OpenShell server via gRPC.
//!
//! A [`tracing`] layer captures log events and sends them through an mpsc
//! channel to a background task. The task batches lines and streams them to
//! the server using the `PushSandboxLogs` client-streaming RPC.

use crate::grpc_client::CachedOpenShellClient;
use openshell_core::proto::{PushSandboxLogsRequest, SandboxLogLine};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

/// Tracing layer that pushes log events to the OpenShell server.
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
        let max_level = std::env::var("OPENSHELL_LOG_PUSH_LEVEL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(tracing::Level::INFO);
        Self {
            sandbox_id,
            tx,
            max_level,
        }
    }
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

        let ts = current_time_ms().unwrap_or(0);

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
        // `rpc_done_tx` fires so the batch loop below knows to reconnect.
        let (rpc_done_tx, mut rpc_done_rx) = mpsc::channel::<()>(1);
        tokio::spawn({
            let mut nav_client = client.raw_client();
            async move {
                if let Err(e) = nav_client.push_sandbox_logs(stream).await {
                    eprintln!("openshell: log push RPC failed: {e}");
                }
                let _ = rpc_done_tx.send(()).await;
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
                _ = rpc_done_rx.recv() => {
                    // The gRPC streaming call ended (server closed / error).
                    break true;
                }
            }
        };

        if stream_broken {
            eprintln!("openshell: log push stream lost, reconnecting...");
            backoff = INITIAL_BACKOFF;
            // Loop back to reconnect.
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
            _ = tokio::time::sleep_until(deadline) => { return; }
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

fn current_time_ms() -> Option<i64> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    i64::try_from(now.as_millis()).ok()
}
