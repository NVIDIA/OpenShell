// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Denial aggregator — collects and deduplicates proxy deny events.
//!
//! The proxy emits a [`DenialEvent`] each time a connection or request is
//! denied. The [`DenialAggregator`] receives these events via an MPSC channel,
//! deduplicates them by `(host, port, binary)` key, and maintains running
//! counters. Periodically, the aggregator flushes accumulated summaries
//! upstream to the gateway via `SubmitPolicyAnalysis`.

use std::collections::HashMap;
use std::future::Future;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::debug;

/// A single denial event emitted by the proxy.
#[derive(Debug, Clone)]
pub struct DenialEvent {
    /// Destination host that was denied.
    pub host: String,
    /// Destination port that was denied.
    pub port: u16,
    /// Binary path that initiated the connection (if resolved).
    pub binary: String,
    /// Ancestor binary paths from process tree walk.
    pub ancestors: Vec<String>,
    /// Reason for denial (e.g. "no matching policy", "internal address").
    pub deny_reason: String,
    /// Denial stage: "connect", "forward", "ssrf", "l7", "bypass".
    pub denial_stage: String,
    /// L7 request details (method, path, decision) if this is an L7 denial.
    pub l7_method: Option<String>,
    /// L7 target path.
    pub l7_path: Option<String>,
}

/// Aggregated denial summary keyed by `(host, port, binary)`.
#[derive(Debug, Clone)]
struct AggregatedDenial {
    host: String,
    port: u16,
    binary: String,
    ancestors: Vec<String>,
    deny_reason: String,
    denial_stage: String,
    first_seen_ms: i64,
    last_seen_ms: i64,
    count: u32,
    sample_cmdlines: Vec<String>,
    l7_samples: Vec<L7Sample>,
}

/// A single L7 request sample for aggregation.
#[derive(Debug, Clone)]
struct L7Sample {
    method: String,
    path: String,
    count: u32,
}

/// The denial aggregator collects proxy deny events and periodically flushes
/// summaries. It is designed to be spawned as a background tokio task.
pub struct DenialAggregator {
    rx: mpsc::UnboundedReceiver<DenialEvent>,
    /// Accumulated denials keyed by `(host, port, binary)`.
    summaries: HashMap<(String, u16, String), AggregatedDenial>,
    /// Flush interval in seconds.
    flush_interval_secs: u64,
}

impl DenialAggregator {
    /// Create a new aggregator that reads from the given channel.
    pub fn new(rx: mpsc::UnboundedReceiver<DenialEvent>, flush_interval_secs: u64) -> Self {
        Self {
            rx,
            summaries: HashMap::new(),
            flush_interval_secs,
        }
    }

    /// Run the aggregator loop. This consumes `self` and runs until the
    /// channel is closed (all senders are dropped).
    ///
    /// `flush_callback` is called periodically with the accumulated summaries.
    /// In production this calls `SubmitPolicyAnalysis` on the gateway.
    pub async fn run<F, Fut>(mut self, flush_callback: F)
    where
        F: Fn(Vec<FlushableDenialSummary>) -> Fut,
        Fut: Future<Output = ()>,
    {
        let mut flush_interval =
            tokio::time::interval(std::time::Duration::from_secs(self.flush_interval_secs));
        // Don't fire immediately on first tick.
        flush_interval.tick().await;

        loop {
            tokio::select! {
                event = self.rx.recv() => {
                    if let Some(evt) = event {
                        self.ingest(evt);
                    } else {
                        // Channel closed; do a final flush and exit.
                        if !self.summaries.is_empty() {
                            let batch = self.drain();
                            flush_callback(batch).await;
                        }
                        debug!("DenialAggregator: channel closed, exiting");
                        return;
                    }
                }
                _ = flush_interval.tick() => {
                    if !self.summaries.is_empty() {
                        let batch = self.drain();
                        debug!(count = batch.len(), "DenialAggregator: flushing summaries");
                        flush_callback(batch).await;
                    }
                }
            }
        }
    }

    /// Ingest a single denial event, merging into existing summary or creating
    /// a new one.
    fn ingest(&mut self, event: DenialEvent) {
        let now_ms = current_time_ms();
        let key = (event.host.clone(), event.port, event.binary.clone());

        let entry = self
            .summaries
            .entry(key)
            .or_insert_with(|| AggregatedDenial {
                host: event.host.clone(),
                port: event.port,
                binary: event.binary.clone(),
                ancestors: event.ancestors.clone(),
                deny_reason: event.deny_reason.clone(),
                denial_stage: event.denial_stage.clone(),
                first_seen_ms: now_ms,
                last_seen_ms: now_ms,
                count: 0,
                sample_cmdlines: Vec::new(),
                l7_samples: Vec::new(),
            });

        entry.count += 1;
        entry.last_seen_ms = now_ms;

        // Merge L7 samples.
        if let (Some(method), Some(path)) = (&event.l7_method, &event.l7_path) {
            if let Some(sample) = entry
                .l7_samples
                .iter_mut()
                .find(|s| s.method == *method && s.path == *path)
            {
                sample.count += 1;
            } else if entry.l7_samples.len() < 20 {
                entry.l7_samples.push(L7Sample {
                    method: method.clone(),
                    path: path.clone(),
                    count: 1,
                });
            }
        }
    }

    /// Drain all accumulated summaries into a flushable batch.
    fn drain(&mut self) -> Vec<FlushableDenialSummary> {
        self.summaries
            .drain()
            .map(|(_, v)| FlushableDenialSummary {
                host: v.host,
                port: v.port,
                binary: v.binary,
                ancestors: v.ancestors,
                deny_reason: v.deny_reason,
                denial_stage: v.denial_stage,
                first_seen_ms: v.first_seen_ms,
                last_seen_ms: v.last_seen_ms,
                count: v.count,
                sample_cmdlines: v.sample_cmdlines,
                l7_samples: v
                    .l7_samples
                    .into_iter()
                    .map(|s| FlushableL7Sample {
                        method: s.method,
                        path: s.path,
                        count: s.count,
                    })
                    .collect(),
            })
            .collect()
    }
}

/// A denial summary ready to be sent to the gateway.
#[derive(Debug, Clone)]
pub struct FlushableDenialSummary {
    pub host: String,
    pub port: u16,
    pub binary: String,
    pub ancestors: Vec<String>,
    pub deny_reason: String,
    pub denial_stage: String,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    pub count: u32,
    pub sample_cmdlines: Vec<String>,
    pub l7_samples: Vec<FlushableL7Sample>,
}

/// L7 request sample in flushable form.
#[derive(Debug, Clone)]
pub struct FlushableL7Sample {
    pub method: String,
    pub path: String,
    pub count: u32,
}

fn current_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}
