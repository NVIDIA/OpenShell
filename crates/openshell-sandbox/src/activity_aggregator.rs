// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Anonymous sandbox network activity counter aggregation.
//!
//! Producer-side types (`ActivityEvent`, `ActivitySender`,
//! `ACTIVITY_EVENT_QUEUE_CAPACITY`, `try_record_activity`) live in
//! `openshell_core::activity` so the supervisor leaves can emit without
//! depending on the orchestrator. This module hosts the aggregator that
//! runs orchestrator-side and flushes summaries to the gateway.

use std::collections::HashMap;
use std::future::Future;
use tokio::sync::mpsc;
use tracing::debug;

pub use openshell_core::activity::ActivityEvent;

const ACTIVITY_FLUSH_QUEUE_CAPACITY: usize = 1;
pub const DEFAULT_ACTIVITY_FLUSH_INTERVAL_SECS: u64 = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlushableActivitySummary {
    pub network_activity_count: u32,
    pub denied_action_count: u32,
    pub denials_by_group: Vec<(String, u32)>,
}

pub struct ActivityAggregator {
    rx: mpsc::Receiver<ActivityEvent>,
    network_activity_count: u32,
    denied_action_count: u32,
    denials_by_group: HashMap<String, u32>,
    flush_interval_secs: u64,
}

impl ActivityAggregator {
    pub fn new(rx: mpsc::Receiver<ActivityEvent>, flush_interval_secs: u64) -> Self {
        Self {
            rx,
            network_activity_count: 0,
            denied_action_count: 0,
            denials_by_group: HashMap::new(),
            flush_interval_secs,
        }
    }

    pub async fn run<F, Fut>(mut self, flush_callback: F)
    where
        F: Fn(FlushableActivitySummary) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let (flush_tx, mut flush_rx) =
            mpsc::channel::<FlushableActivitySummary>(ACTIVITY_FLUSH_QUEUE_CAPACITY);
        tokio::spawn(async move {
            while let Some(summary) = flush_rx.recv().await {
                flush_callback(summary).await;
            }
        });

        let mut flush_interval =
            tokio::time::interval(std::time::Duration::from_secs(self.flush_interval_secs));
        flush_interval.tick().await;

        loop {
            tokio::select! {
                event = self.rx.recv() => {
                    if let Some(event) = event {
                        self.ingest(event);
                    } else {
                        if let Some(summary) = self.drain() {
                            queue_flush_summary(&flush_tx, summary);
                        }
                        debug!("ActivityAggregator: channel closed, exiting");
                        return;
                    }
                }
                _ = flush_interval.tick() => {
                    if let Some(summary) = self.drain() {
                        debug!(
                            count = summary.network_activity_count,
                            denied = summary.denied_action_count,
                            "ActivityAggregator: flushing anonymous activity summary"
                        );
                        queue_flush_summary(&flush_tx, summary);
                    }
                }
            }
        }
    }

    fn ingest(&mut self, event: ActivityEvent) {
        self.network_activity_count = self.network_activity_count.saturating_add(1);
        if event.denied {
            self.denied_action_count = self.denied_action_count.saturating_add(1);
            let group = sanitize_deny_group(event.deny_group).to_string();
            let count = self.denials_by_group.entry(group).or_default();
            *count = count.saturating_add(1);
        }
    }

    fn drain(&mut self) -> Option<FlushableActivitySummary> {
        if self.network_activity_count == 0 {
            return None;
        }
        let mut denials_by_group: Vec<(String, u32)> = self.denials_by_group.drain().collect();
        denials_by_group.sort_by(|left, right| left.0.cmp(&right.0));
        let summary = FlushableActivitySummary {
            network_activity_count: self.network_activity_count,
            denied_action_count: self.denied_action_count,
            denials_by_group,
        };
        self.network_activity_count = 0;
        self.denied_action_count = 0;
        Some(summary)
    }
}

pub fn activity_flush_interval_secs_from_env(value: Option<&str>) -> u64 {
    value
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_ACTIVITY_FLUSH_INTERVAL_SECS)
}

fn queue_flush_summary(
    tx: &mpsc::Sender<FlushableActivitySummary>,
    summary: FlushableActivitySummary,
) -> bool {
    tx.try_send(summary).is_ok()
}

pub fn sanitize_deny_group(raw: &str) -> &'static str {
    match raw {
        "connect_policy" | "connect" | "l4_deny" => "connect_policy",
        "forward_policy" | "forward" => "forward_policy",
        "l7_policy" | "l7" | "l7_deny" | "forward-l7-deny" => "l7_policy",
        "l7_parse_rejection" | "parse_rejection" => "l7_parse_rejection",
        "ssrf" => "ssrf",
        "bypass" => "bypass",
        "policy_stale" => "policy_stale",
        _ => "unknown",
    }
}

#[cfg(test)]
fn denial_rate_pct(network_activity_count: u32, denied_action_count: u32) -> f64 {
    if network_activity_count == 0 {
        return 0.0;
    }
    ((f64::from(denied_action_count) / f64::from(network_activity_count)) * 100.0).clamp(0.0, 100.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_float_eq(actual: f64, expected: f64) {
        assert!((actual - expected).abs() <= f64::EPSILON);
    }

    #[test]
    fn deny_group_sanitization_uses_allowlist() {
        assert_eq!(sanitize_deny_group("connect"), "connect_policy");
        assert_eq!(sanitize_deny_group("forward-l7-deny"), "l7_policy");
        assert_eq!(sanitize_deny_group("host=example.test/path"), "unknown");
        assert_eq!(sanitize_deny_group("acme.internal:443"), "unknown");
        assert_eq!(
            sanitize_deny_group("binary=/usr/local/bin/private"),
            "unknown"
        );
    }

    #[test]
    fn denial_rate_handles_zero_and_clamps() {
        assert_float_eq(denial_rate_pct(0, 10), 0.0);
        assert_float_eq(denial_rate_pct(4, 1), 25.0);
        assert_float_eq(denial_rate_pct(4, 10), 100.0);
    }

    #[test]
    fn flush_summary_drops_when_queue_is_full() {
        let (tx, _rx) = mpsc::channel(1);
        let summary = FlushableActivitySummary {
            network_activity_count: 1,
            denied_action_count: 0,
            denials_by_group: Vec::new(),
        };

        assert!(queue_flush_summary(&tx, summary.clone()));
        assert!(!queue_flush_summary(&tx, summary));
    }

    #[test]
    fn activity_flush_interval_uses_positive_values_only() {
        assert_eq!(
            activity_flush_interval_secs_from_env(None),
            DEFAULT_ACTIVITY_FLUSH_INTERVAL_SECS
        );
        assert_eq!(
            activity_flush_interval_secs_from_env(Some("not-a-number")),
            DEFAULT_ACTIVITY_FLUSH_INTERVAL_SECS
        );
        assert_eq!(
            activity_flush_interval_secs_from_env(Some("0")),
            DEFAULT_ACTIVITY_FLUSH_INTERVAL_SECS
        );
        assert_eq!(activity_flush_interval_secs_from_env(Some("5")), 5);
    }
}
