// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded telemetry buffer with ring-buffer drop semantics.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use tokio::sync::mpsc;

/// Distinguishes trace data from OCSF events in the shared buffer.
#[derive(Debug)]
pub enum TelemetryItem {
    Trace(Vec<u8>),
    Ocsf(Vec<u8>),
}

/// Shared drop/depth counters for the buffer.
#[derive(Debug, Clone)]
pub struct BufferMetrics {
    drop_count: Arc<AtomicU64>,
    queue_depth: Arc<AtomicUsize>,
}

impl BufferMetrics {
    pub fn drops(&self) -> u64 {
        self.drop_count.load(Ordering::Relaxed)
    }

    pub fn depth(&self) -> usize {
        self.queue_depth.load(Ordering::Relaxed)
    }
}

/// Sender half of the telemetry buffer. Implements ring-buffer drop semantics:
/// when the buffer is full, the send still succeeds but the oldest entry is
/// lost and the drop counter increments.
#[derive(Clone)]
pub struct TelemetrySender {
    tx: mpsc::Sender<TelemetryItem>,
    metrics: BufferMetrics,
}

impl TelemetrySender {
    /// Send a telemetry item into the buffer. If the channel is full, the
    /// item is dropped and the drop counter is incremented.
    pub fn send(&self, item: TelemetryItem) {
        match self.tx.try_send(item) {
            Ok(()) => {
                self.metrics.queue_depth.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                self.metrics.drop_count.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn send_trace(&self, data: Vec<u8>) {
        self.send(TelemetryItem::Trace(data));
    }

    pub fn send_ocsf(&self, data: Vec<u8>) {
        self.send(TelemetryItem::Ocsf(data));
    }

    pub fn metrics(&self) -> &BufferMetrics {
        &self.metrics
    }
}

/// Receiver half of the telemetry buffer.
pub struct TelemetryReceiver {
    rx: mpsc::Receiver<TelemetryItem>,
    metrics: BufferMetrics,
}

impl TelemetryReceiver {
    /// Receive the next buffered entry, or `None` if all senders are dropped.
    pub async fn recv(&mut self) -> Option<TelemetryItem> {
        let item = self.rx.recv().await;
        if item.is_some() {
            self.metrics.queue_depth.fetch_sub(1, Ordering::Relaxed);
        }
        item
    }

    /// Drain all currently buffered entries without waiting.
    pub fn drain(&mut self) -> Vec<TelemetryItem> {
        let mut items = Vec::new();
        while let Ok(item) = self.rx.try_recv() {
            self.metrics.queue_depth.fetch_sub(1, Ordering::Relaxed);
            items.push(item);
        }
        items
    }

    pub fn metrics(&self) -> &BufferMetrics {
        &self.metrics
    }
}

/// Create a new telemetry buffer pair with the given capacity.
pub fn new_telemetry_buffer(capacity: usize) -> (TelemetrySender, TelemetryReceiver) {
    let (tx, rx) = mpsc::channel(capacity);
    let metrics = BufferMetrics {
        drop_count: Arc::new(AtomicU64::new(0)),
        queue_depth: Arc::new(AtomicUsize::new(0)),
    };
    (
        TelemetrySender {
            tx,
            metrics: metrics.clone(),
        },
        TelemetryReceiver { rx, metrics },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn buffer_drops_when_full() {
        let (tx, mut rx) = new_telemetry_buffer(2);

        tx.send_trace(vec![1]);
        tx.send_trace(vec![2]);
        tx.send_trace(vec![3]);

        assert_eq!(tx.metrics().drops(), 1);
        assert_eq!(tx.metrics().depth(), 2);

        let first = rx.recv().await.unwrap();
        assert!(matches!(first, TelemetryItem::Trace(v) if v == vec![1]));
        assert_eq!(rx.metrics().depth(), 1);
    }

    #[tokio::test]
    async fn drain_empties_buffer() {
        let (tx, mut rx) = new_telemetry_buffer(16);

        tx.send_trace(vec![1]);
        tx.send_ocsf(vec![2]);
        tx.send_trace(vec![3]);

        let items = rx.drain();
        assert_eq!(items.len(), 3);
        assert!(matches!(&items[0], TelemetryItem::Trace(_)));
        assert!(matches!(&items[1], TelemetryItem::Ocsf(_)));
        assert_eq!(rx.metrics().depth(), 0);
    }
}
