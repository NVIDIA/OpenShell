// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded buffers of enriched, encoded batches between the receiver and the
//! export task, one per signal.
//!
//! Sending never blocks and never drops silently: a full buffer surfaces as
//! [`BufferFull`] so the receiver can answer 503 and the agent SDK retries.

use bytes::Bytes;
use tokio::sync::mpsc;

use super::Signal;

/// The buffer has no room for another batch.
#[derive(Debug, PartialEq, Eq)]
pub enum SendError {
    /// Capacity reached; the batch was not buffered.
    BufferFull,
    /// The export task is gone; the batch was not buffered.
    BufferClosed,
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BufferFull => f.write_str("relay buffer is full"),
            Self::BufferClosed => f.write_str("relay buffer is closed"),
        }
    }
}

impl std::error::Error for SendError {}

/// Producer side, held by the receiver.
/// Not `Clone`: the receiver holds the only sender, so closing the buffer
/// at shutdown ends the export task's input.
pub struct BatchSender {
    queues: [mpsc::Sender<Bytes>; Signal::ALL.len()],
}

impl BatchSender {
    /// Buffers `batch` of `signal` without waiting.
    pub fn try_send(&self, signal: Signal, batch: Bytes) -> Result<(), SendError> {
        self.queues[signal.index()]
            .try_send(batch)
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => SendError::BufferFull,
                mpsc::error::TrySendError::Closed(_) => SendError::BufferClosed,
            })
    }
}

/// Consumer side, held by the export task.
pub struct BatchReceiver {
    queues: [mpsc::Receiver<Bytes>; Signal::ALL.len()],
}

impl BatchReceiver {
    /// Next buffered batch, or `None` once every sender has been dropped and
    /// the buffer is drained. Traces go before logs and logs before metrics
    /// when several are waiting; arrival order holds within a signal.
    pub async fn recv(&mut self) -> Option<(Signal, Bytes)> {
        let [traces, logs, metrics] = &mut self.queues;
        tokio::select! {
            biased;
            Some(batch) = traces.recv() => Some((Signal::Traces, batch)),
            Some(batch) = logs.recv() => Some((Signal::Logs, batch)),
            Some(batch) = metrics.recv() => Some((Signal::Metrics, batch)),
            else => None,
        }
    }
}

/// Creates a buffer holding at most `capacity` trace batches and a quarter
/// of that, rounded up, for each of logs and metrics.
pub fn new_buffer(capacity: usize) -> (BatchSender, BatchReceiver) {
    let (senders, receivers): (Vec<_>, Vec<_>) = Signal::ALL
        .map(|signal| {
            let capacity = match signal {
                Signal::Traces => capacity,
                Signal::Logs | Signal::Metrics => capacity.div_ceil(4),
            };
            mpsc::channel(capacity)
        })
        .into_iter()
        .unzip();
    (
        BatchSender {
            queues: senders.try_into().expect("one queue per signal"),
        },
        BatchReceiver {
            queues: receivers.try_into().expect("one queue per signal"),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: Signal = Signal::Traces;

    #[tokio::test]
    async fn capacity_is_honoured_and_full_is_reported() {
        let (tx, mut rx) = new_buffer(32);
        for i in 0..32u8 {
            tx.try_send(T, Bytes::from(vec![i])).unwrap();
        }
        assert_eq!(
            tx.try_send(T, Bytes::from_static(b"x")),
            Err(SendError::BufferFull)
        );
        assert_eq!(rx.recv().await.unwrap(), (T, Bytes::from(vec![0u8])));
        tx.try_send(T, Bytes::from_static(b"x")).unwrap();
    }

    #[tokio::test]
    async fn a_full_signal_does_not_block_the_others() {
        let (tx, mut rx) = new_buffer(32);
        for _ in 0..8 {
            tx.try_send(Signal::Logs, Bytes::from_static(b"l")).unwrap();
        }
        assert_eq!(
            tx.try_send(Signal::Logs, Bytes::from_static(b"l")),
            Err(SendError::BufferFull)
        );
        tx.try_send(Signal::Metrics, Bytes::from_static(b"m"))
            .unwrap();
        tx.try_send(T, Bytes::from_static(b"t")).unwrap();
        assert_eq!(rx.recv().await.unwrap().0, T);
        assert_eq!(rx.recv().await.unwrap().0, Signal::Logs);
    }

    #[tokio::test]
    async fn recv_returns_none_after_the_sender_drops() {
        let (tx, mut rx) = new_buffer(4);
        tx.try_send(T, Bytes::from_static(b"a")).unwrap();
        tx.try_send(Signal::Metrics, Bytes::from_static(b"b"))
            .unwrap();
        drop(tx);
        assert_eq!(rx.recv().await.unwrap(), (T, Bytes::from_static(b"a")));
        assert_eq!(
            rx.recv().await.unwrap(),
            (Signal::Metrics, Bytes::from_static(b"b"))
        );
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn send_after_receiver_drop_reports_closed() {
        let (tx, rx) = new_buffer(4);
        drop(rx);
        assert_eq!(
            tx.try_send(T, Bytes::from_static(b"a")),
            Err(SendError::BufferClosed)
        );
    }
}
