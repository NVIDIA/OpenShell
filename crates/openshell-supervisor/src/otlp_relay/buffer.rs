// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded buffer of enriched, encoded trace batches between the receiver
//! and the export task.
//!
//! Sending never blocks and never drops silently: a full buffer surfaces as
//! [`BufferFull`] so the receiver can answer 503 and the agent SDK retries.

use bytes::Bytes;
use tokio::sync::mpsc;

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
    tx: mpsc::Sender<Bytes>,
}

impl BatchSender {
    /// Buffers `batch` without waiting.
    pub fn try_send(&self, batch: Bytes) -> Result<(), SendError> {
        self.tx.try_send(batch).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => SendError::BufferFull,
            mpsc::error::TrySendError::Closed(_) => SendError::BufferClosed,
        })
    }
}

/// Consumer side, held by the export task.
pub struct BatchReceiver {
    rx: mpsc::Receiver<Bytes>,
}

impl BatchReceiver {
    /// Next buffered batch in arrival order, or `None` once every sender has
    /// been dropped and the buffer is drained.
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.rx.recv().await
    }
}

/// Creates a buffer holding at most `capacity` batches.
pub fn new_buffer(capacity: usize) -> (BatchSender, BatchReceiver) {
    let (tx, rx) = mpsc::channel(capacity);
    (BatchSender { tx }, BatchReceiver { rx })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn capacity_is_honoured_and_full_is_reported() {
        let (tx, mut rx) = new_buffer(32);
        for i in 0..32u8 {
            tx.try_send(Bytes::from(vec![i])).unwrap();
        }
        assert_eq!(
            tx.try_send(Bytes::from_static(b"x")),
            Err(SendError::BufferFull)
        );
        assert_eq!(rx.recv().await.unwrap(), Bytes::from(vec![0u8]));
        tx.try_send(Bytes::from_static(b"x")).unwrap();
    }

    #[tokio::test]
    async fn recv_returns_none_after_the_sender_drops() {
        let (tx, mut rx) = new_buffer(4);
        tx.try_send(Bytes::from_static(b"a")).unwrap();
        drop(tx);
        assert_eq!(rx.recv().await.unwrap(), Bytes::from_static(b"a"));
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn send_after_receiver_drop_reports_closed() {
        let (tx, rx) = new_buffer(4);
        drop(rx);
        assert_eq!(
            tx.try_send(Bytes::from_static(b"a")),
            Err(SendError::BufferClosed)
        );
    }
}
