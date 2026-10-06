// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded stdin delivery without blocking the shared SSH session callback.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use ryno_isolation_interface::contract::BoundaryInput;
use tokio::io::AsyncWriteExt;
use tokio::sync::Notify;
use tokio::task::{AbortHandle, JoinHandle};

/// Includes queued bytes and the chunk currently being written. Consumed bytes
/// release capacity, so this is not a limit on the total command input size.
pub(super) const MAX_PENDING_INPUT: usize = 4 * 1024 * 1024;
const WRITE_CHUNK: usize = 16 * 1024;

#[derive(Default)]
struct Buffer {
    // Coalescing packets avoids unbounded per-message overhead for tiny writes.
    bytes: VecDeque<u8>,
    in_flight: usize,
    closed: bool,
}

#[derive(Default)]
struct Shared {
    buffer: Mutex<Buffer>,
    ready: Notify,
}

pub(super) struct InputSender(Arc<Shared>);

#[derive(Debug, PartialEq, Eq)]
pub(super) enum SendError {
    Full,
    Closed,
}

impl InputSender {
    pub(super) fn send(&self, bytes: &[u8]) -> Result<(), SendError> {
        let mut buffer = self.0.buffer.lock().map_err(|_| SendError::Closed)?;
        if buffer.closed {
            return Err(SendError::Closed);
        }
        if bytes.len() > MAX_PENDING_INPUT - buffer.bytes.len() - buffer.in_flight {
            return Err(SendError::Full);
        }
        buffer.bytes.extend(bytes);
        drop(buffer);
        self.0.ready.notify_one();
        Ok(())
    }
}

impl Drop for InputSender {
    fn drop(&mut self) {
        if let Ok(mut buffer) = self.0.buffer.lock() {
            buffer.closed = true;
        }
        // EOF wakes an idle writer but leaves accepted bytes to drain.
        self.0.ready.notify_one();
    }
}

/// The channel owns cancellation independently of stdin EOF. Dropping a task
/// handle alone would detach it and retain a blocked write and its queued input.
pub(super) struct InputTask {
    shared: Arc<Shared>,
    task: JoinHandle<()>,
}

impl InputTask {
    pub(super) fn spawn(stdin: BoundaryInput) -> (InputSender, Self) {
        let shared = Arc::new(Shared::default());
        let receiver = Receiver(shared.clone());
        let task = tokio::spawn(receiver.write_to(stdin));
        (InputSender(shared.clone()), Self { shared, task })
    }

    pub(super) fn abort_handle(&self) -> AbortHandle {
        self.task.abort_handle()
    }
}

impl Drop for InputTask {
    fn drop(&mut self) {
        // Release queued allocations even before the runtime polls the aborted
        // writer. Its in-flight chunk and stdin are released when it is dropped.
        if let Ok(mut buffer) = self.shared.buffer.lock() {
            buffer.closed = true;
            buffer.bytes = VecDeque::new();
        }
        self.task.abort();
    }
}

struct Receiver(Arc<Shared>);

impl Receiver {
    async fn write_to(self, mut stdin: BoundaryInput) {
        loop {
            let ready = self.0.ready.notified();
            let chunk = {
                let Ok(mut buffer) = self.0.buffer.lock() else {
                    break;
                };
                if buffer.bytes.is_empty() && buffer.closed {
                    break;
                }
                let size = buffer.bytes.len().min(WRITE_CHUNK);
                buffer.in_flight = size;
                buffer.bytes.drain(..size).collect::<Vec<_>>()
            };
            if chunk.is_empty() {
                ready.await;
                continue;
            }
            if stdin.write_all(&chunk).await.is_err() {
                break;
            }
            let Ok(mut buffer) = self.0.buffer.lock() else {
                break;
            };
            buffer.in_flight = 0;
        }
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        // A failed or cancelled writer must refuse later input and release the
        // queue even if the SSH channel has not yet received a close packet.
        if let Ok(mut buffer) = self.0.buffer.lock() {
            buffer.closed = true;
            buffer.in_flight = 0;
            buffer.bytes = VecDeque::new();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn bound_includes_in_flight_input_and_rejects_before_copying() {
        let (stdin, mut reader) = tokio::io::duplex(1);
        let (sender, _task) = InputTask::spawn(Box::new(stdin));
        assert_eq!(
            sender.send(&vec![0; MAX_PENDING_INPUT + 1]),
            Err(SendError::Full)
        );
        assert_eq!(sender.0.buffer.lock().unwrap().bytes.capacity(), 0);
        sender.send(&vec![42; MAX_PENDING_INPUT]).unwrap();
        // Once the one-byte pipe is full, the rest of this chunk is retained
        // by write_all and must still count against the pending-byte budget.
        reader.read_u8().await.unwrap();
        assert_eq!(sender.send(&[1]), Err(SendError::Full));
        let buffer = sender.0.buffer.lock().unwrap();
        assert_eq!(buffer.bytes.len() + buffer.in_flight, MAX_PENDING_INPUT);
        assert_eq!(buffer.in_flight, WRITE_CHUNK);
    }

    #[tokio::test]
    async fn tiny_packets_share_one_byte_buffer_and_eof_drains_them() {
        let (stdin, mut reader) = tokio::io::duplex(64 * 1024);
        let (sender, _task) = InputTask::spawn(Box::new(stdin));
        for _ in 0..8192 {
            sender.send(&[42]).unwrap();
        }
        drop(sender);
        let mut received = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            reader.read_to_end(&mut received),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(received, vec![42; 8192]);
    }
}
