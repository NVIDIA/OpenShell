// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded stdin delivery without blocking the shared SSH session callback.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use openshell_isolation_interface::contract::BoundaryInput;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Notify, watch};
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
    progress: Option<watch::Sender<InputProgress>>,
}

/// A watch keeps only the newest consumed offset even when SSH output stalls.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct InputProgress {
    pub(super) consumed: u64,
    pub(super) state: InputState,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum InputState {
    #[default]
    Writing,
    Drained,
    Failed,
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
        Self::spawn_inner(stdin, None)
    }

    pub(super) fn spawn_with_progress(
        stdin: BoundaryInput,
    ) -> (InputSender, Self, watch::Receiver<InputProgress>) {
        let (progress, receiver) = watch::channel(InputProgress::default());
        let (sender, task) = Self::spawn_inner(stdin, Some(progress));
        (sender, task, receiver)
    }

    fn spawn_inner(
        stdin: BoundaryInput,
        progress: Option<watch::Sender<InputProgress>>,
    ) -> (InputSender, Self) {
        let shared = Arc::new(Shared {
            progress,
            ..Shared::default()
        });
        let receiver = Receiver {
            shared: shared.clone(),
            consumed: 0,
            finished: false,
        };
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

struct Receiver {
    shared: Arc<Shared>,
    consumed: u64,
    finished: bool,
}

impl Receiver {
    fn publish(&self, state: InputState) {
        if let Some(progress) = &self.shared.progress {
            progress.send_replace(InputProgress {
                consumed: self.consumed,
                state,
            });
        }
    }

    async fn write_to(mut self, mut stdin: BoundaryInput) {
        loop {
            let ready = self.shared.ready.notified();
            let chunk = {
                let Ok(mut buffer) = self.shared.buffer.lock() else {
                    return;
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
                return;
            }
            {
                let Ok(mut buffer) = self.shared.buffer.lock() else {
                    return;
                };
                buffer.in_flight = 0;
            }
            self.consumed += chunk.len() as u64;
            self.publish(InputState::Writing);
        }
        // Ordinary exec retains its existing drop-to-close behavior. Upload
        // needs an explicit shutdown result before claiming the drain complete.
        if self.shared.progress.is_none() || stdin.shutdown().await.is_ok() {
            self.finished = true;
            self.publish(InputState::Drained);
        }
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        // A failed or cancelled writer must refuse later input and release the
        // queue even if the SSH channel has not yet received a close packet.
        if let Ok(mut buffer) = self.shared.buffer.lock() {
            buffer.closed = true;
            buffer.in_flight = 0;
            buffer.bytes = VecDeque::new();
        }
        if !self.finished {
            self.publish(InputState::Failed);
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

    #[tokio::test]
    async fn progress_is_earned_after_complete_writes_and_reports_drain() {
        let (stdin, mut reader) = tokio::io::duplex(1);
        let (sender, _task, mut progress) = InputTask::spawn_with_progress(Box::new(stdin));
        sender.send(&vec![42; WRITE_CHUNK]).unwrap();
        reader.read_u8().await.unwrap();
        assert_eq!(progress.borrow().consumed, 0);
        drop(sender);
        let mut remaining = Vec::new();
        reader.read_to_end(&mut remaining).await.unwrap();
        assert_eq!(remaining, vec![42; WRITE_CHUNK - 1]);
        progress
            .wait_for(|progress| progress.state == InputState::Drained)
            .await
            .unwrap();
        assert_eq!(progress.borrow().consumed, WRITE_CHUNK as u64);
    }

    #[tokio::test]
    async fn failed_writer_publishes_terminal_state_and_refuses_input() {
        let (stdin, reader) = tokio::io::duplex(1);
        let (sender, _task, mut progress) = InputTask::spawn_with_progress(Box::new(stdin));
        drop(reader);
        sender.send(b"write fails").unwrap();
        progress
            .wait_for(|progress| progress.state == InputState::Failed)
            .await
            .unwrap();
        assert_eq!(progress.borrow().consumed, 0);
        assert_eq!(sender.send(b"later input"), Err(SendError::Closed));
    }

    #[tokio::test]
    async fn shutdown_failure_preserves_consumption_without_claiming_drain() {
        struct ShutdownFails(tokio::io::DuplexStream);

        impl tokio::io::AsyncWrite for ShutdownFails {
            fn poll_write(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                bytes: &[u8],
            ) -> std::task::Poll<std::io::Result<usize>> {
                std::pin::Pin::new(&mut self.0).poll_write(cx, bytes)
            }

            fn poll_flush(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::pin::Pin::new(&mut self.0).poll_flush(cx)
            }

            fn poll_shutdown(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Err(std::io::Error::other("shutdown failed")))
            }
        }

        let (stdin, mut reader) = tokio::io::duplex(1024);
        let (sender, _task, mut progress) =
            InputTask::spawn_with_progress(Box::new(ShutdownFails(stdin)));
        sender.send(b"consumed before shutdown").unwrap();
        drop(sender);
        let mut received = Vec::new();
        reader.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"consumed before shutdown");
        progress
            .wait_for(|progress| progress.state == InputState::Failed)
            .await
            .unwrap();
        assert_eq!(progress.borrow().consumed, received.len() as u64);
    }
}
