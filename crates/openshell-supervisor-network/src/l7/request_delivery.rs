// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Observes local upstream writes without deciding whether a request is allowed.

use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};

/// Local forwarding progress; completion does not prove upstream processing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RequestDeliveryState {
    NotStarted,
    Started,
    Completed,
}

/// Shared by the body runner and its writer so cancellation retains progress.
#[derive(Clone, Debug, Default)]
pub(crate) struct RequestDelivery(Arc<AtomicU8>);

impl RequestDelivery {
    /// Observe a header write, retaining Started even if only a prefix is sent.
    pub(crate) async fn write_all<W: tokio::io::AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
        bytes: &[u8],
    ) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt as _;
        self.start();
        writer.write_all(bytes).await
    }

    /// Call before awaiting a write, because an error can follow a partial write.
    pub(crate) fn start(&self) {
        let _ = self
            .0
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire);
    }

    /// Call only after every local body/framing write succeeds.
    pub(crate) fn complete(&self) {
        self.0.store(2, Ordering::Release);
    }

    pub(crate) fn state(&self) -> RequestDeliveryState {
        match self.0.load(Ordering::Acquire) {
            0 => RequestDeliveryState::NotStarted,
            1 => RequestDeliveryState::Started,
            // Only start and complete can write this private atomic.
            _ => RequestDeliveryState::Completed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    struct PartialWriter(Vec<u8>);

    impl tokio::io::AsyncWrite for PartialWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.0.is_empty() {
                self.0.extend_from_slice(&bytes[..2]);
                Poll::Ready(Ok(2))
            } else {
                Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
            }
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn partial_header_write_is_observed_before_error() {
        let delivery = RequestDelivery::default();
        let observer = delivery.clone();
        assert_eq!(observer.state(), RequestDeliveryState::NotStarted);
        let mut writer = PartialWriter(Vec::new());
        let error = delivery
            .write_all(&mut writer, b"POST / HTTP/1.1\r\n\r\n")
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        assert_eq!(writer.0, b"PO");
        assert_eq!(observer.state(), RequestDeliveryState::Started);
    }
}
