// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Upload channels are exec channels whose stdin credit follows consumption.
//!
//! Russh replenishes SSH receive credit before `data()` runs, so the channel
//! reports how many archive bytes extraction stdin accepted. Stdout carries
//! only those totals; extraction output is sent as stderr so it cannot forge
//! credit. The SSH exit status reports the result.

use super::input::{InputProgress, InputState};
use openshell_core::upload::{ACK_INTERVAL_BYTES, PlanError, PlanReader, UploadPlan, WINDOW_BYTES};
use openshell_sandbox_backend::BoundaryProcess;
use russh::ChannelId;
use russh::server::Handle;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::{AbortHandle, JoinHandle};

// Honest clients cannot reach the general pending-input guard.
const _: () = assert!(WINDOW_BYTES < super::input::MAX_PENDING_INPUT as u64);
/// A successful `cat | tar` exit follows stdin EOF, so the writer publishes
/// its drained state almost immediately.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) struct Upload {
    plan: Option<PlanReader>,
    received: u64,
    progress: Option<watch::Receiver<InputProgress>>,
    process: Option<Arc<BoundaryProcess>>,
    acks: Option<AbortHandle>,
    /// Set by whichever side reports the result: the exit task or a rejection.
    reported: Arc<AtomicBool>,
}

impl Upload {
    pub(super) fn new() -> Self {
        Self {
            plan: Some(PlanReader::default()),
            received: 0,
            progress: None,
            process: None,
            acks: None,
            reported: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(super) const fn awaiting_plan(&self) -> bool {
        self.plan.is_some()
    }

    /// Consume plan bytes, leaving archive bytes that follow it in `input`.
    pub(super) fn read_plan(&mut self, input: &mut &[u8]) -> Result<Option<UploadPlan>, PlanError> {
        let plan = self
            .plan
            .as_mut()
            .map_or(Ok(None), |reader| reader.read(input))?;
        if plan.is_some() {
            self.plan = None;
        }
        Ok(plan)
    }

    /// Report extraction progress and return the exit task's finisher.
    pub(super) fn start(
        &mut self,
        channel: ChannelId,
        handle: Handle,
        progress: watch::Receiver<InputProgress>,
        process: Arc<BoundaryProcess>,
    ) -> Finisher {
        let acks = tokio::spawn(send_acks(
            handle,
            channel,
            progress.clone(),
            process.clone(),
        ));
        self.acks = Some(acks.abort_handle());
        self.progress = Some(progress.clone());
        self.process = Some(process);
        Finisher {
            channel,
            progress,
            acks,
            reported: self.reported.clone(),
        }
    }

    /// Whether `bytes` more fit in the credit granted to the client.
    pub(super) fn admits(&self, bytes: usize) -> bool {
        let consumed = self
            .progress
            .as_ref()
            .map_or(0, |progress| progress.borrow().consumed);
        self.received + bytes as u64 - consumed <= WINDOW_BYTES
    }

    pub(super) fn record(&mut self, bytes: usize) {
        self.received += bytes as u64;
    }

    /// Claim the result for a rejection. False means the result was reported.
    pub(super) fn reject(&self) -> bool {
        !self.reported.swap(true, Ordering::AcqRel)
    }
}

impl Drop for Upload {
    fn drop(&mut self) {
        if let Some(acks) = self.acks.take() {
            acks.abort();
        }
        // Disconnects drop channel state without a close request.
        if self.reject()
            && let Some(process) = self.process.take()
        {
            tokio::spawn(async move {
                let _ = process.terminate().await;
            });
        }
    }
}

pub(super) struct Finisher {
    channel: ChannelId,
    progress: watch::Receiver<InputProgress>,
    acks: JoinHandle<()>,
    reported: Arc<AtomicBool>,
}

impl Finisher {
    /// Send the final total for a successful extraction and return the exit
    /// status to report, or `None` when a rejection already reported it.
    pub(super) async fn finish(mut self, handle: &Handle, code: u32) -> Option<u32> {
        self.acks.abort();
        let _ = (&mut self.acks).await;
        let drained = code == 0
            && matches!(
                tokio::time::timeout(
                    DRAIN_TIMEOUT,
                    self.progress.wait_for(|progress| progress.state != InputState::Writing),
                )
                .await,
                Ok(Ok(progress)) if progress.state == InputState::Drained
            );
        if self.reported.swap(true, Ordering::AcqRel) {
            return None;
        }
        if code != 0 {
            return Some(code);
        }
        if !drained {
            return Some(74);
        }
        let consumed = self.progress.borrow().consumed;
        let _ = handle.data(self.channel, ack(consumed)).await;
        Some(0)
    }
}

fn ack(consumed: u64) -> Vec<u8> {
    consumed.to_be_bytes().to_vec()
}

async fn send_acks(
    handle: Handle,
    channel: ChannelId,
    mut progress: watch::Receiver<InputProgress>,
    process: Arc<BoundaryProcess>,
) {
    // Zero tells the client that extraction started.
    if handle.data(channel, ack(0)).await.is_err() {
        return;
    }
    let mut acknowledged = 0;
    while progress.changed().await.is_ok() {
        let latest = *progress.borrow_and_update();
        if latest.state == InputState::Failed {
            // The extractor stopped reading; its exit status explains why.
            let _ = process.terminate().await;
            return;
        }
        if latest.consumed - acknowledged >= ACK_INTERVAL_BYTES {
            if handle.data(channel, ack(latest.consumed)).await.is_err() {
                return;
            }
            acknowledged = latest.consumed;
        }
    }
}
