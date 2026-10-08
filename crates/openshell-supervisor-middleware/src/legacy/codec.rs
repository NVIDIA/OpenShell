// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Plumbing shared by the legacy adapters.
//!
//! An adapter presents one legacy HTTP middleware as a version 2 stage. It
//! runs as an independent task, as a remote service would: it reads
//! [`HttpEvent`]s from the pipeline, calls the legacy RPC, and writes version
//! 2 results back. The pipeline must read results while it sends events,
//! because an adapter stops reading events while its result queue is full.
//!
//! Contract failures from the legacy RPC pass through unchanged, so the
//! pipeline classifies them with [`crate::ContractFailureKind::from_status`].
//! Every other failure of the legacy service follows the entry's 0.1.x
//! `on_error` inside the adapter, which still holds the stage's input:
//! `fail_open` passes the input on and reports
//! [`crate::StageReport::LegacyFailOpen`], and `fail_closed` ends the result
//! stream with a [`LegacyStageFailure`]. A pipeline that breaks an adapter's
//! preconditions gets a [`LegacyStageFailure`] whatever `on_error` says.

use std::collections::HashMap;
use std::future::Future;

use tokio::sync::mpsc;

use openshell_core::proto::{Finding, HttpEvent, HttpResult, MiddlewareDiagnostics, http_result};

use crate::HttpResultStream;

/// Results a legacy stage task may queue before the pipeline reads them.
const RESULT_CHANNEL_CAPACITY: usize = 4;
/// Message of every status a legacy adapter fails its stage closed with.
const STAGE_FAILURE_MESSAGE: &str = "legacy HTTP middleware stage failed closed";

/// HTTP protocol 1 (0.1). Removed in 0.2.0.
///
/// A legacy stage that failed closed.
///
/// The adapter ends its result stream with this failure encoded as a status.
/// After classifying contract failures, the pipeline recovers it with
/// [`Self::from_status`] and fails the exchange with
/// `middleware_failed: {reason}`, as 0.1.x did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyStageFailure {
    /// Platform-owned failure reason, such as `middleware_timeout`.
    pub reason: String,
}

impl LegacyStageFailure {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    /// Recover a failure a legacy adapter ended its result stream with.
    /// `None` for every other status.
    #[must_use]
    pub fn from_status(status: &tonic::Status) -> Option<Self> {
        if status.code() != tonic::Code::Aborted || status.message() != STAGE_FAILURE_MESSAGE {
            return None;
        }
        String::from_utf8(status.details().to_vec())
            .ok()
            .filter(|reason| !reason.is_empty())
            .map(Self::new)
    }

    pub(super) fn into_status(self) -> tonic::Status {
        tonic::Status::with_details(
            tonic::Code::Aborted,
            STAGE_FAILURE_MESSAGE,
            self.reason.into_bytes().into(),
        )
    }
}

/// The pipeline broke an adapter precondition, so the stage fails closed
/// whatever `on_error` says.
pub(super) fn invariant_failure(reason: &str) -> tonic::Status {
    LegacyStageFailure::new(reason).into_status()
}

/// An event arrived out of the version 2 order.
pub(super) fn event_order_failure() -> tonic::Status {
    invariant_failure("legacy_stage_event_order_invalid")
}

/// Sending half of one stage's result stream.
pub(super) struct Results(mpsc::Sender<Result<HttpResult, tonic::Status>>);

impl Results {
    /// Queue one result. False when the pipeline stopped reading.
    pub(super) async fn send(&self, result: http_result::Result) -> bool {
        self.0
            .send(Ok(HttpResult {
                result: Some(result),
            }))
            .await
            .is_ok()
    }

    /// End the stream with `status`.
    pub(super) async fn fail(&self, status: tonic::Status) {
        let _ = self.0.send(Err(status)).await;
    }

    /// Run `future` unless the pipeline stops reading results first, which
    /// abandons the exchange.
    pub(super) async fn unless_closed<T>(&self, future: impl Future<Output = T>) -> Option<T> {
        tokio::select! {
            biased;
            () = self.0.closed() => None,
            value = future => Some(value),
        }
    }
}

/// Run one stage codec as its own task and return its result stream.
pub(super) fn spawn_stage<F>(codec: impl FnOnce(Results) -> F) -> HttpResultStream
where
    F: Future<Output = ()> + Send + 'static,
{
    let (sender, receiver) = mpsc::channel(RESULT_CHANNEL_CAPACITY);
    tokio::spawn(codec(Results(sender)));
    Box::pin(tokio_stream::wrappers::ReceiverStream::new(receiver))
}

/// Diagnostics for a version 2 result. Service reason text is never carried:
/// 0.1.x discarded it, and the codes and findings are already validated and
/// normalized.
pub(super) fn diagnostics(
    reason_code: String,
    findings: Vec<Finding>,
    metadata: HashMap<String, String>,
) -> Option<MiddlewareDiagnostics> {
    (!reason_code.is_empty() || !findings.is_empty() || !metadata.is_empty()).then(|| {
        MiddlewareDiagnostics {
            reason: String::new(),
            reason_code,
            findings,
            metadata,
        }
    })
}

/// Next event, skipping events without an alternative.
pub(super) async fn next_event(
    events: &mut mpsc::Receiver<HttpEvent>,
) -> Option<openshell_core::proto::http_event::Event> {
    loop {
        if let Some(event) = events.recv().await?.event {
            return Some(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_failures_round_trip_through_their_status() {
        let failure = LegacyStageFailure::new("middleware_timeout");
        let status = failure.clone().into_status();
        assert_eq!(LegacyStageFailure::from_status(&status), Some(failure));
        assert_eq!(crate::ContractFailureKind::from_status(&status), None);
    }

    #[test]
    fn other_statuses_are_not_stage_failures() {
        for status in [
            tonic::Status::aborted(STAGE_FAILURE_MESSAGE),
            tonic::Status::with_details(
                tonic::Code::Aborted,
                STAGE_FAILURE_MESSAGE,
                vec![0xff].into(),
            ),
            tonic::Status::aborted("middleware_timeout"),
            tonic::Status::with_details(
                tonic::Code::Unimplemented,
                STAGE_FAILURE_MESSAGE,
                b"middleware_timeout".to_vec().into(),
            ),
        ] {
            assert_eq!(LegacyStageFailure::from_status(&status), None, "{status}");
        }
    }
}
