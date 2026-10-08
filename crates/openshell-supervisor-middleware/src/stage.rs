// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Version 2 HTTP stage transport and stage report sink.
//!
//! A pipeline drives each selected HTTP stage through one
//! [`HttpStageTransport`]: it sends [`HttpEvent`]s on a bounded channel and
//! reads [`openshell_core::proto::HttpResult`]s from the returned stream.
//! Version 2 services open an `EvaluateHttp` stream. A legacy HTTP adapter
//! implements the same transport inside the supervisor by translating events
//! to the legacy RPCs, and reports outcomes that version 2 results cannot
//! express to a [`StageReportSink`].

use std::collections::BTreeMap;
use std::sync::Mutex;

use openshell_core::proto::{
    Finding, HttpEvent, SupervisorMiddlewareOperation, SupervisorMiddlewarePhase,
};
use tokio::sync::mpsc;

use crate::HttpResultStream;

/// Direction of one HTTP middleware exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpDirection {
    /// `HTTP_REQUEST` at `PRE_CREDENTIALS`.
    Request,
    /// `HTTP_RESPONSE` at `PRE_RETURN`.
    Response,
}

impl HttpDirection {
    #[must_use]
    pub const fn operation(self) -> SupervisorMiddlewareOperation {
        match self {
            Self::Request => SupervisorMiddlewareOperation::HttpRequest,
            Self::Response => SupervisorMiddlewareOperation::HttpResponse,
        }
    }

    #[must_use]
    pub const fn phase(self) -> SupervisorMiddlewarePhase {
        match self {
            Self::Request => SupervisorMiddlewarePhase::PreCredentials,
            Self::Response => SupervisorMiddlewarePhase::PreReturn,
        }
    }

    /// Direction of an HTTP operation, or `None` for other operations.
    #[must_use]
    pub fn from_operation(operation: SupervisorMiddlewareOperation) -> Option<Self> {
        match operation {
            SupervisorMiddlewareOperation::HttpRequest => Some(Self::Request),
            SupervisorMiddlewareOperation::HttpResponse => Some(Self::Response),
            SupervisorMiddlewareOperation::Unspecified
            | SupervisorMiddlewareOperation::WebsocketMessage => None,
        }
    }

    /// Stable, audit-safe name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Request => "http_request",
            Self::Response => "http_response",
        }
    }
}

/// Opens version 2 stage exchanges for one resolved chain entry.
///
/// The caller keeps the sending half of `events`, starts with preflight, and
/// reads one result per event that requires one. Dropping the sender ends the
/// exchange. Classify transport errors with
/// [`crate::ContractFailureKind::from_status`] before applying stage failure
/// handling, because contract failures always fail closed.
#[tonic::async_trait]
pub trait HttpStageTransport: Send + Sync {
    /// Open one exchange.
    async fn open(
        &self,
        events: mpsc::Receiver<HttpEvent>,
    ) -> Result<HttpResultStream, tonic::Status>;
}

/// Outcome a stage reports beside its results.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum StageReport {
    /// HTTP protocol 1 (0.1). Removed in 0.2.0.
    ///
    /// A legacy stage failed and `fail_open` passed its original input on.
    /// `reason` is a platform-owned failure reason, never service text.
    LegacyFailOpen { reason: String },
    /// HTTP protocol 1 (0.1). Removed in 0.2.0.
    ///
    /// One step of a legacy response stage, as the 0.1.x engine recorded it,
    /// with the normalized findings and metadata of that step's result.
    /// Version 2 results cannot express per-unit outcomes, so legacy response
    /// stages report their invocation telemetry and diagnostics here as each
    /// step completes.
    LegacyResponseInvocation {
        invocation: crate::HttpResponseInvocation,
        findings: Vec<Finding>,
        metadata: BTreeMap<String, String>,
    },
}

impl StageReport {
    /// Reason of a `fail_open` pass-through, if this report is one.
    #[must_use]
    pub fn fail_open_reason(&self) -> Option<&str> {
        match self {
            Self::LegacyFailOpen { reason } => Some(reason),
            Self::LegacyResponseInvocation { .. } => None,
        }
    }
}

/// Receives stage reports for one exchange, in the order stages produce them.
pub trait StageReportSink: Send + Sync {
    /// Record `report` for the policy-local middleware config `config_name`.
    fn report(&self, config_name: &str, report: StageReport);
}

/// [`StageReportSink`] that retains reports for the relay to drain once the
/// exchange ends.
#[derive(Debug, Default)]
pub struct StageReports {
    reports: Mutex<Vec<(String, StageReport)>>,
}

impl StageReports {
    /// Take every report recorded so far, in arrival order.
    pub fn drain(&self) -> Vec<(String, StageReport)> {
        std::mem::take(
            &mut *self
                .reports
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Take the reports recorded so far for `config_name`, in arrival order.
    pub fn take(&self, config_name: &str) -> Vec<StageReport> {
        let mut reports = self
            .reports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (taken, kept) = std::mem::take(&mut *reports)
            .into_iter()
            .partition::<Vec<_>, _>(|(name, _)| name == config_name);
        *reports = kept;
        taken.into_iter().map(|(_, report)| report).collect()
    }
}

impl StageReportSink for StageReports {
    fn report(&self, config_name: &str, report: StageReport) {
        self.reports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((config_name.to_string(), report));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directions_map_to_their_operation_and_phase() {
        for direction in [HttpDirection::Request, HttpDirection::Response] {
            assert_eq!(
                HttpDirection::from_operation(direction.operation()),
                Some(direction)
            );
        }
        assert_eq!(
            HttpDirection::Response.phase(),
            SupervisorMiddlewarePhase::PreReturn
        );
        assert_eq!(
            HttpDirection::from_operation(SupervisorMiddlewareOperation::WebsocketMessage),
            None
        );
    }

    #[test]
    fn collected_reports_drain_in_arrival_order() {
        let reports = StageReports::default();
        let sink: &dyn StageReportSink = &reports;
        sink.report(
            "first",
            StageReport::LegacyFailOpen {
                reason: "middleware_timeout".into(),
            },
        );
        sink.report(
            "second",
            StageReport::LegacyFailOpen {
                reason: "external_service_error".into(),
            },
        );
        let drained = reports.drain();
        assert_eq!(
            drained
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            ["first", "second"]
        );
        assert!(reports.drain().is_empty());
    }

    #[test]
    fn reports_for_one_stage_are_taken_without_the_others() {
        let reports = StageReports::default();
        for name in ["first", "second", "first"] {
            reports.report(
                name,
                StageReport::LegacyFailOpen {
                    reason: name.into(),
                },
            );
        }
        assert_eq!(reports.take("first").len(), 2);
        assert!(reports.take("first").is_empty());
        assert_eq!(reports.drain().len(), 1);
    }
}
