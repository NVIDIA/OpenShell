// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runtime events the middleware runtime reports to its embedder.
//!
//! This crate does not log. The supervisor attaches a
//! [`MiddlewareRuntimeObserver`] that turns these events into OCSF records, and
//! polls [`crate::ChainRunner::take_reconciliation_request`] to re-describe
//! middleware services after a contract failure.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::{HttpDirection, HttpProtocol};

/// Start of the status message `tonic-prost` reports for every
/// `prost::DecodeError`: it maps the error to `INTERNAL` with the error's
/// `Display` text, which always begins with this prefix.
const DECODE_FAILURE_PREFIX: &str = "failed to decode Protobuf message";
const CONTRACT_FAILURE_REASON_PREFIX: &str = "middleware_contract_failure_";

/// Wire-contract failure from an HTTP middleware RPC.
///
/// A contract failure always fails the exchange closed, regardless of
/// `on_error`, and requests registry reconciliation. Without that, a service
/// swapped to a version 2-only build behind a cached legacy manifest would be
/// skipped under `fail_open`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContractFailureKind {
    /// The service does not implement the RPC its binding selects.
    Unimplemented,
    /// A message from the service could not be decoded.
    Decode,
    /// A version 2 result was unset or used an unknown alternative.
    UnknownResult,
}

impl ContractFailureKind {
    /// Classify a status returned by an HTTP middleware RPC.
    #[must_use]
    pub fn from_status(status: &tonic::Status) -> Option<Self> {
        match status.code() {
            tonic::Code::Unimplemented => Some(Self::Unimplemented),
            tonic::Code::Internal if status.message().starts_with(DECODE_FAILURE_PREFIX) => {
                Some(Self::Decode)
            }
            _ => None,
        }
    }

    /// Stable, audit-safe name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unimplemented => "unimplemented",
            Self::Decode => "decode_failure",
            Self::UnknownResult => "unknown_result",
        }
    }

    /// Platform-owned failure reason recorded for the failed stage.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Unimplemented => "middleware_contract_failure_unimplemented",
            Self::Decode => "middleware_contract_failure_decode_failure",
            Self::UnknownResult => "middleware_contract_failure_unknown_result",
        }
    }

    /// Recover the kind from a failure reason built by [`Self::reason`].
    #[must_use]
    pub fn from_reason(reason: &str) -> Option<Self> {
        match reason.strip_prefix(CONTRACT_FAILURE_REASON_PREFIX)? {
            "unimplemented" => Some(Self::Unimplemented),
            "decode_failure" => Some(Self::Decode),
            "unknown_result" => Some(Self::UnknownResult),
            _ => None,
        }
    }
}

/// Contract failure on one HTTP stage. The exchange failed closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractFailure {
    /// Policy-local middleware config name.
    pub config_name: String,
    /// Built-in name or operator-owned registration name.
    pub implementation: String,
    pub direction: HttpDirection,
    pub protocol: HttpProtocol,
    pub kind: ContractFailureKind,
}

/// A `fail_open` entry that runs fail-closed because its binding uses version
/// 2 of the HTTP protocol, which never fails open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailOpenNotApplied {
    /// Policy-local middleware config name.
    pub config_name: String,
    /// Built-in name or operator-owned registration name.
    pub implementation: String,
    pub direction: HttpDirection,
    /// True when the middleware also has a WebSocket or legacy HTTP binding,
    /// where `fail_open` still applies. False means no binding honors it: the
    /// policy predates the service's switch to version 2 HTTP only, or keeps
    /// `fail_open` only for uninspectable traffic.
    pub applies_elsewhere: bool,
}

/// Receives runtime events from every registry generation of one runner.
///
/// Methods run on the request path and must not block.
pub trait MiddlewareRuntimeObserver: Send + Sync {
    /// An HTTP stage broke the wire contract and failed closed.
    fn contract_failure(&self, failure: &ContractFailure);

    /// A `fail_open` entry runs fail-closed on a version 2 HTTP binding. This
    /// is reported on every chain description, so implementations
    /// deduplicate.
    fn fail_open_not_applied(&self, entry: &FailOpenNotApplied);

    /// The embedder checked for a reconciliation request, which it does once
    /// per reconciliation interval. Contract failures reported after this
    /// belong to the next interval.
    fn reconciliation_interval_ended(&self) {}
}

/// Hooks shared by every registry generation of one runner, like its
/// admission budgets.
#[derive(Default)]
pub struct RuntimeHooks {
    observer: Option<Arc<dyn MiddlewareRuntimeObserver>>,
    reconciliation_requested: AtomicBool,
}

impl RuntimeHooks {
    pub fn with_observer(observer: Arc<dyn MiddlewareRuntimeObserver>) -> Self {
        Self {
            observer: Some(observer),
            reconciliation_requested: AtomicBool::new(false),
        }
    }

    pub fn contract_failure(&self, failure: &ContractFailure) {
        self.reconciliation_requested.store(true, Ordering::Release);
        if let Some(observer) = &self.observer {
            observer.contract_failure(failure);
        }
    }

    pub fn fail_open_not_applied(&self, entry: &FailOpenNotApplied) {
        if let Some(observer) = &self.observer {
            observer.fail_open_not_applied(entry);
        }
    }

    pub fn take_reconciliation_request(&self) -> bool {
        if let Some(observer) = &self.observer {
            observer.reconciliation_interval_ended();
        }
        self.reconciliation_requested.swap(false, Ordering::AcqRel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message as _;

    #[test]
    fn classifies_unimplemented_and_codec_decode_failures_only() {
        assert_eq!(
            ContractFailureKind::from_status(&tonic::Status::unimplemented("no such method")),
            Some(ContractFailureKind::Unimplemented)
        );
        let decode_error = openshell_core::proto::HttpResult::decode(&b"\x0a\x05\x01"[..])
            .expect_err("truncated message must not decode");
        assert_eq!(
            ContractFailureKind::from_status(&tonic::Status::internal(decode_error.to_string())),
            Some(ContractFailureKind::Decode)
        );
        for status in [
            tonic::Status::internal("service error"),
            tonic::Status::unavailable("connection refused"),
            tonic::Status::deadline_exceeded("timed out"),
            tonic::Status::invalid_argument("failed to decode Protobuf message"),
        ] {
            assert_eq!(ContractFailureKind::from_status(&status), None);
        }
    }

    #[derive(Default)]
    struct IntervalCounter(std::sync::atomic::AtomicUsize);

    impl MiddlewareRuntimeObserver for IntervalCounter {
        fn contract_failure(&self, _failure: &ContractFailure) {}

        fn fail_open_not_applied(&self, _entry: &FailOpenNotApplied) {}

        fn reconciliation_interval_ended(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn every_reconciliation_check_ends_an_interval() {
        let counter = Arc::new(IntervalCounter::default());
        let hooks = RuntimeHooks::with_observer(counter.clone());
        assert!(!hooks.take_reconciliation_request());
        hooks.contract_failure(&ContractFailure {
            config_name: "guard".into(),
            implementation: "example/guard".into(),
            direction: HttpDirection::Request,
            protocol: HttpProtocol::V2,
            kind: ContractFailureKind::Unimplemented,
        });
        assert!(hooks.take_reconciliation_request());
        assert_eq!(counter.0.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn failure_reasons_round_trip() {
        for kind in [
            ContractFailureKind::Unimplemented,
            ContractFailureKind::Decode,
            ContractFailureKind::UnknownResult,
        ] {
            assert_eq!(ContractFailureKind::from_reason(kind.reason()), Some(kind));
            assert!(kind.reason().ends_with(kind.as_str()));
        }
        assert_eq!(ContractFailureKind::from_reason("middleware_timeout"), None);
    }
}
