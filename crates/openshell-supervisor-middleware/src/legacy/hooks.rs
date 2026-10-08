// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP protocol 1 (0.1). Removed in 0.2.0.
//!
//! Engine integration points for legacy HTTP adapter stages. An adapter
//! implements [`HttpStageTransport`] inside the supervisor: it answers
//! preflight locally, translates body events to the legacy RPCs, and reports
//! `fail_open` outcomes to the exchange's [`StageReportSink`]. The stage
//! pipeline calls these functions for resolved legacy entries only; version 2
//! entries never get legacy engine behavior.

use std::sync::{Arc, OnceLock};

use openshell_core::proto::HttpBodyMode;
use tokio::time::Instant;

use super::codec::LegacyStageFailure;
use super::request::{LegacyRequestExchange, LegacyRequestStage, legacy_request_collection_limit};
use crate::{
    DescribedChainEntry, HttpDirection, HttpProtocol, HttpStageTransport,
    MAX_MIDDLEWARE_CHAIN_TIMEOUT, OnError, StageReportSink,
};

/// What the pipeline gives a legacy adapter stage when it opens it.
#[derive(Clone)]
pub struct LegacyStageContext {
    /// The legacy entry. Its service, binding, payload limit, timeout, and
    /// `on_error` are visible inside the crate.
    pub entry: DescribedChainEntry,
    pub direction: HttpDirection,
    /// Lowercased names nominated by the message's `Connection` fields.
    /// Mutations must treat them as hop-by-hop.
    pub connection_nominated_headers: Arc<[String]>,
    /// The exchange's 0.1.x chain deadline, shared by its legacy stages.
    pub chain_clock: LegacyChainClock,
    /// Receives this exchange's [`crate::StageReport`]s. Report before
    /// sending the result the report qualifies: the pipeline records a stage
    /// that reports `LegacyFailOpen` with its `Continue` or `Unchanged`
    /// result as failed open.
    pub reports: Arc<dyn StageReportSink>,
}

/// The 30 s chain deadline 0.1.x applied across a chain's legacy
/// evaluations. 0.1.x started it once the body was collected, so it starts
/// when the first legacy stage of the exchange begins a body evaluation.
/// Each legacy RPC runs under `entry.timeout()` capped by it.
#[derive(Clone, Debug, Default)]
pub struct LegacyChainClock {
    deadline: Arc<OnceLock<Instant>>,
}

impl LegacyChainClock {
    /// Start the clock if it has not started, and return the deadline.
    pub fn deadline(&self) -> Instant {
        *self
            .deadline
            .get_or_init(|| Instant::now() + MAX_MIDDLEWARE_CHAIN_TIMEOUT)
    }

    /// A clock whose deadline has already passed.
    #[cfg(test)]
    pub fn expired() -> Self {
        let clock = Self::default();
        let _ = clock.deadline.set(Instant::now());
        clock
    }
}

/// Open the adapter transport for a legacy entry, or `None` while the
/// direction has no adapter.
///
/// Legacy request entries run on the request adapter (`legacy::request`).
/// Legacy response entries run on the legacy response engine until the
/// response cutover (`legacy::response::adapter`), and the pipeline fails a
/// legacy response entry closed if one reaches it.
pub fn open_stage(context: &LegacyStageContext) -> Option<Arc<dyn HttpStageTransport>> {
    #[cfg(test)]
    if let Some(stage) = test_support::open(context) {
        return Some(stage);
    }
    match context.direction {
        HttpDirection::Request => {
            let stage = LegacyRequestStage::new(
                &context.entry,
                LegacyRequestExchange {
                    reports: Arc::clone(&context.reports),
                    connection_nominated_headers: Arc::clone(&context.connection_nominated_headers),
                    chain_clock: context.chain_clock.clone(),
                },
            )?;
            Some(Arc::new(stage))
        }
        HttpDirection::Response => None,
    }
}

/// Platform-owned failure reason a legacy adapter ended its stage with,
/// keeping the 0.1.x reason. The pipeline checks contract failures first.
pub fn failure_reason(status: &tonic::Status) -> Option<String> {
    LegacyStageFailure::from_status(status).map(|failure| failure.reason)
}

/// Body modes the pipeline offers a legacy stage. The adapter applies 0.1.x
/// eligibility when it answers preflight, so version 2 offer rules do not
/// apply: a request stage collects the whole body, and a response stage may
/// select either lifecycle.
pub fn permitted_body_modes(direction: HttpDirection) -> Vec<HttpBodyMode> {
    match direction {
        HttpDirection::Request => vec![HttpBodyMode::Buffered],
        HttpDirection::Response => vec![HttpBodyMode::Buffered, HttpBodyMode::Stream],
    }
}

/// Chains with legacy stages keep 0.1.x work admission in addition to the
/// session budget.
pub fn requires_work_admission(entries: &[DescribedChainEntry]) -> bool {
    entries
        .iter()
        .any(|entry| entry.http_protocol() == Some(HttpProtocol::Legacy))
}

/// Legacy request stages check their request envelope against the platform
/// limits before every call, with the 0.1.x reasons, so a chain without
/// version 2 entries leaves input over those limits to each stage's
/// `on_error`, as 0.1.x did.
pub fn checks_request_input_per_stage(entries: &[DescribedChainEntry]) -> bool {
    entries
        .iter()
        .all(|entry| entry.http_protocol() != Some(HttpProtocol::V2))
}

/// What a legacy BUFFERED stage does when its input outgrows the selected
/// limit or its accumulation deadline expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyOverflow {
    /// Fail the exchange closed.
    Fail,
    /// Report `LegacyFailOpen { reason }` and pass the original input
    /// through the rest of the chain.
    Release { reason: &'static str },
}

/// Engine behavior a legacy stage keeps from 0.1.x.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyStagePolicy {
    direction: HttpDirection,
    /// The entry's effective `on_error` is `fail_open`.
    fail_open: bool,
    /// Largest payload limit among a request chain's legacy stages.
    chain_payload_limit: usize,
}

impl LegacyStagePolicy {
    pub fn new(
        entry: &DescribedChainEntry,
        chain: &[DescribedChainEntry],
        direction: HttpDirection,
    ) -> Self {
        Self {
            direction,
            fail_open: entry.on_error() == OnError::FailOpen,
            chain_payload_limit: match direction {
                HttpDirection::Request => {
                    legacy_request_collection_limit(chain).unwrap_or_default()
                }
                HttpDirection::Response => 0,
            },
        }
    }

    /// BUFFERED limit offered to the stage. A request stage is offered the
    /// chain's largest legacy limit: 0.1.x buffered the body once for the
    /// most capable stage, so the adapter applies each stage's own limit,
    /// with 0.1.x reasons, to the body that stage receives. A response stage
    /// is offered its own limit.
    pub fn offered_buffered_limit(self, own_limit: usize) -> usize {
        match self.direction {
            HttpDirection::Request => own_limit.max(self.chain_payload_limit),
            HttpDirection::Response => own_limit,
        }
    }

    /// Input past the selected limit. A request body over every legacy limit
    /// is denied before upstream contact. A `fail_open` response stage
    /// releases the original, so large downloads pass as in 0.1.x.
    pub fn overflow(self) -> LegacyOverflow {
        match self.direction {
            HttpDirection::Response if self.fail_open => LegacyOverflow::Release {
                reason: "whole_body_over_capacity",
            },
            HttpDirection::Request | HttpDirection::Response => LegacyOverflow::Fail,
        }
    }

    /// Failure reason when input outgrows the selected limit and the stage
    /// fails. 0.1.x failed a request body over a stage's limit with
    /// `request_body_over_capacity`, and a body over every legacy limit is
    /// over each stage's limit.
    pub fn overflow_failure_reason(self) -> &'static str {
        match self.direction {
            HttpDirection::Request => "request_body_over_capacity",
            HttpDirection::Response => "buffered_input_over_capacity",
        }
    }

    /// Whether collecting the stage's input has the BUFFERED whole-body
    /// deadline, and what its expiry does. 0.1.x collected request bodies
    /// without a deadline and gave response stages 2 minutes to accumulate.
    /// The adapter bounds each exchange itself.
    pub fn accumulation_deadline(self) -> Option<LegacyOverflow> {
        match self.direction {
            HttpDirection::Request => None,
            HttpDirection::Response if self.fail_open => Some(LegacyOverflow::Release {
                reason: "whole_body_accumulation_timeout",
            }),
            HttpDirection::Response => Some(LegacyOverflow::Fail),
        }
    }
}

#[cfg(test)]
pub mod test_support {
    //! Test seam that replaces the adapters with test transports.

    use std::cell::RefCell;

    use super::{Arc, HttpStageTransport, LegacyStageContext};

    type Factory = Arc<dyn Fn(&LegacyStageContext) -> Arc<dyn HttpStageTransport>>;

    thread_local! {
        static FACTORY: RefCell<Option<Factory>> = const { RefCell::new(None) };
    }

    /// Open legacy stages with `factory` on this thread until the guard drops.
    pub fn install(
        factory: impl Fn(&LegacyStageContext) -> Arc<dyn HttpStageTransport> + 'static,
    ) -> FactoryGuard {
        FACTORY.with(|slot| *slot.borrow_mut() = Some(Arc::new(factory)));
        FactoryGuard
    }

    pub fn open(context: &LegacyStageContext) -> Option<Arc<dyn HttpStageTransport>> {
        FACTORY.with(|slot| slot.borrow().as_ref().map(|factory| factory(context)))
    }

    pub struct FactoryGuard;

    impl Drop for FactoryGuard {
        fn drop(&mut self) {
            FACTORY.with(|slot| slot.borrow_mut().take());
        }
    }
}
