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

use crate::{
    DescribedChainEntry, HttpDirection, HttpProtocol, HttpStageTransport,
    MAX_MIDDLEWARE_CHAIN_TIMEOUT, OnError, StageReportSink,
};

/// What the pipeline gives a legacy adapter stage when it opens it.
#[derive(Clone)]
#[allow(dead_code, reason = "the legacy adapters read these fields")]
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
    started: Arc<OnceLock<Instant>>,
}

impl LegacyChainClock {
    /// Start the clock if it has not started, and return the deadline.
    #[allow(dead_code, reason = "the legacy adapters start the clock")]
    pub fn deadline(&self) -> Instant {
        *self
            .started
            .get_or_init(|| Instant::now() + MAX_MIDDLEWARE_CHAIN_TIMEOUT)
    }
}

/// Open the adapter transport for a legacy entry, or `None` while the
/// direction has no adapter.
///
/// The request adapter (`legacy::request`, L1) and the response adapter
/// (`legacy::response::adapter`, L2) plug in here. Until their cutovers,
/// legacy entries run on the legacy engines, and the pipeline fails a legacy
/// entry closed if one reaches it.
pub fn open_stage(context: &LegacyStageContext) -> Option<Arc<dyn HttpStageTransport>> {
    #[cfg(test)]
    {
        test_support::open(context)
    }
    #[cfg(not(test))]
    {
        let _ = context;
        None
    }
}

/// Platform-owned failure reason for a status a legacy adapter returns that
/// is not a contract failure, keeping the 0.1.x reason. The pipeline checks
/// contract failures first. The adapters' status classification plugs in
/// here.
pub fn failure_reason(status: &tonic::Status) -> Option<String> {
    let _ = status;
    None
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
    /// Largest payload limit among the chain's legacy stages.
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
            chain_payload_limit: chain
                .iter()
                .filter(|entry| entry.http_protocol() == Some(HttpProtocol::Legacy))
                .map(DescribedChainEntry::max_payload_bytes)
                .max()
                .unwrap_or_default(),
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
    //! Test seam that stands in for the adapters until L1 and L2 land.

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
