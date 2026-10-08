// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF events for supervisor middleware runtime observations.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use openshell_ocsf::{
    ConfigStateChangeBuilder, DetectionFindingBuilder, FindingInfo, OcsfEvent, SeverityId, StateId,
    StatusId, ctx::ctx as ocsf_ctx, ocsf_emit,
};
use openshell_supervisor_middleware::{
    ContractFailure, ContractFailureKind, FailOpenNotApplied, HttpDirection,
    MiddlewareRuntimeObserver,
};

/// Policy-local config name, implementation, and direction of one entry.
type EntryKey = (String, String, HttpDirection);

/// Implementation, direction, and kind of a contract failure.
type ContractFailureKey = (String, HttpDirection, ContractFailureKind);

/// Contract failures of one key reported in the current interval.
struct ContractFailureWindow {
    /// The latest failure, which a summary of suppressed failures describes.
    latest: ContractFailure,
    /// Failures since the key's last finding.
    suppressed: u64,
}

/// Emits OCSF events for the middleware runtime of one policy engine.
pub struct OcsfMiddlewareObserver {
    generation: Arc<AtomicU64>,
    /// Entries already reported, and the policy generation they belong to.
    reported: Mutex<(u64, HashSet<EntryKey>)>,
    /// Contract failures with a finding in the current reconciliation
    /// interval.
    contract_failures: Mutex<HashMap<ContractFailureKey, ContractFailureWindow>>,
}

impl OcsfMiddlewareObserver {
    /// Report each `fail_open` degrade once per generation of `generation`.
    pub fn new(generation: Arc<AtomicU64>) -> Self {
        Self {
            generation,
            reported: Mutex::default(),
            contract_failures: Mutex::default(),
        }
    }

    /// True the first time `entry` is seen in the current policy generation.
    fn first_report(&self, entry: &FailOpenNotApplied) -> bool {
        let generation = self.generation.load(Ordering::Acquire);
        let mut reported = self.reported.lock().unwrap_or_else(PoisonError::into_inner);
        if reported.0 != generation {
            *reported = (generation, HashSet::new());
        }
        reported.1.insert((
            entry.config_name.clone(),
            entry.implementation.clone(),
            entry.direction,
        ))
    }

    /// The finding for `failure`, if one is due. The first failure of a
    /// service, binding, and kind in a reconciliation interval is reported at
    /// once; later ones are counted for [`Self::end_interval`].
    fn record_contract_failure(&self, failure: &ContractFailure) -> Option<OcsfEvent> {
        let mut windows = self
            .contract_failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let key = (
            failure.implementation.clone(),
            failure.direction,
            failure.kind,
        );
        match windows.entry(key) {
            Entry::Occupied(mut window) => {
                let window = window.get_mut();
                window.latest = failure.clone();
                window.suppressed += 1;
                None
            }
            Entry::Vacant(window) => {
                window.insert(ContractFailureWindow {
                    latest: failure.clone(),
                    suppressed: 0,
                });
                Some(contract_failure_event(failure, 0))
            }
        }
    }

    /// End the reconciliation interval with one finding per key whose
    /// failures were suppressed, carrying their count. Such a key keeps its
    /// finding for the next interval, so a persistent failure is reported at
    /// most once per interval. Other keys report their next failure at once.
    fn end_interval(&self) -> Vec<OcsfEvent> {
        let mut windows = self
            .contract_failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut summaries = Vec::new();
        windows.retain(|_, window| {
            if window.suppressed == 0 {
                return false;
            }
            summaries.push(contract_failure_event(&window.latest, window.suppressed));
            window.suppressed = 0;
            true
        });
        summaries
    }
}

impl MiddlewareRuntimeObserver for OcsfMiddlewareObserver {
    fn contract_failure(&self, failure: &ContractFailure) {
        if let Some(event) = self.record_contract_failure(failure) {
            ocsf_emit!(event);
        }
    }

    fn fail_open_not_applied(&self, entry: &FailOpenNotApplied) {
        if self.first_report(entry) {
            ocsf_emit!(fail_open_not_applied_event(entry));
        }
    }

    fn reconciliation_interval_ended(&self) {
        for event in self.end_interval() {
            ocsf_emit!(event);
        }
    }
}

/// The exchange's HTTP activity event records the denial itself; this finding
/// is the paired security finding. It carries no service-provided text. A
/// finding with `suppressed` failures summarizes failures that were not
/// reported one by one, described by the latest of them.
fn contract_failure_event(failure: &ContractFailure, suppressed: u64) -> OcsfEvent {
    let builder = DetectionFindingBuilder::new(ocsf_ctx())
        .severity(SeverityId::High)
        .finding_info(FindingInfo::new(
            "openshell.middleware.contract_failure",
            "Supervisor middleware contract failure",
        ))
        .evidence_pairs(&[
            ("middleware", failure.config_name.as_str()),
            ("implementation", failure.implementation.as_str()),
            ("operation", failure.direction.as_str()),
            ("protocol", failure.protocol.as_str()),
            ("contract_failure", failure.kind.as_str()),
        ])
        .unmapped("middleware", failure.config_name.as_str())
        .unmapped("implementation", failure.implementation.as_str());
    if suppressed == 0 {
        return builder
            .message(format!(
                "Middleware {} broke the {} HTTP middleware contract [operation:{} failure:{}]; failed closed and re-describing middleware services",
                failure.config_name,
                failure.protocol.as_str(),
                failure.direction.as_str(),
                failure.kind.as_str(),
            ))
            .build();
    }
    builder
        .unmapped("suppressed_count", suppressed)
        .message(format!(
            "Middleware {} broke the {} HTTP middleware contract {suppressed} more times since the last finding [operation:{} failure:{}]; failed closed and re-describing middleware services",
            failure.config_name,
            failure.protocol.as_str(),
            failure.direction.as_str(),
            failure.kind.as_str(),
        ))
        .build()
}

fn fail_open_not_applied_event(entry: &FailOpenNotApplied) -> OcsfEvent {
    let builder = ConfigStateChangeBuilder::new(ocsf_ctx())
        .status(StatusId::Success)
        .unmapped("middleware", entry.config_name.as_str())
        .unmapped("implementation", entry.implementation.as_str())
        .unmapped("operation", entry.direction.as_str())
        .unmapped("on_error", "fail_closed");
    if entry.applies_elsewhere {
        builder
            .severity(SeverityId::Informational)
            .state(StateId::Enabled, "fail_open_scoped")
            .message(format!(
                "Middleware {} on_error fail_open applies only to its WebSocket and legacy HTTP bindings; its version 2 {} binding fails closed",
                entry.config_name,
                entry.direction.as_str(),
            ))
            .build()
    } else {
        builder
            .severity(SeverityId::Medium)
            .state(StateId::Other, "fail_open_not_applied")
            .message(format!(
                "Middleware {} sets on_error fail_open, but {} serves version 2 HTTP, which is always fail-closed; its {} binding runs fail_closed",
                entry.config_name,
                entry.implementation,
                entry.direction.as_str(),
            ))
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_supervisor_middleware::HttpProtocol;

    fn contract_failure(
        implementation: &str,
        direction: HttpDirection,
        kind: ContractFailureKind,
    ) -> ContractFailure {
        ContractFailure {
            config_name: "guard".into(),
            implementation: implementation.into(),
            direction,
            protocol: HttpProtocol::V2,
            kind,
        }
    }

    fn suppressed_count(event: &OcsfEvent) -> Option<u64> {
        serde_json::to_value(event).expect("serialize finding")["unmapped"]["suppressed_count"]
            .as_u64()
    }

    #[test]
    fn contract_failure_findings_are_rate_limited_per_reconciliation_interval() {
        use ContractFailureKind::{Decode, Unimplemented};
        use HttpDirection::{Request, Response};

        let observer = OcsfMiddlewareObserver::new(Arc::default());
        let guard = contract_failure("example/guard", Request, Unimplemented);
        let first = observer
            .record_contract_failure(&guard)
            .expect("the first failure is reported at once");
        assert_eq!(suppressed_count(&first), None);
        for _ in 0..3 {
            assert!(observer.record_contract_failure(&guard).is_none());
        }
        for other in [
            contract_failure("example/guard", Response, Unimplemented),
            contract_failure("example/guard", Request, Decode),
            contract_failure("example/other", Request, Unimplemented),
        ] {
            assert!(
                observer.record_contract_failure(&other).is_some(),
                "each service, binding, and kind is limited separately: {other:?}"
            );
        }

        let summaries = observer.end_interval();
        assert_eq!(summaries.len(), 1);
        assert_eq!(suppressed_count(&summaries[0]), Some(3));
        let serialized = serde_json::to_string(&summaries[0]).expect("serialize summary");
        assert!(serialized.contains("\"severity_id\":4"));
        assert!(serialized.contains("3 more times since the last finding"));

        // A failure that persists is summarized once per interval.
        assert!(observer.record_contract_failure(&guard).is_none());
        let summaries = observer.end_interval();
        assert_eq!(summaries.len(), 1);
        assert_eq!(suppressed_count(&summaries[0]), Some(1));

        // After an interval without failures, the next one is reported at once.
        assert!(observer.end_interval().is_empty());
        assert!(observer.record_contract_failure(&guard).is_some());
    }

    fn stale_entry(config_name: &str) -> FailOpenNotApplied {
        FailOpenNotApplied {
            config_name: config_name.into(),
            implementation: "example/guard".into(),
            direction: HttpDirection::Request,
            applies_elsewhere: false,
        }
    }

    #[test]
    fn contract_failure_is_a_high_finding_without_service_text() {
        let event = contract_failure_event(
            &ContractFailure {
                config_name: "guard".into(),
                implementation: "example/guard".into(),
                direction: HttpDirection::Response,
                protocol: HttpProtocol::Legacy,
                kind: ContractFailureKind::Unimplemented,
            },
            0,
        );
        assert_eq!(event.class_uid(), 2004);
        let serialized = serde_json::to_string(&event).expect("serialize finding");
        assert!(serialized.contains("openshell.middleware.contract_failure"));
        assert!(serialized.contains("\"severity_id\":4"));
        assert!(serialized.contains("http_response"));
        assert!(serialized.contains("unimplemented"));
        assert!(serialized.contains("example/guard"));
    }

    #[test]
    fn fail_open_degrade_is_reported_once_per_policy_generation_and_entry() {
        let generation = Arc::new(AtomicU64::new(3));
        let observer = OcsfMiddlewareObserver::new(generation.clone());
        assert!(observer.first_report(&stale_entry("guard")));
        assert!(!observer.first_report(&stale_entry("guard")));
        assert!(observer.first_report(&stale_entry("other")));

        let mut response = stale_entry("guard");
        response.direction = HttpDirection::Response;
        assert!(observer.first_report(&response));

        generation.store(4, Ordering::Release);
        assert!(observer.first_report(&stale_entry("guard")));
        assert!(!observer.first_report(&stale_entry("guard")));
    }

    #[test]
    fn stale_fail_open_is_a_warning_and_websocket_scoping_is_informational() {
        let stale = serde_json::to_string(&fail_open_not_applied_event(&stale_entry("guard")))
            .expect("serialize stale event");
        assert!(stale.contains("\"severity_id\":3"));
        assert!(stale.contains("fail_open_not_applied"));

        let mut scoped = stale_entry("guard");
        scoped.applies_elsewhere = true;
        let scoped = serde_json::to_string(&fail_open_not_applied_event(&scoped))
            .expect("serialize scoped event");
        assert!(scoped.contains("\"severity_id\":1"));
        assert!(scoped.contains("fail_open_scoped"));
    }
}
