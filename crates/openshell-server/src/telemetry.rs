// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Anonymous sandbox activity telemetry forwarding.

use openshell_core::proto::NetworkActivitySummary;
use openshell_core::telemetry::DenyGroup;
#[cfg(not(test))]
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct TelemetryState {
    #[cfg(test)]
    ended_sandbox_sessions: std::sync::Mutex<Vec<String>>,
}

#[allow(clippy::unused_self)]
impl TelemetryState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn sandbox_session_connected(&self, _sandbox_id: &str) {}

    pub fn sandbox_session_disconnected(&self, _sandbox_id: &str) {}

    pub fn end_sandbox_session(&self, sandbox_id: &str) {
        #[cfg(test)]
        self.ended_sandbox_sessions
            .lock()
            .expect("telemetry session lock poisoned")
            .push(sandbox_id.to_string());
        #[cfg(not(test))]
        let _ = sandbox_id;
    }

    #[cfg(test)]
    pub(crate) fn ended_sandbox_sessions(&self) -> Vec<String> {
        self.ended_sandbox_sessions
            .lock()
            .expect("telemetry session lock poisoned")
            .clone()
    }

    pub fn record_network_activity(&self, sandbox_id: &str, summary: &NetworkActivitySummary) {
        if sandbox_id.is_empty() || !openshell_core::telemetry::enabled() {
            return;
        }
        #[cfg(not(test))]
        emit_network_activity_summary(summary);
        #[cfg(test)]
        let _ = summary;
    }
}

#[allow(clippy::cast_precision_loss)]
fn calculate_denial_rate_pct(network_activity_count: u64, denied_action_count: u64) -> f64 {
    if network_activity_count == 0 {
        return 0.0;
    }
    ((denied_action_count as f64 / network_activity_count as f64) * 100.0).clamp(0.0, 100.0)
}

fn sanitize_deny_group(raw: &str) -> DenyGroup {
    DenyGroup::from_raw(raw)
}

#[cfg(not(test))]
fn emit_network_activity_summary(summary: &NetworkActivitySummary) {
    let mut denials_by_group = HashMap::<DenyGroup, u64>::new();
    for group in &summary.denials_by_group {
        let deny_group = sanitize_deny_group(&group.deny_group);
        let entry = denials_by_group.entry(deny_group).or_default();
        *entry = entry.saturating_add(u64::from(group.denied_count));
    }
    openshell_core::telemetry::emit_sandbox_activity_summary(
        u64::from(summary.network_activity_count),
        u64::from(summary.denied_action_count),
        calculate_denial_rate_pct(
            u64::from(summary.network_activity_count),
            u64::from(summary.denied_action_count),
        ),
        denials_by_group,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_float_eq(actual: f64, expected: f64) {
        assert!((actual - expected).abs() <= f64::EPSILON);
    }

    #[test]
    fn denial_rate_handles_empty_and_clamps() {
        assert_float_eq(calculate_denial_rate_pct(0, 1), 0.0);
        assert_float_eq(calculate_denial_rate_pct(10, 2), 20.0);
        assert_float_eq(calculate_denial_rate_pct(10, 15), 100.0);
    }

    #[test]
    fn deny_group_sanitization_drops_raw_values() {
        assert_eq!(sanitize_deny_group("forward-l7-deny"), DenyGroup::L7Policy);
        assert_eq!(
            sanitize_deny_group("host=/secret.example"),
            DenyGroup::Unknown
        );
        assert_eq!(sanitize_deny_group("acme.internal:443"), DenyGroup::Unknown);
        assert_eq!(
            sanitize_deny_group("binary=/usr/local/bin/private"),
            DenyGroup::Unknown
        );
    }

    #[test]
    fn session_lifecycle_hooks_are_noops() {
        let telemetry = TelemetryState::new();
        telemetry.sandbox_session_connected("sb-1");
        telemetry.sandbox_session_disconnected("sb-1");
        telemetry.end_sandbox_session("sb-1");
    }
}
