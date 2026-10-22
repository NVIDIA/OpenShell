// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Keep a deny span active during OCSF emission.

use openshell_ocsf::{ActionId, OcsfEvent};

/// Emit network events inside an INFO deny span when their action or explicit
/// decision is denied. A saved connect span can supply the parent after
/// authorization exits; a disabled DEBUG parent leaves the deny as a root.
macro_rules! ocsf_emit {
    ($event:expr) => {
        $crate::telemetry::emit($event, None, false)
    };
    (parent: $parent:expr, $event:expr) => {
        $crate::telemetry::emit($event, Some($parent), false)
    };
    (parent: $parent:expr, denied: $denied:expr, $event:expr) => {{
        let denied = $denied;
        $crate::telemetry::emit($event, Some($parent), denied)
    }};
    (optional_parent: $parent:expr, $event:expr) => {
        $crate::telemetry::emit($event, $parent, false)
    };
    (denied: $denied:expr, $event:expr) => {{
        let denied = $denied;
        $crate::telemetry::emit($event, None, denied)
    }};
}
pub(crate) use ocsf_emit;

pub fn emit(event: OcsfEvent, parent: Option<&tracing::Span>, denied: bool) {
    let (action, endpoint, policy) = match &event {
        OcsfEvent::NetworkActivity(e) => {
            (e.action, e.dst_endpoint.as_ref(), e.firewall_rule.as_ref())
        }
        OcsfEvent::HttpActivity(e) => (e.action, e.dst_endpoint.as_ref(), e.firewall_rule.as_ref()),
        OcsfEvent::DetectionFinding(e) => (e.action, None, None),
        _ => (None, None, None),
    };
    if !denied && action != Some(ActionId::Denied) {
        openshell_ocsf::ocsf_emit!(event);
        return;
    }

    // Finding evidence supplies decision fields, not a trace parent.
    let evidence = |key: &str| match &event {
        OcsfEvent::DetectionFinding(e) => e.evidences.as_ref().and_then(|items| {
            items
                .iter()
                .find_map(|item| item.data.as_ref()?.get(key)?.as_str())
        }),
        _ => None,
    };
    let policy = policy
        .map(|rule| rule.name.as_str())
        .or_else(|| evidence("policy"));
    let address = endpoint
        .and_then(|endpoint| endpoint.domain.as_deref().or(endpoint.ip.as_deref()))
        .or_else(|| evidence("host"));
    let port = endpoint.and_then(|endpoint| endpoint.port);
    let reason = event.base().status_detail.as_deref();
    let parent = parent.cloned().unwrap_or_else(tracing::Span::current);
    let span = tracing::info_span!(
        parent: &parent,
        "supervisor.egress.deny",
        openshell.policy.decision = "deny",
        openshell.policy.name = tracing::field::Empty,
        openshell.policy.reason = tracing::field::Empty,
        server.address = tracing::field::Empty,
        server.port = tracing::field::Empty,
        ocsf.class_uid = event.class_uid(),
    );
    if let Some(policy) = policy {
        span.record("openshell.policy.name", policy);
    }
    if let Some(reason) = reason {
        span.record("openshell.policy.reason", reason);
    }
    if let Some(address) = address {
        span.record("server.address", address);
    }
    if let Some(port) = port {
        span.record("server.port", i64::from(port));
    }
    span.in_scope(|| openshell_ocsf::ocsf_emit!(event));
}

#[cfg(test)]
pub mod tests;
