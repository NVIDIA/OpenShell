// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Keep a deny span active during OCSF emission.

use openshell_ocsf::{ActionId, OcsfEvent};

/// Emit egress events inside an INFO deny span. `denied:` supplies the decision
/// for findings without an action; domain events carry their own action.
/// A saved connect span parents denies after authorization exits.
macro_rules! egress_emit {
    ($event:expr) => {
        $crate::telemetry::emit($event, None, false)
    };
    (deny_parent: $parent:expr, $event:expr) => {
        $crate::telemetry::emit($event, Some($parent), false)
    };
    (deny_parent: $parent:expr, denied: $denied:expr, $event:expr) => {{
        // Evaluate the decision before moving the event it may inspect.
        let denied = $denied;
        $crate::telemetry::emit($event, Some($parent), denied)
    }};
    (optional_deny_parent: $parent:expr, $event:expr) => {
        $crate::telemetry::emit($event, $parent, false)
    };
    (denied: $denied:expr, $event:expr) => {{
        // Evaluate the decision before moving the event it may inspect.
        let denied = $denied;
        $crate::telemetry::emit($event, None, denied)
    }};
}
pub(crate) use egress_emit;

fn is_denied(event: &OcsfEvent) -> bool {
    match event {
        OcsfEvent::NetworkActivity(event) => event.action == Some(ActionId::Denied),
        OcsfEvent::HttpActivity(event) => event.action == Some(ActionId::Denied),
        OcsfEvent::DetectionFinding(event) => event.action == Some(ActionId::Denied),
        _ => false,
    }
}

pub fn emit(event: OcsfEvent, parent: Option<&tracing::Span>, denied: bool) {
    if !denied && !is_denied(&event) {
        openshell_ocsf::ocsf_emit!(event);
        return;
    }
    let span = deny_span(&event, parent);
    span.in_scope(|| openshell_ocsf::ocsf_emit!(event));
}

/// Emit all records of one synchronous decision under one deny span. Different
/// decisions remain separate, even when they concern the same connection.
pub fn emit_decision(
    events: impl IntoIterator<Item = OcsfEvent>,
    parent: Option<&tracing::Span>,
    denied: bool,
) {
    let events: Vec<_> = events.into_iter().collect();
    let primary = events
        .iter()
        .find(|event| is_denied(event))
        .or_else(|| if denied { events.first() } else { None });
    let span = primary.map(|event| deny_span(event, parent));
    let emit = || {
        for event in events {
            openshell_ocsf::ocsf_emit!(event);
        }
    };
    if let Some(span) = span {
        span.in_scope(emit);
    } else {
        emit();
    }
}

/// Build a decision scope, reusing an active deny scope for its companion
/// records rather than creating another exported span.
pub fn deny_span(event: &OcsfEvent, parent: Option<&tracing::Span>) -> tracing::Span {
    let current = tracing::Span::current();
    if current
        .metadata()
        .is_some_and(|metadata| metadata.name() == "supervisor.egress.deny")
    {
        return current;
    }
    let (endpoint, policy) = match event {
        OcsfEvent::NetworkActivity(e) => (e.dst_endpoint.as_ref(), e.firewall_rule.as_ref()),
        OcsfEvent::HttpActivity(e) => (e.dst_endpoint.as_ref(), e.firewall_rule.as_ref()),
        _ => (None, None),
    };

    // Finding evidence supplies decision fields, not a trace parent.
    let evidence = |key: &str| match event {
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
        ocsf.class_uid = i64::from(event.class_uid()),
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
    span
}

#[cfg(test)]
pub mod tests;
