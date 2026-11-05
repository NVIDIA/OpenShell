// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Keep a deny span active during OCSF emission.

use openshell_ocsf::{ActionId, OcsfEvent};

/// Emit egress events, entering an INFO deny span for denied HTTP Activity.
/// A saved connect span parents denies after authorization exits.
macro_rules! egress_emit {
    ($event:expr) => {
        $crate::telemetry::emit($event, None)
    };
    (deny_parent: $parent:expr, $event:expr) => {
        $crate::telemetry::emit($event, Some($parent))
    };
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

/// Only HTTP Activity carries `trace`, so only a decision with an HTTP record
/// gets a deny span that an OCSF record can point to.
fn is_http(event: &OcsfEvent) -> bool {
    matches!(event, OcsfEvent::HttpActivity(_))
}

pub fn emit(event: OcsfEvent, parent: Option<&tracing::Span>) {
    emit_decision([event], parent);
}

/// Emit all records of one synchronous decision under one deny span. Different
/// decisions remain separate, even when they concern the same connection.
#[allow(clippy::disallowed_macros)]
pub fn emit_decision(events: impl IntoIterator<Item = OcsfEvent>, parent: Option<&tracing::Span>) {
    let events: Vec<_> = events.into_iter().collect();
    let denied = events.iter().any(is_denied);
    let span = events
        .iter()
        .find(|event| denied && is_http(event))
        .map(|event| deny_span(event, parent));
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
        OcsfEvent::HttpActivity(e) => (e.dst_endpoint.as_ref(), e.firewall_rule.as_ref()),
        _ => (None, None),
    };
    let policy = policy.map(|rule| rule.name.as_str());
    let address =
        endpoint.and_then(|endpoint| endpoint.domain.as_deref().or(endpoint.ip.as_deref()));
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
