// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Keep a deny span active during OCSF emission.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

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
        .and_then(|event| deny_span(event, parent));
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
/// records rather than creating another exported span. Returns `None` when the
/// destination has used up its deny spans.
pub fn deny_span(event: &OcsfEvent, parent: Option<&tracing::Span>) -> Option<tracing::Span> {
    let current = tracing::Span::current();
    if current
        .metadata()
        .is_some_and(|metadata| metadata.name() == "supervisor.egress.deny")
    {
        return Some(current);
    }
    let (endpoint, policy) = match event {
        OcsfEvent::HttpActivity(e) => (e.dst_endpoint.as_ref(), e.firewall_rule.as_ref()),
        _ => (None, None),
    };
    let policy = policy.map(|rule| rule.name.as_str());
    let address =
        endpoint.and_then(|endpoint| endpoint.domain.as_deref().or(endpoint.ip.as_deref()));
    let port = endpoint.and_then(|endpoint| endpoint.port);
    let destination = format!(
        "{}:{}",
        address.unwrap_or_default(),
        port.unwrap_or_default()
    );
    if !LIMITER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .allow(&destination, Instant::now())
    {
        return None;
    }
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
    Some(span)
}

/// Deny spans one destination can export at once; one more is allowed per
/// second after that.
pub const DENY_SPAN_BURST: u32 = 10;
const DENY_SPAN_REFILL: Duration = Duration::from_secs(1);
const DENY_SPAN_DESTINATIONS: usize = 1024;

static LIMITER: LazyLock<Mutex<DenySpanLimiter>> = LazyLock::new(|| {
    Mutex::new(DenySpanLimiter::new(
        DENY_SPAN_BURST,
        DENY_SPAN_REFILL,
        DENY_SPAN_DESTINATIONS,
    ))
});

#[cfg(test)]
pub fn reset_deny_span_limiter() {
    *LIMITER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) =
        DenySpanLimiter::new(DENY_SPAN_BURST, DENY_SPAN_REFILL, DENY_SPAN_DESTINATIONS);
}

/// Per-destination token bucket bounding how many deny spans one workload can
/// export. OCSF records are unaffected; a limited decision just has no span.
pub struct DenySpanLimiter {
    burst: u32,
    refill: Duration,
    capacity: usize,
    buckets: HashMap<String, Bucket>,
}

struct Bucket {
    tokens: u32,
    refilled: Instant,
}

impl DenySpanLimiter {
    pub fn new(burst: u32, refill: Duration, capacity: usize) -> Self {
        Self {
            burst,
            refill,
            capacity,
            buckets: HashMap::new(),
        }
    }

    pub fn allow(&mut self, destination: &str, now: Instant) -> bool {
        if !self.buckets.contains_key(destination) && self.buckets.len() >= self.capacity {
            for bucket in self.buckets.values_mut() {
                bucket.refill(self.burst, self.refill, now);
            }
            let burst = self.burst;
            self.buckets.retain(|_, bucket| bucket.tokens < burst);
            if self.buckets.len() >= self.capacity {
                return false;
            }
        }
        let bucket = self
            .buckets
            .entry(destination.to_string())
            .or_insert(Bucket {
                tokens: self.burst,
                refilled: now,
            });
        bucket.refill(self.burst, self.refill, now);
        let allowed = bucket.tokens > 0;
        bucket.tokens = bucket.tokens.saturating_sub(1);
        allowed
    }
}

impl Bucket {
    fn refill(&mut self, burst: u32, interval: Duration, now: Instant) {
        let earned = now.saturating_duration_since(self.refilled).as_nanos() / interval.as_nanos();
        if earned == 0 {
            return;
        }
        let earned = u32::try_from(earned).unwrap_or(u32::MAX);
        self.tokens = self.tokens.saturating_add(earned).min(burst);
        self.refilled = if self.tokens == burst {
            now
        } else {
            self.refilled + interval * earned
        };
    }
}

#[cfg(test)]
pub mod tests;
