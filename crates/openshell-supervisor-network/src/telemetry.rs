// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Keep a deny span active during OCSF emission.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use openshell_ocsf::{ActionId, HttpActivityEvent, OcsfEvent};

/// Emit one egress event, entering an INFO deny span if it is denied HTTP Activity.
macro_rules! egress_emit {
    ($event:expr) => {
        $crate::telemetry::emit_decision([$event], None)
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

fn as_http(event: &OcsfEvent) -> Option<&HttpActivityEvent> {
    match event {
        OcsfEvent::HttpActivity(event) => Some(event),
        _ => None,
    }
}

/// Emit all records of one synchronous decision under one deny span. Only HTTP
/// Activity carries `trace`, so only a denied decision with an HTTP record gets
/// a span. The span describes the denied HTTP record, or the first HTTP record
/// when only a companion finding is denied. A saved `parent` keeps the span in
/// the connect trace after authorization exits.
#[allow(clippy::disallowed_macros)]
pub fn emit_decision(events: impl IntoIterator<Item = OcsfEvent>, parent: Option<&tracing::Span>) {
    let events: Vec<_> = events.into_iter().collect();
    let span = if events.iter().any(is_denied) {
        events
            .iter()
            .filter(|event| is_denied(event))
            .find_map(as_http)
            .or_else(|| events.iter().find_map(as_http))
            .and_then(|event| deny_span(event, parent))
    } else {
        None
    };
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

/// Returns `None` when deny spans are disabled or the destination has used up
/// its deny spans. Disabled spans spend no tokens.
fn deny_span(event: &HttpActivityEvent, parent: Option<&tracing::Span>) -> Option<tracing::Span> {
    if !tracing::enabled!(kind: tracing::metadata::Kind::SPAN, tracing::Level::INFO) {
        return None;
    }
    let endpoint = event.dst_endpoint.as_ref();
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
    let parent = parent.cloned().unwrap_or_else(tracing::Span::current);
    Some(tracing::info_span!(
        parent: &parent,
        "supervisor.egress.deny",
        openshell.policy.decision = "deny",
        openshell.policy.name = event.firewall_rule.as_ref().map(|rule| rule.name.as_str()),
        openshell.policy.reason = event.base.status_detail.as_deref(),
        server.address = address,
        server.port = port.map(i64::from),
        ocsf.class_uid = i64::from(event.base.class_uid),
    ))
}

/// Deny spans one destination can export at once; one more is allowed per
/// second after that.
const DENY_SPAN_BURST: u32 = 10;
const DENY_SPAN_REFILL: Duration = Duration::from_secs(1);
const DENY_SPAN_DESTINATIONS: usize = 1024;
/// Bound aggregate span creation even when a workload rotates destinations.
const DENY_SPAN_GLOBAL_BURST: u32 = 100;
const DENY_SPAN_GLOBAL_REFILL: Duration = Duration::from_millis(10);

static LIMITER: LazyLock<Mutex<DenySpanLimiter>> = LazyLock::new(|| Mutex::new(default_limiter()));

fn default_limiter() -> DenySpanLimiter {
    DenySpanLimiter::new(DENY_SPAN_BURST, DENY_SPAN_REFILL, DENY_SPAN_DESTINATIONS)
}

#[cfg(test)]
fn reset_deny_span_limiter() {
    *LIMITER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = default_limiter();
}

/// Per-destination and process-wide token buckets bounding deny-span work.
/// OCSF records are unaffected; a limited decision creates no additional span.
struct DenySpanLimiter {
    burst: u32,
    refill: Duration,
    capacity: usize,
    buckets: HashMap<String, Bucket>,
    global_burst: u32,
    global_refill: Duration,
    global: Option<Bucket>,
}

struct Bucket {
    tokens: u32,
    refilled: Instant,
}

impl DenySpanLimiter {
    fn new(burst: u32, refill: Duration, capacity: usize) -> Self {
        Self::with_global_limit(
            burst,
            refill,
            capacity,
            DENY_SPAN_GLOBAL_BURST,
            DENY_SPAN_GLOBAL_REFILL,
        )
    }

    fn with_global_limit(
        burst: u32,
        refill: Duration,
        capacity: usize,
        global_burst: u32,
        global_refill: Duration,
    ) -> Self {
        Self {
            burst,
            refill,
            capacity,
            buckets: HashMap::new(),
            global_burst,
            global_refill,
            global: None,
        }
    }

    fn allow(&mut self, destination: &str, now: Instant) -> bool {
        let global = self.global.get_or_insert(Bucket {
            tokens: self.global_burst,
            refilled: now,
        });
        global.refill(self.global_burst, self.global_refill, now);
        if global.tokens == 0 {
            return false;
        }
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
        if allowed {
            bucket.tokens -= 1;
            global.tokens -= 1;
        }
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
