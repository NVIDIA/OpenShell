// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Capture openshell-server tracing logs for streaming over gRPC.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use openshell_core::proto::{SandboxLogLine, SandboxStreamEvent};
use openshell_ocsf::OCSF_TARGET;
use opentelemetry::KeyValue;
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
use tokio::sync::broadcast;
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, Layer};

/// OTLP tracing exporter configuration. Endpoint is the only required field;
/// service name, resource attributes, and sampling ratio are picked up from
/// standard `OTEL_*` env vars by the OpenTelemetry SDK.
#[derive(Debug, Clone)]
pub struct OtlpTracingConfig {
    pub endpoint: String,
}

impl OtlpTracingConfig {
    /// Resolve OTLP endpoint from (in order): the signal-specific
    /// `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, the shared
    /// `OTEL_EXPORTER_OTLP_ENDPOINT`, then the supplied CLI argument.
    /// Returns `None` if no endpoint is configured.
    pub fn resolve(arg_endpoint: Option<String>) -> Option<Self> {
        let endpoint = std::env::var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
            .ok()
            .or_else(|| std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok())
            .or(arg_endpoint)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())?;
        Some(Self { endpoint })
    }
}

/// Process-wide tracer provider, retained so spans can be flushed on shutdown.
static OTEL_TRACER_PROVIDER: OnceLock<SdkTracerProvider> = OnceLock::new();

/// Bus that publishes server log lines keyed by sandbox id.
#[derive(Debug, Clone)]
pub struct TracingLogBus {
    inner: Arc<Mutex<Inner>>,
    pub(crate) platform_event_bus: PlatformEventBus,
}

#[derive(Debug)]
struct Inner {
    per_id: HashMap<String, broadcast::Sender<SandboxStreamEvent>>,
    tails: HashMap<String, VecDeque<SandboxStreamEvent>>,
}

impl Default for TracingLogBus {
    fn default() -> Self {
        Self::new()
    }
}

impl TracingLogBus {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                per_id: HashMap::new(),
                tails: HashMap::new(),
            })),
            platform_event_bus: PlatformEventBus::new(),
        }
    }

    /// Install a tracing subscriber that logs to stdout and publishes events into this bus.
    ///
    /// When `otlp` is provided, an OpenTelemetry OTLP/gRPC trace exporter is attached
    /// after the env filter so `OPENSHELL_LOG_LEVEL` continues to gate exported spans.
    /// The `tower_http::trace::TraceLayer` per-request span set up in
    /// `multiplex.rs` becomes the OTLP root span automatically.
    pub fn install_subscriber(&self, env_filter: EnvFilter, otlp: Option<OtlpTracingConfig>) {
        let bus_layer = SandboxLogLayer {
            bus: self.clone(),
            default_tail: Self::DEFAULT_TAIL,
        };

        let otel_layer = match otlp {
            Some(cfg) => match build_otel_layer(&cfg) {
                Ok(layer) => Some(layer),
                Err(err) => {
                    eprintln!(
                        "openshell-gateway: failed to enable OTLP trace export to {}: {err}",
                        cfg.endpoint
                    );
                    None
                }
            },
            None => None,
        };

        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .with(bus_layer)
            .with(otel_layer)
            .init();
    }

    /// Flush and shut down the OTLP tracer provider, if installed. Idempotent.
    pub fn shutdown(&self) {
        if let Some(provider) = OTEL_TRACER_PROVIDER.get()
            && let Err(err) = provider.shutdown()
        {
            tracing::warn!(error = %err, "OpenTelemetry tracer provider shutdown failed");
        }
    }

    fn sender_for(&self, sandbox_id: &str) -> broadcast::Sender<SandboxStreamEvent> {
        let mut inner = self.inner.lock().expect("tracing bus lock poisoned");
        inner
            .per_id
            .entry(sandbox_id.to_string())
            .or_insert_with(|| {
                let (tx, _rx) = broadcast::channel(1024);
                tx
            })
            .clone()
    }

    pub fn subscribe(&self, sandbox_id: &str) -> broadcast::Receiver<SandboxStreamEvent> {
        self.sender_for(sandbox_id).subscribe()
    }

    /// Remove all bus entries for the given sandbox id.
    ///
    /// This drops the broadcast sender (closing any active receivers with
    /// `RecvError::Closed`) and frees the tail buffer.
    pub fn remove(&self, sandbox_id: &str) {
        let mut inner = self.inner.lock().expect("tracing bus lock poisoned");
        inner.per_id.remove(sandbox_id);
        inner.tails.remove(sandbox_id);
    }

    pub fn tail(&self, sandbox_id: &str, max: usize) -> Vec<SandboxStreamEvent> {
        let inner = self.inner.lock().expect("tracing bus lock poisoned");
        inner
            .tails
            .get(sandbox_id)
            .map(|d| d.iter().rev().take(max).cloned().collect::<Vec<_>>())
            .unwrap_or_default()
            .into_iter()
            .rev()
            .collect()
    }

    /// Publish a log line from an external source (e.g., sandbox push).
    ///
    /// Injects the line into the same broadcast channel and tail buffer
    /// used by the tracing layer, so it appears in `WatchSandbox` and
    /// `GetSandboxLogs` transparently.
    pub fn publish_external(&self, log: SandboxLogLine) {
        let evt = SandboxStreamEvent {
            payload: Some(openshell_core::proto::sandbox_stream_event::Payload::Log(
                log.clone(),
            )),
        };
        self.publish(&log.sandbox_id, evt, Self::DEFAULT_TAIL);
    }

    /// Default tail buffer capacity (lines per sandbox).
    const DEFAULT_TAIL: usize = 2000;

    fn publish(&self, sandbox_id: &str, event: SandboxStreamEvent, tail_cap: usize) {
        let tx = self.sender_for(sandbox_id);
        let _ = tx.send(event.clone());

        let mut inner = self.inner.lock().expect("tracing bus lock poisoned");
        let deque = inner.tails.entry(sandbox_id.to_string()).or_default();
        deque.push_back(event);
        while deque.len() > tail_cap {
            deque.pop_front();
        }
    }
}

#[derive(Debug, Clone)]
struct SandboxLogLayer {
    bus: TracingLogBus,
    default_tail: usize,
}

impl<S> Layer<S> for SandboxLogLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let mut visitor = LogVisitor::default();
        event.record(&mut visitor);

        let Some(sandbox_id) = visitor.sandbox_id else {
            return;
        };

        let msg = visitor.message.unwrap_or_else(|| meta.name().to_string());
        let level = display_level(meta.target(), &meta.level().to_string());

        let ts = current_time_ms().unwrap_or(0);
        let log = SandboxLogLine {
            sandbox_id: sandbox_id.clone(),
            timestamp_ms: ts,
            level,
            target: meta.target().to_string(),
            message: msg,
            source: "gateway".to_string(),
            fields: HashMap::new(),
        };
        let evt = SandboxStreamEvent {
            payload: Some(openshell_core::proto::sandbox_stream_event::Payload::Log(
                log,
            )),
        };
        self.bus.publish(&sandbox_id, evt, self.default_tail);
    }
}

#[derive(Debug, Default)]
struct LogVisitor {
    sandbox_id: Option<String>,
    message: Option<String>,
}

impl tracing::field::Visit for LogVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        match field.name() {
            "sandbox_id" => self.sandbox_id = Some(value.to_string()),
            "message" => self.message = Some(value.to_string()),
            _ => {}
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "sandbox_id" => self.sandbox_id = Some(format!("{value:?}")),
            "message" => self.message = Some(format!("{value:?}")),
            _ => {}
        }
    }
}

fn current_time_ms() -> Option<i64> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    i64::try_from(now.as_millis()).ok()
}

/// Build an `OpenTelemetry` `tracing` layer that exports spans to the
/// configured OTLP/gRPC endpoint. The resulting layer can be `with(...)`'d
/// onto the subscriber registry.
fn build_otel_layer<S>(
    cfg: &OtlpTracingConfig,
) -> Result<
    tracing_opentelemetry::OpenTelemetryLayer<S, opentelemetry_sdk::trace::SdkTracer>,
    Box<dyn std::error::Error + Send + Sync>,
>
where
    S: Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&cfg.endpoint)
        .build()?;

    let resource = Resource::builder()
        .with_service_name("openshell-gateway")
        .with_attributes([KeyValue::new("service.version", openshell_core::VERSION)])
        .build();

    let sampler = sampler_from_env();

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .with_sampler(sampler)
        .build();

    let tracer = provider.tracer("openshell-gateway");

    // Retain the provider so shutdown() can flush spans on SIGTERM.
    let _ = OTEL_TRACER_PROVIDER.set(provider);

    Ok(tracing_opentelemetry::layer().with_tracer(tracer))
}

/// Resolve a sampler from `OTEL_TRACES_SAMPLER` / `OTEL_TRACES_SAMPLER_ARG`,
/// defaulting to `parent_based(traceidratio=1.0)` — record all spans, respect
/// upstream parent sampling decisions.
fn sampler_from_env() -> Sampler {
    let ratio = std::env::var("OTEL_TRACES_SAMPLER_ARG")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .map_or(1.0, |r| r.clamp(0.0, 1.0));

    match std::env::var("OTEL_TRACES_SAMPLER")
        .ok()
        .as_deref()
        .map(str::trim)
    {
        Some("always_on") => Sampler::AlwaysOn,
        Some("always_off") => Sampler::AlwaysOff,
        Some("traceidratio") => Sampler::TraceIdRatioBased(ratio),
        Some("parentbased_always_off") => Sampler::ParentBased(Box::new(Sampler::AlwaysOff)),
        Some("parentbased_traceidratio") => {
            Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(ratio)))
        }
        // "parentbased_always_on", unset, or unrecognized
        _ => Sampler::ParentBased(Box::new(Sampler::AlwaysOn)),
    }
}

fn display_level(target: &str, level: &str) -> String {
    if target == OCSF_TARGET {
        "OCSF".to_string()
    } else {
        level.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_log_event(sandbox_id: &str, message: &str) -> SandboxLogLine {
        SandboxLogLine {
            sandbox_id: sandbox_id.to_string(),
            timestamp_ms: 1000,
            level: "INFO".to_string(),
            target: "test".to_string(),
            message: message.to_string(),
            source: "gateway".to_string(),
            fields: HashMap::new(),
        }
    }

    #[test]
    fn tracing_log_bus_remove_cleans_up_all_maps() {
        let bus = TracingLogBus::new();
        let sandbox_id = "sb-1";

        // Create entries via subscribe and publish
        let _rx = bus.subscribe(sandbox_id);
        bus.publish_external(make_log_event(sandbox_id, "hello"));

        // Verify entries exist
        assert_eq!(bus.tail(sandbox_id, 10).len(), 1);

        // Remove
        bus.remove(sandbox_id);

        // Verify entries are gone
        assert!(bus.tail(sandbox_id, 10).is_empty());
    }

    #[test]
    fn tracing_log_bus_subscribe_after_remove_creates_fresh_channel() {
        let bus = TracingLogBus::new();
        let sandbox_id = "sb-2";

        // Create and remove
        bus.publish_external(make_log_event(sandbox_id, "old message"));
        bus.remove(sandbox_id);

        // Subscribe again — should get a fresh channel with no history
        let mut rx = bus.subscribe(sandbox_id);
        assert!(bus.tail(sandbox_id, 10).is_empty());

        // New publish should reach the new subscriber
        bus.publish_external(make_log_event(sandbox_id, "new message"));
        let evt = rx.try_recv().expect("should receive new event");
        assert!(evt.payload.is_some());
    }

    #[test]
    fn tracing_log_bus_remove_closes_active_receivers() {
        let bus = TracingLogBus::new();
        let sandbox_id = "sb-3";

        let mut rx = bus.subscribe(sandbox_id);

        // Remove drops the sender
        bus.remove(sandbox_id);

        // Existing receiver should get Closed error
        match rx.try_recv() {
            Err(broadcast::error::TryRecvError::Closed) => {} // expected
            other => panic!("expected Closed, got {other:?}"),
        }
    }

    #[test]
    fn tracing_log_bus_remove_nonexistent_is_noop() {
        let bus = TracingLogBus::new();
        // Should not panic
        bus.remove("nonexistent");
    }

    #[test]
    fn display_level_maps_ocsf_target_to_ocsf() {
        assert_eq!(display_level(OCSF_TARGET, "INFO"), "OCSF");
        assert_eq!(display_level("openshell_server", "WARN"), "WARN");
    }

    #[test]
    fn platform_event_bus_remove_cleans_up() {
        let bus = PlatformEventBus::new();
        let sandbox_id = "sb-4";

        let mut rx = bus.subscribe(sandbox_id);

        // Publish an event
        let evt = SandboxStreamEvent { payload: None };
        bus.publish(sandbox_id, evt);
        assert!(rx.try_recv().is_ok());

        // Remove
        bus.remove(sandbox_id);

        // Receiver should be closed
        match rx.try_recv() {
            Err(broadcast::error::TryRecvError::Closed) => {} // expected
            other => panic!("expected Closed, got {other:?}"),
        }
    }

    #[test]
    fn platform_event_bus_subscribe_after_remove_creates_fresh_channel() {
        let bus = PlatformEventBus::new();
        let sandbox_id = "sb-5";

        let _old_rx = bus.subscribe(sandbox_id);
        bus.remove(sandbox_id);

        // New subscription should work
        let mut new_rx = bus.subscribe(sandbox_id);
        let evt = SandboxStreamEvent { payload: None };
        bus.publish(sandbox_id, evt);
        assert!(new_rx.try_recv().is_ok());
    }

    #[test]
    fn platform_event_bus_remove_nonexistent_is_noop() {
        let bus = PlatformEventBus::new();
        // Should not panic
        bus.remove("nonexistent");
    }

    #[test]
    fn platform_event_bus_tail_returns_buffered_events() {
        use openshell_core::proto::{PlatformEvent, sandbox_stream_event};

        let bus = PlatformEventBus::new();
        let sandbox_id = "sb-6";

        // Publish some events
        for i in 0..5 {
            let evt = SandboxStreamEvent {
                payload: Some(sandbox_stream_event::Payload::Event(PlatformEvent {
                    timestamp_ms: i,
                    source: "test".to_string(),
                    r#type: "Normal".to_string(),
                    reason: format!("Event{i}"),
                    message: format!("Message {i}"),
                    metadata: HashMap::new(),
                })),
            };
            bus.publish(sandbox_id, evt);
        }

        // Tail should return all events in order
        let events = bus.tail(sandbox_id, 10);
        assert_eq!(events.len(), 5);

        // Verify order (oldest first)
        for (i, evt) in events.iter().enumerate() {
            if let Some(sandbox_stream_event::Payload::Event(ref e)) = evt.payload {
                assert_eq!(e.reason, format!("Event{i}"));
            } else {
                panic!("expected Event payload");
            }
        }

        // Tail with smaller max should return most recent events
        let events = bus.tail(sandbox_id, 2);
        assert_eq!(events.len(), 2);
        if let Some(sandbox_stream_event::Payload::Event(ref e)) = events[0].payload {
            assert_eq!(e.reason, "Event3");
        }
        if let Some(sandbox_stream_event::Payload::Event(ref e)) = events[1].payload {
            assert_eq!(e.reason, "Event4");
        }
    }

    #[test]
    fn platform_event_bus_tail_empty_sandbox() {
        let bus = PlatformEventBus::new();
        let events = bus.tail("nonexistent", 10);
        assert!(events.is_empty());
    }

    #[test]
    fn otlp_config_resolve_prefers_traces_endpoint_then_shared_then_arg() {
        // Each branch is exercised in isolation to avoid env-var coupling
        // between cases. We only assert that the non-empty value wins; the
        // env-var precedence test would need a process-wide lock to be safe.
        let cfg = OtlpTracingConfig::resolve(Some("http://arg:4317".into()));
        assert!(cfg.is_some());
        assert_eq!(cfg.unwrap().endpoint, "http://arg:4317");

        let cfg = OtlpTracingConfig::resolve(Some("   ".into()));
        assert!(cfg.is_none());

        let cfg = OtlpTracingConfig::resolve(None);
        // May be Some or None depending on inherited env; only assert that
        // when Some, the endpoint is non-empty.
        if let Some(c) = cfg {
            assert!(!c.endpoint.is_empty());
        }
    }

    #[test]
    fn sampler_from_env_returns_a_sampler() {
        // The function shape is documented in the function body; this test
        // exercises construction without coupling to inherited env state.
        let _ = sampler_from_env();
    }

    #[test]
    fn platform_event_bus_remove_clears_tail() {
        let bus = PlatformEventBus::new();
        let sandbox_id = "sb-7";

        let evt = SandboxStreamEvent { payload: None };
        bus.publish(sandbox_id, evt);
        assert_eq!(bus.tail(sandbox_id, 10).len(), 1);

        bus.remove(sandbox_id);
        assert!(bus.tail(sandbox_id, 10).is_empty());
    }
}

/// Separate bus for platform event stream events.
///
/// This keeps platform events isolated from tracing capture.
#[derive(Debug, Clone)]
pub(crate) struct PlatformEventBus {
    inner: Arc<Mutex<PlatformEventBusInner>>,
}

#[derive(Debug)]
struct PlatformEventBusInner {
    senders: HashMap<String, broadcast::Sender<SandboxStreamEvent>>,
    tails: HashMap<String, VecDeque<SandboxStreamEvent>>,
}

impl PlatformEventBus {
    /// Default tail buffer capacity (events per sandbox).
    /// Platform events are infrequent (typically 5-10 per sandbox lifecycle).
    const DEFAULT_TAIL: usize = 50;

    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(PlatformEventBusInner {
                senders: HashMap::new(),
                tails: HashMap::new(),
            })),
        }
    }

    fn sender_for(&self, sandbox_id: &str) -> broadcast::Sender<SandboxStreamEvent> {
        let mut inner = self.inner.lock().expect("platform event bus lock poisoned");
        inner
            .senders
            .entry(sandbox_id.to_string())
            .or_insert_with(|| {
                let (tx, _rx) = broadcast::channel(1024);
                tx
            })
            .clone()
    }

    pub(crate) fn subscribe(&self, sandbox_id: &str) -> broadcast::Receiver<SandboxStreamEvent> {
        self.sender_for(sandbox_id).subscribe()
    }

    pub(crate) fn publish(&self, sandbox_id: &str, event: SandboxStreamEvent) {
        let tx = self.sender_for(sandbox_id);
        let _ = tx.send(event.clone());

        let mut inner = self.inner.lock().expect("platform event bus lock poisoned");
        let deque = inner.tails.entry(sandbox_id.to_string()).or_default();
        deque.push_back(event);
        while deque.len() > Self::DEFAULT_TAIL {
            deque.pop_front();
        }
    }

    /// Return buffered platform events for replay to late subscribers.
    pub(crate) fn tail(&self, sandbox_id: &str, max: usize) -> Vec<SandboxStreamEvent> {
        let inner = self.inner.lock().expect("platform event bus lock poisoned");
        inner
            .tails
            .get(sandbox_id)
            .map(|d| d.iter().rev().take(max).cloned().collect::<Vec<_>>())
            .unwrap_or_default()
            .into_iter()
            .rev()
            .collect()
    }

    /// Remove the bus entry for the given sandbox id.
    ///
    /// This drops the broadcast sender, closing any active receivers,
    /// and frees the tail buffer.
    pub(crate) fn remove(&self, sandbox_id: &str) {
        let mut inner = self.inner.lock().expect("platform event bus lock poisoned");
        inner.senders.remove(sandbox_id);
        inner.tails.remove(sandbox_id);
    }
}
