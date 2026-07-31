// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OpenTelemetry tracing integration for the gateway.
//!
//! Converts selected Rust `tracing` spans into OpenTelemetry traces and
//! exports them over OTLP/gRPC when configured.
//!
//! # Configuration split
//!
//! `[openshell.gateway.otlp]` decides **whether and where** to export: the
//! table's presence is the on-switch, its `endpoint` the destination.
//! `OTEL_EXPORTER_OTLP_ENDPOINT` is deliberately not read, so enablement has
//! one source.
//!
//! **How** to export — sampling, batching, span limits, transport headers —
//! is the SDK's `OTEL_*` environment surface, read as the provider is built
//! and mirrored nowhere here. `docs/reference/gateway-config.mdx` documents
//! the variables operators are likely to want.
//!
//! Only traces are exported. Logs and metrics have their own surfaces (OCSF
//! JSONL and the Prometheus `/metrics` endpoint).

pub use openshell_otel::SetupError;
use openshell_otel::{OtlpTraceConfig, ServiceName};
#[cfg(test)]
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing::Subscriber;
use tracing_subscriber::registry::LookupSpan;

use crate::config_file::OtlpConfig;

/// `service.name` reported when the config file does not override it.
const DEFAULT_SERVICE_NAME: &str = "openshell-gateway";

/// Instrumentation scope recorded on spans this gateway emits.
const INSTRUMENTATION_SCOPE: &str = "openshell-gateway";

fn trace_config(cfg: &OtlpConfig) -> OtlpTraceConfig<'_> {
    let service_name = cfg
        .service_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map_or(
            ServiceName::EnvironmentOr(DEFAULT_SERVICE_NAME),
            ServiceName::Fixed,
        );

    OtlpTraceConfig {
        endpoint: &cfg.endpoint,
        service_name,
        service_version: Some(openshell_core::VERSION),
        resource_attributes: Vec::new(),
    }
}

#[cfg(test)]
fn build_resource(cfg: &OtlpConfig) -> Resource {
    openshell_otel::resource_for(&trace_config(cfg))
}

/// Build a tracer provider exporting over OTLP/gRPC to the configured endpoint.
///
/// Must be called from within a Tokio runtime — the tonic exporter binds to
/// the current reactor as it is constructed. It does not connect: an
/// unreachable collector produces export failures, never a startup failure.
///
/// The sampler and span limits are left at the SDK's defaults, which are
/// themselves resolved from `OTEL_*` env vars (see the module docs).
#[cfg(test)]
fn build_provider(cfg: &OtlpConfig) -> Result<SdkTracerProvider, SetupError> {
    openshell_otel::build_provider(&trace_config(cfg))
}

/// Resolve the tracer provider for a gateway config file's optional
/// `[openshell.gateway.otlp]` table.
///
/// `None` means export is off — not configured, or configured and unusable.
/// Telemetry is diagnostic, so a broken exporter never stops the gateway.
///
/// The error is returned rather than logged because the provider is built
/// before the subscriber it attaches to, so logging here would go nowhere.
pub fn provider_for(cfg: Option<&OtlpConfig>) -> (Option<SdkTracerProvider>, Option<SetupError>) {
    openshell_otel::provider_for(cfg.map(trace_config))
}

/// Build the `tracing` layer that forwards spans to `provider`.
///
/// Events stay on the gateway's logging layers. Spans emitted by the
/// OpenTelemetry crates are excluded to prevent recursive export traffic.
pub fn layer<S>(provider: &SdkTracerProvider) -> openshell_otel::OtlpLayer<S>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    openshell_otel::layer(provider, INSTRUMENTATION_SCOPE)
}

/// Mark `span` as failed.
///
/// The field must be declared on the span at creation — `tracing` drops
/// records for fields a span does not have.
pub fn mark_error(span: &tracing::Span) {
    span.record("otel.status_code", "ERROR");
}

/// In-process OTLP/gRPC trace collector, for tests that need to assert what
/// the gateway actually put on the wire.
#[cfg(test)]
pub mod test_collector {
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use opentelemetry_proto::tonic::collector::trace::v1::{
        ExportTraceServiceRequest, ExportTraceServiceResponse,
        trace_service_server::{TraceService, TraceServiceServer},
    };
    use opentelemetry_proto::tonic::trace::v1::Span;

    /// Spans received by a running [`start`] collector.
    pub type Received = Arc<Mutex<Vec<Span>>>;

    /// The one exporter every traced test reads, installed for the whole test
    /// binary and never swapped.
    ///
    /// A per-test subscriber cannot work here: `tracing` caches callsite
    /// interest process-wide, so a callsite first hit by an untraced test
    /// stays dark for every later one.
    static EXPORTER: std::sync::LazyLock<opentelemetry_sdk::trace::InMemorySpanExporter> =
        std::sync::LazyLock::new(|| {
            use tracing_subscriber::layer::SubscriberExt as _;

            let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
            let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
                .with_simple_exporter(exporter.clone())
                .build();
            let subscriber = tracing_subscriber::registry().with(super::layer(&provider));
            tracing::subscriber::set_global_default(subscriber)
                .expect("test subscriber installs once");
            // Leaked so the provider outlives every span the binary records;
            // dropping it would shut the exporter down mid-suite.
            std::mem::forget(provider);
            exporter
        });

    /// Captures spans until the returned guard is dropped.
    ///
    /// Serialized on [`crate::TEST_TRACING_LOCK`] because the exporter it
    /// clears is shared by the whole binary.
    #[must_use]
    pub fn install_traced() -> TracingTestGuard {
        let lock = crate::TEST_TRACING_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EXPORTER.reset();
        TracingTestGuard {
            _lock: lock,
            exporter: &EXPORTER,
        }
    }

    impl TracingTestGuard {
        /// Every span recorded since [`install_traced`], including any written
        /// concurrently by other callers.
        ///
        /// Prefer [`Self::spans_named`] or [`Self::span_with`] to select spans.
        pub fn finished_spans(&self) -> Vec<opentelemetry_sdk::trace::SpanData> {
            self.exporter.get_finished_spans().expect("in-memory spans")
        }

        /// Spans named `name`.
        pub fn spans_named(&self, name: &str) -> Vec<opentelemetry_sdk::trace::SpanData> {
            self.finished_spans()
                .into_iter()
                .filter(|span| span.name == name)
                .collect()
        }

        /// The span named `name` carrying `key` = `value`.
        pub fn span_with(
            &self,
            name: &str,
            key: &str,
            value: &str,
        ) -> opentelemetry_sdk::trace::SpanData {
            let spans = self.finished_spans();
            spans
                .iter()
                .find(|span| span.name == name && attribute(span, key).as_deref() == Some(value))
                .cloned()
                .unwrap_or_else(|| {
                    panic!(
                        "no span {name:?} with {key}={value:?}, got {:?}",
                        spans.iter().map(|s| &s.name).collect::<Vec<_>>()
                    )
                })
        }
    }

    pub fn assert_is_root(span: &opentelemetry_sdk::trace::SpanData) {
        assert_eq!(
            span.parent_span_id,
            opentelemetry::trace::SpanId::INVALID,
            "{:?} should be a trace root",
            span.name
        );
    }

    pub fn assert_has_parent(span: &opentelemetry_sdk::trace::SpanData) {
        assert_ne!(
            span.parent_span_id,
            opentelemetry::trace::SpanId::INVALID,
            "{:?} should have a parent",
            span.name
        );
    }

    /// Installs `subscriber` for the current thread until dropped, for tests
    /// asserting on log output rather than exported spans.
    ///
    /// Forces the global subscriber up first so callsite interest is decided
    /// by a registry that records, not by the no-op default.
    #[must_use]
    pub fn install_scoped(subscriber: impl Into<tracing::Dispatch>) -> ScopedTracingTestGuard {
        let lock = crate::TEST_TRACING_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::sync::LazyLock::force(&EXPORTER);
        ScopedTracingTestGuard {
            _default: tracing::dispatcher::set_default(&subscriber.into()),
            _lock: lock,
        }
    }

    /// Uninstalls the scoped subscriber before releasing the lock.
    pub struct ScopedTracingTestGuard {
        _default: tracing::dispatcher::DefaultGuard,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    pub struct TracingTestGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        exporter: &'static opentelemetry_sdk::trace::InMemorySpanExporter,
    }

    #[derive(Clone)]
    struct Collector {
        spans: Received,
    }

    #[tonic::async_trait]
    impl TraceService for Collector {
        async fn export(
            &self,
            request: tonic::Request<ExportTraceServiceRequest>,
        ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status> {
            let mut spans = self.spans.lock().expect("collector lock");
            for resource_span in request.into_inner().resource_spans {
                for scope_span in resource_span.scope_spans {
                    spans.extend(scope_span.spans);
                }
            }
            Ok(tonic::Response::new(ExportTraceServiceResponse::default()))
        }
    }

    /// Start a collector on an ephemeral port. Returns its address and a
    /// handle to the spans it receives.
    pub async fn start() -> (SocketAddr, Received) {
        let spans: Received = Arc::new(Mutex::new(Vec::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind collector");
        let addr = listener.local_addr().expect("collector addr");

        let service = Collector {
            spans: Arc::clone(&spans),
        };
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(TraceServiceServer::new(service))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .ok();
        });

        (addr, spans)
    }

    /// Wait for spans named `expected` to arrive, returning everything
    /// received.
    ///
    /// `SdkTracerProvider::force_flush` is not a delivery barrier — it reports
    /// `Ok` even when the collector is unreachable — so asserting on the
    /// collector's contents immediately after it is a race.
    pub async fn wait_for_spans(received: &Received, expected: &[&str]) -> Vec<Span> {
        for _ in 0..200 {
            let spans = received.lock().expect("collector lock").clone();
            if expected
                .iter()
                .all(|name| spans.iter().any(|s| s.name == *name))
            {
                return spans;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        received.lock().expect("collector lock").clone()
    }

    /// Value of `key` on an in-memory span, if present.
    pub fn attribute(span: &opentelemetry_sdk::trace::SpanData, key: &str) -> Option<String> {
        span.attributes
            .iter()
            .find(|kv| kv.key.as_str() == key)
            .map(|kv| kv.value.to_string())
    }

    /// Value of `key` on `span`, if present as a string attribute.
    pub fn string_attribute(span: &Span, key: &str) -> Option<String> {
        use opentelemetry_proto::tonic::common::v1::any_value::Value;

        span.attributes
            .iter()
            .find(|kv| kv.key == key)
            .and_then(|kv| kv.value.as_ref())
            .and_then(|v| v.value.as_ref())
            .map(|v| match v {
                Value::StringValue(s) => s.clone(),
                other => format!("{other:?}"),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> OtlpConfig {
        OtlpConfig {
            endpoint: "http://127.0.0.1:4317".into(),
            service_name: None,
        }
    }

    #[test]
    fn resource_defaults_the_service_name() {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _env = EnvVarGuard::remove("OTEL_SERVICE_NAME");

        assert_eq!(
            service_name_of(&build_resource(&config())),
            Some(DEFAULT_SERVICE_NAME.to_string())
        );
    }

    #[test]
    fn resource_honors_configured_service_name_and_carries_version() {
        let mut cfg = config();
        cfg.service_name = Some("gateway-staging".into());
        let resource = build_resource(&cfg);

        assert_eq!(
            resource
                .get(&opentelemetry::Key::from_static_str("service.name"))
                .map(|v| v.to_string()),
            Some("gateway-staging".to_string())
        );
        assert_eq!(
            resource
                .get(&opentelemetry::Key::from_static_str("service.version"))
                .map(|v| v.to_string()),
            Some(openshell_core::VERSION.to_string())
        );
    }

    struct EnvVarGuard {
        key: &'static str,
        original: Option<String>,
    }

    impl EnvVarGuard {
        #[allow(unsafe_code)]
        fn remove(key: &'static str) -> Self {
            let original = std::env::var(key).ok();
            // SAFETY: tests serialize environment mutation with TEST_ENV_LOCK.
            unsafe { std::env::remove_var(key) };
            Self { key, original }
        }

        #[allow(unsafe_code)]
        fn set(key: &'static str, value: &str) -> Self {
            let original = std::env::var(key).ok();
            // SAFETY: tests serialize environment mutation with TEST_ENV_LOCK.
            unsafe { std::env::set_var(key, value) };
            Self { key, original }
        }
    }

    impl Drop for EnvVarGuard {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            // SAFETY: tests serialize environment mutation with TEST_ENV_LOCK.
            match self.original.as_deref() {
                Some(value) => unsafe { std::env::set_var(self.key, value) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    fn service_name_of(resource: &Resource) -> Option<String> {
        resource
            .get(&opentelemetry::Key::from_static_str("service.name"))
            .map(|v| v.to_string())
    }

    /// Documented in `docs/reference/gateway-config.mdx`: the config file wins
    /// over `OTEL_SERVICE_NAME`, because the gateway owns its own identity
    /// when an operator has stated it explicitly.
    #[test]
    fn configured_service_name_wins_over_the_env_var() {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _env = EnvVarGuard::set("OTEL_SERVICE_NAME", "from-env");

        let mut cfg = config();
        cfg.service_name = Some("from-config".into());

        assert_eq!(
            service_name_of(&build_resource(&cfg)),
            Some("from-config".to_string())
        );
    }

    /// With no `service_name` in the config file, the SDK's env detector is
    /// the fallback rather than the built-in default.
    #[test]
    fn env_service_name_applies_when_config_omits_it() {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _env = EnvVarGuard::set("OTEL_SERVICE_NAME", "from-env");

        assert_eq!(
            service_name_of(&build_resource(&config())),
            Some("from-env".to_string())
        );
    }

    #[test]
    fn blank_service_name_falls_back_to_the_default() {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _env = EnvVarGuard::remove("OTEL_SERVICE_NAME");

        let mut cfg = config();
        cfg.service_name = Some("   ".into());
        assert_eq!(
            service_name_of(&build_resource(&cfg)),
            Some(DEFAULT_SERVICE_NAME.to_string())
        );
    }

    #[test]
    fn provider_rejects_a_malformed_endpoint() {
        let mut cfg = config();
        cfg.endpoint = "definitely not a url".into();
        let err = build_provider(&cfg).expect_err("malformed endpoint");
        assert!(
            err.to_string().contains("definitely not a url"),
            "error names the offending endpoint: {err}"
        );
    }

    #[test]
    fn provider_rejects_an_empty_endpoint() {
        let mut cfg = config();
        cfg.endpoint = "   ".into();
        assert!(build_provider(&cfg).is_err(), "empty endpoint is rejected");
    }

    #[tokio::test]
    async fn provider_builds_without_a_reachable_collector() {
        // The OTLP batch exporter connects lazily, so a valid endpoint must
        // build even when nothing is listening — the gateway must not fail to
        // start because its collector is down.
        let provider = build_provider(&config()).expect("provider builds");
        provider.shutdown().ok();
    }

    /// Not configuring export is not a failure, so it produces nothing to
    /// report. This is distinct from a *broken* configuration, which yields an
    /// error for the caller to log — see the misconfigured-endpoint test.
    #[tokio::test]
    async fn absent_otlp_table_disables_export() {
        let (provider, err) = provider_for(None);
        assert!(provider.is_none(), "export is off");
        assert!(
            err.is_none(),
            "an absent table is a choice, not an error to report"
        );
    }

    #[tokio::test]
    async fn present_otlp_table_enables_export() {
        let (provider, err) = provider_for(Some(&config()));
        assert!(err.is_none());
        provider.expect("provider is present").shutdown().ok();
    }

    /// Telemetry must never be able to take the gateway down. A bad endpoint
    /// disables export and surfaces an error to report; it does not stop the
    /// gateway from starting.
    #[tokio::test]
    async fn misconfigured_endpoint_disables_export_without_failing_startup() {
        let mut cfg = config();
        cfg.endpoint = "definitely not a url".into();

        let (provider, err) = provider_for(Some(&cfg));
        assert!(
            provider.is_none(),
            "a bad endpoint degrades to no export rather than failing startup"
        );
        assert!(err.is_some(), "the failure is reportable, not swallowed");
    }

    #[tokio::test]
    async fn tracing_events_are_not_exported() {
        let traced = test_collector::install_traced();
        let span = tracing::info_span!("outer");
        let entered = span.enter();
        tracing::warn!(target: "opentelemetry-otlp", "export failed");
        tracing::warn!(target: "openshell_server", "gateway warning");
        drop(entered);
        drop(span);

        let spans = traced.finished_spans();
        let outer = spans
            .iter()
            .find(|s| s.name == "outer")
            .expect("outer span recorded");

        assert!(
            outer.events.is_empty(),
            "structured log events stay on the logging paths"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn tracing_spans_reach_the_collector_over_otlp() {
        let (addr, received) = test_collector::start().await;

        let cfg = OtlpConfig {
            endpoint: format!("http://{addr}"),
            service_name: None,
        };
        let provider = build_provider(&cfg).expect("provider builds");

        {
            // Its own subscriber, not the shared in-memory one: this test
            // asserts on what reaches a real collector over the wire.
            use tracing_subscriber::layer::SubscriberExt as _;
            let subscriber = tracing_subscriber::registry().with(layer(&provider));
            let _traced = test_collector::install_scoped(subscriber);
            let span = tracing::info_span!("create_sandbox", sandbox_id = "sb-otlp");
            let _entered = span.enter();
        }

        provider.force_flush().expect("flush spans");

        let spans = test_collector::wait_for_spans(&received, &["create_sandbox"]).await;
        let span = spans
            .iter()
            .find(|s| s.name == "create_sandbox")
            .unwrap_or_else(|| {
                panic!(
                    "collector received the exported span, got {:?}",
                    spans.iter().map(|s| &s.name).collect::<Vec<_>>()
                )
            });
        assert_eq!(
            test_collector::string_attribute(span, "sandbox_id").as_deref(),
            Some("sb-otlp"),
            "tracing fields are exported as span attributes"
        );

        provider.shutdown().ok();
    }
}
