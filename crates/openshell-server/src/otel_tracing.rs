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

use openshell_otel::{OtlpTraceConfig, ServiceName};
pub use openshell_otel::{SetupError, TraceContextInterceptor, mark_error};
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

/// Gateway identity recorded on every exported span.
#[derive(Debug, Clone, Copy, Default)]
pub struct GatewayResourceAttributes<'a> {
    name: Option<&'a str>,
    compute_driver: Option<&'a str>,
}

impl<'a> GatewayResourceAttributes<'a> {
    pub fn new(name: Option<&'a str>, compute_driver: Option<&'a str>) -> Self {
        Self {
            name,
            compute_driver,
        }
    }

    /// The configured gateway installation name, if any.
    pub fn name(&self) -> Option<&'a str> {
        self.name
    }
}

fn trace_config<'cfg>(
    cfg: &'cfg OtlpConfig,
    gateway: GatewayResourceAttributes<'_>,
) -> OtlpTraceConfig<'cfg> {
    let service_name = cfg
        .service_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map_or(
            ServiceName::EnvironmentOr(DEFAULT_SERVICE_NAME),
            ServiceName::Fixed,
        );

    let mut resource_attributes = Vec::new();
    if let Some(name) = gateway.name.map(str::trim).filter(|s| !s.is_empty()) {
        resource_attributes.push(opentelemetry::KeyValue::new(
            "openshell.gateway.name",
            name.to_string(),
        ));
    }
    if let Some(compute_driver) = gateway
        .compute_driver
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        resource_attributes.push(opentelemetry::KeyValue::new(
            "openshell.gateway.compute_driver",
            compute_driver.to_string(),
        ));
    }

    OtlpTraceConfig {
        endpoint: &cfg.endpoint,
        service_name,
        service_version: Some(openshell_core::VERSION),
        resource_attributes,
    }
}

#[cfg(test)]
fn build_resource(cfg: &OtlpConfig, gateway: GatewayResourceAttributes<'_>) -> Resource {
    openshell_otel::resource_for(&trace_config(cfg, gateway))
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
fn build_provider(
    cfg: &OtlpConfig,
    gateway: GatewayResourceAttributes<'_>,
) -> Result<SdkTracerProvider, SetupError> {
    openshell_otel::build_provider(&trace_config(cfg, gateway))
}

/// Resolve the tracer provider for a gateway config file's optional
/// `[openshell.gateway.otlp]` table.
///
/// `None` means export is off — not configured, or configured and unusable.
/// Telemetry is diagnostic, so a broken exporter never stops the gateway.
///
/// The error is returned rather than logged because the provider is built
/// before the subscriber it attaches to, so logging here would go nowhere.
pub fn provider_for(
    cfg: Option<&OtlpConfig>,
    gateway: GatewayResourceAttributes<'_>,
) -> (Option<SdkTracerProvider>, Option<SetupError>) {
    openshell_otel::provider_for(cfg.map(|cfg| trace_config(cfg, gateway)))
}

/// Build the gateway layer while routing one selected in-process driver to
/// its own tracer provider.
pub fn layer_excluding_driver<S>(
    provider: &SdkTracerProvider,
    driver_target_prefix: Option<&'static str>,
) -> openshell_otel::TargetOtlpLayer<S>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    openshell_otel::layer_excluding_target_prefix(
        provider,
        INSTRUMENTATION_SCOPE,
        driver_target_prefix,
    )
}

/// Isolated in-memory span exporters for tracing tests.
#[cfg(test)]
pub mod test_exporter {
    /// Installs a process-wide registry before any scoped test subscriber is
    /// used.
    ///
    /// `tracing` caches callsite interest process-wide. The registry keeps
    /// callsites enabled without exporting spans from unrelated tests.
    static INITIALIZED: std::sync::LazyLock<()> = std::sync::LazyLock::new(|| {
        tracing::subscriber::set_global_default(tracing_subscriber::registry())
            .expect("test subscriber installs once");
    });

    /// Captures spans from the current test thread until the guard is dropped.
    ///
    /// Subscriber changes remain serialized because `tracing` caches callsite
    /// interest process-wide. The exporter itself is private to this guard, so
    /// concurrent non-tracing tests cannot contaminate or reset its spans.
    #[must_use]
    pub fn install_traced() -> TracingTestGuard {
        use tracing_subscriber::layer::SubscriberExt as _;

        let lock = crate::TEST_TRACING_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::sync::LazyLock::force(&INITIALIZED);
        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber =
            tracing_subscriber::registry().with(super::layer_excluding_driver(&provider, None));
        let dispatch = tracing::Dispatch::new(subscriber);
        TracingTestGuard {
            _default: tracing::dispatcher::set_default(&dispatch),
            _provider: provider,
            exporter,
            _lock: lock,
        }
    }

    impl TracingTestGuard {
        /// Every span recorded by this test's in-memory exporter.
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

        /// Returns the completed span named `name`.
        pub fn span_named(&self, name: &str) -> opentelemetry_sdk::trace::SpanData {
            self.find_span(name, |_| true)
        }

        /// The span named `name` carrying `key` = `value`.
        pub fn span_with(
            &self,
            name: &str,
            key: &str,
            value: &str,
        ) -> opentelemetry_sdk::trace::SpanData {
            self.find_span(name, |span| attribute(span, key).as_deref() == Some(value))
        }

        fn find_span(
            &self,
            name: &str,
            predicate: impl Fn(&opentelemetry_sdk::trace::SpanData) -> bool,
        ) -> opentelemetry_sdk::trace::SpanData {
            let spans = self.finished_spans();
            spans
                .iter()
                .find(|span| span.name == name && predicate(span))
                .cloned()
                .unwrap_or_else(|| {
                    panic!(
                        "no matching span {name:?}, got {:?}",
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
        std::sync::LazyLock::force(&INITIALIZED);
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
        _default: tracing::dispatcher::DefaultGuard,
        _provider: opentelemetry_sdk::trace::SdkTracerProvider,
        exporter: opentelemetry_sdk::trace::InMemorySpanExporter,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    /// Value of `key` on an in-memory span, if present.
    pub fn attribute(span: &opentelemetry_sdk::trace::SpanData, key: &str) -> Option<String> {
        span.attributes
            .iter()
            .find(|kv| kv.key.as_str() == key)
            .map(|kv| kv.value.to_string())
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

    fn build_test_resource(cfg: &OtlpConfig) -> Resource {
        build_resource(cfg, GatewayResourceAttributes::default())
    }

    #[test]
    fn resource_defaults_the_service_name() {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _env = EnvVarGuard::remove("OTEL_SERVICE_NAME");

        assert_eq!(
            service_name_of(&build_test_resource(&config())),
            Some(DEFAULT_SERVICE_NAME.to_string())
        );
    }

    #[test]
    fn resource_honors_configured_service_name_and_carries_version() {
        let mut cfg = config();
        cfg.service_name = Some("gateway-staging".into());
        let resource = build_test_resource(&cfg);

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

    #[test]
    fn resource_carries_gateway_name_and_compute_driver() {
        let resource = build_resource(
            &config(),
            GatewayResourceAttributes::new(Some("vm-dev"), Some("vm")),
        );

        assert_eq!(
            resource
                .get(&opentelemetry::Key::from_static_str(
                    "openshell.gateway.name",
                ))
                .map(|v| v.to_string()),
            Some("vm-dev".to_string())
        );
        assert_eq!(
            resource
                .get(&opentelemetry::Key::from_static_str(
                    "openshell.gateway.compute_driver",
                ))
                .map(|v| v.to_string()),
            Some("vm".to_string())
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
            service_name_of(&build_test_resource(&cfg)),
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
            service_name_of(&build_test_resource(&config())),
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
            service_name_of(&build_test_resource(&cfg)),
            Some(DEFAULT_SERVICE_NAME.to_string())
        );
    }

    #[test]
    fn provider_rejects_a_malformed_endpoint() {
        let mut cfg = config();
        cfg.endpoint = "definitely not a url".into();
        let err = build_provider(&cfg, GatewayResourceAttributes::default())
            .expect_err("malformed endpoint");
        assert!(
            err.to_string().contains("definitely not a url"),
            "error names the offending endpoint: {err}"
        );
    }

    #[test]
    fn provider_rejects_an_empty_endpoint() {
        let mut cfg = config();
        cfg.endpoint = "   ".into();
        assert!(
            build_provider(&cfg, GatewayResourceAttributes::default()).is_err(),
            "empty endpoint is rejected"
        );
    }

    #[tokio::test]
    async fn provider_builds_without_a_reachable_collector() {
        // The OTLP batch exporter connects lazily, so a valid endpoint must
        // build even when nothing is listening — the gateway must not fail to
        // start because its collector is down.
        let provider = build_provider(&config(), GatewayResourceAttributes::default())
            .expect("provider builds");
        provider.shutdown().ok();
    }

    /// Not configuring export is not a failure, so it produces nothing to
    /// report. This is distinct from a *broken* configuration, which yields an
    /// error for the caller to log — see the misconfigured-endpoint test.
    #[tokio::test]
    async fn absent_otlp_table_disables_export() {
        let (provider, err) = provider_for(None, GatewayResourceAttributes::default());
        assert!(provider.is_none(), "export is off");
        assert!(
            err.is_none(),
            "an absent table is a choice, not an error to report"
        );
    }

    #[tokio::test]
    async fn present_otlp_table_enables_export() {
        let (provider, err) = provider_for(Some(&config()), GatewayResourceAttributes::default());
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

        let (provider, err) = provider_for(Some(&cfg), GatewayResourceAttributes::default());
        assert!(
            provider.is_none(),
            "a bad endpoint degrades to no export rather than failing startup"
        );
        assert!(err.is_some(), "the failure is reportable, not swallowed");
    }

    #[tokio::test]
    async fn tracing_events_are_not_exported() {
        let traced = test_exporter::install_traced();
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
}
