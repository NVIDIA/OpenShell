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
//! and mirrored nowhere here. `docs/how-it-works/gateways/configuration.mdx` documents
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

    /// The configured compute-driver name, if any.
    pub fn compute_driver(&self) -> Option<&'a str> {
        self.compute_driver
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

    OtlpTraceConfig {
        endpoint: &cfg.endpoint,
        service_name,
        service_version: Some(openshell_core::VERSION),
        resource_attributes: openshell_otel::gateway_resource_attributes(
            gateway.name(),
            gateway.compute_driver(),
        ),
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

/// Build the `tracing` layer that forwards spans to `provider`.
///
/// Events stay on the gateway's logging layers. Spans emitted by the
/// OpenTelemetry crates are excluded to prevent recursive export traffic.
pub fn layer<S>(
    provider: &SdkTracerProvider,
    driver: Option<openshell_otel::ComputeDriverTracing>,
) -> openshell_otel::TargetOtlpLayer<S>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    openshell_otel::layer_excluding_target_prefixes(
        provider,
        INSTRUMENTATION_SCOPE,
        driver
            .into_iter()
            .flat_map(openshell_otel::ComputeDriverTracing::in_process_targets),
    )
}

/// Isolated in-memory span exporters for tracing tests.
#[cfg(test)]
pub mod test_exporter {
    use std::sync::{Arc, OnceLock};

    use tracing::{Dispatch, Subscriber, dispatcher::WeakDispatch};

    /// Keep parent-span cleanup on the registry that created the span.
    ///
    /// `SQLx` moves spans onto its `SQLite` worker without installing the test's
    /// thread-local dispatcher. `tracing-subscriber` closes a child's parent
    /// through the current dispatcher, so the worker can otherwise look up the
    /// parent in the unrelated global registry when it drops the last reference.
    struct CloseWithDispatch<S> {
        inner: S,
        dispatch: OnceLock<WeakDispatch>,
        closed: Arc<tokio::sync::Notify>,
    }

    impl<S: Subscriber> Subscriber for CloseWithDispatch<S> {
        fn on_register_dispatch(&self, dispatch: &Dispatch) {
            self.dispatch
                .set(dispatch.downgrade())
                .expect("test subscriber is registered once");
            self.inner.on_register_dispatch(dispatch);
        }

        fn register_callsite(
            &self,
            metadata: &'static tracing::Metadata<'static>,
        ) -> tracing::subscriber::Interest {
            self.inner.register_callsite(metadata)
        }

        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            self.inner.enabled(metadata)
        }

        fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
            self.inner.max_level_hint()
        }

        fn new_span(&self, attributes: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            self.inner.new_span(attributes)
        }

        fn record(&self, id: &tracing::span::Id, values: &tracing::span::Record<'_>) {
            self.inner.record(id, values);
        }

        fn record_follows_from(&self, id: &tracing::span::Id, follows: &tracing::span::Id) {
            self.inner.record_follows_from(id, follows);
        }

        fn event_enabled(&self, event: &tracing::Event<'_>) -> bool {
            self.inner.event_enabled(event)
        }

        fn event(&self, event: &tracing::Event<'_>) {
            self.inner.event(event);
        }

        fn enter(&self, id: &tracing::span::Id) {
            self.inner.enter(id);
        }

        fn exit(&self, id: &tracing::span::Id) {
            self.inner.exit(id);
        }

        fn clone_span(&self, id: &tracing::span::Id) -> tracing::span::Id {
            self.inner.clone_span(id)
        }

        fn try_close(&self, id: tracing::span::Id) -> bool {
            // The span being closed owns a strong dispatcher reference. Store
            // only a weak reference here to avoid a subscriber/dispatcher cycle.
            let dispatch = self
                .dispatch
                .get()
                .and_then(WeakDispatch::upgrade)
                .expect("a live span keeps its test dispatcher alive");
            let closed = tracing::dispatcher::with_default(&dispatch, || self.inner.try_close(id));
            if closed {
                // The simple exporter has finished before try_close returns.
                // Wake assertions only after the owning registry and layers
                // have completed cleanup, including recursive parent closure.
                self.closed.notify_waiters();
            }
            closed
        }

        fn current_span(&self) -> tracing_core::span::Current {
            self.inner.current_span()
        }

        // OpenTelemetrySpanExt downcasts through the subscriber to its layer.
        // SAFETY: Forward the unchanged TypeId to the inner subscriber, which
        // owns the returned pointer for exactly as long as this wrapper lives.
        #[allow(unsafe_code)]
        unsafe fn downcast_raw(&self, id: std::any::TypeId) -> Option<*const ()> {
            if id == std::any::TypeId::of::<Self>() {
                Some(std::ptr::from_ref(self).cast())
            } else {
                // SAFETY: The inner subscriber owns and validates this downcast.
                unsafe { self.inner.downcast_raw(id) }
            }
        }
    }

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
        let subscriber = tracing_subscriber::registry().with(super::layer(&provider, None));
        let closed = Arc::new(tokio::sync::Notify::new());
        let dispatch = Dispatch::new(CloseWithDispatch {
            inner: subscriber,
            dispatch: OnceLock::new(),
            closed: Arc::clone(&closed),
        });
        TracingTestGuard {
            _default: tracing::dispatcher::set_default(&dispatch),
            _provider: provider,
            exporter,
            closed,
            _lock: lock,
        }
    }

    impl TracingTestGuard {
        /// Every span recorded by this test's in-memory exporter.
        pub fn finished_spans(&self) -> Vec<opentelemetry_sdk::trace::SpanData> {
            self.exporter.get_finished_spans().expect("in-memory spans")
        }

        /// Wait for expected spans to finish before taking an assertion snapshot.
        ///
        /// A completed `SQLx` query may still have its span held by a `SQLite`
        /// worker. Export is synchronous once the span closes, but flushing
        /// cannot close that live span. Await closure notifications instead of
        /// assuming the query result also means tracing cleanup has completed.
        pub async fn wait_for_spans(
            &self,
            predicate: impl Fn(&[opentelemetry_sdk::trace::SpanData]) -> bool + Send + Sync,
        ) -> Vec<opentelemetry_sdk::trace::SpanData> {
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    // notify_waiters wakes futures created before notification,
                    // even before polling. Subscribe before reading so closure
                    // between the snapshot and await cannot lose a wakeup.
                    let notified = self.closed.notified();
                    let spans = self.finished_spans();
                    if predicate(&spans) {
                        return spans;
                    }
                    notified.await;
                }
            })
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "timed out waiting for expected spans, got {:?}",
                    self.finished_spans()
                        .iter()
                        .map(|span| &span.name)
                        .collect::<Vec<_>>()
                )
            })
        }

        /// Wait for the completed span named `name`.
        pub async fn wait_for_span(&self, name: &str) -> opentelemetry_sdk::trace::SpanData {
            let spans = self
                .wait_for_spans(|spans| spans.iter().any(|span| span.name == name))
                .await;
            spans
                .into_iter()
                .find(|span| span.name == name)
                .expect("the awaited snapshot contains the expected span")
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
    pub fn install_scoped(subscriber: impl Into<Dispatch>) -> ScopedTracingTestGuard {
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
        closed: Arc<tokio::sync::Notify>,
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
    use crate::test_environment::Environment;

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
        Environment::new().remove("OTEL_SERVICE_NAME").run(|| {
            assert_eq!(
                service_name_of(&build_test_resource(&config())),
                Some(DEFAULT_SERVICE_NAME.to_string())
            );
        });
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

    fn service_name_of(resource: &Resource) -> Option<String> {
        resource
            .get(&opentelemetry::Key::from_static_str("service.name"))
            .map(|v| v.to_string())
    }

    /// Documented in `docs/how-it-works/gateways/configuration.mdx`: the config file wins
    /// over `OTEL_SERVICE_NAME`, because the gateway owns its own identity
    /// when an operator has stated it explicitly.
    #[test]
    fn configured_service_name_wins_over_the_env_var() {
        Environment::new()
            .set("OTEL_SERVICE_NAME", "from-env")
            .run(|| {
                let mut cfg = config();
                cfg.service_name = Some("from-config".into());

                assert_eq!(
                    service_name_of(&build_test_resource(&cfg)),
                    Some("from-config".to_string())
                );
            });
    }

    /// With no `service_name` in the config file, the SDK's env detector is
    /// the fallback rather than the built-in default.
    #[test]
    fn env_service_name_applies_when_config_omits_it() {
        Environment::new()
            .set("OTEL_SERVICE_NAME", "from-env")
            .run(|| {
                assert_eq!(
                    service_name_of(&build_test_resource(&config())),
                    Some("from-env".to_string())
                );
            });
    }

    #[test]
    fn blank_service_name_falls_back_to_the_default() {
        Environment::new().remove("OTEL_SERVICE_NAME").run(|| {
            let mut cfg = config();
            cfg.service_name = Some("   ".into());
            assert_eq!(
                service_name_of(&build_test_resource(&cfg)),
                Some(DEFAULT_SERVICE_NAME.to_string())
            );
        });
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
    async fn tracing_child_closed_on_worker_keeps_its_parent_and_exporter() {
        use opentelemetry::trace::TraceContextExt as _;
        use tracing_opentelemetry::OpenTelemetrySpanExt as _;

        let traced = test_exporter::install_traced();
        let parent = tracing::info_span!("worker_parent");
        let child = tracing::info_span!(parent: &parent, "worker_child");
        // Also exercise layer downcasting through the fixture's subscriber.
        let parent_context = parent.context();
        let child_context = child.context();
        drop(parent);

        let (release, released) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            released.recv().expect("test releases the worker's span");
            // Like SQLx, enter the carried span without installing its dispatcher.
            let entered = child.enter();
            drop(entered);
            // This is deliberately the child's last reference. Its parent has
            // no remaining references either, so both must close on this worker.
            drop(child);
            // Closing the carried span must also restore the worker's default,
            // so unrelated work cannot leak into this test's private exporter.
            drop(tracing::info_span!("unrelated_worker_span"));
        });

        assert!(traced.finished_spans().is_empty());
        let waiting = traced.wait_for_span("worker_parent");
        tokio::pin!(waiting);
        assert!(futures::poll!(waiting.as_mut()).is_pending());

        release.send(()).unwrap();
        let parent = waiting.await;
        worker
            .join()
            .expect("worker closes spans without consulting the global registry");
        let child = traced.span_named("worker_child");
        test_exporter::assert_is_root(&parent);
        assert_eq!(child.parent_span_id, parent.span_context.span_id());
        assert_eq!(
            child.span_context.trace_id(),
            parent.span_context.trace_id()
        );
        assert_eq!(parent_context.span().span_context(), &parent.span_context);
        assert_eq!(child_context.span().span_context(), &child.span_context);
        assert_eq!(traced.finished_spans().len(), 2);
    }

    #[tokio::test]
    async fn tracing_exporters_isolate_unrelated_threads_and_successive_tests() {
        // Use the same callsite under all dispatchers to exercise the global
        // interest cache without sharing their captured spans.
        fn emit_span() {
            drop(tracing::info_span!("isolated_test_span"));
        }

        let traced = test_exporter::install_traced();
        emit_span();
        std::thread::spawn(emit_span)
            .join()
            .expect("unrelated worker records only into the global registry");
        let first = traced.span_named("isolated_test_span");
        test_exporter::assert_is_root(&first);
        assert_eq!(traced.finished_spans().len(), 1);
        drop(traced);

        let traced = test_exporter::install_traced();
        assert!(traced.finished_spans().is_empty());
        emit_span();
        let second = traced.span_named("isolated_test_span");
        test_exporter::assert_is_root(&second);
        assert_eq!(traced.finished_spans().len(), 1);
        assert_ne!(
            first.span_context.trace_id(),
            second.span_context.trace_id()
        );
    }

    #[tokio::test]
    async fn tracing_wait_does_not_lose_closure_between_snapshot_and_await() {
        let traced = test_exporter::install_traced();
        let span = std::sync::Mutex::new(Some(tracing::info_span!("close_before_await")));
        let spans = traced
            .wait_for_spans(|spans| {
                // The first snapshot is empty. Close its span before polling
                // the notification future, as a worker could do concurrently.
                drop(span.lock().unwrap().take());
                spans.iter().any(|span| span.name == "close_before_await")
            })
            .await;
        assert_eq!(spans.len(), 1);
        test_exporter::assert_is_root(&spans[0]);
    }

    #[tokio::test(start_paused = true)]
    #[should_panic(expected = "timed out waiting for expected spans")]
    async fn tracing_wait_times_out_when_a_span_never_closes() {
        let traced = test_exporter::install_traced();
        let _span = tracing::info_span!("still_open");
        traced.wait_for_span("still_open").await;
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
