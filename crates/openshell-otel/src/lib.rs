// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared OpenTelemetry trace and log export support for `OpenShell` services.

mod driver;
mod grpc;
mod headers;
mod logs;
mod ocsf;
mod propagation;
mod tls;
mod transport;

pub use driver::{
    BoxGrpcStream, ComputeDriverTracing, DriverTracingConfig, DriverTracingHandle,
    IN_PROCESS_COMPUTE_DRIVER_TARGET, InProcessRpcTracer, install_driver_tracing,
};

pub use grpc::{
    COMPUTE_DRIVER_RPC_SERVICE, ComputeDriverRpc, ComputeDriverRpcSpan, RecordGrpcFailure,
    RecordGrpcStatus, TracedGrpcStream, compute_driver_rpc_layer, compute_driver_rpc_operation,
    grpc_status_code_name, record_grpc_status, rpc,
};
pub use headers::{encode_otlp_headers, merge_otlp_headers, parse_otlp_headers};
pub use ocsf::{OcsfOtlp, OcsfOtlpLayer};
pub use propagation::{
    HeaderMapExtractor, MetadataMapInjector, TRACEPARENT_ENV, TRACESTATE_ENV,
    TraceContextInterceptor, current_trace_context_carrier, current_trace_context_environment,
    set_parent_from_environment, set_parent_from_trace_context, trace_context_environment,
};
pub use tls::{OtlpTls, TlsError, TlsFileError};

pub use transport::{OtlpHttpClient, signal_url};

use opentelemetry::KeyValue;
use opentelemetry::trace::TracerProvider as _;
pub use opentelemetry_otlp::LogExporter;
use opentelemetry_otlp::tonic_types::metadata::MetadataMap;
use opentelemetry_otlp::{SpanExporter, WithExportConfig, WithHttpConfig, WithTonicConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::SdkTracer;
pub use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing::Subscriber;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::Layer as _;
use tracing_subscriber::layer::{Context, Filter};
use tracing_subscriber::registry::LookupSpan;

const SDK_UNKNOWN_SERVICE_PREFIX: &str = "unknown_service";

/// Build the resource attributes shared by gateway and compute-driver providers.
pub fn gateway_resource_attributes(
    gateway_name: Option<&str>,
    compute_driver: Option<&str>,
) -> Vec<KeyValue> {
    let mut attributes = Vec::new();
    if let Some(name) = gateway_name.map(str::trim).filter(|name| !name.is_empty()) {
        attributes.push(KeyValue::new("openshell.gateway.name", name.to_string()));
    }
    if let Some(driver) = compute_driver
        .map(str::trim)
        .filter(|driver| !driver.is_empty())
    {
        attributes.push(KeyValue::new(
            "openshell.gateway.compute_driver",
            driver.to_string(),
        ));
    }
    attributes
}

/// Mark `span` as failed.
///
/// The field must be declared on the span at creation because `tracing` drops
/// records for fields a span does not have.
pub fn mark_error(span: &tracing::Span) {
    span.record("otel.status_code", "ERROR");
}

/// Marks the current span when an instrumented operation returns an error.
pub fn record_error_result<T, E>(result: Result<T, E>) -> Result<T, E> {
    if result.is_err() {
        mark_error(&tracing::Span::current());
    }
    result
}

/// Marks an instrumented function's span when it exits before returning success.
///
/// Create the guard at the start of the instrumented function and return the
/// successful result through [`Self::finish`]. An early `?` or error return
/// drops the unfinished guard and marks the captured span as failed.
#[must_use]
pub struct ErrorStatusGuard {
    span: tracing::Span,
    finished: bool,
}

impl ErrorStatusGuard {
    /// Captures the current instrumented span.
    pub fn current() -> Self {
        Self {
            span: tracing::Span::current(),
            finished: false,
        }
    }

    /// Returns `result`, marking this guard complete when it is successful.
    pub fn finish<T, E>(mut self, result: Result<T, E>) -> Result<T, E> {
        self.finished = result.is_ok();
        result
    }
}

impl Drop for ErrorStatusGuard {
    fn drop(&mut self) {
        if !self.finished {
            mark_error(&self.span);
        }
    }
}

/// How a process chooses its OpenTelemetry `service.name`.
#[derive(Debug, Clone, Copy)]
pub enum ServiceName<'a> {
    /// Always use this name, overriding `OTEL_SERVICE_NAME`.
    Fixed(&'a str),
    /// Use `OTEL_SERVICE_NAME` when set, otherwise use this default.
    EnvironmentOr(&'a str),
}

/// OTLP transport to a collector.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Protocol {
    #[default]
    Grpc,
    HttpProtobuf,
}

/// Inputs for OTLP export.
#[derive(Debug, Clone)]
pub struct OtlpExportConfig<'a> {
    pub endpoint: &'a str,
    pub service_name: ServiceName<'a>,
    pub service_version: Option<&'a str>,
    pub resource_attributes: Vec<KeyValue>,
}

/// How exports reach a collector: the transport, request headers, and TLS.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct CollectorTransport {
    pub protocol: Protocol,
    pub headers: http::HeaderMap,
    pub tls: OtlpTls,
}

impl std::fmt::Debug for CollectorTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CollectorTransport")
            .field("protocol", &self.protocol)
            .field("header_names", &self.headers.keys().collect::<Vec<_>>())
            .field("tls", &self.tls)
            .finish()
    }
}

/// Failure to set up OTLP export.
#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    #[error("OTLP endpoint is empty")]
    EmptyEndpoint,

    #[error("invalid OTLP endpoint {endpoint:?}: {source}")]
    InvalidEndpoint {
        endpoint: String,
        source: http::uri::InvalidUri,
    },

    #[error("failed to build the OTLP exporter: {0}")]
    Exporter(#[from] opentelemetry_otlp::ExporterBuildError),

    #[error("invalid OTLP endpoint {endpoint:?}: {source}")]
    InvalidSignalUrl {
        endpoint: String,
        source: http::Error,
    },

    #[error("OTLP TLS settings need an https:// endpoint, not {endpoint:?}")]
    TlsWithoutHttps { endpoint: String },

    #[error("invalid OTLP TLS settings: {0}")]
    Tls(#[from] TlsError),

    #[error("invalid OTLP TLS files: {0}")]
    TlsFiles(#[from] TlsFileError),

    #[error("OTLP/HTTP export needs a tokio runtime")]
    NoRuntime,
}

fn resource_attributes(config: &OtlpExportConfig<'_>) -> Vec<KeyValue> {
    let mut attributes = config.resource_attributes.clone();
    if let Some(version) = config
        .service_version
        .map(str::trim)
        .filter(|version| !version.is_empty())
    {
        attributes.push(KeyValue::new("service.version", version.to_string()));
    }
    attributes
}

/// Build the OpenTelemetry resource for an export configuration.
#[must_use]
pub fn resource_for(config: &OtlpExportConfig<'_>) -> Resource {
    let attributes = resource_attributes(config);
    match config.service_name {
        ServiceName::Fixed(name) => Resource::builder()
            .with_service_name(name.trim().to_string())
            .with_attributes(attributes)
            .build(),
        ServiceName::EnvironmentOr(default) => {
            let detected = Resource::builder()
                .with_attributes(attributes.clone())
                .build();
            if detected
                .get(&opentelemetry::Key::from_static_str("service.name"))
                .is_some_and(|value| !value.to_string().starts_with(SDK_UNKNOWN_SERVICE_PREFIX))
            {
                detected
            } else {
                Resource::builder()
                    .with_service_name(default.trim().to_string())
                    .with_attributes(attributes)
                    .build()
            }
        }
    }
}

/// Trim and validate an OTLP endpoint before handing it to an exporter.
///
/// Every exporter that reads an operator-supplied endpoint uses this, so a
/// value accepted for one signal is accepted for all of them.
pub fn validated_endpoint(endpoint: &str) -> Result<(&str, http::Uri), SetupError> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return Err(SetupError::EmptyEndpoint);
    }
    let uri = endpoint
        .parse::<http::Uri>()
        .map_err(|source| SetupError::InvalidEndpoint {
            endpoint: endpoint.to_string(),
            source,
        })?;
    Ok((endpoint, uri))
}

/// A validated OTLP collector endpoint and the resource that every signal
/// exported to it describes.
#[derive(Clone)]
pub struct OtlpTarget {
    endpoint: String,
    tls: bool,
    protocol: Protocol,
    headers: http::HeaderMap,
    tls_settings: OtlpTls,
    resource: Resource,
}

impl std::fmt::Debug for OtlpTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OtlpTarget")
            .field("endpoint", &self.endpoint)
            .field("tls", &self.tls)
            .field("protocol", &self.protocol)
            .field("header_names", &self.headers.keys().collect::<Vec<_>>())
            .field("tls_settings", &self.tls_settings)
            .field("resource", &self.resource)
            .finish()
    }
}

impl OtlpTarget {
    /// Validate the endpoint and build the resource.
    pub fn new(config: &OtlpExportConfig<'_>) -> Result<Self, SetupError> {
        let (endpoint, uri) = validated_endpoint(config.endpoint)?;
        Ok(Self {
            endpoint: endpoint.to_string(),
            tls: uri.scheme() == Some(&http::uri::Scheme::HTTPS),
            protocol: Protocol::Grpc,
            headers: http::HeaderMap::new(),
            tls_settings: OtlpTls::default(),
            resource: resource_for(config),
        })
    }

    /// Export over `protocol` instead of gRPC.
    #[must_use]
    pub fn with_protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// Send `headers` with every export request. Headers from the process
    /// environment (`OTEL_EXPORTER_OTLP_*HEADERS`) still apply and replace
    /// any of the same name.
    #[must_use]
    pub fn with_headers(mut self, headers: http::HeaderMap) -> Self {
        self.headers = headers;
        self
    }

    /// Reach the collector the way `transport` describes.
    #[must_use]
    pub fn with_transport(self, transport: &CollectorTransport) -> Self {
        self.with_protocol(transport.protocol)
            .with_headers(transport.headers.clone())
            .with_tls(transport.tls.clone())
    }

    /// Verify an `https://` collector and authenticate to it with `tls`.
    #[must_use]
    pub fn with_tls(mut self, tls: OtlpTls) -> Self {
        self.tls_settings = tls;
        self
    }

    /// The URL of `signal_path` under the endpoint, for OTLP/HTTP export.
    pub(crate) fn http_signal_url(&self, signal_path: &str) -> Result<String, SetupError> {
        signal_url(&self.endpoint, signal_path)
            .map(|url| url.to_string())
            .map_err(|source| SetupError::InvalidSignalUrl {
                endpoint: self.endpoint.clone(),
                source,
            })
    }

    /// Point an exporter builder at this target, over TLS for `https://`.
    pub(crate) fn configure<B>(&self, builder: B) -> B
    where
        B: WithExportConfig + WithTonicConfig,
    {
        let builder = builder
            .with_endpoint(self.endpoint.clone())
            .with_metadata(MetadataMap::from_headers(self.headers.clone()));
        if self.tls {
            builder.with_tls_config(self.tls_settings.grpc_config())
        } else {
            builder
        }
    }

    /// Point an OTLP/HTTP exporter builder at `signal_path` under this
    /// target.
    pub(crate) fn configure_http<B>(
        &self,
        builder: B,
        signal_path: &str,
        timeout_var: &str,
    ) -> Result<B, SetupError>
    where
        B: WithExportConfig + WithHttpConfig,
    {
        let headers = self
            .headers
            .iter()
            .filter_map(|(name, value)| Some((name.to_string(), value.to_str().ok()?.to_string())))
            .collect();
        Ok(builder
            .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
            .with_endpoint(self.http_signal_url(signal_path)?)
            .with_http_client(OtlpHttpClient::new(
                self.tls.then_some(&self.tls_settings),
                transport::export_timeout(timeout_var),
            )?)
            .with_headers(headers))
    }

    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    #[must_use]
    pub fn resource(&self) -> &Resource {
        &self.resource
    }

    /// Fails when TLS settings are given for a plaintext endpoint.
    pub(crate) fn check_tls(&self) -> Result<(), SetupError> {
        if self.tls || self.tls_settings.is_default() {
            Ok(())
        } else {
            Err(SetupError::TlsWithoutHttps {
                endpoint: self.endpoint.clone(),
            })
        }
    }

    /// Build a trace provider that exports spans to this target in batches.
    pub fn tracer_provider(&self) -> Result<SdkTracerProvider, SetupError> {
        self.check_tls()?;
        let exporter = match self.protocol {
            Protocol::Grpc => self
                .configure(SpanExporter::builder().with_tonic())
                .build()?,
            Protocol::HttpProtobuf => self
                .configure_http(
                    SpanExporter::builder().with_http(),
                    "v1/traces",
                    "OTEL_EXPORTER_OTLP_TRACES_TIMEOUT",
                )?
                .build()?,
        };
        Ok(SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(self.resource.clone())
            .build())
    }
}

/// Build an OTLP trace provider.
pub fn build_provider(config: &OtlpExportConfig<'_>) -> Result<SdkTracerProvider, SetupError> {
    OtlpTarget::new(config)?.tracer_provider()
}

/// Build the provider for an optional OTLP configuration.
///
/// Telemetry setup failures disable export and remain available for the caller
/// to report after its tracing subscriber is installed.
#[must_use]
pub fn provider_for(
    config: Option<OtlpExportConfig<'_>>,
) -> (Option<SdkTracerProvider>, Option<SetupError>) {
    match config.as_ref().map(build_provider) {
        None => (None, None),
        Some(Ok(provider)) => (Some(provider), None),
        Some(Err(error)) => (None, Some(error)),
    }
}

/// Filtered OpenTelemetry layer returned by [`layer`].
pub type OtlpLayer<S> = tracing_subscriber::filter::Filtered<
    OpenTelemetryLayer<S, SdkTracer>,
    tracing_subscriber::filter::FilterFn,
    S,
>;

pub type TargetOtlpLayer<S> =
    tracing_subscriber::filter::Filtered<OpenTelemetryLayer<S, SdkTracer>, TargetPrefixFilter, S>;

#[derive(Debug, Clone)]
pub struct TargetPrefixFilter {
    prefixes: Vec<&'static str>,
    include: bool,
}

impl<S> Filter<S> for TargetPrefixFilter {
    fn enabled(&self, metadata: &tracing::Metadata<'_>, _ctx: &Context<'_, S>) -> bool {
        let matches_prefix = self
            .prefixes
            .iter()
            .any(|prefix| metadata.target().starts_with(prefix));
        metadata.is_span()
            && !metadata.target().starts_with("opentelemetry")
            && (matches_prefix == self.include)
    }
}

/// Build a tracing layer that exports spans and excludes exporter callsites.
pub fn layer<S>(provider: &SdkTracerProvider, instrumentation_scope: &'static str) -> OtlpLayer<S>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    tracing_opentelemetry::layer()
        .with_tracer(provider.tracer(instrumentation_scope))
        .with_filter(tracing_subscriber::filter::filter_fn(|metadata| {
            metadata.is_span() && !metadata.target().starts_with("opentelemetry")
        }))
}

/// Build a tracing layer that exports only spans from `target_prefix`.
pub fn layer_for_target_prefix<S>(
    provider: &SdkTracerProvider,
    instrumentation_scope: &'static str,
    target_prefix: &'static str,
) -> TargetOtlpLayer<S>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    layer_for_target_prefixes(provider, instrumentation_scope, [target_prefix])
}

/// Build a tracing layer that exports only spans from `target_prefixes`.
pub fn layer_for_target_prefixes<S>(
    provider: &SdkTracerProvider,
    instrumentation_scope: &'static str,
    target_prefixes: impl IntoIterator<Item = &'static str>,
) -> TargetOtlpLayer<S>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    tracing_opentelemetry::layer()
        .with_tracer(provider.tracer(instrumentation_scope))
        .with_filter(TargetPrefixFilter {
            prefixes: target_prefixes.into_iter().collect(),
            include: true,
        })
}

/// Build a tracing layer that excludes spans from `target_prefix`.
///
/// `None` excludes no application spans.
pub fn layer_excluding_target_prefix<S>(
    provider: &SdkTracerProvider,
    instrumentation_scope: &'static str,
    target_prefix: Option<&'static str>,
) -> TargetOtlpLayer<S>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    layer_excluding_target_prefixes(provider, instrumentation_scope, target_prefix)
}

/// Build a tracing layer that excludes spans from `target_prefixes`.
///
/// An empty iterator excludes no application spans.
pub fn layer_excluding_target_prefixes<S>(
    provider: &SdkTracerProvider,
    instrumentation_scope: &'static str,
    target_prefixes: impl IntoIterator<Item = &'static str>,
) -> TargetOtlpLayer<S>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    tracing_opentelemetry::layer()
        .with_tracer(provider.tracer(instrumentation_scope))
        .with_filter(TargetPrefixFilter {
            prefixes: target_prefixes.into_iter().collect(),
            include: false,
        })
}

#[cfg(test)]
pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_status_guard_marks_only_unfinished_results() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let _tracing_lock = test_lock();
        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry().with(layer(&provider, "guard-test"));

        tracing::subscriber::with_default(subscriber, || {
            let failed =
                tracing::info_span!("failed-operation", otel.status_code = tracing::field::Empty);
            {
                let _entered = failed.enter();
                drop(ErrorStatusGuard::current());
            }
            drop(failed);

            let succeeded = tracing::info_span!(
                "successful-operation",
                otel.status_code = tracing::field::Empty
            );
            {
                let _entered = succeeded.enter();
                ErrorStatusGuard::current().finish(Ok::<_, ()>(())).unwrap();
            }
            drop(succeeded);
        });

        let spans = exporter.get_finished_spans().unwrap();
        let failed = spans
            .iter()
            .find(|span| span.name == "failed-operation")
            .unwrap();
        assert!(matches!(
            failed.status,
            opentelemetry::trace::Status::Error { .. }
        ));
        let succeeded = spans
            .iter()
            .find(|span| span.name == "successful-operation")
            .unwrap();
        assert_eq!(succeeded.status, opentelemetry::trace::Status::Unset);
    }

    #[test]
    fn target_scoped_layers_partition_in_process_driver_spans() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let _tracing_lock = test_lock();
        let gateway_exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let gateway_provider = SdkTracerProvider::builder()
            .with_simple_exporter(gateway_exporter.clone())
            .build();
        let driver_exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let driver_provider = SdkTracerProvider::builder()
            .with_simple_exporter(driver_exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(layer_excluding_target_prefix(
                &gateway_provider,
                "gateway",
                Some("driver_target"),
            ))
            .with(layer_for_target_prefix(
                &driver_provider,
                "driver",
                "driver_target",
            ));

        tracing::subscriber::with_default(subscriber, || {
            let gateway = tracing::info_span!(target: "gateway_target", "gateway.span");
            let _entered = gateway.enter();
            drop(tracing::info_span!(target: "driver_target::operation", "driver.span"));
        });

        gateway_provider.force_flush().unwrap();
        driver_provider.force_flush().unwrap();
        let gateway_spans = gateway_exporter.get_finished_spans().unwrap();
        let driver_spans = driver_exporter.get_finished_spans().unwrap();
        assert_eq!(
            gateway_spans
                .iter()
                .map(|span| span.name.as_ref())
                .collect::<Vec<_>>(),
            ["gateway.span"]
        );
        assert_eq!(
            driver_spans
                .iter()
                .map(|span| span.name.as_ref())
                .collect::<Vec<_>>(),
            ["driver.span"]
        );
        assert_eq!(
            driver_spans[0].span_context.trace_id(),
            gateway_spans[0].span_context.trace_id()
        );
        assert_eq!(
            driver_spans[0].parent_span_id,
            gateway_spans[0].span_context.span_id()
        );
    }

    #[test]
    fn excluding_no_target_prefix_exports_all_application_spans() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let _tracing_lock = test_lock();
        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(layer_excluding_target_prefix(&provider, "gateway", None));

        tracing::subscriber::with_default(subscriber, || {
            drop(tracing::info_span!(target: "\0driver_target", "nul-prefixed.span"));
            drop(tracing::info_span!(target: "gateway_target", "gateway.span"));
        });

        provider.force_flush().unwrap();
        let spans = exporter.get_finished_spans().unwrap();
        assert_eq!(spans.len(), 2);
        assert!(spans.iter().any(|span| span.name == "nul-prefixed.span"));
        assert!(spans.iter().any(|span| span.name == "gateway.span"));
    }

    #[test]
    fn resource_uses_fixed_service_identity_and_custom_attributes() {
        let resource = resource_for(&OtlpExportConfig {
            endpoint: "http://127.0.0.1:4317",
            service_name: ServiceName::Fixed("openshell-driver-vm"),
            service_version: Some("1.2.3"),
            resource_attributes: vec![KeyValue::new("openshell.gateway.name", "vm-dev")],
        });

        assert_eq!(
            resource
                .get(&opentelemetry::Key::from_static_str("service.name"))
                .map(|value| value.to_string()),
            Some("openshell-driver-vm".to_string())
        );
        assert_eq!(
            resource
                .get(&opentelemetry::Key::from_static_str("service.version"))
                .map(|value| value.to_string()),
            Some("1.2.3".to_string())
        );
        assert_eq!(
            resource
                .get(&opentelemetry::Key::from_static_str(
                    "openshell.gateway.name",
                ))
                .map(|value| value.to_string()),
            Some("vm-dev".to_string())
        );
    }

    #[tokio::test]
    async fn tls_settings_need_an_https_endpoint() {
        let pki = openshell_otel_test_support::TestPki::generate();
        let tls = OtlpTls::from_pem(Some(pki.ca_pem.as_bytes()), None).unwrap();
        for protocol in [Protocol::Grpc, Protocol::HttpProtobuf] {
            let target = |endpoint| {
                OtlpTarget::new(&OtlpExportConfig {
                    endpoint,
                    service_name: ServiceName::Fixed("test-service"),
                    service_version: None,
                    resource_attributes: Vec::new(),
                })
                .unwrap()
                .with_protocol(protocol)
                .with_tls(tls.clone())
            };
            assert!(matches!(
                target("http://collector:4317").tracer_provider(),
                Err(SetupError::TlsWithoutHttps { .. })
            ));
            assert!(matches!(
                target("http://collector:4317").log_exporter(),
                Err(SetupError::TlsWithoutHttps { .. })
            ));
            assert!(target("https://collector:4317").tracer_provider().is_ok());
        }
    }

    #[test]
    fn debug_output_names_headers_without_their_values() {
        let target = OtlpTarget::new(&OtlpExportConfig {
            endpoint: "http://collector:4317",
            service_name: ServiceName::Fixed("test-service"),
            service_version: None,
            resource_attributes: Vec::new(),
        })
        .unwrap()
        .with_headers(parse_otlp_headers("authorization=Bearer%20secret-token"));

        let debug = format!("{target:?}");
        assert!(debug.contains("authorization"), "{debug}");
        assert!(!debug.contains("secret-token"), "{debug}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn trace_provider_sends_headers_as_grpc_metadata() {
        use opentelemetry::trace::Tracer as _;

        let collector = openshell_otel_test_support::OtlpTestServer::start().await;
        let provider = OtlpTarget::new(&OtlpExportConfig {
            endpoint: collector.endpoint(),
            service_name: ServiceName::Fixed("test-service"),
            service_version: None,
            resource_attributes: Vec::new(),
        })
        .unwrap()
        .with_headers(parse_otlp_headers("authorization=Bearer%20token"))
        .tracer_provider()
        .unwrap();
        provider.tracer("test").in_span("grpc-span", |_| {});
        let flush = tokio::task::spawn_blocking(move || provider.force_flush());

        collector.wait_for_export().await;
        flush.await.unwrap().expect("flush succeeds");
        assert_eq!(collector.received().trace_authorizations, ["Bearer token"]);
    }

    #[tokio::test]
    async fn malformed_endpoint_disables_export_with_a_reportable_error() {
        let (provider, error) = provider_for(Some(OtlpExportConfig {
            endpoint: "definitely not a url",
            service_name: ServiceName::Fixed("test-service"),
            service_version: None,
            resource_attributes: Vec::new(),
        }));

        assert!(provider.is_none());
        assert!(matches!(error, Some(SetupError::InvalidEndpoint { .. })));
    }
}
