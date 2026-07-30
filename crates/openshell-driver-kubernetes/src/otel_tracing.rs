// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OpenTelemetry trace exporting for the Kubernetes compute driver.

use openshell_otel::{OtlpTraceConfig, SdkTracerProvider, ServiceName, SetupError};
pub use openshell_otel::{compute_driver_rpc_layer, compute_driver_rpc_operation};
use tracing::Subscriber;
use tracing_subscriber::registry::LookupSpan;

const SERVICE_NAME: &str = "openshell-driver-kubernetes";
const INSTRUMENTATION_SCOPE: &str = "openshell-driver-kubernetes";
pub const IN_PROCESS_TARGET_PREFIX: &str = "openshell_driver_kubernetes";

/// Build a tracer provider for the configured OTLP/gRPC endpoint and gateway.
#[must_use]
pub fn provider_for(
    endpoint: Option<&str>,
    gateway_name: Option<&str>,
) -> (Option<SdkTracerProvider>, Option<SetupError>) {
    openshell_otel::provider_for(endpoint.map(|endpoint| {
        OtlpTraceConfig {
            endpoint,
            service_name: ServiceName::Fixed(SERVICE_NAME),
            service_version: Some(openshell_core::VERSION),
            resource_attributes: gateway_name
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(|name| {
                    vec![opentelemetry::KeyValue::new(
                        "openshell.gateway.name",
                        name.to_string(),
                    )]
                })
                .unwrap_or_default(),
        }
    }))
}

pub fn layer<S>(provider: &SdkTracerProvider) -> openshell_otel::OtlpLayer<S>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    openshell_otel::layer(provider, INSTRUMENTATION_SCOPE)
}

pub fn in_process_layer<S>(provider: &SdkTracerProvider) -> openshell_otel::TargetOtlpLayer<S>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    openshell_otel::layer_for_target_prefix(
        provider,
        INSTRUMENTATION_SCOPE,
        IN_PROCESS_TARGET_PREFIX,
    )
}

#[cfg(test)]
pub(crate) async fn test_lock() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    static INITIALIZED: std::sync::LazyLock<()> = std::sync::LazyLock::new(|| {
        tracing::subscriber::set_global_default(tracing_subscriber::registry())
            .expect("test tracing subscriber installs once");
    });

    let guard = LOCK.lock().await;
    std::sync::LazyLock::force(&INITIALIZED);
    guard
}

#[cfg(test)]
mod tests {
    use openshell_otel_test_support::OtlpTestServer;
    use tracing_subscriber::layer::SubscriberExt as _;

    #[test]
    fn compute_driver_rpc_names_are_explicitly_mapped_and_schema_bounded() {
        assert_eq!(
            super::compute_driver_rpc_operation(
                "/openshell.compute.v1.ComputeDriver/GetCapabilities"
            ),
            ("driver.get_capabilities", "get_capabilities")
        );
        assert_eq!(
            super::compute_driver_rpc_operation(
                "/openshell.compute.v1.ComputeDriver/AttackerControlled12345"
            ),
            ("driver.unknown", "unknown")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tracing_kubernetes_driver_spans_reach_otlp_collector_with_resource_identity() {
        let _tracing_lock = super::test_lock().await;
        let collector = OtlpTestServer::start().await;
        let (provider, error) =
            super::provider_for(Some(collector.endpoint()), Some("kubernetes-dev"));
        assert!(error.is_none());
        let provider = provider.expect("provider");
        let subscriber = tracing_subscriber::registry().with(super::layer(&provider));
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("kubernetes.create_sandbox", sandbox.id = "sb-otlp");
            drop(span.enter());
            drop(span);
        });
        provider.force_flush().unwrap();
        collector.wait_for_export().await;
        provider.shutdown().unwrap();
        let received = collector.shutdown().await;

        assert!(
            received
                .spans
                .iter()
                .any(|span| span.name == "kubernetes.create_sandbox")
        );
        assert_eq!(received.gateway_names, ["kubernetes-dev"]);
        assert!(
            received
                .service_names
                .iter()
                .any(|name| name == super::SERVICE_NAME)
        );
    }
}
