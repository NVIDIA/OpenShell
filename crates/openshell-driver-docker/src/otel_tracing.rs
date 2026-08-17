// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OpenTelemetry trace exporting for the Docker compute driver.

use openshell_otel::{OtlpTraceConfig, SdkTracerProvider, ServiceName, SetupError};
use tracing::Subscriber;
use tracing_subscriber::registry::LookupSpan;

const SERVICE_NAME: &str = "openshell-driver-docker";
const INSTRUMENTATION_SCOPE: &str = "openshell-driver-docker";
pub const IN_PROCESS_TARGET_PREFIX: &str = "openshell_driver_docker";

#[must_use]
pub fn provider_for(endpoint: Option<&str>) -> (Option<SdkTracerProvider>, Option<SetupError>) {
    openshell_otel::provider_for(endpoint.map(|endpoint| OtlpTraceConfig {
        endpoint,
        service_name: ServiceName::Fixed(SERVICE_NAME),
        service_version: Some(openshell_core::VERSION),
        resource_attributes: Vec::new(),
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tracing_docker_driver_spans_reach_otlp_collector_with_distinct_service_name() {
        let _tracing_lock = super::test_lock().await;
        let collector = OtlpTestServer::start().await;

        let (provider, error) = super::provider_for(Some(collector.endpoint()));
        assert!(error.is_none());
        let provider = provider.expect("provider");
        let subscriber = tracing_subscriber::registry().with(super::layer(&provider));
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("docker.schedule_sandbox", sandbox.id = "sb-otlp");
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
                .any(|span| span.name == "docker.schedule_sandbox")
        );
        assert!(
            received
                .service_names
                .iter()
                .any(|name| name == "openshell-driver-docker")
        );
    }
}
