// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process-owned supervisor metrics export.

use openshell_core::jwt::{OtlpExportCredentials, OtlpTlsMaterial, SecretOtlpHeaders};
use openshell_core::sandbox_env::OtlpProtocol;
use openshell_otel::{
    CollectorTransport, OtlpExportConfig, OtlpTarget, SdkMeterProvider, ServiceName, SetupError,
};
use opentelemetry::KeyValue;
use opentelemetry::metrics::MeterProvider as _;

const SERVICE_NAME: &str = "openshell-supervisor";

/// Create the process's metrics provider inside the runtime driving OTLP.
pub fn start(
    endpoint: &str,
    protocol: OtlpProtocol,
    credentials: OtlpExportCredentials<'_>,
    gateway_name: Option<&str>,
    sandbox_count: impl Fn() -> u64 + Send + Sync + 'static,
) -> Result<SdkMeterProvider, SetupError> {
    let mut resource_attributes = openshell_otel::gateway_resource_attributes(gateway_name, None);
    resource_attributes.push(KeyValue::new(
        "service.instance.id",
        uuid::Uuid::new_v4().to_string(),
    ));
    let config = OtlpExportConfig {
        endpoint,
        service_name: ServiceName::Fixed(SERVICE_NAME),
        service_version: Some(openshell_core::VERSION),
        resource_attributes,
    };
    let transport = CollectorTransport {
        protocol: protocol.into(),
        headers: credentials
            .headers
            .map(SecretOtlpHeaders::expose_secret)
            .map(openshell_otel::parse_otlp_headers)
            .unwrap_or_default(),
        tls: credentials
            .tls
            .map(OtlpTlsMaterial::otlp_tls)
            .transpose()?
            .unwrap_or_default(),
    };
    let provider = OtlpTarget::new(&config)?
        .with_transport(&transport)
        .meter_provider()?;
    let meter = provider.meter(SERVICE_NAME);
    openshell_supervisor_network::metrics::install(&meter);
    meter
        .u64_observable_gauge("openshell_supervisor_sandboxes_active")
        .with_description("Sandboxes assigned to this supervisor.")
        .with_callback(move |observer| observer.observe(sandbox_count(), &[]))
        .build();
    Ok(provider)
}

/// Flush final metrics with the SDK reader's bounded shutdown wait.
pub fn shutdown(provider: &SdkMeterProvider) {
    if let Err(error) = provider.shutdown() {
        tracing::warn!(%error, "OTLP metrics provider shutdown failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_otel_test_support::OtlpHttpTestServer;
    use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
    use opentelemetry_proto::tonic::metrics::v1::metric::Data;
    use prost::Message as _;

    #[tokio::test(flavor = "multi_thread")]
    async fn pushes_supervisor_gauges_and_resource_to_the_collector() {
        let mut collector = OtlpHttpTestServer::start().await;
        let path = format!("{}/receiver", collector.endpoint());
        let headers = SecretOtlpHeaders::new("x-collector-test=metrics".to_string());
        let count = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(2));
        let provider = start(
            &path,
            OtlpProtocol::HttpProtobuf,
            OtlpExportCredentials {
                headers: Some(&headers),
                tls: None,
            },
            Some("test-gateway"),
            {
                let count = count.clone();
                move || count.load(std::sync::atomic::Ordering::Relaxed)
            },
        )
        .unwrap();

        for assigned in [2, 1, 0] {
            count.store(assigned, std::sync::atomic::Ordering::Relaxed);
            let flush = provider.clone();
            tokio::task::spawn_blocking(move || flush.force_flush().unwrap())
                .await
                .unwrap();
            let received = collector.next_export().await;
            assert_eq!(received.path, "/receiver/v1/metrics");
            assert_eq!(received.headers.get("x-collector-test").unwrap(), "metrics");
            let response = ExportMetricsServiceRequest::decode(received.body).unwrap();
            let resource = &response.resource_metrics[0];
            let attributes = &resource.resource.as_ref().unwrap().attributes;
            assert!(attributes.iter().any(|kv| kv.key == "service.instance.id"));
            assert!(
                attributes
                    .iter()
                    .any(|kv| kv.key == "openshell.gateway.name")
            );
            let instruments = resource
                .scope_metrics
                .iter()
                .flat_map(|scope| &scope.metrics)
                .collect::<Vec<_>>();
            let sandboxes = instruments
                .iter()
                .find(|metric| metric.name == "openshell_supervisor_sandboxes_active")
                .unwrap();
            let Some(Data::Gauge(gauge)) = &sandboxes.data else {
                panic!("Expected the assigned sandbox gauge");
            };
            let sample = &gauge.data_points[0];
            assert_eq!(sample.attributes, []);
            assert_eq!(
                sample.value,
                Some(
                    opentelemetry_proto::tonic::metrics::v1::number_data_point::Value::AsInt(
                        i64::try_from(assigned).unwrap()
                    )
                ),
            );
            assert!(instruments.iter().any(|metric| {
                metric.name == "openshell_supervisor_connections_active"
                    && matches!(metric.data, Some(Data::Gauge(_)))
            }));
        }
        tokio::task::spawn_blocking(move || shutdown(&provider))
            .await
            .unwrap();
    }
}
