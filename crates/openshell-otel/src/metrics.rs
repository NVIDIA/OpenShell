// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OTLP metric export support.

use opentelemetry_otlp::MetricExporter;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};

use crate::{OtlpTarget, Protocol, SetupError};

impl OtlpTarget {
    /// Build a meter provider that periodically exports to this collector.
    pub fn meter_provider(&self) -> Result<SdkMeterProvider, SetupError> {
        self.check_tls()?;
        let exporter = match self.protocol {
            Protocol::Grpc => self
                .configure(MetricExporter::builder().with_tonic())
                .build()?,
            Protocol::HttpProtobuf => self
                .configure_http(
                    MetricExporter::builder().with_http(),
                    "v1/metrics",
                    "OTEL_EXPORTER_OTLP_METRICS_TIMEOUT",
                )?
                .build()?,
        };
        Ok(SdkMeterProvider::builder()
            .with_reader(PeriodicReader::builder(exporter).build())
            .with_resource(self.resource().clone())
            .build())
    }
}

#[cfg(test)]
mod tests {
    use openshell_otel_test_support::{OtlpHttpTestServer, OtlpTestServer, ServerTls, TestPki};
    use opentelemetry::{KeyValue, metrics::MeterProvider as _};
    use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
    use opentelemetry_proto::tonic::metrics::v1::{metric, number_data_point};
    use prost::Message as _;

    use super::*;
    use crate::{OtlpExportConfig, OtlpTls, ServiceName};

    fn target(endpoint: &str, protocol: Protocol) -> OtlpTarget {
        OtlpTarget::new(&OtlpExportConfig {
            endpoint,
            service_name: ServiceName::Fixed("metrics-test"),
            service_version: Some("1.2.3"),
            resource_attributes: vec![KeyValue::new("openshell.gateway.name", "test-gateway")],
        })
        .unwrap()
        .with_protocol(protocol)
    }

    fn assert_counter(request: &ExportMetricsServiceRequest) {
        let resource = &request.resource_metrics[0];
        assert!(
            resource
                .resource
                .as_ref()
                .unwrap()
                .attributes
                .iter()
                .any(|attribute| attribute.key == "service.name"
                    && format!("{:?}", attribute.value).contains("metrics-test"))
        );
        let metric = &resource.scope_metrics[0].metrics[0];
        assert_eq!(metric.name, "requests_total");
        let Some(metric::Data::Sum(sum)) = &metric.data else {
            panic!("expected counter sum")
        };
        assert!(sum.is_monotonic);
        assert_eq!(
            sum.data_points[0].value,
            Some(number_data_point::Value::AsInt(7))
        );
        assert_eq!(sum.data_points[0].attributes[0].key, "method");
    }

    #[tokio::test]
    async fn metrics_reuse_headers_and_mutual_tls_over_both_protocols() {
        crate::test_environment::Environment::new()
            .remove("OTEL_EXPORTER_OTLP_HEADERS")
            .remove("OTEL_EXPORTER_OTLP_METRICS_HEADERS")
            .run_async(async {
                let pki = TestPki::generate();
                let server_tls = ServerTls::mutual(&pki);
                let tls = OtlpTls::from_pem(
                    Some(pki.ca_pem.as_bytes()),
                    Some((
                        pki.client.cert_pem.as_bytes(),
                        pki.client.key_pem.as_bytes(),
                    )),
                )
                .unwrap();
                for protocol in [Protocol::Grpc, Protocol::HttpProtobuf] {
                    let grpc = OtlpTestServer::start_with_tls(&server_tls).await;
                    let mut http = OtlpHttpTestServer::start_with_tls(&server_tls).await;
                    let endpoint = if protocol == Protocol::Grpc {
                        grpc.endpoint()
                    } else {
                        http.endpoint()
                    };
                    let provider = target(endpoint, protocol)
                        .with_tls(tls.clone())
                        .with_headers(crate::parse_otlp_headers("authorization=Bearer%20metrics"))
                        .meter_provider()
                        .unwrap();
                    provider
                        .meter("test")
                        .u64_counter("requests_total")
                        .build()
                        .add(7, &[KeyValue::new("method", "GET")]);
                    let flush = {
                        let provider = provider.clone();
                        tokio::task::spawn_blocking(move || provider.force_flush())
                    };
                    flush.await.unwrap().unwrap();
                    tokio::task::spawn_blocking(move || provider.shutdown())
                        .await
                        .unwrap()
                        .unwrap();
                    if protocol == Protocol::Grpc {
                        let received = grpc.shutdown().await;
                        assert_eq!(received.metric_authorizations[0], "Bearer metrics");
                        assert_counter(&received.metric_exports[0]);
                    } else {
                        let export = http.next_export().await;
                        assert_eq!(export.path, "/v1/metrics");
                        assert_eq!(export.headers["authorization"], "Bearer metrics");
                        assert_counter(&ExportMetricsServiceRequest::decode(export.body).unwrap());
                        grpc.shutdown().await;
                    }
                }
            })
            .await;
    }

    #[tokio::test]
    async fn metrics_export_periodically_without_scraping_and_flush_on_shutdown() {
        crate::test_environment::Environment::new()
            .set("OTEL_METRIC_EXPORT_INTERVAL", "25")
            .set("OTEL_EXPORTER_OTLP_METRICS_HEADERS", "x-metrics=from-env")
            .set(
                "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
                "http://ignored.invalid:4318",
            )
            .run_async(async {
                let mut collector = OtlpHttpTestServer::start().await;
                let provider = target(
                    &format!("{}/prefix", collector.endpoint()),
                    Protocol::HttpProtobuf,
                )
                .meter_provider()
                .unwrap();
                let counter = provider.meter("test").u64_counter("requests_total").build();
                counter.add(7, &[KeyValue::new("method", "GET")]);
                for _ in 0..2 {
                    let export = collector.next_export().await;
                    assert_eq!(export.path, "/prefix/v1/metrics");
                    assert_eq!(export.headers["x-metrics"], "from-env");
                    assert_counter(&ExportMetricsServiceRequest::decode(export.body).unwrap());
                }
                tokio::task::spawn_blocking(move || provider.shutdown())
                    .await
                    .unwrap()
                    .unwrap();
                collector.next_export().await;
            })
            .await;
    }
}
