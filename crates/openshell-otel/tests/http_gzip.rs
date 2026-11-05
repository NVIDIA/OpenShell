// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The only test in its binary, since it sets the process environment.

use openshell_otel::{OtlpExportConfig, OtlpTarget, Protocol, ServiceName};
use openshell_otel_test_support::OtlpHttpTestServer;
use opentelemetry::trace::{Tracer as _, TracerProvider as _};

#[tokio::test(flavor = "multi_thread")]
#[allow(unsafe_code)]
async fn http_exports_honor_the_compression_variable() {
    // Nothing else in this binary reads the environment.
    unsafe { std::env::set_var("OTEL_EXPORTER_OTLP_COMPRESSION", "gzip") };
    let mut collector = OtlpHttpTestServer::start().await;
    let provider = OtlpTarget::new(&OtlpExportConfig {
        endpoint: collector.endpoint(),
        service_name: ServiceName::Fixed("gzip-test"),
        service_version: None,
        resource_attributes: Vec::new(),
    })
    .unwrap()
    .with_protocol(Protocol::HttpProtobuf)
    .tracer_provider()
    .expect("gzip is supported over HTTP");
    provider.tracer("test").in_span("gzip-span", |_| {});
    let flush = tokio::task::spawn_blocking(move || provider.force_flush());

    assert_eq!(
        collector.next_export().await.headers["content-encoding"],
        "gzip"
    );
    flush.await.unwrap().expect("flush succeeds");
}
