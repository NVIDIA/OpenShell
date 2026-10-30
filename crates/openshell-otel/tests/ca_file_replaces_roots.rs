// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The only test in its binary, since it sets the process environment.

use openshell_otel::{OtlpExportConfig, OtlpTarget, OtlpTls, Protocol, ServiceName};
use openshell_otel_test_support::{OtlpHttpTestServer, OtlpTestServer, ServerTls, TestPki};
use opentelemetry::trace::{Tracer as _, TracerProvider as _};

async fn delivered(endpoint: &str, protocol: Protocol, tls: Option<&OtlpTls>) -> bool {
    let mut target = OtlpTarget::new(&OtlpExportConfig {
        endpoint,
        service_name: ServiceName::Fixed("ca-test"),
        service_version: None,
        resource_attributes: Vec::new(),
    })
    .unwrap()
    .with_protocol(protocol);
    if let Some(tls) = tls {
        target = target.with_tls(tls.clone());
    }
    let provider = target.tracer_provider().unwrap();
    provider.tracer("test").in_span("ca-span", |_| {});
    tokio::task::spawn_blocking(move || provider.force_flush().is_ok())
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
#[allow(unsafe_code)]
async fn a_ca_file_replaces_the_platform_roots() {
    let platform = TestPki::generate();
    let configured = TestPki::generate();
    let roots = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(roots.path(), &platform.ca_pem).unwrap();
    // Nothing else in this binary reads the environment.
    unsafe { std::env::set_var("SSL_CERT_FILE", roots.path()) };
    let ca_file = OtlpTls::from_pem(Some(configured.ca_pem.as_bytes()), None).unwrap();

    for protocol in [Protocol::Grpc, Protocol::HttpProtobuf] {
        let server = ServerTls::server_only(&platform);
        let (endpoint, _collector): (String, Box<dyn std::any::Any>) = match protocol {
            Protocol::Grpc => {
                let collector = OtlpTestServer::start_with_tls(&server).await;
                (collector.endpoint().to_string(), Box::new(collector))
            }
            Protocol::HttpProtobuf => {
                let collector = OtlpHttpTestServer::start_with_tls(&server).await;
                (collector.endpoint().to_string(), Box::new(collector))
            }
        };
        assert!(
            delivered(&endpoint, protocol, None).await,
            "{protocol:?}: the platform roots trust the collector"
        );
        assert!(
            !delivered(&endpoint, protocol, Some(&ca_file)).await,
            "{protocol:?}: a CA file that does not trust the collector replaces them"
        );
    }
}
