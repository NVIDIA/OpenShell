// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The shared exporter delivers gzip-compressed spans to a collector over TLS.

use openshell_otel::{OtlpTraceConfig, ServiceName, provider_for};
use openshell_otel_test_support::OtlpTestServer;
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use tonic::transport::Identity;
use tracing_subscriber::layer::SubscriberExt as _;

#[tokio::test(flavor = "multi_thread")]
#[allow(unsafe_code)]
async fn gzip_spans_reach_a_collector_trusted_through_platform_roots() {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();

    let server_key = KeyPair::generate().unwrap();
    let mut server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server_params.signed_by(&server_key, &ca, &ca_key).unwrap();

    let roots = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(roots.path(), ca.pem()).unwrap();
    // This binary has one test, so nothing else reads the environment.
    unsafe {
        std::env::set_var("SSL_CERT_FILE", roots.path());
        std::env::set_var("OTEL_EXPORTER_OTLP_COMPRESSION", "gzip");
    }

    let collector = OtlpTestServer::start_tls(Identity::from_pem(
        server_cert.pem(),
        server_key.serialize_pem(),
    ))
    .await;
    let (provider, error) = provider_for(Some(OtlpTraceConfig {
        endpoint: collector.endpoint(),
        service_name: ServiceName::Fixed("tls-test"),
        service_version: None,
        resource_attributes: Vec::new(),
    }));
    assert!(error.is_none(), "{error:?}");
    let provider = provider.unwrap();
    let subscriber =
        tracing_subscriber::registry().with(openshell_otel::layer(&provider, "tls-test"));
    tracing::subscriber::with_default(subscriber, || drop(tracing::info_span!("tls.span")));
    provider.force_flush().unwrap();
    collector.wait_for_export().await;
    provider.shutdown().unwrap();
    let received = collector.shutdown().await;

    assert!(received.spans.iter().any(|span| span.name == "tls.span"));
    assert_eq!(received.encodings, ["gzip"]);
}
