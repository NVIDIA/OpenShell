// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared TLS export scenario for the one-test-per-binary TLS tests.

use openshell_otel::{OtlpExportConfig, ServiceName, provider_for};
use openshell_otel_test_support::{OtlpTestServer, ReceivedTraces};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
};
use tonic::transport::Identity;
use tracing_subscriber::layer::SubscriberExt as _;

fn new_ca() -> (Certificate, KeyPair) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    (params.self_signed(&key).unwrap(), key)
}

/// Export one gzip span to a TLS collector and return the flush outcome and
/// what the collector received. Only one CA is in the platform roots. The
/// collector's certificate is signed by that CA when `server_trusted`, and by
/// an unrelated CA otherwise.
///
/// Callers must be the only test in their binary, since this sets the
/// process environment.
#[allow(unsafe_code)]
pub async fn export_span_over_tls(server_trusted: bool) -> (bool, ReceivedTraces) {
    let (trusted_ca, trusted_key) = new_ca();
    let (other_ca, other_key) = new_ca();
    let (signer, signer_key) = if server_trusted {
        (&trusted_ca, &trusted_key)
    } else {
        (&other_ca, &other_key)
    };

    let server_key = KeyPair::generate().unwrap();
    let mut server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server_params
        .signed_by(&server_key, signer, signer_key)
        .unwrap();

    let roots = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(roots.path(), trusted_ca.pem()).unwrap();
    // The caller's binary has one test, so nothing else reads the environment.
    unsafe {
        std::env::set_var("SSL_CERT_FILE", roots.path());
        std::env::set_var("OTEL_EXPORTER_OTLP_COMPRESSION", "gzip");
    }

    let collector = OtlpTestServer::start_tls(Identity::from_pem(
        server_cert.pem(),
        server_key.serialize_pem(),
    ))
    .await;
    let (provider, error) = provider_for(Some(OtlpExportConfig {
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
    let flushed = provider.force_flush().is_ok();
    if flushed {
        collector.wait_for_export().await;
    }
    let _ = provider.shutdown();
    (flushed, collector.shutdown().await)
}
