// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Separate test executable so another test cannot initialize the global context.
#[tokio::test]
async fn crypto_use_without_a_context_returns_errors() {
    use openshell_crypto::{CryptoError, tls};
    assert!(matches!(
        openshell_crypto::try_default_context(),
        Err(CryptoError::MissingContext)
    ));
    assert!(matches!(
        tls::try_ensure_default_provider(),
        Err(CryptoError::MissingContext)
    ));
    assert!(tls::try_client_builder().is_err());
    assert!(tls::try_server_builder().is_err());
    assert!(openshell_sdk::oidc::try_http_client(false).is_err());
    assert!(
        openshell_sdk::oidc::discover("https://localhost", false)
            .await
            .is_err()
    );
    for insecure in [false, true] {
        let mut config = openshell_sdk::ClientConfig::new("https://localhost:1");
        config.insecure_skip_verify = insecure;
        let error = openshell_sdk::transport::build_channel(&config)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("install_default_context"),
            "{error}"
        );
    }
    assert!(rustls::crypto::CryptoProvider::get_default().is_none());
    use openshell_extension_core::{ExtensionChannelConfig, TransportError, connect_channel};
    assert!(matches!(
        connect_channel(&ExtensionChannelConfig::new("https://localhost:1")).await,
        Err(TransportError::Crypto(CryptoError::MissingContext))
    ));
    let target = openshell_otel::OtlpTarget::new(&openshell_otel::OtlpExportConfig {
        endpoint: "https://localhost:1",
        service_name: openshell_otel::ServiceName::Fixed("consumer-test"),
        service_version: None,
        resource_attributes: vec![],
    })
    .unwrap();
    assert!(matches!(
        target.tracer_provider(),
        Err(openshell_otel::SetupError::Crypto(
            CryptoError::MissingContext
        ))
    ));
    assert!(matches!(
        target.log_exporter_with_headers(None),
        Err(openshell_otel::SetupError::Crypto(
            CryptoError::MissingContext
        ))
    ));
}
