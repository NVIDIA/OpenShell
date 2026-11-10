// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The only test in its binary, since it sets the process environment.

use openshell_otel::{OtlpExportConfig, OtlpTarget, Protocol, ServiceName, SetupError, TlsError};

fn target(endpoint: &str) -> OtlpTarget {
    OtlpTarget::new(&OtlpExportConfig {
        endpoint,
        service_name: ServiceName::Fixed("roots-test"),
        service_version: None,
        resource_attributes: Vec::new(),
    })
    .unwrap()
    .with_protocol(Protocol::HttpProtobuf)
}

#[tokio::test]
#[allow(unsafe_code)]
async fn only_https_collectors_need_platform_roots() {
    let empty = tempfile::NamedTempFile::new().unwrap();
    // Nothing else in this binary reads the environment.
    unsafe {
        std::env::set_var("SSL_CERT_FILE", empty.path());
        std::env::set_var("SSL_CERT_DIR", empty.path());
    }

    assert!(target("http://collector:4318").tracer_provider().is_ok());
    assert!(matches!(
        target("https://collector:4318").tracer_provider(),
        Err(SetupError::Tls(TlsError::NoPlatformRoots))
    ));
}
