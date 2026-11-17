// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// TLS-only consumers may have installed Rustls before importing OpenShell.
// This is a separate process: no facade context is installed by another test.
#[test]
fn sdk_preserves_the_hosts_tls_provider() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .unwrap();
    let host = rustls::crypto::CryptoProvider::get_default().unwrap();
    let _ = openshell_sdk::oidc::http_client(false);
    let config = openshell_sdk::transport::build_insecure_rustls_config().unwrap();
    assert!(std::sync::Arc::ptr_eq(host, config.crypto_provider()));
}
