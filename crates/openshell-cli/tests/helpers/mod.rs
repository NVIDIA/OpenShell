// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared helpers for CLI integration tests.
//!
//! Include this module from a test file with:
//! ```ignore
//! mod helpers;
//! ```

/// The example provider profiles in `providers/`, parsed once per test binary.
///
/// Fake gateways serve these the way a real gateway serves what an operator
/// imported. Nothing is compiled into the CLI, so the fixtures come from the
/// same files the documentation tells operators to import.
#[allow(dead_code)]
pub fn example_profiles() -> &'static [openshell_providers::ProviderTypeProfile] {
    static CATALOG: std::sync::OnceLock<Vec<openshell_providers::ProviderTypeProfile>> =
        std::sync::OnceLock::new();
    CATALOG
        .get_or_init(openshell_providers::example_profiles::load_all)
        .as_slice()
}

#[macro_export]
macro_rules! unimplemented_sandbox_template_rpcs {
    () => {
        fn create_sandbox_template<'life0, 'async_trait>(
            &'life0 self,
            _request: tonic::Request<openshell_core::proto::CreateSandboxTemplateRequest>,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            tonic::Response<openshell_core::proto::SandboxTemplateResponse>,
                            tonic::Status,
                        >,
                    > + Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async { Err(tonic::Status::unimplemented("unused")) })
        }

        fn get_sandbox_template<'life0, 'async_trait>(
            &'life0 self,
            _request: tonic::Request<openshell_core::proto::GetSandboxTemplateRequest>,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            tonic::Response<openshell_core::proto::SandboxTemplateResponse>,
                            tonic::Status,
                        >,
                    > + Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async { Err(tonic::Status::unimplemented("unused")) })
        }

        fn list_sandbox_templates<'life0, 'async_trait>(
            &'life0 self,
            _request: tonic::Request<openshell_core::proto::ListSandboxTemplatesRequest>,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            tonic::Response<openshell_core::proto::ListSandboxTemplatesResponse>,
                            tonic::Status,
                        >,
                    > + Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async { Err(tonic::Status::unimplemented("unused")) })
        }

        fn delete_sandbox_template<'life0, 'async_trait>(
            &'life0 self,
            _request: tonic::Request<openshell_core::proto::DeleteSandboxTemplateRequest>,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            tonic::Response<openshell_core::proto::DeleteSandboxTemplateResponse>,
                            tonic::Status,
                        >,
                    > + Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async { Err(tonic::Status::unimplemented("unused")) })
        }
    };
}

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
};

#[path = "../../../../tests/support/environment.rs"]
mod environment;
#[allow(unused_imports)]
pub use environment::{Environment, FixtureDir as TempDir, fixture_dir as tempdir};

// ── TLS helpers ──────────────────────────────────────────────────────────────

/// Generate a self-signed CA certificate and its key pair.
#[allow(dead_code)]
pub fn build_ca() -> (Certificate, KeyPair) {
    let key_pair = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let cert = params.self_signed(&key_pair).unwrap();
    (cert, key_pair)
}

/// Generate a server certificate signed by `ca`, valid for `localhost`.
///
/// Returns `(cert_pem, key_pem)`.
#[allow(dead_code)]
pub fn build_server_cert(ca: &Certificate, ca_key: &KeyPair) -> (String, String) {
    let key_pair = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let cert = params.signed_by(&key_pair, ca, ca_key).unwrap();
    (cert.pem(), key_pair.serialize_pem())
}

/// Generate a client authentication certificate signed by `ca`.
///
/// Returns `(cert_pem, key_pem)`.
#[allow(dead_code)]
pub fn build_client_cert(ca: &Certificate, ca_key: &KeyPair) -> (String, String) {
    let key_pair = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cert = params.signed_by(&key_pair, ca, ca_key).unwrap();
    (cert.pem(), key_pair.serialize_pem())
}
