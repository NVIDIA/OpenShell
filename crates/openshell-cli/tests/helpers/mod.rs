// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared helpers for CLI integration tests.
//!
//! Include this module from a test file with:
//! ```ignore
//! mod helpers;
//! ```

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
};

// ── EnvVarGuard ──────────────────────────────────────────────────────────────

/// Global mutex that serialises tests which mutate environment variables so
/// concurrent threads don't clobber each other's state.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct SavedVar {
    key: &'static str,
    original: Option<String>,
}

/// RAII guard that acquires `ENV_LOCK` and restores all modified environment
/// variables on drop.
pub struct EnvVarGuard {
    vars: Vec<SavedVar>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

#[allow(dead_code, unsafe_code)]
impl EnvVarGuard {
    /// Acquire the global env-var lock and atomically set one or more
    /// environment variables.  All variables are restored to their prior
    /// state (or removed) when the guard is dropped.
    pub fn set(pairs: &[(&'static str, &str)]) -> Self {
        let lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut vars = Vec::with_capacity(pairs.len());
        for &(key, value) in pairs {
            let original = std::env::var(key).ok();
            unsafe {
                std::env::set_var(key, value);
            }
            vars.push(SavedVar { key, original });
        }
        Self { vars, _lock: lock }
    }
}

#[allow(unsafe_code)]
impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        for var in &self.vars {
            if let Some(value) = &var.original {
                unsafe {
                    std::env::set_var(var.key, value);
                }
            } else {
                unsafe {
                    std::env::remove_var(var.key);
                }
            }
        }
        // _lock drops here, releasing the mutex
    }
}

// ── TLS helpers ──────────────────────────────────────────────────────────────

/// Install the `rustls` ring crypto provider as the process default.
///
/// Safe to call multiple times — subsequent calls are no-ops.
#[allow(dead_code)]
pub fn install_rustls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

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
