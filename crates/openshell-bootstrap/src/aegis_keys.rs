// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! AEGIS gateway ECDSA P-256 keypair lifecycle.
//!
//! This module owns the gateway's signing key for AEGIS execution tickets
//! (see `rfc/0004-aegis-governance`). It generates, persists, loads, rotates,
//! and publishes the public key to well-known paths that the mxc-aegis SDK
//! and AppContainer/IsolationSession drivers probe in priority order.
//!
//! ## Storage layout
//!
//! - `<storage_dir>/aegis-private.pem` — PKCS#8 PEM, owner-only (`0o600` on
//!   Unix; best-effort owner-only on Windows — see TODO below).
//! - `<storage_dir>/aegis-public.pem`  — SPKI PEM.
//!
//! ## Public-key publish locations
//!
//! Per RFC 0004 §"Wire shape", the SDK probes (Windows-only):
//!
//! - `%TEMP%\aegis-pubkey.pem`
//! - `%ProgramData%\aegis\aegis-public.pem`
//!
//! On Linux/macOS we publish to `$XDG_RUNTIME_DIR/aegis-pubkey.pem`
//! (or `$TMPDIR`/`/tmp` fallback) for parity, but this is **not** the
//! primary surface in v1 — the gateway's `GET /.well-known/aegis-public.pem`
//! over mTLS is the canonical cross-host distribution path.
//!
//! ## OCSF
//!
//! This module emits `tracing::info!` on generation and rotation. The OCSF
//! wiring task layers `ConfigStateChangeBuilder` events on top of these
//! call sites — do not emit OCSF events from here directly.

use openshell_core::paths::{ensure_parent_dir_restricted, set_file_owner_only};
use p256::{
    SecretKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding},
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};
use thiserror::Error;
use tracing::info;

/// Filename for the persisted private key under `<storage_dir>`.
const PRIVATE_KEY_FILENAME: &str = "aegis-private.pem";
/// Filename for the persisted public key under `<storage_dir>`.
const PUBLIC_KEY_FILENAME: &str = "aegis-public.pem";

/// Filename used at the SDK's `%TEMP%` probe location.
const PUBLISH_TEMP_FILENAME: &str = "aegis-pubkey.pem";
/// Filename used at the SDK's `%ProgramData%\aegis` probe location.
const PUBLISH_PROGRAMDATA_FILENAME: &str = "aegis-public.pem";
/// Subdirectory created under `%ProgramData%` to host the published key.
const PROGRAMDATA_SUBDIR: &str = "aegis";

/// PEM-encoded PKCS#8 private key + SPKI public key, plus convenience
/// fields used by ticket signing and pubkey distribution.
#[derive(Clone)]
pub struct AegisKeyMaterial {
    /// PKCS#8 PEM-encoded ECDSA P-256 private key.
    pub private_key_pem: String,
    /// SPKI PEM-encoded ECDSA P-256 public key.
    pub public_key_pem: String,
    /// Raw SPKI DER bytes of the public key (the form embedded in
    /// `SignedTicket.public_key` per RFC 0004).
    pub public_key_spki_der: Vec<u8>,
    /// SHA-256 fingerprint of the SPKI DER. Stable identifier for logs
    /// and OCSF events; safe to expose externally.
    pub fingerprint_sha256: [u8; 32],
}

/// Errors produced by the keypair lifecycle API.
#[derive(Debug, Error)]
pub enum AegisKeyError {
    #[error("aegis keys I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse stored aegis private key at {path}: {source}")]
    KeyParse {
        path: PathBuf,
        #[source]
        source: p256::pkcs8::Error,
    },

    #[error("failed to generate aegis ECDSA P-256 keypair: {0}")]
    KeyGenerate(String),

    #[error("failed to encode aegis key material: {0}")]
    KeyEncode(String),

    #[error("failed to publish aegis public key to {path}: {source}")]
    PublishPath {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl AegisKeyMaterial {
    /// Build material from a `SecretKey`, computing PEM/DER/fingerprint.
    fn from_secret(secret: &SecretKey) -> Result<Self, AegisKeyError> {
        let private_key_pem = secret
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| AegisKeyError::KeyEncode(format!("pkcs8 pem: {e}")))?
            .to_string();

        let public_key = secret.public_key();
        let public_key_pem = public_key
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| AegisKeyError::KeyEncode(format!("spki pem: {e}")))?;
        let public_key_spki_der = public_key
            .to_public_key_der()
            .map_err(|e| AegisKeyError::KeyEncode(format!("spki der: {e}")))?
            .as_bytes()
            .to_vec();

        let fingerprint_sha256 = Sha256::digest(&public_key_spki_der).into();

        Ok(Self {
            private_key_pem,
            public_key_pem,
            public_key_spki_der,
            fingerprint_sha256,
        })
    }
}

/// Load the persisted gateway keypair from `storage_dir`, or generate and
/// persist a new one if the private key file does not exist.
///
/// Idempotent: a second call returns identical material.
pub fn load_or_generate(storage_dir: &Path) -> Result<AegisKeyMaterial, AegisKeyError> {
    let private_path = storage_dir.join(PRIVATE_KEY_FILENAME);

    if private_path.exists() {
        let pem = fs::read_to_string(&private_path).map_err(|e| AegisKeyError::Io {
            path: private_path.clone(),
            source: e,
        })?;
        let secret = SecretKey::from_pkcs8_pem(&pem).map_err(|e| AegisKeyError::KeyParse {
            path: private_path.clone(),
            source: e,
        })?;
        let material = AegisKeyMaterial::from_secret(&secret)?;
        // Re-write the public key in case it was deleted out-of-band.
        write_public_key(storage_dir, &material)?;
        return Ok(material);
    }

    let material = generate_and_persist(storage_dir)?;
    info!(
        fingerprint = %hex_fingerprint(&material.fingerprint_sha256),
        "generated new aegis ECDSA P-256 keypair"
    );
    Ok(material)
}

/// Force a new keypair, replacing any existing one under `storage_dir`.
///
/// Always returns material distinct from the previous on-disk state.
pub fn rotate(storage_dir: &Path) -> Result<AegisKeyMaterial, AegisKeyError> {
    let material = generate_and_persist(storage_dir)?;
    info!(
        fingerprint = %hex_fingerprint(&material.fingerprint_sha256),
        "rotated aegis ECDSA P-256 keypair"
    );
    Ok(material)
}

/// Publish the public key PEM to the well-known probe paths used by the
/// mxc-aegis SDK. Returns the list of paths actually written.
///
/// Failure to write to a probe path is returned as `PublishPath`; the caller
/// decides whether to treat it as fatal (the gateway is still functional
/// without local publish — drivers can fall back to the gateway's
/// `/.well-known/aegis-public.pem` endpoint).
pub fn publish_public_key(material: &AegisKeyMaterial) -> Result<Vec<PathBuf>, AegisKeyError> {
    let mut written = Vec::new();
    for path in publish_paths() {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|e| AegisKeyError::PublishPath {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
        fs::write(&path, &material.public_key_pem).map_err(|e| AegisKeyError::PublishPath {
            path: path.clone(),
            source: e,
        })?;
        written.push(path);
    }
    Ok(written)
}

// --- internals ---------------------------------------------------------

fn generate_and_persist(storage_dir: &Path) -> Result<AegisKeyMaterial, AegisKeyError> {
    fs::create_dir_all(storage_dir).map_err(|e| AegisKeyError::Io {
        path: storage_dir.to_path_buf(),
        source: e,
    })?;

    let secret = SecretKey::random(&mut rand_core_compat::OsRng);
    let material = AegisKeyMaterial::from_secret(&secret)?;

    let private_path = storage_dir.join(PRIVATE_KEY_FILENAME);
    ensure_parent_dir_restricted(&private_path)
        .map_err(|e| AegisKeyError::KeyEncode(format!("ensure parent dir: {e:?}")))?;
    fs::write(&private_path, material.private_key_pem.as_bytes()).map_err(|e| {
        AegisKeyError::Io {
            path: private_path.clone(),
            source: e,
        }
    })?;
    // Best-effort restrictive permissions. On Unix this sets 0o600.
    // TODO(windows): set an owner-only DACL via the `windows` crate so the
    // private key isn't world-readable on shared hosts. For now the file
    // inherits the parent directory ACL; combined with a restricted
    // %ProgramData%\openshell parent directory this is adequate for v1.
    set_file_owner_only(&private_path)
        .map_err(|e| AegisKeyError::KeyEncode(format!("set owner-only perms: {e:?}")))?;

    write_public_key(storage_dir, &material)?;

    Ok(material)
}

fn write_public_key(storage_dir: &Path, material: &AegisKeyMaterial) -> Result<(), AegisKeyError> {
    let public_path = storage_dir.join(PUBLIC_KEY_FILENAME);
    fs::write(&public_path, material.public_key_pem.as_bytes()).map_err(|e| AegisKeyError::Io {
        path: public_path,
        source: e,
    })
}

fn hex_fingerprint(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

// --- publish paths -----------------------------------------------------

#[cfg(windows)]
fn publish_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(temp) = std::env::var_os("TEMP") {
        paths.push(PathBuf::from(temp).join(PUBLISH_TEMP_FILENAME));
    }
    if let Some(pd) = std::env::var_os("ProgramData") {
        paths.push(
            PathBuf::from(pd)
                .join(PROGRAMDATA_SUBDIR)
                .join(PUBLISH_PROGRAMDATA_FILENAME),
        );
    }
    paths
}

// On Linux/macOS we publish to a per-user runtime location for parity with
// the Windows SDK probe order. v1 does not use this surface as the primary
// distribution path — drivers on POSIX hosts use the gateway's
// `/.well-known/aegis-public.pem` endpoint over mTLS instead.
#[cfg(not(windows))]
fn publish_paths() -> Vec<PathBuf> {
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("TMPDIR").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    vec![dir.join(PUBLISH_TEMP_FILENAME)]
}

// `p256` 0.13 uses the `rand_core` 0.6 trait surface, which is re-exported
// from the crate itself. We avoid taking a direct `rand_core` dep by using
// the re-export.
mod rand_core_compat {
    pub use p256::elliptic_curve::rand_core::OsRng;
}
