// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Loading the gateway's staged network trust artifact in a launched driver.
//!
//! The startup document carries only the artifact's path, digest, and
//! certificate count. The driver reads the bounded artifact once, checks it
//! against those values, and keeps its own immutable copy.

use std::fs;
use std::io::Read;
use std::path::Path;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use openshell_core::NetworkSupervisorTrustBundle;
use openshell_core::network_trust::MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES;
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt};

/// Read the staged artifact at `path`, verify it against the expected digest
/// and certificate count, and return a bundle that owns the verified bytes.
///
/// The returned bundle's artifact path records provenance only. Do not call
/// `verify_artifact` on it to re-read the mutable gateway-host path.
///
/// # Errors
///
/// Returns a message when the path, digest, or count is invalid, the artifact
/// is unreadable, oversized, not read-only, a symlink, or not canonical PEM, or
/// it does not match the digest or count.
pub fn load_staged_bundle(
    path: &Path,
    expected_digest: &str,
    expected_certificate_count: usize,
) -> Result<NetworkSupervisorTrustBundle, String> {
    if path.as_os_str().is_empty() {
        return Err("additional CA artifact path must not be empty".to_string());
    }
    if expected_certificate_count == 0 {
        return Err("additional CA certificate count must be greater than zero".to_string());
    }
    let expected_digest = normalized_additional_ca_digest(expected_digest)?;
    let pem = read_gateway_additional_ca_artifact(path)?;
    // Deterministic destination-trust generation label, not an
    // authenticity proof: the equality check below only detects
    // staged-artifact drift; trust comes from the gateway's
    // normalization and TLS verification. Classified as a non-security
    // identity hash in openshell-crypto/README.md.
    let actual_digest = format!("sha256:{:x}", Sha256::digest(&pem));
    if actual_digest != expected_digest {
        return Err(format!(
            "additional CA artifact '{}' does not match expected digest {}",
            path.display(),
            expected_digest
        ));
    }
    let actual_certificate_count =
        normalized_additional_ca_certificate_count(&pem).map_err(|error| {
            format!(
                "additional CA artifact '{}' is not a normalized certificate bundle: {error}",
                path.display()
            )
        })?;
    if actual_certificate_count != expected_certificate_count {
        return Err(format!(
            "additional CA artifact '{}' has certificate count {}, expected {}",
            path.display(),
            actual_certificate_count,
            expected_certificate_count
        ));
    }
    Ok(NetworkSupervisorTrustBundle::new(
        pem,
        actual_certificate_count,
        expected_digest,
        path.to_path_buf(),
    ))
}

/// Require the generation form emitted by gateway normalization.
fn normalized_additional_ca_digest(digest: &str) -> Result<String, String> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err("additional CA digest must use the sha256: prefix".to_string());
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("additional CA digest must be a SHA-256 digest".to_string());
    }
    if hex.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err("additional CA digest must use normalized lowercase hexadecimal".to_string());
    }
    Ok(format!("sha256:{hex}"))
}

/// Read a normalized gateway artifact once without following symlinks.
fn read_gateway_additional_ca_artifact(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "inspect additional CA artifact '{}': {error}",
            path.display()
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "additional CA artifact '{}' is not a regular file",
            path.display()
        ));
    }
    validate_gateway_additional_ca_artifact_metadata(path, &metadata)?;

    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        // The pre-open metadata check gives portable diagnostics, while these
        // flags ensure an attacker cannot replace it with a symlink, FIFO, or
        // blocking special file before the actual one-time read.
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("open additional CA artifact '{}': {error}", path.display()))?;
    let opened_metadata = file.metadata().map_err(|error| {
        format!(
            "inspect additional CA artifact '{}': {error}",
            path.display()
        )
    })?;
    if !opened_metadata.file_type().is_file() {
        return Err(format!(
            "additional CA artifact '{}' is not a regular file",
            path.display()
        ));
    }
    validate_gateway_additional_ca_artifact_metadata(path, &opened_metadata)?;

    let capacity = usize::try_from(opened_metadata.len()).map_err(|_| {
        format!(
            "additional CA artifact '{}' exceeds the {}-byte limit",
            path.display(),
            MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES
        )
    })?;
    let mut pem = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take((MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES + 1) as u64)
        .read_to_end(&mut pem)
        .map_err(|error| format!("read additional CA artifact '{}': {error}", path.display()))?;
    if pem.len() > MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES {
        return Err(format!(
            "additional CA artifact '{}' exceeds the {}-byte limit",
            path.display(),
            MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES
        ));
    }
    Ok(pem)
}

fn validate_gateway_additional_ca_artifact_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), String> {
    if metadata.len() > MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES as u64 {
        return Err(format!(
            "additional CA artifact '{}' exceeds the {}-byte limit",
            path.display(),
            MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES
        ));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o7777 != 0o444 {
        return Err(format!(
            "additional CA artifact '{}' does not have the required read-only permissions",
            path.display()
        ));
    }
    Ok(())
}

/// Verify that the bytes are exactly the canonical PEM representation emitted
/// by the gateway's destination-trust normalization boundary, and return its
/// number of certificate blocks.
fn normalized_additional_ca_certificate_count(pem: &[u8]) -> Result<usize, &'static str> {
    let text = std::str::from_utf8(pem).map_err(|_| "bundle is not UTF-8 PEM text")?;
    let mut remainder = text;
    let mut normalized = Vec::with_capacity(pem.len());
    let mut certificate_count = 0_usize;

    while !remainder.is_empty() {
        let Some(after_begin) = remainder.strip_prefix("-----BEGIN CERTIFICATE-----\n") else {
            return Err("bundle contains material outside canonical certificate blocks");
        };
        remainder = after_begin;
        let mut encoded = String::new();
        loop {
            let Some(newline) = remainder.find('\n') else {
                return Err("certificate block is missing its terminating newline");
            };
            let line = &remainder[..newline];
            remainder = &remainder[newline + 1..];
            if line == "-----END CERTIFICATE-----" {
                break;
            }
            if line.is_empty() || line.len() > 64 {
                return Err("certificate block has a non-canonical base64 line");
            }
            encoded.push_str(line);
        }
        let decoded = BASE64_STANDARD
            .decode(encoded.as_bytes())
            .map_err(|_| "certificate block contains invalid base64")?;
        if decoded.is_empty() {
            return Err("certificate block is empty");
        }
        normalized.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n");
        let canonical = BASE64_STANDARD.encode(decoded);
        for line in canonical.as_bytes().chunks(64) {
            normalized.extend_from_slice(line);
            normalized.push(b'\n');
        }
        normalized.extend_from_slice(b"-----END CERTIFICATE-----\n");
        certificate_count += 1;
    }

    if certificate_count == 0 {
        return Err("bundle contains no certificate blocks");
    }
    if normalized != pem {
        return Err("bundle is not canonical normalized PEM");
    }
    Ok(certificate_count)
}
