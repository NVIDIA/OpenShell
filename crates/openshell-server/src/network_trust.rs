// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Startup normalization for the network supervisor destination trust bundle.
//!
//! This module is the only gateway-side boundary that reads the operator's
//! configured source paths.  Drivers receive the normalized, gateway-owned
//! artifact represented by [`NetworkSupervisorTrustBundle`], never a source
//! path from the TOML file.

use base64::Engine as _;
use openshell_core::{Error, NetworkSupervisorTrustBundle, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

use crate::config_file::SupervisorNetworkFileSection;

pub const CONFIG_FIELD: &str = "openshell.supervisor.network.additional_ca_cert_paths";
const ARTIFACT_DIRECTORY: &str = "network-supervisor";
const ARTIFACT_FILE: &str = "additional-ca.crt";

/// Read, strictly validate, normalize, and stage configured destination roots.
///
/// An absent or empty list preserves the legacy startup behavior and returns
/// `None`.  Once a path is configured, every PEM item in every file must be a
/// usable X.509 certificate.  No valid subset is accepted when another item is
/// malformed or is a private key.
pub fn load_from_config(
    config: &SupervisorNetworkFileSection,
) -> Result<Option<NetworkSupervisorTrustBundle>> {
    if config.additional_ca_cert_paths.is_empty() {
        return Ok(None);
    }

    let state_dir = openshell_core::paths::openshell_state_dir().map_err(|error| {
        Error::config(format!(
            "failed to resolve network trust state directory: {error}"
        ))
    })?;
    normalize_and_stage(&config.additional_ca_cert_paths, &state_dir)
}

fn normalize_and_stage(
    source_paths: &[PathBuf],
    state_dir: &Path,
) -> Result<Option<NetworkSupervisorTrustBundle>> {
    if source_paths.is_empty() {
        return Ok(None);
    }

    let mut normalized = Vec::new();
    let mut certificate_count = 0;
    for source_path in source_paths {
        if source_path.as_os_str().is_empty() {
            return Err(config_error(source_path, "path entry is empty"));
        }
        let source = fs::read(source_path).map_err(|error| {
            config_error(source_path, format_args!("could not be read: {error}"))
        })?;
        let (pem, count) = normalize_source(source_path, &source)?;
        normalized.extend_from_slice(&pem);
        certificate_count += count;
    }

    let digest = format!("sha256:{:x}", Sha256::digest(&normalized));
    let artifact_path = stage_artifact(state_dir, &normalized)?;
    Ok(Some(NetworkSupervisorTrustBundle::new(
        normalized,
        certificate_count,
        digest,
        artifact_path,
    )))
}

fn normalize_source(source_path: &Path, source: &[u8]) -> Result<(Vec<u8>, usize)> {
    // `rustls_pemfile` intentionally skips text outside PEM blocks. The
    // gateway contract is stricter: a configured file must not contain a
    // valid subset hidden among unrelated or malformed material.
    if source
        .windows(b"-----BEGIN ".len())
        .any(|window| window == b"-----BEGIN ")
    {
        validate_pem_envelope(source_path, source)?;
    }

    let mut certificates = Vec::new();
    for item in rustls_pemfile::read_all(&mut Cursor::new(source)) {
        let item = item.map_err(|error| {
            config_error(
                source_path,
                format_args!("contains malformed PEM data: {error}"),
            )
        })?;
        let rustls_pemfile::Item::X509Certificate(certificate) = item else {
            return Err(config_error(
                source_path,
                "contains a non-certificate PEM block",
            ));
        };
        certificates.push(certificate);
    }

    if certificates.is_empty() {
        return Err(config_error(
            source_path,
            "contains no PEM certificate blocks",
        ));
    }

    let mut roots = rustls::RootCertStore::empty();
    let certificate_count = certificates.len();
    let (added, ignored) = roots.add_parsable_certificates(certificates.clone());
    if added != certificate_count || ignored != 0 {
        return Err(config_error(
            source_path,
            "contains a certificate that is not a usable X.509 trust anchor",
        ));
    }

    let mut normalized = Vec::new();
    for certificate in certificates {
        normalized.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n");
        let encoded = base64::engine::general_purpose::STANDARD.encode(certificate.as_ref());
        for line in encoded.as_bytes().chunks(64) {
            normalized.extend_from_slice(line);
            normalized.push(b'\n');
        }
        normalized.extend_from_slice(b"-----END CERTIFICATE-----\n");
    }
    Ok((normalized, certificate_count))
}

fn validate_pem_envelope(source_path: &Path, source: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(source).map_err(|_| {
        config_error(
            source_path,
            "contains malformed PEM data: input is not UTF-8 PEM text",
        )
    })?;
    let mut in_block = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if !in_block {
            if line.starts_with("-----BEGIN ") && line.ends_with("-----") {
                in_block = true;
            } else {
                return Err(config_error(
                    source_path,
                    "contains non-PEM content outside certificate blocks",
                ));
            }
        } else if line.starts_with("-----END ") && line.ends_with("-----") {
            in_block = false;
        } else if !line
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        {
            return Err(config_error(source_path, "contains malformed PEM data"));
        }
    }
    if in_block {
        return Err(config_error(
            source_path,
            "contains malformed PEM data: unterminated PEM block",
        ));
    }
    Ok(())
}

fn stage_artifact(state_dir: &Path, normalized: &[u8]) -> Result<PathBuf> {
    let artifact_dir = state_dir.join(ARTIFACT_DIRECTORY);
    fs::create_dir_all(&artifact_dir).map_err(|error| {
        Error::config(format!(
            "failed to create network supervisor trust artifact directory '{}': {error}",
            artifact_dir.display()
        ))
    })?;
    set_artifact_directory_permissions(&artifact_dir)?;

    let artifact_path = artifact_dir.join(ARTIFACT_FILE);
    let mut temporary = NamedTempFile::new_in(&artifact_dir).map_err(|error| {
        Error::config(format!(
            "failed to create network supervisor trust artifact near '{}': {error}",
            artifact_path.display()
        ))
    })?;
    temporary.write_all(normalized).map_err(|error| {
        Error::config(format!(
            "failed to write network supervisor trust artifact '{}': {error}",
            artifact_path.display()
        ))
    })?;
    temporary.as_file().sync_all().map_err(|error| {
        Error::config(format!(
            "failed to flush network supervisor trust artifact '{}': {error}",
            artifact_path.display()
        ))
    })?;
    set_artifact_file_permissions(temporary.path())?;
    temporary.persist(&artifact_path).map_err(|error| {
        Error::config(format!(
            "failed to install network supervisor trust artifact '{}': {}",
            artifact_path.display(),
            error.error
        ))
    })?;
    Ok(artifact_path)
}

fn set_artifact_directory_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(|error| {
            Error::config(format!(
                "failed to set permissions on network supervisor trust directory '{}': {error}",
                path.display()
            ))
        })?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn set_artifact_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).map_err(|error| {
            Error::config(format!(
                "failed to set permissions on network supervisor trust artifact '{}': {error}",
                path.display()
            ))
        })?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn config_error(path: &Path, detail: impl std::fmt::Display) -> Error {
    Error::config(format!(
        "{CONFIG_FIELD} source '{}': {detail}",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::generate_simple_self_signed;
    use std::fs;
    use tempfile::tempdir;

    fn certificate_pem(common_name: &str) -> String {
        generate_simple_self_signed(vec![common_name.to_string()])
            .expect("generate test certificate")
            .cert
            .pem()
    }

    fn write_source(dir: &Path, name: &str, contents: impl AsRef<[u8]>) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, contents).expect("write source fixture");
        path
    }

    fn assert_rejected(path: &Path, state_dir: &Path, expected: &str) {
        let error = normalize_and_stage(&[path.to_path_buf()], state_dir)
            .expect_err("invalid trust material must fail closed");
        let message = error.to_string();
        assert!(message.contains(CONFIG_FIELD), "missing field in {message}");
        assert!(
            message.contains(&path.display().to_string()),
            "missing source path in {message}"
        );
        assert!(
            message.contains(expected),
            "missing {expected:?} in {message}"
        );
        assert!(
            !message.contains("CERTIFICATE"),
            "certificate body/framing leaked in {message}"
        );
    }

    #[test]
    fn normalizes_multiple_certificates_and_stages_redacted_metadata() {
        let source_dir = tempdir().expect("source dir");
        let state_dir = tempdir().expect("state dir");
        let first = certificate_pem("ca-one.example");
        let second = certificate_pem("ca-two.example");
        let source = write_source(
            source_dir.path(),
            "bundle.pem",
            format!("{first}\n{second}"),
        );

        let bundle = normalize_and_stage(&[source], state_dir.path())
            .expect("normalize")
            .expect("configured bundle");
        assert_eq!(bundle.certificate_count(), 2);
        assert!(bundle.digest().starts_with("sha256:"));
        assert_eq!(
            fs::read(bundle.artifact_path()).expect("artifact"),
            bundle.pem()
        );
        assert_eq!(
            bundle.artifact_path(),
            state_dir
                .path()
                .join(ARTIFACT_DIRECTORY)
                .join(ARTIFACT_FILE)
        );
        let debug = format!("{bundle:?}");
        assert!(!debug.contains(&first));
        assert!(!debug.contains(&second));
    }

    #[test]
    fn omitted_sources_do_not_create_an_artifact() {
        let state_dir = tempdir().expect("state dir");
        assert!(
            normalize_and_stage(&[], state_dir.path())
                .expect("no setting")
                .is_none()
        );
        assert!(!state_dir.path().join(ARTIFACT_DIRECTORY).exists());
    }

    #[test]
    fn rejects_missing_source() {
        let source_dir = tempdir().expect("source dir");
        let state_dir = tempdir().expect("state dir");
        assert_rejected(
            &source_dir.path().join("missing.pem"),
            state_dir.path(),
            "could not be read",
        );
    }

    #[test]
    fn rejects_empty_source() {
        let source_dir = tempdir().expect("source dir");
        let state_dir = tempdir().expect("state dir");
        let source = write_source(source_dir.path(), "empty.pem", []);
        assert_rejected(&source, state_dir.path(), "no PEM certificate blocks");
    }

    #[test]
    fn rejects_malformed_source() {
        let source_dir = tempdir().expect("source dir");
        let state_dir = tempdir().expect("state dir");
        let source = write_source(source_dir.path(), "malformed.pem", b"not pem");
        assert_rejected(&source, state_dir.path(), "no PEM certificate blocks");
    }

    #[test]
    fn rejects_private_key_source() {
        let source_dir = tempdir().expect("source dir");
        let state_dir = tempdir().expect("state dir");
        let generated =
            generate_simple_self_signed(vec!["key.example".to_string()]).expect("certificate");
        let source = write_source(
            source_dir.path(),
            "private-key.pem",
            generated.key_pair.serialize_pem(),
        );
        assert_rejected(&source, state_dir.path(), "non-certificate PEM block");
    }

    #[test]
    fn rejects_mixed_certificate_and_private_key_source() {
        let source_dir = tempdir().expect("source dir");
        let state_dir = tempdir().expect("state dir");
        let generated =
            generate_simple_self_signed(vec!["mixed.example".to_string()]).expect("certificate");
        let source = write_source(
            source_dir.path(),
            "mixed.pem",
            format!(
                "{}\n{}",
                generated.cert.pem(),
                generated.key_pair.serialize_pem()
            ),
        );
        assert_rejected(&source, state_dir.path(), "non-certificate PEM block");
    }

    #[test]
    fn rejects_valid_certificate_mixed_with_malformed_text() {
        let source_dir = tempdir().expect("source dir");
        let state_dir = tempdir().expect("state dir");
        let certificate = certificate_pem("malformed-mix.example");
        let source = write_source(
            source_dir.path(),
            "malformed-mix.pem",
            format!("{certificate}\nnot pem content"),
        );
        assert_rejected(
            &source,
            state_dir.path(),
            "non-PEM content outside certificate blocks",
        );
    }

    #[test]
    fn rejects_empty_path_entry() {
        let state_dir = tempdir().expect("state dir");
        assert_rejected(Path::new(""), state_dir.path(), "path entry is empty");
    }

    #[test]
    fn rejects_certificate_free_source_without_leaking_fixture_body() {
        let source_dir = tempdir().expect("source dir");
        let state_dir = tempdir().expect("state dir");
        let fixture_body = "-----BEGIN PRIVATE KEY-----\nfixture-body\n-----END PRIVATE KEY-----\n";
        let source = write_source(source_dir.path(), "non-certificate.pem", fixture_body);
        let error = normalize_and_stage(std::slice::from_ref(&source), state_dir.path())
            .expect_err("non-certificate source must fail");
        let message = error.to_string();
        assert!(message.contains(CONFIG_FIELD));
        assert!(message.contains(&source.display().to_string()));
        assert!(!message.contains(fixture_body));
    }
}
