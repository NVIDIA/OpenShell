// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Startup normalization for the network supervisor destination trust bundle.
//!
//! This module is the only gateway-side boundary that reads the operator's
//! configured source paths.  Drivers receive the normalized, gateway-owned
//! artifact represented by [`NetworkSupervisorTrustBundle`], never a source
//! path from the TOML file.

use base64::Engine as _;
use openshell_core::network_trust::MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES;
use openshell_core::{Error, NetworkSupervisorTrustBundle, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

use crate::config_file::SupervisorNetworkFileSection;

pub const CONFIG_FIELD: &str = "openshell.supervisor.network.additional_ca_cert_paths";
const ARTIFACT_DIRECTORY: &str = "network-supervisor";
const ARTIFACT_FILE: &str = "additional-ca.crt";

/// Normalized source material that has not yet been staged as a state artifact.
///
/// Configuration preflight intentionally uses this type rather than a
/// [`NetworkSupervisorTrustBundle`], so it can validate operator-provided
/// sources without creating state directories or files.
pub struct NormalizedNetworkSupervisorTrust {
    normalized_pem: Vec<u8>,
    certificate_count: usize,
    digest: String,
}

impl NormalizedNetworkSupervisorTrust {
    pub fn certificate_count(&self) -> usize {
        self.certificate_count
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// Read and strictly normalize configured destination roots without writing a
/// gateway state artifact.
///
/// An absent or empty list preserves the legacy startup behavior and returns
/// `None`. Once a path is configured, every PEM item in every file must be a
/// usable X.509 certificate. No valid subset is accepted when another item is
/// malformed or is a private key.
pub fn normalize_from_config(
    config: &SupervisorNetworkFileSection,
) -> Result<Option<NormalizedNetworkSupervisorTrust>> {
    normalize_sources(&config.additional_ca_cert_paths)
}

pub fn stage_normalized(
    normalized: NormalizedNetworkSupervisorTrust,
) -> Result<NetworkSupervisorTrustBundle> {
    let state_dir = openshell_core::paths::openshell_state_dir().map_err(|error| {
        Error::config(format!(
            "failed to resolve network trust state directory: {error}"
        ))
    })?;
    stage_normalized_in(normalized, &state_dir)
}

#[cfg(test)]
fn normalize_and_stage(
    source_paths: &[PathBuf],
    state_dir: &Path,
) -> Result<Option<NetworkSupervisorTrustBundle>> {
    let Some(normalized) = normalize_sources(source_paths)? else {
        return Ok(None);
    };
    stage_normalized_in(normalized, state_dir).map(Some)
}

fn normalize_sources(source_paths: &[PathBuf]) -> Result<Option<NormalizedNetworkSupervisorTrust>> {
    if source_paths.is_empty() {
        return Ok(None);
    }

    let mut normalized = Vec::new();
    let mut certificate_count = 0;
    for source_path in source_paths {
        if source_path.as_os_str().is_empty() {
            return Err(config_error(source_path, "path entry is empty"));
        }
        let source = read_source_bounded(source_path)?;
        let (pem, count) = normalize_source(source_path, &source)?;
        append_normalized(source_path, &mut normalized, &pem)?;
        certificate_count += count;
    }

    Ok(Some(NormalizedNetworkSupervisorTrust {
        digest: format!("sha256:{:x}", Sha256::digest(&normalized)),
        normalized_pem: normalized,
        certificate_count,
    }))
}

fn read_source_bounded(source_path: &Path) -> Result<Vec<u8>> {
    let path_metadata = fs::symlink_metadata(source_path)
        .map_err(|error| config_error(source_path, format_args!("could not be read: {error}")))?;
    if !path_metadata.file_type().is_file() {
        return Err(config_error(source_path, "is not a regular file"));
    }

    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // Avoid blocking on a path replaced with a FIFO after the preflight
        // metadata check. Validate the opened handle below to close the race.
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options
        .open(source_path)
        .map_err(|error| config_error(source_path, format_args!("could not be read: {error}")))?;
    let opened_metadata = file
        .metadata()
        .map_err(|error| config_error(source_path, format_args!("could not be read: {error}")))?;
    if !opened_metadata.file_type().is_file() {
        return Err(config_error(source_path, "is not a regular file"));
    }
    if opened_metadata.len() > MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES as u64 {
        return Err(config_error(
            source_path,
            format_args!(
                "exceeds the maximum readable size of {MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES} bytes"
            ),
        ));
    }

    let mut source = Vec::new();
    Read::by_ref(&mut file)
        .take((MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES + 1) as u64)
        .read_to_end(&mut source)
        .map_err(|error| config_error(source_path, format_args!("could not be read: {error}")))?;
    if source.len() > MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES {
        return Err(config_error(
            source_path,
            format_args!(
                "exceeds the maximum readable size of {MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES} bytes"
            ),
        ));
    }
    Ok(source)
}

fn append_normalized(source_path: &Path, destination: &mut Vec<u8>, source: &[u8]) -> Result<()> {
    let combined_size = destination.len().saturating_add(source.len());
    if combined_size > MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES {
        return Err(config_error(
            source_path,
            format_args!(
                "combined normalized trust bundle exceeds the maximum size of {MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES} bytes"
            ),
        ));
    }
    destination.extend_from_slice(source);
    Ok(())
}

fn stage_normalized_in(
    normalized: NormalizedNetworkSupervisorTrust,
    state_dir: &Path,
) -> Result<NetworkSupervisorTrustBundle> {
    let artifact_path = stage_artifact(state_dir, &normalized.normalized_pem)?;
    Ok(NetworkSupervisorTrustBundle::new(
        normalized.normalized_pem,
        normalized.certificate_count,
        normalized.digest,
        artifact_path,
    ))
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
    let mut begin_label = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(expected_label) = begin_label {
            if let Some(end_label) = pem_label(line, "-----END ") {
                if end_label != expected_label {
                    return Err(config_error(
                        source_path,
                        "contains malformed PEM data: END label does not match BEGIN label",
                    ));
                }
                begin_label = None;
            } else if pem_label(line, "-----BEGIN ").is_some()
                || !line
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
            {
                return Err(config_error(source_path, "contains malformed PEM data"));
            }
        } else if let Some(label) = pem_label(line, "-----BEGIN ") {
            begin_label = Some(label);
        } else {
            return Err(config_error(
                source_path,
                "contains non-PEM content outside certificate blocks",
            ));
        }
    }
    if begin_label.is_some() {
        return Err(config_error(
            source_path,
            "contains malformed PEM data: unterminated PEM block",
        ));
    }
    Ok(())
}

/// Return a syntactically valid PEM boundary label. Labels are intentionally
/// compared byte-for-byte, preventing a certificate body from being paired
/// with a differently labelled END line.
fn pem_label<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    let label = line.strip_prefix(prefix)?.strip_suffix("-----")?;
    (!label.is_empty()
        && label
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b' '))
    .then_some(label)
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

    #[test]
    fn accepts_normalized_output_exactly_at_the_bundle_limit() {
        let source = Path::new("exact-limit.pem");
        let mut normalized = Vec::new();
        append_normalized(
            source,
            &mut normalized,
            &vec![b'x'; MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES],
        )
        .expect("an exactly-at-limit normalized bundle is permitted");
        assert_eq!(normalized.len(), MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES);
    }

    #[test]
    fn rejects_combined_normalized_output_over_the_bundle_limit_without_staging() {
        let source_dir = tempdir().expect("source dir");
        let state_dir = tempdir().expect("state dir");
        let source = source_dir.path().join("over-limit.pem");
        let mut normalized = vec![b'x'; MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES];
        let error = append_normalized(&source, &mut normalized, b"x")
            .expect_err("a normalized bundle over the shared limit must be rejected");
        let message = error.to_string();
        assert!(message.contains(CONFIG_FIELD));
        assert!(message.contains("combined normalized trust bundle exceeds"));
        assert!(message.contains(&MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES.to_string()));
        assert!(!state_dir.path().join(ARTIFACT_DIRECTORY).exists());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_fifo_and_device_sources_without_blocking() {
        use nix::sys::stat::Mode;
        use nix::unistd::mkfifo;

        let source_dir = tempdir().expect("source dir");
        let state_dir = tempdir().expect("state dir");
        let fifo = source_dir.path().join("destination-ca.fifo");
        mkfifo(&fifo, Mode::S_IRUSR | Mode::S_IWUSR).expect("create FIFO");

        assert_rejected(&fifo, state_dir.path(), "is not a regular file");
        assert_rejected(
            Path::new("/dev/zero"),
            state_dir.path(),
            "is not a regular file",
        );
    }

    #[test]
    fn rejects_over_limit_source_reads_without_leaking_source_contents() {
        let source_dir = tempdir().expect("source dir");
        let state_dir = tempdir().expect("state dir");
        let source = write_source(
            source_dir.path(),
            "oversized.pem",
            vec![b's'; MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES + 1],
        );
        let error = normalize_and_stage(std::slice::from_ref(&source), state_dir.path())
            .expect_err("source reads must be bounded");
        let message = error.to_string();
        assert!(message.contains(CONFIG_FIELD));
        assert!(message.contains("maximum readable size"));
        assert!(message.contains(&MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES.to_string()));
        assert!(!message.contains(&"s".repeat(32)));
        assert!(!state_dir.path().join(ARTIFACT_DIRECTORY).exists());
    }

    #[test]
    fn rejects_mismatched_pem_boundary_labels() {
        let source_dir = tempdir().expect("source dir");
        let state_dir = tempdir().expect("state dir");
        let source = write_source(
            source_dir.path(),
            "mismatched-label.pem",
            "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END PRIVATE KEY-----\n",
        );
        assert_rejected(
            &source,
            state_dir.path(),
            "END label does not match BEGIN label",
        );
    }
}
