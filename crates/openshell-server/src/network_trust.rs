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
use std::io::{Cursor, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use crate::config_file::SupervisorNetworkFileSection;

pub const CONFIG_FIELD: &str = "openshell.supervisor.network.additional_ca_cert_paths";
const ARTIFACT_DIRECTORY: &str = "network-supervisor";
const ARTIFACT_FILE_PREFIX: &str = "additional-ca-";
const ARTIFACT_FILE_SUFFIX: &str = ".crt";
const ARTIFACT_TEMP_FILE_PREFIX: &str = ".additional-ca-";
const ARTIFACT_TEMP_FILE_SUFFIX: &str = ".tmp";

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
    let artifact_path = stage_artifact(state_dir, &normalized.normalized_pem, &normalized.digest)?;
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

fn stage_artifact(state_dir: &Path, normalized: &[u8], digest: &str) -> Result<PathBuf> {
    let artifact_dir = state_dir.join(ARTIFACT_DIRECTORY);
    ensure_artifact_directory(&artifact_dir)?;

    let artifact_path = artifact_dir.join(artifact_file_name(digest)?);
    let temporary_path = stage_temporary_artifact(&artifact_dir, normalized)?;

    // Both names are in `artifact_dir`, so hard_link is a same-filesystem,
    // no-replace publication operation. Unlike rename/persist, it cannot
    // overwrite an existing generation.
    let published_new_artifact = match fs::hard_link(&temporary_path, &artifact_path) {
        Ok(()) => true,
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            // A concurrent gateway may have published this generation first.
            // Reuse it only after the ordinary no-follow, exact-byte, regular
            // file, and read-only verification succeeds.
            verify_existing_artifact(&artifact_path, normalized, digest)?;
            false
        }
        Err(error) => {
            return Err(Error::config(format!(
                "failed to atomically publish network supervisor trust artifact '{}': {error}",
                artifact_path.display()
            )));
        }
    };

    // TempPath provides cleanup on every earlier return path. Drop it before
    // syncing a new publication so the directory sync makes both the final
    // name and removal of this process's temporary name durable where the
    // platform supports directory syncs.
    drop(temporary_path);
    if published_new_artifact {
        sync_artifact_directory(&artifact_dir)?;
    }

    // Generations are deliberately never removed or overwritten here. A
    // running Docker or Podman sandbox can still be bind-mounting an older
    // generation while a later gateway startup stages this one.
    Ok(artifact_path)
}

/// Write a completed, read-only artifact to a private sibling temporary file.
///
/// `TempPath` retains ownership after its file handle is closed, so it removes
/// the temporary name if publishing or validating a race winner returns an
/// error.
fn stage_temporary_artifact(artifact_dir: &Path, normalized: &[u8]) -> Result<tempfile::TempPath> {
    let mut temporary = tempfile::Builder::new()
        .prefix(ARTIFACT_TEMP_FILE_PREFIX)
        .suffix(ARTIFACT_TEMP_FILE_SUFFIX)
        .tempfile_in(artifact_dir)
        .map_err(|error| {
            Error::config(format!(
                "failed to create network supervisor trust temporary artifact in '{}': {error}",
                artifact_dir.display()
            ))
        })?;
    let temporary_path = temporary.path().to_path_buf();

    temporary.write_all(normalized).map_err(|error| {
        Error::config(format!(
            "failed to write network supervisor trust temporary artifact '{}': {error}",
            temporary_path.display()
        ))
    })?;
    set_artifact_file_permissions(temporary.as_file(), &temporary_path)?;
    temporary.as_file().sync_all().map_err(|error| {
        Error::config(format!(
            "failed to flush network supervisor trust temporary artifact '{}': {error}",
            temporary_path.display()
        ))
    })?;

    // into_temp_path drops the open File before returning while preserving
    // TempPath's RAII removal behavior for the sibling temporary name.
    Ok(temporary.into_temp_path())
}

fn artifact_file_name(digest: &str) -> Result<String> {
    let hex = digest.strip_prefix("sha256:").filter(|hex| {
        hex.len() == Sha256::output_size() * 2 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
    });
    let Some(hex) = hex else {
        return Err(Error::config(
            "failed to derive network supervisor trust artifact name from its digest",
        ));
    };
    Ok(format!("{ARTIFACT_FILE_PREFIX}{hex}{ARTIFACT_FILE_SUFFIX}"))
}

fn ensure_artifact_directory(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|error| {
        Error::config(format!(
            "failed to create network supervisor trust artifact directory '{}': {error}",
            path.display()
        ))
    })?;
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        Error::config(format!(
            "failed to inspect network supervisor trust artifact directory '{}': {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_dir() {
        return Err(Error::config(format!(
            "network supervisor trust artifact directory '{}' is not a directory",
            path.display()
        )));
    }
    set_artifact_directory_permissions(path)
}

fn verify_existing_artifact(path: &Path, normalized: &[u8], digest: &str) -> Result<()> {
    NetworkSupervisorTrustBundle::new(normalized.to_vec(), 0, digest, path.to_path_buf())
        .verify_artifact()
        .map_err(|error| {
            Error::config(format!(
                "existing network supervisor trust artifact '{}' cannot be reused: {error}",
                path.display()
            ))
        })
}

fn set_artifact_directory_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
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

fn set_artifact_file_permissions(file: &fs::File, path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(fs::Permissions::from_mode(0o444))
            .map_err(|error| {
                Error::config(format!(
                    "failed to set permissions on network supervisor trust temporary artifact '{}': {error}",
                    path.display()
                ))
            })?;
    }
    #[cfg(not(unix))]
    let _ = (file, path);
    Ok(())
}

/// Durably record a successful hard-link publication on platforms that permit
/// syncing directories. This follows the same `File::open(...).sync_all()`
/// pattern used for other atomic state writes in the repository.
fn sync_artifact_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        fs::File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                Error::config(format!(
                    "failed to sync network supervisor trust artifact directory '{}': {error}",
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

    fn staged_artifact_path(state_dir: &Path, digest: &str) -> PathBuf {
        state_dir
            .join(ARTIFACT_DIRECTORY)
            .join(artifact_file_name(digest).expect("artifact file name"))
    }

    fn normalized_from_source(source: PathBuf) -> NormalizedNetworkSupervisorTrust {
        normalize_sources(&[source])
            .expect("normalize source")
            .expect("configured source")
    }

    fn digest_for(contents: &[u8]) -> String {
        format!("sha256:{:x}", Sha256::digest(contents))
    }

    fn assert_no_artifact_temporary_names(state_dir: &Path) {
        let artifact_dir = state_dir.join(ARTIFACT_DIRECTORY);
        let temporary_names: Vec<_> = fs::read_dir(&artifact_dir)
            .expect("read artifact directory")
            .map(|entry| entry.expect("read artifact directory entry").file_name())
            .filter(|name| {
                name.to_str().is_some_and(|name| {
                    name.starts_with(ARTIFACT_TEMP_FILE_PREFIX)
                        && name.ends_with(ARTIFACT_TEMP_FILE_SUFFIX)
                })
            })
            .collect();
        assert!(
            temporary_names.is_empty(),
            "temporary artifacts remained in '{}': {temporary_names:?}",
            artifact_dir.display()
        );
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
        let digest_hex = bundle
            .digest()
            .strip_prefix("sha256:")
            .expect("digest prefix");
        assert_eq!(digest_hex.len(), Sha256::output_size() * 2);
        assert_eq!(
            bundle.artifact_path(),
            state_dir
                .path()
                .join(ARTIFACT_DIRECTORY)
                .join(format!("additional-ca-{digest_hex}.crt"))
        );
        let debug = format!("{bundle:?}");
        assert!(!debug.contains(&first));
        assert!(!debug.contains(&second));
    }

    #[test]
    fn same_generation_reuses_the_content_addressed_artifact() {
        let source_dir = tempdir().expect("source dir");
        let state_dir = tempdir().expect("state dir");
        let source = write_source(
            source_dir.path(),
            "bundle.pem",
            certificate_pem("same-generation.example"),
        );

        let first = normalize_and_stage(std::slice::from_ref(&source), state_dir.path())
            .expect("first stage")
            .expect("configured bundle");
        let second = normalize_and_stage(&[source], state_dir.path())
            .expect("second stage")
            .expect("configured bundle");

        assert_eq!(first.digest(), second.digest());
        assert_eq!(first.artifact_path(), second.artifact_path());
        assert_eq!(
            fs::read(second.artifact_path()).expect("artifact"),
            second.pem()
        );
    }

    #[test]
    fn successful_publication_removes_its_temporary_artifact() {
        let state_dir = tempdir().expect("state dir");
        let normalized = b"canonical normalized CA bytes\n";
        let digest = digest_for(normalized);

        let artifact_path = stage_artifact(state_dir.path(), normalized, &digest)
            .expect("publish a new artifact generation");

        assert_eq!(
            artifact_path,
            staged_artifact_path(state_dir.path(), &digest)
        );
        assert_eq!(fs::read(&artifact_path).expect("artifact"), normalized);
        verify_existing_artifact(&artifact_path, normalized, &digest)
            .expect("new artifact satisfies reuse validation");
        assert_no_artifact_temporary_names(state_dir.path());
    }

    #[test]
    fn existing_race_winner_is_validated_and_removes_its_temporary_artifact() {
        let state_dir = tempdir().expect("state dir");
        let normalized = b"canonical normalized CA bytes\n";
        let digest = digest_for(normalized);

        let first_path =
            stage_artifact(state_dir.path(), normalized, &digest).expect("publish the race winner");
        let reused_path = stage_artifact(state_dir.path(), normalized, &digest)
            .expect("validate and reuse existing race winner");

        assert_eq!(reused_path, first_path);
        assert_eq!(fs::read(&reused_path).expect("artifact"), normalized);
        assert_no_artifact_temporary_names(state_dir.path());
    }

    #[test]
    fn concurrent_same_generation_publication_returns_one_exact_artifact() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        const CONTENDERS: usize = 12;

        let state_dir = tempdir().expect("state dir");
        let normalized = Arc::new(b"canonical normalized CA bytes\n".to_vec());
        let digest = Arc::new(digest_for(&normalized));
        let expected_path = staged_artifact_path(state_dir.path(), &digest);
        let barrier = Arc::new(Barrier::new(CONTENDERS));
        // Spawn every contender before joining: each thread waits on the same
        // barrier, so joining while constructing this list would deadlock.
        let mut contenders = Vec::with_capacity(CONTENDERS);
        for _ in 0..CONTENDERS {
            let state_dir = state_dir.path().to_path_buf();
            let normalized = Arc::clone(&normalized);
            let digest = Arc::clone(&digest);
            let barrier = Arc::clone(&barrier);
            contenders.push(thread::spawn(move || {
                barrier.wait();
                stage_artifact(&state_dir, normalized.as_slice(), digest.as_str())
                    .map_err(|error| error.to_string())
            }));
        }

        let paths: Vec<_> = contenders
            .into_iter()
            .map(|contender| {
                contender
                    .join()
                    .expect("publication contender must not panic")
                    .expect("each contender must publish or validate the same generation")
            })
            .collect();
        assert!(
            paths.iter().all(|path| path == &expected_path),
            "all contenders must return the same artifact path: {paths:?}"
        );
        assert_eq!(
            fs::read(&expected_path).expect("artifact"),
            normalized.as_slice()
        );
        verify_existing_artifact(&expected_path, normalized.as_slice(), &digest)
            .expect("concurrent publication leaves a valid artifact");
        assert_no_artifact_temporary_names(state_dir.path());
    }

    #[test]
    fn failed_existing_generation_validation_cleans_its_temporary_artifact() {
        let state_dir = tempdir().expect("state dir");
        let normalized = b"canonical normalized CA bytes\n";
        let digest = digest_for(normalized);
        let artifact_path = staged_artifact_path(state_dir.path(), &digest);
        ensure_artifact_directory(artifact_path.parent().expect("artifact directory"))
            .expect("create artifact directory");
        let replacement = b"different CA bytes that must not be disclosed\n";
        fs::write(&artifact_path, replacement).expect("write invalid existing generation");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&artifact_path, fs::Permissions::from_mode(0o444))
                .expect("make invalid generation read-only");
        }

        let error = stage_artifact(state_dir.path(), normalized, &digest)
            .expect_err("a wrong existing generation must fail closed");

        assert!(error.to_string().contains("does not match"));
        assert!(!error.to_string().contains("different CA bytes"));
        assert_eq!(fs::read(&artifact_path).expect("artifact"), replacement);
        assert_no_artifact_temporary_names(state_dir.path());
    }

    #[test]
    fn staging_does_not_remove_preexisting_temporary_names() {
        let state_dir = tempdir().expect("state dir");
        let artifact_dir = state_dir.path().join(ARTIFACT_DIRECTORY);
        ensure_artifact_directory(&artifact_dir).expect("create artifact directory");
        let stale_temporary = artifact_dir.join(".additional-ca-stale.tmp");
        fs::write(&stale_temporary, b"stale temporary bytes").expect("write stale temporary");
        let normalized = b"canonical normalized CA bytes\n";
        let digest = digest_for(normalized);

        stage_artifact(state_dir.path(), normalized, &digest).expect("publish artifact");

        assert_eq!(
            fs::read(&stale_temporary).expect("stale temporary"),
            b"stale temporary bytes"
        );
    }

    #[cfg(unix)]
    #[test]
    fn artifact_directory_sync_reports_a_missing_directory() {
        let state_dir = tempdir().expect("state dir");
        let missing = state_dir.path().join("missing-artifact-directory");

        let error = sync_artifact_directory(&missing)
            .expect_err("syncing a missing artifact directory must fail");

        assert!(error.to_string().contains(&missing.display().to_string()));
    }

    #[test]
    fn different_generations_have_distinct_content_addressed_artifacts() {
        let source_dir = tempdir().expect("source dir");
        let state_dir = tempdir().expect("state dir");
        let first_source = write_source(
            source_dir.path(),
            "first.pem",
            certificate_pem("first-generation.example"),
        );
        let second_source = write_source(
            source_dir.path(),
            "second.pem",
            certificate_pem("second-generation.example"),
        );

        let first = normalize_and_stage(&[first_source], state_dir.path())
            .expect("first stage")
            .expect("configured bundle");
        let second = normalize_and_stage(&[second_source], state_dir.path())
            .expect("second stage")
            .expect("configured bundle");

        assert_ne!(first.digest(), second.digest());
        assert_ne!(first.artifact_path(), second.artifact_path());
        assert!(first.artifact_path().is_file());
        assert!(second.artifact_path().is_file());
    }

    #[test]
    fn fixed_legacy_artifact_path_is_not_consumed() {
        let source_dir = tempdir().expect("source dir");
        let state_dir = tempdir().expect("state dir");
        let legacy_dir = state_dir.path().join(ARTIFACT_DIRECTORY);
        fs::create_dir(&legacy_dir).expect("legacy artifact directory");
        let legacy_path = legacy_dir.join("additional-ca.crt");
        let legacy_contents = b"legacy artifact must remain untouched";
        fs::write(&legacy_path, legacy_contents).expect("legacy artifact");
        let source = write_source(
            source_dir.path(),
            "bundle.pem",
            certificate_pem("legacy-path.example"),
        );

        let bundle = normalize_and_stage(&[source], state_dir.path())
            .expect("stage")
            .expect("configured bundle");

        assert_ne!(bundle.artifact_path(), legacy_path);
        assert_eq!(
            fs::read(&legacy_path).expect("legacy artifact"),
            legacy_contents
        );
    }

    #[cfg(unix)]
    #[test]
    fn staged_artifact_and_its_directory_have_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let source_dir = tempdir().expect("source dir");
        let state_dir = tempdir().expect("state dir");
        let source = write_source(
            source_dir.path(),
            "bundle.pem",
            certificate_pem("permissions.example"),
        );
        let bundle = normalize_and_stage(&[source], state_dir.path())
            .expect("stage")
            .expect("configured bundle");

        assert_eq!(
            fs::metadata(state_dir.path().join(ARTIFACT_DIRECTORY))
                .expect("artifact directory")
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
        assert_eq!(
            fs::metadata(bundle.artifact_path())
                .expect("artifact")
                .permissions()
                .mode()
                & 0o7777,
            0o444
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_preexisting_symlink_generation_without_changing_it() {
        use std::os::unix::fs::symlink;

        let source_dir = tempdir().expect("source dir");
        let state_dir = tempdir().expect("state dir");
        let source = write_source(
            source_dir.path(),
            "bundle.pem",
            certificate_pem("symlink-generation.example"),
        );
        let normalized = normalized_from_source(source);
        let artifact_path = staged_artifact_path(state_dir.path(), normalized.digest());
        fs::create_dir(artifact_path.parent().expect("artifact parent")).expect("artifact dir");
        let target = state_dir.path().join("symlink-target");
        let target_contents = b"symlink target bytes must not leak";
        fs::write(&target, target_contents).expect("target");
        symlink(&target, &artifact_path).expect("artifact symlink");

        let error = stage_normalized_in(normalized, state_dir.path())
            .expect_err("symlink generation must be rejected");
        assert!(error.to_string().contains("not a regular file"));
        assert!(!error.to_string().contains("symlink target bytes"));
        assert!(
            fs::symlink_metadata(&artifact_path)
                .expect("artifact link")
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(target).expect("target"), target_contents);
    }

    #[test]
    fn rejects_preexisting_directory_generation_without_changing_it() {
        let source_dir = tempdir().expect("source dir");
        let state_dir = tempdir().expect("state dir");
        let source = write_source(
            source_dir.path(),
            "bundle.pem",
            certificate_pem("directory-generation.example"),
        );
        let normalized = normalized_from_source(source);
        let artifact_path = staged_artifact_path(state_dir.path(), normalized.digest());
        fs::create_dir_all(&artifact_path).expect("artifact directory");

        let error = stage_normalized_in(normalized, state_dir.path())
            .expect_err("directory generation must be rejected");
        assert!(error.to_string().contains("not a regular file"));
        assert!(
            fs::metadata(&artifact_path)
                .expect("artifact directory")
                .is_dir()
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_preexisting_wrong_generation_bytes_without_changing_or_disclosing_them() {
        use std::os::unix::fs::PermissionsExt as _;

        let source_dir = tempdir().expect("source dir");
        let state_dir = tempdir().expect("state dir");
        let source = write_source(
            source_dir.path(),
            "bundle.pem",
            certificate_pem("wrong-bytes-generation.example"),
        );
        let normalized = normalized_from_source(source);
        let artifact_path = staged_artifact_path(state_dir.path(), normalized.digest());
        fs::create_dir(artifact_path.parent().expect("artifact parent")).expect("artifact dir");
        let replacement = b"replacement CA bytes must not leak";
        fs::write(&artifact_path, replacement).expect("replacement artifact");
        fs::set_permissions(&artifact_path, fs::Permissions::from_mode(0o444))
            .expect("read-only replacement");

        let error = stage_normalized_in(normalized, state_dir.path())
            .expect_err("wrong generation bytes must be rejected");
        assert!(error.to_string().contains("does not match"));
        assert!(!error.to_string().contains("replacement CA bytes"));
        assert_eq!(fs::read(&artifact_path).expect("artifact"), replacement);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_preexisting_oversized_generation_without_changing_it() {
        use std::os::unix::fs::PermissionsExt as _;

        let source_dir = tempdir().expect("source dir");
        let state_dir = tempdir().expect("state dir");
        let source = write_source(
            source_dir.path(),
            "bundle.pem",
            certificate_pem("oversized-generation.example"),
        );
        let normalized = normalized_from_source(source);
        let artifact_path = staged_artifact_path(state_dir.path(), normalized.digest());
        fs::create_dir(artifact_path.parent().expect("artifact parent")).expect("artifact dir");
        let oversized = vec![b'x'; MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES + 1];
        fs::write(&artifact_path, &oversized).expect("oversized artifact");
        fs::set_permissions(&artifact_path, fs::Permissions::from_mode(0o444))
            .expect("read-only permissions");

        let error = stage_normalized_in(normalized, state_dir.path())
            .expect_err("oversized generation must be rejected");
        assert!(error.to_string().contains("exceeds the shared"));
        assert!(!error.to_string().contains(&"x".repeat(64)));
        assert_eq!(
            fs::metadata(&artifact_path).expect("artifact").len(),
            oversized.len() as u64
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_preexisting_writable_generation_without_changing_or_disclosing_it() {
        use std::os::unix::fs::PermissionsExt as _;

        let source_dir = tempdir().expect("source dir");
        let state_dir = tempdir().expect("state dir");
        let source = write_source(
            source_dir.path(),
            "bundle.pem",
            certificate_pem("writable-generation.example"),
        );
        let normalized = normalized_from_source(source);
        let artifact_path = staged_artifact_path(state_dir.path(), normalized.digest());
        fs::create_dir(artifact_path.parent().expect("artifact parent")).expect("artifact dir");
        let expected_bytes = normalized.normalized_pem.clone();
        fs::write(&artifact_path, &expected_bytes).expect("writable artifact");
        fs::set_permissions(&artifact_path, fs::Permissions::from_mode(0o644))
            .expect("writable permissions");

        let error = stage_normalized_in(normalized, state_dir.path())
            .expect_err("writable generation must be rejected");
        assert!(error.to_string().contains("required read-only permissions"));
        assert!(!error.to_string().contains("BEGIN CERTIFICATE"));
        assert_eq!(fs::read(&artifact_path).expect("artifact"), expected_bytes);
        assert_eq!(
            fs::metadata(&artifact_path)
                .expect("artifact")
                .permissions()
                .mode()
                & 0o7777,
            0o644
        );
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
