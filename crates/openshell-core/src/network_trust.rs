// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared representation of gateway-configured destination trust material.
//!
//! The gateway owns validation and creation of this material.  This type keeps
//! the normalized certificate bytes separate from gateway mTLS material while
//! giving compute-driver adapters read-only access to the data they must stage
//! for the network supervisor.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Maximum number of normalized PEM bytes accepted for destination trust.
///
/// This bound is shared by the gateway normalization boundary and all compute
/// driver consumers. Kubernetes counts the `ca.crt` key and value toward its
/// 1 MiB `ConfigMap` data limit, so reserve the six key bytes here to keep every
/// supported driver on the same deployable boundary.
pub const MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES: usize = 1024 * 1024 - "ca.crt".len();

/// Protected resource metadata key recording the destination-trust generation
/// used to build a sandbox startup artifact.
///
/// Kubernetes stores this value in an annotation because a `sha256:<hex>`
/// digest exceeds the 63-character label-value limit. Local container drivers
/// may store the same protected key in a container label.
pub const NETWORK_SUPERVISOR_TRUST_GENERATION_KEY: &str =
    "openshell.ai/network-additional-ca-generation";

/// Explicit generation marker for an omitted destination-trust configuration.
///
/// An explicit value, rather than an absent marker, lets a stopped sandbox
/// distinguish a removal from a resource created by an older gateway.
pub const NETWORK_SUPERVISOR_TRUST_GENERATION_NONE: &str = "none";

/// Normalized, gateway-owned trust material for sandbox destination TLS.
///
/// The PEM bytes contain only canonical X.509 certificate blocks.  The type is
/// deliberately distinct from gateway client TLS material: its contents must
/// never be used to authenticate the gateway control plane.
#[derive(Clone, Eq, PartialEq)]
pub struct NetworkSupervisorTrustBundle {
    normalized_pem: Arc<[u8]>,
    certificate_count: usize,
    digest: String,
    artifact_path: PathBuf,
}

impl NetworkSupervisorTrustBundle {
    /// Construct a bundle from already-normalized certificate material.
    ///
    /// Callers are responsible for validating and canonicalizing the PEM
    /// before constructing the shared value.  The gateway performs that work
    /// at startup; drivers only consume the resulting read-only data.
    #[must_use]
    pub fn new(
        normalized_pem: Vec<u8>,
        certificate_count: usize,
        digest: impl Into<String>,
        artifact_path: PathBuf,
    ) -> Self {
        Self {
            normalized_pem: Arc::from(normalized_pem),
            certificate_count,
            digest: digest.into(),
            artifact_path,
        }
    }

    /// Return the canonical certificate PEM bytes.
    #[must_use]
    pub fn pem(&self) -> &[u8] {
        &self.normalized_pem
    }

    /// Alias documenting that the returned bytes are normalized material.
    #[must_use]
    pub fn normalized_pem(&self) -> &[u8] {
        self.pem()
    }

    /// Return the number of certificates in the normalized bundle.
    #[must_use]
    pub const fn certificate_count(&self) -> usize {
        self.certificate_count
    }

    /// Return the non-secret digest of the normalized bundle.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Return the gateway-owned host path that local/VM adapters may stage.
    #[must_use]
    pub fn artifact_path(&self) -> &Path {
        &self.artifact_path
    }

    /// Return whether the bundle contains no normalized bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.normalized_pem.is_empty()
    }

    /// Verify that the staged artifact still exactly matches this startup
    /// snapshot.
    ///
    /// Local drivers call this before building or replacing a stopped sandbox.
    /// The check is deliberately bounded and follows no symlinks on Unix so a
    /// changed, missing, or non-regular artifact fails closed before a runtime
    /// can consume it. Diagnostics identify only the artifact path and digest;
    /// certificate contents are never included.
    pub fn verify_artifact(&self) -> Result<(), NetworkSupervisorTrustArtifactError> {
        use std::fs::{self, OpenOptions};
        use std::io::Read as _;

        let path = self.artifact_path();
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            NetworkSupervisorTrustArtifactError::Read {
                path: path.to_path_buf(),
                error,
            }
        })?;
        if !metadata.file_type().is_file() {
            return Err(NetworkSupervisorTrustArtifactError::NotRegularFile {
                path: path.to_path_buf(),
            });
        }
        if !has_expected_artifact_permissions(&metadata) {
            return Err(NetworkSupervisorTrustArtifactError::InsecurePermissions {
                path: path.to_path_buf(),
            });
        }
        if metadata.len() > MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES as u64 {
            return Err(NetworkSupervisorTrustArtifactError::TooLarge {
                path: path.to_path_buf(),
                limit: MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES,
            });
        }

        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let mut file =
            options
                .open(path)
                .map_err(|error| NetworkSupervisorTrustArtifactError::Read {
                    path: path.to_path_buf(),
                    error,
                })?;
        let opened_metadata =
            file.metadata()
                .map_err(|error| NetworkSupervisorTrustArtifactError::Read {
                    path: path.to_path_buf(),
                    error,
                })?;
        if !opened_metadata.file_type().is_file() {
            return Err(NetworkSupervisorTrustArtifactError::NotRegularFile {
                path: path.to_path_buf(),
            });
        }
        if !has_expected_artifact_permissions(&opened_metadata) {
            return Err(NetworkSupervisorTrustArtifactError::InsecurePermissions {
                path: path.to_path_buf(),
            });
        }
        if opened_metadata.len() > MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES as u64 {
            return Err(NetworkSupervisorTrustArtifactError::TooLarge {
                path: path.to_path_buf(),
                limit: MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES,
            });
        }

        let capacity = usize::try_from(opened_metadata.len()).map_err(|_| {
            NetworkSupervisorTrustArtifactError::TooLarge {
                path: path.to_path_buf(),
                limit: MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES,
            }
        })?;
        let mut actual = Vec::with_capacity(capacity);
        file.by_ref()
            .take((MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES + 1) as u64)
            .read_to_end(&mut actual)
            .map_err(|error| NetworkSupervisorTrustArtifactError::Read {
                path: path.to_path_buf(),
                error,
            })?;
        if actual.len() > MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES {
            return Err(NetworkSupervisorTrustArtifactError::TooLarge {
                path: path.to_path_buf(),
                limit: MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES,
            });
        }
        if actual != self.normalized_pem() {
            return Err(NetworkSupervisorTrustArtifactError::GenerationMismatch {
                path: path.to_path_buf(),
                digest: self.digest.clone(),
            });
        }
        Ok(())
    }
}

/// Return whether metadata has the read-only artifact permissions created by
/// the gateway. The containing `0700` directory limits access to its owner;
/// `0444` allows both root Docker and rootless Podman consumers to read a bind
/// mounted generation without allowing any process to modify it.
fn has_expected_artifact_permissions(metadata: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        metadata.permissions().mode() & 0o7777 == 0o444
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        true
    }
}

/// Non-secret failures while re-reading a gateway-owned staged trust artifact.
#[derive(Debug, thiserror::Error)]
pub enum NetworkSupervisorTrustArtifactError {
    #[error("network additional CA artifact '{path}' could not be read: {error}")]
    Read {
        path: PathBuf,
        #[source]
        error: std::io::Error,
    },
    #[error("network additional CA artifact '{path}' is not a regular file")]
    NotRegularFile { path: PathBuf },
    #[error(
        "network additional CA artifact '{path}' does not have the required read-only permissions"
    )]
    InsecurePermissions { path: PathBuf },
    #[error("network additional CA artifact '{path}' exceeds the shared {limit}-byte limit")]
    TooLarge { path: PathBuf, limit: usize },
    #[error(
        "network additional CA artifact '{path}' does not match the gateway startup trust generation {digest}"
    )]
    GenerationMismatch { path: PathBuf, digest: String },
}

impl fmt::Debug for NetworkSupervisorTrustBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetworkSupervisorTrustBundle")
            .field("certificate_count", &self.certificate_count)
            .field("digest", &self.digest)
            .field("artifact_path", &self.artifact_path)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_representation_redacts_pem_bytes() {
        let pem = b"-----BEGIN CERTIFICATE-----\nnot-secret-in-a-real-fixture\n-----END CERTIFICATE-----\n";
        let bundle = NetworkSupervisorTrustBundle::new(
            pem.to_vec(),
            1,
            "sha256:test-digest",
            PathBuf::from("/var/lib/openshell/network/additional-ca.crt"),
        );

        let debug = format!("{bundle:?}");
        assert!(debug.contains("certificate_count: 1"));
        assert!(debug.contains("sha256:test-digest"));
        assert!(debug.contains("additional-ca.crt"));
        assert!(!debug.contains("not-secret-in-a-real-fixture"));
        assert_eq!(bundle.pem(), pem);
        assert_eq!(bundle.normalized_pem(), pem);
        assert_eq!(bundle.certificate_count(), 1);
        assert_eq!(bundle.digest(), "sha256:test-digest");
        assert_eq!(
            bundle.artifact_path(),
            Path::new("/var/lib/openshell/network/additional-ca.crt")
        );
        assert!(!bundle.is_empty());
    }

    #[test]
    fn cloned_bundles_share_immutable_material() {
        let bundle = NetworkSupervisorTrustBundle::new(
            b"certificate".to_vec(),
            1,
            "sha256:test",
            PathBuf::from("/tmp/additional-ca.crt"),
        );
        assert_eq!(bundle.clone(), bundle);
    }

    fn test_bundle(path: PathBuf, contents: &[u8]) -> NetworkSupervisorTrustBundle {
        NetworkSupervisorTrustBundle::new(contents.to_vec(), 1, "sha256:test-generation", path)
    }

    fn set_read_only(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o444)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = path;
    }

    #[cfg(unix)]
    #[test]
    fn artifact_verifier_rejects_writable_files() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("additional-ca.crt");
        std::fs::write(&path, b"normalized test CA\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let error = test_bundle(path, b"normalized test CA\n")
            .verify_artifact()
            .unwrap_err();
        assert!(matches!(
            error,
            NetworkSupervisorTrustArtifactError::InsecurePermissions { .. }
        ));
        assert!(!error.to_string().contains("normalized test CA"));
    }

    #[test]
    fn artifact_verifier_accepts_exact_file_contents() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("additional-ca.crt");
        let contents = b"normalized test CA\n";
        std::fs::write(&path, contents).unwrap();
        set_read_only(&path);

        test_bundle(path, contents).verify_artifact().unwrap();
    }

    #[test]
    fn artifact_verifier_rejects_replaced_contents_without_disclosing_them() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("additional-ca.crt");
        let expected = b"expected normalized CA\n";
        let replacement = b"replacement private CA must not be disclosed\n";
        std::fs::write(&path, replacement).unwrap();
        set_read_only(&path);

        let error = test_bundle(path, expected).verify_artifact().unwrap_err();
        assert!(matches!(
            error,
            NetworkSupervisorTrustArtifactError::GenerationMismatch { .. }
        ));
        let diagnostic = error.to_string();
        assert!(diagnostic.contains("sha256:test-generation"));
        assert!(!diagnostic.contains("expected normalized CA"));
        assert!(!diagnostic.contains("replacement private CA"));
    }

    #[test]
    fn artifact_verifier_rejects_non_regular_files() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("directory");
        std::fs::create_dir(&path).unwrap();

        let error = test_bundle(path, b"contents")
            .verify_artifact()
            .unwrap_err();
        assert!(matches!(
            error,
            NetworkSupervisorTrustArtifactError::NotRegularFile { .. }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn artifact_verifier_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        let link = temp.path().join("additional-ca.crt");
        std::fs::write(&target, b"normalized test CA\n").unwrap();
        symlink(&target, &link).unwrap();

        let error = test_bundle(link, b"normalized test CA\n")
            .verify_artifact()
            .unwrap_err();
        assert!(matches!(
            error,
            NetworkSupervisorTrustArtifactError::NotRegularFile { .. }
        ));
    }

    #[test]
    fn artifact_verifier_enforces_shared_size_bound() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("additional-ca.crt");
        let at_limit = vec![b'x'; MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES];
        std::fs::write(&path, &at_limit).unwrap();
        set_read_only(&path);
        test_bundle(path.clone(), &at_limit)
            .verify_artifact()
            .unwrap();

        let oversized = vec![b'x'; MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES + 1];
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, &oversized).unwrap();
        set_read_only(&path);
        let error = test_bundle(path, b"expected")
            .verify_artifact()
            .unwrap_err();
        assert!(matches!(
            error,
            NetworkSupervisorTrustArtifactError::TooLarge { limit, .. }
                if limit == MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES
        ));
        assert!(!error.to_string().contains(&"x".repeat(64)));
    }
}
