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
}
