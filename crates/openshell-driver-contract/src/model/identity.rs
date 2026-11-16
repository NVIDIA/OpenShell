// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Identity, evidence, descriptor and error types shared by compute drivers and
//! isolation backends.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Classified failures at the common contract boundary.
///
/// An error never advances the lifecycle or authorizes an operation.
#[derive(Debug)]
pub enum BackendError {
    /// Descriptor missing, malformed, unsupported, or mismatched against admission.
    Descriptor(String),
    /// Authenticated attachment rejection (incompatible or already-bound resource).
    Denied(String),
    /// Boundary temporarily unavailable.
    Unavailable(String),
    /// The selected backend does not implement an optional contract operation.
    Unsupported(String),
    /// Attachment-phase failure (establishment or mediation bring-up).
    Attach(String),
    /// Readiness confirmation failed (do not start workload code).
    Confirm(String),
    /// Process start or exec failure.
    Process(String),
    /// Abnormal boundary or workload loss, or an operation against an inactive
    /// boundary.
    Terminated(String),
}

/// Coarse, machine-readable classification of a [`BackendError`] for supervisor
/// status mapping. The error's variant and message carry the structured context
/// (which operation failed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendErrorKind {
    /// Descriptor or backend mismatch.
    Invalid,
    /// Authenticated attachment rejection.
    Denied,
    /// Transient inability to serve an operation.
    Unavailable,
    /// The selected backend does not implement the requested optional operation.
    Unsupported,
    /// Attachment, confirmation, start, or runtime operation failure.
    Failed,
    /// Abnormal boundary/workload loss, or an operation against an inactive
    /// boundary.
    Terminated,
}

impl BackendError {
    /// The machine-readable kind for this error.
    #[must_use]
    pub fn kind(&self) -> BackendErrorKind {
        match self {
            Self::Descriptor(_) => BackendErrorKind::Invalid,
            Self::Denied(_) => BackendErrorKind::Denied,
            Self::Unavailable(_) => BackendErrorKind::Unavailable,
            Self::Unsupported(_) => BackendErrorKind::Unsupported,
            Self::Attach(_) | Self::Confirm(_) | Self::Process(_) => BackendErrorKind::Failed,
            Self::Terminated(_) => BackendErrorKind::Terminated,
        }
    }
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Descriptor(m) => write!(f, "descriptor error: {m}"),
            Self::Denied(m) => write!(f, "attachment denied: {m}"),
            Self::Unavailable(m) => write!(f, "boundary unavailable: {m}"),
            Self::Unsupported(m) => write!(f, "operation unsupported: {m}"),
            Self::Attach(m) => write!(f, "attachment failed: {m}"),
            Self::Confirm(m) => write!(f, "confirmation failed: {m}"),
            Self::Process(m) => write!(f, "process error: {m}"),
            Self::Terminated(m) => write!(f, "boundary terminated: {m}"),
        }
    }
}

impl std::error::Error for BackendError {}

/// Why an identity resolution failed. Resolution failure fails closed: the
/// mediation service denies and audits the connection; it never authorizes.
#[derive(Debug, Clone)]
pub enum ResolveError {
    /// No process owns the connection (stale or unknown attribution).
    NotFound,
    /// Resolution attempted but could not produce trustworthy identity.
    Failed(String),
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "connection owner not found"),
            Self::Failed(m) => write!(f, "identity resolution failed: {m}"),
        }
    }
}

impl std::error::Error for ResolveError {}

/// The common isolation backend descriptor envelope.
///
/// The compute driver supplies one for the selected isolation backend. The opaque
/// payload identifies an existing resource or carries the trusted prepared
/// inputs the backend needs to establish one during `attach`; its protection
/// and resource lifecycle remain owned by the compute driver.
#[derive(Debug, Clone)]
pub struct BackendDescriptor {
    /// The backend the supervisor must instantiate.
    pub backend_name: String,
    /// Backend-specific attachment data.
    pub payload: Vec<u8>,
}

/// Exact non-root identity selected before the immutable workload is created.
///
/// Validation and normalization run in [`ResolvedWorkloadIdentity::new`] and
/// again when a value is decoded from a serialized descriptor: deserialization
/// routes through the same constructor, so an invalid identity fails to decode
/// instead of bypassing the contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawResolvedWorkloadIdentity")]
pub struct ResolvedWorkloadIdentity {
    /// Effective and real user ID used by sandbox and all workload children.
    pub uid: u32,
    /// Primary group ID used by sandbox and all workload children.
    pub gid: u32,
    /// Sorted, unique supplementary groups inherited unchanged by children.
    pub supplementary_gids: Vec<u32>,
    /// Driver-defined resolution source (`policy`, `template`, or `image`).
    pub source: String,
    /// Digest of the immutable image/rootfs/config used for resolution.
    pub resource_digest: String,
}

impl ResolvedWorkloadIdentity {
    /// Validate and construct a final workload identity.
    pub fn new(
        uid: u32,
        gid: u32,
        mut supplementary_gids: Vec<u32>,
        source: String,
        resource_digest: String,
    ) -> Result<Self, BackendError> {
        if uid == 0 || gid == 0 || supplementary_gids.contains(&0) {
            return Err(BackendError::Descriptor(
                "workload identity must not contain UID or GID zero".to_string(),
            ));
        }
        if source.trim().is_empty() || resource_digest.trim().is_empty() {
            return Err(BackendError::Descriptor(
                "workload identity source and resource digest are required".to_string(),
            ));
        }
        supplementary_gids.retain(|supplementary_gid| *supplementary_gid != gid);
        supplementary_gids.sort_unstable();
        supplementary_gids.dedup();
        Ok(Self {
            uid,
            gid,
            supplementary_gids,
            source,
            resource_digest,
        })
    }
}

/// Unvalidated wire shape of [`ResolvedWorkloadIdentity`], existing only so
/// serde decoding can route through [`ResolvedWorkloadIdentity::new`].
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawResolvedWorkloadIdentity {
    uid: u32,
    gid: u32,
    supplementary_gids: Vec<u32>,
    source: String,
    resource_digest: String,
}

impl TryFrom<RawResolvedWorkloadIdentity> for ResolvedWorkloadIdentity {
    type Error = BackendError;

    fn try_from(raw: RawResolvedWorkloadIdentity) -> Result<Self, Self::Error> {
        Self::new(
            raw.uid,
            raw.gid,
            raw.supplementary_gids,
            raw.source,
            raw.resource_digest,
        )
    }
}

/// Commitment to provisioning facts validated by the trusted compute driver.
///
/// The driver validates its native placement and enforcement requirements before
/// constructing this binding. The digest includes the runtime generation, so
/// confirmation cannot reuse evidence from another launch. It is a binding,
/// not independent proof that the backend enforces policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisioningEvidence {
    pub generation: String,
    pub evidence_digest: Sha256Digest,
}

impl ProvisioningEvidence {
    /// Bind already-validated native provisioning evidence to one generation.
    pub fn from_enforcement_evidence(
        generation: impl Into<String>,
        native_evidence: &[u8],
    ) -> Result<Self, BackendError> {
        let generation = generation.into();
        if generation.is_empty() || native_evidence.is_empty() {
            return Err(BackendError::Descriptor(
                "provisioning generation and native evidence are required".to_string(),
            ));
        }
        let mut binding = Vec::with_capacity(8 + generation.len() + native_evidence.len());
        binding.extend_from_slice(&(generation.len() as u64).to_be_bytes());
        binding.extend_from_slice(generation.as_bytes());
        binding.extend_from_slice(native_evidence);
        Ok(Self {
            generation,
            evidence_digest: Sha256Digest::compute(&binding),
        })
    }

    /// Reject evidence bound to a different launch.
    pub fn validate(&self, expected_generation: &str) -> Result<(), BackendError> {
        if !self.generation.is_empty() && self.generation == expected_generation {
            Ok(())
        } else {
            Err(BackendError::Confirm(
                "provisioning evidence belongs to another generation".to_string(),
            ))
        }
    }
}

/// A SHA-256 digest, kept typed so the identity field is not coupled to its
/// textual encoding or forced to repeat the algorithm in its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Sha256Digest([u8; 32]);

impl TryFrom<String> for Sha256Digest {
    type Error = ResolveError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<Sha256Digest> for String {
    fn from(value: Sha256Digest) -> Self {
        value.to_string()
    }
}

impl Sha256Digest {
    fn compute(bytes: &[u8]) -> Self {
        use sha2::{Digest as _, Sha256};

        Self(Sha256::digest(bytes).into())
    }

    /// Return the raw digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for Sha256Digest {
    type Err = ResolveError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ResolveError::Failed(
                "SHA-256 digest must contain 64 hexadecimal characters".to_string(),
            ));
        }
        let mut bytes = [0_u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| {
                ResolveError::Failed("SHA-256 digest contains non-hexadecimal data".to_string())
            })?;
        }
        Ok(Self(bytes))
    }
}
