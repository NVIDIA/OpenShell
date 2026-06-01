// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Trait-level abstraction over "where the gateway fetches policy from".
//!
//! The gateway speaks a single wire protocol with an out-of-process policy
//! engine. This module isolates that protocol behind a trait so the
//! attested-policy driver can be built and tested without ever importing
//! generated proto types, and so an alternate transport could be slotted in
//! later without touching the driver.
//!
//! This file is intentionally the **only** module in the new code path that
//! is permitted to depend on `openshell_core::proto::policy::*`. If a future
//! change needs proto types elsewhere, that is a leak in the abstraction —
//! restructure rather than paper over.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
use ed25519_dalek::{Signer, SigningKey};
use rand_core_06::OsRng;
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Status};
use tower::service_fn;

use openshell_core::proto::policy::v1alpha1 as wire;
use wire::engine_client::EngineClient;

// ---------------------------------------------------------------------------
// OpenShell-internal types
// ---------------------------------------------------------------------------

/// Opaque token returned by the policy source's `acquire_handle` call.
///
/// The gateway treats this purely as bytes; it must not parse, hash, or
/// otherwise derive identity from it. The `Debug` impl elides the inner
/// bytes — handles may be sensitive.
#[derive(Clone)]
pub struct Handle(Vec<u8>);

impl Handle {
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[allow(dead_code)] // surface helper; used in follow-up handle-persistence work
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl std::ops::Deref for Handle {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Debug for Handle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handle")
            .field("len", &self.0.len())
            .finish()
    }
}

/// Gateway-asserted facts about a sandbox session that the engine binds to
/// a handle. Mirrors the wire's `RuntimeContextEnvelope` with idiomatic
/// Rust types.
#[derive(Debug, Clone)]
pub struct RuntimeContext {
    pub sandbox_id: String,
    pub user_subject: String,
    pub attested_at: SystemTime,
    /// Detached signature over the envelope payload. Empty when the
    /// gateway is not signing.
    pub signature: Vec<u8>,
}

/// Policy bytes plus integrity metadata, fetched against a handle.
#[derive(Debug, Clone)]
pub struct ProjectionEnvelope {
    pub surface_id: String,
    pub schema_version: String,
    pub policy_digest: Vec<u8>,
    pub bundle_digest: Vec<u8>,
    pub body: Vec<u8>,
    /// Detached signature over the envelope payload. Empty in early
    /// deployments where the engine has not yet shipped attestation.
    pub signature: Vec<u8>,
    /// Identifier of the key that produced `signature`. `None` when
    /// `signature` is empty.
    pub signing_key_id: Option<String>,
}

/// Errors returned by [`PolicySource`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum PolicySourceError {
    /// Could not establish a transport-level connection to the configured
    /// source (UDS path missing, daemon not listening, etc.).
    #[error("policy source connect failed: {0}")]
    Connect(String),

    /// The RPC reached the source but returned a non-OK status.
    #[error("policy source rpc failed: {0}")]
    Rpc(#[from] Status),

    /// The source returned a response the gateway could not decode (an
    /// envelope field whose contents were inconsistent with its declared
    /// type, etc.).
    #[error("policy source decode failed: {0}")]
    Decode(String),

    /// The source returned a successful response that the gateway-side
    /// admission policy refuses to consume (e.g. the engine reports
    /// `DRAINING` so no new handles should be acquired).
    #[error("policy source rejected request: {reason}")]
    Rejected { reason: String },
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Abstracts the gateway-to-engine wire.
///
/// The trait surface mirrors the four RPCs on the wire. Implementations may
/// be a real gRPC client (production), an in-process mock (tests), or any
/// other transport — the consumer never knows.
#[async_trait]
pub trait PolicySource: Send + Sync + std::fmt::Debug {
    /// Liveness/readiness probe. The driver calls this once at startup
    /// before admitting any sandbox through the source.
    async fn health(&self) -> Result<(), PolicySourceError>;

    /// Bind a sandbox runtime context to an engine-chosen handle.
    async fn acquire_handle(
        &self,
        ctx: &RuntimeContext,
    ) -> Result<Handle, PolicySourceError>;

    /// Fetch the projection bound to `handle`, decoded into the policy
    /// schema named by `surface_id`.
    async fn get_projection(
        &self,
        handle: &Handle,
        surface_id: &str,
    ) -> Result<ProjectionEnvelope, PolicySourceError>;

    /// Drop engine-side state held for `handle`. Idempotent — releasing an
    /// unknown handle is OK.
    async fn release_handle(&self, handle: &Handle) -> Result<(), PolicySourceError>;
}

// ---------------------------------------------------------------------------
// Production gRPC impl
// ---------------------------------------------------------------------------

/// Production implementation of [`PolicySource`] backed by a tonic gRPC
/// client over UDS.
///
/// The instance owns a fresh Ed25519 signing key used to populate the
/// runtime-context envelope's `signature` field on every
/// [`acquire_handle`] call. The matching public key is provisioned to the
/// engine out-of-band today (v0 cutoff); persistence of the signing key,
/// and the broader handle-persistence story it belongs to, is a follow-up.
#[derive(Debug)]
pub struct GrpcPolicySource {
    client: Mutex<EngineClient<Channel>>,
    /// Path the source was dialed against. Kept for diagnostics only;
    /// `client` is the live connection.
    #[allow(dead_code)] // referenced by `uds_path()` accessor
    uds_path: PathBuf,
    /// Gateway-side runtime-context signing key. Fresh per process; not
    /// persisted in v0. Tracked under handle-persistence follow-up.
    signing_key: Arc<SigningKey>,
}

impl GrpcPolicySource {
    /// Dial the engine over UDS and build a client.
    ///
    /// Does **not** call `health` — the caller (the driver constructor)
    /// runs the health round-trip so a failure surfaces as a startup
    /// error against the driver, not against this helper.
    pub async fn connect(uds_path: &Path) -> Result<Self, PolicySourceError> {
        let path = uds_path.to_path_buf();
        let display = path.clone();

        // tonic's UDS pattern: a static URI, with the real connect step
        // performed by a `service_fn` closure that opens the unix
        // socket. Mirrors `crates/openshell-server/src/compute/vm.rs`'s
        // helper.
        let connect_path = path.clone();
        let channel = Endpoint::from_static("http://[::]:50051")
            .connect_with_connector(service_fn(move |_: tonic::transport::Uri| {
                let connect_path = connect_path.clone();
                async move {
                    UnixStream::connect(connect_path)
                        .await
                        .map(hyper_util::rt::TokioIo::new)
                }
            }))
            .await
            .map_err(|e| {
                PolicySourceError::Connect(format!(
                    "failed to connect to policy source socket '{}': {e}",
                    display.display()
                ))
            })?;

        let client = EngineClient::new(channel);
        let signing_key = Arc::new(SigningKey::generate(&mut OsRng));

        Ok(Self {
            client: Mutex::new(client),
            uds_path: path,
            signing_key,
        })
    }

    /// Path the source was dialed against, for diagnostic logging.
    #[allow(dead_code)] // used by future audit / error-path logging
    #[must_use]
    pub fn uds_path(&self) -> &Path {
        &self.uds_path
    }
}

/// Canonical byte ordering for the runtime-context envelope signature.
///
/// The signature covers the concatenation of the textual fields followed
/// by the millis timestamp. The engine reproduces the same byte order on
/// its side to verify.
fn canonical_runtime_context_bytes(
    sandbox_id: &str,
    user_subject: &str,
    attested_at_ms: i64,
) -> Vec<u8> {
    let mut buf =
        Vec::with_capacity(sandbox_id.len() + user_subject.len() + 8);
    buf.extend_from_slice(sandbox_id.as_bytes());
    buf.push(0);
    buf.extend_from_slice(user_subject.as_bytes());
    buf.push(0);
    buf.extend_from_slice(&attested_at_ms.to_be_bytes());
    buf
}

#[async_trait]
impl PolicySource for GrpcPolicySource {
    async fn health(&self) -> Result<(), PolicySourceError> {
        let req = tonic::Request::new(wire::HealthRequest {});
        let resp = {
            let mut client = self.client.lock().await;
            client.health(req).await?
        };
        let status = resp.into_inner().status();
        match status {
            wire::health_response::Status::Serving => Ok(()),
            wire::health_response::Status::Draining => Err(PolicySourceError::Rejected {
                reason: "policy source reports DRAINING".to_string(),
            }),
            wire::health_response::Status::NotServing
            | wire::health_response::Status::Unspecified => Err(PolicySourceError::Rejected {
                reason: format!("policy source reports {status:?}"),
            }),
        }
    }

    async fn acquire_handle(
        &self,
        ctx: &RuntimeContext,
    ) -> Result<Handle, PolicySourceError> {
        let attested_at_ms = ctx
            .attested_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| {
                i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
            })
            .unwrap_or(0);

        let signature = if ctx.signature.is_empty() {
            let payload = canonical_runtime_context_bytes(
                &ctx.sandbox_id,
                &ctx.user_subject,
                attested_at_ms,
            );
            self.signing_key.sign(&payload).to_bytes().to_vec()
        } else {
            ctx.signature.clone()
        };

        let envelope = wire::RuntimeContextEnvelope {
            sandbox_id: ctx.sandbox_id.clone(),
            user_subject: ctx.user_subject.clone(),
            attested_at_ms,
            signature,
        };
        let req = tonic::Request::new(wire::AcquireHandleRequest {
            envelope: Some(envelope),
        });

        let resp = {
            let mut client = self.client.lock().await;
            client.acquire_handle(req).await?
        };
        let inner = resp.into_inner();
        if inner.handle.is_empty() {
            return Err(PolicySourceError::Decode(
                "engine returned empty handle".to_string(),
            ));
        }
        Ok(Handle::new(inner.handle))
    }

    async fn get_projection(
        &self,
        handle: &Handle,
        surface_id: &str,
    ) -> Result<ProjectionEnvelope, PolicySourceError> {
        let req = tonic::Request::new(wire::GetProjectionRequest {
            handle: handle.as_bytes().to_vec(),
            surface_id: surface_id.to_string(),
        });
        let resp = {
            let mut client = self.client.lock().await;
            client.get_projection(req).await?
        };
        let inner = resp.into_inner();
        let env = inner.envelope.ok_or_else(|| {
            PolicySourceError::Decode("response missing envelope".to_string())
        })?;

        let signing_key_id = if env.signing_key_id.is_empty() {
            None
        } else {
            Some(env.signing_key_id.clone())
        };

        // Mismatch between signature presence and key id is a wire-level
        // contract violation — flag rather than admit.
        match (env.signature.is_empty(), signing_key_id.is_none()) {
            (true, true) | (false, false) => {}
            (true, false) => {
                return Err(PolicySourceError::Decode(
                    "signing_key_id set but signature is empty".to_string(),
                ));
            }
            (false, true) => {
                return Err(PolicySourceError::Decode(
                    "signature set but signing_key_id is empty".to_string(),
                ));
            }
        }

        Ok(ProjectionEnvelope {
            surface_id: env.surface_id,
            schema_version: env.schema_version,
            policy_digest: env.policy_digest,
            bundle_digest: env.bundle_digest,
            body: env.body,
            signature: env.signature,
            signing_key_id,
        })
    }

    async fn release_handle(&self, handle: &Handle) -> Result<(), PolicySourceError> {
        let req = tonic::Request::new(wire::ReleaseHandleRequest {
            handle: handle.as_bytes().to_vec(),
        });
        let result = {
            let mut client = self.client.lock().await;
            client.release_handle(req).await
        };
        match result {
            Ok(_) => Ok(()),
            // Release is contractually idempotent; treat NotFound as OK
            // so a follow-up retry after a transient error does not
            // surface as a release failure.
            Err(status) if status.code() == Code::NotFound => Ok(()),
            Err(status) => Err(PolicySourceError::Rpc(status)),
        }
    }
}

// ---------------------------------------------------------------------------
// Canonical projection payload bytes
// ---------------------------------------------------------------------------

/// Canonical byte ordering for the projection envelope signature.
///
/// The signature covers `surface_id`, `schema_version`, `policy_digest`,
/// `bundle_digest`, and `body`, concatenated in that order with zero-byte
/// separators between the textual fields.
#[must_use]
pub fn canonical_projection_bytes(env: &ProjectionEnvelope) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        env.surface_id.len()
            + env.schema_version.len()
            + env.policy_digest.len()
            + env.bundle_digest.len()
            + env.body.len()
            + 4,
    );
    buf.extend_from_slice(env.surface_id.as_bytes());
    buf.push(0);
    buf.extend_from_slice(env.schema_version.as_bytes());
    buf.push(0);
    buf.extend_from_slice(&env.policy_digest);
    buf.push(0);
    buf.extend_from_slice(&env.bundle_digest);
    buf.push(0);
    buf.extend_from_slice(&env.body);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_debug_elides_bytes() {
        let h = Handle::new(b"secret-handle-bytes".to_vec());
        let debug = format!("{h:?}");
        assert!(!debug.contains("secret-handle-bytes"));
        assert!(debug.contains("len"));
    }

    #[test]
    fn handle_deref_yields_inner_bytes() {
        let h = Handle::new(vec![1, 2, 3]);
        let slice: &[u8] = &h;
        assert_eq!(slice, &[1, 2, 3]);
    }

    #[test]
    fn canonical_runtime_context_bytes_is_stable() {
        let a = canonical_runtime_context_bytes("sb-1", "alice", 1_700_000_000_000);
        let b = canonical_runtime_context_bytes("sb-1", "alice", 1_700_000_000_000);
        assert_eq!(a, b);
        // Different sandbox produces different bytes.
        let c = canonical_runtime_context_bytes("sb-2", "alice", 1_700_000_000_000);
        assert_ne!(a, c);
    }

    #[test]
    fn canonical_projection_bytes_is_stable() {
        let env = ProjectionEnvelope {
            surface_id: "openshell.sandbox.v1".to_string(),
            schema_version: "1".to_string(),
            policy_digest: vec![1, 2, 3],
            bundle_digest: vec![4, 5, 6],
            body: vec![7, 8, 9],
            signature: vec![],
            signing_key_id: None,
        };
        let a = canonical_projection_bytes(&env);
        let b = canonical_projection_bytes(&env);
        assert_eq!(a, b);
    }
}
