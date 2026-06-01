// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Attested policy-provider driver.
//!
//! Resolves a sandbox's effective policy by talking to a configured policy
//! source over the wire trait. The driver:
//!
//!   1. Builds a runtime context for the sandbox.
//!   2. Acquires a handle from the configured source.
//!   3. Fetches the projection envelope for the OpenShell sandbox surface.
//!   4. Verifies the envelope signature against the configured trust
//!      store.
//!   5. Decodes the policy body and returns it.
//!   6. Releases the handle.
//!
//! The driver inherits the trait's default `Unsupported` impls for
//! `set_policy` / `update_policy` / `delete_policy` / `permits_mutation` —
//! mutation is not part of this driver's surface.

use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
use prost::Message;
use tracing::warn;

use super::source::{
    canonical_projection_bytes, PolicySource, PolicySourceError, ProjectionEnvelope,
    RuntimeContext,
};
#[cfg(test)]
use super::source::Handle;
use super::trust_store::{TrustStore, TrustStoreError};
use super::{PolicyError, PolicyProvider, ATTESTED_POLICY_TYPE_ID};

/// Surface id this driver fetches by default. Matches the gateway's
/// canonical sandbox policy schema.
const SANDBOX_POLICY_SURFACE_ID: &str = "openshell.sandbox.v1";

/// Attested policy provider.
///
/// Routes `get_effective_policy` through the configured policy source and
/// admits the returned policy only if the envelope signature verifies
/// against the trust store. Inherits the trait's default `Unsupported`
/// behaviour for every mutator.
#[derive(Debug)]
pub struct AttestedPolicyProvider {
    source: Arc<dyn PolicySource>,
    trust_store: TrustStore,
}

impl AttestedPolicyProvider {
    /// Construct the driver. Runs an initial `health` round-trip against
    /// the source so a misconfigured deployment surfaces at gateway
    /// startup rather than on the first sandbox admission.
    pub async fn new(
        source: Arc<dyn PolicySource>,
        trust_store: TrustStore,
    ) -> Result<Self, PolicySourceError> {
        source.health().await?;
        Ok(Self {
            source,
            trust_store,
        })
    }
}

#[async_trait]
impl PolicyProvider for AttestedPolicyProvider {
    fn id(&self) -> &'static str {
        ATTESTED_POLICY_TYPE_ID
    }

    async fn get_effective_policy(
        &self,
        sandbox_id: &str,
    ) -> Result<Option<openshell_core::proto::SandboxPolicy>, PolicyError> {
        // The gateway has not yet wired user-subject capture into this
        // call path; for now the runtime context carries the sandbox id
        // alone. User-subject capture is part of the auth-mode gate work
        // (deferred follow-up).
        let ctx = RuntimeContext {
            sandbox_id: sandbox_id.to_string(),
            user_subject: String::new(),
            attested_at: SystemTime::now(),
            signature: Vec::new(),
        };

        let handle = self
            .source
            .acquire_handle(&ctx)
            .await
            .map_err(PolicyError::from)?;

        let envelope = match self
            .source
            .get_projection(&handle, SANDBOX_POLICY_SURFACE_ID)
            .await
        {
            Ok(env) => env,
            Err(e) => {
                // Best-effort cleanup. Release errors are not fatal here
                // because the original projection error is the
                // load-bearing failure to surface.
                let _ = self.source.release_handle(&handle).await;
                return Err(PolicyError::from(e));
            }
        };

        // Signature verification. Two valid states:
        //
        //   - Both signature and signing_key_id are populated → verify
        //     against the trust store; reject on any failure.
        //   - Both are empty → admit with a one-time warning per call.
        //     This is the v0 fallback for sources that have not yet
        //     shipped attestation. When the source starts emitting
        //     signed envelopes this branch stops firing automatically.
        //
        // (Mismatched populated/empty pairs are filtered upstream in
        // the source impl and surface as `PolicySourceError::Decode`.)
        let verify_result = match (envelope.signature.is_empty(), &envelope.signing_key_id) {
            (true, None) => {
                warn!(
                    sandbox_id,
                    "policy source returned an unsigned envelope; admitting under v0 fallback"
                );
                Ok(())
            }
            (false, Some(key_id)) => {
                let payload = canonical_projection_bytes(&envelope);
                self.trust_store
                    .verify(key_id, &payload, &envelope.signature)
                    .map_err(PolicyError::from)
            }
            // Source impl rejects these combinations before returning to
            // the driver; defensive handling for completeness.
            _ => Err(PolicyError::SourceError(PolicySourceError::Decode(
                "envelope signature/key_id presence mismatch".to_string(),
            ))),
        };

        if let Err(e) = verify_result {
            let _ = self.source.release_handle(&handle).await;
            return Err(e);
        }

        let policy = match decode_sandbox_policy(&envelope) {
            Ok(p) => p,
            Err(e) => {
                let _ = self.source.release_handle(&handle).await;
                return Err(e);
            }
        };

        // Release immediately for this phase. Handle persistence — the
        // story under which the gateway retains handles across sandbox
        // lifetimes and releases them only on sandbox deletion — is a
        // follow-up.
        if let Err(release_err) = self.source.release_handle(&handle).await {
            warn!(
                sandbox_id,
                error = %release_err,
                "policy source release_handle failed; admission proceeds"
            );
        }

        Ok(Some(policy))
    }
}

fn decode_sandbox_policy(
    envelope: &ProjectionEnvelope,
) -> Result<openshell_core::proto::SandboxPolicy, PolicyError> {
    if envelope.surface_id != SANDBOX_POLICY_SURFACE_ID {
        return Err(PolicyError::SourceError(PolicySourceError::Decode(format!(
            "expected surface_id '{SANDBOX_POLICY_SURFACE_ID}', got '{}'",
            envelope.surface_id
        ))));
    }
    openshell_core::proto::SandboxPolicy::decode(envelope.body.as_slice()).map_err(|e| {
        PolicyError::SourceError(PolicySourceError::Decode(format!(
            "decode sandbox policy body failed: {e}"
        )))
    })
}

impl From<TrustStoreError> for PolicyError {
    fn from(e: TrustStoreError) -> Self {
        Self::SourceError(PolicySourceError::Rejected {
            reason: e.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::SandboxPolicy;
    use std::sync::Mutex;

    // ----- Mock source -------------------------------------------------

    type HealthFn = Box<dyn Fn() -> Result<(), PolicySourceError> + Send + Sync>;
    type AcquireFn =
        Box<dyn Fn(&RuntimeContext) -> Result<Handle, PolicySourceError> + Send + Sync>;
    type GetFn = Box<
        dyn Fn(&Handle, &str) -> Result<ProjectionEnvelope, PolicySourceError> + Send + Sync,
    >;
    type ReleaseFn = Box<dyn Fn(&Handle) -> Result<(), PolicySourceError> + Send + Sync>;

    /// Test fixture standing in for a real engine on the wire. Each call
    /// site overrides the relevant closure; the rest default to "OK".
    #[derive(Default)]
    struct MockPolicySource {
        health_fn: Mutex<Option<HealthFn>>,
        acquire_fn: Mutex<Option<AcquireFn>>,
        get_fn: Mutex<Option<GetFn>>,
        release_fn: Mutex<Option<ReleaseFn>>,
        release_count: std::sync::atomic::AtomicUsize,
    }

    impl std::fmt::Debug for MockPolicySource {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MockPolicySource").finish()
        }
    }

    impl MockPolicySource {
        fn with_health(self, f: HealthFn) -> Self {
            *self.health_fn.lock().unwrap() = Some(f);
            self
        }
        fn with_acquire(self, f: AcquireFn) -> Self {
            *self.acquire_fn.lock().unwrap() = Some(f);
            self
        }
        fn with_get(self, f: GetFn) -> Self {
            *self.get_fn.lock().unwrap() = Some(f);
            self
        }
        #[allow(dead_code)]
        fn with_release(self, f: ReleaseFn) -> Self {
            *self.release_fn.lock().unwrap() = Some(f);
            self
        }
        fn release_count(&self) -> usize {
            self.release_count
                .load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl PolicySource for MockPolicySource {
        async fn health(&self) -> Result<(), PolicySourceError> {
            let guard = self.health_fn.lock().unwrap();
            match guard.as_ref() {
                Some(f) => f(),
                None => Ok(()),
            }
        }

        async fn acquire_handle(
            &self,
            ctx: &RuntimeContext,
        ) -> Result<Handle, PolicySourceError> {
            let guard = self.acquire_fn.lock().unwrap();
            match guard.as_ref() {
                Some(f) => f(ctx),
                None => Ok(Handle::new(b"default-handle".to_vec())),
            }
        }

        async fn get_projection(
            &self,
            handle: &Handle,
            surface_id: &str,
        ) -> Result<ProjectionEnvelope, PolicySourceError> {
            let guard = self.get_fn.lock().unwrap();
            match guard.as_ref() {
                Some(f) => f(handle, surface_id),
                None => Err(PolicySourceError::Decode("no get fixture set".into())),
            }
        }

        async fn release_handle(&self, handle: &Handle) -> Result<(), PolicySourceError> {
            self.release_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let guard = self.release_fn.lock().unwrap();
            match guard.as_ref() {
                Some(f) => f(handle),
                None => Ok(()),
            }
        }
    }

    // ----- Helpers -----------------------------------------------------

    fn fresh_keypair() -> (ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey) {
        use rand_core_06::OsRng;
        let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn trust_store_with(key_id: &str, vk: ed25519_dalek::VerifyingKey) -> TrustStore {
        let mut map = std::collections::HashMap::new();
        map.insert(key_id.to_string(), vk);
        TrustStore::from_keys(map)
    }

    fn signed_envelope(sk: &ed25519_dalek::SigningKey, key_id: &str) -> ProjectionEnvelope {
        use ed25519_dalek::Signer;
        let policy = SandboxPolicy {
            version: 7,
            ..Default::default()
        };
        let body = policy.encode_to_vec();
        let mut env = ProjectionEnvelope {
            surface_id: SANDBOX_POLICY_SURFACE_ID.to_string(),
            schema_version: "1".to_string(),
            policy_digest: vec![0xaa; 32],
            bundle_digest: vec![0xbb; 32],
            body,
            signature: Vec::new(),
            signing_key_id: None,
        };
        let payload = canonical_projection_bytes(&env);
        let sig = sk.sign(&payload).to_bytes();
        env.signature = sig.to_vec();
        env.signing_key_id = Some(key_id.to_string());
        env
    }

    fn unsigned_envelope() -> ProjectionEnvelope {
        let policy = SandboxPolicy {
            version: 3,
            ..Default::default()
        };
        ProjectionEnvelope {
            surface_id: SANDBOX_POLICY_SURFACE_ID.to_string(),
            schema_version: "1".to_string(),
            policy_digest: vec![],
            bundle_digest: vec![],
            body: policy.encode_to_vec(),
            signature: Vec::new(),
            signing_key_id: None,
        }
    }

    // ----- Tests -------------------------------------------------------

    #[tokio::test]
    async fn new_fails_when_source_health_fails() {
        let source = Arc::new(MockPolicySource::default().with_health(Box::new(|| {
            Err(PolicySourceError::Connect("nope".into()))
        })));
        let (_, vk) = fresh_keypair();
        let ts = trust_store_with("k-1", vk);
        let err = AttestedPolicyProvider::new(source, ts)
            .await
            .expect_err("health failure must surface as constructor error");
        assert!(matches!(err, PolicySourceError::Connect(_)));
    }

    #[tokio::test]
    async fn get_effective_policy_returns_some_on_valid_signed_envelope() {
        let (sk, vk) = fresh_keypair();
        let env = signed_envelope(&sk, "k-1");

        let source = Arc::new(
            MockPolicySource::default()
                .with_acquire(Box::new(|_ctx| Ok(Handle::new(b"h".to_vec()))))
                .with_get(Box::new(move |_h, _s| Ok(env.clone()))),
        );
        let ts = trust_store_with("k-1", vk);
        let driver = AttestedPolicyProvider::new(source.clone(), ts)
            .await
            .expect("new ok");

        let policy = driver
            .get_effective_policy("sb-1")
            .await
            .expect("get_effective_policy ok")
            .expect("policy present");
        assert_eq!(policy.version, 7);
        // Released exactly once after a successful round-trip.
        assert_eq!(source.release_count(), 1);
    }

    #[tokio::test]
    async fn get_effective_policy_admits_unsigned_envelope_in_v0_fallback() {
        let source = Arc::new(
            MockPolicySource::default()
                .with_acquire(Box::new(|_ctx| Ok(Handle::new(b"h".to_vec()))))
                .with_get(Box::new(|_h, _s| Ok(unsigned_envelope()))),
        );
        let (_, vk) = fresh_keypair();
        let ts = trust_store_with("k-1", vk);
        let driver = AttestedPolicyProvider::new(source.clone(), ts)
            .await
            .expect("new ok");

        let policy = driver
            .get_effective_policy("sb-1")
            .await
            .expect("get_effective_policy ok")
            .expect("policy present");
        assert_eq!(policy.version, 3);
        assert_eq!(source.release_count(), 1);
    }

    #[tokio::test]
    async fn get_effective_policy_rejects_signed_envelope_with_unknown_key_id() {
        let (sk_other, _) = fresh_keypair();
        let env = signed_envelope(&sk_other, "unknown-key");

        let source = Arc::new(
            MockPolicySource::default()
                .with_acquire(Box::new(|_ctx| Ok(Handle::new(b"h".to_vec()))))
                .with_get(Box::new(move |_h, _s| Ok(env.clone()))),
        );
        let (_, vk) = fresh_keypair();
        let ts = trust_store_with("k-1", vk);
        let driver = AttestedPolicyProvider::new(source.clone(), ts)
            .await
            .expect("new ok");

        let err = driver
            .get_effective_policy("sb-1")
            .await
            .expect_err("unknown key must reject");
        match err {
            PolicyError::SourceError(PolicySourceError::Rejected { reason }) => {
                assert!(
                    reason.contains("unknown-key"),
                    "reason should mention rejected key: {reason}"
                );
            }
            other => panic!("expected SourceError(Rejected), got {other:?}"),
        }
        // Handle still released even on rejection.
        assert_eq!(source.release_count(), 1);
    }

    #[tokio::test]
    async fn get_effective_policy_rejects_signed_envelope_with_tampered_body() {
        let (sk, vk) = fresh_keypair();
        let mut env = signed_envelope(&sk, "k-1");
        // Tamper with the body after signing.
        env.body = SandboxPolicy {
            version: 99,
            ..Default::default()
        }
        .encode_to_vec();

        let source = Arc::new(
            MockPolicySource::default()
                .with_acquire(Box::new(|_ctx| Ok(Handle::new(b"h".to_vec()))))
                .with_get(Box::new(move |_h, _s| Ok(env.clone()))),
        );
        let ts = trust_store_with("k-1", vk);
        let driver = AttestedPolicyProvider::new(source.clone(), ts)
            .await
            .expect("new ok");

        let err = driver
            .get_effective_policy("sb-1")
            .await
            .expect_err("tampered body must reject");
        assert!(matches!(
            err,
            PolicyError::SourceError(PolicySourceError::Rejected { .. })
        ));
    }

    #[tokio::test]
    async fn get_effective_policy_surfaces_acquire_failure() {
        let source = Arc::new(MockPolicySource::default().with_acquire(Box::new(|_ctx| {
            Err(PolicySourceError::Connect("unreachable".into()))
        })));
        let (_, vk) = fresh_keypair();
        let ts = trust_store_with("k-1", vk);
        let driver = AttestedPolicyProvider::new(source.clone(), ts)
            .await
            .expect("new ok");

        let err = driver
            .get_effective_policy("sb-1")
            .await
            .expect_err("acquire failure must propagate");
        assert!(matches!(
            err,
            PolicyError::SourceError(PolicySourceError::Connect(_))
        ));
        // Nothing to release.
        assert_eq!(source.release_count(), 0);
    }

    #[tokio::test]
    async fn get_effective_policy_releases_handle_on_get_projection_failure() {
        let source = Arc::new(
            MockPolicySource::default()
                .with_acquire(Box::new(|_ctx| Ok(Handle::new(b"h".to_vec()))))
                .with_get(Box::new(|_h, _s| {
                    Err(PolicySourceError::Decode("bad bytes".into()))
                })),
        );
        let (_, vk) = fresh_keypair();
        let ts = trust_store_with("k-1", vk);
        let driver = AttestedPolicyProvider::new(source.clone(), ts)
            .await
            .expect("new ok");

        let err = driver
            .get_effective_policy("sb-1")
            .await
            .expect_err("get failure must propagate");
        assert!(matches!(
            err,
            PolicyError::SourceError(PolicySourceError::Decode(_))
        ));
        assert_eq!(source.release_count(), 1);
    }

    #[tokio::test]
    async fn driver_id_is_attested_constant() {
        let source = Arc::new(MockPolicySource::default());
        let (_, vk) = fresh_keypair();
        let ts = trust_store_with("k-1", vk);
        let driver = AttestedPolicyProvider::new(source, ts).await.expect("ok");
        assert_eq!(driver.id(), ATTESTED_POLICY_TYPE_ID);
        assert_eq!(driver.id(), "attested");
    }

    #[tokio::test]
    async fn driver_inherits_unsupported_for_mutators() {
        let source = Arc::new(MockPolicySource::default());
        let (_, vk) = fresh_keypair();
        let ts = trust_store_with("k-1", vk);
        let driver = AttestedPolicyProvider::new(source, ts).await.expect("ok");

        let err = driver
            .permits_mutation()
            .await
            .expect_err("attested must refuse mutation surface");
        assert!(matches!(
            err,
            PolicyError::Unsupported {
                policy_type: "attested",
                operation: "mutation"
            }
        ));

        let err = driver
            .set_policy(&super::super::SetSandboxPolicyCtx {
                sandbox_id: "sb".into(),
                sandbox_name: "sb".into(),
                expected_resource_version: 0,
                policy: SandboxPolicy::default(),
            })
            .await
            .expect_err("attested must refuse set_policy");
        assert!(matches!(
            err,
            PolicyError::Unsupported {
                policy_type: "attested",
                operation: "set_policy"
            }
        ));

        let err = driver
            .update_policy(&super::super::UpdateSandboxPolicyCtx {
                sandbox_id: "sb".into(),
                sandbox_name: "sb".into(),
                merge_operations: vec![],
                baseline_policy: None,
            })
            .await
            .expect_err("attested must refuse update_policy");
        assert!(matches!(
            err,
            PolicyError::Unsupported {
                policy_type: "attested",
                operation: "update_policy"
            }
        ));

        let err = driver
            .delete_policy(&super::super::DeleteGlobalPolicyCtx {
                global_policy_sandbox_id: "__global__".into(),
            })
            .await
            .expect_err("attested must refuse delete_policy");
        assert!(matches!(
            err,
            PolicyError::Unsupported {
                policy_type: "attested",
                operation: "delete_policy"
            }
        ));
    }

    #[tokio::test]
    async fn get_effective_policy_rejects_envelope_with_wrong_surface_id() {
        let (sk, vk) = fresh_keypair();
        // Build an envelope whose surface_id is wrong; sign it correctly
        // so the signature passes verification and the surface check is
        // the dispositive failure.
        use ed25519_dalek::Signer;
        let policy = SandboxPolicy {
            version: 1,
            ..Default::default()
        };
        let mut env = ProjectionEnvelope {
            surface_id: "openshell.something.v1".to_string(),
            schema_version: "1".to_string(),
            policy_digest: vec![0xaa; 32],
            bundle_digest: vec![0xbb; 32],
            body: policy.encode_to_vec(),
            signature: Vec::new(),
            signing_key_id: None,
        };
        let payload = canonical_projection_bytes(&env);
        env.signature = sk.sign(&payload).to_bytes().to_vec();
        env.signing_key_id = Some("k-1".to_string());

        let source = Arc::new(
            MockPolicySource::default()
                .with_acquire(Box::new(|_ctx| Ok(Handle::new(b"h".to_vec()))))
                .with_get(Box::new(move |_h, _s| Ok(env.clone()))),
        );
        let ts = trust_store_with("k-1", vk);
        let driver = AttestedPolicyProvider::new(source.clone(), ts)
            .await
            .expect("new ok");

        let err = driver
            .get_effective_policy("sb-1")
            .await
            .expect_err("wrong surface must reject");
        assert!(matches!(
            err,
            PolicyError::SourceError(PolicySourceError::Decode(_))
        ));
    }
}
