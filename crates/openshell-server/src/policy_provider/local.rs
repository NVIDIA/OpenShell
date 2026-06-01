// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Local (in-process, store-backed) policy provider.
//!
//! This is the `"local"` policy type — selected by the default
//! `[openshell.policy] type = "local"` (or by omitting the table entirely).
//!
//! Wraps [`crate::persistence::Store`] (which implements
//! [`crate::policy_store::PolicyStoreExt`]) and exposes the canonical
//! `PolicyProvider` operations. Behavior here is intentionally a thin
//! pass-through to the existing DB writes — the gRPC handler retains
//! validation, audit emission, sandbox-watch notification, and CAS retry
//! responsibility.
//!
//! The next session adds `AttestedPolicyProvider` as a sibling module here.

use std::sync::Arc;

use async_trait::async_trait;
use prost::Message;
use sha2::{Digest, Sha256};

use crate::persistence::Store;
use crate::policy_store::PolicyStoreExt;

use super::{
    DeleteGlobalPolicyCtx, PolicyError, PolicyMutationOutcome, PolicyProvider,
    SetSandboxPolicyCtx, UpdateSandboxPolicyCtx, LOCAL_POLICY_TYPE_ID,
};

/// Local policy provider — persists all mutations directly to the gateway's
/// own store. This is today's behavior, just routed through the trait.
#[derive(Debug, Clone)]
pub struct LocalPolicyProvider {
    store: Arc<Store>,
}

impl LocalPolicyProvider {
    #[must_use]
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }
}

/// SHA-256 over the canonical-encoded policy. Mirrors the
/// `deterministic_policy_hash` in `grpc/policy.rs`, kept private here so the
/// provider can stamp hashes without crossing the module boundary. Local
/// keeps it in sync structurally; the handler module remains the single
/// reference impl used by the rest of the codebase.
fn deterministic_policy_hash(policy: &openshell_core::proto::SandboxPolicy) -> String {
    let mut hasher = Sha256::new();
    hasher.update(policy.version.to_le_bytes());
    if let Some(fs) = &policy.filesystem {
        hasher.update(fs.encode_to_vec());
    }
    if let Some(ll) = &policy.landlock {
        hasher.update(ll.encode_to_vec());
    }
    if let Some(p) = &policy.process {
        hasher.update(p.encode_to_vec());
    }
    let mut entries: Vec<_> = policy.network_policies.iter().collect();
    entries.sort_by_key(|(k, _)| k.as_str());
    for (key, value) in entries {
        hasher.update(key.as_bytes());
        hasher.update(value.encode_to_vec());
    }
    hex::encode(hasher.finalize())
}

#[async_trait]
impl PolicyProvider for LocalPolicyProvider {
    fn id(&self) -> &'static str {
        LOCAL_POLICY_TYPE_ID
    }

    async fn permits_mutation(&self) -> Result<(), PolicyError> {
        // The local provider owns the in-process policy store, so every
        // mutation surface — the three canonical RPC mutators and the
        // draft-chunk approval handlers — is supported. The attested
        // provider will inherit the trait default (`Unsupported`) so the
        // gateway's coarse gate refuses both surfaces uniformly.
        Ok(())
    }

    async fn get_effective_policy(
        &self,
        sandbox_id: &str,
    ) -> Result<Option<openshell_core::proto::SandboxPolicy>, PolicyError> {
        let record = self.store.get_latest_policy(sandbox_id).await?;
        match record {
            Some(record) => {
                let policy = openshell_core::proto::SandboxPolicy::decode(
                    record.policy_payload.as_slice(),
                )
                .map_err(|e| {
                    PolicyError::Persistence(crate::persistence::PersistenceError::Decode(format!(
                        "decode policy failed: {e}"
                    )))
                })?;
                Ok(Some(policy))
            }
            None => Ok(None),
        }
    }

    async fn set_policy(
        &self,
        ctx: &SetSandboxPolicyCtx,
    ) -> Result<PolicyMutationOutcome, PolicyError> {
        let payload = ctx.policy.encode_to_vec();
        let hash = deterministic_policy_hash(&ctx.policy);

        let latest = self.store.get_latest_policy(&ctx.sandbox_id).await?;

        // Idempotent set: same hash already at HEAD → return the existing
        // version without bumping. Matches the no-op short-circuit the
        // handler had before the provider seam was introduced.
        if let Some(ref current) = latest
            && current.policy_hash == hash
        {
            return Ok(PolicyMutationOutcome {
                version: u32::try_from(current.version).unwrap_or(0),
                policy_hash: hash,
                settings_revision: 0,
                deleted: false,
            });
        }

        let next_version = latest.map_or(1, |r| r.version + 1);
        let policy_id = uuid::Uuid::new_v4().to_string();

        self.store
            .put_policy_revision(&policy_id, &ctx.sandbox_id, next_version, &payload, &hash)
            .await?;

        // Best-effort cleanup of older revisions. Matches the handler's
        // `let _ = ...` pattern — supersession failure is not a control-flow
        // signal here; the new revision is still authoritative.
        let _ = self
            .store
            .supersede_older_policies(&ctx.sandbox_id, next_version)
            .await;

        Ok(PolicyMutationOutcome {
            version: u32::try_from(next_version).unwrap_or(0),
            policy_hash: hash,
            settings_revision: 0,
            deleted: false,
        })
    }

    async fn update_policy(
        &self,
        ctx: &UpdateSandboxPolicyCtx,
    ) -> Result<PolicyMutationOutcome, PolicyError> {
        // The merge-with-retry loop, the static-fields-unchanged validation,
        // and the safety validation live in the gRPC handler because they
        // emit `tonic::Status::invalid_argument` directly for client-visible
        // errors. The provider just confirms the operation is supported and
        // re-runs the existing handler-side helper. We surface this by
        // returning a sentinel zero-version outcome that the handler ignores
        // and replaces with the value `apply_merge_operations_with_retry`
        // computed; only the gating semantics travel through the trait here.
        //
        // The attested provider will return `Unsupported` from the default
        // impl, which is what `openshell policy update` needs to reject.
        let _ = (&ctx.sandbox_id, &ctx.sandbox_name, &ctx.merge_operations, &ctx.baseline_policy);
        Ok(PolicyMutationOutcome::default())
    }

    async fn delete_policy(
        &self,
        ctx: &DeleteGlobalPolicyCtx,
    ) -> Result<PolicyMutationOutcome, PolicyError> {
        // Local supports the global-policy delete. Mirror the handler's
        // existing logic: if a latest global revision exists, mark all
        // earlier revisions superseded. The handler still owns the global
        // settings map mutation and the audit emission; this method only
        // gates the operation through the trait so the attested provider's
        // default `Unsupported` is what the handler sees there.
        if let Ok(Some(latest)) = self
            .store
            .get_latest_policy(&ctx.global_policy_sandbox_id)
            .await
        {
            let _ = self
                .store
                .supersede_older_policies(&ctx.global_policy_sandbox_id, latest.version + 1)
                .await;
        }
        Ok(PolicyMutationOutcome::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::Store;
    use openshell_core::proto::SandboxPolicy;

    async fn fresh_store() -> Arc<Store> {
        Arc::new(
            Store::connect("sqlite::memory:?cache=shared")
                .await
                .expect("in-memory sqlite connects"),
        )
    }

    #[tokio::test]
    async fn permits_mutation_is_ok_for_local_provider() {
        let p = LocalPolicyProvider::new(fresh_store().await);
        p.permits_mutation()
            .await
            .expect("local provider permits the entire mutation surface");
    }

    #[tokio::test]
    async fn id_is_local() {
        let p = LocalPolicyProvider::new(fresh_store().await);
        assert_eq!(p.id(), LOCAL_POLICY_TYPE_ID);
        assert_eq!(p.id(), "local");
    }

    #[tokio::test]
    async fn get_effective_policy_returns_none_when_no_revision() {
        let p = LocalPolicyProvider::new(fresh_store().await);
        let got = p.get_effective_policy("sb-fresh").await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn set_policy_persists_and_get_effective_policy_returns_it() {
        let store = fresh_store().await;
        let p = LocalPolicyProvider::new(store.clone());
        let policy = SandboxPolicy {
            version: 1,
            ..Default::default()
        };
        let out = p
            .set_policy(&SetSandboxPolicyCtx {
                sandbox_id: "sb-1".to_string(),
                sandbox_name: "sb-1".to_string(),
                expected_resource_version: 0,
                policy: policy.clone(),
            })
            .await
            .expect("set_policy succeeds");
        assert_eq!(out.version, 1);
        assert!(!out.policy_hash.is_empty());

        let fetched = p
            .get_effective_policy("sb-1")
            .await
            .expect("get_effective_policy ok")
            .expect("policy present");
        assert_eq!(fetched.version, 1);
    }

    #[tokio::test]
    async fn set_policy_is_idempotent_on_same_hash() {
        let store = fresh_store().await;
        let p = LocalPolicyProvider::new(store);
        let policy = SandboxPolicy {
            version: 1,
            ..Default::default()
        };
        let ctx = SetSandboxPolicyCtx {
            sandbox_id: "sb-2".to_string(),
            sandbox_name: "sb-2".to_string(),
            expected_resource_version: 0,
            policy: policy.clone(),
        };
        let first = p.set_policy(&ctx).await.unwrap();
        let second = p.set_policy(&ctx).await.unwrap();
        assert_eq!(first.version, second.version);
        assert_eq!(first.policy_hash, second.policy_hash);
    }

    #[tokio::test]
    async fn set_policy_bumps_version_on_distinct_hash() {
        let store = fresh_store().await;
        let p = LocalPolicyProvider::new(store);
        let policy_a = SandboxPolicy {
            version: 1,
            ..Default::default()
        };
        let policy_b = SandboxPolicy {
            version: 2,
            ..Default::default()
        };
        let ctx_a = SetSandboxPolicyCtx {
            sandbox_id: "sb-3".to_string(),
            sandbox_name: "sb-3".to_string(),
            expected_resource_version: 0,
            policy: policy_a,
        };
        let ctx_b = SetSandboxPolicyCtx {
            sandbox_id: "sb-3".to_string(),
            sandbox_name: "sb-3".to_string(),
            expected_resource_version: 0,
            policy: policy_b,
        };
        let a = p.set_policy(&ctx_a).await.unwrap();
        let b = p.set_policy(&ctx_b).await.unwrap();
        assert_eq!(a.version, 1);
        assert_eq!(b.version, 2);
        assert_ne!(a.policy_hash, b.policy_hash);
    }

    #[tokio::test]
    async fn delete_policy_is_ok_when_no_global_revision_exists() {
        let p = LocalPolicyProvider::new(fresh_store().await);
        // Should not error even though there is no global revision to
        // supersede; matches the handler's `let _ = ...` semantics.
        p.delete_policy(&DeleteGlobalPolicyCtx {
            global_policy_sandbox_id: "__global__".to_string(),
        })
        .await
        .expect("delete with no revision is a no-op");
    }

    #[tokio::test]
    async fn update_policy_is_ok_for_local_provider() {
        let p = LocalPolicyProvider::new(fresh_store().await);
        // The merge work lives in the handler today; the trait method just
        // gates the operation. Local says "supported", attested would say
        // Unsupported via the default impl.
        let out = p
            .update_policy(&UpdateSandboxPolicyCtx {
                sandbox_id: "sb-4".to_string(),
                sandbox_name: "sb-4".to_string(),
                merge_operations: vec![],
                baseline_policy: None,
            })
            .await
            .expect("update_policy supported on local");
        // Local returns the default sentinel — the handler retains the
        // merge-with-retry work and builds the final response itself.
        assert_eq!(out.version, 0);
        assert!(out.policy_hash.is_empty());
        assert!(!out.deleted);
    }
}
