// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox-lifetime SSH identities. Public objects contain only fingerprints;
//! the credential driver owns private keys and this internal row owns handles.

use std::collections::HashMap;
use std::sync::Arc;

use openshell_core::jwt::{SandboxLaunchAuthentication, SecretSshHostKey};
use openshell_core::proto::Sandbox;
use openshell_core::proto::datamodel::v1::{CredentialHandle, ObjectMeta, Provider};
use openshell_core::{ObjectId as _, ObjectName as _, ObjectWorkspace as _};
use prost::Message as _;
use russh::keys::{Algorithm, HashAlg, PrivateKey};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tonic::Status;

use crate::credentials::CredentialRuntime;
use crate::persistence::{PersistenceError, Store};

const OBJECT_TYPE: &str = "sandbox_ssh_identity_v1";
const CANDIDATE_TYPE: &str = "sandbox_ssh_identity_candidate_v1";
const CREDENTIAL_KEY: &str = "SSH_HOST_PRIVATE_KEY";

#[derive(Clone)]
pub struct SshIdentityStore {
    store: Arc<Store>,
    credentials: CredentialRuntime,
    mutation: Arc<Mutex<()>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::jwt::{CredentialEpoch, SecretJwt, SessionRotation, SupervisorAuthBundle};
    use openshell_core::{SandboxSessionId, sandbox_generation::SandboxGenerationId};

    async fn fixture() -> SshIdentityStore {
        let store = Arc::new(Store::connect("sqlite::memory:").await.unwrap());
        let config = crate::Config::new(None)
            .with_credential_drivers(["test-static"])
            .with_default_credential_driver(Some("test-static"));
        let credentials =
            CredentialRuntime::from_config_with_store(&config, store.clone()).unwrap();
        store.put_message(&sandbox("sandbox-a")).await.unwrap();
        SshIdentityStore::new(store, credentials)
    }

    fn sandbox(id: &str) -> Sandbox {
        Sandbox {
            metadata: Some(ObjectMeta {
                id: id.to_string(),
                name: "same-name".to_string(),
                workspace: "default".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn authentication() -> SandboxLaunchAuthentication {
        SandboxLaunchAuthentication {
            supervisor: SupervisorAuthBundle {
                session_id: SandboxSessionId::new(),
                runtime_generation: SandboxGenerationId::parse("generation").unwrap(),
                session_rotation: SessionRotation::new(1).unwrap(),
                auth_epoch: CredentialEpoch::new(1).unwrap(),
                gateway_token: SecretJwt::parse("gateway-token").unwrap(),
                gateway_expires_at: 0,
                sandbox_token: SecretJwt::parse("sandbox-token").unwrap(),
                sandbox_expires_at: 0,
                ssh_host_private_key: None,
            },
            gateway_id: "gateway".to_string(),
            verification_keys: Vec::new(),
        }
    }

    #[tokio::test]
    async fn concurrent_candidates_keep_one_resolvable_identity() {
        let identities = fixture().await;
        let sb = sandbox("sandbox-a");
        let (entered, release) = identities.credentials.gate_next_store();
        let first = identities.clone();
        let sb1 = sb.clone();
        let task = tokio::spawn(async move { first.get_or_create(&sb1).await.unwrap() });
        entered.await.unwrap();
        let winner = identities.get_or_create(&sb).await.unwrap();
        release.send(()).unwrap();
        let loser = task.await.unwrap();
        assert_eq!(winner.fingerprint, loser.fingerprint);
        assert_eq!(identities.credentials.stored_credential_count(), Some(1));
        identities
            .prepare(&mut sb.clone(), &mut authentication())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn identity_survives_reload_and_is_never_public() {
        let identities = fixture().await;
        let mut sb = sandbox("sandbox-a");
        let mut first = authentication();
        identities.prepare(&mut sb, &mut first).await.unwrap();
        let restored =
            SshIdentityStore::new(identities.store.clone(), identities.credentials.clone());
        let mut next = authentication();
        restored.prepare(&mut sb, &mut next).await.unwrap();
        let private = first.supervisor.ssh_host_private_key.unwrap();
        assert_eq!(
            private.expose_secret(),
            next.supervisor
                .ssh_host_private_key
                .as_ref()
                .unwrap()
                .expose_secret()
        );
        let key = PrivateKey::from_openssh(private.expose_secret()).unwrap();
        assert_eq!(
            sb.host_key_fingerprint,
            key.public_key().fingerprint(HashAlg::Sha256).to_string()
        );
        assert!(!format!("{sb:?}").contains("PRIVATE KEY"));
        assert!(!format!("{next:?}").contains("PRIVATE KEY"));
        let stored = identities
            .store
            .get(OBJECT_TYPE, &SshIdentityStore::identity_id(&sb))
            .await
            .unwrap()
            .unwrap();
        assert!(!String::from_utf8_lossy(&stored.payload).contains("PRIVATE KEY"));
    }

    #[tokio::test]
    async fn deletion_retries_before_releasing_key_ownership() {
        let identities = fixture().await;
        let sb = sandbox("sandbox-a");
        let original = identities.get_or_create(&sb).await.unwrap();
        identities.credentials.fail_next_delete();
        assert!(identities.delete(&sb).await.is_err());
        assert_eq!(
            identities.load(&sb).await.unwrap().unwrap().fingerprint,
            original.fingerprint
        );
        identities.delete(&sb).await.unwrap();
        assert!(identities.load(&sb).await.unwrap().is_none());
        assert_eq!(identities.credentials.stored_credential_count(), Some(0));
        identities.delete(&sb).await.unwrap();
        let replacement = identities
            .get_or_create(&sandbox("sandbox-b"))
            .await
            .unwrap();
        assert_ne!(original.fingerprint, replacement.fingerprint);
    }

    #[tokio::test]
    async fn cancelled_prepare_finishes_before_deletion_and_cannot_recreate_identity() {
        let identities = fixture().await;
        let (entered, release) = identities.credentials.gate_next_store();
        let preparing = identities.clone();
        let task = tokio::spawn(async move {
            preparing
                .prepare(&mut sandbox("sandbox-a"), &mut authentication())
                .await
        });
        entered.await.unwrap();
        task.abort();
        let deleting = identities
            .store
            .update_message_cas::<Sandbox, _>("sandbox-a", 0, |sb| {
                sb.set_phase(openshell_core::proto::SandboxPhase::Deleting.into());
            })
            .await
            .unwrap();
        let cleanup = identities.clone();
        let deleted = tokio::spawn(async move { cleanup.delete(&deleting).await });
        release.send(()).unwrap();
        deleted.await.unwrap().unwrap();
        assert_eq!(identities.credentials.stored_credential_count(), Some(0));
        assert!(
            identities
                .prepare(&mut sandbox("sandbox-a"), &mut authentication())
                .await
                .is_err()
        );
        identities
            .store
            .delete("sandbox", "sandbox-a")
            .await
            .unwrap();
        assert!(
            identities
                .prepare(&mut sandbox("sandbox-a"), &mut authentication())
                .await
                .is_err()
        );
        assert_eq!(identities.credentials.stored_credential_count(), Some(0));
    }

    #[tokio::test]
    async fn losing_candidate_cleanup_failure_remains_owned_for_deletion() {
        let identities = fixture().await;
        let sb = sandbox("sandbox-a");
        let (entered, release) = identities.credentials.gate_next_store();
        let candidate = identities.clone();
        let task =
            tokio::spawn(async move { candidate.get_or_create(&sandbox("sandbox-a")).await });
        entered.await.unwrap();
        identities.get_or_create(&sb).await.unwrap();
        identities.credentials.fail_next_delete();
        release.send(()).unwrap();
        assert!(task.await.unwrap().is_err());
        assert_eq!(identities.credentials.stored_credential_count(), Some(2));
        identities.delete(&sb).await.unwrap();
        assert_eq!(identities.credentials.stored_credential_count(), Some(0));
        assert!(
            identities
                .store
                .list_by_scope(CANDIDATE_TYPE, "sandbox-a", 100, 0)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn published_identity_is_never_replaced_when_storage_is_inconsistent() {
        let identities = fixture().await;
        let mut sb = sandbox("sandbox-a");
        identities
            .prepare(&mut sb, &mut authentication())
            .await
            .unwrap();
        identities
            .store
            .update_message_cas::<Sandbox, _>("sandbox-a", 0, |sb| {
                sb.host_key_fingerprint = "SHA256:inconsistent".to_string();
            })
            .await
            .unwrap();
        assert!(
            identities
                .prepare(&mut sb, &mut authentication())
                .await
                .is_err()
        );
        let stored = identities
            .store
            .get_message::<Sandbox>("sandbox-a")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.host_key_fingerprint, "SHA256:inconsistent");
        identities
            .store
            .delete(OBJECT_TYPE, &SshIdentityStore::identity_id(&sb))
            .await
            .unwrap();
        assert!(
            identities
                .prepare(&mut sb, &mut authentication())
                .await
                .is_err()
        );
        assert_eq!(identities.credentials.stored_credential_count(), Some(1));
    }

    #[tokio::test]
    async fn default_credential_store_persists_key_across_runtime_reconstruction() {
        let store = Arc::new(Store::connect("sqlite::memory:").await.unwrap());
        let config = crate::Config::new(None);
        let first = SshIdentityStore::new(
            store.clone(),
            CredentialRuntime::from_config_with_store(&config, store.clone()).unwrap(),
        );
        let mut sb = sandbox("sandbox-a");
        first.store.put_message(&sb).await.unwrap();
        first.prepare(&mut sb, &mut authentication()).await.unwrap();
        let fingerprint = sb.host_key_fingerprint.clone();
        let next = SshIdentityStore::new(
            store.clone(),
            CredentialRuntime::from_config_with_store(&config, store).unwrap(),
        );
        next.prepare(&mut sb, &mut authentication()).await.unwrap();
        assert_eq!(fingerprint, sb.host_key_fingerprint);
        next.delete(&sb).await.unwrap();
    }
}

#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    fingerprint: String,
    // Protobuf bytes avoid introducing another durable handle schema.
    credential_handle: Vec<u8>,
}

impl SshIdentityStore {
    pub(crate) fn new(store: Arc<Store>, credentials: CredentialRuntime) -> Self {
        Self {
            store,
            credentials,
            mutation: Arc::new(Mutex::new(())),
        }
    }

    /// Keep credential staging and publication alive if the calling RPC is
    /// cancelled. The independent identity lock fences parent deletion on
    /// every replica without nesting the creation mutation guard.
    pub(crate) async fn prepare(
        &self,
        sandbox: &mut Sandbox,
        authentication: &mut SandboxLaunchAuthentication,
    ) -> Result<(), Status> {
        let identities = self.clone();
        let id = sandbox.object_id().to_string();
        let (updated, private_key) = tokio::spawn(async move {
            let _local = identities.mutation.clone().lock_owned().await;
            let _distributed = identities
                .store
                .acquire_ssh_identity_mutation_guard()
                .await
                .map_err(|_| Status::unavailable("lock sandbox SSH identity failed"))?;
            let mut current = identities
                .store
                .get_message::<Sandbox>(&id)
                .await
                .map_err(|_| Status::unavailable("load sandbox SSH identity owner failed"))?
                .ok_or_else(|| Status::not_found("sandbox SSH identity owner was deleted"))?;
            if current.phase() == i32::from(openshell_core::proto::SandboxPhase::Deleting) {
                return Err(Status::failed_precondition(
                    "sandbox SSH identity owner is deleting",
                ));
            }
            let private_key = identities.prepare_locked(&mut current).await?;
            Ok::<_, Status>((current, private_key))
        })
        .await
        .map_err(|_| Status::internal("sandbox SSH identity worker failed"))??;
        *sandbox = updated;
        authentication.supervisor.ssh_host_private_key = Some(private_key);
        Ok(())
    }

    async fn prepare_locked(&self, sandbox: &mut Sandbox) -> Result<SecretSshHostKey, Status> {
        let identity = self.get_or_create(sandbox).await?;
        if !sandbox.host_key_fingerprint.is_empty()
            && sandbox.host_key_fingerprint != identity.fingerprint
        {
            return Err(Status::internal(
                "sandbox SSH identity does not match its published fingerprint",
            ));
        }
        let handle = CredentialHandle::decode(identity.credential_handle.as_slice())
            .map_err(|_| Status::internal("invalid SSH identity credential handle"))?;
        let provider = Self::owner(
            sandbox,
            HashMap::from([(CREDENTIAL_KEY.to_string(), handle)]),
        );
        let mut resolved = self
            .credentials
            .resolve_provider_handles(&provider, 0)
            .await?;
        let private_key = resolved
            .values
            .remove(CREDENTIAL_KEY)
            .ok_or_else(|| Status::unavailable("sandbox SSH host key is unavailable"))?;
        let key = PrivateKey::from_openssh(&private_key)
            .map_err(|_| Status::internal("invalid stored sandbox SSH host key"))?;
        if key.public_key().fingerprint(HashAlg::Sha256).to_string() != identity.fingerprint {
            return Err(Status::internal(
                "sandbox SSH identity does not match its stored key",
            ));
        }
        if sandbox.host_key_fingerprint.is_empty() {
            let fingerprint = identity.fingerprint;
            *sandbox = self
                .store
                .update_message_cas::<Sandbox, _>(sandbox.object_id(), 0, |sandbox| {
                    sandbox.host_key_fingerprint.clone_from(&fingerprint);
                })
                .await
                .map_err(|_| Status::aborted("publish sandbox SSH identity failed"))?;
        }
        Ok(SecretSshHostKey::new(private_key))
    }

    fn identity_id(sandbox: &Sandbox) -> String {
        format!("sandbox-ssh:{}", sandbox.object_id())
    }

    fn owner(sandbox: &Sandbox, handles: HashMap<String, CredentialHandle>) -> Provider {
        Provider {
            metadata: Some(ObjectMeta {
                id: sandbox.object_id().to_string(),
                name: format!("sandbox-ssh-{}", sandbox.object_id()),
                workspace: sandbox.object_workspace().to_string(),
                ..Default::default()
            }),
            credential_handles: handles,
            ..Default::default()
        }
    }

    async fn load(&self, sandbox: &Sandbox) -> Result<Option<StoredIdentity>, Status> {
        self.store
            .get(OBJECT_TYPE, &Self::identity_id(sandbox))
            .await
            .map_err(|_| Status::unavailable("load sandbox SSH identity failed"))?
            .map(|record| {
                serde_json::from_slice(&record.payload)
                    .map_err(|_| Status::internal("invalid stored sandbox SSH identity"))
            })
            .transpose()
    }

    async fn get_or_create(&self, sandbox: &Sandbox) -> Result<StoredIdentity, Status> {
        if let Some(identity) = self.load(sandbox).await? {
            return Ok(identity);
        }
        if !sandbox.host_key_fingerprint.is_empty() {
            return Err(Status::unavailable(
                "sandbox SSH host key is missing; refusing to replace its identity",
            ));
        }
        let key = PrivateKey::random(&mut rand_ssh::rng(), Algorithm::Ed25519)
            .map_err(|_| Status::internal("generate sandbox SSH host key failed"))?;
        let private_key = key
            .to_openssh(russh::keys::ssh_key::LineEnding::default())
            .map_err(|_| Status::internal("encode sandbox SSH host key failed"))?;
        let owner = Self::owner(sandbox, HashMap::new());
        // A distinct candidate path is essential for K8s/Vault: losing a CAS
        // must never overwrite or delete the winning candidate's credential.
        let candidate_id = uuid::Uuid::new_v4().to_string();
        let handles = self
            .credentials
            .store_provider_credentials_with_object_id(
                owner.object_name(),
                sandbox.object_workspace(),
                sandbox.object_id(),
                &candidate_id,
                &HashMap::from([(CREDENTIAL_KEY.to_string(), private_key.to_string())]),
                &HashMap::new(),
            )
            .await?;
        let handle = handles
            .get(CREDENTIAL_KEY)
            .ok_or_else(|| Status::internal("credential driver omitted sandbox SSH host key"))?;
        let identity = StoredIdentity {
            fingerprint: key.public_key().fingerprint(HashAlg::Sha256).to_string(),
            credential_handle: handle.encode_to_vec(),
        };
        let payload = serde_json::to_vec(&identity)
            .map_err(|_| Status::internal("encode sandbox SSH identity failed"))?;
        // Retain losing handles until cleanup succeeds, so deletion can retry
        // a credential-driver failure instead of losing ownership of the key.
        if self
            .store
            .create_scoped(
                CANDIDATE_TYPE,
                &candidate_id,
                &candidate_id,
                sandbox.object_workspace(),
                sandbox.object_id(),
                &payload,
                None,
            )
            .await
            .is_err()
        {
            self.credentials
                .delete_provider_credential_handles(
                    owner.object_name(),
                    sandbox.object_workspace(),
                    sandbox.object_id(),
                    &handles,
                )
                .await?;
            return Err(Status::unavailable("stage sandbox SSH identity failed"));
        }
        match self
            .store
            .create_scoped(
                OBJECT_TYPE,
                &Self::identity_id(sandbox),
                sandbox.object_id(),
                sandbox.object_workspace(),
                sandbox.object_id(),
                &payload,
                None,
            )
            .await
        {
            Ok(_) => {
                self.store
                    .delete(CANDIDATE_TYPE, &candidate_id)
                    .await
                    .map_err(|_| {
                        Status::unavailable("finish sandbox SSH identity staging failed")
                    })?;
                Ok(identity)
            }
            Err(error) => {
                self.credentials
                    .delete_provider_credential_handles(
                        owner.object_name(),
                        sandbox.object_workspace(),
                        sandbox.object_id(),
                        &handles,
                    )
                    .await?;
                self.store
                    .delete(CANDIDATE_TYPE, &candidate_id)
                    .await
                    .map_err(|_| {
                        Status::unavailable("finish sandbox SSH identity cleanup failed")
                    })?;
                if matches!(error, PersistenceError::UniqueViolation { .. }) {
                    self.load(sandbox).await?.ok_or_else(|| {
                        Status::aborted("sandbox SSH identity was concurrently removed")
                    })
                } else {
                    Err(Status::unavailable("persist sandbox SSH identity failed"))
                }
            }
        }
    }

    /// Credential deletion precedes row deletion so failure retains ownership
    /// and can be retried by the normal sandbox deletion controller.
    pub(crate) async fn delete(&self, sandbox: &Sandbox) -> Result<(), Status> {
        let identities = self.clone();
        let sandbox = sandbox.clone();
        tokio::spawn(async move {
            let _local = identities.mutation.clone().lock_owned().await;
            let _distributed = identities
                .store
                .acquire_ssh_identity_mutation_guard()
                .await
                .map_err(|_| Status::unavailable("lock sandbox SSH identity failed"))?;
            identities.delete_locked(&sandbox).await
        })
        .await
        .map_err(|_| Status::internal("sandbox SSH identity deletion worker failed"))?
    }

    async fn delete_locked(&self, sandbox: &Sandbox) -> Result<(), Status> {
        loop {
            let candidates = self
                .store
                .list_by_scope(CANDIDATE_TYPE, sandbox.object_id(), 100, 0)
                .await
                .map_err(|_| Status::unavailable("load staged sandbox SSH identities failed"))?;
            if candidates.is_empty() {
                break;
            }
            for candidate in candidates {
                let identity: StoredIdentity = serde_json::from_slice(&candidate.payload)
                    .map_err(|_| Status::internal("invalid staged sandbox SSH identity"))?;
                self.delete_credential(sandbox, &identity).await?;
                self.store
                    .delete(CANDIDATE_TYPE, &candidate.id)
                    .await
                    .map_err(|_| {
                        Status::unavailable("delete staged sandbox SSH identity failed")
                    })?;
            }
        }
        let Some(identity) = self.load(sandbox).await? else {
            return Ok(());
        };
        self.delete_credential(sandbox, &identity).await?;
        self.store
            .delete(OBJECT_TYPE, &Self::identity_id(sandbox))
            .await
            .map_err(|_| Status::unavailable("delete sandbox SSH identity failed"))?;
        Ok(())
    }

    async fn delete_credential(
        &self,
        sandbox: &Sandbox,
        identity: &StoredIdentity,
    ) -> Result<(), Status> {
        let handle = CredentialHandle::decode(identity.credential_handle.as_slice())
            .map_err(|_| Status::internal("invalid SSH identity credential handle"))?;
        let owner = Self::owner(sandbox, HashMap::new());
        self.credentials
            .delete_provider_credential_handles(
                owner.object_name(),
                sandbox.object_workspace(),
                sandbox.object_id(),
                &HashMap::from([(CREDENTIAL_KEY.to_string(), handle)]),
            )
            .await?;
        Ok(())
    }
}
