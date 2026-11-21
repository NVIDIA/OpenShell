// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Temporary provider-write integration for embedded refresh. Secret staging,
//! backend selection, cleanup, and refresh recovery remain in the issuer.
use std::sync::Arc;

use async_trait::async_trait;
use openshell_core::proto::{Provider, ProviderCredentialRefreshStrategy};
use openshell_core::{GetResourceVersion, ObjectId, ObjectName, ObjectWorkspace};
use openshell_credential_issuer::refresh::{
    CommittedRefreshOutputs, GatewayRefreshCommit, RefreshAttempt, RefreshChange,
    RefreshCommitSink, RefreshOutputs, RefreshStateStore,
};
use openshell_credential_issuer::{Handles, SecretOwner};
use prost::Message;
use tonic::Status;

use crate::compute::ComputeRuntime;
use crate::persistence::{AtomicWrite, ObjectType, Store};
use crate::storage_proto::StoredProviderCredentialRefreshState;

#[derive(Debug, Clone)]
pub struct ServerRefreshCommit {
    pub store: Arc<Store>,
    pub compute: Option<ComputeRuntime>,
    pub refresh_store: Arc<dyn RefreshStateStore>,
}

struct ProviderAttempt {
    integration: ServerRefreshCommit,
    provider: Provider,
}

#[async_trait]
impl GatewayRefreshCommit for ServerRefreshCommit {
    async fn observe(
        &self,
        workspace: &str,
        name: &str,
    ) -> Result<Box<dyn RefreshAttempt>, Status> {
        let provider = self
            .store
            .get_message_by_name::<Provider>(workspace, name)
            .await
            .map_err(|e| Status::internal(format!("fetch provider failed: {e}")))?
            .ok_or_else(|| Status::not_found("provider not found"))?;
        Ok(Box::new(ProviderAttempt {
            integration: self.clone(),
            provider,
        }))
    }
}

#[async_trait]
impl RefreshAttempt for ProviderAttempt {
    fn owner(&self) -> SecretOwner<'_> {
        SecretOwner::provider(
            self.provider.object_workspace(),
            self.provider.object_id(),
            self.provider.object_name(),
        )
    }

    async fn prepare_workspace(&self) -> Result<(), Status> {
        if let Some(compute) = &self.integration.compute {
            compute
                .ensure_workspace(self.provider.object_workspace())
                .await?;
        }
        Ok(())
    }

    async fn commit(&self, outputs: RefreshOutputs<'_>) -> Result<CommittedRefreshOutputs, Status> {
        let workspace = self.provider.object_workspace();
        // Network exchange and staging have already completed. Preserve the
        // short workspace guard around attachment validation and provider CAS.
        let _guard = if let Some(compute) = &self.integration.compute {
            Some(
                compute
                    .mutation_guard(crate::compute::MutationScope::Workspace(workspace))
                    .await
                    .map_err(|error| {
                        crate::grpc::persistence_error_to_status(
                            error,
                            "acquire provider mutation lock",
                        )
                    })?,
            )
        } else {
            None
        };
        // Refresh grants can change while the endpoint call is in flight. Read
        // the provider revision before the epoch check: changing a GitHub grant
        // also bumps that revision, so its old mint cannot win the provider CAS.
        let mut current = if outputs.grant.is_some() {
            self.integration
                .store
                .get_message::<Provider>(self.provider.object_id())
                .await
                .map_err(|e| Status::internal(format!("fetch provider for refresh commit: {e}")))?
                .ok_or_else(|| Status::aborted("provider was deleted"))?
        } else {
            self.provider.clone()
        };
        let mut first_mint = None;
        let expected_version = if let Some((epoch, grant_version)) = outputs.grant {
            let grant = self
                .integration
                .refresh_store
                .get(workspace, self.provider.object_id(), outputs.credential_key)
                .await?
                .ok_or_else(|| Status::aborted("provider refresh was deleted"))?;
            if openshell_credential_issuer::refresh::effective_authorization_epoch(&grant)? != epoch
            {
                return Err(Status::aborted("provider refresh was reconfigured"));
            }
            if grant.strategy == ProviderCredentialRefreshStrategy::GithubAppInstallation as i32
                && grant.first_mint_provider_version == 0
            {
                first_mint = Some((
                    StoredProviderCredentialRefreshState::from(&grant),
                    grant_version,
                ));
            }
            current.get_resource_version()
        } else {
            0
        };
        let mut replaced = Handles::new();
        apply_outputs(&mut current, &outputs, &mut replaced);
        crate::grpc::provider::validate_provider_update_against_attached_sandboxes(
            &self.integration.store,
            crate::provider_refresh::RefreshStateReader::CommitStore(
                self.integration.refresh_store.as_ref(),
            ),
            workspace,
            &current,
        )
        .await?;
        // Persist ownership in the same transaction as the first publication.
        // A backend failure leaves the static value intact; even a crash before
        // the issuer finishes its receipt leaves a published token identifiable.
        if let Some((mut grant, grant_version)) = first_mint {
            let provider_version = expected_version + 1;
            grant.first_mint_provider_version = provider_version;
            self.integration
                .store
                .write_atomically(&[
                    AtomicWrite::Update {
                        object_type: Provider::object_type().into(),
                        id: current.object_id().into(),
                        payload: current.encode_to_vec(),
                        expected_version,
                    },
                    AtomicWrite::Update {
                        object_type: StoredProviderCredentialRefreshState::object_type().into(),
                        id: grant.object_id().into(),
                        payload: grant.encode_to_vec(),
                        expected_version: grant_version,
                    },
                ])
                .await
                .map_err(|e| {
                    crate::grpc::persistence_error_to_status(e, "publish first GitHub App token")
                })?;
            return Ok(CommittedRefreshOutputs {
                replaced,
                provider_version,
                grant_version: Some(grant_version + 1),
            });
        }
        let mut replaced = Handles::new();
        let published = self
            .integration
            .store
            .update_message_cas::<Provider, _>(
                self.provider.object_id(),
                expected_version,
                |current| {
                    apply_outputs(current, &outputs, &mut replaced);
                },
            )
            .await
            .map_err(|e| {
                Status::internal(format!("persist refreshed provider credential failed: {e}"))
            })?;
        Ok(CommittedRefreshOutputs {
            replaced,
            provider_version: published.get_resource_version(),
            grant_version: None,
        })
    }
}

fn apply_outputs(provider: &mut Provider, outputs: &RefreshOutputs<'_>, replaced: &mut Handles) {
    if let Some(handles) = outputs.handles {
        for (key, handle) in handles {
            provider.credentials.remove(key);
            if let Some(previous) = provider
                .credential_handles
                .insert(key.clone(), handle.clone())
                && previous != *handle
            {
                replaced.insert(key.clone(), previous);
            }
        }
    } else {
        provider.credentials.extend(outputs.inline.clone());
    }
    for key in std::iter::once(outputs.credential_key)
        .chain(outputs.additional_keys.iter().map(String::as_str))
    {
        if let Some(expiration) = outputs.expiration {
            provider
                .credential_expiration_times
                .insert(key.to_string(), expiration);
        } else {
            provider.credential_expiration_times.remove(key);
        }
    }
}

pub struct ServerRefreshCommitSink<'a>(pub &'a Arc<crate::ServerState>);
impl RefreshCommitSink for ServerRefreshCommitSink<'_> {
    fn notify(&self, change: &RefreshChange) {
        crate::config_delivery::publish_provider(self.0, &change.workspace, &change.provider_name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::CredentialRuntime;
    use crate::persistence::{ObjectType, test_store};
    use openshell_core::{Config, proto::ObjectMeta};
    use openshell_credential_issuer::refresh::minter::MintedCredential;
    use std::collections::HashMap;

    #[tokio::test]
    async fn observed_provider_commit_does_not_target_same_name_replacement() {
        let store = Arc::new(test_store().await);
        let mut provider = Provider {
            metadata: Some(ObjectMeta {
                id: "original".into(),
                name: "provider".into(),
                workspace: "default".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        store.put_message(&provider).await.unwrap();
        let adapter = ServerRefreshCommit {
            store: Arc::clone(&store),
            compute: None,
            refresh_store: Arc::new(crate::refresh_store::ServerRefreshStore(Arc::clone(&store))),
        };
        let attempt = adapter.observe("default", "provider").await.unwrap();
        store
            .delete(Provider::object_type(), "original")
            .await
            .unwrap();
        provider.metadata.as_mut().unwrap().id = "replacement".into();
        provider
            .credentials
            .insert("TOKEN".into(), "replacement-secret".into());
        store.put_message(&provider).await.unwrap();
        let credentials = CredentialRuntime::from_config(
            &Config::new(None).with_credential_drivers(["test-static"]),
        )
        .unwrap();
        let minted = MintedCredential {
            access_token: "stale-mint".into(),
            expires_at_ms: 4_000_000_000_000,
            refresh_token: None,
            additional_credentials: HashMap::new(),
        };
        let error = openshell_credential_issuer::refresh::engine::apply_minted_credential(
            Some(&credentials.issuer()),
            attempt.as_ref(),
            "TOKEN",
            &minted,
            None,
        )
        .await
        .map(|_| ())
        .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Internal);
        let replacement = store
            .get_message::<Provider>("replacement")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(replacement.credentials["TOKEN"], "replacement-secret");
        assert!(replacement.credential_handles.is_empty());
        assert_eq!(credentials.stored_credential_count(), Some(0));
    }
}
