// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Temporary provider-write integration for embedded refresh. Secret staging,
//! backend selection, cleanup, and refresh recovery remain in the issuer.
use std::sync::Arc;

use async_trait::async_trait;
use openshell_core::proto::Provider;
use openshell_core::{ObjectId, ObjectName, ObjectWorkspace};
use openshell_credential_issuer::refresh::{
    GatewayRefreshCommit, RefreshAttempt, RefreshChange, RefreshCommitSink, RefreshOutputs,
    RefreshStateStore,
};
use openshell_credential_issuer::{Handles, SecretOwner};
use tonic::Status;

use crate::compute::ComputeRuntime;
use crate::persistence::Store;

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

    async fn commit(&self, outputs: RefreshOutputs<'_>) -> Result<Handles, Status> {
        let workspace = self.provider.object_workspace();
        let mut updated = self.provider.clone();
        apply_outputs(&mut updated, &outputs, &mut Handles::new());
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
        crate::grpc::provider::validate_provider_update_against_attached_sandboxes(
            &self.integration.store,
            crate::provider_refresh::RefreshStateReader::CommitStore(
                self.integration.refresh_store.as_ref(),
            ),
            workspace,
            &updated,
        )
        .await?;
        let mut replaced = Handles::new();
        self.integration
            .store
            .update_message_cas::<Provider, _>(self.provider.object_id(), 0, |current| {
                apply_outputs(current, &outputs, &mut replaced);
            })
            .await
            .map_err(|e| {
                Status::internal(format!("persist refreshed provider credential failed: {e}"))
            })?;
        Ok(replaced)
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
        )
        .await
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
