// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::credentials::CredentialRuntime;
use crate::grpc::test_support::authed_request;
use openshell_core::proto::{DeletionOutcome, ObjectMeta};
use openshell_credential_issuer::refresh::{RefreshState, RefreshStateStore};

struct Fixture {
    _directory: tempfile::TempDir,
    state: Arc<ServerState>,
}

impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(crate::persistence::test_store().await);
        crate::ensure_default_workspace(&store).await.unwrap();
        let key = directory.path().join("intent-key");
        std::fs::write(&key, b"test-only stable private fingerprint material").unwrap();
        let mut config = openshell_core::Config::new(None).with_credential_drivers(["test-static"]);
        config.enable_versioned_credentials = true;
        config.gateway_jwt = Some(openshell_core::config::GatewayJwtConfig {
            signing_key_path: key,
            public_key_path: directory.path().join("public"),
            kid_path: directory.path().join("kid"),
            gateway_id: "test".into(),
            ttl_secs: None,
        });
        let credentials =
            CredentialRuntime::from_config_file_with_store(&config, None, Arc::clone(&store))
                .await
                .unwrap();
        let compute = crate::compute::new_test_runtime(Arc::clone(&store)).await;
        let state = Arc::new(ServerState::new_with_credentials(
            config,
            store,
            compute,
            crate::sandbox_index::SandboxIndex::new(),
            crate::sandbox_watch::SandboxWatchBus::new(),
            crate::tracing_bus::TracingLogBus::new(),
            Arc::new(crate::supervisor_session::SupervisorSessionRegistry::new()),
            None,
            credentials,
        ));
        let catalog = state
            .provider_profile_sources
            .snapshot_catalog(&state.store, "default")
            .await
            .unwrap();
        create_provider_record_validating(
            &state.store,
            "default",
            &catalog,
            Provider {
                metadata: Some(ObjectMeta {
                    name: "provider".into(),
                    workspace: "default".into(),
                    ..Default::default()
                }),
                r#type: "custom".into(),
                credentials: HashMap::from([("TOKEN".into(), "original".into())]),
                ..Default::default()
            },
            Some(&state.credentials),
        )
        .await
        .unwrap();
        Self {
            _directory: directory,
            state,
        }
    }

    async fn provider(&self) -> Provider {
        self.state
            .store
            .get_message_by_name("default", "provider")
            .await
            .unwrap()
            .unwrap()
    }

    fn configure_request() -> ConfigureProviderRefreshRequest {
        ConfigureProviderRefreshRequest {
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            provider: "provider".into(),
            credential_key: "TOKEN".into(),
            strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32,
            material: HashMap::from([
                ("client_id".into(), "client".into()),
                ("client_secret".into(), "secret".into()),
            ]),
            ..Default::default()
        }
    }

    async fn configure(&self) -> RefreshState {
        handle_configure_provider_refresh(&self.state, authed_request(Self::configure_request()))
            .await
            .unwrap();
        let provider = self.provider().await;
        self.state
            .refresh
            .get("default", provider.object_id(), "TOKEN")
            .await
            .unwrap()
            .unwrap()
    }

    async fn delete(&self) -> Result<DeletionOutcome, Status> {
        Ok(handle_delete_provider_refresh(
            &self.state,
            authed_request(DeleteProviderRefreshRequest {
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                provider: "provider".into(),
                credential_key: "TOKEN".into(),
                ..Default::default()
            }),
        )
        .await?
        .into_inner()
        .outcome())
    }

    async fn status(
        &self,
        key: &str,
    ) -> Vec<openshell_core::proto::ProviderCredentialRefreshStatus> {
        handle_get_provider_refresh_status(
            &self.state,
            authed_request(GetProviderRefreshStatusRequest {
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                provider: "provider".into(),
                credential_key: key.into(),
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .credentials
    }

    async fn update(&self) -> Result<(), Status> {
        handle_update_provider(
            &self.state,
            authed_request(UpdateProviderRequest {
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                provider: Some(Provider {
                    metadata: Some(ObjectMeta {
                        name: "provider".into(),
                        ..Default::default()
                    }),
                    credentials: HashMap::from([("TOKEN".into(), "updated".into())]),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        )
        .await
        .map(|_| ())
    }
}

#[tokio::test]
async fn versioned_foreground_delete_retries_material_cleanup_and_unblocks_updates() {
    let f = Fixture::new().await;
    let grant = f.configure().await;
    f.state.credentials.fail_next_delete();
    assert!(f.delete().await.is_err());
    let provider = f.provider().await;
    let versioned = f.state.credentials.versioned().unwrap();
    let deleting = versioned
        .get_by_id(grant.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(deleting.status, "deleting");
    assert!(deleting.metadata.as_ref().unwrap().deletion_time.is_some());
    assert!(
        f.state
            .refresh
            .get("default", provider.object_id(), "TOKEN")
            .await
            .unwrap()
            .is_none(),
        "cleanup is not live authorization"
    );
    assert_eq!(
        f.update().await.unwrap_err().code(),
        tonic::Code::FailedPrecondition
    );
    // The backend's one-shot failure has recovered. Retry must complete now,
    // without waiting for a worker sweep or changing the provider's static outputs.
    assert_eq!(f.delete().await.unwrap(), DeletionOutcome::Completed);
    assert!(
        versioned
            .get_by_id(grant.object_id())
            .await
            .unwrap()
            .is_none()
    );
    assert!(f.status("TOKEN").await.is_empty());
    assert!(f.status("").await.is_empty());
    assert_eq!(f.provider().await, provider);
    f.update().await.unwrap();
    let updated = f.provider().await;
    assert_eq!(
        f.state
            .credentials
            .resolve_provider_handles(&updated, openshell_core::time::now_ms())
            .await
            .unwrap()
            .values["TOKEN"],
        "updated"
    );
}

#[tokio::test]
async fn versioned_keyed_status_exposes_current_deletion_and_configure_requires_cleanup() {
    let f = Fixture::new().await;
    f.configure().await;
    f.state.credentials.fail_next_delete();
    assert!(f.delete().await.is_err());
    let listed = f.status("").await;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].status, "deleting");
    assert_eq!(f.status("TOKEN").await, listed);
    assert_eq!(
        handle_configure_provider_refresh(&f.state, authed_request(Fixture::configure_request()))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    assert_eq!(f.delete().await.unwrap(), DeletionOutcome::Completed);
    f.configure().await;
}

#[tokio::test]
async fn observed_deletion_cleanup_preserves_newer_versioned_binding() {
    let f = Fixture::new().await;
    f.configure().await;
    f.state.credentials.fail_next_delete();
    assert!(f.delete().await.is_err());
    let provider = f.provider().await;
    let versioned = f.state.credentials.versioned().unwrap();
    let observed = versioned
        .current_refresh_state(&provider, "TOKEN")
        .await
        .unwrap()
        .unwrap();
    // Exercise the exact-ID fence if a separately authorized binding publication
    // wins after cleanup selected its snapshot. Ordinary foreground configure
    // correctly refuses to start while this deletion is pending (covered above).
    let mut replacement = observed.clone();
    replacement.metadata.as_mut().unwrap().deletion_time = None;
    replacement.authorization_epoch = uuid::Uuid::new_v4().to_string();
    replacement.status = "configured".into();
    replacement.next_refresh_at_ms = 0;
    replacement.secret_material_handles = f
        .state
        .credentials
        .store_refresh_material_with_object_id(
            openshell_credential_issuer::refresh::refresh_material_scope(&replacement),
            &uuid::Uuid::new_v4().to_string(),
            &HashMap::from([("client_secret".into(), "replacement-secret".into())]),
            &HashMap::new(),
        )
        .await
        .unwrap();
    let winner = versioned
        .configure(&provider, replacement, "test-static", None, ())
        .await
        .unwrap();
    assert_ne!(winner.object_id(), observed.object_id());
    let winning_provider = f.provider().await;
    f.state.refresh.delete(observed.clone()).await.unwrap();
    assert!(
        versioned
            .get_by_id(observed.object_id())
            .await
            .unwrap()
            .is_none()
    );
    let live = f
        .state
        .refresh
        .get("default", winner.provider_id.as_str(), "TOKEN")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(live.object_id(), winner.object_id());
    assert_eq!(live.metadata, winner.metadata);
    assert_eq!(f.provider().await, winning_provider);
    assert_eq!(f.status("TOKEN").await, f.status("").await);
    assert_eq!(
        f.state
            .credentials
            .resolve_refresh_material(
                openshell_credential_issuer::refresh::refresh_material_scope(&winner),
                &winner.secret_material_handles,
            )
            .await
            .unwrap()["client_secret"],
        "replacement-secret"
    );
    assert_eq!(
        f.state
            .credentials
            .resolve_provider_handles(&winning_provider, openshell_core::time::now_ms())
            .await
            .unwrap()
            .values["TOKEN"],
        "original"
    );
}
