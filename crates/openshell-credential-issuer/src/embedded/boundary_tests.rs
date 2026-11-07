// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::CredentialIssuer;
use std::sync::Mutex;
use tonic::Code;

const DRIVER_NAME: &str = "recording";
const FAKE_VALUE: &str = "fixed-fake-secret";

#[derive(Clone, Copy, Default)]
enum ResponseMode {
    #[default]
    Valid,
    MissingId,
    UnknownId,
    DuplicateId,
    MissingResponse,
}

#[derive(Default)]
struct RecordingState {
    stores: Vec<StoreCredentialRequest>,
    resolves: Vec<ResolveCredentialRequest>,
    deletes: Vec<DeleteCredentialRequest>,
    values: HashMap<String, String>,
}

#[derive(Default)]
struct RecordingDriver {
    state: Mutex<RecordingState>,
    response_mode: ResponseMode,
    expiration_time: Option<prost_types::Timestamp>,
    fail_store_key: Option<&'static str>,
}

// Requests and stored values contain secrets. Never derive Debug for this fake
// or its state, including when an issuer trait object is formatted on failure.
impl std::fmt::Debug for RecordingDriver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecordingDriver")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl CredentialDriver for RecordingDriver {
    async fn store_credential(
        &self,
        request: StoreCredentialRequest,
    ) -> Result<CredentialHandle, Status> {
        let mut state = self.state.lock().expect("recording state lock");
        let fails = self.fail_store_key == Some(request.credential_key.as_str());
        let handle = CredentialHandle {
            driver: DRIVER_NAME.to_string(),
            handle: format!("opaque:{}:{}", request.object_id, request.credential_key),
            metadata: HashMap::from([("format".to_string(), "legacy-v1".to_string())]),
        };
        if !fails {
            state
                .values
                .insert(handle.handle.clone(), request.value.clone());
        }
        state.stores.push(request);
        if fails {
            return Err(Status::unavailable("injected store failure"));
        }
        Ok(handle)
    }

    async fn delete_credential(&self, request: DeleteCredentialRequest) -> Result<(), Status> {
        let mut state = self.state.lock().expect("recording state lock");
        if let Some(handle) = &request.handle {
            state.values.remove(&handle.handle);
        }
        state.deletes.push(request);
        Ok(())
    }

    async fn resolve_credentials(
        &self,
        requests: Vec<ResolveCredentialRequest>,
    ) -> Result<Vec<ResolvedCredential>, Status> {
        let mut state = self.state.lock().expect("recording state lock");
        let mut responses = requests
            .iter()
            .map(|request| {
                let value = request
                    .handle
                    .as_ref()
                    .and_then(|handle| state.values.get(&handle.handle))
                    .cloned()
                    .ok_or_else(|| Status::not_found("recording handle not found"))?;
                Ok(ResolvedCredential {
                    request_id: request.request_id.clone(),
                    value,
                    expiration_time: self.expiration_time,
                })
            })
            .collect::<Result<Vec<_>, Status>>()?;
        state.resolves.extend(requests);

        match self.response_mode {
            ResponseMode::Valid => {
                // Correlation must use IDs rather than response position.
                responses.reverse();
            }
            ResponseMode::MissingId => responses[0].request_id.clear(),
            ResponseMode::UnknownId => {
                "unknown-request".clone_into(&mut responses[0].request_id);
            }
            ResponseMode::DuplicateId => responses.push(responses[0].clone()),
            ResponseMode::MissingResponse => {
                responses.pop();
            }
        }
        Ok(responses)
    }
}

fn issuer_with_driver(
    driver: RecordingDriver,
) -> (Arc<dyn CredentialIssuer>, Arc<RecordingDriver>) {
    let config = IssuerConfig {
        credential_drivers: vec![DRIVER_NAME.to_string()],
        default_credential_driver: Some(DRIVER_NAME.to_string()),
        ..IssuerConfig::default()
    };
    let driver = Arc::new(driver);
    let backend: Arc<dyn CredentialDriver> = driver.clone();
    let issuer = EmbeddedCredentialIssuer {
        registry: CredentialDriverRegistry::from_config(&config).expect("recording registry"),
        drivers: BTreeMap::from([(DRIVER_NAME.to_string(), backend)]),
        _driver_processes: Vec::new(),
        negotiated_extensions: Vec::new(),
    };
    (Arc::new(issuer), driver)
}

async fn assert_owner_round_trip(
    owner: SecretOwner<'_>,
    expected_provider: &str,
    expected_owner_id: &str,
) {
    let (issuer, driver) = issuer_with_driver(RecordingDriver::default());
    let values = HashMap::from([("SECRET_KEY".to_string(), FAKE_VALUE.to_string())]);
    let existing_handles = Handles::new();
    let handles = issuer
        .store(StoreSecrets {
            owner,
            object_id: Some("write-candidate-id"),
            values: &values,
            existing_handles: &existing_handles,
        })
        .await
        .expect("store through issuer trait object");
    assert_eq!(handles.len(), 1);
    let handle = handles.get("SECRET_KEY").expect("stored key");
    assert_eq!(handle.driver, DRIVER_NAME);
    assert_eq!(handle.handle, "opaque:write-candidate-id:SECRET_KEY");
    assert_eq!(
        handle.metadata.get("format").map(String::as_str),
        Some("legacy-v1")
    );
    issuer.validate_handles(&handles).expect("valid handles");
    assert!(issuer.stores_provider_credentials());
    assert!(issuer.storage_owns_handle(handle));

    let resolved = issuer
        .resolve(owner, &handles)
        .await
        .expect("resolve through issuer trait object");
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].credential_key, "SECRET_KEY");
    assert!(resolved[0].value == FAKE_VALUE);
    assert!(resolved[0].expiration_time.is_none());
    issuer
        .delete(owner, &handles)
        .await
        .expect("delete through issuer trait object");

    let state = driver.state.lock().expect("recording state lock");
    assert_eq!(state.stores.len(), 1);
    let stored = &state.stores[0];
    assert_eq!(stored.provider, expected_provider);
    assert_eq!(stored.provider_id, expected_owner_id);
    assert_eq!(stored.workspace, "workspace-a");
    assert_eq!(stored.credential_key, "SECRET_KEY");
    assert_eq!(stored.object_id, "write-candidate-id");
    assert!(stored.existing_handle.is_none());
    assert!(stored.value == FAKE_VALUE);

    assert_eq!(state.resolves.len(), 1);
    let request = &state.resolves[0];
    assert_eq!(request.provider, expected_provider);
    assert_eq!(request.provider_id, expected_owner_id);
    assert_eq!(request.workspace, "workspace-a");
    assert_eq!(request.credential_key, "SECRET_KEY");
    assert!(!request.request_id.is_empty());
    assert_eq!(request.handle.as_ref(), Some(handle));

    assert_eq!(state.deletes.len(), 1);
    let deleted = &state.deletes[0];
    assert_eq!(deleted.provider, expected_provider);
    assert_eq!(deleted.provider_id, expected_owner_id);
    assert_eq!(deleted.workspace, "workspace-a");
    assert_eq!(deleted.credential_key, "SECRET_KEY");
    assert_eq!(deleted.handle.as_ref(), Some(handle));
    assert!(state.values.is_empty());
}

#[tokio::test]
async fn provider_trait_object_preserves_legacy_scope_and_staging_identity() {
    assert_owner_round_trip(
        SecretOwner::provider("workspace-a", "provider-id", "provider-name"),
        "provider-name",
        "provider-id",
    )
    .await;
}

#[tokio::test]
async fn sandbox_trait_object_preserves_legacy_scope_and_staging_identity() {
    assert_owner_round_trip(
        SecretOwner::sandbox("workspace-a", "sandbox-id"),
        "sandbox-ssh-sandbox-id",
        "sandbox-id",
    )
    .await;
}

#[tokio::test]
async fn supervisor_instance_trait_object_preserves_assignment_scope_and_staging_identity() {
    assert_owner_round_trip(
        SecretOwner::supervisor_instance("workspace-a", "assignment-sandbox-id"),
        "sandbox-instance-assignment-sandbox-id",
        "assignment-sandbox-id",
    )
    .await;
}

#[tokio::test]
async fn absent_write_identity_defaults_to_owner_id_for_all_owner_kinds() {
    for owner in [
        SecretOwner::provider("workspace-a", "owner-id", "provider-name"),
        SecretOwner::sandbox("workspace-a", "owner-id"),
        SecretOwner::supervisor_instance("workspace-a", "owner-id"),
    ] {
        let (issuer, driver) = issuer_with_driver(RecordingDriver::default());
        issuer
            .store(StoreSecrets {
                owner,
                object_id: None,
                values: &HashMap::from([("SECRET_KEY".to_string(), FAKE_VALUE.to_string())]),
                existing_handles: &Handles::new(),
            })
            .await
            .expect("store with default object identity");
        let state = driver.state.lock().expect("recording state lock");
        assert_eq!(state.stores[0].provider_id, "owner-id");
        assert_eq!(state.stores[0].object_id, "owner-id");
    }
}

async fn assert_rejected_response(mode: ResponseMode, expected_message: &str) {
    let (issuer, _) = issuer_with_driver(RecordingDriver {
        response_mode: mode,
        ..RecordingDriver::default()
    });
    let owner = SecretOwner::provider("workspace-a", "provider-id", "provider-name");
    let handles = issuer
        .store(StoreSecrets {
            owner,
            object_id: None,
            values: &HashMap::from([("SECRET_KEY".to_string(), FAKE_VALUE.to_string())]),
            existing_handles: &Handles::new(),
        })
        .await
        .expect("seed response correlation test");
    let Err(error) = issuer.resolve(owner, &handles).await else {
        panic!("malformed driver response must be rejected");
    };
    assert_eq!(error.code(), Code::Internal);
    assert!(error.message().contains(expected_message));
}

#[tokio::test]
async fn resolve_rejects_response_without_correlation_id() {
    assert_rejected_response(ResponseMode::MissingId, "without request_id").await;
}

#[tokio::test]
async fn resolve_rejects_unknown_correlation_id() {
    assert_rejected_response(ResponseMode::UnknownId, "unknown request_id").await;
}

#[tokio::test]
async fn resolve_rejects_duplicate_correlation_id() {
    assert_rejected_response(ResponseMode::DuplicateId, "duplicate request_id").await;
}

#[tokio::test]
async fn resolve_rejects_missing_correlated_response() {
    assert_rejected_response(ResponseMode::MissingResponse, "did not return a response").await;
}

#[tokio::test]
async fn resolve_correlates_reordered_batch_responses_by_id() {
    let (issuer, _) = issuer_with_driver(RecordingDriver::default());
    let owner = SecretOwner::provider("workspace-a", "provider-id", "provider-name");
    let values = HashMap::from([
        ("FIRST_KEY".to_string(), "fixed-first-secret".to_string()),
        ("SECOND_KEY".to_string(), "fixed-second-secret".to_string()),
    ]);
    let handles = issuer
        .store(StoreSecrets {
            owner,
            object_id: None,
            values: &values,
            existing_handles: &Handles::new(),
        })
        .await
        .expect("seed reordered batch");
    let resolved = issuer
        .resolve(owner, &handles)
        .await
        .expect("resolve batch");
    assert_eq!(resolved.len(), values.len());
    for secret in resolved {
        assert!(values.get(&secret.credential_key) == Some(&secret.value));
    }
}

#[tokio::test]
async fn raw_resolve_retains_expired_backend_metadata_without_filtering_values() {
    // Both timestamps are unambiguously expired, without consulting a clock.
    // Raw issuer resolution carries metadata; gateway policy decides usability.
    for expiration in [
        prost_types::Timestamp {
            seconds: 1,
            nanos: 123,
        },
        prost_types::Timestamp {
            seconds: -1,
            nanos: 0,
        },
    ] {
        let (issuer, _) = issuer_with_driver(RecordingDriver {
            expiration_time: Some(expiration),
            ..RecordingDriver::default()
        });
        let owner = SecretOwner::provider("workspace-a", "provider-id", "provider-name");
        let handles = issuer
            .store(StoreSecrets {
                owner,
                object_id: None,
                values: &HashMap::from([("SECRET_KEY".to_string(), FAKE_VALUE.to_string())]),
                existing_handles: &Handles::new(),
            })
            .await
            .expect("seed expired credential");
        let resolved = issuer
            .resolve(owner, &handles)
            .await
            .expect("raw resolution retains backend expiration");
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].credential_key, "SECRET_KEY");
        assert!(resolved[0].value == FAKE_VALUE);
        assert_eq!(resolved[0].expiration_time, Some(expiration));
    }
}

#[tokio::test]
async fn failed_batch_store_cleans_up_only_successfully_staged_handles() {
    let (issuer, driver) = issuer_with_driver(RecordingDriver {
        fail_store_key: Some("FAILED_KEY"),
        ..RecordingDriver::default()
    });
    let owner = SecretOwner::sandbox("workspace-a", "sandbox-id");
    let error = issuer
        .store(StoreSecrets {
            owner,
            object_id: Some("failed-batch-candidate"),
            values: &HashMap::from([
                ("SUCCESS_KEY".to_string(), FAKE_VALUE.to_string()),
                ("FAILED_KEY".to_string(), FAKE_VALUE.to_string()),
            ]),
            existing_handles: &Handles::new(),
        })
        .await
        .expect_err("one failed key must fail the batch");
    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(error.message(), "injected store failure");

    let state = driver.state.lock().expect("recording state lock");
    assert_eq!(state.stores.len(), 2);
    for request in &state.stores {
        assert_eq!(request.provider, "sandbox-ssh-sandbox-id");
        assert_eq!(request.provider_id, "sandbox-id");
        assert_eq!(request.workspace, "workspace-a");
        assert_eq!(request.object_id, "failed-batch-candidate");
    }
    assert_eq!(state.deletes.len(), 1);
    let deleted = &state.deletes[0];
    assert_eq!(deleted.provider, "sandbox-ssh-sandbox-id");
    assert_eq!(deleted.provider_id, "sandbox-id");
    assert_eq!(deleted.workspace, "workspace-a");
    assert_eq!(deleted.credential_key, "SUCCESS_KEY");
    let handle = deleted.handle.as_ref().expect("cleanup handle");
    assert_eq!(handle.driver, DRIVER_NAME);
    assert_eq!(handle.handle, "opaque:failed-batch-candidate:SUCCESS_KEY");
    assert!(state.values.is_empty());
}
