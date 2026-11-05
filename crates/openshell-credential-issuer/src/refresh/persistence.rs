// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Issuer-owned grant encoding. This is deliberately separate from the frozen
//! gateway V1/V2 records. Plaintext refresh material cannot enter this format.

use std::collections::BTreeMap;

use openshell_core::proto::{CredentialHandle, ObjectMeta};
use prost::Message;
use serde::{Deserialize, Serialize};
use tonic::Status;

use super::RefreshState;
use crate::RefreshMaterialDeletion;

const SCHEMA: u32 = 1;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantRecord {
    schema: u32,
    metadata: Option<Vec<u8>>,
    provider_id: String,
    provider_name: String,
    credential_key: String,
    strategy: i32,
    #[serde(default)]
    strategy_name: Option<String>,
    material: BTreeMap<String, String>,
    secret_material_keys: Vec<String>,
    expires_at_ms: i64,
    next_refresh_at_ms: i64,
    last_refresh_at_ms: i64,
    status: String,
    last_error: String,
    token_url: String,
    scopes: Vec<String>,
    refresh_before: Option<Duration>,
    max_lifetime: Option<Duration>,
    additional_output_keys: BTreeMap<String, String>,
    authorization_epoch: String,
    secret_material_handles: BTreeMap<String, Handle>,
    pending_secret_deletions: Vec<Deletion>,
    recovery_action: i32,
    failure_code: String,
    provider_error_subtype: String,
    last_error_at_ms: i64,
    #[serde(default)]
    output_references: BTreeMap<String, Handle>,
    #[serde(default)]
    reference_generation: u64,
}

#[derive(Serialize, Deserialize)]
struct Duration {
    seconds: i64,
    nanos: i32,
}

impl From<prost_types::Duration> for Duration {
    fn from(value: prost_types::Duration) -> Self {
        Self {
            seconds: value.seconds,
            nanos: value.nanos,
        }
    }
}

impl From<Duration> for prost_types::Duration {
    fn from(value: Duration) -> Self {
        Self {
            seconds: value.seconds,
            nanos: value.nanos,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Handle {
    driver: String,
    #[serde(rename = "handle")]
    opaque: String,
    metadata: BTreeMap<String, String>,
}

impl From<&CredentialHandle> for Handle {
    fn from(value: &CredentialHandle) -> Self {
        Self {
            driver: value.driver.clone(),
            opaque: value.handle.clone(),
            metadata: value
                .metadata
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        }
    }
}

impl From<Handle> for CredentialHandle {
    fn from(value: Handle) -> Self {
        Self {
            driver: value.driver,
            handle: value.opaque,
            metadata: value.metadata.into_iter().collect(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Deletion {
    material_key: String,
    handle: Option<Handle>,
}

fn ensure_no_inline_secrets(state: &RefreshState) -> Result<(), Status> {
    if state
        .secret_material_keys
        .iter()
        .any(|key| state.material.contains_key(key))
        || super::strategy_secret_material_keys(
            openshell_core::proto::ProviderCredentialRefreshStrategy::try_from(state.strategy)
                .unwrap_or(openshell_core::proto::ProviderCredentialRefreshStrategy::Unspecified),
        )
        .iter()
        .any(|key| state.material.contains_key(*key))
    {
        return Err(Status::failed_precondition(
            "inline refresh secrets must be migrated before versioned grant persistence",
        ));
    }
    Ok(())
}

// Preserve the generated protobuf wire format without depending on HashMap
// iteration order. Encoding each sorted map entry separately still decodes as
// one ordinary ObjectMeta, including fields added to the generated type later.
fn metadata_bytes(metadata: &ObjectMeta) -> Vec<u8> {
    let mut scalar = metadata.clone();
    scalar.labels.clear();
    scalar.annotations.clear();
    let mut bytes = scalar.encode_to_vec();
    let sorted_labels: BTreeMap<_, _> = metadata.labels.iter().collect();
    for (key, value) in sorted_labels {
        bytes.extend(
            ObjectMeta {
                labels: [(key.clone(), value.clone())].into(),
                ..Default::default()
            }
            .encode_to_vec(),
        );
    }
    let sorted_annotations: BTreeMap<_, _> = metadata.annotations.iter().collect();
    for (key, value) in sorted_annotations {
        bytes.extend(
            ObjectMeta {
                annotations: [(key.clone(), value.clone())].into(),
                ..Default::default()
            }
            .encode_to_vec(),
        );
    }
    bytes
}

/// Encode only validated, handle-backed material. No `Serialize` implementation
/// is exposed on the transient domain state or its secret-bearing requests.
pub fn encode(state: &RefreshState) -> Result<Vec<u8>, Status> {
    ensure_no_inline_secrets(state)?;
    let record = GrantRecord {
        schema: SCHEMA,
        metadata: state.metadata.as_ref().map(metadata_bytes),
        provider_id: state.provider_id.clone(),
        provider_name: state.provider_name.clone(),
        credential_key: state.credential_key.clone(),
        strategy: state.strategy,
        strategy_name: state.strategy_name.clone(),
        material: state
            .material
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        secret_material_keys: state.secret_material_keys.clone(),
        expires_at_ms: state.expires_at_ms,
        next_refresh_at_ms: state.next_refresh_at_ms,
        last_refresh_at_ms: state.last_refresh_at_ms,
        status: state.status.clone(),
        last_error: state.last_error.clone(),
        token_url: state.token_url.clone(),
        scopes: state.scopes.clone(),
        refresh_before: state.refresh_before.map(Into::into),
        max_lifetime: state.max_lifetime.map(Into::into),
        additional_output_keys: state
            .additional_output_keys
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        authorization_epoch: state.authorization_epoch.clone(),
        secret_material_handles: state
            .secret_material_handles
            .iter()
            .map(|(k, v)| (k.clone(), v.into()))
            .collect(),
        pending_secret_deletions: state
            .pending_secret_deletions
            .iter()
            .map(|item| Deletion {
                material_key: item.material_key.clone(),
                handle: item.handle.as_ref().map(Into::into),
            })
            .collect(),
        recovery_action: state.recovery_action,
        failure_code: state.failure_code.clone(),
        provider_error_subtype: state.provider_error_subtype.clone(),
        last_error_at_ms: state.last_error_at_ms,
        output_references: state
            .output_references
            .iter()
            .map(|(k, v)| (k.clone(), v.into()))
            .collect(),
        reference_generation: state.reference_generation,
    };
    serde_json::to_vec(&record).map_err(|_| Status::internal("encode issuer grant failed"))
}

/// Decode the reviewed issuer schema; errors never contain payload bytes.
pub fn decode(payload: &[u8]) -> Result<RefreshState, Status> {
    let record: GrantRecord = serde_json::from_slice(payload)
        .map_err(|_| Status::data_loss("invalid issuer grant record"))?;
    if record.schema != SCHEMA {
        return Err(Status::failed_precondition(
            "unsupported issuer grant schema",
        ));
    }
    let state = RefreshState {
        metadata: record
            .metadata
            .map(|bytes| ObjectMeta::decode(bytes.as_slice()))
            .transpose()
            .map_err(|_| Status::data_loss("invalid issuer grant metadata"))?,
        provider_id: record.provider_id,
        provider_name: record.provider_name,
        credential_key: record.credential_key,
        strategy: record.strategy,
        strategy_name: record.strategy_name,
        material: record.material.into_iter().collect(),
        secret_material_keys: record.secret_material_keys,
        expires_at_ms: record.expires_at_ms,
        next_refresh_at_ms: record.next_refresh_at_ms,
        last_refresh_at_ms: record.last_refresh_at_ms,
        status: record.status,
        last_error: record.last_error,
        token_url: record.token_url,
        scopes: record.scopes,
        refresh_before: record.refresh_before.map(Into::into),
        max_lifetime: record.max_lifetime.map(Into::into),
        additional_output_keys: record.additional_output_keys.into_iter().collect(),
        authorization_epoch: record.authorization_epoch,
        secret_material_handles: record
            .secret_material_handles
            .into_iter()
            .map(|(k, v)| (k, v.into()))
            .collect(),
        pending_secret_deletions: record
            .pending_secret_deletions
            .into_iter()
            .map(|item| RefreshMaterialDeletion {
                material_key: item.material_key,
                handle: item.handle.map(Into::into),
            })
            .collect(),
        recovery_action: record.recovery_action,
        failure_code: record.failure_code,
        provider_error_subtype: record.provider_error_subtype,
        last_error_at_ms: record.last_error_at_ms,
        output_references: record
            .output_references
            .into_iter()
            .map(|(k, v)| (k, v.into()))
            .collect(),
        reference_generation: record.reference_generation,
    };
    ensure_no_inline_secrets(&state)?;
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_codec_is_lossless_and_deterministic() {
        let state = RefreshState {
            metadata: Some(ObjectMeta {
                id: "grant-id".into(),
                name: "grant-name".into(),
                workspace: "work".into(),
                resource_version: 42,
                annotations: [("future".into(), "retained".into())].into(),
                deletion_time: Some(prost_types::Timestamp {
                    seconds: 7,
                    nanos: 11,
                }),
                ..Default::default()
            }),
            provider_id: "provider-id".into(),
            provider_name: "provider".into(),
            credential_key: "access_token".into(),
            strategy: 12345,
            authorization_epoch: "epoch".into(),
            refresh_before: Some(prost_types::Duration {
                seconds: 2,
                nanos: 333,
            }),
            max_lifetime: Some(prost_types::Duration {
                seconds: 31,
                nanos: 444,
            }),
            material: [("config".into(), "public".into())].into(),
            secret_material_keys: vec!["refresh_token".into()],
            secret_material_handles: [(
                "refresh_token".into(),
                CredentialHandle {
                    driver: "vault".into(),
                    handle: "unchanged".into(),
                    metadata: [("future".into(), "kept".into())].into(),
                },
            )]
            .into(),
            pending_secret_deletions: vec![RefreshMaterialDeletion {
                material_key: "old".into(),
                handle: None,
            }],
            recovery_action: 999,
            failure_code: "uncertain".into(),
            ..Default::default()
        };
        let bytes = encode(&state).unwrap();
        let loaded = decode(&bytes).unwrap();
        assert_eq!(encode(&loaded).unwrap(), bytes);
        assert_eq!(loaded.metadata, state.metadata);
        assert_eq!(loaded.strategy, 12345);
        assert_eq!(loaded.refresh_before, state.refresh_before);
        assert_eq!(loaded.max_lifetime, state.max_lifetime);
        assert_eq!(
            loaded.secret_material_handles,
            state.secret_material_handles
        );
        assert!(loaded.pending_secret_deletions[0].handle.is_none());
        assert_eq!(loaded.recovery_action, 999);
    }

    #[test]
    fn inline_material_and_malformed_records_are_rejected_without_values() {
        let mut state = RefreshState {
            secret_material_keys: vec!["secret".into()],
            ..Default::default()
        };
        state
            .material
            .insert("secret".into(), "DO_NOT_PERSIST".into());
        let error = encode(&state).unwrap_err();
        assert!(!error.message().contains("DO_NOT_PERSIST"));
        assert!(
            decode(b"DO_NOT_ECHO")
                .unwrap_err()
                .message()
                .contains("invalid issuer")
        );
    }

    #[test]
    fn grant_metadata_maps_are_canonical_across_independent_reconstructions() {
        let original = RefreshState {
            metadata: Some(ObjectMeta {
                id: "grant".into(),
                name: "name".into(),
                workspace: "workspace".into(),
                labels: (0..16)
                    .map(|i| (format!("label-{i}"), i.to_string()))
                    .collect(),
                annotations: (0..16)
                    .map(|i| (format!("annotation-{i}"), i.to_string()))
                    .collect(),
                created_time: Some(prost_types::Timestamp {
                    seconds: 23,
                    nanos: 45,
                }),
                deletion_time: Some(prost_types::Timestamp {
                    seconds: 67,
                    nanos: 89,
                }),
                resource_version: 123,
            }),
            ..Default::default()
        };
        let expected = encode(&original).unwrap();
        for _ in 0..32 {
            // Decode with independently seeded generated HashMaps, just as a
            // restarted migration reconstructs its frozen legacy source row.
            let mut reconstructed = original.clone();
            reconstructed.metadata = Some(
                ObjectMeta::decode(
                    original
                        .metadata
                        .as_ref()
                        .unwrap()
                        .encode_to_vec()
                        .as_slice(),
                )
                .unwrap(),
            );
            assert_eq!(encode(&reconstructed).unwrap(), expected);
            let decoded = decode(&expected).unwrap();
            assert_eq!(decoded.metadata, original.metadata);
            assert_eq!(encode(&decoded).unwrap(), expected);
        }
    }
}
