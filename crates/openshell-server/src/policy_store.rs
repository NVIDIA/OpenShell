// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::persistence::{DraftChunkRecord, PersistenceResult, PolicyRecord, Store};
use openshell_core::proto::{
    DraftChunkPayload, NetworkPolicyRule, PolicyRevisionPayload,
    SandboxPolicy as ProtoSandboxPolicy,
};
use prost::Message;

pub(crate) trait PolicyStoreExt {
    async fn put_policy_revision(
        &self,
        id: &str,
        sandbox_id: &str,
        version: i64,
        payload: &[u8],
        hash: &str,
    ) -> PersistenceResult<()>;

    async fn get_latest_policy(&self, sandbox_id: &str) -> PersistenceResult<Option<PolicyRecord>>;

    #[allow(dead_code)]
    async fn get_latest_loaded_policy(
        &self,
        sandbox_id: &str,
    ) -> PersistenceResult<Option<PolicyRecord>>;

    async fn get_policy_by_version(
        &self,
        sandbox_id: &str,
        version: i64,
    ) -> PersistenceResult<Option<PolicyRecord>>;

    async fn list_policies(
        &self,
        sandbox_id: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<PolicyRecord>>;

    async fn update_policy_status(
        &self,
        sandbox_id: &str,
        version: i64,
        status: &str,
        load_error: Option<&str>,
        loaded_at_ms: Option<i64>,
    ) -> PersistenceResult<bool>;

    async fn supersede_older_policies(
        &self,
        sandbox_id: &str,
        before_version: i64,
    ) -> PersistenceResult<u64>;

    async fn put_draft_chunk(&self, chunk: &DraftChunkRecord) -> PersistenceResult<()>;

    async fn get_draft_chunk(&self, id: &str) -> PersistenceResult<Option<DraftChunkRecord>>;

    async fn list_draft_chunks(
        &self,
        sandbox_id: &str,
        status_filter: Option<&str>,
    ) -> PersistenceResult<Vec<DraftChunkRecord>>;

    async fn update_draft_chunk_status(
        &self,
        id: &str,
        status: &str,
        decided_at_ms: Option<i64>,
    ) -> PersistenceResult<bool>;

    async fn update_draft_chunk_rule(
        &self,
        id: &str,
        proposed_rule: &[u8],
    ) -> PersistenceResult<bool>;

    async fn delete_draft_chunks(&self, sandbox_id: &str, status: &str) -> PersistenceResult<u64>;

    async fn get_draft_version(&self, sandbox_id: &str) -> PersistenceResult<i64>;
}

impl PolicyStoreExt for Store {
    async fn put_policy_revision(
        &self,
        id: &str,
        sandbox_id: &str,
        version: i64,
        payload: &[u8],
        hash: &str,
    ) -> PersistenceResult<()> {
        match self {
            Self::Postgres(store) => {
                store
                    .put_policy_revision(id, sandbox_id, version, payload, hash)
                    .await
            }
            Self::Sqlite(store) => {
                store
                    .put_policy_revision(id, sandbox_id, version, payload, hash)
                    .await
            }
        }
    }

    async fn get_latest_policy(&self, sandbox_id: &str) -> PersistenceResult<Option<PolicyRecord>> {
        match self {
            Self::Postgres(store) => store.get_latest_policy(sandbox_id).await,
            Self::Sqlite(store) => store.get_latest_policy(sandbox_id).await,
        }
    }

    async fn get_latest_loaded_policy(
        &self,
        sandbox_id: &str,
    ) -> PersistenceResult<Option<PolicyRecord>> {
        match self {
            Self::Postgres(store) => store.get_latest_loaded_policy(sandbox_id).await,
            Self::Sqlite(store) => store.get_latest_loaded_policy(sandbox_id).await,
        }
    }

    async fn get_policy_by_version(
        &self,
        sandbox_id: &str,
        version: i64,
    ) -> PersistenceResult<Option<PolicyRecord>> {
        match self {
            Self::Postgres(store) => store.get_policy_by_version(sandbox_id, version).await,
            Self::Sqlite(store) => store.get_policy_by_version(sandbox_id, version).await,
        }
    }

    async fn list_policies(
        &self,
        sandbox_id: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<PolicyRecord>> {
        match self {
            Self::Postgres(store) => store.list_policies(sandbox_id, limit, offset).await,
            Self::Sqlite(store) => store.list_policies(sandbox_id, limit, offset).await,
        }
    }

    async fn update_policy_status(
        &self,
        sandbox_id: &str,
        version: i64,
        status: &str,
        load_error: Option<&str>,
        loaded_at_ms: Option<i64>,
    ) -> PersistenceResult<bool> {
        match self {
            Self::Postgres(store) => {
                store
                    .update_policy_status(sandbox_id, version, status, load_error, loaded_at_ms)
                    .await
            }
            Self::Sqlite(store) => {
                store
                    .update_policy_status(sandbox_id, version, status, load_error, loaded_at_ms)
                    .await
            }
        }
    }

    async fn supersede_older_policies(
        &self,
        sandbox_id: &str,
        before_version: i64,
    ) -> PersistenceResult<u64> {
        match self {
            Self::Postgres(store) => {
                store
                    .supersede_older_policies(sandbox_id, before_version)
                    .await
            }
            Self::Sqlite(store) => {
                store
                    .supersede_older_policies(sandbox_id, before_version)
                    .await
            }
        }
    }

    async fn put_draft_chunk(&self, chunk: &DraftChunkRecord) -> PersistenceResult<()> {
        match self {
            Self::Postgres(store) => store.put_draft_chunk(chunk).await,
            Self::Sqlite(store) => store.put_draft_chunk(chunk).await,
        }
    }

    async fn get_draft_chunk(&self, id: &str) -> PersistenceResult<Option<DraftChunkRecord>> {
        match self {
            Self::Postgres(store) => store.get_draft_chunk(id).await,
            Self::Sqlite(store) => store.get_draft_chunk(id).await,
        }
    }

    async fn list_draft_chunks(
        &self,
        sandbox_id: &str,
        status_filter: Option<&str>,
    ) -> PersistenceResult<Vec<DraftChunkRecord>> {
        match self {
            Self::Postgres(store) => store.list_draft_chunks(sandbox_id, status_filter).await,
            Self::Sqlite(store) => store.list_draft_chunks(sandbox_id, status_filter).await,
        }
    }

    async fn update_draft_chunk_status(
        &self,
        id: &str,
        status: &str,
        decided_at_ms: Option<i64>,
    ) -> PersistenceResult<bool> {
        match self {
            Self::Postgres(store) => {
                store
                    .update_draft_chunk_status(id, status, decided_at_ms)
                    .await
            }
            Self::Sqlite(store) => {
                store
                    .update_draft_chunk_status(id, status, decided_at_ms)
                    .await
            }
        }
    }

    async fn update_draft_chunk_rule(
        &self,
        id: &str,
        proposed_rule: &[u8],
    ) -> PersistenceResult<bool> {
        match self {
            Self::Postgres(store) => store.update_draft_chunk_rule(id, proposed_rule).await,
            Self::Sqlite(store) => store.update_draft_chunk_rule(id, proposed_rule).await,
        }
    }

    async fn delete_draft_chunks(&self, sandbox_id: &str, status: &str) -> PersistenceResult<u64> {
        match self {
            Self::Postgres(store) => store.delete_draft_chunks(sandbox_id, status).await,
            Self::Sqlite(store) => store.delete_draft_chunks(sandbox_id, status).await,
        }
    }

    async fn get_draft_version(&self, sandbox_id: &str) -> PersistenceResult<i64> {
        match self {
            Self::Postgres(store) => store.get_draft_version(sandbox_id).await,
            Self::Sqlite(store) => store.get_draft_version(sandbox_id).await,
        }
    }
}

pub(crate) fn policy_payload_from_record(record: &PolicyRecord) -> PersistenceResult<Vec<u8>> {
    let policy = ProtoSandboxPolicy::decode(record.policy_payload.as_slice()).map_err(|e| {
        crate::persistence::PersistenceError::Decode(format!("decode policy payload failed: {e}"))
    })?;
    Ok(PolicyRevisionPayload {
        policy: Some(policy),
        hash: record.policy_hash.clone(),
        load_error: record.load_error.clone().unwrap_or_default(),
        loaded_at_ms: record.loaded_at_ms.unwrap_or(0),
    }
    .encode_to_vec())
}

pub(crate) fn policy_record_from_parts(
    id: String,
    sandbox_id: String,
    version: i64,
    status: String,
    payload: &[u8],
    created_at_ms: i64,
) -> PersistenceResult<PolicyRecord> {
    let wrapper = PolicyRevisionPayload::decode(payload).map_err(|e| {
        crate::persistence::PersistenceError::Decode(format!("decode policy wrapper failed: {e}"))
    })?;
    let policy = wrapper.policy.ok_or_else(|| {
        crate::persistence::PersistenceError::Decode("policy wrapper missing policy".to_string())
    })?;
    Ok(PolicyRecord {
        id,
        sandbox_id,
        version,
        policy_payload: policy.encode_to_vec(),
        policy_hash: wrapper.hash,
        status,
        load_error: if wrapper.load_error.is_empty() {
            None
        } else {
            Some(wrapper.load_error)
        },
        created_at_ms,
        loaded_at_ms: (wrapper.loaded_at_ms > 0).then_some(wrapper.loaded_at_ms),
    })
}

pub(crate) fn draft_chunk_payload_from_record(
    chunk: &DraftChunkRecord,
) -> PersistenceResult<Vec<u8>> {
    let proposed_rule = if chunk.proposed_rule.is_empty() {
        None
    } else {
        Some(
            NetworkPolicyRule::decode(chunk.proposed_rule.as_slice()).map_err(|e| {
                crate::persistence::PersistenceError::Decode(format!(
                    "decode draft rule failed: {e}"
                ))
            })?,
        )
    };
    Ok(DraftChunkPayload {
        rule_name: chunk.rule_name.clone(),
        proposed_rule,
        rationale: chunk.rationale.clone(),
        security_notes: chunk.security_notes.clone(),
        confidence: chunk.confidence as f32,
        decided_at_ms: chunk.decided_at_ms.unwrap_or(0),
        host: chunk.host.clone(),
        port: chunk.port,
        binary: chunk.binary.clone(),
        draft_version: chunk.draft_version,
    }
    .encode_to_vec())
}

pub(crate) fn draft_chunk_record_from_parts(
    id: String,
    sandbox_id: String,
    status: String,
    hit_count: i64,
    payload: &[u8],
    created_at_ms: i64,
    updated_at_ms: i64,
) -> PersistenceResult<DraftChunkRecord> {
    let wrapper = DraftChunkPayload::decode(payload).map_err(|e| {
        crate::persistence::PersistenceError::Decode(format!(
            "decode draft chunk wrapper failed: {e}"
        ))
    })?;
    let proposed_rule = wrapper
        .proposed_rule
        .map(|rule| rule.encode_to_vec())
        .unwrap_or_default();
    Ok(DraftChunkRecord {
        id,
        sandbox_id,
        draft_version: wrapper.draft_version,
        status,
        rule_name: wrapper.rule_name,
        proposed_rule,
        rationale: wrapper.rationale,
        security_notes: wrapper.security_notes,
        confidence: f64::from(wrapper.confidence),
        created_at_ms,
        decided_at_ms: (wrapper.decided_at_ms > 0).then_some(wrapper.decided_at_ms),
        host: wrapper.host,
        port: wrapper.port,
        binary: wrapper.binary,
        hit_count: i32::try_from(hit_count).unwrap_or(i32::MAX),
        first_seen_ms: created_at_ms,
        last_seen_ms: updated_at_ms,
    })
}
