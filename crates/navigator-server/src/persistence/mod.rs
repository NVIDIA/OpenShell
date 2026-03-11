// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Persistence layer for `OpenShell` Server.

mod postgres;
mod sqlite;

use navigator_core::{Error, Result};
use prost::Message;
use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};

pub use postgres::PostgresStore;
pub use sqlite::SqliteStore;

/// Stored object record.
#[derive(Debug, Clone)]
pub struct ObjectRecord {
    pub object_type: String,
    pub id: String,
    pub name: String,
    pub payload: Vec<u8>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

/// Stored sandbox policy revision record.
#[derive(Debug, Clone)]
pub struct PolicyRecord {
    pub id: String,
    pub sandbox_id: String,
    pub version: i64,
    pub policy_payload: Vec<u8>,
    pub policy_hash: String,
    pub status: String,
    pub load_error: Option<String>,
    pub created_at_ms: i64,
    pub loaded_at_ms: Option<i64>,
}

/// Persistence store implementations.
#[derive(Debug, Clone)]
pub enum Store {
    Postgres(PostgresStore),
    Sqlite(SqliteStore),
}

/// Trait for inferring an object type string from a message type.
pub trait ObjectType {
    fn object_type() -> &'static str;
}

/// Trait for extracting an object id from a message instance.
pub trait ObjectId {
    fn object_id(&self) -> &str;
}

/// Trait for extracting an object name from a message instance.
pub trait ObjectName {
    fn object_name(&self) -> &str;
}

/// Generate a random 6-character lowercase alphabetic name.
pub fn generate_name() -> String {
    let mut rng = rand::rng();
    (0..6)
        .map(|_| rng.random_range(b'a'..=b'z') as char)
        .collect()
}

impl Store {
    /// Connect to a persistence store based on the database URL.
    pub async fn connect(url: &str) -> Result<Self> {
        if url.starts_with("postgres://") || url.starts_with("postgresql://") {
            let store = PostgresStore::connect(url).await?;
            store.migrate().await?;
            Ok(Self::Postgres(store))
        } else if url.starts_with("sqlite:") {
            let store = SqliteStore::connect(url).await?;
            store.migrate().await?;
            Ok(Self::Sqlite(store))
        } else {
            Err(Error::config(format!(
                "unsupported database URL scheme: {url}"
            )))
        }
    }

    /// Insert or update an object.
    pub async fn put(&self, object_type: &str, id: &str, name: &str, payload: &[u8]) -> Result<()> {
        match self {
            Self::Postgres(store) => store.put(object_type, id, name, payload).await,
            Self::Sqlite(store) => store.put(object_type, id, name, payload).await,
        }
    }

    /// Fetch an object by id.
    pub async fn get(&self, object_type: &str, id: &str) -> Result<Option<ObjectRecord>> {
        match self {
            Self::Postgres(store) => store.get(object_type, id).await,
            Self::Sqlite(store) => store.get(object_type, id).await,
        }
    }

    /// Fetch an object by name within an object type.
    pub async fn get_by_name(&self, object_type: &str, name: &str) -> Result<Option<ObjectRecord>> {
        match self {
            Self::Postgres(store) => store.get_by_name(object_type, name).await,
            Self::Sqlite(store) => store.get_by_name(object_type, name).await,
        }
    }

    /// Delete an object by id.
    pub async fn delete(&self, object_type: &str, id: &str) -> Result<bool> {
        match self {
            Self::Postgres(store) => store.delete(object_type, id).await,
            Self::Sqlite(store) => store.delete(object_type, id).await,
        }
    }

    /// Delete an object by name within an object type.
    pub async fn delete_by_name(&self, object_type: &str, name: &str) -> Result<bool> {
        match self {
            Self::Postgres(store) => store.delete_by_name(object_type, name).await,
            Self::Sqlite(store) => store.delete_by_name(object_type, name).await,
        }
    }

    /// List objects by type.
    pub async fn list(
        &self,
        object_type: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<ObjectRecord>> {
        match self {
            Self::Postgres(store) => store.list(object_type, limit, offset).await,
            Self::Sqlite(store) => store.list(object_type, limit, offset).await,
        }
    }

    // -----------------------------------------------------------------------
    // Policy revision operations
    // -----------------------------------------------------------------------

    /// Insert a new policy revision.
    pub async fn put_policy_revision(
        &self,
        id: &str,
        sandbox_id: &str,
        version: i64,
        payload: &[u8],
        hash: &str,
    ) -> Result<()> {
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

    /// Get the latest policy revision for a sandbox (by highest version, any status).
    pub async fn get_latest_policy(&self, sandbox_id: &str) -> Result<Option<PolicyRecord>> {
        match self {
            Self::Postgres(store) => store.get_latest_policy(sandbox_id).await,
            Self::Sqlite(store) => store.get_latest_policy(sandbox_id).await,
        }
    }

    /// Get the latest loaded policy revision for a sandbox.
    pub async fn get_latest_loaded_policy(&self, sandbox_id: &str) -> Result<Option<PolicyRecord>> {
        match self {
            Self::Postgres(store) => store.get_latest_loaded_policy(sandbox_id).await,
            Self::Sqlite(store) => store.get_latest_loaded_policy(sandbox_id).await,
        }
    }

    /// Get a specific policy revision by sandbox id and version.
    pub async fn get_policy_by_version(
        &self,
        sandbox_id: &str,
        version: i64,
    ) -> Result<Option<PolicyRecord>> {
        match self {
            Self::Postgres(store) => store.get_policy_by_version(sandbox_id, version).await,
            Self::Sqlite(store) => store.get_policy_by_version(sandbox_id, version).await,
        }
    }

    /// List policy revisions for a sandbox, ordered by version descending.
    pub async fn list_policies(
        &self,
        sandbox_id: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<PolicyRecord>> {
        match self {
            Self::Postgres(store) => store.list_policies(sandbox_id, limit, offset).await,
            Self::Sqlite(store) => store.list_policies(sandbox_id, limit, offset).await,
        }
    }

    /// Update the status of a policy revision.
    pub async fn update_policy_status(
        &self,
        sandbox_id: &str,
        version: i64,
        status: &str,
        load_error: Option<&str>,
        loaded_at_ms: Option<i64>,
    ) -> Result<bool> {
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

    /// Mark all pending and loaded policy revisions older than `before_version` as superseded.
    pub async fn supersede_older_policies(
        &self,
        sandbox_id: &str,
        before_version: i64,
    ) -> Result<u64> {
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

    // -----------------------------------------------------------------------
    // Generic protobuf message helpers
    // -----------------------------------------------------------------------

    /// Insert or update a protobuf message using its inferred object type, id, and name.
    pub async fn put_message<T: Message + ObjectType + ObjectId + ObjectName>(
        &self,
        message: &T,
    ) -> Result<()> {
        self.put(
            T::object_type(),
            message.object_id(),
            message.object_name(),
            &message.encode_to_vec(),
        )
        .await
    }

    /// Fetch and decode a protobuf message by id.
    pub async fn get_message<T: Message + Default + ObjectType>(
        &self,
        id: &str,
    ) -> Result<Option<T>> {
        let record = self.get(T::object_type(), id).await?;
        let Some(record) = record else {
            return Ok(None);
        };

        T::decode(record.payload.as_slice())
            .map(Some)
            .map_err(|e| Error::execution(format!("protobuf decode error: {e}")))
    }

    /// Fetch and decode a protobuf message by name.
    pub async fn get_message_by_name<T: Message + Default + ObjectType>(
        &self,
        name: &str,
    ) -> Result<Option<T>> {
        let record = self.get_by_name(T::object_type(), name).await?;
        let Some(record) = record else {
            return Ok(None);
        };

        T::decode(record.payload.as_slice())
            .map(Some)
            .map_err(|e| Error::execution(format!("protobuf decode error: {e}")))
    }

    // -----------------------------------------------------------------------
    // Draft policy chunk operations
    // -----------------------------------------------------------------------

    /// Insert a new draft policy chunk.
    pub async fn put_draft_chunk(&self, chunk: &DraftChunkRecord) -> Result<()> {
        match self {
            Self::Postgres(store) => store.put_draft_chunk(chunk).await,
            Self::Sqlite(store) => store.put_draft_chunk(chunk).await,
        }
    }

    /// Fetch a single draft chunk by id.
    pub async fn get_draft_chunk(&self, id: &str) -> Result<Option<DraftChunkRecord>> {
        match self {
            Self::Postgres(store) => store.get_draft_chunk(id).await,
            Self::Sqlite(store) => store.get_draft_chunk(id).await,
        }
    }

    /// List draft chunks for a sandbox, optionally filtered by status.
    pub async fn list_draft_chunks(
        &self,
        sandbox_id: &str,
        status_filter: Option<&str>,
    ) -> Result<Vec<DraftChunkRecord>> {
        match self {
            Self::Postgres(store) => store.list_draft_chunks(sandbox_id, status_filter).await,
            Self::Sqlite(store) => store.list_draft_chunks(sandbox_id, status_filter).await,
        }
    }

    /// Update the status of a draft chunk.
    pub async fn update_draft_chunk_status(
        &self,
        id: &str,
        status: &str,
        decided_at_ms: Option<i64>,
    ) -> Result<bool> {
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

    /// Update the proposed rule on a pending draft chunk.
    pub async fn update_draft_chunk_rule(&self, id: &str, proposed_rule: &[u8]) -> Result<bool> {
        match self {
            Self::Postgres(store) => store.update_draft_chunk_rule(id, proposed_rule).await,
            Self::Sqlite(store) => store.update_draft_chunk_rule(id, proposed_rule).await,
        }
    }

    /// Delete all draft chunks for a sandbox with a given status.
    pub async fn delete_draft_chunks(&self, sandbox_id: &str, status: &str) -> Result<u64> {
        match self {
            Self::Postgres(store) => store.delete_draft_chunks(sandbox_id, status).await,
            Self::Sqlite(store) => store.delete_draft_chunks(sandbox_id, status).await,
        }
    }

    /// Get the current maximum draft version for a sandbox.
    pub async fn get_draft_version(&self, sandbox_id: &str) -> Result<i64> {
        match self {
            Self::Postgres(store) => store.get_draft_version(sandbox_id).await,
            Self::Sqlite(store) => store.get_draft_version(sandbox_id).await,
        }
    }

    // -----------------------------------------------------------------------
    // Denial summary operations
    // -----------------------------------------------------------------------

    /// Upsert a denial summary (insert or update by sandbox+host+port+binary).
    pub async fn upsert_denial_summary(&self, summary: &DenialSummaryRecord) -> Result<()> {
        match self {
            Self::Postgres(store) => store.upsert_denial_summary(summary).await,
            Self::Sqlite(store) => store.upsert_denial_summary(summary).await,
        }
    }

    /// List denial summaries for a sandbox, optionally filtered by status.
    pub async fn list_denial_summaries(
        &self,
        sandbox_id: &str,
        status_filter: Option<&str>,
    ) -> Result<Vec<DenialSummaryRecord>> {
        match self {
            Self::Postgres(store) => store.list_denial_summaries(sandbox_id, status_filter).await,
            Self::Sqlite(store) => store.list_denial_summaries(sandbox_id, status_filter).await,
        }
    }

    /// Update denial summary status (e.g. new → analyzed → resolved).
    pub async fn update_denial_summary_status(&self, id: &str, status: &str) -> Result<bool> {
        match self {
            Self::Postgres(store) => store.update_denial_summary_status(id, status).await,
            Self::Sqlite(store) => store.update_denial_summary_status(id, status).await,
        }
    }
}

/// Stored draft policy chunk record.
#[derive(Debug, Clone)]
pub struct DraftChunkRecord {
    pub id: String,
    pub sandbox_id: String,
    pub draft_version: i64,
    pub status: String,
    pub stage: String,
    pub rule_name: String,
    pub proposed_rule: Vec<u8>,
    pub rationale: String,
    pub security_notes: String,
    pub confidence: f64,
    pub denial_refs: String,
    pub supersedes_chunk_id: String,
    pub analysis_mode: String,
    pub created_at_ms: i64,
    pub decided_at_ms: Option<i64>,
    pub decided_by: String,
    /// Denormalized endpoint host (lowercase) for DB-level dedup.
    pub host: String,
    /// Denormalized endpoint port for DB-level dedup.
    pub port: i32,
    /// How many times this endpoint has been seen across denial flush cycles.
    pub hit_count: i32,
    /// First time this endpoint was proposed (ms since epoch).
    pub first_seen_ms: i64,
    /// Most recent time this endpoint was re-proposed (ms since epoch).
    pub last_seen_ms: i64,
}

/// Stored denial summary record.
#[derive(Debug, Clone)]
pub struct DenialSummaryRecord {
    pub id: String,
    pub sandbox_id: String,
    pub host: String,
    pub port: i32,
    pub binary: String,
    pub ancestors: String,
    pub deny_reason: String,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    pub count: i32,
    pub suppressed_count: i32,
    pub total_count: i32,
    pub sample_cmdlines: String,
    pub binary_sha256: String,
    pub persistent: bool,
    pub denial_stage: String,
    pub resolved_ips: String,
    pub is_private_ip: bool,
    pub l7_request_samples: String,
    pub l7_inspection_active: bool,
    pub status: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

fn current_time_ms() -> Result<i64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| Error::execution(format!("time error: {e}")))?;
    i64::try_from(now.as_millis())
        .map_err(|e| Error::execution(format!("time conversion error: {e}")))
}

fn map_db_error(error: &sqlx::Error) -> Error {
    Error::execution(format!("database error: {error}"))
}

fn map_migrate_error(error: &sqlx::migrate::MigrateError) -> Error {
    Error::execution(format!("migration error: {error}"))
}

#[cfg(test)]
mod tests;
