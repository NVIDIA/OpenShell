// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Persistence layer for `OpenShell` Server.

mod postgres;
mod sqlite;

pub use openshell_core::proto::{
    StoredDraftChunk as DraftChunkRecord, StoredPolicyRevision as PolicyRecord,
};

use openshell_core::{Error as CoreError, Result as CoreResult};
use prost::Message;
use rand::Rng;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub use postgres::PostgresStore;
pub use sqlite::SqliteStore;

pub type PersistenceResult<T> = Result<T, PersistenceError>;

/// Persistence-layer error type.
#[derive(Debug, Error, Clone)]
pub enum PersistenceError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("database error: {0}")]
    Database(String),
    #[error("migration error: {0}")]
    Migration(String),
    #[error("decode error: {0}")]
    Decode(String),
    #[error("encode error: {0}")]
    Encode(String),
    #[error("unique violation{constraint_msg}")]
    UniqueViolation {
        constraint: Option<String>,
        detail: Option<String>,
        constraint_msg: String,
    },
}

impl PersistenceError {
    pub fn unique_violation(constraint: Option<String>, detail: Option<String>) -> Self {
        let constraint_msg = constraint
            .as_ref()
            .map(|value| format!(" on {value}"))
            .unwrap_or_default();
        Self::UniqueViolation {
            constraint,
            detail,
            constraint_msg,
        }
    }

    pub fn is_unique_violation_on(&self, constraint: &str) -> bool {
        matches!(
            self,
            Self::UniqueViolation {
                constraint: Some(value),
                ..
            } if value == constraint
        )
    }
}

/// Stored object record.
#[derive(Debug, Clone)]
pub struct ObjectRecord {
    pub object_type: String,
    pub id: String,
    pub name: String,
    pub payload: Vec<u8>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    /// JSON-serialized labels (key-value pairs).
    pub labels: Option<String>,
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

// Import object metadata accessor traits from openshell-core
// (implementations for all proto types are in openshell-core::metadata)
pub use openshell_core::{ObjectId, ObjectLabels, ObjectName};

/// Generate a random 6-character lowercase alphabetic name.
pub fn generate_name() -> String {
    let mut rng = rand::rng();
    (0..6)
        .map(|_| rng.random_range(b'a'..=b'z') as char)
        .collect()
}

impl Store {
    /// Connect to a persistence store based on the database URL.
    pub async fn connect(url: &str) -> CoreResult<Self> {
        if url.starts_with("postgres://") || url.starts_with("postgresql://") {
            let store = PostgresStore::connect(url)
                .await
                .map_err(|e| CoreError::execution(e.to_string()))?;
            store
                .migrate()
                .await
                .map_err(|e| CoreError::execution(e.to_string()))?;
            Ok(Self::Postgres(store))
        } else if url.starts_with("sqlite:") {
            let store = SqliteStore::connect(url)
                .await
                .map_err(|e| CoreError::execution(e.to_string()))?;
            store
                .migrate()
                .await
                .map_err(|e| CoreError::execution(e.to_string()))?;
            Ok(Self::Sqlite(store))
        } else {
            Err(CoreError::config(format!(
                "unsupported database URL scheme: {url}"
            )))
        }
    }

    /// Insert or update a generic named object.
    pub async fn put(
        &self,
        object_type: &str,
        id: &str,
        name: &str,
        payload: &[u8],
        labels: Option<&str>,
    ) -> PersistenceResult<()> {
        match self {
            Self::Postgres(store) => store.put(object_type, id, name, payload, labels).await,
            Self::Sqlite(store) => store.put(object_type, id, name, payload, labels).await,
        }
    }

    /// Fetch an object by id.
    pub async fn get(
        &self,
        object_type: &str,
        id: &str,
    ) -> PersistenceResult<Option<ObjectRecord>> {
        match self {
            Self::Postgres(store) => store.get(object_type, id).await,
            Self::Sqlite(store) => store.get(object_type, id).await,
        }
    }

    /// Fetch an object by name within an object type.
    pub async fn get_by_name(
        &self,
        object_type: &str,
        name: &str,
    ) -> PersistenceResult<Option<ObjectRecord>> {
        match self {
            Self::Postgres(store) => store.get_by_name(object_type, name).await,
            Self::Sqlite(store) => store.get_by_name(object_type, name).await,
        }
    }

    /// Delete an object by id.
    pub async fn delete(&self, object_type: &str, id: &str) -> PersistenceResult<bool> {
        match self {
            Self::Postgres(store) => store.delete(object_type, id).await,
            Self::Sqlite(store) => store.delete(object_type, id).await,
        }
    }

    /// Delete an object by name within an object type.
    pub async fn delete_by_name(&self, object_type: &str, name: &str) -> PersistenceResult<bool> {
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
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        match self {
            Self::Postgres(store) => store.list(object_type, limit, offset).await,
            Self::Sqlite(store) => store.list(object_type, limit, offset).await,
        }
    }

    /// List objects by type with label selector filtering.
    /// Label selector format: "key1=value1,key2=value2" (comma-separated equality matches).
    pub async fn list_with_selector(
        &self,
        object_type: &str,
        label_selector: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        match self {
            Self::Postgres(store) => {
                store
                    .list_with_selector(object_type, label_selector, limit, offset)
                    .await
            }
            Self::Sqlite(store) => {
                store
                    .list_with_selector(object_type, label_selector, limit, offset)
                    .await
            }
        }
    }

    // -----------------------------------------------------------------------
    // Generic protobuf message helpers
    // -----------------------------------------------------------------------

    /// Insert or update a protobuf message using its inferred object type, id, and name.
    pub async fn put_message<T: Message + ObjectType + ObjectId + ObjectName + ObjectLabels>(
        &self,
        message: &T,
    ) -> PersistenceResult<()> {
        // Serialize labels to JSON
        let labels_map = message.object_labels();
        let labels_json = if labels_map.as_ref().is_none_or(HashMap::is_empty) {
            None
        } else {
            Some(serde_json::to_string(&labels_map).map_err(|e| {
                PersistenceError::Encode(format!("failed to serialize labels: {e}"))
            })?)
        };

        self.put(
            T::object_type(),
            message.object_id(),
            message.object_name(),
            &message.encode_to_vec(),
            labels_json.as_deref(),
        )
        .await
    }

    /// Fetch and decode a protobuf message by id.
    pub async fn get_message<T: Message + Default + ObjectType>(
        &self,
        id: &str,
    ) -> PersistenceResult<Option<T>> {
        let record = self.get(T::object_type(), id).await?;
        let Some(record) = record else {
            return Ok(None);
        };

        T::decode(record.payload.as_slice())
            .map(Some)
            .map_err(|e| PersistenceError::Decode(format!("protobuf decode error: {e}")))
    }

    /// Fetch and decode a protobuf message by name.
    pub async fn get_message_by_name<T: Message + Default + ObjectType>(
        &self,
        name: &str,
    ) -> PersistenceResult<Option<T>> {
        let record = self.get_by_name(T::object_type(), name).await?;
        let Some(record) = record else {
            return Ok(None);
        };

        T::decode(record.payload.as_slice())
            .map(Some)
            .map_err(|e| PersistenceError::Decode(format!("protobuf decode error: {e}")))
    }
}

pub fn current_time_ms() -> PersistenceResult<i64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| PersistenceError::Database(format!("time error: {e}")))?;
    i64::try_from(now.as_millis())
        .map_err(|e| PersistenceError::Database(format!("time conversion error: {e}")))
}

fn map_db_error(error: &sqlx::Error) -> PersistenceError {
    if let sqlx::Error::Database(db) = error
        && db.is_unique_violation()
    {
        let constraint = db
            .constraint()
            .map(ToString::to_string)
            .or_else(|| infer_sqlite_unique_constraint(db.message()));
        return PersistenceError::unique_violation(constraint, Some(db.message().to_string()));
    }
    PersistenceError::Database(error.to_string())
}

fn infer_sqlite_unique_constraint(message: &str) -> Option<String> {
    if message.contains("objects.object_type, objects.scope, objects.version") {
        Some("objects_version_uq".to_string())
    } else if message.contains("objects.object_type, objects.scope, objects.dedup_key") {
        Some("objects_dedup_uq".to_string())
    } else if message.contains("objects.object_type, objects.name") {
        Some("objects_name_uq".to_string())
    } else if message.contains("objects.id") {
        Some("objects_pkey".to_string())
    } else {
        None
    }
}

fn map_migrate_error(error: &sqlx::migrate::MigrateError) -> PersistenceError {
    PersistenceError::Migration(error.to_string())
}

/// Parse a simple label selector string into key-value pairs.
/// Format: "key1=value1,key2=value2"
/// Returns a `HashMap` of label requirements.
///
/// Note: Input validation should be performed at the gRPC layer using
/// `grpc::validation::validate_label_selector()` before calling this function.
/// Errors returned here indicate unexpected internal errors, not user input errors.
pub fn parse_label_selector(selector: &str) -> PersistenceResult<HashMap<String, String>> {
    if selector.is_empty() {
        return Ok(HashMap::new());
    }

    let mut labels = HashMap::new();
    for pair in selector.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }

        let parts: Vec<&str> = pair.splitn(2, '=').collect();
        if parts.len() != 2 {
            return Err(PersistenceError::Decode(format!(
                "invalid label selector: expected 'key=value', got '{pair}'"
            )));
        }

        let key = parts[0].trim();
        let value = parts[1].trim();

        if key.is_empty() {
            return Err(PersistenceError::Decode(format!(
                "invalid label selector: key cannot be empty in '{pair}'"
            )));
        }

        labels.insert(key.to_string(), value.to_string());
    }

    Ok(labels)
}

#[cfg(test)]
mod tests;
