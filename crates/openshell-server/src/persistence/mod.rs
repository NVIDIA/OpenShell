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
use thiserror::Error;

pub use postgres::PostgresStore;
pub use sqlite::SqliteStore;

/// Object type string for sandbox policy records.
pub const POLICY_OBJECT_TYPE: &str = "sandbox_policy";
/// Object type string for draft policy chunk records.
pub const DRAFT_CHUNK_OBJECT_TYPE: &str = "draft_policy_chunk";

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
    #[error("resource version conflict: expected version does not match current")]
    Conflict {
        current_resource_version: Option<u64>,
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
    /// Optimistic concurrency control version.
    /// Incremented on each update for compare-and-swap operations.
    pub resource_version: u64,
}

/// Write condition for compare-and-swap operations.
#[derive(Debug, Clone, Copy)]
pub enum WriteCondition {
    /// Object must not exist (insert only).
    MustCreate,
    /// Object must exist with the specified resource version (update only).
    MatchResourceVersion(u64),
    /// Unconditional write (insert or update).
    Unconditional,
}

/// Result of a successful write operation.
#[derive(Debug, Clone)]
pub struct WriteResult {
    pub resource_version: u64,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
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
pub use openshell_core::{
    GetResourceVersion, ObjectId, ObjectLabels, ObjectName, SetResourceVersion,
};

/// Generate a random 6-character lowercase alphabetic name.
pub fn generate_name() -> String {
    let mut rng = rand::rng();
    (0..6)
        .map(|_| rng.random_range(b'a'..=b'z') as char)
        .collect()
}

/// Decode a single [`ObjectRecord`] into a protobuf message, hydrating
/// `resource_version` from the authoritative DB row.
///
/// Extracted to avoid repeating the identical decode-and-hydrate block across
/// `get_message`, `get_message_by_name`, `list_messages`, and
/// `list_messages_with_selector`.
fn decode_record<T: Message + Default + SetResourceVersion>(
    record: ObjectRecord,
) -> PersistenceResult<T> {
    let mut message = T::decode(record.payload.as_slice())
        .map_err(|e| PersistenceError::Decode(format!("protobuf decode error: {e}")))?;
    message.set_resource_version(record.resource_version);
    Ok(message)
}

/// Dispatch a method call to the underlying store implementation.
///
/// Every `Store` method is a two-arm `match self { Postgres(s) => s.method(...).await, … }`
/// with no logic of its own. This macro captures the common pattern so that
/// each method body is a single line.
macro_rules! store_dispatch {
    ($self:ident . $method:ident ( $($arg:expr),* )) => {
        match $self {
            Self::Postgres(s) => s.$method($($arg),*).await,
            Self::Sqlite(s) => s.$method($($arg),*).await,
        }
    };
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

    /// Verify connectivity to the underlying database.
    pub async fn ping(&self) -> PersistenceResult<()> {
        store_dispatch!(self.ping())
    }

    /// Test support only: close the underlying connection pool.
    ///
    /// There is no runtime shutdown path yet. If we add graceful shutdown,
    /// this API can be made public for that explicit shutdown flow.
    ///
    /// Do not call from runtime code today; this tears down the active pool.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn close(&self) {
        store_dispatch!(self.close());
    }

    /// Insert or update a generic object with compare-and-swap support.
    ///
    /// # Arguments
    /// * `object_type` - Type discriminator for the object
    /// * `id` - Stable object identifier
    /// * `name` - Human-readable object name
    /// * `payload` - Serialized object data
    /// * `labels` - Optional JSON-serialized labels
    /// * `condition` - Write precondition (`MustCreate`, `MatchResourceVersion`, or `Unconditional`)
    ///
    /// # Returns
    /// * `Ok(WriteResult)` - Write succeeded with new `resource_version` and timestamps
    /// * `Err(Conflict)` - Resource version mismatch (for `MatchResourceVersion`)
    /// * `Err(UniqueViolation)` - Object already exists (for `MustCreate`) or name conflict
    pub async fn put_if(
        &self,
        object_type: &str,
        id: &str,
        name: &str,
        payload: &[u8],
        labels: Option<&str>,
        condition: WriteCondition,
    ) -> PersistenceResult<WriteResult> {
        store_dispatch!(self.put_if(object_type, id, name, payload, labels, condition))
    }

    /// Delete an object by id with compare-and-swap support.
    ///
    /// # Arguments
    /// * `object_type` - Type discriminator for the object
    /// * `id` - Stable object identifier
    /// * `expected_resource_version` - Required resource version for the delete to proceed
    ///
    /// # Returns
    /// * `Ok(true)` - Object was deleted
    /// * `Ok(false)` - Object not found
    /// * `Err(Conflict)` - Resource version mismatch
    pub async fn delete_if(
        &self,
        object_type: &str,
        id: &str,
        expected_resource_version: u64,
    ) -> PersistenceResult<bool> {
        store_dispatch!(self.delete_if(object_type, id, expected_resource_version))
    }

    /// Insert or update a generic named object with an application-owned scope.
    pub async fn put_scoped(
        &self,
        object_type: &str,
        id: &str,
        name: &str,
        scope: &str,
        payload: &[u8],
        labels: Option<&str>,
    ) -> PersistenceResult<()> {
        store_dispatch!(self.put_scoped(object_type, id, name, scope, payload, labels))
    }

    /// Fetch an object by id.
    pub async fn get(
        &self,
        object_type: &str,
        id: &str,
    ) -> PersistenceResult<Option<ObjectRecord>> {
        store_dispatch!(self.get(object_type, id))
    }

    /// Fetch an object by name within an object type.
    pub async fn get_by_name(
        &self,
        object_type: &str,
        name: &str,
    ) -> PersistenceResult<Option<ObjectRecord>> {
        store_dispatch!(self.get_by_name(object_type, name))
    }

    /// Delete an object by id.
    pub async fn delete(&self, object_type: &str, id: &str) -> PersistenceResult<bool> {
        store_dispatch!(self.delete(object_type, id))
    }

    /// Delete an object by name within an object type.
    pub async fn delete_by_name(&self, object_type: &str, name: &str) -> PersistenceResult<bool> {
        store_dispatch!(self.delete_by_name(object_type, name))
    }

    /// List objects by type.
    pub async fn list(
        &self,
        object_type: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        store_dispatch!(self.list(object_type, limit, offset))
    }

    /// List objects by type and application-owned scope.
    pub async fn list_by_scope(
        &self,
        object_type: &str,
        scope: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        store_dispatch!(self.list_by_scope(object_type, scope, limit, offset))
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
        store_dispatch!(self.list_with_selector(object_type, label_selector, limit, offset))
    }

    // -----------------------------------------------------------------------
    // Generic protobuf message helpers
    // -----------------------------------------------------------------------

    /// Insert or update a protobuf message under an application-owned scope.
    pub async fn put_scoped_message<
        T: Message + ObjectType + ObjectId + ObjectName + ObjectLabels,
    >(
        &self,
        message: &T,
        scope: &str,
    ) -> PersistenceResult<()> {
        let labels_map = message.object_labels();
        let labels_json = if labels_map.as_ref().is_none_or(HashMap::is_empty) {
            None
        } else {
            Some(serde_json::to_string(&labels_map).map_err(|e| {
                PersistenceError::Encode(format!("failed to serialize labels: {e}"))
            })?)
        };

        self.put_scoped(
            T::object_type(),
            message.object_id(),
            message.object_name(),
            scope,
            &message.encode_to_vec(),
            labels_json.as_deref(),
        )
        .await
    }

    /// Fetch and decode a protobuf message by id.
    pub async fn get_message<T: Message + Default + ObjectType + SetResourceVersion>(
        &self,
        id: &str,
    ) -> PersistenceResult<Option<T>> {
        self.get(T::object_type(), id)
            .await?
            .map(decode_record)
            .transpose()
    }

    /// Fetch and decode a protobuf message by name.
    pub async fn get_message_by_name<T: Message + Default + ObjectType + SetResourceVersion>(
        &self,
        name: &str,
    ) -> PersistenceResult<Option<T>> {
        self.get_by_name(T::object_type(), name)
            .await?
            .map(decode_record)
            .transpose()
    }

    /// List and decode protobuf messages, hydrating `resource_version` from
    /// the authoritative DB row (mirrors `get_message`).
    pub async fn list_messages<T: Message + Default + ObjectType + SetResourceVersion>(
        &self,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<T>> {
        self.list(T::object_type(), limit, offset)
            .await?
            .into_iter()
            .map(decode_record)
            .collect()
    }

    /// List and decode protobuf messages with label selector filtering,
    /// hydrating `resource_version` from the authoritative DB row.
    pub async fn list_messages_with_selector<
        T: Message + Default + ObjectType + SetResourceVersion,
    >(
        &self,
        label_selector: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<T>> {
        self.list_with_selector(T::object_type(), label_selector, limit, offset)
            .await?
            .into_iter()
            .map(decode_record)
            .collect()
    }

    /// Update a protobuf message using CAS (compare-and-swap).
    ///
    /// Fetches the current object, validates the expected version, applies the
    /// mutation function, and attempts a single CAS write. Returns Conflict on
    /// version mismatch for caller-driven retry.
    ///
    /// # Arguments
    /// * `id` - Object ID to update
    /// * `expected_version` - Required resource version for the update to proceed.
    ///   Pass 0 to use the current version (internal operations only).
    ///   For client-facing operations, pass the client-provided expected version.
    /// * `mutate` - Function that modifies the object in place
    ///
    /// # Returns
    /// * `Ok(T)` - Successfully updated object with new `resource_version`
    /// * `Err(Conflict)` - Version mismatch; caller should retry
    /// * `Err(Database)` - Object not found or other DB error
    pub async fn update_message_cas<T, F>(
        &self,
        id: &str,
        expected_version: u64,
        mut mutate: F,
    ) -> PersistenceResult<T>
    where
        T: Message
            + Default
            + ObjectType
            + ObjectId
            + ObjectName
            + ObjectLabels
            + SetResourceVersion
            + GetResourceVersion
            + Clone,
        F: FnMut(&mut T),
    {
        // Fetch current object with authoritative resource_version
        let current = self
            .get_message::<T>(id)
            .await?
            .ok_or_else(|| PersistenceError::Database(format!("object {id} not found")))?;

        let current_version = current.get_resource_version();

        // Determine the version to use for CAS:
        // - If expected_version is 0, use current version (internal operations)
        // - Otherwise, validate that expected matches current (client-facing operations)
        let cas_version = if expected_version == 0 {
            current_version
        } else {
            if expected_version != current_version {
                return Err(PersistenceError::Conflict {
                    current_resource_version: Some(current_version),
                });
            }
            expected_version
        };

        // Apply mutation
        let mut updated = current.clone();
        mutate(&mut updated);

        // Serialize labels
        let labels_map = updated.object_labels();
        let labels_json = if labels_map.as_ref().is_none_or(HashMap::is_empty) {
            None
        } else {
            Some(serde_json::to_string(&labels_map).map_err(|e| {
                PersistenceError::Encode(format!("failed to serialize labels: {e}"))
            })?)
        };

        // Single-attempt CAS write - fails with Conflict on version mismatch
        let result = self
            .put_if(
                T::object_type(),
                updated.object_id(),
                updated.object_name(),
                &updated.encode_to_vec(),
                labels_json.as_deref(),
                WriteCondition::MatchResourceVersion(cas_version),
            )
            .await?;

        // Success - hydrate the new resource_version and return
        updated.set_resource_version(result.resource_version);
        Ok(updated)
    }
}

pub fn current_time_ms() -> i64 {
    openshell_core::time::now_ms()
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

/// Unconditional write helpers — test-only.
///
/// Production code must use [`Store::put_if`] (with [`WriteCondition`]) or
/// [`Store::update_message_cas`] to ensure every write is CAS-protected.
#[cfg(test)]
impl Store {
    pub async fn put(
        &self,
        object_type: &str,
        id: &str,
        name: &str,
        payload: &[u8],
        labels: Option<&str>,
    ) -> PersistenceResult<()> {
        store_dispatch!(self.put(object_type, id, name, payload, labels))
    }

    pub async fn put_message<T: Message + ObjectType + ObjectId + ObjectName + ObjectLabels>(
        &self,
        message: &T,
    ) -> PersistenceResult<()> {
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
}

#[cfg(test)]
pub async fn test_store() -> Store {
    Store::connect("sqlite::memory:?cache=shared")
        .await
        .expect("in-memory SQLite store should connect")
}

#[cfg(test)]
mod tests;
