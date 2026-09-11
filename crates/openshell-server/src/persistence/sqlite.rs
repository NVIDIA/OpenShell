// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{
    AtomicSandboxProjection, DraftChunkRecord, ObjectCursor, ObjectListQuery, ObjectRecord,
    PersistenceError, PersistenceResult, PolicyRecord, WriteCondition, WriteResult,
    current_time_ms, map_db_error, map_migrate_error,
};
use crate::policy_store::{
    AtomicPolicyRevisionWrite, draft_chunk_payload_from_record, draft_chunk_record_from_parts,
    policy_payload_from_record, policy_record_for_atomic_write, policy_record_from_parts,
    project_policy_revision_onto_sandbox,
};
use openshell_core::SetResourceVersion;
use openshell_core::paths::set_file_owner_only;
use openshell_core::proto::Sandbox;
use prost::Message;
use sqlx::sqlite::{SqliteConnectOptions, SqliteConnection, SqlitePoolOptions};
use sqlx::{Connection, QueryBuilder, Row, Sqlite, SqlitePool};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Mutex;

static SQLITE_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/sqlite");

#[cfg(test)]
pub(super) fn embedded_migration_sql(version: i64) -> Option<&'static str> {
    SQLITE_MIGRATOR
        .iter()
        .find(|migration| migration.version == version)
        .map(|migration| migration.sql.as_ref())
}
static IN_MEMORY_DB_SEQUENCE: AtomicU64 = AtomicU64::new(0);

use super::{DELETE_MANY_BATCH_SIZE, DRAFT_CHUNK_OBJECT_TYPE, POLICY_OBJECT_TYPE};

async fn insert_update_operation_sqlite(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    record: &crate::storage_proto::StoredConfigUpdateOperation,
    now_ms: i64,
) -> PersistenceResult<()> {
    let metadata = record
        .metadata
        .as_ref()
        .ok_or_else(|| PersistenceError::Encode("update operation metadata missing".to_string()))?;
    let operation = record
        .operation
        .as_ref()
        .ok_or_else(|| PersistenceError::Encode("update operation payload missing".to_string()))?;
    let state = openshell_core::proto::ConfigUpdateOperationState::try_from(operation.state)
        .unwrap_or_default();
    sqlx::query(
        r#"
INSERT INTO "objects" (
    "object_type", "id", "name", "workspace", "scope", "version", "status", "payload",
    "created_at_ms", "updated_at_ms", "labels", "resource_version", "next_attempt_at_ms"
)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9, '{}', 1, ?10)
"#,
    )
    .bind(crate::config_update_operation::CONFIG_UPDATE_OPERATION_OBJECT_TYPE)
    .bind(&metadata.id)
    .bind(&metadata.name)
    .bind(&metadata.workspace)
    .bind(&operation.sandbox_id)
    .bind(Option::<i64>::None)
    .bind(state.as_str_name())
    .bind(record.encode_to_vec())
    .bind(now_ms)
    .bind(record.next_attempt_at_ms)
    .execute(&mut **tx)
    .await
    .map_err(|error| map_db_error(&error))?;
    Ok(())
}

async fn lock_sandbox_config_fence(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    sandbox_id: &str,
) -> PersistenceResult<()> {
    sqlx::query(
        r#"INSERT INTO "sandbox_config_fences" ("sandbox_id") VALUES (?1) ON CONFLICT DO NOTHING"#,
    )
    .bind(sandbox_id)
    .execute(&mut **tx)
    .await
    .map_err(|error| map_db_error(&error))?;
    Ok(())
}

async fn operation_with_current_policy_target(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    record: &crate::storage_proto::StoredConfigUpdateOperation,
) -> PersistenceResult<crate::storage_proto::StoredConfigUpdateOperation> {
    let sandbox_id = record
        .operation
        .as_ref()
        .ok_or_else(|| PersistenceError::Encode("update operation payload missing".to_string()))?
        .sandbox_id
        .as_str();
    let version: Option<i64> = sqlx::query_scalar(
        r#"SELECT "version" FROM "objects" WHERE "object_type" = ?1 AND "scope" = ?2 ORDER BY "version" DESC LIMIT 1"#,
    )
    .bind(POLICY_OBJECT_TYPE)
    .bind(sandbox_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| map_db_error(&error))?;
    let mut record = record.clone();
    record.target_policy_version =
        version.map_or(0, |value| u32::try_from(value).unwrap_or(u32::MAX));
    Ok(record)
}

async fn operation_with_current_settings_target(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    record: &crate::storage_proto::StoredConfigUpdateOperation,
    workspace: &str,
    sandbox_name: &str,
) -> PersistenceResult<crate::storage_proto::StoredConfigUpdateOperation> {
    let payload: Option<Vec<u8>> = sqlx::query_scalar(
        r#"SELECT "payload" FROM "objects" WHERE "object_type" = ?1 AND "workspace" = ?2 AND "name" = ?3"#,
    )
    .bind(crate::grpc::policy::SANDBOX_SETTINGS_OBJECT_TYPE)
    .bind(workspace)
    .bind(sandbox_name)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| map_db_error(&error))?;
    let revision = payload
        .as_deref()
        .map(serde_json::from_slice::<serde_json::Value>)
        .transpose()
        .map_err(|error| {
            PersistenceError::Decode(format!("decode settings payload failed: {error}"))
        })?
        .and_then(|value| value.get("revision").and_then(serde_json::Value::as_u64))
        .unwrap_or(0);
    let mut record = record.clone();
    record.target_settings_revision = revision;
    Ok(record)
}

#[derive(Debug, Clone)]
pub struct SqliteStore {
    pool: SqlitePool,
    #[cfg_attr(not(any(test, feature = "test-support")), allow(dead_code))]
    in_memory_keepalive: Option<Arc<Mutex<Option<SqliteConnection>>>>,
}

fn push_label_selector(
    sql: &mut QueryBuilder<Sqlite>,
    label_selector: &str,
) -> PersistenceResult<()> {
    let mut labels: Vec<_> = super::parse_label_selector(label_selector)?
        .into_iter()
        .collect();
    labels.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    for (key, value) in labels {
        let escaped_key = key
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\'', "''");
        sql.push(format!(
            " AND json_extract(o.labels, '$.\"{escaped_key}\"') = "
        ))
        .push_bind(value);
    }
    Ok(())
}

#[cfg(test)]
pub(super) async fn replace_pool_connection(store: &SqliteStore) -> PersistenceResult<()> {
    let connection = store.pool.acquire().await.map_err(|e| map_db_error(&e))?;
    connection.close().await.map_err(|e| map_db_error(&e))
}

impl SqliteStore {
    /// Closes the connection pool.
    #[cfg(test)]
    pub(crate) async fn close_for_test(&self) {
        self.close().await;
    }

    pub fn max_connections(&self) -> u32 {
        self.pool.options().get_max_connections()
    }

    pub async fn connect(url: &str) -> PersistenceResult<Self> {
        let is_in_memory = url.contains(":memory:") || url.contains("mode=memory");
        let max_connections = if is_in_memory { 1 } else { 5 };

        let mut options = SqliteConnectOptions::from_str(url)
            .map_err(|e| map_db_error(&e))?
            .create_if_missing(true);

        if is_in_memory {
            if options.get_filename().as_os_str().is_empty()
                || options.get_filename() == Path::new(":memory:")
            {
                let sequence = IN_MEMORY_DB_SEQUENCE.fetch_add(1, Ordering::Relaxed);
                options = options.filename(format!("file:openshell-in-memory-{sequence}"));
            }
            options = options.shared_cache(true);
        }

        let mut pool_options = SqlitePoolOptions::new()
            .max_connections(max_connections)
            .min_connections(max_connections);

        if is_in_memory {
            pool_options = pool_options.idle_timeout(None).max_lifetime(None);
        }

        // Capture the on-disk path before `connect_with` consumes the options
        // so we can restrict the permissions after the database is connected.
        let db_path = (!is_in_memory).then(|| options.get_filename().to_path_buf());

        let in_memory_keepalive = if is_in_memory {
            let connection = SqliteConnection::connect_with(&options)
                .await
                .map_err(|e| map_db_error(&e))?;
            Some(Arc::new(Mutex::new(Some(connection))))
        } else {
            None
        };

        let pool = pool_options
            .connect_with(options)
            .await
            .map_err(|e| map_db_error(&e))?;

        // Tighten the permissions of the database file to owner-only access (0o600).
        if let Some(path) = db_path {
            restrict_db_file_permissions(&path)?;
        }

        Ok(Self {
            pool,
            in_memory_keepalive,
        })
    }

    pub async fn migrate(&self) -> PersistenceResult<()> {
        SQLITE_MIGRATOR
            .run(&self.pool)
            .await
            .map_err(|e| map_migrate_error(&e))
    }

    /// Verify the database is reachable by acquiring a pooled connection
    /// and issuing a ping.
    pub async fn ping(&self) -> PersistenceResult<()> {
        let mut conn = self.pool.acquire().await.map_err(|e| map_db_error(&e))?;
        conn.ping().await.map_err(|e| map_db_error(&e))
    }

    /// Test support only: close the underlying connection pool.
    ///
    /// Do not call from runtime code; this tears down the active pool.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn close(&self) {
        self.pool.close().await;
        if let Some(keepalive) = &self.in_memory_keepalive {
            let connection = keepalive.lock().await.take();
            if let Some(connection) = connection {
                let _ = connection.close().await;
            }
        }
    }

    pub async fn put(
        &self,
        object_type: &str,
        id: &str,
        name: &str,
        workspace: &str,
        payload: &[u8],
        labels: Option<&str>,
    ) -> PersistenceResult<()> {
        let now_ms = current_time_ms();

        sqlx::query(
            r#"
INSERT INTO "objects" ("object_type", "id", "name", "workspace", "payload", "created_at_ms", "updated_at_ms", "labels")
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7)
ON CONFLICT ("object_type", "workspace", "name") WHERE "name" IS NOT NULL DO UPDATE SET
    "payload" = excluded."payload",
    "updated_at_ms" = excluded."updated_at_ms",
    "labels" = excluded."labels"
"#,
        )
        .bind(object_type)
        .bind(id)
        .bind(name)
        .bind(workspace)
        .bind(payload)
        .bind(now_ms)
        .bind(labels.unwrap_or("{}"))
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn put_if(
        &self,
        object_type: &str,
        id: &str,
        name: &str,
        workspace: &str,
        payload: &[u8],
        labels: Option<&str>,
        condition: WriteCondition,
    ) -> PersistenceResult<WriteResult> {
        let now_ms = current_time_ms();

        match condition {
            WriteCondition::MustCreate => {
                // Insert only - fail if object exists
                sqlx::query(
                    r#"
INSERT INTO "objects" ("object_type", "id", "name", "workspace", "payload", "created_at_ms", "updated_at_ms", "labels", "resource_version")
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7, 1)
"#,
                )
                .bind(object_type)
                .bind(id)
                .bind(name)
                .bind(workspace)
                .bind(payload)
                .bind(now_ms)
                .bind(labels.unwrap_or("{}"))
                .execute(&self.pool)
                .await
                .map_err(|e| map_db_error(&e))?;

                Ok(WriteResult {
                    resource_version: 1,
                    created_at_ms: now_ms,
                    updated_at_ms: now_ms,
                })
            }
            WriteCondition::MatchResourceVersion(expected_version) => {
                // Update with version check
                let result = sqlx::query(
                    r#"
UPDATE "objects"
SET "payload" = ?4, "labels" = ?5, "updated_at_ms" = ?6, "resource_version" = "resource_version" + 1
WHERE "object_type" = ?1 AND "id" = ?2 AND "resource_version" = ?3
"#,
                )
                .bind(object_type)
                .bind(id)
                .bind(i64::try_from(expected_version).unwrap_or(i64::MAX))
                .bind(payload)
                .bind(labels.unwrap_or("{}"))
                .bind(now_ms)
                .execute(&self.pool)
                .await
                .map_err(|e| map_db_error(&e))?;

                if result.rows_affected() == 0 {
                    // The version-matched UPDATE matched no row. Distinguish a
                    // version mismatch (row present, different version) from an
                    // absent row (deleted / never existed). Both are CAS
                    // precondition failures, so report them as typed `Conflict`
                    // rather than a backend-dependent error string: absent rows
                    // carry `current_resource_version: None`.
                    let existing = self.get(object_type, id).await?;
                    return Err(PersistenceError::Conflict {
                        current_resource_version: existing.map(|record| record.resource_version),
                    });
                }

                // Fetch the updated record to get the new resource_version
                let updated = self.get(object_type, id).await?.ok_or_else(|| {
                    PersistenceError::Database("object disappeared after update".to_string())
                })?;

                Ok(WriteResult {
                    resource_version: updated.resource_version,
                    created_at_ms: updated.created_at_ms,
                    updated_at_ms: updated.updated_at_ms,
                })
            }
            WriteCondition::Unconditional => {
                // Unconditional upsert by name
                sqlx::query(
                    r#"
INSERT INTO "objects" ("object_type", "id", "name", "workspace", "payload", "created_at_ms", "updated_at_ms", "labels", "resource_version")
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7, 1)
ON CONFLICT ("object_type", "workspace", "name") WHERE "name" IS NOT NULL DO UPDATE SET
    "payload" = excluded."payload",
    "updated_at_ms" = excluded."updated_at_ms",
    "labels" = excluded."labels",
    "resource_version" = "objects"."resource_version" + 1
"#,
                )
                .bind(object_type)
                .bind(id)
                .bind(name)
                .bind(workspace)
                .bind(payload)
                .bind(now_ms)
                .bind(labels.unwrap_or("{}"))
                .execute(&self.pool)
                .await
                .map_err(|e| map_db_error(&e))?;

                // Fetch the result to get the resource_version
                let record = self
                    .get_by_name(object_type, workspace, name)
                    .await?
                    .ok_or_else(|| {
                        PersistenceError::Database("object disappeared after upsert".to_string())
                    })?;

                Ok(WriteResult {
                    resource_version: record.resource_version,
                    created_at_ms: record.created_at_ms,
                    updated_at_ms: record.updated_at_ms,
                })
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn put_if_with_operation(
        &self,
        object_type: &str,
        id: &str,
        name: &str,
        workspace: &str,
        payload: &[u8],
        condition: WriteCondition,
        operation_record: &crate::storage_proto::StoredConfigUpdateOperation,
        sandbox_projection: Option<&AtomicSandboxProjection<'_>>,
    ) -> PersistenceResult<WriteResult> {
        let now_ms = current_time_ms();
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|error| map_db_error(&error))?;
        let sandbox_id = operation_record
            .operation
            .as_ref()
            .ok_or_else(|| {
                PersistenceError::Encode("update operation payload missing".to_string())
            })?
            .sandbox_id
            .clone();
        lock_sandbox_config_fence(&mut tx, &sandbox_id).await?;
        let operation_record =
            operation_with_current_policy_target(&mut tx, operation_record).await?;
        let resource_version = match condition {
            WriteCondition::MustCreate => {
                sqlx::query(
                    r#"
INSERT INTO "objects" ("object_type", "id", "name", "workspace", "payload", "created_at_ms", "updated_at_ms", "labels", "resource_version")
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, '{}', 1)
"#,
                )
                .bind(object_type)
                .bind(id)
                .bind(name)
                .bind(workspace)
                .bind(payload)
                .bind(now_ms)
                .execute(&mut *tx)
                .await
                .map_err(|error| map_db_error(&error))?;
                1
            }
            WriteCondition::MatchResourceVersion(expected) => {
                let result = sqlx::query(
                    r#"
UPDATE "objects"
SET "payload" = ?4, "updated_at_ms" = ?5, "resource_version" = "resource_version" + 1
WHERE "object_type" = ?1 AND "id" = ?2 AND "resource_version" = ?3
"#,
                )
                .bind(object_type)
                .bind(id)
                .bind(i64::try_from(expected).unwrap_or(i64::MAX))
                .bind(payload)
                .bind(now_ms)
                .execute(&mut *tx)
                .await
                .map_err(|error| map_db_error(&error))?;
                if result.rows_affected() != 1 {
                    return Err(PersistenceError::Conflict {
                        current_resource_version: None,
                    });
                }
                expected.saturating_add(1)
            }
            WriteCondition::Unconditional => {
                return Err(PersistenceError::Config(
                    "atomic settings operation requires a CAS condition".to_string(),
                ));
            }
        };
        if let Some(projection) = sandbox_projection {
            let result = sqlx::query(
                r#"
UPDATE "objects"
SET "payload" = ?2, "updated_at_ms" = ?3, "resource_version" = "resource_version" + 1
WHERE "object_type" = 'sandbox' AND "id" = ?1 AND "resource_version" = ?4
"#,
            )
            .bind(projection.sandbox_id)
            .bind(projection.payload)
            .bind(now_ms)
            .bind(i64::try_from(projection.expected_resource_version).unwrap_or(i64::MAX))
            .execute(&mut *tx)
            .await
            .map_err(|error| map_db_error(&error))?;
            if result.rows_affected() != 1 {
                return Err(PersistenceError::Conflict {
                    current_resource_version: None,
                });
            }
        }
        insert_update_operation_sqlite(&mut tx, &operation_record, now_ms).await?;
        tx.commit().await.map_err(|error| map_db_error(&error))?;
        Ok(WriteResult {
            resource_version,
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
        })
    }

    pub async fn update_config_operation_cas(
        &self,
        record: &crate::storage_proto::StoredConfigUpdateOperation,
        expected_resource_version: u64,
    ) -> PersistenceResult<Option<u64>> {
        let metadata = record.metadata.as_ref().ok_or_else(|| {
            PersistenceError::Encode("update operation metadata missing".to_string())
        })?;
        let operation = record.operation.as_ref().ok_or_else(|| {
            PersistenceError::Encode("update operation payload missing".to_string())
        })?;
        let state = openshell_core::proto::ConfigUpdateOperationState::try_from(operation.state)
            .unwrap_or_default();
        let result = sqlx::query(
            r#"
UPDATE "objects"
SET "payload" = ?4, "status" = ?5, "next_attempt_at_ms" = ?6,
    "updated_at_ms" = ?7, "resource_version" = "resource_version" + 1
WHERE "object_type" = ?1 AND "id" = ?2 AND "resource_version" = ?3
"#,
        )
        .bind(crate::config_update_operation::CONFIG_UPDATE_OPERATION_OBJECT_TYPE)
        .bind(&metadata.id)
        .bind(i64::try_from(expected_resource_version).unwrap_or(i64::MAX))
        .bind(record.encode_to_vec())
        .bind(state.as_str_name())
        .bind(record.next_attempt_at_ms)
        .bind(current_time_ms())
        .execute(&self.pool)
        .await
        .map_err(|error| map_db_error(&error))?;
        Ok((result.rows_affected() == 1).then(|| expected_resource_version.saturating_add(1)))
    }

    pub async fn list_pending_config_operations_for_scope(
        &self,
        scope: &str,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        let rows = sqlx::query(
            r#"
SELECT "object_type", "id", "name", "workspace", "payload", "created_at_ms", "updated_at_ms",
       "labels", "resource_version"
FROM "objects"
WHERE "object_type" = ?1 AND "status" = ?2 AND "scope" = ?3
ORDER BY "created_at_ms" ASC, "id" ASC
"#,
        )
        .bind(crate::config_update_operation::CONFIG_UPDATE_OPERATION_OBJECT_TYPE)
        .bind(openshell_core::proto::ConfigUpdateOperationState::Pending.as_str_name())
        .bind(scope)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| map_db_error(&error))?;
        Ok(rows.into_iter().map(row_to_object_record).collect())
    }

    pub async fn list_due_config_update_operations(
        &self,
        now_ms: i64,
        limit: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        let rows = sqlx::query(
            r#"
SELECT "object_type", "id", "name", "workspace", "payload", "created_at_ms", "updated_at_ms",
       "labels", "resource_version"
FROM "objects"
WHERE "object_type" = ?1 AND "status" = ?2 AND "next_attempt_at_ms" <= ?3
ORDER BY "next_attempt_at_ms" ASC, "id" ASC
LIMIT ?4
"#,
        )
        .bind(crate::config_update_operation::CONFIG_UPDATE_OPERATION_OBJECT_TYPE)
        .bind(openshell_core::proto::ConfigUpdateOperationState::Pending.as_str_name())
        .bind(now_ms)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(|error| map_db_error(&error))?;
        Ok(rows.into_iter().map(row_to_object_record).collect())
    }

    pub async fn count_pending_config_update_operations(&self) -> PersistenceResult<u64> {
        let count: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM "objects" WHERE "object_type" = ?1 AND "status" = ?2"#,
        )
        .bind(crate::config_update_operation::CONFIG_UPDATE_OPERATION_OBJECT_TYPE)
        .bind(openshell_core::proto::ConfigUpdateOperationState::Pending.as_str_name())
        .fetch_one(&self.pool)
        .await
        .map_err(|error| map_db_error(&error))?;
        Ok(count.max(0).cast_unsigned())
    }

    pub async fn delete_if(
        &self,
        object_type: &str,
        id: &str,
        expected_resource_version: u64,
    ) -> PersistenceResult<bool> {
        let result = sqlx::query(
            r#"
DELETE FROM "objects"
WHERE "object_type" = ?1 AND "id" = ?2 AND "resource_version" = ?3
"#,
        )
        .bind(object_type)
        .bind(id)
        .bind(i64::try_from(expected_resource_version).unwrap_or(i64::MAX))
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        if result.rows_affected() > 0 {
            Ok(true)
        } else {
            // Check if object exists to distinguish NotFound from Conflict
            let existing = self.get(object_type, id).await?;
            if let Some(record) = existing {
                return Err(PersistenceError::Conflict {
                    current_resource_version: Some(record.resource_version),
                });
            }
            Ok(false)
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn put_scoped(
        &self,
        object_type: &str,
        id: &str,
        name: &str,
        workspace: &str,
        scope: &str,
        payload: &[u8],
        labels: Option<&str>,
    ) -> PersistenceResult<()> {
        let now_ms = current_time_ms();

        sqlx::query(
            r#"
INSERT INTO "objects" ("object_type", "id", "name", "workspace", "scope", "payload", "created_at_ms", "updated_at_ms", "labels", "resource_version")
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?8, 1)
ON CONFLICT ("object_type", "workspace", "name") WHERE "name" IS NOT NULL DO UPDATE SET
    "scope" = excluded."scope",
    "payload" = excluded."payload",
    "updated_at_ms" = excluded."updated_at_ms",
    "labels" = excluded."labels",
    "resource_version" = "objects"."resource_version" + 1
"#,
        )
        .bind(object_type)
        .bind(id)
        .bind(name)
        .bind(workspace)
        .bind(scope)
        .bind(payload)
        .bind(now_ms)
        .bind(labels.unwrap_or("{}"))
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_scoped(
        &self,
        object_type: &str,
        id: &str,
        name: &str,
        workspace: &str,
        scope: &str,
        payload: &[u8],
        labels: Option<&str>,
    ) -> PersistenceResult<WriteResult> {
        let now_ms = current_time_ms();

        sqlx::query(
            r#"
INSERT INTO "objects" ("object_type", "id", "name", "workspace", "scope", "payload", "created_at_ms", "updated_at_ms", "labels", "resource_version")
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?8, 1)
"#,
        )
        .bind(object_type)
        .bind(id)
        .bind(name)
        .bind(workspace)
        .bind(scope)
        .bind(payload)
        .bind(now_ms)
        .bind(labels.unwrap_or("{}"))
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(WriteResult {
            resource_version: 1,
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_if_workspace_count_below(
        &self,
        object_type: &str,
        id: &str,
        name: &str,
        workspace: &str,
        payload: &[u8],
        labels: Option<&str>,
        max_count: u64,
    ) -> PersistenceResult<Option<WriteResult>> {
        let now_ms = current_time_ms();
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|e| map_db_error(&e))?;

        let row: (i64,) = sqlx::query_as(
            r#"
SELECT COUNT(*) FROM "objects"
WHERE "object_type" = ?1 AND "workspace" = ?2
"#,
        )
        .bind(object_type)
        .bind(workspace)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| map_db_error(&e))?;
        let count = u64::try_from(row.0).unwrap_or(0);
        if count >= max_count {
            tx.commit().await.map_err(|e| map_db_error(&e))?;
            return Ok(None);
        }

        sqlx::query(
            r#"
INSERT INTO "objects" ("object_type", "id", "name", "workspace", "payload", "created_at_ms", "updated_at_ms", "labels", "resource_version")
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7, 1)
"#,
        )
        .bind(object_type)
        .bind(id)
        .bind(name)
        .bind(workspace)
        .bind(payload)
        .bind(now_ms)
        .bind(labels.unwrap_or("{}"))
        .execute(&mut *tx)
        .await
        .map_err(|e| map_db_error(&e))?;

        tx.commit().await.map_err(|e| map_db_error(&e))?;

        Ok(Some(WriteResult {
            resource_version: 1,
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
        }))
    }

    pub async fn get(
        &self,
        object_type: &str,
        id: &str,
    ) -> PersistenceResult<Option<ObjectRecord>> {
        let row = sqlx::query(
            r#"
SELECT "object_type", "id", "name", "workspace", "payload", "created_at_ms", "updated_at_ms", "labels", "resource_version"
FROM "objects"
WHERE "object_type" = ?1 AND "id" = ?2
"#,
        )
        .bind(object_type)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(row.map(row_to_object_record))
    }

    pub async fn get_by_name(
        &self,
        object_type: &str,
        workspace: &str,
        name: &str,
    ) -> PersistenceResult<Option<ObjectRecord>> {
        let row = sqlx::query(
            r#"
SELECT "object_type", "id", "name", "workspace", "payload", "created_at_ms", "updated_at_ms", "labels", "resource_version"
FROM "objects"
WHERE "object_type" = ?1 AND "workspace" = ?2 AND "name" = ?3
"#,
        )
        .bind(object_type)
        .bind(workspace)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(row.map(row_to_object_record))
    }

    pub async fn delete(&self, object_type: &str, id: &str) -> PersistenceResult<bool> {
        let result = sqlx::query(
            r#"
DELETE FROM "objects"
WHERE "object_type" = ?1 AND "id" = ?2
"#,
        )
        .bind(object_type)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn delete_many(&self, object_type: &str, ids: &[String]) -> PersistenceResult<u64> {
        let mut deleted = 0_u64;
        for ids in ids.chunks(DELETE_MANY_BATCH_SIZE) {
            let mut query = QueryBuilder::<Sqlite>::new("DELETE FROM objects WHERE object_type = ");
            query.push_bind(object_type).push(" AND id IN (");
            let mut separated = query.separated(", ");
            for id in ids {
                separated.push_bind(id);
            }
            separated.push_unseparated(")");

            deleted += query
                .build()
                .execute(&self.pool)
                .await
                .map_err(|e| map_db_error(&e))?
                .rows_affected();
        }
        Ok(deleted)
    }

    pub async fn count_in_workspace(
        &self,
        object_type: &str,
        workspace: &str,
    ) -> PersistenceResult<u64> {
        let row: (i64,) = sqlx::query_as(
            r#"
SELECT COUNT(*) FROM "objects"
WHERE "object_type" = ?1 AND "workspace" = ?2
"#,
        )
        .bind(object_type)
        .bind(workspace)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(u64::try_from(row.0).unwrap_or(0))
    }

    pub async fn delete_all_in_workspace(
        &self,
        object_type: &str,
        workspace: &str,
    ) -> PersistenceResult<u64> {
        let result = sqlx::query(
            r#"
DELETE FROM "objects"
WHERE "object_type" = ?1 AND "workspace" = ?2
"#,
        )
        .bind(object_type)
        .bind(workspace)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected())
    }

    pub async fn delete_by_scope(&self, object_type: &str, scope: &str) -> PersistenceResult<u64> {
        let result = sqlx::query(
            r#"
DELETE FROM "objects"
WHERE "object_type" = ?1 AND "scope" = ?2
"#,
        )
        .bind(object_type)
        .bind(scope)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected())
    }

    pub async fn delete_by_name(
        &self,
        object_type: &str,
        workspace: &str,
        name: &str,
    ) -> PersistenceResult<bool> {
        let result = sqlx::query(
            r#"
DELETE FROM "objects"
WHERE "object_type" = ?1 AND "workspace" = ?2 AND "name" = ?3
"#,
        )
        .bind(object_type)
        .bind(workspace)
        .bind(name)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn list(
        &self,
        object_type: &str,
        workspace: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        let rows = sqlx::query(
            r#"
SELECT "object_type", "id", "name", "workspace", "payload", "created_at_ms", "updated_at_ms", "labels", "resource_version"
FROM "objects"
WHERE "object_type" = ?1 AND "workspace" = ?2
ORDER BY "created_at_ms" ASC, "name" ASC
LIMIT ?3 OFFSET ?4
"#,
        )
        .bind(object_type)
        .bind(workspace)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(rows.into_iter().map(row_to_object_record).collect())
    }

    pub async fn list_by_type(
        &self,
        object_type: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        let rows = sqlx::query(
            r#"
SELECT "object_type", "id", "name", "workspace", "payload", "created_at_ms", "updated_at_ms", "labels", "resource_version"
FROM "objects"
WHERE "object_type" = ?1
ORDER BY "created_at_ms" ASC, "name" ASC, "workspace" ASC, "id" ASC
LIMIT ?2 OFFSET ?3
"#,
        )
        .bind(object_type)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(rows.into_iter().map(row_to_object_record).collect())
    }
    pub async fn list_after(
        &self,
        object_type: &str,
        workspace: &str,
        after: Option<&ObjectCursor>,
        limit: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        let rows = if let Some(cursor) = after {
            sqlx::query(
                r#"
SELECT "object_type", "id", "name", "workspace", "payload", "created_at_ms", "updated_at_ms", "labels", "resource_version"
FROM "objects"
WHERE "object_type" = ?1 AND "workspace" = ?2
  AND ("created_at_ms", "name", "id") > (?3, ?4, ?5)
ORDER BY "created_at_ms" ASC, "name" ASC, "id" ASC
LIMIT ?6
"#,
            )
            .bind(object_type)
            .bind(workspace)
            .bind(cursor.created_at_ms)
            .bind(&cursor.name)
            .bind(&cursor.id)
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query(
                r#"
SELECT "object_type", "id", "name", "workspace", "payload", "created_at_ms", "updated_at_ms", "labels", "resource_version"
FROM "objects"
WHERE "object_type" = ?1 AND "workspace" = ?2
ORDER BY "created_at_ms" ASC, "name" ASC, "id" ASC
LIMIT ?3
"#,
            )
            .bind(object_type)
            .bind(workspace)
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await
        }
        .map_err(|e| map_db_error(&e))?;
        Ok(rows.into_iter().map(row_to_object_record).collect())
    }
    pub async fn list_by_type_after(
        &self,
        object_type: &str,
        after: Option<&ObjectCursor>,
        limit: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        let rows = if let Some(cursor) = after {
            sqlx::query(r#"
SELECT "object_type", "id", "name", "workspace", "payload", "created_at_ms", "updated_at_ms", "labels", "resource_version"
FROM "objects"
WHERE "object_type" = ?1
  AND ("created_at_ms", "name", "workspace", "id") > (?2, ?3, ?4, ?5)
ORDER BY "created_at_ms" ASC, "name" ASC, "workspace" ASC, "id" ASC
LIMIT ?6
"#).bind(object_type).bind(cursor.created_at_ms).bind(&cursor.name).bind(&cursor.workspace).bind(&cursor.id).bind(i64::from(limit)).fetch_all(&self.pool).await
        } else {
            sqlx::query(r#"
SELECT "object_type", "id", "name", "workspace", "payload", "created_at_ms", "updated_at_ms", "labels", "resource_version"
FROM "objects"
WHERE "object_type" = ?1
ORDER BY "created_at_ms" ASC, "name" ASC, "workspace" ASC, "id" ASC
LIMIT ?2
"#).bind(object_type).bind(i64::from(limit)).fetch_all(&self.pool).await
        }.map_err(|e| map_db_error(&e))?;
        Ok(rows.into_iter().map(row_to_object_record).collect())
    }

    pub async fn list_object_page(
        &self,
        object_type: &str,
        query: ObjectListQuery<'_>,
        after: Option<&ObjectCursor>,
        limit: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        let mut sql = QueryBuilder::<Sqlite>::new(
            "SELECT o.object_type, o.id, o.name, o.workspace, o.payload, \
             o.created_at_ms, o.updated_at_ms, o.labels, o.resource_version \
             FROM objects o WHERE o.object_type = ",
        );
        sql.push_bind(object_type);

        match query {
            ObjectListQuery::Workspace(workspace) => {
                sql.push(" AND o.workspace = ").push_bind(workspace);
            }
            ObjectListQuery::AllWorkspaces => {}
            ObjectListQuery::Scope(scope) => {
                sql.push(" AND o.scope = ").push_bind(scope);
            }
            ObjectListQuery::WorkspaceSelector {
                workspace,
                label_selector,
            } => {
                sql.push(" AND o.workspace = ").push_bind(workspace);
                push_label_selector(&mut sql, label_selector)?;
            }
            ObjectListQuery::AllWorkspacesSelector(label_selector) => {
                push_label_selector(&mut sql, label_selector)?;
            }
            ObjectListQuery::Membership {
                member_type,
                member_name,
            } => {
                sql.push(
                    " AND o.workspace = '' AND EXISTS (SELECT 1 FROM objects m \
                          WHERE m.object_type = ",
                )
                .push_bind(member_type)
                .push(" AND m.workspace = o.name AND m.name = ")
                .push_bind(member_name)
                .push(")");
            }
            ObjectListQuery::MembershipSelector {
                member_type,
                member_name,
                label_selector,
            } => {
                sql.push(
                    " AND o.workspace = '' AND EXISTS (SELECT 1 FROM objects m \
                          WHERE m.object_type = ",
                )
                .push_bind(member_type)
                .push(" AND m.workspace = o.name AND m.name = ")
                .push_bind(member_name)
                .push(")");
                push_label_selector(&mut sql, label_selector)?;
            }
        }

        if let Some(cursor) = after {
            sql.push(" AND (o.created_at_ms, COALESCE(o.name, ''), o.workspace, o.id) > (")
                .push_bind(cursor.created_at_ms)
                .push(", ")
                .push_bind(&cursor.name)
                .push(", ")
                .push_bind(&cursor.workspace)
                .push(", ")
                .push_bind(&cursor.id)
                .push(")");
        }
        sql.push(
            " ORDER BY o.created_at_ms ASC, COALESCE(o.name, '') ASC, \
             o.workspace ASC, o.id ASC LIMIT ",
        )
        .push_bind(i64::from(limit));

        let rows = sql
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(|e| map_db_error(&e))?;
        Ok(rows.into_iter().map(row_to_object_record).collect())
    }

    pub async fn list_with_membership(
        &self,
        object_type: &str,
        member_type: &str,
        member_name: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        let rows = sqlx::query(
            r#"
SELECT w."object_type", w."id", w."name", w."workspace", w."payload",
       w."created_at_ms", w."updated_at_ms", w."labels", w."resource_version"
FROM "objects" w
WHERE w."object_type" = ?1 AND w."workspace" = ''
AND EXISTS (
    SELECT 1 FROM "objects" m
    WHERE m."object_type" = ?2
    AND m."workspace" = w."name"
    AND m."name" = ?3
)
ORDER BY w."created_at_ms" ASC, w."name" ASC
LIMIT ?4 OFFSET ?5
"#,
        )
        .bind(object_type)
        .bind(member_type)
        .bind(member_name)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(rows.into_iter().map(row_to_object_record).collect())
    }

    pub async fn list_with_membership_and_selector(
        &self,
        object_type: &str,
        member_type: &str,
        member_name: &str,
        label_selector: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        use std::fmt::Write;

        use super::parse_label_selector;

        let required_labels = parse_label_selector(label_selector)?;

        let mut sql = String::from(
            r#"
SELECT w."object_type", w."id", w."name", w."workspace", w."payload",
       w."created_at_ms", w."updated_at_ms", w."labels", w."resource_version"
FROM "objects" w
WHERE w."object_type" = ?1 AND w."workspace" = ''
AND EXISTS (
    SELECT 1 FROM "objects" m
    WHERE m."object_type" = ?2
    AND m."workspace" = w."name"
    AND m."name" = ?3
)"#,
        );

        let label_pairs: Vec<(&String, &String)> = required_labels.iter().collect();
        for (i, (key, _)) in label_pairs.iter().enumerate() {
            let param_idx = 4 + i;
            write!(
                sql,
                "\nAND json_extract(w.\"labels\", '$.\"{}\"') = ?{}",
                key.replace('\\', "\\\\")
                    .replace('"', "\\\"")
                    .replace('\'', "''"),
                param_idx
            )
            .unwrap();
        }

        let limit_idx = 4 + label_pairs.len();
        let offset_idx = limit_idx + 1;
        write!(
            sql,
            "\nORDER BY w.\"created_at_ms\" ASC, w.\"name\" ASC\nLIMIT ?{limit_idx} OFFSET ?{offset_idx}\n"
        )
        .unwrap();

        // Label paths above escape SQL quotes; all values remain bound parameters.
        let mut query = sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
            .bind(object_type)
            .bind(member_type)
            .bind(member_name);

        for (_, value) in &label_pairs {
            query = query.bind(*value);
        }

        query = query.bind(i64::from(limit)).bind(i64::from(offset));

        let rows = query
            .fetch_all(&self.pool)
            .await
            .map_err(|e| map_db_error(&e))?;

        Ok(rows.into_iter().map(row_to_object_record).collect())
    }

    pub async fn list_by_scope(
        &self,
        object_type: &str,
        scope: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        let rows = sqlx::query(
            r#"
SELECT "object_type", "id", "name", "workspace", "payload", "created_at_ms", "updated_at_ms", "labels", "resource_version"
FROM "objects"
WHERE "object_type" = ?1 AND "scope" = ?2
ORDER BY "created_at_ms" ASC, "name" ASC
LIMIT ?3 OFFSET ?4
"#,
        )
        .bind(object_type)
        .bind(scope)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(rows.into_iter().map(row_to_object_record).collect())
    }
    pub async fn list_with_selector(
        &self,
        object_type: &str,
        workspace: &str,
        label_selector: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        let mut sql = QueryBuilder::<Sqlite>::new(
            r#"SELECT o."object_type", o."id", o."name", o."workspace", o."payload", o."created_at_ms", o."updated_at_ms", o."labels", o."resource_version"
FROM "objects" o
WHERE o."object_type" = "#,
        );
        sql.push_bind(object_type).push(" AND o.\"workspace\" = ");
        sql.push_bind(workspace);
        push_label_selector(&mut sql, label_selector)?;
        sql.push(" ORDER BY o.\"created_at_ms\" ASC, o.\"name\" ASC LIMIT ")
            .push_bind(i64::from(limit))
            .push(" OFFSET ")
            .push_bind(i64::from(offset));
        let rows = sql
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(|e| map_db_error(&e))?;
        Ok(rows.into_iter().map(row_to_object_record).collect())
    }

    pub async fn list_all_with_selector(
        &self,
        object_type: &str,
        label_selector: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        let mut sql = QueryBuilder::<Sqlite>::new(
            r#"SELECT o."object_type", o."id", o."name", o."workspace", o."payload", o."created_at_ms", o."updated_at_ms", o."labels", o."resource_version"
FROM "objects" o
WHERE o."object_type" = "#,
        );
        sql.push_bind(object_type);
        push_label_selector(&mut sql, label_selector)?;
        sql.push(" ORDER BY o.\"created_at_ms\" ASC, o.\"name\" ASC LIMIT ")
            .push_bind(i64::from(limit))
            .push(" OFFSET ")
            .push_bind(i64::from(offset));
        let rows = sql
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(|e| map_db_error(&e))?;
        Ok(rows.into_iter().map(row_to_object_record).collect())
    }
    pub async fn put_policy_revision(
        &self,
        id: &str,
        sandbox_id: &str,
        workspace: &str,
        version: i64,
        payload: &[u8],
        hash: &str,
    ) -> PersistenceResult<()> {
        let now_ms = current_time_ms();
        let record = PolicyRecord {
            id: id.to_string(),
            sandbox_id: sandbox_id.to_string(),
            version,
            policy_payload: payload.to_vec(),
            policy_hash: hash.to_string(),
            status: "pending".to_string(),
            load_error: None,
            created_at_ms: now_ms,
            loaded_at_ms: None,
            provenance: std::collections::HashMap::default(),
        };
        let wrapped_payload = policy_payload_from_record(&record)?;

        sqlx::query(
            r#"
INSERT INTO "objects" (
    "object_type", "id", "scope", "version", "status", "payload", "created_at_ms", "updated_at_ms", "workspace"
)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?8)
"#,
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(id)
        .bind(sandbox_id)
        .bind(version)
        .bind("pending")
        .bind(wrapped_payload)
        .bind(now_ms)
        .bind(workspace)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(())
    }

    pub async fn put_initial_policy_revision(
        &self,
        record: &PolicyRecord,
        workspace: &str,
    ) -> PersistenceResult<()> {
        let wrapped_payload = policy_payload_from_record(record)?;
        sqlx::query(
            r#"
INSERT INTO "objects" (
    "object_type", "id", "scope", "version", "status", "payload", "created_at_ms", "updated_at_ms", "workspace"
)
SELECT ?1, ?2, ?3, 1, ?4, ?5, ?6, ?6, ?7
WHERE EXISTS (SELECT 1 FROM "objects" WHERE "object_type" = 'sandbox' AND "id" = ?3)
  AND NOT EXISTS (SELECT 1 FROM "objects" WHERE "object_type" = ?1 AND "scope" = ?3)
ON CONFLICT DO NOTHING
"#,
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(&record.id)
        .bind(&record.sandbox_id)
        .bind(&record.status)
        .bind(wrapped_payload)
        .bind(record.created_at_ms)
        .bind(workspace)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(())
    }

    pub async fn put_policy_revision_atomic(
        &self,
        write: &AtomicPolicyRevisionWrite,
    ) -> PersistenceResult<Sandbox> {
        let now_ms = current_time_ms();
        let record = policy_record_for_atomic_write(write, now_ms);
        let wrapped_payload = policy_payload_from_record(&record)?;
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|e| map_db_error(&e))?;

        lock_sandbox_config_fence(&mut tx, &write.sandbox_id).await?;

        let row = sqlx::query(
            r#"
SELECT "payload", "resource_version"
FROM "objects"
WHERE "object_type" = 'sandbox' AND "id" = ?1
"#,
        )
        .bind(&write.sandbox_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| map_db_error(&e))?
        .ok_or_else(|| {
            PersistenceError::Database(format!("sandbox object {} not found", write.sandbox_id))
        })?;

        let sandbox_payload: Vec<u8> = row.get("payload");
        let current_version: i64 = row.try_get("resource_version").unwrap_or(1);
        let current_version = current_version.max(1).cast_unsigned();
        let (mut sandbox, sandbox_changed) =
            project_policy_revision_onto_sandbox(write, &sandbox_payload, current_version)?;

        let resulting_version = if sandbox_changed {
            let result = sqlx::query(
                r#"
UPDATE "objects"
SET "payload" = ?2, "updated_at_ms" = ?3, "resource_version" = "resource_version" + 1
WHERE "object_type" = 'sandbox' AND "id" = ?1 AND "resource_version" = ?4
"#,
            )
            .bind(&write.sandbox_id)
            .bind(sandbox.encode_to_vec())
            .bind(now_ms)
            .bind(i64::try_from(current_version).unwrap_or(i64::MAX))
            .execute(&mut *tx)
            .await
            .map_err(|e| map_db_error(&e))?;
            if result.rows_affected() != 1 {
                return Err(PersistenceError::Conflict {
                    current_resource_version: Some(current_version),
                });
            }
            current_version.saturating_add(1)
        } else {
            current_version
        };

        sqlx::query(
            r#"
INSERT INTO "objects" (
    "object_type", "id", "scope", "version", "status", "payload", "created_at_ms", "updated_at_ms", "workspace"
)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?8)
"#,
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(&write.id)
        .bind(&write.sandbox_id)
        .bind(write.version)
        .bind("pending")
        .bind(wrapped_payload)
        .bind(now_ms)
        .bind(&write.workspace)
        .execute(&mut *tx)
        .await
        .map_err(|e| map_db_error(&e))?;

        if let Some(operation_record) = write.operation.as_ref() {
            let sandbox_name = sandbox
                .metadata
                .as_ref()
                .map_or("", |metadata| metadata.name.as_str());
            let operation_record = operation_with_current_settings_target(
                &mut tx,
                operation_record,
                &write.workspace,
                sandbox_name,
            )
            .await?;
            insert_update_operation_sqlite(&mut tx, &operation_record, now_ms).await?;
        }

        sqlx::query(
            r#"
UPDATE "objects"
SET "status" = 'superseded', "updated_at_ms" = ?4
WHERE "object_type" = ?1
  AND "scope" = ?2
  AND "version" < ?3
  AND "status" IN ('pending', 'loaded')
"#,
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(&write.sandbox_id)
        .bind(write.version)
        .bind(now_ms)
        .execute(&mut *tx)
        .await
        .map_err(|e| map_db_error(&e))?;

        tx.commit().await.map_err(|e| map_db_error(&e))?;
        sandbox.set_resource_version(resulting_version);
        Ok(sandbox)
    }

    pub async fn get_latest_policy(
        &self,
        sandbox_id: &str,
    ) -> PersistenceResult<Option<PolicyRecord>> {
        let row = sqlx::query(
            r#"
SELECT "id", "scope", "version", "status", "payload", "created_at_ms"
FROM "objects"
WHERE "object_type" = ?1 AND "scope" = ?2
ORDER BY "version" DESC, "created_at_ms" DESC
LIMIT 1
"#,
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(sandbox_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        row.map(row_to_policy_record).transpose()
    }

    pub async fn get_latest_loaded_policy(
        &self,
        sandbox_id: &str,
    ) -> PersistenceResult<Option<PolicyRecord>> {
        let row = sqlx::query(
            r#"
SELECT "id", "scope", "version", "status", "payload", "created_at_ms"
FROM "objects"
WHERE "object_type" = ?1 AND "scope" = ?2 AND "status" = 'loaded'
ORDER BY "version" DESC, "created_at_ms" DESC
LIMIT 1
"#,
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(sandbox_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        row.map(row_to_policy_record).transpose()
    }

    pub async fn get_policy_by_version(
        &self,
        sandbox_id: &str,
        version: i64,
    ) -> PersistenceResult<Option<PolicyRecord>> {
        let row = sqlx::query(
            r#"
SELECT "id", "scope", "version", "status", "payload", "created_at_ms"
FROM "objects"
WHERE "object_type" = ?1 AND "scope" = ?2 AND "version" = ?3
"#,
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(sandbox_id)
        .bind(version)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        row.map(row_to_policy_record).transpose()
    }

    pub async fn list_policies(
        &self,
        sandbox_id: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<PolicyRecord>> {
        let rows = sqlx::query(
            r#"
SELECT "id", "scope", "version", "status", "payload", "created_at_ms"
FROM "objects"
WHERE "object_type" = ?1 AND "scope" = ?2
ORDER BY "version" DESC, "created_at_ms" DESC
LIMIT ?3 OFFSET ?4
"#,
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(sandbox_id)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        rows.into_iter().map(row_to_policy_record).collect()
    }

    pub async fn list_policies_before(
        &self,
        sandbox_id: &str,
        limit: u32,
        before_version: Option<i64>,
    ) -> PersistenceResult<Vec<PolicyRecord>> {
        let rows = sqlx::query(
            r#"
SELECT "id", "scope", "version", "status", "payload", "created_at_ms"
FROM "objects"
WHERE "object_type" = ?1 AND "scope" = ?2 AND (?3 IS NULL OR "version" < ?3)
ORDER BY "version" DESC
LIMIT ?4
"#,
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(sandbox_id)
        .bind(before_version)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        rows.into_iter().map(row_to_policy_record).collect()
    }

    pub async fn update_policy_status(
        &self,
        sandbox_id: &str,
        version: i64,
        status: &str,
        load_error: Option<&str>,
        loaded_at_ms: Option<i64>,
    ) -> PersistenceResult<bool> {
        let Some(mut record) = self.get_policy_by_version(sandbox_id, version).await? else {
            return Ok(false);
        };

        record.status = status.to_string();
        record.load_error = load_error.map(ToOwned::to_owned);
        record.loaded_at_ms = loaded_at_ms;
        let payload = policy_payload_from_record(&record)?;
        let now_ms = current_time_ms();

        let result = sqlx::query(
            r#"
UPDATE "objects"
SET "status" = ?4, "payload" = ?5, "updated_at_ms" = ?6
WHERE "object_type" = ?1 AND "scope" = ?2 AND "version" = ?3
"#,
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(sandbox_id)
        .bind(version)
        .bind(status)
        .bind(payload)
        .bind(now_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn supersede_older_policies(
        &self,
        sandbox_id: &str,
        before_version: i64,
    ) -> PersistenceResult<u64> {
        let now_ms = current_time_ms();
        let result = sqlx::query(
            r#"
UPDATE "objects"
SET "status" = 'superseded', "updated_at_ms" = ?4
WHERE "object_type" = ?1
  AND "scope" = ?2
  AND "version" < ?3
  AND "status" IN ('pending', 'loaded')
"#,
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(sandbox_id)
        .bind(before_version)
        .bind(now_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected())
    }

    pub async fn put_draft_chunk(
        &self,
        chunk: &DraftChunkRecord,
        dedup_key: Option<&str>,
        workspace: &str,
    ) -> PersistenceResult<String> {
        let payload = draft_chunk_payload_from_record(chunk)?;
        // RETURNING "id" gives us the row's effective id regardless of
        // whether INSERT inserted a fresh row or ON CONFLICT updated an
        // existing one. Callers report this id to clients so the response
        // can never advertise a chunk_id that isn't actually persisted.
        let row = sqlx::query(
            r#"
INSERT INTO "objects" (
    "object_type", "id", "scope", "status", "dedup_key", "hit_count", "payload", "created_at_ms", "updated_at_ms", "workspace"
)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
ON CONFLICT ("object_type", "scope", "dedup_key") WHERE "dedup_key" IS NOT NULL DO UPDATE SET
    "hit_count" = "objects"."hit_count" + excluded."hit_count",
    "updated_at_ms" = excluded."updated_at_ms"
RETURNING "id"
"#,
        )
        .bind(DRAFT_CHUNK_OBJECT_TYPE)
        .bind(&chunk.id)
        .bind(&chunk.sandbox_id)
        .bind(&chunk.status)
        .bind(dedup_key)
        .bind(i64::from(chunk.hit_count))
        .bind(payload)
        .bind(chunk.first_seen_ms)
        .bind(chunk.last_seen_ms)
        .bind(workspace)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(row.get::<String, _>("id"))
    }

    pub async fn get_draft_chunk(&self, id: &str) -> PersistenceResult<Option<DraftChunkRecord>> {
        let row = sqlx::query(
            r#"
SELECT "id", "scope", "status", "hit_count", "payload", "created_at_ms", "updated_at_ms"
FROM "objects"
WHERE "object_type" = ?1 AND "id" = ?2
"#,
        )
        .bind(DRAFT_CHUNK_OBJECT_TYPE)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        row.map(row_to_draft_chunk_record).transpose()
    }

    pub async fn list_draft_chunks(
        &self,
        sandbox_id: &str,
        status_filter: Option<&str>,
    ) -> PersistenceResult<Vec<DraftChunkRecord>> {
        let rows = if let Some(status) = status_filter {
            sqlx::query(
                r#"
SELECT "id", "scope", "status", "hit_count", "payload", "created_at_ms", "updated_at_ms"
FROM "objects"
WHERE "object_type" = ?1 AND "scope" = ?2 AND "status" = ?3
ORDER BY "created_at_ms" DESC
"#,
            )
            .bind(DRAFT_CHUNK_OBJECT_TYPE)
            .bind(sandbox_id)
            .bind(status)
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query(
                r#"
SELECT "id", "scope", "status", "hit_count", "payload", "created_at_ms", "updated_at_ms"
FROM "objects"
WHERE "object_type" = ?1 AND "scope" = ?2
ORDER BY "created_at_ms" DESC
"#,
            )
            .bind(DRAFT_CHUNK_OBJECT_TYPE)
            .bind(sandbox_id)
            .fetch_all(&self.pool)
            .await
        }
        .map_err(|e| map_db_error(&e))?;

        rows.into_iter().map(row_to_draft_chunk_record).collect()
    }

    pub async fn update_draft_chunk_status(
        &self,
        id: &str,
        status: &str,
        decided_at_ms: Option<i64>,
        rejection_reason: Option<&str>,
    ) -> PersistenceResult<bool> {
        let Some(mut record) = self.get_draft_chunk(id).await? else {
            return Ok(false);
        };

        record.status = status.to_string();
        record.decided_at_ms = decided_at_ms;
        record.last_seen_ms = current_time_ms();
        if let Some(reason) = rejection_reason {
            record.rejection_reason = reason.to_string();
        }
        let payload = draft_chunk_payload_from_record(&record)?;

        let result = sqlx::query(
            r#"
UPDATE "objects"
SET "status" = ?3, "payload" = ?4, "updated_at_ms" = ?5
WHERE "object_type" = ?1 AND "id" = ?2
"#,
        )
        .bind(DRAFT_CHUNK_OBJECT_TYPE)
        .bind(id)
        .bind(status)
        .bind(payload)
        .bind(record.last_seen_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn conditionally_reject_draft_chunk(
        &self,
        id: &str,
        decided_at_ms: i64,
        rejection_reason: &str,
    ) -> PersistenceResult<bool> {
        let Some(mut record) = self.get_draft_chunk(id).await? else {
            return Ok(false);
        };

        if record.status != "pending" {
            return Ok(false);
        }

        record.status = "rejected".to_string();
        record.decided_at_ms = Some(decided_at_ms);
        record.rejection_reason = rejection_reason.to_string();
        record.last_seen_ms = current_time_ms();
        let payload = draft_chunk_payload_from_record(&record)?;

        let result = sqlx::query(
            r#"
UPDATE "objects"
SET "status" = ?3, "payload" = ?4, "updated_at_ms" = ?5
WHERE "object_type" = ?1 AND "id" = ?2 AND "status" = 'pending'
"#,
        )
        .bind(DRAFT_CHUNK_OBJECT_TYPE)
        .bind(id)
        .bind("rejected")
        .bind(payload)
        .bind(record.last_seen_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn update_draft_chunk_rule(
        &self,
        id: &str,
        proposed_rule: &[u8],
    ) -> PersistenceResult<bool> {
        let Some(mut record) = self.get_draft_chunk(id).await? else {
            return Ok(false);
        };

        if record.status != "pending" {
            return Ok(false);
        }

        record.proposed_rule = proposed_rule.to_vec();
        record.last_seen_ms = current_time_ms();
        let payload = draft_chunk_payload_from_record(&record)?;

        let result = sqlx::query(
            r#"
UPDATE "objects"
SET "payload" = ?3, "updated_at_ms" = ?4
WHERE "object_type" = ?1 AND "id" = ?2 AND "status" = 'pending'
"#,
        )
        .bind(DRAFT_CHUNK_OBJECT_TYPE)
        .bind(id)
        .bind(payload)
        .bind(record.last_seen_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn update_draft_chunk_evaluation(
        &self,
        chunk: &DraftChunkRecord,
    ) -> PersistenceResult<bool> {
        let payload = draft_chunk_payload_from_record(chunk)?;
        let result = sqlx::query(
            r#"
UPDATE "objects"
SET "payload" = ?3, "updated_at_ms" = ?4
WHERE "object_type" = ?1 AND "id" = ?2 AND "status" IN ('pending', 'rejected')
"#,
        )
        .bind(DRAFT_CHUNK_OBJECT_TYPE)
        .bind(&chunk.id)
        .bind(payload)
        .bind(chunk.last_seen_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn delete_draft_chunks(
        &self,
        sandbox_id: &str,
        status: &str,
    ) -> PersistenceResult<u64> {
        let result = sqlx::query(
            r#"
DELETE FROM "objects"
WHERE "object_type" = ?1 AND "scope" = ?2 AND "status" = ?3
"#,
        )
        .bind(DRAFT_CHUNK_OBJECT_TYPE)
        .bind(sandbox_id)
        .bind(status)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected())
    }

    pub async fn get_draft_version(&self, sandbox_id: &str) -> PersistenceResult<i64> {
        let rows = sqlx::query(
            r#"
SELECT "payload"
FROM "objects"
WHERE "object_type" = ?1 AND "scope" = ?2
"#,
        )
        .bind(DRAFT_CHUNK_OBJECT_TYPE)
        .bind(sandbox_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        let mut max_version = 0_i64;
        for row in rows {
            let payload: Vec<u8> = row.get("payload");
            let wrapper = draft_chunk_record_from_parts(
                String::new(),
                sandbox_id.to_string(),
                String::new(),
                0,
                &payload,
                0,
                0,
            )?;
            max_version = max_version.max(wrapper.draft_version);
        }
        Ok(max_version)
    }
}

/// Restrict the on-disk `SQLite` database file (and its WAL/SHM sidecars,
/// when present) to owner-only read/write (`0o600`).
///
/// In WAL mode, `SQLite` keeps two sidecars next to
/// the main database file: `<db>-wal` (uncommitted page log)
/// and `<db>-shm` (shared memory index). They mirror the same sensitive data
/// as the main file, so they get the same `0o600` treatment whenever they exist on disk.
///
/// Delegates to `set_file_owner_only`, which is a no-op on non-Unix platforms.
pub(super) fn restrict_db_file_permissions(path: &Path) -> PersistenceResult<()> {
    set_file_owner_only(path).map_err(|err| PersistenceError::Database(err.to_string()))?;

    for sidecar in sqlite_sidecar_paths(path) {
        if sidecar.exists() {
            set_file_owner_only(&sidecar)
                .map_err(|err| PersistenceError::Database(err.to_string()))?;
        }
    }
    Ok(())
}

/// Compute the WAL/SHM sidecar paths `SQLite` derives from a main database file
/// (e.g. `foo.db` -> [`foo.db-wal`, `foo.db-shm`]).
pub(super) fn sqlite_sidecar_paths(path: &Path) -> [PathBuf; 2] {
    let with_suffix = |suffix: &str| -> PathBuf {
        let mut buf = path.as_os_str().to_os_string();
        buf.push(suffix);
        PathBuf::from(buf)
    };
    [with_suffix("-wal"), with_suffix("-shm")]
}

fn row_to_object_record(row: sqlx::sqlite::SqliteRow) -> ObjectRecord {
    let resource_version_i64: i64 = row.try_get("resource_version").unwrap_or(1);
    ObjectRecord {
        object_type: row.get("object_type"),
        id: row.get("id"),
        name: row.get("name"),
        workspace: row.try_get("workspace").unwrap_or_default(),
        payload: row.get("payload"),
        created_at_ms: row.get("created_at_ms"),
        updated_at_ms: row.get("updated_at_ms"),
        labels: row.get("labels"),
        resource_version: resource_version_i64.max(1).cast_unsigned(),
    }
}

fn row_to_policy_record(row: sqlx::sqlite::SqliteRow) -> PersistenceResult<PolicyRecord> {
    let id: String = row.get("id");
    let sandbox_id: String = row.get("scope");
    let version: i64 = row.get("version");
    let status: String = row.get("status");
    let payload: Vec<u8> = row.get("payload");
    let created_at_ms: i64 = row.get("created_at_ms");
    policy_record_from_parts(id, sandbox_id, version, status, &payload, created_at_ms)
}

fn row_to_draft_chunk_record(row: sqlx::sqlite::SqliteRow) -> PersistenceResult<DraftChunkRecord> {
    let id: String = row.get("id");
    let sandbox_id: String = row.get("scope");
    let status: String = row.get("status");
    let hit_count: i64 = row.get("hit_count");
    let payload: Vec<u8> = row.get("payload");
    let created_at_ms: i64 = row.get("created_at_ms");
    let updated_at_ms: i64 = row.get("updated_at_ms");
    draft_chunk_record_from_parts(
        id,
        sandbox_id,
        status,
        hit_count,
        &payload,
        created_at_ms,
        updated_at_ms,
    )
}
