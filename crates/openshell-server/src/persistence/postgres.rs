// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{
    DraftChunkRecord, ObjectRecord, PersistenceError, PersistenceResult, PolicyRecord,
    WriteCondition, WriteResult, current_time_ms, map_db_error, map_migrate_error,
};
use crate::policy_store::{
    draft_chunk_payload_from_record, draft_chunk_record_from_parts, policy_payload_from_record,
    policy_record_from_parts,
};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Connection, PgPool, Row};

static POSTGRES_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/postgres");

use super::{DRAFT_CHUNK_OBJECT_TYPE, POLICY_OBJECT_TYPE};

#[derive(Debug, Clone)]
pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    pub async fn connect(url: &str) -> PersistenceResult<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(url)
            .await
            .map_err(|e| map_db_error(&e))?;

        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> PersistenceResult<()> {
        POSTGRES_MIGRATOR
            .run(&self.pool)
            .await
            .map_err(|e| map_migrate_error(&e))
    }

    /// Verify the database is reachable by acquiring a pooled connection
    /// and issuing a protocol-level ping.
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
    }

    pub async fn put(
        &self,
        object_type: &str,
        id: &str,
        name: &str,
        payload: &[u8],
        labels: Option<&str>,
    ) -> PersistenceResult<()> {
        let now_ms = current_time_ms();
        let labels_jsonb: Option<serde_json::Value> = labels
            .map(serde_json::from_str)
            .transpose()
            .map_err(|e| PersistenceError::Encode(format!("invalid labels JSON: {e}")))?;

        sqlx::query(
            r"
INSERT INTO objects (object_type, id, name, payload, created_at_ms, updated_at_ms, labels)
VALUES ($1, $2, $3, $4, $5, $5, COALESCE($6, '{}'::jsonb))
ON CONFLICT (object_type, name) WHERE name IS NOT NULL DO UPDATE SET
    payload = EXCLUDED.payload,
    updated_at_ms = EXCLUDED.updated_at_ms,
    labels = EXCLUDED.labels
",
        )
        .bind(object_type)
        .bind(id)
        .bind(name)
        .bind(payload)
        .bind(now_ms)
        .bind(labels_jsonb)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(())
    }

    pub async fn put_if(
        &self,
        object_type: &str,
        id: &str,
        name: &str,
        payload: &[u8],
        labels: Option<&str>,
        condition: WriteCondition,
    ) -> PersistenceResult<WriteResult> {
        let now_ms = current_time_ms();
        let labels_jsonb: Option<serde_json::Value> = labels
            .map(serde_json::from_str)
            .transpose()
            .map_err(|e| PersistenceError::Encode(format!("invalid labels JSON: {e}")))?;

        match condition {
            WriteCondition::MustCreate => {
                // Insert only - fail if object exists
                let row = sqlx::query(
                    r"
INSERT INTO objects (object_type, id, name, payload, created_at_ms, updated_at_ms, labels, resource_version)
VALUES ($1, $2, $3, $4, $5, $5, COALESCE($6, '{}'::jsonb), 1)
RETURNING resource_version, created_at_ms, updated_at_ms
",
                )
                .bind(object_type)
                .bind(id)
                .bind(name)
                .bind(payload)
                .bind(now_ms)
                .bind(labels_jsonb)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| map_db_error(&e))?;

                let resource_version_i64: i64 = row.try_get("resource_version").unwrap_or(1);
                Ok(WriteResult {
                    resource_version: resource_version_i64.max(1).cast_unsigned(),
                    created_at_ms: row.get("created_at_ms"),
                    updated_at_ms: row.get("updated_at_ms"),
                })
            }
            WriteCondition::MatchResourceVersion(expected_version) => {
                // Update with version check using RETURNING
                let row_result = sqlx::query(
                    r"
UPDATE objects
SET payload = $4, labels = COALESCE($5, '{}'::jsonb), updated_at_ms = $6, resource_version = resource_version + 1
WHERE object_type = $1 AND id = $2 AND resource_version = $3
RETURNING resource_version, created_at_ms, updated_at_ms
",
                )
                .bind(object_type)
                .bind(id)
                .bind(i64::try_from(expected_version).unwrap_or(i64::MAX))
                .bind(payload)
                .bind(labels_jsonb)
                .bind(now_ms)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| map_db_error(&e))?;

                if let Some(row) = row_result {
                    let resource_version_i64: i64 = row.try_get("resource_version").unwrap_or(1);
                    Ok(WriteResult {
                        resource_version: resource_version_i64.max(1).cast_unsigned(),
                        created_at_ms: row.get("created_at_ms"),
                        updated_at_ms: row.get("updated_at_ms"),
                    })
                } else {
                    // Check if object exists to distinguish NotFound from Conflict
                    let existing = self.get(object_type, id).await?;
                    if let Some(record) = existing {
                        Err(PersistenceError::Conflict {
                            current_resource_version: Some(record.resource_version),
                        })
                    } else {
                        Err(PersistenceError::Database(format!(
                            "object not found: {object_type}/{id}"
                        )))
                    }
                }
            }
            WriteCondition::Unconditional => {
                // Unconditional upsert by name
                let row = sqlx::query(
                    r"
INSERT INTO objects (object_type, id, name, payload, created_at_ms, updated_at_ms, labels, resource_version)
VALUES ($1, $2, $3, $4, $5, $5, COALESCE($6, '{}'::jsonb), 1)
ON CONFLICT (object_type, name) WHERE name IS NOT NULL DO UPDATE SET
    payload = EXCLUDED.payload,
    updated_at_ms = EXCLUDED.updated_at_ms,
    labels = EXCLUDED.labels,
    resource_version = objects.resource_version + 1
RETURNING resource_version, created_at_ms, updated_at_ms
",
                )
                .bind(object_type)
                .bind(id)
                .bind(name)
                .bind(payload)
                .bind(now_ms)
                .bind(labels_jsonb)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| map_db_error(&e))?;

                let resource_version_i64: i64 = row.try_get("resource_version").unwrap_or(1);
                Ok(WriteResult {
                    resource_version: resource_version_i64.max(1).cast_unsigned(),
                    created_at_ms: row.get("created_at_ms"),
                    updated_at_ms: row.get("updated_at_ms"),
                })
            }
        }
    }

    pub async fn delete_if(
        &self,
        object_type: &str,
        id: &str,
        expected_resource_version: u64,
    ) -> PersistenceResult<bool> {
        let result = sqlx::query(
            r"
DELETE FROM objects
WHERE object_type = $1 AND id = $2 AND resource_version = $3
",
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
                Err(PersistenceError::Conflict {
                    current_resource_version: Some(record.resource_version),
                })
            } else {
                Ok(false)
            }
        }
    }

    pub async fn put_scoped(
        &self,
        object_type: &str,
        id: &str,
        name: &str,
        scope: &str,
        payload: &[u8],
        labels: Option<&str>,
    ) -> PersistenceResult<()> {
        let now_ms = current_time_ms();
        let labels_jsonb: Option<serde_json::Value> = labels
            .map(serde_json::from_str)
            .transpose()
            .map_err(|e| PersistenceError::Encode(format!("invalid labels JSON: {e}")))?;

        sqlx::query(
            r"
INSERT INTO objects (object_type, id, name, scope, payload, created_at_ms, updated_at_ms, labels, resource_version)
VALUES ($1, $2, $3, $4, $5, $6, $6, COALESCE($7, '{}'::jsonb), 1)
ON CONFLICT (object_type, name) WHERE name IS NOT NULL DO UPDATE SET
    scope = EXCLUDED.scope,
    payload = EXCLUDED.payload,
    updated_at_ms = EXCLUDED.updated_at_ms,
    labels = EXCLUDED.labels,
    resource_version = objects.resource_version + 1
",
        )
        .bind(object_type)
        .bind(id)
        .bind(name)
        .bind(scope)
        .bind(payload)
        .bind(now_ms)
        .bind(labels_jsonb)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(())
    }

    pub async fn get(
        &self,
        object_type: &str,
        id: &str,
    ) -> PersistenceResult<Option<ObjectRecord>> {
        let row = sqlx::query(
            r"
SELECT object_type, id, name, payload, created_at_ms, updated_at_ms, labels, resource_version
FROM objects
WHERE object_type = $1 AND id = $2
",
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
        name: &str,
    ) -> PersistenceResult<Option<ObjectRecord>> {
        let row = sqlx::query(
            r"
SELECT object_type, id, name, payload, created_at_ms, updated_at_ms, labels, resource_version
FROM objects
WHERE object_type = $1 AND name = $2
",
        )
        .bind(object_type)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(row.map(row_to_object_record))
    }

    pub async fn delete(&self, object_type: &str, id: &str) -> PersistenceResult<bool> {
        let result = sqlx::query("DELETE FROM objects WHERE object_type = $1 AND id = $2")
            .bind(object_type)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn delete_by_name(&self, object_type: &str, name: &str) -> PersistenceResult<bool> {
        let result = sqlx::query("DELETE FROM objects WHERE object_type = $1 AND name = $2")
            .bind(object_type)
            .bind(name)
            .execute(&self.pool)
            .await
            .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn list(
        &self,
        object_type: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        let rows = sqlx::query(
            r"
SELECT object_type, id, name, payload, created_at_ms, updated_at_ms, labels, resource_version
FROM objects
WHERE object_type = $1
ORDER BY created_at_ms ASC, name ASC
LIMIT $2 OFFSET $3
",
        )
        .bind(object_type)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
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
            r"
SELECT object_type, id, name, payload, created_at_ms, updated_at_ms, labels
FROM objects
WHERE object_type = $1 AND scope = $2
ORDER BY created_at_ms ASC, name ASC
LIMIT $3 OFFSET $4
",
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
        label_selector: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        use super::parse_label_selector;

        let required_labels = parse_label_selector(label_selector)?;
        let labels_jsonb = serde_json::to_value(&required_labels)
            .map_err(|e| PersistenceError::Encode(format!("failed to serialize labels: {e}")))?;

        let rows = sqlx::query(
            r"
SELECT object_type, id, name, payload, created_at_ms, updated_at_ms, labels, resource_version
FROM objects
WHERE object_type = $1 AND labels @> $2
ORDER BY created_at_ms ASC, name ASC
LIMIT $3 OFFSET $4
",
        )
        .bind(object_type)
        .bind(&labels_jsonb)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(rows.into_iter().map(row_to_object_record).collect())
    }

    pub async fn put_policy_revision(
        &self,
        id: &str,
        sandbox_id: &str,
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
        };
        let wrapped_payload = policy_payload_from_record(&record)?;

        sqlx::query(
            r"
INSERT INTO objects (
    object_type, id, scope, version, status, payload, created_at_ms, updated_at_ms
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
",
        )
        .bind(POLICY_OBJECT_TYPE)
        .bind(id)
        .bind(sandbox_id)
        .bind(version)
        .bind("pending")
        .bind(wrapped_payload)
        .bind(now_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(())
    }

    pub async fn get_latest_policy(
        &self,
        sandbox_id: &str,
    ) -> PersistenceResult<Option<PolicyRecord>> {
        let row = sqlx::query(
            r"
SELECT id, scope, version, status, payload, created_at_ms
FROM objects
WHERE object_type = $1 AND scope = $2
ORDER BY version DESC, created_at_ms DESC
LIMIT 1
",
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
            r"
SELECT id, scope, version, status, payload, created_at_ms
FROM objects
WHERE object_type = $1 AND scope = $2 AND status = 'loaded'
ORDER BY version DESC, created_at_ms DESC
LIMIT 1
",
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
            r"
SELECT id, scope, version, status, payload, created_at_ms
FROM objects
WHERE object_type = $1 AND scope = $2 AND version = $3
",
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
            r"
SELECT id, scope, version, status, payload, created_at_ms
FROM objects
WHERE object_type = $1 AND scope = $2
ORDER BY version DESC, created_at_ms DESC
LIMIT $3 OFFSET $4
",
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
            r"
UPDATE objects
SET status = $4, payload = $5, updated_at_ms = $6
WHERE object_type = $1 AND scope = $2 AND version = $3
",
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
            r"
UPDATE objects
SET status = 'superseded', updated_at_ms = $4
WHERE object_type = $1
  AND scope = $2
  AND version < $3
  AND status IN ('pending', 'loaded')
",
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
    ) -> PersistenceResult<String> {
        let payload = draft_chunk_payload_from_record(chunk)?;
        // RETURNING id gives the row's effective id whether INSERT inserted
        // a fresh row or ON CONFLICT updated an existing one. See the
        // matching sqlite path for the rationale.
        let row = sqlx::query(
            r"
INSERT INTO objects (
    object_type, id, scope, status, dedup_key, hit_count, payload, created_at_ms, updated_at_ms
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (object_type, scope, dedup_key) WHERE dedup_key IS NOT NULL DO UPDATE SET
    hit_count = objects.hit_count + EXCLUDED.hit_count,
    updated_at_ms = EXCLUDED.updated_at_ms
RETURNING id
",
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
        .fetch_one(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(row.get::<String, _>("id"))
    }

    pub async fn get_draft_chunk(&self, id: &str) -> PersistenceResult<Option<DraftChunkRecord>> {
        let row = sqlx::query(
            r"
SELECT id, scope, status, hit_count, payload, created_at_ms, updated_at_ms
FROM objects
WHERE object_type = $1 AND id = $2
",
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
                r"
SELECT id, scope, status, hit_count, payload, created_at_ms, updated_at_ms
FROM objects
WHERE object_type = $1 AND scope = $2 AND status = $3
ORDER BY created_at_ms DESC
",
            )
            .bind(DRAFT_CHUNK_OBJECT_TYPE)
            .bind(sandbox_id)
            .bind(status)
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query(
                r"
SELECT id, scope, status, hit_count, payload, created_at_ms, updated_at_ms
FROM objects
WHERE object_type = $1 AND scope = $2
ORDER BY created_at_ms DESC
",
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
            r"
UPDATE objects
SET status = $3, payload = $4, updated_at_ms = $5
WHERE object_type = $1 AND id = $2
",
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
            r"
UPDATE objects
SET payload = $3, updated_at_ms = $4
WHERE object_type = $1 AND id = $2 AND status = 'pending'
",
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

    pub async fn delete_draft_chunks(
        &self,
        sandbox_id: &str,
        status: &str,
    ) -> PersistenceResult<u64> {
        let result = sqlx::query(
            r"
DELETE FROM objects
WHERE object_type = $1 AND scope = $2 AND status = $3
",
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
            r"
SELECT payload
FROM objects
WHERE object_type = $1 AND scope = $2
",
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

fn row_to_object_record(row: sqlx::postgres::PgRow) -> ObjectRecord {
    let labels_jsonb: Option<serde_json::Value> = row.get("labels");
    let resource_version_i64: i64 = row.try_get("resource_version").unwrap_or(1);
    ObjectRecord {
        object_type: row.get("object_type"),
        id: row.get("id"),
        name: row.get("name"),
        payload: row.get("payload"),
        created_at_ms: row.get("created_at_ms"),
        updated_at_ms: row.get("updated_at_ms"),
        labels: labels_jsonb.map(|value| value.to_string()),
        resource_version: resource_version_i64.max(1).cast_unsigned(),
    }
}

fn row_to_policy_record(row: sqlx::postgres::PgRow) -> PersistenceResult<PolicyRecord> {
    let id: String = row.get("id");
    let sandbox_id: String = row.get("scope");
    let version: i64 = row.get("version");
    let status: String = row.get("status");
    let payload: Vec<u8> = row.get("payload");
    let created_at_ms: i64 = row.get("created_at_ms");
    policy_record_from_parts(id, sandbox_id, version, status, &payload, created_at_ms)
}

fn row_to_draft_chunk_record(row: sqlx::postgres::PgRow) -> PersistenceResult<DraftChunkRecord> {
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
