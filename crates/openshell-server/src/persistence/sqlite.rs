// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{
    DraftChunkRecord, ObjectRecord, PersistenceResult, PolicyRecord, current_time_ms, map_db_error,
    map_migrate_error,
};
use crate::policy_store::{
    draft_chunk_payload_from_record, draft_chunk_record_from_parts, policy_payload_from_record,
    policy_record_from_parts,
};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};
use std::str::FromStr;

static SQLITE_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/sqlite");

const POLICY_OBJECT_TYPE: &str = "sandbox_policy";
const DRAFT_CHUNK_OBJECT_TYPE: &str = "draft_policy_chunk";

#[derive(Debug, Clone)]
pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    pub async fn connect(url: &str) -> PersistenceResult<Self> {
        let is_in_memory = url.contains(":memory:") || url.contains("mode=memory");
        let max_connections = if is_in_memory { 1 } else { 5 };

        let options = SqliteConnectOptions::from_str(url)
            .map_err(|e| map_db_error(&e))?
            .create_if_missing(true);

        let mut pool_options = SqlitePoolOptions::new()
            .max_connections(max_connections)
            .min_connections(max_connections);

        if is_in_memory {
            pool_options = pool_options.idle_timeout(None).max_lifetime(None);
        }

        let pool = pool_options
            .connect_with(options)
            .await
            .map_err(|e| map_db_error(&e))?;

        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> PersistenceResult<()> {
        SQLITE_MIGRATOR
            .run(&self.pool)
            .await
            .map_err(|e| map_migrate_error(&e))
    }

    pub async fn put(
        &self,
        object_type: &str,
        id: &str,
        name: &str,
        payload: &[u8],
        labels: Option<&str>,
    ) -> PersistenceResult<()> {
        let now_ms = current_time_ms()?;

        sqlx::query(
            r#"
INSERT INTO "objects" ("object_type", "id", "name", "payload", "created_at_ms", "updated_at_ms", "labels")
VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6)
ON CONFLICT ("object_type", "name") WHERE "name" IS NOT NULL DO UPDATE SET
    "payload" = excluded."payload",
    "updated_at_ms" = excluded."updated_at_ms",
    "labels" = excluded."labels"
"#,
        )
        .bind(object_type)
        .bind(id)
        .bind(name)
        .bind(payload)
        .bind(now_ms)
        .bind(labels.unwrap_or("{}"))
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
            r#"
SELECT "object_type", "id", "name", "payload", "created_at_ms", "updated_at_ms", "labels"
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
        name: &str,
    ) -> PersistenceResult<Option<ObjectRecord>> {
        let row = sqlx::query(
            r#"
SELECT "object_type", "id", "name", "payload", "created_at_ms", "updated_at_ms", "labels"
FROM "objects"
WHERE "object_type" = ?1 AND "name" = ?2
"#,
        )
        .bind(object_type)
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

    pub async fn delete_by_name(&self, object_type: &str, name: &str) -> PersistenceResult<bool> {
        let result = sqlx::query(
            r#"
DELETE FROM "objects"
WHERE "object_type" = ?1 AND "name" = ?2
"#,
        )
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
            r#"
SELECT "object_type", "id", "name", "payload", "created_at_ms", "updated_at_ms", "labels"
FROM "objects"
WHERE "object_type" = ?1
ORDER BY "created_at_ms" ASC, "name" ASC
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
    pub async fn list_with_selector(
        &self,
        object_type: &str,
        label_selector: &str,
        limit: u32,
        offset: u32,
    ) -> PersistenceResult<Vec<ObjectRecord>> {
        use super::parse_label_selector;

        let required_labels = parse_label_selector(label_selector)?;
        let all_records = self.list(object_type, u32::MAX, 0).await?;

        let filtered: Vec<ObjectRecord> = all_records
            .into_iter()
            .filter(|record| {
                let labels_json = record.labels.as_deref().unwrap_or("{}");
                let labels: std::collections::HashMap<String, String> =
                    serde_json::from_str(labels_json).unwrap_or_default();

                required_labels
                    .iter()
                    .all(|(key, value)| labels.get(key).map(|v| v == value).unwrap_or(false))
            })
            .skip(offset as usize)
            .take(limit as usize)
            .collect();

        Ok(filtered)
    }
    pub async fn put_policy_revision(
        &self,
        id: &str,
        sandbox_id: &str,
        version: i64,
        payload: &[u8],
        hash: &str,
    ) -> PersistenceResult<()> {
        let now_ms = current_time_ms()?;
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
            r#"
INSERT INTO "objects" (
    "object_type", "id", "scope", "version", "status", "payload", "created_at_ms", "updated_at_ms"
)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
"#,
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
        let now_ms = current_time_ms()?;

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
        let now_ms = current_time_ms()?;
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

    pub async fn put_draft_chunk(&self, chunk: &DraftChunkRecord) -> PersistenceResult<()> {
        let payload = draft_chunk_payload_from_record(chunk)?;
        sqlx::query(
            r#"
INSERT INTO "objects" (
    "object_type", "id", "scope", "status", "dedup_key", "hit_count", "payload", "created_at_ms", "updated_at_ms"
)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
ON CONFLICT ("object_type", "scope", "dedup_key") WHERE "dedup_key" IS NOT NULL DO UPDATE SET
    "hit_count" = "objects"."hit_count" + excluded."hit_count",
    "updated_at_ms" = excluded."updated_at_ms"
"#,
        )
        .bind(DRAFT_CHUNK_OBJECT_TYPE)
        .bind(&chunk.id)
        .bind(&chunk.sandbox_id)
        .bind(&chunk.status)
        .bind(draft_chunk_dedup_key(chunk))
        .bind(i64::from(chunk.hit_count))
        .bind(payload)
        .bind(chunk.first_seen_ms)
        .bind(chunk.last_seen_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(())
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
    ) -> PersistenceResult<bool> {
        let Some(mut record) = self.get_draft_chunk(id).await? else {
            return Ok(false);
        };

        record.status = status.to_string();
        record.decided_at_ms = decided_at_ms;
        record.last_seen_ms = current_time_ms()?;
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
        record.last_seen_ms = current_time_ms()?;
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

fn draft_chunk_dedup_key(chunk: &DraftChunkRecord) -> String {
    format!("{}|{}|{}", chunk.host, chunk.port, chunk.binary)
}

fn row_to_object_record(row: sqlx::sqlite::SqliteRow) -> ObjectRecord {
    ObjectRecord {
        object_type: row.get("object_type"),
        id: row.get("id"),
        name: row.get("name"),
        payload: row.get("payload"),
        created_at_ms: row.get("created_at_ms"),
        updated_at_ms: row.get("updated_at_ms"),
        labels: row.get("labels"),
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
