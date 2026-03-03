// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{ObjectRecord, PolicyRecord, current_time_ms, map_db_error, map_migrate_error};
use navigator_core::Result;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    pub async fn connect(url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(url)
            .await
            .map_err(|e| map_db_error(&e))?;

        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> Result<()> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("migrations")
            .join("postgres");
        let migrator = sqlx::migrate::Migrator::new(path)
            .await
            .map_err(|e| map_migrate_error(&e))?;
        migrator
            .run(&self.pool)
            .await
            .map_err(|e| map_migrate_error(&e))
    }

    pub async fn put(&self, object_type: &str, id: &str, name: &str, payload: &[u8]) -> Result<()> {
        let now_ms = current_time_ms()?;
        sqlx::query(
            r"
INSERT INTO objects (object_type, id, name, payload, created_at_ms, updated_at_ms)
VALUES ($1, $2, $3, $4, $5, $5)
ON CONFLICT (id) DO UPDATE SET
    payload = EXCLUDED.payload,
    updated_at_ms = EXCLUDED.updated_at_ms
WHERE objects.object_type = EXCLUDED.object_type
",
        )
        .bind(object_type)
        .bind(id)
        .bind(name)
        .bind(payload)
        .bind(now_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(())
    }

    pub async fn get(&self, object_type: &str, id: &str) -> Result<Option<ObjectRecord>> {
        let row = sqlx::query(
            r"
SELECT object_type, id, name, payload, created_at_ms, updated_at_ms
FROM objects
WHERE object_type = $1 AND id = $2
",
        )
        .bind(object_type)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(row.map(|row| ObjectRecord {
            object_type: row.get("object_type"),
            id: row.get("id"),
            name: row.get("name"),
            payload: row.get("payload"),
            created_at_ms: row.get("created_at_ms"),
            updated_at_ms: row.get("updated_at_ms"),
        }))
    }

    pub async fn get_by_name(&self, object_type: &str, name: &str) -> Result<Option<ObjectRecord>> {
        let row = sqlx::query(
            r"
SELECT object_type, id, name, payload, created_at_ms, updated_at_ms
FROM objects
WHERE object_type = $1 AND name = $2
",
        )
        .bind(object_type)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(row.map(|row| ObjectRecord {
            object_type: row.get("object_type"),
            id: row.get("id"),
            name: row.get("name"),
            payload: row.get("payload"),
            created_at_ms: row.get("created_at_ms"),
            updated_at_ms: row.get("updated_at_ms"),
        }))
    }

    pub async fn delete(&self, object_type: &str, id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM objects WHERE object_type = $1 AND id = $2")
            .bind(object_type)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn delete_by_name(&self, object_type: &str, name: &str) -> Result<bool> {
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
    ) -> Result<Vec<ObjectRecord>> {
        let rows = sqlx::query(
            r"
SELECT object_type, id, name, payload, created_at_ms, updated_at_ms
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

        let records = rows
            .into_iter()
            .map(|row| ObjectRecord {
                object_type: row.get("object_type"),
                id: row.get("id"),
                name: row.get("name"),
                payload: row.get("payload"),
                created_at_ms: row.get("created_at_ms"),
                updated_at_ms: row.get("updated_at_ms"),
            })
            .collect();

        Ok(records)
    }

    // -------------------------------------------------------------------
    // Policy revision operations
    // -------------------------------------------------------------------

    pub async fn put_policy_revision(
        &self,
        id: &str,
        sandbox_id: &str,
        version: i64,
        payload: &[u8],
        hash: &str,
    ) -> Result<()> {
        let now_ms = current_time_ms()?;
        sqlx::query(
            r"
INSERT INTO sandbox_policies (id, sandbox_id, version, policy_payload, policy_hash, status, created_at_ms)
VALUES ($1, $2, $3, $4, $5, 'pending', $6)
",
        )
        .bind(id)
        .bind(sandbox_id)
        .bind(version)
        .bind(payload)
        .bind(hash)
        .bind(now_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(())
    }

    pub async fn get_latest_policy(&self, sandbox_id: &str) -> Result<Option<PolicyRecord>> {
        let row = sqlx::query(
            r"
SELECT id, sandbox_id, version, policy_payload, policy_hash, status, load_error, created_at_ms, loaded_at_ms
FROM sandbox_policies
WHERE sandbox_id = $1
ORDER BY version DESC
LIMIT 1
",
        )
        .bind(sandbox_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(row.map(row_to_policy_record))
    }

    pub async fn get_latest_loaded_policy(&self, sandbox_id: &str) -> Result<Option<PolicyRecord>> {
        let row = sqlx::query(
            r"
SELECT id, sandbox_id, version, policy_payload, policy_hash, status, load_error, created_at_ms, loaded_at_ms
FROM sandbox_policies
WHERE sandbox_id = $1 AND status = 'loaded'
ORDER BY version DESC
LIMIT 1
",
        )
        .bind(sandbox_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(row.map(row_to_policy_record))
    }

    pub async fn get_policy_by_version(
        &self,
        sandbox_id: &str,
        version: i64,
    ) -> Result<Option<PolicyRecord>> {
        let row = sqlx::query(
            r"
SELECT id, sandbox_id, version, policy_payload, policy_hash, status, load_error, created_at_ms, loaded_at_ms
FROM sandbox_policies
WHERE sandbox_id = $1 AND version = $2
",
        )
        .bind(sandbox_id)
        .bind(version)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(row.map(row_to_policy_record))
    }

    pub async fn list_policies(
        &self,
        sandbox_id: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<PolicyRecord>> {
        let rows = sqlx::query(
            r"
SELECT id, sandbox_id, version, policy_payload, policy_hash, status, load_error, created_at_ms, loaded_at_ms
FROM sandbox_policies
WHERE sandbox_id = $1
ORDER BY version DESC
LIMIT $2 OFFSET $3
",
        )
        .bind(sandbox_id)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(rows.into_iter().map(row_to_policy_record).collect())
    }

    pub async fn update_policy_status(
        &self,
        sandbox_id: &str,
        version: i64,
        status: &str,
        load_error: Option<&str>,
        loaded_at_ms: Option<i64>,
    ) -> Result<bool> {
        let result = sqlx::query(
            r"
UPDATE sandbox_policies
SET status = $3, load_error = $4, loaded_at_ms = $5
WHERE sandbox_id = $1 AND version = $2
",
        )
        .bind(sandbox_id)
        .bind(version)
        .bind(status)
        .bind(load_error)
        .bind(loaded_at_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn supersede_older_policies(
        &self,
        sandbox_id: &str,
        before_version: i64,
    ) -> Result<u64> {
        let result = sqlx::query(
            r"
UPDATE sandbox_policies
SET status = 'superseded'
WHERE sandbox_id = $1 AND version < $2 AND status IN ('pending', 'loaded')
",
        )
        .bind(sandbox_id)
        .bind(before_version)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected())
    }
}

fn row_to_policy_record(row: sqlx::postgres::PgRow) -> PolicyRecord {
    PolicyRecord {
        id: row.get("id"),
        sandbox_id: row.get("sandbox_id"),
        version: row.get("version"),
        policy_payload: row.get("policy_payload"),
        policy_hash: row.get("policy_hash"),
        status: row.get("status"),
        load_error: row.get("load_error"),
        created_at_ms: row.get("created_at_ms"),
        loaded_at_ms: row.get("loaded_at_ms"),
    }
}
