// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Durable mutation admission storage.
//!
//! Each caller bucket has a counter row, so admission does not count the bucket
//! on every request. Deletions never decrement it; once it reaches the limit,
//! admission recounts the bucket under the same per-bucket lock.

use super::{PersistenceResult, Store, WriteResult, current_time_ms, map_db_error};

pub const ADMISSION_OBJECT_TYPE: &str = "mutation_admission_v1";
const COUNTER_OBJECT_TYPE: &str = "mutation_admission_count_v1";

fn counter_id(bucket: &str) -> String {
    format!("mutation-admission-count:{bucket}")
}

/// A completed admission selected for expiry checks.
pub struct CompletedAdmission {
    pub id: String,
    pub payload: Vec<u8>,
}

impl Store {
    /// Insert an admission unless its bucket already holds `limit` admissions.
    ///
    /// Returns `Ok(None)` when the bucket is full. A duplicate name still
    /// returns [`super::PersistenceError::UniqueViolation`].
    pub(crate) async fn create_mutation_admission(
        &self,
        id: &str,
        name: &str,
        bucket: &str,
        payload: &[u8],
        limit: u32,
    ) -> PersistenceResult<Option<WriteResult>> {
        let now_ms = current_time_ms();
        let limit = i64::from(limit);
        let counter = counter_id(bucket);
        let admitted = match self {
            Self::Postgres(store) => {
                let mut tx = store.pool.begin().await.map_err(|e| map_db_error(&e))?;
                sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))")
                    .bind(ADMISSION_OBJECT_TYPE)
                    .bind(bucket)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| map_db_error(&e))?;
                let stored: Option<i64> = sqlx::query_scalar(
                    "SELECT hit_count FROM objects WHERE object_type = $1 AND id = $2",
                )
                .bind(COUNTER_OBJECT_TYPE)
                .bind(&counter)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| map_db_error(&e))?;
                let count = match stored {
                    Some(count) if count < limit => count,
                    _ => sqlx::query_scalar(
                        "SELECT COUNT(*) FROM objects WHERE object_type = $1 AND workspace = $2",
                    )
                    .bind(ADMISSION_OBJECT_TYPE)
                    .bind(bucket)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(|e| map_db_error(&e))?,
                };
                let admitted = count < limit;
                if admitted {
                    sqlx::query(
                        "INSERT INTO objects (object_type, id, name, workspace, payload, created_at_ms, updated_at_ms, labels, resource_version)
VALUES ($1, $2, $3, $4, $5, $6, $6, '{}'::jsonb, 1)",
                    )
                    .bind(ADMISSION_OBJECT_TYPE)
                    .bind(id)
                    .bind(name)
                    .bind(bucket)
                    .bind(payload)
                    .bind(now_ms)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| map_db_error(&e))?;
                }
                sqlx::query(
                    "INSERT INTO objects (object_type, id, workspace, payload, created_at_ms, updated_at_ms, labels, resource_version, hit_count)
VALUES ($1, $2, $3, ''::bytea, $4, $4, '{}'::jsonb, 1, $5)
ON CONFLICT (id) DO UPDATE SET hit_count = EXCLUDED.hit_count, updated_at_ms = EXCLUDED.updated_at_ms",
                )
                .bind(COUNTER_OBJECT_TYPE)
                .bind(&counter)
                .bind(bucket)
                .bind(now_ms)
                .bind(count + i64::from(admitted))
                .execute(&mut *tx)
                .await
                .map_err(|e| map_db_error(&e))?;
                tx.commit().await.map_err(|e| map_db_error(&e))?;
                admitted
            }
            Self::Sqlite(store) => {
                let mut tx = store
                    .pool
                    .begin_with("BEGIN IMMEDIATE")
                    .await
                    .map_err(|e| map_db_error(&e))?;
                let stored: Option<i64> = sqlx::query_scalar(
                    "SELECT hit_count FROM objects WHERE object_type = ?1 AND id = ?2",
                )
                .bind(COUNTER_OBJECT_TYPE)
                .bind(&counter)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| map_db_error(&e))?;
                let count = match stored {
                    Some(count) if count < limit => count,
                    _ => sqlx::query_scalar(
                        "SELECT COUNT(*) FROM objects WHERE object_type = ?1 AND workspace = ?2",
                    )
                    .bind(ADMISSION_OBJECT_TYPE)
                    .bind(bucket)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(|e| map_db_error(&e))?,
                };
                let admitted = count < limit;
                if admitted {
                    sqlx::query(
                        "INSERT INTO objects (object_type, id, name, workspace, payload, created_at_ms, updated_at_ms, labels, resource_version)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, '{}', 1)",
                    )
                    .bind(ADMISSION_OBJECT_TYPE)
                    .bind(id)
                    .bind(name)
                    .bind(bucket)
                    .bind(payload)
                    .bind(now_ms)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| map_db_error(&e))?;
                }
                sqlx::query(
                    "INSERT INTO objects (object_type, id, workspace, payload, created_at_ms, updated_at_ms, labels, resource_version, hit_count)
VALUES (?1, ?2, ?3, X'', ?4, ?4, '{}', 1, ?5)
ON CONFLICT (id) DO UPDATE SET hit_count = excluded.hit_count, updated_at_ms = excluded.updated_at_ms",
                )
                .bind(COUNTER_OBJECT_TYPE)
                .bind(&counter)
                .bind(bucket)
                .bind(now_ms)
                .bind(count + i64::from(admitted))
                .execute(&mut *tx)
                .await
                .map_err(|e| map_db_error(&e))?;
                tx.commit().await.map_err(|e| map_db_error(&e))?;
                admitted
            }
        };
        Ok(admitted.then_some(WriteResult {
            resource_version: 1,
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
        }))
    }

    /// List completed admissions last written at or before `cutoff_ms`, oldest
    /// first, through a partial index. Admissions are rewritten only once, on
    /// completion, so `resource_version > 1` marks them for every gateway version.
    pub(crate) async fn list_completed_mutation_admissions(
        &self,
        cutoff_ms: i64,
        limit: u32,
    ) -> PersistenceResult<Vec<CompletedAdmission>> {
        let rows: Vec<(String, Vec<u8>)> = match self {
            Self::Postgres(store) => {
                sqlx::query_as(
                    "SELECT id, payload FROM objects
WHERE object_type = 'mutation_admission_v1' AND resource_version > 1 AND updated_at_ms <= $1
ORDER BY updated_at_ms LIMIT $2",
                )
                .bind(cutoff_ms)
                .bind(i64::from(limit))
                .fetch_all(&store.pool)
                .await
            }
            Self::Sqlite(store) => {
                sqlx::query_as(
                    "SELECT id, payload FROM objects
WHERE object_type = 'mutation_admission_v1' AND resource_version > 1 AND updated_at_ms <= ?1
ORDER BY updated_at_ms LIMIT ?2",
                )
                .bind(cutoff_ms)
                .bind(i64::from(limit))
                .fetch_all(&store.pool)
                .await
            }
        }
        .map_err(|e| map_db_error(&e))?;
        Ok(rows
            .into_iter()
            .map(|(id, payload)| CompletedAdmission { id, payload })
            .collect())
    }

    /// Backdate an admission's last write to exercise expiry.
    #[cfg(test)]
    pub(crate) async fn backdate_mutation_admission(
        &self,
        id: &str,
        updated_at_ms: i64,
    ) -> PersistenceResult<()> {
        match self {
            Self::Postgres(store) => sqlx::query(
                "UPDATE objects SET updated_at_ms = $1 WHERE object_type = $2 AND id = $3",
            )
            .bind(updated_at_ms)
            .bind(ADMISSION_OBJECT_TYPE)
            .bind(id)
            .execute(&store.pool)
            .await
            .map(drop),
            Self::Sqlite(store) => sqlx::query(
                "UPDATE objects SET updated_at_ms = ?1 WHERE object_type = ?2 AND id = ?3",
            )
            .bind(updated_at_ms)
            .bind(ADMISSION_OBJECT_TYPE)
            .bind(id)
            .execute(&store.pool)
            .await
            .map(drop),
        }
        .map_err(|e| map_db_error(&e))
    }
}
