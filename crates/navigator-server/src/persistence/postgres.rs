// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{
    DenialSummaryRecord, DraftChunkRecord, ObjectRecord, PolicyRecord, current_time_ms,
    map_db_error, map_migrate_error,
};
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

    // -------------------------------------------------------------------
    // Draft policy chunk operations
    // -------------------------------------------------------------------

    pub async fn put_draft_chunk(&self, chunk: &DraftChunkRecord) -> Result<()> {
        sqlx::query(
            r"
INSERT INTO draft_policy_chunks
    (id, sandbox_id, draft_version, status, stage, rule_name,
     proposed_rule, rationale, security_notes, confidence,
     denial_refs, supersedes_chunk_id, analysis_mode, created_at_ms,
     decided_at_ms, decided_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
",
        )
        .bind(&chunk.id)
        .bind(&chunk.sandbox_id)
        .bind(chunk.draft_version)
        .bind(&chunk.status)
        .bind(&chunk.stage)
        .bind(&chunk.rule_name)
        .bind(&chunk.proposed_rule)
        .bind(&chunk.rationale)
        .bind(&chunk.security_notes)
        .bind(chunk.confidence)
        .bind(&chunk.denial_refs)
        .bind(&chunk.supersedes_chunk_id)
        .bind(&chunk.analysis_mode)
        .bind(chunk.created_at_ms)
        .bind(chunk.decided_at_ms)
        .bind(&chunk.decided_by)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(())
    }

    pub async fn get_draft_chunk(&self, id: &str) -> Result<Option<DraftChunkRecord>> {
        let row = sqlx::query(
            r"
SELECT * FROM draft_policy_chunks WHERE id = $1
",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(row.map(row_to_draft_chunk_record))
    }

    pub async fn list_draft_chunks(
        &self,
        sandbox_id: &str,
        status_filter: Option<&str>,
    ) -> Result<Vec<DraftChunkRecord>> {
        let rows = if let Some(status) = status_filter {
            sqlx::query(
                r"
SELECT * FROM draft_policy_chunks
WHERE sandbox_id = $1 AND status = $2
ORDER BY created_at_ms DESC
",
            )
            .bind(sandbox_id)
            .bind(status)
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query(
                r"
SELECT * FROM draft_policy_chunks
WHERE sandbox_id = $1
ORDER BY created_at_ms DESC
",
            )
            .bind(sandbox_id)
            .fetch_all(&self.pool)
            .await
        }
        .map_err(|e| map_db_error(&e))?;

        Ok(rows.into_iter().map(row_to_draft_chunk_record).collect())
    }

    pub async fn update_draft_chunk_status(
        &self,
        id: &str,
        status: &str,
        decided_at_ms: Option<i64>,
    ) -> Result<bool> {
        let result = sqlx::query(
            r"
UPDATE draft_policy_chunks
SET status = $2, decided_at_ms = $3
WHERE id = $1
",
        )
        .bind(id)
        .bind(status)
        .bind(decided_at_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn update_draft_chunk_rule(&self, id: &str, proposed_rule: &[u8]) -> Result<bool> {
        let result = sqlx::query(
            r"
UPDATE draft_policy_chunks
SET proposed_rule = $2
WHERE id = $1 AND status = 'pending'
",
        )
        .bind(id)
        .bind(proposed_rule)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn delete_draft_chunks(&self, sandbox_id: &str, status: &str) -> Result<u64> {
        let result = sqlx::query(
            r"
DELETE FROM draft_policy_chunks
WHERE sandbox_id = $1 AND status = $2
",
        )
        .bind(sandbox_id)
        .bind(status)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected())
    }

    pub async fn get_draft_version(&self, sandbox_id: &str) -> Result<i64> {
        let row = sqlx::query(
            r"
SELECT COALESCE(MAX(draft_version), 0) as max_version
FROM draft_policy_chunks
WHERE sandbox_id = $1
",
        )
        .bind(sandbox_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(row.get("max_version"))
    }

    // -------------------------------------------------------------------
    // Denial summary operations
    // -------------------------------------------------------------------

    pub async fn upsert_denial_summary(&self, s: &DenialSummaryRecord) -> Result<()> {
        sqlx::query(
            r"
INSERT INTO denial_summaries
    (id, sandbox_id, host, port, binary, ancestors, deny_reason,
     first_seen_ms, last_seen_ms, count, suppressed_count, total_count,
     sample_cmdlines, binary_sha256, persistent, denial_stage,
     resolved_ips, is_private_ip, l7_request_samples, l7_inspection_active,
     status, created_at_ms, updated_at_ms)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
        $17, $18, $19, $20, $21, $22, $23)
ON CONFLICT (sandbox_id, host, port, binary) DO UPDATE SET
    last_seen_ms = excluded.last_seen_ms,
    count = excluded.count,
    suppressed_count = excluded.suppressed_count,
    total_count = excluded.total_count,
    sample_cmdlines = excluded.sample_cmdlines,
    persistent = excluded.persistent,
    denial_stage = excluded.denial_stage,
    l7_request_samples = excluded.l7_request_samples,
    l7_inspection_active = excluded.l7_inspection_active,
    updated_at_ms = excluded.updated_at_ms
",
        )
        .bind(&s.id)
        .bind(&s.sandbox_id)
        .bind(&s.host)
        .bind(s.port)
        .bind(&s.binary)
        .bind(&s.ancestors)
        .bind(&s.deny_reason)
        .bind(s.first_seen_ms)
        .bind(s.last_seen_ms)
        .bind(s.count)
        .bind(s.suppressed_count)
        .bind(s.total_count)
        .bind(&s.sample_cmdlines)
        .bind(&s.binary_sha256)
        .bind(s.persistent)
        .bind(&s.denial_stage)
        .bind(&s.resolved_ips)
        .bind(s.is_private_ip)
        .bind(&s.l7_request_samples)
        .bind(s.l7_inspection_active)
        .bind(&s.status)
        .bind(s.created_at_ms)
        .bind(s.updated_at_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(())
    }

    pub async fn list_denial_summaries(
        &self,
        sandbox_id: &str,
        status_filter: Option<&str>,
    ) -> Result<Vec<DenialSummaryRecord>> {
        let rows = if let Some(status) = status_filter {
            sqlx::query(
                r"
SELECT * FROM denial_summaries
WHERE sandbox_id = $1 AND status = $2
ORDER BY total_count DESC
",
            )
            .bind(sandbox_id)
            .bind(status)
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query(
                r"
SELECT * FROM denial_summaries
WHERE sandbox_id = $1
ORDER BY total_count DESC
",
            )
            .bind(sandbox_id)
            .fetch_all(&self.pool)
            .await
        }
        .map_err(|e| map_db_error(&e))?;

        Ok(rows.into_iter().map(row_to_denial_summary_record).collect())
    }

    pub async fn update_denial_summary_status(&self, id: &str, status: &str) -> Result<bool> {
        let now_ms = current_time_ms()?;
        let result = sqlx::query(
            r"
UPDATE denial_summaries
SET status = $2, updated_at_ms = $3
WHERE id = $1
",
        )
        .bind(id)
        .bind(status)
        .bind(now_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(result.rows_affected() > 0)
    }
}

fn row_to_draft_chunk_record(row: sqlx::postgres::PgRow) -> DraftChunkRecord {
    DraftChunkRecord {
        id: row.get("id"),
        sandbox_id: row.get("sandbox_id"),
        draft_version: row.get("draft_version"),
        status: row.get("status"),
        stage: row.get("stage"),
        rule_name: row.get("rule_name"),
        proposed_rule: row.get("proposed_rule"),
        rationale: row.get("rationale"),
        security_notes: row.get("security_notes"),
        confidence: row.get("confidence"),
        denial_refs: row.get("denial_refs"),
        supersedes_chunk_id: row.get("supersedes_chunk_id"),
        analysis_mode: row.get("analysis_mode"),
        created_at_ms: row.get("created_at_ms"),
        decided_at_ms: row.get("decided_at_ms"),
        decided_by: row.get("decided_by"),
    }
}

fn row_to_denial_summary_record(row: sqlx::postgres::PgRow) -> DenialSummaryRecord {
    DenialSummaryRecord {
        id: row.get("id"),
        sandbox_id: row.get("sandbox_id"),
        host: row.get("host"),
        port: row.get("port"),
        binary: row.get("binary"),
        ancestors: row.get("ancestors"),
        deny_reason: row.get("deny_reason"),
        first_seen_ms: row.get("first_seen_ms"),
        last_seen_ms: row.get("last_seen_ms"),
        count: row.get("count"),
        suppressed_count: row.get("suppressed_count"),
        total_count: row.get("total_count"),
        sample_cmdlines: row.get("sample_cmdlines"),
        binary_sha256: row.get("binary_sha256"),
        persistent: row.get("persistent"),
        denial_stage: row.get("denial_stage"),
        resolved_ips: row.get("resolved_ips"),
        is_private_ip: row.get("is_private_ip"),
        l7_request_samples: row.get("l7_request_samples"),
        l7_inspection_active: row.get("l7_inspection_active"),
        status: row.get("status"),
        created_at_ms: row.get("created_at_ms"),
        updated_at_ms: row.get("updated_at_ms"),
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
