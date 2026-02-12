use super::{ObjectRecord, current_time_ms, map_db_error, map_migrate_error};
use navigator_core::Result;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{Row, SqlitePool};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    pub async fn connect(url: &str) -> Result<Self> {
        let max_connections = if url.contains(":memory:") || url.contains("mode=memory") {
            1
        } else {
            5
        };

        let pool = SqlitePoolOptions::new()
            .max_connections(max_connections)
            .min_connections(max_connections)
            .connect(url)
            .await
            .map_err(|e| map_db_error(&e))?;

        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> Result<()> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("migrations")
            .join("sqlite");
        let migrator = sqlx::migrate::Migrator::new(path)
            .await
            .map_err(|e| map_migrate_error(&e))?;
        migrator
            .run(&self.pool)
            .await
            .map_err(|e| map_migrate_error(&e))
    }

    pub async fn put(&self, object_type: &str, id: &str, payload: &[u8]) -> Result<()> {
        let now_ms = current_time_ms()?;

        sqlx::query(
            r#"
INSERT INTO "objects" ("object_type", "id", "payload", "created_at_ms", "updated_at_ms")
VALUES (?1, ?2, ?3, ?4, ?4)
ON CONFLICT ("object_type", "id")
DO UPDATE SET "payload" = excluded."payload", "updated_at_ms" = excluded."updated_at_ms"
"#,
        )
        .bind(object_type)
        .bind(id)
        .bind(payload)
        .bind(now_ms)
        .execute(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;
        Ok(())
    }

    pub async fn get(&self, object_type: &str, id: &str) -> Result<Option<ObjectRecord>> {
        let row = sqlx::query(
            r#"
SELECT "object_type", "id", "payload", "created_at_ms", "updated_at_ms"
FROM "objects"
WHERE "object_type" = ?1 AND "id" = ?2
"#,
        )
        .bind(object_type)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_db_error(&e))?;

        Ok(row.map(|row| ObjectRecord {
            object_type: row.get("object_type"),
            id: row.get("id"),
            payload: row.get("payload"),
            created_at_ms: row.get("created_at_ms"),
            updated_at_ms: row.get("updated_at_ms"),
        }))
    }

    pub async fn delete(&self, object_type: &str, id: &str) -> Result<bool> {
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

    pub async fn list(
        &self,
        object_type: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<ObjectRecord>> {
        let rows = sqlx::query(
            r#"
SELECT "object_type", "id", "payload", "created_at_ms", "updated_at_ms"
FROM "objects"
WHERE "object_type" = ?1
ORDER BY "created_at_ms" ASC, "id" ASC
LIMIT ?2 OFFSET ?3
"#,
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
                payload: row.get("payload"),
                created_at_ms: row.get("created_at_ms"),
                updated_at_ms: row.get("updated_at_ms"),
            })
            .collect();

        Ok(records)
    }
}
