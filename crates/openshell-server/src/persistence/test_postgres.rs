// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Disposable `PostgreSQL` schemas for `#[ignore]`d backend tests.

use super::Store;

/// Names the disposable `PostgreSQL` database for `#[ignore]`d tests.
/// `mise run test:rust:postgres` always exports it.
pub const TEST_POSTGRES_URL_ENV: &str = "OPENSHELL_TEST_POSTGRES_URL";

/// A uniquely named schema. Stores connected through it see only that schema.
pub struct TestSchema {
    admin: sqlx::PgPool,
    schema: String,
    url: String,
}

impl TestSchema {
    /// Create a schema named `<prefix>_<uuid>` in the database named by
    /// [`TEST_POSTGRES_URL_ENV`].
    ///
    /// Panics when the variable is unset; callers are `#[ignore]`d.
    pub async fn create(prefix: &str) -> Self {
        let base = std::env::var(TEST_POSTGRES_URL_ENV).unwrap_or_else(|_| {
            panic!(
                "{TEST_POSTGRES_URL_ENV} must name a disposable PostgreSQL database; \
                 run mise run test:rust:postgres"
            )
        });
        assert!(
            base.starts_with("postgres"),
            "{TEST_POSTGRES_URL_ENV} must be a postgres:// URL"
        );
        let schema = format!("{prefix}_{}", uuid::Uuid::new_v4().simple());
        let admin = sqlx::PgPool::connect(&base)
            .await
            .expect("connect to the disposable PostgreSQL database");
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await
            .expect("create the test schema");
        let mut url = url::Url::parse(&base).expect("parse the PostgreSQL URL");
        url.query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"));
        Self {
            admin,
            schema,
            url: url.into(),
        }
    }

    /// Connection URL scoped to this schema.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// A new store with its own pool, as a separate gateway replica would
    /// have. Runs migrations.
    pub async fn connect_store(&self) -> Store {
        Store::connect(&self.url)
            .await
            .expect("connect a store to the test schema")
    }

    /// Drops only this test's schema.
    pub async fn drop_schema(self) {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            self.schema
        )))
        .execute(&self.admin)
        .await
        .expect("drop the test schema");
        self.admin.close().await;
    }
}
