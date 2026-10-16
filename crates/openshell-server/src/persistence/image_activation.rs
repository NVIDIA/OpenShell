// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Additional, fail-closed deployment checks for operator-activated image updates.
//!
//! These snapshots are not a durable fence or proof that old processes have
//! stopped. Membership can expire, gateways need not advertise peer endpoints,
//! and a backend can connect after the check. The explicit operator activation
//! must attest that incompatible gateways have been drained and retired. The
//! old-understood pending-operation interlock, not these observations, protects
//! an accepted image mutation from a subsequent legacy Start.

use super::{ObjectRecord, PersistenceError, PersistenceResult, Store, map_db_error};
use crate::gateway_members::MEMBER_TTL;
use openshell_core::time::now_ms;

/// Compatibility marker advertised by both gateway `PostgreSQL` connection pools.
///
/// This marker describes a protocol, not an exact build version. It is neither
/// authentication nor a security boundary: database clients can set it too.
pub(super) const IMAGE_UPDATE_APPLICATION_NAME: &str = "openshell-image-update-v1";

const MEMBER_OBJECT_TYPE: &str = "gateway_member";
const MEMBER_LIMIT: u32 = 1024;

impl Store {
    /// Reject observable incompatible or unknown gateway deployment participants.
    ///
    /// The caller separately enforces the default-off operator activation flag.
    /// `SQLite` returns success under its supported single-gateway deployment
    /// contract; this does not enforce process exclusion for a shared file.
    /// `PostgreSQL` checks every client backend in this database, not merely
    /// registered peers, and then strictly checks all fresh membership records.
    /// Administrative clients without the marker also prevent activation. Any
    /// database read failure propagates rather than granting compatibility.
    pub async fn ensure_image_update_deployment_compatible(&self) -> PersistenceResult<()> {
        let Self::Postgres(store) = self else {
            return Ok(());
        };

        let incompatible_backend: bool = sqlx::query_scalar(
            r"
SELECT EXISTS (
    SELECT 1 FROM pg_stat_activity
    WHERE datname = current_database()
      AND (backend_type = 'client backend' OR backend_type IS NULL)
      AND application_name IS DISTINCT FROM $1
)
",
        )
        .bind(IMAGE_UPDATE_APPLICATION_NAME)
        .fetch_one(&store.pool)
        .await
        .map_err(|error| map_db_error(&error))?;
        if incompatible_backend {
            return Err(PersistenceError::Config(
                "sandbox image updates require a uniformly compatible gateway deployment; \
                 a PostgreSQL client backend has an unknown or legacy image-update protocol"
                    .into(),
            ));
        }

        // One extra row distinguishes a complete bounded snapshot from a
        // truncated listing. Never silently treat uninspected rows as compatible.
        let records = self
            .list_by_type(MEMBER_OBJECT_TYPE, MEMBER_LIMIT + 1, 0)
            .await?;
        ensure_live_members_compatible(&records, now_ms())
    }
}

fn ensure_live_members_compatible(records: &[ObjectRecord], now: i64) -> PersistenceResult<()> {
    if records.len() > MEMBER_LIMIT as usize {
        return Err(PersistenceError::Config(
            "cannot establish image-update deployment compatibility: gateway membership listing exceeds its limit"
                .into(),
        ));
    }
    let ttl_ms = i64::try_from(MEMBER_TTL.as_millis()).unwrap_or(i64::MAX);
    for record in records {
        // Match membership liveness semantics, including clock-skew clamping.
        // Ignoring expired records is not evidence that their processes stopped.
        let age_ms = now.saturating_sub(record.updated_at_ms).max(0);
        if age_ms >= ttl_ms {
            continue;
        }
        let member: serde_json::Map<String, serde_json::Value> =
            serde_json::from_slice(&record.payload).map_err(|_| {
                PersistenceError::Config(
                    "cannot establish image-update deployment compatibility: a live gateway membership record is not a valid JSON object"
                        .into(),
                )
            })?;
        let replica_id = member.get("replica_id").and_then(serde_json::Value::as_str);
        let protocol = member
            .get("image_update_protocol")
            .and_then(serde_json::Value::as_u64);
        if replica_id.is_none_or(|id| id.trim().is_empty()) || protocol != Some(1) {
            return Err(PersistenceError::Config(
                "sandbox image updates require every live gateway membership record to advertise image-update protocol 1 and a nonempty replica id"
                    .into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(payload: &[u8], updated_at_ms: i64) -> ObjectRecord {
        ObjectRecord {
            object_type: MEMBER_OBJECT_TYPE.into(),
            id: "gateway-member:gw-0".into(),
            name: "gw-0".into(),
            workspace: String::new(),
            payload: payload.to_vec(),
            created_at_ms: updated_at_ms,
            updated_at_ms,
            labels: None,
            resource_version: 1,
        }
    }

    #[tokio::test]
    async fn sqlite_uses_the_supported_single_gateway_contract() {
        let store = super::super::test_store().await;
        store
            .ensure_image_update_deployment_compatible()
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires a disposable PostgreSQL database and CREATEDB privileges in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
    async fn postgres_image_activation_checks_client_backends_and_live_members() {
        use super::super::test_postgres::TEST_POSTGRES_URL_ENV;
        use super::super::{MutationLockSet, WriteCondition};
        use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
        use std::time::Duration;

        // This check intentionally includes every backend in a database. A
        // disposable schema would share unmarked test-control/other-test
        // sessions and make its positive assertions dependent on test order.
        // Keep the unmarked control pool in the original database instead.
        let base = std::env::var(TEST_POSTGRES_URL_ENV)
            .expect("OPENSHELL_TEST_POSTGRES_URL must name a disposable PostgreSQL database");
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&base)
            .await
            .expect("connect to the test-control database");
        let database = format!("image_activation_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {database}")))
            .execute(&admin)
            .await
            .expect("create a dedicated activation-test database (requires CREATEDB)");
        let mut url = url::Url::parse(&base).expect("parse the test PostgreSQL URL");
        url.set_path(&format!("/{database}"));
        let first = Store::connect(url.as_str()).await.unwrap();
        let second = Store::connect(url.as_str()).await.unwrap();

        // Exercise both data pools and a lazily opened mutation-lock pool.
        let guard = second
            .acquire_distributed_mutation_guard(
                &MutationLockSet::sandbox_lifecycle("activation-test-sandbox"),
                tokio::time::Instant::now() + Duration::from_secs(10),
            )
            .await
            .unwrap();
        first
            .ensure_image_update_deployment_compatible()
            .await
            .expect("compatible data and lock pools must pass despite the other database's control pool");
        drop(guard);

        // No membership record is needed to detect an old or administrative
        // client. Do not weaken the production filter to exempt this session.
        let legacy_options = url
            .as_str()
            .parse::<PgConnectOptions>()
            .unwrap()
            .application_name("legacy-image-activation-test");
        let legacy = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(legacy_options)
            .await
            .unwrap();
        assert!(matches!(
            first.ensure_image_update_deployment_compatible().await,
            Err(PersistenceError::Config(_))
        ));
        legacy.close().await;

        // SQLx closing its socket can precede the server removing the backend.
        // Bound this wait instead of depending on a fixed scheduling delay.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match first.ensure_image_update_deployment_compatible().await {
                    Ok(()) => break,
                    Err(PersistenceError::Config(_)) => {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    Err(error) => panic!("compatibility read failed: {error}"),
                }
            }
        })
        .await
        .expect("closed legacy backend must disappear from pg_stat_activity");

        let member = first
            .put_if(
                MEMBER_OBJECT_TYPE,
                "gateway-member:legacy",
                "legacy",
                "",
                br#"{"replica_id":"legacy"}"#,
                None,
                WriteCondition::MustCreate,
            )
            .await
            .unwrap();
        assert!(matches!(
            first.ensure_image_update_deployment_compatible().await,
            Err(PersistenceError::Config(_))
        ));
        first
            .put_if(
                MEMBER_OBJECT_TYPE,
                "gateway-member:legacy",
                "legacy",
                "",
                br#"{"replica_id":"legacy","image_update_protocol":1}"#,
                None,
                WriteCondition::MatchResourceVersion(member.resource_version),
            )
            .await
            .unwrap();
        first
            .ensure_image_update_deployment_compatible()
            .await
            .unwrap();

        first.close().await;
        assert!(matches!(
            first.ensure_image_update_deployment_compatible().await,
            Err(PersistenceError::Database(_))
        ));
        second.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE {database} WITH (FORCE)"
        )))
        .execute(&admin)
        .await
        .expect("drop the isolated activation-test database");
        admin.close().await;
    }

    #[test]
    fn compatible_live_members_and_empty_snapshot_pass() {
        assert!(ensure_live_members_compatible(&[], 100).is_ok());
        let member = record(
            br#"{"replica_id":"gw-0","peer_endpoint":"https://gw-0:8443","image_update_protocol":1}"#,
            100,
        );
        assert!(ensure_live_members_compatible(&[member], 100).is_ok());
    }

    #[test]
    fn malformed_missing_unknown_or_ill_typed_protocols_fail_closed() {
        let invalid: &[&[u8]] = &[
            b"not JSON",
            br"[]",
            br#"["gw-0",1]"#,
            br"null",
            br#"{"replica_id":"gw-0"}"#,
            br#"{"replica_id":"gw-0","image_update_protocol":0}"#,
            br#"{"replica_id":"gw-0","image_update_protocol":2}"#,
            br#"{"replica_id":"gw-0","image_update_protocol":"1"}"#,
            br#"{"replica_id":"gw-0","image_update_protocol":true}"#,
            br#"{"replica_id":"gw-0","image_update_protocol":1.0}"#,
            br#"{"image_update_protocol":1}"#,
            br#"{"replica_id":"","image_update_protocol":1}"#,
            br#"{"replica_id":"  ","image_update_protocol":1}"#,
        ];
        for payload in invalid {
            assert!(ensure_live_members_compatible(&[record(payload, 100)], 100).is_err());
        }
    }

    #[test]
    fn expired_records_are_not_considered_live_but_future_timestamps_are() {
        let ttl_ms = i64::try_from(MEMBER_TTL.as_millis()).unwrap();
        assert!(ensure_live_members_compatible(&[record(b"legacy", 100)], 100 + ttl_ms).is_ok());
        assert!(
            ensure_live_members_compatible(&[record(b"legacy", 100)], 100 + ttl_ms - 1).is_err()
        );
        assert!(ensure_live_members_compatible(&[record(b"legacy", 200)], 100).is_err());
    }

    #[test]
    fn any_incompatible_live_member_rejects_the_snapshot() {
        let compatible = record(br#"{"replica_id":"gw-0","image_update_protocol":1}"#, 100);
        let legacy = record(br#"{"replica_id":"gw-1"}"#, 100);
        assert!(ensure_live_members_compatible(&[compatible, legacy], 100).is_err());
    }

    #[test]
    fn listing_truncation_fails_closed_even_when_extra_rows_are_expired() {
        let records = vec![record(b"legacy", 0); MEMBER_LIMIT as usize + 1];
        let now = i64::try_from(MEMBER_TTL.as_millis()).unwrap();
        assert!(ensure_live_members_compatible(&records, now).is_err());
    }
}
