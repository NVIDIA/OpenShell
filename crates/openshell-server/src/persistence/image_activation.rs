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

use super::{ObjectRecord, PersistenceError, PersistenceResult, Store};
use crate::gateway_members::{MEMBER_TTL, SANDBOX_UPDATE_PROTOCOL};
use openshell_core::time::now_ms;

const MEMBER_OBJECT_TYPE: &str = "gateway_member";
const MEMBER_LIMIT: u32 = 1024;

impl Store {
    /// Reject observable incompatible or unknown gateway deployment participants.
    ///
    /// The caller separately enforces the default-off operator activation flag.
    /// `SQLite` returns success under its supported single-gateway deployment
    /// contract; this does not enforce process exclusion for a shared file.
    /// `PostgreSQL` checks fresh gateway membership records. Administrative,
    /// monitoring, and backup sessions are not gateway participants. Operator
    /// activation attests that unregistered legacy processes have been retired.
    /// Recovery of accepted operations does not use this admission check.
    pub async fn ensure_image_update_deployment_compatible(&self) -> PersistenceResult<()> {
        let Self::Postgres(_) = self else {
            return Ok(());
        };

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
            .get("sandbox_update_protocol")
            .and_then(serde_json::Value::as_u64);
        if replica_id.is_none_or(|id| id.trim().is_empty())
            || protocol != Some(u64::from(SANDBOX_UPDATE_PROTOCOL))
        {
            return Err(PersistenceError::Config(format!(
                "sandbox updates require every live gateway membership record to advertise sandbox-update protocol {SANDBOX_UPDATE_PROTOCOL} and a nonempty replica id"
            )));
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
    #[ignore = "requires OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
    async fn postgres_activation_ignores_administrative_sessions_and_preserves_application_name() {
        use super::super::test_postgres::TestSchema;
        let schema = TestSchema::create("sandbox_update_activation").await;
        let mut url = url::Url::parse(schema.url()).unwrap();
        url.query_pairs_mut()
            .append_pair("application_name", "operator-custom-name");
        let store = Store::connect(url.as_str()).await.unwrap();
        let Store::Postgres(pg) = &store else {
            unreachable!()
        };
        let name: String = sqlx::query_scalar("SHOW application_name")
            .fetch_one(&pg.pool)
            .await
            .unwrap();
        assert_eq!(name, "operator-custom-name");
        // TestSchema's unmarked admin connection remains open in this database.
        store
            .ensure_image_update_deployment_compatible()
            .await
            .unwrap();
        let index = crate::gateway_members::GatewayMemberIndex::new(
            std::sync::Arc::new(store.clone()),
            MEMBER_TTL,
        );
        index
            .register("compatible", "https://gateway:8443")
            .await
            .unwrap();
        store
            .ensure_image_update_deployment_compatible()
            .await
            .unwrap();
        store
            .put_if(
                MEMBER_OBJECT_TYPE,
                "gateway-member:legacy",
                "legacy",
                "",
                br#"{"replica_id":"legacy"}"#,
                None,
                super::super::WriteCondition::MustCreate,
            )
            .await
            .unwrap();
        assert!(matches!(
            store.ensure_image_update_deployment_compatible().await,
            Err(PersistenceError::Config(_))
        ));
        store.close().await;
        schema.drop_schema().await;
    }

    #[test]
    fn compatible_live_members_and_empty_snapshot_pass() {
        assert!(ensure_live_members_compatible(&[], 100).is_ok());
        let member = record(
            br#"{"replica_id":"gw-0","peer_endpoint":"https://gw-0:8443","sandbox_update_protocol":1}"#,
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
            br#"{"replica_id":"gw-0","sandbox_update_protocol":0}"#,
            br#"{"replica_id":"gw-0","sandbox_update_protocol":2}"#,
            br#"{"replica_id":"gw-0","sandbox_update_protocol":"1"}"#,
            br#"{"replica_id":"gw-0","sandbox_update_protocol":true}"#,
            br#"{"replica_id":"gw-0","sandbox_update_protocol":1.0}"#,
            br#"{"sandbox_update_protocol":1}"#,
            br#"{"replica_id":"","sandbox_update_protocol":1}"#,
            br#"{"replica_id":"  ","sandbox_update_protocol":1}"#,
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
        let compatible = record(br#"{"replica_id":"gw-0","sandbox_update_protocol":1}"#, 100);
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
