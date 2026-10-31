// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Creation-only mode and first-accepted policy, separate from public sandbox rows.

use super::{
    AtomicWrite, PersistenceError, PersistenceResult, Store, WriteResult, current_time_ms,
    map_db_error,
};
use crate::storage_proto::StoredFrozenSandboxPolicy;
use openshell_core::proto::{FrozenSandboxPolicy, Sandbox};
use openshell_core::{
    GetResourceVersion, ObjectId, ObjectLabels, ObjectName, ObjectWorkspace, SetResourceVersion,
};
use prost::Message;

pub const FROZEN_POLICY_OBJECT_TYPE: &str = "sandbox_frozen_policy";

pub fn frozen_policy_id(sandbox_id: &str) -> String {
    format!("sandbox-frozen-policy:{sandbox_id}")
}

pub fn decode_frozen_policy(
    sandbox_id: &str,
    payload: &[u8],
) -> PersistenceResult<StoredFrozenSandboxPolicy> {
    let state = StoredFrozenSandboxPolicy::decode(payload)
        .map_err(|error| PersistenceError::Decode(error.to_string()))?;
    if state.sandbox_id != sandbox_id {
        return Err(PersistenceError::Decode(
            "invalid frozen sandbox policy identity".into(),
        ));
    }
    Ok(state)
}

impl Store {
    pub(crate) async fn get_sandbox_frozen_policy(
        &self,
        sandbox_id: &str,
    ) -> PersistenceResult<Option<StoredFrozenSandboxPolicy>> {
        self.get(FROZEN_POLICY_OBJECT_TYPE, &frozen_policy_id(sandbox_id))
            .await?
            .map(|record| decode_frozen_policy(sandbox_id, &record.payload))
            .transpose()
    }

    /// Commit the immutable mode with the public identity before any driver dispatch.
    pub(crate) async fn create_frozen_sandbox(
        &self,
        sandbox: &Sandbox,
    ) -> PersistenceResult<WriteResult> {
        let sandbox_id = sandbox.object_id();
        if sandbox_id.is_empty() || sandbox.object_workspace().is_empty() {
            return Err(PersistenceError::Encode(
                "frozen sandbox requires an immutable id and workspace".into(),
            ));
        }
        let private_id = frozen_policy_id(sandbox_id);
        let payload = sandbox.encode_to_vec();
        let private_payload = StoredFrozenSandboxPolicy {
            sandbox_id: sandbox_id.into(),
            policy: None,
        }
        .encode_to_vec();
        let labels = serde_json::to_value(sandbox.object_labels().unwrap_or_default())
            .map_err(|error| PersistenceError::Encode(error.to_string()))?;
        let now_ms = current_time_ms();
        match self {
            Self::Sqlite(store) => {
                let mut tx = store
                    .pool
                    .begin_with("BEGIN IMMEDIATE")
                    .await
                    .map_err(|error| map_db_error(&error))?;
                sqlx::query("INSERT INTO objects (object_type, id, name, workspace, payload, labels, created_at_ms, updated_at_ms, resource_version) VALUES ('sandbox', ?1, ?2, ?3, ?4, ?5, ?6, ?6, 1)")
                    .bind(sandbox_id).bind(sandbox.object_name()).bind(sandbox.object_workspace())
                    .bind(&payload).bind(labels.to_string()).bind(now_ms)
                    .execute(&mut *tx).await.map_err(|error| map_db_error(&error))?;
                sqlx::query("INSERT INTO objects (object_type, id, name, workspace, scope, payload, created_at_ms, updated_at_ms, resource_version) VALUES (?1, ?2, NULL, '', ?3, ?4, ?5, ?5, 1)")
                    .bind(FROZEN_POLICY_OBJECT_TYPE).bind(&private_id).bind(sandbox_id).bind(&private_payload).bind(now_ms)
                    .execute(&mut *tx).await.map_err(|error| map_db_error(&error))?;
                tx.commit().await.map_err(|error| map_db_error(&error))?;
            }
            Self::Postgres(store) => {
                let mut tx = store
                    .pool
                    .begin()
                    .await
                    .map_err(|error| map_db_error(&error))?;
                sqlx::query("INSERT INTO objects (object_type, id, name, workspace, payload, labels, created_at_ms, updated_at_ms, resource_version) VALUES ('sandbox', $1, $2, $3, $4, $5, $6, $6, 1)")
                    .bind(sandbox_id).bind(sandbox.object_name()).bind(sandbox.object_workspace())
                    .bind(&payload).bind(&labels).bind(now_ms)
                    .execute(&mut *tx).await.map_err(|error| map_db_error(&error))?;
                sqlx::query("INSERT INTO objects (object_type, id, name, workspace, scope, payload, created_at_ms, updated_at_ms, resource_version) VALUES ($1, $2, NULL, '', $3, $4, $5, $5, 1)")
                    .bind(FROZEN_POLICY_OBJECT_TYPE).bind(&private_id).bind(sandbox_id).bind(&private_payload).bind(now_ms)
                    .execute(&mut *tx).await.map_err(|error| map_db_error(&error))?;
                tx.commit().await.map_err(|error| map_db_error(&error))?;
            }
        }
        Ok(WriteResult {
            resource_version: 1,
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
        })
    }

    /// The sandbox CAS fences every writer that read before first acceptance.
    pub(crate) async fn accept_frozen_sandbox_configuration(
        &self,
        mut sandbox: Sandbox,
        policy: FrozenSandboxPolicy,
    ) -> PersistenceResult<Sandbox> {
        let sandbox_id = sandbox.object_id().to_string();
        let private_id = frozen_policy_id(&sandbox_id);
        let record = self
            .get(FROZEN_POLICY_OBJECT_TYPE, &private_id)
            .await?
            .ok_or_else(|| PersistenceError::Decode("frozen sandbox mode is missing".into()))?;
        let mut state = decode_frozen_policy(&sandbox_id, &record.payload)?;
        if state.policy.is_some() {
            return Err(PersistenceError::Conflict {
                current_resource_version: Some(sandbox.get_resource_version()),
            });
        }
        state.policy = Some(policy);
        let results = self
            .write_atomically(&[
                AtomicWrite::Update {
                    object_type: "sandbox".into(),
                    id: sandbox_id,
                    payload: sandbox.encode_to_vec(),
                    expected_version: sandbox.get_resource_version(),
                },
                AtomicWrite::Update {
                    object_type: FROZEN_POLICY_OBJECT_TYPE.into(),
                    id: private_id,
                    payload: state.encode_to_vec(),
                    expected_version: record.resource_version,
                },
            ])
            .await?;
        sandbox.set_resource_version(
            results[0]
                .as_ref()
                .expect("sandbox update result")
                .resource_version,
        );
        Ok(sandbox)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_store::{AtomicPolicyRevisionWrite, PolicyStoreExt};
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    use openshell_core::proto::{PolicySource, SandboxPhase, SandboxSpec, SandboxStatus};
    use std::collections::HashMap;

    fn sandbox(id: &str, name: &str) -> Sandbox {
        Sandbox {
            metadata: Some(ObjectMeta {
                id: id.into(),
                name: name.into(),
                workspace: "default".into(),
                labels: HashMap::from([("team".into(), "frozen-test".into())]),
                ..Default::default()
            }),
            spec: Some(SandboxSpec::default()),
            status: Some(SandboxStatus::default()),
            ..Default::default()
        }
    }

    async fn exercise_frozen_policy_persistence(store: &Store) {
        Box::pin(async move {
            let original = sandbox("frozen-id", "frozen-name");
            store.create_frozen_sandbox(&original).await.unwrap();
            let stale = store
                .get_message::<Sandbox>("frozen-id")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                store
                    .get_sandbox_frozen_policy("frozen-id")
                    .await
                    .unwrap()
                    .unwrap()
                    .policy,
                None
            );
            let record = store.get("sandbox", "frozen-id").await.unwrap().unwrap();
            assert!(record.labels.unwrap().contains("frozen-test"));

            // Name contention cannot leave an orphan mode for an uncreated identity.
            assert!(
                store
                    .create_frozen_sandbox(&sandbox("other-id", "frozen-name"))
                    .await
                    .is_err()
            );
            assert!(
                store
                    .get_message::<Sandbox>("other-id")
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                store
                    .get_sandbox_frozen_policy("other-id")
                    .await
                    .unwrap()
                    .is_none()
            );

            let current = store
                .update_message_cas::<Sandbox, _>(
                    "frozen-id",
                    stale.get_resource_version(),
                    |sandbox| {
                        sandbox.status.as_mut().unwrap().phase = SandboxPhase::Ready.into();
                    },
                )
                .await
                .unwrap();
            let policy = openshell_policy::restrictive_default_policy();
            let snapshot = FrozenSandboxPolicy {
                policy: Some(policy.clone()),
                policy_hash: openshell_core::policy_identity::deterministic_policy_hash(&policy),
                policy_source: PolicySource::Sandbox.into(),
                version: 1,
                ..Default::default()
            };
            assert!(matches!(
                store
                    .accept_frozen_sandbox_configuration(stale, snapshot.clone())
                    .await,
                Err(PersistenceError::Conflict { .. })
            ));
            assert!(
                store
                    .get_sandbox_frozen_policy("frozen-id")
                    .await
                    .unwrap()
                    .unwrap()
                    .policy
                    .is_none()
            );
            let accepted = store
                .accept_frozen_sandbox_configuration(current, snapshot.clone())
                .await
                .unwrap();
            // Even a policy writer without an expected sandbox version is fenced in
            // the same transaction that would insert its revision.
            let write = AtomicPolicyRevisionWrite {
                id: "forbidden-revision".into(),
                sandbox_id: "frozen-id".into(),
                workspace: "default".into(),
                version: 2,
                policy_payload: policy.encode_to_vec(),
                policy_hash: snapshot.policy_hash.clone(),
                provenance: HashMap::new(),
                expected_resource_version: 0,
                annotations: HashMap::new(),
                backfill_policy: None,
            };
            assert!(matches!(
                store.put_policy_revision_atomic(&write).await,
                Err(PersistenceError::Conflict { .. })
            ));
            assert!(
                store
                    .get_latest_policy("frozen-id")
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(matches!(
                store
                    .accept_frozen_sandbox_configuration(accepted.clone(), snapshot.clone())
                    .await,
                Err(PersistenceError::Conflict { .. })
            ));

            // A public status rewrite cannot clear the gateway-private snapshot.
            let updated = store
                .update_message_cas::<Sandbox, _>(
                    "frozen-id",
                    accepted.get_resource_version(),
                    |sandbox| {
                        sandbox.status = Some(SandboxStatus::default());
                    },
                )
                .await
                .unwrap();
            assert_eq!(
                store
                    .get_sandbox_frozen_policy("frozen-id")
                    .await
                    .unwrap()
                    .unwrap()
                    .policy,
                Some(snapshot)
            );
            assert!(matches!(
                store
                    .delete_sandbox_with_image_state_if(
                        "frozen-id",
                        accepted.get_resource_version()
                    )
                    .await,
                Err(PersistenceError::Conflict { .. })
            ));
            assert!(
                store
                    .get_sandbox_frozen_policy("frozen-id")
                    .await
                    .unwrap()
                    .is_some()
            );
            assert!(
                store
                    .delete_sandbox_with_image_state_if("frozen-id", updated.get_resource_version())
                    .await
                    .unwrap()
            );
            assert!(
                store
                    .get_sandbox_frozen_policy("frozen-id")
                    .await
                    .unwrap()
                    .is_none()
            );
            let replacement = sandbox("replacement-id", "frozen-name");
            store.put_message(&replacement).await.unwrap();
            assert!(
                store
                    .get_sandbox_frozen_policy("replacement-id")
                    .await
                    .unwrap()
                    .is_none()
            );
        })
        .await;
    }

    #[tokio::test]
    async fn frozen_policy_persistence_is_atomic_and_identity_scoped() {
        exercise_frozen_policy_persistence(&super::super::test_store().await).await;
    }

    #[tokio::test]
    #[ignore = "requires a disposable PostgreSQL database"]
    async fn frozen_policy_persistence_postgres() {
        let schema = super::super::test_postgres::TestSchema::create("frozen_policy").await;
        exercise_frozen_policy_persistence(&schema.connect_store().await).await;
        schema.drop_schema().await;
    }

    #[test]
    fn frozen_policy_rejects_mismatched_private_identity() {
        let payload = StoredFrozenSandboxPolicy {
            sandbox_id: "other".into(),
            policy: None,
        }
        .encode_to_vec();
        assert!(decode_frozen_policy("expected", &payload).is_err());
    }
}
