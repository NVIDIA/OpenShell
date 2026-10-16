// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Private, atomic image-update intent storage.
//!
//! The intent is deliberately not part of `Sandbox`: an older gateway decoding
//! and rewriting that public message must not erase an accepted update. Every
//! transaction locks the sandbox first, then its independent image-state row.

use super::{PersistenceError, PersistenceResult, Store, current_time_ms, map_db_error};
use crate::storage_proto::{StoredSandboxImageState, StoredSandboxImageUpdate};
use openshell_core::SetResourceVersion;
use openshell_core::proto::{Sandbox, SandboxPhase, SandboxProvisioning};
use prost::Message;
use sqlx::{Postgres, Sqlite, Transaction};

const IMAGE_STATE_OBJECT_TYPE: &str = "sandbox_image_state";

fn state_id(sandbox_id: &str) -> String {
    format!("sandbox-image-state:{sandbox_id}")
}

fn conflict(current_resource_version: Option<u64>) -> PersistenceError {
    PersistenceError::Conflict {
        current_resource_version,
    }
}

fn decode_state(sandbox_id: &str, payload: &[u8]) -> PersistenceResult<StoredSandboxImageState> {
    let state = StoredSandboxImageState::decode(payload)
        .map_err(|error| PersistenceError::Decode(error.to_string()))?;
    if state.sandbox_id != sandbox_id
        || state
            .pending
            .as_ref()
            .is_some_and(|pending| pending.revision == 0 || pending.revision != state.revision)
        || (state.pending.is_none() && state.previous_provisioning.is_some())
        || state
            .previous_provisioning
            .as_ref()
            .is_some_and(|previous| previous.driver_operation_pending)
    {
        return Err(PersistenceError::Database(
            "inconsistent stored sandbox image state".into(),
        ));
    }
    Ok(state)
}

fn decode_sandbox(
    sandbox_id: &str,
    payload: &[u8],
    resource_version: i64,
) -> PersistenceResult<Sandbox> {
    if resource_version < 1 {
        return Err(PersistenceError::Database(
            "invalid sandbox resource version".into(),
        ));
    }
    let payload = super::legacy_time_wire::migrate("sandbox", payload)?;
    let mut sandbox = Sandbox::decode(payload.as_slice())
        .map_err(|error| PersistenceError::Decode(error.to_string()))?;
    if sandbox
        .metadata
        .as_ref()
        .is_none_or(|meta| meta.id != sandbox_id)
    {
        return Err(PersistenceError::Database(
            "inconsistent stored sandbox identity".into(),
        ));
    }
    // The SQL column, not a possibly stale protobuf field, is authoritative.
    sandbox.set_resource_version(resource_version.cast_unsigned());
    Ok(sandbox)
}

fn resource_version(sandbox: &Sandbox) -> u64 {
    sandbox
        .metadata
        .as_ref()
        .map_or(0, |meta| meta.resource_version)
}

fn require_stopped(sandbox: &Sandbox) -> PersistenceResult<()> {
    if sandbox
        .metadata
        .as_ref()
        .is_none_or(|meta| meta.deletion_time.is_some())
        || sandbox
            .status
            .as_ref()
            .is_none_or(|status| status.phase != SandboxPhase::Stopped as i32)
    {
        return Err(conflict(Some(resource_version(sandbox))));
    }
    Ok(())
}

fn validate_intent(intent: &StoredSandboxImageUpdate) -> PersistenceResult<()> {
    if intent.operation_id.is_empty()
        || intent.previous_image.is_empty()
        || intent.image.is_empty()
        || intent.revision == 0
    {
        return Err(PersistenceError::Encode(
            "image update requires an operation id, both images, and a nonzero revision".into(),
        ));
    }
    Ok(())
}

fn bump_resource_version(sandbox: &mut Sandbox) -> PersistenceResult<()> {
    let next = resource_version(sandbox)
        .checked_add(1)
        .filter(|next| i64::try_from(*next).is_ok())
        .ok_or_else(|| PersistenceError::Encode("sandbox resource version exhausted".into()))?;
    sandbox.set_resource_version(next);
    Ok(())
}

/// Pure projection: all acceptance checks happen before either row is written.
fn project_begin(
    mut sandbox: Sandbox,
    state: Option<StoredSandboxImageState>,
    expected_sandbox_resource_version: u64,
    expected_revision: u64,
    intent: &StoredSandboxImageUpdate,
) -> PersistenceResult<(Sandbox, StoredSandboxImageState)> {
    let current_version = resource_version(&sandbox);
    if expected_sandbox_resource_version == 0
        || expected_sandbox_resource_version != current_version
    {
        return Err(conflict(Some(current_version)));
    }
    require_stopped(&sandbox)?;
    validate_intent(intent)?;
    let mut state = state.unwrap_or_else(|| StoredSandboxImageState {
        sandbox_id: sandbox
            .metadata
            .as_ref()
            .map_or_else(String::new, |meta| meta.id.clone()),
        revision: 0,
        pending: None,
        previous_provisioning: None,
    });
    if state.revision != expected_revision || state.pending.is_some() {
        return Err(conflict(Some(current_version)));
    }
    let next_revision = expected_revision
        .checked_add(1)
        .ok_or_else(|| PersistenceError::Encode("sandbox image revision exhausted".into()))?;
    if intent.revision != next_revision {
        return Err(conflict(Some(current_version)));
    }
    let previous_provisioning = sandbox
        .status
        .as_ref()
        .and_then(|status| status.provisioning.clone());
    if previous_provisioning
        .as_ref()
        .is_some_and(|previous| previous.driver_operation_pending)
    {
        return Err(conflict(Some(current_version)));
    }
    let template = sandbox
        .spec
        .as_mut()
        .and_then(|spec| spec.template.as_mut())
        .ok_or_else(|| conflict(Some(current_version)))?;
    if template.image != intent.previous_image {
        return Err(conflict(Some(current_version)));
    }
    template.image.clone_from(&intent.image);
    state.revision = next_revision;
    state.pending = Some(intent.clone());
    state.previous_provisioning = previous_provisioning;
    let status = sandbox
        .status
        .as_mut()
        .ok_or_else(|| conflict(Some(current_version)))?;
    let operation = status
        .provisioning
        .get_or_insert_with(|| SandboxProvisioning {
            attempt_id: format!("image-update:{}", intent.operation_id),
            ..Default::default()
        });
    // This is an existing, baseline-known lifecycle interlock. Old gateways
    // retain it on ordinary status writes and refuse Start/Stop/Delete while
    // it is pending. Do not settle it on an ambiguous driver error.
    operation.driver_operation_pending = true;
    operation
        .driver_operation_id
        .clone_from(&intent.operation_id);
    bump_resource_version(&mut sandbox)?;
    Ok((sandbox, state))
}

fn project_complete(
    mut sandbox: Sandbox,
    state: Option<StoredSandboxImageState>,
    intent: &StoredSandboxImageUpdate,
) -> PersistenceResult<(Sandbox, StoredSandboxImageState)> {
    let current_version = resource_version(&sandbox);
    require_stopped(&sandbox)?;
    validate_intent(intent)?;
    let mut state = state.ok_or_else(|| conflict(Some(current_version)))?;
    if state.revision != intent.revision || state.pending.as_ref() != Some(intent) {
        return Err(conflict(Some(current_version)));
    }
    if sandbox
        .spec
        .as_ref()
        .and_then(|spec| spec.template.as_ref())
        .is_none_or(|template| template.image != intent.image)
    {
        return Err(conflict(Some(current_version)));
    }
    let status = sandbox
        .status
        .as_mut()
        .ok_or_else(|| conflict(Some(current_version)))?;
    let expected_attempt = state.previous_provisioning.as_ref().map_or_else(
        || format!("image-update:{}", intent.operation_id),
        |previous| previous.attempt_id.clone(),
    );
    let operation = status
        .provisioning
        .as_mut()
        .ok_or_else(|| conflict(Some(current_version)))?;
    if !operation.driver_operation_pending
        || operation.driver_operation_id != intent.operation_id
        || operation.attempt_id != expected_attempt
    {
        return Err(conflict(Some(current_version)));
    }
    // Retire only our flag on the CURRENT record. Restoring a saved snapshot
    // would erase a concurrent provider attachment's accepted clock edit.
    // Keep the newest operation ID to reject delayed older callbacks (ABA).
    let unchanged_legacy_record = state.previous_provisioning.is_none()
        && *operation
            == SandboxProvisioning {
                attempt_id: expected_attempt,
                driver_operation_id: intent.operation_id.clone(),
                driver_operation_pending: true,
                ..Default::default()
            };
    if unchanged_legacy_record {
        status.provisioning = None;
    } else {
        operation.driver_operation_pending = false;
    }
    state.previous_provisioning = None;
    state.pending = None;
    // Completing an intent invalidates any Start CAS based on pending state.
    bump_resource_version(&mut sandbox)?;
    Ok((sandbox, state))
}

impl Store {
    /// Read gateway-private image state by immutable sandbox identity.
    pub async fn get_sandbox_image_state(
        &self,
        sandbox_id: &str,
    ) -> PersistenceResult<Option<StoredSandboxImageState>> {
        let id = state_id(sandbox_id);
        let payload = match self {
            Self::Sqlite(store) => {
                sqlx::query_scalar::<_, Vec<u8>>(
                    r#"SELECT "payload" FROM "objects" WHERE "object_type" = ?1 AND "id" = ?2"#,
                )
                .bind(IMAGE_STATE_OBJECT_TYPE)
                .bind(&id)
                .fetch_optional(&store.pool)
                .await
            }
            Self::Postgres(store) => {
                sqlx::query_scalar::<_, Vec<u8>>(
                    "SELECT payload FROM objects WHERE object_type = $1 AND id = $2",
                )
                .bind(IMAGE_STATE_OBJECT_TYPE)
                .bind(&id)
                .fetch_optional(&store.pool)
                .await
            }
        }
        .map_err(|error| map_db_error(&error))?;
        payload
            .map(|payload| decode_state(sandbox_id, &payload))
            .transpose()
    }

    /// Atomically accept a stopped-sandbox image change and its private intent.
    pub async fn begin_sandbox_image_update(
        &self,
        sandbox_id: &str,
        expected_sandbox_resource_version: u64,
        expected_revision: u64,
        intent: &StoredSandboxImageUpdate,
    ) -> PersistenceResult<Sandbox> {
        let mut tx = ImageTransaction::begin(self).await?;
        let sandbox = tx.lock_sandbox(sandbox_id).await?;
        let state = tx.lock_state(sandbox_id).await?;
        let previous_version = resource_version(&sandbox);
        let (sandbox, state) = project_begin(
            sandbox,
            state,
            expected_sandbox_resource_version,
            expected_revision,
            intent,
        )?;
        tx.write_projection(sandbox_id, previous_version, &sandbox, &state)
            .await?;
        tx.commit().await?;
        Ok(sandbox)
    }

    /// Retire only the exact pending intent, retaining its monotonic revision.
    pub async fn complete_sandbox_image_update(
        &self,
        sandbox_id: &str,
        intent: &StoredSandboxImageUpdate,
    ) -> PersistenceResult<Sandbox> {
        let mut tx = ImageTransaction::begin(self).await?;
        let sandbox = tx.lock_sandbox(sandbox_id).await?;
        let state = tx.lock_state(sandbox_id).await?;
        let previous_version = resource_version(&sandbox);
        let (sandbox, state) = project_complete(sandbox, state, intent)?;
        tx.write_projection(sandbox_id, previous_version, &sandbox, &state)
            .await?;
        tx.commit().await?;
        Ok(sandbox)
    }
}

/// Dropping an unfinished `SQLx` transaction rolls back both projections.
enum ImageTransaction {
    Sqlite(Transaction<'static, Sqlite>),
    Postgres(Transaction<'static, Postgres>),
}

impl ImageTransaction {
    async fn begin(store: &Store) -> PersistenceResult<Self> {
        match store {
            Store::Sqlite(store) => store
                .pool
                .begin_with("BEGIN IMMEDIATE")
                .await
                .map(Self::Sqlite),
            Store::Postgres(store) => store.pool.begin().await.map(Self::Postgres),
        }
        .map_err(|error| map_db_error(&error))
    }

    async fn lock_sandbox(&mut self, sandbox_id: &str) -> PersistenceResult<Sandbox> {
        let row = match self {
            Self::Sqlite(tx) => {
                sqlx::query_as::<_, (Vec<u8>, i64)>(
                    r#"SELECT "payload", "resource_version" FROM "objects"
WHERE "object_type" = 'sandbox' AND "id" = ?1"#,
                )
                .bind(sandbox_id)
                .fetch_optional(&mut **tx)
                .await
            }
            Self::Postgres(tx) => {
                sqlx::query_as::<_, (Vec<u8>, i64)>(
                    "SELECT payload, resource_version FROM objects
WHERE object_type = 'sandbox' AND id = $1 FOR UPDATE",
                )
                .bind(sandbox_id)
                .fetch_optional(&mut **tx)
                .await
            }
        }
        .map_err(|error| map_db_error(&error))?
        .ok_or_else(|| conflict(None))?;
        decode_sandbox(sandbox_id, &row.0, row.1)
    }

    async fn lock_state(
        &mut self,
        sandbox_id: &str,
    ) -> PersistenceResult<Option<StoredSandboxImageState>> {
        let id = state_id(sandbox_id);
        let payload = match self {
            Self::Sqlite(tx) => {
                sqlx::query_scalar::<_, Vec<u8>>(
                    r#"SELECT "payload" FROM "objects" WHERE "object_type" = ?1 AND "id" = ?2"#,
                )
                .bind(IMAGE_STATE_OBJECT_TYPE)
                .bind(&id)
                .fetch_optional(&mut **tx)
                .await
            }
            Self::Postgres(tx) => {
                sqlx::query_scalar::<_, Vec<u8>>(
                    "SELECT payload FROM objects WHERE object_type = $1 AND id = $2 FOR UPDATE",
                )
                .bind(IMAGE_STATE_OBJECT_TYPE)
                .bind(&id)
                .fetch_optional(&mut **tx)
                .await
            }
        }
        .map_err(|error| map_db_error(&error))?;
        payload
            .map(|payload| decode_state(sandbox_id, &payload))
            .transpose()
    }

    async fn write_projection(
        &mut self,
        sandbox_id: &str,
        previous_version: u64,
        sandbox: &Sandbox,
        state: &StoredSandboxImageState,
    ) -> PersistenceResult<()> {
        let previous_version_sql = i64::try_from(previous_version).map_err(|_| {
            PersistenceError::Encode("sandbox resource version exceeds database range".into())
        })?;
        let now_ms = current_time_ms();
        let sandbox_payload = sandbox.encode_to_vec();
        let affected = match self {
            Self::Sqlite(tx) => sqlx::query(
                r#"UPDATE "objects"
SET "payload" = ?2, "updated_at_ms" = ?3, "resource_version" = "resource_version" + 1
WHERE "object_type" = 'sandbox' AND "id" = ?1 AND "resource_version" = ?4"#,
            )
            .bind(sandbox_id)
            .bind(&sandbox_payload)
            .bind(now_ms)
            .bind(previous_version_sql)
            .execute(&mut **tx)
            .await
            .map(|result| result.rows_affected()),
            Self::Postgres(tx) => sqlx::query(
                "UPDATE objects
SET payload = $2, updated_at_ms = $3, resource_version = resource_version + 1
WHERE object_type = 'sandbox' AND id = $1 AND resource_version = $4",
            )
            .bind(sandbox_id)
            .bind(&sandbox_payload)
            .bind(now_ms)
            .bind(previous_version_sql)
            .execute(&mut **tx)
            .await
            .map(|result| result.rows_affected()),
        }
        .map_err(|error| map_db_error(&error))?;
        if affected != 1 {
            return Err(conflict(Some(previous_version)));
        }

        let id = state_id(sandbox_id);
        let state_payload = state.encode_to_vec();
        let affected = match self {
            Self::Sqlite(tx) => sqlx::query(
                r#"INSERT INTO "objects" (
    "object_type", "id", "name", "workspace", "payload", "created_at_ms", "updated_at_ms"
) VALUES (?1, ?2, NULL, '', ?3, ?4, ?4)
ON CONFLICT ("id") DO UPDATE
SET "payload" = excluded."payload", "updated_at_ms" = excluded."updated_at_ms",
    "resource_version" = "objects"."resource_version" + 1
WHERE "objects"."object_type" = ?1 AND "objects"."name" IS NULL AND "objects"."workspace" = ''"#,
            )
            .bind(IMAGE_STATE_OBJECT_TYPE)
            .bind(&id)
            .bind(&state_payload)
            .bind(now_ms)
            .execute(&mut **tx)
            .await
            .map(|result| result.rows_affected()),
            Self::Postgres(tx) => sqlx::query(
                "INSERT INTO objects (
    object_type, id, name, workspace, payload, created_at_ms, updated_at_ms
) VALUES ($1, $2, NULL, '', $3, $4, $4)
ON CONFLICT (id) DO UPDATE
SET payload = EXCLUDED.payload, updated_at_ms = EXCLUDED.updated_at_ms,
    resource_version = objects.resource_version + 1
WHERE objects.object_type = $1 AND objects.name IS NULL AND objects.workspace = ''",
            )
            .bind(IMAGE_STATE_OBJECT_TYPE)
            .bind(&id)
            .bind(&state_payload)
            .bind(now_ms)
            .execute(&mut **tx)
            .await
            .map(|result| result.rows_affected()),
        }
        .map_err(|error| map_db_error(&error))?;
        if affected != 1 {
            return Err(PersistenceError::Database(
                "sandbox image state identity is already occupied".into(),
            ));
        }
        Ok(())
    }

    async fn commit(self) -> PersistenceResult<()> {
        match self {
            Self::Sqlite(tx) => tx.commit().await,
            Self::Postgres(tx) => tx.commit().await,
        }
        .map_err(|error| map_db_error(&error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{ObjectMeta, SandboxSpec, SandboxStatus, SandboxTemplate};

    fn sandbox() -> Sandbox {
        Sandbox {
            metadata: Some(ObjectMeta {
                id: "sandbox-id".into(),
                name: "sandbox-name".into(),
                workspace: "default".into(),
                resource_version: 5,
                ..Default::default()
            }),
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate {
                    image: "old-image".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            status: Some(SandboxStatus {
                phase: SandboxPhase::Stopped as i32,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn intent() -> StoredSandboxImageUpdate {
        StoredSandboxImageUpdate {
            operation_id: "operation-id".into(),
            previous_image: "old-image".into(),
            image: "new-image".into(),
            revision: 1,
        }
    }

    fn image(sandbox: &Sandbox) -> &str {
        &sandbox
            .spec
            .as_ref()
            .unwrap()
            .template
            .as_ref()
            .unwrap()
            .image
    }

    #[test]
    fn begin_and_complete_project_image_and_baseline_known_interlock() {
        let original = sandbox();
        let (accepted, state) = project_begin(original.clone(), None, 5, 0, &intent()).unwrap();
        assert_eq!(image(&accepted), "new-image");
        assert_eq!(resource_version(&accepted), 6);
        let operation = accepted
            .status
            .as_ref()
            .unwrap()
            .provisioning
            .as_ref()
            .unwrap();
        assert!(operation.driver_operation_pending);
        assert_eq!(operation.driver_operation_id, intent().operation_id);
        assert_eq!(operation.attempt_id, "image-update:operation-id");
        assert!(operation.deadline.is_none());
        assert!(operation.preparation_deadline.is_none());
        assert!(state.previous_provisioning.is_none());
        assert_eq!(state.pending, Some(intent()));
        let (completed, state) = project_complete(accepted, Some(state), &intent()).unwrap();
        assert_eq!(resource_version(&completed), 7);
        assert_eq!(completed.status, original.status);
        assert_eq!(state.revision, 1);
        assert!(state.pending.is_none());
        assert!(state.previous_provisioning.is_none());
    }

    #[test]
    fn completion_restores_existing_provisioning_except_last_operation_identity() {
        let mut original = sandbox();
        let previous = SandboxProvisioning {
            attempt_id: "previous-attempt".into(),
            driver_operation_id: "previous-settled-operation".into(),
            timeout_time: Some(prost_types::Timestamp {
                seconds: 123,
                nanos: 456,
            }),
            cleanup_completed_time: Some(prost_types::Timestamp {
                seconds: 124,
                nanos: 0,
            }),
            cleanup_error: "retained diagnostic".into(),
            ..Default::default()
        };
        original.status.as_mut().unwrap().provisioning = Some(previous.clone());
        let (accepted, state) = project_begin(original.clone(), None, 5, 0, &intent()).unwrap();
        assert_eq!(state.previous_provisioning, Some(previous));
        let (completed, cleared) = project_complete(accepted, Some(state), &intent()).unwrap();
        original
            .status
            .as_mut()
            .unwrap()
            .provisioning
            .as_mut()
            .unwrap()
            .driver_operation_id = intent().operation_id;
        assert_eq!(completed.status, original.status);
        assert!(cleared.previous_provisioning.is_none());
        assert!(cleared.pending.is_none());
        assert_eq!(cleared.revision, 1);
    }

    #[test]
    fn delayed_previous_operation_cannot_match_completed_image_operation() {
        let mut original = sandbox();
        let previous = SandboxProvisioning {
            attempt_id: "retained-attempt".into(),
            driver_operation_id: "delayed-operation".into(),
            timeout_time: Some(prost_types::Timestamp {
                seconds: 456,
                nanos: 0,
            }),
            cleanup_completed_time: Some(prost_types::Timestamp {
                seconds: 457,
                nanos: 0,
            }),
            ..Default::default()
        };
        original.status.as_mut().unwrap().provisioning = Some(previous.clone());
        let (accepted, state) = project_begin(original, None, 5, 0, &intent()).unwrap();
        let (completed, _) = project_complete(accepted, Some(state), &intent()).unwrap();
        let current = completed
            .status
            .as_ref()
            .unwrap()
            .provisioning
            .as_ref()
            .unwrap();
        // Baseline same_operation compares this pair. Preserve the attempt and
        // timeout provenance without resurrecting the old callback's identity.
        assert_ne!(
            (&current.attempt_id, &current.driver_operation_id),
            (&previous.attempt_id, &previous.driver_operation_id)
        );
        assert_eq!(current.attempt_id, previous.attempt_id);
        assert_eq!(current.driver_operation_id, intent().operation_id);
        assert!(!current.driver_operation_pending);
        assert_eq!(current.timeout_time, previous.timeout_time);
        assert_eq!(
            current.cleanup_completed_time,
            previous.cleanup_completed_time
        );
    }

    #[test]
    fn image_completion_preserves_concurrent_attachment_clock_edits() {
        let mut original = sandbox();
        let mut previous = crate::compute::provisioning_deadline::new_preparation_record(0, 1800);
        previous.driver_operation_id = "prior-operation".into();
        previous.attachment_change_id = "before-attachment".into();
        original.status.as_mut().unwrap().provisioning = Some(previous);
        let (mut accepted, state) = project_begin(original, None, 5, 0, &intent()).unwrap();
        crate::compute::provisioning_deadline::attachments_changed(&mut accepted, 2_000);
        let mut expected = accepted
            .status
            .as_ref()
            .unwrap()
            .provisioning
            .as_ref()
            .unwrap()
            .clone();
        assert_ne!(expected.attachment_change_id, "before-attachment");
        expected.driver_operation_pending = false;
        let (completed, state) = project_complete(accepted, Some(state), &intent()).unwrap();
        assert_eq!(completed.status.unwrap().provisioning, Some(expected));
        assert!(state.previous_provisioning.is_none());
    }

    #[test]
    fn image_completion_cannot_settle_a_replaced_provisioning_attempt() {
        let (mut accepted, state) = project_begin(sandbox(), None, 5, 0, &intent()).unwrap();
        accepted
            .status
            .as_mut()
            .unwrap()
            .provisioning
            .as_mut()
            .unwrap()
            .attempt_id = "replacement-attempt".into();
        assert!(matches!(
            project_complete(accepted, Some(state), &intent()),
            Err(PersistenceError::Conflict { .. })
        ));
    }

    #[test]
    fn pending_driver_operation_is_not_overwritten_and_completion_requires_its_fence() {
        let mut occupied = sandbox();
        occupied.status.as_mut().unwrap().provisioning = Some(SandboxProvisioning {
            attempt_id: "other-attempt".into(),
            driver_operation_pending: true,
            driver_operation_id: "other-operation".into(),
            ..Default::default()
        });
        assert!(project_begin(occupied, None, 5, 0, &intent()).is_err());
        let (accepted, state) = project_begin(sandbox(), None, 5, 0, &intent()).unwrap();
        let mut missing = accepted.clone();
        missing.status.as_mut().unwrap().provisioning = None;
        assert!(project_complete(missing, Some(state.clone()), &intent()).is_err());
        let mut cleared = accepted.clone();
        cleared
            .status
            .as_mut()
            .unwrap()
            .provisioning
            .as_mut()
            .unwrap()
            .driver_operation_pending = false;
        assert!(project_complete(cleared, Some(state.clone()), &intent()).is_err());
        let mut other = accepted;
        other
            .status
            .as_mut()
            .unwrap()
            .provisioning
            .as_mut()
            .unwrap()
            .driver_operation_id = "other".into();
        assert!(project_complete(other, Some(state), &intent()).is_err());
    }

    #[test]
    fn begin_rejects_stale_versions_revisions_and_pending_updates() {
        for version in [0, 4, 6] {
            assert!(matches!(
                project_begin(sandbox(), None, version, 0, &intent()),
                Err(PersistenceError::Conflict { .. })
            ));
        }
        assert!(project_begin(sandbox(), None, 5, 1, &intent()).is_err());
        let mut wrong = intent();
        wrong.revision = 2;
        assert!(project_begin(sandbox(), None, 5, 0, &wrong).is_err());
        let (accepted, state) = project_begin(sandbox(), None, 5, 0, &intent()).unwrap();
        let next = StoredSandboxImageUpdate {
            operation_id: "next-operation".into(),
            previous_image: "new-image".into(),
            image: "newer-image".into(),
            revision: 2,
        };
        assert!(project_begin(accepted, Some(state), 6, 1, &next).is_err());
    }

    #[test]
    fn lifecycle_and_image_checks_apply_at_acceptance_and_completion() {
        let mut running = sandbox();
        running.status.as_mut().unwrap().phase = SandboxPhase::Ready as i32;
        assert!(project_begin(running, None, 5, 0, &intent()).is_err());
        let mut deleting = sandbox();
        deleting.metadata.as_mut().unwrap().deletion_time = Some(prost_types::Timestamp::default());
        assert!(project_begin(deleting, None, 5, 0, &intent()).is_err());
        let mut wrong_image = sandbox();
        wrong_image
            .spec
            .as_mut()
            .unwrap()
            .template
            .as_mut()
            .unwrap()
            .image = "other".into();
        assert!(project_begin(wrong_image, None, 5, 0, &intent()).is_err());
        let (accepted, state) = project_begin(sandbox(), None, 5, 0, &intent()).unwrap();
        let mut stale_intent = intent();
        stale_intent.operation_id = "other-operation".into();
        assert!(project_complete(accepted.clone(), Some(state.clone()), &stale_intent).is_err());
        let mut changed = accepted.clone();
        changed
            .spec
            .as_mut()
            .unwrap()
            .template
            .as_mut()
            .unwrap()
            .image = "other".into();
        assert!(project_complete(changed, Some(state.clone()), &intent()).is_err());
        let mut running = accepted.clone();
        running.status.as_mut().unwrap().phase = SandboxPhase::Starting as i32;
        assert!(project_complete(running, Some(state.clone()), &intent()).is_err());
        let mut deleting = accepted.clone();
        deleting.metadata.as_mut().unwrap().deletion_time = Some(prost_types::Timestamp::default());
        assert!(project_complete(deleting, Some(state.clone()), &intent()).is_err());
        let mut wrong_revision = state;
        wrong_revision.revision = 2;
        assert!(project_complete(accepted.clone(), Some(wrong_revision), &intent()).is_err());
        assert!(project_complete(accepted, None, &intent()).is_err());
    }

    #[test]
    fn sandbox_decode_uses_authoritative_column_and_rejects_invalid_identity() {
        let original = sandbox();
        let decoded = decode_sandbox("sandbox-id", &original.encode_to_vec(), 12).unwrap();
        assert_eq!(resource_version(&decoded), 12);
        assert!(decode_sandbox("other-id", &original.encode_to_vec(), 12).is_err());
        assert!(decode_sandbox("sandbox-id", &original.encode_to_vec(), 0).is_err());
    }

    #[test]
    fn resource_version_overflow_and_invalid_intents_do_not_project() {
        let mut exhausted = sandbox();
        exhausted.set_resource_version(i64::MAX.cast_unsigned());
        assert!(matches!(
            project_begin(exhausted, None, i64::MAX.cast_unsigned(), 0, &intent()),
            Err(PersistenceError::Encode(_))
        ));
        let mut invalid = intent();
        invalid.operation_id.clear();
        assert!(matches!(
            project_begin(sandbox(), None, 5, 0, &invalid),
            Err(PersistenceError::Encode(_))
        ));
    }

    async fn fixture() -> (Store, Sandbox) {
        let store = super::super::test_store().await;
        store.put_message(&sandbox()).await.unwrap();
        let stored = store
            .get_message::<Sandbox>("sandbox-id")
            .await
            .unwrap()
            .unwrap();
        (store, stored)
    }

    #[tokio::test]
    async fn sqlite_accept_complete_and_legacy_rewrite_preserve_independent_state() {
        let (store, original) = fixture().await;
        let version = resource_version(&original);
        let accepted = store
            .begin_sandbox_image_update("sandbox-id", version, 0, &intent())
            .await
            .unwrap();
        assert_eq!(resource_version(&accepted), version + 1);
        assert_eq!(image(&accepted), "new-image");
        let pending = store
            .get_sandbox_image_state("sandbox-id")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pending.pending, Some(intent()));
        // Generic Sandbox decode/reencode cannot remove the separate intent.
        let decoded = Sandbox::decode(accepted.encode_to_vec().as_slice()).unwrap();
        assert!(
            decoded
                .status
                .as_ref()
                .unwrap()
                .provisioning
                .as_ref()
                .unwrap()
                .driver_operation_pending
        );
        assert_eq!(
            decoded
                .status
                .as_ref()
                .unwrap()
                .provisioning
                .as_ref()
                .unwrap()
                .driver_operation_id,
            intent().operation_id
        );
        store.put_message(&decoded).await.unwrap();
        assert_eq!(
            store.get_sandbox_image_state("sandbox-id").await.unwrap(),
            Some(pending)
        );
        let before_complete = store
            .get_message::<Sandbox>("sandbox-id")
            .await
            .unwrap()
            .unwrap();
        let completed = store
            .complete_sandbox_image_update("sandbox-id", &intent())
            .await
            .unwrap();
        assert_eq!(
            resource_version(&completed),
            resource_version(&before_complete) + 1
        );
        let retained = store
            .get_sandbox_image_state("sandbox-id")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retained.revision, 1);
        assert!(retained.pending.is_none());
        assert!(retained.previous_provisioning.is_none());
        assert_eq!(completed.status, original.status);
        // A Start based on any pre-completion snapshot must lose its CAS.
        let mut stale_start = before_complete.clone();
        stale_start.status.as_mut().unwrap().phase = SandboxPhase::Starting as i32;
        assert!(matches!(
            store
                .put_if(
                    "sandbox",
                    "sandbox-id",
                    "sandbox-name",
                    "default",
                    &stale_start.encode_to_vec(),
                    None,
                    super::super::WriteCondition::MatchResourceVersion(resource_version(
                        &before_complete
                    )),
                )
                .await,
            Err(PersistenceError::Conflict { .. })
        ));
        // Neither a completed operation nor an older generation can be replayed.
        assert!(
            store
                .complete_sandbox_image_update("sandbox-id", &intent())
                .await
                .is_err()
        );
        let next = StoredSandboxImageUpdate {
            operation_id: "next-operation".into(),
            previous_image: "new-image".into(),
            image: "newer-image".into(),
            revision: 2,
        };
        store
            .begin_sandbox_image_update("sandbox-id", resource_version(&completed), 1, &next)
            .await
            .unwrap();
        assert!(
            store
                .complete_sandbox_image_update("sandbox-id", &intent())
                .await
                .is_err()
        );
        assert_eq!(
            store
                .get_sandbox_image_state("sandbox-id")
                .await
                .unwrap()
                .unwrap()
                .pending,
            Some(next)
        );
    }

    #[tokio::test]
    async fn sqlite_restores_prior_provisioning_and_wrong_completion_keeps_fence() {
        let (store, mut original) = fixture().await;
        let previous = SandboxProvisioning {
            attempt_id: "timed-out-attempt".into(),
            driver_operation_id: "settled-driver-operation".into(),
            timeout_time: Some(prost_types::Timestamp {
                seconds: 123,
                nanos: 0,
            }),
            cleanup_completed_time: Some(prost_types::Timestamp {
                seconds: 124,
                nanos: 0,
            }),
            ..Default::default()
        };
        original.status.as_mut().unwrap().provisioning = Some(previous.clone());
        store.put_message(&original).await.unwrap();
        let mut original = store
            .get_message::<Sandbox>("sandbox-id")
            .await
            .unwrap()
            .unwrap();
        let accepted = store
            .begin_sandbox_image_update("sandbox-id", resource_version(&original), 0, &intent())
            .await
            .unwrap();
        let mut wrong = intent();
        wrong.operation_id = "stale-operation".into();
        assert!(
            store
                .complete_sandbox_image_update("sandbox-id", &wrong)
                .await
                .is_err()
        );
        assert_eq!(
            store
                .get_message::<Sandbox>("sandbox-id")
                .await
                .unwrap()
                .unwrap(),
            accepted
        );
        let state = store
            .get_sandbox_image_state("sandbox-id")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.pending, Some(intent()));
        assert_eq!(state.previous_provisioning, Some(previous.clone()));
        let completed = store
            .complete_sandbox_image_update("sandbox-id", &intent())
            .await
            .unwrap();
        let mut expected = previous;
        expected.driver_operation_id = intent().operation_id;
        assert_eq!(
            completed.status.as_ref().unwrap().provisioning,
            Some(expected.clone())
        );
        original.status.as_mut().unwrap().provisioning = Some(expected);
        assert_eq!(completed.status, original.status);
        assert!(
            store
                .get_sandbox_image_state("sandbox-id")
                .await
                .unwrap()
                .unwrap()
                .previous_provisioning
                .is_none()
        );
    }

    #[tokio::test]
    async fn sqlite_failed_cas_has_no_private_write() {
        let (store, original) = fixture().await;
        for version in [0, resource_version(&original) + 1] {
            assert!(matches!(
                store
                    .begin_sandbox_image_update("sandbox-id", version, 0, &intent())
                    .await,
                Err(PersistenceError::Conflict { .. })
            ));
        }
        assert!(
            store
                .get_sandbox_image_state("sandbox-id")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .get_message::<Sandbox>("sandbox-id")
                .await
                .unwrap()
                .unwrap(),
            original
        );
    }

    #[tokio::test]
    async fn sqlite_private_write_failure_rolls_back_sandbox_and_completion() {
        let (store, original) = fixture().await;
        let Store::Sqlite(sqlite) = &store else {
            unreachable!()
        };
        sqlx::query(
            "CREATE TRIGGER fail_image_insert BEFORE INSERT ON objects
WHEN NEW.object_type = 'sandbox_image_state'
BEGIN SELECT RAISE(ABORT, 'injected image state write failure'); END",
        )
        .execute(&sqlite.pool)
        .await
        .unwrap();
        assert!(
            store
                .begin_sandbox_image_update("sandbox-id", resource_version(&original), 0, &intent())
                .await
                .is_err()
        );
        assert_eq!(
            store
                .get_message::<Sandbox>("sandbox-id")
                .await
                .unwrap()
                .unwrap(),
            original
        );
        assert!(
            store
                .get_sandbox_image_state("sandbox-id")
                .await
                .unwrap()
                .is_none()
        );
        sqlx::query("DROP TRIGGER fail_image_insert")
            .execute(&sqlite.pool)
            .await
            .unwrap();
        let accepted = store
            .begin_sandbox_image_update("sandbox-id", resource_version(&original), 0, &intent())
            .await
            .unwrap();
        let pending = store.get_sandbox_image_state("sandbox-id").await.unwrap();
        sqlx::query(
            "CREATE TRIGGER fail_image_update BEFORE UPDATE ON objects
WHEN NEW.object_type = 'sandbox_image_state'
BEGIN SELECT RAISE(ABORT, 'injected image state write failure'); END",
        )
        .execute(&sqlite.pool)
        .await
        .unwrap();
        assert!(
            store
                .complete_sandbox_image_update("sandbox-id", &intent())
                .await
                .is_err()
        );
        assert_eq!(
            store
                .get_message::<Sandbox>("sandbox-id")
                .await
                .unwrap()
                .unwrap(),
            accepted
        );
        assert_eq!(
            store.get_sandbox_image_state("sandbox-id").await.unwrap(),
            pending
        );
    }

    #[tokio::test]
    #[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
    async fn postgres_sandbox_image_state_survives_legacy_writes_and_fences_concurrent_updates() {
        use super::super::{WriteCondition, test_postgres::TestSchema};

        let schema = TestSchema::create("sandbox_image").await;
        let first = schema.connect_store().await;
        let second = schema.connect_store().await;
        crate::ensure_default_workspace(&first).await.unwrap();
        first.put_message(&sandbox()).await.unwrap();
        let original = second
            .get_message::<Sandbox>("sandbox-id")
            .await
            .unwrap()
            .unwrap();
        let version = resource_version(&original);
        let left = intent();
        let right = StoredSandboxImageUpdate {
            operation_id: "competing-operation".into(),
            image: "competing-image".into(),
            ..intent()
        };

        // Independent pools contend on the same sandbox row; exactly one
        // transaction may publish revision 1 and its matching operation fence.
        let (left_result, right_result) = tokio::join!(
            first.begin_sandbox_image_update("sandbox-id", version, 0, &left),
            second.begin_sandbox_image_update("sandbox-id", version, 0, &right),
        );
        let (accepted, winning_intent) = match (left_result, right_result) {
            (Ok(accepted), Err(PersistenceError::Conflict { .. })) => (accepted, left),
            (Err(PersistenceError::Conflict { .. }), Ok(accepted)) => (accepted, right),
            results => panic!("expected one accepted image update and one conflict: {results:?}"),
        };
        let visible = second
            .get_message::<Sandbox>("sandbox-id")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(visible, accepted);
        assert_eq!(resource_version(&visible), version + 1);
        assert_eq!(image(&visible), winning_intent.image);
        let pending = second
            .get_sandbox_image_state("sandbox-id")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pending.revision, 1);
        assert_eq!(pending.pending, Some(winning_intent.clone()));
        let operation = visible
            .status
            .as_ref()
            .unwrap()
            .provisioning
            .as_ref()
            .unwrap();
        assert!(operation.driver_operation_pending);
        assert_eq!(operation.driver_operation_id, winning_intent.operation_id);

        let mut stale_start = original;
        stale_start.status.as_mut().unwrap().phase = SandboxPhase::Starting as i32;
        assert!(matches!(
            second
                .put_if(
                    "sandbox",
                    "sandbox-id",
                    "sandbox-name",
                    "default",
                    &stale_start.encode_to_vec(),
                    None,
                    WriteCondition::MatchResourceVersion(version),
                )
                .await,
            Err(PersistenceError::Conflict { .. })
        ));

        // Model an old gateway's ordinary unrelated Sandbox-only SQL rewrite.
        // All provisioning fields used here are baseline-known. The private
        // state has no public Sandbox field for this roundtrip to overwrite.
        let mut legacy_rewrite = Sandbox::decode(visible.encode_to_vec().as_slice()).unwrap();
        legacy_rewrite
            .metadata
            .as_mut()
            .unwrap()
            .annotations
            .insert(
                "test.openshell.dev/legacy-write".into(),
                "unrelated-edit".into(),
            );
        let Store::Postgres(legacy_store) = &second else {
            unreachable!()
        };
        let rewritten = sqlx::query(
            "UPDATE objects SET payload = $2, resource_version = resource_version + 1,
updated_at_ms = $3 WHERE object_type = 'sandbox' AND id = $1 AND resource_version = $4",
        )
        .bind("sandbox-id")
        .bind(legacy_rewrite.encode_to_vec())
        .bind(current_time_ms())
        .bind(i64::try_from(resource_version(&visible)).unwrap())
        .execute(&legacy_store.pool)
        .await
        .unwrap();
        assert_eq!(rewritten.rows_affected(), 1);
        assert_eq!(
            first.get_sandbox_image_state("sandbox-id").await.unwrap(),
            Some(pending)
        );
        let rewritten = first
            .get_message::<Sandbox>("sandbox-id")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resource_version(&rewritten), resource_version(&visible) + 1);
        let operation = rewritten
            .status
            .as_ref()
            .unwrap()
            .provisioning
            .as_ref()
            .unwrap();
        assert!(operation.driver_operation_pending);
        assert_eq!(operation.driver_operation_id, winning_intent.operation_id);
        let private_identity = sqlx::query_as::<_, (Option<String>, String)>(
            "SELECT name, workspace FROM objects WHERE object_type = $1 AND id = $2",
        )
        .bind(IMAGE_STATE_OBJECT_TYPE)
        .bind(state_id("sandbox-id"))
        .fetch_one(&legacy_store.pool)
        .await
        .unwrap();
        assert_eq!(private_identity, (None, String::new()));

        let completed = first
            .complete_sandbox_image_update("sandbox-id", &winning_intent)
            .await
            .unwrap();
        assert_eq!(
            resource_version(&completed),
            resource_version(&rewritten) + 1
        );
        assert!(completed.status.as_ref().unwrap().provisioning.is_none());
        let retained = second
            .get_sandbox_image_state("sandbox-id")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retained.revision, 1);
        assert!(retained.pending.is_none());
        assert!(retained.previous_provisioning.is_none());

        let next = StoredSandboxImageUpdate {
            operation_id: "next-generation-operation".into(),
            previous_image: winning_intent.image.clone(),
            image: "next-generation-image".into(),
            revision: 2,
        };
        let accepted_next = second
            .begin_sandbox_image_update("sandbox-id", resource_version(&completed), 1, &next)
            .await
            .unwrap();
        assert_eq!(image(&accepted_next), next.image);
        assert!(matches!(
            first
                .complete_sandbox_image_update("sandbox-id", &winning_intent)
                .await,
            Err(PersistenceError::Conflict { .. })
        ));
        let still_pending = first
            .get_sandbox_image_state("sandbox-id")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(still_pending.revision, 2);
        assert_eq!(still_pending.pending, Some(next.clone()));
        assert_eq!(
            first
                .get_message::<Sandbox>("sandbox-id")
                .await
                .unwrap()
                .unwrap(),
            accepted_next
        );

        let final_sandbox = first
            .complete_sandbox_image_update("sandbox-id", &next)
            .await
            .unwrap();
        assert_eq!(
            resource_version(&final_sandbox),
            resource_version(&accepted_next) + 1
        );
        assert!(
            final_sandbox
                .status
                .as_ref()
                .unwrap()
                .provisioning
                .is_none()
        );
        assert_eq!(
            second
                .get_message::<Sandbox>("sandbox-id")
                .await
                .unwrap()
                .unwrap(),
            final_sandbox
        );
        let retained = second
            .get_sandbox_image_state("sandbox-id")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retained.revision, 2);
        assert!(retained.pending.is_none());
        assert!(retained.previous_provisioning.is_none());
        // Completion also invalidates a Start CAS based on the pending snapshot.
        assert!(matches!(
            second
                .put_if(
                    "sandbox",
                    "sandbox-id",
                    "sandbox-name",
                    "default",
                    &accepted_next.encode_to_vec(),
                    None,
                    WriteCondition::MatchResourceVersion(resource_version(&accepted_next)),
                )
                .await,
            Err(PersistenceError::Conflict { .. })
        ));

        first.close().await;
        second.close().await;
        schema.drop_schema().await;
    }
}
