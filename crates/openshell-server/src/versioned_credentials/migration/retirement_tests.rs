// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use sqlx::Connection as _;

async fn connection(fixture: &Fixture) -> sqlx::SqliteConnection {
    sqlx::SqliteConnection::connect(&format!(
        "sqlite://{}?mode=rw",
        fixture.directory.path().join("state.sqlite").display()
    ))
    .await
    .unwrap()
}

async fn legacy_fixture(fixture: &Fixture) -> RefreshState {
    let mut provider = provider();
    provider
        .credentials
        .insert("TOKEN".into(), "retirement-output".into());
    fixture.save(&provider).await;
    let mut source = state();
    source
        .material
        .insert("client_secret".into(), "retirement-inline-secret".into());
    source.secret_material_keys.push("client_secret".into());
    save_state(fixture, &source).await;
    source
}

async fn fail_retirement(fixture: &Fixture) {
    let mut connection = connection(fixture).await;
    sqlx::query(
        "CREATE TRIGGER fail_legacy_retirement BEFORE DELETE ON objects
WHEN OLD.object_type = 'provider_credential_refresh_state'
BEGIN SELECT RAISE(ABORT, 'injected legacy retirement failure'); END",
    )
    .execute(&mut connection)
    .await
    .unwrap();
}

async fn allow_retirement(fixture: &Fixture) {
    let mut connection = connection(fixture).await;
    sqlx::query("DROP TRIGGER fail_legacy_retirement")
        .execute(&mut connection)
        .await
        .unwrap();
}

async fn retirement_records(fixture: &Fixture) -> Vec<(ObjectRecord, Retirement)> {
    fixture
        .store
        .collect_records(RETIREMENT_TYPE, ObjectListQuery::AllWorkspaces)
        .await
        .unwrap()
        .into_iter()
        .map(|record| {
            let retirement = serde_json::from_slice(&record.payload).unwrap();
            (record, retirement)
        })
        .collect()
}

#[tokio::test]
async fn retirement_is_atomic_and_restart_does_not_rewrite_material_or_versions() {
    let fixture = Fixture::new().await;
    let source = legacy_fixture(&fixture).await;
    fail_retirement(&fixture).await;
    let versioned = fixture.versioned();
    let mut activation = fixture.activation().await;
    assert_eq!(
        migrate(&fixture.runtime, &versioned, &mut activation)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unavailable
    );
    assert!(
        fixture
            .store
            .get(LEGACY_REFRESH_TYPE, source.object_id())
            .await
            .unwrap()
            .is_some()
    );
    let pending = retirement_records(&fixture).await;
    assert_eq!(pending.len(), 1);
    assert!(
        !pending[0].1.complete,
        "failed source deletion must roll back completion"
    );
    assert!(!String::from_utf8_lossy(&pending[0].0.payload).contains("retirement-inline-secret"));
    let before = versioned
        .references
        .get_grant(owner(&source), source.object_id())
        .await
        .unwrap()
        .unwrap();
    assert!(before.active && !before.prepared);
    let backend_before = fixture
        .store
        .collect_records(
            openshell_credential_issuer::persistence::OBJECT_TYPE,
            ObjectListQuery::AllWorkspaces,
        )
        .await
        .unwrap();
    drop(activation);
    assert!(
        crate::credential_activation::begin(Arc::clone(&fixture.store), false)
            .await
            .is_err()
    );
    allow_retirement(&fixture).await;
    let reopened =
        VersionedCredentials::new(Arc::clone(&fixture.store), fixture.backend().await).unwrap();
    let mut activation = fixture.activation().await;
    migrate(&fixture.runtime, &reopened, &mut activation)
        .await
        .unwrap();
    activation.finish().await.unwrap();
    assert!(
        fixture
            .store
            .get(LEGACY_REFRESH_TYPE, source.object_id())
            .await
            .unwrap()
            .is_none()
    );
    assert!(retirement_records(&fixture).await[0].1.complete);
    let after = reopened
        .references
        .get_grant(owner(&source), source.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.resource_version, before.resource_version);
    assert_eq!(after.state, before.state);
    let backend_after = fixture
        .store
        .collect_records(
            openshell_credential_issuer::persistence::OBJECT_TYPE,
            ObjectListQuery::AllWorkspaces,
        )
        .await
        .unwrap();
    assert_eq!(backend_before.len(), backend_after.len());
    for (before, after) in backend_before.iter().zip(&backend_after) {
        assert_eq!(
            (before.id.as_str(), &before.payload, before.resource_version),
            (after.id.as_str(), &after.payload, after.resource_version)
        );
    }
    let current = reopened
        .get_by_id(source.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        reopened
            .backend
            .resolve_refresh_material(
                refresh_material_scope(&current),
                &current.secret_material_handles
            )
            .await
            .unwrap()["client_secret"],
        "retirement-inline-secret"
    );
    assert_eq!(
        resolve(&reopened, &fixture.provider().await).await[0].version,
        1
    );
    migrate(&fixture.runtime, &reopened, &mut activation)
        .await
        .unwrap();
    assert_eq!(retirement_records(&fixture).await[0].0.resource_version, 2);
}

#[tokio::test]
async fn changed_source_after_retirement_intent_is_not_silently_discarded() {
    let fixture = Fixture::new().await;
    let mut source = legacy_fixture(&fixture).await;
    fail_retirement(&fixture).await;
    let versioned = fixture.versioned();
    let mut activation = fixture.activation().await;
    assert!(
        migrate(&fixture.runtime, &versioned, &mut activation)
            .await
            .is_err()
    );
    source.material.insert(
        "client_secret".into(),
        "unreviewed-replacement-material".into(),
    );
    save_state(&fixture, &source).await;
    allow_retirement(&fixture).await;
    let error = migrate(&fixture.runtime, &versioned, &mut activation)
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert!(error.message().contains("source changed"));
    let legacy = crate::refresh_store::get_refresh_state(
        &fixture.store,
        "workspace",
        "provider-id",
        "TOKEN",
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        legacy.material["client_secret"],
        "unreviewed-replacement-material"
    );
    assert!(!retirement_records(&fixture).await[0].1.complete);
    let current = versioned
        .get_by_id(source.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        versioned
            .backend
            .resolve_refresh_material(
                refresh_material_scope(&current),
                &current.secret_material_handles
            )
            .await
            .unwrap()["client_secret"],
        "retirement-inline-secret"
    );
}

#[tokio::test]
async fn already_active_upgrade_retires_old_sources_without_reviving_revoked_grants() {
    let fixture = Fixture::new().await;
    let source = legacy_fixture(&fixture).await;
    let versioned = fixture.run().await;
    // Model the preceding compatible build: Active marker and durable grant,
    // but a frozen source row and no retirement protocol/checkpoint yet.
    for (record, _) in retirement_records(&fixture).await {
        fixture
            .store
            .delete(RETIREMENT_TYPE, &record.id)
            .await
            .unwrap();
    }
    save_state(&fixture, &source).await;
    let current = versioned
        .get_by_id(source.object_id())
        .await
        .unwrap()
        .unwrap();
    let revoked = versioned
        .references
        .tombstone_grant(
            owner(&current),
            current.object_id(),
            current.metadata.as_ref().unwrap().resource_version,
            &persistence::encode(&current).unwrap(),
        )
        .await
        .unwrap();
    fixture
        .store
        .delete("provider", "provider-id")
        .await
        .unwrap();
    let reopened =
        VersionedCredentials::new(Arc::clone(&fixture.store), fixture.backend().await).unwrap();
    let mut activation = fixture.activation().await;
    assert!(activation.already_active());
    migrate(&fixture.runtime, &reopened, &mut activation)
        .await
        .unwrap();
    assert!(
        fixture
            .store
            .get(LEGACY_REFRESH_TYPE, source.object_id())
            .await
            .unwrap()
            .is_none()
    );
    let after = reopened
        .references
        .get_grant(owner(&source), source.object_id())
        .await
        .unwrap()
        .unwrap();
    assert!(!after.active && !after.prepared);
    assert_eq!(after.resource_version, revoked.resource_version);
    assert_eq!(after.state, revoked.state);
    assert!(
        reopened
            .get_by_id(source.object_id())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn active_repair_preserves_source_without_a_durable_matching_grant() {
    let fixture = Fixture::new().await;
    let source = legacy_fixture(&fixture).await;
    let versioned = fixture.versioned();
    let mut activation = fixture.activation().await;
    activation.finish().await.unwrap();
    let error = migrate(&fixture.runtime, &versioned, &mut activation)
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert!(
        fixture
            .store
            .get(LEGACY_REFRESH_TYPE, source.object_id())
            .await
            .unwrap()
            .is_some()
    );
    assert!(retirement_records(&fixture).await.is_empty());
}

#[tokio::test]
async fn prepared_or_wrong_epoch_grants_cannot_authorize_retirement() {
    for prepared in [true, false] {
        let fixture = Fixture::new().await;
        let source = legacy_fixture(&fixture).await;
        let versioned = fixture.versioned();
        let mut sanitized = source.clone();
        sanitized.material.remove("client_secret");
        let bytes = persistence::encode(&sanitized).unwrap();
        if prepared {
            versioned
                .references
                .prepare_grant(
                    owner(&source),
                    source.object_id(),
                    source.object_id(),
                    &bytes,
                )
                .await
                .unwrap();
        } else {
            versioned
                .references
                .put_grant(
                    owner(&source),
                    source.object_id(),
                    None,
                    "different-epoch",
                    &bytes,
                    false,
                )
                .await
                .unwrap();
        }
        let mut activation = fixture.activation().await;
        activation.finish().await.unwrap();
        let error = migrate(&fixture.runtime, &versioned, &mut activation)
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(
            fixture
                .store
                .get(LEGACY_REFRESH_TYPE, source.object_id())
                .await
                .unwrap()
                .is_some()
        );
        assert!(retirement_records(&fixture).await.is_empty());
    }
}

#[tokio::test]
async fn a_completed_retirement_rejects_recreated_legacy_rows() {
    let fixture = Fixture::new().await;
    let source = legacy_fixture(&fixture).await;
    let versioned = fixture.run().await;
    save_state(&fixture, &source).await;
    let mut activation = fixture.activation().await;
    let error = migrate(&fixture.runtime, &versioned, &mut activation)
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert!(
        fixture
            .store
            .get(LEGACY_REFRESH_TYPE, source.object_id())
            .await
            .unwrap()
            .is_some()
    );
    assert!(retirement_records(&fixture).await[0].1.complete);
}

#[tokio::test]
async fn retirement_ticket_failure_precedes_import_and_retry_adopts_the_new_source() {
    let fixture = Fixture::new().await;
    let mut source = legacy_fixture(&fixture).await;
    let before = fixture.provider().await;
    let mut connection = connection(&fixture).await;
    sqlx::query(
        "CREATE TRIGGER fail_retirement_ticket BEFORE INSERT ON objects
WHEN NEW.object_type = 'credential_issuer_legacy_retirement_v1'
BEGIN SELECT RAISE(ABORT, 'injected pre-import ticket failure'); END",
    )
    .execute(&mut connection)
    .await
    .unwrap();
    let versioned = fixture.versioned();
    let mut activation = fixture.activation().await;
    assert!(
        migrate(&fixture.runtime, &versioned, &mut activation)
            .await
            .is_err()
    );
    assert_eq!(fixture.provider().await, before);
    assert!(
        versioned
            .references
            .get_grant(owner(&source), source.object_id())
            .await
            .unwrap()
            .is_none()
    );
    assert!(retirement_records(&fixture).await.is_empty());
    assert!(
        fixture
            .store
            .collect_records(JOURNAL_TYPE, ObjectListQuery::AllWorkspaces)
            .await
            .unwrap()
            .is_empty()
    );
    source
        .material
        .insert("client_secret".into(), "new-pre-import-material".into());
    save_state(&fixture, &source).await;
    drop(activation);
    sqlx::query("DROP TRIGGER fail_retirement_ticket")
        .execute(&mut connection)
        .await
        .unwrap();
    let versioned = fixture.run().await;
    let current = versioned
        .get_by_id(source.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        versioned
            .backend
            .resolve_refresh_material(
                refresh_material_scope(&current),
                &current.secret_material_handles
            )
            .await
            .unwrap()["client_secret"],
        "new-pre-import-material"
    );
}

#[tokio::test]
async fn source_changed_after_import_before_retirement_inventory_survives_restart() {
    let fixture = Fixture::new().await;
    let source = legacy_fixture(&fixture).await;
    let mut changed = source.clone();
    changed
        .material
        .insert("client_secret".into(), "not-imported-material".into());
    let changed: crate::storage_proto::StoredProviderCredentialRefreshStateV2 = (&changed).into();
    let mut payload = String::new();
    for byte in changed.encode_to_vec() {
        write!(&mut payload, "{byte:02x}").unwrap();
    }
    let mut connection = connection(&fixture).await;
    // The Provider is published only after the original grant is prepared.
    // Change the legacy source before the first retirement inventory, not after
    // a retirement attempt. No caller/worker timing assumptions are involved.
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE TRIGGER change_source_after_import AFTER UPDATE ON objects
WHEN NEW.object_type = 'provider'
BEGIN UPDATE objects SET payload = X'{payload}', resource_version = resource_version + 1
WHERE object_type = 'provider_credential_refresh_state'; END"
    )))
    .execute(&mut connection)
    .await
    .unwrap();
    let versioned = fixture.versioned();
    let mut activation = fixture.activation().await;
    assert_eq!(
        migrate(&fixture.runtime, &versioned, &mut activation)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    let ticket = retirement_records(&fixture).await;
    assert_eq!(ticket.len(), 1);
    assert!(!ticket[0].1.complete);
    let original_grant = versioned
        .references
        .get_grant(owner(&source), source.object_id())
        .await
        .unwrap()
        .unwrap();
    drop(activation);
    sqlx::query("DROP TRIGGER change_source_after_import")
        .execute(&mut connection)
        .await
        .unwrap();
    let mut activation = fixture.activation().await;
    assert_eq!(
        migrate(&fixture.runtime, &versioned, &mut activation)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    let retained = crate::refresh_store::get_refresh_state(
        &fixture.store,
        "workspace",
        "provider-id",
        "TOKEN",
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(retained.material["client_secret"], "not-imported-material");
    let current = versioned
        .references
        .get_grant(owner(&source), source.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.resource_version, original_grant.resource_version);
    assert_eq!(current.state, original_grant.state);
}

#[tokio::test]
async fn incomplete_conversion_cannot_bootstrap_a_missing_source_ticket() {
    let fixture = Fixture::new().await;
    let source = legacy_fixture(&fixture).await;
    fail_retirement(&fixture).await;
    let versioned = fixture.versioned();
    let mut activation = fixture.activation().await;
    assert!(
        migrate(&fixture.runtime, &versioned, &mut activation)
            .await
            .is_err()
    );
    let grant = versioned
        .references
        .get_grant(owner(&source), source.object_id())
        .await
        .unwrap()
        .unwrap();
    for (record, _) in retirement_records(&fixture).await {
        fixture
            .store
            .delete(RETIREMENT_TYPE, &record.id)
            .await
            .unwrap();
    }
    drop(activation);
    allow_retirement(&fixture).await;
    let mut activation = fixture.activation().await;
    assert!(!activation.already_active());
    let error = migrate(&fixture.runtime, &versioned, &mut activation)
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert!(error.message().contains("pre-import retirement intent"));
    assert!(
        fixture
            .store
            .get(LEGACY_REFRESH_TYPE, source.object_id())
            .await
            .unwrap()
            .is_some()
    );
    assert!(retirement_records(&fixture).await.is_empty());
    let after = versioned
        .references
        .get_grant(owner(&source), source.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.state, grant.state);
    assert_eq!(after.resource_version, grant.resource_version);
}
