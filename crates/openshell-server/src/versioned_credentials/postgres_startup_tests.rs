// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Joined startup qualification, not old-binary fencing: the operator must have
//! drained incompatible writers before enabling versioned credentials.

use super::*;
use crate::credentials::CredentialRuntime;
use crate::persistence::ObjectRecord;
use openshell_core::Config;
use openshell_core::proto::{
    CredentialHandle, ObjectMeta, Provider, ProviderCredentialRefreshStrategy,
};
use openshell_credential_issuer::references::ReferenceProjection;
use openshell_credential_issuer::refresh::{refresh_material_scope, refresh_state_name};
use std::collections::BTreeMap;
use std::time::Duration;

const PROVIDER_ID: &str = "startup-provider";
const PROVIDER_NAME: &str = "startup-provider-name";
const WORKSPACE: &str = "startup-workspace";
const GRANT_ID: &str = "startup-grant";
const LEGACY_TYPE: &str = "provider_credential_refresh_state";
const RAW_SECRET: &str = "postgres-legacy-handle-secret-marker";
const INLINE_SECRET: &str = "postgres-inline-provider-secret-marker";
const SESSION_SECRET: &str = "postgres-inline-session-secret-marker";
const REFRESH_SECRET: &str = "postgres-inline-refresh-secret-marker";

struct StartupFixture {
    directory: tempfile::TempDir,
    config: Config,
    file: crate::config_file::ConfigFile,
    schema: TestSchema,
    first: Arc<Store>,
    second: Arc<Store>,
    control: sqlx::PgPool,
    original_handle: CredentialHandle,
    original_ciphertext: ObjectRecord,
}

impl StartupFixture {
    async fn new(prefix: &str) -> Self {
        Self::with_pool_size(prefix, None).await
    }

    async fn with_pool_size(prefix: &str, max_connections: Option<u32>) -> Self {
        let schema = TestSchema::create(prefix).await;
        let first = Arc::new(
            Store::connect_with_pool_sizes(schema.url(), max_connections, None)
                .await
                .unwrap(),
        );
        let second = Arc::new(
            Store::connect_with_pool_sizes(schema.url(), max_connections, None)
                .await
                .unwrap(),
        );
        let control = sqlx::PgPool::connect(schema.url()).await.unwrap();
        let directory = tempfile::tempdir().unwrap();
        let key_path = directory.path().join("credential-kek");
        let file = toml::from_str(&format!(
            "[openshell.gateway.credential_storage]\nkey_encryption_key_path = {}\n",
            serde_json::to_string(&key_path.to_string_lossy()).unwrap(),
        ))
        .unwrap();
        let mut config = Config::new(None);
        config.database_max_connections = max_connections;
        // Initialize the real encrypted DB backend/key before concurrent starts.
        // No test-static backend or shared in-memory issuer is used here.
        let legacy = CredentialRuntime::from_config_file_with_store(
            &config,
            Some(&file),
            Arc::clone(&first),
        )
        .await
        .unwrap();
        assert!(!legacy.is_versioned());
        assert_eq!(std::fs::metadata(&key_path).unwrap().len(), 32);
        let handles = legacy
            .store_provider_credentials(
                PROVIDER_NAME,
                WORKSPACE,
                PROVIDER_ID,
                &HashMap::from([("ACCESS".into(), RAW_SECRET.into())]),
                &Handles::new(),
            )
            .await
            .unwrap();
        let original_handle = handles["ACCESS"].clone();
        let mut ciphertext = first
            .collect_records(
                openshell_credential_issuer::persistence::OBJECT_TYPE,
                ObjectListQuery::AllWorkspaces,
            )
            .await
            .unwrap();
        assert_eq!(ciphertext.len(), 1);
        let provider = Provider {
            metadata: Some(ObjectMeta {
                id: PROVIDER_ID.into(),
                name: PROVIDER_NAME.into(),
                workspace: WORKSPACE.into(),
                ..Default::default()
            }),
            credential_handles: handles,
            credentials: HashMap::from([
                ("SECRET".into(), INLINE_SECRET.into()),
                ("SESSION".into(), SESSION_SECRET.into()),
            ]),
            ..Default::default()
        };
        first.put_message(&provider).await.unwrap();
        let state = RefreshState {
            metadata: Some(ObjectMeta {
                id: GRANT_ID.into(),
                name: refresh_state_name(PROVIDER_ID, "ACCESS"),
                workspace: WORKSPACE.into(),
                ..Default::default()
            }),
            provider_id: PROVIDER_ID.into(),
            provider_name: PROVIDER_NAME.into(),
            credential_key: "ACCESS".into(),
            strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials.into(),
            material: HashMap::from([
                ("client_id".into(), "nonsecret-client".into()),
                ("client_secret".into(), REFRESH_SECRET.into()),
            ]),
            secret_material_keys: vec!["client_secret".into()],
            additional_output_keys: HashMap::from([
                ("secret".into(), "SECRET".into()),
                ("session".into(), "SESSION".into()),
            ]),
            authorization_epoch: "startup-authorization-epoch".into(),
            status: "ready".into(),
            next_refresh_at_ms: i64::MAX,
            ..Default::default()
        };
        let stored: crate::storage_proto::StoredProviderCredentialRefreshStateV2 = (&state).into();
        crate::refresh_store::put_refresh_state(&first, &stored)
            .await
            .unwrap();
        let intent_key = directory.path().join("stable-intent-key");
        std::fs::write(
            &intent_key,
            b"stable postgres startup test-only private material",
        )
        .unwrap();
        config.gateway_jwt = Some(openshell_core::config::GatewayJwtConfig {
            signing_key_path: intent_key,
            public_key_path: directory.path().join("unused-public"),
            kid_path: directory.path().join("unused-kid"),
            gateway_id: "postgres-startup-test".into(),
            ttl_secs: None,
        });
        config.enable_versioned_credentials = true;
        Self {
            directory,
            config,
            file,
            schema,
            first,
            second,
            control,
            original_handle,
            original_ciphertext: ciphertext.remove(0),
        }
    }

    async fn start(&self, store: &Arc<Store>) -> openshell_core::Result<CredentialRuntime> {
        CredentialRuntime::from_config_file_with_store(
            &self.config,
            Some(&self.file),
            Arc::clone(store),
        )
        .await
    }

    async fn provider(&self) -> Provider {
        self.first.get_message(PROVIDER_ID).await.unwrap().unwrap()
    }

    async fn rows(&self, object_type: &str) -> BTreeMap<String, (u64, Vec<u8>)> {
        self.first
            .collect_records(object_type, ObjectListQuery::AllWorkspaces)
            .await
            .unwrap()
            .into_iter()
            .map(|row| (row.id, (row.resource_version, row.payload)))
            .collect()
    }

    async fn assert_migrated(&self, runtime: &CredentialRuntime) {
        assert!(runtime.is_versioned());
        let provider = self.provider().await;
        assert!(provider.credentials.is_empty());
        assert_eq!(provider.credential_handles.len(), 3);
        let adopted = &provider.credential_handles["ACCESS"];
        assert_eq!(adopted.driver, self.original_handle.driver);
        assert_eq!(adopted.handle, self.original_handle.handle);
        for (key, value) in &self.original_handle.metadata {
            assert_eq!(adopted.metadata.get(key), Some(value));
        }
        for handle in provider.credential_handles.values() {
            assert!(ReferenceProjection::from_handle(handle).unwrap().is_some());
        }
        let versioned = runtime.versioned().unwrap();
        let owner = SecretOwner::provider(WORKSPACE, PROVIDER_ID, PROVIDER_NAME);
        let values = versioned
            .references
            .resolve(owner, &provider.credential_handles)
            .await
            .unwrap();
        assert_eq!(values.len(), 3);
        let expected = HashMap::from([
            ("ACCESS", RAW_SECRET),
            ("SECRET", INLINE_SECRET),
            ("SESSION", SESSION_SECRET),
        ]);
        for value in values {
            assert_eq!(value.version, 1);
            assert_eq!(value.generation, 1);
            assert_eq!(value.value, expected[value.credential_key.as_str()]);
        }
        versioned.validate_provider_grants(&provider).await.unwrap();
        let state = versioned.get_by_id(GRANT_ID).await.unwrap().unwrap();
        assert_eq!(state.reference_generation, 1);
        assert_eq!(state.output_references, provider.credential_handles);
        assert_eq!(state.material.get("client_id").unwrap(), "nonsecret-client");
        assert!(!state.material.contains_key("client_secret"));
        let grant = versioned
            .references
            .get_grant(owner, GRANT_ID)
            .await
            .unwrap()
            .unwrap();
        assert!(grant.active && !grant.prepared);
        let material = versioned
            .backend
            .resolve_refresh_material(
                refresh_material_scope(&state),
                &state.secret_material_handles,
            )
            .await
            .unwrap();
        assert_eq!(material["client_secret"], REFRESH_SECRET);
        let ciphertext = self
            .first
            .get(
                openshell_credential_issuer::persistence::OBJECT_TYPE,
                &self.original_ciphertext.id,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ciphertext.payload, self.original_ciphertext.payload);
        assert_eq!(
            ciphertext.resource_version,
            self.original_ciphertext.resource_version
        );
        assert_eq!(self.rows(REFERENCE_OBJECT_TYPE).await.len(), 1);
        // Include every gateway application row, especially frozen legacy inputs
        // and retirement/recovery evidence: new-store-only scans miss leaks.
        let rows: Vec<(String, Vec<u8>)> =
            sqlx::query_as("SELECT object_type, payload FROM objects")
                .fetch_all(&self.control)
                .await
                .unwrap();
        for (object_type, payload) in rows {
            for marker in [RAW_SECRET, INLINE_SECRET, SESSION_SECRET, REFRESH_SECRET] {
                assert!(
                    !payload
                        .windows(marker.len())
                        .any(|window| window == marker.as_bytes()),
                    "plaintext secret remains in {object_type}"
                );
            }
        }
    }

    async fn close(self) {
        self.first.close().await;
        self.second.close().await;
        self.control.close().await;
        self.schema.drop_schema().await;
        drop(self.directory);
    }
}

#[tokio::test]
#[ignore = "requires OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
async fn postgres_startup_concurrent_enabled_replicas_serialize_migration_and_adopt_once() {
    let fixture = StartupFixture::new("issuer_startup").await;
    let legacy_provider = fixture.provider().await;
    let original_row = fixture.rows("provider").await;
    // Hold the actual DB lease through a third pool, not LOCAL_MIGRATION. Both
    // startup futures must remain pending until this compatible lease releases.
    let lease_store = fixture.schema.connect_store().await;
    let lease = lease_store
        .acquire_refresh_guard("embedded-credential-references-v1", "migration")
        .await
        .unwrap();
    let (first, second) = {
        let first = fixture.start(&fixture.first);
        let second = fixture.start(&fixture.second);
        tokio::pin!(first, second);
        tokio::select! {
            result = &mut first => panic!("first startup bypassed migration lease: {result:?}"),
            result = &mut second => panic!("second startup bypassed migration lease: {result:?}"),
            () = tokio::time::sleep(Duration::from_millis(150)) => {},
        }
        assert_eq!(fixture.provider().await, legacy_provider);
        assert_eq!(fixture.rows("provider").await, original_row);
        assert!(
            fixture
                .rows("credential_issuer_activation")
                .await
                .is_empty()
        );
        drop(lease);
        tokio::time::timeout(Duration::from_secs(30), async {
            tokio::join!(&mut first, &mut second)
        })
        .await
        .expect("both compatible startup replicas finish after lease release")
    };
    let first = first.unwrap();
    let second = second.unwrap();
    fixture.assert_migrated(&first).await;
    fixture.assert_migrated(&second).await;
    let providers = fixture.rows("provider").await;
    assert_eq!(
        providers[PROVIDER_ID].0,
        original_row[PROVIDER_ID].0 + 1,
        "two enabled startups must publish the Provider exactly once"
    );
    let references = fixture.rows(REFERENCE_OBJECT_TYPE).await;
    let ciphertext = fixture
        .rows(openshell_credential_issuer::persistence::OBJECT_TYPE)
        .await;
    // A further actual startup must be a binding/backend no-op, not another
    // adoption or inline write, and must read the same persisted active grant.
    let restarted = fixture.start(&fixture.second).await.unwrap();
    fixture.assert_migrated(&restarted).await;
    assert_eq!(fixture.rows("provider").await, providers);
    assert_eq!(fixture.rows(REFERENCE_OBJECT_TYPE).await, references);
    assert_eq!(
        fixture
            .rows(openshell_credential_issuer::persistence::OBJECT_TYPE)
            .await,
        ciphertext
    );
    drop((first, second, restarted));
    lease_store.close().await;
    fixture.close().await;
}

#[tokio::test]
#[ignore = "requires OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
async fn postgres_startup_two_connection_pool_activates_and_restarts_without_self_exhaustion() {
    let fixture = StartupFixture::with_pool_size("issuer_startup_min_pool", Some(2)).await;
    assert_eq!(fixture.config.database_max_connections, Some(2));
    // Inspect the actual pools: setting Config alone does not resize an already
    // connected Store and would leave this regression hidden by the default 10.
    for store in [&fixture.first, &fixture.second] {
        let Store::Postgres(postgres) = store.as_ref() else {
            panic!("minimum-pool startup qualification requires PostgreSQL");
        };
        assert_eq!(postgres.max_connections(), 2);
    }
    let before = fixture.rows("provider").await;
    let first = tokio::time::timeout(Duration::from_secs(10), fixture.start(&fixture.first))
        .await
        .expect("first activation must make progress with two data connections, not wait on its own migration/credential leases")
        .expect("first activation must succeed at the supported PostgreSQL pool minimum");
    fixture.assert_migrated(&first).await;
    assert!(fixture.rows(LEGACY_TYPE).await.is_empty());
    let providers = fixture.rows("provider").await;
    assert_eq!(providers[PROVIDER_ID].0, before[PROVIDER_ID].0 + 1);
    let references = fixture.rows(REFERENCE_OBJECT_TYPE).await;
    let ciphertext = fixture
        .rows(openshell_credential_issuer::persistence::OBJECT_TYPE)
        .await;
    drop(first);

    // Restart through a genuinely independent two-connection Store/backend.
    // Existing provider-bound grant recovery must also leave a connection free
    // for database work while the activation migration lease is retained.
    let restarted = tokio::time::timeout(Duration::from_secs(10), fixture.start(&fixture.second))
        .await
        .expect("already-active startup must make progress with two data connections, including binding recovery")
        .expect("already-active startup must succeed at the supported PostgreSQL pool minimum");
    fixture.assert_migrated(&restarted).await;
    assert!(fixture.rows(LEGACY_TYPE).await.is_empty());
    assert_eq!(fixture.rows("provider").await, providers);
    assert_eq!(fixture.rows(REFERENCE_OBJECT_TYPE).await, references);
    assert_eq!(
        fixture
            .rows(openshell_credential_issuer::persistence::OBJECT_TYPE)
            .await,
        ciphertext
    );
    drop(restarted);
    fixture.close().await;
}

async fn failed_retirement_resumes(already_active: bool) {
    let fixture = StartupFixture::new("issuer_retirement").await;
    let control = &fixture.control;
    // Function, trigger, sequence, and objects all use this disposable schema.
    // Sequence increments survive the rejected statement and prove that the
    // injected retirement fault, not an unrelated startup error, was reached.
    sqlx::query("CREATE SEQUENCE retirement_fault_hits")
        .execute(control)
        .await
        .unwrap();
    // Reject both delete retirement and an implementation that sanitizes in place.
    sqlx::query(
        "CREATE FUNCTION reject_legacy_retirement() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN
           IF OLD.object_type = 'provider_credential_refresh_state' THEN
             PERFORM nextval('retirement_fault_hits');
             RAISE EXCEPTION 'test-only legacy retirement failure';
           END IF;
           IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
           RETURN NEW;
         END $$",
    )
    .execute(control)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER reject_legacy_retirement BEFORE DELETE OR UPDATE ON objects
         FOR EACH ROW EXECUTE FUNCTION reject_legacy_retirement()",
    )
    .execute(control)
    .await
    .unwrap();
    assert!(fixture.start(&fixture.first).await.is_err());
    let fault_reached: bool = sqlx::query_scalar("SELECT is_called FROM retirement_fault_hits")
        .fetch_one(control)
        .await
        .unwrap();
    assert!(
        fault_reached,
        "startup must reach the injected retirement fault"
    );
    assert!(
        crate::credential_activation::uses_reference_records(&fixture.second)
            .await
            .unwrap()
    );
    let legacy = fixture.rows(LEGACY_TYPE).await;
    assert_eq!(legacy.len(), 1);
    assert!(
        legacy[GRANT_ID]
            .1
            .windows(REFRESH_SECRET.len())
            .any(|window| window == REFRESH_SECRET.as_bytes())
    );
    let provider_before_resume = fixture.rows("provider").await;
    let reference_before_resume = fixture.rows(REFERENCE_OBJECT_TYPE).await;
    let ciphertext_before_resume = fixture
        .rows(openshell_credential_issuer::persistence::OBJECT_TYPE)
        .await;
    let versioned = VersionedCredentials::new(
        Arc::clone(&fixture.second),
        // A legacy, default-off runtime cannot open the converting database.
        // Reconstruct only the real encrypted backend to inspect durable grants.
        Arc::new(
            EmbeddedCredentialIssuer::from_options(
                &IssuerConfig {
                    credential_storage: fixture
                        .file
                        .openshell
                        .gateway
                        .credential_storage
                        .clone()
                        .unwrap(),
                    ..IssuerConfig::from(&fixture.config)
                },
                Some(Arc::new(
                    crate::credential_store::ServerDbCredstoreObjectStore::new(Arc::clone(
                        &fixture.second,
                    )),
                )),
            )
            .await
            .unwrap(),
        ),
    )
    .unwrap();
    let owner = SecretOwner::provider(WORKSPACE, PROVIDER_ID, PROVIDER_NAME);
    let grant_before_resume = versioned
        .references
        .get_grant(owner, GRANT_ID)
        .await
        .unwrap()
        .unwrap();
    assert!(grant_before_resume.active && !grant_before_resume.prepared);
    if already_active {
        // Model a previously completed pre-retirement release: issuer bindings
        // are committed but its old activation marker still says Active.
        let mut activation = crate::credential_activation::begin(Arc::clone(&fixture.second), true)
            .await
            .unwrap()
            .unwrap();
        activation.finish().await.unwrap();
        drop(activation);
    }
    let mut disabled = fixture.config.clone();
    disabled.enable_versioned_credentials = false;
    assert!(
        CredentialRuntime::from_config_file_with_store(
            &disabled,
            Some(&fixture.file),
            Arc::clone(&fixture.second)
        )
        .await
        .is_err()
    );
    sqlx::query("DROP TRIGGER reject_legacy_retirement ON objects")
        .execute(control)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION reject_legacy_retirement()")
        .execute(control)
        .await
        .unwrap();
    sqlx::query("DROP SEQUENCE retirement_fault_hits")
        .execute(control)
        .await
        .unwrap();
    let resumed = fixture.start(&fixture.second).await.unwrap();
    fixture.assert_migrated(&resumed).await;
    assert_eq!(fixture.rows("provider").await, provider_before_resume);
    assert_eq!(
        fixture.rows(REFERENCE_OBJECT_TYPE).await,
        reference_before_resume
    );
    assert_eq!(
        fixture
            .rows(openshell_credential_issuer::persistence::OBJECT_TYPE)
            .await,
        ciphertext_before_resume
    );
    let grant = resumed
        .versioned()
        .unwrap()
        .references
        .get_grant(owner, GRANT_ID)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(grant.resource_version, grant_before_resume.resource_version);
    assert_eq!(grant.state, grant_before_resume.state);
    drop((resumed, versioned));
    fixture.close().await;
}

#[tokio::test]
#[ignore = "requires OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
async fn postgres_startup_failed_legacy_retirement_resumes_without_reminting_or_rebinding() {
    Box::pin(failed_retirement_resumes(false)).await;
}

#[tokio::test]
#[ignore = "requires OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
async fn postgres_startup_already_active_marker_still_retires_legacy_plaintext_on_restart() {
    Box::pin(failed_retirement_resumes(true)).await;
}
