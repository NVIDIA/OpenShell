// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{RefreshMaterialDeletion, RefreshMaterialScope, ResolvedSecret};
use openshell_core::extension_protocol::NegotiatedExtension;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

mod retention;

#[derive(Default)]
struct MemoryStore {
    records: Mutex<HashMap<String, ReferenceRecord>>,
    retention_records: Mutex<HashMap<String, ReferenceRecord>>,
    conflicts: AtomicUsize,
    lose_activation_reply: AtomicBool,
    lose_retention_reply: AtomicBool,
    put_gate: Mutex<Option<crate::TestGate>>,
}

#[async_trait]
impl ReferenceStateStore for MemoryStore {
    async fn list(&self) -> Result<Vec<ReferenceRecord>, Status> {
        Ok(self.records.lock().unwrap().values().cloned().collect())
    }
    async fn get(&self, id: &str) -> Result<Option<ReferenceRecord>, Status> {
        Ok(self.records.lock().unwrap().get(id).cloned())
    }
    async fn get_retention(&self, id: &str) -> Result<Option<ReferenceRecord>, Status> {
        Ok(self.retention_records.lock().unwrap().get(id).cloned())
    }
    async fn put_retention(&self, id: &str, payload: Vec<u8>) -> Result<(), Status> {
        let mut records = self.retention_records.lock().unwrap();
        if records.contains_key(id) {
            return Err(Status::already_exists("retention ID already exists"));
        }
        records.insert(
            id.to_owned(),
            ReferenceRecord {
                resource_version: 1,
                payload,
            },
        );
        if self.lose_retention_reply.swap(false, Ordering::SeqCst) {
            return Err(Status::unavailable("lost retention reply"));
        }
        Ok(())
    }
    async fn put(&self, id: &str, expected: Option<u64>, payload: Vec<u8>) -> Result<(), Status> {
        let gate = self.put_gate.lock().unwrap().take();
        if let Some((release, entered)) = gate {
            let _ = entered.send(());
            let _ = release.await;
        }
        if self
            .conflicts
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_sub(1))
            .is_ok()
        {
            return Err(Status::aborted("injected conflict"));
        }
        let mut records = self.records.lock().unwrap();
        if records.get(id).map(|r| r.resource_version) != expected {
            return Err(Status::aborted("CAS conflict"));
        }
        let state: OwnerState = serde_json::from_slice(&payload).unwrap();
        let activated = state.operations.values().any(|op| op.result.is_some());
        records.insert(
            id.to_owned(),
            ReferenceRecord {
                resource_version: expected.unwrap_or(0).checked_add(1).unwrap(),
                payload,
            },
        );
        if activated && self.lose_activation_reply.swap(false, Ordering::SeqCst) {
            return Err(Status::unavailable("lost committed reply"));
        }
        Ok(())
    }
}

#[derive(Default)]
struct Backend {
    values: Mutex<HashMap<String, (String, Option<Timestamp>)>>,
    writes: AtomicUsize,
    fail_delete: AtomicBool,
    resolve_gate: Mutex<Option<crate::TestGate>>,
}
impl std::fmt::Debug for Backend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Backend([REDACTED])")
    }
}
impl Backend {
    fn put(&self, key: &str, id: &str, value: &str) -> CredentialHandle {
        let handle = CredentialHandle {
            driver: "test-driver".to_owned(),
            handle: id.to_owned(),
            metadata: HashMap::from([("legacy".to_owned(), "unchanged".to_owned())]),
        };
        self.values.lock().unwrap().insert(
            reference_id(key, &handle).unwrap(),
            (value.to_owned(), None),
        );
        handle
    }
    fn gate_resolve(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        *self.resolve_gate.lock().unwrap() = Some((release_rx, entered_tx));
        (entered_rx, release_tx)
    }
}

#[async_trait]
impl CredentialIssuer for Backend {
    fn validate_handles(&self, handles: &Handles) -> Result<(), Status> {
        if handles
            .values()
            .any(|h| h.driver != "test-driver" || h.handle.is_empty())
        {
            return Err(Status::invalid_argument("invalid backend handle"));
        }
        Ok(())
    }
    fn stores_provider_credentials(&self) -> bool {
        true
    }
    fn storage_owns_handle(&self, handle: &CredentialHandle) -> bool {
        handle.driver == "test-driver"
    }
    fn negotiated_extensions(&self) -> &[NegotiatedExtension] {
        &[]
    }
    async fn store(&self, request: StoreSecrets<'_>) -> Result<Handles, Status> {
        assert!(
            request.existing_handles.is_empty(),
            "immutable staging must not reuse an active backend handle"
        );
        self.writes.fetch_add(1, Ordering::SeqCst);
        Ok(request
            .values
            .iter()
            .map(|(key, value)| {
                (
                    key.clone(),
                    self.put(key, &format!("{}:{key}", request.object_id.unwrap()), value),
                )
            })
            .collect())
    }
    async fn delete(&self, _: SecretOwner<'_>, handles: &Handles) -> Result<(), Status> {
        if self.fail_delete.load(Ordering::SeqCst) {
            return Err(Status::unavailable("uncertain delete"));
        }
        for (key, handle) in handles {
            self.values
                .lock()
                .unwrap()
                .remove(&reference_id(key, handle)?);
        }
        Ok(())
    }
    async fn resolve(
        &self,
        _: SecretOwner<'_>,
        handles: &Handles,
    ) -> Result<Vec<ResolvedSecret>, Status> {
        let gate = self.resolve_gate.lock().unwrap().take();
        if let Some((release, entered)) = gate {
            let _ = entered.send(());
            let _ = release.await;
        }
        handles
            .iter()
            .map(|(key, handle)| {
                assert!(
                    ReferenceProjection::from_handle(handle).unwrap().is_none(),
                    "reference projection leaked into backend"
                );
                let values = self.values.lock().unwrap();
                let (value, expiration_time) = values
                    .get(&reference_id(key, handle)?)
                    .ok_or_else(|| Status::not_found("missing candidate"))?;
                Ok(ResolvedSecret {
                    credential_key: key.clone(),
                    value: value.clone(),
                    expiration_time: *expiration_time,
                })
            })
            .collect()
    }
    async fn store_refresh_material_with_object_id(
        &self,
        _: RefreshMaterialScope<'_>,
        _: &str,
        _: &HashMap<String, String>,
        _: &Handles,
    ) -> Result<Handles, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn resolve_refresh_material(
        &self,
        _: RefreshMaterialScope<'_>,
        _: &Handles,
    ) -> Result<HashMap<String, String>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn delete_refresh_material_handles(
        &self,
        _: RefreshMaterialScope<'_>,
        _: &Handles,
    ) -> Result<(), Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn delete_refresh_material_deletions(
        &self,
        _: RefreshMaterialScope<'_>,
        _: &[RefreshMaterialDeletion],
    ) -> Result<(), Status> {
        Err(Status::unimplemented("unused"))
    }
}

fn owner() -> SecretOwner<'static> {
    SecretOwner::provider("workspace", "immutable-owner-id", "display-name")
}
fn fixture() -> (Arc<ReferenceRuntime>, Arc<Backend>, Arc<MemoryStore>) {
    let backend = Arc::new(Backend::default());
    let store = Arc::new(MemoryStore::default());
    (
        Arc::new(ReferenceRuntime::new("durable-issuer", backend.clone(), store.clone()).unwrap()),
        backend,
        store,
    )
}
fn now() -> Timestamp {
    Timestamp {
        seconds: 10,
        nanos: 0,
    }
}
fn bundle(backend: &Backend, suffix: &str, value: &str) -> Handles {
    ["ACCESS", "SECRET", "SESSION"]
        .into_iter()
        .map(|key| {
            (
                key.to_owned(),
                backend.put(key, &format!("{key}-{suffix}"), &format!("{value}-{key}")),
            )
        })
        .collect()
}
async fn activate(
    runtime: &ReferenceRuntime,
    references: &Handles,
    candidates: &Handles,
    id: &str,
    generation: u64,
) -> Result<ActivatedBundle, Status> {
    runtime
        .activate_bundle(ActivateBundle {
            owner: owner(),
            epoch: "epoch",
            references,
            candidates,
            operation_id: id,
            expected_generation: generation,
            expiration_time: None,
            grant: None,
        })
        .await
}

#[tokio::test]
async fn adoption_preserves_bytes_metadata_and_starts_at_one_after_restart() {
    let (runtime, backend, store) = fixture();
    let originals = bundle(
        &backend,
        "legacy:opaque/bytes",
        "super-secret-never-persisted",
    );
    let references = runtime
        .adopt_with_expiration(owner(), "epoch", &originals, None, "migration")
        .await
        .unwrap();
    for (key, handle) in &references {
        assert_eq!(handle.handle, originals[key].handle);
        assert_eq!(handle.driver, originals[key].driver);
        assert_eq!(handle.metadata["legacy"], "unchanged");
        assert!(ReferenceProjection::from_handle(handle).unwrap().is_some());
    }
    let restarted = ReferenceRuntime::new("durable-issuer", backend, store.clone()).unwrap();
    let values = restarted
        .resolve_at(owner(), &references, now())
        .await
        .unwrap();
    assert_eq!(values.len(), 3);
    assert!(
        values
            .iter()
            .all(|value| value.version == 1 && value.generation == 1)
    );
    let again = restarted
        .adopt_with_expiration(owner(), "epoch", &originals, None, "migration")
        .await
        .unwrap();
    assert_eq!(references, again);
    for record in store.records.lock().unwrap().values() {
        assert!(!String::from_utf8_lossy(&record.payload).contains("super-secret-never-persisted"));
    }
}

#[tokio::test]
async fn pending_and_missing_adoption_cannot_fabricate_a_value() {
    let (runtime, backend, _) = fixture();
    let originals = bundle(&backend, "missing", "value");
    backend.values.lock().unwrap().clear();
    assert_eq!(
        runtime
            .adopt_with_expiration(owner(), "epoch", &originals, None, "migration")
            .await
            .err()
            .unwrap()
            .code(),
        Code::NotFound
    );
    let references = runtime
        .prepare_bundle(
            owner(),
            "epoch",
            &originals,
            &encode_string(&("adopt-prepare", "migration")).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        runtime
            .resolve_at(owner(), &references, now())
            .await
            .err()
            .unwrap()
            .code(),
        Code::FailedPrecondition
    );
}

#[tokio::test]
async fn successful_same_bytes_increment_but_idempotent_replay_and_failed_cas_do_not() {
    let (runtime, backend, store) = fixture();
    let first = bundle(&backend, "first", "same");
    let references = runtime
        .adopt_with_expiration(owner(), "epoch", &first, None, "adopt")
        .await
        .unwrap();
    let second = bundle(&backend, "second", "same");
    store.conflicts.store(2, Ordering::SeqCst);
    let result = activate(&runtime, &references, &second, "write-two", 1)
        .await
        .unwrap();
    assert!(result.receipt.versions.values().all(|v| *v == 2));
    assert_eq!(
        activate(&runtime, &references, &second, "write-two", 1)
            .await
            .unwrap()
            .receipt,
        result.receipt
    );
    let third = bundle(&backend, "third", "same");
    assert_eq!(
        activate(&runtime, &references, &third, "stale", 1)
            .await
            .err()
            .unwrap()
            .code(),
        Code::Aborted
    );
    assert_eq!(
        activate(&runtime, &references, &third, "write-two", 1)
            .await
            .err()
            .unwrap()
            .code(),
        Code::AlreadyExists
    );
    assert!(
        runtime
            .resolve_at(owner(), &references, now())
            .await
            .unwrap()
            .iter()
            .all(|v| v.version == 2 && v.generation == 2)
    );
}

#[tokio::test]
async fn lost_activation_reply_replays_the_original_committed_receipt() {
    let (runtime, backend, store) = fixture();
    let candidates = bundle(&backend, "first", "value");
    let references = runtime
        .prepare_bundle(owner(), "epoch", &candidates, "prepare")
        .await
        .unwrap();
    store.lose_activation_reply.store(true, Ordering::SeqCst);
    assert_eq!(
        activate(&runtime, &references, &candidates, "activate", 0)
            .await
            .err()
            .unwrap()
            .code(),
        Code::Unavailable
    );
    let result = activate(&runtime, &references, &candidates, "activate", 0)
        .await
        .unwrap();
    assert!(result.receipt.versions.values().all(|v| *v == 1));
    assert_eq!(result.receipt.generation, 1);
}

#[tokio::test]
async fn owner_key_driver_namespace_and_replacement_mismatches_are_denied() {
    let (runtime, backend, _) = fixture();
    let candidates = bundle(&backend, "first", "value");
    let references = runtime.adopt(owner(), &candidates, "adopt").await.unwrap();
    for other in [
        SecretOwner::provider("other-workspace", "immutable-owner-id", "display-name"),
        SecretOwner::provider("workspace", "replacement-id", "display-name"),
        SecretOwner::sandbox("workspace", "immutable-owner-id"),
    ] {
        assert_eq!(
            runtime
                .resolve_at(other, &references, now())
                .await
                .err()
                .unwrap()
                .code(),
            Code::PermissionDenied
        );
    }
    let renamed = SecretOwner::provider("workspace", "immutable-owner-id", "renamed-display");
    assert_eq!(
        runtime
            .resolve_at(renamed, &references, now())
            .await
            .unwrap()
            .len(),
        3
    );
    let mut wrong_driver = references.clone();
    wrong_driver.get_mut("ACCESS").unwrap().driver = "other".to_owned();
    assert_eq!(
        runtime
            .resolve_at(owner(), &wrong_driver, now())
            .await
            .err()
            .unwrap()
            .code(),
        Code::PermissionDenied
    );
    let mut wrong_key = references.clone();
    let misplaced = wrong_key.remove("ACCESS").unwrap();
    wrong_key.insert("WRONG".to_owned(), misplaced);
    assert_eq!(
        runtime
            .resolve_at(owner(), &wrong_key, now())
            .await
            .err()
            .unwrap()
            .code(),
        Code::PermissionDenied
    );
}

#[tokio::test]
async fn exact_tombstone_never_resurrects_or_resets_version() {
    let (runtime, backend, _) = fixture();
    let first = bundle(&backend, "first", "value");
    let references = runtime
        .adopt_with_expiration(owner(), "epoch", &first, None, "adopt")
        .await
        .unwrap();
    runtime.delete(owner(), &references).await.unwrap();
    runtime.delete(owner(), &references).await.unwrap();
    let second = bundle(&backend, "second", "value");
    assert_eq!(
        activate(&runtime, &references, &second, "late-mint", 1)
            .await
            .err()
            .unwrap()
            .code(),
        Code::FailedPrecondition
    );
    assert_eq!(
        runtime
            .prepare_bundle(owner(), "new-epoch", &first, "reuse-identity")
            .await
            .err()
            .unwrap()
            .code(),
        Code::AlreadyExists
    );
    assert_eq!(
        runtime
            .resolve_at(owner(), &references, now())
            .await
            .err()
            .unwrap()
            .code(),
        Code::FailedPrecondition
    );
    let identities =
        ReferenceRuntime::pending_handles("test-driver", first.keys().cloned()).unwrap();
    let replacement = runtime
        .prepare_bundle(owner(), "new-epoch", &identities, "replacement")
        .await
        .unwrap();
    runtime
        .activate_bundle(ActivateBundle {
            owner: owner(),
            epoch: "new-epoch",
            references: &replacement,
            candidates: &second,
            operation_id: "first-new",
            expected_generation: 0,
            expiration_time: None,
            grant: None,
        })
        .await
        .unwrap();
    assert!(
        runtime
            .resolve_at(owner(), &replacement, now())
            .await
            .unwrap()
            .iter()
            .all(|v| v.version == 1)
    );
}

#[tokio::test]
async fn checked_overflow_leaves_entire_bundle_unchanged() {
    let (runtime, backend, _) = fixture();
    let first = bundle(&backend, "first", "value");
    let references = runtime
        .adopt_with_expiration(owner(), "epoch", &first, None, "adopt")
        .await
        .unwrap();
    let (version, mut state) = runtime.load(owner()).await.unwrap();
    let manifest_id = ReferenceProjection::from_handle(&references["ACCESS"])
        .unwrap()
        .unwrap()
        .manifest_id;
    state
        .manifests
        .get_mut(&manifest_id)
        .unwrap()
        .outputs
        .get_mut("SECRET")
        .unwrap()
        .version = u64::MAX;
    runtime.save(owner(), version, &state).await.unwrap();
    let second = bundle(&backend, "second", "value");
    assert_eq!(
        activate(&runtime, &references, &second, "overflow", 1)
            .await
            .err()
            .unwrap()
            .code(),
        Code::OutOfRange
    );
    let values = runtime
        .resolve_at(owner(), &references, now())
        .await
        .unwrap();
    assert!(values.iter().all(|v| v.generation == 1));
    assert_eq!(
        values
            .iter()
            .find(|v| v.credential_key == "SECRET")
            .unwrap()
            .version,
        u64::MAX
    );
}

#[tokio::test]
async fn resolve_racing_activation_and_cleanup_retries_the_whole_capture() {
    let (runtime, backend, _) = fixture();
    let first = bundle(&backend, "first", "old");
    let references = runtime
        .adopt_with_expiration(owner(), "epoch", &first, None, "adopt")
        .await
        .unwrap();
    let (entered, release) = backend.gate_resolve();
    let reader = {
        let runtime = runtime.clone();
        let references = references.clone();
        tokio::spawn(async move { runtime.resolve_at(owner(), &references, now()).await })
    };
    entered.await.unwrap();
    let second = bundle(&backend, "second", "new");
    activate(&runtime, &references, &second, "next", 1)
        .await
        .unwrap();
    assert_eq!(runtime.reclaim(owner(), 10).await.unwrap(), 3);
    release.send(()).unwrap();
    let values = reader.await.unwrap().unwrap();
    assert!(
        values
            .iter()
            .all(|v| v.version == 2 && v.generation == 2 && v.value.starts_with("new-"))
    );
}

#[tokio::test]
async fn issuer_and_backend_expiration_are_captured_and_minimized() {
    let (runtime, backend, _) = fixture();
    let candidate = backend.put("KEY", "candidate", "value");
    backend
        .values
        .lock()
        .unwrap()
        .get_mut(&reference_id("KEY", &candidate).unwrap())
        .unwrap()
        .1 = Some(Timestamp {
        seconds: 20,
        nanos: 0,
    });
    let candidates = HashMap::from([("KEY".to_owned(), candidate)]);
    let references = runtime
        .adopt_with_expiration(
            owner(),
            "epoch",
            &candidates,
            Some(Timestamp {
                seconds: 15,
                nanos: 500,
            }),
            "adopt",
        )
        .await
        .unwrap();
    let values = runtime
        .resolve_at(owner(), &references, now())
        .await
        .unwrap();
    assert_eq!(
        values[0].expiration_time,
        Some(Timestamp {
            seconds: 15,
            nanos: 500
        })
    );
    assert_eq!(
        runtime
            .resolve_at(
                owner(),
                &references,
                Timestamp {
                    seconds: 15,
                    nanos: 500
                }
            )
            .await
            .err()
            .unwrap()
            .code(),
        Code::FailedPrecondition
    );
}

#[tokio::test]
async fn shared_candidate_is_not_reclaimed_and_claimed_candidate_cannot_gain_a_link() {
    let (runtime, backend, _) = fixture();
    let candidates = bundle(&backend, "shared", "value");
    let old = runtime
        .adopt_with_expiration(owner(), "epoch", &candidates, None, "old")
        .await
        .unwrap();
    let identities =
        ReferenceRuntime::pending_handles("test-driver", candidates.keys().cloned()).unwrap();
    let retained = runtime
        .prepare_bundle(owner(), "static-retained", &identities, "retained")
        .await
        .unwrap();
    runtime
        .activate_bundle(ActivateBundle {
            owner: owner(),
            epoch: "static-retained",
            references: &retained,
            candidates: &candidates,
            operation_id: "retain",
            expected_generation: 0,
            expiration_time: None,
            grant: None,
        })
        .await
        .unwrap();
    runtime.delete(owner(), &old).await.unwrap();
    assert_eq!(runtime.reclaim(owner(), 10).await.unwrap(), 0);
    assert_eq!(
        runtime
            .resolve_at(owner(), &retained, now())
            .await
            .unwrap()
            .len(),
        3
    );
    runtime.delete(owner(), &retained).await.unwrap();
    backend.fail_delete.store(true, Ordering::SeqCst);
    assert_eq!(
        runtime.reclaim(owner(), 1).await.err().unwrap().code(),
        Code::Unavailable
    );
    let identities =
        ReferenceRuntime::pending_handles("test-driver", candidates.keys().cloned()).unwrap();
    let resurrection = runtime
        .prepare_bundle(owner(), "another-epoch", &identities, "another")
        .await
        .unwrap();
    assert_eq!(
        runtime
            .activate_bundle(ActivateBundle {
                owner: owner(),
                epoch: "another-epoch",
                references: &resurrection,
                candidates: &candidates,
                operation_id: "too-late",
                expected_generation: 0,
                expiration_time: None,
                grant: None
            })
            .await
            .err()
            .unwrap()
            .code(),
        Code::FailedPrecondition
    );
    backend.fail_delete.store(false, Ordering::SeqCst);
    assert_eq!(runtime.reclaim(owner(), 10).await.unwrap(), 3);
}

#[tokio::test]
async fn grant_finalization_and_all_output_versions_share_one_cas() {
    let (runtime, backend, _) = fixture();
    let candidates = bundle(&backend, "first", "value");
    let references = runtime
        .prepare_bundle(owner(), "epoch", &candidates, "prepare")
        .await
        .unwrap();
    let grant = runtime
        .put_grant(owner(), "grant", None, "epoch", b"parked", true)
        .await
        .unwrap();
    let request = |version| ActivateBundle {
        owner: owner(),
        epoch: "epoch",
        references: &references,
        candidates: &candidates,
        operation_id: "activate",
        expected_generation: 0,
        expiration_time: None,
        grant: Some(GrantTransition {
            grant_id: "grant",
            expected_resource_version: version,
            state: b"refreshed",
        }),
    };
    assert_eq!(
        runtime
            .activate_bundle(request(grant.resource_version + 1))
            .await
            .err()
            .unwrap()
            .code(),
        Code::Aborted
    );
    runtime
        .activate_bundle(request(grant.resource_version))
        .await
        .unwrap();
    let current = runtime.get_grant(owner(), "grant").await.unwrap().unwrap();
    assert_eq!(current.resource_version, grant.resource_version + 1);
    assert_eq!(current.state, b"refreshed");
    assert!(
        runtime
            .resolve_at(owner(), &references, now())
            .await
            .unwrap()
            .iter()
            .all(|v| v.version == 1)
    );
    runtime
        .activate_bundle(request(grant.resource_version))
        .await
        .unwrap();
    assert_eq!(
        runtime
            .get_grant(owner(), "grant")
            .await
            .unwrap()
            .unwrap()
            .resource_version,
        current.resource_version
    );
    runtime
        .revoke(owner(), &references, Some("grant"))
        .await
        .unwrap();
    let grant = runtime.get_grant(owner(), "grant").await.unwrap().unwrap();
    assert!(!grant.active);
    assert_eq!(
        runtime
            .put_grant(
                owner(),
                "grant",
                Some(grant.resource_version),
                "epoch",
                b"revive",
                true
            )
            .await
            .err()
            .unwrap()
            .code(),
        Code::FailedPrecondition
    );
}

#[tokio::test]
async fn static_updates_preserve_identity_increment_same_bytes_and_bind_protected_intent() {
    let (runtime, backend, store) = fixture();
    let values = HashMap::from([(
        "KEY".to_owned(),
        "plaintext-not-in-reference-state".to_owned(),
    )]);
    let empty = Handles::new();
    let first = runtime
        .store(StoreReferenceSecrets {
            owner: owner(),
            epoch: "static",
            write_id: "first",
            protected_intent: b"authenticated-ciphertext-one",
            values: &values,
            existing_handles: &empty,
            expiration_time: None,
        })
        .await
        .unwrap();
    let repeated = runtime
        .store(StoreReferenceSecrets {
            owner: owner(),
            epoch: "static",
            write_id: "first",
            protected_intent: b"authenticated-ciphertext-one",
            values: &values,
            existing_handles: &empty,
            expiration_time: None,
        })
        .await
        .unwrap();
    assert_eq!(first, repeated);
    assert_eq!(backend.writes.load(Ordering::SeqCst), 1);
    let updated = runtime
        .store(StoreReferenceSecrets {
            owner: owner(),
            epoch: "static",
            write_id: "second",
            protected_intent: b"authenticated-ciphertext-two",
            values: &values,
            existing_handles: &first,
            expiration_time: None,
        })
        .await
        .unwrap();
    assert_eq!(updated, first);
    assert_eq!(
        runtime.resolve_at(owner(), &updated, now()).await.unwrap()[0].version,
        2
    );
    assert_eq!(
        runtime
            .store(StoreReferenceSecrets {
                owner: owner(),
                epoch: "static",
                write_id: "second",
                protected_intent: b"different-intent",
                values: &values,
                existing_handles: &first,
                expiration_time: None
            })
            .await
            .err()
            .unwrap()
            .code(),
        Code::AlreadyExists
    );
    assert_eq!(runtime.write_recovery(owner()).await.unwrap().len(), 2);
    for record in store.records.lock().unwrap().values() {
        assert!(
            !String::from_utf8_lossy(&record.payload).contains("plaintext-not-in-reference-state")
        );
    }
}

#[tokio::test]
async fn prepared_grant_and_replacement_activation_are_atomic_and_restart_safe() {
    let (runtime, backend, store) = fixture();
    let first = bundle(&backend, "old", "old-value");
    let old_refs = runtime
        .prepare_bundle(owner(), "old-epoch", &first, "old-refs")
        .await
        .unwrap();
    let old = runtime
        .prepare_grant(owner(), "old-grant", "old-epoch", b"old-config")
        .await
        .unwrap();
    assert!(old.prepared && !old.active);
    assert_eq!(
        runtime
            .prepare_grant(owner(), "old-grant", "old-epoch", b"old-config")
            .await
            .unwrap()
            .resource_version,
        1
    );
    assert_eq!(
        runtime
            .resolve_at(owner(), &old_refs, now())
            .await
            .err()
            .unwrap()
            .code(),
        Code::FailedPrecondition
    );
    let old = runtime
        .activate_grant(owner(), "old-grant", old.resource_version, None)
        .await
        .unwrap();
    runtime
        .activate_bundle(ActivateBundle {
            owner: owner(),
            epoch: "old-epoch",
            references: &old_refs,
            candidates: &first,
            operation_id: "first-output",
            expected_generation: 0,
            expiration_time: None,
            grant: Some(GrantTransition {
                grant_id: "old-grant",
                expected_resource_version: old.resource_version,
                state: b"old-refreshed",
            }),
        })
        .await
        .unwrap();
    let old = runtime
        .get_grant(owner(), "old-grant")
        .await
        .unwrap()
        .unwrap();
    let new = runtime
        .prepare_grant(owner(), "new-grant", "new-epoch", b"new-config")
        .await
        .unwrap();
    assert_eq!(
        runtime
            .list_grants(Some("immutable-owner-id"))
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        runtime
            .activate_grant(
                owner(),
                "new-grant",
                new.resource_version,
                Some(("old-grant", old.resource_version - 1))
            )
            .await
            .err()
            .unwrap()
            .code(),
        Code::Aborted
    );
    assert_eq!(
        runtime
            .resolve_at(owner(), &old_refs, now())
            .await
            .unwrap()
            .len(),
        3
    );
    assert!(
        runtime
            .get_grant(owner(), "new-grant")
            .await
            .unwrap()
            .unwrap()
            .prepared
    );
    store.conflicts.store(2, Ordering::SeqCst);
    let activated = runtime
        .activate_grant(
            owner(),
            "new-grant",
            new.resource_version,
            Some(("old-grant", old.resource_version)),
        )
        .await
        .unwrap();
    assert!(activated.active && !activated.prepared);
    assert!(
        !runtime
            .get_grant(owner(), "old-grant")
            .await
            .unwrap()
            .unwrap()
            .active
    );
    assert_eq!(
        runtime
            .resolve_at(owner(), &old_refs, now())
            .await
            .err()
            .unwrap()
            .code(),
        Code::FailedPrecondition
    );
    let restarted = ReferenceRuntime::new("durable-issuer", backend, store).unwrap();
    let replayed = restarted
        .activate_grant(
            owner(),
            "new-grant",
            new.resource_version,
            Some(("old-grant", old.resource_version)),
        )
        .await
        .unwrap();
    assert_eq!(replayed.resource_version, activated.resource_version);
    assert_eq!(
        restarted
            .activate_grant(owner(), "new-grant", new.resource_version, None)
            .await
            .err()
            .unwrap()
            .code(),
        Code::AlreadyExists
    );
}

#[tokio::test]
async fn tombstone_persists_deletion_bytes_with_revocation_and_cleanup_never_erases_identity() {
    let (runtime, backend, _) = fixture();
    let candidates = bundle(&backend, "old", "value");
    let refs = runtime
        .prepare_bundle(owner(), "epoch", &candidates, "references")
        .await
        .unwrap();
    let grant = runtime
        .prepare_grant(owner(), "grant", "epoch", b"configured")
        .await
        .unwrap();
    let grant = runtime
        .activate_grant(owner(), "grant", grant.resource_version, None)
        .await
        .unwrap();
    runtime
        .activate_bundle(ActivateBundle {
            owner: owner(),
            epoch: "epoch",
            references: &refs,
            candidates: &candidates,
            operation_id: "first",
            expected_generation: 0,
            expiration_time: None,
            grant: Some(GrantTransition {
                grant_id: "grant",
                expected_resource_version: grant.resource_version,
                state: b"refreshed",
            }),
        })
        .await
        .unwrap();
    let grant = runtime.get_grant(owner(), "grant").await.unwrap().unwrap();
    let deleted = runtime
        .tombstone_grant(
            owner(),
            "grant",
            grant.resource_version,
            b"new-domain-revocation-marker-with-cleanup-debt",
        )
        .await
        .unwrap();
    assert_eq!(deleted.epoch, "epoch");
    assert!(!deleted.active && !deleted.prepared);
    assert_eq!(
        deleted.state,
        b"new-domain-revocation-marker-with-cleanup-debt"
    );
    assert_eq!(
        runtime
            .resolve_at(owner(), &refs, now())
            .await
            .err()
            .unwrap()
            .code(),
        Code::FailedPrecondition
    );
    let replay = runtime
        .tombstone_grant(
            owner(),
            "grant",
            grant.resource_version,
            b"new-domain-revocation-marker-with-cleanup-debt",
        )
        .await
        .unwrap();
    assert_eq!(replay.resource_version, deleted.resource_version);
    let cleaned = runtime
        .finish_grant_cleanup(
            owner(),
            "grant",
            deleted.resource_version,
            b"cleanup-complete",
        )
        .await
        .unwrap();
    assert_eq!(cleaned.resource_version, deleted.resource_version + 1);
    assert!(!cleaned.active && !cleaned.prepared);
    assert_eq!(
        runtime
            .prepare_grant(owner(), "grant", "replacement", b"new-config")
            .await
            .err()
            .unwrap()
            .code(),
        Code::AlreadyExists
    );
    assert_eq!(
        runtime
            .activate_grant(owner(), "grant", cleaned.resource_version, None)
            .await
            .err()
            .unwrap()
            .code(),
        Code::FailedPrecondition
    );
    assert_eq!(runtime.list_grants(None).await.unwrap().len(), 1);
}

#[tokio::test]
async fn abandoned_prepared_grant_is_a_tombstone_not_an_authorizable_candidate() {
    let (runtime, _, _) = fixture();
    let grant = runtime
        .prepare_grant(owner(), "abandoned", "epoch", b"before-provider-cas")
        .await
        .unwrap();
    let tombstone = runtime
        .tombstone_grant(
            owner(),
            "abandoned",
            grant.resource_version,
            b"provider-cas-lost",
        )
        .await
        .unwrap();
    assert!(!tombstone.active && !tombstone.prepared);
    assert_eq!(
        runtime
            .activate_grant(owner(), "abandoned", tombstone.resource_version, None)
            .await
            .err()
            .unwrap()
            .code(),
        Code::FailedPrecondition
    );
}

#[tokio::test]
async fn binding_validation_allows_an_older_capture_but_not_pending_or_revoked_epochs() {
    let (runtime, backend, _) = fixture();
    let first = bundle(&backend, "old", "old-value");
    let references = runtime
        .prepare_bundle(owner(), "epoch", &first, "prepare")
        .await
        .unwrap();
    assert!(
        !runtime
            .validate_bindings(owner(), &references)
            .await
            .unwrap()
    );
    activate(&runtime, &references, &first, "initial", 0)
        .await
        .unwrap();
    let captured = runtime
        .resolve_at(owner(), &references, now())
        .await
        .unwrap();
    let second = bundle(&backend, "new", "new-value");
    activate(&runtime, &references, &second, "rotation", 1)
        .await
        .unwrap();
    assert!(
        runtime
            .validate_bindings(owner(), &references)
            .await
            .unwrap()
    );
    assert!(
        !runtime
            .validate_resolution(owner(), &references, &captured)
            .await
            .unwrap()
    );
    runtime.delete(owner(), &references).await.unwrap();
    assert!(
        !runtime
            .validate_bindings(owner(), &references)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn rebind_retains_candidates_and_each_exact_expiration_without_backend_writes() {
    let (runtime, backend, _) = fixture();
    let originals = bundle(&backend, "retained", "value");
    let source = runtime
        .adopt_with_expiration(owner(), "epoch", &originals, None, "old")
        .await
        .unwrap();
    let (version, mut state) = runtime.load(owner()).await.unwrap();
    let old_manifest_id = ReferenceProjection::from_handle(&source["ACCESS"])
        .unwrap()
        .unwrap()
        .manifest_id;
    let old_manifest = state.manifests.get_mut(&old_manifest_id).unwrap();
    for (index, output) in old_manifest.outputs.values_mut().enumerate() {
        output.version = 40;
        output.expiration = Some(Expiry {
            seconds: 30 + i64::try_from(index).unwrap(),
            nanos: 125,
        });
    }
    runtime.save(owner(), version, &state).await.unwrap();
    let old = runtime.resolve_at(owner(), &source, now()).await.unwrap();
    let identities =
        ReferenceRuntime::pending_handles("test-driver", originals.keys().cloned()).unwrap();
    let retained = runtime
        .rebind_bundle(
            owner(),
            "retained-epoch",
            &source,
            &identities,
            "retain-values",
        )
        .await
        .unwrap();
    assert_eq!(
        runtime
            .manifest_generation(owner(), "retained-epoch", &retained)
            .await
            .unwrap(),
        1
    );
    let new = runtime.resolve_at(owner(), &retained, now()).await.unwrap();
    for (old, new) in old.iter().zip(&new) {
        assert_eq!(old.credential_key, new.credential_key);
        assert_eq!(old.expiration_time, new.expiration_time);
        assert_eq!(old.value, new.value);
        assert_eq!(new.version, 1);
        assert_ne!(old.reference.reference_id, new.reference.reference_id);
    }
    runtime.delete(owner(), &source).await.unwrap();
    assert_eq!(runtime.reclaim(owner(), 10).await.unwrap(), 0);
    assert_eq!(
        runtime
            .resolve_at(owner(), &retained, now())
            .await
            .unwrap()
            .len(),
        3
    );
    assert_eq!(
        runtime
            .rebind_bundle(
                owner(),
                "retained-epoch",
                &source,
                &identities,
                "retain-values"
            )
            .await
            .unwrap(),
        retained
    );
    assert_eq!(backend.writes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn rebind_from_pending_stays_pending_and_cannot_retain_a_revoked_source() {
    let (runtime, backend, _) = fixture();
    let originals = bundle(&backend, "pending", "value");
    let source = runtime
        .prepare_bundle(owner(), "epoch", &originals, "source")
        .await
        .unwrap();
    let identities =
        ReferenceRuntime::pending_handles("test-driver", originals.keys().cloned()).unwrap();
    let retained = runtime
        .rebind_bundle(owner(), "new-epoch", &source, &identities, "retain-pending")
        .await
        .unwrap();
    assert_eq!(
        runtime
            .manifest_generation(owner(), "new-epoch", &retained)
            .await
            .unwrap(),
        0
    );
    assert!(!runtime.validate_bindings(owner(), &retained).await.unwrap());
    activate(&runtime, &source, &originals, "first", 0)
        .await
        .unwrap();
    assert_eq!(
        runtime
            .rebind_bundle(owner(), "new-epoch", &source, &identities, "retain-pending")
            .await
            .unwrap(),
        retained
    );
    assert_eq!(
        runtime
            .manifest_generation(owner(), "new-epoch", &retained)
            .await
            .unwrap(),
        0
    );
    runtime.delete(owner(), &source).await.unwrap();
    let other =
        ReferenceRuntime::pending_handles("test-driver", originals.keys().cloned()).unwrap();
    assert_eq!(
        runtime
            .rebind_bundle(owner(), "other-epoch", &source, &other, "revoked-source")
            .await
            .err()
            .unwrap()
            .code(),
        Code::FailedPrecondition
    );
}

#[tokio::test]
async fn static_retention_clears_only_issuer_expiry_and_remains_independently_writable() {
    let (runtime, backend, _) = fixture();
    let handle = backend.put("KEY", "candidate", "value");
    backend
        .values
        .lock()
        .unwrap()
        .get_mut(&reference_id("KEY", &handle).unwrap())
        .unwrap()
        .1 = Some(Timestamp {
        seconds: 50,
        nanos: 25,
    });
    let candidates = HashMap::from([("KEY".to_owned(), handle)]);
    let source = runtime
        .adopt_with_expiration(
            owner(),
            "epoch",
            &candidates,
            Some(Timestamp {
                seconds: 20,
                nanos: 0,
            }),
            "adopt",
        )
        .await
        .unwrap();
    let identities =
        ReferenceRuntime::pending_handles("test-driver", vec!["KEY".to_owned()]).unwrap();
    let retained = runtime
        .rebind_static(owner(), &source, &identities, "disable-refresh")
        .await
        .unwrap();
    let value = runtime
        .resolve_at(
            owner(),
            &retained,
            Timestamp {
                seconds: 30,
                nanos: 0,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        value[0].expiration_time,
        Some(Timestamp {
            seconds: 50,
            nanos: 25
        })
    );
    assert_eq!(value[0].reference.epoch, "static");
    runtime.delete(owner(), &source).await.unwrap();
    assert_eq!(runtime.reclaim(owner(), 10).await.unwrap(), 0);
    let values = HashMap::from([("KEY".to_owned(), "new-static-value".to_owned())]);
    let updated = runtime
        .store(StoreReferenceSecrets {
            owner: owner(),
            epoch: "static",
            write_id: "direct-static-update",
            protected_intent: b"protected-new-intent",
            values: &values,
            existing_handles: &retained,
            expiration_time: None,
        })
        .await
        .unwrap();
    assert_eq!(updated, retained);
    assert_eq!(
        runtime.resolve_at(owner(), &updated, now()).await.unwrap()[0].version,
        2
    );
}

#[tokio::test]
async fn retained_values_are_withheld_while_the_new_grant_is_only_prepared() {
    let (runtime, backend, _) = fixture();
    let originals = bundle(&backend, "old", "value");
    let source = runtime
        .adopt_with_expiration(owner(), "epoch", &originals, None, "source")
        .await
        .unwrap();
    let identities =
        ReferenceRuntime::pending_handles("test-driver", originals.keys().cloned()).unwrap();
    let retained = runtime
        .rebind_bundle(owner(), "new-epoch", &source, &identities, "retain")
        .await
        .unwrap();
    let prepared = runtime
        .prepare_grant(
            owner(),
            "new-grant",
            "new-epoch",
            b"prepared-provider-binding",
        )
        .await
        .unwrap();
    assert!(!runtime.validate_bindings(owner(), &retained).await.unwrap());
    assert_eq!(
        runtime
            .resolve_at(owner(), &retained, now())
            .await
            .err()
            .unwrap()
            .code(),
        Code::FailedPrecondition
    );
    runtime
        .activate_grant(owner(), "new-grant", prepared.resource_version, None)
        .await
        .unwrap();
    assert!(runtime.validate_bindings(owner(), &retained).await.unwrap());
    assert_eq!(
        runtime
            .resolve_at(owner(), &retained, now())
            .await
            .unwrap()
            .len(),
        3
    );
}

#[tokio::test]
async fn metadata_only_grant_reader_needs_no_backend_and_keeps_namespace_and_owner_filters() {
    let (runtime, _, store) = fixture();
    runtime
        .prepare_grant(owner(), "z-prepared", "epoch-z", b"prepared-metadata")
        .await
        .unwrap();
    let tombstone = runtime
        .prepare_grant(owner(), "a-tombstone", "epoch-a", b"prepared-metadata")
        .await
        .unwrap();
    runtime
        .tombstone_grant(
            owner(),
            "a-tombstone",
            tombstone.resource_version,
            b"deleted-metadata",
        )
        .await
        .unwrap();
    drop(runtime);
    let records = read_grants(store.as_ref(), "durable-issuer", Some("immutable-owner-id"))
        .await
        .unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].1, "a-tombstone");
    assert!(!records[0].2.active && !records[0].2.prepared);
    assert_eq!(records[1].1, "z-prepared");
    assert!(records[1].2.prepared);
    assert!(
        read_grants(store.as_ref(), "different-issuer", None)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        read_grants(
            store.as_ref(),
            "durable-issuer",
            Some("replacement-owner-id")
        )
        .await
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        read_grants(store.as_ref(), "", None)
            .await
            .err()
            .unwrap()
            .code(),
        Code::InvalidArgument
    );
}

#[tokio::test]
async fn prepared_primary_expiration_changes_without_versions_and_cannot_change_after_activation() {
    let (runtime, backend, store) = fixture();
    let originals = bundle(&backend, "source", "value");
    let source = runtime
        .adopt_with_expiration(
            owner(),
            "epoch",
            &originals,
            Some(Timestamp {
                seconds: 40,
                nanos: 0,
            }),
            "source",
        )
        .await
        .unwrap();
    let identities =
        ReferenceRuntime::pending_handles("test-driver", originals.keys().cloned()).unwrap();
    let retained = runtime
        .rebind_bundle(owner(), "new-epoch", &source, &identities, "retain")
        .await
        .unwrap();
    let grant = runtime
        .prepare_grant(owner(), "prepared", "new-epoch", b"new-config")
        .await
        .unwrap();
    let requested = Timestamp {
        seconds: 25,
        nanos: 125,
    };
    store.conflicts.store(2, Ordering::SeqCst);
    runtime
        .set_prepared_grant_expiration(owner(), "prepared", "ACCESS", Some(requested))
        .await
        .unwrap();
    runtime
        .set_prepared_grant_expiration(owner(), "prepared", "ACCESS", Some(requested))
        .await
        .unwrap();
    assert_eq!(
        runtime
            .manifest_generation(owner(), "new-epoch", &retained)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        runtime
            .get_grant(owner(), "prepared")
            .await
            .unwrap()
            .unwrap()
            .resource_version,
        grant.resource_version
    );
    runtime
        .activate_grant(owner(), "prepared", grant.resource_version, None)
        .await
        .unwrap();
    let resolved = runtime.resolve_at(owner(), &retained, now()).await.unwrap();
    assert!(
        resolved
            .iter()
            .all(|value| value.version == 1 && value.generation == 1)
    );
    assert_eq!(
        resolved
            .iter()
            .find(|value| value.credential_key == "ACCESS")
            .unwrap()
            .expiration_time,
        Some(requested)
    );
    assert!(
        resolved
            .iter()
            .filter(|value| value.credential_key != "ACCESS")
            .all(|value| value.expiration_time
                == Some(Timestamp {
                    seconds: 40,
                    nanos: 0
                }))
    );
    assert_eq!(
        runtime
            .set_prepared_grant_expiration(owner(), "prepared", "ACCESS", None)
            .await
            .err()
            .unwrap()
            .code(),
        Code::FailedPrecondition
    );
}

#[tokio::test]
async fn prepared_expiration_can_clear_retained_expiry_and_leaves_pending_outputs_pending() {
    let (runtime, backend, _) = fixture();
    let candidates = bundle(&backend, "source", "value");
    let source = runtime
        .adopt_with_expiration(
            owner(),
            "epoch",
            &candidates,
            Some(Timestamp {
                seconds: 20,
                nanos: 0,
            }),
            "source",
        )
        .await
        .unwrap();
    let identities =
        ReferenceRuntime::pending_handles("test-driver", candidates.keys().cloned()).unwrap();
    let retained = runtime
        .rebind_bundle(owner(), "new-epoch", &source, &identities, "retained")
        .await
        .unwrap();
    let grant = runtime
        .prepare_grant(owner(), "prepared", "new-epoch", b"config")
        .await
        .unwrap();
    runtime
        .set_prepared_grant_expiration(owner(), "prepared", "ACCESS", None)
        .await
        .unwrap();
    runtime
        .activate_grant(owner(), "prepared", grant.resource_version, None)
        .await
        .unwrap();
    let resolved = runtime
        .resolve_at(
            owner(),
            &HashMap::from([("ACCESS".to_owned(), retained["ACCESS"].clone())]),
            Timestamp {
                seconds: 30,
                nanos: 0,
            },
        )
        .await
        .unwrap();
    assert_eq!(resolved[0].expiration_time, None);
    let identities =
        ReferenceRuntime::pending_handles("test-driver", candidates.keys().cloned()).unwrap();
    let pending = runtime
        .prepare_bundle(owner(), "pending-epoch", &identities, "pending")
        .await
        .unwrap();
    let pending_grant = runtime
        .prepare_grant(owner(), "pending-grant", "pending-epoch", b"pending-config")
        .await
        .unwrap();
    runtime
        .set_prepared_grant_expiration(
            owner(),
            "pending-grant",
            "ACCESS",
            Some(Timestamp {
                seconds: 25,
                nanos: 0,
            }),
        )
        .await
        .unwrap();
    assert_eq!(
        runtime
            .manifest_generation(owner(), "pending-epoch", &pending)
            .await
            .unwrap(),
        0
    );
    runtime
        .activate_grant(
            owner(),
            "pending-grant",
            pending_grant.resource_version,
            None,
        )
        .await
        .unwrap();
    assert!(!runtime.validate_bindings(owner(), &pending).await.unwrap());
    runtime
        .tombstone_grant(owner(), "prepared", grant.resource_version + 1, b"deleted")
        .await
        .unwrap();
    assert_eq!(
        runtime
            .set_prepared_grant_expiration(owner(), "prepared", "ACCESS", None)
            .await
            .err()
            .unwrap()
            .code(),
        Code::FailedPrecondition
    );
}

mod backend_protocol;

#[tokio::test]
async fn static_bundle_retention_retries_entire_source_capture_after_activation_race() {
    let (runtime, backend, store) = fixture();
    let first = bundle(&backend, "first", "old");
    let source = runtime
        .adopt_with_expiration(
            owner(),
            "epoch",
            &first,
            Some(Timestamp {
                seconds: 20,
                nanos: 0,
            }),
            "adopt-source",
        )
        .await
        .unwrap();
    let identities =
        ReferenceRuntime::pending_handles("test-driver", first.keys().cloned()).unwrap();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    *store.put_gate.lock().unwrap() = Some((release_rx, entered_tx));
    let retaining = {
        let runtime = runtime.clone();
        let source = source.clone();
        let identities = identities.clone();
        tokio::spawn(async move {
            runtime
                .rebind_static_bundle(owner(), &source, &identities, "disable")
                .await
        })
    };
    // Retention has captured generation one but has not committed any static
    // output. Simulate an old mint continuing after its advisory session loss.
    entered_rx.await.unwrap();
    let (_, before_commit) = runtime.load(owner()).await.unwrap();
    for (key, handle) in &identities {
        assert!(
            !before_commit
                .bindings
                .contains_key(&reference_id(key, handle).unwrap())
        );
    }
    let second = bundle(&backend, "second", "new");
    for (key, handle) in &second {
        backend
            .values
            .lock()
            .unwrap()
            .get_mut(&reference_id(key, handle).unwrap())
            .unwrap()
            .1 = Some(Timestamp {
            seconds: 50,
            nanos: 25,
        });
    }
    runtime
        .activate_bundle(ActivateBundle {
            owner: owner(),
            epoch: "epoch",
            references: &source,
            candidates: &second,
            operation_id: "concurrent-activation",
            expected_generation: 1,
            expiration_time: Some(Timestamp {
                seconds: 20,
                nanos: 0,
            }),
            grant: None,
        })
        .await
        .unwrap();
    release_tx.send(()).unwrap();
    let retained = retaining.await.unwrap().unwrap();
    let resolved = runtime
        .resolve_at(
            owner(),
            &retained,
            Timestamp {
                seconds: 30,
                nanos: 0,
            },
        )
        .await
        .unwrap();
    assert_eq!(resolved.len(), 3);
    assert!(resolved.iter().all(|value| value.value.starts_with("new-")
        && value.version == 1
        && value.generation == 1
        && value.expiration_time
            == Some(Timestamp {
                seconds: 50,
                nanos: 25
            })));
    let manifest_ids: BTreeSet<_> = retained
        .values()
        .map(|handle| {
            ReferenceProjection::from_handle(handle)
                .unwrap()
                .unwrap()
                .manifest_id
        })
        .collect();
    assert_eq!(
        manifest_ids.len(),
        3,
        "retained static keys must be independently writable"
    );
    runtime.delete(owner(), &source).await.unwrap();
    assert_eq!(
        runtime.reclaim(owner(), 10).await.unwrap(),
        3,
        "only replaced generation one is reclaimed"
    );
    assert_eq!(
        runtime
            .rebind_static_bundle(owner(), &source, &identities, "disable")
            .await
            .unwrap(),
        retained
    );
    let mut changed = identities.clone();
    changed
        .get_mut("ACCESS")
        .unwrap()
        .handle
        .push_str("changed");
    assert_eq!(
        runtime
            .rebind_static_bundle(owner(), &source, &changed, "disable")
            .await
            .unwrap_err()
            .code(),
        Code::AlreadyExists
    );
    let single = Handles::from([("ACCESS".into(), retained["ACCESS"].clone())]);
    let updated = runtime
        .store(StoreReferenceSecrets {
            owner: owner(),
            epoch: "static",
            write_id: "independent-update",
            protected_intent: b"protected-update",
            values: &HashMap::from([("ACCESS".into(), "static".into())]),
            existing_handles: &single,
            expiration_time: None,
        })
        .await
        .unwrap();
    assert_eq!(
        runtime.resolve_at(owner(), &updated, now()).await.unwrap()[0].version,
        2
    );
}

#[tokio::test]
async fn static_bundle_retention_keeps_pending_bundle_wholly_pending_and_rejects_partial_or_revoked_sources()
 {
    let (runtime, backend, _) = fixture();
    let original = bundle(&backend, "source", "value");
    let source = runtime
        .prepare_bundle(owner(), "epoch", &original, "pending-source")
        .await
        .unwrap();
    let identities =
        ReferenceRuntime::pending_handles("test-driver", original.keys().cloned()).unwrap();
    let retained = runtime
        .rebind_static_bundle(owner(), &source, &identities, "disable-pending")
        .await
        .unwrap();
    for (key, handle) in &retained {
        let single = Handles::from([(key.clone(), handle.clone())]);
        assert_eq!(
            runtime
                .manifest_generation(owner(), "static", &single)
                .await
                .unwrap(),
            0
        );
        assert!(!runtime.validate_bindings(owner(), &single).await.unwrap());
    }
    activate(&runtime, &source, &original, "first-source-output", 0)
        .await
        .unwrap();
    assert_eq!(
        runtime
            .rebind_static_bundle(owner(), &source, &identities, "disable-pending")
            .await
            .unwrap(),
        retained
    );
    assert!(!runtime.validate_bindings(owner(), &retained).await.unwrap());
    let partial = Handles::from([("ACCESS".into(), source["ACCESS"].clone())]);
    let partial_identities =
        ReferenceRuntime::pending_handles("test-driver", ["ACCESS".into()]).unwrap();
    assert_eq!(
        runtime
            .rebind_static_bundle(owner(), &partial, &partial_identities, "partial")
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    runtime.delete(owner(), &source).await.unwrap();
    let other = ReferenceRuntime::pending_handles("test-driver", original.keys().cloned()).unwrap();
    assert_eq!(
        runtime
            .rebind_static_bundle(owner(), &source, &other, "revoked")
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    let wrong_owner = SecretOwner::sandbox("workspace", "immutable-owner-id");
    assert_eq!(
        runtime
            .rebind_static_bundle(wrong_owner, &source, &other, "wrong-owner")
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
}

#[tokio::test]
async fn static_bundle_retention_replays_lost_reply_and_withholds_prepared_source_grant() {
    let (runtime, backend, store) = fixture();
    let original = bundle(&backend, "original", "value");
    let source = runtime
        .adopt_with_expiration(owner(), "epoch", &original, None, "source")
        .await
        .unwrap();
    let prepared = runtime
        .prepare_grant(owner(), "prepared", "epoch", b"prepared")
        .await
        .unwrap();
    let identities =
        ReferenceRuntime::pending_handles("test-driver", original.keys().cloned()).unwrap();
    store.lose_activation_reply.store(true, Ordering::SeqCst);
    assert_eq!(
        runtime
            .rebind_static_bundle(owner(), &source, &identities, "retain-prepared")
            .await
            .unwrap_err()
            .code(),
        Code::Unavailable
    );
    let retained = runtime
        .rebind_static_bundle(owner(), &source, &identities, "retain-prepared")
        .await
        .unwrap();
    assert!(!runtime.validate_bindings(owner(), &retained).await.unwrap());
    runtime
        .activate_grant(owner(), "prepared", prepared.resource_version, None)
        .await
        .unwrap();
    assert_eq!(
        runtime
            .resolve_at(owner(), &source, now())
            .await
            .unwrap()
            .len(),
        3
    );
    assert_eq!(
        runtime
            .rebind_static_bundle(owner(), &source, &identities, "retain-prepared")
            .await
            .unwrap(),
        retained
    );
    assert!(!runtime.validate_bindings(owner(), &retained).await.unwrap());
}

#[tokio::test]
async fn committed_expirations_use_only_activated_manifest_without_backend_reads() {
    let (runtime, backend, _) = fixture();
    let original = bundle(&backend, "expiry", "value");
    let expiry = Timestamp {
        seconds: 40,
        nanos: 125,
    };
    let source = runtime
        .adopt_with_expiration(owner(), "epoch", &original, Some(expiry), "source")
        .await
        .unwrap();
    let prepared = runtime
        .prepare_grant(owner(), "grant", "epoch", b"configured")
        .await
        .unwrap();
    assert!(
        runtime
            .committed_expirations(owner(), &source)
            .await
            .unwrap()
            .is_empty()
    );
    let active = runtime
        .activate_grant(owner(), "grant", prepared.resource_version, None)
        .await
        .unwrap();
    // A committing journal can already describe a future mint's expiration.
    // It is not authority until output activation has selected its candidates.
    runtime
        .put_grant(
            owner(),
            "grant",
            Some(active.resource_version),
            "epoch",
            b"refresh_committing:new-expiration-99",
            true,
        )
        .await
        .unwrap();
    backend.values.lock().unwrap().clear();
    let observed = runtime
        .committed_expirations(owner(), &source)
        .await
        .unwrap();
    assert_eq!(observed.len(), 3);
    assert!(observed.values().all(|value| *value == Some(expiry)));
    let pending_identities =
        ReferenceRuntime::pending_handles("test-driver", ["PENDING".into()]).unwrap();
    let pending = runtime
        .prepare_bundle(owner(), "pending", &pending_identities, "pending")
        .await
        .unwrap();
    let mut mixed = source.clone();
    mixed.extend(pending);
    assert_eq!(
        runtime
            .committed_expirations(owner(), &mixed)
            .await
            .unwrap(),
        observed
    );
    let no_expiry_original = Handles::from([(
        "STATIC".into(),
        backend.put("STATIC", "static-candidate", "static"),
    )]);
    let no_expiry = runtime
        .adopt_with_expiration(owner(), "static", &no_expiry_original, None, "static")
        .await
        .unwrap();
    assert_eq!(
        runtime
            .committed_expirations(owner(), &no_expiry)
            .await
            .unwrap()
            .get("STATIC"),
        Some(&None)
    );
    let wrong_owner = SecretOwner::sandbox("workspace", "immutable-owner-id");
    assert_eq!(
        runtime
            .committed_expirations(wrong_owner, &source)
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    runtime.delete(owner(), &source).await.unwrap();
    assert_eq!(
        runtime
            .committed_expirations(owner(), &source)
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
}
