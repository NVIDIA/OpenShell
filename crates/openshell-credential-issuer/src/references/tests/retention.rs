// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[derive(Default)]
struct StaticReplayStore {
    inner: MemoryStore,
    lose_activation_reply: AtomicBool,
    pause_get_after: AtomicUsize,
    get_gate: Mutex<Option<crate::TestGate>>,
}

impl StaticReplayStore {
    fn pause_retry(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        *self.get_gate.lock().unwrap() = Some((release_rx, entered_tx));
        // Load the incomplete wrapper, then pause before reading owner state
        // again. All intervening mutations use the public runtime API.
        self.pause_get_after.store(2, Ordering::SeqCst);
        (entered_rx, release_tx)
    }

    fn record(&self) -> ReferenceRecord {
        let records = self.inner.records.lock().unwrap();
        assert_eq!(records.len(), 1);
        records.values().next().unwrap().clone()
    }
}

#[async_trait]
impl ReferenceStateStore for StaticReplayStore {
    async fn get(&self, id: &str) -> Result<Option<ReferenceRecord>, Status> {
        let pause = self
            .pause_get_after
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_sub(1))
            .ok()
            == Some(1);
        if pause {
            let gate = self.get_gate.lock().unwrap().take();
            if let Some((release, entered)) = gate {
                let _ = entered.send(());
                let _ = release.await;
            }
        }
        self.inner.get(id).await
    }

    async fn put(&self, id: &str, expected: Option<u64>, payload: Vec<u8>) -> Result<(), Status> {
        let state: OwnerState = serde_json::from_slice(&payload).unwrap();
        let activated = state
            .operations
            .get(&encode_string(&("static-activate", "raced", "TOKEN"))?)
            .is_some_and(|operation| operation.result.is_some());
        self.inner.put(id, expected, payload).await?;
        if activated && self.lose_activation_reply.swap(false, Ordering::SeqCst) {
            return Err(Status::unavailable(
                "lost committed static activation reply",
            ));
        }
        Ok(())
    }

    async fn get_retention(&self, id: &str) -> Result<Option<ReferenceRecord>, Status> {
        self.inner.get_retention(id).await
    }

    async fn put_retention(&self, id: &str, payload: Vec<u8>) -> Result<(), Status> {
        self.inner.put_retention(id, payload).await
    }
}

async fn static_write(
    runtime: &ReferenceRuntime,
    references: &Handles,
    id: &str,
    intent: &[u8],
) -> Result<Handles, Status> {
    runtime
        .store(StoreReferenceSecrets {
            owner: owner(),
            epoch: "static",
            write_id: id,
            protected_intent: intent,
            values: &HashMap::from([("TOKEN".to_owned(), "same-value".to_owned())]),
            existing_handles: references,
            expiration_time: None,
        })
        .await
}

async fn static_replay_fixture() -> (
    Arc<ReferenceRuntime>,
    Arc<Backend>,
    Arc<StaticReplayStore>,
    Handles,
) {
    let backend = Arc::new(Backend::default());
    let store = Arc::new(StaticReplayStore::default());
    let runtime =
        Arc::new(ReferenceRuntime::new("durable-issuer", backend.clone(), store.clone()).unwrap());
    let references = static_write(&runtime, &Handles::new(), "initial", b"protected-initial")
        .await
        .unwrap();
    store.lose_activation_reply.store(true, Ordering::SeqCst);
    assert_eq!(
        static_write(&runtime, &references, "raced", b"protected-raced")
            .await
            .unwrap_err()
            .code(),
        Code::Unavailable
    );
    assert_eq!(
        runtime
            .resolve_at(owner(), &references, now())
            .await
            .unwrap()[0]
            .version,
        2
    );
    (runtime, backend, store, references)
}

#[tokio::test]
async fn completed_static_write_retry_reloads_receipt_after_concurrent_completion_and_reclamation()
{
    let (runtime, backend, store, references) = static_replay_fixture().await;
    let competing =
        ReferenceRuntime::new("durable-issuer", backend.clone(), store.clone()).unwrap();
    let (entered, release) = store.pause_retry();
    let retry = {
        let runtime = runtime.clone();
        let references = references.clone();
        tokio::spawn(async move {
            static_write(&runtime, &references, "raced", b"protected-raced").await
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), entered)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        static_write(&competing, &references, "raced", b"protected-raced")
            .await
            .unwrap(),
        references
    );
    assert_eq!(
        static_write(&competing, &references, "newer", b"protected-newer")
            .await
            .unwrap(),
        references
    );
    runtime.reclaim(owner(), 8).await.unwrap();
    let before = store.record();
    let state: OwnerState = serde_json::from_slice(&before.payload).unwrap();
    let wrapper = &state.operations[&encode_string(&("static-write", "raced", "TOKEN")).unwrap()];
    assert!(wrapper.result.is_some());
    assert_eq!(wrapper.staged.len(), 1);
    assert_eq!(
        state.candidates.len(),
        1,
        "only the newest candidate remains"
    );
    assert!(
        wrapper
            .staged
            .values()
            .all(|id| !state.candidates.contains_key(id)),
        "the old candidate must really be pruned"
    );
    let writes = backend.writes.load(Ordering::SeqCst);
    assert_eq!(writes, 3);
    release.send(()).unwrap();
    assert_eq!(retry.await.unwrap().unwrap(), references);
    assert_eq!(
        static_write(&runtime, &references, "raced", b"protected-raced")
            .await
            .unwrap(),
        references
    );
    assert_eq!(
        static_write(&runtime, &references, "raced", b"changed-intent")
            .await
            .unwrap_err()
            .code(),
        Code::AlreadyExists
    );
    assert_eq!(
        static_write(&runtime, &Handles::new(), "raced", b"protected-raced")
            .await
            .unwrap_err()
            .code(),
        Code::AlreadyExists
    );
    let after = store.record();
    assert_eq!(after.resource_version, before.resource_version);
    assert_eq!(after.payload, before.payload);
    assert_eq!(backend.writes.load(Ordering::SeqCst), writes);
    let resolved = runtime
        .resolve_at(owner(), &references, now())
        .await
        .unwrap();
    assert_eq!(resolved[0].version, 3);
    assert_eq!(resolved[0].generation, 3);
    assert_eq!(resolved[0].value, "same-value");

    // Historical success is a receipt, not fresh authorization. Exact replay
    // after revocation must neither revive a binding nor recreate a candidate.
    runtime.delete(owner(), &references).await.unwrap();
    runtime.reclaim(owner(), 8).await.unwrap();
    let before = store.record();
    let restarted =
        ReferenceRuntime::new("durable-issuer", backend.clone(), store.clone()).unwrap();
    assert_eq!(
        static_write(&restarted, &references, "raced", b"protected-raced")
            .await
            .unwrap(),
        references
    );
    assert_eq!(
        static_write(&restarted, &references, "raced", b"changed-intent")
            .await
            .unwrap_err()
            .code(),
        Code::AlreadyExists
    );
    assert_eq!(
        restarted
            .resolve_at(owner(), &references, now())
            .await
            .err()
            .unwrap()
            .code(),
        Code::FailedPrecondition
    );
    assert_eq!(store.record().resource_version, before.resource_version);
    assert_eq!(store.record().payload, before.payload);
    assert_eq!(backend.writes.load(Ordering::SeqCst), writes);
}

#[tokio::test]
async fn incomplete_static_write_retry_reloads_abandonment_before_reconstructing_candidates() {
    let (runtime, backend, store, references) = static_replay_fixture().await;
    let (entered, release) = store.pause_retry();
    let retry = {
        let runtime = runtime.clone();
        let references = references.clone();
        tokio::spawn(async move {
            static_write(&runtime, &references, "raced", b"protected-raced").await
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), entered)
        .await
        .unwrap()
        .unwrap();
    runtime.delete(owner(), &references).await.unwrap();
    runtime.reclaim(owner(), 8).await.unwrap();
    let before = store.record();
    release.send(()).unwrap();
    assert_eq!(
        retry.await.unwrap().unwrap_err().code(),
        Code::FailedPrecondition
    );
    assert_eq!(store.record().resource_version, before.resource_version);
    assert_eq!(store.record().payload, before.payload);
    assert_eq!(backend.writes.load(Ordering::SeqCst), 2);
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
async fn repeated_successful_activations_bound_hot_history_and_preserve_receipts() {
    let (runtime, backend, store) = fixture();
    let identities = Handles::from([(
        "TOKEN".to_owned(),
        backend.put("TOKEN", "identity", "unused"),
    )]);
    let references = runtime
        .prepare_bundle(owner(), "epoch", &identities, "prepare")
        .await
        .unwrap();
    let terminal = vec![42; 16_384];
    let mut grant = runtime
        .put_grant(owner(), "grant", None, "epoch", &terminal, true)
        .await
        .unwrap();
    let first_candidates = Handles::from([(
        "TOKEN".to_owned(),
        backend.put("TOKEN", "candidate-1", "same-value"),
    )]);
    let first_version = grant.resource_version;
    let mut first_receipt = None;
    let mut baseline_bytes = 0;
    for generation in 1..=300 {
        let candidates = if generation == 1 {
            first_candidates.clone()
        } else {
            Handles::from([(
                "TOKEN".to_owned(),
                backend.put("TOKEN", &format!("candidate-{generation}"), "same-value"),
            )])
        };
        let result = runtime
            .activate_bundle(ActivateBundle {
                owner: owner(),
                epoch: "epoch",
                references: &references,
                candidates: &candidates,
                operation_id: &format!("activate-{generation}"),
                expected_generation: generation - 1,
                expiration_time: None,
                grant: Some(GrantTransition {
                    grant_id: "grant",
                    expected_resource_version: grant.resource_version,
                    state: &terminal,
                }),
            })
            .await
            .unwrap();
        if generation == 1 {
            first_receipt = Some(result.receipt);
        }
        runtime.reclaim(owner(), 8).await.unwrap();
        grant = runtime.get_grant(owner(), "grant").await.unwrap().unwrap();
        let (_, state) = runtime.load(owner()).await.unwrap();
        assert_eq!(
            state.operations.len(),
            2,
            "one preparation and current activation"
        );
        assert_eq!(state.candidates.len(), 1);
        assert!(
            state
                .candidates
                .values()
                .all(|candidate| candidate.status == CandidateStatus::Available)
        );
        assert_eq!(grant.state, terminal);
        let bytes = store
            .get(&runtime.state_id(owner()).unwrap())
            .await
            .unwrap()
            .unwrap()
            .payload
            .len();
        if generation == 1 {
            baseline_bytes = bytes;
        }
        assert!(
            bytes <= baseline_bytes + 128,
            "hot row grew from {baseline_bytes} to {bytes}"
        );
    }
    let restarted =
        ReferenceRuntime::new("durable-issuer", backend.clone(), store.clone()).unwrap();
    let before = store
        .get(&runtime.state_id(owner()).unwrap())
        .await
        .unwrap()
        .unwrap()
        .resource_version;
    let replay = restarted
        .activate_bundle(ActivateBundle {
            owner: owner(),
            epoch: "epoch",
            references: &references,
            candidates: &first_candidates,
            operation_id: "activate-1",
            expected_generation: 0,
            expiration_time: None,
            grant: Some(GrantTransition {
                grant_id: "grant",
                expected_resource_version: first_version,
                state: &terminal,
            }),
        })
        .await
        .unwrap();
    assert_eq!(replay.receipt, first_receipt.unwrap());
    assert_eq!(
        store
            .get(&runtime.state_id(owner()).unwrap())
            .await
            .unwrap()
            .unwrap()
            .resource_version,
        before
    );
    let resolved = restarted
        .resolve_at(owner(), &references, now())
        .await
        .unwrap();
    assert_eq!(resolved[0].version, 300);
    assert_eq!(resolved[0].value, "same-value");
    assert_eq!(
        restarted.list_grants(None).await.unwrap().len(),
        1,
        "retention records are not grants"
    );

    // An arbitrary ID is not a monotonic attempt counter. Its old intent must
    // remain bound even if a caller supplies otherwise-current generation/RV.
    let changed = restarted
        .activate_bundle(ActivateBundle {
            owner: owner(),
            epoch: "epoch",
            references: &references,
            candidates: &first_candidates,
            operation_id: "activate-1",
            expected_generation: 300,
            expiration_time: None,
            grant: Some(GrantTransition {
                grant_id: "grant",
                expected_resource_version: grant.resource_version,
                state: &terminal,
            }),
        })
        .await;
    assert_eq!(changed.err().unwrap().code(), Code::AlreadyExists);
    let changed_terminal = restarted
        .activate_bundle(ActivateBundle {
            owner: owner(),
            epoch: "epoch",
            references: &references,
            candidates: &first_candidates,
            operation_id: "activate-1",
            expected_generation: 0,
            expiration_time: None,
            grant: Some(GrantTransition {
                grant_id: "grant",
                expected_resource_version: first_version,
                state: b"different terminal state",
            }),
        })
        .await;
    assert_eq!(changed_terminal.err().unwrap().code(), Code::AlreadyExists);
    assert_eq!(
        restarted
            .abandon_operation(owner(), "activate-1")
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    assert_eq!(
        restarted
            .prepare_bundle(owner(), "new-epoch", &identities, "activate-1")
            .await
            .unwrap_err()
            .code(),
        Code::AlreadyExists
    );
    assert_eq!(
        runtime
            .get_grant(owner(), "grant")
            .await
            .unwrap()
            .unwrap()
            .resource_version,
        grant.resource_version
    );
}

#[tokio::test]
async fn compacted_deleted_candidates_cannot_be_relinked_and_stale_attempts_cannot_win() {
    let (runtime, backend, store) = fixture();
    let identities = bundle(&backend, "identities", "unused");
    let references = runtime
        .prepare_bundle(owner(), "epoch", &identities, "prepare")
        .await
        .unwrap();
    let old = bundle(&backend, "old", "first");
    let first = activate(&runtime, &references, &old, "first", 0)
        .await
        .unwrap()
        .receipt;
    let current = bundle(&backend, "current", "second");
    activate(&runtime, &references, &current, "current", 1)
        .await
        .unwrap();
    runtime.reclaim(owner(), 8).await.unwrap();
    assert_eq!(runtime.load(owner()).await.unwrap().1.candidates.len(), 3);
    let restarted = ReferenceRuntime::new("durable-issuer", backend.clone(), store).unwrap();
    assert_eq!(
        activate(&restarted, &references, &old, "first", 0)
            .await
            .unwrap()
            .receipt,
        first
    );
    let stale = bundle(&backend, "stale", "third");
    assert_eq!(
        activate(&restarted, &references, &stale, "unseen-stale-id", 0)
            .await
            .err()
            .unwrap()
            .code(),
        Code::Aborted
    );
    assert_eq!(
        activate(&restarted, &references, &old, "new-id-old-candidates", 2)
            .await
            .err()
            .unwrap()
            .code(),
        Code::FailedPrecondition
    );
    // Even if a backend accidentally recreates an opaque identity, durable
    // denial evidence must forbid adoption/relinking it as a fresh object.
    let recreated = bundle(&backend, "old", "recreated");
    let alias = restarted
        .prepare_bundle(owner(), "another-epoch", &recreated, "new-alias")
        .await
        .unwrap();
    assert_eq!(
        restarted
            .activate_bundle(ActivateBundle {
                owner: owner(),
                epoch: "another-epoch",
                references: &alias,
                candidates: &recreated,
                operation_id: "recreate",
                expected_generation: 0,
                expiration_time: None,
                grant: None,
            })
            .await
            .err()
            .unwrap()
            .code(),
        Code::FailedPrecondition
    );
    runtime.delete(owner(), &references).await.unwrap();
    // Exact historic success is only a receipt, never authorization or revival.
    activate(&restarted, &references, &old, "first", 0)
        .await
        .unwrap();
    assert_eq!(
        restarted
            .resolve_at(owner(), &references, now())
            .await
            .err()
            .unwrap()
            .code(),
        Code::FailedPrecondition
    );
}

#[tokio::test]
async fn compaction_preserves_unfinished_staging_and_failed_reclamation_debt() {
    let (runtime, backend, _) = fixture();
    let identities = bundle(&backend, "identities", "unused");
    let references = runtime
        .prepare_bundle(owner(), "epoch", &identities, "prepare")
        .await
        .unwrap();
    let old = bundle(&backend, "old", "first");
    activate(&runtime, &references, &old, "first", 0)
        .await
        .unwrap();
    let debt = bundle(&backend, "debt", "pending");
    // Persist the same pre-activation state the public activation path writes
    // before a crash, retaining all candidate links and recovery metadata.
    let (version, mut state) = runtime.load(owner()).await.unwrap();
    let mut pending = state.operations["first"].clone();
    pending.intent.expected_generation = 1;
    pending.intent.candidates = debt
        .iter()
        .map(|(key, handle)| (key.clone(), StoredHandle::of(handle)))
        .collect();
    pending.result = None;
    pending.write_attempts = vec!["uncertain-backend-attempt".to_owned()];
    pending.staged.clear();
    for (key, handle) in &debt {
        pending.staged.insert(
            key.clone(),
            link_candidate(&runtime, &mut state, owner(), key, handle)
                .await
                .unwrap(),
        );
    }
    state.operations.insert("pending".to_owned(), pending);
    runtime.save(owner(), version, &state).await.unwrap();
    let current = bundle(&backend, "current", "second");
    activate(&runtime, &references, &current, "second", 1)
        .await
        .unwrap();
    backend.fail_delete.store(true, Ordering::SeqCst);
    assert_eq!(
        runtime.reclaim(owner(), 1).await.unwrap_err().code(),
        Code::Unavailable
    );
    let (_, state) = runtime.load(owner()).await.unwrap();
    assert!(state.operations.contains_key("pending"));
    assert_eq!(
        runtime.write_recovery(owner()).await.unwrap()[0].attempt_object_ids,
        ["uncertain-backend-attempt"]
    );
    assert!(
        state
            .candidates
            .values()
            .any(|candidate| candidate.status == CandidateStatus::Reclaiming)
    );
    assert!(
        state.operations["pending"]
            .staged
            .values()
            .all(|id| state.candidates[id].status == CandidateStatus::Available)
    );
    backend.fail_delete.store(false, Ordering::SeqCst);
    runtime.reclaim(owner(), 8).await.unwrap();
    assert_eq!(
        runtime.load(owner()).await.unwrap().1.candidates.len(),
        6,
        "current + unfinished staged candidates"
    );
}

#[tokio::test]
async fn lost_archive_reply_never_publishes_an_uncommitted_activation() {
    let (runtime, backend, store) = fixture();
    let identities = bundle(&backend, "identity", "unused");
    let references = runtime
        .prepare_bundle(owner(), "epoch", &identities, "prepare")
        .await
        .unwrap();
    let old = bundle(&backend, "old", "first");
    let receipt = activate(&runtime, &references, &old, "first", 0)
        .await
        .unwrap()
        .receipt;
    let next = bundle(&backend, "next", "second");
    store.lose_retention_reply.store(true, Ordering::SeqCst);
    assert_eq!(
        activate(&runtime, &references, &next, "second", 1)
            .await
            .err()
            .unwrap()
            .code(),
        Code::Unavailable
    );
    assert_eq!(
        runtime
            .resolve_at(owner(), &references, now())
            .await
            .unwrap()[0]
            .version,
        1
    );
    assert_eq!(
        activate(&runtime, &references, &old, "first", 0)
            .await
            .unwrap()
            .receipt,
        receipt
    );
    assert_eq!(
        activate(&runtime, &references, &next, "second", 1)
            .await
            .unwrap()
            .receipt
            .generation,
        2
    );
    assert_eq!(runtime.load(owner()).await.unwrap().1.operations.len(), 2);
}

#[tokio::test]
async fn static_update_markers_and_protected_writes_replay_after_activation_compaction() {
    use crate::references::static_updates::{StaticReplacement, StaticUpdate};
    let (runtime, backend, store) = fixture();
    let empty = Handles::new();
    let values = HashMap::from([("TOKEN".to_owned(), "same-value".to_owned())]);
    let destination = runtime
        .store(StoreReferenceSecrets {
            owner: owner(),
            epoch: "static",
            write_id: "initial",
            protected_intent: b"protected-initial",
            values: &values,
            existing_handles: &empty,
            expiration_time: None,
        })
        .await
        .unwrap();
    let staged = runtime
        .store(StoreReferenceSecrets {
            owner: owner(),
            epoch: "static",
            write_id: "staged",
            protected_intent: b"protected-staged",
            values: &values,
            existing_handles: &empty,
            expiration_time: None,
        })
        .await
        .unwrap();
    let update = StaticUpdate {
        operation_id: "provider-update".to_owned(),
        replacements: vec![StaticReplacement {
            destination: ReferenceProjection::from_handle(&destination["TOKEN"])
                .unwrap()
                .unwrap(),
            staged: ReferenceProjection::from_handle(&staged["TOKEN"])
                .unwrap()
                .unwrap(),
            expected_generation: 1,
        }],
    };
    assert!(
        !runtime
            .static_update_committed(owner(), &update)
            .await
            .unwrap()
    );
    runtime
        .activate_static_update(owner(), &update)
        .await
        .unwrap();
    runtime.reclaim(owner(), 8).await.unwrap();
    // Advance the destination again: generation alone cannot stand in for the
    // exact provider transition receipt when checking a pending marker.
    runtime
        .store(StoreReferenceSecrets {
            owner: owner(),
            epoch: "static",
            write_id: "later",
            protected_intent: b"protected-later",
            values: &values,
            existing_handles: &destination,
            expiration_time: None,
        })
        .await
        .unwrap();
    runtime.reclaim(owner(), 8).await.unwrap();
    let restarted = ReferenceRuntime::new("durable-issuer", backend.clone(), store).unwrap();
    assert!(
        restarted
            .static_update_committed(owner(), &update)
            .await
            .unwrap()
    );
    restarted
        .activate_static_update(owner(), &update)
        .await
        .unwrap();
    assert_eq!(
        restarted
            .resolve_at(owner(), &destination, now())
            .await
            .unwrap()[0]
            .version,
        3
    );
    let mut changed = update.clone();
    changed.replacements[0].expected_generation = 3;
    assert_eq!(
        restarted
            .static_update_committed(owner(), &changed)
            .await
            .unwrap_err()
            .code(),
        Code::AlreadyExists
    );
    assert_eq!(
        restarted
            .activate_static_update(owner(), &changed)
            .await
            .unwrap_err()
            .code(),
        Code::AlreadyExists
    );
    changed.operation_id = "unseen-stale-marker".to_owned();
    changed.replacements[0].expected_generation = 1;
    assert!(
        !restarted
            .static_update_committed(owner(), &changed)
            .await
            .unwrap()
    );
    assert!(
        restarted
            .activate_static_update(owner(), &changed)
            .await
            .is_err()
    );
    let writes = backend.writes.load(Ordering::SeqCst);
    let replay = restarted
        .store(StoreReferenceSecrets {
            owner: owner(),
            epoch: "static",
            write_id: "initial",
            protected_intent: b"protected-initial",
            values: &values,
            existing_handles: &empty,
            expiration_time: None,
        })
        .await
        .unwrap();
    assert_eq!(replay, destination);
    assert_eq!(backend.writes.load(Ordering::SeqCst), writes);
    assert_eq!(
        restarted
            .store(StoreReferenceSecrets {
                owner: owner(),
                epoch: "static",
                write_id: "initial",
                protected_intent: b"changed-protected-intent",
                values: &values,
                existing_handles: &empty,
                expiration_time: None,
            })
            .await
            .err()
            .unwrap()
            .code(),
        Code::AlreadyExists
    );
}
