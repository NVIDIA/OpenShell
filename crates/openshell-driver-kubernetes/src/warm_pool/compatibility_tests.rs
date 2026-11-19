// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[tokio::test]
async fn compatibility_uses_effective_workload_and_ignores_inventory_policy() {
    let mut driver = fixture(Arc::new(Mutex::new(State::default())));
    let mut pool = pool_config();
    let trust = request().trust;
    let original = driver.warm_pool_fingerprint(&pool, &trust).await.unwrap();
    // An explicit template image overrides this default. These other settings
    // control admission, maintenance or a supervisor this pool does not create.
    driver.config.default_image = "unused-default:v2".into();
    driver.config.supervisor_image = "unused-dedicated:v2".into();
    driver.config.supervisor_runtime_class_name = "unused-class".into();
    driver.config.runtime_bootstrap_grace_seconds += 10;
    driver
        .config
        .allowed_pod_annotations
        .push("example.com/*".into());
    driver.config.warm_pool.enabled = false;
    driver.config.warm_pool.revision += 1;
    driver.config.warm_pool.max_size += 1;
    pool.revision += 1;
    pool.target_size = 1;
    pool.max_size += 1;
    pool.max_age_secs += 1;
    pool.preparation_timeout_secs += 1;
    assert_eq!(
        driver.warm_pool_fingerprint(&pool, &trust).await.unwrap(),
        original
    );

    pool.spec.template.as_mut().unwrap().image.clear();
    let fallback = driver.warm_pool_fingerprint(&pool, &trust).await.unwrap();
    driver.config.default_image = "used-default:v3".into();
    assert_ne!(
        driver.warm_pool_fingerprint(&pool, &trust).await.unwrap(),
        fallback
    );
}

#[tokio::test]
async fn namespace_scc_changes_invalidate_spares_before_claim() {
    let state = Arc::new(Mutex::new(State::default()));
    let mut driver = fixture(state.clone());
    driver.config.sandbox_uid = None;
    driver.config.sandbox_gid = None;
    let pool = pool_config();
    let request = request();
    let before = driver
        .warm_pool_fingerprint(&pool, &request.trust)
        .await
        .unwrap();
    let spare = driver.prepare_warm_runtime(&request).await.unwrap();
    state
        .lock()
        .unwrap()
        .objects
        .get_mut("/api/v1/namespaces/openshell")
        .unwrap()["metadata"]["annotations"] = json!({"openshift.io/sa.scc.uid-range": "1000000000/10000", "openshift.io/sa.scc.supplemental-groups": "1000010000/10000"});
    assert_ne!(
        before,
        driver
            .warm_pool_fingerprint(&pool, &request.trust)
            .await
            .unwrap()
    );
    let (api, object, record) = claim_object(&driver, &spare.resource).await;
    let sandbox = claiming_sandbox(&request, "logical-scc");
    assert!(
        !driver
            .claim_warm_object(&sandbox, &api, &object, &record, spare.registration)
            .await
            .unwrap()
    );
    assert!(state.lock().unwrap().activated.is_empty());
}

#[tokio::test]
async fn compatibility_changes_with_runtime_shape_and_trust() {
    let driver = fixture(Arc::new(Mutex::new(State::default())));
    let pool = pool_config();
    let trust = request().trust;
    let original = driver.warm_pool_fingerprint(&pool, &trust).await.unwrap();
    let cases: [fn(&mut KubernetesComputeConfig); 6] = [
        |c| c.sandbox_runtime_image = "runtime:v2".into(),
        |c| c.service_account_name = "another-account".into(),
        |c| c.sandbox_uid = Some(2000),
        |c| c.sandbox_runtime.boundary_port += 1,
        |c| c.workspace_default_storage_size = "3Gi".into(),
        |c| c.image_pull_secrets.push("another-registry".into()),
    ];
    for change in cases {
        let mut changed = driver.clone();
        change(&mut changed.config);
        assert_ne!(
            changed.warm_pool_fingerprint(&pool, &trust).await.unwrap(),
            original
        );
    }
    let mut changed_pool = pool.clone();
    changed_pool.spec.template.as_mut().unwrap().image = "workload:v2".into();
    assert_ne!(
        driver
            .warm_pool_fingerprint(&changed_pool, &trust)
            .await
            .unwrap(),
        original
    );
    changed_pool = pool.clone();
    changed_pool
        .spec
        .environment
        .insert("TASK_ENV".into(), "changed".into());
    assert_ne!(
        driver
            .warm_pool_fingerprint(&changed_pool, &trust)
            .await
            .unwrap(),
        original
    );
    let mut changed_trust = trust.clone();
    changed_trust.auth_epoch = CredentialEpoch::new(2).unwrap();
    assert_ne!(
        driver
            .warm_pool_fingerprint(&pool, &changed_trust)
            .await
            .unwrap(),
        original
    );
    changed_trust = request().trust;
    assert_ne!(
        driver
            .warm_pool_fingerprint(&pool, &changed_trust)
            .await
            .unwrap(),
        original
    );
}

#[tokio::test]
async fn compatibility_includes_dedicated_supervisor_rendering() {
    let mut driver = fixture(Arc::new(Mutex::new(State::default())));
    driver.shared_supervisor = None;
    let pool = pool_config();
    let trust = request().trust;
    let original = driver.warm_pool_fingerprint(&pool, &trust).await.unwrap();
    let cases: [fn(&mut KubernetesComputeConfig); 5] = [
        |c| c.supervisor_image = "supervisor:v2".into(),
        |c| c.supervisor_runtime_class_name = "another-class".into(),
        |c| c.grpc_endpoint = "https://another-gateway:8080".into(),
        |c| c.https_proxy = Some("https://proxy:8443".into()),
        |c| c.sandbox_attach_request_timeout_seconds = Some(15),
    ];
    for change in cases {
        let mut changed = driver.clone();
        change(&mut changed.config);
        assert_ne!(
            changed.warm_pool_fingerprint(&pool, &trust).await.unwrap(),
            original
        );
    }
}

#[tokio::test]
async fn compatibility_canonicalizes_environment_and_uses_overridden_values() {
    let driver = fixture(Arc::new(Mutex::new(State::default())));
    let mut pool = pool_config();
    let trust = request().trust;
    pool.spec
        .environment
        .extend([("A".into(), "one".into()), ("B".into(), "two".into())]);
    pool.spec
        .template
        .as_mut()
        .unwrap()
        .environment
        .insert("A".into(), "overridden".into());
    let original = driver.warm_pool_fingerprint(&pool, &trust).await.unwrap();
    pool.spec.environment.clear();
    pool.spec
        .environment
        .extend([("B".into(), "two".into()), ("A".into(), "one".into())]);
    pool.spec
        .template
        .as_mut()
        .unwrap()
        .environment
        .insert("A".into(), "also-overridden".into());
    assert_eq!(
        driver.warm_pool_fingerprint(&pool, &trust).await.unwrap(),
        original
    );
}

fn sessions(state: &Arc<Mutex<State>>) -> Vec<SandboxSessionId> {
    state
        .lock()
        .unwrap()
        .journal
        .as_ref()
        .unwrap()
        .state
        .entries
        .iter()
        .map(|entry| entry.session_id)
        .collect()
}

#[tokio::test]
async fn policy_revision_preserves_compatible_spares_and_fences_stale_replicas() {
    let state = Arc::new(Mutex::new(State::default()));
    let driver = fixture(state.clone());
    let mut pool = pool_config();
    driver.reconcile_warm_pool(&pool).await.unwrap();
    let original = sessions(&state);
    pool.max_size = 3;
    assert!(driver.reconcile_warm_pool(&pool).await.unwrap().suspended);
    assert_eq!(sessions(&state), original);
    pool.revision += 1;
    let report = driver.reconcile_warm_pool(&pool).await.unwrap();
    assert!(!report.suspended);
    assert_eq!(report.retiring, 0);
    assert_eq!(sessions(&state), original);
    assert!(driver.reconcile_warm_pool(&pool_config()).await.is_err());

    // A new runtime image still needs a revision and replaces incompatible spares.
    let mut upgraded = driver.clone();
    upgraded.config.sandbox_runtime_image = "runtime:v2".into();
    assert!(upgraded.reconcile_warm_pool(&pool).await.unwrap().suspended);
    assert_eq!(sessions(&state), original);
    pool.revision += 1;
    permit_next_attempt(&state);
    assert_eq!(
        upgraded.reconcile_warm_pool(&pool).await.unwrap().retiring,
        2
    );
}

#[tokio::test]
async fn mismatch_uses_recorded_expiry_and_original_epoch_without_refilling() {
    let state = Arc::new(Mutex::new(State::default()));
    let driver = fixture(state.clone());
    let pool = pool_config();
    driver.reconcile_warm_pool(&pool).await.unwrap();
    {
        let mut state = state.lock().unwrap();
        state.public_trust.as_mut().unwrap()["auth_epoch"] = json!(2);
        // One preparation expired under the recorded 120-second timeout;
        // the other must survive this replica's locally shorter timeout.
        let entries = &mut state.journal.as_mut().unwrap().state.entries;
        entries[0].created_at_ms -= 130_000;
        entries[1].created_at_ms -= 40_000;
    }
    let mut changed = pool.clone();
    changed.preparation_timeout_secs = 30;
    permit_next_attempt(&state);
    let report = driver.reconcile_warm_pool(&changed).await.unwrap();
    assert!(report.suspended);
    assert_eq!((report.retiring, report.failed), (1, 0));
    for _ in 0..3 {
        permit_next_attempt(&state);
        driver.reconcile_warm_pool(&changed).await.unwrap();
    }
    assert_eq!(sessions(&state).len(), 1);
    assert!(
        state
            .lock()
            .unwrap()
            .retired
            .values()
            .all(|r| r.auth_epoch == CredentialEpoch::new(1).unwrap())
    );
}

#[tokio::test]
async fn mismatched_disable_drains_and_requires_new_revision_to_reenable() {
    let state = Arc::new(Mutex::new(State::default()));
    let driver = fixture(state.clone());
    let mut pool = pool_config();
    driver.reconcile_warm_pool(&pool).await.unwrap();
    let mut disabled = driver.clone();
    disabled.config.sandbox_runtime_image = "runtime:v2".into();
    disabled.config.warm_pool.enabled = false;
    pool.target_size = 0;
    for _ in 0..4 {
        permit_next_attempt(&state);
        assert_eq!(disabled.reconcile_warm_pool(&pool).await.unwrap().failed, 0);
    }
    assert!(sessions(&state).is_empty());
    let report = driver.reconcile_warm_pool(&pool_config()).await.unwrap();
    assert!(report.suspended);
    assert!(sessions(&state).is_empty());
    pool = pool_config();
    pool.revision += 1;
    assert!(!driver.reconcile_warm_pool(&pool).await.unwrap().suspended);
    assert_eq!(sessions(&state).len(), 2);
}
