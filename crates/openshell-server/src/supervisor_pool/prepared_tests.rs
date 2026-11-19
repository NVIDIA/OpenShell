// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::tests::Fixture;
use super::*;
use crate::persistence::ObjectType;
use openshell_core::jwt::CredentialEpoch;
use openshell_supervisor_control::{PreparedRuntimeRegistration, SandboxInstanceRegistration};

async fn preparation(fixture: &Fixture, route: &str) -> PreparationRequest {
    let session = openshell_core::SandboxSessionId::new();
    let route = if route.is_empty() {
        format!("rt-{session}")
    } else {
        route.into()
    };
    let name = format!("sandbox.{session}.openshell.internal");
    let tls = openshell_crypto::pki::generate_simple_self_signed(vec![name.clone()]).unwrap();
    let registration: PreparedRuntimeRegistration = serde_json::from_value(serde_json::json!({
        "route": route,
        "runtime_descriptor": {
            "boundary_id": "", "generation": "generation-1", "session_id": session,
            "workload_identity": {"uid": 1000, "gid": 1000, "supplementary_gids": [],
                "source": "test", "resource_digest": "a".repeat(64)},
            "transport": {"kind": "runtime-initiated-routed", "authority": "supervisor:5500", "route": route},
            "tls": {"server_name": name, "trust_anchor_pem": tls.cert.pem()},
            "resource_claims": {"kubernetes.workload_pod_uid": "pod-1"},
            "provisioning_evidence": {"generation": "generation-1", "evidence_digest": "a".repeat(64)}
        }
    })).unwrap();
    registration.validate().unwrap();
    let request = PreparationRequest {
        pool_id: "test-pool".into(),
        registration,
        workspace: "default".into(),
        auth_epoch: CredentialEpoch::new(1).unwrap(),
    };
    authorize_preparation(fixture, &request).await;
    request
}

fn activation(prepared: &PreparationRequest, sandbox: &str) -> ActivationRequest {
    let mut descriptor = prepared.registration.runtime_descriptor.clone();
    descriptor.boundary_id = sandbox.into();
    let registration: SandboxInstanceRegistration = serde_json::from_value(serde_json::json!({
        "route": prepared.registration.route, "sandbox_id": sandbox, "sandbox_name": sandbox,
        "runtime_descriptor": descriptor,
        "auth": {
            "session_id": descriptor.session_id, "runtime_generation": descriptor.generation,
            "session_rotation": 1, "auth_epoch": prepared.auth_epoch.get(),
            "gateway_token": "test-gateway", "gateway_expires_at": 0,
            "sandbox_token": "test-sandbox", "sandbox_expires_at": 0
        },
        "main_process_spec": serde_json::to_string(&openshell_core::sandbox_env::MainProcessConfig::scratch()).unwrap(),
        "proxy_ca": {"certificate_pem": "test-ca", "private_key_pem": "test-key"}
    })).unwrap();
    registration.validate().unwrap();
    ActivationRequest {
        runtime_identity: "runtime-identity".into(),
        assignment: registration.to_assignment().unwrap(),
        expected_generation: openshell_core::sandbox_generation::SandboxGenerationId::parse(
            "generation-1",
        )
        .unwrap(),
        expected_auth_epoch: CredentialEpoch::new(1).unwrap(),
    }
}

async fn authorize_preparation(fixture: &Fixture, request: &PreparationRequest) {
    use openshell_supervisor_control::warm_pool::{WarmPoolEntry, WarmPoolState, WarmPoolUpdate};
    let pool = fixture.replica("journal-writer");
    let previous = pool
        .warm_pool_state(&request.workspace, &request.pool_id)
        .await
        .unwrap();
    let expected_version = previous.as_ref().map(|snapshot| snapshot.resource_version);
    let mut state = previous.map_or_else(
        || WarmPoolState {
            revision: 1,
            fingerprint: "a".repeat(64),
            policy: None,
            entries: Vec::new(),
        },
        |snapshot| snapshot.state,
    );
    state.entries.push(WarmPoolEntry {
        session_id: request.registration.runtime_descriptor.session_id,
        created_at_ms: now_ms(),
        last_attempt_at_ms: None,
        last_ready_at_ms: None,
        resource_uid: None,
        retiring: false,
        auth_epoch: Some(request.auth_epoch),
    });
    assert!(
        pool.update_warm_pool(WarmPoolUpdate {
            finish_drain: false,
            workspace: request.workspace.clone(),
            pool_id: request.pool_id.clone(),
            expected_version,
            state,
        })
        .await
        .unwrap()
    );
}

async fn setup() -> (Fixture, Arc<SupervisorPool>, PreparationRequest) {
    let fixture = Fixture::new().await;
    fixture.member("m1", "p1", false).await;
    fixture
        .sandbox("sandbox-a", "generation-1", SandboxPhase::Provisioning)
        .await;
    let pool = fixture.replica("gateway-a");
    let prepared = preparation(&fixture, "rt-prepared-0123456789").await;
    pool.prepare_runtime(prepared.clone()).await.unwrap();
    (fixture, pool, prepared)
}

async fn inventory(pool: &SupervisorPool, prepared: &PreparationRequest) -> PreparedRuntime {
    let mut runtimes = pool
        .prepared_runtimes("default", vec![prepared.registration.route.clone()])
        .await
        .unwrap();
    assert_eq!(runtimes.len(), 1);
    runtimes.pop().unwrap()
}

#[tokio::test]
async fn preparation_inventory_is_scoped_durable_and_excludes_unadmitted_and_claimed_runtimes() {
    let (fixture, pool, prepared) = setup().await;
    let before = inventory(&pool, &prepared).await;
    let mut other = preparation(&fixture, "rt-other-workspace-0123456789").await;
    other.workspace = "another-workspace".into();
    authorize_preparation(&fixture, &other).await;
    pool.prepare_runtime(other.clone()).await.unwrap();
    let pending = preparation(&fixture, "rt-unadmitted-0123456789").await;
    pool.record_assignment_scoped(
        &pending.registration.to_assignment().unwrap(),
        RecordPhase::Admitting,
        Some(("default", 1, "test-pool")),
    )
    .await
    .unwrap();

    // A replica needs no locally published state to recover the inventory.
    let recovered = fixture.replica("gateway-restarted");
    let after = inventory(&recovered, &prepared).await;
    assert_eq!(before.revision, after.revision);
    assert_eq!(after.registration, prepared.registration);
    assert_eq!(after.auth_epoch, prepared.auth_epoch);
    assert_eq!(after.published_at_ms, before.published_at_ms);
    assert_eq!(
        after.owner,
        Some(PreparedRuntimeOwner {
            member_id: "m1".into(),
            process_id: "p1".into(),
            available: true,
        })
    );
    assert!(
        recovered
            .prepared_runtimes("", vec![prepared.registration.route.clone()])
            .await
            .is_err()
    );
    assert!(
        recovered
            .prepared_runtimes("missing", vec![prepared.registration.route.clone()])
            .await
            .unwrap()
            .is_empty()
    );
    let scoped = recovered
        .prepared_runtimes(&other.workspace, vec![other.registration.route.clone()])
        .await
        .unwrap();
    assert_eq!(scoped.len(), 1);
    assert_eq!(scoped[0].registration, other.registration);
    recovered
        .activate_runtime(activation(&prepared, "sandbox-a"))
        .await
        .unwrap();
    assert!(
        recovered
            .prepared_runtimes("default", vec![prepared.registration.route.clone()])
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn preparation_inventory_reports_the_original_process_availability() {
    let (fixture, pool, prepared) = setup().await;
    fixture.member("m1", "p1", true).await;
    assert!(!inventory(&pool, &prepared).await.owner.unwrap().available);
    fixture.remove_member("m1").await;
    assert!(!inventory(&pool, &prepared).await.owner.unwrap().available);
    fixture.member("m1", "replacement", false).await;
    let owner = inventory(&pool, &prepared).await.owner.unwrap();
    assert_eq!(owner.process_id, "p1");
    assert!(!owner.available);
    fixture.member("m1", "p1", false).await;
    assert!(inventory(&pool, &prepared).await.owner.unwrap().available);
}

#[tokio::test]
async fn unreadable_preparation_material_fails_inventory_without_affecting_other_workspaces() {
    let (fixture, pool, prepared) = setup().await;
    let healthy = preparation(&fixture, "rt-healthy-0123456789").await;
    pool.prepare_runtime(healthy.clone()).await.unwrap();
    let record = pool
        .assignment(&prepared.registration.route)
        .await
        .unwrap()
        .unwrap();
    let handle = CredentialHandle::decode(record.payload.material_handle.as_slice()).unwrap();
    pool.delete_material(&record.payload, handle).await.unwrap();
    let scoped = pool
        .prepared_runtimes("default", vec![healthy.registration.route.clone()])
        .await
        .unwrap();
    assert_eq!(scoped.len(), 1);
    assert_eq!(scoped[0].registration, healthy.registration);
    assert!(
        pool.prepared_runtimes("default", vec![prepared.registration.route.clone()])
            .await
            .is_err()
    );
    assert!(
        pool.prepared_runtimes(
            "another-workspace",
            vec![prepared.registration.route.clone()]
        )
        .await
        .unwrap()
        .is_empty()
    );
    assert!(
        pool.assignment(&prepared.registration.route)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn preparation_release_is_idempotent_and_reclaims_capacity() {
    let (fixture, pool, prepared) = setup().await;
    let other = fixture.replica("gateway-cleaner");
    let supervision = openshell_supervisor_control::SharedSupervision::new();
    supervision
        .controller()
        .install_placement(Arc::new(PoolPlacement(other.clone())));
    let observed = supervision
        .prepared_runtimes("default", vec![prepared.registration.route.clone()])
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(
        supervision
            .release_preparation(observed.revision.clone())
            .await
            .unwrap(),
        PreparationRelease::Released
    );
    assert_eq!(
        supervision
            .release_preparation(observed.revision)
            .await
            .unwrap(),
        PreparationRelease::Released
    );
    assert!(other.controller.pool_withdrawals().is_empty());
    assert!(supervision.controller().pool_withdrawals().is_empty());
    assert!(
        pool.prepared_runtimes("default", vec![prepared.registration.route.clone()])
            .await
            .unwrap()
            .is_empty()
    );
    pool.reconcile_once().await.unwrap();
    assert!(fixture.owner(&prepared.registration.route).await.is_none());
    assert!(pool.capacity("m1").await.unwrap().payload.routes.is_empty());
    assert_eq!(fixture.candidates().await, 0);
}

#[tokio::test]
async fn malformed_preparation_is_neither_an_empty_inventory_nor_an_absent_route() {
    let (_fixture, pool, prepared) = setup().await;
    let observed = inventory(&pool, &prepared).await;
    let revision = observed.revision;
    pool.store
        .put_if(
            ASSIGNMENT_OBJECT_TYPE,
            &assignment_object_id(&revision.route, &revision.reservation_id),
            &revision.route,
            "",
            b"{}",
            None,
            WriteCondition::MatchResourceVersion(revision.resource_version),
        )
        .await
        .unwrap();
    assert!(
        pool.prepared_runtimes("default", vec![prepared.registration.route.clone()])
            .await
            .is_err()
    );
    assert!(
        pool.runtime_assignment("default", &revision.route)
            .await
            .is_err()
    );
    assert!(pool.warm_claim("default", &revision.route).await.is_err());
    assert!(pool.release_preparation(revision).await.is_err());
    assert!(pool.controller.pool_withdrawals().is_empty());
}

#[tokio::test]
async fn preparation_release_rejects_wrong_workspace_and_prevents_route_reuse() {
    let (fixture, pool, prepared) = setup().await;
    let observed = inventory(&pool, &prepared).await;
    let mut wrong_workspace = observed.revision.clone();
    wrong_workspace.workspace = "another-workspace".into();
    assert_eq!(
        pool.release_preparation(wrong_workspace).await.unwrap(),
        PreparationRelease::Changed
    );
    assert_eq!(
        pool.release_preparation(observed.revision.clone())
            .await
            .unwrap(),
        PreparationRelease::Released
    );
    pool.reconcile_once().await.unwrap();

    // Delayed retries and accidental reuse cannot resurrect a retired route.
    let replacement = preparation(&fixture, &prepared.registration.route).await;
    assert!(pool.prepare_runtime(replacement).await.is_err());
    assert!(pool.prepare_runtime(prepared.clone()).await.is_err());
    assert_eq!(
        pool.release_preparation(observed.revision).await.unwrap(),
        PreparationRelease::Released
    );
    pool.reconcile_once().await.unwrap();
    assert!(
        pool.prepared_runtimes("default", vec![prepared.registration.route.clone()])
            .await
            .unwrap()
            .is_empty()
    );
    assert!(fixture.owner(&prepared.registration.route).await.is_none());
}

#[tokio::test]
async fn conditional_release_preserves_a_winning_claim_and_its_credentials() {
    let (fixture, pool, prepared) = setup().await;
    let observed = inventory(&pool, &prepared).await;
    let published = pool
        .activate_runtime(activation(&prepared, "sandbox-a"))
        .await
        .unwrap();
    let cleaner = fixture.replica("gateway-cleaner");
    assert_eq!(
        cleaner
            .release_preparation(observed.revision)
            .await
            .unwrap(),
        PreparationRelease::Changed
    );
    assert!(cleaner.controller.pool_withdrawals().is_empty());
    cleaner.reconcile_once().await.unwrap();
    pool.reconcile_once().await.unwrap();
    let active = pool
        .assignment(&prepared.registration.route)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        pool.load_material(&active.payload).await.unwrap(),
        published.launch_material
    );
    assert_eq!(
        fixture
            .owner(&prepared.registration.route)
            .await
            .unwrap()
            .sandbox_id,
        "sandbox-a"
    );
    assert_eq!(pool.capacity("m1").await.unwrap().payload.routes.len(), 1);
    assert_eq!(fixture.candidates().await, 0);
}

#[tokio::test]
async fn conditional_release_fences_an_inflight_claim() {
    let (fixture, pool, prepared) = setup().await;
    let observed = inventory(&pool, &prepared).await;
    let original_identity = fixture.identity("sandbox-a").await;
    let (task, resume) = pause_claim(&pool, activation(&prepared, "sandbox-a")).await;
    let cleaner = fixture.replica("gateway-cleaner");
    assert_eq!(
        cleaner
            .release_preparation(observed.revision)
            .await
            .unwrap(),
        PreparationRelease::Released
    );
    resume.send(()).unwrap();
    assert!(task.await.unwrap().is_err());
    pool.reconcile_once().await.unwrap();
    assert_eq!(
        pool.assignment(&prepared.registration.route)
            .await
            .unwrap()
            .unwrap()
            .payload
            .phase,
        RecordPhase::Retired
    );
    assert_eq!(fixture.identity("sandbox-a").await, original_identity);
    assert!(fixture.owner(&prepared.registration.route).await.is_none());
    assert!(pool.capacity("m1").await.unwrap().payload.routes.is_empty());
    assert_eq!(fixture.candidates().await, 0);
}

#[tokio::test]
async fn preparation_survives_gateway_recovery_and_claim_keeps_its_slot() {
    let (fixture, pool, prepared) = setup().await;
    let route = &prepared.registration.route;
    let before = fixture.owner(route).await.unwrap();
    assert!(before.sandbox_id.is_empty());
    assert!(
        pool.recorded().await.unwrap().is_empty(),
        "sandbox recovery excludes warm reservations"
    );
    pool.prepare_runtime(prepared.clone()).await.unwrap();
    let restarted = fixture.replica("gateway-b");
    restarted.reconcile_once().await.unwrap();
    restarted.reconcile_once().await.unwrap();
    let record = restarted.assignment(route).await.unwrap().unwrap();
    assert!(record.payload.prepared);
    assert_eq!(
        restarted.load_material(&record.payload).await.unwrap(),
        prepared
            .registration
            .to_assignment()
            .unwrap()
            .launch_material
    );
    assert_eq!(fixture.owner(route).await.unwrap(), before);
    let charge = restarted.capacity("m1").await.unwrap();
    let claim = activation(&prepared, "sandbox-a");
    restarted.activate_runtime(claim.clone()).await.unwrap();
    restarted.activate_runtime(claim.clone()).await.unwrap();
    let after = fixture.owner(route).await.unwrap();
    assert_eq!(after.sandbox_id, "sandbox-a");
    assert_eq!(
        (after.member_id, after.process_id, after.auth_epoch),
        (before.member_id, before.process_id, before.auth_epoch)
    );
    assert_eq!(
        restarted.capacity("m1").await.unwrap().resource_version,
        charge.resource_version
    );
    assert!(
        !restarted
            .assignment(route)
            .await
            .unwrap()
            .unwrap()
            .payload
            .prepared
    );
    assert!(restarted.recorded().await.unwrap().contains_key(route));
    assert!(restarted.prepare_runtime(prepared).await.is_err());
    assert_eq!(fixture.candidates().await, 0);
}

#[tokio::test]
async fn claim_adopts_physical_identity_and_issues_bound_credentials() {
    use crate::auth::sandbox_session::{advance_identity_for_takeover, authorize_persisted};
    use openshell_core::jwt::{SessionJwtVerifier, SessionTokenProfile, SystemJwtClock};
    let (fixture, pool, prepared) = setup().await;
    fixture
        .sandbox(
            "sandbox-a",
            "proposed-cold-generation",
            SandboxPhase::Provisioning,
        )
        .await;
    let before = fixture.identity("sandbox-a").await;
    let cold = pool
        .authority
        .mint_persisted_launch("sandbox-a", &before)
        .unwrap();
    let old_principal = pool
        .authority
        .verify_gateway_token(cold.supervisor.gateway_token.expose_secret())
        .unwrap();
    let mut request = activation(&prepared, "sandbox-a");
    request.expected_generation = before.runtime_generation;
    let published = pool.activate_runtime(request.clone()).await.unwrap();
    let registration = SandboxInstanceRegistration::from_assignment(&published).unwrap();
    let after = fixture.identity("sandbox-a").await;
    assert_eq!(
        after.runtime_generation.as_str(),
        prepared.registration.runtime_descriptor.generation
    );
    assert_ne!(after.gateway_token_id, before.gateway_token_id);
    assert_eq!(
        registration.auth.session_id,
        prepared.registration.runtime_descriptor.session_id
    );
    assert_eq!(pool.activate_runtime(request).await.unwrap(), published);
    assert!(
        authorize_persisted(&pool.store, &old_principal)
            .await
            .is_err()
    );
    let issued = pool
        .authority
        .verify_gateway_token(registration.auth.gateway_token.expose_secret())
        .unwrap();
    authorize_persisted(&pool.store, &issued).await.unwrap();
    let verifier = SessionJwtVerifier::new(
        "test-gateway",
        SessionTokenProfile::Sandbox,
        cold.verification_keys,
        Arc::new(SystemJwtClock),
    )
    .unwrap();
    let principal = verifier
        .verify(registration.auth.sandbox_token.expose_secret())
        .unwrap();
    assert_eq!(
        principal.resource_binding,
        prepared.registration.runtime_descriptor.resource_claims
    );
    assert_eq!(principal.runtime_generation, after.runtime_generation);
    assert_eq!(principal.sandbox_id.as_str(), "sandbox-a");
    assert_eq!(principal.auth_epoch, prepared.auth_epoch);
    assert!(issued.resource_binding.is_empty());

    // Reissuance before the runtime's first protocol request remains bound.
    let reissued = pool
        .authority
        .mint_persisted_launch("sandbox-a", &after)
        .unwrap();
    assert_eq!(
        verifier
            .verify(reissued.supervisor.sandbox_token.expose_secret())
            .unwrap()
            .resource_binding,
        principal.resource_binding
    );
    assert_eq!(reissued.supervisor.session_id, registration.auth.session_id);
    fixture.set_phase("sandbox-a", SandboxPhase::Ready).await;
    advance_identity_for_takeover(
        &pool.store,
        "sandbox-a",
        after.runtime_generation.as_str(),
        CredentialEpoch::new(2).unwrap(),
        Uuid::new_v4(),
    )
    .await
    .unwrap();
    let takeover = fixture.identity("sandbox-a").await;
    assert_eq!(takeover.prepared_runtime, after.prepared_runtime);
    let renewed = pool
        .authority
        .mint_persisted_launch("sandbox-a", &takeover)
        .unwrap();
    assert_eq!(renewed.supervisor.session_id, registration.auth.session_id);
    assert_eq!(
        verifier
            .verify(renewed.supervisor.sandbox_token.expose_secret())
            .unwrap()
            .auth_epoch
            .get(),
        2
    );
}

#[tokio::test]
async fn one_sandbox_cannot_claim_two_preparations() {
    let (fixture, pool, first) = setup().await;
    let second = preparation(&fixture, "rt-second-0123456789").await;
    pool.prepare_runtime(second.clone()).await.unwrap();
    let other = fixture.replica("gateway-b");
    let (a, b) = tokio::join!(
        pool.activate_runtime(activation(&first, "sandbox-a")),
        other.activate_runtime(activation(&second, "sandbox-a")),
    );
    assert_ne!(a.is_ok(), b.is_ok());
    let loser = if a.is_err() { first } else { second };
    assert!(
        pool.assignment(&loser.registration.route)
            .await
            .unwrap()
            .unwrap()
            .payload
            .prepared
    );
    assert!(
        pool.activate_runtime(activation(&loser, "sandbox-a"))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn claim_refuses_stale_launch_identity_and_non_launch_phases() {
    let (fixture, pool, prepared) = setup().await;
    let mut request = activation(&prepared, "sandbox-a");
    request.expected_auth_epoch = CredentialEpoch::new(2).unwrap();
    assert!(pool.activate_runtime(request).await.is_err());
    let mut request = activation(&prepared, "sandbox-a");
    request.expected_generation =
        openshell_core::sandbox_generation::SandboxGenerationId::parse("stale").unwrap();
    assert!(pool.activate_runtime(request).await.is_err());
    for phase in [
        SandboxPhase::Ready,
        SandboxPhase::Stopping,
        SandboxPhase::Stopped,
        SandboxPhase::Deleting,
        SandboxPhase::Error,
        SandboxPhase::Suspending,
        SandboxPhase::Suspended,
        SandboxPhase::Completed,
        SandboxPhase::Unknown,
    ] {
        fixture.set_phase("sandbox-a", phase).await;
        assert!(
            pool.activate_runtime(activation(&prepared, "sandbox-a"))
                .await
                .is_err(),
            "{phase:?}"
        );
    }
    assert!(
        fixture
            .identity("sandbox-a")
            .await
            .prepared_runtime
            .is_none()
    );
}

#[tokio::test]
async fn winning_claim_retry_cannot_republish_an_ended_launch() {
    let (fixture, pool, prepared) = setup().await;
    let request = activation(&prepared, "sandbox-a");
    pool.activate_runtime(request.clone()).await.unwrap();
    fixture.set_phase("sandbox-a", SandboxPhase::Stopping).await;
    assert!(pool.activate_runtime(request.clone()).await.is_err());
    fixture
        .sandbox(
            "sandbox-a",
            "replacement-generation",
            SandboxPhase::Starting,
        )
        .await;
    assert!(pool.activate_runtime(request).await.is_err());
}

#[tokio::test]
async fn warm_and_active_reservations_share_capacity_and_claim_needs_no_free_slot() {
    let (fixture, pool, prepared) = setup().await;
    fixture.fill("m1", "p1", MAX_ASSIGNED_INSTANCES - 1).await;
    let overflow = preparation(&fixture, "rt-overflow-0123456789").await;
    assert!(pool.prepare_runtime(overflow.clone()).await.is_err());
    assert!(
        pool.assignment(&overflow.registration.route)
            .await
            .unwrap()
            .is_none()
    );
    pool.activate_runtime(activation(&prepared, "sandbox-a"))
        .await
        .unwrap();
    assert_eq!(
        pool.capacity("m1").await.unwrap().payload.routes.len(),
        MAX_ASSIGNED_INSTANCES
    );
}

#[tokio::test]
async fn concurrent_activation_of_the_same_intent_returns_the_committed_material() {
    let (fixture, pool, prepared) = setup().await;
    pool.record_warm_claim("default", claim_intent(&prepared, "sandbox-a"))
        .await
        .unwrap();
    let claim = activation(&prepared, "sandbox-a");
    let (task, resume) = pause_claim(&pool, claim.clone()).await;
    let other = fixture.replica("gateway-b");
    let winner = other.activate_runtime(claim).await.unwrap();
    resume.send(()).unwrap();
    assert_eq!(task.await.unwrap().unwrap(), winner);
    assert_eq!(fixture.candidates().await, 0);
}

#[tokio::test]
async fn activation_rechecks_a_concurrent_sandbox_status_update() {
    let (fixture, pool, prepared) = setup().await;
    let (task, resume) = pause_claim(&pool, activation(&prepared, "sandbox-a")).await;
    fixture.set_phase("sandbox-a", SandboxPhase::Starting).await;
    resume.send(()).unwrap();
    let published = task.await.unwrap().unwrap();
    assert_eq!(published.sandbox_id, "sandbox-a");
    assert_eq!(fixture.candidates().await, 0);
}

#[tokio::test]
async fn two_claims_have_one_winner_and_the_loser_cannot_replace_it() {
    let (fixture, pool, prepared) = setup().await;
    fixture
        .sandbox("sandbox-b", "generation-1", SandboxPhase::Provisioning)
        .await;
    let other = fixture.replica("gateway-b");
    let a = activation(&prepared, "sandbox-a");
    let b = activation(&prepared, "sandbox-b");
    let (first, second) = tokio::join!(
        pool.activate_runtime(a.clone()),
        other.activate_runtime(b.clone())
    );
    assert_ne!(first.is_ok(), second.is_ok());
    let (winner, loser) = if first.is_ok() { (a, b) } else { (b, a) };
    let published = pool.activate_runtime(winner.clone()).await.unwrap();
    assert!(pool.activate_runtime(loser).await.is_err());
    pool.remove_stale_candidates().await;
    let record = pool
        .assignment(&prepared.registration.route)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        pool.load_material(&record.payload).await.unwrap(),
        published.launch_material
    );
    assert_eq!(fixture.candidates().await, 0);
}

#[tokio::test]
async fn conflicting_preparation_and_claim_coordinates_are_rejected() {
    let (_fixture, pool, prepared) = setup().await;
    let mut changed = prepared.clone();
    changed
        .registration
        .runtime_descriptor
        .resource_claims
        .insert("kubernetes.workload_pod_uid".into(), "other-pod".into());
    assert!(pool.prepare_runtime(changed.clone()).await.is_err());
    assert!(
        pool.activate_runtime(activation(&changed, "sandbox-a"))
            .await
            .is_err()
    );
    let mut changed = prepared.clone();
    changed.workspace = "other-workspace".into();
    assert!(pool.prepare_runtime(changed).await.is_err());
    let mut changed = prepared.clone();
    changed.auth_epoch = CredentialEpoch::new(2).unwrap();
    assert!(pool.prepare_runtime(changed.clone()).await.is_err());
    assert!(
        pool.activate_runtime(activation(&changed, "sandbox-a"))
            .await
            .is_err()
    );
    pool.activate_runtime(activation(&prepared, "sandbox-a"))
        .await
        .unwrap();
}

#[tokio::test]
async fn lost_prepared_owner_is_not_taken_over_and_cannot_be_claimed() {
    let (fixture, pool, prepared) = setup().await;
    let route = &prepared.registration.route;
    let owner = fixture.owner(route).await.unwrap();
    fixture.remove_member("m1").await;
    fixture.member("m2", "p2", false).await;
    pool.reconcile_once().await.unwrap();
    assert_eq!(fixture.owner(route).await.unwrap(), owner);
    assert!(
        pool.activate_runtime(activation(&prepared, "sandbox-a"))
            .await
            .is_err()
    );
    fixture.member("m1", "replacement-process", false).await;
    pool.reconcile_once().await.unwrap();
    assert!(
        pool.activate_runtime(activation(&prepared, "sandbox-a"))
            .await
            .is_err()
    );
    pool.controller.unassign(route);
    pool.reconcile_once().await.unwrap();
    assert_eq!(
        pool.assignment(route).await.unwrap().unwrap().payload.phase,
        RecordPhase::Retired
    );
    assert!(fixture.owner(route).await.is_none());
    assert!(pool.capacity("m1").await.unwrap().payload.routes.is_empty());
}

async fn pause_claim(
    pool: &Arc<SupervisorPool>,
    claim: ActivationRequest,
) -> (
    tokio::task::JoinHandle<Result<SandboxInstanceAssignment, String>>,
    tokio::sync::oneshot::Sender<()>,
) {
    let (reached, wait) = tokio::sync::oneshot::channel();
    let (resume, resumed) = tokio::sync::oneshot::channel();
    *lock(&pool.staged_gate) = Some((reached, resumed));
    let pool = pool.clone();
    let task = tokio::spawn(async move { pool.activate_runtime(claim).await });
    tokio::time::timeout(Duration::from_secs(5), wait)
        .await
        .unwrap()
        .unwrap();
    (task, resume)
}

#[tokio::test]
async fn material_collection_fences_an_activation_that_stalled() {
    let (fixture, pool, prepared) = setup().await;
    let claim = activation(&prepared, "sandbox-a");
    let (task, resume) = pause_claim(&pool, claim.clone()).await;
    pool.remove_stale_candidates().await;
    resume.send(()).unwrap();
    assert!(task.await.unwrap().is_err());
    assert!(
        pool.assignment(&prepared.registration.route)
            .await
            .unwrap()
            .unwrap()
            .payload
            .prepared
    );
    pool.activate_runtime(claim).await.unwrap();
    assert_eq!(fixture.candidates().await, 0);
}

#[tokio::test]
async fn withdrawal_fences_a_claim_and_collects_both_materials() {
    let (fixture, pool, prepared) = setup().await;
    let route = &prepared.registration.route;
    let (task, resume) = pause_claim(&pool, activation(&prepared, "sandbox-a")).await;
    pool.controller.unassign(route);
    pool.reconcile_once().await.unwrap();
    resume.send(()).unwrap();
    assert!(task.await.unwrap().is_err());
    pool.remove_stale_candidates().await;
    assert_eq!(
        pool.assignment(route).await.unwrap().unwrap().payload.phase,
        RecordPhase::Retired
    );
    assert!(fixture.owner(route).await.is_none());
    assert_eq!(fixture.candidates().await, 0);
}

fn retirement(prepared: &PreparationRequest) -> PreparationRetirement {
    PreparationRetirement {
        workspace: prepared.workspace.clone(),
        route: prepared.registration.route.clone(),
        generation: openshell_core::sandbox_generation::SandboxGenerationId::parse(
            prepared.registration.runtime_descriptor.generation.clone(),
        )
        .unwrap(),
        auth_epoch: prepared.auth_epoch,
    }
}

#[tokio::test]
async fn a_claimed_runtime_keeps_its_single_use_identity_after_the_sandbox_stops() {
    let (fixture, pool, prepared) = setup().await;
    pool.activate_runtime(activation(&prepared, "sandbox-a"))
        .await
        .unwrap();
    fixture
        .sandbox("sandbox-a", "generation-1", SandboxPhase::Stopped)
        .await;
    let route = &prepared.registration.route;
    pool.controller.unassign(route);
    pool.reconcile_once().await.unwrap();
    let record = pool.assignment(route).await.unwrap().unwrap();
    assert_eq!(record.payload.phase, RecordPhase::Retired);
    assert!(!record.payload.prepared);
    assert!(record.payload.material_handle.is_empty());
    assert!(pool.prepare_runtime(prepared.clone()).await.is_err());
    let recovered = fixture.replica("gateway-restarted");
    assert!(recovered.prepare_runtime(prepared.clone()).await.is_err());
    assert_eq!(
        recovered
            .retire_preparation(retirement(&prepared))
            .await
            .unwrap(),
        PreparationRelease::Changed
    );
    assert!(fixture.owner(route).await.is_none());
    assert!(
        recovered
            .capacity("m1")
            .await
            .unwrap()
            .payload
            .routes
            .is_empty()
    );
    assert_eq!(fixture.candidates().await, 0);
}

#[tokio::test]
async fn retirement_before_preparation_survives_restart_and_blocks_late_preparation() {
    let fixture = Fixture::new().await;
    fixture.member("m1", "p1", false).await;
    let pool = fixture.replica("gateway-a");
    let prepared = preparation(&fixture, "rt-never-admitted-0123456789").await;
    let request = retirement(&prepared);
    assert_eq!(
        pool.retire_preparation(request.clone()).await.unwrap(),
        PreparationRelease::Released
    );
    let recovered = fixture.replica("gateway-restarted");
    assert_eq!(
        recovered.retire_preparation(request).await.unwrap(),
        PreparationRelease::Released
    );
    assert!(recovered.prepare_runtime(prepared.clone()).await.is_err());
    recovered.reconcile_once().await.unwrap();
    assert!(
        recovered
            .prepared_runtimes("default", vec![prepared.registration.route.clone()])
            .await
            .unwrap()
            .is_empty()
    );
    assert!(recovered.recorded().await.unwrap().is_empty());
    assert!(fixture.owner(&prepared.registration.route).await.is_none());
    assert!(
        recovered
            .capacity("m1")
            .await
            .unwrap()
            .payload
            .routes
            .is_empty()
    );
    // Ordinary route withdrawal must never remove the retirement fence.
    recovered.controller.unassign(&prepared.registration.route);
    recovered.reconcile_once().await.unwrap();
    assert!(recovered.prepare_runtime(prepared).await.is_err());
}

#[tokio::test]
async fn retirement_fences_preparation_while_its_material_is_being_staged() {
    let fixture = Fixture::new().await;
    fixture.member("m1", "p1", false).await;
    let pool = fixture.replica("gateway-a");
    let prepared = preparation(&fixture, "rt-staging-0123456789").await;
    let request = retirement(&prepared);
    let (reached, wait) = tokio::sync::oneshot::channel();
    let (resume, resumed) = tokio::sync::oneshot::channel();
    *lock(&pool.staged_gate) = Some((reached, resumed));
    let worker = pool.clone();
    let task = tokio::spawn(async move { worker.prepare_runtime(prepared).await });
    tokio::time::timeout(Duration::from_secs(5), wait)
        .await
        .unwrap()
        .unwrap();
    let cleaner = fixture.replica("gateway-cleaner");
    assert_eq!(
        cleaner.retire_preparation(request.clone()).await.unwrap(),
        PreparationRelease::Released
    );
    resume.send(()).unwrap();
    assert!(task.await.unwrap().is_err());
    cleaner.reconcile_once().await.unwrap();
    assert_eq!(fixture.candidates().await, 0);
    assert!(fixture.owner(&request.route).await.is_none());
    assert_eq!(
        cleaner
            .assignment(&request.route)
            .await
            .unwrap()
            .unwrap()
            .payload
            .phase,
        RecordPhase::Retired
    );
}

#[tokio::test]
async fn retirement_covers_admitting_records_but_never_a_claim_or_other_identity() {
    let (fixture, pool, prepared) = setup().await;
    for field in ["workspace", "generation", "epoch"] {
        let mut request = retirement(&prepared);
        match field {
            "workspace" => request.workspace = "other".into(),
            "generation" => {
                request.generation =
                    openshell_core::sandbox_generation::SandboxGenerationId::parse("other")
                        .unwrap();
            }
            _ => request.auth_epoch = CredentialEpoch::new(2).unwrap(),
        }
        assert_eq!(
            pool.retire_preparation(request).await.unwrap(),
            PreparationRelease::Changed
        );
    }
    let pending = preparation(&fixture, "rt-admitting-0123456789").await;
    pool.record_assignment_scoped(
        &pending.registration.to_assignment().unwrap(),
        RecordPhase::Admitting,
        Some(("default", 1, "test-pool")),
    )
    .await
    .unwrap();
    assert_eq!(
        pool.retire_preparation(retirement(&pending)).await.unwrap(),
        PreparationRelease::Released
    );
    pool.remove_stale_candidates().await;
    assert_eq!(fixture.candidates().await, 0);
    let published = pool
        .activate_runtime(activation(&prepared, "sandbox-a"))
        .await
        .unwrap();
    assert_eq!(
        pool.retire_preparation(retirement(&prepared))
            .await
            .unwrap(),
        PreparationRelease::Changed
    );
    let active = pool
        .assignment(&prepared.registration.route)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        pool.load_material(&active.payload).await.unwrap(),
        published.launch_material
    );
    assert_eq!(pool.capacity("m1").await.unwrap().payload.routes.len(), 1);
}

#[tokio::test]
async fn stale_withdrawal_cannot_remove_the_winning_claim_or_its_material() {
    let (_fixture, pool, prepared) = setup().await;
    let route = &prepared.registration.route;
    let old = pool.assignment(route).await.unwrap().unwrap();
    let claim = activation(&prepared, "sandbox-a");
    let published = pool.activate_runtime(claim.clone()).await.unwrap();
    assert!(pool.delete_assignment(&old).await.is_err());
    pool.remove_stale_candidates().await;
    let active = pool.assignment(route).await.unwrap().unwrap();
    assert_eq!(
        pool.load_material(&active.payload).await.unwrap(),
        published.launch_material
    );
}

#[tokio::test]
async fn supervisor_departure_while_staging_keeps_the_runtime_unassigned() {
    let (fixture, pool, prepared) = setup().await;
    let (task, resume) = pause_claim(&pool, activation(&prepared, "sandbox-a")).await;
    fixture.member("m1", "p1", true).await;
    resume.send(()).unwrap();
    assert!(task.await.unwrap().is_err());
    pool.remove_stale_candidates().await;
    assert!(
        pool.assignment(&prepared.registration.route)
            .await
            .unwrap()
            .unwrap()
            .payload
            .prepared
    );
    assert_eq!(fixture.candidates().await, 0);
}

#[tokio::test]
async fn sandbox_stop_fences_a_staged_claim() {
    let (fixture, pool, prepared) = setup().await;
    let (task, resume) = pause_claim(&pool, activation(&prepared, "sandbox-a")).await;
    fixture.set_phase("sandbox-a", SandboxPhase::Stopped).await;
    resume.send(()).unwrap();
    assert!(task.await.unwrap().is_err());
    pool.remove_stale_candidates().await;
    assert!(
        pool.assignment(&prepared.registration.route)
            .await
            .unwrap()
            .unwrap()
            .payload
            .prepared
    );
    assert_eq!(fixture.candidates().await, 0);
}

async fn dedicated_setup() -> (Fixture, Arc<SupervisorPool>, PreparationRequest) {
    let fixture = Fixture::new().await;
    fixture
        .sandbox("sandbox-a", "generation-1", SandboxPhase::Provisioning)
        .await;
    let mut pool = fixture.replica("dedicated");
    Arc::get_mut(&mut pool).unwrap().dedicated = true;
    let mut request = preparation(&fixture, "rt-dedicated-0123456789").await;
    request
        .registration
        .runtime_descriptor
        .resource_claims
        .insert(
            "kubernetes.supervisor_pod_uid".into(),
            "supervisor-pod".into(),
        );
    pool.prepare_runtime(request.clone()).await.unwrap();
    (fixture, pool, request)
}

#[tokio::test]
async fn dedicated_claim_uses_the_common_transaction_without_shared_capacity() {
    let (fixture, pool, prepared) = dedicated_setup().await;
    assert!(pool.owners().await.unwrap().is_empty());
    assert!(pool.capacities().await.unwrap().is_empty());
    assert_eq!(
        inventory(&pool, &prepared).await.owner.unwrap().process_id,
        "supervisor-pod"
    );
    let request = activation(&prepared, "sandbox-a");
    let canonical = pool.activate_runtime(request.clone()).await.unwrap();
    assert_ne!(
        canonical.launch_material,
        request.assignment.launch_material
    );
    assert_eq!(pool.activate_runtime(request).await.unwrap(), canonical);
    let mut restarted = fixture.replica("restarted");
    Arc::get_mut(&mut restarted).unwrap().dedicated = true;
    assert_eq!(
        restarted
            .activate_runtime(activation(&prepared, "sandbox-a"))
            .await
            .unwrap(),
        canonical
    );
    assert!(pool.owners().await.unwrap().is_empty());
    assert!(
        fixture
            .replica("shared")
            .all_assignments()
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        fixture
            .replica("shared")
            .activate_runtime(activation(&prepared, "sandbox-a"))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn dedicated_retirement_fences_late_preparation_and_claim() {
    let (_fixture, pool, prepared) = dedicated_setup().await;
    let revision = inventory(&pool, &prepared).await.revision;
    assert_eq!(
        pool.release_preparation(revision).await.unwrap(),
        PreparationRelease::Released
    );
    assert!(pool.prepare_runtime(prepared.clone()).await.is_err());
    assert!(
        pool.activate_runtime(activation(&prepared, "sandbox-a"))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn dedicated_stop_racing_activation_keeps_the_sandbox_unclaimed() {
    let (fixture, pool, prepared) = dedicated_setup().await;
    fixture
        .sandbox("sandbox-a", "generation-1", SandboxPhase::Stopped)
        .await;
    assert!(
        pool.activate_runtime(activation(&prepared, "sandbox-a"))
            .await
            .is_err()
    );
    assert_eq!(
        inventory(&pool, &prepared).await.registration,
        prepared.registration
    );
}

fn registration_identity(
    prepared: &PreparationRequest,
) -> openshell_core::proto::compute::v1::SupervisorRegistrationIdentity {
    let descriptor = &prepared.registration.runtime_descriptor;
    openshell_core::proto::compute::v1::SupervisorRegistrationIdentity {
        route: prepared.registration.route.clone(),
        generation: descriptor.generation.clone(),
        session_id: descriptor.session_id.to_string(),
        resource_claims: descriptor.resource_claims.clone().into_iter().collect(),
    }
}

#[tokio::test]
async fn dedicated_registration_is_pending_until_commit_and_recovers_the_same_launch() {
    let (fixture, pool, prepared) = dedicated_setup().await;
    let identity = registration_identity(&prepared);
    assert!(
        pool.dedicated_registration(&identity)
            .await
            .unwrap()
            .is_none()
    );
    let mut subscription = pool.registrations.subscribe(&identity.route).unwrap();
    let canonical = pool
        .activate_runtime(activation(&prepared, "sandbox-a"))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), subscription.changed())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        pool.dedicated_registration(&identity)
            .await
            .unwrap()
            .unwrap(),
        canonical.launch_material
    );
    let placement = PoolPlacement(pool.clone());
    let session = prepared.registration.runtime_descriptor.session_id;
    assert!(
        !placement
            .dedicated_claim_started("sandbox-a".into(), session)
            .await
            .unwrap()
    );
    let mut sandbox = pool
        .store
        .get_message::<Sandbox>("sandbox-a")
        .await
        .unwrap()
        .unwrap();
    sandbox.status.as_mut().unwrap().configuration_admission =
        Some(openshell_core::proto::SandboxConfigurationAdmission {
            instance_id: "connected-instance".into(),
            ..Default::default()
        });
    pool.store.put_message(&sandbox).await.unwrap();
    assert!(
        placement
            .dedicated_claim_started("sandbox-a".into(), session)
            .await
            .unwrap()
    );
    assert!(
        !placement
            .dedicated_claim_started("sandbox-a".into(), openshell_core::SandboxSessionId::new())
            .await
            .unwrap()
    );
    // A failed identity read must leave the committed launch available for retry.
    let saved = pool
        .store
        .get_message::<Sandbox>("sandbox-a")
        .await
        .unwrap()
        .unwrap();
    pool.store
        .put(
            Sandbox::object_type(),
            "sandbox-a",
            "sandbox-a",
            "default",
            &[0xff],
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        pool.dedicated_registration(&identity)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unavailable
    );
    pool.store.put_message(&saved).await.unwrap();
    let mut recovered = fixture.replica("different-gateway");
    Arc::get_mut(&mut recovered).unwrap().dedicated = true;
    assert_eq!(
        recovered
            .dedicated_registration(&identity)
            .await
            .unwrap()
            .unwrap(),
        canonical.launch_material
    );
    for field in ["route", "generation", "session", "pod"] {
        let mut stale = identity.clone();
        match field {
            "route" => stale.route = "rt-other-0123456789".into(),
            "generation" => stale.generation = "another-generation".into(),
            "session" => stale.session_id = openshell_core::SandboxSessionId::new().to_string(),
            _ => {
                stale
                    .resource_claims
                    .insert("kubernetes.supervisor_pod_uid".into(), "replacement".into());
            }
        }
        assert!(
            pool.dedicated_registration(&stale).await.is_err(),
            "{field}"
        );
    }
    fixture
        .sandbox("sandbox-a", "generation-1", SandboxPhase::Stopped)
        .await;
    assert!(pool.dedicated_registration(&identity).await.is_err());
}

#[tokio::test]
async fn dedicated_registration_rejects_retirement_and_credential_epoch_changes() {
    let (_, pool, prepared) = dedicated_setup().await;
    let identity = registration_identity(&prepared);
    pool.activate_runtime(activation(&prepared, "sandbox-a"))
        .await
        .unwrap();
    advance_identity_for_takeover(
        &pool.store,
        "sandbox-a",
        "generation-1",
        CredentialEpoch::new(2).unwrap(),
        Uuid::new_v4(),
    )
    .await
    .unwrap();
    assert!(pool.dedicated_registration(&identity).await.is_err());
    let (_, pool, prepared) = dedicated_setup().await;
    let identity = registration_identity(&prepared);
    pool.release_preparation(inventory(&pool, &prepared).await.revision)
        .await
        .unwrap();
    assert!(pool.dedicated_registration(&identity).await.is_err());
}

#[tokio::test]
async fn dedicated_registration_watcher_observes_remote_activation_and_local_retirement() {
    use futures::FutureExt as _;

    let (fixture, pool, prepared) = dedicated_setup().await;
    let identity = registration_identity(&prepared);
    let mut other = preparation(&fixture, "rt-unaffected-0123456789").await;
    other
        .registration
        .runtime_descriptor
        .resource_claims
        .insert(
            "kubernetes.supervisor_pod_uid".into(),
            "other-supervisor".into(),
        );
    pool.prepare_runtime(other.clone()).await.unwrap();
    let mut subscription = pool.registrations.subscribe(&identity.route).unwrap();
    let mut unaffected = pool
        .registrations
        .subscribe(&other.registration.route)
        .unwrap();
    let (stamp, pending) = pool.check_dedicated_registration(&identity).await.unwrap();
    assert!(pending.is_none());
    subscription.baseline(stamp);
    let (stamp, _) = pool
        .check_dedicated_registration(&registration_identity(&other))
        .await
        .unwrap();
    unaffected.baseline(stamp);
    for _ in 0..3 {
        pool.registrations.observe(&pool.store).await.unwrap();
        assert!(subscription.changed().now_or_never().is_none());
        assert!(unaffected.changed().now_or_never().is_none());
    }
    let mut remote = fixture.replica("remote");
    Arc::get_mut(&mut remote).unwrap().dedicated = true;
    let claimed = remote
        .activate_runtime(activation(&prepared, "sandbox-a"))
        .await
        .unwrap();
    assert!(lock(&remote.materials).is_empty());
    assert!(lock(&pool.materials).is_empty());
    assert!(subscription.changed().now_or_never().is_none());
    pool.registrations.observe(&pool.store).await.unwrap();
    subscription.changed().await.unwrap();
    assert!(unaffected.changed().now_or_never().is_none());
    assert_eq!(
        pool.dedicated_registration(&identity)
            .await
            .unwrap()
            .unwrap(),
        claimed.launch_material
    );

    let remaining = inventory(&pool, &other).await;
    assert_eq!(remaining.registration.route, other.registration.route);
    pool.release_preparation(remaining.revision).await.unwrap();
    unaffected.changed().await.unwrap();
    assert!(
        pool.dedicated_registration(&registration_identity(&other))
            .await
            .is_err()
    );
}

fn claim_intent(
    prepared: &PreparationRequest,
    sandbox: &str,
) -> openshell_supervisor_control::WarmClaimIntent {
    let request = activation(prepared, sandbox);
    openshell_supervisor_control::WarmClaimIntent {
        registration: SandboxInstanceRegistration::from_assignment(&request.assignment).unwrap(),
        expected_generation: request.expected_generation,
        expected_auth_epoch: request.expected_auth_epoch,
    }
}

fn claim_lookup(
    intent: &openshell_supervisor_control::WarmClaimIntent,
) -> openshell_supervisor_control::WarmClaimLookup {
    openshell_supervisor_control::WarmClaimLookup {
        workspace: "default".into(),
        sandbox_id: intent.registration.sandbox_id.clone(),
        expected_generation: intent.expected_generation.clone(),
        expected_auth_epoch: intent.expected_auth_epoch,
    }
}

#[tokio::test]
async fn committed_intent_owns_the_preparation_before_infrastructure_binding() {
    let (fixture, pool, prepared) = setup().await;
    let mut sandbox = pool
        .store
        .get_message::<Sandbox>("sandbox-a")
        .await
        .unwrap()
        .unwrap();
    sandbox.status.as_mut().unwrap().provisioning =
        Some(openshell_core::proto::SandboxProvisioning {
            driver_operation_pending: true,
            driver_operation_id: "original-create".into(),
            ..Default::default()
        });
    pool.store.put_message(&sandbox).await.unwrap();
    let intent = claim_intent(&prepared, "sandbox-a");
    pool.record_warm_claim("default", intent.clone())
        .await
        .unwrap();
    let restarted = fixture.replica("gateway-restarted");
    let observed = inventory(&restarted, &prepared).await;
    assert_eq!(
        restarted
            .release_preparation(observed.revision)
            .await
            .unwrap(),
        PreparationRelease::Changed
    );
    assert_eq!(
        restarted
            .retire_preparation(retirement(&prepared))
            .await
            .unwrap(),
        PreparationRelease::Changed
    );
    let scope = (prepared.workspace.clone(), prepared.pool_id.clone());
    let other_scope = (prepared.workspace.clone(), "other-pool".into());
    let mut inventories = restarted
        .pending_warm_claims(vec![scope.clone(), other_scope.clone()], None)
        .await
        .unwrap();
    let other = inventories.remove(&other_scope).unwrap().unwrap();
    assert!(other.pending.is_empty() && other.retired.is_empty());
    let recovered = inventories.remove(&scope).unwrap().unwrap();
    assert_eq!(recovered.pending.len(), 1);
    assert!(recovered.retired.is_empty());
    assert_eq!(
        recovered.pending[0].intent.registration.route,
        prepared.registration.route
    );
    assert!(
        restarted
            .choose_cold_launch(claim_lookup(&intent))
            .await
            .unwrap()
            .is_some()
    );
    let mut pending = restarted
        .store
        .get_message::<Sandbox>("sandbox-a")
        .await
        .unwrap()
        .unwrap();
    let original = pending.clone();
    pending
        .status
        .as_mut()
        .unwrap()
        .provisioning
        .as_mut()
        .unwrap()
        .driver_operation_id = "another-create".into();
    restarted.store.put_message(&pending).await.unwrap();
    assert!(
        restarted
            .activate_runtime(activation(&prepared, "sandbox-a"))
            .await
            .is_err()
    );
    assert!(
        restarted
            .store
            .get_message::<Sandbox>("sandbox-a")
            .await
            .unwrap()
            .unwrap()
            .status
            .unwrap()
            .provisioning
            .unwrap()
            .driver_operation_pending
    );
    restarted.store.put_message(&original).await.unwrap();
    restarted
        .activate_runtime(activation(&prepared, "sandbox-a"))
        .await
        .unwrap();
    let settled = restarted
        .store
        .get_message::<Sandbox>("sandbox-a")
        .await
        .unwrap()
        .unwrap();
    let op = settled.status.unwrap().provisioning.unwrap();
    assert!(!op.driver_operation_pending);
    assert_eq!(op.driver_operation_id, "original-create");
    let annotations = settled.metadata.unwrap().annotations;
    assert_eq!(
        annotations[crate::compute::COMPUTE_RUNTIME_IDENTITY_ANNOTATION],
        "runtime-identity"
    );
    assert_eq!(
        annotations[crate::compute::COMPUTE_DRIVER_ANNOTATION],
        "kubernetes"
    );
    assert!(
        !restarted
            .cancel_warm_claim("default", &prepared.registration.route)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn retirement_winner_is_a_typed_miss_and_allows_a_cold_decision() {
    let (fixture, pool, prepared) = setup().await;
    let intent = claim_intent(&prepared, "sandbox-a");
    pool.retire_preparation(retirement(&prepared))
        .await
        .unwrap();
    assert!(matches!(
        pool.reserve_warm_claim("default", intent.clone())
            .await
            .unwrap(),
        openshell_supervisor_control::WarmClaimReservation::Unavailable
    ));
    assert!(
        pool.choose_cold_launch(claim_lookup(&intent))
            .await
            .unwrap()
            .is_none()
    );
    let other = preparation(&fixture, "rt-other-prepared-0123456789").await;
    pool.prepare_runtime(other.clone()).await.unwrap();
    assert!(matches!(
        pool.reserve_warm_claim("default", claim_intent(&other, "sandbox-a"))
            .await
            .unwrap(),
        openshell_supervisor_control::WarmClaimReservation::Unavailable
    ));
    assert!(
        pool.activate_runtime(activation(&other, "sandbox-a"))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn cold_decision_fences_a_staged_warm_intent() {
    let (fixture, pool, prepared) = setup().await;
    let intent = claim_intent(&prepared, "sandbox-a");
    let (reached, wait) = tokio::sync::oneshot::channel();
    let (resume, resumed) = tokio::sync::oneshot::channel();
    *lock(&pool.staged_gate) = Some((reached, resumed));
    let worker = pool.clone();
    let proposed = intent.clone();
    let task = tokio::spawn(async move { worker.reserve_warm_claim("default", proposed).await });
    tokio::time::timeout(Duration::from_secs(5), wait)
        .await
        .unwrap()
        .unwrap();
    let other = fixture.replica("gateway-cold");
    assert!(
        other
            .choose_cold_launch(claim_lookup(&intent))
            .await
            .unwrap()
            .is_none()
    );
    resume.send(()).unwrap();
    assert!(matches!(
        task.await.unwrap().unwrap(),
        openshell_supervisor_control::WarmClaimReservation::Unavailable
    ));
    assert!(
        other
            .warm_claim_for_launch(claim_lookup(&intent))
            .await
            .unwrap()
            .is_none()
    );
    other.remove_stale_candidates().await;
    assert_eq!(fixture.candidates().await, 0);
}

#[tokio::test]
async fn cancellation_fences_staged_activation_and_preserves_a_terminal_launch_decision() {
    let (fixture, pool, prepared) = setup().await;
    let intent = claim_intent(&prepared, "sandbox-a");
    pool.record_warm_claim("default", intent.clone())
        .await
        .unwrap();
    let (task, resume) = pause_claim(&pool, activation(&prepared, "sandbox-a")).await;
    let other = fixture.replica("gateway-cancel");
    assert!(
        other
            .cancel_warm_claim("default", &prepared.registration.route)
            .await
            .unwrap()
    );
    resume.send(()).unwrap();
    assert!(task.await.unwrap().is_err());
    assert!(
        other
            .choose_cold_launch(claim_lookup(&intent))
            .await
            .is_err()
    );
    assert!(
        other
            .warm_claim_for_launch(claim_lookup(&intent))
            .await
            .is_err()
    );
    let inventory = other
        .pending_warm_claims(vec![("default".into(), "test-pool".into())], None)
        .await
        .unwrap()
        .remove(&("default".into(), "test-pool".into()))
        .unwrap()
        .unwrap();
    assert!(inventory.pending.is_empty());
    assert_eq!(inventory.retired.len(), 1);
    assert!(
        other
            .cancel_warm_claim("default", &prepared.registration.route)
            .await
            .unwrap()
    );
    other.remove_stale_candidates().await;
    assert_eq!(fixture.candidates().await, 0);
}

#[tokio::test]
async fn cancellation_after_restart_settles_only_the_reserved_create() {
    for replace_operation in [false, true] {
        let (fixture, pool, prepared) = setup().await;
        let set_operation = |sandbox: &mut Sandbox, id: &str| {
            sandbox.status.as_mut().unwrap().provisioning =
                Some(openshell_core::proto::SandboxProvisioning {
                    driver_operation_id: id.into(),
                    driver_operation_pending: true,
                    ..Default::default()
                });
        };
        let mut sandbox = pool
            .store
            .get_message::<Sandbox>("sandbox-a")
            .await
            .unwrap()
            .unwrap();
        set_operation(&mut sandbox, "original");
        pool.store.put_message(&sandbox).await.unwrap();
        pool.record_warm_claim("default", claim_intent(&prepared, "sandbox-a"))
            .await
            .unwrap();
        if replace_operation {
            let mut sandbox = pool
                .store
                .get_message::<Sandbox>("sandbox-a")
                .await
                .unwrap()
                .unwrap();
            set_operation(&mut sandbox, "replacement");
            pool.store.put_message(&sandbox).await.unwrap();
        }
        let restarted = fixture.replica("recovery");
        assert!(
            restarted
                .cancel_warm_claim("default", &prepared.registration.route)
                .await
                .unwrap()
        );
        let sandbox = restarted
            .store
            .get_message::<Sandbox>("sandbox-a")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            sandbox.phase() == SandboxPhase::Error as i32,
            !replace_operation
        );
        assert_eq!(
            sandbox
                .status
                .unwrap()
                .provisioning
                .unwrap()
                .driver_operation_pending,
            replace_operation
        );
    }
}

#[tokio::test]
async fn abandoned_claim_cleanup_preserves_a_newer_launch() {
    for restart in [false, true] {
        let (fixture, pool, prepared) = setup().await;
        let intent = claim_intent(&prepared, "sandbox-a");
        pool.record_warm_claim("default", intent.clone())
            .await
            .unwrap();
        if restart {
            fixture
                .sandbox("sandbox-a", "next-generation", SandboxPhase::Provisioning)
                .await;
        } else {
            fixture.set_phase("sandbox-a", SandboxPhase::Stopped).await;
        }
        let restarted = fixture.replica("gateway-restarted");
        restarted
            .cancel_abandoned_warm_claims(&restarted.all_assignments().await.unwrap())
            .await;
        let inventory = restarted
            .pending_warm_claims(vec![("default".into(), "test-pool".into())], None)
            .await
            .unwrap()
            .remove(&("default".into(), "test-pool".into()))
            .unwrap()
            .unwrap();
        assert!(inventory.pending.is_empty());
        assert_eq!(inventory.retired.len(), 1);
        if restart {
            let mut lookup = claim_lookup(&intent);
            lookup.expected_generation =
                openshell_core::sandbox_generation::SandboxGenerationId::parse("next-generation")
                    .unwrap();
            assert!(
                restarted
                    .choose_cold_launch(lookup)
                    .await
                    .unwrap()
                    .is_none()
            );
        } else {
            assert!(
                restarted
                    .choose_cold_launch(claim_lookup(&intent))
                    .await
                    .is_err()
            );
        }
    }
}

#[tokio::test]
async fn warm_claim_journal_survives_restart_activation_and_collects_on_retirement() {
    let (fixture, pool, prepared) = setup().await;
    let route = &prepared.registration.route;
    let intent = claim_intent(&prepared, "sandbox-a");
    let persisted = pool
        .record_warm_claim("default", intent.clone())
        .await
        .unwrap();
    let restarted = fixture.replica("gateway-restarted");
    let recovered = restarted.warm_claim("default", route).await.unwrap();
    assert_eq!(
        serde_json::to_vec(&persisted).unwrap(),
        serde_json::to_vec(&recovered).unwrap()
    );
    assert!(
        restarted
            .warm_claim("other-workspace", route)
            .await
            .is_err()
    );
    assert!(
        restarted
            .runtime_assignment("other-workspace", route)
            .await
            .is_err()
    );
    let reference = restarted.assignment(route).await.unwrap().unwrap();
    let intent_material = AssignmentPayload {
        material_handle: reference.payload.claim_handle.clone(),
        prepared: true,
        sandbox_id: String::new(),
        ..reference.payload.clone()
    };
    // Database records carry a credential handle, not tokens or the proxy key.
    let record_bytes = serde_json::to_string(&reference.payload).unwrap();
    assert!(!record_bytes.contains("test-key"));
    assert!(!record_bytes.contains("test-gateway"));
    let committed = restarted
        .activate_runtime(activation(&prepared, "sandbox-a"))
        .await
        .unwrap();
    assert_eq!(
        restarted
            .runtime_assignment("default", route)
            .await
            .unwrap()
            .unwrap(),
        committed
    );
    assert_eq!(
        serde_json::to_vec(&restarted.warm_claim("default", route).await.unwrap()).unwrap(),
        serde_json::to_vec(&intent).unwrap()
    );
    restarted.remove_stale_candidates().await;
    assert!(restarted.load_material(&intent_material).await.is_ok());
    let current = restarted.assignment(route).await.unwrap().unwrap();
    restarted.retire_assignment(&current).await.unwrap();
    restarted.remove_stale_candidates().await;
    assert!(restarted.load_material(&intent_material).await.is_err());
    assert!(restarted.warm_claim("default", route).await.is_err());
    assert!(
        restarted
            .record_warm_claim("default", intent)
            .await
            .is_err()
    );
    assert_eq!(fixture.candidates().await, 0);
}

#[tokio::test]
async fn concurrent_warm_claim_intents_preserve_one_winner_and_collect_losers() {
    let (fixture, first, prepared) = setup().await;
    let second = fixture.replica("gateway-b");
    let intent = claim_intent(&prepared, "sandbox-a");
    let mut retry = intent.clone();
    retry.registration.auth.gateway_token =
        openshell_core::jwt::SecretJwt::parse("refreshed-proposed-token").unwrap();
    retry.registration.auth.gateway_expires_at = 123;

    retry.registration.proxy_ca = openshell_supervisor_control::ProxyCaMaterial {
        certificate_pem: "another-ca".into(),
        private_key_pem: openshell_supervisor_control::SecretPem::new("another-key".into()),
    };
    let (a, b) = tokio::join!(
        first.record_warm_claim("default", intent),
        second.record_warm_claim("default", retry)
    );
    assert_eq!(
        serde_json::to_vec(&a.unwrap()).unwrap(),
        serde_json::to_vec(&b.unwrap()).unwrap()
    );
    first.remove_stale_candidates().await;
    let winning = first
        .warm_claim("default", &prepared.registration.route)
        .await
        .unwrap();
    let mut changed = winning.clone();
    changed.expected_auth_epoch = CredentialEpoch::new(2).unwrap();
    assert!(first.record_warm_claim("default", changed).await.is_err());
    fixture
        .sandbox("sandbox-b", "generation-1", SandboxPhase::Provisioning)
        .await;
    assert!(
        first
            .record_warm_claim("default", claim_intent(&prepared, "sandbox-b"))
            .await
            .is_err()
    );
    assert_eq!(fixture.candidates().await, 0);
    assert_eq!(
        serde_json::to_vec(&winning).unwrap(),
        serde_json::to_vec(
            &first
                .warm_claim("default", &prepared.registration.route)
                .await
                .unwrap()
        )
        .unwrap()
    );
}

#[tokio::test]
async fn warm_claim_collection_and_retirement_fence_delayed_intent_publication() {
    for retire in [false, true] {
        let (fixture, pool, prepared) = setup().await;
        let (reached, wait) = tokio::sync::oneshot::channel();
        let (resume, resumed) = tokio::sync::oneshot::channel();
        *lock(&pool.staged_gate) = Some((reached, resumed));
        let worker = pool.clone();
        let intent = claim_intent(&prepared, "sandbox-a");
        let task = tokio::spawn(async move { worker.record_warm_claim("default", intent).await });
        tokio::time::timeout(Duration::from_secs(5), wait)
            .await
            .unwrap()
            .unwrap();
        let collector = fixture.replica("gateway-collector");
        if retire {
            assert_eq!(
                collector
                    .retire_preparation(retirement(&prepared))
                    .await
                    .unwrap(),
                PreparationRelease::Released
            );
        }
        collector.remove_stale_candidates().await;
        resume.send(()).unwrap();
        assert!(task.await.unwrap().is_err());
        assert!(
            collector
                .warm_claim("default", &prepared.registration.route)
                .await
                .is_err()
        );
        assert_eq!(fixture.candidates().await, 0);
    }
}

#[tokio::test]
async fn caller_annotation_cannot_block_or_replace_a_launch_decision() {
    let (_, pool, prepared) = setup().await;
    let intent = claim_intent(&prepared, "sandbox-a");
    let lookup = claim_lookup(&intent);
    let mut sandbox = pool
        .store
        .get_message::<Sandbox>("sandbox-a")
        .await
        .unwrap()
        .unwrap();
    sandbox.metadata.as_mut().unwrap().annotations.insert(
        "openshell.ai/warm-claim-intent".into(),
        "caller text".into(),
    );
    pool.store.put_message(&sandbox).await.unwrap();
    assert!(
        pool.warm_claim_for_launch(lookup.clone())
            .await
            .unwrap()
            .is_none()
    );
    pool.reserve_warm_claim("default", intent).await.unwrap();
    let mut sandbox = pool
        .store
        .get_message::<Sandbox>("sandbox-a")
        .await
        .unwrap()
        .unwrap();
    openshell_core::sandbox_update::apply_configuration(
        &mut sandbox,
        None,
        None,
        None,
        Some(&openshell_core::proto::SandboxMapUpdate::default()),
    );
    pool.store.put_message(&sandbox).await.unwrap();
    assert_eq!(
        pool.warm_claim_for_launch(lookup)
            .await
            .unwrap()
            .unwrap()
            .registration
            .route,
        prepared.registration.route
    );
}

#[tokio::test]
async fn one_logical_launch_selects_one_intent_before_either_cr_is_bound() {
    let (fixture, first, prepared) = setup().await;
    let other = preparation(&fixture, "rt-another-prepared-0123456789").await;
    first.prepare_runtime(other.clone()).await.unwrap();
    let second = fixture.replica("gateway-b");
    let (a, b) = tokio::join!(
        first.record_warm_claim("default", claim_intent(&prepared, "sandbox-a")),
        second.record_warm_claim("default", claim_intent(&other, "sandbox-a")),
    );
    assert_ne!(
        a.is_ok(),
        b.is_ok(),
        "only one physical route can bind the logical launch"
    );
    let winning = a.or(b).unwrap();
    let lookup = openshell_supervisor_control::WarmClaimLookup {
        workspace: "default".into(),
        sandbox_id: "sandbox-a".into(),
        expected_generation: winning.expected_generation.clone(),
        expected_auth_epoch: winning.expected_auth_epoch,
    };
    let restarted = fixture.replica("gateway-restarted");
    let recovered = restarted
        .warm_claim_for_launch(lookup.clone())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(winning.registration.route, recovered.registration.route);
    let mut later = lookup;
    later.expected_generation =
        openshell_core::sandbox_generation::SandboxGenerationId::parse("next-launch").unwrap();
    assert!(
        restarted
            .warm_claim_for_launch(later)
            .await
            .unwrap()
            .is_none()
    );
    restarted.remove_stale_candidates().await;
    assert_eq!(fixture.candidates().await, 0);
}

async fn remove_preparation_intent(pool: &SupervisorPool, prepared: &PreparationRequest) {
    use openshell_supervisor_control::warm_pool::WarmPoolUpdate;
    let mut snapshot = pool
        .warm_pool_state(&prepared.workspace, &prepared.pool_id)
        .await
        .unwrap()
        .unwrap();
    snapshot
        .state
        .entries
        .retain(|entry| entry.session_id != prepared.registration.runtime_descriptor.session_id);
    assert!(
        pool.update_warm_pool(WarmPoolUpdate {
            finish_drain: false,
            workspace: prepared.workspace.clone(),
            pool_id: prepared.pool_id.clone(),
            expected_version: Some(snapshot.resource_version),
            state: snapshot.state,
        })
        .await
        .unwrap()
    );
}

async fn aged_assignments(pool: &SupervisorPool) -> BTreeMap<String, AssignmentRecord> {
    let mut records = pool.all_assignments().await.unwrap();
    for record in records.values_mut() {
        record.updated_at_ms = now_ms() - 25 * 60 * 60 * 1000;
    }
    records
}

#[tokio::test]
async fn retirement_cleanup_waits_for_retention_and_journal_removal() {
    let (fixture, pool, prepared) = dedicated_setup().await;
    pool.retire_preparation(retirement(&prepared))
        .await
        .unwrap();
    let aged = aged_assignments(&pool).await;
    pool.remove_retired_assignments(&aged).await;
    assert!(
        pool.assignment(&prepared.registration.route)
            .await
            .unwrap()
            .is_some()
    );
    remove_preparation_intent(&pool, &prepared).await;
    pool.reconcile_once().await.unwrap();
    assert!(
        pool.assignment(&prepared.registration.route)
            .await
            .unwrap()
            .is_some()
    );
    pool.remove_retired_assignments(&aged).await;
    assert!(
        pool.assignment(&prepared.registration.route)
            .await
            .unwrap()
            .is_none()
    );
    let mut recovered = fixture.replica("restarted");
    Arc::get_mut(&mut recovered).unwrap().dedicated = true;
    assert!(recovered.prepare_runtime(prepared.clone()).await.is_err());
    assert!(
        recovered
            .activate_runtime(activation(&prepared, "sandbox-a"))
            .await
            .is_err()
    );
    assert!(
        recovered
            .assignment(&prepared.registration.route)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn retirement_cleanup_fences_preparation_paused_before_reservation() {
    for dedicated in [false, true] {
        retirement_cleanup_race(&Fixture::new().await, dedicated).await;
    }
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL database; run mise run test:rust:postgres"]
async fn postgres_retirement_cleanup_fences_preparation_paused_before_reservation() {
    let schema = crate::persistence::test_postgres::TestSchema::create("retirement_cleanup").await;
    for dedicated in [false, true] {
        retirement_cleanup_race(
            &Fixture::with_store(schema.connect_store().await),
            dedicated,
        )
        .await;
    }
    schema.drop_schema().await;
}

async fn retirement_cleanup_race(fixture: &Fixture, dedicated: bool) {
    fixture.member("m1", "p1", false).await;
    let mut pool = fixture.replica("preparer");
    Arc::get_mut(&mut pool).unwrap().dedicated = dedicated;
    let mut prepared = preparation(fixture, "").await;
    prepared
        .registration
        .runtime_descriptor
        .resource_claims
        .insert(
            "kubernetes.supervisor_pod_uid".into(),
            "supervisor-pod".into(),
        );
    let (reached, wait) = tokio::sync::oneshot::channel();
    let (resume, resumed) = tokio::sync::oneshot::channel();
    *lock(&pool.hooks.preparation_gate) = Some((reached, resumed));
    let worker = pool.clone();
    let request = prepared.clone();
    let task = tokio::spawn(async move { worker.prepare_runtime(request).await });
    tokio::time::timeout(Duration::from_secs(5), wait)
        .await
        .unwrap()
        .unwrap();
    pool.retire_preparation(retirement(&prepared))
        .await
        .unwrap();
    remove_preparation_intent(&pool, &prepared).await;
    pool.remove_retired_assignments(&aged_assignments(&pool).await)
        .await;
    assert!(
        pool.assignment(&prepared.registration.route)
            .await
            .unwrap()
            .is_none()
    );
    resume.send(()).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert!(
        pool.assignment(&prepared.registration.route)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(fixture.candidates().await, 0);
}

#[tokio::test]
async fn retirement_cleanup_preserves_changed_rows_and_fails_closed_on_invalid_journals() {
    let (_fixture, pool, prepared) = dedicated_setup().await;
    pool.retire_preparation(retirement(&prepared))
        .await
        .unwrap();
    remove_preparation_intent(&pool, &prepared).await;
    let aged = aged_assignments(&pool).await;
    let record = &aged[&prepared.registration.route];
    let journal_id = serde_json::to_string(&(&prepared.workspace, &prepared.pool_id)).unwrap();
    let journal = pool
        .store
        .get("warm_pool_journal", &journal_id)
        .await
        .unwrap()
        .unwrap();
    pool.store
        .put_if(
            "warm_pool_journal",
            &journal.id,
            &journal.name,
            &journal.workspace,
            b"invalid",
            None,
            WriteCondition::Unconditional,
        )
        .await
        .unwrap();
    pool.remove_retired_assignments(&aged).await;
    assert!(
        pool.assignment(&prepared.registration.route)
            .await
            .unwrap()
            .is_some()
    );
    pool.store
        .put_if(
            "warm_pool_journal",
            &journal.id,
            &journal.name,
            &journal.workspace,
            &journal.payload,
            None,
            WriteCondition::Unconditional,
        )
        .await
        .unwrap();
    // An old collector must not delete a row changed by another replica.
    pool.store
        .put_if(
            ASSIGNMENT_OBJECT_TYPE,
            &assignment_object_id(&record.payload.route, &record.payload.writer),
            &record.payload.route,
            "",
            &serde_json::to_vec(&record.payload).unwrap(),
            None,
            WriteCondition::MatchResourceVersion(record.resource_version),
        )
        .await
        .unwrap();
    pool.remove_retired_assignments(&aged).await;
    assert!(
        pool.assignment(&prepared.registration.route)
            .await
            .unwrap()
            .is_some()
    );
    pool.remove_retired_assignments(&aged_assignments(&pool).await)
        .await;
    assert!(
        pool.assignment(&prepared.registration.route)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn retirement_cleanup_is_bounded_and_preserves_active_assignments() {
    let (fixture, pool, prepared) = dedicated_setup().await;
    let mut request = retirement(&prepared);
    for _ in 0..=CLEANUP_PER_PASS {
        request.route = format!("rt-{}", openshell_core::SandboxSessionId::new());
        pool.retire_preparation(request.clone()).await.unwrap();
    }
    pool.remove_retired_assignments(&aged_assignments(&pool).await)
        .await;
    let records = pool.all_assignments().await.unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records[&prepared.registration.route].payload.phase,
        RecordPhase::Published
    );
    pool.remove_retired_assignments(&aged_assignments(&pool).await)
        .await;
    assert_eq!(pool.all_assignments().await.unwrap().len(), 1);
    assert_eq!(fixture.candidates().await, 0);
}
