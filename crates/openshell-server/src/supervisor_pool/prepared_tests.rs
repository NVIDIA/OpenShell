// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::tests::Fixture;
use super::*;
use openshell_core::jwt::CredentialEpoch;
use openshell_supervisor_control::{PreparedRuntimeRegistration, SandboxInstanceRegistration};

fn preparation(route: &str) -> PreparationRequest {
    let session = openshell_core::SandboxSessionId::new();
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
    PreparationRequest {
        registration,
        workspace: "default".into(),
        auth_epoch: CredentialEpoch::new(1).unwrap(),
    }
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
        assignment: registration.to_assignment().unwrap(),
        expected_generation: openshell_core::sandbox_generation::SandboxGenerationId::parse(
            "generation-1",
        )
        .unwrap(),
        expected_auth_epoch: CredentialEpoch::new(1).unwrap(),
    }
}

async fn setup() -> (Fixture, Arc<SupervisorPool>, PreparationRequest) {
    let fixture = Fixture::new().await;
    fixture.member("m1", "p1", false).await;
    fixture
        .sandbox("sandbox-a", "generation-1", SandboxPhase::Provisioning)
        .await;
    let pool = fixture.replica("gateway-a");
    let prepared = preparation("rt-prepared-0123456789");
    pool.prepare_runtime(prepared.clone()).await.unwrap();
    (fixture, pool, prepared)
}

async fn inventory(pool: &SupervisorPool) -> PreparedRuntime {
    let mut runtimes = pool.prepared_runtimes("default").await.unwrap();
    assert_eq!(runtimes.len(), 1);
    runtimes.pop().unwrap()
}

#[tokio::test]
async fn preparation_inventory_is_scoped_durable_and_excludes_unadmitted_and_claimed_runtimes() {
    let (fixture, pool, prepared) = setup().await;
    let before = inventory(&pool).await;
    let mut other = preparation("rt-other-workspace-0123456789");
    other.workspace = "another-workspace".into();
    pool.prepare_runtime(other.clone()).await.unwrap();
    let pending = preparation("rt-unadmitted-0123456789");
    pool.record_assignment_scoped(
        &pending.registration.to_assignment().unwrap(),
        RecordPhase::Admitting,
        Some(("default", 1)),
    )
    .await
    .unwrap();

    // A replica needs no locally published state to recover the inventory.
    let recovered = fixture.replica("gateway-restarted");
    let after = inventory(&recovered).await;
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
    assert!(recovered.prepared_runtimes("").await.is_err());
    assert!(
        recovered
            .prepared_runtimes("missing")
            .await
            .unwrap()
            .is_empty()
    );
    let scoped = recovered.prepared_runtimes(&other.workspace).await.unwrap();
    assert_eq!(scoped.len(), 1);
    assert_eq!(scoped[0].registration, other.registration);
    recovered
        .activate_runtime(activation(&prepared, "sandbox-a"))
        .await
        .unwrap();
    assert!(
        recovered
            .prepared_runtimes("default")
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn preparation_inventory_reports_the_original_process_availability() {
    let (fixture, pool, _prepared) = setup().await;
    fixture.member("m1", "p1", true).await;
    assert!(!inventory(&pool).await.owner.unwrap().available);
    fixture.remove_member("m1").await;
    assert!(!inventory(&pool).await.owner.unwrap().available);
    fixture.member("m1", "replacement", false).await;
    let owner = inventory(&pool).await.owner.unwrap();
    assert_eq!(owner.process_id, "p1");
    assert!(!owner.available);
    fixture.member("m1", "p1", false).await;
    assert!(inventory(&pool).await.owner.unwrap().available);
}

#[tokio::test]
async fn unreadable_preparation_material_fails_inventory_without_affecting_other_workspaces() {
    let (_fixture, pool, prepared) = setup().await;
    let record = pool
        .assignment(&prepared.registration.route)
        .await
        .unwrap()
        .unwrap();
    let handle = CredentialHandle::decode(record.payload.material_handle.as_slice()).unwrap();
    pool.delete_material(&record.payload, handle).await.unwrap();
    assert!(pool.prepared_runtimes("default").await.is_err());
    assert!(
        pool.prepared_runtimes("another-workspace")
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
        .prepared_runtimes("default")
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
    assert!(pool.prepared_runtimes("default").await.unwrap().is_empty());
    pool.reconcile_once().await.unwrap();
    assert!(fixture.owner(&prepared.registration.route).await.is_none());
    assert!(pool.capacity("m1").await.unwrap().payload.routes.is_empty());
    assert_eq!(fixture.candidates().await, 0);
}

#[tokio::test]
async fn malformed_preparation_is_neither_an_empty_inventory_nor_an_absent_route() {
    let (_fixture, pool, _prepared) = setup().await;
    let observed = inventory(&pool).await;
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
    assert!(pool.prepared_runtimes("default").await.is_err());
    assert!(pool.release_preparation(revision).await.is_err());
    assert!(pool.controller.pool_withdrawals().is_empty());
}

#[tokio::test]
async fn preparation_release_rejects_wrong_workspace_and_prevents_route_reuse() {
    let (fixture, pool, prepared) = setup().await;
    let observed = inventory(&pool).await;
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
    let replacement = preparation(&prepared.registration.route);
    assert!(pool.prepare_runtime(replacement).await.is_err());
    assert!(pool.prepare_runtime(prepared.clone()).await.is_err());
    assert_eq!(
        pool.release_preparation(observed.revision).await.unwrap(),
        PreparationRelease::Released
    );
    pool.reconcile_once().await.unwrap();
    assert!(pool.prepared_runtimes("default").await.unwrap().is_empty());
    assert!(fixture.owner(&prepared.registration.route).await.is_none());
}

#[tokio::test]
async fn conditional_release_preserves_a_winning_claim_and_its_credentials() {
    let (fixture, pool, prepared) = setup().await;
    let observed = inventory(&pool).await;
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
    let observed = inventory(&pool).await;
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
    let second = preparation("rt-second-0123456789");
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
    let overflow = preparation("rt-overflow-0123456789");
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
    let prepared = preparation("rt-never-admitted-0123456789");
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
            .prepared_runtimes("default")
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
    let prepared = preparation("rt-staging-0123456789");
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
    let pending = preparation("rt-admitting-0123456789");
    pool.record_assignment_scoped(
        &pending.registration.to_assignment().unwrap(),
        RecordPhase::Admitting,
        Some(("default", 1)),
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
    let mut request = preparation("rt-dedicated-0123456789");
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
        inventory(&pool).await.owner.unwrap().process_id,
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
    let revision = inventory(&pool).await.revision;
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
    assert_eq!(inventory(&pool).await.registration, prepared.registration);
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
    let changed = pool.claim_changed.notified();
    tokio::pin!(changed);
    changed.as_mut().enable();
    let canonical = pool
        .activate_runtime(activation(&prepared, "sandbox-a"))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), changed)
        .await
        .unwrap();
    assert_eq!(
        pool.dedicated_registration(&identity)
            .await
            .unwrap()
            .unwrap(),
        canonical.launch_material
    );
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
    pool.release_preparation(inventory(&pool).await.revision)
        .await
        .unwrap();
    assert!(pool.dedicated_registration(&identity).await.is_err());
}
