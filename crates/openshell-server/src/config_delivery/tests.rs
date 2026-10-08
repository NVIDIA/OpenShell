// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use openshell_core::proto::{
    ConfigApplyOutcome, ConfigPartIdentity, ConfigPartResult, ConfigUpdate, ConfigUpdateResult,
    ConfigurationAdmissionState, GatewayMessage, GetSandboxConfigResponse,
    GetSandboxProviderEnvironmentResponse, Sandbox, SandboxConfigurationAdmission, SandboxPhase,
    SandboxSpec, SandboxStatus, gateway_message,
};
use tokio::time::timeout;

use super::scheduler::{BuildPermit, BuildScheduler};
use super::session::{BuiltPart, PartEffect, ResultRejection, SessionDelivery};
use super::*;
use crate::gateway_metrics::ConfigPart;
use crate::grpc::test_support::test_server_state;
use crate::persistence::ObjectId as _;

const ACK: Duration = Duration::from_mins(1);

fn config(version: u32, provider_env_revision: u64) -> BuiltPart<GetSandboxConfigResponse> {
    BuiltPart::sandbox_config(GetSandboxConfigResponse {
        version,
        policy_hash: format!("hash-{version}"),
        config_revision: u64::from(version) * 10,
        provider_env_revision,
        configuration_admitted: true,
        ..Default::default()
    })
}

fn provider(revision: u64, policy_hash: &str) -> BuiltPart<GetSandboxProviderEnvironmentResponse> {
    BuiltPart::provider_environment(GetSandboxProviderEnvironmentResponse {
        provider_env_revision: revision,
        policy_hash: policy_hash.to_string(),
        environment: HashMap::from([("TOKEN".to_string(), format!("secret-{revision}"))]),
        ..Default::default()
    })
}

fn answer(outcome: ConfigApplyOutcome, identity: &ConfigPartIdentity) -> ConfigPartResult {
    ConfigPartResult {
        outcome: outcome.into(),
        identity: Some(identity.clone()),
        error: String::new(),
    }
}

fn config_result(
    delivery_id: u64,
    outcome: ConfigApplyOutcome,
    identity: &ConfigPartIdentity,
) -> ConfigUpdateResult {
    ConfigUpdateResult {
        delivery_id,
        sandbox_config: Some(answer(outcome, identity)),
        ..Default::default()
    }
}

/// A session whose initial snapshot has been sent and acknowledged.
fn started_session(now: Instant) -> SessionDelivery {
    let mut session = SessionDelivery::default();
    let initial = config(1, 0);
    let identity = initial.identity.clone();
    assert!(session.sandbox_config.offer(initial));
    let update = session.next_update(now).expect("initial update");
    assert!(update.initial);
    let answered = session.answer(&config_result(
        update.delivery_id,
        ConfigApplyOutcome::Applied,
        &identity,
    ));
    assert_eq!(
        answered.sandbox_config.unwrap().unwrap().effect,
        PartEffect::Acknowledged
    );
    session
}

#[test]
fn initial_update_waits_for_the_policy_part_and_carries_both_parts() {
    let now = Instant::now();
    let mut session = SessionDelivery::default();
    assert!(session.provider_environment.offer(provider(0, "hash-1")));
    assert!(
        session.next_update(now).is_none(),
        "the initial snapshot needs the policy part"
    );
    assert!(session.sandbox_config.offer(config(1, 0)));
    let update = session.next_update(now).expect("initial update");
    assert!(update.initial);
    assert_eq!(update.delivery_id, 1);
    assert!(update.sandbox_config.is_some());
    assert!(update.provider_environment.is_some());
    assert!(session.next_update(now).is_none());
}

#[test]
fn unchanged_parts_are_not_sent_again() {
    let now = Instant::now();
    let mut session = started_session(now);
    assert!(
        !session.sandbox_config.offer(config(1, 0)),
        "the supervisor already has this part"
    );
    assert!(session.next_update(now).is_none());
}

#[test]
fn newer_updates_wait_for_the_answer_and_only_the_latest_is_sent() {
    let now = Instant::now();
    let mut session = started_session(now);
    assert!(session.sandbox_config.offer(config(2, 0)));
    let update = session.next_update(now).unwrap();
    let in_flight = update.sandbox_config.unwrap();
    assert_eq!(in_flight.version, 2);

    assert!(session.sandbox_config.offer(config(3, 0)));
    assert!(session.sandbox_config.offer(config(4, 0)));
    assert!(
        session.next_update(now).is_none(),
        "one update per part may be unanswered"
    );
    // A build equal to the queued one is a duplicate.
    assert!(!session.sandbox_config.offer(config(4, 0)));

    let identity = config(2, 0).identity;
    session.answer(&config_result(
        update.delivery_id,
        ConfigApplyOutcome::Applied,
        &identity,
    ));
    let next = session.next_update(now).unwrap();
    assert_eq!(
        next.sandbox_config.unwrap().version,
        4,
        "older queued builds are replaced"
    );
}

#[test]
fn results_must_match_the_update_they_answer() {
    let now = Instant::now();
    let mut session = started_session(now);
    assert!(session.sandbox_config.offer(config(2, 0)));
    let update = session.next_update(now).unwrap();
    let identity = config(2, 0).identity;

    let wrong_delivery = session.answer(&config_result(
        update.delivery_id + 1,
        ConfigApplyOutcome::Applied,
        &identity,
    ));
    assert_eq!(
        wrong_delivery.sandbox_config.unwrap().unwrap_err(),
        ResultRejection::UnknownDelivery
    );
    let wrong_identity = session.answer(&config_result(
        update.delivery_id,
        ConfigApplyOutcome::Applied,
        &config(3, 0).identity,
    ));
    assert_eq!(
        wrong_identity.sandbox_config.unwrap().unwrap_err(),
        ResultRejection::IdentityMismatch
    );
    let unspecified = session.answer(&config_result(
        update.delivery_id,
        ConfigApplyOutcome::Unspecified,
        &identity,
    ));
    assert_eq!(
        unspecified.sandbox_config.unwrap().unwrap_err(),
        ResultRejection::InvalidOutcome
    );
    let valid = session.answer(&config_result(
        update.delivery_id,
        ConfigApplyOutcome::Applied,
        &identity,
    ));
    assert!(valid.sandbox_config.unwrap().is_ok());
}

#[test]
fn rejected_configuration_can_never_be_reported_as_accepted() {
    let now = Instant::now();
    let mut session = started_session(now);
    let mut rejected = config(2, 0);
    rejected.message.configuration_admitted = false;
    let rejected = BuiltPart::sandbox_config(rejected.message);
    let identity = rejected.identity.clone();
    assert!(session.sandbox_config.offer(rejected));
    let update = session.next_update(now).unwrap();
    for outcome in [
        ConfigApplyOutcome::Applied,
        ConfigApplyOutcome::IgnoredDuplicate,
        ConfigApplyOutcome::Degraded,
    ] {
        let answered = session.answer(&config_result(update.delivery_id, outcome, &identity));
        assert_eq!(
            answered.sandbox_config.unwrap().unwrap_err(),
            ResultRejection::NotAdmitted
        );
    }
    let answered = session.answer(&config_result(
        update.delivery_id,
        ConfigApplyOutcome::FailedClosed,
        &identity,
    ));
    assert_eq!(
        answered.sandbox_config.unwrap().unwrap().effect,
        PartEffect::Acknowledged
    );
}

#[test]
fn a_lost_answer_expires_and_the_part_is_sent_again() {
    let now = Instant::now();
    let mut session = started_session(now);
    assert!(session.sandbox_config.offer(config(2, 0)));
    let first = session.next_update(now).unwrap();
    assert_eq!(session.next_expiry(ACK), Some(now + ACK));
    assert!(session.expire(now + ACK / 2, ACK).is_empty());
    assert_eq!(
        session.expire(now + ACK, ACK),
        vec![ConfigPart::SandboxConfig]
    );

    // The rebuild equals the lost update, which the supervisor never
    // acknowledged, so it is sent again under a new delivery id.
    assert!(session.sandbox_config.offer(config(2, 0)));
    let again = session.next_update(now + ACK).unwrap();
    assert!(again.delivery_id > first.delivery_id);
    // A late answer to the expired update is rejected.
    let late = session.answer(&config_result(
        first.delivery_id,
        ConfigApplyOutcome::Applied,
        &config(2, 0).identity,
    ));
    assert_eq!(
        late.sandbox_config.unwrap().unwrap_err(),
        ResultRejection::UnknownDelivery
    );
}

#[test]
fn a_held_part_is_completed_by_a_later_update() {
    let now = Instant::now();
    let mut session = started_session(now);
    let needs_provider = config(2, 7);
    let config_identity = needs_provider.identity.clone();
    assert!(session.sandbox_config.offer(needs_provider));
    let update = session.next_update(now).unwrap();
    let held = session.answer(&config_result(
        update.delivery_id,
        ConfigApplyOutcome::AwaitingComponent,
        &config_identity,
    ));
    assert_eq!(
        held.sandbox_config.unwrap().unwrap().effect,
        PartEffect::AwaitingOther
    );
    // The supervisor holds it, so an identical rebuild is not resent.
    assert!(!session.sandbox_config.offer(config(2, 7)));

    let environment = provider(7, "hash-2");
    let provider_identity = environment.identity.clone();
    assert!(session.provider_environment.offer(environment));
    let provider_update = session.next_update(now).unwrap();
    assert!(provider_update.sandbox_config.is_none());

    let completed = session.answer(&ConfigUpdateResult {
        delivery_id: provider_update.delivery_id,
        sandbox_config: Some(answer(ConfigApplyOutcome::Applied, &config_identity)),
        provider_environment: Some(answer(ConfigApplyOutcome::Applied, &provider_identity)),
        ..Default::default()
    });
    assert_eq!(
        completed.sandbox_config.unwrap().unwrap().effect,
        PartEffect::Acknowledged
    );
    assert_eq!(
        completed.provider_environment.unwrap().unwrap().effect,
        PartEffect::Acknowledged
    );
}

#[test]
fn awaiting_twice_for_the_same_held_part_is_rejected() {
    let now = Instant::now();
    let mut session = started_session(now);
    let needs_provider = config(2, 7);
    let identity = needs_provider.identity.clone();
    assert!(session.sandbox_config.offer(needs_provider));
    let update = session.next_update(now).unwrap();
    session.answer(&config_result(
        update.delivery_id,
        ConfigApplyOutcome::AwaitingComponent,
        &identity,
    ));
    assert!(session.provider_environment.offer(provider(7, "hash-1")));
    let later = session.next_update(now).unwrap();
    let repeated = session.answer(&config_result(
        later.delivery_id,
        ConfigApplyOutcome::AwaitingComponent,
        &identity,
    ));
    assert_eq!(
        repeated.sandbox_config.unwrap().unwrap_err(),
        ResultRejection::InvalidOutcome,
        "a held part can only be completed, which bounds the rebuilds it causes"
    );
}

#[test]
fn provider_environment_is_built_only_when_its_identity_moves() {
    let now = Instant::now();
    let mut session = SessionDelivery::default();
    let first = config(1, 0);
    assert!(session.needs_provider_environment(&first));
    session.sandbox_config.offer(first);
    session.provider_environment.offer(provider(0, "hash-1"));
    session.next_update(now).unwrap();

    assert!(!session.needs_provider_environment(&config(1, 0)));
    assert!(
        session.needs_provider_environment(&config(2, 0)),
        "a new policy hash changes the credential bindings"
    );
    assert!(session.needs_provider_environment(&config(1, 5)));
    let mut rejected = config(2, 0).message;
    rejected.configuration_admitted = false;
    assert!(
        !session.needs_provider_environment(&BuiltPart::sandbox_config(rejected)),
        "a rejected policy part is never paired with credentials"
    );
}

#[test]
fn forced_provider_environment_is_resent_even_when_acknowledged() {
    let now = Instant::now();
    let mut session = SessionDelivery::default();
    let environment = provider(0, "hash-1");
    let identity = environment.identity.clone();
    session.sandbox_config.offer(config(1, 0));
    session.provider_environment.offer(environment);
    let update = session.next_update(now).unwrap();
    session.answer(&ConfigUpdateResult {
        delivery_id: update.delivery_id,
        provider_environment: Some(answer(ConfigApplyOutcome::Applied, &identity)),
        ..Default::default()
    });
    assert!(!session.provider_environment.offer(provider(0, "hash-1")));
    assert!(
        session
            .provider_environment
            .offer_forced(provider(0, "hash-1"))
    );
    assert!(
        !session
            .provider_environment
            .offer_forced(provider(0, "hash-1"))
    );
}

#[test]
fn fingerprints_ignore_map_order_and_cover_credential_values() {
    let mut first = GetSandboxProviderEnvironmentResponse::default();
    let mut second = GetSandboxProviderEnvironmentResponse::default();
    for index in 0..32 {
        first
            .environment
            .insert(format!("KEY_{index}"), format!("value-{index}"));
    }
    for index in (0..32).rev() {
        second
            .environment
            .insert(format!("KEY_{index}"), format!("value-{index}"));
    }
    first.non_secret_environment_keys = vec!["A".into(), "B".into()];
    second.non_secret_environment_keys = vec!["B".into(), "A".into()];
    assert_eq!(
        BuiltPart::provider_environment(first.clone()).fingerprint,
        BuiltPart::provider_environment(second).fingerprint
    );
    let mut rotated = first.clone();
    rotated.environment.insert("KEY_0".into(), "rotated".into());
    assert_ne!(
        BuiltPart::provider_environment(first).fingerprint,
        BuiltPart::provider_environment(rotated).fingerprint
    );
}

// ---------------------------------------------------------------------------
// Delivery tasks against a real gateway state
// ---------------------------------------------------------------------------

const INSTANCE_ID: &str = "00000000-0000-4000-8000-000000000002";

async fn push_state() -> Arc<ServerState> {
    push_state_checking_every(Duration::from_hours(1)).await
}

async fn push_state_checking_every(interval: Duration) -> Arc<ServerState> {
    let mut state = test_server_state().await;
    Arc::get_mut(&mut state)
        .expect("fresh test state")
        .config_delivery = Some(Arc::new(ConfigDelivery::new(
        interval,
        BuildScheduler::for_pool(state.store.pool_size()),
    )));
    state
}

/// Successful pushed builds of `part` recorded in `rendered` metrics.
fn push_builds(rendered: &str, part: ConfigPart) -> u64 {
    rendered
        .lines()
        .filter(|line| {
            line.starts_with("openshell_server_config_build_duration_seconds_count{")
                && line.contains(&format!("part=\"{}\"", part.label()))
                && line.contains("trigger=\"push\"")
                && line.contains("outcome=\"ok\"")
        })
        .filter_map(|line| line.rsplit(' ').next()?.parse::<u64>().ok())
        .sum()
}

async fn put_policy_version(state: &ServerState, sandbox_id: &str, version: u32) {
    use crate::policy_store::PolicyStoreExt as _;
    use prost::Message as _;
    let mut policy = openshell_policy::restrictive_default_policy();
    policy
        .filesystem
        .get_or_insert_with(Default::default)
        .read_only
        .push(format!("/opt/v{version}"));
    state
        .store
        .put_policy_revision(
            &format!("{sandbox_id}-rev-{version}"),
            sandbox_id,
            "default",
            i64::from(version),
            &policy.encode_to_vec(),
            &openshell_core::policy_identity::deterministic_policy_hash(&policy),
        )
        .await
        .unwrap();
}

async fn store_sandbox(state: &ServerState, id: &str) -> Sandbox {
    let mut sandbox = Sandbox {
        metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
            id: id.to_string(),
            name: format!("{id}-name"),
            workspace: "default".to_string(),
            ..Default::default()
        }),
        spec: Some(SandboxSpec {
            policy: Some(openshell_policy::restrictive_default_policy()),
            provider_attachment_epoch: "epoch-1".to_string(),
            ..Default::default()
        }),
        status: Some(SandboxStatus {
            configuration_admission: Some(SandboxConfigurationAdmission {
                instance_id: INSTANCE_ID.to_string(),
                state: ConfigurationAdmissionState::Pending.into(),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    sandbox.set_phase(SandboxPhase::Provisioning as i32);
    state.store.put_message(&sandbox).await.unwrap();
    sandbox
}

fn delivery(state: &ServerState) -> &Arc<ConfigDelivery> {
    state.config_delivery.as_ref().unwrap()
}

fn register(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    session_id: &str,
) -> mpsc::Receiver<GatewayMessage> {
    let (tx, rx) = mpsc::channel(2);
    delivery(state).register(state.clone(), sandbox_id, session_id, tx);
    rx
}

async fn next_update(rx: &mut mpsc::Receiver<GatewayMessage>) -> ConfigUpdate {
    let message = timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("configuration update timed out")
        .expect("session outbound closed");
    match message.payload {
        Some(gateway_message::Payload::ConfigUpdate(update)) => update,
        other => panic!("unexpected message {other:?}"),
    }
}

async fn assert_quiet(rx: &mut mpsc::Receiver<GatewayMessage>) {
    assert!(
        timeout(Duration::from_millis(300), rx.recv())
            .await
            .is_err(),
        "no configuration update was expected"
    );
}

fn acknowledge(update: &ConfigUpdate, outcome: ConfigApplyOutcome) -> ConfigUpdateResult {
    ConfigUpdateResult {
        delivery_id: update.delivery_id,
        configuration_instance_id: INSTANCE_ID.to_string(),
        sandbox_config: update
            .sandbox_config
            .as_ref()
            .map(|part| answer(outcome, &BuiltPart::sandbox_config(part.clone()).identity)),
        provider_environment: update.provider_environment.as_ref().map(|part| {
            answer(
                outcome,
                &BuiltPart::provider_environment(part.clone()).identity,
            )
        }),
    }
}

#[tokio::test]
async fn poll_mode_publishing_keeps_no_state() {
    let state = test_server_state().await;
    assert!(state.config_delivery.is_none());
    publish(&state, Scope::All);
    publish(&state, Scope::Sandbox("anything".into()));
    assert!(!negotiate(
        &state,
        &SupervisorHello {
            supports_config_push: true,
            ..Default::default()
        }
    ));
}

#[tokio::test]
async fn initial_snapshot_carries_matching_parts_and_records_admission() {
    let state = push_state().await;
    store_sandbox(&state, "sbx-initial").await;
    let mut rx = register(&state, "sbx-initial", "session-1");

    let update = next_update(&mut rx).await;
    assert!(update.initial);
    let config = update.sandbox_config.clone().expect("policy part");
    let environment = update
        .provider_environment
        .clone()
        .expect("provider environment part");
    assert!(config.configuration_admitted);
    assert_eq!(
        config.provider_env_revision,
        environment.provider_env_revision
    );
    assert_eq!(config.policy_hash, environment.policy_hash);
    assert_eq!(config.provider_attachment_epoch, "epoch-1");
    assert_eq!(environment.provider_attachment_epoch, "epoch-1");

    delivery(&state).deliver_result(
        "sbx-initial",
        "session-1",
        acknowledge(&update, ConfigApplyOutcome::Applied),
    );
    let mut admitted = None;
    for _ in 0..50 {
        let sandbox = state
            .store
            .get_message::<Sandbox>("sbx-initial")
            .await
            .unwrap()
            .unwrap();
        let admission = sandbox.status.unwrap().configuration_admission.unwrap();
        if admission.state == i32::from(ConfigurationAdmissionState::Accepted) {
            admitted = Some(admission);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let admitted = admitted.expect("pushed result records admission");
    assert_eq!(admitted.config_revision, config.config_revision);
    assert_eq!(admitted.policy_hash, config.policy_hash);
}

#[tokio::test]
async fn unchanged_publish_sends_nothing_and_a_change_sends_a_new_snapshot() {
    let state = push_state().await;
    store_sandbox(&state, "sbx-change").await;
    let mut rx = register(&state, "sbx-change", "session-1");
    let initial = next_update(&mut rx).await;
    delivery(&state).deliver_result(
        "sbx-change",
        "session-1",
        acknowledge(&initial, ConfigApplyOutcome::Applied),
    );

    publish(&state, Scope::Sandbox("sbx-change".into()));
    publish(&state, Scope::All);
    assert_quiet(&mut rx).await;

    put_policy_version(&state, "sbx-change", 2).await;
    publish(&state, Scope::Sandbox("sbx-change".into()));

    let update = next_update(&mut rx).await;
    assert!(!update.initial);
    let config = update.sandbox_config.expect("changed policy part");
    assert_eq!(config.version, 2);
    let environment = update
        .provider_environment
        .expect("a new policy hash rebinds the provider environment");
    assert_eq!(environment.policy_hash, config.policy_hash);
}

#[tokio::test]
async fn changes_wait_for_the_initial_answer_and_coalesce() {
    let state = push_state().await;
    store_sandbox(&state, "sbx-coalesce").await;
    let mut rx = register(&state, "sbx-coalesce", "session-1");
    let initial = next_update(&mut rx).await;

    for version in 2..=4 {
        put_policy_version(&state, "sbx-coalesce", version).await;
        publish(&state, Scope::Sandbox("sbx-coalesce".into()));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_quiet(&mut rx).await;

    delivery(&state).deliver_result(
        "sbx-coalesce",
        "session-1",
        acknowledge(&initial, ConfigApplyOutcome::Applied),
    );
    let update = next_update(&mut rx).await;
    assert_eq!(
        update.sandbox_config.unwrap().version,
        4,
        "only the latest change is sent"
    );
    assert_quiet(&mut rx).await;
}

#[tokio::test]
async fn awaiting_policy_part_rebuilds_the_provider_environment_once() {
    let state = push_state().await;
    let mut sandbox = store_sandbox(&state, "sbx-await").await;
    let mut rx = register(&state, "sbx-await", "session-1");
    let initial = next_update(&mut rx).await;
    let environment = initial.provider_environment.clone().unwrap();
    delivery(&state).deliver_result(
        "sbx-await",
        "session-1",
        acknowledge(&initial, ConfigApplyOutcome::Applied),
    );
    tokio::time::sleep(Duration::from_millis(100)).await;

    // A new registration fence changes the policy part but not the identity
    // its provider environment is bound to.
    sandbox = state
        .store
        .get_message::<Sandbox>(sandbox.object_id())
        .await
        .unwrap()
        .unwrap();
    sandbox
        .status
        .as_mut()
        .unwrap()
        .configuration_admission
        .as_mut()
        .unwrap()
        .instance_id = "00000000-0000-4000-8000-000000000003".to_string();
    state.store.put_message(&sandbox).await.unwrap();
    publish(&state, Scope::Sandbox("sbx-await".into()));
    let update = next_update(&mut rx).await;
    assert!(update.sandbox_config.is_some());
    assert!(update.provider_environment.is_none());

    // The supervisor lost its provider environment and asks for it.
    let mut result = acknowledge(&update, ConfigApplyOutcome::AwaitingComponent);
    result.configuration_instance_id.clear();
    delivery(&state).deliver_result("sbx-await", "session-1", result);
    let resent = next_update(&mut rx).await;
    assert!(resent.sandbox_config.is_none());
    assert_eq!(
        resent.provider_environment.unwrap().provider_env_revision,
        environment.provider_env_revision,
        "the acknowledged environment is sent again on request"
    );
    assert_quiet(&mut rx).await;
}

#[tokio::test]
async fn a_replacement_session_gets_its_own_initial_snapshot() {
    let state = push_state().await;
    store_sandbox(&state, "sbx-replace").await;
    let mut first = register(&state, "sbx-replace", "session-1");
    let _ = next_update(&mut first).await;

    let mut second = register(&state, "sbx-replace", "session-2");
    let update = next_update(&mut second).await;
    assert!(update.initial);
    assert_eq!(update.delivery_id, 1);

    publish(&state, Scope::Sandbox("sbx-replace".into()));
    // The first session's task was stopped; its outbound queue is closed.
    assert!(
        timeout(Duration::from_secs(1), first.recv())
            .await
            .expect("closed queue")
            .is_none()
    );
    // Results for the old session are ignored.
    delivery(&state).deliver_result(
        "sbx-replace",
        "session-1",
        acknowledge(&update, ConfigApplyOutcome::Applied),
    );
    delivery(&state).unregister("sbx-replace", "session-1");
    assert!(
        delivery(&state)
            .sessions
            .lock()
            .unwrap()
            .contains_key("sbx-replace"),
        "unregistering the old session leaves the new one"
    );
}

#[tokio::test]
async fn publication_reaches_only_the_sessions_in_scope() {
    let state = push_state().await;
    store_sandbox(&state, "sbx-scope-a").await;
    store_sandbox(&state, "sbx-scope-b").await;
    let mut a = register(&state, "sbx-scope-a", "session-a");
    let mut b = register(&state, "sbx-scope-b", "session-b");
    let _ = next_update(&mut a).await;
    let _ = next_update(&mut b).await;

    let entries = delivery(&state).sessions.lock().unwrap().clone();
    let entry_a = entries.get("sbx-scope-a").unwrap();
    let entry_b = entries.get("sbx-scope-b").unwrap();
    assert!(entry_a.covers(&Scope::Workspace("default".into())));
    assert!(!entry_a.covers(&Scope::Workspace("other".into())));
    assert!(!entry_a.covers(&Scope::Provider("provider-1".into())));
    entry_b.record_coverage("default".into(), Some(vec!["provider-1".into()]));
    assert!(!entry_b.covers(&Scope::Provider("provider-2".into())));
    assert!(entry_b.covers(&Scope::Provider("provider-1".into())));
    assert!(entry_a.covers(&Scope::All));
    assert!(!entry_a.covers(&Scope::Sandbox("sbx-scope-b".into())));
}

#[tokio::test]
async fn control_messages_are_sent_before_configuration() {
    use tokio_stream::StreamExt as _;
    let (control_tx, control_rx) = mpsc::channel(4);
    let (config_tx, config_rx) = mpsc::channel(2);
    config_tx
        .try_send(GatewayMessage {
            payload: Some(gateway_message::Payload::ConfigUpdate(
                ConfigUpdate::default(),
            )),
        })
        .unwrap();
    control_tx
        .try_send(GatewayMessage {
            payload: Some(gateway_message::Payload::Heartbeat(
                openshell_core::proto::GatewayHeartbeat {},
            )),
        })
        .unwrap();
    let mut stream =
        crate::supervisor_session::session_outbound_stream(control_rx, Some(config_rx));
    let first = stream.next().await.unwrap().unwrap();
    assert!(matches!(
        first.payload,
        Some(gateway_message::Payload::Heartbeat(_))
    ));
    let second = stream.next().await.unwrap().unwrap();
    assert!(matches!(
        second.payload,
        Some(gateway_message::Payload::ConfigUpdate(_))
    ));
}

#[tokio::test]
async fn consistency_checks_send_nothing_when_unchanged_and_repair_missed_changes() {
    let metrics = crate::gateway_metrics::MetricsCapture::install();
    let state = push_state_checking_every(Duration::from_millis(100)).await;
    store_sandbox(&state, "sbx-check").await;
    let mut rx = register(&state, "sbx-check", "session-1");
    let initial = next_update(&mut rx).await;
    delivery(&state).deliver_result(
        "sbx-check",
        "session-1",
        acknowledge(&initial, ConfigApplyOutcome::Applied),
    );
    let provider_builds = push_builds(&metrics.render(), ConfigPart::ProviderEnvironment);
    let config_builds = push_builds(&metrics.render(), ConfigPart::SandboxConfig);
    assert_eq!(provider_builds, 1);

    assert_quiet(&mut rx).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let rendered = metrics.render();
    assert!(
        push_builds(&rendered, ConfigPart::SandboxConfig) > config_builds,
        "checks rebuilt the policy part"
    );
    assert_eq!(
        push_builds(&rendered, ConfigPart::ProviderEnvironment),
        provider_builds,
        "an unchanged check calls no credential backend"
    );

    // A change committed without publishing is repaired by the next check,
    // with exactly one provider environment build for the moved identity.
    put_policy_version(&state, "sbx-check", 2).await;
    let repaired = next_update(&mut rx).await;
    assert_eq!(repaired.sandbox_config.as_ref().unwrap().version, 2);
    assert!(repaired.provider_environment.is_some());
    delivery(&state).deliver_result(
        "sbx-check",
        "session-1",
        acknowledge(&repaired, ConfigApplyOutcome::Applied),
    );
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_quiet(&mut rx).await;
    assert_eq!(
        push_builds(&metrics.render(), ConfigPart::ProviderEnvironment),
        provider_builds + 1
    );
}

// ---------------------------------------------------------------------------
// Build scheduling
// ---------------------------------------------------------------------------

use futures::FutureExt as _;

fn waiting_acquire(
    scheduler: &Arc<BuildScheduler>,
    lane: BuildLane,
    workspace: &str,
) -> tokio::task::JoinHandle<BuildPermit> {
    let scheduler = scheduler.clone();
    let workspace = workspace.to_string();
    tokio::spawn(async move { scheduler.acquire(lane, &workspace).await })
}

async fn settle() {
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn sandbox_scoped_builds_are_never_starved_by_fleet_wide_ones() {
    let scheduler = BuildScheduler::new(1, 2);
    let fanout_a = scheduler.acquire(BuildLane::Fanout, "ws").await;
    let _fanout_b = scheduler.acquire(BuildLane::Fanout, "ws").await;
    let queued_fanout = waiting_acquire(&scheduler, BuildLane::Fanout, "ws");
    settle().await;
    assert_eq!(scheduler.waiting(), 1);

    // The reserve serves a sandbox-scoped build while fanout saturates the
    // shared capacity.
    let sandbox = scheduler
        .acquire(BuildLane::Sandbox, "ws")
        .now_or_never()
        .expect("reserved capacity is available");
    // With the reserve busy, a second sandbox-scoped build queues ahead of
    // the fleet-wide one for shared capacity.
    let queued_sandbox = waiting_acquire(&scheduler, BuildLane::Sandbox, "ws");
    settle().await;
    drop(fanout_a);
    settle().await;
    assert!(queued_sandbox.is_finished());
    assert!(!queued_fanout.is_finished());
    drop(sandbox);
    // The reserve never goes to fleet-wide builds.
    settle().await;
    assert!(!queued_fanout.is_finished());
    drop(queued_sandbox.await.unwrap());
    settle().await;
    assert!(queued_fanout.is_finished());
}

#[tokio::test]
async fn fleet_wide_builds_are_shared_fairly_between_workspaces() {
    let scheduler = BuildScheduler::new(1, 1);
    let held = scheduler.acquire(BuildLane::Fanout, "alpha").await;
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut waiters = Vec::new();
    for (index, workspace) in ["alpha", "alpha", "alpha", "alpha", "beta"]
        .into_iter()
        .enumerate()
    {
        let scheduler = scheduler.clone();
        let order = order.clone();
        waiters.push(tokio::spawn(async move {
            let permit = scheduler.acquire(BuildLane::Fanout, workspace).await;
            order.lock().unwrap().push((index, workspace));
            drop(permit);
        }));
        settle().await;
    }
    drop(held);
    for waiter in waiters {
        waiter.await.unwrap();
    }
    let order = order.lock().unwrap().clone();
    let beta = order
        .iter()
        .position(|(_, workspace)| *workspace == "beta")
        .unwrap();
    assert!(
        beta <= 1,
        "beta's single build must not wait behind alpha's whole pass: {order:?}"
    );
}

#[tokio::test]
async fn a_waiter_that_gives_up_does_not_leak_capacity() {
    let scheduler = BuildScheduler::new(1, 1);
    let reserved = scheduler.acquire(BuildLane::Sandbox, "ws").await;
    let shared = scheduler.acquire(BuildLane::Fanout, "ws").await;
    let abandoned = waiting_acquire(&scheduler, BuildLane::Fanout, "ws");
    settle().await;
    abandoned.abort();
    let _ = abandoned.await;
    let next = waiting_acquire(&scheduler, BuildLane::Fanout, "ws");
    settle().await;
    drop(shared);
    settle().await;
    assert!(next.is_finished(), "the permit skips the abandoned waiter");
    drop(next.await.unwrap());
    drop(reserved);
    // All capacity is back.
    let _a = scheduler
        .acquire(BuildLane::Sandbox, "ws")
        .now_or_never()
        .unwrap();
    let _b = scheduler
        .acquire(BuildLane::Fanout, "ws")
        .now_or_never()
        .unwrap();
}

#[tokio::test]
async fn a_fleet_wide_change_keeps_one_pending_build_per_session() {
    let delivery = ConfigDelivery::new(Duration::from_hours(1), BuildScheduler::new(1, 1));
    let entries: Vec<Arc<SessionEntry>> = (0..5000)
        .map(|index| detached_entry(&format!("sbx-{index}")))
        .collect();
    {
        let mut sessions = delivery.sessions.lock().unwrap();
        for entry in &entries {
            sessions.insert(entry.sandbox_id.clone(), entry.clone());
        }
    }
    for _ in 0..100 {
        delivery.publish(&Scope::All);
    }
    delivery.publish(&Scope::Sandbox("sbx-7".into()));
    for entry in &entries {
        let request = entry.take().expect("every session needs one build");
        assert!(entry.take().is_none(), "repeated changes coalesce");
        let expected = if entry.sandbox_id == "sbx-7" {
            BuildLane::Sandbox
        } else {
            BuildLane::Fanout
        };
        assert_eq!(request.lane, expected);
    }
}

async fn store_provider(state: &ServerState, name: &str, token: &str) {
    let provider = openshell_core::proto::Provider {
        metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
            id: format!("provider-{name}"),
            name: name.to_string(),
            workspace: "default".to_string(),
            ..Default::default()
        }),
        r#type: "github".to_string(),
        credentials: HashMap::from([("GITHUB_TOKEN".to_string(), token.to_string())]),
        profile_workspace: "default".to_string(),
        ..Default::default()
    };
    state.store.put_message(&provider).await.unwrap();
}

#[tokio::test]
async fn provider_changes_reach_only_sandboxes_that_attach_the_provider() {
    let state = push_state().await;
    store_provider(&state, "gh", "token-1").await;
    store_sandbox(&state, "sbx-without").await;
    let mut with = store_sandbox(&state, "sbx-with").await;
    with.spec.as_mut().unwrap().providers = vec!["gh".to_string()];
    state.store.put_message(&with).await.unwrap();

    let mut rx_with = register(&state, "sbx-with", "session-with");
    let mut rx_without = register(&state, "sbx-without", "session-without");
    let initial_with = next_update(&mut rx_with).await;
    let initial_without = next_update(&mut rx_without).await;
    for (sandbox, session, update) in [
        ("sbx-with", "session-with", &initial_with),
        ("sbx-without", "session-without", &initial_without),
    ] {
        delivery(&state).deliver_result(
            sandbox,
            session,
            acknowledge(update, ConfigApplyOutcome::Applied),
        );
    }
    let revision = initial_with
        .provider_environment
        .as_ref()
        .unwrap()
        .provider_env_revision;

    // Rotate the credential the way UpdateProvider does, with a new record
    // version.
    state
        .store
        .update_message_cas::<openshell_core::proto::Provider, _>("provider-gh", 0, |provider| {
            provider
                .credentials
                .insert("GITHUB_TOKEN".to_string(), "token-2".to_string());
        })
        .await
        .unwrap();
    publish(&state, Scope::Provider("provider-gh".to_string()));
    let update = next_update(&mut rx_with).await;
    let environment = update
        .provider_environment
        .expect("the attached sandbox gets the rotated environment");
    assert_ne!(environment.provider_env_revision, revision);
    assert_eq!(
        update.sandbox_config.unwrap().provider_env_revision,
        environment.provider_env_revision
    );
    assert_quiet(&mut rx_without).await;
}

#[tokio::test]
async fn failed_builds_retry_with_backoff_until_they_succeed() {
    let state = push_state().await;
    store_sandbox(&state, "sbx-retry").await;
    delivery(&state)
        .injected_build_failures
        .store(2, std::sync::atomic::Ordering::SeqCst);
    let started = Instant::now();
    let mut rx = register(&state, "sbx-retry", "session-1");
    let update = next_update(&mut rx).await;
    assert!(update.initial);
    // Two failures back off one and then two seconds.
    assert!(started.elapsed() >= Duration::from_millis(2900));
    assert_eq!(
        delivery(&state)
            .injected_build_failures
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

fn detached_entry(sandbox_id: &str) -> Arc<SessionEntry> {
    Arc::new(SessionEntry {
        sandbox_id: sandbox_id.to_string(),
        session_id: format!("session-{sandbox_id}"),
        dirty: Mutex::new(Dirty::default()),
        coverage: Mutex::new(Coverage::default()),
        wake: Notify::new(),
        results: mpsc::channel(1).0,
        task: Mutex::new(None),
        _gauge: GaugeSlot::config_push_session(),
    })
}

#[tokio::test]
async fn changes_during_a_build_reach_the_session_whatever_their_scope() {
    let delivery = ConfigDelivery::new(Duration::from_hours(1), BuildScheduler::new(1, 1));
    let entry = detached_entry("sbx-racing");
    delivery
        .sessions
        .lock()
        .unwrap()
        .insert("sbx-racing".into(), entry.clone());

    // Before the first build finishes, the session may depend on anything.
    assert!(entry.covers(&Scope::Provider("p".into())));
    entry.record_coverage("default".into(), Some(Vec::new()));
    assert!(!entry.covers(&Scope::Provider("attached-later".into())));
    assert!(!entry.covers(&Scope::Workspace("other".into())));

    // A build has taken the dirty state and is reading inputs; a provider it
    // will see only after this commit publishes now.
    entry.mark(BuildLane::Fanout, false);
    let _request = entry.take().expect("pending build");
    delivery.publish(&Scope::Provider("attached-later".into()));
    assert!(entry.lane().is_some(), "the change is not lost");
    let _ = entry.take();

    // Invalid stored configuration hides which providers matter.
    entry.record_coverage("default".into(), None);
    assert!(entry.covers(&Scope::Provider("any".into())));
    assert!(!entry.covers(&Scope::Workspace("other".into())));
}
