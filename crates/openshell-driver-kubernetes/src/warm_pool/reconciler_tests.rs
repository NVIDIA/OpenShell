// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

fn pool() -> WarmPoolConfig {
    WarmPoolConfig {
        workspace: "team".into(),
        name: "agents".into(),
        revision: 1,
        target_size: 8,
        max_size: 10,
        max_age_secs: 600,
        preparation_timeout_secs: 120,
        spec: SandboxSpec {
            template: Some(SandboxTemplate {
                image: "test:1".into(),
                ..Default::default()
            }),
            ..Default::default()
        },
    }
}

fn state() -> WarmPoolState {
    WarmPoolState {
        revision: 1,
        fingerprint: "a".repeat(64),
        entries: Vec::new(),
    }
}

fn resource(entry: &WarmPoolEntry) -> WarmRuntimeResource {
    WarmRuntimeResource {
        namespace: "default".into(),
        name: format!("warm-{}", entry.session_id),
        uid: "uid".into(),
        workspace: "team".into(),
        pool_id: "agents".into(),
        session_id: entry.session_id,
        pod_uid: Some("pod".into()),
        released: true,
        retiring: false,
        deleting: false,
        claimed: false,
    }
}

#[test]
fn refill_is_bounded_and_pending_requests_are_not_duplicated() {
    let pool = pool();
    let mut state = state();
    let empty = BTreeSet::new();
    let (actions, report) = plan(&pool, &mut state, &[], &empty, &empty, 1000);
    assert_eq!((actions.len(), report.pending, report.ready), (4, 4, 0));
    let first: Vec<_> = state.entries.iter().map(|entry| entry.session_id).collect();
    let (actions, _) = plan(&pool, &mut state, &[], &empty, &empty, 2000);
    assert_eq!(actions.len(), 4);
    assert_eq!(state.entries.len(), 8);
    assert!(
        actions
            .iter()
            .all(|action| !first.contains(&action.entry.session_id))
    );
    let (actions, _) = plan(&pool, &mut state, &[], &empty, &empty, 3000);
    assert!(actions.is_empty());
    let (actions, _) = plan(&pool, &mut state, &[], &empty, &empty, 32_000);
    assert_eq!(actions.len(), 4);
    assert!(
        actions
            .iter()
            .all(|action| first.contains(&action.entry.session_id))
    );
}

#[test]
fn readiness_requires_connection_and_disconnect_expiry_retires_without_exceeding_cap() {
    let mut pool = pool();
    pool.target_size = 2;
    pool.max_size = 2;
    let mut state = state();
    let empty = BTreeSet::new();
    plan(&pool, &mut state, &[], &empty, &empty, 0);
    let resources: Vec<_> = state.entries.iter().map(resource).collect();
    let ready = BTreeSet::from([state.entries[0].session_id]);
    let (_, report) = plan(&pool, &mut state, &resources, &ready, &empty, 1000);
    assert_eq!((report.ready, report.pending), (1, 1));
    let (_, report) = plan(&pool, &mut state, &resources, &empty, &empty, 62_000);
    assert_eq!((report.ready, report.pending, report.retiring), (0, 1, 1));
    assert_eq!(state.entries.len(), 2);
    let (actions, report) = plan(&pool, &mut state, &resources, &empty, &empty, 121_000);
    assert_eq!(report.retiring, 2);
    assert!(actions.iter().all(|action| action.entry.retiring));
    assert_eq!(state.entries.len(), 2);
}

#[test]
fn drain_claims_host_loss_and_orphans_preserve_physical_accounting() {
    let mut pool = pool();
    pool.target_size = 2;
    pool.max_size = 2;
    let mut state = state();
    let empty = BTreeSet::new();
    plan(&pool, &mut state, &[], &empty, &empty, 0);
    let mut resources: Vec<_> = state.entries.iter().map(resource).collect();
    let lost = BTreeSet::from([state.entries[0].session_id]);
    resources[1].claimed = true;
    plan(&pool, &mut state, &resources, &empty, &lost, 31_000);
    assert_eq!(state.entries.len(), 2);
    assert!(state.entries[0].retiring);
    assert!(
        state
            .entries
            .iter()
            .all(|entry| entry.session_id != resources[1].session_id)
    );
    pool.target_size = 0;
    let (_, report) = plan(&pool, &mut state, &resources, &empty, &empty, 62_000);
    assert_eq!(report.retiring, 2);
    // An untracked late CR consumes the maximum and is cleaned, not adopted.
    let mut state = WarmPoolState {
        entries: Vec::new(),
        ..state
    };
    pool.target_size = 1;
    pool.max_size = 1;
    let (actions, _) = plan(&pool, &mut state, &resources, &empty, &empty, 63_000);
    assert!(state.entries.is_empty());
    assert_eq!(actions.len(), 1);
    assert!(actions[0].entry.retiring);
}

#[test]
fn missing_or_replaced_observed_resources_are_retired_instead_of_recreated() {
    let mut pool = pool();
    pool.target_size = 1;
    pool.max_size = 1;
    let mut state = state();
    let empty = BTreeSet::new();
    plan(&pool, &mut state, &[], &empty, &empty, 0);
    let physical = resource(&state.entries[0]);
    plan(&pool, &mut state, &[physical], &empty, &empty, 1000);
    let mut replaced = state.clone();
    let mut replacement = resource(&replaced.entries[0]);
    replacement.uid = "replacement".into();
    let (actions, _) = plan(&pool, &mut state, &[], &empty, &empty, 31_000);
    assert_eq!(actions.len(), 1);
    assert!(actions[0].entry.retiring);
    let (actions, _) = plan(&pool, &mut replaced, &[replacement], &empty, &empty, 31_000);
    assert_eq!(actions.len(), 1);
    assert!(actions[0].entry.retiring);
}

#[test]
fn warm_pool_configuration_rejects_unsupported_or_unbounded_pools() {
    let valid = pool();
    valid.validate().unwrap();
    let mut invalid = valid.clone();
    invalid.target_size = 11;
    assert!(invalid.validate().is_err());
    invalid = valid.clone();
    invalid.max_size = 257;
    assert!(invalid.validate().is_err());
    invalid = valid;
    invalid.preparation_timeout_secs = 601;
    assert!(invalid.validate().is_err());
    let mut config = KubernetesComputeConfig {
        workspace_mode: WorkspaceMode::Shared,
        ..Default::default()
    };
    assert!(config.validate_warm_pools().is_ok());
    config.workspace_mode = WorkspaceMode::Managed;
    assert!(config.validate_warm_pools().is_ok());
    assert!(config.warm_pool.enabled);
    config.warm_pool.max_size = 257;
    assert!(config.validate_warm_pools().is_err());
}
