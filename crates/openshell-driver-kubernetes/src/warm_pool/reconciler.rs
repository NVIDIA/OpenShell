// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::config::WarmPoolConfig;
use openshell_supervisor_control::warm_pool::{
    WarmPoolEntry, WarmPoolPolicy, WarmPoolState, WarmPoolUpdate,
};
use std::collections::BTreeSet;

const BURST: usize = 4;
const INTERVAL: Duration = Duration::from_secs(5);
const RETRY_MS: i64 = 30_000;
const DISCONNECTED_MS: i64 = 60_000;
const OPERATION_TIMEOUT: Duration = Duration::from_secs(25);

/// Snapshot of one successful inventory/plan pass. Readiness is observed from
/// the pinned supervisor's authenticated stream, never inferred from Pod status.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WarmPoolReport {
    pub ready: usize,
    pub pending: usize,
    pub retiring: usize,
    pub attempted: usize,
    pub failed: usize,
    pub conflicted: bool,
    pub suspended: bool,
}

#[derive(Clone)]
struct Action {
    entry: WarmPoolEntry,
    resource: Option<WarmRuntimeResource>,
}

fn now_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(i64::MAX)
}

fn policy(pool: &WarmPoolConfig) -> WarmPoolPolicy {
    WarmPoolPolicy {
        target_size: pool.target_size,
        max_size: pool.max_size,
        max_age_secs: pool.max_age_secs,
        preparation_timeout_secs: pool.preparation_timeout_secs,
    }
}

pub(super) fn spec(pool: &WarmPoolConfig) -> SandboxSpec {
    pool.spec.clone()
}

/// Plan only: the caller must win the journal CAS before executing any action.
fn plan(
    pool: &WarmPoolConfig,
    state: &mut WarmPoolState,
    inventory: &[WarmRuntimeResource],
    ready: &BTreeSet<SandboxSessionId>,
    lost: &BTreeSet<SandboxSessionId>,
    now: i64,
    prepare: Option<CredentialEpoch>,
) -> (Vec<Action>, WarmPoolReport) {
    let resources: BTreeMap<_, _> = inventory
        .iter()
        .map(|resource| (resource.session_id, resource))
        .collect();
    state.entries.retain(|entry| {
        !resources
            .get(&entry.session_id)
            .is_some_and(|resource| resource.claimed)
    });
    for entry in &mut state.entries {
        if let Some(resource) = resources.get(&entry.session_id) {
            entry.auth_epoch.get_or_insert(resource.auth_epoch);
        }
        if let Some(uid) = &entry.resource_uid {
            entry.retiring |= resources
                .get(&entry.session_id)
                .is_none_or(|resource| &resource.uid != uid);
        } else if let Some(resource) = resources.get(&entry.session_id) {
            entry.resource_uid = Some(resource.uid.clone());
        }
        if ready.contains(&entry.session_id) {
            entry.last_ready_at_ms = Some(now);
        }
        let age = now.saturating_sub(entry.created_at_ms);
        let unhealthy = entry.last_ready_at_ms.map_or_else(
            || age >= i64::try_from(pool.preparation_timeout_secs * 1000).unwrap_or(i64::MAX),
            |last| now.saturating_sub(last) >= DISCONNECTED_MS,
        );
        entry.retiring |= age >= i64::try_from(pool.max_age_secs * 1000).unwrap_or(i64::MAX)
            || unhealthy
            || lost.contains(&entry.session_id)
            || resources
                .get(&entry.session_id)
                .is_some_and(|resource| resource.retiring || resource.deleting);
    }
    // Keep the oldest useful spares on scale-down. Every retirement still counts
    // against the maximum until its physical CR has gone and its route is fenced.
    let mut retained = 0;
    for entry in &mut state.entries {
        if !entry.retiring {
            retained += 1;
            entry.retiring = retained > pool.target_size;
        }
    }
    let known: BTreeSet<_> = state.entries.iter().map(|entry| entry.session_id).collect();
    let orphans: Vec<_> = inventory
        .iter()
        .filter(|resource| !resource.claimed && !known.contains(&resource.session_id))
        .collect();
    let useful = state.entries.iter().filter(|entry| !entry.retiring).count();
    let occupied = state.entries.len() + orphans.len();
    let refill = (pool.target_size as usize)
        .saturating_sub(useful)
        .min((pool.max_size as usize).saturating_sub(occupied))
        .min(BURST);
    for _ in 0..if prepare.is_some() { refill } else { 0 } {
        state.entries.push(WarmPoolEntry {
            session_id: SandboxSessionId::new(),
            created_at_ms: now,
            last_attempt_at_ms: None,
            last_ready_at_ms: None,
            resource_uid: None,
            retiring: false,
            auth_epoch: prepare,
        });
    }
    let mut actions = Vec::new();
    // Repair late physical writes after a retired intent was completed. They
    // count against capacity and are never adopted as fresh preparations.
    for resource in orphans.into_iter().take(BURST) {
        actions.push(Action {
            entry: WarmPoolEntry {
                session_id: resource.session_id,
                created_at_ms: now,
                last_attempt_at_ms: None,
                last_ready_at_ms: None,
                resource_uid: Some(resource.uid.clone()),
                retiring: true,
                auth_epoch: Some(resource.auth_epoch),
            },
            resource: Some(resource.clone()),
        });
    }
    let mut candidates: Vec<_> = state
        .entries
        .iter_mut()
        .filter(|entry| {
            (entry.retiring
                || (prepare.is_some()
                    && !resources
                        .get(&entry.session_id)
                        .is_some_and(|resource| resource.released)))
                && entry
                    .last_attempt_at_ms
                    .is_none_or(|last| now.saturating_sub(last) >= RETRY_MS)
        })
        .collect();
    candidates.sort_by_key(|entry| (entry.last_attempt_at_ms, entry.created_at_ms));
    for entry in candidates
        .into_iter()
        .take(BURST.saturating_sub(actions.len()))
    {
        entry.last_attempt_at_ms = Some(now);
        actions.push(Action {
            entry: entry.clone(),
            resource: resources
                .get(&entry.session_id)
                .map(|resource| (*resource).clone()),
        });
    }
    let retiring = state.entries.iter().filter(|entry| entry.retiring).count();
    let ready_count = state
        .entries
        .iter()
        .filter(|entry| !entry.retiring && ready.contains(&entry.session_id))
        .count();
    let report = WarmPoolReport {
        ready: ready_count,
        pending: state.entries.len() - retiring - ready_count,
        retiring,
        attempted: actions.len(),
        ..Default::default()
    };
    (actions, report)
}

impl KubernetesComputeDriver {
    pub(super) async fn template_warm_pools(
        &self,
        sandbox_id: Option<String>,
    ) -> Result<Vec<WarmPoolConfig>, KubernetesDriverError> {
        let settings = &self.config.warm_pool;
        self.warm_supervision()?
            .warm_pool_targets(sandbox_id)
            .await
            .map_err(KubernetesDriverError::Message)
            .map(|targets| {
                targets
                    .into_iter()
                    .map(|target| WarmPoolConfig {
                        name: target.pool_id,
                        workspace: target.workspace,
                        revision: if target.spec.is_none() {
                            u64::MAX
                        } else {
                            settings.revision
                        },
                        target_size: if settings.enabled {
                            target.target.min(settings.max_size)
                        } else {
                            0
                        },
                        max_size: settings.max_size,
                        max_age_secs: settings.max_age_secs,
                        preparation_timeout_secs: settings.preparation_timeout_secs,
                        spec: target.spec.unwrap_or_default(),
                    })
                    .collect()
            })
    }

    /// Pool mutations follow a journal CAS; claim recovery uses the gateway's
    /// assignment fences. Errors leave creation identities intact for retry.
    pub async fn reconcile_warm_pool(
        &self,
        pool: &WarmPoolConfig,
    ) -> Result<WarmPoolReport, KubernetesDriverError> {
        self.check_warm_runtime_support()?;
        pool.validate()
            .map_err(KubernetesDriverError::Precondition)?;
        let supervision = self.warm_supervision()?;
        let snapshot = supervision
            .warm_pool_state(&pool.workspace, &pool.name)
            .await
            .map_err(KubernetesDriverError::Message)?;
        if snapshot.is_none() && pool.revision == u64::MAX {
            // Another replica finished this drain after target discovery.
            return Ok(WarmPoolReport::default());
        }
        if snapshot
            .as_ref()
            .is_some_and(|s| s.state.revision > pool.revision)
        {
            return Err(invalid(
                "warm pool has a newer revision; this replica cannot change it",
            ));
        }
        if snapshot.is_none()
            && pool.target_size > 0
            && self.config.workspace_mode == WorkspaceMode::Managed
        {
            self.ensure_namespace(&pool.workspace).await?;
        }
        let trust = supervision
            .warm_runtime_trust()
            .await
            .map_err(KubernetesDriverError::Message)
            .and_then(|trust| {
                validate_trust(&trust)?;
                Ok(trust)
            });
        let fingerprint = match &trust {
            Ok(trust) => self.warm_pool_fingerprint(pool, trust).await,
            Err(error) => Err(invalid(&error.to_string())),
        };
        let mut inventory = self
            .list_warm_runtime_inventory(&pool.workspace, Some(&pool.name))
            .await?;
        let recovering = self
            .recover_pending_warm_claims(&pool.workspace, &pool.name, &mut inventory)
            .await?;
        let inventory: Vec<_> = inventory
            .into_iter()
            .filter(|resource| resource.pool_id == pool.name)
            .collect();
        let sessions: BTreeSet<_> =
            inventory
                .iter()
                .filter(|resource| !resource.claimed)
                .map(|resource| resource.session_id)
                .chain(snapshot.iter().flat_map(|snapshot| {
                    snapshot.state.entries.iter().map(|entry| entry.session_id)
                }))
                .collect();
        let routes = sessions
            .into_iter()
            .map(|session| format!("rt-{session}"))
            .collect();
        let preparations = supervision
            .prepared_runtimes(&pool.workspace, routes)
            .await
            .map_err(KubernetesDriverError::Message)?;
        let mut ready = BTreeSet::new();
        let mut lost = BTreeSet::new();
        for preparation in &preparations {
            let session = preparation.registration.runtime_descriptor.session_id;
            if preparation
                .owner
                .as_ref()
                .is_none_or(|owner| !owner.available)
                || !inventory
                    .iter()
                    .any(|resource| resource.session_id == session)
            {
                lost.insert(session);
            } else if let Some(resource) = inventory
                .iter()
                .find(|resource| resource.session_id == session)
                && self.warm_connection_ready(resource).await?
            {
                ready.insert(session);
            }
        }
        let expected_version = snapshot.as_ref().map(|snapshot| snapshot.resource_version);
        let mut state = match snapshot {
            Some(snapshot) => snapshot.state,
            None => WarmPoolState {
                revision: pool.revision,
                fingerprint: fingerprint
                    .as_ref()
                    .map_err(|error| invalid(&error.to_string()))?
                    .clone(),
                policy: Some(policy(pool)),
                entries: Vec::new(),
            },
        };
        let compatible = fingerprint
            .as_ref()
            .is_ok_and(|value| *value == state.fingerprint);
        let desired_policy = policy(pool);
        if state.revision < pool.revision && (fingerprint.is_ok() || pool.target_size == 0) {
            if !compatible {
                for entry in &mut state.entries {
                    entry.retiring = true;
                }
            }
            state.revision = pool.revision;
            if let Ok(fingerprint) = &fingerprint {
                state.fingerprint.clone_from(fingerprint);
            }
            state.policy = Some(desired_policy.clone());
        } else if pool.target_size == 0 {
            // A same-revision disable is monotonic: enabled replicas cannot undo it.
            let stored = state.policy.get_or_insert_with(|| desired_policy.clone());
            stored.target_size = 0;
        } else if compatible && state.policy.is_none() {
            state.policy = Some(desired_policy.clone());
        }
        let suspended = !fingerprint
            .as_ref()
            .is_ok_and(|value| *value == state.fingerprint)
            || state.revision != pool.revision
            || state.policy.as_ref() != Some(&desired_policy);
        if suspended {
            warn!(workspace = %pool.workspace, pool = %pool.name,
                stored_revision = state.revision, local_revision = pool.revision,
                error = ?fingerprint.as_ref().err(),
                "warm provisioning suspended: configuration changed; deploy a higher warm_pool.revision; recorded cleanup continues");
        }
        // A mismatching replica uses the recorded policy only for cleanup. It
        // cannot refill, resume preparations, or impose its own expiry settings.
        let mut effective = pool.clone();
        if let Some(policy) = &state.policy {
            effective.target_size = policy.target_size;
            effective.max_size = policy.max_size;
            effective.max_age_secs = policy.max_age_secs;
            effective.preparation_timeout_secs = policy.preparation_timeout_secs;
        } else {
            // Legacy journals have no authoritative lifetime policy. Only finish
            // existing retirements until an operator publishes a new revision.
            effective.target_size = u32::MAX;
            effective.max_age_secs = u64::MAX / 1000;
            effective.preparation_timeout_secs = u64::MAX / 1000;
        }
        for entry in &mut state.entries {
            if entry.auth_epoch.is_none() {
                entry.auth_epoch = preparations
                    .iter()
                    .find(|p| p.registration.runtime_descriptor.session_id == entry.session_id)
                    .map(|p| p.auth_epoch);
            }
        }
        let newly_ready: Vec<_> = state
            .entries
            .iter()
            .filter(|entry| {
                !entry.retiring
                    && entry.last_ready_at_ms.is_none()
                    && ready.contains(&entry.session_id)
            })
            .map(|entry| entry.session_id)
            .collect();
        let prepare = if suspended {
            None
        } else {
            trust.as_ref().ok().map(|t| t.auth_epoch)
        };
        let (actions, mut report) = plan(
            &effective,
            &mut state,
            &inventory,
            &ready,
            &lost,
            now_ms(),
            prepare,
        );
        report.suspended = suspended;
        let finish_drain = pool.revision == u64::MAX
            && state.entries.is_empty()
            && actions.is_empty()
            && !recovering
            && inventory.iter().all(|resource| resource.claimed);
        if !supervision
            .update_warm_pool(WarmPoolUpdate {
                finish_drain,
                workspace: pool.workspace.clone(),
                pool_id: pool.name.clone(),
                expected_version,
                state,
            })
            .await
            .map_err(KubernetesDriverError::Message)?
        {
            report.conflicted = true;
            report.attempted = 0;
            return Ok(report);
        }
        for session_id in newly_ready {
            info!(workspace = %pool.workspace, pool = %pool.name, %session_id, "warm runtime ready for claim");
        }
        let results = futures::stream::iter(actions.into_iter().map(|action| {
            let trust = &trust;
            async move {
                tokio::time::timeout(
                    OPERATION_TIMEOUT,
                    Box::pin(self.execute_warm_action(pool, action, trust.as_ref().ok())),
                )
                .await
                .map_err(|_| invalid("warm pool operation timed out; its intent is retained"))?
            }
        }))
        .buffer_unordered(BURST)
        .collect::<Vec<_>>()
        .await;
        for result in results {
            if let Err(error) = result {
                report.failed += 1;
                warn!(workspace = %pool.workspace, pool = %pool.name, %error, "warm pool operation will be reconciled");
            }
        }
        Ok(report)
    }

    async fn execute_warm_action(
        &self,
        pool: &WarmPoolConfig,
        action: Action,
        trust: Option<&WarmRuntimeTrust>,
    ) -> Result<(), KubernetesDriverError> {
        if !action.entry.retiring {
            let trust =
                trust.ok_or_else(|| invalid("preparation requires current runtime trust"))?;
            if let Some(resource) = &action.resource {
                self.resume_warm_runtime(resource).await?;
            } else {
                self.prepare_warm_runtime(&WarmRuntimeRequest {
                    workspace: pool.workspace.clone(),
                    pool_id: pool.name.clone(),
                    session_id: action.entry.session_id,
                    spec: spec(pool),
                    trust: trust.clone(),
                })
                .await?;
            }
            return Ok(());
        }
        if let Some(resource) = &action.resource
            && self.retire_warm_runtime(resource).await? != WarmRuntimeRetirement::Absent
        {
            return Ok(());
        }
        let supervision = self.warm_supervision()?;
        // Fence even an intent whose create never reached Kubernetes. A delayed
        // prepare cannot reserve capacity after this intent is forgotten.
        if supervision
            .retire_preparation(PreparationRetirement {
                workspace: pool.workspace.clone(),
                route: format!("rt-{}", action.entry.session_id),
                generation: openshell_core::sandbox_generation::SandboxGenerationId::parse(
                    action.entry.session_id.to_string(),
                )
                .map_err(|_| invalid("invalid generation"))?,
                auth_epoch: action.entry.auth_epoch.ok_or_else(|| {
                    invalid("retirement is missing its original credential epoch")
                })?,
            })
            .await
            .map_err(KubernetesDriverError::Message)?
            != PreparationRelease::Released
        {
            return Ok(());
        }
        // A conflict simply leaves the retired entry for the next pass.
        if let Some(mut snapshot) = supervision
            .warm_pool_state(&pool.workspace, &pool.name)
            .await
            .map_err(KubernetesDriverError::Message)?
        {
            snapshot
                .state
                .entries
                .retain(|entry| entry.session_id != action.entry.session_id || !entry.retiring);
            supervision
                .update_warm_pool(WarmPoolUpdate {
                    finish_drain: false,
                    workspace: pool.workspace.clone(),
                    pool_id: pool.name.clone(),
                    expected_version: Some(snapshot.resource_version),
                    state: snapshot.state,
                })
                .await
                .map_err(KubernetesDriverError::Message)?;
        }
        Ok(())
    }

    pub(in crate::driver) fn spawn_warm_pool_reconciler(
        &self,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        if self.check_warm_runtime_support().is_err() {
            return;
        }
        let driver = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                if *shutdown.borrow() {
                    break;
                }
                tokio::select! {
                    result = shutdown.changed() => { if result.is_err() || *shutdown.borrow() { break; } }
                    _ = interval.tick() => {
                        let pools = match driver.template_warm_pools(None).await {
                            Ok(pools) => pools,
                            Err(error) => { warn!(%error, "warm template inventory unavailable"); continue; }
                        };
                        let jobs = pools.into_iter().map(|pool| {
                            let driver = driver.clone();
                            async move {
                                if let Err(error) = driver.reconcile_warm_pool(&pool).await {
                                    warn!(workspace = %pool.workspace, pool = %pool.name, %error, "warm pool reconciliation deferred");
                                }
                            }
                        });
                        let pass = futures::stream::iter(jobs).buffer_unordered(BURST).collect::<Vec<_>>();
                        tokio::select! {
                            _ = pass => {}
                            _ = shutdown.changed() => { break; }
                        }
                    }
                }
            }
        });
    }
}

#[cfg(test)]
#[path = "reconciler_tests.rs"]
mod tests;
