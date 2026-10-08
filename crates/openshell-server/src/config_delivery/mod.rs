// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configuration delivery to sandbox supervisors.
//!
//! In `poll` mode, supervisors poll `GetSandboxConfig` and the gateway keeps
//! no delivery state: `ServerState::config_delivery` is `None` and every
//! function here is a no-op. In `push` mode, the gateway pushes complete
//! configuration snapshots over each capable supervisor session.
//!
//! Request handlers [`publish`] what a committed change affects. Publishing
//! only marks sessions dirty and wakes them; it never blocks or drops a
//! change. Each push session has a delivery task that builds both
//! configuration parts from one read of the gateway's state when it is dirty,
//! sends what the supervisor does not already have, and matches the
//! supervisor's answers to what it sent.

mod build;
mod scheduler;
mod session;
mod task;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use openshell_core::proto::{ConfigUpdateResult, GatewayMessage, SupervisorHello};
use openshell_core::{Config, ConfigDeliveryMode};
use tokio::sync::{Notify, mpsc};
use tokio::time::Instant;
use tracing::{debug, warn};

use crate::ServerState;
use crate::gateway_metrics::{BuildLane, GaugeSlot};

/// Supervisor answers queued for one session's delivery task. The protocol
/// allows at most two unanswered updates.
const RESULT_QUEUE: usize = 8;

/// What a committed change affects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    /// One sandbox, by object id.
    Sandbox(String),
    /// Every sandbox in a workspace.
    Workspace(String),
    /// Every sandbox whose last build read this provider, by object id.
    Provider(String),
    /// Every sandbox.
    All,
}

impl Scope {
    /// Scope of a provider profile change. Platform profiles (empty
    /// workspace) are visible in every workspace's catalog.
    pub fn for_profiles(workspace: &str) -> Self {
        if workspace.is_empty() {
            Self::All
        } else {
            Self::Workspace(workspace.to_string())
        }
    }
}

/// Record that a committed change affects `scope`. A no-op in poll mode.
pub fn publish(state: &ServerState, scope: Scope) {
    if let Some(delivery) = state.config_delivery.as_ref() {
        delivery.publish(&scope);
    }
}

/// Publish every remote provider profile catalog change to all sessions.
/// A catalog change can add or withdraw credentialed endpoints anywhere.
pub fn spawn_profile_catalog_publisher(
    state: Arc<ServerState>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut catalog = state.provider_profile_sources.subscribe_changes();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                changed = catalog.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    publish(&state, Scope::All);
                }
                _ = shutdown.changed() => return,
            }
        }
    });
}

/// Whether to push configuration on a new session.
pub fn negotiate(state: &ServerState, hello: &SupervisorHello) -> bool {
    state.config_delivery.is_some() && hello.supports_config_push
}

/// Push-mode delivery state shared by every supervisor session.
#[derive(Debug)]
pub struct ConfigDelivery {
    consistency_check_interval: Duration,
    sessions: Mutex<HashMap<String, Arc<SessionEntry>>>,
    scheduler: Arc<scheduler::BuildScheduler>,
    /// Builds that fail before reading anything, for tests.
    #[cfg(test)]
    injected_build_failures: std::sync::atomic::AtomicU32,
}

/// What a session's next build must cover.
#[derive(Debug, Default)]
struct Dirty {
    /// A build is needed.
    pending: bool,
    /// Build the provider environment even if its identity did not move.
    force_provider: bool,
    lane: Option<BuildLane>,
    since: Option<Instant>,
    waiting: Option<GaugeSlot>,
}

/// Change-scoping facts captured by the session's last build.
#[derive(Debug, Default)]
struct Coverage {
    workspace: Option<String>,
    /// Providers the last build read. `None` when it could not tell, for
    /// example because the stored configuration was invalid.
    provider_ids: Option<HashSet<String>>,
    /// A build is reading inputs. Its coverage is not yet known, so every
    /// workspace- and provider-scoped change marks the session.
    building: bool,
}

/// A build request taken from a session's dirty state.
#[derive(Debug, Clone, Copy)]
struct BuildRequest {
    force_provider: bool,
    lane: BuildLane,
    since: Instant,
}

#[derive(Debug)]
struct SessionEntry {
    sandbox_id: String,
    session_id: String,
    dirty: Mutex<Dirty>,
    coverage: Mutex<Coverage>,
    wake: Notify,
    results: mpsc::Sender<ConfigUpdateResult>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    _gauge: GaugeSlot,
}

impl SessionEntry {
    fn mark(&self, lane: BuildLane, force_provider: bool) {
        {
            let mut dirty = self.dirty.lock().unwrap_or_else(PoisonError::into_inner);
            if !dirty.pending {
                dirty.pending = true;
                dirty.since = Some(Instant::now());
                dirty.waiting = Some(GaugeSlot::config_build_waiting());
            }
            dirty.force_provider |= force_provider;
            dirty.lane = Some(dirty.lane.map_or(lane, |current| current.min(lane)));
        }
        self.wake.notify_one();
    }

    /// The lane of the pending build, if one is needed.
    fn lane(&self) -> Option<BuildLane> {
        let dirty = self.dirty.lock().unwrap_or_else(PoisonError::into_inner);
        dirty.pending.then_some(dirty.lane).flatten()
    }

    fn workspace(&self) -> String {
        self.coverage
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .workspace
            .clone()
            .unwrap_or_default()
    }

    /// Take the dirty state when a build starts. Changes recorded from now
    /// on cause another build, so none can be lost.
    fn take(&self) -> Option<BuildRequest> {
        let mut dirty = self.dirty.lock().unwrap_or_else(PoisonError::into_inner);
        if !dirty.pending {
            return None;
        }
        let request = BuildRequest {
            force_provider: dirty.force_provider,
            lane: dirty.lane.unwrap_or(BuildLane::Fanout),
            since: dirty.since.unwrap_or_else(Instant::now),
        };
        *dirty = Dirty::default();
        self.coverage
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .building = true;
        Some(request)
    }

    /// Put back a request whose build failed, keeping anything recorded
    /// since.
    fn restore(&self, request: BuildRequest) {
        self.coverage
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .building = false;
        let mut dirty = self.dirty.lock().unwrap_or_else(PoisonError::into_inner);
        if !dirty.pending {
            dirty.pending = true;
            dirty.waiting = Some(GaugeSlot::config_build_waiting());
        }
        dirty.force_provider |= request.force_provider;
        dirty.lane = Some(
            dirty
                .lane
                .map_or(request.lane, |lane| lane.min(request.lane)),
        );
        dirty.since = Some(
            dirty
                .since
                .map_or(request.since, |since| since.min(request.since)),
        );
    }

    fn covers(&self, scope: &Scope) -> bool {
        let coverage = self.coverage.lock().unwrap_or_else(PoisonError::into_inner);
        // Until a build has finished, the session may depend on anything.
        let unknown = coverage.building || coverage.workspace.is_none();
        match scope {
            Scope::Sandbox(sandbox_id) => *sandbox_id == self.sandbox_id,
            Scope::Workspace(workspace) => {
                unknown || coverage.workspace.as_deref() == Some(workspace)
            }
            Scope::Provider(provider_id) => {
                unknown
                    || coverage
                        .provider_ids
                        .as_ref()
                        .is_none_or(|ids| ids.contains(provider_id))
            }
            Scope::All => true,
        }
    }

    fn record_coverage(&self, workspace: String, provider_ids: Option<Vec<String>>) {
        let mut coverage = self.coverage.lock().unwrap_or_else(PoisonError::into_inner);
        coverage.workspace = Some(workspace);
        coverage.provider_ids = provider_ids.map(|ids| ids.into_iter().collect());
        coverage.building = false;
    }
}

impl ConfigDelivery {
    /// Delivery state for `config`, or `None` in poll mode.
    ///
    /// Push requires a single-replica gateway: a change committed on one
    /// replica cannot yet reach a session owned by another.
    pub fn from_config(
        config: &Config,
        single_replica: bool,
        pool_size: usize,
    ) -> Result<Option<Arc<Self>>, String> {
        match config.config_delivery_mode {
            ConfigDeliveryMode::Poll => Ok(None),
            ConfigDeliveryMode::Push if !single_replica => Err(
                "config_delivery_mode = \"push\" requires a single-replica gateway (SQLite); \
                 multi-replica gateways must use \"poll\""
                    .to_string(),
            ),
            ConfigDeliveryMode::Push => Ok(Some(Arc::new(Self::new(
                Duration::from_secs(u64::from(config.config_consistency_check_interval_seconds)),
                scheduler::BuildScheduler::for_pool(pool_size),
            )))),
        }
    }

    fn new(
        consistency_check_interval: Duration,
        scheduler: Arc<scheduler::BuildScheduler>,
    ) -> Self {
        Self {
            consistency_check_interval,
            sessions: Mutex::new(HashMap::new()),
            scheduler,
            #[cfg(test)]
            injected_build_failures: std::sync::atomic::AtomicU32::new(0),
        }
    }

    fn publish(&self, scope: &Scope) {
        let lane = match scope {
            Scope::Sandbox(_) => BuildLane::Sandbox,
            Scope::Workspace(_) | Scope::Provider(_) | Scope::All => BuildLane::Fanout,
        };
        let sessions = self.sessions.lock().unwrap_or_else(PoisonError::into_inner);
        if let Scope::Sandbox(sandbox_id) = scope {
            if let Some(entry) = sessions.get(sandbox_id) {
                entry.mark(lane, false);
            }
            return;
        }
        let mut marked = 0usize;
        for entry in sessions.values().filter(|entry| entry.covers(scope)) {
            entry.mark(lane, false);
            marked += 1;
        }
        debug!(?scope, sessions = marked, "configuration change published");
    }

    /// Start pushing configuration on a new session. The first update is
    /// the initial snapshot. A replaced session's task is stopped.
    pub fn register(
        self: &Arc<Self>,
        state: Arc<ServerState>,
        sandbox_id: &str,
        session_id: &str,
        outbound: mpsc::Sender<GatewayMessage>,
    ) {
        let (results_tx, results_rx) = mpsc::channel(RESULT_QUEUE);
        let entry = Arc::new(SessionEntry {
            sandbox_id: sandbox_id.to_string(),
            session_id: session_id.to_string(),
            dirty: Mutex::new(Dirty::default()),
            coverage: Mutex::new(Coverage::default()),
            wake: Notify::new(),
            results: results_tx,
            task: Mutex::new(None),
            _gauge: GaugeSlot::config_push_session(),
        });
        // The initial snapshot carries both parts.
        entry.mark(BuildLane::Sandbox, true);
        let previous = self
            .sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(sandbox_id.to_string(), entry.clone());
        if let Some(previous) = previous {
            previous.stop();
        }
        let handle = tokio::spawn(
            task::DeliveryTask::new(state, self.clone(), entry.clone(), outbound, results_rx).run(),
        );
        *entry.task.lock().unwrap_or_else(PoisonError::into_inner) = Some(handle);
    }

    /// Stop pushing on a session that ended. A newer session for the same
    /// sandbox is left alone.
    pub fn unregister(&self, sandbox_id: &str, session_id: &str) {
        let mut sessions = self.sessions.lock().unwrap_or_else(PoisonError::into_inner);
        if sessions
            .get(sandbox_id)
            .is_some_and(|entry| entry.session_id == session_id)
            && let Some(entry) = sessions.remove(sandbox_id)
        {
            entry.stop();
        }
    }

    /// Hand a supervisor's answer to the session's delivery task.
    pub fn deliver_result(&self, sandbox_id: &str, session_id: &str, result: ConfigUpdateResult) {
        let entry = self
            .sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(sandbox_id)
            .filter(|entry| entry.session_id == session_id)
            .cloned();
        let Some(entry) = entry else {
            warn!(
                sandbox_id,
                session_id, "configuration result for a session without push; ignoring"
            );
            return;
        };
        if entry.results.try_send(result).is_err() {
            warn!(
                sandbox_id,
                session_id, "configuration result queue is full; ignoring result"
            );
        }
    }

    const fn consistency_check_interval(&self) -> Duration {
        self.consistency_check_interval
    }
}

impl SessionEntry {
    fn stop(&self) {
        let task = self
            .task
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(task) = task {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests;
