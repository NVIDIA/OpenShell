// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Synchronous coalescing queue for supervisor configuration delivery.
//!
//! Every publication takes a sequence number. When a build starts, its
//! key records the highest sequence issued so far. Publications are issued
//! after their commits, so that build observes state at least as new as every
//! publication it covers, and a key needs work for publication `P` only while
//! its `last_build_seq < P`.
//!
//! Admission never rejects: every key set is bounded by sandboxes, workspaces,
//! and providers, so repeated publications only coalesce. Fanouts are cursors
//! over the sorted local recipients rather than queued keys, and build slots
//! are granted only here, with a reserve for sandbox-scoped work.

use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::ops::Bound;
use std::time::Instant;

use metrics::{counter, gauge, histogram};

use super::{ConfigComponentKind, ConfigComponents};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeliveryKey {
    pub sandbox_id: String,
    pub component: ConfigComponentKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FanoutScope {
    AllConnected,
    Workspace(String),
    /// Sandboxes in `workspace` that attach the named provider.
    Provider {
        workspace: String,
        name: String,
    },
}

impl FanoutScope {
    fn includes(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::AllConnected, _) => true,
            (
                Self::Workspace(workspace),
                Self::Workspace(other)
                | Self::Provider {
                    workspace: other, ..
                },
            ) => workspace == other,
            (Self::Provider { .. }, Self::Provider { .. }) => self == other,
            _ => false,
        }
    }

    fn workspace(&self) -> Option<&str> {
        match self {
            Self::AllConnected => None,
            Self::Workspace(workspace) | Self::Provider { workspace, .. } => Some(workspace),
        }
    }

    fn metric_label(&self) -> &'static str {
        match self {
            Self::AllConnected => "all_connected",
            Self::Workspace(_) => "workspace",
            Self::Provider { .. } => "provider",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FanoutKey {
    scope: FanoutScope,
    component: ConfigComponentKind,
}

/// Lanes are ordered by priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Lane {
    Fanout,
    Sandbox,
}

impl Lane {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Fanout => "fanout",
            Self::Sandbox => "sandbox",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    builds: usize,
    sandbox_reserve: usize,
    peer_notifies: usize,
}

impl Limits {
    /// Fanout work may use every build slot except `sandbox_reserve`, and
    /// sandbox-scoped work leaves one slot for waiting fanout work.
    pub(crate) fn new(builds: usize, peer_notifies: usize) -> Self {
        let builds = builds.max(2);
        Self {
            builds,
            sandbox_reserve: (builds / 4).clamp(1, builds - 1),
            peer_notifies: peer_notifies.max(1),
        }
    }

    #[cfg(test)]
    pub(crate) fn builds(self) -> usize {
        self.builds
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Work {
    Build(BuildTicket),
    PeerNotify(PeerNotifyTicket),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildTicket {
    pub key: DeliveryKey,
    pub lane: Lane,
    /// Session registered when the build started. Delivery must not
    /// cross into a replacement session, which received its own bootstrap.
    pub session_id: String,
    epoch: u64,
    seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PeerNotifyTarget {
    /// Sandbox without a local push recipient; its owner may be a peer.
    Sandbox(String),
    /// Scope notification for every peer gateway.
    Peers(FanoutScope),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerNotifyTicket {
    pub target: PeerNotifyTarget,
    pub components: ConfigComponents,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildOutcome {
    /// `providers` is the attachment list read with the snapshot, when the
    /// sandbox still exists.
    Built {
        providers: Option<HashSet<String>>,
    },
    Failed,
}

#[derive(Debug, Clone)]
pub struct Registration {
    pub sandbox_id: String,
    pub session_id: String,
    pub workspace: String,
    pub providers: HashSet<String>,
    /// `current_seq()` observed before the bootstrap build started.
    pub captured_seq: u64,
    pub bootstrap_built: bool,
}

#[derive(Debug, Default)]
struct KeyState {
    last_build_seq: u64,
    rollback_seq: u64,
    in_flight: bool,
    queued: Option<Lane>,
    requeue: Option<Lane>,
    /// A fanout skipped this in-flight key as current; rebuild if it fails.
    requeue_on_failure: Option<Lane>,
    waiting_since: Option<Instant>,
}

#[derive(Debug)]
struct Recipient {
    session_id: String,
    epoch: u64,
    workspace: String,
    providers: HashSet<String>,
    /// Start sequence of the build that last refreshed `providers`. Builds
    /// can finish out of order, and an older attachment list must not win.
    providers_seq: u64,
    sandbox_config: KeyState,
    provider_environment: KeyState,
}

impl Recipient {
    fn key(&self, component: ConfigComponentKind) -> &KeyState {
        match component {
            ConfigComponentKind::SandboxConfig => &self.sandbox_config,
            ConfigComponentKind::ProviderEnvironment => &self.provider_environment,
        }
    }

    fn key_mut(&mut self, component: ConfigComponentKind) -> &mut KeyState {
        match component {
            ConfigComponentKind::SandboxConfig => &mut self.sandbox_config,
            ConfigComponentKind::ProviderEnvironment => &mut self.provider_environment,
        }
    }
}

#[derive(Debug)]
struct Cursor {
    target_seq: u64,
    /// Last sandbox handed out or skipped in sorted order.
    position: Option<String>,
    /// Position at the latest publication. After wrapping, the pass ends here.
    lap_end: Option<String>,
    wrapped: bool,
    started: Instant,
}

#[derive(Debug, Default)]
struct PeerNotifyState {
    pending: ConfigComponents,
    queued: bool,
    in_flight: bool,
}

#[derive(Debug, Default)]
struct Running {
    sandbox: usize,
    fanout: usize,
    peer_notifies: usize,
}

impl Running {
    fn builds(&self) -> usize {
        self.sandbox + self.fanout
    }

    fn lane_mut(&mut self, lane: Lane) -> &mut usize {
        match lane {
            Lane::Sandbox => &mut self.sandbox,
            Lane::Fanout => &mut self.fanout,
        }
    }
}

#[derive(Debug, Default)]
struct QueuedCounts {
    sandbox: usize,
    fanout: usize,
}

impl QueuedCounts {
    fn transition(&mut self, from: Option<Lane>, to: Option<Lane>) {
        if let Some(lane) = from {
            *self.lane_mut(lane) -= 1;
        }
        if let Some(lane) = to {
            *self.lane_mut(lane) += 1;
        }
    }

    fn lane_mut(&mut self, lane: Lane) -> &mut usize {
        match lane {
            Lane::Sandbox => &mut self.sandbox,
            Lane::Fanout => &mut self.fanout,
        }
    }
}

#[derive(Debug)]
pub struct DeliveryQueue {
    limits: Limits,
    seq: u64,
    next_epoch: u64,
    recipients: BTreeMap<String, Recipient>,
    by_workspace: HashMap<String, BTreeSet<String>>,
    sandbox_keys: VecDeque<DeliveryKey>,
    fanout_retry: VecDeque<DeliveryKey>,
    queued: QueuedCounts,
    cursors: HashMap<FanoutKey, Cursor>,
    cursor_order: VecDeque<FanoutKey>,
    peer_notifies: HashMap<PeerNotifyTarget, PeerNotifyState>,
    peer_notify_ready: VecDeque<PeerNotifyTarget>,
    running: Running,
}

impl DeliveryQueue {
    pub(crate) fn new(limits: Limits) -> Self {
        Self {
            limits,
            seq: 0,
            next_epoch: 0,
            recipients: BTreeMap::new(),
            by_workspace: HashMap::new(),
            sandbox_keys: VecDeque::new(),
            fanout_retry: VecDeque::new(),
            queued: QueuedCounts::default(),
            cursors: HashMap::new(),
            cursor_order: VecDeque::new(),
            peer_notifies: HashMap::new(),
            peer_notify_ready: VecDeque::new(),
            running: Running::default(),
        }
    }

    #[cfg(test)]
    pub(crate) fn limits(&self) -> Limits {
        self.limits
    }

    pub(crate) fn current_seq(&self) -> u64 {
        self.seq
    }

    #[cfg(test)]
    pub(crate) fn has_recipient(&self, sandbox_id: &str) -> bool {
        self.recipients.contains_key(sandbox_id)
    }

    /// Add or replace the local push recipient for a sandbox.
    ///
    /// A publication between bootstrap and registration may have passed this
    /// sandbox's cursor position before it became visible, so it is rebuilt
    /// directly.
    pub(crate) fn register(&mut self, registration: Registration, now: Instant) {
        let Registration {
            sandbox_id,
            session_id,
            workspace,
            providers,
            captured_seq,
            bootstrap_built,
        } = registration;
        self.remove_recipient(&sandbox_id);
        self.next_epoch += 1;
        let built_seq = if bootstrap_built { captured_seq } else { 0 };
        let built = || KeyState {
            last_build_seq: built_seq,
            rollback_seq: built_seq,
            ..KeyState::default()
        };
        self.by_workspace
            .entry(workspace.clone())
            .or_default()
            .insert(sandbox_id.clone());
        self.recipients.insert(
            sandbox_id.clone(),
            Recipient {
                session_id,
                epoch: self.next_epoch,
                workspace,
                providers,
                providers_seq: captured_seq,
                sandbox_config: built(),
                provider_environment: built(),
            },
        );
        if self.seq > captured_seq {
            for component in ConfigComponents::ALL.selected() {
                self.enqueue_key(&sandbox_id, component, Lane::Sandbox, now);
            }
        }
    }

    pub(crate) fn unregister(&mut self, sandbox_id: &str, session_id: &str) {
        if self
            .recipients
            .get(sandbox_id)
            .is_some_and(|recipient| recipient.session_id == session_id)
        {
            self.remove_recipient(sandbox_id);
        }
    }

    /// Returns false when this gateway has no push recipient for the sandbox.
    pub(crate) fn publish_sandbox(
        &mut self,
        sandbox_id: &str,
        components: ConfigComponents,
        now: Instant,
    ) -> bool {
        self.seq += 1;
        if !self.recipients.contains_key(sandbox_id) {
            return false;
        }
        for component in components.selected() {
            self.enqueue_key(sandbox_id, component, Lane::Sandbox, now);
        }
        true
    }

    pub(crate) fn publish_fanout(
        &mut self,
        scope: &FanoutScope,
        components: ConfigComponents,
        notify_peers: bool,
        now: Instant,
    ) {
        self.seq += 1;
        let seq = self.seq;
        for component in components.selected() {
            self.cursors.retain(|key, _| {
                key.component != component || key.scope == *scope || !scope.includes(&key.scope)
            });
            let key = FanoutKey {
                scope: scope.clone(),
                component,
            };
            match self.cursors.entry(key.clone()) {
                Entry::Occupied(mut entry) => {
                    let cursor = entry.get_mut();
                    cursor.target_seq = seq;
                    cursor.lap_end.clone_from(&cursor.position);
                    cursor.wrapped = false;
                }
                Entry::Vacant(entry) => {
                    entry.insert(Cursor {
                        target_seq: seq,
                        position: None,
                        lap_end: None,
                        wrapped: false,
                        started: now,
                    });
                    self.cursor_order.push_back(key);
                }
            }
        }
        let cursors = &self.cursors;
        self.cursor_order.retain(|key| cursors.contains_key(key));
        if notify_peers {
            self.notify_peer(PeerNotifyTarget::Peers(scope.clone()), components);
        }
    }

    pub(crate) fn notify_peer(&mut self, target: PeerNotifyTarget, components: ConfigComponents) {
        let state = self.peer_notifies.entry(target.clone()).or_default();
        state.pending = state.pending.union(components);
        if !state.queued && !state.in_flight {
            state.queued = true;
            self.peer_notify_ready.push_back(target);
        }
    }

    pub(crate) fn next_work(&mut self, now: Instant) -> Option<Work> {
        if self.running.peer_notifies < self.limits.peer_notifies
            && let Some(target) = self.peer_notify_ready.pop_front()
        {
            let state = self
                .peer_notifies
                .get_mut(&target)
                .expect("ready peer notification has state");
            state.queued = false;
            state.in_flight = true;
            self.running.peer_notifies += 1;
            return Some(Work::PeerNotify(PeerNotifyTicket {
                target,
                components: std::mem::take(&mut state.pending),
            }));
        }
        self.next_build(now)
    }

    pub(crate) fn complete_build(
        &mut self,
        ticket: &BuildTicket,
        outcome: BuildOutcome,
        now: Instant,
    ) {
        *self.running.lane_mut(ticket.lane) -= 1;
        let Some(recipient) = self.recipients.get_mut(&ticket.key.sandbox_id) else {
            return;
        };
        if recipient.epoch != ticket.epoch {
            return;
        }
        let failed = outcome == BuildOutcome::Failed;
        if let BuildOutcome::Built {
            providers: Some(providers),
        } = outcome
            && ticket.seq >= recipient.providers_seq
        {
            recipient.providers = providers;
            recipient.providers_seq = ticket.seq;
        }
        let state = recipient.key_mut(ticket.key.component);
        state.in_flight = false;
        let requeue = if failed {
            state.last_build_seq = state.rollback_seq;
            state.requeue.take().max(state.requeue_on_failure.take())
        } else {
            state.requeue_on_failure = None;
            state.requeue.take()
        };
        if let Some(lane) = requeue {
            self.enqueue_key(&ticket.key.sandbox_id, ticket.key.component, lane, now);
        }
    }

    pub(crate) fn complete_peer_notify(&mut self, ticket: &PeerNotifyTicket) {
        self.running.peer_notifies -= 1;
        let Some(state) = self.peer_notifies.get_mut(&ticket.target) else {
            return;
        };
        state.in_flight = false;
        if state.pending.is_empty() {
            self.peer_notifies.remove(&ticket.target);
        } else {
            state.queued = true;
            self.peer_notify_ready.push_back(ticket.target.clone());
        }
    }

    pub(crate) fn has_running_work(&self) -> bool {
        self.running.builds() > 0 || self.running.peer_notifies > 0
    }

    pub(crate) fn record_gauges(&self) {
        gauge!("openshell_supervisor_config_pending", "lane" => "sandbox")
            .set(u32::try_from(self.queued.sandbox).unwrap_or(u32::MAX));
        gauge!("openshell_supervisor_config_pending", "lane" => "fanout")
            .set(u32::try_from(self.queued.fanout).unwrap_or(u32::MAX));
        gauge!("openshell_supervisor_config_pending", "lane" => "peer_notify")
            .set(u32::try_from(self.peer_notify_ready.len()).unwrap_or(u32::MAX));
        gauge!("openshell_supervisor_config_active_fanouts")
            .set(u32::try_from(self.cursors.len()).unwrap_or(u32::MAX));
    }

    fn next_build(&mut self, now: Instant) -> Option<Work> {
        if self.running.builds() >= self.limits.builds {
            return None;
        }
        // Sandbox work leaves the last slot to waiting fanout work that has no
        // build running yet.
        let fanout_waiting = !self.fanout_retry.is_empty() || !self.cursors.is_empty();
        let keeps_fanout_floor = fanout_waiting
            && self.running.fanout == 0
            && self.running.builds() + 1 == self.limits.builds;
        if !keeps_fanout_floor && let Some(key) = self.pop_queued(Lane::Sandbox) {
            return Some(self.start_build(key, Lane::Sandbox, now));
        }
        if self.running.fanout < self.limits.builds - self.limits.sandbox_reserve
            && let Some(work) = self.next_fanout(now)
        {
            return Some(work);
        }
        // Fanout had nothing to start, so the floor is not needed.
        if keeps_fanout_floor && let Some(key) = self.pop_queued(Lane::Sandbox) {
            return Some(self.start_build(key, Lane::Sandbox, now));
        }
        None
    }

    fn next_fanout(&mut self, now: Instant) -> Option<Work> {
        if let Some(key) = self.pop_queued(Lane::Fanout) {
            return Some(self.start_build(key, Lane::Fanout, now));
        }
        for _ in 0..self.cursor_order.len() {
            let key = self.cursor_order.pop_front()?;
            let Some(mut cursor) = self.cursors.remove(&key) else {
                continue;
            };
            if let Some(sandbox_id) = self.advance(&key, &mut cursor) {
                let component = key.component;
                self.cursors.insert(key.clone(), cursor);
                self.cursor_order.push_back(key);
                return Some(self.start_build(
                    DeliveryKey {
                        sandbox_id,
                        component,
                    },
                    Lane::Fanout,
                    now,
                ));
            }
            histogram!(
                "openshell_supervisor_config_fanout_pass_seconds",
                "scope" => key.scope.metric_label(),
            )
            .record(now.saturating_duration_since(cursor.started).as_secs_f64());
        }
        None
    }

    fn advance(&mut self, key: &FanoutKey, cursor: &mut Cursor) -> Option<String> {
        let component = key.component;
        loop {
            let Some(sandbox_id) = self.next_in_scope(&key.scope, cursor.position.as_deref())
            else {
                if cursor.wrapped || cursor.lap_end.is_none() {
                    return None;
                }
                cursor.wrapped = true;
                cursor.position = None;
                continue;
            };
            if cursor.wrapped
                && cursor
                    .lap_end
                    .as_deref()
                    .is_some_and(|end| sandbox_id.as_str() > end)
            {
                return None;
            }
            cursor.position = Some(sandbox_id.clone());
            let recipient = self
                .recipients
                .get_mut(&sandbox_id)
                .expect("scope index lists only recipients");
            // An in-flight build may be the one that installs a new attachment
            // in the provider cache, so it cannot be filtered out yet.
            if let FanoutScope::Provider { name, .. } = &key.scope
                && !recipient.providers.contains(name)
                && !recipient.key(component).in_flight
            {
                record_skip(component, "not_attached");
                continue;
            }
            let state = recipient.key_mut(component);
            if state.in_flight {
                if state.last_build_seq < cursor.target_seq {
                    state.requeue = state.requeue.max(Some(Lane::Fanout));
                } else {
                    state.requeue_on_failure = state.requeue_on_failure.max(Some(Lane::Fanout));
                }
                record_skip(component, "in_flight");
                continue;
            }
            if state.last_build_seq >= cursor.target_seq {
                record_skip(component, "current");
                continue;
            }
            if state.queued.is_some() {
                record_skip(component, "queued");
                continue;
            }
            return Some(sandbox_id);
        }
    }

    fn next_in_scope(&self, scope: &FanoutScope, after: Option<&str>) -> Option<String> {
        let range = (
            after.map_or(Bound::Unbounded, Bound::Excluded),
            Bound::Unbounded,
        );
        match scope.workspace() {
            None => self
                .recipients
                .range::<str, _>(range)
                .next()
                .map(|(sandbox_id, _)| sandbox_id.clone()),
            Some(workspace) => self
                .by_workspace
                .get(workspace)?
                .range::<str, _>(range)
                .next()
                .cloned(),
        }
    }

    fn pop_queued(&mut self, lane: Lane) -> Option<DeliveryKey> {
        loop {
            let key = match lane {
                Lane::Sandbox => self.sandbox_keys.pop_front(),
                Lane::Fanout => self.fanout_retry.pop_front(),
            }?;
            if self
                .recipients
                .get(&key.sandbox_id)
                .is_some_and(|recipient| recipient.key(key.component).queued == Some(lane))
            {
                return Some(key);
            }
        }
    }

    fn start_build(&mut self, key: DeliveryKey, lane: Lane, now: Instant) -> Work {
        let seq = self.seq;
        let recipient = self
            .recipients
            .get_mut(&key.sandbox_id)
            .expect("started key has a recipient");
        let state = recipient.key_mut(key.component);
        self.queued.transition(state.queued, None);
        state.queued = None;
        state.in_flight = true;
        state.rollback_seq = state.last_build_seq;
        state.last_build_seq = seq;
        if let Some(since) = state.waiting_since.take() {
            histogram!(
                "openshell_supervisor_config_queue_wait_seconds",
                "lane" => lane.name(),
            )
            .record(now.saturating_duration_since(since).as_secs_f64());
        }
        *self.running.lane_mut(lane) += 1;
        Work::Build(BuildTicket {
            key,
            lane,
            session_id: recipient.session_id.clone(),
            epoch: recipient.epoch,
            seq,
        })
    }

    fn enqueue_key(
        &mut self,
        sandbox_id: &str,
        component: ConfigComponentKind,
        lane: Lane,
        now: Instant,
    ) {
        let Some(recipient) = self.recipients.get_mut(sandbox_id) else {
            return;
        };
        let state = recipient.key_mut(component);
        if lane == Lane::Sandbox && state.waiting_since.is_none() {
            state.waiting_since = Some(now);
        }
        if state.in_flight {
            state.requeue = state.requeue.max(Some(lane));
            return;
        }
        if state.queued.is_some_and(|queued| queued >= lane) {
            return;
        }
        self.queued.transition(state.queued, Some(lane));
        state.queued = Some(lane);
        let key = DeliveryKey {
            sandbox_id: sandbox_id.to_string(),
            component,
        };
        match lane {
            Lane::Sandbox => self.sandbox_keys.push_back(key),
            Lane::Fanout => self.fanout_retry.push_back(key),
        }
    }

    fn remove_recipient(&mut self, sandbox_id: &str) {
        let Some(recipient) = self.recipients.remove(sandbox_id) else {
            return;
        };
        self.queued
            .transition(recipient.sandbox_config.queued, None);
        self.queued
            .transition(recipient.provider_environment.queued, None);
        if let Some(sandboxes) = self.by_workspace.get_mut(&recipient.workspace) {
            sandboxes.remove(sandbox_id);
            if sandboxes.is_empty() {
                self.by_workspace.remove(&recipient.workspace);
            }
        }
    }
}

fn record_skip(component: ConfigComponentKind, reason: &'static str) {
    counter!(
        "openshell_supervisor_config_build_skips_total",
        "component" => component.name(),
        "reason" => reason,
    )
    .increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registration(sandbox_id: &str, workspace: &str, providers: &[&str]) -> Registration {
        Registration {
            sandbox_id: sandbox_id.to_string(),
            session_id: format!("{sandbox_id}-session"),
            workspace: workspace.to_string(),
            providers: providers.iter().map(ToString::to_string).collect(),
            captured_seq: 0,
            bootstrap_built: true,
        }
    }

    fn queue(builds: usize) -> DeliveryQueue {
        DeliveryQueue::new(Limits::new(builds, 2))
    }

    fn with_recipients(builds: usize, count: usize) -> DeliveryQueue {
        let mut queue = queue(builds);
        for index in 0..count {
            queue.register(
                registration(&format!("sb-{index:04}"), "ws", &[]),
                Instant::now(),
            );
        }
        queue
    }

    fn build(work: Work) -> BuildTicket {
        match work {
            Work::Build(ticket) => ticket,
            Work::PeerNotify(ticket) => panic!("expected a build, got {ticket:?}"),
        }
    }

    fn built() -> BuildOutcome {
        BuildOutcome::Built { providers: None }
    }

    /// Run all available work to completion, one ticket at a time.
    fn drain(queue: &mut DeliveryQueue) -> Vec<BuildTicket> {
        let mut completed = Vec::new();
        while let Some(work) = queue.next_work(Instant::now()) {
            match work {
                Work::Build(ticket) => {
                    queue.complete_build(&ticket, built(), Instant::now());
                    completed.push(ticket);
                }
                Work::PeerNotify(ticket) => queue.complete_peer_notify(&ticket),
            }
        }
        completed
    }

    fn sandbox_ids(tickets: &[BuildTicket]) -> Vec<&str> {
        tickets
            .iter()
            .map(|ticket| ticket.key.sandbox_id.as_str())
            .collect()
    }

    #[test]
    fn sandbox_update_starts_while_a_fleet_fanout_holds_its_slots() {
        let mut queue = with_recipients(4, 1000);
        queue.publish_fanout(
            &FanoutScope::AllConnected,
            ConfigComponents::SANDBOX_CONFIG,
            false,
            Instant::now(),
        );
        let mut fanout = Vec::new();
        while let Some(work) = queue.next_work(Instant::now()) {
            fanout.push(build(work));
        }
        assert_eq!(fanout.len(), 3, "fanout leaves the sandbox reserve free");
        assert!(fanout.iter().all(|ticket| ticket.lane == Lane::Fanout));

        assert!(queue.publish_sandbox("sb-0999", ConfigComponents::SANDBOX_CONFIG, Instant::now()));
        let sandbox_build = build(queue.next_work(Instant::now()).unwrap());
        assert_eq!(sandbox_build.key.sandbox_id, "sb-0999");
        assert_eq!(sandbox_build.lane, Lane::Sandbox);
    }

    #[test]
    fn sandbox_updates_never_freeze_a_fanout() {
        let mut queue = queue(4);
        for index in 0..100 {
            queue.register(
                registration(&format!("quiet-{index:03}"), "quiet", &[]),
                Instant::now(),
            );
            queue.register(
                registration(&format!("busy-{index:03}"), "busy", &[]),
                Instant::now(),
            );
        }
        queue.publish_fanout(
            &FanoutScope::Workspace("quiet".into()),
            ConfigComponents::SANDBOX_CONFIG,
            false,
            Instant::now(),
        );
        for index in 0..100 {
            queue.publish_sandbox(
                &format!("busy-{index:03}"),
                ConfigComponents::SANDBOX_CONFIG,
                Instant::now(),
            );
        }
        let lanes = (0..4)
            .map(|_| build(queue.next_work(Instant::now()).unwrap()).lane)
            .collect::<Vec<_>>();
        assert_eq!(
            lanes,
            [Lane::Sandbox, Lane::Sandbox, Lane::Sandbox, Lane::Fanout]
        );
    }

    #[test]
    fn repeated_updates_coalesce_without_rejection() {
        let mut queue = with_recipients(2, 50);
        for _ in 0..3 {
            for index in 0..50 {
                queue.publish_sandbox(
                    &format!("sb-{index:04}"),
                    ConfigComponents::ALL,
                    Instant::now(),
                );
            }
        }
        let completed = drain(&mut queue);
        assert_eq!(completed.len(), 100, "one build per sandbox component");
        let distinct = completed
            .iter()
            .map(|ticket| ticket.key.clone())
            .collect::<HashSet<_>>();
        assert_eq!(distinct.len(), 100);
    }

    #[test]
    fn publication_during_a_pass_costs_one_circle() {
        const RECIPIENTS: usize = 100;
        const BEFORE: usize = 30;
        let mut queue = with_recipients(2, RECIPIENTS);
        let scope = FanoutScope::AllConnected;
        queue.publish_fanout(
            &scope,
            ConfigComponents::SANDBOX_CONFIG,
            false,
            Instant::now(),
        );
        for _ in 0..BEFORE {
            let ticket = build(queue.next_work(Instant::now()).unwrap());
            queue.complete_build(&ticket, built(), Instant::now());
        }
        queue.publish_fanout(
            &scope,
            ConfigComponents::SANDBOX_CONFIG,
            false,
            Instant::now(),
        );
        let second = queue.current_seq();
        let completed = drain(&mut queue);

        assert_eq!(completed.len(), RECIPIENTS);
        assert_eq!(
            completed.first().unwrap().key.sandbox_id,
            format!("sb-{BEFORE:04}"),
            "the pass continues from its position"
        );
        assert!(
            queue
                .recipients
                .values()
                .all(|recipient| recipient.sandbox_config.last_build_seq >= second)
        );
        assert!(queue.cursors.is_empty());
    }

    #[test]
    fn wider_publication_replaces_narrower_passes() {
        let mut queue = queue(4);
        for (sandbox_id, workspace) in [("a", "ws-1"), ("b", "ws-1"), ("c", "ws-2")] {
            queue.register(registration(sandbox_id, workspace, &["p"]), Instant::now());
        }
        queue.publish_fanout(
            &FanoutScope::Provider {
                workspace: "ws-1".into(),
                name: "p".into(),
            },
            ConfigComponents::SANDBOX_CONFIG,
            false,
            Instant::now(),
        );
        queue.publish_fanout(
            &FanoutScope::Workspace("ws-1".into()),
            ConfigComponents::SANDBOX_CONFIG,
            false,
            Instant::now(),
        );
        queue.publish_fanout(
            &FanoutScope::AllConnected,
            ConfigComponents::SANDBOX_CONFIG,
            false,
            Instant::now(),
        );
        assert_eq!(queue.cursors.len(), 1);
        assert_eq!(sandbox_ids(&drain(&mut queue)), ["a", "b", "c"]);
    }

    #[test]
    fn overlapping_passes_build_each_sandbox_once() {
        let mut queue = with_recipients(4, 20);
        queue.publish_fanout(
            &FanoutScope::AllConnected,
            ConfigComponents::SANDBOX_CONFIG,
            false,
            Instant::now(),
        );
        queue.publish_fanout(
            &FanoutScope::Workspace("ws".into()),
            ConfigComponents::SANDBOX_CONFIG,
            false,
            Instant::now(),
        );
        assert_eq!(queue.cursors.len(), 2);
        assert_eq!(drain(&mut queue).len(), 20);
    }

    #[test]
    fn fanout_skips_a_sandbox_rebuilt_after_its_publication() {
        let mut queue = with_recipients(4, 3);
        queue.publish_fanout(
            &FanoutScope::AllConnected,
            ConfigComponents::SANDBOX_CONFIG,
            false,
            Instant::now(),
        );
        queue.publish_sandbox("sb-0002", ConfigComponents::SANDBOX_CONFIG, Instant::now());
        let completed = drain(&mut queue);
        assert_eq!(sandbox_ids(&completed), ["sb-0002", "sb-0000", "sb-0001"]);
    }

    #[test]
    fn publication_during_a_build_rebuilds_once_in_its_lane() {
        let mut queue = with_recipients(4, 1);
        queue.publish_sandbox("sb-0000", ConfigComponents::SANDBOX_CONFIG, Instant::now());
        let first = build(queue.next_work(Instant::now()).unwrap());
        queue.publish_fanout(
            &FanoutScope::AllConnected,
            ConfigComponents::SANDBOX_CONFIG,
            false,
            Instant::now(),
        );
        queue.publish_sandbox("sb-0000", ConfigComponents::SANDBOX_CONFIG, Instant::now());
        assert!(
            queue.next_work(Instant::now()).is_none(),
            "an in-flight key is not built twice concurrently"
        );
        queue.complete_build(&first, built(), Instant::now());
        let second = build(queue.next_work(Instant::now()).unwrap());
        assert_eq!(second.lane, Lane::Sandbox);
        queue.complete_build(&second, built(), Instant::now());
        assert!(drain(&mut queue).is_empty());
    }

    #[test]
    fn failed_build_restores_its_sequence() {
        let mut queue = with_recipients(4, 1);
        queue.publish_sandbox("sb-0000", ConfigComponents::SANDBOX_CONFIG, Instant::now());
        let ticket = build(queue.next_work(Instant::now()).unwrap());
        queue.complete_build(&ticket, BuildOutcome::Failed, Instant::now());
        assert!(queue.next_work(Instant::now()).is_none());

        queue.publish_fanout(
            &FanoutScope::AllConnected,
            ConfigComponents::SANDBOX_CONFIG,
            false,
            Instant::now(),
        );
        assert_eq!(drain(&mut queue).len(), 1);
    }

    #[test]
    fn failed_build_retries_when_a_fanout_skipped_it_as_current() {
        let mut queue = with_recipients(4, 1);
        queue.publish_fanout(
            &FanoutScope::AllConnected,
            ConfigComponents::SANDBOX_CONFIG,
            false,
            Instant::now(),
        );
        queue.publish_sandbox("sb-0000", ConfigComponents::SANDBOX_CONFIG, Instant::now());
        let ticket = build(queue.next_work(Instant::now()).unwrap());
        assert_eq!(ticket.lane, Lane::Sandbox);
        assert!(queue.next_work(Instant::now()).is_none());
        queue.complete_build(&ticket, BuildOutcome::Failed, Instant::now());
        let retry = build(queue.next_work(Instant::now()).unwrap());
        assert_eq!(retry.lane, Lane::Fanout);
    }

    #[test]
    fn bootstrap_covers_registration_until_a_publication_races_it() {
        let mut queue = queue(4);
        let captured = queue.current_seq();
        queue.register(
            Registration {
                captured_seq: captured,
                ..registration("fresh", "ws", &[])
            },
            Instant::now(),
        );
        queue.publish_fanout(
            &FanoutScope::Workspace("other".into()),
            ConfigComponents::SANDBOX_CONFIG,
            false,
            Instant::now(),
        );
        assert!(drain(&mut queue).is_empty());

        let captured = queue.current_seq();
        queue.publish_sandbox(
            "unrelated",
            ConfigComponents::SANDBOX_CONFIG,
            Instant::now(),
        );
        queue.register(
            Registration {
                captured_seq: captured,
                ..registration("raced", "ws", &[])
            },
            Instant::now(),
        );
        let completed = drain(&mut queue);
        assert_eq!(completed.len(), 2);
        assert!(completed.iter().all(|ticket| ticket.lane == Lane::Sandbox));
    }

    #[test]
    fn provider_pass_builds_only_attached_sandboxes() {
        let mut queue = queue(4);
        queue.register(registration("attached", "ws", &["github"]), Instant::now());
        queue.register(registration("other", "ws", &["gitlab"]), Instant::now());
        queue.register(
            registration("elsewhere", "ws-2", &["github"]),
            Instant::now(),
        );
        queue.publish_fanout(
            &FanoutScope::Provider {
                workspace: "ws".into(),
                name: "github".into(),
            },
            ConfigComponents::ALL,
            false,
            Instant::now(),
        );
        let completed = drain(&mut queue);
        assert_eq!(completed.len(), 2);
        assert!(
            completed
                .iter()
                .all(|ticket| ticket.key.sandbox_id == "attached")
        );
    }

    #[test]
    fn provider_pass_includes_an_attachment_still_being_built() {
        let mut queue = queue(4);
        queue.register(registration("sb", "ws", &[]), Instant::now());
        queue.publish_sandbox("sb", ConfigComponents::SANDBOX_CONFIG, Instant::now());
        let attach = build(queue.next_work(Instant::now()).unwrap());
        queue.publish_fanout(
            &FanoutScope::Provider {
                workspace: "ws".into(),
                name: "github".into(),
            },
            ConfigComponents::SANDBOX_CONFIG,
            false,
            Instant::now(),
        );
        assert!(queue.next_work(Instant::now()).is_none());
        queue.complete_build(
            &attach,
            BuildOutcome::Built {
                providers: Some(HashSet::from(["github".to_string()])),
            },
            Instant::now(),
        );
        assert_eq!(sandbox_ids(&drain(&mut queue)), ["sb"]);

        queue.publish_fanout(
            &FanoutScope::Provider {
                workspace: "ws".into(),
                name: "github".into(),
            },
            ConfigComponents::SANDBOX_CONFIG,
            false,
            Instant::now(),
        );
        assert_eq!(
            sandbox_ids(&drain(&mut queue)),
            ["sb"],
            "the refreshed attachment cache keeps the sandbox in scope"
        );
    }

    #[test]
    fn late_build_does_not_roll_back_the_attachment_cache() {
        let mut queue = queue(4);
        queue.register(registration("sb", "ws", &[]), Instant::now());
        queue.publish_sandbox("sb", ConfigComponents::SANDBOX_CONFIG, Instant::now());
        let before_attach = build(queue.next_work(Instant::now()).unwrap());
        queue.publish_sandbox("sb", ConfigComponents::ALL, Instant::now());
        let after_attach = build(queue.next_work(Instant::now()).unwrap());
        assert_eq!(
            after_attach.key.component,
            ConfigComponentKind::ProviderEnvironment
        );
        queue.complete_build(
            &after_attach,
            BuildOutcome::Built {
                providers: Some(HashSet::from(["github".to_string()])),
            },
            Instant::now(),
        );
        queue.complete_build(
            &before_attach,
            BuildOutcome::Built {
                providers: Some(HashSet::new()),
            },
            Instant::now(),
        );
        queue.publish_fanout(
            &FanoutScope::Provider {
                workspace: "ws".into(),
                name: "github".into(),
            },
            ConfigComponents::ALL,
            false,
            Instant::now(),
        );
        let components = drain(&mut queue)
            .into_iter()
            .map(|ticket| ticket.key.component)
            .collect::<HashSet<_>>();
        assert!(
            components.contains(&ConfigComponentKind::ProviderEnvironment),
            "the provider pass must reach the attached sandbox"
        );
    }

    #[test]
    fn fanout_floor_releases_when_fanout_has_nothing_to_start() {
        let mut queue = queue(4);
        for index in 0..4 {
            queue.register(
                registration(&format!("busy-{index}"), "busy", &[]),
                Instant::now(),
            );
        }
        queue.publish_fanout(
            &FanoutScope::Workspace("empty".into()),
            ConfigComponents::SANDBOX_CONFIG,
            false,
            Instant::now(),
        );
        for index in 0..4 {
            queue.publish_sandbox(
                &format!("busy-{index}"),
                ConfigComponents::SANDBOX_CONFIG,
                Instant::now(),
            );
        }
        let lanes = (0..4)
            .map(|_| build(queue.next_work(Instant::now()).unwrap()).lane)
            .collect::<Vec<_>>();
        assert_eq!(lanes, [Lane::Sandbox; 4]);
    }

    #[test]
    fn remote_sandbox_updates_coalesce_into_one_peer_notification() {
        let mut queue = queue(4);
        assert!(!queue.publish_sandbox("remote", ConfigComponents::SANDBOX_CONFIG, Instant::now()));
        queue.notify_peer(
            PeerNotifyTarget::Sandbox("remote".into()),
            ConfigComponents::SANDBOX_CONFIG,
        );
        queue.notify_peer(
            PeerNotifyTarget::Sandbox("remote".into()),
            ConfigComponents {
                sandbox_config: false,
                provider_environment: true,
            },
        );
        let Some(Work::PeerNotify(ticket)) = queue.next_work(Instant::now()) else {
            panic!("expected a peer notification");
        };
        assert_eq!(ticket.components, ConfigComponents::ALL);
        assert!(queue.next_work(Instant::now()).is_none());

        queue.notify_peer(
            PeerNotifyTarget::Sandbox("remote".into()),
            ConfigComponents::SANDBOX_CONFIG,
        );
        assert!(queue.next_work(Instant::now()).is_none());
        queue.complete_peer_notify(&ticket);
        let Some(Work::PeerNotify(again)) = queue.next_work(Instant::now()) else {
            panic!("an update during a peer notification notifies again");
        };
        assert_eq!(again.components, ConfigComponents::SANDBOX_CONFIG);
        queue.complete_peer_notify(&again);
        assert!(queue.peer_notifies.is_empty());
    }

    #[test]
    fn local_fanout_notifies_peers_once_per_publication() {
        let mut queue = queue(4);
        let scope = FanoutScope::Workspace("ws".into());
        queue.publish_fanout(
            &scope,
            ConfigComponents::SANDBOX_CONFIG,
            true,
            Instant::now(),
        );
        queue.publish_fanout(&scope, ConfigComponents::ALL, true, Instant::now());
        let Some(Work::PeerNotify(ticket)) = queue.next_work(Instant::now()) else {
            panic!("expected a peer notification");
        };
        assert_eq!(ticket.target, PeerNotifyTarget::Peers(scope));
        assert_eq!(ticket.components, ConfigComponents::ALL);
        queue.complete_peer_notify(&ticket);
        assert!(queue.next_work(Instant::now()).is_none());
    }

    #[test]
    fn replaced_or_removed_sessions_drop_their_work() {
        let mut queue = with_recipients(4, 1);
        queue.publish_sandbox("sb-0000", ConfigComponents::SANDBOX_CONFIG, Instant::now());
        let stale = build(queue.next_work(Instant::now()).unwrap());
        queue.register(registration("sb-0000", "ws", &[]), Instant::now());
        queue.publish_sandbox("sb-0000", ConfigComponents::SANDBOX_CONFIG, Instant::now());
        queue.complete_build(&stale, built(), Instant::now());
        let current = build(queue.next_work(Instant::now()).unwrap());
        assert_ne!(current.epoch, stale.epoch);

        queue.publish_sandbox("sb-0000", ConfigComponents::SANDBOX_CONFIG, Instant::now());
        queue.unregister("sb-0000", "other-session");
        assert!(queue.recipients.contains_key("sb-0000"));
        queue.unregister("sb-0000", "sb-0000-session");
        queue.complete_build(&current, built(), Instant::now());
        assert!(queue.next_work(Instant::now()).is_none());
        assert!(!queue.has_running_work());
        assert!(queue.by_workspace.is_empty());
        assert_eq!((queue.queued.sandbox, queue.queued.fanout), (0, 0));
    }

    #[test]
    fn limits_keep_both_lanes_schedulable() {
        assert_eq!(Limits::new(0, 0), Limits::new(2, 1));
        let small = Limits::new(2, 1);
        assert_eq!((small.builds, small.sandbox_reserve), (2, 1));
        let large = Limits::new(20, 8);
        assert_eq!((large.builds, large.sandbox_reserve), (20, 5));
    }
}
