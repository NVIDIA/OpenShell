// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Build capacity shared by all push sessions.
//!
//! Builds wait on store round trips, so capacity follows the store's
//! connection pool. Part of it is reserved for sandbox-scoped builds (one
//! sandbox's change, an initial snapshot, a repair), so a fleet-wide change
//! never starves them. Shared capacity goes first to waiting sandbox-scoped
//! builds, then to fleet-wide builds round-robin by workspace, so one
//! workspace's fleet-wide change does not wait behind another workspace's
//! whole pass. Each waiting session holds at most one queue entry.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};

use tokio::sync::oneshot;

use crate::gateway_metrics::BuildLane;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Reserved,
    Shared,
}

#[derive(Debug)]
struct State {
    reserved_free: usize,
    shared_free: usize,
    sandbox: VecDeque<oneshot::Sender<BuildPermit>>,
    fanout: BTreeMap<String, VecDeque<oneshot::Sender<BuildPermit>>>,
    /// Workspace served last by shared capacity.
    cursor: Option<String>,
}

impl State {
    fn next_fanout(&mut self) -> Option<oneshot::Sender<BuildPermit>> {
        let workspace = self
            .cursor
            .as_ref()
            .and_then(|cursor| {
                self.fanout
                    .range::<String, _>((
                        std::ops::Bound::Excluded(cursor),
                        std::ops::Bound::Unbounded,
                    ))
                    .next()
            })
            .or_else(|| self.fanout.iter().next())
            .map(|(workspace, _)| workspace.clone())?;
        let queue = self.fanout.get_mut(&workspace)?;
        let waiter = queue.pop_front();
        if queue.is_empty() {
            self.fanout.remove(&workspace);
        }
        self.cursor = Some(workspace);
        waiter
    }

    /// The waiter that gets a released permit, or `None` after returning
    /// the permit to the pool.
    fn hand_off(&mut self, kind: Kind) -> Option<oneshot::Sender<BuildPermit>> {
        if let Some(waiter) = self.sandbox.pop_front() {
            return Some(waiter);
        }
        if kind == Kind::Shared
            && let Some(waiter) = self.next_fanout()
        {
            return Some(waiter);
        }
        match kind {
            Kind::Reserved => self.reserved_free += 1,
            Kind::Shared => self.shared_free += 1,
        }
        None
    }
}

#[derive(Debug)]
pub struct BuildScheduler {
    state: Mutex<State>,
}

/// Permission to run one build. Dropping it frees the capacity.
#[derive(Debug)]
pub struct BuildPermit {
    scheduler: Option<Arc<BuildScheduler>>,
    kind: Kind,
}

impl Drop for BuildPermit {
    fn drop(&mut self) {
        if let Some(scheduler) = self.scheduler.take() {
            scheduler.release(self.kind);
        }
    }
}

impl BuildScheduler {
    /// Capacity sized from a store with `pool_size` connections. Builds
    /// fan out several reads each, so they may use at most half the pool and
    /// leave the rest to request handlers.
    pub fn for_pool(pool_size: usize) -> Arc<Self> {
        let total = (pool_size / 2).max(2);
        let reserved = (total / 4).max(1);
        Self::new(reserved, total - reserved)
    }

    pub fn new(reserved: usize, shared: usize) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                reserved_free: reserved,
                shared_free: shared,
                sandbox: VecDeque::new(),
                fanout: BTreeMap::new(),
                cursor: None,
            }),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Wait for capacity for a build in `lane` for a sandbox in `workspace`.
    /// Dropping the future gives up its place.
    pub async fn acquire(self: &Arc<Self>, lane: BuildLane, workspace: &str) -> BuildPermit {
        let receiver = {
            let mut state = self.lock();
            let available = match lane {
                BuildLane::Sandbox if state.reserved_free > 0 => {
                    state.reserved_free -= 1;
                    Some(Kind::Reserved)
                }
                _ if state.shared_free > 0 => {
                    state.shared_free -= 1;
                    Some(Kind::Shared)
                }
                _ => None,
            };
            if let Some(kind) = available {
                return BuildPermit {
                    scheduler: Some(self.clone()),
                    kind,
                };
            }
            let (sender, receiver) = oneshot::channel();
            match lane {
                BuildLane::Sandbox => state.sandbox.push_back(sender),
                BuildLane::Fanout => state
                    .fanout
                    .entry(workspace.to_string())
                    .or_default()
                    .push_back(sender),
            }
            receiver
        };
        // A permit is only handed off with the scheduler alive, so the
        // sender is never dropped without sending.
        receiver
            .await
            .expect("build scheduler hands off every permit")
    }

    fn release(self: &Arc<Self>, kind: Kind) {
        loop {
            let Some(waiter) = self.lock().hand_off(kind) else {
                return;
            };
            let permit = BuildPermit {
                scheduler: Some(self.clone()),
                kind,
            };
            match waiter.send(permit) {
                Ok(()) => return,
                // The waiter gave up. Offer the permit to the next one
                // without recursing through `Drop`.
                Err(mut permit) => {
                    permit.scheduler = None;
                }
            }
        }
    }

    #[cfg(test)]
    pub fn waiting(&self) -> usize {
        let state = self.lock();
        state.sandbox.len() + state.fanout.values().map(VecDeque::len).sum::<usize>()
    }
}
