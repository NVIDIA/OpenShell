// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Serialized persistence of supervisor results for running workloads.
//!
//! Persisting a configuration admission or a sandbox policy result takes the
//! compute sandbox lock, which user mutations such as `UpdateConfig` and
//! provider attachment also take. A fanout acknowledged by N sessions at once
//! would queue N waiters ahead of any user write on that FIFO lock.
//!
//! Once a workload runs, its admission no longer gates startup, so results
//! for running workloads are queued here and written by one task. A user
//! write then waits for at most one result write, and repeated admissions for
//! one sandbox collapse into the newest. Policy results are all kept, because
//! each one settles the status of its own policy revision.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use metrics::{counter, gauge};
use openshell_core::proto::SandboxConfigurationAdmission;
use tracing::{debug, warn};

use crate::ServerState;

/// Attempts per queued write before it is dropped.
const MAX_WRITE_ATTEMPTS: u32 = 5;
/// Delay before retrying a failed write, so a struggling store is not hammered.
const RETRY_DELAY: Duration = Duration::from_millis(500);

/// A sandbox policy load result reported by a supervisor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PolicyResult {
    pub(super) version: u32,
    pub(super) loaded: bool,
    pub(super) error: Option<String>,
}

#[derive(Debug)]
struct QueuedAdmission {
    session_id: String,
    instance_id: String,
    admission: SandboxConfigurationAdmission,
    attempts: u32,
}

#[derive(Debug)]
struct QueuedPolicyResult {
    result: PolicyResult,
    attempts: u32,
}

#[derive(Debug, Default)]
struct PendingWrites {
    admission: Option<QueuedAdmission>,
    policy_results: Vec<QueuedPolicyResult>,
}

#[derive(Debug, Default)]
struct Queue {
    running: bool,
    order: VecDeque<String>,
    pending: HashMap<String, PendingWrites>,
}

impl Queue {
    fn entry(&mut self, sandbox_id: &str) -> &mut PendingWrites {
        if !self.pending.contains_key(sandbox_id) {
            self.order.push_back(sandbox_id.to_string());
        }
        self.pending.entry(sandbox_id.to_string()).or_default()
    }

    /// Mark the writer running, returning whether the caller must start it.
    fn claim_start(&mut self) -> bool {
        !std::mem::replace(&mut self.running, true)
    }

    fn report_pending(&self) {
        let pending = u32::try_from(self.pending.len()).unwrap_or(u32::MAX);
        gauge!("openshell_supervisor_config_result_writes_pending").set(f64::from(pending));
    }
}

/// Queue of result writes drained by a single task.
#[derive(Debug, Default)]
pub struct ResultWriter {
    queue: Mutex<Queue>,
}

impl ResultWriter {
    fn queue(&self) -> std::sync::MutexGuard<'_, Queue> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }

    #[cfg(test)]
    pub(super) fn is_idle(&self) -> bool {
        let queue = self.queue();
        !queue.running && queue.pending.is_empty()
    }
}

/// Queue the newest admission of a running workload's session.
pub(super) fn queue_admission(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    session_id: &str,
    instance_id: &str,
    admission: &SandboxConfigurationAdmission,
) {
    let writer = &state.config_delivery.results;
    let start = {
        let mut queue = writer.queue();
        let entry = queue.entry(sandbox_id);
        if entry
            .admission
            .replace(QueuedAdmission {
                session_id: session_id.to_string(),
                instance_id: instance_id.to_string(),
                admission: admission.clone(),
                attempts: 0,
            })
            .is_some()
        {
            counter!(
                "openshell_supervisor_config_result_writes_total",
                "kind" => "admission",
                "outcome" => "coalesced",
            )
            .increment(1);
        }
        queue.report_pending();
        queue.claim_start()
    };
    if start {
        tokio::spawn(run(Arc::clone(state)));
    }
}

/// Queue a sandbox policy load result.
pub(super) fn queue_policy_result(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    result: PolicyResult,
) {
    let writer = &state.config_delivery.results;
    let start = {
        let mut queue = writer.queue();
        queue
            .entry(sandbox_id)
            .policy_results
            .push(QueuedPolicyResult {
                result,
                attempts: 0,
            });
        queue.report_pending();
        queue.claim_start()
    };
    if start {
        tokio::spawn(run(Arc::clone(state)));
    }
}

async fn run(state: Arc<ServerState>) {
    loop {
        let next = {
            let mut queue = state.config_delivery.results.queue();
            let next = queue.order.pop_front().and_then(|sandbox_id| {
                queue
                    .pending
                    .remove(&sandbox_id)
                    .map(|pending| (sandbox_id, pending))
            });
            queue.report_pending();
            if next.is_none() {
                queue.running = false;
            }
            next
        };
        let Some((sandbox_id, pending)) = next else {
            return;
        };
        let retry = write(&state, &sandbox_id, pending).await;
        if !retry.policy_results.is_empty() || retry.admission.is_some() {
            tokio::time::sleep(RETRY_DELAY).await;
            requeue(&state, &sandbox_id, retry);
        }
    }
}

/// Write one sandbox's pending results, returning the writes to retry.
async fn write(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    pending: PendingWrites,
) -> PendingWrites {
    let mut retry = PendingWrites::default();
    for mut queued in pending.policy_results {
        let result = &queued.result;
        match crate::grpc::policy::record_policy_apply_result(
            state,
            sandbox_id,
            result.version,
            result.loaded,
            result.error.as_deref(),
            "stream",
        )
        .await
        {
            Ok(()) => record_write("policy_result", "written"),
            Err(error) if error.code() == tonic::Code::NotFound => {
                // The sandbox or its revision is gone; nothing left to record.
                debug!(sandbox_id, version = result.version, error = %error, "dropped policy result for a missing revision");
                record_write("policy_result", "dropped");
            }
            Err(error) => {
                queued.attempts += 1;
                if queued.attempts < MAX_WRITE_ATTEMPTS {
                    record_write("policy_result", "retried");
                    retry.policy_results.push(queued);
                } else {
                    warn!(sandbox_id, version = result.version, error = %error, "failed to persist supervisor policy result");
                    record_write("policy_result", "dropped");
                }
            }
        }
    }
    if let Some(mut queued) = pending.admission {
        if !state
            .supervisor_sessions
            .is_current_session(sandbox_id, &queued.session_id)
        {
            // A newer session reports its own admission.
            record_write("admission", "stale_session");
            return retry;
        }
        match state
            .compute
            .supervisor_session_admission(sandbox_id, &queued.instance_id, &queued.admission)
            .await
        {
            Ok(()) => record_write("admission", "written"),
            Err(error) => {
                queued.attempts += 1;
                if queued.attempts < MAX_WRITE_ATTEMPTS {
                    record_write("admission", "retried");
                    retry.admission = Some(queued);
                } else {
                    warn!(sandbox_id, session_id = %queued.session_id, error = %error, "failed to persist supervisor configuration admission");
                    record_write("admission", "dropped");
                }
            }
        }
    }
    retry
}

/// Requeue failed writes behind anything queued since, keeping a newer
/// admission over the retried one.
fn requeue(state: &Arc<ServerState>, sandbox_id: &str, retry: PendingWrites) {
    let mut queue = state.config_delivery.results.queue();
    let entry = queue.entry(sandbox_id);
    if entry.admission.is_none() {
        entry.admission = retry.admission;
    }
    let newer = std::mem::take(&mut entry.policy_results);
    entry.policy_results = retry.policy_results;
    entry.policy_results.extend(newer);
    // The writer task is still running, so it drains the requeued entry.
}

fn record_write(kind: &'static str, outcome: &'static str) {
    counter!(
        "openshell_supervisor_config_result_writes_total",
        "kind" => kind,
        "outcome" => outcome,
    )
    .increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_keeps_first_seen_order_and_one_entry_per_sandbox() {
        let mut queue = Queue::default();
        queue.entry("a").policy_results.push(QueuedPolicyResult {
            result: PolicyResult {
                version: 1,
                loaded: true,
                error: None,
            },
            attempts: 0,
        });
        queue.entry("b");
        queue.entry("a").policy_results.push(QueuedPolicyResult {
            result: PolicyResult {
                version: 2,
                loaded: true,
                error: None,
            },
            attempts: 0,
        });
        assert_eq!(
            queue.order,
            VecDeque::from(["a".to_string(), "b".to_string()])
        );
        assert_eq!(queue.pending["a"].policy_results.len(), 2);
    }

    #[test]
    fn claim_start_returns_true_only_for_the_first_caller() {
        let mut queue = Queue::default();
        assert!(queue.claim_start());
        assert!(!queue.claim_start());
    }
}
