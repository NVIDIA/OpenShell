// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway-owned coordination of the shared supervisor pool.
//!
//! The gateway constructs a [`SharedSupervision`] and hands it to the compute
//! driver that provisions the host's sandbox instances. The driver supplies
//! each instance's registration and operations over its own durable records;
//! this module owns the contracts those operations are sequenced by: launch
//! material is persisted before an instance is assigned, a recovery baseline
//! is captured before the driver lists its records, an incomplete recovery
//! never replaces the published set, and the host's observations are
//! interpreted in one place. The driver keeps everything that is specific to
//! its infrastructure: where the records live, how its workloads reach the
//! host, and which of its own objects must exist for an instance to count as
//! supervised.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::watch;

use crate::controller::{
    AssignmentError, ObservedInstance, SupervisorCredential, SupervisorHostController,
};
use crate::registration::{RegistrationError, SandboxInstanceRegistration};
use crate::status::SandboxInstanceStatusReport;

/// Interval at which [`SharedSupervision::wait_for_ready`] re-reads the
/// host's observations.
const READINESS_POLL: Duration = Duration::from_secs(1);
/// Age, before a driver recovery began listing, past which a pool record the
/// listing omits is withdrawn.
///
/// Younger records may come from a launch the listing raced on another
/// gateway replica, whose clock may also differ.
const RECOVERY_PRUNE_MARGIN: Duration = Duration::from_mins(1);

/// Why a launch was not assigned.
#[derive(Debug, thiserror::Error)]
pub enum LaunchError<E> {
    /// The registration is not valid; nothing was persisted or assigned.
    #[error("{0}")]
    Invalid(RegistrationError),
    /// The driver could not persist the launch material; nothing was assigned.
    #[error("{0}")]
    Persist(E),
    /// The host is at capacity. The material was persisted; the caller rolls
    /// the generation back before its workload runs.
    #[error("{0}")]
    Refused(AssignmentError),
    /// The pool could not place the instance: it is not ready, no member is
    /// attached or has room, or its records could not be read or written.
    /// The material was persisted; the caller rolls the generation back
    /// before its workload runs.
    #[error("{0}")]
    Unplaced(String),
}

/// A new pool instance to record durably before it is assigned.
#[derive(Clone, PartialEq, Eq)]
pub struct PlacementRequest {
    /// The instance's assignment, launch material included.
    pub assignment: crate::proto::SandboxInstanceAssignment,
    /// Credential epoch of the launch credentials.
    pub auth_epoch: u64,
}

impl std::fmt::Debug for PlacementRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PlacementRequest")
            .field("route", &self.assignment.route)
            .field("sandbox_id", &self.assignment.sandbox_id)
            .field("generation", &self.assignment.generation)
            .field("auth_epoch", &self.auth_epoch)
            .finish_non_exhaustive()
    }
}

/// Outcome of one durable pool operation.
pub type PlacementFuture<T = ()> = Pin<Box<dyn Future<Output = Result<T, String>> + Send>>;

/// The gateway's durable records of a supervisor pool's instances.
///
/// Installed by the gateway before instances launch, they make the pool's
/// desired set, ownership, and launch material available to every gateway
/// replica, whichever replica launched an instance or runs the compute
/// driver's watch.
pub trait InstancePlacement: Send + Sync + std::fmt::Debug {
    /// Durably record a new instance, launch material included, and the
    /// owner of its launch term: the pool member the consistent-hash ring
    /// prefers among live members with room, and its current process. Fails
    /// when no live member has room.
    fn place_launch(&self, request: PlacementRequest) -> PlacementFuture;

    /// Routes of the durably recorded instances, with when each was
    /// published (Unix milliseconds).
    fn recorded(&self) -> PlacementFuture<BTreeMap<String, i64>>;

    /// Durably record an instance a driver recovery found without a record,
    /// such as one launched before the host became a pool; the pool places
    /// it, fencing whichever process may supervise it.
    fn record_recovered(
        &self,
        assignment: crate::proto::SandboxInstanceAssignment,
    ) -> PlacementFuture;
}

/// When a recovery began, read before the driver listed its durable records.
///
/// A pool record published after it may come from a launch the listing raced,
/// so it is never withdrawn for missing from the listing.
#[must_use = "complete the recovery with the records listed after this baseline was read"]
pub struct RecoveryBaseline {
    /// When the baseline was read (Unix milliseconds).
    read_at_ms: i64,
}

/// A generation that may run on the shared supervisor, as the driver's
/// durable records describe it, with the record the driver needs to read its
/// persisted launch material.
pub struct RecoverableInstance<R> {
    pub route: String,
    pub sandbox_id: String,
    pub record: R,
}

/// Result of a recovery pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryOutcome {
    /// The records match the listing; carries the desired revision in force.
    Published(u64),
    /// The gateway has not installed its records yet, launch material could
    /// not be read or does not match its record, or a record could not be
    /// written; the next pass tries again.
    Kept,
}

/// What the host's observations say about one instance's supervision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceSupervision {
    /// The host supervises the instance and the gateway accepts it.
    Available,
    /// The host has not reconciled to the assigning snapshot yet, or hosts
    /// the instance but it is still starting.
    Degraded,
    /// The host reconciled past the assignment and does not host the
    /// instance, hosts it for another sandbox, or reports it ended.
    Unavailable,
    /// No host is connected, so nothing is known.
    Unknown,
}

/// The gateway's coordination of the shared supervisor pool: the desired set
/// it publishes, the token it delivers, and the observations it reads back.
///
/// Clones share one controller. The gateway keeps one for serving the host's
/// stream and minting its token, and gives one to the compute driver.
#[derive(Clone, Debug, Default)]
pub struct SharedSupervision {
    controller: SupervisorHostController,
}

impl SharedSupervision {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Offer each instance's runtime `recovery_timeout_secs` instead of
    /// [`POOL_RECOVERY_TIMEOUT_SECS`](crate::controller::POOL_RECOVERY_TIMEOUT_SECS).
    /// The gateway also installs its durable records with
    /// [`SupervisorHostController::install_placement`] before instances
    /// launch.
    pub fn set_recovery_timeout_secs(&self, recovery_timeout_secs: u32) {
        self.controller
            .set_recovery_timeout_secs(recovery_timeout_secs);
    }

    /// The controller the gateway serves to the host and publishes the
    /// supervisor token into.
    #[must_use]
    pub fn controller(&self) -> &SupervisorHostController {
        &self.controller
    }

    /// The current supervisor token and every renewal after it, for the
    /// driver to deliver to the host (see
    /// [`deliver_credentials`](crate::credential::deliver_credentials)).
    #[must_use]
    pub fn credentials(&self) -> watch::Receiver<Option<SupervisorCredential>> {
        self.controller.credential()
    }

    /// Register a generation's sandbox instance: validate `registration`,
    /// persist its encoded launch material through `persist`, and only then
    /// assign the instance so the host starts it. The launch material is
    /// persisted first so a restarted gateway recovers the assignment from the
    /// generation's own records. The pool records the instance durably for
    /// every gateway replica, on a live member with room; without one the
    /// launch fails as [`LaunchError::Unplaced`], and beyond the pool's
    /// capacity as [`LaunchError::Refused`], so the caller fails its create
    /// before the workload runs. An identical assignment changes nothing.
    pub async fn launch<E, F>(
        &self,
        registration: &SandboxInstanceRegistration,
        persist: impl FnOnce(Vec<u8>) -> F + Send,
    ) -> Result<(), LaunchError<E>>
    where
        E: Send,
        F: Future<Output = Result<(), E>> + Send,
    {
        registration.validate().map_err(LaunchError::Invalid)?;
        let assignment = registration.to_assignment().map_err(LaunchError::Invalid)?;
        persist(assignment.launch_material.clone())
            .await
            .map_err(LaunchError::Persist)?;
        // The instance and the owner of its launch term are durable before
        // any member is assigned it, so every gateway replica serves it and a
        // later failure of that member is recovered by takeover.
        let Some(placement) = self.controller.placement() else {
            const NOT_READY: &str = "the supervisor pool is not ready to place sandbox instances";
            tracing::warn!(route = %registration.route, "{NOT_READY}");
            return Err(LaunchError::Unplaced(NOT_READY.to_string()));
        };
        if let Err(error) = placement
            .place_launch(PlacementRequest {
                assignment: assignment.clone(),
                auth_epoch: registration.auth.auth_epoch.get(),
            })
            .await
        {
            tracing::warn!(
                route = %registration.route,
                sandbox_id = %registration.sandbox_id,
                %error,
                "could not place a shared sandbox instance in the supervisor pool"
            );
            return Err(LaunchError::Unplaced(error));
        }
        let route = assignment.route.clone();
        self.controller.assign(assignment).map_err(|error| {
            // A refused instance must not stay desired durably.
            self.controller.unassign(&route);
            LaunchError::Refused(error)
        })
    }

    /// Withdraw a generation's sandbox instance so its owner stops it. The
    /// gateway removes the instance's durable record right after.
    pub fn withdraw(&self, route: &str) {
        self.controller.unassign(route);
    }

    /// Start a recovery pass. Call it before listing the durable records the
    /// pass derives the desired set from, so a lifecycle edit that lands
    /// during the list is detected by [`Self::complete_recovery`] instead of
    /// being undone.
    pub fn begin_recovery(&self) -> RecoveryBaseline {
        RecoveryBaseline {
            read_at_ms: unix_millis(),
        }
    }

    /// Reconcile the pool's durable records, which are the desired set every
    /// gateway replica serves, with `candidates`, the generations that may run
    /// according to the records the driver listed after `baseline` was read.
    /// A candidate without a record is recorded from its launch material,
    /// read by `read` from the driver's record (`None` when it is gone);
    /// material is decoded without quoting values, bound to the recorded route
    /// and sandbox, and validated. A record the listing omits is withdrawn
    /// when it was published before the listing. Until the gateway installs
    /// its records, or when a read fails or material is unusable, the pass
    /// reports [`RecoveryOutcome::Kept`].
    pub async fn complete_recovery<R, E, F>(
        &self,
        baseline: RecoveryBaseline,
        candidates: Vec<RecoverableInstance<R>>,
        read: impl Fn(&R) -> F + Send + Sync,
    ) -> RecoveryOutcome
    where
        R: Send + Sync,
        E: Display,
        F: Future<Output = Result<Option<Vec<u8>>, E>> + Send,
    {
        self.reconcile_pool(&baseline, &candidates, read).await
    }

    /// Reconcile a pool's durable records with the generations a driver
    /// recovery listed after `baseline`.
    async fn reconcile_pool<R, E, F>(
        &self,
        baseline: &RecoveryBaseline,
        candidates: &[RecoverableInstance<R>],
        read: impl Fn(&R) -> F + Send + Sync,
    ) -> RecoveryOutcome
    where
        R: Send + Sync,
        E: Display,
        F: Future<Output = Result<Option<Vec<u8>>, E>> + Send,
    {
        let Some(placement) = self.controller.placement() else {
            return RecoveryOutcome::Kept;
        };
        let recorded = match placement.recorded().await {
            Ok(recorded) => recorded,
            Err(error) => {
                tracing::warn!(%error, "could not list the supervisor pool's instances; recovery skipped");
                return RecoveryOutcome::Kept;
            }
        };
        let mut outcome = RecoveryOutcome::Published(self.controller.revision());
        for candidate in candidates {
            if recorded.contains_key(&candidate.route) {
                continue;
            }
            let assignment = match read(&candidate.record).await {
                Ok(Some(material)) => recovered_assignment(candidate, &material),
                Ok(None) => continue,
                Err(error) => {
                    tracing::warn!(
                        sandbox_id = %candidate.sandbox_id,
                        route = %candidate.route,
                        %error,
                        "could not read shared sandbox instance launch material"
                    );
                    outcome = RecoveryOutcome::Kept;
                    continue;
                }
            };
            let recorded = match assignment {
                Ok(assignment) => placement.record_recovered(assignment).await,
                Err(error) => Err(error.to_string()),
            };
            if let Err(error) = recorded {
                tracing::warn!(
                    sandbox_id = %candidate.sandbox_id,
                    route = %candidate.route,
                    %error,
                    "could not record a recovered shared sandbox instance in the supervisor pool"
                );
                outcome = RecoveryOutcome::Kept;
            }
        }
        let listed = candidates
            .iter()
            .map(|candidate| candidate.route.as_str())
            .collect::<BTreeSet<_>>();
        let margin = i64::try_from(RECOVERY_PRUNE_MARGIN.as_millis()).unwrap_or(i64::MAX);
        for (route, published_at_ms) in &recorded {
            if !listed.contains(route.as_str())
                && *published_at_ms < baseline.read_at_ms.saturating_sub(margin)
            {
                tracing::info!(
                    route,
                    "withdrawing a supervisor pool instance its driver no longer runs"
                );
                self.withdraw(route);
            }
        }
        outcome
    }

    /// What the host's observations say about the instance of `sandbox_id`
    /// on `route`. Only a host that has reconciled to the assigning snapshot
    /// renders a verdict; a disconnected or still-reconciling host is not
    /// evidence that a running instance is gone. For a pool only the owning
    /// process's host renders it, so an instance being taken over by another
    /// member reads as degraded or unknown, never unavailable, until its new
    /// owner has reconciled.
    #[must_use]
    pub fn supervision(&self, route: &str, sandbox_id: &str) -> InstanceSupervision {
        match self.controller.observed(route) {
            ObservedInstance::Reported(status) => {
                let status = SandboxInstanceStatusReport::from_proto(&status);
                if status.sandbox_id != sandbox_id || status.phase.is_terminal() {
                    InstanceSupervision::Unavailable
                } else if status.ready {
                    InstanceSupervision::Available
                } else {
                    InstanceSupervision::Degraded
                }
            }
            ObservedInstance::Pending => InstanceSupervision::Degraded,
            ObservedInstance::Absent => InstanceSupervision::Unavailable,
            ObservedInstance::NoHost => InstanceSupervision::Unknown,
        }
    }

    /// Wait for the instance to become available: `true` once the host
    /// reports it ready, `false` once the host has reconciled past the
    /// assignment without hosting it or reports it ended. A disconnected or
    /// still-reconciling host is not a verdict, so the caller bounds the wait
    /// with its own bootstrap grace.
    pub async fn wait_for_ready(&self, route: &str, sandbox_id: &str) -> bool {
        loop {
            match self.supervision(route, sandbox_id) {
                InstanceSupervision::Available => return true,
                InstanceSupervision::Unavailable => return false,
                InstanceSupervision::Degraded | InstanceSupervision::Unknown => {
                    tokio::time::sleep(READINESS_POLL).await;
                }
            }
        }
    }
}

fn unix_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}

/// Decode persisted launch material for `candidate`, binding it to the
/// recorded route and sandbox before trusting it.
fn recovered_assignment<R>(
    candidate: &RecoverableInstance<R>,
    material: &[u8],
) -> Result<crate::proto::SandboxInstanceAssignment, RegistrationError> {
    let registration = SandboxInstanceRegistration::from_launch_material(material)?;
    if registration.route != candidate.route || registration.sandbox_id != candidate.sandbox_id {
        return Err(RegistrationError::new(
            "shared sandbox instance launch material does not match the recorded generation",
        ));
    }
    registration.validate()?;
    registration.to_assignment()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::SandboxInstanceAssignment;
    use std::sync::Mutex;

    /// Durable pool records kept in memory.
    #[derive(Debug, Default)]
    struct RecordedPool {
        created_at_ms: Mutex<BTreeMap<String, i64>>,
        recovered: Mutex<Vec<String>>,
    }

    impl InstancePlacement for std::sync::Arc<RecordedPool> {
        fn place_launch(&self, request: PlacementRequest) -> PlacementFuture {
            self.created_at_ms
                .lock()
                .unwrap()
                .insert(request.assignment.route, unix_millis());
            Box::pin(async { Ok(()) })
        }

        fn recorded(&self) -> PlacementFuture<BTreeMap<String, i64>> {
            let recorded = self.created_at_ms.lock().unwrap().clone();
            Box::pin(async move { Ok(recorded) })
        }

        fn record_recovered(&self, assignment: SandboxInstanceAssignment) -> PlacementFuture {
            self.recovered.lock().unwrap().push(assignment.route);
            Box::pin(async { Ok(()) })
        }
    }

    fn candidate(route: &str, sandbox_id: &str) -> RecoverableInstance<&'static str> {
        RecoverableInstance {
            route: route.to_string(),
            sandbox_id: sandbox_id.to_string(),
            record: if route.starts_with("rt-unreadable") {
                "unreadable"
            } else {
                "record"
            },
        }
    }

    #[tokio::test]
    async fn pool_recovery_reconciles_durable_records_with_the_drivers_listing() {
        let supervision = SharedSupervision::new();
        let records = std::sync::Arc::new(RecordedPool::default());
        // A recovery before the gateway installed its records changes nothing.
        let outcome = supervision
            .complete_recovery(
                supervision.begin_recovery(),
                vec![candidate("rt-listed-0123456789", "sandbox-a")],
                |_record| async { Ok::<Option<Vec<u8>>, &str>(None) },
            )
            .await;
        assert_eq!(outcome, RecoveryOutcome::Kept);
        supervision
            .controller()
            .install_placement(std::sync::Arc::new(records.clone()));

        let old = unix_millis() - 2 * 60 * 1000;
        records.created_at_ms.lock().unwrap().extend([
            ("rt-listed-0123456789".to_string(), old),
            ("rt-stale-0123456789".to_string(), old),
        ]);
        let baseline = supervision.begin_recovery();
        // A launch the listing raced on another replica is younger than it.
        records
            .created_at_ms
            .lock()
            .unwrap()
            .insert("rt-raced-0123456789".to_string(), unix_millis());
        let outcome = supervision
            .complete_recovery(
                baseline,
                vec![
                    candidate("rt-listed-0123456789", "sandbox-a"),
                    candidate("rt-unreadable-0123456789", "sandbox-b"),
                    candidate("rt-gone-0123456789", "sandbox-c"),
                ],
                |record: &&str| {
                    let unreadable = *record == "unreadable";
                    async move {
                        if unreadable {
                            Ok::<_, &str>(Some(b"{\"secret\":1}".to_vec()))
                        } else {
                            Ok(None)
                        }
                    }
                },
            )
            .await;
        // Unusable material keeps the pass from reporting success and is
        // never recorded; a listed record is not read again.
        assert_eq!(outcome, RecoveryOutcome::Kept);
        assert!(records.recovered.lock().unwrap().is_empty());
        // Only the old record the listing omits is withdrawn.
        assert_eq!(
            supervision.controller().pool_withdrawals(),
            ["rt-stale-0123456789"]
        );
    }
}
