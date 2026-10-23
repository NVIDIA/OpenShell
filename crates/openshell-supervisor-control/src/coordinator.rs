// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway-owned coordination of one shared supervisor host.
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

use std::fmt::Display;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use tokio::sync::watch;

use crate::controller::{
    AssignmentError, ObservedInstance, SupervisorCredential, SupervisorHostController,
};
use crate::registration::{RegistrationError, SandboxInstanceRegistration};
use crate::status::SandboxInstanceStatusReport;

/// Interval at which [`SharedSupervision::wait_for_ready`] re-reads the
/// host's observations.
const READINESS_POLL: Duration = Duration::from_secs(1);

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
    /// No pool member could be recorded as the instance's owner. The material
    /// was persisted; the caller rolls the generation back.
    #[error("{0}")]
    Unplaced(String),
}

/// The launch term of a new pool instance, to record before it is assigned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlacementRequest {
    pub route: String,
    pub sandbox_id: String,
    pub generation: String,
    /// Credential epoch of the launch credentials.
    pub auth_epoch: u64,
}

/// Outcome of recording a launch owner.
pub type PlacementFuture = Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;

/// The gateway's durable placement of pool instances, installed by the
/// gateway when the host is a supervisor pool.
pub trait InstancePlacement: Send + Sync + std::fmt::Debug {
    /// Durably record the owner of a new instance's launch term: the pool
    /// member the consistent-hash ring prefers among live members, and its
    /// current process. Fails when no member is live.
    fn place_launch(&self, request: PlacementRequest) -> PlacementFuture;
}

/// Revision of the desired set read before the driver listed its durable
/// records. Completing a recovery with it makes the replacement
/// compare-and-replace against that revision.
#[must_use = "complete the recovery with the records listed after this baseline was read"]
pub struct RecoveryBaseline {
    revision: u64,
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
    /// The desired set matches the records; carries the revision in force.
    Published(u64),
    /// The desired set changed while the records were listed; the next pass
    /// derives them again.
    Conflict,
    /// Launch material could not be read or does not match its record, or the
    /// set exceeds the host's capacity; the previous set stays published.
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

/// The gateway's coordination of one shared supervisor host or pool: the
/// desired set it publishes, the token it delivers, and the observations it
/// reads back.
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

    /// Supervise with a pool of shared supervisor replicas (high
    /// availability) instead of one host. The gateway must then install its
    /// placement with
    /// [`SupervisorHostController::install_placement`] before instances
    /// launch.
    pub fn enable_pool(&self) {
        self.controller.enable_pool();
    }

    /// Whether instances are supervised by a pool.
    #[must_use]
    pub fn is_pool(&self) -> bool {
        self.controller.is_pool()
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
    /// generation's own records. An identical assignment changes nothing.
    /// Capacity is refused as [`LaunchError::Refused`], so the caller fails
    /// its create before the workload runs.
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
        if self.controller.is_pool() {
            // The owner of the launch term is durable before any member is
            // assigned the instance, so every gateway replica agrees on it
            // and a later failure of that member is recovered by takeover.
            let placement = self.controller.placement().ok_or_else(|| {
                LaunchError::Unplaced(
                    "the supervisor pool is not ready to place sandbox instances".to_string(),
                )
            })?;
            placement
                .place_launch(PlacementRequest {
                    route: registration.route.clone(),
                    sandbox_id: registration.sandbox_id.clone(),
                    generation: registration.auth.runtime_generation.to_string(),
                    auth_epoch: registration.auth.auth_epoch.get(),
                })
                .await
                .map_err(LaunchError::Unplaced)?;
        }
        self.controller
            .assign(assignment)
            .map_err(LaunchError::Refused)
    }

    /// Withdraw a generation's sandbox instance so the host stops it. Nothing
    /// happens for a route that is not assigned.
    pub fn withdraw(&self, route: &str) {
        self.controller.unassign(route);
    }

    /// Start a recovery pass. Call it before listing the durable records the
    /// pass derives the desired set from, so a lifecycle edit that lands
    /// during the list is detected by [`Self::complete_recovery`] instead of
    /// being undone.
    pub fn begin_recovery(&self) -> RecoveryBaseline {
        RecoveryBaseline {
            revision: self.controller.revision(),
        }
    }

    /// Replace the desired set with `candidates`, the generations that may
    /// run according to the records listed after `baseline` was read. Each
    /// candidate's launch material comes from its current assignment or, for
    /// a generation this gateway has not assigned since it started, from
    /// `read` on the driver's record, which returns the persisted bytes or
    /// `None` when they are gone. Material is decoded without quoting values,
    /// bound to the recorded route and sandbox, and validated.
    ///
    /// The first completed pass initializes the desired set; until then
    /// nothing is sent to the host. A failed or mismatched read keeps the
    /// previous set, because an incomplete set would stop running instances.
    /// A pass that raced a lifecycle edit is refused and derived again next
    /// time.
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
        let mut assignments = Vec::with_capacity(candidates.len());
        for candidate in &candidates {
            if let Some(assignment) = self.controller.assignment(&candidate.route) {
                assignments.push(assignment);
                continue;
            }
            let material = match read(&candidate.record).await {
                Ok(Some(material)) => material,
                Ok(None) => {
                    tracing::warn!(
                        sandbox_id = %candidate.sandbox_id,
                        route = %candidate.route,
                        "shared sandbox instance has no launch material; it stays unassigned"
                    );
                    continue;
                }
                Err(error) => {
                    tracing::warn!(
                        sandbox_id = %candidate.sandbox_id,
                        route = %candidate.route,
                        %error,
                        "could not read shared sandbox instance launch material; keeping the previous assignments"
                    );
                    return RecoveryOutcome::Kept;
                }
            };
            match recovered_assignment(candidate, &material) {
                Ok(assignment) => assignments.push(assignment),
                Err(error) => {
                    tracing::warn!(
                        sandbox_id = %candidate.sandbox_id,
                        route = %candidate.route,
                        %error,
                        "shared sandbox instance launch material is unusable; keeping the previous assignments"
                    );
                    return RecoveryOutcome::Kept;
                }
            }
        }
        match self
            .controller
            .replace_assignments(baseline.revision, assignments)
        {
            Ok(revision) => RecoveryOutcome::Published(revision),
            Err(AssignmentError::Conflict { .. }) => RecoveryOutcome::Conflict,
            Err(error) => {
                tracing::warn!(%error, "could not publish the shared sandbox instances; keeping the previous assignments");
                RecoveryOutcome::Kept
            }
        }
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

    fn candidate(route: &str, sandbox_id: &str) -> RecoverableInstance<&'static str> {
        RecoverableInstance {
            route: route.to_string(),
            sandbox_id: sandbox_id.to_string(),
            record: "record",
        }
    }

    #[tokio::test]
    async fn recovery_keeps_the_previous_set_unless_every_record_is_usable() {
        let supervision = SharedSupervision::new();
        let assigned = SandboxInstanceAssignment {
            route: "rt-assigned-0123456789".to_string(),
            sandbox_id: "sandbox-a".to_string(),
            generation: "gen".to_string(),
            launch_material: b"opaque".to_vec(),
            takeover: None,
        };
        // An assignment made before the first recovery is carried by it.
        supervision.controller().assign(assigned.clone()).unwrap();

        // A record whose material cannot be read keeps the set uninitialized.
        let baseline = supervision.begin_recovery();
        let outcome = supervision
            .complete_recovery(
                baseline,
                vec![
                    candidate(&assigned.route, &assigned.sandbox_id),
                    candidate("rt-unreadable-0123456789", "sandbox-b"),
                ],
                |_record| async { Err::<Option<Vec<u8>>, _>("boom") },
            )
            .await;
        assert_eq!(outcome, RecoveryOutcome::Kept);
        assert!(!supervision.controller().is_initialized());

        // Material that is not a registration is refused without quoting it.
        let baseline = supervision.begin_recovery();
        let outcome = supervision
            .complete_recovery(
                baseline,
                vec![candidate("rt-garbage-0123456789", "sandbox-c")],
                |_record| async { Ok::<_, &str>(Some(b"{\"secret\":1}".to_vec())) },
            )
            .await;
        assert_eq!(outcome, RecoveryOutcome::Kept);
        assert!(!supervision.controller().is_initialized());

        // A record without material is skipped; the current assignment is
        // reused without a read; the pass initializes the set.
        let baseline = supervision.begin_recovery();
        let outcome = supervision
            .complete_recovery(
                baseline,
                vec![
                    candidate(&assigned.route, &assigned.sandbox_id),
                    candidate("rt-gone-0123456789", "sandbox-d"),
                ],
                |_record| async { Ok::<Option<Vec<u8>>, &str>(None) },
            )
            .await;
        assert_eq!(outcome, RecoveryOutcome::Published(1));
        assert!(supervision.controller().is_initialized());
        assert_eq!(
            supervision.controller().assignment(&assigned.route),
            Some(assigned.clone())
        );

        // A baseline read before a lifecycle edit is refused, and the edit stands.
        let baseline = supervision.begin_recovery();
        supervision.withdraw(&assigned.route);
        let outcome = supervision
            .complete_recovery(
                baseline,
                vec![candidate(&assigned.route, &assigned.sandbox_id)],
                |_record| async { Ok::<Option<Vec<u8>>, &str>(None) },
            )
            .await;
        assert_eq!(outcome, RecoveryOutcome::Conflict);
        assert!(
            supervision
                .controller()
                .assignment(&assigned.route)
                .is_none()
        );
    }
}
