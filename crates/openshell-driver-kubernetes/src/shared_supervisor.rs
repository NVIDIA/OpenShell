// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generations supervised by the gateway's shared supervisor.
//!
//! Each runtime generation records where its supervisor runs when it starts.
//! Every later lifecycle decision reads that record, so changing the gateway
//! topology setting never reinterprets an existing generation.
//!
//! The gateway owns which sandbox instances the shared supervisor hosts. The
//! driver publishes that set into a [`SupervisorHostController`], which the
//! gateway serves to the supervisor over the private supervisor host stream,
//! and reads the host's observations back from it. The durable source of the
//! set is the generation's Sandbox resource plus its launch Secret, so a
//! restarted gateway rebuilds it before publishing anything, and a full
//! resync is compare-and-replace against the revision it started from.

use std::path::PathBuf;

use kube::core::DynamicObject;
use openshell_core::proto::supervisor_host::v1::{
    SandboxInstanceAssignment, SandboxInstanceStatus,
};
use openshell_core::supervisor_host::{
    AssignmentError, ObservedInstance, SupervisorHostController,
};
use openshell_sandbox_backend::sandbox_instance::{
    SandboxInstanceRegistration, SandboxInstanceStatusReport,
};

use crate::config::SharedSupervisorConfig;
use crate::driver::KubernetesDriverError;

/// Supervisor placement of the current generation; absent means a dedicated
/// supervisor Pod.
pub const ANNOTATION_SUPERVISOR_TOPOLOGY: &str = "openshell.ai/sandbox-runtime-supervisor-topology";
/// Route of a generation's sandbox instance on the shared supervisor. The
/// annotation key keeps its established `-session` name.
pub const ANNOTATION_SUPERVISOR_SESSION: &str = "openshell.ai/sandbox-runtime-supervisor-session";
pub const GATEWAY_TOPOLOGY: &str = "gateway";

/// Where a generation's supervisor runs, as recorded when it started.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SupervisorPlacement {
    /// A supervisor Pod paired with this generation's workload Pod.
    Dedicated,
    /// A sandbox instance on the gateway's shared supervisor.
    Shared { route: String },
}

/// Read the recorded placement. An unknown or incomplete record fails closed.
pub fn supervisor_placement(
    object: &DynamicObject,
) -> Result<SupervisorPlacement, KubernetesDriverError> {
    let annotations = object.metadata.annotations.as_ref();
    let annotation = |key: &str| annotations.and_then(|annotations| annotations.get(key));
    match annotation(ANNOTATION_SUPERVISOR_TOPOLOGY).map(String::as_str) {
        None => Ok(SupervisorPlacement::Dedicated),
        Some(GATEWAY_TOPOLOGY) => {
            let route = annotation(ANNOTATION_SUPERVISOR_SESSION)
                .filter(|route| {
                    openshell_sandbox_backend::runtime_routed::validate_route_handle(route).is_ok()
                })
                .ok_or_else(|| {
                    KubernetesDriverError::Precondition(
                        "shared supervisor generation has no valid sandbox instance route"
                            .to_string(),
                    )
                })?;
            Ok(SupervisorPlacement::Shared {
                route: route.clone(),
            })
        }
        Some(other) => Err(KubernetesDriverError::Precondition(format!(
            "unknown sandbox-runtime supervisor topology {other:?}"
        ))),
    }
}

/// The gateway's desired set of shared sandbox instances and the host's
/// observations of them. The controller is the only owner of that state;
/// this type only translates between the driver's launch material and its
/// wire form.
#[derive(Clone, Debug)]
pub struct SharedSupervisor {
    config: SharedSupervisorConfig,
    controller: SupervisorHostController,
}

impl SharedSupervisor {
    pub fn new(config: SharedSupervisorConfig) -> Self {
        let controller = SupervisorHostController::new(PathBuf::from(&config.host_ca_file));
        Self { config, controller }
    }

    pub fn config(&self) -> &SharedSupervisorConfig {
        &self.config
    }

    /// The controller the gateway serves to the supervisor host.
    pub fn controller(&self) -> &SupervisorHostController {
        &self.controller
    }

    /// Assign a generation's sandbox instance; an identical assignment
    /// changes nothing. Refused as a precondition when the host is at
    /// capacity, so the create fails before its workload runs.
    pub fn assign(
        &self,
        registration: &SandboxInstanceRegistration,
    ) -> Result<(), KubernetesDriverError> {
        let assignment = registration
            .to_assignment()
            .map_err(|error| KubernetesDriverError::Message(error.to_string()))?;
        self.controller
            .assign(assignment)
            .map_err(|error| KubernetesDriverError::Precondition(error.to_string()))
    }

    /// Withdraw a generation's sandbox instance so the host stops it.
    pub fn withdraw(&self, route: &str) {
        self.controller.unassign(route);
    }

    /// Current desired revision, read before deriving a full list for
    /// [`Self::resync`].
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.controller.revision()
    }

    /// The current assignment of a route, if any, so a resync keeps the
    /// launch material it already holds instead of reading the Secret again.
    #[must_use]
    pub fn assignment(&self, route: &str) -> Option<SandboxInstanceAssignment> {
        self.controller.assignment(route)
    }

    /// Replace the desired set with the generations that may run, derived
    /// from Sandbox resources and their launch Secrets while the revision was
    /// `baseline`. The first call initializes the gateway's view; until then
    /// nothing is sent to the host. A list that raced a lifecycle edit is
    /// refused and derived again on the next reconciliation.
    pub fn resync(
        &self,
        baseline: u64,
        assignments: Vec<SandboxInstanceAssignment>,
    ) -> Result<u64, AssignmentError> {
        self.controller.replace_assignments(baseline, assignments)
    }

    /// The host's view of one route.
    #[must_use]
    pub fn observed(&self, route: &str) -> ObservedInstance {
        self.controller.observed(route)
    }
}

/// The host's report of one instance, in the driver's terms.
#[must_use]
pub fn reported(status: &SandboxInstanceStatus) -> SandboxInstanceStatusReport {
    SandboxInstanceStatusReport::from_proto(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::{ApiResource, GroupVersionKind};

    fn object(annotations: &[(&str, &str)]) -> DynamicObject {
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
            "agents.x-k8s.io",
            "v1beta1",
            "Sandbox",
        ));
        let mut object = DynamicObject::new("sandbox-a", &resource);
        object.metadata.annotations = Some(
            annotations
                .iter()
                .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                .collect(),
        );
        object
    }

    #[test]
    fn recorded_placement_is_read_and_unknown_records_fail_closed() {
        assert_eq!(
            supervisor_placement(&object(&[])).unwrap(),
            SupervisorPlacement::Dedicated
        );
        let route = openshell_sandbox_backend::runtime_routed::new_route_handle();
        assert_eq!(
            supervisor_placement(&object(&[
                (ANNOTATION_SUPERVISOR_TOPOLOGY, GATEWAY_TOPOLOGY),
                (ANNOTATION_SUPERVISOR_SESSION, &route),
            ]))
            .unwrap(),
            SupervisorPlacement::Shared { route }
        );
        for annotations in [
            &[(ANNOTATION_SUPERVISOR_TOPOLOGY, GATEWAY_TOPOLOGY)][..],
            &[
                (ANNOTATION_SUPERVISOR_TOPOLOGY, GATEWAY_TOPOLOGY),
                (ANNOTATION_SUPERVISOR_SESSION, "Not/A/Route"),
            ],
            &[(ANNOTATION_SUPERVISOR_TOPOLOGY, "workspace")],
        ] {
            assert!(supervisor_placement(&object(annotations)).is_err());
        }
    }
}
