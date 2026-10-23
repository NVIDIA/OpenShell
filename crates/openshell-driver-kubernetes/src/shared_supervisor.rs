// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generations supervised by the gateway's shared supervisor.
//!
//! Each runtime generation records where its supervisor runs when it starts.
//! Every later lifecycle decision reads that record, so changing the gateway
//! topology setting never reinterprets an existing generation.
//!
//! The gateway owns which sandbox instances the shared supervisor hosts and
//! coordinates them through `openshell_supervisor_control::SharedSupervision`,
//! which it constructs and hands to this driver. The driver's part is
//! Kubernetes: the placement record on the Sandbox resource, the launch
//! Secret the coordinator persists launch material into and reads it back
//! from, the egress allowance from the workload to the supervisor's Service,
//! and delivery of the gateway-minted supervisor token into the Secret the
//! supervisor Pod mounts.

use std::collections::BTreeMap;
use std::time::Duration;

use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, ObjectMeta, Patch, PatchParams};
use kube::core::DynamicObject;
use openshell_supervisor_control::{SharedSupervision, SupervisorCredential, deliver_credentials};
use tracing::info;

use crate::config::SharedSupervisorConfig;
use crate::driver::KubernetesDriverError;

/// Supervisor placement of the current generation; absent means a dedicated
/// supervisor Pod.
pub const ANNOTATION_SUPERVISOR_TOPOLOGY: &str = "openshell.ai/sandbox-runtime-supervisor-topology";
/// Route of a generation's sandbox instance on the shared supervisor. The
/// annotation key keeps its established `-session` name.
pub const ANNOTATION_SUPERVISOR_SESSION: &str = "openshell.ai/sandbox-runtime-supervisor-session";
pub const GATEWAY_TOPOLOGY: &str = "gateway";
/// Key of the supervisor token in `shared_supervisor.token_secret_name`.
pub const TOKEN_SECRET_KEY: &str = "token";
/// Annotation recording the token's expiry (Unix seconds) for operators.
pub const ANNOTATION_TOKEN_EXPIRES_AT: &str = "openshell.ai/supervisor-token-expires-at";
const TOKEN_WRITE_RETRY: Duration = Duration::from_secs(5);

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

/// The shared supervisor as this driver reaches it: the Helm-deployed
/// Service and token Secret it is configured with, and the gateway's
/// coordination of its sandbox instances.
#[derive(Clone, Debug)]
pub struct SharedSupervisor {
    config: SharedSupervisorConfig,
    supervision: SharedSupervision,
}

impl SharedSupervisor {
    /// The shared supervisor this driver is configured with. A
    /// high-availability configuration makes the gateway coordinate a pool of
    /// supervisor replicas, before any of them attaches.
    pub fn new(config: SharedSupervisorConfig, supervision: SharedSupervision) -> Self {
        if config.high_availability {
            supervision.enable_pool();
        }
        Self {
            config,
            supervision,
        }
    }

    /// Keep the supervisor token Secret current with every token the gateway
    /// publishes, until shutdown. The Secret itself is deployment packaging
    /// (the chart creates it empty); the driver only replaces its token.
    pub fn spawn_token_secret_writer(
        &self,
        client: kube::Client,
        shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) {
        let secrets = Api::<Secret>::namespaced(client, &self.config.service_namespace);
        let name = self.config.token_secret_name.clone();
        tokio::spawn(deliver_credentials(
            self.supervision.credentials(),
            shutdown_rx,
            TOKEN_WRITE_RETRY,
            move |credential| {
                let secrets = secrets.clone();
                let name = name.clone();
                async move { write_token_secret(&secrets, &name, &credential).await }
            },
        ));
    }

    pub fn config(&self) -> &SharedSupervisorConfig {
        &self.config
    }

    /// The gateway's coordination of the host's sandbox instances.
    pub fn supervision(&self) -> &SharedSupervision {
        &self.supervision
    }
}

/// Replace the token in the chart-created Secret. The error names what an
/// operator must restore when the write cannot succeed on its own.
async fn write_token_secret(
    secrets: &Api<Secret>,
    name: &str,
    credential: &SupervisorCredential,
) -> Result<(), String> {
    let secret = Secret {
        metadata: ObjectMeta {
            annotations: Some(BTreeMap::from([(
                ANNOTATION_TOKEN_EXPIRES_AT.to_string(),
                credential.expires_at.to_string(),
            )])),
            ..ObjectMeta::default()
        },
        string_data: Some(BTreeMap::from([(
            TOKEN_SECRET_KEY.to_string(),
            credential.token.expose_secret().to_string(),
        )])),
        ..Secret::default()
    };
    secrets
        .patch(name, &PatchParams::default(), &Patch::Merge(&secret))
        .await
        .map_err(|error| match &error {
            kube::Error::Api(response) if response.code == 404 => format!(
                "the supervisor token Secret {name} does not exist; the chart creates it, \
                 restore it (helm upgrade) so the shared supervisor can authenticate"
            ),
            kube::Error::Api(response) if response.code == 403 => format!(
                "the gateway may not patch the supervisor token Secret {name}; check the \
                 chart's gateway Role"
            ),
            _ => format!("failed to write the supervisor token Secret {name}: {error}"),
        })?;
    info!(
        secret = %name,
        expires_at = credential.expires_at,
        "wrote the supervisor token Secret"
    );
    Ok(())
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
