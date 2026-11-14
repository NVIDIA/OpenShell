// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use k8s_openapi::api::core::v1::{SecretVolumeSource, Volume, VolumeMount};

const PREPARED_KEY: &str = "prepared-runtime.json";
const PREPARED_DIR: &str = "/.openshell/prepared";

fn registration_read_error(error: KubeError) -> tonic::Status {
    if matches!(error, KubeError::Api(ref response) if response.code == 404) {
        tonic::Status::permission_denied("warm supervisor physical resource no longer exists")
    } else {
        tonic::Status::unavailable("cannot check warm supervisor physical resource")
    }
}

pub(in crate::driver) fn claimed_supervisor_pair<'a>(
    pod: &'a Pod,
    logical_id: &str,
) -> Option<&'a str> {
    (pod.metadata
        .annotations
        .as_ref()?
        .get(claim::CLAIM)?
        .as_str()
        == logical_id)
        .then(|| {
            pod.metadata
                .labels
                .as_ref()?
                .get(BOUNDARY_PAIR_LABEL)
                .map(String::as_str)
        })?
}

/// A Pod marker is only a lookup hint. `TokenReview` authentication also binds it
/// to the live CR claim, physical generation, and original supervisor Pod UID.
#[allow(clippy::result_large_err)]
pub(in crate::driver) fn validate_claimed_supervisor(
    pod: &Pod,
    object: &DynamicObject,
    logical_id: &str,
) -> Result<(), tonic::Status> {
    let physical = physical_resource_id(object, logical_id);
    if physical == logical_id
        || annotation(object, claim::CLAIM).is_none()
        || claimed_supervisor_pair(pod, logical_id) != Some(physical.as_str())
        || pod.metadata.uid.as_deref()
            != annotation(object, ANNOTATION_SANDBOX_RUNTIME_SUPERVISOR_UID)
        || supervisor_placement(object).ok() != Some(SupervisorPlacement::Dedicated)
        || !sandbox_runtime_should_run(object)
    {
        return Err(tonic::Status::permission_denied(
            "warm supervisor does not match the current sandbox claim",
        ));
    }
    Ok(())
}

pub(in crate::driver) fn configure_dedicated_pod(
    pod: &mut Pod,
    names: &SandboxRuntimeNames,
    port: u16,
) {
    let spec = pod.spec.as_mut().expect("supervisor spec");
    let container = &mut spec.containers[0];
    container.startup_probe = Some(k8s_openapi::api::core::v1::Probe {
        tcp_socket: Some(k8s_openapi::api::core::v1::TCPSocketAction {
            port: IntOrString::Int(5502),
            ..Default::default()
        }),
        period_seconds: Some(1),
        failure_threshold: Some(3600),
        ..Default::default()
    });
    container
        .command
        .as_mut()
        .expect("supervisor command")
        .extend([
            "--warm-health-port".into(),
            "5502".into(),
            "--warm-prepared-file".into(),
            format!("{PREPARED_DIR}/{PREPARED_KEY}"),
            "--runtime-listen".into(),
            format!("0.0.0.0:{port}"),
        ]);
    container
        .volume_mounts
        .get_or_insert_default()
        .push(VolumeMount {
            name: "warm-prepared".into(),
            mount_path: PREPARED_DIR.into(),
            read_only: Some(true),
            ..Default::default()
        });
    let volumes = spec.volumes.get_or_insert_default();
    let bootstrap = volumes
        .iter_mut()
        .find(|v| v.name == "bootstrap")
        .expect("bootstrap volume")
        .secret
        .as_mut()
        .expect("bootstrap Secret");
    bootstrap.secret_name = Some(format!("{}-prepared", names.supervisor_secret));
    bootstrap.optional = Some(false);
    volumes.push(Volume {
        name: "warm-prepared".into(),
        secret: Some(SecretVolumeSource {
            secret_name: Some(format!("{}-prepared", names.supervisor_secret)),
            default_mode: Some(0o440),
            ..Default::default()
        }),
        ..Default::default()
    });
}

pub(in crate::driver) fn validate_dedicated_pod(
    stored: &Pod,
    expected: &Pod,
) -> Result<(), KubernetesDriverError> {
    let mut actual = serde_json::to_value(stored).map_err(record_error)?;
    let mut expected_spec = serde_json::to_value(expected).map_err(record_error)?;
    // Gate removal is the only mutation performed after preparation. Kubernetes
    // may default omitted fields, but supplied container and security fields bind.
    actual["spec"]
        .as_object_mut()
        .expect("Pod spec")
        .remove("schedulingGates");
    expected_spec["spec"]
        .as_object_mut()
        .expect("Pod spec")
        .remove("schedulingGates");
    if stored.metadata.deletion_timestamp.is_some()
        || stored.metadata.owner_references != expected.metadata.owner_references
        || !requested_shape_matches(&expected_spec["spec"], &actual["spec"])
    {
        return Err(invalid("warm supervisor Pod changed"));
    }
    Ok(())
}

pub(super) struct WarmTarget {
    pub(super) supervisor: KubernetesSupervisorClaim,
    pub(super) authority: String,
    pub(super) address: std::net::SocketAddr,
    pub(super) namespace: String,
    pub(super) control_policy: VerifiedControlPolicy,
}

impl KubernetesComputeDriver {
    pub(crate) async fn authenticate_warm_supervisor(
        &self,
        credential: &str,
    ) -> Result<openshell_core::proto::compute::v1::SupervisorRegistrationIdentity, tonic::Status>
    {
        let denied =
            || tonic::Status::permission_denied("warm supervisor physical binding is invalid");
        if self.warm_supervision.is_none() || self.shared_supervisor.is_some() {
            return Err(denied());
        }
        let (identity, pod) =
            self.authenticate_supervisor_pod(credential)
                .await
                .map_err(|status| {
                    if status.code() == tonic::Code::Internal {
                        tonic::Status::unavailable("supervisor identity provider is unavailable")
                    } else {
                        status
                    }
                })?;
        let owner = sandbox_owner_reference(&pod, false)?;
        let api = self
            .supported_agent_sandbox_api(self.client.clone(), &identity.namespace)
            .await
            .map_err(|_| tonic::Status::unavailable("Sandbox API is unavailable"))?;
        let object = api
            .api
            .get(&owner.name)
            .await
            .map_err(registration_read_error)?;
        let record = read_record(&object, &self.config.gateway_id).map_err(|_| denied())?;
        let names = record.names();
        if object.metadata.uid.as_deref() != Some(&owner.uid)
            || object.metadata.deletion_timestamp.is_some()
            || pod.metadata.deletion_timestamp.is_some()
            || annotation(&object, RETIRING).is_some()
            || annotation(&object, ANNOTATION_SANDBOX_RUNTIME_SUPERVISOR_UID)
                != Some(identity.pod_uid.as_str())
            || pod.metadata.name.as_deref() != Some(names.supervisor_pod.as_str())
        {
            return Err(denied());
        }
        let mut physical_pod = pod.clone();
        physical_pod
            .metadata
            .labels
            .get_or_insert_default()
            .insert(LABEL_SANDBOX_ID.into(), record.physical_id());
        validate_proxy_control_labels(&physical_pod, &record.physical_id())?;
        let secret = Api::<Secret>::namespaced(self.client.clone(), &identity.namespace)
            .get(&format!("{}-prepared", names.supervisor_secret))
            .await
            .map_err(registration_read_error)?;
        if secret.metadata.owner_references.as_deref()
            != Some(&[runtime_pod_owner(&names.supervisor_pod, &identity.pod_uid)])
            || secret.immutable != Some(true)
            || secret.metadata.deletion_timestamp.is_some()
        {
            return Err(denied());
        }
        let bytes = secret
            .data
            .as_ref()
            .and_then(|data| data.get(PREPARED_KEY))
            .ok_or_else(denied)?;
        if bytes.0.len() > openshell_supervisor_control::MAX_LAUNCH_MATERIAL_BYTES {
            return Err(denied());
        }
        let prepared: PreparedRuntimeRegistration =
            serde_json::from_slice(&bytes.0).map_err(|_| denied())?;
        prepared.validate().map_err(|_| denied())?;
        let descriptor = &prepared.runtime_descriptor;
        let workload = Api::<Pod>::namespaced(self.client.clone(), &identity.namespace)
            .get(&owner.name)
            .await
            .map_err(registration_read_error)?;
        let namespace = Api::<Namespace>::all(self.client.clone())
            .get(&identity.namespace)
            .await
            .map_err(registration_read_error)?;
        if prepared.route != record.route()
            || descriptor.session_id != record.session_id
            || descriptor.generation != record.physical_id()
            || descriptor
                .resource_claims
                .get("kubernetes.supervisor_pod_uid")
                != Some(&identity.pod_uid)
            || descriptor
                .resource_claims
                .get("kubernetes.sandbox_resource_uid")
                != Some(&owner.uid)
            || descriptor
                .resource_claims
                .get("kubernetes.workload_pod_uid")
                != workload.metadata.uid.as_ref()
            || descriptor.resource_claims.get("kubernetes.namespace_uid")
                != namespace.metadata.uid.as_ref()
            || workload.metadata.deletion_timestamp.is_some()
            || namespace.metadata.deletion_timestamp.is_some()
        {
            return Err(denied());
        }
        Ok(
            openshell_core::proto::compute::v1::SupervisorRegistrationIdentity {
                route: prepared.route,
                generation: descriptor.generation.clone(),
                session_id: descriptor.session_id.to_string(),
                resource_claims: descriptor.resource_claims.clone().into_iter().collect(),
            },
        )
    }

    pub(super) async fn warm_target(
        &self,
        api: &AgentSandboxApi,
        object: &mut DynamicObject,
        record: &Record,
    ) -> Result<WarmTarget, KubernetesDriverError> {
        let resource = resource_from_object(object, record)?;
        let names = record.names();
        let owner = sandbox_runtime_sandbox_owner_reference(
            &resource.name,
            &resource.uid,
            &api.resource.api_version,
            false,
        );
        if self.shared_supervisor.is_some() {
            let (_, target) = self.shared_supervisor_target().await?;
            let policy = self
                .ensure_sandbox_runtime_shared_control_policy(
                    &resource.namespace,
                    &names,
                    &record.physical_id(),
                    &target,
                    owner,
                )
                .await?;
            return Ok(WarmTarget {
                supervisor: KubernetesSupervisorClaim::SandboxInstance(record.route()),
                authority: target.authority,
                address: target.address,
                namespace: target.namespace,
                control_policy: policy,
            });
        }
        for mode in [
            KubernetesControlConnection::SupervisorInitiated,
            KubernetesControlConnection::RuntimeInitiated,
        ] {
            self.ensure_sandbox_runtime_service(
                &resource.namespace,
                &names,
                &record.physical_id(),
                mode,
                owner.clone(),
            )
            .await?;
        }
        let staged = self.read_staged_bootstrap_material().await?;
        let uid = self
            .create_sandbox_runtime_supervisor(
                &resource.namespace,
                &names,
                &record.physical_id(),
                "",
                owner.clone(),
                record.uid,
                record.gid,
                &openshell_core::sandbox_env::MainProcessConfig::encode_driver_spec(None)
                    .map_err(record_error)?,
                "info",
                staged.upstream_proxy_ca_bundle.is_some(),
                true,
            )
            .await?;
        match annotation(object, ANNOTATION_SANDBOX_RUNTIME_SUPERVISOR_UID) {
            Some(expected) if expected != uid => {
                return Err(invalid("warm supervisor Pod was replaced"));
            }
            None => {
                *object = patch_annotations(
                    &api.api,
                    object,
                    serde_json::json!({ANNOTATION_SANDBOX_RUNTIME_SUPERVISOR_UID: uid}),
                )
                .await?;
            }
            _ => {}
        }
        let target = self
            .resolve_generation_launch_target(
                &resource.namespace,
                &names,
                &record.physical_id(),
                &GenerationSupervisor::Dedicated {
                    pod_uid: uid.clone(),
                    connection: KubernetesControlConnection::RuntimeInitiated,
                },
                owner,
            )
            .await?;
        let GenerationLaunchTarget::Dedicated {
            service_ip,
            control_policy: Some(policy),
            ..
        } = target
        else {
            return Err(invalid("dedicated warm control path missing"));
        };
        Ok(WarmTarget {
            supervisor: KubernetesSupervisorClaim::Pod(uid),
            authority: boundary_service_authority(
                &resource.namespace,
                &names,
                self.config.sandbox_runtime.boundary_port,
                KubernetesControlConnection::RuntimeInitiated,
            ),
            address: std::net::SocketAddr::new(
                service_ip,
                self.config.sandbox_runtime.boundary_port,
            ),
            namespace: resource.namespace,
            control_policy: policy,
        })
    }

    pub(super) async fn release_warm_dedicated(
        &self,
        object: &DynamicObject,
        record: &Record,
        registration: &PreparedRuntimeRegistration,
    ) -> Result<(), KubernetesDriverError> {
        let resource = resource_from_object(object, record)?;
        let names = record.names();
        let uid = annotation(object, ANNOTATION_SANDBOX_RUNTIME_SUPERVISOR_UID)
            .ok_or_else(|| invalid("warm supervisor UID missing"))?;
        let mut secret = shared_instance_secret(
            &resource.namespace,
            &names,
            &record.physical_id(),
            serde_json::to_vec(registration).map_err(record_error)?,
            runtime_pod_owner(&names.supervisor_pod, uid),
        );
        secret.metadata.name = Some(format!("{}-prepared", names.supervisor_secret));
        let bytes = secret
            .data
            .as_mut()
            .expect("data")
            .remove(SHARED_INSTANCE_KEY)
            .expect("registration");
        secret
            .data
            .as_mut()
            .expect("data")
            .insert(PREPARED_KEY.into(), bytes);
        let staged = self.read_staged_bootstrap_material().await?;
        let data = secret.data.as_mut().expect("prepared data");
        if let Some(tls) = staged.client_tls {
            data.insert(
                crate::sandbox_runtime::CLIENT_TLS_CA_KEY.into(),
                k8s_openapi::ByteString(tls.ca_certificate),
            );
        }
        if let Some(bundle) = staged.upstream_proxy_ca_bundle {
            data.insert(
                crate::sandbox_runtime::UPSTREAM_PROXY_CA_BUNDLE_KEY.into(),
                k8s_openapi::ByteString(bundle),
            );
        }
        self.create_immutable_warm_secret(&resource.namespace, &secret)
            .await?;
        let pods = Api::<Pod>::namespaced(self.client.clone(), &resource.namespace);
        let pod = pods
            .get(&names.supervisor_pod)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        if pod.metadata.uid.as_deref() != Some(uid) || pod.metadata.deletion_timestamp.is_some() {
            return Err(invalid("warm supervisor changed before release"));
        }
        release_gate(&pods, &pod).await
    }

    pub(super) async fn create_immutable_warm_secret(
        &self,
        namespace: &str,
        secret: &Secret,
    ) -> Result<(), KubernetesDriverError> {
        let secrets = Api::<Secret>::namespaced(self.client.clone(), namespace);
        match secrets.create(&PostParams::default(), secret).await {
            Ok(_) => Ok(()),
            Err(KubeError::Api(error)) if error.code == 409 => {
                let stored = secrets
                    .get(secret.metadata.name.as_deref().expect("named Secret"))
                    .await
                    .map_err(KubernetesDriverError::from_kube)?;
                if stored.immutable != secret.immutable
                    || stored.data != secret.data
                    || stored.metadata.owner_references != secret.metadata.owner_references
                    || stored.metadata.deletion_timestamp.is_some()
                {
                    return Err(invalid("warm supervisor Secret changed"));
                }
                Ok(())
            }
            Err(error) => Err(KubernetesDriverError::from_kube(error)),
        }
    }

    pub(super) async fn warm_connection_ready(
        &self,
        resource: &WarmRuntimeResource,
    ) -> Result<bool, KubernetesDriverError> {
        if let Some(shared) = &self.shared_supervisor {
            return Ok(shared
                .supervision()
                .prepared_connection_ready(&format!("rt-{}", resource.session_id)));
        }
        let api = self
            .supported_agent_sandbox_api(self.client.clone(), &resource.namespace)
            .await
            .map_err(KubernetesDriverError::Message)?;
        let object = api
            .api
            .get(&resource.name)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        let record = read_record(&object, &self.config.gateway_id)?;
        let pods = Api::<Pod>::namespaced(self.client.clone(), &resource.namespace);
        let names = record.names();
        let (pod, workload) = tokio::try_join!(
            pods.get_opt(&names.supervisor_pod),
            pods.get_opt(&resource.name),
        )
        .map_err(KubernetesDriverError::from_kube)?;
        Ok(object.metadata.uid.as_deref() == Some(&resource.uid)
            && workload.is_some_and(|pod| {
                pod.metadata.uid == resource.pod_uid
                    && pod.metadata.deletion_timestamp.is_none()
                    && pod
                        .status
                        .as_ref()
                        .is_some_and(|status| status.phase.as_deref() == Some("Running"))
            })
            && pod.is_some_and(|pod| {
                pod.metadata.uid.as_deref()
                    == annotation(&object, ANNOTATION_SANDBOX_RUNTIME_SUPERVISOR_UID)
                    && pod.metadata.deletion_timestamp.is_none()
                    && pod.status.as_ref().is_some_and(|status| {
                        status.phase.as_deref() == Some("Running")
                            && status
                                .container_statuses
                                .as_ref()
                                .is_some_and(|containers| {
                                    containers.iter().any(|container| {
                                        container.name == "supervisor"
                                            && container.started == Some(true)
                                            && container.restart_count == 0
                                            && container
                                                .state
                                                .as_ref()
                                                .is_some_and(|state| state.running.is_some())
                                    })
                                })
                    })
            }))
    }

    pub(super) async fn publish_dedicated_claim_identity(
        &self,
        object: &DynamicObject,
        record: &Record,
        registration: &SandboxInstanceRegistration,
    ) -> Result<(), KubernetesDriverError> {
        let resource = resource_from_object(object, record)?;
        let names = record.names();
        let uid = annotation(object, ANNOTATION_SANDBOX_RUNTIME_SUPERVISOR_UID)
            .ok_or_else(|| invalid("warm supervisor UID missing"))?;
        let pods = Api::<Pod>::namespaced(self.client.clone(), &resource.namespace);
        let pod = pods
            .get(&names.supervisor_pod)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        if pod.metadata.uid.as_deref() != Some(uid) || pod.metadata.deletion_timestamp.is_some() {
            return Err(invalid("claimed supervisor Pod was replaced"));
        }
        // Publish the logical identity before making credentials available, so
        // Pod identity consumers (including SPIFFE registration) see the claim.
        if pod
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(claim::CLAIM))
            != Some(&registration.sandbox_id)
        {
            pods.patch(&names.supervisor_pod, &PatchParams::default(), &Patch::Merge(&serde_json::json!({
                "metadata": {"uid": uid, "resourceVersion": pod.metadata.resource_version,
                    "annotations": {claim::CLAIM: registration.sandbox_id, LABEL_SANDBOX_ID: registration.sandbox_id},
                    "labels": {LABEL_SANDBOX_ID: registration.sandbox_id}}
            }))).await.map_err(KubernetesDriverError::from_kube)?;
        }
        Ok(())
    }
}

impl Record {
    pub(super) fn control_policy_name(&self, dedicated: bool) -> String {
        if dedicated {
            self.names().control_policy
        } else {
            self.names().shared_control_policy
        }
    }
}
