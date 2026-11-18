// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use openshell_core::sandbox_generation::SandboxGenerationId;

pub(super) const CLAIM: &str = "openshell.ai/warm-claim";
const CLAIM_COMPLETE: &str = "openshell.ai/warm-claim-complete";
use openshell_supervisor_control::{WarmClaimIntent, WarmClaimLookup, WarmClaimReservation};

pub(in crate::driver) fn physical_resource_id(object: &DynamicObject, logical_id: &str) -> String {
    annotation(object, RECORD)
        .and_then(|value| serde_json::from_str::<Record>(value).ok())
        .filter(|record| sandbox_runtime_generation(object) == Some(record.physical_id().as_str()))
        .map_or_else(|| logical_id.to_string(), |record| record.physical_id())
}

/// Corrupt warm records must not enable legacy workspace Secret recovery.
pub(in crate::driver) fn requires_gateway_recovery(object: &DynamicObject) -> bool {
    annotation(object, RECORD).is_some_and(|value| {
        serde_json::from_str::<Record>(value).map_or(true, |record| {
            sandbox_runtime_generation(object) == Some(record.physical_id().as_str())
        })
    })
}

pub(in crate::driver) fn claim_pending(object: &DynamicObject) -> bool {
    annotation(object, CLAIM).is_some()
        && annotation(object, CLAIM_COMPLETE) != Some("true")
        && annotation(object, RECORD)
            .and_then(|value| serde_json::from_str::<Record>(value).ok())
            .is_some_and(|record| {
                sandbox_runtime_generation(object) == Some(record.physical_id().as_str())
            })
}

impl KubernetesComputeDriver {
    pub(in crate::driver) async fn try_claim_warm_runtime(
        &self,
        sandbox: &Sandbox,
        namespace: &str,
    ) -> Result<Option<String>, KubernetesDriverError> {
        if self.warm_supervision().is_err() {
            return Ok(None);
        }
        if let Some(identity) = self.select_warm_runtime(sandbox, namespace).await? {
            return Ok(Some(identity));
        }
        // Fence delayed warm selection before creating cold infrastructure.
        if let Some(intent) = self
            .warm_supervision()?
            .choose_cold_launch(launch_lookup(sandbox)?)
            .await
            .map_err(KubernetesDriverError::Message)?
        {
            return self
                .resume_warm_claim(sandbox, namespace, intent)
                .await
                .map(Some);
        }
        Ok(None)
    }

    async fn select_warm_runtime(
        &self,
        sandbox: &Sandbox,
        namespace: &str,
    ) -> Result<Option<String>, KubernetesDriverError> {
        let supervision = self.warm_supervision()?;
        let api = self
            .supported_agent_sandbox_api(self.client.clone(), namespace)
            .await
            .map_err(KubernetesDriverError::Message)?;
        let existing = api
            .api
            .list(&ListParams::default().labels(&self.sandbox_lookup_selector(&sandbox.id)))
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        if existing.items.len() > 1 {
            return Err(invalid("multiple physical resources name the sandbox"));
        }
        if let Some(object) = existing.items.first() {
            if annotation(object, CLAIM).is_some()
                && physical_resource_id(object, &sandbox.id) != sandbox.id
                && annotation_or_label(object, LABEL_SANDBOX_WORKSPACE).as_deref()
                    == Some(&sandbox.workspace)
                && annotation_or_label(object, LABEL_SANDBOX_NAME).as_deref() == Some(&sandbox.name)
            {
                self.validate_claim_retry(sandbox, object).await?;
                self.finish_warm_claim(&api, object).await?;
                return claim_runtime_identity(object).map(Some);
            }
            if annotation(object, CLAIM).is_some() {
                return Err(invalid(
                    "the sandbox already owns another runtime generation",
                ));
            }
            return Ok(None);
        }
        if let Some(intent) = supervision
            .warm_claim_for_launch(launch_lookup(sandbox)?)
            .await
            .map_err(KubernetesDriverError::Message)?
        {
            // The gateway selected this physical runtime before the CR was bound.
            // Resume it even when the pool is disabled; never choose a second one.
            return self
                .resume_warm_claim(sandbox, namespace, intent)
                .await
                .map(Some);
        }
        if !self.config.warm_pool.enabled {
            return Ok(None);
        }
        let pools = self.template_warm_pools(Some(sandbox.id.clone())).await?;
        let pools: Vec<_> = pools
            .into_iter()
            .filter(|pool| pool.workspace == sandbox.workspace && pool.target_size > 0)
            .collect();
        if pools.is_empty() {
            return Ok(None);
        }
        let trust = supervision
            .warm_runtime_trust()
            .await
            .map_err(KubernetesDriverError::Message)?;
        let inventory = self.warm_runtime_inventory(&sandbox.workspace).await?;
        for pool in &pools {
            let Some(snapshot) = supervision
                .warm_pool_state(&pool.workspace, &pool.name)
                .await
                .map_err(KubernetesDriverError::Message)?
            else {
                continue;
            };
            if snapshot
                .state
                .policy
                .as_ref()
                .is_some_and(|policy| policy.target_size == 0)
                || snapshot.state.revision != pool.revision
                || snapshot.state.fingerprint != self.warm_pool_fingerprint(pool, &trust).await?
            {
                continue;
            }
            for resource in inventory.iter().filter(|resource| {
                resource.pool_id == pool.name
                    && resource.released
                    && !resource.claimed
                    && !resource.retiring
                    && !resource.deleting
            }) {
                if !snapshot.state.entries.iter().any(|entry| {
                    entry.session_id == resource.session_id
                        && !entry.retiring
                        && entry
                            .resource_uid
                            .as_ref()
                            .is_none_or(|uid| uid == &resource.uid)
                        && openshell_core::time::now_ms().saturating_sub(entry.created_at_ms)
                            < i64::try_from(
                                snapshot
                                    .state
                                    .policy
                                    .as_ref()
                                    .map_or(pool.max_age_secs, |policy| policy.max_age_secs)
                                    * 1000,
                            )
                            .unwrap_or(i64::MAX)
                }) {
                    continue;
                }
                // Recheck Pod identity, durable preparation, admission and fences.
                let result = async {
                    if !self.warm_connection_ready(resource).await? {
                        return Ok(None);
                    }
                    let object = api
                        .api
                        .get(&resource.name)
                        .await
                        .map_err(KubernetesDriverError::from_kube)?;
                    let record = read_record(&object, &self.config.gateway_id)?;
                    if !self.warm_shape_matches(sandbox, &record)? {
                        return Ok(None);
                    }
                    let prepared = self.resume_warm_runtime(resource).await?;
                    let object = api
                        .api
                        .get(&resource.name)
                        .await
                        .map_err(KubernetesDriverError::from_kube)?;
                    if self
                        .claim_warm_object(sandbox, &api, &object, &record, prepared.registration)
                        .await?
                    {
                        claim_runtime_identity(&object).map(Some)
                    } else {
                        Ok(None)
                    }
                }
                .await;
                match result {
                    Ok(Some(identity)) => return Ok(Some(identity)),
                    Ok(None) => {}
                    Err(error) => {
                        if let Some(intent) = supervision
                            .warm_claim_for_launch(launch_lookup(sandbox)?)
                            .await
                            .map_err(KubernetesDriverError::Message)?
                        {
                            return self
                                .resume_warm_claim(sandbox, namespace, intent)
                                .await
                                .map(Some);
                        }
                        if supervision
                            .pending_warm_claims(&resource.workspace)
                            .await
                            .map_err(KubernetesDriverError::Message)?
                            .retired
                            .iter()
                            .any(|retired| {
                                retired.route == format!("rt-{}", resource.session_id)
                                    && retired.generation.as_str()
                                        == resource.session_id.to_string()
                            })
                        {
                            continue;
                        }
                        // Inventory can race another create. Only a durable claim
                        // for another sandbox proves that this attempt cannot have
                        // committed; missing/unreadable intent remains ambiguous.
                        if supervision
                            .warm_claim(&resource.workspace, &format!("rt-{}", resource.session_id))
                            .await
                            .is_ok_and(|intent| intent.registration.sandbox_id != sandbox.id)
                        {
                            continue;
                        }
                        return Err(error);
                    }
                }
            }
        }
        Ok(None)
    }

    async fn resume_warm_claim(
        &self,
        sandbox: &Sandbox,
        namespace: &str,
        intent: WarmClaimIntent,
    ) -> Result<String, KubernetesDriverError> {
        let api = self
            .supported_agent_sandbox_api(self.client.clone(), namespace)
            .await
            .map_err(KubernetesDriverError::Message)?;
        let name = format!("warm-{}", intent.registration.runtime_descriptor.session_id);
        let Some(object) = api
            .api
            .get_opt(&name)
            .await
            .map_err(KubernetesDriverError::from_kube)?
        else {
            self.warm_supervision()?
                .cancel_warm_claim(&sandbox.workspace, &intent.registration.route)
                .await
                .map_err(KubernetesDriverError::Message)?;
            return Err(invalid("reserved warm runtime disappeared"));
        };
        let record = read_record(&object, &self.config.gateway_id)?;
        let claims = &intent.registration.runtime_descriptor.resource_claims;
        let pod = Api::<Pod>::namespaced(self.client.clone(), namespace)
            .get_opt(&name)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        if claims.get("kubernetes.sandbox_resource_uid") != object.metadata.uid.as_ref()
            || object.metadata.deletion_timestamp.is_some()
            || pod.as_ref().is_none_or(|pod| {
                claims.get("kubernetes.workload_pod_uid") != pod.metadata.uid.as_ref()
                    || pod.metadata.deletion_timestamp.is_some()
            })
        {
            self.warm_supervision()?
                .cancel_warm_claim(&sandbox.workspace, &intent.registration.route)
                .await
                .map_err(KubernetesDriverError::Message)?;
            return Err(invalid("reserved warm runtime was lost or replaced"));
        }
        if !self.warm_shape_matches(sandbox, &record)?
            || intent.registration.sandbox_id != sandbox.id
            || intent.registration.main_process_spec
                != openshell_core::sandbox_env::MainProcessConfig::encode_driver_spec(
                    sandbox.spec.as_ref(),
                )
                .map_err(record_error)?
        {
            return Err(invalid("create retry differs from the pending warm claim"));
        }
        if annotation(&object, CLAIM).is_some() {
            if annotation(&object, CLAIM) != Some(intent.registration.route.as_str())
                || sandbox_id_from_object(&object).map_err(KubernetesDriverError::Message)?
                    != sandbox.id
            {
                return Err(invalid("warm claim CR belongs to another launch"));
            }
            self.finish_warm_claim(&api, &object).await?;
        } else {
            self.bind_warm_claim(sandbox, &api, &object, &record, &intent)
                .await?;
        }
        claim_runtime_identity(&object)
    }

    /// Recover gateway reservations even when no CR carries the logical ID yet.
    /// Return their sessions so pool maintenance excludes them from spare capacity.
    pub(super) async fn recover_pending_warm_claims(
        &self,
        workspace: &str,
        resources: &[WarmRuntimeResource],
    ) -> Result<std::collections::BTreeSet<SandboxSessionId>, KubernetesDriverError> {
        let claims = self
            .warm_supervision()?
            .pending_warm_claims(workspace)
            .await
            .map_err(KubernetesDriverError::Message)?;
        let mut reserved = std::collections::BTreeSet::new();
        for pending in claims.pending {
            let session = pending.intent.registration.runtime_descriptor.session_id;
            reserved.insert(session);
            let Ok(_guard) = self
                .lifecycle_gates
                .gate_for(&pending.sandbox.id)
                .try_lock_owned()
            else {
                continue;
            };
            let namespace = self.warm_runtime_namespace(workspace).await?;
            if let Err(error) = self
                .resume_warm_claim(&pending.sandbox, &namespace, pending.intent)
                .await
            {
                warn!(sandbox_id = %pending.sandbox.id, %error, "warm claim completion remains pending");
            }
        }
        for retired in claims.retired {
            if let Some(resource) = resources.iter().find(|resource| {
                retired.route == format!("rt-{}", resource.session_id)
                    && retired.generation.as_str() == resource.session_id.to_string()
            }) {
                self.retire_warm_runtime(resource).await?;
            }
        }
        Ok(reserved)
    }

    async fn validate_claim_retry(
        &self,
        sandbox: &Sandbox,
        object: &DynamicObject,
    ) -> Result<(), KubernetesDriverError> {
        let record = read_record(object, &self.config.gateway_id)?;
        if annotation(object, CLAIM) != Some(record.route().as_str()) {
            return Err(invalid(
                "legacy or changed warm claim reference; finish Secret-backed claims with the previous gateway before upgrading",
            ));
        }
        let intent = self
            .warm_supervision()?
            .warm_claim(&record.workspace, &record.route())
            .await
            .map_err(KubernetesDriverError::Message)?;
        let auth = decode_launch_authentication(
            &sandbox
                .spec
                .as_ref()
                .ok_or_else(|| invalid("sandbox spec missing"))?
                .launch_authentication,
        )?;
        let process = openshell_core::sandbox_env::MainProcessConfig::encode_driver_spec(
            sandbox.spec.as_ref(),
        )
        .map_err(record_error)?;
        if intent.expected_generation != auth.supervisor.runtime_generation
            || intent.expected_auth_epoch != auth.supervisor.auth_epoch
            || intent.registration.sandbox_id != sandbox.id
            || intent.registration.main_process_spec != process
            || !self.warm_shape_matches(sandbox, &record)?
        {
            return Err(invalid("create retry differs from the recorded warm claim"));
        }
        Ok(())
    }

    pub(super) fn warm_shape_matches(
        &self,
        sandbox: &Sandbox,
        record: &Record,
    ) -> Result<bool, KubernetesDriverError> {
        let names = record.names();
        let physical_id = record.physical_id();
        let (data, env) = self.warm_runtime_shape(
            sandbox.spec.as_ref(),
            &physical_id,
            &names,
            record.uid,
            record.gid,
        )?;
        Ok(data == record.shape && env == record.child_env)
    }

    pub(super) async fn claim_warm_object(
        &self,
        sandbox: &Sandbox,
        api: &AgentSandboxApi,
        object: &DynamicObject,
        record: &Record,
        prepared: PreparedRuntimeRegistration,
    ) -> Result<bool, KubernetesDriverError> {
        ensure_unclaimed(object)?;
        let resource = resource_from_object(object, record)?;
        if !resource.released {
            return Err(invalid("warm runtime is not released"));
        }
        let mut auth = decode_launch_authentication(
            &sandbox
                .spec
                .as_ref()
                .ok_or_else(|| invalid("missing sandbox spec"))?
                .launch_authentication,
        )?;
        let expected_generation = auth.supervisor.runtime_generation.clone();
        let expected_auth_epoch = auth.supervisor.auth_epoch;
        // Only a fresh launch can adopt the bootstrap epoch.
        if expected_auth_epoch != record.trust.auth_epoch {
            return Err(invalid(
                "warm claim credential epoch differs from bootstrap",
            ));
        }
        auth.supervisor.runtime_generation = SandboxGenerationId::parse(record.physical_id())
            .map_err(|_| invalid("invalid generation"))?;
        auth.supervisor.session_id = record.session_id;
        auth.supervisor.session_rotation = record.trust.session_rotation;
        let mut descriptor = prepared.runtime_descriptor.clone();
        descriptor.boundary_id.clone_from(&sandbox.id);
        let mut claimed = object.clone();
        let annotations = claimed.metadata.annotations.get_or_insert_default();
        annotations.extend(sandbox_annotations(sandbox));
        annotations.insert(
            ANNOTATION_SANDBOX_RUNTIME_MAIN_PROCESS_SPEC.into(),
            openshell_core::sandbox_env::MainProcessConfig::encode_driver_spec(
                sandbox.spec.as_ref(),
            )
            .map_err(record_error)?,
        );
        annotations.insert(
            ANNOTATION_SANDBOX_RUNTIME_LOG_LEVEL.into(),
            openshell_core::driver_utils::sandbox_log_level(sandbox, "info"),
        );
        let registration = shared_instance_registration(
            &claimed,
            &record.route(),
            &sandbox.id,
            descriptor,
            &auth,
            generate_proxy_ca_material().map_err(KubernetesDriverError::Message)?,
        )?;
        prepared
            .validate_activation(&registration)
            .map_err(|_| invalid("claim does not match preparation"))?;
        let intent = WarmClaimIntent {
            registration,
            expected_generation,
            expected_auth_epoch,
        };
        let reservation = self
            .warm_supervision()?
            .reserve_warm_claim(&record.workspace, intent)
            .await
            .map_err(KubernetesDriverError::Message)?;
        let WarmClaimReservation::Reserved(intent) = reservation else {
            return Ok(false);
        };
        self.bind_warm_claim(sandbox, api, object, record, &intent)
            .await?;
        Ok(true)
    }

    async fn bind_warm_claim(
        &self,
        sandbox: &Sandbox,
        api: &AgentSandboxApi,
        object: &DynamicObject,
        record: &Record,
        intent: &WarmClaimIntent,
    ) -> Result<(), KubernetesDriverError> {
        ensure_unclaimed(object)?;
        let resource = resource_from_object(object, record)?;
        if intent.registration.sandbox_id != sandbox.id
            || intent.registration.route != record.route()
            || intent
                .registration
                .runtime_descriptor
                .resource_claims
                .get("kubernetes.sandbox_resource_uid")
                != Some(&resource.uid)
            || intent
                .registration
                .runtime_descriptor
                .resource_claims
                .get("kubernetes.workload_pod_uid")
                != resource.pod_uid.as_ref()
        {
            return Err(invalid("warm claim physical identity changed"));
        }
        let prepared = PreparedRuntimeRegistration {
            route: record.route(),
            runtime_descriptor: intent.registration.runtime_descriptor.clone(),
        };
        let mut claimed = object.clone();
        let annotations = claimed.metadata.annotations.get_or_insert_default();
        annotations.extend(sandbox_annotations(sandbox));
        annotations.insert(
            ANNOTATION_SANDBOX_RUNTIME_MAIN_PROCESS_SPEC.into(),
            intent.registration.main_process_spec.clone(),
        );
        annotations.insert(
            ANNOTATION_SANDBOX_RUNTIME_LOG_LEVEL.into(),
            openshell_core::driver_utils::sandbox_log_level(sandbox, "info"),
        );
        let intent_name = record.route();
        let policies = Api::<NetworkPolicy>::namespaced(self.client.clone(), &resource.namespace);
        let fence = policies
            .get(&record.names().workload_policy)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        let control = policies
            .get(&record.control_policy_name(self.shared_supervisor.is_none()))
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        verify_claim_policy(&prepared, &fence, "egress")?;
        verify_claim_policy(&prepared, &control, "control")?;
        let annotations = claimed.metadata.annotations.get_or_insert_default();
        annotations.extend(BTreeMap::from([
            (CLAIM.into(), intent_name),
            (
                ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAPPING.into(),
                "true".into(),
            ),
            (
                ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_STARTED_AT.into(),
                openshell_core::time::now_ms().to_string(),
            ),
            (
                ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_OPERATION.into(),
                "create".into(),
            ),
            (
                ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_PHASE.into(),
                SandboxRuntimeBootstrapPhase::Released.as_str().into(),
            ),
            (
                ANNOTATION_SANDBOX_RUNTIME_GENERATION.into(),
                record.physical_id(),
            ),
            (
                ANNOTATION_SANDBOX_RUNTIME_CONTROL_GENERATION.into(),
                record.physical_id(),
            ),
            (
                ANNOTATION_SANDBOX_RUNTIME_CONTROL_CONNECTION.into(),
                KubernetesControlConnection::RuntimeInitiated
                    .as_str()
                    .into(),
            ),
            (
                ANNOTATION_SUPERVISOR_TOPOLOGY.into(),
                GATEWAY_TOPOLOGY.into(),
            ),
            (ANNOTATION_SUPERVISOR_SESSION.into(), record.route()),
            (
                ANNOTATION_SANDBOX_RUNTIME_WORKLOAD_UID.into(),
                resource.pod_uid.clone().expect("checked above"),
            ),
            (
                ANNOTATION_SANDBOX_RUNTIME_NETWORK_POLICY_UID.into(),
                fence
                    .metadata
                    .uid
                    .ok_or_else(|| invalid("fence UID missing"))?,
            ),
            (
                ANNOTATION_SANDBOX_RUNTIME_NETWORK_POLICY_GENERATION.into(),
                fence
                    .metadata
                    .generation
                    .ok_or_else(|| invalid("fence generation missing"))?
                    .to_string(),
            ),
            (
                ANNOTATION_SANDBOX_RUNTIME_CONTROL_POLICY_UID.into(),
                control
                    .metadata
                    .uid
                    .ok_or_else(|| invalid("control UID missing"))?,
            ),
            (
                ANNOTATION_SANDBOX_RUNTIME_CONTROL_POLICY_GENERATION.into(),
                control
                    .metadata
                    .generation
                    .ok_or_else(|| invalid("control generation missing"))?
                    .to_string(),
            ),
        ]));
        if self.shared_supervisor.is_none() {
            annotations.remove(ANNOTATION_SUPERVISOR_TOPOLOGY);
            annotations.remove(ANNOTATION_SUPERVISOR_SESSION);
        }
        let claimed = patch_object(&api.api, object, serde_json::json!({"metadata": {
            "labels": sandbox_labels(sandbox, Some(&self.config.gateway_id)), "annotations": annotations,
        }})).await?;
        self.finish_warm_claim(api, &claimed).await?;
        Ok(())
    }

    pub(in crate::driver) async fn finish_warm_claim(
        &self,
        api: &AgentSandboxApi,
        object: &DynamicObject,
    ) -> Result<(), KubernetesDriverError> {
        Box::pin(self.finish_warm_claim_inner(api, object)).await
    }

    async fn finish_warm_claim_inner(
        &self,
        api: &AgentSandboxApi,
        object: &DynamicObject,
    ) -> Result<(), KubernetesDriverError> {
        if !claim_pending(object) {
            return Ok(());
        }
        if object.metadata.deletion_timestamp.is_some() || !sandbox_runtime_should_run(object) {
            return Err(invalid("warm claim is no longer runnable"));
        }
        let record = read_record(object, &self.config.gateway_id)?;
        if sandbox_runtime_generation(object) != Some(record.physical_id().as_str()) {
            return Err(invalid("warm claim generation changed"));
        }
        let resource = resource_from_object(object, &record)?;
        let logical_id = sandbox_id_from_object(object).map_err(KubernetesDriverError::Message)?;
        if annotation(object, CLAIM) != Some(record.route().as_str()) {
            return Err(invalid("warm claim reference changed"));
        }
        let intent = self
            .warm_supervision()?
            .warm_claim(&record.workspace, &record.route())
            .await
            .map_err(KubernetesDriverError::Message)?;
        if intent.registration.sandbox_id != logical_id
            || intent.registration.route != record.route()
            || intent.registration.runtime_descriptor.session_id != record.session_id
            || intent
                .registration
                .runtime_descriptor
                .resource_claims
                .get("kubernetes.sandbox_resource_uid")
                != Some(&resource.uid)
            || intent
                .registration
                .runtime_descriptor
                .resource_claims
                .get("kubernetes.workload_pod_uid")
                != resource.pod_uid.as_ref()
        {
            return Err(invalid("warm claim physical identity changed"));
        }
        let pod = Api::<Pod>::namespaced(self.client.clone(), &resource.namespace)
            .get(&resource.name)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        if pod.metadata.uid != resource.pod_uid || pod.metadata.deletion_timestamp.is_some() {
            return Err(invalid("claimed warm Pod was replaced"));
        }
        let mut unclaimed = object.clone();
        unclaimed
            .metadata
            .labels
            .get_or_insert_default()
            .remove(LABEL_SANDBOX_ID);
        unclaimed
            .metadata
            .annotations
            .get_or_insert_default()
            .remove(LABEL_SANDBOX_ID);
        validate_pod(&pod, &unclaimed, &record)?;
        self.admit_stored_resources(object)
            .await
            .map_err(admission_error)?;
        self.create_sandbox_runtime_fence(&resource.namespace, &record.names())
            .await?;
        let policies = Api::<NetworkPolicy>::namespaced(self.client.clone(), &resource.namespace);
        let physical = PreparedRuntimeRegistration {
            route: record.route(),
            runtime_descriptor: intent.registration.runtime_descriptor.clone(),
        };
        for (name, kind) in [
            (record.names().workload_policy, "egress"),
            (
                record.control_policy_name(self.shared_supervisor.is_none()),
                "control",
            ),
        ] {
            let policy = policies
                .get(&name)
                .await
                .map_err(KubernetesDriverError::from_kube)?;
            verify_claim_policy(&physical, &policy, kind)?;
        }
        let namespace = Api::<Namespace>::all(self.client.clone())
            .get(&resource.namespace)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        if intent
            .registration
            .runtime_descriptor
            .resource_claims
            .get("kubernetes.namespace_uid")
            != namespace.metadata.uid.as_ref()
        {
            return Err(invalid("warm claim namespace was replaced"));
        }
        self.verify_sandbox_runtime_control_path(object, &logical_id, &resource.namespace, true)
            .await?;
        let supervision = self.warm_supervision()?;
        if self.shared_supervisor.is_none() {
            self.publish_dedicated_claim_identity(object, &record, &intent.registration)
                .await?;
        }
        supervision
            .activate_warm_claim(&record.workspace, &record.route())
            .await
            .map_err(KubernetesDriverError::Message)?;
        complete_claim(&api.api, object).await
    }
}

fn launch_lookup(sandbox: &Sandbox) -> Result<WarmClaimLookup, KubernetesDriverError> {
    let auth = decode_launch_authentication(
        &sandbox
            .spec
            .as_ref()
            .ok_or_else(|| invalid("sandbox spec missing"))?
            .launch_authentication,
    )?;
    Ok(WarmClaimLookup {
        workspace: sandbox.workspace.clone(),
        sandbox_id: sandbox.id.clone(),
        expected_generation: auth.supervisor.runtime_generation,
        expected_auth_epoch: auth.supervisor.auth_epoch,
    })
}

async fn complete_claim(
    api: &Api<DynamicObject>,
    object: &DynamicObject,
) -> Result<(), KubernetesDriverError> {
    let name = object
        .metadata
        .name
        .as_deref()
        .ok_or_else(|| invalid("claim CR name missing"))?;
    let mut current = object.clone();
    for _ in 0..4 {
        if current.metadata.uid != object.metadata.uid
            || sandbox_id_from_object(&current) != sandbox_id_from_object(object)
            || sandbox_runtime_generation(&current) != sandbox_runtime_generation(object)
            || annotation(&current, CLAIM) != annotation(object, CLAIM)
            || !sandbox_runtime_should_run(&current)
            || current.metadata.deletion_timestamp.is_some()
        {
            return Err(invalid("warm claim changed before completion"));
        }
        match api.patch(name, &PatchParams::default(), &Patch::Merge(&serde_json::json!({"metadata": {
            "uid": object.metadata.uid, "resourceVersion": required_version(&current)?, "annotations": {CLAIM_COMPLETE: "true"}
        }}))).await {
            Ok(_) => return Ok(()),
            Err(KubeError::Api(error)) if error.code == 409 => {
                current = api.get(name).await.map_err(KubernetesDriverError::from_kube)?;
            }
            Err(error) => return Err(KubernetesDriverError::from_kube(error)),
        }
    }
    Err(invalid("warm claim completion remained busy"))
}

fn claim_runtime_identity(object: &DynamicObject) -> Result<String, KubernetesDriverError> {
    let record: Record = serde_json::from_str(
        annotation(object, RECORD).ok_or_else(|| invalid("warm record missing"))?,
    )
    .map_err(record_error)?;
    Ok(kubernetes_runtime_identity(
        object
            .metadata
            .namespace
            .as_deref()
            .ok_or_else(|| invalid("warm namespace missing"))?,
        object
            .metadata
            .uid
            .as_deref()
            .ok_or_else(|| invalid("warm CR UID missing"))?,
        annotation(object, ANNOTATION_SANDBOX_RUNTIME_SUPERVISOR_UID).unwrap_or(&record.route()),
    ))
}

fn verify_claim_policy(
    prepared: &PreparedRuntimeRegistration,
    policy: &NetworkPolicy,
    kind: &str,
) -> Result<(), KubernetesDriverError> {
    let claims = &prepared.runtime_descriptor.resource_claims;
    if claims.get(&format!("kubernetes.{kind}_policy_uid")) != policy.metadata.uid.as_ref()
        || claims.get(&format!("kubernetes.{kind}_policy_resource_version"))
            != policy.metadata.resource_version.as_ref()
    {
        return Err(invalid("warm runtime network fence changed before claim"));
    }
    Ok(())
}
