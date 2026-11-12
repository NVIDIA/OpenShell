// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use openshell_core::jwt::CredentialEpoch;
use openshell_core::sandbox_generation::SandboxGenerationId;

pub(super) const CLAIM: &str = "openshell.ai/warm-claim";
const CLAIM_COMPLETE: &str = "openshell.ai/warm-claim-complete";
const INTENT_KEY: &str = "claim.json";

// Credentials and the proxy CA belong in a Pod-owned immutable Secret, never
// in annotations. The CR CAS arbitrates with retirement before DB activation.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimIntent {
    registration: SandboxInstanceRegistration,
    expected_generation: SandboxGenerationId,
    expected_auth_epoch: CredentialEpoch,
}

pub(in crate::driver) fn physical_resource_id(object: &DynamicObject, logical_id: &str) -> String {
    annotation(object, RECORD)
        .and_then(|value| serde_json::from_str::<Record>(value).ok())
        .filter(|record| sandbox_runtime_generation(object) == Some(record.physical_id().as_str()))
        .map_or_else(|| logical_id.to_string(), |record| record.physical_id())
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
    /// No match returns None before any claim is written. Once a claim may have
    /// committed, errors propagate: falling back could launch a second workload.
    pub(in crate::driver) async fn try_claim_warm_runtime(
        &self,
        sandbox: &Sandbox,
        namespace: &str,
    ) -> Result<Option<String>, KubernetesDriverError> {
        if self.warm_supervision().is_err() {
            return Ok(None);
        }
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
            if snapshot.state.revision != pool.revision
                || snapshot.state.fingerprint
                    != reconciler::fingerprint(&self.config, pool, &trust)?
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
                            < i64::try_from(pool.max_age_secs * 1000).unwrap_or(i64::MAX)
                }) || !self.warm_connection_ready(resource).await?
                {
                    continue;
                }
                let object = api
                    .api
                    .get(&resource.name)
                    .await
                    .map_err(KubernetesDriverError::from_kube)?;
                let record = read_record(&object, &self.config.gateway_id)?;
                if !self.warm_shape_matches(sandbox, &record)? {
                    continue;
                }
                // Recheck Pod identity, immutable bootstrap, admission and fences.
                let prepared = self.resume_warm_runtime(resource).await?;
                let object = api
                    .api
                    .get(&resource.name)
                    .await
                    .map_err(KubernetesDriverError::from_kube)?;
                self.claim_warm_object(sandbox, &api, &object, &record, prepared.registration)
                    .await?;
                return claim_runtime_identity(&object).map(Some);
            }
        }
        Ok(None)
    }

    async fn validate_claim_retry(
        &self,
        sandbox: &Sandbox,
        object: &DynamicObject,
    ) -> Result<(), KubernetesDriverError> {
        let record = read_record(object, &self.config.gateway_id)?;
        let namespace = object
            .metadata
            .namespace
            .as_deref()
            .ok_or_else(|| invalid("claim namespace missing"))?;
        let name = format!(
            "{}-claim",
            SandboxRuntimeNames::for_generation(&sandbox.id, &record.physical_id())
                .supervisor_secret
        );
        let secret = Api::<Secret>::namespaced(self.client.clone(), namespace)
            .get(&name)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        let bytes = secret
            .data
            .as_ref()
            .and_then(|data| data.get(INTENT_KEY))
            .filter(|bytes| {
                bytes.0.len() <= openshell_supervisor_control::MAX_LAUNCH_MATERIAL_BYTES
            })
            .ok_or_else(|| invalid("claim intent missing or oversized"))?;
        let intent: ClaimIntent =
            serde_json::from_slice(&bytes.0).map_err(|_| invalid("invalid claim intent"))?;
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
        let mut data = sandbox_to_k8s_spec(
            sandbox.spec.as_ref(),
            &SandboxPodParams {
                default_image: &self.config.default_image,
                image_pull_policy: self.config.image_pull_policy,
                image_pull_secrets: &self.config.image_pull_secrets,
                sandbox_runtime_image: &self.config.sandbox_runtime_image,
                sandbox_runtime_image_pull_policy: self.config.sandbox_runtime_image_pull_policy,
                service_account_name: &self.config.service_account_name,
                sandbox_id: &physical_id,
                enable_user_namespaces: self.config.enable_user_namespaces,
                workspace_default_storage_size: &self.config.workspace_default_storage_size,
                workspace_storage_class: &self.config.workspace_storage_class,
                default_runtime_class_name: &self.config.default_runtime_class_name,
                sandbox_uid: record.uid,
                sandbox_gid: record.gid,
                boundary_port: self.config.sandbox_runtime.boundary_port,
                sandbox_secret_name: &names.sandbox_secret,
            },
        )
        .map_err(KubernetesDriverError::InvalidArgument)?;
        canonicalize_environment(&mut data);
        let mut env: BTreeMap<String, String> = sandbox
            .spec
            .as_ref()
            .and_then(|spec| spec.template.as_ref())
            .map(|template| template.environment.clone().into_iter().collect())
            .unwrap_or_default();
        if let Some(spec) = &sandbox.spec {
            env.extend(spec.environment.clone());
        }
        env.retain(|key, _| !key.starts_with("OPENSHELL_"));
        Ok(data == record.shape && env == record.child_env)
    }

    pub(super) async fn claim_warm_object(
        &self,
        sandbox: &Sandbox,
        api: &AgentSandboxApi,
        object: &DynamicObject,
        record: &Record,
        prepared: PreparedRuntimeRegistration,
    ) -> Result<(), KubernetesDriverError> {
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
        let intent = ClaimIntent {
            registration,
            expected_generation,
            expected_auth_epoch,
        };
        let names = SandboxRuntimeNames::for_generation(&sandbox.id, &record.physical_id());
        let intent_name = format!("{}-claim", names.supervisor_secret);
        let owner = runtime_pod_owner(
            &resource.name,
            resource
                .pod_uid
                .as_deref()
                .ok_or_else(|| invalid("warm Pod UID missing"))?,
        );
        let mut secret = shared_instance_secret(
            &resource.namespace,
            &names,
            &sandbox.id,
            serde_json::to_vec(&intent).map_err(record_error)?,
            owner,
        );
        secret.metadata.name = Some(intent_name.clone());
        let bytes = secret
            .data
            .as_mut()
            .expect("shared instance data")
            .remove(SHARED_INSTANCE_KEY)
            .expect("shared instance key");
        secret
            .data
            .as_mut()
            .expect("shared instance data")
            .insert(INTENT_KEY.into(), bytes);
        // A fresh name is unique to this logical/physical pairing. A conflict is
        // retried through the CR journal, never by replacing existing credentials.
        let secrets = Api::<Secret>::namespaced(self.client.clone(), &resource.namespace);
        match secrets.create(&PostParams::default(), &secret).await {
            Ok(_) => {}
            Err(KubeError::Api(error)) if error.code == 409 => {
                let stored = secrets
                    .get(&intent_name)
                    .await
                    .map_err(KubernetesDriverError::from_kube)?;
                let bytes = stored
                    .data
                    .as_ref()
                    .and_then(|data| data.get(INTENT_KEY))
                    .filter(|bytes| {
                        bytes.0.len() <= openshell_supervisor_control::MAX_LAUNCH_MATERIAL_BYTES
                    })
                    .ok_or_else(|| invalid("warm claim intent missing or oversized"))?;
                let previous: ClaimIntent = serde_json::from_slice(&bytes.0)
                    .map_err(|_| invalid("invalid warm claim intent"))?;
                let mut expected = intent;
                expected
                    .registration
                    .proxy_ca
                    .clone_from(&previous.registration.proxy_ca);
                expected
                    .registration
                    .trace_context
                    .clone_from(&previous.registration.trace_context);
                if stored.immutable != secret.immutable
                    || stored.metadata.owner_references != secret.metadata.owner_references
                    || serde_json::to_value(&expected).map_err(record_error)?
                        != serde_json::to_value(&previous).map_err(record_error)?
                {
                    return Err(invalid("warm claim intent changed"));
                }
            }
            Err(error) => return Err(KubernetesDriverError::from_kube(error)),
        }
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
        let names = SandboxRuntimeNames::for_generation(&logical_id, &record.physical_id());
        let intent_name = format!("{}-claim", names.supervisor_secret);
        if annotation(object, CLAIM) != Some(intent_name.as_str()) {
            return Err(invalid("warm claim Secret reference changed"));
        }
        let secrets = Api::<Secret>::namespaced(self.client.clone(), &resource.namespace);
        let intent_secret = secrets
            .get(&intent_name)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        let owner = runtime_pod_owner(
            &resource.name,
            resource
                .pod_uid
                .as_deref()
                .ok_or_else(|| invalid("warm Pod UID missing"))?,
        );
        if intent_secret.immutable != Some(true)
            || intent_secret.metadata.owner_references.as_deref()
                != Some(std::slice::from_ref(&owner))
        {
            return Err(invalid("warm claim Secret ownership changed"));
        }
        let bytes = intent_secret
            .data
            .as_ref()
            .and_then(|data| data.get(INTENT_KEY))
            .ok_or_else(|| invalid("warm claim material missing"))?;
        if bytes.0.len() > openshell_supervisor_control::MAX_LAUNCH_MATERIAL_BYTES {
            return Err(invalid("warm claim material too large"));
        }
        let intent: ClaimIntent =
            serde_json::from_slice(&bytes.0).map_err(|_| invalid("invalid warm claim material"))?;
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
        let committed = supervision
            .activate(
                &intent.registration,
                intent.expected_generation,
                intent.expected_auth_epoch,
            )
            .await
            .map_err(KubernetesDriverError::Message)?;
        let material = committed
            .to_assignment()
            .map_err(|_| invalid("invalid committed claim"))?
            .launch_material;
        let canonical =
            shared_instance_secret(&resource.namespace, &names, &logical_id, material, owner);
        match secrets.create(&PostParams::default(), &canonical).await {
            Ok(_) => {}
            Err(KubeError::Api(error)) if error.code == 409 => {
                let stored = secrets
                    .get(&names.supervisor_secret)
                    .await
                    .map_err(KubernetesDriverError::from_kube)?;
                if stored.immutable != canonical.immutable
                    || stored.data != canonical.data
                    || stored.metadata.owner_references != canonical.metadata.owner_references
                {
                    return Err(invalid("committed warm claim material changed"));
                }
            }
            Err(error) => return Err(KubernetesDriverError::from_kube(error)),
        }
        complete_claim(&api.api, object).await
    }
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
