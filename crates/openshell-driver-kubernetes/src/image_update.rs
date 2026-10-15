// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Storage-preserving, stopped-only workload image mutation.

use super::{
    KUBE_API_TIMEOUT, KubernetesComputeDriver, KubernetesDriverError, LABEL_SANDBOX_ID,
    LABEL_SANDBOX_NAME, SANDBOX_POD_NAME_ANNOTATION, SANDBOX_VERSION_V1BETA1,
    WORKSPACE_INIT_CONTAINER_NAME, accepts_auth_namespace, admission_error, annotation_or_label,
    is_kube_resource_version_conflict, parse_kubernetes_runtime_identity, sandbox_id_from_object,
    sandbox_runtime_bootstrap_in_progress, select_expected_sandbox_runtime,
};
use k8s_openapi::api::core::v1::Pod;
use kube::Api;
use kube::api::{DynamicObject, ListParams, Patch, PatchParams};
use openshell_core::proto::compute::v1::UpdateSandboxImageRequest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::LazyLock;

// Deliberately separate from the runtime bootstrap operation annotations. Those
// annotations drive reconciliation and only describe create/start/stop.
const IMAGE_UPDATE_ANNOTATION: &str = "openshell.ai/sandbox-image-update";

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
struct ImageUpdateRecord {
    operation_id: String,
    expected_image: String,
    image: String,
    revision: u64,
}

impl KubernetesComputeDriver {
    /// Update only a suspended Sandbox's workload and workspace seed images.
    /// The resource, claim templates, existing claims, and runtime bootstrap
    /// annotations are never replaced. A retry is recognized from durable
    /// operation evidence on the same immutable Sandbox resource.
    #[tracing::instrument(
        name = "kubernetes.update_sandbox_image",
        skip_all,
        fields(
            otel.name = "kubernetes.update_sandbox_image",
            otel.status_code = tracing::field::Empty,
            sandbox.id = %request.sandbox_id,
        )
    )]
    pub async fn update_sandbox_image(
        &self,
        request: &UpdateSandboxImageRequest,
    ) -> Result<(), KubernetesDriverError> {
        let span_status = openshell_otel::ErrorStatusGuard::current();
        validate_image_update_request(request)?;
        let _guard = self
            .lifecycle_gates
            .gate_for(&request.sandbox_id)
            .lock_owned()
            .await;
        // Include discovery, admission and Pod pagination in a single bound.
        let result =
            tokio::time::timeout(KUBE_API_TIMEOUT, self.update_sandbox_image_inner(request))
                .await
                .unwrap_or_else(|_| {
                    Err(KubernetesDriverError::Message(
                        "timed out updating Kubernetes sandbox image; retry the same operation"
                            .into(),
                    ))
                });
        span_status.finish(result)
    }

    async fn update_sandbox_image_inner(
        &self,
        request: &UpdateSandboxImageRequest,
    ) -> Result<(), KubernetesDriverError> {
        let expected = parse_kubernetes_runtime_identity(&request.expected_runtime_identity)?;
        self.wait_for_operator_allowlist()
            .await
            .map_err(admission_error)?;
        if !accepts_auth_namespace(
            &self.config,
            self.operator_allowlist.as_ref(),
            &expected.namespace,
        ) {
            return Err(KubernetesDriverError::Precondition(
                "persisted runtime namespace is outside the driver's configured scope".into(),
            ));
        }
        let lookup = self
            .supported_sandbox_api_for_lookup(self.client.clone())
            .await
            .map_err(KubernetesDriverError::Message)?;
        let objects = lookup
            .api
            .list(&ListParams::default().labels(&self.sandbox_lookup_selector(&request.sandbox_id)))
            .await
            .map_err(KubernetesDriverError::from_kube)?
            .items;
        let selected = select_expected_sandbox_runtime(objects, &expected)?;
        let name = selected.metadata.name.as_deref().ok_or_else(|| {
            KubernetesDriverError::Precondition("Sandbox resource has no name".into())
        })?;
        let api = Self::agent_sandbox_api(
            self.client.clone(),
            &lookup.resource.version,
            &expected.namespace,
        );
        // Refresh after selection, then use exactly this snapshot's version in
        // the patch. Never retry a resourceVersion conflict with a stale image,
        // attachment inventory or operating-state decision.
        let object = api
            .api
            .get(name)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        let object = select_expected_sandbox_runtime(vec![object], &expected)?;
        if sandbox_id_from_object(&object).as_deref() != Ok(request.sandbox_id.as_str())
            || annotation_or_label(&object, LABEL_SANDBOX_NAME).as_deref()
                != Some(request.name.as_str())
        {
            return Err(KubernetesDriverError::Precondition(
                "Sandbox resource does not match the requested sandbox identity".into(),
            ));
        }
        require_stopped_for_image_update(&object, &lookup.resource.version)?;
        let mut candidate = object.clone();
        let repeat = prepare_image_update(&mut candidate, request)?;
        // Revalidate the saved provenance and attachment UIDs against current
        // operator policy, even for retries. Do not manufacture new provenance
        // or re-render driver_config from a caller's request.
        self.admit_stored_resources(&candidate)
            .await
            .map_err(admission_error)?;
        self.require_image_update_pods_absent(&object, &request.sandbox_id, &expected.namespace)
            .await?;
        if request.validate_only || repeat {
            return Ok(());
        }
        let version = object
            .metadata
            .resource_version
            .as_deref()
            .filter(|version| !version.is_empty())
            .ok_or_else(|| {
                KubernetesDriverError::Precondition(
                    "Sandbox resource has no resourceVersion".into(),
                )
            })?;
        let record = candidate
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(IMAGE_UPDATE_ANNOTATION))
            .expect("prepared image update has operation evidence");
        let mut patch = serde_json::json!({
            "metadata": {
                "uid": expected.resource_uid,
                "resourceVersion": version,
                "annotations": {IMAGE_UPDATE_ANNOTATION: record}
            },
            "spec": {"podTemplate": {"spec": {
                "containers": candidate.data["spec"]["podTemplate"]["spec"]["containers"]
            }}}
        });
        if let Some(init) = candidate
            .data
            .pointer("/spec/podTemplate/spec/initContainers")
        {
            patch["spec"]["podTemplate"]["spec"]["initContainers"] = init.clone();
        }
        api.api
            .patch(name, &PatchParams::default(), &Patch::Merge(&patch))
            .await
            .map_err(|error| {
                if is_kube_resource_version_conflict(&error) {
                    KubernetesDriverError::Precondition(
                        "Sandbox changed during image update; retry the same operation".into(),
                    )
                } else {
                    KubernetesDriverError::from_kube(error)
                }
            })?;
        Ok(())
    }

    async fn require_image_update_pods_absent(
        &self,
        object: &DynamicObject,
        sandbox_id: &str,
        namespace: &str,
    ) -> Result<(), KubernetesDriverError> {
        let pods = Api::<Pod>::namespaced(self.client.clone(), namespace);
        // The controller's workload Pod need not carry the OpenShell sandbox
        // label. Inspect owner UIDs and recorded names as well as labels and
        // annotations, and reject terminating Pods too. Listing the namespace
        // also catches supervisors from earlier runtime generations.
        let mut params = ListParams::default().limit(500);
        loop {
            let page = pods
                .list(&params)
                .await
                .map_err(KubernetesDriverError::from_kube)?;
            if page
                .items
                .iter()
                .any(|pod| image_update_pod_matches(pod, object, sandbox_id))
            {
                return Err(KubernetesDriverError::Precondition(
                    "cannot update image while sandbox workload or supervisor Pods still exist"
                        .into(),
                ));
            }
            match page.metadata.continue_.filter(|token| !token.is_empty()) {
                Some(token) => params = params.continue_token(&token),
                None => return Ok(()),
            }
        }
    }
}

fn validate_image_update_request(
    request: &UpdateSandboxImageRequest,
) -> Result<(), KubernetesDriverError> {
    for (field, value) in [
        ("sandbox_id", request.sandbox_id.as_str()),
        ("name", request.name.as_str()),
        ("operation_id", request.operation_id.as_str()),
    ] {
        if value.is_empty()
            || value.len() > 1024
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(KubernetesDriverError::InvalidArgument(format!(
                "{field} must be a nonempty bounded identifier"
            )));
        }
    }
    if request.revision == 0 {
        return Err(KubernetesDriverError::InvalidArgument(
            "image update revision must be nonzero".into(),
        ));
    }
    validate_workload_image(&request.image)?;
    // The old reference is only a compare-and-swap precondition, not a new
    // launch input. Legacy create accepted references that kubelet cannot pull;
    // validating their syntax here would prevent repairing those sandboxes.
    if request.expected_image.is_empty() || request.expected_image.len() > 2048 {
        return Err(KubernetesDriverError::InvalidArgument(
            "expected_image must be a nonempty bounded reference".into(),
        ));
    }
    Ok(())
}

fn validate_workload_image(image: &str) -> Result<(), KubernetesDriverError> {
    // Distribution reference grammar: registry (including a port or bracketed
    // IPv6), lowercase repository path, optional tag and/or algorithm:digest.
    // Validation is syntax only: resolving/pulling the image remains kubelet's
    // job, using the existing operator-selected image-pull Secret inventory.
    static REFERENCE: LazyLock<regex::Regex> = LazyLock::new(|| {
        let host_component = r"[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?";
        let host = format!(r"(?:{host_component}(?:\.{host_component})*|\[[a-fA-F0-9:]+\])");
        let path = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*";
        regex::Regex::new(&format!(
            r"^(?:{host}(?::[0-9]+)?/)?{path}(?:/{path})*(?::[a-zA-Z0-9_][a-zA-Z0-9_.-]{{0,127}})?(?:@[a-zA-Z][a-zA-Z0-9]*(?:[-_+.][a-zA-Z][a-zA-Z0-9]*)*:[a-fA-F0-9]{{32,}})?$"
        )).expect("valid distribution reference grammar")
    });
    let named = image.split('@').next().unwrap_or_default();
    let repository =
        named.rsplit_once(':').map_or(
            named,
            |(prefix, suffix)| {
                if suffix.contains('/') { named } else { prefix }
            },
        );
    let digest_length_valid = image.rsplit_once('@').is_none_or(|(_, digest)| {
        digest
            .split_once(':')
            .is_some_and(|(algorithm, encoded)| match algorithm {
                "sha256" => encoded.len() == 64,
                "sha384" => encoded.len() == 96,
                "sha512" => encoded.len() == 128,
                _ => true,
            })
    });
    if image.len() > 2048
        || repository.len() > 255
        || !digest_length_valid
        || !REFERENCE.is_match(image)
    {
        return Err(KubernetesDriverError::InvalidArgument(
            "image must be a valid container image reference of at most 2048 bytes".into(),
        ));
    }
    Ok(())
}

fn require_stopped_for_image_update(
    object: &DynamicObject,
    version: &str,
) -> Result<(), KubernetesDriverError> {
    let suspended = if version == SANDBOX_VERSION_V1BETA1 {
        object
            .data
            .pointer("/spec/operatingMode")
            .and_then(serde_json::Value::as_str)
            == Some("Suspended")
    } else {
        object
            .data
            .pointer("/spec/replicas")
            .and_then(serde_json::Value::as_i64)
            == Some(0)
    };
    if !suspended
        || object.metadata.deletion_timestamp.is_some()
        || sandbox_runtime_bootstrap_in_progress(object)
    {
        return Err(KubernetesDriverError::Precondition(
            "image updates require a stopped, suspended sandbox with no runtime bootstrap in progress".into(),
        ));
    }
    Ok(())
}

/// Apply the image-only mutation in memory; return true for an exact retry.
fn prepare_image_update(
    object: &mut DynamicObject,
    request: &UpdateSandboxImageRequest,
) -> Result<bool, KubernetesDriverError> {
    let evidence = object
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(IMAGE_UPDATE_ANNOTATION))
        .map(|value| serde_json::from_str::<ImageUpdateRecord>(value))
        .transpose()
        .map_err(|_| {
            KubernetesDriverError::Precondition("invalid stored image update evidence".into())
        })?;
    let record = ImageUpdateRecord {
        operation_id: request.operation_id.clone(),
        expected_image: request.expected_image.clone(),
        image: request.image.clone(),
        revision: request.revision,
    };
    if let Some(saved) = &evidence {
        if request.revision < saved.revision {
            return Err(KubernetesDriverError::Precondition(
                "image update revision is older than the stored image revision".into(),
            ));
        }
        if request.revision == saved.revision && saved != &record {
            return Err(KubernetesDriverError::Precondition(
                "image update revision was already used with different operation parameters".into(),
            ));
        }
        if saved.operation_id == request.operation_id && saved != &record {
            return Err(KubernetesDriverError::Precondition(
                "image update operation_id was already used with different parameters".into(),
            ));
        }
    }
    let repeat = evidence.as_ref() == Some(&record);
    let containers = object
        .data
        .pointer_mut("/spec/podTemplate/spec/containers")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| {
            KubernetesDriverError::Precondition("Sandbox has no workload containers".into())
        })?;
    let mut agents = containers
        .iter_mut()
        .filter(|container| container["name"] == "agent");
    let agent = agents.next().ok_or_else(|| {
        KubernetesDriverError::Precondition("Sandbox has no agent container".into())
    })?;
    if agents.next().is_some() {
        return Err(KubernetesDriverError::Precondition(
            "Sandbox has multiple agent containers".into(),
        ));
    }
    let expected: &str = if repeat {
        &request.image
    } else {
        &request.expected_image
    };
    if agent["image"].as_str() != Some(expected) {
        return Err(KubernetesDriverError::Precondition(
            "Sandbox workload image does not match expected_image or the recorded operation target"
                .into(),
        ));
    }
    agent["image"] = serde_json::json!(request.image);
    if let Some(init) = object
        .data
        .pointer_mut("/spec/podTemplate/spec/initContainers")
        .and_then(serde_json::Value::as_array_mut)
    {
        for container in init
            .iter_mut()
            .filter(|container| container["name"] == WORKSPACE_INIT_CONTAINER_NAME)
        {
            if container["image"].as_str() != Some(expected) {
                return Err(KubernetesDriverError::Precondition(
                    "Sandbox workspace seed image does not match its workload image".into(),
                ));
            }
            container["image"] = serde_json::json!(request.image);
        }
    }
    object
        .metadata
        .annotations
        .get_or_insert_with(BTreeMap::new)
        .insert(
            IMAGE_UPDATE_ANNOTATION.into(),
            serde_json::to_string(&record).expect("image update record serializes"),
        );
    Ok(repeat)
}

fn image_update_pod_matches(pod: &Pod, object: &DynamicObject, sandbox_id: &str) -> bool {
    let metadata = &pod.metadata;
    metadata.owner_references.as_ref().is_some_and(|owners| {
        owners
            .iter()
            .any(|owner| Some(owner.uid.as_str()) == object.metadata.uid.as_deref())
    }) || metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(LABEL_SANDBOX_ID))
        .map(String::as_str)
        == Some(sandbox_id)
        || metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(LABEL_SANDBOX_ID))
            .map(String::as_str)
            == Some(sandbox_id)
        || metadata.name.as_deref().is_some_and(|name| {
            Some(name) == object.metadata.name.as_deref()
                || object
                    .metadata
                    .annotations
                    .as_ref()
                    .and_then(|annotations| annotations.get(SANDBOX_POD_NAME_ANNOTATION))
                    .map(String::as_str)
                    == Some(name)
        })
}

#[cfg(test)]
#[path = "image_update_tests.rs"]
mod tests;
