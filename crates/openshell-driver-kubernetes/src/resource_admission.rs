// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Closed workload-reference inventory and metadata-only resource resolution.

use kube::{
    Api, Client,
    api::ApiResource,
    core::{DynamicObject, GroupVersionKind},
};
use openshell_core::resource_admission::ResourceAdmissionConfig;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use tonic::Status;

pub const IDENTITIES: &str = "openshell.ai/resource-admission-identities";
pub const CONFIG_USED: &str = "openshell.ai/caller-driver-config-used";
pub type Identities = BTreeMap<String, String>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Scope {
    /// Data-bearing resources selected for one `OpenShell` workspace.
    Workspace,
    /// Operator infrastructure intentionally reusable across workspaces.
    Shared,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Reference {
    kind: &'static str,
    name: String,
    scope: Scope,
}

fn resource_description(reference: &Reference, namespace: &str, cluster: bool) -> String {
    if cluster {
        format!("{} '{}'", reference.kind, reference.name)
    } else {
        format!("{} '{}/{}'", reference.kind, namespace, reference.name)
    }
}

fn contextualize(status: Status, resource: &str) -> Status {
    Status::new(status.code(), format!("{resource}: {}", status.message()))
}

fn metadata_lookup_error(error: kube::Error, resource: &str) -> Status {
    match error {
        kube::Error::Api(response) if response.code == 404 => {
            Status::failed_precondition(format!("{resource} does not exist"))
        }
        kube::Error::Api(response) if response.code == 403 => Status::unavailable(format!(
            "gateway is forbidden from reading metadata for {resource} (Kubernetes 403); check gateway RBAC"
        )),
        kube::Error::Api(response) if response.code == 401 => Status::unavailable(format!(
            "gateway authentication was rejected while reading metadata for {resource} (Kubernetes 401)"
        )),
        kube::Error::Api(response) => Status::unavailable(format!(
            "Kubernetes API returned {} ({}) while reading metadata for {resource}",
            response.code, response.reason
        )),
        kube::Error::RustlsTls(_) | kube::Error::TlsRequired => Status::unavailable(format!(
            "Kubernetes API TLS failed while reading metadata for {resource}"
        )),
        kube::Error::Auth(_) => Status::unavailable(format!(
            "Kubernetes client authentication failed while reading metadata for {resource}"
        )),
        kube::Error::HyperError(_) | kube::Error::Service(_) => Status::unavailable(format!(
            "Kubernetes API connection failed while reading metadata for {resource}"
        )),
        _ => Status::unavailable(format!(
            "Kubernetes client failed while reading metadata for {resource}"
        )),
    }
}

fn reference(refs: &mut BTreeSet<Reference>, kind: &'static str, name: Option<&str>, scope: Scope) {
    if let Some(name) = name.filter(|name| !name.is_empty()) {
        refs.insert(Reference {
            kind,
            name: name.into(),
            scope,
        });
    }
}

fn inventory(spec: &Value, private_secret: &str) -> Result<BTreeSet<Reference>, Status> {
    let deny = || {
        Status::failed_precondition("workload contains an unsupported external resource attachment")
    };
    let mut refs = BTreeSet::new();
    reference(
        &mut refs,
        "RuntimeClass",
        spec["runtimeClassName"].as_str(),
        Scope::Shared,
    );
    reference(
        &mut refs,
        "PriorityClass",
        spec["priorityClassName"].as_str(),
        Scope::Shared,
    );
    // With automatic and projected tokens prohibited, the workload gets no
    // ServiceAccount credentials. Selecting the Pod's identity is not a grant.
    if spec["automountServiceAccountToken"] != false
        || spec
            .get("resourceClaims")
            .is_some_and(|v| v.as_array().is_none_or(|a| !a.is_empty()))
    {
        return Err(deny());
    }
    // Image-pull Secrets are selected by gateway configuration rather than by
    // the sandbox caller. The kubelet resolves them; they are not workload data
    // attachments and do not participate in caller resource admission.
    for volume in spec["volumes"].as_array().into_iter().flatten() {
        let object = volume.as_object().ok_or_else(deny)?;
        let sources: Vec<_> = object.keys().filter(|key| key.as_str() != "name").collect();
        if sources.len() != 1 {
            return Err(deny());
        }
        match sources[0].as_str() {
            "emptyDir" | "downwardAPI" => {}
            "persistentVolumeClaim" => reference(
                &mut refs,
                "PersistentVolumeClaim",
                volume["persistentVolumeClaim"]["claimName"].as_str(),
                Scope::Workspace,
            ),
            "secret" if volume["secret"]["secretName"].as_str() == Some(private_secret) => {}
            // The typed Kubernetes driver config does not expose Secret or
            // ConfigMap volumes. The closed-set fallback rejects them instead
            // of expanding gateway RBAC for attachments callers cannot request.
            _ => return Err(deny()),
        }
    }
    for field in ["containers", "initContainers", "ephemeralContainers"] {
        for container in spec[field].as_array().into_iter().flatten() {
            if container["envFrom"]
                .as_array()
                .is_some_and(|env| !env.is_empty())
            {
                return Err(deny());
            }
            for env in container["env"].as_array().into_iter().flatten() {
                if !env["valueFrom"]["secretKeyRef"].is_null()
                    || !env["valueFrom"]["configMapKeyRef"].is_null()
                {
                    return Err(deny());
                }
            }
            for field in ["requests", "limits"] {
                for (resource, _) in container["resources"][field]
                    .as_object()
                    .into_iter()
                    .flatten()
                {
                    if resource.contains('/') && resource != "nvidia.com/gpu" {
                        return Err(deny());
                    }
                }
            }
        }
    }
    Ok(refs)
}

/// Resolve references selected through the OpenShell-owned Pod template.
/// Kubernetes control-plane mutations of the eventual live Pod are outside the
/// workspace-user authorization boundary and are not inventoried here.
pub async fn admit(
    client: &Client,
    policy: &ResourceAdmissionConfig,
    workspace: &str,
    namespace: &str,
    spec: &Value,
    private_secret: &str,
) -> Result<Identities, Status> {
    policy.validate().map_err(Status::failed_precondition)?;
    if !policy.enabled {
        return Ok(BTreeMap::new());
    }
    let mut identities = BTreeMap::new();
    for reference in inventory(spec, private_secret)? {
        let (group, version, plural, cluster) = match reference.kind {
            "PersistentVolumeClaim" => ("", "v1", "persistentvolumeclaims", false),
            "RuntimeClass" => ("node.k8s.io", "v1", "runtimeclasses", true),
            "PriorityClass" => ("scheduling.k8s.io", "v1", "priorityclasses", true),
            _ => unreachable!("closed resource inventory"),
        };
        let resource = ApiResource::from_gvk_with_plural(
            &GroupVersionKind::gvk(group, version, reference.kind),
            plural,
        );
        let api: Api<DynamicObject> = if cluster {
            Api::all_with(client.clone(), &resource)
        } else {
            Api::namespaced_with(client.clone(), namespace, &resource)
        };
        let description = resource_description(&reference, namespace, cluster);
        let object = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            api.get_metadata(&reference.name),
        )
        .await
        .map_err(|_| {
            Status::unavailable(format!(
                "Kubernetes API timed out while reading metadata for {description}"
            ))
        })?
        .map_err(|error| metadata_lookup_error(error, &description))?;
        let metadata = object.metadata;
        if metadata.deletion_timestamp.is_some() {
            return Err(Status::failed_precondition(format!(
                "{description} is being deleted"
            )));
        }
        let uid = metadata.uid.filter(|uid| !uid.is_empty()).ok_or_else(|| {
            Status::failed_precondition(format!("{description} has no Kubernetes UID"))
        })?;
        let labels = metadata
            .labels
            .as_ref()
            .into_iter()
            .flat_map(|labels| labels.iter());
        match reference.scope {
            Scope::Workspace => policy
                .admit(workspace, labels)
                .map_err(|status| contextualize(status, &description))?,
            Scope::Shared => policy
                .admit_shared(labels)
                .map_err(|status| contextualize(status, &description))?,
        }
        identities.insert(
            format!(
                "{}/{}/{}",
                reference.kind,
                if cluster { "" } else { namespace },
                reference.name
            ),
            uid,
        );
    }
    Ok(identities)
}

pub fn check_record(
    annotations: Option<&BTreeMap<String, String>>,
    allow_config: bool,
) -> Result<Identities, Status> {
    let annotations = annotations.ok_or_else(|| {
        Status::failed_precondition("sandbox lacks admission provenance; recreate it")
    })?;
    match annotations.get(CONFIG_USED).map(String::as_str) {
        Some("false") => {}
        Some("true") if allow_config => {}
        _ => {
            return Err(Status::failed_precondition(
                "sandbox driver config is disabled or lacks admission provenance; recreate it",
            ));
        }
    }
    annotations
        .get(IDENTITIES)
        .ok_or_else(|| {
            Status::failed_precondition("sandbox lacks resource identities; recreate it")
        })
        .and_then(|value| {
            serde_json::from_str(value)
                .map_err(|_| Status::failed_precondition("invalid resource admission record"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pvc_admission_uses_resource_metadata_not_namespace_or_read_only() {
        for (labels, allowed) in [
            (serde_json::json!({}), false),
            (
                serde_json::json!({"openshell.ai/sandbox-attachable":"true","openshell.ai/sandbox-attachable-workspace":"other"}),
                false,
            ),
            (
                serde_json::json!({"openshell.ai/sandbox-attachable":"true","openshell.ai/sandbox-attachable-workspace":"team-a"}),
                true,
            ),
        ] {
            for read_only in [false, true] {
                let labels = labels.clone();
                let service = tower::service_fn(
                    move |request: http::Request<kube::client::Body>| {
                        assert_eq!(request.method(), http::Method::GET);
                        assert_eq!(
                            request.uri().path(),
                            "/api/v1/namespaces/shared/persistentvolumeclaims/openshell-data-openshell-0"
                        );
                        assert!(
                            request.headers()["accept"]
                                .to_str()
                                .unwrap()
                                .contains("PartialObjectMetadata")
                        );
                        let body = serde_json::json!({"apiVersion":"meta.k8s.io/v1","kind":"PartialObjectMetadata",
                        "metadata":{"name":"openshell-data-openshell-0","namespace":"shared","uid":"fixture-pvc","labels":labels}});
                        async move {
                            Ok::<_, std::convert::Infallible>(
                                http::Response::builder()
                                    .header("content-type", "application/json")
                                    .body(kube::client::Body::from(body.to_string().into_bytes()))
                                    .unwrap(),
                            )
                        }
                    },
                );
                let client = Client::new(service, "shared");
                let spec = serde_json::json!({"automountServiceAccountToken":false,"volumes":[{
                    "name":"data","persistentVolumeClaim":{"claimName":"openshell-data-openshell-0","readOnly":read_only}}]});
                let result = admit(
                    &client,
                    &ResourceAdmissionConfig::default(),
                    "team-a",
                    "shared",
                    &spec,
                    "private",
                )
                .await;
                assert_eq!(result.is_ok(), allowed, "{result:?}");
                if let Ok(identities) = result {
                    assert_eq!(identities.len(), 1);
                }
            }
        }
    }

    #[tokio::test]
    async fn metadata_lookup_errors_identify_the_resource_and_failure_class() {
        for (http_status, reason, expected_code, expected_message) in [
            (
                404,
                "NotFound",
                tonic::Code::FailedPrecondition,
                "does not exist",
            ),
            (
                403,
                "Forbidden",
                tonic::Code::Unavailable,
                "check gateway RBAC",
            ),
            (
                503,
                "ServiceUnavailable",
                tonic::Code::Unavailable,
                "Kubernetes API returned 503 (ServiceUnavailable)",
            ),
        ] {
            let service = tower::service_fn(
                move |_request: http::Request<kube::client::Body>| async move {
                    let body = serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "Status",
                        "status": "Failure",
                        "message": "fixture failure",
                        "reason": reason,
                        "code": http_status,
                    });
                    Ok::<_, std::convert::Infallible>(
                        http::Response::builder()
                            .status(http_status)
                            .header("content-type", "application/json")
                            .body(kube::client::Body::from(body.to_string().into_bytes()))
                            .unwrap(),
                    )
                },
            );
            let client = Client::new(service, "shared");
            let spec = serde_json::json!({
                "automountServiceAccountToken": false,
                "volumes": [{
                    "name": "data",
                    "persistentVolumeClaim": {"claimName": "team-data"}
                }]
            });

            let error = admit(
                &client,
                &ResourceAdmissionConfig::default(),
                "team-a",
                "shared",
                &spec,
                "private",
            )
            .await
            .expect_err("lookup must fail");

            assert_eq!(error.code(), expected_code);
            assert!(
                error
                    .message()
                    .contains("PersistentVolumeClaim 'shared/team-data'"),
                "unexpected error: {error}"
            );
            assert!(
                error.message().contains(expected_message),
                "unexpected error: {error}"
            );
        }
    }

    #[tokio::test]
    async fn label_denial_identifies_the_resource() {
        let service = tower::service_fn(|_request: http::Request<kube::client::Body>| async move {
            let body = serde_json::json!({
                "apiVersion": "meta.k8s.io/v1",
                "kind": "PartialObjectMetadata",
                "metadata": {
                    "name": "kata",
                    "uid": "runtime-class-uid",
                    "labels": {}
                }
            });
            Ok::<_, std::convert::Infallible>(
                http::Response::builder()
                    .header("content-type", "application/json")
                    .body(kube::client::Body::from(body.to_string().into_bytes()))
                    .unwrap(),
            )
        });
        let client = Client::new(service, "shared");
        let spec = serde_json::json!({
            "automountServiceAccountToken": false,
            "runtimeClassName": "kata"
        });

        let error = admit(
            &client,
            &ResourceAdmissionConfig::default(),
            "team-a",
            "shared",
            &spec,
            "private",
        )
        .await
        .expect_err("unlabelled RuntimeClass must be denied");

        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            error.message(),
            "RuntimeClass 'kata': external resource not admitted by required labels"
        );
    }

    #[test]
    fn inventories_supported_external_resources() {
        let pod = serde_json::json!({"automountServiceAccountToken":false,"runtimeClassName":"r","priorityClassName":"p",
            "volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"gateway-db","readOnly":true}}],
            "imagePullSecrets":[{"name":"regcred"}]});
        let refs = inventory(&pod, "private").unwrap();
        assert_eq!(refs.len(), 3);
        assert!(
            refs.iter()
                .any(|r| r.name == "gateway-db" && r.scope == Scope::Workspace)
        );
        assert!(
            refs.iter()
                .any(|r| r.name == "r" && r.scope == Scope::Shared)
        );
    }
    #[test]
    fn rejects_unsupported_volume_sources_but_allows_gpu() {
        for kind in ["hostPath", "csi", "projected", "image", "configMap"] {
            assert!(inventory(&serde_json::json!({"automountServiceAccountToken":false,"volumes":[{"name":"x",kind:{}}]}), "private").is_err());
        }
        assert!(inventory(&serde_json::json!({"automountServiceAccountToken":false,"volumes":[{"name":"x","secret":{"secretName":"external"}}]}), "private").is_err());
        assert!(inventory(&serde_json::json!({"automountServiceAccountToken":false,"volumes":[{"name":"x","secret":{"secretName":"private"}}]}), "private").is_ok());
        assert!(inventory(&serde_json::json!({"automountServiceAccountToken":false,"containers":[{"envFrom":[{"secretRef":{"name":"external"}}]}]}), "private").is_err());
        assert!(inventory(&serde_json::json!({"automountServiceAccountToken":false,"containers":[{"env":[{"valueFrom":{"configMapKeyRef":{"name":"external"}}}]}]}), "private").is_err());
        assert!(inventory(&serde_json::json!({"automountServiceAccountToken":false,"containers":[{"resources":{"limits":{"nvidia.com/gpu":"1"}}}]}), "private").is_ok());
    }
    #[test]
    fn legacy_and_forbidden_config_records_fail_closed() {
        assert!(check_record(None, true).is_err());
        let record = BTreeMap::from([
            (CONFIG_USED.into(), "true".into()),
            (IDENTITIES.into(), "{}".into()),
        ]);
        assert!(check_record(Some(&record), false).is_err());
        assert!(check_record(Some(&record), true).is_ok());
    }
}
