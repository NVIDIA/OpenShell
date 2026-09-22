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
    for secret in spec["imagePullSecrets"].as_array().into_iter().flatten() {
        reference(&mut refs, "Secret", secret["name"].as_str(), Scope::Shared);
    }
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
            "secret" => {
                let name = volume["secret"]["secretName"].as_str();
                if name != Some(private_secret) {
                    reference(&mut refs, "Secret", name, Scope::Workspace);
                }
            }
            "configMap" => reference(
                &mut refs,
                "ConfigMap",
                volume["configMap"]["name"].as_str(),
                Scope::Workspace,
            ),
            _ => return Err(deny()),
        }
    }
    for field in ["containers", "initContainers", "ephemeralContainers"] {
        for container in spec[field].as_array().into_iter().flatten() {
            for env in container["envFrom"].as_array().into_iter().flatten() {
                reference(
                    &mut refs,
                    "Secret",
                    env["secretRef"]["name"].as_str(),
                    Scope::Workspace,
                );
                reference(
                    &mut refs,
                    "ConfigMap",
                    env["configMapRef"]["name"].as_str(),
                    Scope::Workspace,
                );
            }
            for env in container["env"].as_array().into_iter().flatten() {
                reference(
                    &mut refs,
                    "Secret",
                    env["valueFrom"]["secretKeyRef"]["name"].as_str(),
                    Scope::Workspace,
                );
                reference(
                    &mut refs,
                    "ConfigMap",
                    env["valueFrom"]["configMapKeyRef"]["name"].as_str(),
                    Scope::Workspace,
                );
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
            "Secret" => ("", "v1", "secrets", false),
            "ConfigMap" => ("", "v1", "configmaps", false),
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
        let object = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            api.get_metadata(&reference.name),
        )
        .await
        .map_err(|_| Status::unavailable("resource admission lookup timed out"))?
        .map_err(|error| match error {
            kube::Error::Api(response) if response.code == 404 => {
                Status::failed_precondition("external resource not admitted")
            }
            _ => Status::unavailable("resource admission metadata lookup failed"),
        })?;
        let metadata = object.metadata;
        if metadata.deletion_timestamp.is_some() {
            return Err(Status::failed_precondition("resource is being deleted"));
        }
        let uid = metadata
            .uid
            .filter(|uid| !uid.is_empty())
            .ok_or_else(|| Status::failed_precondition("resource has no identity"))?;
        let labels = metadata
            .labels
            .as_ref()
            .into_iter()
            .flat_map(|labels| labels.iter());
        match reference.scope {
            Scope::Workspace => policy.admit(workspace, labels)?,
            Scope::Shared => policy.admit_shared(labels)?,
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
                serde_json::json!({"openshell.ai/sandbox-attachable":"true","openshell.ai/workspace":"other"}),
                false,
            ),
            (
                serde_json::json!({"openshell.ai/sandbox-attachable":"true","openshell.ai/workspace":"team-a"}),
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
    #[test]
    fn inventories_all_containers_and_reference_aliases() {
        let pod = serde_json::json!({"automountServiceAccountToken":false,"runtimeClassName":"r","priorityClassName":"p",
            "volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"gateway-db","readOnly":true}}],
            "initContainers":[{"envFrom":[{"secretRef":{"name":"secret"}}]}],
            "containers":[{"env":[{"valueFrom":{"configMapKeyRef":{"name":"config"}}}]}]});
        let refs = inventory(&pod, "private").unwrap();
        assert_eq!(refs.len(), 5);
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
        for kind in ["hostPath", "csi", "projected", "image"] {
            assert!(inventory(&serde_json::json!({"automountServiceAccountToken":false,"volumes":[{"name":"x",kind:{}}]}), "private").is_err());
        }
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
