// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Mutating admission webhook for `SandboxRuntime` CRDs.
//!
//! Sets default values and injects labels on CREATE, analogous to
//! Kagenti's pod_mutator.go (simplified for CRD mutation).

use axum::{http::StatusCode, response::IntoResponse, Json};
use kube::core::admission::{AdmissionRequest, AdmissionResponse, AdmissionReview};
use tracing::{info, warn};

use crate::crd::SandboxRuntime;

/// Build the list of JSON Patch operations to apply to the incoming object.
///
/// Returns an empty vec when no mutations are needed.
///
/// V1 review fixes incorporated:
/// - Ensures `/metadata/labels` exists before adding label keys (RFC 6902).
/// - Uses single early-return guard instead of redundant nesting.
/// - Tests actually call this function and verify patch output.
pub fn build_patches(request: &AdmissionRequest<SandboxRuntime>) -> Vec<json_patch::PatchOperation> {
    let Some(runtime) = &request.object else {
        return Vec::new();
    };

    let mut patches = Vec::new();

    // Ensure /metadata/labels exists before adding a label key into it.
    // Without this, the Add at a nested path fails if labels is null/absent
    // (RFC 6902: Add at a nested path requires all parents to exist).
    let has_labels = runtime
        .metadata
        .labels
        .as_ref()
        .is_some_and(|l| !l.is_empty());
    if !has_labels {
        patches.push(json_patch::PatchOperation::Add(json_patch::AddOperation {
            path: "/metadata/labels".to_string(),
            value: serde_json::json!({}),
        }));
    }

    // Inject managed-by label.
    patches.push(json_patch::PatchOperation::Add(json_patch::AddOperation {
        // RFC 6901: ~1 encodes "/" in JSON Pointer paths.
        path: "/metadata/labels/app.kubernetes.io~1managed-by".to_string(),
        value: serde_json::Value::String(crate::labels::MANAGER_NAME.to_string()),
    }));

    // Set targetRef.name to metadata.name if not specified.
    if runtime.spec.target_ref.name.is_empty() && !request.name.is_empty() {
        patches.push(json_patch::PatchOperation::Add(json_patch::AddOperation {
            path: "/spec/targetRef/name".to_string(),
            value: serde_json::Value::String(request.name.clone()),
        }));
    }

    patches
}

/// Handler for the mutating admission webhook.
pub async fn handle_mutate(
    Json(review): Json<AdmissionReview<SandboxRuntime>>,
) -> impl IntoResponse {
    let request: AdmissionRequest<SandboxRuntime> = match review.try_into() {
        Ok(req) => req,
        Err(e) => {
            warn!(error = %e, "failed to parse admission request");
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };

    let patches = build_patches(&request);

    let response = if patches.is_empty() {
        AdmissionResponse::from(&request).into_review()
    } else {
        let patch = json_patch::Patch(patches);
        match AdmissionResponse::from(&request).with_patch(patch) {
            Ok(resp) => {
                let name = if request.name.is_empty() {
                    "-"
                } else {
                    &request.name
                };
                info!(name, "mutation applied");
                resp.into_review()
            }
            Err(e) => {
                warn!(error = %e, "failed to apply mutation patch");
                AdmissionResponse::from(&request)
                    .deny(e.to_string())
                    .into_review()
            }
        }
    };

    Json(response).into_response()
}

#[cfg(test)]
mod tests {
    use crate::crd::{SandboxRuntimeSpec, ServicePort, TargetRef};

    use super::*;

    fn make_request(spec: SandboxRuntimeSpec) -> AdmissionRequest<SandboxRuntime> {
        let runtime = SandboxRuntime::new("test-runtime", spec);
        let review_json = serde_json::json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "test-uid-12345",
                "kind": {
                    "group": "openshell.io",
                    "version": "v1alpha1",
                    "kind": "SandboxRuntime"
                },
                "resource": {
                    "group": "openshell.io",
                    "version": "v1alpha1",
                    "resource": "sandboxruntimes"
                },
                "operation": "CREATE",
                "name": "test-runtime",
                "namespace": "default",
                "userInfo": {
                    "username": "system:admin"
                },
                "object": serde_json::to_value(&runtime).unwrap()
            }
        });
        let review: AdmissionReview<SandboxRuntime> =
            serde_json::from_value(review_json).unwrap();
        review.try_into().unwrap()
    }

    fn valid_spec() -> SandboxRuntimeSpec {
        SandboxRuntimeSpec {
            runtime_type: "agent".into(),
            target_ref: TargetRef {
                api_version: "apps/v1".into(),
                kind: "Deployment".into(),
                name: "test-runtime".into(),
            },
            image: "my-image:v1".into(),
            replicas: 1,
            env: vec![],
            resources: None,
            service_ports: vec![ServicePort {
                name: "http".into(),
                port: 8080,
                target_port: 8000,
                protocol: "TCP".into(),
            }],
            description: String::new(),
        }
    }

    #[test]
    fn always_patches_managed_by_label() {
        let request = make_request(valid_spec());
        let patches = build_patches(&request);
        let has_managed_by = patches.iter().any(|p| match p {
            json_patch::PatchOperation::Add(op) => op.path.contains("managed-by"),
            _ => false,
        });
        assert!(
            has_managed_by,
            "expected managed-by patch, got: {patches:?}"
        );
    }

    #[test]
    fn patches_target_ref_name_when_empty() {
        let mut spec = valid_spec();
        spec.target_ref.name = String::new();
        let request = make_request(spec);
        let patches = build_patches(&request);
        let has_target_ref = patches.iter().any(|p| match p {
            json_patch::PatchOperation::Add(op) => op.path == "/spec/targetRef/name",
            _ => false,
        });
        assert!(
            has_target_ref,
            "expected targetRef/name patch, got: {patches:?}"
        );
    }

    #[test]
    fn no_target_ref_patch_when_name_set() {
        let request = make_request(valid_spec());
        let patches = build_patches(&request);
        let has_target_ref = patches.iter().any(|p| match p {
            json_patch::PatchOperation::Add(op) => op.path == "/spec/targetRef/name",
            _ => false,
        });
        assert!(
            !has_target_ref,
            "should NOT have targetRef/name patch when name is set"
        );
    }

    #[test]
    fn ensures_labels_object_exists() {
        let request = make_request(valid_spec());
        let patches = build_patches(&request);
        // The very first patch should ensure /metadata/labels exists
        // (SandboxRuntime::new doesn't set labels by default).
        let first_path = match &patches[0] {
            json_patch::PatchOperation::Add(op) => &op.path,
            _ => panic!("expected Add operation"),
        };
        assert_eq!(first_path, "/metadata/labels");
    }

    #[test]
    fn no_patches_when_no_object() {
        let mut request = make_request(valid_spec());
        request.object = None;
        let patches = build_patches(&request);
        assert!(patches.is_empty());
    }

    #[test]
    fn managed_by_value_is_operator() {
        let request = make_request(valid_spec());
        let patches = build_patches(&request);
        let managed_by_patch = patches
            .iter()
            .find(|p| match p {
                json_patch::PatchOperation::Add(op) => op.path.contains("managed-by"),
                _ => false,
            })
            .expect("expected managed-by patch");
        if let json_patch::PatchOperation::Add(op) = managed_by_patch {
            assert_eq!(op.value, serde_json::json!("openshell-operator"));
        }
    }
}
