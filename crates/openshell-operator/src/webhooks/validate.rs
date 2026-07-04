// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Validating admission webhook for `SandboxRuntime` CRDs.
//!
//! Validates field combinations and constraints on CREATE and UPDATE
//! operations, analogous to Kagenti's `agentruntime_webhook.go`.

use axum::{http::StatusCode, response::IntoResponse, Json};
use kube::core::admission::{AdmissionRequest, AdmissionResponse, AdmissionReview};
use tracing::{info, warn};

use crate::crd::SandboxRuntime;

/// Handler for the validating admission webhook.
///
/// Receives `AdmissionReview<SandboxRuntime>` -- the type parameter must be
/// `SandboxRuntime` (implements `kube::Resource`), NOT `SandboxRuntimeSpec`.
pub async fn handle_validate(
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

    let response = match validate_runtime(&request) {
        Ok(()) => {
            let name = if request.name.is_empty() {
                "-"
            } else {
                &request.name
            };
            let ns = request.namespace.as_deref().unwrap_or("-");
            info!(name, namespace = ns, "validation passed");
            AdmissionResponse::from(&request).into_review()
        }
        Err(reason) => {
            let name = if request.name.is_empty() {
                "-"
            } else {
                &request.name
            };
            warn!(name, reason = %reason, "validation rejected");
            AdmissionResponse::from(&request)
                .deny(reason)
                .into_review()
        }
    };

    Json(response).into_response()
}

/// Validate a `SandboxRuntime` custom resource.
///
/// `request.object` is `Option<SandboxRuntime>`, not `Option<SandboxRuntimeSpec>`.
pub fn validate_runtime(request: &AdmissionRequest<SandboxRuntime>) -> Result<(), String> {
    let Some(runtime) = &request.object else {
        return Err("missing object in admission request".to_string());
    };

    let spec = &runtime.spec;

    // Validate targetRef kind.
    let valid_kinds = ["Deployment", "StatefulSet", "Sandbox"];
    if !valid_kinds.contains(&spec.target_ref.kind.as_str()) {
        return Err(format!(
            "unsupported targetRef kind '{}', must be one of: {}",
            spec.target_ref.kind,
            valid_kinds.join(", ")
        ));
    }

    // Validate image is not empty.
    if spec.image.is_empty() {
        return Err("spec.image must not be empty".to_string());
    }

    // Validate replicas >= 1.
    if spec.replicas < 1 {
        return Err(format!(
            "spec.replicas must be >= 1, got {}",
            spec.replicas
        ));
    }

    // Validate targetRef.name matches metadata.name if both are set.
    if !request.name.is_empty()
        && !spec.target_ref.name.is_empty()
        && spec.target_ref.name != request.name
    {
        return Err(format!(
            "spec.targetRef.name '{}' must match metadata.name '{}'",
            spec.target_ref.name, request.name
        ));
    }

    // Validate environment variable names.
    for env_var in &spec.env {
        if env_var.name.is_empty() {
            return Err("env variable name must not be empty".to_string());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{SandboxRuntimeSpec, ServicePort, TargetRef};

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
    fn valid_deployment_spec_passes() {
        let req = make_request(valid_spec());
        assert!(validate_runtime(&req).is_ok());
    }

    #[test]
    fn valid_statefulset_spec_passes() {
        let mut spec = valid_spec();
        spec.target_ref.kind = "StatefulSet".into();
        let req = make_request(spec);
        assert!(validate_runtime(&req).is_ok());
    }

    #[test]
    fn valid_sandbox_spec_passes() {
        let mut spec = valid_spec();
        spec.target_ref.kind = "Sandbox".into();
        spec.target_ref.api_version = "agents.x-k8s.io/v1alpha1".into();
        let req = make_request(spec);
        assert!(validate_runtime(&req).is_ok());
    }

    #[test]
    fn rejects_unknown_workload_kind() {
        let mut spec = valid_spec();
        spec.target_ref.kind = "CronJob".into();
        let req = make_request(spec);
        let err = validate_runtime(&req).unwrap_err();
        assert!(err.contains("unsupported targetRef kind"), "got: {err}");
    }

    #[test]
    fn rejects_empty_image() {
        let mut spec = valid_spec();
        spec.image = String::new();
        let req = make_request(spec);
        let err = validate_runtime(&req).unwrap_err();
        assert!(err.contains("image must not be empty"), "got: {err}");
    }

    #[test]
    fn rejects_zero_replicas() {
        let mut spec = valid_spec();
        spec.replicas = 0;
        let req = make_request(spec);
        let err = validate_runtime(&req).unwrap_err();
        assert!(err.contains("replicas must be >= 1"), "got: {err}");
    }

    #[test]
    fn rejects_mismatched_target_ref_name() {
        let mut spec = valid_spec();
        spec.target_ref.name = "different-name".into();
        let req = make_request(spec);
        let err = validate_runtime(&req).unwrap_err();
        assert!(err.contains("must match metadata.name"), "got: {err}");
    }

    #[test]
    fn rejects_empty_env_var_name() {
        let mut spec = valid_spec();
        spec.env = vec![crate::crd::EnvVar {
            name: String::new(),
            value: "val".into(),
        }];
        let req = make_request(spec);
        let err = validate_runtime(&req).unwrap_err();
        assert!(
            err.contains("env variable name must not be empty"),
            "got: {err}"
        );
    }

    #[test]
    fn allows_empty_target_ref_name() {
        let mut spec = valid_spec();
        spec.target_ref.name = String::new();
        let req = make_request(spec);
        assert!(validate_runtime(&req).is_ok());
    }

    #[test]
    fn rejects_negative_replicas() {
        let mut spec = valid_spec();
        spec.replicas = -1;
        let req = make_request(spec);
        let err = validate_runtime(&req).unwrap_err();
        assert!(err.contains("replicas must be >= 1"), "got: {err}");
    }
}
