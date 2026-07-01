// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_core::proto::SandboxPolicy;
use openshell_supervisor_middleware::MiddlewareRegistry;
use tonic::Status;

/// Validate implementation-owned middleware config before accepting a policy.
pub async fn validate_policy(
    registry: &MiddlewareRegistry,
    policy: &SandboxPolicy,
) -> Result<(), Status> {
    registry
        .validate_policy_configs(policy)
        .await
        .map_err(|error| {
            Status::invalid_argument(format!("policy middleware validation failed: {error}"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::NetworkMiddlewareConfig;

    #[tokio::test]
    async fn unregistered_external_binding_is_rejected_before_admission() {
        let policy = SandboxPolicy {
            network_middlewares: vec![NetworkMiddlewareConfig {
                name: "guard".into(),
                middleware: "example/content-guard".into(),
                ..Default::default()
            }],
            ..Default::default()
        };

        let error = validate_policy(&MiddlewareRegistry::default(), &policy)
            .await
            .expect_err("unregistered binding must fail");
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(error.message().contains("not registered"));
    }
}
