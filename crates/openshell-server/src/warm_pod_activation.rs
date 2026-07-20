// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway-side warm supervisor pod activation.
//!
//! The Kubernetes claim controller will call this module after it observes and
//! revalidates a claim that binds a warm pod UID to an `OpenShell` sandbox.

use crate::ServerState;
use crate::auth::principal::RegisteredPodIdentity;
use async_trait::async_trait;
use openshell_core::proto::{PodActivationMessage, Sandbox};
use std::sync::Arc;
use tonic::Status;
use tracing::{info, warn};

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct WarmPodActivationTarget {
    pub pod_uid: String,
    pub sandbox_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct ValidatedWarmPodActivation {
    pub pod_uid: String,
    pub pod_name: String,
    pub sandbox_owner_uid: String,
    pub sandbox_id: String,
}

#[async_trait]
#[allow(dead_code)]
pub trait WarmPodActivationValidator: Send + Sync {
    async fn validate(
        &self,
        target: &WarmPodActivationTarget,
        pending: &RegisteredPodIdentity,
    ) -> Result<ValidatedWarmPodActivation, Status>;
}

#[allow(clippy::result_large_err)]
#[allow(dead_code)]
pub async fn activate_warm_pod<V>(
    state: &Arc<ServerState>,
    validator: &V,
    target: WarmPodActivationTarget,
) -> Result<(), Status>
where
    V: WarmPodActivationValidator + ?Sized,
{
    let pending = state
        .supervisor_pod_registrations
        .pending_identity(&target.pod_uid)?;
    let activation_result = async {
        let validated = validator.validate(&target, &pending).await?;
        ensure_validated_activation_matches_pending(&target, &pending, &validated)?;
        mint_pod_activation(state, &validated.sandbox_id, "WarmPodActivation").await
    }
    .await;
    let activation = match activation_result {
        Ok(activation) => activation,
        Err(status) => {
            let stream_status = clone_status(&status);
            state
                .supervisor_pod_registrations
                .fail_pending(&target.pod_uid, stream_status)?;
            return Err(status);
        }
    };

    state
        .supervisor_pod_registrations
        .activate(&target.pod_uid, activation)?;
    Ok(())
}

fn clone_status(status: &Status) -> Status {
    Status::new(status.code(), status.message().to_string())
}

#[allow(clippy::result_large_err)]
fn ensure_validated_activation_matches_pending(
    target: &WarmPodActivationTarget,
    pending: &RegisteredPodIdentity,
    validated: &ValidatedWarmPodActivation,
) -> Result<(), Status> {
    if validated.pod_uid != target.pod_uid || validated.pod_uid != pending.pod_uid {
        return Err(Status::permission_denied(
            "validated pod UID does not match pending registration",
        ));
    }
    if validated.pod_name != pending.pod_name {
        return Err(Status::permission_denied(
            "validated pod name does not match pending registration",
        ));
    }
    if validated.sandbox_owner_uid != pending.sandbox_owner_uid {
        return Err(Status::permission_denied(
            "validated Sandbox owner UID does not match pending registration",
        ));
    }
    if validated.sandbox_id != target.sandbox_id {
        return Err(Status::permission_denied(
            "validated sandbox ID does not match activation target",
        ));
    }
    Ok(())
}

#[allow(clippy::result_large_err)]
pub async fn mint_pod_activation(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    reason: &'static str,
) -> Result<PodActivationMessage, Status> {
    let issuer = state.sandbox_jwt_issuer.as_ref().ok_or_else(|| {
        warn!(
            sandbox_id = %sandbox_id,
            reason,
            "pod activation requested but sandbox JWT issuer is not configured"
        );
        Status::unavailable("sandbox JWT minting is not configured on this gateway")
    })?;

    let record = load_sandbox(state, sandbox_id).await?;
    let minted = issuer.mint(sandbox_id)?;
    let sandbox_name = record
        .metadata
        .as_ref()
        .map_or_else(String::new, |m| m.name.clone());
    info!(
        sandbox_id = %sandbox_id,
        reason,
        "issued gateway sandbox JWT for pod activation"
    );

    Ok(PodActivationMessage {
        sandbox_id: sandbox_id.to_string(),
        sandbox_name,
        token: minted.token,
        token_expires_at_ms: minted.expires_at_ms,
        startup_metadata: std::collections::HashMap::default(),
    })
}

pub async fn load_sandbox(state: &Arc<ServerState>, sandbox_id: &str) -> Result<Sandbox, Status> {
    if sandbox_id.is_empty() {
        return Err(Status::invalid_argument("sandbox_id is required"));
    }

    state
        .store
        .get_message::<Sandbox>(sandbox_id)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::sandbox_jwt::SandboxJwtIssuer;
    use crate::compute::new_test_runtime;
    use crate::persistence::Store;
    use crate::sandbox_index::SandboxIndex;
    use crate::sandbox_watch::SandboxWatchBus;
    use crate::supervisor_session::SupervisorSessionRegistry;
    use crate::tracing_bus::TracingLogBus;
    use openshell_bootstrap::jwt::generate_jwt_key;
    use openshell_core::Config;
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    use openshell_core::proto::{Sandbox, SandboxPhase, SandboxSpec};
    use std::collections::HashMap;
    use std::time::Duration;
    use tokio_stream::StreamExt;

    struct StaticValidator {
        validated: ValidatedWarmPodActivation,
    }

    #[async_trait]
    impl WarmPodActivationValidator for StaticValidator {
        async fn validate(
            &self,
            _target: &WarmPodActivationTarget,
            _pending: &RegisteredPodIdentity,
        ) -> Result<ValidatedWarmPodActivation, Status> {
            Ok(self.validated.clone())
        }
    }

    async fn state_with_issuer() -> Arc<ServerState> {
        let mat = generate_jwt_key().expect("jwt key");
        let store = Arc::new(
            Store::connect("sqlite::memory:?cache=shared")
                .await
                .unwrap(),
        );
        let compute = new_test_runtime(store.clone()).await;
        let mut state = ServerState::new(
            Config::new(None).with_database_url("sqlite::memory:?cache=shared"),
            store,
            compute,
            SandboxIndex::new(),
            SandboxWatchBus::new(),
            TracingLogBus::new(),
            Arc::new(SupervisorSessionRegistry::new()),
            None,
        );
        let issuer = SandboxJwtIssuer::from_pem(
            mat.signing_key_pem.as_bytes(),
            mat.kid,
            "test-gateway",
            Duration::from_secs(3600),
        )
        .unwrap();
        state.sandbox_jwt_issuer = Some(Arc::new(issuer));
        let state = Arc::new(state);
        insert_sandbox(&state, "sandbox-a").await;
        state
    }

    async fn insert_sandbox(state: &Arc<ServerState>, sandbox_id: &str) {
        let mut sandbox = Sandbox {
            metadata: Some(ObjectMeta {
                id: sandbox_id.to_string(),
                name: sandbox_id.to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::default(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: None,
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        state.store.put_message(&sandbox).await.unwrap();
    }

    fn pending_pod() -> RegisteredPodIdentity {
        RegisteredPodIdentity {
            pod_name: "warm-pod-a".to_string(),
            pod_uid: "pod-uid-a".to_string(),
            sandbox_id: None,
            sandbox_owner_name: "sandbox-owner-a".to_string(),
            sandbox_owner_uid: "owner-uid-a".to_string(),
        }
    }

    fn activation_target(sandbox_id: &str) -> WarmPodActivationTarget {
        WarmPodActivationTarget {
            pod_uid: "pod-uid-a".to_string(),
            sandbox_id: sandbox_id.to_string(),
        }
    }

    fn validated_activation(sandbox_id: &str) -> ValidatedWarmPodActivation {
        ValidatedWarmPodActivation {
            pod_uid: "pod-uid-a".to_string(),
            pod_name: "warm-pod-a".to_string(),
            sandbox_owner_uid: "owner-uid-a".to_string(),
            sandbox_id: sandbox_id.to_string(),
        }
    }

    #[tokio::test]
    async fn pending_warm_pod_receives_activation_token() {
        let state = state_with_issuer().await;
        let mut stream = state
            .supervisor_pod_registrations
            .register_pending(pending_pod())
            .expect("register pending");
        let validator = StaticValidator {
            validated: validated_activation("sandbox-a"),
        };

        activate_warm_pod(&state, &validator, activation_target("sandbox-a"))
            .await
            .expect("activate");

        let received = stream
            .next()
            .await
            .expect("activation message")
            .expect("activation OK");
        assert_eq!(received.sandbox_id, "sandbox-a");
        assert_eq!(received.sandbox_name, "sandbox-a");
        assert!(!received.token.is_empty());
        assert_eq!(state.supervisor_pod_registrations.pending_count(), 0);
        assert_eq!(state.supervisor_pod_registrations.activated_count(), 1);
    }

    #[tokio::test]
    async fn activation_for_unknown_pod_uid_fails_before_validation() {
        let state = state_with_issuer().await;
        let validator = StaticValidator {
            validated: validated_activation("sandbox-a"),
        };

        let err = activate_warm_pod(&state, &validator, activation_target("sandbox-a"))
            .await
            .expect_err("unknown pod UID must fail");

        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn missing_target_sandbox_fails_without_token_emission() {
        let state = state_with_issuer().await;
        let mut stream = state
            .supervisor_pod_registrations
            .register_pending(pending_pod())
            .expect("register pending");
        let validator = StaticValidator {
            validated: validated_activation("sandbox-deleted"),
        };

        let err = activate_warm_pod(&state, &validator, activation_target("sandbox-deleted"))
            .await
            .expect_err("missing sandbox must fail");

        assert_eq!(err.code(), tonic::Code::NotFound);
        assert_eq!(state.supervisor_pod_registrations.pending_count(), 0);
        let stream_err = stream
            .next()
            .await
            .expect("failure message")
            .expect_err("missing sandbox should fail stream");
        assert_eq!(stream_err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn duplicate_activation_for_same_pod_uid_is_rejected() {
        let state = state_with_issuer().await;
        let mut stream = state
            .supervisor_pod_registrations
            .register_pending(pending_pod())
            .expect("register pending");
        let validator = StaticValidator {
            validated: validated_activation("sandbox-a"),
        };

        activate_warm_pod(&state, &validator, activation_target("sandbox-a"))
            .await
            .expect("first activation");
        let _ = stream.next().await.expect("activation");
        let err = activate_warm_pod(&state, &validator, activation_target("sandbox-a"))
            .await
            .expect_err("duplicate activation must fail");

        assert_eq!(err.code(), tonic::Code::AlreadyExists);
    }

    #[tokio::test]
    async fn revalidation_metadata_must_match_pending_registration() {
        let state = state_with_issuer().await;
        let mut stream = state
            .supervisor_pod_registrations
            .register_pending(pending_pod())
            .expect("register pending");
        let mut validated = validated_activation("sandbox-a");
        validated.sandbox_owner_uid = "other-owner".to_string();
        let validator = StaticValidator { validated };

        let err = activate_warm_pod(&state, &validator, activation_target("sandbox-a"))
            .await
            .expect_err("mismatched revalidation metadata must fail");

        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        let stream_err = stream
            .next()
            .await
            .expect("failure message")
            .expect_err("validation mismatch should fail stream");
        assert_eq!(stream_err.code(), tonic::Code::PermissionDenied);
    }
}
