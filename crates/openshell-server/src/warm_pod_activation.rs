// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway-side warm supervisor pod activation.
//!
//! The Kubernetes claim controller will call this module after it observes and
//! revalidates a claim that binds a warm supervisor instance to an `OpenShell`
//! sandbox.

use crate::ServerState;
use async_trait::async_trait;
use openshell_core::proto::{Sandbox, SupervisorActivationMessage};
use openshell_core::supervisor_bootstrap::{
    SupervisorBootstrapActivationRequest, SupervisorBootstrapActivator, SupervisorBootstrapIdentity,
};
use std::sync::Arc;
use tonic::Status;
use tracing::{info, warn};

const ACTIVATION_SESSION_RETRY_ATTEMPTS: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct WarmPodActivationTarget {
    pub driver: String,
    pub instance_id: String,
    pub sandbox_id: String,
    pub owner_uid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct ValidatedWarmPodActivation {
    pub driver: String,
    pub instance_id: String,
    pub instance_name: String,
    pub owner_uid: String,
    pub sandbox_id: String,
}

#[async_trait]
#[allow(dead_code)]
pub trait WarmPodActivationValidator: Send + Sync {
    async fn validate(
        &self,
        target: &WarmPodActivationTarget,
        pending: &SupervisorBootstrapIdentity,
    ) -> Result<ValidatedWarmPodActivation, Status>;
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct GatewaySupervisorBootstrapActivator {
    state: Arc<ServerState>,
}

impl GatewaySupervisorBootstrapActivator {
    #[must_use]
    #[allow(dead_code)]
    pub fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }
}

#[async_trait]
impl SupervisorBootstrapActivator for GatewaySupervisorBootstrapActivator {
    async fn activate_registered_supervisor(
        &self,
        request: SupervisorBootstrapActivationRequest,
    ) -> Result<(), Status> {
        let target = WarmPodActivationTarget {
            driver: request.driver,
            instance_id: request.instance_id,
            sandbox_id: request.sandbox_id,
            owner_uid: request.owner_uid,
        };
        activate_warm_pod(&self.state, &TrustDriverActivationRequest, target).await
    }
}

struct TrustDriverActivationRequest;

#[async_trait]
impl WarmPodActivationValidator for TrustDriverActivationRequest {
    async fn validate(
        &self,
        target: &WarmPodActivationTarget,
        pending: &SupervisorBootstrapIdentity,
    ) -> Result<ValidatedWarmPodActivation, Status> {
        Ok(ValidatedWarmPodActivation {
            driver: target.driver.clone(),
            instance_id: target.instance_id.clone(),
            instance_name: pending.instance_name.clone(),
            owner_uid: target.owner_uid.clone(),
            sandbox_id: target.sandbox_id.clone(),
        })
    }
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
    for _ in 0..ACTIVATION_SESSION_RETRY_ATTEMPTS {
        let pending = state
            .supervisor_pod_registrations
            .pending_identity(&target.instance_id)?;
        let activation_result = async {
            let validated = validator.validate(&target, &pending.identity).await?;
            ensure_validated_activation_matches_pending(&target, &pending.identity, &validated)?;
            mint_pod_activation(state, &validated.sandbox_id, "WarmPodActivation").await
        }
        .await;
        let activation = match activation_result {
            Ok(activation) => activation,
            Err(status) => {
                let stream_status = clone_status(&status);
                match state.supervisor_pod_registrations.fail_if_session(
                    &target.instance_id,
                    pending.session_id,
                    stream_status,
                ) {
                    Ok(()) => return Err(status),
                    Err(replaced) if replaced.code() == tonic::Code::Aborted => continue,
                    Err(delivery) => return Err(delivery),
                }
            }
        };

        match state.supervisor_pod_registrations.activate_if_session(
            &target.instance_id,
            pending.session_id,
            activation,
        ) {
            Ok(()) => return Ok(()),
            Err(replaced) if replaced.code() == tonic::Code::Aborted => {}
            Err(status) => return Err(status),
        }
    }

    warn!(
        driver = %target.driver,
        instance_id = %target.instance_id,
        sandbox_id = %target.sandbox_id,
        owner_uid = %target.owner_uid,
        attempts = ACTIVATION_SESSION_RETRY_ATTEMPTS,
        "supervisor registration changed repeatedly during warm pod activation"
    );
    Err(Status::aborted(
        "supervisor registration changed repeatedly during activation",
    ))
}

fn clone_status(status: &Status) -> Status {
    Status::new(status.code(), status.message().to_string())
}

#[allow(clippy::result_large_err)]
fn ensure_validated_activation_matches_pending(
    target: &WarmPodActivationTarget,
    pending: &SupervisorBootstrapIdentity,
    validated: &ValidatedWarmPodActivation,
) -> Result<(), Status> {
    if validated.driver != target.driver || validated.driver != pending.driver {
        return Err(Status::permission_denied(
            "validated driver does not match pending registration",
        ));
    }
    if validated.instance_id != target.instance_id || validated.instance_id != pending.instance_id {
        return Err(Status::permission_denied(
            "validated instance ID does not match pending registration",
        ));
    }
    if validated.instance_name != pending.instance_name {
        return Err(Status::permission_denied(
            "validated instance name does not match pending registration",
        ));
    }
    if validated.owner_uid != target.owner_uid || validated.owner_uid != pending.owner_uid {
        return Err(Status::permission_denied(
            "validated owner UID does not match pending registration",
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
) -> Result<SupervisorActivationMessage, Status> {
    let issuer = state.sandbox_jwt_issuer.as_ref().ok_or_else(|| {
        warn!(
            sandbox_id = %sandbox_id,
            reason,
            "supervisor activation requested but sandbox JWT issuer is not configured"
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
        "issued gateway sandbox JWT for supervisor activation"
    );

    Ok(SupervisorActivationMessage {
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
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};
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
            _pending: &SupervisorBootstrapIdentity,
        ) -> Result<ValidatedWarmPodActivation, Status> {
            Ok(self.validated.clone())
        }
    }

    struct ReplaceRegistrationOnceValidator {
        state: Arc<ServerState>,
        replaced: AtomicBool,
        replacement_stream:
            Mutex<Option<crate::supervisor_pod_registration::PendingRegistrationStream>>,
        validated: ValidatedWarmPodActivation,
    }

    #[async_trait]
    impl WarmPodActivationValidator for ReplaceRegistrationOnceValidator {
        async fn validate(
            &self,
            _target: &WarmPodActivationTarget,
            _pending: &SupervisorBootstrapIdentity,
        ) -> Result<ValidatedWarmPodActivation, Status> {
            if !self.replaced.swap(true, Ordering::SeqCst) {
                let stream = self
                    .state
                    .supervisor_pod_registrations
                    .register_pending(pending_identity())?;
                *self.replacement_stream.lock().unwrap() = Some(stream);
            }
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
                annotations: HashMap::default(),
                resource_version: 0,
                workspace: "default".to_string(),
                ..Default::default()
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

    fn pending_identity() -> SupervisorBootstrapIdentity {
        SupervisorBootstrapIdentity {
            driver: "kubernetes".to_string(),
            instance_name: "warm-pod-a".to_string(),
            instance_id: "pod-uid-a".to_string(),
            owner_name: "sandbox-owner-a".to_string(),
            owner_uid: "owner-uid-a".to_string(),
            binding: openshell_core::supervisor_bootstrap::SupervisorBootstrapBinding::WarmPending,
        }
    }

    fn activation_target(sandbox_id: &str) -> WarmPodActivationTarget {
        WarmPodActivationTarget {
            driver: "kubernetes".to_string(),
            instance_id: "pod-uid-a".to_string(),
            sandbox_id: sandbox_id.to_string(),
            owner_uid: "owner-uid-a".to_string(),
        }
    }

    fn validated_activation(sandbox_id: &str) -> ValidatedWarmPodActivation {
        ValidatedWarmPodActivation {
            driver: "kubernetes".to_string(),
            instance_id: "pod-uid-a".to_string(),
            instance_name: "warm-pod-a".to_string(),
            owner_uid: "owner-uid-a".to_string(),
            sandbox_id: sandbox_id.to_string(),
        }
    }

    #[tokio::test]
    async fn pending_warm_pod_receives_activation_token() {
        let state = state_with_issuer().await;
        let mut stream = state
            .supervisor_pod_registrations
            .register_pending(pending_identity())
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
    async fn activation_for_unknown_instance_id_fails_before_validation() {
        let state = state_with_issuer().await;
        let validator = StaticValidator {
            validated: validated_activation("sandbox-a"),
        };

        let err = activate_warm_pod(&state, &validator, activation_target("sandbox-a"))
            .await
            .expect_err("unknown instance ID must fail");

        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn missing_target_sandbox_fails_without_token_emission() {
        let state = state_with_issuer().await;
        let mut stream = state
            .supervisor_pod_registrations
            .register_pending(pending_identity())
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
    async fn duplicate_activation_for_same_instance_id_is_rejected() {
        let state = state_with_issuer().await;
        let mut stream = state
            .supervisor_pod_registrations
            .register_pending(pending_identity())
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
    async fn same_pod_uid_can_reregister_after_activation() {
        let state = state_with_issuer().await;
        let mut first_stream = state
            .supervisor_pod_registrations
            .register_pending(pending_identity())
            .expect("register first process");
        let validator = StaticValidator {
            validated: validated_activation("sandbox-a"),
        };

        activate_warm_pod(&state, &validator, activation_target("sandbox-a"))
            .await
            .expect("activate first process");
        let first = first_stream.next().await.unwrap().unwrap();

        let mut restarted_stream = state
            .supervisor_pod_registrations
            .register_pending(pending_identity())
            .expect("same pod UID must reregister");
        activate_warm_pod(&state, &validator, activation_target("sandbox-a"))
            .await
            .expect("activate restarted process");
        let restarted = restarted_stream.next().await.unwrap().unwrap();

        assert_eq!(first.sandbox_id, restarted.sandbox_id);
        assert!(!restarted.token.is_empty());
    }

    #[tokio::test]
    async fn replacement_pod_uid_can_activate_existing_sandbox() {
        let state = state_with_issuer().await;
        let mut replacement_identity = pending_identity();
        replacement_identity.instance_id = "pod-uid-b".to_string();
        replacement_identity.instance_name = "warm-pod-b".to_string();
        let mut stream = state
            .supervisor_pod_registrations
            .register_pending(replacement_identity)
            .expect("register replacement pod");
        let validator = StaticValidator {
            validated: ValidatedWarmPodActivation {
                instance_id: "pod-uid-b".to_string(),
                instance_name: "warm-pod-b".to_string(),
                ..validated_activation("sandbox-a")
            },
        };
        let target = WarmPodActivationTarget {
            instance_id: "pod-uid-b".to_string(),
            ..activation_target("sandbox-a")
        };

        activate_warm_pod(&state, &validator, target)
            .await
            .expect("activate replacement pod");
        let activation = stream.next().await.unwrap().unwrap();

        assert_eq!(activation.sandbox_id, "sandbox-a");
        assert!(!activation.token.is_empty());
    }

    #[tokio::test]
    async fn activation_retries_when_registration_changes_during_validation() {
        let state = state_with_issuer().await;
        let old_stream = state
            .supervisor_pod_registrations
            .register_pending(pending_identity())
            .expect("register old process");
        let validator = ReplaceRegistrationOnceValidator {
            state: state.clone(),
            replaced: AtomicBool::new(false),
            replacement_stream: Mutex::new(None),
            validated: validated_activation("sandbox-a"),
        };

        activate_warm_pod(&state, &validator, activation_target("sandbox-a"))
            .await
            .expect("replacement session should activate");
        let mut replacement_stream = validator
            .replacement_stream
            .lock()
            .unwrap()
            .take()
            .expect("replacement stream");
        let activation = replacement_stream.next().await.unwrap().unwrap();

        assert_eq!(activation.sandbox_id, "sandbox-a");
        drop(old_stream);
    }

    #[tokio::test]
    async fn revalidation_metadata_must_match_pending_registration() {
        let state = state_with_issuer().await;
        let mut stream = state
            .supervisor_pod_registrations
            .register_pending(pending_identity())
            .expect("register pending");
        let mut validated = validated_activation("sandbox-a");
        validated.owner_uid = "other-owner".to_string();
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
