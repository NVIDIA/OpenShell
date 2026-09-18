// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Initial assignment over a driver-authenticated registration connection.

use crate::{
    ServerState,
    auth::{
        principal::{Principal, SandboxIdentitySource},
        sandbox_session::PersistedSandboxIdentity,
    },
};
use openshell_core::proto::{
    RegisterSupervisorRequest, RegisterSupervisorResponse, Sandbox, SandboxPhase,
};
use std::{sync::Arc, time::Duration};
use tonic::{Request, Response, Status};

pub(super) async fn register(
    state: &Arc<ServerState>,
    request: Request<RegisterSupervisorRequest>,
) -> Result<Response<RegisterSupervisorResponse>, Status> {
    let Principal::Sandbox(principal) = super::extract_principal(&request)? else {
        return Err(Status::permission_denied(
            "registration requires a driver-authenticated proxy",
        ));
    };
    let SandboxIdentitySource::SupervisorRegistration {
        registration: expected,
    } = principal.source
    else {
        return Err(Status::permission_denied(
            "operational credentials cannot register a proxy",
        ));
    };
    let credential = request
        .metadata()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| Status::unauthenticated("missing registration credential"))?;

    // A bounded wait lets clients reread projected credentials and reconnect.
    // Durable state is authoritative; no assignment depends on this handler's lifetime.
    // Subscribe before reading assignment so a claim during the read cannot be
    // lost. Notifications carry no authority; every wake repeats authentication.
    let mut assignments = state.compute.subscribe_assignments();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while tokio::time::Instant::now() < deadline {
        let observed = state.compute.authenticate_supervisor(credential).await?;
        let registration = observed
            .registration
            .ok_or_else(|| Status::permission_denied("missing registration identity"))?;
        if registration.instance_id != expected.instance_id
            || registration.sandbox_resource_uid != expected.sandbox_resource_uid
            || registration.workload_pod_uid != expected.workload_pod_uid
            || registration.runtime_generation != expected.runtime_generation
            || registration.session_id != expected.session_id
            || registration.resource_binding != expected.resource_binding
        {
            return Err(Status::permission_denied(
                "prepared runtime changed during registration",
            ));
        }
        if !observed.sandbox_id.is_empty()
            && let Some(sandbox) = state
                .store
                .get_message::<Sandbox>(&observed.sandbox_id)
                .await
                .map_err(|_| Status::unavailable("sandbox persistence unavailable"))?
        {
            let authority = state
                .sandbox_session_jwt_authority
                .as_ref()
                .ok_or_else(|| Status::unavailable("session signing unavailable"))?;
            return assignment_response(authority, &observed.sandbox_id, &sandbox, registration)
                .map(Response::new);
        }
        tokio::select! {
            _ = assignments.changed() => {},
            // Other gateway replicas and crash recovery still use durable state.
            () = tokio::time::sleep(Duration::from_secs(1)) => {},
            () = tokio::time::sleep_until(deadline) => break,
        }
    }
    Err(Status::unavailable("proxy is still awaiting assignment"))
}

fn assignment_response(
    authority: &crate::auth::sandbox_jwt::SandboxSessionJwtAuthority,
    sandbox_id: &str,
    sandbox: &Sandbox,
    registration: openshell_core::proto::compute::v1::SupervisorRegistration,
) -> Result<RegisterSupervisorResponse, Status> {
    let phase = SandboxPhase::try_from(sandbox.phase()).unwrap_or(SandboxPhase::Unknown);
    if !matches!(
        phase,
        SandboxPhase::Provisioning
            | SandboxPhase::Starting
            | SandboxPhase::Ready
            | SandboxPhase::Completed
    ) {
        return Err(Status::failed_precondition(
            "sandbox does not permit activation",
        ));
    }
    let metadata = sandbox
        .metadata
        .as_ref()
        .ok_or_else(|| Status::internal("missing sandbox metadata"))?;
    let identity = PersistedSandboxIdentity::read(&metadata.annotations)
        .map_err(|_| Status::failed_precondition("missing runtime identity"))?;
    if metadata.id != sandbox_id || metadata.deletion_time.is_some() {
        return Err(Status::failed_precondition(
            "sandbox assignment is not active",
        ));
    }
    if crate::compute::warm_pool::candidate(sandbox)?
        .is_some_and(|pair| pair.uid != registration.sandbox_resource_uid)
    {
        return Err(Status::permission_denied(
            "proxy does not belong to persisted pair",
        ));
    }
    if registration.runtime_generation != identity.runtime_generation.as_str() {
        return Err(Status::failed_precondition(
            "prepared generation does not match persisted assignment",
        ));
    }
    if registration.resource_binding.is_empty() {
        return Err(Status::permission_denied(
            "missing driver registration binding",
        ));
    }
    let session_id = registration
        .session_id
        .parse()
        .map_err(|_| Status::internal("invalid prepared session identity"))?;
    let bundle = authority.mint_registration(
        sandbox_id,
        &identity,
        session_id,
        registration.resource_binding.into_iter().collect(),
    )?;
    Ok(RegisterSupervisorResponse {
        sandbox_id: sandbox_id.to_string(),
        sandbox_name: metadata.name.clone(),
        backend_descriptor: registration.backend_descriptor,
        auth_bundle: serde_json::to_vec(&bundle)
            .map_err(|_| Status::internal("encode credentials"))?,
        main_process_spec: registration.main_process_spec,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{
        sandbox_jwt::SandboxSessionJwtAuthority, sandbox_session::RefreshRequestHash,
    };
    use openshell_core::proto::compute::v1::WarmPairCandidate;
    use openshell_core::{
        SandboxSessionId,
        jwt::{
            SessionJwtVerifier, SessionTokenProfile, SessionVerificationKey, SupervisorAuthBundle,
            SystemJwtClock,
        },
        proto::{compute::v1::SupervisorRegistration, datamodel::v1::ObjectMeta},
    };
    use prost::Message;

    #[test]
    fn registration_retries_preserve_assignment_and_cannot_revive_refreshed_credentials() {
        let key = openshell_bootstrap::jwt::generate_jwt_key().unwrap();
        let authority = SandboxSessionJwtAuthority::from_pem(
            key.signing_key_pem.as_bytes(),
            key.public_key_pem.as_bytes(),
            key.kid.clone(),
            "gateway",
            Duration::from_hours(1),
        )
        .unwrap();
        let verifier = SessionJwtVerifier::new(
            "gateway",
            SessionTokenProfile::Sandbox,
            [SessionVerificationKey {
                key_id: key.kid,
                public_key_pem: key.public_key_pem.into_bytes(),
            }],
            Arc::new(SystemJwtClock),
        )
        .unwrap();
        let identity = PersistedSandboxIdentity::new().unwrap();
        let mut sandbox = Sandbox {
            metadata: Some(ObjectMeta {
                id: "sandbox-a".into(),
                name: "example".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        identity.write(&mut sandbox.metadata.as_mut().unwrap().annotations);
        sandbox.set_phase(SandboxPhase::Provisioning as i32);
        let registration = SupervisorRegistration {
            runtime_generation: identity.runtime_generation.to_string(),
            session_id: SandboxSessionId::new().to_string(),
            resource_binding: [("workload-uid".into(), "pod-a".into())].into(),
            ..Default::default()
        };
        let first =
            assignment_response(&authority, "sandbox-a", &sandbox, registration.clone()).unwrap();
        let second =
            assignment_response(&authority, "sandbox-a", &sandbox, registration.clone()).unwrap();
        let first: SupervisorAuthBundle = serde_json::from_slice(&first.auth_bundle).unwrap();
        let second: SupervisorAuthBundle = serde_json::from_slice(&second.auth_bundle).unwrap();
        assert_eq!(first.session_id, second.session_id);
        assert_eq!(first.runtime_generation, second.runtime_generation);
        assert_eq!(
            authority
                .verify_gateway_token(first.gateway_token.expose_secret())
                .unwrap()
                .token_id,
            authority
                .verify_gateway_token(second.gateway_token.expose_secret())
                .unwrap()
                .token_id
        );
        let signed = verifier
            .verify(first.sandbox_token.expose_secret())
            .unwrap();
        assert_eq!(signed.resource_binding["workload-uid"], "pod-a");
        assert_eq!(signed.sandbox_id.as_str(), "sandbox-a");

        let mut warm_registration = registration.clone();
        warm_registration.sandbox_resource_uid = "prepared-parent".into();
        let pair = WarmPairCandidate {
            uid: "prepared-parent".into(),
            ..Default::default()
        };
        sandbox.metadata.as_mut().unwrap().annotations.insert(
            "internal.openshell.ai/warm-pair-candidate".into(),
            hex::encode(pair.encode_to_vec()),
        );
        assert!(assignment_response(&authority, "sandbox-a", &sandbox, warm_registration).is_ok());
        assert_eq!(
            assignment_response(&authority, "sandbox-a", &sandbox, registration.clone())
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        sandbox
            .metadata
            .as_mut()
            .unwrap()
            .annotations
            .remove("internal.openshell.ai/warm-pair-candidate");

        let mut wrong = registration.clone();
        wrong.runtime_generation = "other-generation".into();
        assert!(assignment_response(&authority, "sandbox-a", &sandbox, wrong).is_err());
        let mut wrong = registration.clone();
        wrong.resource_binding.clear();
        assert!(assignment_response(&authority, "sandbox-a", &sandbox, wrong).is_err());
        sandbox.set_phase(SandboxPhase::Stopped as i32);
        assert!(
            assignment_response(&authority, "sandbox-a", &sandbox, registration.clone()).is_err()
        );
        sandbox.set_phase(SandboxPhase::Ready as i32);
        let refreshed = identity.next_gateway_token(
            RefreshRequestHash::from_extension_services(&[]),
            1_900_000_000,
            60,
        );
        refreshed.write(&mut sandbox.metadata.as_mut().unwrap().annotations);
        assert!(assignment_response(&authority, "sandbox-a", &sandbox, registration).is_err());
    }
}
