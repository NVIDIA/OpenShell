// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway-scoped delegated OIDC identity credentials for sandbox token exchange.

use crate::ServerState;
use crate::auth::principal::{Principal, UserPrincipal};
use crate::auth::workspace_authz::{
    AuthGrant, MinWorkspaceRole, authorize_workspace, require_platform_admin,
};
use crate::credentials::SecretMaterialScope;
use crate::persistence::{ObjectType, PersistenceError, WriteCondition, current_time_ms};
use openshell_core::proto::datamodel::v1::ObjectMeta;
use openshell_core::proto::{
    AuthorizeDelegatedIdentityRequest, AuthorizeDelegatedIdentityResponse, CredentialHandle,
    DelegatedIdentityAuthorizationGrant, DelegatedIdentityCredential,
    DelegatedIdentityCredentialSummary, DelegatedIdentityRefreshLease, DelegatedIdentityRequest,
    DeleteDelegatedIdentityCredentialRequest, DeleteDelegatedIdentityCredentialResponse,
    ExtendSandboxDelegatedIdentityRequest, ExtendSandboxDelegatedIdentityResponse,
    GetDelegatedIdentityAuthorizationStatusRequest,
    GetDelegatedIdentityAuthorizationStatusResponse, GetDelegatedIdentityCredentialStatusRequest,
    GetDelegatedIdentityCredentialStatusResponse, GetSandboxDelegatedIdentityStatusRequest,
    GetSandboxDelegatedIdentityStatusResponse, ListDelegatedIdentityCredentialsRequest,
    ListDelegatedIdentityCredentialsResponse, RevokeDelegatedIdentityCredentialRequest,
    RevokeDelegatedIdentityCredentialResponse, Sandbox, SandboxDelegatedIdentity,
    SandboxDelegatedIdentityRecord, StoredRefreshMaterialDeletion,
    WithdrawSandboxDelegatedIdentityRequest, WithdrawSandboxDelegatedIdentityResponse,
};
use openshell_core::{GetResourceVersion, ObjectId, ObjectLabels, ObjectName, ObjectWorkspace};
use prost::Message;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tonic::{Request, Response, Status};

const CREDENTIAL_OBJECT_TYPE: &str = "delegated_identity_credential";
const SANDBOX_DELEGATION_OBJECT_TYPE: &str = "sandbox_delegated_identity";
const GLOBAL_WORKSPACE: &str = "";
const DELEGATED_IDENTITY_SECRET_OWNER: &str = "openshell-delegated-identity";
const DELEGATED_IDENTITY_SECRET_NAMESPACE: &str = "delegated-identity";
const ACCESS_TOKEN_MATERIAL_KEY: &str = "access_token";
const REFRESH_TOKEN_MATERIAL_KEY: &str = "refresh_token";
const REFRESH_SKEW_MS: i64 = 60_000;
const REFRESH_LEASE_DURATION_MS: i64 = 120_000;
const REFRESH_LEASE_POLL_INTERVAL: Duration = Duration::from_millis(100);
const REFRESH_LEASE_WAIT_LIMIT: Duration = Duration::from_secs(125);
static DELEGATED_IDENTITY_HTTP_CLIENT: LazyLock<Result<reqwest::Client, String>> =
    LazyLock::new(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(30))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| format!("delegated identity HTTP client configuration failed: {err}"))
    });

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegatedSandboxLifecycleOperation {
    Start,
    Stop,
}

impl DelegatedSandboxLifecycleOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
        }
    }
}

pub struct PreparedSandboxDelegatedIdentity {
    pub record: SandboxDelegatedIdentityRecord,
}

impl ObjectType for DelegatedIdentityCredential {
    fn object_type() -> &'static str {
        CREDENTIAL_OBJECT_TYPE
    }
}

impl ObjectType for SandboxDelegatedIdentityRecord {
    fn object_type() -> &'static str {
        SANDBOX_DELEGATION_OBJECT_TYPE
    }
}

pub async fn prepare_for_sandbox_create(
    state: &Arc<ServerState>,
    principal: &Principal,
    sandbox: &Sandbox,
    request: Option<DelegatedIdentityRequest>,
) -> Result<Option<PreparedSandboxDelegatedIdentity>, Status> {
    let Some(request) = request else {
        return Ok(None);
    };
    let user = require_user(principal)?;
    validate_delegation_window(state, request.delegated_until_ms)?;
    let credential = get_user_credential(state, user).await?.ok_or_else(|| {
        Status::failed_precondition(
            "delegated identity authorization is missing; authorize it before creating the sandbox",
        )
    })?;
    ensure_delegated_credential_usable(&credential)?;
    ensure_delegated_credential_material_present(&credential)?;
    let credential_id = credential.object_id().to_string();
    let sandbox_id = sandbox.object_id().to_string();
    let record_id = sandbox_delegated_identity_record_id(&sandbox_id);
    Ok(Some(PreparedSandboxDelegatedIdentity {
        record: SandboxDelegatedIdentityRecord {
            metadata: Some(ObjectMeta {
                id: record_id.clone(),
                name: record_id,
                created_at_ms: current_time_ms(),
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: sandbox.object_workspace().to_string(),
                deletion_timestamp_ms: 0,
            }),
            sandbox_id,
            delegated_identity: Some(SandboxDelegatedIdentity {
                credential_id,
                principal_subject: user.identity.subject.clone(),
                delegated_until_ms: request.delegated_until_ms,
                withdrawn_at_ms: 0,
            }),
        },
    }))
}

pub async fn store_prepared_sandbox_delegation(
    state: &Arc<ServerState>,
    prepared: Option<&PreparedSandboxDelegatedIdentity>,
) -> Result<(), Status> {
    let Some(prepared) = prepared else {
        return Ok(());
    };
    state
        .store
        .put_scoped_message(&prepared.record, &prepared.record.sandbox_id)
        .await
        .map_err(|e| Status::internal(format!("persist sandbox delegated identity failed: {e}")))
}

pub async fn delete_prepared_sandbox_delegation(
    state: &Arc<ServerState>,
    prepared: Option<&PreparedSandboxDelegatedIdentity>,
) -> Result<(), Status> {
    let Some(prepared) = prepared else {
        return Ok(());
    };
    state
        .store
        .delete(
            SandboxDelegatedIdentityRecord::object_type(),
            prepared.record.object_id(),
        )
        .await
        .map(|_| ())
        .map_err(|e| Status::internal(format!("delete sandbox delegated identity failed: {e}")))
}

pub async fn resolve_subject_access_token(
    state: &Arc<ServerState>,
    sandbox: &Sandbox,
) -> Result<(String, i64, String), Status> {
    let record = sandbox_delegated_identity_record(state, sandbox).await?;
    let delegation = record
        .as_ref()
        .and_then(|record| record.delegated_identity.as_ref())
        .ok_or_else(|| {
            Status::failed_precondition("sandbox was not created with delegated identity")
        })?;
    if delegation.withdrawn_at_ms > 0 {
        return Err(Status::failed_precondition("delegated identity withdrawn"));
    }
    let now = current_time_ms();
    if delegation.delegated_until_ms <= now {
        return Err(Status::failed_precondition("delegated identity expired"));
    }
    let credential = state
        .store
        .get_message::<DelegatedIdentityCredential>(&delegation.credential_id)
        .await
        .map_err(|e| Status::internal(format!("fetch delegated credential failed: {e}")))?
        .ok_or_else(|| Status::failed_precondition("delegated credential missing"))?;
    if credential.principal_subject != delegation.principal_subject {
        return Err(Status::failed_precondition(
            "delegated credential principal does not match sandbox delegation",
        ));
    }
    ensure_delegated_credential_usable(&credential)?;
    let resolved = refresh_if_needed(state, credential).await?;
    let credential_id = resolved.credential.object_id().to_string();
    Ok((
        resolved.access_token,
        resolved.credential.access_token_expires_at_ms,
        credential_id,
    ))
}

pub async fn handle_authorization_status(
    state: &Arc<ServerState>,
    request: Request<GetDelegatedIdentityAuthorizationStatusRequest>,
) -> Result<Response<GetDelegatedIdentityAuthorizationStatusResponse>, Status> {
    let principal = crate::grpc::extract_principal(&request)?;
    let user = require_user(&principal)?;
    let now_ms = current_time_ms();
    let Some(credential) = get_user_credential(state, user).await? else {
        return Ok(Response::new(
            GetDelegatedIdentityAuthorizationStatusResponse {
                usable: false,
                reauthorization_required: true,
                reason: "delegated identity authorization is missing".to_string(),
                credential: None,
                now_ms,
            },
        ));
    };

    if delegated_credential_is_deleting(&credential) {
        return Ok(Response::new(
            GetDelegatedIdentityAuthorizationStatusResponse {
                usable: false,
                reauthorization_required: false,
                reason: "delegated identity credential is being deleted".to_string(),
                credential: Some(delegated_credential_summary(credential)),
                now_ms,
            },
        ));
    }
    if let Err(status) = ensure_delegated_credential_usable(&credential)
        .and_then(|()| ensure_delegated_credential_material_present(&credential))
    {
        return Ok(Response::new(
            GetDelegatedIdentityAuthorizationStatusResponse {
                usable: false,
                reauthorization_required: true,
                reason: status.message().to_string(),
                credential: Some(delegated_credential_summary(credential)),
                now_ms,
            },
        ));
    }

    match refresh_if_needed(state, credential).await {
        Ok(resolved) => Ok(Response::new(
            GetDelegatedIdentityAuthorizationStatusResponse {
                usable: true,
                reauthorization_required: false,
                reason: String::new(),
                credential: Some(delegated_credential_summary(resolved.credential)),
                now_ms: current_time_ms(),
            },
        )),
        Err(status) if delegated_refresh_requires_reauthorization(&status) => Ok(Response::new(
            GetDelegatedIdentityAuthorizationStatusResponse {
                usable: false,
                reauthorization_required: true,
                reason: status.message().to_string(),
                credential: None,
                now_ms: current_time_ms(),
            },
        )),
        Err(status) => Err(status),
    }
}

pub async fn handle_authorize(
    state: &Arc<ServerState>,
    request: Request<AuthorizeDelegatedIdentityRequest>,
) -> Result<Response<AuthorizeDelegatedIdentityResponse>, Status> {
    let principal = crate::grpc::extract_principal(&request)?;
    let user = require_user(&principal)?;
    let grant = request
        .into_inner()
        .grant
        .ok_or_else(|| Status::invalid_argument("grant is required"))?;
    let access_token_expires_at_ms = validate_authorization_grant(state, user, &grant).await?;
    let credential = upsert_credential(state, user, grant, access_token_expires_at_ms).await?;
    Ok(Response::new(AuthorizeDelegatedIdentityResponse {
        credential: Some(delegated_credential_summary(credential)),
        now_ms: current_time_ms(),
    }))
}

pub async fn handle_status(
    state: &Arc<ServerState>,
    request: Request<GetSandboxDelegatedIdentityStatusRequest>,
) -> Result<Response<GetSandboxDelegatedIdentityStatusResponse>, Status> {
    let principal = crate::grpc::extract_principal(&request)?;
    let req = request.into_inner();
    let sandbox = authorized_sandbox_by_name(state, &principal, &req.workspace, &req.name).await?;
    let record = sandbox_delegated_identity_record(state, &sandbox).await?;
    let delegation = record
        .as_ref()
        .and_then(|record| record.delegated_identity.as_ref());
    if delegation.is_some() {
        ensure_delegator(&principal, delegation)?;
    }
    let (credential_revoked_at_ms, credential_missing) =
        sandbox_delegated_identity_credential_status(state, delegation).await?;
    Ok(Response::new(GetSandboxDelegatedIdentityStatusResponse {
        delegated_identity: delegation.cloned(),
        now_ms: current_time_ms(),
        credential_revoked_at_ms,
        credential_missing,
    }))
}

async fn sandbox_delegated_identity_credential_status(
    state: &Arc<ServerState>,
    delegation: Option<&SandboxDelegatedIdentity>,
) -> Result<(i64, bool), Status> {
    let Some(delegation) = delegation else {
        return Ok((0, true));
    };
    let credential = state
        .store
        .get_message::<DelegatedIdentityCredential>(&delegation.credential_id)
        .await
        .map_err(|e| Status::internal(format!("fetch delegated credential failed: {e}")))?;
    Ok(delegated_credential_status_fields(credential.as_ref()))
}

fn delegated_credential_status_fields(
    credential: Option<&DelegatedIdentityCredential>,
) -> (i64, bool) {
    credential.map_or((0, true), |credential| (credential.revoked_at_ms, false))
}

async fn sandbox_delegated_identity_record(
    state: &Arc<ServerState>,
    sandbox: &Sandbox,
) -> Result<Option<SandboxDelegatedIdentityRecord>, Status> {
    state
        .store
        .get_message::<SandboxDelegatedIdentityRecord>(&sandbox_delegated_identity_record_id(
            sandbox.object_id(),
        ))
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox delegated identity failed: {e}")))
}

pub fn sandbox_delegated_identity_record_id(sandbox_id: &str) -> String {
    format!("sandbox-delegated-identity-{sandbox_id}")
}

pub async fn ensure_delegated_identity_sandbox_user(
    state: &Arc<ServerState>,
    principal: &Principal,
    sandbox: &Sandbox,
) -> Result<(), Status> {
    let record = sandbox_delegated_identity_record(state, sandbox).await?;
    let Some(delegation) = record
        .as_ref()
        .and_then(|record| record.delegated_identity.as_ref())
    else {
        return Ok(());
    };

    match principal {
        Principal::User(user) if user.identity.subject == delegation.principal_subject => Ok(()),
        Principal::User(_) => Err(Status::permission_denied(
            "delegated identity sandbox access denied: caller is not the delegating principal",
        )),
        Principal::Sandbox(_) => Ok(()),
        Principal::Anonymous => Err(Status::unauthenticated(
            "sandbox-scoped methods require an authenticated caller",
        )),
    }
}

/// Enforce the operation-specific lifecycle policy for delegated sandboxes.
///
/// The delegator may start or stop their sandbox. Workspace and Platform
/// Admins may stop it for containment, but cannot restart a workload acting on
/// another user's behalf. Ordinary sandboxes retain the workspace role model.
pub async fn ensure_delegated_identity_sandbox_lifecycle_operation(
    state: &Arc<ServerState>,
    principal: &Principal,
    grant: AuthGrant,
    sandbox: &Sandbox,
    operation: DelegatedSandboxLifecycleOperation,
) -> Result<(), Status> {
    let record = sandbox_delegated_identity_record(state, sandbox).await?;
    let Some(delegation) = record
        .as_ref()
        .and_then(|record| record.delegated_identity.as_ref())
    else {
        return Ok(());
    };

    let is_delegator = matches!(
        principal,
        Principal::User(user) if user.identity.subject == delegation.principal_subject
    );
    let is_containment_admin = matches!(
        grant,
        AuthGrant::PlatformAdmin | AuthGrant::Member(openshell_core::proto::WorkspaceRole::Admin)
    );
    if is_delegator
        || (operation == DelegatedSandboxLifecycleOperation::Stop && is_containment_admin)
    {
        return Ok(());
    }

    if matches!(principal, Principal::Anonymous) {
        return Err(Status::unauthenticated(
            "sandbox lifecycle methods require an authenticated caller",
        ));
    }

    tracing::info!(
        sandbox_id = %sandbox.object_id(),
        operation = operation.as_str(),
        "delegated identity sandbox lifecycle access denied"
    );
    Err(Status::permission_denied(format!(
        "only the delegating principal may {} this delegated identity sandbox",
        operation.as_str()
    )))
}

pub async fn handle_withdraw(
    state: &Arc<ServerState>,
    request: Request<WithdrawSandboxDelegatedIdentityRequest>,
) -> Result<Response<WithdrawSandboxDelegatedIdentityResponse>, Status> {
    let principal = crate::grpc::extract_principal(&request)?;
    let req = request.into_inner();
    let sandbox = authorized_sandbox_by_name(state, &principal, &req.workspace, &req.name).await?;
    let record = sandbox_delegated_identity_record(state, &sandbox).await?;
    let delegation = record
        .as_ref()
        .and_then(|record| record.delegated_identity.as_ref());
    ensure_delegator(&principal, delegation)?;
    let Some(record) = record else {
        return Err(Status::invalid_argument(
            "sandbox delegated identity is not enabled",
        ));
    };
    let now = current_time_ms();
    let mut changed = false;
    state
        .store
        .update_message_cas::<SandboxDelegatedIdentityRecord, _>(record.object_id(), 0, |current| {
            if let Some(delegation) = current.delegated_identity.as_mut()
                && delegation.withdrawn_at_ms == 0
            {
                delegation.withdrawn_at_ms = now;
                changed = true;
            }
        })
        .await
        .map_err(|e| crate::grpc::persistence_error_to_status(e, "withdraw delegated identity"))?;
    Ok(Response::new(WithdrawSandboxDelegatedIdentityResponse {
        sandbox: Some(sandbox),
        withdrawn: changed,
    }))
}

pub async fn handle_extend(
    state: &Arc<ServerState>,
    request: Request<ExtendSandboxDelegatedIdentityRequest>,
) -> Result<Response<ExtendSandboxDelegatedIdentityResponse>, Status> {
    let principal = crate::grpc::extract_principal(&request)?;
    let req = request.into_inner();
    let requested = req
        .delegated_identity
        .ok_or_else(|| Status::invalid_argument("delegated_identity is required"))?;
    let sandbox = authorized_sandbox_by_name(state, &principal, &req.workspace, &req.name).await?;
    let _sandbox_sync_guard = state.compute.sandbox_sync_guard().await;
    let record = sandbox_delegated_identity_record(state, &sandbox).await?;
    let delegation = record
        .as_ref()
        .and_then(|record| record.delegated_identity.as_ref());
    ensure_delegator(&principal, delegation)?;
    let Some(record) = record else {
        return Err(Status::invalid_argument(
            "sandbox delegated identity is not enabled",
        ));
    };
    let user = require_user(&principal)?;
    validate_delegation_window(state, requested.delegated_until_ms)?;
    let credential = get_user_credential(state, user).await?.ok_or_else(|| {
        Status::failed_precondition(
            "delegated identity authorization is missing; authorize it before extending the sandbox",
        )
    })?;
    ensure_delegated_credential_usable(&credential)?;
    ensure_delegated_credential_material_present(&credential)?;
    state
        .store
        .update_message_cas::<SandboxDelegatedIdentityRecord, _>(record.object_id(), 0, |current| {
            if let Some(delegation) = current.delegated_identity.as_mut() {
                delegation.credential_id = credential.object_id().to_string();
                delegation.delegated_until_ms = requested.delegated_until_ms;
                delegation.withdrawn_at_ms = 0;
            }
        })
        .await
        .map_err(|error| {
            crate::grpc::persistence_error_to_status(error, "extend delegated identity")
        })?;
    Ok(Response::new(ExtendSandboxDelegatedIdentityResponse {
        sandbox: Some(sandbox),
    }))
}

pub async fn handle_list_credentials(
    state: &Arc<ServerState>,
    request: Request<ListDelegatedIdentityCredentialsRequest>,
) -> Result<Response<ListDelegatedIdentityCredentialsResponse>, Status> {
    let principal = crate::grpc::extract_principal(&request)?;
    require_platform_admin(&state.admin_role, &principal)?;
    let req = request.into_inner();
    let credentials = state
        .store
        .list_all_messages::<DelegatedIdentityCredential>(
            crate::grpc::clamp_limit(req.limit, 100, crate::grpc::MAX_PAGE_SIZE),
            req.offset,
        )
        .await
        .map_err(|e| Status::internal(format!("list delegated credentials failed: {e}")))?;
    let credentials = credentials
        .into_iter()
        .map(delegated_credential_summary)
        .collect();
    Ok(Response::new(ListDelegatedIdentityCredentialsResponse {
        credentials,
    }))
}

pub async fn handle_get_credential_status(
    state: &Arc<ServerState>,
    request: Request<GetDelegatedIdentityCredentialStatusRequest>,
) -> Result<Response<GetDelegatedIdentityCredentialStatusResponse>, Status> {
    let principal = crate::grpc::extract_principal(&request)?;
    require_platform_admin(&state.admin_role, &principal)?;
    let req = request.into_inner();
    let credential = state
        .store
        .get_message::<DelegatedIdentityCredential>(&req.id)
        .await
        .map_err(|e| Status::internal(format!("fetch delegated credential failed: {e}")))?
        .ok_or_else(|| Status::not_found("delegated credential not found"))?;
    Ok(Response::new(
        GetDelegatedIdentityCredentialStatusResponse {
            credential: Some(delegated_credential_summary(credential)),
            now_ms: current_time_ms(),
        },
    ))
}

fn delegated_credential_summary(
    credential: DelegatedIdentityCredential,
) -> DelegatedIdentityCredentialSummary {
    DelegatedIdentityCredentialSummary {
        metadata: credential.metadata,
        issuer: credential.issuer,
        client_id: credential.client_id,
        principal_subject: credential.principal_subject,
        refresh_token_present: credential
            .secret_material_handles
            .contains_key(REFRESH_TOKEN_MATERIAL_KEY),
        access_token_present: credential
            .secret_material_handles
            .contains_key(ACCESS_TOKEN_MATERIAL_KEY),
        access_token_expires_at_ms: credential.access_token_expires_at_ms,
        scopes: credential.scopes,
        audience: credential.audience,
        last_refresh_at_ms: credential.last_refresh_at_ms,
        revoked_at_ms: credential.revoked_at_ms,
    }
}

pub async fn handle_revoke_credential(
    state: &Arc<ServerState>,
    request: Request<RevokeDelegatedIdentityCredentialRequest>,
) -> Result<Response<RevokeDelegatedIdentityCredentialResponse>, Status> {
    let principal = crate::grpc::extract_principal(&request)?;
    require_platform_admin(&state.admin_role, &principal)?;
    let req = request.into_inner();
    let now = current_time_ms();
    let mut revoked = false;
    let credential = state
        .store
        .update_message_cas::<DelegatedIdentityCredential, _>(
            &req.id,
            req.expected_resource_version,
            |credential| {
                if credential.revoked_at_ms == 0 {
                    credential.revoked_at_ms = now;
                    revoked = true;
                }
                move_active_handles_to_pending(credential);
            },
        )
        .await
        .map_err(|e| crate::grpc::persistence_error_to_status(e, "revoke delegated credential"))?;
    let credential = match cleanup_pending_secret_deletions(state, credential).await {
        Ok(cleaned) => cleaned,
        Err(error) => {
            tracing::warn!(
                credential_id = %req.id,
                error = %error,
                "delegated credential revoked; secret cleanup will be retried"
            );
            state
                .store
                .get_message::<DelegatedIdentityCredential>(&req.id)
                .await
                .map_err(|e| {
                    Status::internal(format!("fetch revoked delegated credential failed: {e}"))
                })?
                .ok_or_else(|| Status::not_found("delegated credential not found"))?
        }
    };
    let resource_version = credential
        .metadata
        .as_ref()
        .map(|metadata| metadata.resource_version)
        .unwrap_or_default();
    Ok(Response::new(RevokeDelegatedIdentityCredentialResponse {
        revoked,
        revoked_at_ms: credential.revoked_at_ms,
        resource_version,
    }))
}

pub async fn handle_delete_credential(
    state: &Arc<ServerState>,
    request: Request<DeleteDelegatedIdentityCredentialRequest>,
) -> Result<Response<DeleteDelegatedIdentityCredentialResponse>, Status> {
    let principal = crate::grpc::extract_principal(&request)?;
    require_platform_admin(&state.admin_role, &principal)?;
    let req = request.into_inner();
    let _sandbox_sync_guard = state.compute.sandbox_sync_guard().await;
    let credential = state
        .store
        .get_message::<DelegatedIdentityCredential>(&req.id)
        .await
        .map_err(|e| Status::internal(format!("fetch delegated credential failed: {e}")))?;
    let Some(credential) = credential else {
        return Ok(Response::new(DeleteDelegatedIdentityCredentialResponse {
            deleted: false,
        }));
    };
    let is_tombstoned = credential
        .metadata
        .as_ref()
        .is_some_and(|metadata| metadata.deletion_timestamp_ms != 0);
    if !is_tombstoned {
        ensure_expected_resource_version(&credential, req.expected_resource_version)?;
        ensure_no_active_delegation_references(state, &req.id).await?;
    }
    let expected_resource_version = if is_tombstoned || req.expected_resource_version == 0 {
        credential.get_resource_version()
    } else {
        req.expected_resource_version
    };
    let deleted =
        tombstone_and_delete_credential(state, &req.id, expected_resource_version).await?;
    Ok(Response::new(DeleteDelegatedIdentityCredentialResponse {
        deleted,
    }))
}

fn ensure_expected_resource_version(
    credential: &DelegatedIdentityCredential,
    expected_resource_version: u64,
) -> Result<(), Status> {
    if expected_resource_version == 0
        || credential.get_resource_version() == expected_resource_version
    {
        return Ok(());
    }
    Err(Status::aborted(
        "delegated credential resource version conflict",
    ))
}

async fn ensure_no_active_delegation_references(
    state: &Arc<ServerState>,
    credential_id: &str,
) -> Result<(), Status> {
    let now = current_time_ms();
    let mut offset = 0;
    loop {
        let records = state
            .store
            .list_all_messages::<SandboxDelegatedIdentityRecord>(crate::grpc::MAX_PAGE_SIZE, offset)
            .await
            .map_err(|e| {
                Status::internal(format!(
                    "list sandbox delegated identity references failed: {e}"
                ))
            })?;
        if records.iter().any(|record| {
            record
                .delegated_identity
                .as_ref()
                .is_some_and(|delegation| {
                    delegation.credential_id == credential_id
                        && delegation.withdrawn_at_ms == 0
                        && delegation.delegated_until_ms > now
                })
        }) {
            return Err(Status::failed_precondition(
                "delegated credential is referenced by an active sandbox delegation",
            ));
        }
        if records.len() < crate::grpc::MAX_PAGE_SIZE as usize {
            return Ok(());
        }
        offset = offset.saturating_add(crate::grpc::MAX_PAGE_SIZE);
    }
}

async fn tombstone_and_delete_credential(
    state: &Arc<ServerState>,
    credential_id: &str,
    expected_resource_version: u64,
) -> Result<bool, Status> {
    let now = current_time_ms();
    let credential = state
        .store
        .update_message_cas::<DelegatedIdentityCredential, _>(
            credential_id,
            expected_resource_version,
            |credential| {
                if let Some(metadata) = credential.metadata.as_mut()
                    && metadata.deletion_timestamp_ms == 0
                {
                    metadata.deletion_timestamp_ms = now;
                }
                if credential.revoked_at_ms == 0 {
                    credential.revoked_at_ms = now;
                }
                move_active_handles_to_pending(credential);
            },
        )
        .await
        .map_err(|error| {
            crate::grpc::persistence_error_to_status(error, "delete delegated credential")
        })?;

    state
        .credentials
        .delete_secret_material_deletions(
            delegated_secret_scope(credential_id),
            &credential.pending_secret_deletions,
        )
        .await
        .map_err(|error| {
            Status::new(
                error.code(),
                format!(
                    "delegated credential is disabled, but secret cleanup failed and will be retried: {}",
                    error.message()
                ),
            )
        })?;

    state
        .store
        .delete_if(
            DelegatedIdentityCredential::object_type(),
            credential_id,
            credential.get_resource_version(),
        )
        .await
        .map_err(|error| {
            crate::grpc::persistence_error_to_status(error, "delete delegated credential")
        })
}

fn move_active_handles_to_pending(credential: &mut DelegatedIdentityCredential) {
    credential.refresh_lease = None;
    let handles = std::mem::take(&mut credential.secret_material_handles);
    enqueue_handle_deletions(&mut credential.pending_secret_deletions, handles);
}

fn enqueue_handle_deletions(
    pending: &mut Vec<StoredRefreshMaterialDeletion>,
    handles: HashMap<String, CredentialHandle>,
) {
    pending.extend(handles.into_iter().map(|(material_key, handle)| {
        StoredRefreshMaterialDeletion {
            material_key,
            handle: Some(handle),
        }
    }));
}

async fn cleanup_pending_secret_deletions(
    state: &Arc<ServerState>,
    credential: DelegatedIdentityCredential,
) -> Result<DelegatedIdentityCredential, Status> {
    if credential.pending_secret_deletions.is_empty() {
        return Ok(credential);
    }
    state
        .credentials
        .delete_secret_material_deletions(
            delegated_secret_scope(credential.object_id()),
            &credential.pending_secret_deletions,
        )
        .await?;
    state
        .store
        .update_message_cas::<DelegatedIdentityCredential, _>(
            credential.object_id(),
            credential.get_resource_version(),
            |current| current.pending_secret_deletions.clear(),
        )
        .await
        .map_err(|error| {
            crate::grpc::persistence_error_to_status(
                error,
                "record delegated credential secret cleanup",
            )
        })
}

async fn cleanup_pending_secret_deletions_best_effort(
    state: &Arc<ServerState>,
    credential: DelegatedIdentityCredential,
) -> DelegatedIdentityCredential {
    let retained = credential.clone();
    match cleanup_pending_secret_deletions(state, credential).await {
        Ok(cleaned) => cleaned,
        Err(error) => {
            tracing::warn!(
                credential_id = %retained.object_id(),
                error = %error,
                "failed to clean up superseded delegated credential material; retrying later"
            );
            retained
        }
    }
}

fn require_user(principal: &Principal) -> Result<&UserPrincipal, Status> {
    match principal {
        Principal::User(user) => Ok(user),
        _ => Err(Status::permission_denied(
            "delegated identity requires an authenticated user principal",
        )),
    }
}

fn ensure_delegator(
    principal: &Principal,
    delegation: Option<&SandboxDelegatedIdentity>,
) -> Result<(), Status> {
    let user = require_user(principal)?;
    let delegation = delegation.ok_or_else(|| {
        Status::failed_precondition("sandbox was not created with delegated identity")
    })?;
    if delegation.principal_subject != user.identity.subject {
        return Err(Status::permission_denied(
            "only the delegating principal may manage this sandbox delegated identity",
        ));
    }
    Ok(())
}

fn validate_delegation_window(
    state: &Arc<ServerState>,
    delegated_until_ms: i64,
) -> Result<(), Status> {
    let now = current_time_ms();
    if delegated_until_ms <= now {
        return Err(Status::invalid_argument(
            "delegated_identity.delegated_until_ms must be in the future",
        ));
    }
    let max_ms = i64::try_from(state.config.max_delegated_identity_duration_secs)
        .unwrap_or(i64::MAX / 1000)
        .saturating_mul(1000);
    if delegated_until_ms.saturating_sub(now) > max_ms {
        return Err(Status::failed_precondition(format!(
            "delegated identity duration exceeds gateway maximum of {} seconds",
            state.config.max_delegated_identity_duration_secs
        )));
    }
    Ok(())
}

fn configured_delegated_issuer(state: &Arc<ServerState>) -> Result<&str, Status> {
    state
        .config
        .oidc
        .as_ref()
        .map(|oidc| oidc.issuer.trim_end_matches('/'))
        .ok_or_else(|| {
            Status::failed_precondition(
                "delegated identity requires gateway OIDC authentication to be configured",
            )
        })
}

async fn validate_authorization_grant(
    state: &Arc<ServerState>,
    user: &UserPrincipal,
    grant: &DelegatedIdentityAuthorizationGrant,
) -> Result<i64, Status> {
    if grant.issuer.trim().is_empty() {
        return Err(Status::invalid_argument("grant.issuer is required"));
    }
    if grant.issuer.trim_end_matches('/') != configured_delegated_issuer(state)? {
        return Err(Status::invalid_argument(
            "grant.issuer must match the gateway OIDC issuer",
        ));
    }
    if grant.client_id.trim().is_empty() {
        return Err(Status::invalid_argument("grant.client_id is required"));
    }
    if grant.refresh_token.trim().is_empty() {
        return Err(Status::invalid_argument("grant.refresh_token is required"));
    }
    if grant.access_token.trim().is_empty() {
        return Err(Status::invalid_argument("grant.access_token is required"));
    }
    validate_delegated_access_token_subject(state, user, grant).await
}

async fn validate_delegated_access_token_subject(
    state: &Arc<ServerState>,
    user: &UserPrincipal,
    grant: &DelegatedIdentityAuthorizationGrant,
) -> Result<i64, Status> {
    validate_delegated_access_token_subject_value(
        state,
        &grant.access_token,
        &user.identity.subject,
    )
    .await
}

async fn validate_delegated_access_token_subject_value(
    state: &Arc<ServerState>,
    access_token: &str,
    expected_subject: &str,
) -> Result<i64, Status> {
    let cache = state.oidc_cache.as_ref().ok_or_else(|| {
        Status::failed_precondition(
            "delegated identity requires gateway OIDC token validation to be configured",
        )
    })?;
    let validated = cache.validate_token_details(access_token).await?;
    ensure_delegated_token_subject_matches(&validated.identity.subject, expected_subject)?;
    Ok(validated.expires_at_ms)
}

fn ensure_delegated_token_subject_matches(
    token_subject: &str,
    caller_subject: &str,
) -> Result<(), Status> {
    if token_subject == caller_subject {
        Ok(())
    } else {
        Err(Status::permission_denied(
            "delegated_identity.access_token subject must match the authenticated caller",
        ))
    }
}

async fn authorized_sandbox_by_name(
    state: &Arc<ServerState>,
    principal: &Principal,
    workspace: &str,
    name: &str,
) -> Result<Sandbox, Status> {
    if name.trim().is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }
    let authz = authorize_workspace(
        &state.store,
        &state.admin_role,
        principal,
        workspace,
        MinWorkspaceRole::User,
    )
    .await?;
    let workspace =
        crate::grpc::workspace::resolve_workspace(state.store.as_ref(), &authz.workspace)
            .await?
            .name;
    state
        .store
        .get_message_by_name::<Sandbox>(&workspace, name)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))
}

async fn upsert_credential(
    state: &Arc<ServerState>,
    user: &UserPrincipal,
    grant: DelegatedIdentityAuthorizationGrant,
    access_token_expires_at_ms: i64,
) -> Result<DelegatedIdentityCredential, Status> {
    let id = delegated_credential_id(&grant.issuer, &user.identity.subject);
    let now = current_time_ms();
    let existing = state
        .store
        .get_message::<DelegatedIdentityCredential>(&id)
        .await
        .map_err(|e| Status::internal(format!("fetch delegated credential failed: {e}")))?;
    if existing.as_ref().is_some_and(|credential| {
        credential
            .metadata
            .as_ref()
            .is_some_and(|metadata| metadata.deletion_timestamp_ms != 0)
    }) {
        return Err(Status::failed_precondition(
            "delegated identity credential is being deleted",
        ));
    }

    let material = HashMap::from([
        (REFRESH_TOKEN_MATERIAL_KEY.to_string(), grant.refresh_token),
        (ACCESS_TOKEN_MATERIAL_KEY.to_string(), grant.access_token),
    ]);
    let staged_handles = store_staged_secret_material(state, &id, &material).await?;
    let mut credential = DelegatedIdentityCredential {
        metadata: Some(ObjectMeta {
            id: id.clone(),
            name: id.clone(),
            created_at_ms: now,
            labels: HashMap::new(),
            resource_version: 0,
            annotations: HashMap::new(),
            workspace: GLOBAL_WORKSPACE.to_string(),
            deletion_timestamp_ms: 0,
        }),
        issuer: grant.issuer,
        client_id: grant.client_id,
        principal_subject: user.identity.subject.clone(),
        access_token_expires_at_ms,
        scopes: grant.scopes,
        audience: grant.audience,
        last_refresh_at_ms: now,
        revoked_at_ms: 0,
        secret_material_handles: staged_handles.clone(),
        pending_secret_deletions: Vec::new(),
        refresh_lease: None,
    };

    let write_condition = if let Some(existing) = existing {
        let write_condition = delegated_credential_upsert_condition(&existing);
        credential.metadata = existing.metadata;
        credential.pending_secret_deletions = existing.pending_secret_deletions;
        enqueue_handle_deletions(
            &mut credential.pending_secret_deletions,
            existing.secret_material_handles,
        );
        write_condition
    } else {
        WriteCondition::MustCreate
    };
    let labels = credential
        .object_labels()
        .filter(|labels| !labels.is_empty())
        .map(|labels| {
            serde_json::to_string(&labels)
                .map_err(|e| Status::internal(format!("serialize labels failed: {e}")))
        })
        .transpose()?;
    let result = state
        .store
        .put_if(
            DelegatedIdentityCredential::object_type(),
            credential.object_id(),
            credential.object_name(),
            credential.object_workspace(),
            &credential.encode_to_vec(),
            labels.as_deref(),
            write_condition,
        )
        .await;
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            cleanup_staged_secret_material(state, &id, &staged_handles).await;
            return Err(crate::grpc::persistence_error_to_status(
                error,
                "persist delegated credential",
            ));
        }
    };
    if let Some(metadata) = credential.metadata.as_mut() {
        metadata.resource_version = result.resource_version;
    }
    credential = cleanup_pending_secret_deletions_best_effort(state, credential).await;
    Ok(credential)
}

fn delegated_credential_upsert_condition(existing: &DelegatedIdentityCredential) -> WriteCondition {
    WriteCondition::MatchResourceVersion(existing.get_resource_version())
}

fn ensure_delegated_credential_usable(
    credential: &DelegatedIdentityCredential,
) -> Result<(), Status> {
    if credential.revoked_at_ms > 0 {
        return Err(Status::failed_precondition(
            "delegated identity credential is revoked",
        ));
    }
    if delegated_credential_is_deleting(credential) {
        return Err(Status::failed_precondition(
            "delegated identity credential is being deleted",
        ));
    }
    Ok(())
}

fn delegated_credential_is_deleting(credential: &DelegatedIdentityCredential) -> bool {
    credential
        .metadata
        .as_ref()
        .is_some_and(|metadata| metadata.deletion_timestamp_ms != 0)
}

fn ensure_delegated_credential_material_present(
    credential: &DelegatedIdentityCredential,
) -> Result<(), Status> {
    if !credential
        .secret_material_handles
        .contains_key(ACCESS_TOKEN_MATERIAL_KEY)
        || !credential
            .secret_material_handles
            .contains_key(REFRESH_TOKEN_MATERIAL_KEY)
    {
        return Err(Status::failed_precondition(
            "delegated identity authorization is incomplete",
        ));
    }
    Ok(())
}

fn delegated_credential_id(issuer: &str, principal_subject: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(issuer.trim_end_matches('/'));
    hasher.update(b"\0");
    hasher.update(principal_subject);
    format!("delegated-identity-{:x}", hasher.finalize())
}

async fn get_user_credential(
    state: &Arc<ServerState>,
    user: &UserPrincipal,
) -> Result<Option<DelegatedIdentityCredential>, Status> {
    let id = delegated_credential_id(configured_delegated_issuer(state)?, &user.identity.subject);
    state
        .store
        .get_message::<DelegatedIdentityCredential>(&id)
        .await
        .map_err(|error| Status::internal(format!("fetch delegated credential failed: {error}")))
}

fn delegated_secret_scope(credential_id: &str) -> SecretMaterialScope<'_> {
    SecretMaterialScope {
        owner_name: DELEGATED_IDENTITY_SECRET_OWNER,
        workspace: GLOBAL_WORKSPACE,
        owner_id: credential_id,
        key_namespace: DELEGATED_IDENTITY_SECRET_NAMESPACE,
    }
}

async fn store_staged_secret_material(
    state: &Arc<ServerState>,
    credential_id: &str,
    material: &HashMap<String, String>,
) -> Result<HashMap<String, CredentialHandle>, Status> {
    let staging_id = format!("{credential_id}-material-{}", uuid::Uuid::new_v4());
    let handles = state
        .credentials
        .store_secret_material_with_object_id(
            delegated_secret_scope(credential_id),
            &staging_id,
            material,
            &HashMap::new(),
        )
        .await?;
    if material.keys().all(|key| handles.contains_key(key)) {
        return Ok(handles);
    }
    cleanup_staged_secret_material(state, credential_id, &handles).await;
    Err(Status::internal(
        "credential driver did not return every delegated identity material handle",
    ))
}

async fn cleanup_staged_secret_material(
    state: &Arc<ServerState>,
    credential_id: &str,
    handles: &HashMap<String, CredentialHandle>,
) {
    if handles.is_empty() {
        return;
    }
    if let Err(error) = state
        .credentials
        .delete_secret_material_handles(delegated_secret_scope(credential_id), handles)
        .await
    {
        let pending_error = persist_staged_cleanup_handles(state, credential_id, handles).await;
        tracing::warn!(
            credential_id,
            error = %error,
            pending_cleanup_recorded = pending_error.is_ok(),
            pending_cleanup_error = pending_error.as_ref().err().map(Status::message),
            "failed to clean up staged delegated credential material"
        );
    }
}

async fn persist_staged_cleanup_handles(
    state: &Arc<ServerState>,
    credential_id: &str,
    handles: &HashMap<String, CredentialHandle>,
) -> Result<(), Status> {
    let current = state
        .store
        .get_message::<DelegatedIdentityCredential>(credential_id)
        .await
        .map_err(|error| {
            Status::internal(format!(
                "fetch delegated credential for staged cleanup failed: {error}"
            ))
        })?
        .ok_or_else(|| {
            Status::not_found("delegated credential is unavailable for staged cleanup")
        })?;
    let handles = handles.clone();
    state
        .store
        .update_message_cas::<DelegatedIdentityCredential, _>(
            credential_id,
            current.get_resource_version(),
            |credential| {
                enqueue_handle_deletions(&mut credential.pending_secret_deletions, handles.clone());
            },
        )
        .await
        .map(|_| ())
        .map_err(|error| {
            crate::grpc::persistence_error_to_status(
                error,
                "record staged delegated credential cleanup",
            )
        })
}

struct DelegatedSecretMaterial {
    access_token: String,
    refresh_token: String,
}

#[derive(Debug)]
struct ResolvedDelegatedAccessToken {
    credential: DelegatedIdentityCredential,
    access_token: String,
}

async fn resolve_delegated_secret_material(
    state: &Arc<ServerState>,
    credential: &DelegatedIdentityCredential,
) -> Result<DelegatedSecretMaterial, Status> {
    let mut material = state
        .credentials
        .resolve_secret_material(
            delegated_secret_scope(credential.object_id()),
            &credential.secret_material_handles,
        )
        .await?;
    let access_token = material.remove(ACCESS_TOKEN_MATERIAL_KEY).ok_or_else(|| {
        Status::failed_precondition("delegated credential access token is missing")
    })?;
    let refresh_token = material.remove(REFRESH_TOKEN_MATERIAL_KEY).ok_or_else(|| {
        Status::failed_precondition("delegated credential refresh token is missing")
    })?;
    Ok(DelegatedSecretMaterial {
        access_token,
        refresh_token,
    })
}

pub fn spawn_credential_cleanup_worker(state: Arc<ServerState>, interval: Duration) {
    tracing::info!(
        interval_seconds = interval.as_secs(),
        "delegated credential cleanup worker started"
    );
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if let Err(error) = run_credential_cleanup_tick(&state).await {
                tracing::warn!(
                    error = %error,
                    "delegated credential cleanup worker tick failed"
                );
            }
        }
    });
}

async fn run_credential_cleanup_tick(state: &Arc<ServerState>) -> Result<(), Status> {
    let mut offset = 0;
    loop {
        let credentials = state
            .store
            .list_all_messages::<DelegatedIdentityCredential>(crate::grpc::MAX_PAGE_SIZE, offset)
            .await
            .map_err(|error| {
                Status::internal(format!(
                    "list delegated credentials for cleanup failed: {error}"
                ))
            })?;
        for credential in &credentials {
            let deleting = credential
                .metadata
                .as_ref()
                .is_some_and(|metadata| metadata.deletion_timestamp_ms != 0);
            if deleting {
                if let Err(error) = tombstone_and_delete_credential(
                    state,
                    credential.object_id(),
                    credential.get_resource_version(),
                )
                .await
                {
                    tracing::warn!(
                        credential_id = %credential.object_id(),
                        error = %error,
                        "failed to finalize delegated credential deletion; retrying later"
                    );
                }
            } else if !credential.pending_secret_deletions.is_empty()
                && let Err(error) =
                    cleanup_pending_secret_deletions(state, credential.clone()).await
            {
                tracing::warn!(
                    credential_id = %credential.object_id(),
                    error = %error,
                    "failed to retry delegated credential secret cleanup"
                );
            }
        }
        if credentials.len() < crate::grpc::MAX_PAGE_SIZE as usize {
            return Ok(());
        }
        offset = offset.saturating_add(crate::grpc::MAX_PAGE_SIZE);
    }
}

async fn refresh_if_needed(
    state: &Arc<ServerState>,
    credential: DelegatedIdentityCredential,
) -> Result<ResolvedDelegatedAccessToken, Status> {
    ensure_delegated_credential_usable(&credential)?;
    let mut credential = cleanup_pending_secret_deletions_best_effort(state, credential).await;
    let wait_started = tokio::time::Instant::now();

    loop {
        ensure_delegated_credential_usable(&credential)?;
        ensure_delegated_credential_material_present(&credential)?;
        let now = current_time_ms();
        if credential.access_token_expires_at_ms > 0
            && credential.access_token_expires_at_ms.saturating_sub(now) > REFRESH_SKEW_MS
        {
            let material = resolve_delegated_secret_material(state, &credential).await?;
            return Ok(ResolvedDelegatedAccessToken {
                credential,
                access_token: material.access_token,
            });
        }

        match try_acquire_refresh_lease(state, &credential).await? {
            RefreshLeaseAttempt::Acquired {
                credential,
                owner_id,
            } => {
                return refresh_with_owned_lease(state, *credential, &owner_id).await;
            }
            RefreshLeaseAttempt::Held => {
                if wait_started.elapsed() >= REFRESH_LEASE_WAIT_LIMIT {
                    return Err(Status::deadline_exceeded(
                        "timed out waiting for delegated credential refresh",
                    ));
                }
                tokio::time::sleep(REFRESH_LEASE_POLL_INTERVAL).await;
                credential = state
                    .store
                    .get_message::<DelegatedIdentityCredential>(credential.object_id())
                    .await
                    .map_err(|error| {
                        Status::internal(format!(
                            "reload delegated credential while waiting for refresh failed: {error}"
                        ))
                    })?
                    .ok_or_else(|| {
                        Status::failed_precondition("delegated identity credential is missing")
                    })?;
            }
        }
    }
}

enum RefreshLeaseAttempt {
    Acquired {
        credential: Box<DelegatedIdentityCredential>,
        owner_id: String,
    },
    Held,
}

async fn try_acquire_refresh_lease(
    state: &Arc<ServerState>,
    credential: &DelegatedIdentityCredential,
) -> Result<RefreshLeaseAttempt, Status> {
    let now = current_time_ms();
    if credential
        .refresh_lease
        .as_ref()
        .is_some_and(|lease| lease.expires_at_ms > now)
    {
        return Ok(RefreshLeaseAttempt::Held);
    }

    let owner_id = uuid::Uuid::new_v4().to_string();
    let owner_id_for_update = owner_id.clone();
    let result = state
        .store
        .update_message_cas::<DelegatedIdentityCredential, _>(
            credential.object_id(),
            credential.get_resource_version(),
            move |current| {
                current.refresh_lease = Some(DelegatedIdentityRefreshLease {
                    owner_id: owner_id_for_update.clone(),
                    expires_at_ms: now.saturating_add(REFRESH_LEASE_DURATION_MS),
                });
            },
        )
        .await;
    match result {
        Ok(credential) => Ok(RefreshLeaseAttempt::Acquired {
            credential: Box::new(credential),
            owner_id,
        }),
        Err(PersistenceError::Conflict { .. }) => Ok(RefreshLeaseAttempt::Held),
        Err(error) => Err(crate::grpc::persistence_error_to_status(
            error,
            "acquire delegated credential refresh lease",
        )),
    }
}

async fn refresh_with_owned_lease(
    state: &Arc<ServerState>,
    credential: DelegatedIdentityCredential,
    owner_id: &str,
) -> Result<ResolvedDelegatedAccessToken, Status> {
    let result = refresh_with_owned_lease_inner(state, credential.clone(), owner_id).await;
    if result.is_err() {
        release_refresh_lease_best_effort(state, credential.object_id(), owner_id).await;
    }
    result
}

async fn refresh_with_owned_lease_inner(
    state: &Arc<ServerState>,
    credential: DelegatedIdentityCredential,
    owner_id: &str,
) -> Result<ResolvedDelegatedAccessToken, Status> {
    ensure_refresh_lease_owner(&credential, owner_id)?;
    let material = resolve_delegated_secret_material(state, &credential).await?;
    let client = delegated_identity_http_client()?;
    let token_endpoint = discover_token_endpoint(client, &credential.issuer).await?;
    let scopes = credential
        .scopes
        .split_whitespace()
        .filter(|scope| !scope.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let refreshed = openshell_core::oauth::post_oauth_refresh_token(
        client,
        &token_endpoint,
        &openshell_core::oauth::RefreshTokenParams {
            refresh_token: &material.refresh_token,
            client_id: &credential.client_id,
            scopes: &scopes,
            allow_insecure_http: delegated_refresh_allows_insecure_http(
                &credential.issuer,
                &token_endpoint,
            ),
        },
    )
    .await
    .map_err(|e| Status::failed_precondition(delegated_refresh_error_message(&e.to_string())))?;
    let expires_at_ms = validate_delegated_access_token_subject_value(
        state,
        &refreshed.access_token,
        &credential.principal_subject,
    )
    .await?;
    let refreshed_at_ms = current_time_ms();
    let refreshed_access_token = refreshed.access_token;
    let mut replacement_material = HashMap::from([(
        ACCESS_TOKEN_MATERIAL_KEY.to_string(),
        refreshed_access_token.clone(),
    )]);
    if let Some(refresh_token) = refreshed.refresh_token {
        replacement_material.insert(REFRESH_TOKEN_MATERIAL_KEY.to_string(), refresh_token);
    }
    let credential_id = credential.object_id().to_string();
    let staged_handles =
        store_staged_secret_material(state, &credential_id, &replacement_material).await?;
    let updated = match commit_refreshed_material(
        state,
        &credential_id,
        owner_id,
        &staged_handles,
        expires_at_ms,
        refreshed_at_ms,
    )
    .await
    {
        Ok(updated) => updated,
        Err(status) => {
            cleanup_staged_secret_material(state, &credential_id, &staged_handles).await;
            return Err(status);
        }
    };
    let updated = cleanup_pending_secret_deletions_best_effort(state, updated).await;
    Ok(ResolvedDelegatedAccessToken {
        credential: updated,
        access_token: refreshed_access_token,
    })
}

async fn commit_refreshed_material(
    state: &Arc<ServerState>,
    credential_id: &str,
    owner_id: &str,
    staged_handles: &HashMap<String, CredentialHandle>,
    expires_at_ms: i64,
    refreshed_at_ms: i64,
) -> Result<DelegatedIdentityCredential, Status> {
    loop {
        let current = state
            .store
            .get_message::<DelegatedIdentityCredential>(credential_id)
            .await
            .map_err(|error| {
                Status::internal(format!(
                    "reload delegated credential before committing refresh failed: {error}"
                ))
            })?
            .ok_or_else(|| {
                Status::failed_precondition("delegated identity credential was deleted")
            })?;
        ensure_delegated_credential_usable(&current)?;
        ensure_refresh_lease_owner(&current, owner_id)?;
        let staged_handles_for_update = staged_handles.clone();
        let result = state
            .store
            .update_message_cas::<DelegatedIdentityCredential, _>(
                credential_id,
                current.get_resource_version(),
                move |credential| {
                    for (material_key, handle) in &staged_handles_for_update {
                        if let Some(previous) = credential
                            .secret_material_handles
                            .insert(material_key.clone(), handle.clone())
                        {
                            credential.pending_secret_deletions.push(
                                StoredRefreshMaterialDeletion {
                                    material_key: material_key.clone(),
                                    handle: Some(previous),
                                },
                            );
                        }
                    }
                    credential.access_token_expires_at_ms = expires_at_ms;
                    credential.last_refresh_at_ms = refreshed_at_ms;
                    credential.refresh_lease = None;
                },
            )
            .await;
        match result {
            Ok(updated) => return Ok(updated),
            Err(PersistenceError::Conflict { .. }) => {}
            Err(error) => {
                return Err(crate::grpc::persistence_error_to_status(
                    error,
                    "refresh delegated credential",
                ));
            }
        }
    }
}

fn ensure_refresh_lease_owner(
    credential: &DelegatedIdentityCredential,
    owner_id: &str,
) -> Result<(), Status> {
    if credential
        .refresh_lease
        .as_ref()
        .is_some_and(|lease| lease.owner_id == owner_id)
    {
        return Ok(());
    }
    Err(Status::aborted(
        "delegated credential refresh lease ownership changed",
    ))
}

async fn release_refresh_lease_best_effort(
    state: &Arc<ServerState>,
    credential_id: &str,
    owner_id: &str,
) {
    loop {
        let current = match state
            .store
            .get_message::<DelegatedIdentityCredential>(credential_id)
            .await
        {
            Ok(Some(current)) => current,
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(
                    credential_id,
                    error = %error,
                    "failed to reload delegated credential while releasing refresh lease"
                );
                return;
            }
        };
        if current
            .refresh_lease
            .as_ref()
            .is_none_or(|lease| lease.owner_id != owner_id)
        {
            return;
        }
        let result = state
            .store
            .update_message_cas::<DelegatedIdentityCredential, _>(
                credential_id,
                current.get_resource_version(),
                |credential| credential.refresh_lease = None,
            )
            .await;
        match result {
            Ok(_) => return,
            Err(PersistenceError::Conflict { .. }) => {}
            Err(error) => {
                tracing::warn!(
                    credential_id,
                    error = %error,
                    "failed to release delegated credential refresh lease"
                );
                return;
            }
        }
    }
}

fn delegated_identity_http_client() -> Result<&'static reqwest::Client, Status> {
    DELEGATED_IDENTITY_HTTP_CLIENT
        .as_ref()
        .map_err(|err| Status::internal(err.clone()))
}

fn delegated_refresh_allows_insecure_http(issuer: &str, token_endpoint: &str) -> bool {
    let Ok(issuer) = reqwest::Url::parse(issuer) else {
        return false;
    };
    let Ok(token_endpoint) = reqwest::Url::parse(token_endpoint) else {
        return false;
    };
    issuer.scheme() == "http"
        && token_endpoint.scheme() == "http"
        && issuer.host_str() == token_endpoint.host_str()
        && issuer.port_or_known_default() == token_endpoint.port_or_known_default()
}

fn delegated_refresh_error_message(error: &str) -> String {
    let mut message = format!("delegated credential refresh failed: {error}");
    if inactive_refresh_token_error(error) {
        message.push_str(
            "; the stored delegated identity refresh token is no longer active. \
             Retry sandbox create or delegated-identity extend to authorize a new delegated grant.",
        );
    }
    message
}

fn delegated_refresh_requires_reauthorization(status: &Status) -> bool {
    status.code() == tonic::Code::FailedPrecondition
        && (status.message().contains("no longer active")
            || status.message().contains("authorization is incomplete"))
}

fn inactive_refresh_token_error(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains("invalid_grant")
}

#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    issuer: String,
    token_endpoint: String,
}

async fn discover_token_endpoint(client: &reqwest::Client, issuer: &str) -> Result<String, Status> {
    let normalized = issuer.trim_end_matches('/');
    let url = format!("{normalized}/.well-known/openid-configuration");
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| Status::failed_precondition(format!("OIDC discovery failed: {e}")))?;
    if response.status().is_redirection() {
        return Err(Status::failed_precondition(format!(
            "OIDC discovery failed: redirect response {} is not allowed",
            response.status()
        )));
    }
    let discovery = response
        .error_for_status()
        .map_err(|e| Status::failed_precondition(format!("OIDC discovery failed: {e}")))?
        .json::<OidcDiscovery>()
        .await
        .map_err(|e| Status::failed_precondition(format!("OIDC discovery parse failed: {e}")))?;
    if discovery.issuer.trim_end_matches('/') != normalized {
        return Err(Status::failed_precondition(
            "OIDC discovery issuer does not match delegated credential issuer",
        ));
    }
    Ok(discovery.token_endpoint)
}

#[cfg(test)]
mod tests {
    use super::{
        delegated_credential_id, delegated_credential_status_fields, delegated_credential_summary,
        delegated_credential_upsert_condition, delegated_refresh_allows_insecure_http,
        delegated_refresh_error_message, ensure_delegated_credential_usable,
        ensure_delegated_token_subject_matches, ensure_expected_resource_version,
        sandbox_delegated_identity_record_id,
    };
    use crate::grpc::test_support::{authed_request, test_server_state};
    use crate::persistence::{ObjectType, Store, WriteCondition, current_time_ms};
    use crate::sandbox_index::SandboxIndex;
    use crate::sandbox_watch::SandboxWatchBus;
    use crate::supervisor_session::SupervisorSessionRegistry;
    use crate::tracing_bus::TracingLogBus;
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    use openshell_core::proto::{
        AuthorizeDelegatedIdentityRequest, DelegatedIdentityAuthorizationGrant,
        DelegatedIdentityCredential, DelegatedIdentityRefreshLease, DelegatedIdentityRequest,
        DeleteDelegatedIdentityCredentialRequest, ExtendSandboxDelegatedIdentityRequest,
        GetDelegatedIdentityAuthorizationStatusRequest, GetSandboxDelegatedIdentityStatusRequest,
        RevokeDelegatedIdentityCredentialRequest, Sandbox, SandboxDelegatedIdentity,
        SandboxDelegatedIdentityRecord, SandboxSpec, SandboxStatus,
    };
    use openshell_core::{Config, GetResourceVersion, ObjectId, OidcConfig};
    use prost::Message as _;
    use std::collections::HashMap;
    use std::sync::{Arc, LazyLock};
    use tonic::Code;
    use tonic::Request;

    const TEST_KID: &str = "test-signing-key";
    const TEST_AUDIENCE: &str = "openshell-cli";

    static TEST_RSA_KEY: LazyLock<TestRsaKey> = LazyLock::new(TestRsaKey::generate);

    struct TestRsaKey {
        private_pem: String,
        modulus_b64: String,
        exponent_b64: String,
    }

    impl TestRsaKey {
        fn generate() -> Self {
            use base64::Engine as _;
            use rsa::pkcs1::EncodeRsaPrivateKey as _;
            use rsa::traits::PublicKeyParts as _;

            let private = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048)
                .expect("generate RSA test key");
            let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            Self {
                private_pem: private
                    .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
                    .expect("encode RSA private key as PEM")
                    .to_string(),
                modulus_b64: b64.encode(private.n().to_bytes_be()),
                exponent_b64: b64.encode(private.e().to_bytes_be()),
            }
        }
    }

    #[test]
    fn delegated_refresh_allows_insecure_http_only_for_same_http_origin() {
        assert!(delegated_refresh_allows_insecure_http(
            "http://keycloak.127.0.0.1.sslip.io:9090/realms/openshell",
            "http://keycloak.127.0.0.1.sslip.io:9090/realms/openshell/protocol/openid-connect/token",
        ));
        assert!(!delegated_refresh_allows_insecure_http(
            "https://idp.example.com/realms/openshell",
            "http://idp.example.com/realms/openshell/protocol/openid-connect/token",
        ));
        assert!(!delegated_refresh_allows_insecure_http(
            "http://idp.example.com/realms/openshell",
            "http://metadata.internal/token",
        ));
        assert!(!delegated_refresh_allows_insecure_http(
            "not an issuer url",
            "http://idp.example.com/token",
        ));
    }

    #[test]
    fn delegated_refresh_error_message_explains_inactive_session_recovery() {
        let message = delegated_refresh_error_message(
            "token grant failed with status 400 Bad Request: error=invalid_grant; error_description=Session not active",
        );

        assert!(message.contains("delegated credential refresh failed"));
        assert!(message.contains("stored delegated identity refresh token is no longer active"));
        assert!(message.contains("authorize a new delegated grant"));
    }

    #[tokio::test]
    async fn delegated_oidc_discovery_does_not_follow_redirects() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let redirect_target = wiremock::MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": redirect_target.uri(),
                "token_endpoint": format!("{}/token", redirect_target.uri()),
            })))
            .mount(&redirect_target)
            .await;

        let issuer = wiremock::MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(307).insert_header(
                "Location",
                format!("{}/.well-known/openid-configuration", redirect_target.uri()),
            ))
            .mount(&issuer)
            .await;

        let status = super::discover_token_endpoint(
            super::delegated_identity_http_client().expect("delegated identity HTTP client"),
            &issuer.uri(),
        )
        .await
        .expect_err("OIDC discovery redirect must be rejected");

        assert_eq!(status.code(), Code::FailedPrecondition);
        assert!(status.message().contains("redirect response 307"));
        assert!(status.message().contains("not allowed"));
        assert!(
            redirect_target
                .received_requests()
                .await
                .expect("redirect target records requests")
                .is_empty(),
            "discovery redirect target must not receive a request"
        );
    }

    #[tokio::test]
    async fn delegated_refresh_does_not_replay_token_body_across_redirects() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let redirect_target = wiremock::MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "unexpected-token",
                "token_type": "Bearer",
                "expires_in": 3600,
            })))
            .mount(&redirect_target)
            .await;

        let token_server = wiremock::MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(308)
                    .insert_header("Location", format!("{}/token", redirect_target.uri())),
            )
            .mount(&token_server)
            .await;

        let error = openshell_core::oauth::post_oauth_refresh_token(
            super::delegated_identity_http_client().expect("delegated identity HTTP client"),
            &format!("{}/token", token_server.uri()),
            &openshell_core::oauth::RefreshTokenParams {
                refresh_token: "refresh-secret",
                client_id: "openshell-cli",
                scopes: &[],
                allow_insecure_http: true,
            },
        )
        .await
        .expect_err("refresh redirect must be rejected");

        let message = error.to_string();
        assert!(message.contains("308 Permanent Redirect"));
        assert!(!message.contains("refresh-secret"));
        assert!(
            redirect_target
                .received_requests()
                .await
                .expect("redirect target records requests")
                .is_empty(),
            "refresh redirect target must not receive the token form"
        );
    }

    #[tokio::test]
    async fn delegated_http_client_bypasses_ambient_proxy() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        const CHILD_ENV: &str = "OPENSHELL_TEST_DELEGATED_HTTP_PROXY_CHILD";
        const ISSUER_ENV: &str = "OPENSHELL_TEST_DELEGATED_HTTP_DIRECT_ISSUER";

        if std::env::var_os(CHILD_ENV).is_some() {
            let issuer = std::env::var(ISSUER_ENV).expect("direct issuer is set for child");
            let token_endpoint = super::discover_token_endpoint(
                super::delegated_identity_http_client().expect("delegated identity HTTP client"),
                &issuer,
            )
            .await
            .expect("delegated client should bypass ambient proxy");
            assert_eq!(token_endpoint, format!("{issuer}/token"));
            return;
        }

        let direct = wiremock::MockServer::start().await;
        let issuer = direct.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": issuer,
                "token_endpoint": format!("{issuer}/token"),
            })))
            .mount(&direct)
            .await;

        let proxy = wiremock::MockServer::start().await;
        Mock::given(wiremock::matchers::any())
            .respond_with(ResponseTemplate::new(502))
            .mount(&proxy)
            .await;

        let executable = std::env::current_exe().expect("current test executable");
        let output = tokio::process::Command::new(executable)
            .arg("--exact")
            .arg("delegated_identity::tests::delegated_http_client_bypasses_ambient_proxy")
            .arg("--nocapture")
            .env(CHILD_ENV, "1")
            .env(ISSUER_ENV, &issuer)
            .env("HTTP_PROXY", proxy.uri())
            .env("HTTPS_PROXY", proxy.uri())
            .env("ALL_PROXY", proxy.uri())
            .env("http_proxy", proxy.uri())
            .env("https_proxy", proxy.uri())
            .env("all_proxy", proxy.uri())
            .env("NO_PROXY", "")
            .env("no_proxy", "")
            .output()
            .await
            .expect("run delegated HTTP proxy child test");

        assert!(
            output.status.success(),
            "child test failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            direct
                .received_requests()
                .await
                .expect("direct server records requests")
                .len(),
            1,
            "delegated client should connect directly to the issuer"
        );
        assert!(
            proxy
                .received_requests()
                .await
                .expect("proxy records requests")
                .is_empty(),
            "ambient proxy must not receive delegated OIDC traffic"
        );
    }

    #[test]
    fn revoked_delegated_credential_is_not_usable_without_reauthorization() {
        let active = DelegatedIdentityCredential {
            revoked_at_ms: 0,
            ..Default::default()
        };
        ensure_delegated_credential_usable(&active).expect("active credential is reusable");

        let revoked = DelegatedIdentityCredential {
            revoked_at_ms: 42,
            ..Default::default()
        };
        let status = ensure_delegated_credential_usable(&revoked)
            .expect_err("revoked credential must stay revoked");

        assert_eq!(status.code(), Code::FailedPrecondition);
        assert!(status.message().contains("credential is revoked"));
    }

    #[test]
    fn delegated_access_token_subject_must_match_authenticated_caller() {
        ensure_delegated_token_subject_matches("user-a", "user-a")
            .expect("matching subject should be accepted");

        let status = ensure_delegated_token_subject_matches("user-b", "user-a")
            .expect_err("mismatched subject must be rejected");

        assert_eq!(status.code(), Code::PermissionDenied);
        assert!(status.message().contains("subject must match"));
    }

    #[test]
    fn delegated_credential_resource_version_is_enforced_when_requested() {
        let credential = DelegatedIdentityCredential {
            metadata: Some(ObjectMeta {
                id: "delegated-identity-test".to_string(),
                name: "delegated-identity-test".to_string(),
                resource_version: 7,
                workspace: String::new(),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                ..Default::default()
            }),
            ..Default::default()
        };

        ensure_expected_resource_version(&credential, 0)
            .expect("zero should use the current resource version");
        ensure_expected_resource_version(&credential, 7)
            .expect("matching resource version should pass");
        let status = ensure_expected_resource_version(&credential, 42)
            .expect_err("mismatched resource version should fail");
        assert_eq!(status.code(), Code::Aborted);
    }

    #[test]
    fn admin_credential_response_uses_non_secret_summary() {
        let credential = DelegatedIdentityCredential {
            issuer: "https://issuer.example.com".to_string(),
            client_id: "openshell-cli".to_string(),
            principal_subject: "user-1".to_string(),
            secret_material_handles: HashMap::from([
                (
                    super::REFRESH_TOKEN_MATERIAL_KEY.to_string(),
                    openshell_core::proto::CredentialHandle {
                        driver: "test-static".to_string(),
                        handle: "opaque-refresh-handle".to_string(),
                        ..Default::default()
                    },
                ),
                (
                    super::ACCESS_TOKEN_MATERIAL_KEY.to_string(),
                    openshell_core::proto::CredentialHandle {
                        driver: "test-static".to_string(),
                        handle: "opaque-access-handle".to_string(),
                        ..Default::default()
                    },
                ),
            ]),
            access_token_expires_at_ms: 123,
            scopes: "openid profile".to_string(),
            audience: "api://resource".to_string(),
            last_refresh_at_ms: 42,
            revoked_at_ms: 0,
            ..Default::default()
        };

        let summary = delegated_credential_summary(credential);

        assert!(summary.refresh_token_present);
        assert!(summary.access_token_present);
        assert_eq!(summary.issuer, "https://issuer.example.com");
        assert_eq!(summary.principal_subject, "user-1");
        assert_eq!(summary.access_token_expires_at_ms, 123);
    }

    #[test]
    fn delegated_credential_upsert_uses_existing_resource_version_for_cas() {
        let credential = DelegatedIdentityCredential {
            metadata: Some(ObjectMeta {
                id: "delegated-identity-test".to_string(),
                name: "delegated-identity-test".to_string(),
                resource_version: 7,
                workspace: String::new(),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert!(matches!(
            delegated_credential_upsert_condition(&credential),
            WriteCondition::MatchResourceVersion(7)
        ));
    }

    #[test]
    fn sandbox_status_reports_revoked_backing_credential() {
        let credential = DelegatedIdentityCredential {
            metadata: Some(ObjectMeta {
                id: "delegated-identity-test".to_string(),
                name: "delegated-identity-test".to_string(),
                resource_version: 7,
                workspace: String::new(),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                ..Default::default()
            }),
            revoked_at_ms: 42,
            ..Default::default()
        };

        let (revoked_at_ms, missing) = delegated_credential_status_fields(Some(&credential));
        assert_eq!(revoked_at_ms, 42);
        assert!(!missing);
        assert_eq!(delegated_credential_status_fields(None), (0, true));
    }

    #[tokio::test]
    async fn delegated_refresh_rejects_access_token_for_different_subject() {
        let server = wiremock::MockServer::start().await;
        mount_test_oidc_issuer(&server).await;
        let issuer = server.uri();
        let state = test_server_state_with_oidc(issuer.clone()).await;
        let original_access_token =
            mint_test_access_token(&issuer, "alice", current_time_secs() + 3600);
        let mismatched_access_token =
            mint_test_access_token(&issuer, "bob", current_time_secs() + 3600);
        let credential = DelegatedIdentityCredential {
            metadata: Some(ObjectMeta {
                id: "delegated-identity-refresh".to_string(),
                name: "delegated-identity-refresh".to_string(),
                workspace: String::new(),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                ..Default::default()
            }),
            issuer: issuer.clone(),
            client_id: TEST_AUDIENCE.to_string(),
            principal_subject: "alice".to_string(),
            access_token_expires_at_ms: current_time_ms() - 1,
            scopes: "openid profile".to_string(),
            ..Default::default()
        };
        let mut credential = credential;
        credential.secret_material_handles = super::store_staged_secret_material(
            &state,
            credential.object_id(),
            &HashMap::from([
                (
                    super::REFRESH_TOKEN_MATERIAL_KEY.to_string(),
                    "refresh-token".to_string(),
                ),
                (
                    super::ACCESS_TOKEN_MATERIAL_KEY.to_string(),
                    original_access_token.clone(),
                ),
            ]),
        )
        .await
        .unwrap();
        state.store.put_message(&credential).await.unwrap();
        let credential = state
            .store
            .get_message::<DelegatedIdentityCredential>("delegated-identity-refresh")
            .await
            .unwrap()
            .unwrap();
        mount_refresh_token_response(&server, &mismatched_access_token).await;

        let status = super::refresh_if_needed(&state, credential)
            .await
            .expect_err("mismatched refreshed subject must be rejected");

        assert_eq!(status.code(), Code::PermissionDenied);
        assert!(status.message().contains("subject must match"));
        let stored = state
            .store
            .get_message::<DelegatedIdentityCredential>("delegated-identity-refresh")
            .await
            .unwrap()
            .unwrap();
        let material = super::resolve_delegated_secret_material(&state, &stored)
            .await
            .unwrap();
        assert_eq!(material.access_token, original_access_token);
        assert_eq!(stored.principal_subject, "alice");
    }

    #[tokio::test]
    async fn delegated_refresh_rotates_driver_handles_and_deletes_superseded_material() {
        let server = wiremock::MockServer::start().await;
        mount_test_oidc_issuer(&server).await;
        let issuer = server.uri();
        let state = test_server_state_with_oidc(issuer.clone()).await;
        let original_access_token =
            mint_test_access_token(&issuer, "alice", current_time_secs() - 1);
        let refreshed_access_token =
            mint_test_access_token(&issuer, "alice", current_time_secs() + 3600);
        let mut credential = DelegatedIdentityCredential {
            metadata: Some(ObjectMeta {
                id: "delegated-identity-rotate".to_string(),
                name: "delegated-identity-rotate".to_string(),
                workspace: String::new(),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                ..Default::default()
            }),
            issuer: issuer.clone(),
            client_id: TEST_AUDIENCE.to_string(),
            principal_subject: "alice".to_string(),
            access_token_expires_at_ms: current_time_ms() - 1,
            scopes: "openid profile".to_string(),
            ..Default::default()
        };
        credential.secret_material_handles = super::store_staged_secret_material(
            &state,
            credential.object_id(),
            &HashMap::from([
                (
                    super::REFRESH_TOKEN_MATERIAL_KEY.to_string(),
                    "original-refresh-token".to_string(),
                ),
                (
                    super::ACCESS_TOKEN_MATERIAL_KEY.to_string(),
                    original_access_token,
                ),
            ]),
        )
        .await
        .unwrap();
        let original_handles = credential.secret_material_handles.clone();
        state.store.put_message(&credential).await.unwrap();
        let credential = state
            .store
            .get_message::<DelegatedIdentityCredential>(credential.object_id())
            .await
            .unwrap()
            .unwrap();
        mount_refresh_token_rotation_response(
            &server,
            &refreshed_access_token,
            "rotated-refresh-token",
        )
        .await;

        let resolved = super::refresh_if_needed(&state, credential)
            .await
            .expect("delegated credential should refresh");

        assert_eq!(resolved.access_token, refreshed_access_token);
        assert!(resolved.credential.pending_secret_deletions.is_empty());
        assert_ne!(
            resolved.credential.secret_material_handles,
            original_handles
        );
        assert_eq!(state.credentials.stored_credential_count(), Some(2));
        let material = super::resolve_delegated_secret_material(&state, &resolved.credential)
            .await
            .unwrap();
        assert_eq!(material.refresh_token, "rotated-refresh-token");
        assert_eq!(material.access_token, refreshed_access_token);
    }

    #[tokio::test]
    async fn delegated_refresh_lease_serializes_gateway_replicas() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let server = wiremock::MockServer::start().await;
        mount_test_oidc_issuer(&server).await;
        let issuer = server.uri();
        let state = test_server_state_with_oidc(issuer.clone()).await;
        let refreshed_access_token =
            mint_test_access_token(&issuer, "alice", current_time_secs() + 3600);
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": refreshed_access_token.clone(),
                "refresh_token": "rotated-refresh-token",
                "token_type": "Bearer",
                "expires_in": 3600,
            })))
            .expect(1)
            .mount(&server)
            .await;

        let mut credential = DelegatedIdentityCredential {
            metadata: Some(ObjectMeta {
                id: "delegated-identity-shared-refresh".to_string(),
                name: "delegated-identity-shared-refresh".to_string(),
                workspace: String::new(),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                ..Default::default()
            }),
            issuer,
            client_id: TEST_AUDIENCE.to_string(),
            principal_subject: "alice".to_string(),
            access_token_expires_at_ms: current_time_ms() - 1,
            scopes: "offline_access".to_string(),
            ..Default::default()
        };
        credential.secret_material_handles = super::store_staged_secret_material(
            &state,
            credential.object_id(),
            &HashMap::from([
                (
                    super::REFRESH_TOKEN_MATERIAL_KEY.to_string(),
                    "single-use-refresh-token".to_string(),
                ),
                (
                    super::ACCESS_TOKEN_MATERIAL_KEY.to_string(),
                    "expired-access-token".to_string(),
                ),
            ]),
        )
        .await
        .unwrap();
        state.store.put_message(&credential).await.unwrap();
        let credential = state
            .store
            .get_message::<DelegatedIdentityCredential>(credential.object_id())
            .await
            .unwrap()
            .unwrap();

        let second_compute = crate::compute::new_test_runtime(Arc::clone(&state.store)).await;
        let second_state = Arc::new(crate::ServerState::new_with_credentials(
            state.config.clone(),
            Arc::clone(&state.store),
            second_compute,
            SandboxIndex::new(),
            SandboxWatchBus::new(),
            TracingLogBus::new(),
            Arc::new(SupervisorSessionRegistry::new()),
            state.oidc_cache.clone(),
            state.credentials.clone(),
        ));
        let first_credential = credential.clone();
        let (first, second) = tokio::join!(
            super::refresh_if_needed(&state, first_credential),
            super::refresh_if_needed(&second_state, credential),
        );

        assert_eq!(first.unwrap().access_token, refreshed_access_token);
        assert_eq!(second.unwrap().access_token, refreshed_access_token);
        server.verify().await;
    }

    #[tokio::test]
    async fn delegated_refresh_recovers_an_expired_lease() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let server = wiremock::MockServer::start().await;
        mount_test_oidc_issuer(&server).await;
        let issuer = server.uri();
        let state = test_server_state_with_oidc(issuer.clone()).await;
        let refreshed_access_token =
            mint_test_access_token(&issuer, "alice", current_time_secs() + 3600);
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": refreshed_access_token.clone(),
                "refresh_token": "recovered-refresh-token",
                "token_type": "Bearer",
                "expires_in": 3600,
            })))
            .expect(1)
            .mount(&server)
            .await;

        let mut credential = DelegatedIdentityCredential {
            metadata: Some(ObjectMeta {
                id: "delegated-identity-expired-lease".to_string(),
                name: "delegated-identity-expired-lease".to_string(),
                workspace: String::new(),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                ..Default::default()
            }),
            issuer,
            client_id: TEST_AUDIENCE.to_string(),
            principal_subject: "alice".to_string(),
            access_token_expires_at_ms: current_time_ms() - 1,
            scopes: "openid offline_access".to_string(),
            refresh_lease: Some(DelegatedIdentityRefreshLease {
                owner_id: "crashed-gateway".to_string(),
                expires_at_ms: current_time_ms() - 1,
            }),
            ..Default::default()
        };
        credential.secret_material_handles = super::store_staged_secret_material(
            &state,
            credential.object_id(),
            &HashMap::from([
                (
                    super::REFRESH_TOKEN_MATERIAL_KEY.to_string(),
                    "stale-owner-refresh-token".to_string(),
                ),
                (
                    super::ACCESS_TOKEN_MATERIAL_KEY.to_string(),
                    "expired-access-token".to_string(),
                ),
            ]),
        )
        .await
        .unwrap();
        state.store.put_message(&credential).await.unwrap();
        let credential = state
            .store
            .get_message::<DelegatedIdentityCredential>(credential.object_id())
            .await
            .unwrap()
            .unwrap();

        let resolved = super::refresh_if_needed(&state, credential)
            .await
            .expect("expired lease should be recoverable");

        assert_eq!(resolved.access_token, refreshed_access_token);
        assert!(resolved.credential.refresh_lease.is_none());
        server.verify().await;
    }

    #[tokio::test]
    async fn revocation_during_refresh_prevents_credential_repopulation() {
        let server = wiremock::MockServer::start().await;
        mount_test_oidc_issuer(&server).await;
        let issuer = server.uri();
        let state = test_server_state_with_oidc(issuer.clone()).await;
        let refreshed_access_token =
            mint_test_access_token(&issuer, "alice", current_time_secs() + 3600);
        mount_refresh_token_rotation_response(
            &server,
            &refreshed_access_token,
            "rotated-refresh-token",
        )
        .await;
        let mut credential = DelegatedIdentityCredential {
            metadata: Some(ObjectMeta {
                id: "delegated-identity-revoke-during-refresh".to_string(),
                name: "delegated-identity-revoke-during-refresh".to_string(),
                workspace: String::new(),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                ..Default::default()
            }),
            issuer,
            client_id: TEST_AUDIENCE.to_string(),
            principal_subject: "alice".to_string(),
            access_token_expires_at_ms: current_time_ms() - 1,
            scopes: "offline_access".to_string(),
            ..Default::default()
        };
        credential.secret_material_handles = super::store_staged_secret_material(
            &state,
            credential.object_id(),
            &HashMap::from([
                (
                    super::REFRESH_TOKEN_MATERIAL_KEY.to_string(),
                    "single-use-refresh-token".to_string(),
                ),
                (
                    super::ACCESS_TOKEN_MATERIAL_KEY.to_string(),
                    "expired-access-token".to_string(),
                ),
            ]),
        )
        .await
        .unwrap();
        state.store.put_message(&credential).await.unwrap();
        let credential = state
            .store
            .get_message::<DelegatedIdentityCredential>(credential.object_id())
            .await
            .unwrap()
            .unwrap();
        let credential_id = credential.object_id().to_string();
        let (store_started, release_store) = state.credentials.gate_next_store();
        let task_state = Arc::clone(&state);
        let refresh =
            tokio::spawn(async move { super::refresh_if_needed(&task_state, credential).await });
        store_started
            .await
            .expect("replacement material staging should start");

        let current = state
            .store
            .get_message::<DelegatedIdentityCredential>(&credential_id)
            .await
            .unwrap()
            .unwrap();
        state
            .store
            .update_message_cas::<DelegatedIdentityCredential, _>(
                &credential_id,
                current.get_resource_version(),
                |credential| {
                    credential.revoked_at_ms = current_time_ms();
                    super::move_active_handles_to_pending(credential);
                },
            )
            .await
            .unwrap();
        release_store.send(()).expect("release replacement staging");

        let status = refresh
            .await
            .expect("refresh task should finish")
            .expect_err("revocation must win over an in-flight refresh");
        assert_eq!(status.code(), Code::FailedPrecondition);
        assert!(status.message().contains("revoked"));
        let stored = state
            .store
            .get_message::<DelegatedIdentityCredential>(&credential_id)
            .await
            .unwrap()
            .unwrap();
        assert!(stored.revoked_at_ms > 0);
        assert!(stored.secret_material_handles.is_empty());
        assert!(stored.refresh_lease.is_none());
    }

    #[tokio::test]
    async fn delegated_upsert_cas_failure_deletes_staged_driver_material() {
        let state = test_server_state().await;
        let user = test_user("alice");
        let issuer = "https://issuer.example.com";
        let client_id = "openshell-cli-cas";
        let credential_id = delegated_credential_id(issuer, "alice");
        let request = DelegatedIdentityAuthorizationGrant {
            issuer: issuer.to_string(),
            client_id: client_id.to_string(),
            refresh_token: "cas-refresh-secret".to_string(),
            access_token: "cas-access-secret".to_string(),
            scopes: "openid".to_string(),
            audience: TEST_AUDIENCE.to_string(),
        };
        let (store_started, release_store) = state.credentials.gate_next_store();
        let task_state = Arc::clone(&state);
        let task = tokio::spawn(async move {
            super::upsert_credential(&task_state, &user, request, current_time_ms() + 600_000).await
        });
        store_started.await.expect("staged storage should start");
        state
            .store
            .put_message(&DelegatedIdentityCredential {
                metadata: Some(ObjectMeta {
                    id: credential_id.clone(),
                    name: credential_id.clone(),
                    workspace: String::new(),
                    labels: HashMap::new(),
                    annotations: HashMap::new(),
                    ..Default::default()
                }),
                issuer: issuer.to_string(),
                client_id: client_id.to_string(),
                principal_subject: "alice".to_string(),
                ..Default::default()
            })
            .await
            .unwrap();
        release_store.send(()).expect("release staged storage");

        let status = task
            .await
            .expect("upsert task should finish")
            .expect_err("competing create should fail delegated credential CAS");

        assert_eq!(status.code(), Code::Internal);
        assert!(status.message().contains("persist delegated credential"));
        assert_eq!(state.credentials.stored_credential_count(), Some(0));
        assert!(!status.message().contains("cas-refresh-secret"));
        assert!(!status.message().contains("cas-access-secret"));
    }

    #[tokio::test]
    async fn delegated_upsert_cas_cleanup_failure_persists_retry_handles() {
        let state = test_server_state().await;
        let user = test_user("alice");
        let issuer = "https://issuer.example.com";
        let client_id = "openshell-cli-cas-retry";
        let credential_id = delegated_credential_id(issuer, "alice");
        let request = DelegatedIdentityAuthorizationGrant {
            issuer: issuer.to_string(),
            client_id: client_id.to_string(),
            refresh_token: "cas-retry-refresh-secret".to_string(),
            access_token: "cas-retry-access-secret".to_string(),
            scopes: "openid".to_string(),
            audience: TEST_AUDIENCE.to_string(),
        };
        let (store_started, release_store) = state.credentials.gate_next_store();
        let task_state = Arc::clone(&state);
        let task = tokio::spawn(async move {
            super::upsert_credential(&task_state, &user, request, current_time_ms() + 600_000).await
        });
        store_started.await.expect("staged storage should start");
        state
            .store
            .put_message(&DelegatedIdentityCredential {
                metadata: Some(ObjectMeta {
                    id: credential_id.clone(),
                    name: credential_id.clone(),
                    workspace: String::new(),
                    labels: HashMap::new(),
                    annotations: HashMap::new(),
                    ..Default::default()
                }),
                issuer: issuer.to_string(),
                client_id: client_id.to_string(),
                principal_subject: "alice".to_string(),
                ..Default::default()
            })
            .await
            .unwrap();
        state.credentials.fail_next_delete();
        release_store.send(()).expect("release staged storage");
        task.await
            .expect("upsert task should finish")
            .expect_err("competing create should fail delegated credential CAS");

        let stored = state
            .store
            .get_message::<DelegatedIdentityCredential>(&credential_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.pending_secret_deletions.len(), 2);
        assert_eq!(state.credentials.stored_credential_count(), Some(1));

        super::run_credential_cleanup_tick(&state).await.unwrap();
        let stored = state
            .store
            .get_message::<DelegatedIdentityCredential>(&credential_id)
            .await
            .unwrap()
            .unwrap();
        assert!(stored.pending_secret_deletions.is_empty());
        assert_eq!(state.credentials.stored_credential_count(), Some(0));
    }

    #[tokio::test]
    async fn delegated_reauthorization_retains_failed_superseded_cleanup_for_retry() {
        let state = test_server_state().await;
        let user = test_user("alice");
        let request =
            |refresh_token: &str, access_token: &str| DelegatedIdentityAuthorizationGrant {
                issuer: "https://issuer.example.com".to_string(),
                client_id: "openshell-cli-reauthorize".to_string(),
                refresh_token: refresh_token.to_string(),
                access_token: access_token.to_string(),
                scopes: "openid".to_string(),
                audience: TEST_AUDIENCE.to_string(),
            };
        let original = super::upsert_credential(
            &state,
            &user,
            request("old-refresh", "old-access"),
            current_time_ms() + 600_000,
        )
        .await
        .unwrap();
        let original_handles = original.secret_material_handles;
        state.credentials.fail_next_delete();

        let replacement = super::upsert_credential(
            &state,
            &user,
            request("new-refresh", "new-access"),
            current_time_ms() + 600_000,
        )
        .await
        .expect("replacement should commit before cleanup");

        assert_eq!(replacement.pending_secret_deletions.len(), 2);
        assert_ne!(replacement.secret_material_handles, original_handles);
        let material = super::resolve_delegated_secret_material(&state, &replacement)
            .await
            .unwrap();
        assert_eq!(material.refresh_token, "new-refresh");
        assert_eq!(material.access_token, "new-access");

        super::run_credential_cleanup_tick(&state).await.unwrap();
        let stored = state
            .store
            .get_message::<DelegatedIdentityCredential>(replacement.object_id())
            .await
            .unwrap()
            .unwrap();
        assert!(stored.pending_secret_deletions.is_empty());
        assert_eq!(state.credentials.stored_credential_count(), Some(2));
    }

    #[tokio::test]
    async fn separate_reauthorization_reactivates_a_revoked_user_credential() {
        let state = test_server_state().await;
        let user = test_user("alice");
        let grant = |refresh_token: &str, access_token: &str| DelegatedIdentityAuthorizationGrant {
            issuer: "https://issuer.example.com".to_string(),
            client_id: "openshell-cli".to_string(),
            refresh_token: refresh_token.to_string(),
            access_token: access_token.to_string(),
            scopes: "offline_access".to_string(),
            audience: TEST_AUDIENCE.to_string(),
        };
        let original = super::upsert_credential(
            &state,
            &user,
            grant("old-refresh", "old-access"),
            current_time_ms() + 600_000,
        )
        .await
        .unwrap();
        super::handle_revoke_credential(
            &state,
            authed_request(RevokeDelegatedIdentityCredentialRequest {
                id: original.object_id().to_string(),
                expected_resource_version: original.get_resource_version(),
            }),
        )
        .await
        .expect("credential revocation should succeed");

        let replacement = super::upsert_credential(
            &state,
            &user,
            grant("new-refresh", "new-access"),
            current_time_ms() + 600_000,
        )
        .await
        .expect("a separate grant should replace a revoked credential");

        assert_eq!(replacement.revoked_at_ms, 0);
        let material = super::resolve_delegated_secret_material(&state, &replacement)
            .await
            .unwrap();
        assert_eq!(material.refresh_token, "new-refresh");
        assert_eq!(material.access_token, "new-access");
    }

    #[tokio::test]
    async fn revoke_disables_resolution_while_failed_cleanup_remains_retryable() {
        let state = test_server_state().await;
        put_test_sandbox(&state, "delegated-revoke").await;
        let credential =
            put_test_credential_for_subject(&state, "delegated-identity-revoke", "dev-user").await;
        put_test_delegation(
            &state,
            "sandbox-delegated-revoke",
            credential.object_id(),
            "dev-user",
        )
        .await;
        state.credentials.fail_next_delete();

        let response = super::handle_revoke_credential(
            &state,
            authed_request(RevokeDelegatedIdentityCredentialRequest {
                id: credential.object_id().to_string(),
                expected_resource_version: credential.get_resource_version(),
            }),
        )
        .await
        .expect("revocation should succeed even when cleanup is deferred")
        .into_inner();

        assert!(response.revoked);
        let stored = state
            .store
            .get_message::<DelegatedIdentityCredential>(credential.object_id())
            .await
            .unwrap()
            .unwrap();
        assert!(stored.revoked_at_ms > 0);
        assert!(stored.secret_material_handles.is_empty());
        assert_eq!(stored.pending_secret_deletions.len(), 2);
        let sandbox = state
            .store
            .get_message::<Sandbox>("sandbox-delegated-revoke")
            .await
            .unwrap()
            .unwrap();
        let status = super::resolve_subject_access_token(&state, &sandbox)
            .await
            .expect_err("revoked credential must remain unusable");
        assert_eq!(status.code(), Code::FailedPrecondition);
        assert!(status.message().contains("revoked"));

        super::run_credential_cleanup_tick(&state)
            .await
            .expect("cleanup retry should run");
        let stored = state
            .store
            .get_message::<DelegatedIdentityCredential>(credential.object_id())
            .await
            .unwrap()
            .unwrap();
        assert!(stored.pending_secret_deletions.is_empty());
        assert_eq!(state.credentials.stored_credential_count(), Some(0));
    }

    #[tokio::test]
    async fn delete_unreferenced_credential_removes_generic_and_driver_records() {
        let state = test_server_state().await;
        let credential = put_test_credential(&state, "delegated-identity-delete").await;
        assert_eq!(state.credentials.stored_credential_count(), Some(2));

        let response = super::handle_delete_credential(
            &state,
            authed_request(DeleteDelegatedIdentityCredentialRequest {
                id: credential.object_id().to_string(),
                expected_resource_version: credential.get_resource_version(),
            }),
        )
        .await
        .expect("unreferenced credential should delete")
        .into_inner();

        assert!(response.deleted);
        assert!(
            state
                .store
                .get_message::<DelegatedIdentityCredential>(credential.object_id())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(state.credentials.stored_credential_count(), Some(0));
    }

    #[tokio::test]
    async fn delete_credential_waits_for_sandbox_sync_guard() {
        let state = test_server_state().await;
        let credential = put_test_credential(&state, "delegated-identity-delete-guard").await;
        let guard = state.compute.sandbox_sync_guard().await;
        let task_state = state.clone();
        let credential_id = credential.object_id().to_string();
        let expected_resource_version = credential.get_resource_version();
        let task = tokio::spawn(async move {
            super::handle_delete_credential(
                &task_state,
                authed_request(DeleteDelegatedIdentityCredentialRequest {
                    id: credential_id,
                    expected_resource_version,
                }),
            )
            .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(
            !task.is_finished(),
            "credential deletion should wait for sandbox sync guard"
        );
        drop(guard);

        let response = tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("delete should finish after guard release")
            .expect("join delete task")
            .expect("delete should succeed")
            .into_inner();
        assert!(response.deleted);
    }

    #[tokio::test]
    async fn delete_cleanup_failure_leaves_tombstone_for_retry() {
        let state = test_server_state().await;
        let credential = put_test_credential(&state, "delegated-identity-delete-retry").await;
        state.credentials.fail_next_delete();

        let status = super::handle_delete_credential(
            &state,
            authed_request(DeleteDelegatedIdentityCredentialRequest {
                id: credential.object_id().to_string(),
                expected_resource_version: credential.get_resource_version(),
            }),
        )
        .await
        .expect_err("cleanup failure should defer final deletion");

        assert!(status.message().contains("disabled"));
        let tombstone = state
            .store
            .get_message::<DelegatedIdentityCredential>(credential.object_id())
            .await
            .unwrap()
            .unwrap();
        assert!(tombstone.revoked_at_ms > 0);
        assert!(
            tombstone
                .metadata
                .as_ref()
                .is_some_and(|metadata| metadata.deletion_timestamp_ms > 0)
        );
        assert!(tombstone.secret_material_handles.is_empty());
        assert_eq!(tombstone.pending_secret_deletions.len(), 2);

        let response = super::handle_delete_credential(
            &state,
            authed_request(DeleteDelegatedIdentityCredentialRequest {
                id: credential.object_id().to_string(),
                // A retry can use the pre-tombstone version because the record
                // is already disabled and no longer admits state changes.
                expected_resource_version: credential.get_resource_version(),
            }),
        )
        .await
        .expect("deletion retry should clean material and remove the tombstone")
        .into_inner();
        assert!(response.deleted);
        assert_eq!(state.credentials.stored_credential_count(), Some(0));
    }

    #[tokio::test]
    async fn delete_rejects_active_sandbox_delegation_reference() {
        let state = test_server_state().await;
        let credential =
            put_test_credential_for_subject(&state, "delegated-identity-referenced", "dev-user")
                .await;
        put_test_delegation(
            &state,
            "sandbox-referenced",
            credential.object_id(),
            "dev-user",
        )
        .await;

        let status = super::handle_delete_credential(
            &state,
            authed_request(DeleteDelegatedIdentityCredentialRequest {
                id: credential.object_id().to_string(),
                expected_resource_version: credential.get_resource_version(),
            }),
        )
        .await
        .expect_err("active sandbox reference must prevent credential deletion");

        assert_eq!(status.code(), Code::FailedPrecondition);
        assert!(status.message().contains("active sandbox delegation"));
        assert_eq!(state.credentials.stored_credential_count(), Some(2));
    }

    #[tokio::test]
    async fn delegated_request_expiry_is_derived_from_validated_access_token() {
        let server = wiremock::MockServer::start().await;
        mount_test_oidc_issuer(&server).await;
        let issuer = server.uri();
        let state = test_server_state_with_oidc(issuer.clone()).await;
        let exp_secs = current_time_secs() + 1800;
        let user = crate::auth::principal::UserPrincipal {
            identity: crate::auth::identity::Identity {
                subject: "alice".to_string(),
                display_name: None,
                roles: vec!["openshell-user".to_string()],
                scopes: vec![],
                provider: crate::auth::identity::IdentityProvider::Oidc,
            },
        };
        let refresh_token = "recognizable-delegated-refresh-token".to_string();
        let access_token = mint_test_access_token(&issuer, "alice", exp_secs);
        let request = DelegatedIdentityAuthorizationGrant {
            issuer: issuer.clone(),
            client_id: TEST_AUDIENCE.to_string(),
            refresh_token: refresh_token.clone(),
            access_token: access_token.clone(),
            scopes: "openid profile".to_string(),
            audience: TEST_AUDIENCE.to_string(),
        };

        let expires_at_ms = super::validate_authorization_grant(&state, &user, &request)
            .await
            .expect("delegation request should validate");
        let upserted = super::upsert_credential(&state, &user, request, expires_at_ms)
            .await
            .expect("credential should persist");

        assert_eq!(expires_at_ms, exp_secs.saturating_mul(1000));
        assert_eq!(
            upserted.access_token_expires_at_ms,
            exp_secs.saturating_mul(1000)
        );
        assert_eq!(upserted.secret_material_handles.len(), 2);
        let record = state
            .store
            .get(
                DelegatedIdentityCredential::object_type(),
                upserted.object_id(),
            )
            .await
            .unwrap()
            .unwrap();
        assert!(
            !record
                .payload
                .windows(refresh_token.len())
                .any(|window| window == refresh_token.as_bytes()),
            "generic delegated credential payload must not contain the refresh token"
        );
        assert!(
            !record
                .payload
                .windows(access_token.len())
                .any(|window| window == access_token.as_bytes()),
            "generic delegated credential payload must not contain the access token"
        );
        let resolved = super::resolve_delegated_secret_material(&state, &upserted)
            .await
            .expect("credential handles should resolve through the active driver");
        assert_eq!(resolved.refresh_token, refresh_token);
        assert_eq!(resolved.access_token, access_token);
        let debug = format!("{upserted:?}");
        assert!(!debug.contains(&resolved.refresh_token));
        assert!(!debug.contains(&resolved.access_token));
    }

    #[tokio::test]
    async fn user_authorizes_and_reuses_a_separate_delegated_grant() {
        let server = wiremock::MockServer::start().await;
        mount_test_oidc_issuer(&server).await;
        let issuer = server.uri();
        let state = test_server_state_with_oidc(issuer.clone()).await;
        let access_token = mint_test_access_token(&issuer, "dev-user", current_time_secs() + 3600);

        let missing = super::handle_authorization_status(
            &state,
            authed_request(GetDelegatedIdentityAuthorizationStatusRequest {}),
        )
        .await
        .expect("missing grant status should succeed")
        .into_inner();
        assert!(!missing.usable);
        assert!(missing.reauthorization_required);
        assert!(missing.reason.contains("missing"));

        let response = super::handle_authorize(
            &state,
            authed_request(AuthorizeDelegatedIdentityRequest {
                grant: Some(DelegatedIdentityAuthorizationGrant {
                    issuer,
                    client_id: TEST_AUDIENCE.to_string(),
                    refresh_token: "delegated-refresh-token".to_string(),
                    access_token,
                    scopes: "offline_access".to_string(),
                    audience: TEST_AUDIENCE.to_string(),
                }),
            }),
        )
        .await
        .expect("separate delegated grant should be accepted")
        .into_inner();

        let credential = response.credential.expect("credential summary");
        assert_eq!(credential.principal_subject, "dev-user");
        assert_eq!(credential.scopes, "offline_access");
        let status = super::handle_authorization_status(
            &state,
            authed_request(GetDelegatedIdentityAuthorizationStatusRequest {}),
        )
        .await
        .expect("healthy grant status should succeed")
        .into_inner();
        assert!(status.usable);
        assert!(!status.reauthorization_required);
        let summary = status.credential.expect("healthy credential summary");
        assert_eq!(summary.principal_subject, "dev-user");

        let credential_id = summary.metadata.expect("credential metadata").id;
        let current = state
            .store
            .get_message::<DelegatedIdentityCredential>(&credential_id)
            .await
            .unwrap()
            .unwrap();
        state
            .store
            .update_message_cas::<DelegatedIdentityCredential, _>(
                &credential_id,
                current.get_resource_version(),
                |credential| {
                    credential.revoked_at_ms = current_time_ms();
                    super::move_active_handles_to_pending(credential);
                },
            )
            .await
            .unwrap();
        let revoked = super::handle_authorization_status(
            &state,
            authed_request(GetDelegatedIdentityAuthorizationStatusRequest {}),
        )
        .await
        .expect("revoked grant status should succeed")
        .into_inner();
        assert!(!revoked.usable);
        assert!(revoked.reauthorization_required);
        assert!(revoked.reason.contains("revoked"));
    }

    #[tokio::test]
    async fn delegated_grant_subject_must_match_rpc_caller() {
        let server = wiremock::MockServer::start().await;
        mount_test_oidc_issuer(&server).await;
        let issuer = server.uri();
        let state = test_server_state_with_oidc(issuer.clone()).await;

        let status = super::handle_authorize(
            &state,
            authed_request(AuthorizeDelegatedIdentityRequest {
                grant: Some(DelegatedIdentityAuthorizationGrant {
                    issuer: issuer.clone(),
                    client_id: TEST_AUDIENCE.to_string(),
                    refresh_token: "delegated-refresh-token".to_string(),
                    access_token: mint_test_access_token(
                        &issuer,
                        "different-user",
                        current_time_secs() + 3600,
                    ),
                    scopes: "offline_access".to_string(),
                    audience: TEST_AUDIENCE.to_string(),
                }),
            }),
        )
        .await
        .expect_err("a user must not transfer another subject's grant");

        assert_eq!(status.code(), Code::PermissionDenied);
        assert!(status.message().contains("subject must match"));
    }

    #[tokio::test]
    async fn inactive_delegated_refresh_requests_separate_reauthorization() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let server = wiremock::MockServer::start().await;
        mount_test_oidc_issuer(&server).await;
        let issuer = server.uri();
        let state = test_server_state_with_oidc(issuer.clone()).await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "Session not active"
            })))
            .expect(1)
            .mount(&server)
            .await;
        super::upsert_credential(
            &state,
            &test_user("dev-user"),
            DelegatedIdentityAuthorizationGrant {
                issuer,
                client_id: TEST_AUDIENCE.to_string(),
                refresh_token: "inactive-refresh-token".to_string(),
                access_token: "expired-access-token".to_string(),
                scopes: "openid offline_access".to_string(),
                audience: TEST_AUDIENCE.to_string(),
            },
            current_time_ms() - 1,
        )
        .await
        .expect("store an expired delegated grant");

        let status = super::handle_authorization_status(
            &state,
            authed_request(GetDelegatedIdentityAuthorizationStatusRequest {}),
        )
        .await
        .expect("inactive refresh should become a status result")
        .into_inner();

        assert!(!status.usable);
        assert!(status.reauthorization_required);
        assert!(status.reason.contains("no longer active"));
        server.verify().await;
    }

    #[tokio::test]
    async fn extend_failure_preserves_pre_authorized_credential() {
        let server = wiremock::MockServer::start().await;
        mount_test_oidc_issuer(&server).await;
        let issuer = server.uri();
        let state = test_server_state_with_oidc(issuer.clone()).await;
        put_test_sandbox(&state, "delegated").await;
        let current_credential_id = delegated_credential_id(&issuer, "dev-user");
        let existing_credential =
            put_test_credential_for_subject(&state, &current_credential_id, "dev-user").await;
        let sandbox_id = "sandbox-delegated";
        let record_id = sandbox_delegated_identity_record_id(sandbox_id);
        let malformed_record = SandboxDelegatedIdentityRecord {
            metadata: Some(ObjectMeta {
                id: String::new(),
                name: record_id.clone(),
                workspace: "default".to_string(),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                ..Default::default()
            }),
            sandbox_id: sandbox_id.to_string(),
            delegated_identity: Some(SandboxDelegatedIdentity {
                credential_id: existing_credential.object_id().to_string(),
                principal_subject: "dev-user".to_string(),
                delegated_until_ms: current_time_ms() + 600_000,
                withdrawn_at_ms: 0,
            }),
        };
        state
            .store
            .put_scoped(
                SandboxDelegatedIdentityRecord::object_type(),
                &record_id,
                &record_id,
                "default",
                sandbox_id,
                &malformed_record.encode_to_vec(),
                None,
            )
            .await
            .expect("store malformed record under valid lookup key");

        let request = authed_request(ExtendSandboxDelegatedIdentityRequest {
            name: "delegated".to_string(),
            workspace: "default".to_string(),
            delegated_identity: Some(DelegatedIdentityRequest {
                delegated_until_ms: current_time_ms() + 600_000,
            }),
        });

        let status = super::handle_extend(&state, request)
            .await
            .expect_err("record update failure should fail extend");

        assert!(
            status.message().contains("extend delegated identity"),
            "unexpected error: {status:?}"
        );
        assert!(
            state
                .store
                .get_message::<DelegatedIdentityCredential>(existing_credential.object_id())
                .await
                .unwrap()
                .is_some(),
            "pre-authorized credential should not be coupled to extend rollback"
        );
    }

    #[tokio::test]
    async fn extend_waits_for_sandbox_sync_guard() {
        let state = test_server_state().await;
        put_test_sandbox(&state, "delegated-extend-guard").await;
        put_test_delegation(
            &state,
            "sandbox-delegated-extend-guard",
            "delegated-identity-extend-guard",
            "dev-user",
        )
        .await;
        let guard = state.compute.sandbox_sync_guard().await;
        let task_state = state.clone();
        let task = tokio::spawn(async move {
            super::handle_extend(
                &task_state,
                authed_request(ExtendSandboxDelegatedIdentityRequest {
                    name: "delegated-extend-guard".to_string(),
                    workspace: "default".to_string(),
                    delegated_identity: Some(DelegatedIdentityRequest {
                        delegated_until_ms: current_time_ms() + 600_000,
                    }),
                }),
            )
            .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(
            !task.is_finished(),
            "delegation extension should wait for sandbox sync guard"
        );
        drop(guard);

        let status = tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("extend should finish after guard release")
            .expect("join extend task")
            .expect_err("extend without configured OIDC should fail after acquiring the guard");
        assert!(status.message().contains("OIDC"));
    }

    #[tokio::test]
    async fn sandbox_delegated_identity_status_reports_disabled_for_regular_sandbox() {
        let state = test_server_state().await;
        put_test_sandbox(&state, "regular").await;

        let response = super::handle_status(
            &state,
            authed_request(GetSandboxDelegatedIdentityStatusRequest {
                name: "regular".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .expect("regular sandbox status should report disabled")
        .into_inner();

        assert!(response.delegated_identity.is_none());
        assert!(response.credential_missing);
        assert_eq!(response.credential_revoked_at_ms, 0);
        assert!(response.now_ms > 0);
    }

    #[tokio::test]
    async fn sandbox_delegated_identity_status_rejects_non_delegating_user() {
        let state = test_server_state().await;
        put_test_sandbox(&state, "delegated").await;
        let credential = put_test_credential(&state, "delegated-identity-status").await;
        state
            .store
            .put_scoped_message(
                &SandboxDelegatedIdentityRecord {
                    metadata: Some(ObjectMeta {
                        id: "sandbox-delegated-identity-sandbox-delegated".to_string(),
                        name: "sandbox-delegated-identity-sandbox-delegated".to_string(),
                        workspace: "default".to_string(),
                        labels: HashMap::new(),
                        annotations: HashMap::new(),
                        ..Default::default()
                    }),
                    sandbox_id: "sandbox-delegated".to_string(),
                    delegated_identity: Some(SandboxDelegatedIdentity {
                        credential_id: credential.object_id().to_string(),
                        principal_subject: "alice".to_string(),
                        delegated_until_ms: 2_000_000,
                        withdrawn_at_ms: 0,
                    }),
                },
                "sandbox-delegated",
            )
            .await
            .unwrap();

        let mut request = Request::new(GetSandboxDelegatedIdentityStatusRequest {
            name: "delegated".to_string(),
            workspace: "default".to_string(),
        });
        request
            .extensions_mut()
            .insert(crate::auth::principal::Principal::User(
                crate::auth::principal::UserPrincipal {
                    identity: crate::auth::identity::Identity {
                        subject: "bob".to_string(),
                        display_name: None,
                        roles: vec!["openshell-user".to_string()],
                        scopes: vec![],
                        provider: crate::auth::identity::IdentityProvider::Oidc,
                    },
                },
            ));

        let status = super::handle_status(&state, request)
            .await
            .expect_err("non-delegating user should be rejected");

        assert_eq!(status.code(), Code::PermissionDenied);
        assert!(status.message().contains("delegating principal"));
    }

    async fn put_test_credential(
        state: &Arc<crate::ServerState>,
        id: &str,
    ) -> DelegatedIdentityCredential {
        put_test_credential_for_subject(state, id, "user-1").await
    }

    async fn put_test_credential_for_subject(
        state: &Arc<crate::ServerState>,
        id: &str,
        subject: &str,
    ) -> DelegatedIdentityCredential {
        let credential = DelegatedIdentityCredential {
            metadata: Some(ObjectMeta {
                id: id.to_string(),
                name: id.to_string(),
                workspace: String::new(),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                ..Default::default()
            }),
            issuer: "https://issuer.example.com".to_string(),
            client_id: "openshell-cli".to_string(),
            principal_subject: subject.to_string(),
            ..Default::default()
        };
        let mut credential = credential;
        credential.secret_material_handles = super::store_staged_secret_material(
            state,
            id,
            &HashMap::from([
                (
                    super::REFRESH_TOKEN_MATERIAL_KEY.to_string(),
                    "refresh".to_string(),
                ),
                (
                    super::ACCESS_TOKEN_MATERIAL_KEY.to_string(),
                    "access".to_string(),
                ),
            ]),
        )
        .await
        .unwrap();
        state.store.put_message(&credential).await.unwrap();
        state
            .store
            .get_message::<DelegatedIdentityCredential>(id)
            .await
            .unwrap()
            .unwrap()
    }

    async fn put_test_sandbox(state: &Arc<crate::ServerState>, name: &str) {
        state
            .store
            .put_message(&Sandbox {
                metadata: Some(ObjectMeta {
                    id: format!("sandbox-{name}"),
                    name: name.to_string(),
                    workspace: "default".to_string(),
                    labels: HashMap::new(),
                    annotations: HashMap::new(),
                    ..Default::default()
                }),
                spec: Some(SandboxSpec::default()),
                status: Some(SandboxStatus::default()),
                created_from_workload_template: None,
            })
            .await
            .unwrap();
    }

    async fn put_test_delegation(
        state: &Arc<crate::ServerState>,
        sandbox_id: &str,
        credential_id: &str,
        subject: &str,
    ) {
        let record_id = sandbox_delegated_identity_record_id(sandbox_id);
        state
            .store
            .put_scoped_message(
                &SandboxDelegatedIdentityRecord {
                    metadata: Some(ObjectMeta {
                        id: record_id.clone(),
                        name: record_id,
                        workspace: "default".to_string(),
                        labels: HashMap::new(),
                        annotations: HashMap::new(),
                        ..Default::default()
                    }),
                    sandbox_id: sandbox_id.to_string(),
                    delegated_identity: Some(SandboxDelegatedIdentity {
                        credential_id: credential_id.to_string(),
                        principal_subject: subject.to_string(),
                        delegated_until_ms: current_time_ms() + 600_000,
                        withdrawn_at_ms: 0,
                    }),
                },
                sandbox_id,
            )
            .await
            .unwrap();
    }

    fn test_user(subject: &str) -> crate::auth::principal::UserPrincipal {
        crate::auth::principal::UserPrincipal {
            identity: crate::auth::identity::Identity {
                subject: subject.to_string(),
                display_name: None,
                roles: vec!["openshell-user".to_string()],
                scopes: vec![],
                provider: crate::auth::identity::IdentityProvider::Oidc,
            },
        }
    }

    async fn test_server_state_with_oidc(issuer: String) -> Arc<crate::ServerState> {
        let store = Arc::new(
            Store::connect("sqlite::memory:?cache=shared")
                .await
                .unwrap(),
        );
        crate::ensure_default_workspace(&store).await.unwrap();
        let compute = crate::compute::new_test_runtime(store.clone()).await;
        let oidc = OidcConfig {
            issuer,
            audience: TEST_AUDIENCE.to_string(),
            jwks_ttl_secs: 3600,
            roles_claim: "realm_access.roles".to_string(),
            admin_role: "openshell-admin".to_string(),
            user_role: "openshell-user".to_string(),
            scopes_claim: "scope".to_string(),
        };
        let oidc_cache = Arc::new(
            crate::auth::oidc::JwksCache::new(&oidc)
                .await
                .expect("OIDC cache should build from mock issuer"),
        );
        Arc::new(crate::ServerState::new(
            Config::new(None)
                .with_database_url("sqlite::memory:?cache=shared")
                .with_credential_drivers(["test-static"])
                .with_oidc(oidc),
            store,
            compute,
            SandboxIndex::new(),
            SandboxWatchBus::new(),
            TracingLogBus::new(),
            Arc::new(SupervisorSessionRegistry::new()),
            Some(oidc_cache),
        ))
    }

    async fn mount_test_oidc_issuer(server: &wiremock::MockServer) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let issuer = server.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": issuer,
                "jwks_uri": format!("{issuer}/jwks"),
                "token_endpoint": format!("{issuer}/token"),
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [{
                    "kid": TEST_KID,
                    "kty": "RSA",
                    "n": TEST_RSA_KEY.modulus_b64,
                    "e": TEST_RSA_KEY.exponent_b64,
                }],
            })))
            .mount(server)
            .await;
    }

    async fn mount_refresh_token_response(server: &wiremock::MockServer, access_token: &str) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": 3600,
            })))
            .mount(server)
            .await;
    }

    async fn mount_refresh_token_rotation_response(
        server: &wiremock::MockServer,
        access_token: &str,
        refresh_token: &str,
    ) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "Bearer",
                "expires_in": 3600,
            })))
            .mount(server)
            .await;
    }

    fn mint_test_access_token(issuer: &str, subject: &str, exp: i64) -> String {
        crate::install_jsonwebtoken_crypto_provider();

        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(TEST_KID.to_string());
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(TEST_RSA_KEY.private_pem.as_bytes())
            .expect("load RSA signing key");
        jsonwebtoken::encode(
            &header,
            &serde_json::json!({
                "sub": subject,
                "preferred_username": subject,
                "iss": issuer,
                "aud": TEST_AUDIENCE,
                "exp": exp,
                "scope": "openid profile sandbox:write",
                "realm_access": { "roles": ["openshell-user"] },
            }),
            &key,
        )
        .expect("sign RS256 token")
    }

    fn current_time_secs() -> i64 {
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock is after the unix epoch")
                .as_secs(),
        )
        .expect("current time fits in i64")
    }
}
