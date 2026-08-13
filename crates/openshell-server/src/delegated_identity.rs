// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway-scoped delegated OIDC identity credentials for sandbox token exchange.

use crate::ServerState;
use crate::auth::principal::{Principal, UserPrincipal};
use crate::auth::workspace_authz::{MinWorkspaceRole, authorize_workspace, require_platform_admin};
use crate::persistence::{ObjectType, WriteCondition, current_time_ms};
use openshell_core::proto::datamodel::v1::ObjectMeta;
use openshell_core::proto::{
    DelegatedIdentityCredential, DelegatedIdentityCredentialSummary, DelegatedIdentityRequest,
    DeleteDelegatedIdentityCredentialRequest, DeleteDelegatedIdentityCredentialResponse,
    ExtendSandboxDelegatedIdentityRequest, ExtendSandboxDelegatedIdentityResponse,
    GetDelegatedIdentityCredentialStatusRequest, GetDelegatedIdentityCredentialStatusResponse,
    GetSandboxDelegatedIdentityStatusRequest, GetSandboxDelegatedIdentityStatusResponse,
    ListDelegatedIdentityCredentialsRequest, ListDelegatedIdentityCredentialsResponse,
    RevokeDelegatedIdentityCredentialRequest, RevokeDelegatedIdentityCredentialResponse, Sandbox,
    SandboxDelegatedIdentity, SandboxDelegatedIdentityRecord,
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
const REFRESH_SKEW_MS: i64 = 60_000;
static DELEGATED_IDENTITY_HTTP_CLIENT: LazyLock<Result<reqwest::Client, String>> =
    LazyLock::new(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(30))
            .build()
            .map_err(|err| format!("delegated identity HTTP client configuration failed: {err}"))
    });

pub struct PreparedSandboxDelegatedIdentity {
    pub record: SandboxDelegatedIdentityRecord,
    credential_id: String,
    credential_resource_version: u64,
    credential_created: bool,
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
    let access_token_expires_at_ms = validate_delegation_request(state, user, &request).await?;
    let credential =
        upsert_credential(state, user, request.clone(), access_token_expires_at_ms).await?;
    let credential_id = credential.credential.object_id().to_string();
    let credential_resource_version = credential.credential.get_resource_version();
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
                credential_id: credential_id.clone(),
                principal_subject: user.identity.subject.clone(),
                delegated_until_ms: request.delegated_until_ms,
                withdrawn_at_ms: 0,
            }),
        },
        credential_id,
        credential_resource_version,
        credential_created: credential.created,
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

pub async fn delete_new_prepared_sandbox_credential(
    state: &Arc<ServerState>,
    prepared: Option<&PreparedSandboxDelegatedIdentity>,
) -> Result<(), Status> {
    let Some(prepared) = prepared.filter(|prepared| prepared.credential_created) else {
        return Ok(());
    };
    state
        .store
        .delete_if(
            DelegatedIdentityCredential::object_type(),
            &prepared.credential_id,
            prepared.credential_resource_version,
        )
        .await
        .map(|_| ())
        .map_err(|e| Status::internal(format!("delete prepared delegated credential failed: {e}")))
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
    if credential.revoked_at_ms > 0 {
        return Err(Status::failed_precondition("delegated credential revoked"));
    }
    let credential = refresh_if_needed(state, credential).await?;
    let credential_id = credential.object_id().to_string();
    Ok((
        credential.access_token,
        credential.access_token_expires_at_ms,
        credential_id,
    ))
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
    let material = req
        .delegated_identity
        .ok_or_else(|| Status::invalid_argument("delegated_identity is required"))?;
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
    let user = require_user(&principal)?;
    let access_token_expires_at_ms = validate_delegation_request(state, user, &material).await?;
    let credential =
        upsert_credential(state, user, material.clone(), access_token_expires_at_ms).await?;
    let update_result = state
        .store
        .update_message_cas::<SandboxDelegatedIdentityRecord, _>(record.object_id(), 0, |current| {
            if let Some(delegation) = current.delegated_identity.as_mut() {
                delegation.credential_id = credential.credential.object_id().to_string();
                delegation.delegated_until_ms = material.delegated_until_ms;
                delegation.withdrawn_at_ms = 0;
            }
        })
        .await;
    if let Err(error) = update_result {
        cleanup_new_credential_after_prepare_failure(state, &credential).await?;
        return Err(crate::grpc::persistence_error_to_status(
            error,
            "extend delegated identity",
        ));
    }
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
        refresh_token_present: !credential.refresh_token.is_empty(),
        access_token_present: !credential.access_token.is_empty(),
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
            },
        )
        .await
        .map_err(|e| crate::grpc::persistence_error_to_status(e, "revoke delegated credential"))?;
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
    let expected_resource_version =
        delete_credential_resource_version(state, &req.id, req.expected_resource_version).await?;
    let Some(expected_resource_version) = expected_resource_version else {
        return Ok(Response::new(DeleteDelegatedIdentityCredentialResponse {
            deleted: false,
        }));
    };
    let deleted = state
        .store
        .delete_if(
            DelegatedIdentityCredential::object_type(),
            &req.id,
            expected_resource_version,
        )
        .await
        .map_err(|e| crate::grpc::persistence_error_to_status(e, "delete delegated credential"))?;
    Ok(Response::new(DeleteDelegatedIdentityCredentialResponse {
        deleted,
    }))
}

async fn delete_credential_resource_version(
    state: &Arc<ServerState>,
    id: &str,
    expected_resource_version: u64,
) -> Result<Option<u64>, Status> {
    if expected_resource_version != 0 {
        return Ok(Some(expected_resource_version));
    }
    let credential = state
        .store
        .get_message::<DelegatedIdentityCredential>(id)
        .await
        .map_err(|e| Status::internal(format!("fetch delegated credential failed: {e}")))?;
    Ok(effective_delete_credential_resource_version(
        credential.as_ref(),
        expected_resource_version,
    ))
}

fn effective_delete_credential_resource_version(
    credential: Option<&DelegatedIdentityCredential>,
    expected_resource_version: u64,
) -> Option<u64> {
    if expected_resource_version != 0 {
        Some(expected_resource_version)
    } else {
        credential
            .and_then(|credential| credential.metadata.as_ref())
            .map(|metadata| metadata.resource_version)
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

async fn validate_delegation_request(
    state: &Arc<ServerState>,
    user: &UserPrincipal,
    request: &DelegatedIdentityRequest,
) -> Result<i64, Status> {
    if request.issuer.trim().is_empty() {
        return Err(Status::invalid_argument(
            "delegated_identity.issuer is required",
        ));
    }
    let configured_issuer = state
        .config
        .oidc
        .as_ref()
        .map(|oidc| oidc.issuer.trim_end_matches('/'))
        .ok_or_else(|| {
            Status::failed_precondition(
                "delegated identity requires gateway OIDC authentication to be configured",
            )
        })?;
    if request.issuer.trim_end_matches('/') != configured_issuer {
        return Err(Status::invalid_argument(
            "delegated_identity.issuer must match the gateway OIDC issuer",
        ));
    }
    if request.client_id.trim().is_empty() {
        return Err(Status::invalid_argument(
            "delegated_identity.client_id is required",
        ));
    }
    if request.refresh_token.trim().is_empty() {
        return Err(Status::invalid_argument(
            "delegated_identity.refresh_token is required",
        ));
    }
    if request.access_token.trim().is_empty() {
        return Err(Status::invalid_argument(
            "delegated_identity.access_token is required",
        ));
    }
    let access_token_expires_at_ms =
        validate_delegated_access_token_subject(state, user, request).await?;
    let now = current_time_ms();
    if request.delegated_until_ms <= now {
        return Err(Status::invalid_argument(
            "delegated_identity.delegated_until_ms must be in the future",
        ));
    }
    let max_ms = i64::try_from(state.config.max_delegated_identity_duration_secs)
        .unwrap_or(i64::MAX / 1000)
        .saturating_mul(1000);
    if request.delegated_until_ms.saturating_sub(now) > max_ms {
        return Err(Status::failed_precondition(format!(
            "delegated identity duration exceeds gateway maximum of {} seconds",
            state.config.max_delegated_identity_duration_secs
        )));
    }
    Ok(access_token_expires_at_ms)
}

async fn validate_delegated_access_token_subject(
    state: &Arc<ServerState>,
    user: &UserPrincipal,
    request: &DelegatedIdentityRequest,
) -> Result<i64, Status> {
    validate_delegated_access_token_subject_value(
        state,
        &request.access_token,
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
    request: DelegatedIdentityRequest,
    access_token_expires_at_ms: i64,
) -> Result<UpsertedCredential, Status> {
    let id = delegated_credential_id(&request.issuer, &request.client_id, &user.identity.subject);
    let now = current_time_ms();
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
        issuer: request.issuer,
        client_id: request.client_id,
        principal_subject: user.identity.subject.clone(),
        refresh_token: request.refresh_token,
        access_token: request.access_token,
        access_token_expires_at_ms,
        scopes: request.scopes,
        audience: request.audience,
        last_refresh_at_ms: now,
        revoked_at_ms: 0,
    };

    let existing = state
        .store
        .get_message::<DelegatedIdentityCredential>(&id)
        .await
        .map_err(|e| Status::internal(format!("fetch delegated credential failed: {e}")))?;
    let (created, write_condition) = if let Some(existing) = existing {
        ensure_delegated_credential_not_revoked(&existing)?;
        let write_condition = delegated_credential_upsert_condition(&existing);
        credential.metadata = existing.metadata;
        credential.revoked_at_ms = existing.revoked_at_ms;
        (false, write_condition)
    } else {
        (true, WriteCondition::MustCreate)
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
        .await
        .map_err(|e| crate::grpc::persistence_error_to_status(e, "persist delegated credential"))?;
    if let Some(metadata) = credential.metadata.as_mut() {
        metadata.resource_version = result.resource_version;
    }
    Ok(UpsertedCredential {
        credential,
        created,
    })
}

fn delegated_credential_upsert_condition(existing: &DelegatedIdentityCredential) -> WriteCondition {
    WriteCondition::MatchResourceVersion(existing.get_resource_version())
}

struct UpsertedCredential {
    credential: DelegatedIdentityCredential,
    created: bool,
}

async fn cleanup_new_credential_after_prepare_failure(
    state: &Arc<ServerState>,
    credential: &UpsertedCredential,
) -> Result<(), Status> {
    if !credential.created {
        return Ok(());
    }
    state
        .store
        .delete_if(
            DelegatedIdentityCredential::object_type(),
            credential.credential.object_id(),
            credential.credential.get_resource_version(),
        )
        .await
        .map(|_| ())
        .map_err(|e| Status::internal(format!("delete prepared delegated credential failed: {e}")))
}

fn ensure_delegated_credential_not_revoked(
    credential: &DelegatedIdentityCredential,
) -> Result<(), Status> {
    if credential.revoked_at_ms > 0 {
        Err(Status::failed_precondition(
            "delegated identity credential is revoked",
        ))
    } else {
        Ok(())
    }
}

fn delegated_credential_id(issuer: &str, client_id: &str, principal_subject: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(issuer.trim_end_matches('/'));
    hasher.update(b"\0");
    hasher.update(client_id);
    hasher.update(b"\0");
    hasher.update(principal_subject);
    format!("delegated-identity-{:x}", hasher.finalize())
}

async fn refresh_if_needed(
    state: &Arc<ServerState>,
    credential: DelegatedIdentityCredential,
) -> Result<DelegatedIdentityCredential, Status> {
    let now = current_time_ms();
    if credential.access_token_expires_at_ms > 0
        && credential.access_token_expires_at_ms.saturating_sub(now) > REFRESH_SKEW_MS
    {
        return Ok(credential);
    }
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
            refresh_token: &credential.refresh_token,
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
    let refreshed_refresh_token = refreshed.refresh_token;
    let refreshed_access_token = refreshed.access_token;
    let updated = state
        .store
        .update_message_cas::<DelegatedIdentityCredential, _>(
            credential.object_id(),
            credential.get_resource_version(),
            |current| {
                current.access_token.clone_from(&refreshed_access_token);
                current.access_token_expires_at_ms = expires_at_ms;
                current.last_refresh_at_ms = now;
                if let Some(refresh_token) = refreshed_refresh_token.as_ref() {
                    current.refresh_token.clone_from(refresh_token);
                }
            },
        )
        .await
        .map_err(|e| crate::grpc::persistence_error_to_status(e, "refresh delegated credential"))?;
    Ok(updated)
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
             Re-authenticate with `openshell gateway logout` followed by `openshell gateway login`, \
             then run `openshell sandbox delegated-identity extend <sandbox> --for=<duration>`.",
        );
    }
    message
}

fn inactive_refresh_token_error(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains("invalid_grant")
        && (error.contains("session not active")
            || error.contains("session inactive")
            || error.contains("refresh token"))
}

#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    issuer: String,
    token_endpoint: String,
}

async fn discover_token_endpoint(client: &reqwest::Client, issuer: &str) -> Result<String, Status> {
    let normalized = issuer.trim_end_matches('/');
    let url = format!("{normalized}/.well-known/openid-configuration");
    let discovery = client
        .get(url)
        .send()
        .await
        .map_err(|e| Status::failed_precondition(format!("OIDC discovery failed: {e}")))?
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
        PreparedSandboxDelegatedIdentity, delegated_credential_id,
        delegated_credential_status_fields, delegated_credential_summary,
        delegated_credential_upsert_condition, delegated_refresh_allows_insecure_http,
        delegated_refresh_error_message, delete_new_prepared_sandbox_credential,
        effective_delete_credential_resource_version, ensure_delegated_credential_not_revoked,
        ensure_delegated_token_subject_matches, sandbox_delegated_identity_record_id,
    };
    use crate::grpc::test_support::{authed_request, test_server_state};
    use crate::persistence::{ObjectType, Store, WriteCondition, current_time_ms};
    use crate::sandbox_index::SandboxIndex;
    use crate::sandbox_watch::SandboxWatchBus;
    use crate::supervisor_session::SupervisorSessionRegistry;
    use crate::tracing_bus::TracingLogBus;
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    use openshell_core::proto::{
        DelegatedIdentityCredential, DelegatedIdentityRequest,
        ExtendSandboxDelegatedIdentityRequest, GetSandboxDelegatedIdentityStatusRequest, Sandbox,
        SandboxDelegatedIdentity, SandboxDelegatedIdentityRecord, SandboxSpec, SandboxStatus,
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
        assert!(message.contains("openshell sandbox delegated-identity extend <sandbox>"));
    }

    #[test]
    fn revoked_delegated_credential_rejects_upsert_reactivation() {
        let active = DelegatedIdentityCredential {
            revoked_at_ms: 0,
            ..Default::default()
        };
        ensure_delegated_credential_not_revoked(&active).expect("active credential is reusable");

        let revoked = DelegatedIdentityCredential {
            revoked_at_ms: 42,
            ..Default::default()
        };
        let status = ensure_delegated_credential_not_revoked(&revoked)
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
    fn delete_credential_resource_version_zero_uses_current_version() {
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

        let version = effective_delete_credential_resource_version(Some(&credential), 0);

        assert_eq!(version, Some(7));
        assert_eq!(effective_delete_credential_resource_version(None, 0), None);
        assert_eq!(
            effective_delete_credential_resource_version(Some(&credential), 42),
            Some(42)
        );
    }

    #[test]
    fn admin_credential_response_uses_non_secret_summary() {
        let credential = DelegatedIdentityCredential {
            issuer: "https://issuer.example.com".to_string(),
            client_id: "openshell-cli".to_string(),
            principal_subject: "user-1".to_string(),
            refresh_token: "refresh-secret".to_string(),
            access_token: "access-secret".to_string(),
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
    async fn prepared_sandbox_create_cleanup_deletes_only_new_credentials() {
        let state = test_server_state().await;
        let new = put_test_credential(&state, "delegated-identity-new").await;
        let reused = put_test_credential(&state, "delegated-identity-reused").await;

        delete_new_prepared_sandbox_credential(&state, Some(&prepared_test_delegation(&new, true)))
            .await
            .expect("new credential cleanup should succeed");
        delete_new_prepared_sandbox_credential(
            &state,
            Some(&prepared_test_delegation(&reused, false)),
        )
        .await
        .expect("reused credential cleanup should be a no-op");

        assert!(
            state
                .store
                .get_message::<DelegatedIdentityCredential>(new.object_id())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            state
                .store
                .get_message::<DelegatedIdentityCredential>(reused.object_id())
                .await
                .unwrap()
                .is_some()
        );
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
            refresh_token: "refresh-token".to_string(),
            access_token: original_access_token.clone(),
            access_token_expires_at_ms: current_time_ms() - 1,
            scopes: "openid profile".to_string(),
            ..Default::default()
        };
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
        assert_eq!(stored.access_token, original_access_token);
        assert_eq!(stored.principal_subject, "alice");
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
        let request = DelegatedIdentityRequest {
            issuer: issuer.clone(),
            client_id: TEST_AUDIENCE.to_string(),
            refresh_token: "refresh-token".to_string(),
            access_token: mint_test_access_token(&issuer, "alice", exp_secs),
            delegated_until_ms: current_time_ms() + 600_000,
            scopes: "openid profile".to_string(),
            audience: TEST_AUDIENCE.to_string(),
        };

        let expires_at_ms = super::validate_delegation_request(&state, &user, &request)
            .await
            .expect("delegation request should validate");
        let upserted = super::upsert_credential(&state, &user, request, expires_at_ms)
            .await
            .expect("credential should persist");

        assert_eq!(expires_at_ms, exp_secs.saturating_mul(1000));
        assert_eq!(
            upserted.credential.access_token_expires_at_ms,
            exp_secs.saturating_mul(1000)
        );
    }

    #[tokio::test]
    async fn extend_cleanup_deletes_new_credential_when_record_update_fails() {
        let server = wiremock::MockServer::start().await;
        mount_test_oidc_issuer(&server).await;
        let issuer = server.uri();
        let state = test_server_state_with_oidc(issuer.clone()).await;
        put_test_sandbox(&state, "delegated").await;
        let existing_credential =
            put_test_credential_for_subject(&state, "delegated-identity-existing", "dev-user")
                .await;
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

        let new_client_id = "openshell-cli-extend";
        let new_credential_id = delegated_credential_id(&issuer, new_client_id, "dev-user");
        let request = authed_request(ExtendSandboxDelegatedIdentityRequest {
            name: "delegated".to_string(),
            workspace: "default".to_string(),
            delegated_identity: Some(DelegatedIdentityRequest {
                issuer: issuer.clone(),
                client_id: new_client_id.to_string(),
                refresh_token: "new-refresh".to_string(),
                access_token: mint_test_access_token(
                    &issuer,
                    "dev-user",
                    current_time_secs() + 3600,
                ),
                delegated_until_ms: current_time_ms() + 600_000,
                scopes: "openid profile".to_string(),
                audience: TEST_AUDIENCE.to_string(),
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
                .get_message::<DelegatedIdentityCredential>(&new_credential_id)
                .await
                .unwrap()
                .is_none(),
            "newly-created credential should be cleaned up"
        );
        assert!(
            state
                .store
                .get_message::<DelegatedIdentityCredential>(existing_credential.object_id())
                .await
                .unwrap()
                .is_some(),
            "pre-existing credential should not be cleaned up"
        );
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
            refresh_token: "refresh".to_string(),
            access_token: "access".to_string(),
            ..Default::default()
        };
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
            })
            .await
            .unwrap();
    }

    fn prepared_test_delegation(
        credential: &DelegatedIdentityCredential,
        credential_created: bool,
    ) -> PreparedSandboxDelegatedIdentity {
        PreparedSandboxDelegatedIdentity {
            record: SandboxDelegatedIdentityRecord {
                metadata: Some(ObjectMeta {
                    id: format!("sandbox-delegated-identity-{credential_created}"),
                    name: format!("sandbox-delegated-identity-{credential_created}"),
                    workspace: "default".to_string(),
                    labels: HashMap::new(),
                    annotations: HashMap::new(),
                    ..Default::default()
                }),
                sandbox_id: "sandbox-test".to_string(),
                delegated_identity: Some(SandboxDelegatedIdentity {
                    credential_id: credential.object_id().to_string(),
                    principal_subject: credential.principal_subject.clone(),
                    delegated_until_ms: 2_000_000,
                    withdrawn_at_ms: 0,
                }),
            },
            credential_id: credential.object_id().to_string(),
            credential_resource_version: credential.get_resource_version(),
            credential_created,
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
