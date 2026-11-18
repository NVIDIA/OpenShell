// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Workspace secrets: shared, never-injected credential minting material.
//!
//! The gateway record holds only non-secret metadata and an opaque credential
//! storage handle. Values are written through the credential issuer under the
//! `WorkspaceSecret` owner kind and are never returned by these handlers.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use openshell_core::proto::datamodel::v1::{CredentialHandle, ObjectMeta};
use openshell_core::proto::{
    CreateSecretRequest, DeleteSecretRequest, DeleteSecretResponse, DeletionOutcome,
    GetSecretRequest, ListSecretsRequest, ListSecretsResponse, RevealSecretRequest,
    RevealSecretResponse, Secret, SecretRefreshUse, SecretResponse, UpdateSecretRequest,
};
use openshell_core::{GetResourceVersion, ObjectId, ObjectLabels, ObjectName, ObjectWorkspace};
use openshell_credential_issuer::endpoint::normalize_token_endpoint;
use openshell_credential_issuer::refresh::secret_refs;
use openshell_credential_issuer::{Handles, SecretOwner};
use prost::Message;
use tonic::{Request, Response, Status};
use tracing::warn;

use super::validation::validate_dns1123_label;
use super::{MAX_MAP_VALUE_LEN, MAX_NAME_LEN};
use crate::ServerState;
use crate::auth::principal::Principal;
use crate::auth::workspace_authz::{
    MinWorkspaceRole, authorize_workspace, selected_workspace_name,
};
use crate::compute::MutationScope;
use crate::pagination::Pagination;
use crate::persistence::{
    ObjectCursor, ObjectListQuery, ObjectType, PersistenceError, Store, WriteCondition,
    current_time_ms,
};
use crate::storage_proto::{StoredSecretRefreshUse, StoredWorkspaceSecret};

/// Logical key of the single value each secret stores.
pub const SECRET_VALUE_KEY: &str = secret_refs::WORKSPACE_SECRET_VALUE_KEY;
const MAX_SECRETS_PER_WORKSPACE: u32 = 500;
const MAX_ALLOWED_ENDPOINTS: usize = 16;
const MAX_ENDPOINT_LEN: usize = 2048;
const MAX_DESCRIPTION_LEN: usize = 1024;
const SWEEP_PAGE_SIZE: u32 = 1000;

impl ObjectType for StoredWorkspaceSecret {
    fn object_type() -> &'static str {
        "workspace_secret"
    }
}

/// Project a stored record to its public form. Never carries handles.
pub fn public_secret(stored: &StoredWorkspaceSecret) -> Secret {
    Secret {
        metadata: stored.metadata.clone(),
        description: stored.description.clone(),
        refresh_use: stored
            .refresh_use
            .as_ref()
            .map(|refresh_use| SecretRefreshUse {
                allowed_endpoints: refresh_use.allowed_endpoints.clone(),
            }),
        value_update_time: stored.value_update_time,
    }
}

fn is_tombstoned(stored: &StoredWorkspaceSecret) -> bool {
    stored
        .metadata
        .as_ref()
        .is_some_and(|metadata| metadata.deletion_time.is_some())
}

fn owner(stored: &StoredWorkspaceSecret) -> SecretOwner<'_> {
    SecretOwner::workspace_secret(stored.object_workspace(), stored.object_id())
}

fn value_handles(handle: CredentialHandle) -> Handles {
    HashMap::from([(SECRET_VALUE_KEY.to_string(), handle)])
}

fn labels_json(stored: &StoredWorkspaceSecret) -> Result<Option<String>, Status> {
    match stored.object_labels() {
        Some(labels) if !labels.is_empty() => serde_json::to_string(&labels)
            .map(Some)
            .map_err(|e| Status::internal(format!("failed to serialize labels: {e}"))),
        _ => Ok(None),
    }
}

/// Reject secret creation and new references unless the operator activated
/// workspace secrets and no observable live gateway lacks support for them.
pub async fn ensure_workspace_secrets_active(state: &ServerState) -> Result<(), Status> {
    if !state.config.workspace_secrets.enabled {
        return Err(Status::failed_precondition(
            "workspace secrets are not enabled; set enable_workspace_secrets after every gateway supports them",
        ));
    }
    state
        .store
        .ensure_workspace_secrets_deployment_compatible()
        .await
        .map_err(|err| Status::failed_precondition(err.to_string()))
}

fn ensure_credential_storage(state: &ServerState) -> Result<(), Status> {
    if state.credentials.stores_provider_credentials() {
        Ok(())
    } else {
        Err(Status::failed_precondition(
            "workspace secrets require configured credential storage",
        ))
    }
}

fn validate_name(name: &str) -> Result<(), Status> {
    if name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }
    if name.len() > MAX_NAME_LEN {
        return Err(Status::invalid_argument(format!(
            "name exceeds maximum length ({} > {MAX_NAME_LEN})",
            name.len()
        )));
    }
    validate_dns1123_label(name, "name")
}

fn validate_value(value: &str) -> Result<(), Status> {
    if value.is_empty() {
        return Err(Status::invalid_argument("value must not be empty"));
    }
    if value.len() > MAX_MAP_VALUE_LEN {
        return Err(Status::invalid_argument(format!(
            "value exceeds maximum length ({} > {MAX_MAP_VALUE_LEN})",
            value.len()
        )));
    }
    Ok(())
}

fn validate_description(description: &str) -> Result<(), Status> {
    if description.len() > MAX_DESCRIPTION_LEN {
        return Err(Status::invalid_argument(format!(
            "description exceeds maximum length ({} > {MAX_DESCRIPTION_LEN})",
            description.len()
        )));
    }
    Ok(())
}

fn normalize_allowed_endpoints(endpoints: &[String]) -> Result<Vec<String>, Status> {
    if endpoints.is_empty() {
        return Err(Status::invalid_argument(
            "refresh_use.allowed_endpoints must name at least one token endpoint; omit refresh_use for a reveal-only secret",
        ));
    }
    if endpoints.len() > MAX_ALLOWED_ENDPOINTS {
        return Err(Status::invalid_argument(format!(
            "allowed_endpoints exceeds maximum entries ({} > {MAX_ALLOWED_ENDPOINTS})",
            endpoints.len()
        )));
    }
    let mut normalized = BTreeSet::new();
    for endpoint in endpoints {
        if endpoint.len() > MAX_ENDPOINT_LEN {
            return Err(Status::invalid_argument(format!(
                "allowed_endpoints entry exceeds maximum length ({} > {MAX_ENDPOINT_LEN})",
                endpoint.len()
            )));
        }
        let value = normalize_token_endpoint(endpoint).map_err(|reason| {
            Status::invalid_argument(format!("allowed_endpoints entry '{endpoint}' {reason}"))
        })?;
        normalized.insert(value);
    }
    Ok(normalized.into_iter().collect())
}

/// Validate labels by reusing the shared metadata validator.
fn validate_labels(labels: &HashMap<String, String>) -> Result<(), Status> {
    super::validation::validate_object_metadata(
        Some(&ObjectMeta {
            id: "validation".to_string(),
            name: "validation".to_string(),
            labels: labels.clone(),
            ..ObjectMeta::default()
        }),
        "secret",
    )
}

async fn authorized_workspace(
    state: &ServerState,
    request_principal: &Principal,
    workspace_scope: Option<&openshell_core::proto::WorkspaceSelector>,
    role: MinWorkspaceRole,
) -> Result<super::workspace::ResolvedWorkspace, Status> {
    let authz = authorize_workspace(
        &state.store,
        &state.admin_role,
        request_principal,
        selected_workspace_name(workspace_scope)?,
        role,
    )
    .await?;
    super::workspace::resolve_workspace(state.store.as_ref(), &authz.workspace).await
}

/// Fetch a live (not tombstoned) secret by name.
pub async fn get_live_secret(
    store: &Store,
    workspace: &str,
    name: &str,
) -> Result<Option<StoredWorkspaceSecret>, Status> {
    let stored = store
        .get_message_by_name::<StoredWorkspaceSecret>(workspace, name)
        .await
        .map_err(|e| Status::internal(format!("fetch secret failed: {e}")))?;
    Ok(stored.filter(is_live))
}

async fn stage_value(
    state: &ServerState,
    workspace: &str,
    secret_id: &str,
    value: &str,
) -> Result<CredentialHandle, Status> {
    let values = HashMap::from([(SECRET_VALUE_KEY.to_string(), value.to_string())]);
    let staging_id = format!("{secret_id}-value-{}", uuid::Uuid::new_v4());
    let mut handles = state
        .credentials
        .store_secrets_with_object_id(
            SecretOwner::workspace_secret(workspace, secret_id),
            &staging_id,
            &values,
            &HashMap::new(),
        )
        .await?;
    handles
        .remove(SECRET_VALUE_KEY)
        .ok_or_else(|| Status::internal("credential storage returned no secret handle"))
}

async fn discard_staged_value(
    state: &ServerState,
    workspace: &str,
    secret_id: &str,
    handle: CredentialHandle,
) {
    if let Err(err) = state
        .credentials
        .delete_secrets(
            SecretOwner::workspace_secret(workspace, secret_id),
            &value_handles(handle),
        )
        .await
    {
        warn!(secret_id, error = %err, "failed to discard staged workspace secret value");
    }
}

pub(super) async fn handle_create_secret(
    state: &Arc<ServerState>,
    request: Request<CreateSecretRequest>,
) -> Result<Response<SecretResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let req = request.into_inner();
    // Read the workspace instance before checking membership, so the secret is
    // published only under the instance the caller was authorized against. A
    // replacement after this read fails the check after the insert. Report the
    // lookup only after authorization, so non-members learn nothing.
    let requested = selected_workspace_name(req.workspace_scope.as_ref())?.to_string();
    let instance = active_workspace_instance(&state.store, &requested).await;
    let workspace = authorized_workspace(
        state,
        &principal,
        req.workspace_scope.as_ref(),
        MinWorkspaceRole::Admin,
    )
    .await?
    .ensure_active()?;
    let workspace_id = match instance? {
        Some(id) if workspace == requested => id,
        _ => {
            return Err(Status::failed_precondition(format!(
                "workspace '{workspace}' is being deleted"
            )));
        }
    };
    validate_name(&req.name)?;
    validate_value(&req.value)?;
    validate_description(&req.description)?;
    validate_labels(&req.labels)?;
    let refresh_use = req
        .refresh_use
        .as_ref()
        .map(|refresh_use| {
            normalize_allowed_endpoints(&refresh_use.allowed_endpoints)
                .map(|allowed_endpoints| StoredSecretRefreshUse { allowed_endpoints })
        })
        .transpose()?;
    ensure_workspace_secrets_active(state).await?;
    ensure_credential_storage(state)?;
    clear_stale_record(state, &workspace, &workspace_id, &req.name).await?;

    let id = uuid::Uuid::new_v4().to_string();
    let now = openshell_core::time::timestamp_from_millis(current_time_ms()).ok();
    let handle = stage_value(state, &workspace, &id, &req.value).await?;
    // Insert the record as a pending create bound to the resolved workspace
    // ID. Until it is published it is invisible, but it already blocks
    // workspace deletion. If the gateway exits before publishing, the sweep
    // discards it, so no live secret can outlive its workspace.
    let mut stored = StoredWorkspaceSecret {
        metadata: Some(ObjectMeta {
            id: id.clone(),
            name: req.name.clone(),
            created_time: now,
            labels: req.labels,
            resource_version: 0,
            annotations: HashMap::new(),
            workspace: workspace.clone(),
            deletion_time: None,
        }),
        description: req.description,
        refresh_use,
        value_update_time: now,
        value_handle: Some(handle.clone()),
        pending_handle_deletions: Vec::new(),
        workspace_id: workspace_id.clone(),
        create_pending_since: now,
    };
    let labels = labels_json(&stored)?;
    let write = state
        .store
        .create_if_workspace_count_below(
            StoredWorkspaceSecret::object_type(),
            stored.object_id(),
            stored.object_name(),
            &workspace,
            &stored.encode_to_vec(),
            labels.as_deref(),
            u64::from(MAX_SECRETS_PER_WORKSPACE),
        )
        .await;
    let write = match write {
        Ok(Some(write)) => write,
        Ok(None) => {
            discard_staged_value(state, &workspace, &id, handle).await;
            return Err(Status::resource_exhausted(format!(
                "workspace has reached the maximum of {MAX_SECRETS_PER_WORKSPACE} secrets"
            )));
        }
        Err(PersistenceError::UniqueViolation { .. }) => {
            discard_staged_value(state, &workspace, &id, handle).await;
            return Err(Status::already_exists("secret already exists"));
        }
        Err(err) => {
            discard_staged_value(state, &workspace, &id, handle).await;
            return Err(Status::internal(format!("persist secret failed: {err}")));
        }
    };
    if let Some(metadata) = stored.metadata.as_mut() {
        metadata.resource_version = write.resource_version;
    }

    // Workspace deletion marks the workspace terminating before it scans for
    // blocking resources. If that scan ran before the insert, the workspace is
    // no longer the active one we resolved, so discard the pending record.
    // Otherwise the scan finds the record and the deletion is blocked.
    let still_active = active_workspace_id(&state.store, &workspace)
        .await
        .is_ok_and(|current| current == workspace_id);
    if !still_active {
        if let Err(err) = discard_pending_create(state, stored).await {
            warn!(error = %err, "workspace secret cleanup will be retried");
        }
        return Err(Status::failed_precondition(format!(
            "workspace '{workspace}' was deleted while the secret was being created"
        )));
    }

    stored.create_pending_since = None;
    let published = state
        .store
        .put_if(
            StoredWorkspaceSecret::object_type(),
            stored.object_id(),
            stored.object_name(),
            &workspace,
            &stored.encode_to_vec(),
            labels.as_deref(),
            WriteCondition::MatchResourceVersion(write.resource_version),
        )
        .await;
    let published = match published {
        Ok(published) => published,
        // The sweep claimed the record first; it owns the cleanup.
        Err(PersistenceError::Conflict { .. }) => {
            return Err(Status::aborted(
                "secret creation was interrupted by workspace cleanup; retry",
            ));
        }
        Err(err) => {
            if let Err(cleanup) = discard_pending_create(state, stored).await {
                warn!(error = %cleanup, "workspace secret cleanup will be retried");
            }
            return Err(Status::internal(format!("publish secret failed: {err}")));
        }
    };
    if let Some(metadata) = stored.metadata.as_mut() {
        metadata.resource_version = published.resource_version;
    }
    Ok(Response::new(SecretResponse {
        secret: Some(public_secret(&stored)),
    }))
}

/// Free `name` for a new secret: finish a deletion an earlier request could not
/// complete, or discard a create that never published. Fails while another
/// create of the same name may still be in flight, or when cleanup fails.
async fn clear_stale_record(
    state: &ServerState,
    workspace: &str,
    workspace_id: &str,
    name: &str,
) -> Result<(), Status> {
    let existing = state
        .store
        .get_message_by_name::<StoredWorkspaceSecret>(workspace, name)
        .await
        .map_err(|e| Status::internal(format!("fetch secret failed: {e}")))?;
    let Some(existing) = existing else {
        return Ok(());
    };
    if is_pending_create(&existing) && !is_tombstoned(&existing) {
        if existing.workspace_id == workspace_id && !pending_create_is_stale(&existing) {
            return Err(Status::failed_precondition(format!(
                "secret '{name}' is being created; retry later"
            )));
        }
        // If the earlier create published first, the insert below reports
        // that the name is taken.
        discard_pending_create(state, existing).await.map_err(|err| {
            Status::failed_precondition(format!(
                "secret '{name}' has an abandoned create that could not be cleaned up ({}); retry later",
                err.message()
            ))
        })?;
        return Ok(());
    }
    if !is_tombstoned(&existing) {
        return Ok(());
    }
    finish_deletion(state, existing).await.map_err(|err| {
        Status::failed_precondition(format!(
            "secret '{name}' is still being deleted and cleanup failed ({}); retry later",
            err.message()
        ))
    })
}

/// How long a create may take between insert and publication before the
/// record counts as abandoned.
const PENDING_CREATE_TIMEOUT_MS: i64 = 5 * 60 * 1000;

fn is_pending_create(stored: &StoredWorkspaceSecret) -> bool {
    stored.create_pending_since.is_some()
}

fn pending_create_is_stale(stored: &StoredWorkspaceSecret) -> bool {
    stored
        .create_pending_since
        .as_ref()
        .and_then(|since| openshell_core::time::timestamp_to_millis(since).ok())
        .is_none_or(|since| current_time_ms().saturating_sub(since) >= PENDING_CREATE_TIMEOUT_MS)
}

/// Whether reads and references may see the record: published and not being
/// deleted.
fn is_live(stored: &StoredWorkspaceSecret) -> bool {
    !is_pending_create(stored) && !is_tombstoned(stored)
}

/// Remove a create that never published. The record is first claimed with
/// the version-checked transition to deleting, so a create that publishes
/// concurrently wins and keeps its value. Only the claimant deletes the value.
/// Returns whether this caller claimed the record. A claimant whose cleanup
/// fails leaves a tombstone that the sweep finishes.
async fn discard_pending_create(
    state: &ServerState,
    stored: StoredWorkspaceSecret,
) -> Result<bool, Status> {
    let claimed = match tombstone(state, stored).await {
        Ok(claimed) => claimed,
        Err(err) if err.code() == tonic::Code::Aborted => return Ok(false),
        Err(err) => return Err(err),
    };
    finish_deletion(state, claimed).await?;
    Ok(true)
}

/// ID of the named workspace while it is active, or `None` when it is missing
/// or being deleted. A store error is returned, never reported as absence.
async fn active_workspace_instance(
    store: &Store,
    workspace: &str,
) -> Result<Option<String>, Status> {
    let record: Option<openshell_core::proto::Workspace> = store
        .get_message_by_name("", workspace)
        .await
        .map_err(|e| Status::internal(format!("fetch workspace failed: {e}")))?;
    Ok(record
        .and_then(|record| record.metadata)
        .filter(|metadata| metadata.deletion_time.is_none())
        .map(|metadata| metadata.id))
}

/// ID of the named workspace while it is active.
async fn active_workspace_id(store: &Store, workspace: &str) -> Result<String, Status> {
    active_workspace_instance(store, workspace)
        .await?
        .ok_or_else(|| {
            Status::failed_precondition(format!("workspace '{workspace}' is being deleted"))
        })
}

pub(super) async fn handle_get_secret(
    state: &Arc<ServerState>,
    request: Request<GetSecretRequest>,
) -> Result<Response<SecretResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let req = request.into_inner();
    if req.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }
    let workspace = authorized_workspace(
        state,
        &principal,
        req.workspace_scope.as_ref(),
        MinWorkspaceRole::User,
    )
    .await?
    .name;
    // A secret whose deletion is unfinished is returned with its deletion
    // time set, so it is visible while it still holds its name and quota. A
    // create that has not published is invisible.
    let stored = state
        .store
        .get_message_by_name::<StoredWorkspaceSecret>(&workspace, &req.name)
        .await
        .map_err(|e| Status::internal(format!("fetch secret failed: {e}")))?
        .filter(|stored| !is_pending_create(stored))
        .ok_or_else(|| Status::not_found("secret not found"))?;
    Ok(Response::new(SecretResponse {
        secret: Some(public_secret(&stored)),
    }))
}

pub(super) async fn handle_list_secrets(
    state: &Arc<ServerState>,
    request: Request<ListSecretsRequest>,
) -> Result<Response<ListSecretsResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let req = request.into_inner();
    let workspace = authorized_workspace(
        state,
        &principal,
        req.workspace_scope.as_ref(),
        MinWorkspaceRole::User,
    )
    .await?
    .name;
    if !req.label_selector.is_empty() {
        super::validation::validate_label_selector(&req.label_selector)?;
    }
    let pagination = Pagination::new(
        req.page_size,
        &req.page_token,
        "ListSecrets",
        &[&workspace, &req.label_selector],
    )?;
    let after = pagination.object_cursor()?;
    let query = if req.label_selector.is_empty() {
        ObjectListQuery::Workspace(&workspace)
    } else {
        ObjectListQuery::WorkspaceSelector {
            workspace: &workspace,
            label_selector: &req.label_selector,
        }
    };
    let page = state
        .store
        .list_message_page::<StoredWorkspaceSecret>(query, after.as_ref(), pagination.page_size())
        .await
        .map_err(|e| Status::internal(format!("list secrets failed: {e}")))?;
    let next_page_token = pagination.next_object_token(page.next_cursor.as_ref());
    Ok(Response::new(ListSecretsResponse {
        // Unfinished deletions stay in the listing, with their deletion time
        // set, so pages stay full and the secrets stay visible.
        secrets: page
            .messages
            .iter()
            .filter(|stored| !is_pending_create(stored))
            .map(public_secret)
            .collect(),
        next_page_token,
    }))
}

pub(super) async fn handle_update_secret(
    state: &Arc<ServerState>,
    request: Request<UpdateSecretRequest>,
) -> Result<Response<SecretResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let req = request.into_inner();
    if req.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }
    let workspace = authorized_workspace(
        state,
        &principal,
        req.workspace_scope.as_ref(),
        MinWorkspaceRole::Admin,
    )
    .await?
    .name;
    if let Some(value) = req.value.as_deref() {
        validate_value(value)?;
    }
    if let Some(description) = req.description.as_deref() {
        validate_description(description)?;
    }
    if let Some(labels) = req.labels.as_ref() {
        validate_labels(&labels.labels)?;
    }

    let current = state
        .store
        .get_message_by_name::<StoredWorkspaceSecret>(&workspace, &req.name)
        .await
        .map_err(|e| Status::internal(format!("fetch secret failed: {e}")))?
        .filter(|stored| !is_pending_create(stored))
        .ok_or_else(|| Status::not_found("secret not found"))?;
    if is_tombstoned(&current) {
        return Err(Status::failed_precondition(format!(
            "secret '{}' is being deleted",
            req.name
        )));
    }
    let current_version = current.get_resource_version();
    if let Some(expected) = req.expected_resource_version
        && expected != current_version
    {
        return Err(Status::failed_precondition(format!(
            "secret resource version is {current_version}, not {expected}"
        )));
    }
    if req.value.is_none() && req.description.is_none() && req.labels.is_none() {
        return Ok(Response::new(SecretResponse {
            secret: Some(public_secret(&current)),
        }));
    }

    let mut updated = current.clone();
    let staged = if let Some(value) = req.value.as_deref() {
        ensure_credential_storage(state)?;
        let handle = stage_value(state, &workspace, current.object_id(), value).await?;
        if let Some(previous) = updated.value_handle.replace(handle.clone()) {
            updated.pending_handle_deletions.push(previous);
        }
        updated.value_update_time =
            openshell_core::time::timestamp_from_millis(current_time_ms()).ok();
        Some(handle)
    } else {
        None
    };
    if let Some(description) = req.description {
        updated.description = description;
    }
    if let (Some(labels), Some(metadata)) = (req.labels, updated.metadata.as_mut()) {
        metadata.labels = labels.labels;
    }

    let labels = labels_json(&updated)?;
    let write = state
        .store
        .put_if(
            StoredWorkspaceSecret::object_type(),
            updated.object_id(),
            updated.object_name(),
            &workspace,
            &updated.encode_to_vec(),
            labels.as_deref(),
            WriteCondition::MatchResourceVersion(current_version),
        )
        .await;
    let write = match write {
        Ok(write) => write,
        Err(err) => {
            if let Some(handle) = staged {
                discard_staged_value(state, &workspace, current.object_id(), handle).await;
            }
            return Err(match err {
                PersistenceError::Conflict { .. } => {
                    Status::aborted("secret was concurrently modified; retry the update")
                }
                err => Status::internal(format!("persist secret failed: {err}")),
            });
        }
    };
    if let Some(metadata) = updated.metadata.as_mut() {
        metadata.resource_version = write.resource_version;
    }
    // Delete the superseded value now so a racing mint re-reads the record and
    // uses the new value. Report the record as it ends up, so the returned
    // resource version is current.
    if !updated.pending_handle_deletions.is_empty() {
        match drain_pending_deletions(state, updated.clone()).await {
            Ok(drained) => updated = drained,
            Err(err) => {
                warn!(error = %err, "workspace secret handle cleanup deferred to the sweep");
            }
        }
    }
    Ok(Response::new(SecretResponse {
        secret: Some(public_secret(&updated)),
    }))
}

pub(super) async fn handle_delete_secret(
    state: &Arc<ServerState>,
    request: Request<DeleteSecretRequest>,
) -> Result<Response<DeleteSecretResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let req = request.into_inner();
    if req.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }
    let workspace = authorized_workspace(
        state,
        &principal,
        req.workspace_scope.as_ref(),
        MinWorkspaceRole::Admin,
    )
    .await?
    .name;
    // Configuring refresh holds this lock too, so no new reference can appear
    // between the dependency check and the tombstone.
    let _mutation_guard = state
        .compute
        .mutation_guard(MutationScope::Workspace(&workspace))
        .await
        .map_err(|err| super::persistence_error_to_status(err, "acquire secret mutation lock"))?;
    let stored = state
        .store
        .get_message_by_name::<StoredWorkspaceSecret>(&workspace, &req.name)
        .await
        .map_err(|e| Status::internal(format!("fetch secret failed: {e}")))?
        .filter(|stored| !is_pending_create(stored));
    let Some(stored) = stored else {
        return Ok(Response::new(DeleteSecretResponse {
            outcome: super::deletion_outcome(false, req.allow_missing, "secret")?,
        }));
    };
    if !is_tombstoned(&stored) {
        let dependents = secret_dependents(&state.store, &workspace, stored.object_id()).await?;
        if !dependents.is_empty() {
            return Err(Status::failed_precondition(format!(
                "secret '{}' is referenced by provider refresh configuration: {}",
                req.name,
                dependents.join(", ")
            )));
        }
    }
    let tombstoned = tombstone(state, stored).await?;
    finish_deletion(state, tombstoned).await?;
    Ok(Response::new(DeleteSecretResponse {
        outcome: DeletionOutcome::Completed.into(),
    }))
}

pub(super) async fn handle_reveal_secret(
    state: &Arc<ServerState>,
    request: Request<RevealSecretRequest>,
) -> Result<Response<RevealSecretResponse>, Status> {
    // Only a verified mTLS operator may reveal. Check it before anything else,
    // so other callers cannot learn whether reveal is enabled.
    crate::auth::guard::require_operator(&request)?;
    let principal = super::extract_principal(&request)?;
    let req = request.into_inner();
    let workspace = authorized_workspace(
        state,
        &principal,
        req.workspace_scope.as_ref(),
        MinWorkspaceRole::Admin,
    )
    .await?
    .name;
    if !state.config.workspace_secrets.reveal_enabled {
        return Err(Status::failed_precondition(
            "secret reveal is not enabled; set enable_secret_reveal for control-plane callers",
        ));
    }
    if req.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }
    let stored = get_live_secret(&state.store, &workspace, &req.name)
        .await?
        .ok_or_else(|| Status::not_found("secret not found"))?;
    let handle = stored
        .value_handle
        .clone()
        .ok_or_else(|| Status::not_found("secret not found"))?;
    let resolved = state
        .credentials
        .resolve_secrets(owner(&stored), &value_handles(handle), 0)
        .await?;
    let value = resolved
        .values
        .get(SECRET_VALUE_KEY)
        .cloned()
        .ok_or_else(|| Status::unavailable("secret value could not be read"))?;
    Ok(Response::new(RevealSecretResponse {
        value,
        value_update_time: stored.value_update_time,
    }))
}

/// Live refresh configurations in a workspace that reference a secret, named
/// `provider/credential_key`. A malformed binding annotation counts as a
/// reference so deletion fails closed.
async fn secret_dependents(
    store: &Store,
    workspace: &str,
    secret_id: &str,
) -> Result<Vec<String>, Status> {
    let states = crate::refresh_store::list_refresh_states_in_workspace(store, workspace).await?;
    let mut dependents: Vec<String> = states
        .iter()
        .filter(|state| {
            state
                .metadata
                .as_ref()
                .is_some_and(|metadata| metadata.deletion_time.is_none())
        })
        .filter(|state| {
            secret_refs::material_secret_bindings(state.metadata.as_ref())
                .map_or(true, |bindings| {
                    bindings.values().any(|binding| binding.id == secret_id)
                })
        })
        .map(|state| format!("{}/{}", state.provider_name, state.credential_key))
        .collect();
    dependents.sort();
    dependents.dedup();
    Ok(dependents)
}

/// Mark a secret deleted and queue its value handle for backend deletion. A
/// tombstoned secret is invisible to reads and cannot be referenced.
async fn tombstone(
    state: &ServerState,
    mut stored: StoredWorkspaceSecret,
) -> Result<StoredWorkspaceSecret, Status> {
    if is_tombstoned(&stored) {
        return Ok(stored);
    }
    let version = stored.get_resource_version();
    if let Some(metadata) = stored.metadata.as_mut() {
        metadata.deletion_time =
            openshell_core::time::timestamp_from_millis(current_time_ms()).ok();
    }
    if let Some(handle) = stored.value_handle.take() {
        stored.pending_handle_deletions.push(handle);
    }
    let write = state
        .store
        .put_if(
            StoredWorkspaceSecret::object_type(),
            stored.object_id(),
            stored.object_name(),
            stored.object_workspace(),
            &stored.encode_to_vec(),
            labels_json(&stored)?.as_deref(),
            WriteCondition::MatchResourceVersion(version),
        )
        .await
        .map_err(|err| match err {
            PersistenceError::Conflict { .. } => {
                Status::aborted("secret was concurrently modified; retry the delete")
            }
            err => Status::internal(format!("tombstone secret failed: {err}")),
        })?;
    if let Some(metadata) = stored.metadata.as_mut() {
        metadata.resource_version = write.resource_version;
    }
    Ok(stored)
}

/// Delete a tombstoned secret's backend handles, then its record.
async fn finish_deletion(state: &ServerState, stored: StoredWorkspaceSecret) -> Result<(), Status> {
    let stored = drain_pending_deletions(state, stored).await?;
    state
        .store
        .delete_if(
            StoredWorkspaceSecret::object_type(),
            stored.object_id(),
            stored.get_resource_version(),
        )
        .await
        .map_err(|e| Status::internal(format!("delete secret failed: {e}")))?;
    Ok(())
}

/// Delete superseded backend handles, then clear them from the record. A
/// failure leaves the record unchanged so the sweep retries it.
async fn drain_pending_deletions(
    state: &ServerState,
    mut stored: StoredWorkspaceSecret,
) -> Result<StoredWorkspaceSecret, Status> {
    if stored.pending_handle_deletions.is_empty() {
        return Ok(stored);
    }
    for handle in &stored.pending_handle_deletions {
        state
            .credentials
            .delete_secrets(owner(&stored), &value_handles(handle.clone()))
            .await?;
    }
    stored.pending_handle_deletions.clear();
    let write = state
        .store
        .put_if(
            StoredWorkspaceSecret::object_type(),
            stored.object_id(),
            stored.object_name(),
            stored.object_workspace(),
            &stored.encode_to_vec(),
            labels_json(&stored)?.as_deref(),
            WriteCondition::MatchResourceVersion(stored.get_resource_version()),
        )
        .await
        .map_err(|err| match err {
            PersistenceError::Conflict { .. } => {
                Status::aborted("secret was concurrently modified during cleanup")
            }
            err => Status::internal(format!("persist secret cleanup failed: {err}")),
        })?;
    if let Some(metadata) = stored.metadata.as_mut() {
        metadata.resource_version = write.resource_version;
    }
    Ok(stored)
}

/// Retry backend deletions and tombstone removal that an earlier request could
/// not finish. Runs on the gateway's periodic maintenance tick.
pub async fn sweep_workspace_secrets(state: &ServerState) -> Result<usize, Status> {
    let mut finished = 0;
    let mut after: Option<ObjectCursor> = None;
    // Page through every record: healthy secrets never leave the listing, so
    // rereading one fixed page would starve later pending cleanup.
    loop {
        let records = state
            .store
            .list_by_type_after(
                StoredWorkspaceSecret::object_type(),
                after.as_ref(),
                SWEEP_PAGE_SIZE,
            )
            .await
            .map_err(|e| Status::internal(format!("list secrets failed: {e}")))?;
        let last_page = records.len() < SWEEP_PAGE_SIZE as usize;
        after = records.last().map(ObjectCursor::from);
        finished += sweep_page(state, records).await?;
        if last_page {
            return Ok(finished);
        }
    }
}

/// What the sweep does with a create that has not published.
#[derive(Debug, PartialEq, Eq)]
enum PendingFate {
    /// It may still publish.
    Keep,
    /// It can no longer publish: it is stale, or its workspace is gone or is
    /// a different workspace with the same name.
    Discard,
    /// The workspace could not be read; decide on a later sweep.
    Defer,
}

fn pending_fate(
    stored: &StoredWorkspaceSecret,
    workspace: Result<Option<String>, Status>,
) -> PendingFate {
    if pending_create_is_stale(stored) {
        return PendingFate::Discard;
    }
    match workspace {
        Err(_) => PendingFate::Defer,
        Ok(Some(current)) if current == stored.workspace_id => PendingFate::Keep,
        Ok(_) => PendingFate::Discard,
    }
}

async fn sweep_page(
    state: &ServerState,
    records: Vec<crate::persistence::ObjectRecord>,
) -> Result<usize, Status> {
    let mut finished = 0;
    for record in records {
        let mut stored = StoredWorkspaceSecret::decode(record.payload.as_slice())
            .map_err(|e| Status::internal(format!("decode secret failed: {e}")))?;
        stored
            .metadata
            .get_or_insert_with(ObjectMeta::default)
            .resource_version = record.resource_version;
        // A claimed pending create is a tombstone; finish it below.
        if is_pending_create(&stored) && !is_tombstoned(&stored) {
            let workspace = if pending_create_is_stale(&stored) {
                Ok(None)
            } else {
                active_workspace_instance(&state.store, stored.object_workspace()).await
            };
            match pending_fate(&stored, workspace) {
                PendingFate::Keep => {}
                PendingFate::Defer => {
                    warn!("workspace lookup failed; pending secret cleanup deferred");
                }
                PendingFate::Discard => match discard_pending_create(state, stored).await {
                    Ok(true) => finished += 1,
                    Ok(false) => {}
                    Err(err) => warn!(error = %err, "workspace secret cleanup will be retried"),
                },
            }
            continue;
        }
        if !is_tombstoned(&stored) && stored.pending_handle_deletions.is_empty() {
            continue;
        }
        let result = if is_tombstoned(&stored) {
            finish_deletion(state, stored).await
        } else {
            drain_pending_deletions(state, stored).await.map(|_| ())
        };
        match result {
            Ok(()) => finished += 1,
            Err(err) => warn!(error = %err, "workspace secret cleanup will be retried"),
        }
    }
    Ok(finished)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::identity::IdentityProvider;
    use crate::grpc::test_support::{authed_request, test_server_state};
    use openshell_core::proto::{SecretLabels, workspace_selector};
    use tonic::Code;

    type Mutate = fn(&mut CreateSecretRequest);

    async fn enabled_state() -> Arc<ServerState> {
        let mut state = test_server_state().await;
        Arc::get_mut(&mut state)
            .expect("test state is not shared yet")
            .config
            .workspace_secrets
            .enabled = true;
        state
    }

    fn create_request(name: &str, value: &str) -> CreateSecretRequest {
        CreateSecretRequest {
            workspace_scope: Some(workspace_selector("default".to_string())),
            name: name.to_string(),
            description: "shared OAuth client secret".to_string(),
            value: value.to_string(),
            refresh_use: Some(SecretRefreshUse {
                allowed_endpoints: vec!["HTTPS://Login.Example.com:443/oauth/token".to_string()],
            }),
            labels: HashMap::from([("team".to_string(), "platform".to_string())]),
            request_id: String::new(),
        }
    }

    async fn create(state: &Arc<ServerState>, name: &str, value: &str) -> Secret {
        handle_create_secret(state, authed_request(create_request(name, value)))
            .await
            .expect("create secret")
            .into_inner()
            .secret
            .expect("secret")
    }

    async fn stored(state: &Arc<ServerState>, name: &str) -> Option<StoredWorkspaceSecret> {
        state
            .store
            .get_message_by_name::<StoredWorkspaceSecret>("default", name)
            .await
            .unwrap()
    }

    async fn resolve_value(
        state: &Arc<ServerState>,
        stored: &StoredWorkspaceSecret,
        handle: &CredentialHandle,
    ) -> Result<String, Status> {
        let resolved = state
            .credentials
            .resolve_secrets(owner(stored), &value_handles(handle.clone()), 0)
            .await?;
        resolved
            .values
            .get(SECRET_VALUE_KEY)
            .cloned()
            .ok_or_else(|| Status::not_found("value"))
    }

    #[tokio::test]
    async fn create_requires_operator_activation() {
        let state = test_server_state().await;
        let err = handle_create_secret(&state, authed_request(create_request("acme", "s3cret")))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("enable_workspace_secrets"));
        assert!(stored(&state, "acme").await.is_none());
    }

    #[tokio::test]
    async fn lifecycle_never_returns_the_value_and_rotates_handles() {
        let state = enabled_state().await;
        let created = create(&state, "acme", "first-value").await;
        let metadata = created.metadata.as_ref().unwrap();
        assert_eq!(metadata.name, "acme");
        assert_eq!(metadata.workspace, "default");
        assert_ne!(metadata.resource_version, 0);
        assert_eq!(
            created.refresh_use.as_ref().unwrap().allowed_endpoints,
            vec!["https://login.example.com/oauth/token".to_string()]
        );
        let encoded = format!("{created:?}");
        assert!(!encoded.contains("first-value"));

        let record = stored(&state, "acme").await.unwrap();
        let first_handle = record.value_handle.clone().unwrap();
        assert_eq!(
            resolve_value(&state, &record, &first_handle).await.unwrap(),
            "first-value"
        );

        let fetched = handle_get_secret(
            &state,
            authed_request(GetSecretRequest {
                workspace_scope: Some(workspace_selector("default".to_string())),
                name: "acme".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .secret
        .unwrap();
        assert_eq!(fetched, created);

        let updated = handle_update_secret(
            &state,
            authed_request(UpdateSecretRequest {
                workspace_scope: Some(workspace_selector("default".to_string())),
                name: "acme".to_string(),
                value: Some("second-value".to_string()),
                description: None,
                labels: Some(SecretLabels {
                    labels: HashMap::new(),
                }),
                expected_resource_version: Some(metadata.resource_version),
                request_id: String::new(),
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .secret
        .unwrap();
        let record = stored(&state, "acme").await.unwrap();
        assert_eq!(
            updated.metadata.as_ref().unwrap().resource_version,
            record.get_resource_version(),
            "the response reports the record after handle cleanup"
        );
        assert!(record.pending_handle_deletions.is_empty());
        assert!(updated.metadata.as_ref().unwrap().labels.is_empty());
        assert_eq!(updated.description, "shared OAuth client secret");
        let second_handle = record.value_handle.clone().unwrap();
        assert_ne!(first_handle, second_handle);
        assert_eq!(
            resolve_value(&state, &record, &second_handle)
                .await
                .unwrap(),
            "second-value"
        );
        assert!(
            resolve_value(&state, &record, &first_handle).await.is_err(),
            "the superseded value is deleted from credential storage"
        );

        let listed = handle_list_secrets(
            &state,
            authed_request(ListSecretsRequest {
                workspace_scope: Some(workspace_selector("default".to_string())),
                page_size: 0,
                page_token: String::new(),
                label_selector: String::new(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(listed.secrets, vec![updated]);

        let delete = |allow_missing| {
            handle_delete_secret(
                &state,
                authed_request(DeleteSecretRequest {
                    workspace_scope: Some(workspace_selector("default".to_string())),
                    name: "acme".to_string(),
                    allow_missing,
                    request_id: String::new(),
                }),
            )
        };
        assert_eq!(
            delete(false).await.unwrap().into_inner().outcome(),
            DeletionOutcome::Completed
        );
        assert!(stored(&state, "acme").await.is_none());
        assert!(
            resolve_value(&state, &record, &second_handle)
                .await
                .is_err()
        );
        assert_eq!(delete(false).await.unwrap_err().code(), Code::NotFound);
        assert_eq!(
            delete(true).await.unwrap().into_inner().outcome(),
            DeletionOutcome::AlreadyAbsent
        );
    }

    #[tokio::test]
    async fn create_rejects_invalid_input_before_storing_anything() {
        let state = enabled_state().await;
        let cases: [(&str, Mutate); 5] = [
            ("empty value", |req| req.value.clear()),
            ("refresh use without endpoints", |req| {
                req.refresh_use = Some(SecretRefreshUse::default());
            }),
            ("non-loopback http", |req| {
                req.refresh_use = Some(SecretRefreshUse {
                    allowed_endpoints: vec!["http://login.example.com/token".to_string()],
                });
            }),
            ("query string", |req| {
                req.refresh_use = Some(SecretRefreshUse {
                    allowed_endpoints: vec!["https://login.example.com/token?a=b".to_string()],
                });
            }),
            ("invalid name", |req| req.name = "Not_A_Label".to_string()),
        ];
        for (case, mutate) in cases {
            let mut request = create_request("acme", "value");
            mutate(&mut request);
            let err = handle_create_secret(&state, authed_request(request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument, "{case}");
        }
        assert!(stored(&state, "acme").await.is_none());
    }

    #[tokio::test]
    async fn duplicate_names_are_rejected() {
        let state = enabled_state().await;
        create(&state, "acme", "value").await;
        let err = handle_create_secret(&state, authed_request(create_request("acme", "other")))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::AlreadyExists);
    }

    #[tokio::test]
    async fn update_rejects_stale_versions_and_empty_values() {
        let state = enabled_state().await;
        let created = create(&state, "acme", "value").await;
        let version = created.metadata.unwrap().resource_version;
        let update = |value: Option<&str>, expected| {
            handle_update_secret(
                &state,
                authed_request(UpdateSecretRequest {
                    workspace_scope: Some(workspace_selector("default".to_string())),
                    name: "acme".to_string(),
                    value: value.map(str::to_string),
                    description: None,
                    labels: None,
                    expected_resource_version: expected,
                    request_id: String::new(),
                }),
            )
        };
        let err = update(Some("next"), Some(version + 10)).await.unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        let err = update(Some(""), None).await.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        let unchanged = update(None, None)
            .await
            .unwrap()
            .into_inner()
            .secret
            .unwrap();
        assert_eq!(unchanged.metadata.unwrap().resource_version, version);
    }

    #[tokio::test]
    async fn sweep_finishes_an_interrupted_deletion() {
        let state = enabled_state().await;
        create(&state, "acme", "value").await;
        let record = stored(&state, "acme").await.unwrap();
        let handle = record.value_handle.clone().unwrap();
        let tombstoned = tombstone(&state, record).await.unwrap();
        assert!(tombstoned.value_handle.is_none());
        assert_eq!(tombstoned.pending_handle_deletions, vec![handle.clone()]);

        // A tombstoned secret is invisible to reads.
        assert!(
            get_live_secret(&state.store, "default", "acme")
                .await
                .unwrap()
                .is_none()
        );

        assert_eq!(sweep_workspace_secrets(&state).await.unwrap(), 1);
        assert!(stored(&state, "acme").await.is_none());
        assert!(resolve_value(&state, &tombstoned, &handle).await.is_err());
    }

    fn oidc_config(scopes_claim: &str) -> openshell_core::OidcConfig {
        openshell_core::OidcConfig {
            issuer: "https://issuer.example.com".to_string(),
            ca_bundle: None,
            dangerously_allow_insecure_http: false,
            jwks_allowed_origins: Vec::new(),
            audience: "openshell".to_string(),
            jwks_ttl_secs: 3600,
            roles_claim: "roles".to_string(),
            admin_role: String::new(),
            user_role: String::new(),
            scopes_claim: scopes_claim.to_string(),
        }
    }

    async fn reveal_state(scopes_claim: Option<&str>) -> Arc<ServerState> {
        let mut state = enabled_state().await;
        create(&state, "acme", "the-value").await;
        let config = &mut Arc::get_mut(&mut state)
            .expect("test state is not shared yet")
            .config;
        config.workspace_secrets.reveal_enabled = true;
        config.oidc = scopes_claim.map(oidc_config);
        state
    }

    fn user(provider: IdentityProvider, scopes: &[&str]) -> Principal {
        Principal::User(crate::auth::principal::UserPrincipal {
            identity: crate::auth::identity::Identity {
                subject: "occ".to_string(),
                display_name: None,
                roles: vec!["openshell-admin".to_string()],
                scopes: scopes.iter().map(ToString::to_string).collect(),
                provider,
            },
        })
    }

    async fn reveal(state: &Arc<ServerState>, principal: Principal) -> Result<String, Status> {
        let mut request = Request::new(RevealSecretRequest {
            workspace_scope: Some(workspace_selector("default".to_string())),
            name: "acme".to_string(),
        });
        request.extensions_mut().insert(principal);
        handle_reveal_secret(state, request)
            .await
            .map(|response| response.into_inner().value)
    }

    fn operator() -> Principal {
        Principal::Operator(crate::auth::principal::OperatorPrincipal {
            identity: crate::auth::identity::Identity {
                subject: "operator".to_string(),
                display_name: None,
                roles: vec!["operator".to_string()],
                scopes: Vec::new(),
                provider: IdentityProvider::Mtls,
            },
            certificate_sha256: "00".to_string(),
        })
    }

    #[tokio::test]
    async fn reveal_is_disabled_by_default() {
        let mut state = reveal_state(Some("scope")).await;
        Arc::get_mut(&mut state)
            .expect("test state is not shared")
            .config
            .workspace_secrets
            .reveal_enabled = false;
        let err = reveal(&state, operator()).await.unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        // A caller who may not reveal learns nothing about the setting.
        let err = reveal(&state, user(IdentityProvider::Oidc, &["openshell:all"]))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
    }

    #[tokio::test]
    async fn only_mtls_operators_may_reveal() {
        // Even a scope-enforcing OIDC gateway grants users no reveal access.
        let state = reveal_state(Some("scope")).await;
        assert_eq!(reveal(&state, operator()).await.unwrap(), "the-value");
        for principal in [
            user(IdentityProvider::Oidc, &["secret:reveal"]),
            user(IdentityProvider::Oidc, &["openshell:all"]),
            user(IdentityProvider::Mtls, &[]),
            user(IdentityProvider::LocalDev, &[]),
        ] {
            assert_eq!(
                reveal(&state, principal).await.unwrap_err().code(),
                Code::PermissionDenied
            );
        }
    }

    #[tokio::test]
    async fn a_create_racing_workspace_deletion_leaves_nothing_behind() {
        use openshell_core::proto::{CreateWorkspaceRequest, DeleteWorkspaceRequest};
        let state = enabled_state().await;
        super::super::workspace::handle_create_workspace(
            &state,
            Request::new(CreateWorkspaceRequest {
                request_id: String::new(),
                name: "team".to_string(),
                labels: HashMap::new(),
            }),
        )
        .await
        .unwrap();
        let baseline = state.credentials.stored_credential_count();

        // Pause the create after its activity check, while it stages the value.
        let (entered, release) = state.credentials.gate_next_store();
        let creator = Arc::clone(&state);
        let create = tokio::spawn(async move {
            let mut request = create_request("acme", "value");
            request.workspace_scope = Some(workspace_selector("team".to_string()));
            handle_create_secret(&creator, authed_request(request)).await
        });
        entered.await.unwrap();
        // The scan finds no secret yet, so the deletion completes.
        super::super::workspace::handle_delete_workspace(
            &state,
            Request::new(DeleteWorkspaceRequest {
                request_id: String::new(),
                allow_missing: false,
                name: "team".to_string(),
            }),
        )
        .await
        .expect("workspace deletion completes");
        release.send(()).unwrap();

        let err = create.await.unwrap().unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(
            state
                .store
                .get_message_by_name::<StoredWorkspaceSecret>("team", "acme")
                .await
                .unwrap()
                .is_none(),
            "no secret row outlives the workspace"
        );
        assert_eq!(
            state.credentials.stored_credential_count(),
            baseline,
            "the staged value is discarded"
        );
    }

    #[tokio::test]
    async fn sweep_reaches_pending_cleanup_behind_a_full_page_of_healthy_secrets() {
        let state = enabled_state().await;
        for index in 0..SWEEP_PAGE_SIZE {
            let healthy = StoredWorkspaceSecret {
                metadata: Some(ObjectMeta {
                    id: format!("healthy-{index:04}"),
                    name: format!("healthy-{index:04}"),
                    // Another workspace, so the pending secret stays under
                    // the per-workspace quota. The sweep covers every workspace.
                    workspace: "elsewhere".to_string(),
                    ..ObjectMeta::default()
                }),
                ..Default::default()
            };
            state.store.put_message(&healthy).await.unwrap();
        }
        create(&state, "zzz-pending", "value").await;
        let record = stored(&state, "zzz-pending").await.unwrap();
        tombstone(&state, record).await.unwrap();

        assert_eq!(sweep_workspace_secrets(&state).await.unwrap(), 1);
        assert!(stored(&state, "zzz-pending").await.is_none());
    }

    #[tokio::test]
    async fn an_unfinished_deletion_stays_visible_and_frees_its_name_on_recreate() {
        let state = enabled_state().await;
        create(&state, "acme", "value").await;
        let record = stored(&state, "acme").await.unwrap();
        tombstone(&state, record).await.unwrap();

        let fetched = handle_get_secret(
            &state,
            authed_request(GetSecretRequest {
                workspace_scope: Some(workspace_selector("default".to_string())),
                name: "acme".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .secret
        .unwrap();
        assert!(fetched.metadata.as_ref().unwrap().deletion_time.is_some());
        let listed = handle_list_secrets(
            &state,
            authed_request(ListSecretsRequest {
                workspace_scope: Some(workspace_selector("default".to_string())),
                page_size: 1,
                page_token: String::new(),
                label_selector: String::new(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(listed.secrets.len(), 1, "pages are not shortened");

        let err = handle_update_secret(
            &state,
            authed_request(UpdateSecretRequest {
                workspace_scope: Some(workspace_selector("default".to_string())),
                name: "acme".to_string(),
                value: Some("next".to_string()),
                ..Default::default()
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("being deleted"));

        // Recreating the name finishes the earlier deletion first.
        let recreated = create(&state, "acme", "fresh").await;
        assert!(recreated.metadata.unwrap().deletion_time.is_none());
    }

    #[tokio::test]
    async fn a_secret_without_refresh_use_is_reveal_only() {
        let state = enabled_state().await;
        let mut request = create_request("signing-key", "value");
        request.refresh_use = None;
        let created = handle_create_secret(&state, authed_request(request))
            .await
            .expect("create a reveal-only secret")
            .into_inner()
            .secret
            .unwrap();
        assert!(created.refresh_use.is_none());
        assert!(
            stored(&state, "signing-key")
                .await
                .unwrap()
                .refresh_use
                .is_none()
        );
    }

    async fn create_workspace(state: &Arc<ServerState>, name: &str) -> String {
        use openshell_core::proto::CreateWorkspaceRequest;
        super::super::workspace::handle_create_workspace(
            state,
            Request::new(CreateWorkspaceRequest {
                request_id: String::new(),
                name: name.to_string(),
                labels: HashMap::new(),
            }),
        )
        .await
        .unwrap();
        active_workspace_id(&state.store, name).await.unwrap()
    }

    async fn delete_workspace(state: &Arc<ServerState>, name: &str) -> Result<(), Status> {
        use openshell_core::proto::DeleteWorkspaceRequest;
        super::super::workspace::handle_delete_workspace(
            state,
            Request::new(DeleteWorkspaceRequest {
                request_id: String::new(),
                allow_missing: false,
                name: name.to_string(),
            }),
        )
        .await
        .map(|_| ())
    }

    /// The record a create leaves behind when the gateway exits between its
    /// insert and its publication.
    async fn crashed_create(
        state: &Arc<ServerState>,
        workspace: &str,
        workspace_id: &str,
        pending_since_ms: i64,
    ) -> StoredWorkspaceSecret {
        let id = uuid::Uuid::new_v4().to_string();
        let handle = stage_value(state, workspace, &id, "orphaned")
            .await
            .unwrap();
        let stored = StoredWorkspaceSecret {
            metadata: Some(ObjectMeta {
                id,
                name: "acme".to_string(),
                workspace: workspace.to_string(),
                ..ObjectMeta::default()
            }),
            value_handle: Some(handle),
            workspace_id: workspace_id.to_string(),
            create_pending_since: openshell_core::time::timestamp_from_millis(pending_since_ms)
                .ok(),
            ..Default::default()
        };
        state.store.put_message(&stored).await.unwrap();
        stored
    }

    fn get_request(workspace: &str) -> GetSecretRequest {
        GetSecretRequest {
            workspace_scope: Some(workspace_selector(workspace.to_string())),
            name: "acme".to_string(),
        }
    }

    #[tokio::test]
    async fn a_create_that_never_published_blocks_deletion_until_swept() {
        let state = enabled_state().await;
        let workspace_id = create_workspace(&state, "team").await;
        let baseline = state.credentials.stored_credential_count();
        let pending = crashed_create(&state, "team", &workspace_id, current_time_ms()).await;
        assert_eq!(
            state.credentials.stored_credential_count(),
            baseline.map(|count| count + 1)
        );

        // Invisible to reads. While fresh it may still be in flight, so the
        // sweep keeps it.
        let err = handle_get_secret(&state, authed_request(get_request("team")))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::NotFound);
        assert!(
            get_live_secret(&state.store, "team", "acme")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(sweep_workspace_secrets(&state).await.unwrap(), 0);
        drop(pending);

        // The workspace cannot be deleted under it. The attempt leaves the
        // workspace terminating, so the create can never publish, and the
        // sweep discards the record and its value.
        let err = delete_workspace(&state, "team").await.unwrap_err();
        assert!(err.message().contains("secret"), "{}", err.message());
        assert_eq!(sweep_workspace_secrets(&state).await.unwrap(), 1);
        assert_eq!(state.credentials.stored_credential_count(), baseline);
        delete_workspace(&state, "team")
            .await
            .expect("nothing blocks deletion now");
    }

    #[tokio::test]
    async fn the_sweep_discards_a_stale_pending_create_in_an_active_workspace() {
        let state = enabled_state().await;
        let workspace_id = active_workspace_id(&state.store, "default").await.unwrap();
        let baseline = state.credentials.stored_credential_count();
        crashed_create(
            &state,
            "default",
            &workspace_id,
            current_time_ms() - PENDING_CREATE_TIMEOUT_MS - 1,
        )
        .await;
        assert_eq!(sweep_workspace_secrets(&state).await.unwrap(), 1);
        assert_eq!(state.credentials.stored_credential_count(), baseline);
        assert!(stored(&state, "acme").await.is_none());
    }

    #[tokio::test]
    async fn a_crashed_create_is_never_inherited_by_a_recreated_workspace() {
        let state = enabled_state().await;
        let old_id = create_workspace(&state, "team").await;
        delete_workspace(&state, "team").await.unwrap();
        let new_id = create_workspace(&state, "team").await;
        assert_ne!(old_id, new_id);
        let baseline = state.credentials.stored_credential_count();
        // The create had resolved the old workspace, then the gateway exited.
        crashed_create(&state, "team", &old_id, current_time_ms()).await;

        let err = handle_get_secret(&state, authed_request(get_request("team")))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::NotFound, "the new workspace sees nothing");

        // Its workspace is gone, so the sweep discards it at once.
        assert_eq!(sweep_workspace_secrets(&state).await.unwrap(), 1);
        assert_eq!(state.credentials.stored_credential_count(), baseline);
        assert!(stored_in(&state, "team", "acme").await.is_none());
    }

    #[tokio::test]
    async fn create_reuses_a_name_only_from_an_abandoned_pending_create() {
        let state = enabled_state().await;
        let workspace_id = create_workspace(&state, "team").await;
        let pending = crashed_create(&state, "team", &workspace_id, current_time_ms()).await;
        let mut request = create_request("acme", "value");
        request.workspace_scope = Some(workspace_selector("team".to_string()));

        let err = handle_create_secret(&state, authed_request(request.clone()))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("being created"));

        let mut abandoned = pending;
        abandoned.create_pending_since = openshell_core::time::timestamp_from_millis(
            current_time_ms() - PENDING_CREATE_TIMEOUT_MS - 1,
        )
        .ok();
        state.store.put_message(&abandoned).await.unwrap();
        let created = handle_create_secret(&state, authed_request(request))
            .await
            .expect("an abandoned create frees the name")
            .into_inner()
            .secret
            .unwrap();
        let record = stored_in(&state, "team", "acme").await.unwrap();
        assert!(
            record.create_pending_since.is_none(),
            "the create published"
        );
        assert_eq!(
            created.metadata.unwrap().resource_version,
            record.get_resource_version()
        );
    }

    async fn stored_in(
        state: &Arc<ServerState>,
        workspace: &str,
        name: &str,
    ) -> Option<StoredWorkspaceSecret> {
        state
            .store
            .get_message_by_name::<StoredWorkspaceSecret>(workspace, name)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_cleanup_that_loses_to_publication_keeps_the_value() {
        let state = enabled_state().await;
        let workspace_id = create_workspace(&state, "team").await;
        crashed_create(&state, "team", &workspace_id, current_time_ms()).await;
        // The sweep read this snapshot and judged the record abandoned...
        let snapshot = stored_in(&state, "team", "acme").await.unwrap();
        // ...and then the creator published.
        let mut published = snapshot.clone();
        published.create_pending_since = None;
        state
            .store
            .put_if(
                StoredWorkspaceSecret::object_type(),
                published.object_id(),
                published.object_name(),
                "team",
                &published.encode_to_vec(),
                None,
                WriteCondition::MatchResourceVersion(snapshot.get_resource_version()),
            )
            .await
            .unwrap();

        assert!(
            !discard_pending_create(&state, snapshot).await.unwrap(),
            "the claim loses to the publication"
        );
        let live = get_live_secret(&state.store, "team", "acme")
            .await
            .unwrap()
            .expect("the published secret survives");
        let handle = live.value_handle.clone().unwrap();
        assert_eq!(
            resolve_value(&state, &live, &handle).await.unwrap(),
            "orphaned",
            "its value was not deleted"
        );
    }

    #[test]
    fn pending_fate_defers_when_the_workspace_cannot_be_read() {
        let fresh = StoredWorkspaceSecret {
            workspace_id: "ws-1".to_string(),
            create_pending_since: openshell_core::time::timestamp_from_millis(current_time_ms())
                .ok(),
            ..Default::default()
        };
        assert_eq!(
            pending_fate(&fresh, Err(Status::unavailable("database down"))),
            PendingFate::Defer
        );
        assert_eq!(
            pending_fate(&fresh, Ok(Some("ws-1".into()))),
            PendingFate::Keep
        );
        assert_eq!(
            pending_fate(&fresh, Ok(Some("ws-2".into()))),
            PendingFate::Discard
        );
        assert_eq!(pending_fate(&fresh, Ok(None)), PendingFate::Discard);

        let stale = StoredWorkspaceSecret {
            create_pending_since: openshell_core::time::timestamp_from_millis(
                current_time_ms() - PENDING_CREATE_TIMEOUT_MS - 1,
            )
            .ok(),
            ..fresh
        };
        assert_eq!(
            pending_fate(&stale, Err(Status::unavailable("database down"))),
            PendingFate::Discard,
            "staleness does not depend on the workspace"
        );
    }

    #[tokio::test]
    async fn a_create_never_publishes_into_a_replacement_workspace() {
        let state = enabled_state().await;
        create_workspace(&state, "team").await;
        let baseline = state.credentials.stored_credential_count();

        let (entered, release) = state.credentials.gate_next_store();
        let creator = Arc::clone(&state);
        let create = tokio::spawn(async move {
            let mut request = create_request("acme", "value");
            request.workspace_scope = Some(workspace_selector("team".to_string()));
            handle_create_secret(&creator, authed_request(request)).await
        });
        entered.await.unwrap();
        // Replace the workspace the create was authorized against.
        delete_workspace(&state, "team").await.unwrap();
        create_workspace(&state, "team").await;
        release.send(()).unwrap();

        let err = create.await.unwrap().unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(stored_in(&state, "team", "acme").await.is_none());
        assert_eq!(state.credentials.stored_credential_count(), baseline);
    }
}
