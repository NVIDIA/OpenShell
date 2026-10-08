// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Privileged export of selected runtime credentials, not raw storage access.

#![allow(clippy::result_large_err)]

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use openshell_core::ObjectId;
use openshell_core::proto::{
    GetProviderCredentialsRequest, GetProviderCredentialsResponse, Provider,
    ProviderCredentialRefreshRecoveryAction, ProviderCredentialRefreshStrategy,
    ProviderCredentialValue,
};
use tonic::{Request, Response, Status};

use crate::ServerState;
use crate::storage_proto::StoredProviderCredentialRefreshStateV2;

#[cfg(test)]
#[path = "provider_credentials_tests.rs"]
mod tests;

const MAX_KEYS: usize = 32;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const DEFAULT_LIFETIME: Duration = Duration::from_mins(5);
const MAX_LIFETIME: Duration = Duration::from_hours(24);

#[derive(Default)]
struct RefreshAudit {
    attempts: usize,
    completed: usize,
}

pub(super) async fn handle(
    state: &Arc<ServerState>,
    request: Request<GetProviderCredentialsRequest>,
) -> Result<Response<GetProviderCredentialsResponse>, Status> {
    let operator = crate::auth::guard::require_operator(&request)?;
    let subject = operator.identity.subject.clone();
    let fingerprint = operator.certificate_sha256.clone();
    let request = request.into_inner();
    // Validate before logging selectors: a malformed key could contain a value.
    let selection =
        crate::auth::workspace_authz::selected_workspace_name(request.workspace_scope.as_ref())
            .and_then(|workspace| validate(&request).map(|lifetime| (workspace, lifetime)));
    let (workspace, lifetime) = match selection {
        Ok(selection) => selection,
        Err(error) => {
            tracing::info!(operator_subject = %subject, certificate_sha256 = %fingerprint,
                outcome = "invalid_request", status = ?error.code(), "operator provider credential retrieval");
            return Err(error);
        }
    };
    // Admission survives RPC cancellation, while completion records the refresh
    // effects even if the final all-or-nothing delivery fails.
    tracing::info!(
        operator_subject = %subject,
        certificate_sha256 = %fingerprint,
        workspace,
        provider = %request.name,
        credential_keys = ?request.credential_keys,
        outcome = "requested",
        "operator provider credential retrieval"
    );
    let mut refresh_audit = RefreshAudit::default();
    let result = retrieve(state, workspace, &request, lifetime, &mut refresh_audit).await;
    tracing::info!(
        operator_subject = %subject,
        certificate_sha256 = %fingerprint,
        workspace,
        provider = %request.name,
        credential_keys = ?request.credential_keys,
        outcome = if result.is_ok() { "delivered" } else { "failed" },
        refresh_attempts = refresh_audit.attempts,
        refresh_completed = refresh_audit.completed,
        "operator provider credential retrieval"
    );
    result.map(Response::new)
}

fn validate(request: &GetProviderCredentialsRequest) -> Result<Duration, Status> {
    if request.name.is_empty() || request.name.trim() != request.name || request.name.len() > 253 {
        return Err(Status::invalid_argument(
            "canonical provider name is required",
        ));
    }
    if request.credential_keys.is_empty() || request.credential_keys.len() > MAX_KEYS {
        return Err(Status::invalid_argument(
            "select between 1 and 32 runtime credential keys",
        ));
    }
    let mut seen = HashSet::new();
    for key in &request.credential_keys {
        if key.len() > 256 || !super::provider::is_valid_env_key(key) || !seen.insert(key) {
            return Err(Status::invalid_argument(
                "credential keys must be unique runtime environment keys",
            ));
        }
    }
    let lifetime = request
        .minimum_remaining_lifetime
        .as_ref()
        .map(openshell_core::time::duration_to_std)
        .transpose()
        .map_err(|_| Status::invalid_argument("invalid minimum_remaining_lifetime"))?
        .filter(|duration| !duration.is_zero())
        .unwrap_or(DEFAULT_LIFETIME);
    if lifetime > MAX_LIFETIME {
        return Err(Status::invalid_argument(
            "minimum_remaining_lifetime exceeds 24 hours",
        ));
    }
    Ok(lifetime)
}

async fn load(state: &ServerState, workspace: &str, name: &str) -> Result<Provider, Status> {
    state
        .store
        .get_message_by_name::<Provider>(workspace, name)
        .await
        .map_err(|_| Status::internal("provider lookup failed"))?
        .ok_or_else(|| Status::not_found("provider not found"))
}

fn sanitize(error: Status) -> Status {
    // Driver diagnostics may contain backend details. Never propagate them to
    // the public export API, or attach them to its audit record.
    Status::new(
        error.code(),
        "runtime credential retrieval failed; inspect provider refresh status",
    )
}

async fn retrieve(
    state: &ServerState,
    workspace: &str,
    request: &GetProviderCredentialsRequest,
    lifetime: Duration,
    refresh_audit: &mut RefreshAudit,
) -> Result<GetProviderCredentialsResponse, Status> {
    let provider = load(state, workspace, &request.name).await?;
    let catalog = state
        .provider_profile_sources
        .snapshot_catalog(state.store.as_ref(), workspace)
        .await
        .map_err(sanitize)?;
    let profile = super::provider::get_provider_type_profile_for_scope(
        &catalog,
        &provider.r#type,
        &provider.profile_workspace,
    )
    .ok_or_else(|| {
        Status::failed_precondition("provider has no supported runtime credential profile")
    })?
    .to_proto();
    let broker_keys = super::provider::broker_only_provider_credential_keys(&profile);
    // Prevalidate the entire selection before resolving secrets or minting.
    for key in &request.credential_keys {
        let declaration = profile
            .credentials
            .iter()
            .find(|credential| credential.env_vars.contains(key));
        if broker_keys.contains(key)
            || super::provider::is_non_injectable_provider_credential(&provider, key)
            || declaration.is_none()
            || declaration.is_some_and(|credential| credential.token_grant.is_some())
        {
            return Err(Status::failed_precondition(
                "selected key is not an exportable static or gateway-refresh-managed runtime credential",
            ));
        }
    }
    let refreshes = crate::provider_refresh::list_refresh_states_for_provider(
        state.store.as_ref(),
        provider.object_id(),
    )
    .await
    .map_err(sanitize)?;
    let mut owners = HashMap::new();
    for key in &request.credential_keys {
        let matching: Vec<_> = refreshes
            .iter()
            .filter(|refresh| {
                refresh.credential_key == *key
                    || refresh
                        .additional_output_keys
                        .values()
                        .any(|output| output == key)
            })
            .collect();
        if matching.len() > 1 {
            return Err(Status::failed_precondition(
                "runtime credential has ambiguous refresh ownership",
            ));
        }
        if let Some(refresh) = matching.first() {
            if refresh
                .metadata
                .as_ref()
                .is_some_and(|metadata| metadata.deletion_time.is_some())
            {
                return Err(Status::failed_precondition(
                    "credential refresh is being deleted",
                ));
            }
            owners.insert(key.clone(), (*refresh).clone());
        }
        if !provider.credentials.contains_key(key)
            && !provider.credential_handles.contains_key(key)
            && !owners.contains_key(key)
        {
            return Err(Status::not_found("selected runtime credential is missing"));
        }
    }
    // State and provider reads are not a transaction. Reload after observing
    // refresh generations so a just-completed mint is reused, not repeated
    // against an old provider snapshot paired with a new refresh generation.
    let initial_provider = load(state, workspace, &request.name).await?;
    if initial_provider.object_id() != provider.object_id()
        || initial_provider.r#type != provider.r#type
        || initial_provider.profile_workspace != provider.profile_workspace
    {
        return Err(Status::aborted("provider was replaced or reconfigured"));
    }
    // Resolve initial handles individually so NOT_FOUND can be attributed to
    // a refresh-owned output. A missing static handle or any other backend
    // error still fails closed, without exporting an inline fallback.
    let mut initial = HashMap::new();
    for key in &request.credential_keys {
        match resolve_selected(state, &initial_provider, std::slice::from_ref(key)).await {
            Ok(values) => initial.extend(values),
            Err(error) if error.code() == tonic::Code::NotFound && owners.contains_key(key) => {}
            Err(error) => return Err(error),
        }
    }
    let mut minted = HashSet::new();
    for key in &request.credential_keys {
        if sufficiently_valid(initial.get(key), lifetime)? {
            continue;
        }
        let refresh = owners.get(key).ok_or_else(|| {
            Status::failed_precondition("credential cannot meet the requested remaining lifetime")
        })?;
        ensure_refreshable(refresh)?;
        if minted.insert(refresh.object_id().to_string()) {
            refresh_audit.attempts += 1;
            crate::provider_refresh::refresh_from_snapshot(
                state.store.as_ref(),
                &state.credentials,
                Some(&state.compute),
                refresh.clone(),
            )
            .await
            .map_err(sanitize)?;
            refresh_audit.completed += 1;
        }
    }
    // Capture refresh generations before resolving the final provider snapshot.
    let mut delivery_owners = HashMap::new();
    for owner in owners.values() {
        let latest = crate::provider_refresh::get_refresh_state(
            state.store.as_ref(),
            workspace,
            provider.object_id(),
            &owner.credential_key,
        )
        .await
        .map_err(sanitize)?
        .ok_or_else(|| Status::aborted("credential refresh was deleted"))?;
        if latest.object_id() != owner.object_id()
            || crate::provider_refresh::effective_authorization_epoch(&latest)?
                != crate::provider_refresh::effective_authorization_epoch(owner)?
            || latest
                .metadata
                .as_ref()
                .is_some_and(|metadata| metadata.deletion_time.is_some())
            || matches!(
                latest.status.as_str(),
                "refresh_in_progress" | "refresh_committing"
            )
        {
            return Err(Status::aborted(
                "credential refresh changed during retrieval",
            ));
        }
        delivery_owners.insert(owner.credential_key.clone(), latest);
    }
    let current = load(state, workspace, &request.name).await?;
    if current.object_id() != provider.object_id()
        || current.r#type != provider.r#type
        || current.profile_workspace != provider.profile_workspace
    {
        return Err(Status::aborted("provider was replaced or reconfigured"));
    }
    // Fresh handles/expiration come from committed state, never transient minted values.
    let values = resolve_selected(state, &current, &request.credential_keys).await?;
    for key in &request.credential_keys {
        if !sufficiently_valid(values.get(key), lifetime)? {
            return Err(Status::failed_precondition(
                "credential cannot meet the requested remaining lifetime",
            ));
        }
    }
    let latest = load(state, workspace, &request.name).await?;
    if latest
        .metadata
        .as_ref()
        .map(|metadata| (&metadata.id, metadata.resource_version))
        != current
            .metadata
            .as_ref()
            .map(|metadata| (&metadata.id, metadata.resource_version))
    {
        return Err(Status::aborted(
            "provider changed during credential resolution",
        ));
    }
    // A refresh grant can be reconfigured without a provider update.
    for owner in delivery_owners.values() {
        let latest = crate::provider_refresh::get_refresh_state(
            state.store.as_ref(),
            workspace,
            current.object_id(),
            &owner.credential_key,
        )
        .await
        .map_err(sanitize)?
        .ok_or_else(|| Status::aborted("credential refresh was deleted"))?;
        if latest
            .metadata
            .as_ref()
            .map(|metadata| (&metadata.id, metadata.resource_version))
            != owner
                .metadata
                .as_ref()
                .map(|metadata| (&metadata.id, metadata.resource_version))
            || crate::provider_refresh::effective_authorization_epoch(&latest)?
                != crate::provider_refresh::effective_authorization_epoch(owner)?
            || latest
                .metadata
                .as_ref()
                .is_some_and(|metadata| metadata.deletion_time.is_some())
        {
            return Err(Status::aborted("credential refresh was reconfigured"));
        }
    }
    let latest_catalog = state
        .provider_profile_sources
        .snapshot_catalog(state.store.as_ref(), workspace)
        .await
        .map_err(sanitize)?;
    let latest_profile = super::provider::get_provider_type_profile_for_scope(
        &latest_catalog,
        &current.r#type,
        &current.profile_workspace,
    )
    .map(|profile| profile.to_proto());
    if latest_profile.as_ref() != Some(&profile) {
        return Err(Status::aborted(
            "provider credential declarations changed during retrieval",
        ));
    }
    if values
        .iter()
        .map(|(key, value)| key.len() + value.value.len() + 64)
        .sum::<usize>()
        > MAX_RESPONSE_BYTES
    {
        return Err(Status::resource_exhausted(
            "credential response exceeds 1 MiB",
        ));
    }
    // Recheck at delivery, after all driver and database round trips.
    for value in values.values() {
        if !sufficiently_valid(Some(value), lifetime)? {
            return Err(Status::failed_precondition(
                "credential lifetime elapsed during resolution",
            ));
        }
    }
    Ok(GetProviderCredentialsResponse {
        credentials: values,
    })
}

fn ensure_refreshable(refresh: &StoredProviderCredentialRefreshStateV2) -> Result<(), Status> {
    let strategy = ProviderCredentialRefreshStrategy::try_from(refresh.strategy)
        .unwrap_or(ProviderCredentialRefreshStrategy::Unspecified);
    if !matches!(
        strategy,
        ProviderCredentialRefreshStrategy::Oauth2RefreshToken
            | ProviderCredentialRefreshStrategy::Oauth2ClientCredentials
            | ProviderCredentialRefreshStrategy::GoogleServiceAccountJwt
            | ProviderCredentialRefreshStrategy::AwsStsAssumeRole
    ) {
        return Err(Status::failed_precondition(
            "credential has no gateway-managed minting strategy",
        ));
    }
    // Wait for an active mint through shared coordination. If its owner died,
    // the durable marker is still rejected after acquiring the distributed lock.
    if matches!(
        refresh.status.as_str(),
        "refresh_in_progress" | "refresh_committing"
    ) {
        return Ok(());
    }
    if matches!(
        ProviderCredentialRefreshRecoveryAction::try_from(refresh.recovery_action),
        Ok(ProviderCredentialRefreshRecoveryAction::Reauthorize
            | ProviderCredentialRefreshRecoveryAction::FixConfiguration
            | ProviderCredentialRefreshRecoveryAction::Investigate)
    ) {
        return Err(Status::failed_precondition(
            "credential refresh requires recovery",
        ));
    }
    if refresh.recovery_action == ProviderCredentialRefreshRecoveryAction::Retry as i32
        && refresh.next_refresh_at_ms > crate::persistence::current_time_ms()
    {
        return Err(Status::unavailable(
            "credential refresh is in retry backoff",
        ));
    }
    Ok(())
}

async fn resolve_selected(
    state: &ServerState,
    provider: &Provider,
    keys: &[String],
) -> Result<HashMap<String, ProviderCredentialValue>, Status> {
    let mut selected = provider.clone();
    selected
        .credential_handles
        .retain(|key, _| keys.contains(key));
    // Expired handle-backed credentials are omitted by the shared runtime and
    // consequently trigger refresh, or a failure for nonrefreshable credentials.
    let resolved = state
        .credentials
        .resolve_provider_handles(&selected, crate::persistence::current_time_ms())
        .await
        .map_err(sanitize)?;
    let mut result = HashMap::new();
    for key in keys {
        if provider.credential_handles.contains_key(key) {
            if let Some(value) = resolved.values.get(key) {
                result.insert(
                    key.clone(),
                    ProviderCredentialValue {
                        value: value.clone(),
                        expiration_time: resolved
                            .expires_at_ms
                            .get(key)
                            .map(|expiration| {
                                openshell_core::time::timestamp_from_millis(*expiration)
                            })
                            .transpose()
                            .map_err(|_| {
                                Status::failed_precondition("invalid credential expiration")
                            })?,
                    },
                );
            }
        } else if let Some(value) = provider.credentials.get(key) {
            result.insert(
                key.clone(),
                ProviderCredentialValue {
                    value: value.clone(),
                    expiration_time: provider.credential_expiration_times.get(key).copied(),
                },
            );
        }
    }
    Ok(result)
}

fn sufficiently_valid(
    value: Option<&ProviderCredentialValue>,
    lifetime: Duration,
) -> Result<bool, Status> {
    let Some(value) = value else {
        return Ok(false);
    };
    let Some(expiration) = value.expiration_time.as_ref() else {
        return Ok(true);
    };
    let expiration = openshell_core::time::timestamp_to_millis(expiration)
        .map_err(|_| Status::failed_precondition("invalid credential expiration"))?;
    let millis =
        lifetime.as_millis() + u128::from(!lifetime.subsec_nanos().is_multiple_of(1_000_000));
    let deadline = crate::persistence::current_time_ms()
        .checked_add(
            i64::try_from(millis)
                .map_err(|_| Status::invalid_argument("invalid remaining lifetime"))?,
        )
        .ok_or_else(|| Status::invalid_argument("invalid remaining lifetime"))?;
    Ok(expiration > deadline)
}
