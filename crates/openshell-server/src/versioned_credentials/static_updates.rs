// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provider-CAS-gated static updates. Markers contain only issuer references and
//! expected generations, never values or unprotected secret fingerprints.

use std::collections::HashMap;

use openshell_core::proto::{CredentialHandle, Provider};
use openshell_core::{ObjectId, ObjectName, ObjectWorkspace};
use openshell_credential_issuer::SecretOwner;
use openshell_credential_issuer::references::ReferenceProjection;
use openshell_credential_issuer::references::static_updates::{StaticReplacement, StaticUpdate};
use tonic::Status;

use super::VersionedCredentials;
use crate::persistence::ObjectListQuery;

pub const ANNOTATION: &str = "internal.openshell.ai/issuer-static-update";

pub struct PreparedStaticUpdate {
    pub marker: String,
    pub published_handles: HashMap<String, CredentialHandle>,
}

pub async fn prepare(
    versioned: &VersionedCredentials,
    owner: SecretOwner<'_>,
    staged: &HashMap<String, CredentialHandle>,
    existing: &HashMap<String, CredentialHandle>,
) -> Result<PreparedStaticUpdate, Status> {
    let mut keys: Vec<_> = staged.keys().collect();
    keys.sort();
    let mut published_handles = HashMap::new();
    let mut replacements = Vec::new();
    for key in keys {
        let staged_handle = &staged[key];
        let destination_handle = existing.get(key).unwrap_or(staged_handle);
        let destination = projection(destination_handle)?;
        let staged = projection(staged_handle)?;
        let expected_generation = versioned
            .references
            .manifest_generation(
                owner,
                &destination.epoch,
                &HashMap::from([(key.clone(), destination_handle.clone())]),
            )
            .await?;
        replacements.push(StaticReplacement {
            destination,
            staged,
            expected_generation,
        });
        published_handles.insert(key.clone(), destination_handle.clone());
    }
    let marker = serde_json::to_string(&StaticUpdate {
        operation_id: format!("provider-static-update:{}", uuid::Uuid::new_v4()),
        replacements,
    })
    .map_err(|_| Status::internal("encode static update marker failed"))?;
    Ok(PreparedStaticUpdate {
        marker,
        published_handles,
    })
}

fn projection(handle: &CredentialHandle) -> Result<ReferenceProjection, Status> {
    ReferenceProjection::from_handle(handle)?
        .ok_or_else(|| Status::failed_precondition("static update requires versioned binding"))
}

fn marker(provider: &Provider) -> Result<Option<StaticUpdate>, Status> {
    let Some(encoded) = provider
        .metadata
        .as_ref()
        .and_then(|meta| meta.annotations.get(ANNOTATION))
    else {
        return Ok(None);
    };
    let update: StaticUpdate = serde_json::from_str(encoded)
        .map_err(|_| Status::data_loss("invalid provider static update marker"))?;
    if update.replacements.is_empty() {
        return Err(Status::data_loss("empty provider static update marker"));
    }
    Ok(Some(update))
}

fn validate_mapping(provider: &Provider, update: &StaticUpdate) -> Result<(), Status> {
    for replacement in &update.replacements {
        let handle = provider
            .credential_handles
            .get(&replacement.destination.credential_key)
            .ok_or_else(|| Status::failed_precondition("provider static update binding changed"))?;
        if projection(handle)? != replacement.destination {
            return Err(Status::failed_precondition(
                "provider static update binding changed",
            ));
        }
    }
    Ok(())
}

/// Fail closed after provider CAS until the exact static activation is durable.
/// Completed markers remain as non-secret receipts; no extra provider CAS is
/// needed to clear them and no backend read is required to validate them.
pub async fn validate(versioned: &VersionedCredentials, provider: &Provider) -> Result<(), Status> {
    let Some(update) = marker(provider)? else {
        return Ok(());
    };
    let owner = SecretOwner::provider(
        provider.object_workspace(),
        provider.object_id(),
        provider.object_name(),
    );
    if !versioned
        .references
        .static_update_committed(owner, &update)
        .await?
    {
        return Err(Status::failed_precondition(
            "provider static update is pending activation",
        ));
    }
    Ok(())
}

/// Resume only the exact marker installed by the winning provider CAS. A
/// concurrent mutation must settle this transition before it can replace it.
pub async fn finish(versioned: &VersionedCredentials, provider: &Provider) -> Result<(), Status> {
    let Some(update) = marker(provider)? else {
        return Ok(());
    };
    let owner = SecretOwner::provider(
        provider.object_workspace(),
        provider.object_id(),
        provider.object_name(),
    );
    if versioned
        .references
        .static_update_committed(owner, &update)
        .await?
    {
        return Ok(());
    }
    let current = versioned
        .store
        .get_message::<Provider>(provider.object_id())
        .await
        .map_err(|_| Status::unavailable("read static update provider failed"))?
        .ok_or_else(|| Status::failed_precondition("static update provider was deleted"))?;
    if current.object_workspace() != provider.object_workspace()
        || current
            .metadata
            .as_ref()
            .and_then(|meta| meta.annotations.get(ANNOTATION))
            != provider
                .metadata
                .as_ref()
                .and_then(|meta| meta.annotations.get(ANNOTATION))
    {
        return Err(Status::aborted("provider static update marker changed"));
    }
    // Revalidate the durable destination mapping, not merely the caller copy.
    validate_mapping(&current, &update)?;
    let owner = SecretOwner::provider(
        current.object_workspace(),
        current.object_id(),
        current.object_name(),
    );
    versioned
        .references
        .activate_static_update(owner, &update)
        .await?;
    if let Err(error) = versioned.references.reclaim(owner, 16).await {
        tracing::warn!(code = ?error.code(), "static update cleanup remains pending");
    }
    Ok(())
}

/// Startup recovery never mints or requires plaintext request material.
pub async fn recover(versioned: &VersionedCredentials) -> Result<(), Status> {
    let providers: Vec<Provider> = versioned
        .store
        .collect_messages(ObjectListQuery::AllWorkspaces)
        .await
        .map_err(|_| Status::unavailable("list static update providers failed"))?;
    for provider in providers {
        finish(versioned, &provider).await?;
    }
    Ok(())
}
