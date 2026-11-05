// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded, maintenance-window adoption. The old refresh rows are frozen inputs,
//! never a second live journal. Every external write has a durable, non-secret
//! identity before I/O; every incompatible gateway switch follows the rollback
//! barrier and uses an exact resource-version CAS.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::sync::Arc;

use openshell_core::proto::{
    CredentialHandle, Provider, ProviderCredentialRefreshStrategy, Sandbox,
};
use openshell_core::{ObjectId, ObjectName, ObjectWorkspace};
use openshell_credential_issuer::references::{
    OwnerIdentity, ReferenceProjection, ReferenceRuntime,
};
use openshell_credential_issuer::refresh::{
    RefreshState, effective_authorization_epoch, persistence, refresh_has_expiration,
    refresh_material_scope, strategy_secret_material_keys,
};
use openshell_credential_issuer::{Handles, SecretOwner, StoreSecrets};
use prost::Message;
use serde::{Deserialize, Serialize};
use tonic::Status;

use super::{
    BindingTransition, VersionedCredentials, annotation_key, disabled_annotation_key, owner,
};
use crate::credential_activation::Activation;
use crate::credentials::CredentialRuntime;
use crate::persistence::{ObjectListQuery, ObjectRecord, WriteCondition};

const JOURNAL_TYPE: &str = "credential_issuer_migration_v1";
const MIGRATED: &str = "internal.openshell.ai/issuer-migrated-v1";
const GRANT_PREFIX: &str = "internal.openshell.ai/issuer-grant-";

// Keep the journal's handle representation independent of serde support on
// generated public messages. No value or unprotected secret fingerprint enters
// this record. Source identity is immutable during the operator-owned window.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema: u32,
    source: String,
    write_id: String,
    driver: String,
    keys: BTreeSet<String>,
    handles: Option<BTreeMap<String, Vec<u8>>>,
}

fn unavailable() -> Status {
    Status::unavailable("credential migration persistence unavailable")
}
fn corrupt() -> Status {
    Status::data_loss("invalid credential migration state")
}

fn identity(value: &impl Serialize) -> Result<String, Status> {
    let bytes = serde_json::to_vec(value).map_err(|_| corrupt())?;
    let hash = || {
        let mut digest = openshell_crypto::sha256_digest()?;
        digest.update(b"openshell/credential-migration/v1\0")?;
        digest.update(&bytes)?;
        digest.finish()
    };
    let bytes = hash().map_err(|_: openshell_crypto::CryptoError| {
        Status::internal("credential migration identity derivation failed")
    })?;
    let mut id = String::from("migration-");
    for byte in bytes {
        write!(&mut id, "{byte:02x}").expect("writing a String cannot fail");
    }
    Ok(id)
}

// Candidate rows compare their encoded handle bytes with the published row.
// Generated protobuf maps use HashMap iteration order, so canonicalize map
// entries using the generated message itself (no parallel durable schema).
fn handle_bytes(handle: &CredentialHandle) -> Vec<u8> {
    let mut bytes = CredentialHandle {
        driver: handle.driver.clone(),
        handle: handle.handle.clone(),
        metadata: HashMap::new(),
    }
    .encode_to_vec();
    let sorted_metadata = handle.metadata.iter().collect::<BTreeMap<_, _>>();
    for (key, value) in sorted_metadata {
        bytes.extend(
            CredentialHandle {
                metadata: HashMap::from([(key.clone(), value.clone())]),
                ..Default::default()
            }
            .encode_to_vec(),
        );
    }
    bytes
}

fn encode_handles(handles: &Handles) -> BTreeMap<String, Vec<u8>> {
    handles
        .iter()
        .map(|(key, handle)| (key.clone(), handle_bytes(handle)))
        .collect()
}
fn decode_handles(handles: &BTreeMap<String, Vec<u8>>) -> Result<Handles, Status> {
    handles
        .iter()
        .map(|(key, bytes)| {
            Ok((
                key.clone(),
                CredentialHandle::decode(bytes.as_slice()).map_err(|_| corrupt())?,
            ))
        })
        .collect()
}

async fn journal(
    versioned: &VersionedCredentials,
    source: String,
    keys: BTreeSet<String>,
    driver: &str,
) -> Result<(ObjectRecord, Journal), Status> {
    let id = identity(&source)?;
    if let Some(record) = versioned
        .store
        .get(JOURNAL_TYPE, &id)
        .await
        .map_err(|_| unavailable())?
    {
        let journal: Journal = serde_json::from_slice(&record.payload).map_err(|_| corrupt())?;
        if journal.schema != 1
            || journal.source != source
            || journal.keys != keys
            || journal.driver != driver
            || uuid::Uuid::parse_str(&journal.write_id).is_err()
        {
            return Err(Status::failed_precondition(
                "credential migration journal intent changed",
            ));
        }
        return Ok((record, journal));
    }
    let journal = Journal {
        schema: 1,
        source,
        write_id: uuid::Uuid::new_v4().to_string(),
        driver: driver.to_owned(),
        keys,
        handles: None,
    };
    let payload = serde_json::to_vec(&journal).map_err(|_| corrupt())?;
    versioned
        .store
        .put_if(
            JOURNAL_TYPE,
            &id,
            &id,
            "",
            &payload,
            None,
            WriteCondition::MustCreate,
        )
        .await
        .map_err(|_| unavailable())?;
    let record = versioned
        .store
        .get(JOURNAL_TYPE, &id)
        .await
        .map_err(|_| unavailable())?
        .ok_or_else(corrupt)?;
    Ok((record, journal))
}

async fn record_handles(
    versioned: &VersionedCredentials,
    record: &ObjectRecord,
    mut journal: Journal,
    handles: Handles,
) -> Result<Handles, Status> {
    if handles.keys().cloned().collect::<BTreeSet<_>>() != journal.keys {
        return Err(Status::failed_precondition(
            "credential migration backend omitted staged outputs",
        ));
    }
    journal.handles = Some(encode_handles(&handles));
    versioned
        .store
        .put_if(
            JOURNAL_TYPE,
            &record.id,
            &record.name,
            &record.workspace,
            &serde_json::to_vec(&journal).map_err(|_| corrupt())?,
            record.labels.as_deref(),
            WriteCondition::MatchResourceVersion(record.resource_version),
        )
        .await
        .map_err(|_| unavailable())?;
    Ok(handles)
}

async fn inline_provider(
    runtime: &CredentialRuntime,
    versioned: &VersionedCredentials,
    provider: &Provider,
) -> Result<Handles, Status> {
    if provider.credentials.is_empty() {
        return Ok(Handles::new());
    }
    let source = serde_json::to_string(&(
        "provider-inline",
        OwnerIdentity::of(provider_owner(provider)),
        provider
            .metadata
            .as_ref()
            .ok_or_else(corrupt)?
            .resource_version,
    ))
    .map_err(|_| corrupt())?;
    let (record, journal) = journal(
        versioned,
        source,
        provider.credentials.keys().cloned().collect(),
        runtime.storage_driver_name(),
    )
    .await?;
    if let Some(handles) = &journal.handles {
        return decode_handles(handles);
    }
    let handles = versioned
        .backend
        .store(StoreSecrets {
            owner: provider_owner(provider),
            object_id: Some(&journal.write_id),
            values: &provider.credentials,
            existing_handles: &Handles::new(),
        })
        .await?;
    record_handles(versioned, &record, journal, handles).await
}

async fn inline_material(
    runtime: &CredentialRuntime,
    versioned: &VersionedCredentials,
    state: &mut RefreshState,
) -> Result<(), Status> {
    versioned
        .backend
        .validate_handles(&state.secret_material_handles)?;
    for deletion in &state.pending_secret_deletions {
        if let Some(handle) = &deletion.handle {
            versioned.backend.validate_handles(&Handles::from([(
                deletion.material_key.clone(),
                handle.clone(),
            )]))?;
        }
    }
    if !state.secret_material_handles.is_empty()
        && state.status != "deleted"
        && state
            .metadata
            .as_ref()
            .is_some_and(|metadata| metadata.deletion_time.is_none())
    {
        let resolved = versioned
            .backend
            .resolve_refresh_material(
                refresh_material_scope(state),
                &state.secret_material_handles,
            )
            .await?;
        if resolved.len() != state.secret_material_handles.len()
            || state
                .secret_material_handles
                .keys()
                .any(|key| !resolved.contains_key(key))
        {
            return Err(Status::failed_precondition(
                "legacy refresh material backend values are missing",
            ));
        }
    }
    let mut keys: BTreeSet<String> = state.secret_material_keys.iter().cloned().collect();
    keys.extend(state.secret_material_handles.keys().cloned());
    keys.extend(
        strategy_secret_material_keys(
            ProviderCredentialRefreshStrategy::try_from(state.strategy)
                .unwrap_or(ProviderCredentialRefreshStrategy::Unspecified),
        )
        .iter()
        .map(|key| (*key).to_owned()),
    );
    let material: HashMap<_, _> = keys
        .iter()
        .filter_map(|key| {
            state
                .material
                .get(key)
                .map(|value| (key.clone(), value.clone()))
        })
        .collect();
    if material.is_empty() {
        return Ok(());
    }
    if material
        .keys()
        .any(|key| state.secret_material_handles.contains_key(key))
    {
        // Legacy resolution lets a handle override inline material. Preserve
        // that precedence; never overwrite a potentially rotated valid token.
        for key in state.secret_material_handles.keys() {
            state.material.remove(key);
        }
    }
    let material: HashMap<_, _> = material
        .into_iter()
        .filter(|(key, _)| !state.secret_material_handles.contains_key(key))
        .collect();
    if !material.is_empty() {
        let source = serde_json::to_string(&(
            "refresh-inline",
            OwnerIdentity::of(owner(state)),
            state.object_id(),
            state
                .metadata
                .as_ref()
                .ok_or_else(corrupt)?
                .resource_version,
        ))
        .map_err(|_| corrupt())?;
        let (record, journal) = journal(
            versioned,
            source,
            material.keys().cloned().collect(),
            runtime.storage_driver_name(),
        )
        .await?;
        let handles = if let Some(handles) = &journal.handles {
            decode_handles(handles)?
        } else {
            let handles = versioned
                .backend
                .store_refresh_material_with_object_id(
                    refresh_material_scope(state),
                    &journal.write_id,
                    &material,
                    &Handles::new(),
                )
                .await?;
            record_handles(versioned, &record, journal, handles).await?
        };
        state.secret_material_handles.extend(handles);
    }
    for key in keys {
        state.material.remove(&key);
    }
    Ok(())
}

fn provider_owner(provider: &Provider) -> SecretOwner<'_> {
    SecretOwner::provider(
        provider.object_workspace(),
        provider.object_id(),
        provider.object_name(),
    )
}

fn grant_expiration(state: &RefreshState) -> Result<Option<prost_types::Timestamp>, Status> {
    if refresh_has_expiration(state) {
        openshell_core::time::timestamp_from_millis(state.expires_at_ms)
            .map(Some)
            .map_err(|_| Status::data_loss("invalid legacy refresh expiration"))
    } else {
        Ok(None)
    }
}

/// Reconcile ONLY exact provider-bound preparations. This runs on every startup,
/// including after the global activation marker is complete. Frozen old rows
/// must never reimport a subsequently revoked/reconfigured authorization.
async fn recover_bindings(
    versioned: &VersionedCredentials,
    provider: &Provider,
    activation: &mut Activation,
) -> Result<(), Status> {
    let metadata = provider.metadata.as_ref().ok_or_else(corrupt)?;
    for (key, bytes) in &metadata.annotations {
        let disabling = key.starts_with("internal.openshell.ai/issuer-disabled-");
        if !disabling && !key.starts_with(GRANT_PREFIX) {
            continue;
        }
        let mut transition: BindingTransition =
            serde_json::from_str(bytes).map_err(|_| corrupt())?;
        // The startup lease does not exclude an already running compatible
        // replica's refresh. Reload the binding and journals under the same
        // credential lease used by refresh/configure/delete.
        let grant = versioned
            .references
            .get_grant(provider_owner(provider), &transition.grant_id)
            .await?
            .ok_or_else(|| Status::failed_precondition("provider-bound issuer grant is missing"))?;
        let observed = super::decode(
            &grant,
            &transition.grant_id,
            provider.object_workspace(),
            provider.object_id(),
        )?;
        let _lease = versioned
            .store
            .acquire_refresh_guard(provider.object_id(), &observed.credential_key)
            .await
            .map_err(|_| {
                Status::unavailable("credential binding recovery coordination unavailable")
            })?;
        let Some(mut current) = current_binding(versioned, provider, key, bytes).await? else {
            continue;
        };
        let grant = versioned
            .references
            .get_grant(provider_owner(&current), &transition.grant_id)
            .await?
            .ok_or_else(|| Status::failed_precondition("provider-bound issuer grant is missing"))?;
        let state = super::decode(
            &grant,
            &transition.grant_id,
            current.object_workspace(),
            current.object_id(),
        )?;
        if state.credential_key != observed.credential_key || grant.epoch != transition.epoch {
            return Err(corrupt());
        }
        if disabling {
            if disabled_annotation_key(&state.credential_key)? != *key {
                return Err(corrupt());
            }
            if state.status != "deleted" {
                activation.mark_irreversible().await?;
                let store: Arc<dyn openshell_credential_issuer::refresh::RefreshStateStore> =
                    Arc::new(versioned.clone());
                openshell_credential_issuer::refresh::engine::delete_observed_refresh_state_with_credentials(
                    &store, &versioned.backend, state).await?;
            }
            continue;
        }
        // Stale evidence cannot reactivate a revoked grant. Active journals
        // may already have advanced through arbitrary successful refreshes.
        if !grant.prepared {
            if grant.active {
                retire_references(versioned, provider_owner(&current), &transition, activation)
                    .await?;
            }
            continue;
        }
        if grant.active || grant.resource_version != transition.prepared_version {
            return Err(Status::failed_precondition(
                "provider-bound issuer preparation does not match",
            ));
        }
        if effective_authorization_epoch(&state)? != transition.epoch
            || annotation_key(&state.credential_key)? != *key
            || state.output_references.is_empty()
            || state
                .output_references
                .iter()
                .any(|(key, reference)| current.credential_handles.get(key) != Some(reference))
        {
            return Err(Status::failed_precondition(
                "prepared issuer grant differs from provider binding",
            ));
        }
        refresh_old_grant_expectation(
            versioned,
            &mut current,
            key,
            &state,
            &grant.epoch,
            &mut transition,
            activation,
        )
        .await?;
        let old = transition
            .old_grant_id
            .as_deref()
            .zip(transition.old_grant_version);
        activation.mark_irreversible().await?;
        versioned
            .references
            .activate_grant(
                provider_owner(&current),
                &transition.grant_id,
                transition.prepared_version,
                old,
            )
            .await?;
        retire_references(versioned, provider_owner(&current), &transition, activation).await?;
    }
    Ok(())
}

/// Inventory can become stale while another compatible replica configures or
/// deletes a provider. Startup is not authority to revive a losing preparation.
async fn current_binding(
    versioned: &VersionedCredentials,
    observed: &Provider,
    key: &str,
    encoded: &str,
) -> Result<Option<Provider>, Status> {
    let Some(current) = versioned
        .store
        .get_message::<Provider>(observed.object_id())
        .await
        .map_err(|_| unavailable())?
    else {
        return Ok(None);
    };
    if current.object_workspace() != observed.object_workspace()
        || current.object_id() != observed.object_id()
    {
        return Err(corrupt());
    }
    let metadata = current.metadata.as_ref().ok_or_else(corrupt)?;
    if metadata.deletion_time.is_some()
        || metadata.annotations.get(key).map(String::as_str) != Some(encoded)
    {
        return Ok(None);
    }
    Ok(Some(current))
}

/// Called only while holding the credential lease. Refresh bookkeeping may
/// advance an old grant after the provider switched to a new prepared binding.
/// Core IDs/epochs are immutable: reload ONLY that exact old identity, validate
/// its owner/key/epoch, then durably repair the expected version before activation.
async fn refresh_old_grant_expectation(
    versioned: &VersionedCredentials,
    provider: &mut Provider,
    annotation: &str,
    state: &RefreshState,
    new_epoch: &str,
    transition: &mut BindingTransition,
    activation: &mut Activation,
) -> Result<(), Status> {
    let (id, expected) = match (&transition.old_grant_id, transition.old_grant_version) {
        (Some(id), Some(expected)) => (id, expected),
        (None, None) => return Ok(()),
        _ => return Err(corrupt()),
    };
    let old = versioned
        .references
        .get_grant(provider_owner(provider), id)
        .await?
        .ok_or_else(|| Status::failed_precondition("old provider-bound issuer grant is missing"))?;
    let old_state = super::decode(&old, id, provider.object_workspace(), provider.object_id())?;
    if !old.active
        || old.prepared
        || old.epoch == new_epoch
        || effective_authorization_epoch(&old_state)? != old.epoch
        || old_state.credential_key != state.credential_key
        || old.resource_version < expected
    {
        return Err(Status::failed_precondition(
            "old issuer grant identity or epoch changed during binding recovery",
        ));
    }
    if old.resource_version != expected {
        transition.old_grant_version = Some(old.resource_version);
        // Persist the repaired operation intent first. Lost activation replies
        // must never require reusing one operation ID for a different old tuple.
        let metadata = provider.metadata.as_mut().ok_or_else(corrupt)?;
        metadata.annotations.insert(
            annotation.to_owned(),
            serde_json::to_string(transition).map_err(|_| corrupt())?,
        );
        let labels = if metadata.labels.is_empty() {
            None
        } else {
            Some(serde_json::to_string(&metadata.labels).map_err(|_| corrupt())?)
        };
        let expected_provider_version = metadata.resource_version;
        activation.mark_irreversible().await?;
        versioned
            .store
            .put_if(
                "provider",
                provider.object_id(),
                provider.object_name(),
                provider.object_workspace(),
                &provider.encode_to_vec(),
                labels.as_deref(),
                WriteCondition::MatchResourceVersion(expected_provider_version),
            )
            .await
            .map_err(|_| Status::aborted("provider binding changed during issuer recovery"))?;
    }
    Ok(())
}

async fn retire_references(
    versioned: &VersionedCredentials,
    owner: SecretOwner<'_>,
    transition: &BindingTransition,
    activation: &mut Activation,
) -> Result<(), Status> {
    if !transition.retired_references.is_empty() {
        let retired = decode_handles(&transition.retired_references)?;
        activation.mark_irreversible().await?;
        versioned.references.delete(owner, &retired).await?;
    }
    Ok(())
}

async fn migrate_provider(
    runtime: &CredentialRuntime,
    versioned: &VersionedCredentials,
    provider: Provider,
    states: &[RefreshState],
    activation: &mut Activation,
) -> Result<(), Status> {
    if provider
        .metadata
        .as_ref()
        .and_then(|m| m.annotations.get(MIGRATED))
        .is_some()
    {
        return Ok(());
    }
    let owner = provider_owner(&provider);
    let mut candidates = provider.credential_handles.clone();
    // A partially upgraded row can contain both: existing handle precedence is
    // retained. Inline-only values are staged without another plaintext copy.
    let inline = inline_provider(runtime, versioned, &provider).await?;
    for (key, handle) in inline {
        candidates.entry(key).or_insert(handle);
    }
    let mut next = provider.clone();
    let mut refresh_keys = BTreeSet::new();
    let mut transitions = Vec::new();
    for legacy in states {
        if legacy.status == "deleted"
            || legacy
                .metadata
                .as_ref()
                .is_some_and(|m| m.deletion_time.is_some())
        {
            continue;
        }
        if legacy.object_workspace() != provider.object_workspace()
            || legacy.provider_id != provider.object_id()
        {
            return Err(corrupt());
        }
        let mut state = legacy.clone();
        let epoch = effective_authorization_epoch(&state)?.to_owned();
        let mut keys = BTreeSet::from([state.credential_key.clone()]);
        keys.extend(state.additional_output_keys.values().cloned());
        if keys.len() != state.additional_output_keys.len() + 1
            || keys
                .iter()
                .any(|key| key.is_empty() || !refresh_keys.insert(key.clone()))
        {
            return Err(Status::failed_precondition(
                "legacy refresh output ownership overlaps",
            ));
        }
        let mut bundle: Handles = keys
            .iter()
            .filter_map(|key| {
                candidates
                    .get(key)
                    .map(|handle| (key.clone(), handle.clone()))
            })
            .collect();
        let projected = bundle
            .values()
            .map(ReferenceProjection::from_handle)
            .collect::<Result<Vec<_>, _>>()?;
        if projected.iter().any(Option::is_some) {
            return Err(Status::failed_precondition(
                "untracked legacy refresh contains issuer projections",
            ));
        }
        let operation = identity(&(
            "refresh-outputs",
            OwnerIdentity::of(owner),
            state.object_id(),
            &epoch,
        ))?;
        let missing: BTreeSet<_> = keys
            .iter()
            .filter(|key| !bundle.contains_key(*key))
            .cloned()
            .collect();
        if missing.is_empty() {
            state.output_references = versioned
                .references
                .adopt_with_expiration(
                    owner,
                    &epoch,
                    &bundle,
                    grant_expiration(&state)?,
                    &operation,
                )
                .await?;
        } else {
            // Validate every claimed existing backend value. A storage outage or
            // missing old object must not be disguised as a new pending output.
            if !bundle.is_empty() {
                let resolved = versioned.backend.resolve(owner, &bundle).await?;
                let resolved_keys: BTreeSet<_> = resolved
                    .iter()
                    .map(|value| value.credential_key.as_str())
                    .collect();
                if resolved_keys.len() != bundle.len()
                    || bundle
                        .keys()
                        .any(|key| !resolved_keys.contains(key.as_str()))
                {
                    return Err(Status::failed_precondition(
                        "legacy refresh backend outputs are missing",
                    ));
                }
            }
            let (record, journal) = journal(
                versioned,
                serde_json::to_string(&("pending-outputs", &operation)).map_err(|_| corrupt())?,
                missing.clone(),
                runtime.storage_driver_name(),
            )
            .await?;
            let pending = if let Some(handles) = &journal.handles {
                decode_handles(handles)?
            } else {
                let handles =
                    ReferenceRuntime::pending_handles(runtime.storage_driver_name(), missing)?;
                record_handles(versioned, &record, journal, handles).await?
            };
            bundle.extend(pending);
            // An incomplete fixed bundle stays pending atomically; it cannot
            // resolve a mixed/partial AWS generation. Its first mint is v1.
            state.output_references = versioned
                .references
                .prepare_bundle(owner, &epoch, &bundle, &operation)
                .await?;
        }
        state.reference_generation = versioned
            .references
            .manifest_generation(owner, &epoch, &state.output_references)
            .await?;
        inline_material(runtime, versioned, &mut state).await?;
        let prepared = versioned
            .references
            .prepare_grant(
                owner,
                state.object_id(),
                &epoch,
                &persistence::encode(&state)?,
            )
            .await?;
        let transition = BindingTransition {
            grant_id: state.object_id().to_owned(),
            prepared_version: prepared.resource_version,
            old_grant_id: None,
            old_grant_version: None,
            epoch,
            retired_references: BTreeMap::new(),
        };
        next.metadata
            .as_mut()
            .ok_or_else(corrupt)?
            .annotations
            .insert(
                annotation_key(&state.credential_key)?,
                serde_json::to_string(&transition).map_err(|_| corrupt())?,
            );
        for (key, reference) in &state.output_references {
            next.credential_handles
                .insert(key.clone(), reference.clone());
            next.credentials.remove(key);
            // Only a timestamp equal to the legacy refresh's copied expiry is
            // refresh-owned. An independently authored limit remains enforced.
            if next.credential_expiration_times.get(key) == grant_expiration(&state)?.as_ref() {
                next.credential_expiration_times.remove(key);
            }
        }
        transitions.push(transition);
    }
    for (key, handle) in &candidates {
        if refresh_keys.contains(key) {
            continue;
        }
        if ReferenceProjection::from_handle(handle)?.is_some() {
            continue;
        }
        let operation = identity(&(
            "static-output",
            OwnerIdentity::of(owner),
            key,
            handle.driver.as_str(),
            handle.handle.as_str(),
        ))?;
        let references = versioned
            .references
            .adopt_with_expiration(
                owner,
                "static",
                &HashMap::from([(key.clone(), handle.clone())]),
                None,
                &operation,
            )
            .await?;
        next.credential_handles.extend(references);
    }
    next.credentials.clear();
    next.metadata
        .as_mut()
        .ok_or_else(corrupt)?
        .annotations
        .insert(MIGRATED.to_owned(), "1".to_owned());
    let metadata = provider.metadata.as_ref().ok_or_else(corrupt)?;
    let labels = if metadata.labels.is_empty() {
        None
    } else {
        Some(serde_json::to_string(&metadata.labels).map_err(|_| corrupt())?)
    };
    activation.mark_irreversible().await?;
    versioned
        .store
        .put_if(
            "provider",
            provider.object_id(),
            provider.object_name(),
            provider.object_workspace(),
            &next.encode_to_vec(),
            labels.as_deref(),
            WriteCondition::MatchResourceVersion(metadata.resource_version),
        )
        .await
        .map_err(|_| Status::aborted("legacy provider changed during credential migration"))?;
    for transition in transitions {
        versioned
            .references
            .activate_grant(
                owner,
                &transition.grant_id,
                transition.prepared_version,
                None,
            )
            .await?;
    }
    Ok(())
}

/// Convert a storage-only handle without changing the physical candidate. The
/// operation identity is shared by duplicate legacy bookkeeping links so the
/// same owner/key/handle is never prepared twice with incompatible identities.
async fn internal_handle(
    versioned: &VersionedCredentials,
    owner: SecretOwner<'_>,
    key: &str,
    bytes: &[u8],
) -> Result<Vec<u8>, Status> {
    let handle = CredentialHandle::decode(bytes).map_err(|_| corrupt())?;
    if let Some(projection) = ReferenceProjection::from_handle(&handle)? {
        versioned
            .references
            .manifest_generation(
                owner,
                &projection.epoch,
                &Handles::from([(key.to_owned(), handle.clone())]),
            )
            .await?;
        return Ok(handle_bytes(&handle));
    }
    let operation = identity(&(
        "internal",
        OwnerIdentity::of(owner),
        key,
        &handle.driver,
        &handle.handle,
    ))?;
    let mut handles = versioned
        .references
        .adopt_with_expiration(
            owner,
            "static",
            &HashMap::from([(key.to_owned(), handle)]),
            None,
            &operation,
        )
        .await?;
    Ok(handle_bytes(&handles.remove(key).ok_or_else(corrupt)?))
}

async fn replace_internal(
    versioned: &VersionedCredentials,
    record: &ObjectRecord,
    payload: &serde_json::Value,
    activation: &mut Activation,
) -> Result<(), Status> {
    let bytes = serde_json::to_vec(payload).map_err(|_| corrupt())?;
    if bytes == record.payload {
        return Ok(());
    }
    activation.mark_irreversible().await?;
    versioned
        .store
        .put_if(
            &record.object_type,
            &record.id,
            &record.name,
            &record.workspace,
            &bytes,
            record.labels.as_deref(),
            WriteCondition::MatchResourceVersion(record.resource_version),
        )
        .await
        .map_err(|_| Status::aborted("internal secret binding changed during migration"))?;
    Ok(())
}

async fn migrate_internal(
    versioned: &VersionedCredentials,
    activation: &mut Activation,
) -> Result<(), Status> {
    let sandboxes: Vec<Sandbox> = versioned
        .store
        .collect_messages(ObjectListQuery::AllWorkspaces)
        .await
        .map_err(|_| unavailable())?;
    let mut seen = BTreeSet::new();
    for sandbox in &sandboxes {
        let owner = SecretOwner::sandbox(sandbox.object_workspace(), sandbox.object_id());
        let published = versioned
            .store
            .get(
                "sandbox_ssh_identity_v1",
                &format!("sandbox-ssh:{}", sandbox.object_id()),
            )
            .await
            .map_err(|_| unavailable())?;
        let mut published_handle = None;
        if let Some(record) = published {
            let mut payload: serde_json::Value =
                serde_json::from_slice(&record.payload).map_err(|_| corrupt())?;
            let bytes: Vec<u8> = serde_json::from_value(
                payload
                    .get("credential_handle")
                    .ok_or_else(corrupt)?
                    .clone(),
            )
            .map_err(|_| corrupt())?;
            let handle = internal_handle(versioned, owner, "SSH_HOST_PRIVATE_KEY", &bytes).await?;
            published_handle = Some(handle.clone());
            payload["credential_handle"] = serde_json::to_value(&handle).map_err(|_| corrupt())?;
            replace_internal(versioned, &record, &payload, activation).await?;
            seen.insert((record.object_type, record.id));
        }
        let candidates = versioned
            .store
            .collect_records(
                "sandbox_ssh_identity_candidate_v1",
                ObjectListQuery::Scope(sandbox.object_id()),
            )
            .await
            .map_err(|_| unavailable())?;
        for record in candidates {
            let mut payload: serde_json::Value =
                serde_json::from_slice(&record.payload).map_err(|_| corrupt())?;
            let bytes: Vec<u8> = serde_json::from_value(
                payload
                    .get("credential_handle")
                    .ok_or_else(corrupt)?
                    .clone(),
            )
            .map_err(|_| corrupt())?;
            let handle = internal_handle(versioned, owner, "SSH_HOST_PRIVATE_KEY", &bytes).await?;
            if published_handle.as_ref() == Some(&handle) {
                // A losing bookkeeping link is not a losing physical secret.
                // Release only this duplicate row, never the shared candidate.
                activation.mark_irreversible().await?;
                versioned
                    .store
                    .delete_if(&record.object_type, &record.id, record.resource_version)
                    .await
                    .map_err(|_| unavailable())?;
            } else {
                payload["credential_handle"] =
                    serde_json::to_value(handle).map_err(|_| corrupt())?;
                replace_internal(versioned, &record, &payload, activation).await?;
            }
            seen.insert((record.object_type, record.id));
        }
    }
    for object_type in [
        "sandbox_ssh_identity_v1",
        "sandbox_ssh_identity_candidate_v1",
    ] {
        for record in versioned
            .store
            .collect_records(object_type, ObjectListQuery::AllWorkspaces)
            .await
            .map_err(|_| unavailable())?
        {
            if !seen.contains(&(record.object_type, record.id)) {
                return Err(Status::failed_precondition(
                    "legacy SSH secret has no durable sandbox owner",
                ));
            }
        }
    }
    for object_type in [
        "supervisor_instance_assignment",
        "supervisor_instance_material_candidate",
    ] {
        for record in versioned
            .store
            .collect_records(object_type, ObjectListQuery::AllWorkspaces)
            .await
            .map_err(|_| unavailable())?
        {
            let mut payload: serde_json::Value =
                serde_json::from_slice(&record.payload).map_err(|_| corrupt())?;
            let bytes: Vec<u8> =
                serde_json::from_value(payload.get("material_handle").ok_or_else(corrupt)?.clone())
                    .map_err(|_| corrupt())?;
            if bytes.is_empty() {
                continue;
            } // A reservation owns no material.
            let workspace = payload
                .get("workspace")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(corrupt)?
                .to_owned();
            let sandbox_id = payload
                .get("sandbox_id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(corrupt)?
                .to_owned();
            let owner = SecretOwner::supervisor_instance(&workspace, &sandbox_id);
            let handle =
                internal_handle(versioned, owner, "SHARED_INSTANCE_LAUNCH_MATERIAL", &bytes)
                    .await?;
            payload["material_handle"] = serde_json::to_value(handle).map_err(|_| corrupt())?;
            replace_internal(versioned, &record, &payload, activation).await?;
        }
    }
    Ok(())
}

pub async fn migrate(
    runtime: &CredentialRuntime,
    versioned: &Arc<VersionedCredentials>,
    activation: &mut Activation,
) -> Result<(), Status> {
    let providers: Vec<Provider> = versioned
        .store
        .collect_messages(ObjectListQuery::AllWorkspaces)
        .await
        .map_err(|_| unavailable())?;
    for provider in &providers {
        recover_bindings(versioned, provider, activation).await?;
    }
    super::static_updates::recover(versioned).await?;
    if activation.already_active() {
        return Ok(());
    }
    let legacy = crate::refresh_store::list_all_refresh_states(&versioned.store).await?;
    let states: Vec<RefreshState> = legacy.iter().map(Into::into).collect();
    for provider in providers {
        let matching: Vec<_> = states
            .iter()
            .filter(|state| state.provider_id == provider.object_id())
            .cloned()
            .collect();
        migrate_provider(runtime, versioned, provider, &matching, activation).await?;
    }
    for mut state in states {
        if versioned
            .references
            .get_grant(owner(&state), state.object_id())
            .await?
            .is_some()
        {
            continue;
        }
        if state.status != "deleted"
            && state
                .metadata
                .as_ref()
                .is_none_or(|m| m.deletion_time.is_none())
        {
            return Err(Status::failed_precondition(
                "legacy refresh has no migrated provider binding",
            ));
        }
        // Preserve all parked/pending deletion generations; never run cleanup
        // as part of adoption, and never resurrect a deleting authorization.
        inline_material(runtime, versioned, &mut state).await?;
        activation.mark_irreversible().await?;
        versioned
            .references
            .put_grant(
                owner(&state),
                state.object_id(),
                None,
                effective_authorization_epoch(&state)?,
                &persistence::encode(&state)?,
                false,
            )
            .await?;
    }
    migrate_internal(versioned, activation).await?;
    // Reload the rows installed by the gateway CASes, not the stale inventory.
    // Pending fixed outputs are valid, but every binding must have a durable,
    // owner-qualified manifest before the deployment marker can become Active.
    let providers: Vec<Provider> = versioned
        .store
        .collect_messages(ObjectListQuery::AllWorkspaces)
        .await
        .map_err(|_| unavailable())?;
    for provider in providers {
        if !provider.credentials.is_empty() {
            return Err(Status::failed_precondition(
                "inline credentials remain after migration",
            ));
        }
        let mut bundles: BTreeMap<(String, String), Handles> = BTreeMap::new();
        for (key, handle) in &provider.credential_handles {
            let projection = ReferenceProjection::from_handle(handle)?.ok_or_else(|| {
                Status::failed_precondition("legacy credentials remain after migration")
            })?;
            bundles
                .entry((projection.manifest_id, projection.epoch))
                .or_default()
                .insert(key.clone(), handle.clone());
        }
        for ((_, epoch), bundle) in bundles {
            versioned
                .references
                .manifest_generation(provider_owner(&provider), &epoch, &bundle)
                .await?;
        }
        versioned.validate_provider_grants(&provider).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
