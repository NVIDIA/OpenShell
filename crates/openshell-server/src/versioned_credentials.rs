// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Embedded adapter for issuer-owned reference/grant records. Provider policy
//! and configuration sagas stay in the gateway; refresh activation uses only
//! the issuer manifest and its non-secret grant journal.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use openshell_core::{ObjectId, ObjectWorkspace};
use openshell_credential_issuer::references::{
    ActivateBundle, GrantRecord, GrantTransition, REFERENCE_OBJECT_TYPE, ReferenceRecord,
    ReferenceRuntime, ReferenceStateStore,
};
use openshell_credential_issuer::refresh::{
    ReferenceActivationError, ReferenceOutputStore, RefreshLease, RefreshState, RefreshStateStore,
    effective_authorization_epoch, persistence,
};
use openshell_credential_issuer::{CredentialIssuer, Handles, SecretOwner, StoreSecrets};
use tonic::{Code, Status};

use crate::persistence::{ObjectListQuery, PersistenceError, Store, WriteCondition};

mod migration;
pub mod static_updates;
pub use migration::migrate;

#[derive(Debug, Clone)]
pub struct ServerReferenceStateStore(pub Arc<Store>);

fn persistence_error(error: PersistenceError) -> Status {
    match error {
        PersistenceError::Conflict { .. } => Status::aborted("issuer record changed"),
        PersistenceError::UniqueViolation { .. } => {
            Status::already_exists("issuer record already exists")
        }
        _ => Status::unavailable("issuer record persistence unavailable"),
    }
}

#[async_trait]
impl ReferenceStateStore for ServerReferenceStateStore {
    async fn get_retention(&self, id: &str) -> Result<Option<ReferenceRecord>, Status> {
        self.0
            .get(
                openshell_credential_issuer::references::REFERENCE_RETENTION_OBJECT_TYPE,
                id,
            )
            .await
            .map(|record| {
                record.map(|record| ReferenceRecord {
                    resource_version: record.resource_version,
                    payload: record.payload,
                })
            })
            .map_err(persistence_error)
    }

    async fn put_retention(&self, id: &str, payload: Vec<u8>) -> Result<(), Status> {
        self.0
            .put_if(
                openshell_credential_issuer::references::REFERENCE_RETENTION_OBJECT_TYPE,
                id,
                id,
                "",
                &payload,
                None,
                WriteCondition::MustCreate,
            )
            .await
            .map(|_| ())
            .map_err(persistence_error)
    }

    async fn get(&self, id: &str) -> Result<Option<ReferenceRecord>, Status> {
        self.0
            .get(REFERENCE_OBJECT_TYPE, id)
            .await
            .map(|record| {
                record.map(|record| ReferenceRecord {
                    resource_version: record.resource_version,
                    payload: record.payload,
                })
            })
            .map_err(persistence_error)
    }

    async fn put(&self, id: &str, expected: Option<u64>, payload: Vec<u8>) -> Result<(), Status> {
        self.0
            .put_if(
                REFERENCE_OBJECT_TYPE,
                id,
                id,
                "",
                &payload,
                None,
                expected.map_or(
                    WriteCondition::MustCreate,
                    WriteCondition::MatchResourceVersion,
                ),
            )
            .await
            .map(|_| ())
            .map_err(persistence_error)
    }

    async fn list(&self) -> Result<Vec<ReferenceRecord>, Status> {
        self.0
            .collect_records(REFERENCE_OBJECT_TYPE, ObjectListQuery::AllWorkspaces)
            .await
            .map(|records| {
                records
                    .into_iter()
                    .map(|record| ReferenceRecord {
                        resource_version: record.resource_version,
                        payload: record.payload,
                    })
                    .collect()
            })
            .map_err(persistence_error)
    }
}

#[derive(Clone)]
pub struct VersionedCredentials {
    pub references: Arc<ReferenceRuntime>,
    pub backend: Arc<dyn CredentialIssuer>,
    pub store: Arc<Store>,
}

impl std::fmt::Debug for VersionedCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VersionedCredentials")
            .finish_non_exhaustive()
    }
}

pub fn owner(state: &RefreshState) -> SecretOwner<'_> {
    SecretOwner::provider(
        state.object_workspace(),
        &state.provider_id,
        &state.provider_name,
    )
}

fn decode(
    grant: &GrantRecord,
    id: &str,
    workspace: &str,
    provider_id: &str,
) -> Result<RefreshState, Status> {
    let mut state = persistence::decode(&grant.state)?;
    if state.object_id() != id
        || state.object_workspace() != workspace
        || state.provider_id != provider_id
    {
        return Err(Status::data_loss("issuer grant owner binding mismatch"));
    }
    state
        .metadata
        .as_mut()
        .ok_or_else(|| Status::data_loss("issuer grant metadata missing"))?
        .resource_version = grant.resource_version;
    Ok(state)
}

impl VersionedCredentials {
    pub fn new(store: Arc<Store>, backend: Arc<dyn CredentialIssuer>) -> Result<Arc<Self>, Status> {
        let references = Arc::new(ReferenceRuntime::new(
            "embedded-v1",
            Arc::clone(&backend),
            Arc::new(ServerReferenceStateStore(Arc::clone(&store))),
        )?);
        Ok(Arc::new(Self {
            references,
            backend,
            store,
        }))
    }

    /// Project committed issuer expiration without resolving secret values or
    /// trusting a refresh journal that may still describe staged outputs.
    pub async fn project_expirations(
        &self,
        provider: &mut openshell_core::proto::Provider,
    ) -> Result<(), Status> {
        let owner = SecretOwner::provider(
            provider.object_workspace(),
            provider.object_id(),
            provider
                .metadata
                .as_ref()
                .map_or("", |meta| meta.name.as_str()),
        );
        let expirations = self
            .references
            .committed_expirations(owner, &provider.credential_handles)
            .await?;
        for (key, expiration) in expirations {
            let Some(expiration) = expiration else {
                continue;
            };
            let issuer_ms = openshell_core::time::timestamp_to_millis(&expiration)
                .map_err(|_| Status::data_loss("invalid committed credential expiration"))?;
            let authored = provider
                .credential_expiration_times
                .get(&key)
                .map(openshell_core::time::timestamp_to_millis)
                .transpose()
                .map_err(|_| Status::data_loss("invalid provider credential expiration"))?;
            if authored.is_none_or(|authored| issuer_ms < authored) {
                provider.credential_expiration_times.insert(key, expiration);
            }
        }
        Ok(())
    }

    pub async fn states(&self, provider_id: Option<&str>) -> Result<Vec<RefreshState>, Status> {
        let mut states = Vec::new();
        for (identity, id, grant) in self.references.list_grants(provider_id).await? {
            if identity.kind != "provider" || grant.prepared {
                continue;
            }
            let state = decode(&grant, &id, &identity.workspace, &identity.id)?;
            if state.status != "deleted"
                && (grant.active
                    || state
                        .metadata
                        .as_ref()
                        .is_some_and(|m| m.deletion_time.is_some()))
            {
                states.push(state);
            }
        }
        Ok(states)
    }

    async fn exact(&self, id: &str) -> Result<Option<RefreshState>, Status> {
        Ok(self
            .states(None)
            .await?
            .into_iter()
            .find(|state| state.object_id() == id))
    }

    /// Foreground management may resume the current binding's deletion, but
    /// authorization lookup must continue to exclude every revoked grant.
    /// Never select abandoned preparation cleanup merely because its key matches.
    pub async fn current_refresh_state(
        &self,
        provider: &openshell_core::proto::Provider,
        key: &str,
    ) -> Result<Option<RefreshState>, Status> {
        if let Some(live) = self
            .get(provider.object_workspace(), provider.object_id(), key)
            .await?
        {
            return Ok(Some(live));
        }
        let Some(metadata) = provider.metadata.as_ref() else {
            return Ok(None);
        };
        let binding_key = annotation_key(key)?;
        let disabled_key = disabled_annotation_key(key)?;
        let Some(encoded) = metadata
            .annotations
            .get(&binding_key)
            .or_else(|| metadata.annotations.get(&disabled_key))
        else {
            return Ok(None);
        };
        let transition: BindingTransition = serde_json::from_str(encoded)
            .map_err(|_| Status::data_loss("invalid provider grant binding"))?;
        let Some(state) = self.exact(&transition.grant_id).await? else {
            return Ok(None);
        };
        Ok((state.object_workspace() == provider.object_workspace()
            && state.provider_id == provider.object_id()
            && state.credential_key == key
            && state
                .metadata
                .as_ref()
                .is_some_and(|metadata| metadata.deletion_time.is_some()))
        .then_some(state))
    }
}

#[async_trait]
impl RefreshStateStore for VersionedCredentials {
    async fn get(
        &self,
        workspace: &str,
        provider_id: &str,
        key: &str,
    ) -> Result<Option<RefreshState>, Status> {
        let mut states = self
            .states(Some(provider_id))
            .await?
            .into_iter()
            // Inactive cleanup debt remains enumerable by immutable ID, but
            // must never compete with the winning grant's live authorization.
            .filter(|state| {
                state.object_workspace() == workspace
                    && state.credential_key == key
                    && state
                        .metadata
                        .as_ref()
                        .is_none_or(|metadata| metadata.deletion_time.is_none())
            });
        let first = states.next();
        if states.next().is_some() {
            return Err(Status::data_loss(
                "multiple active issuer grants for credential",
            ));
        }
        Ok(first)
    }

    async fn get_by_id(&self, id: &str) -> Result<Option<RefreshState>, Status> {
        self.exact(id).await
    }
    async fn list(&self, provider_id: Option<&str>) -> Result<Vec<RefreshState>, Status> {
        self.states(provider_id).await
    }

    async fn create(&self, state: &RefreshState) -> Result<(), Status> {
        if state.output_references.is_empty() {
            return Err(Status::failed_precondition(
                "versioned grant requires prepared output references",
            ));
        }
        self.references
            .put_grant(
                owner(state),
                state.object_id(),
                None,
                effective_authorization_epoch(state)?,
                &persistence::encode(state)?,
                true,
            )
            .await?;
        Ok(())
    }

    async fn replace(&self, state: &RefreshState, version: u64) -> Result<Option<u64>, Status> {
        let Some(current) = self.exact(state.object_id()).await? else {
            return Ok(None);
        };
        let Some(grant) = self
            .references
            .get_grant(owner(&current), current.object_id())
            .await?
        else {
            return Ok(None);
        };
        if grant.resource_version != version {
            return Ok(None);
        }
        let mut next = state.clone();
        // Public/gateway legacy projections do not carry issuer implementation
        // fields. A status/delete adaptation must not erase the fixed binding.
        if next.output_references.is_empty() {
            next.output_references
                .clone_from(&current.output_references);
            next.reference_generation = current.reference_generation;
        }
        let bytes = persistence::encode(&next)?;
        let result = if next
            .metadata
            .as_ref()
            .is_some_and(|m| m.deletion_time.is_some())
        {
            self.references
                .tombstone_grant(owner(&current), current.object_id(), version, &bytes)
                .await
        } else {
            self.references
                .put_grant(
                    owner(&current),
                    current.object_id(),
                    Some(version),
                    &grant.epoch,
                    &bytes,
                    grant.active,
                )
                .await
        };
        match result {
            Ok(grant) => Ok(Some(grant.resource_version)),
            Err(error) if error.code() == Code::Aborted => Ok(None),
            Err(error) => Err(error),
        }
    }

    async fn delete(&self, id: &str, version: u64) -> Result<(), Status> {
        let Some(mut state) = self.exact(id).await? else {
            return Ok(());
        };
        state.status = "deleted".into();
        state.secret_material_handles.clear();
        state.pending_secret_deletions.clear();
        self.references
            .finish_grant_cleanup(owner(&state), id, version, &persistence::encode(&state)?)
            .await?;
        Ok(())
    }

    async fn acquire(&self, provider_id: &str, key: &str) -> Result<Box<dyn RefreshLease>, Status> {
        self.store
            .acquire_refresh_guard(provider_id, key)
            .await
            .map(|guard| -> Box<dyn RefreshLease> { Box::new(guard) })
            .map_err(|_| Status::unavailable("credential refresh coordination unavailable"))
    }
}

#[async_trait]
impl ReferenceOutputStore for VersionedCredentials {
    async fn activate(
        &self,
        mut state: RefreshState,
        expected_version: u64,
        values: HashMap<String, String>,
        expiration: Option<prost_types::Timestamp>,
    ) -> Result<RefreshState, ReferenceActivationError> {
        if state.output_references.len() != values.len()
            || state
                .output_references
                .keys()
                .any(|key| !values.contains_key(key))
        {
            if let Some(metadata) = state.metadata.as_mut() {
                metadata.resource_version = expected_version;
            }
            return Err(ReferenceActivationError::NotActivated {
                state: Box::new(state),
                error: Status::failed_precondition(
                    "minted outputs differ from fixed grant binding",
                ),
            });
        }
        let epoch = effective_authorization_epoch(&state)?.to_owned();
        let staging_id = format!(
            "issuer-output-{}-{}",
            state.object_id(),
            uuid::Uuid::new_v4()
        );
        // The non-secret intent exists before external storage I/O. A lost
        // backend response retains this exact write identity for recovery.
        let mut parked = state.clone();
        parked.status = "refresh_committing".into();
        parked.next_refresh_at_ms = i64::MAX;
        let metadata = parked
            .metadata
            .as_mut()
            .ok_or_else(|| Status::data_loss("issuer grant metadata missing"))?;
        metadata
            .annotations
            .remove("openshell.nvidia.com/refresh-completed-mint");
        // Even an unsuccessful backend response may have stored unreachable
        // material. Keep prior write IDs as recovery debt across later retries.
        // CredentialIssuer cannot enumerate/delete by object ID: reconciliation
        // of these unknown handles is operator/backend-owned, like the static
        // ReferenceRuntime::write_recovery inventory. The ordinary reference
        // reclaimer cannot safely claim that this material has been deleted.
        if let Some(previous) = metadata
            .annotations
            .remove("openshell.nvidia.com/issuer-output-staging")
        {
            let debt = metadata
                .annotations
                .entry("openshell.nvidia.com/issuer-output-staging-debt".into())
                .or_default();
            if !debt.is_empty() {
                debt.push(',');
            }
            debt.push_str(&previous);
        }
        metadata.annotations.insert(
            "openshell.nvidia.com/issuer-output-staging".into(),
            staging_id.clone(),
        );
        let staged_grant = self
            .references
            .put_grant(
                owner(&state),
                state.object_id(),
                Some(expected_version),
                &epoch,
                &persistence::encode(&parked)?,
                true,
            )
            .await?;
        parked
            .metadata
            .as_mut()
            .expect("validated metadata")
            .resource_version = staged_grant.resource_version;
        let candidates = match self
            .backend
            .store(StoreSecrets {
                owner: owner(&state),
                object_id: Some(&staging_id),
                values: &values,
                existing_handles: &Handles::new(),
            })
            .await
        {
            Ok(candidates) => candidates,
            Err(error) => {
                tracing::warn!(
                    grant_id = state.object_id(),
                    workspace = state.object_workspace(),
                    provider_id = %state.provider_id,
                    object_id = %staging_id,
                    code = ?error.code(),
                    "refresh output activation was not attempted; backend write identity retained for operator/backend recovery"
                );
                return Err(ReferenceActivationError::NotActivated {
                    state: Box::new(parked),
                    error,
                });
            }
        };
        if let Some(debt) = parked.metadata.as_ref().and_then(|metadata| {
            metadata
                .annotations
                .get("openshell.nvidia.com/issuer-output-staging-debt")
        }) {
            state
                .metadata
                .as_mut()
                .expect("validated metadata")
                .annotations
                .insert(
                    "openshell.nvidia.com/issuer-output-staging-debt".into(),
                    debt.clone(),
                );
        }
        state.reference_generation = state
            .reference_generation
            .checked_add(1)
            .ok_or_else(|| Status::out_of_range("reference generation exhausted"))?;
        let metadata = state
            .metadata
            .as_mut()
            .ok_or_else(|| Status::data_loss("issuer grant metadata missing"))?;
        metadata.resource_version = staged_grant
            .resource_version
            .checked_add(1)
            .ok_or_else(|| Status::out_of_range("grant version exhausted"))?;
        metadata
            .annotations
            .remove("openshell.nvidia.com/issuer-output-staging");
        let bytes = persistence::encode(&state)?;
        let expected_generation = state.reference_generation - 1;
        self.references
            .activate_bundle(ActivateBundle {
                owner: owner(&state),
                epoch: &epoch,
                references: &state.output_references,
                candidates: &candidates,
                operation_id: &staging_id,
                expected_generation,
                expiration_time: expiration,
                grant: Some(GrantTransition {
                    grant_id: state.object_id(),
                    expected_resource_version: staged_grant.resource_version,
                    state: &bytes,
                }),
            })
            .await?;
        // Replaced candidates are now cleanup debt. Cleanup is explicitly
        // best-effort after a winning activation and cannot turn it into a loss.
        if let Err(error) = self.references.reclaim(owner(&state), 16).await {
            tracing::warn!(code = ?error.code(), "issuer output cleanup deferred");
        }
        Ok(state)
    }
}

/// Non-secret evidence of a gateway binding switch. It is installed in the same
/// provider CAS as the new references, so startup can finish exactly that saga.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingTransition {
    pub grant_id: String,
    pub prepared_version: u64,
    pub old_grant_id: Option<String>,
    pub old_grant_version: Option<u64>,
    pub epoch: String,
    #[serde(default)]
    pub retired_references: std::collections::BTreeMap<String, Vec<u8>>,
}

pub fn disabled_annotation_key(key: &str) -> Result<String, Status> {
    Ok(annotation_key(key)?.replacen("issuer-grant-", "issuer-disabled-", 1))
}

pub fn annotation_key(key: &str) -> Result<String, Status> {
    use std::fmt::Write as _;
    let bytes = openshell_crypto::sha256(key.as_bytes())
        .map_err(|_| Status::internal("derive issuer grant binding key failed"))?;
    let mut name = String::from("internal.openshell.ai/issuer-grant-");
    // A qualified annotation's name segment is bounded to 63 characters.
    // A domain-owned 128-bit identifier avoids embedding arbitrary env keys.
    for byte in &bytes[..16] {
        write!(&mut name, "{byte:02x}").expect("write String");
    }
    Ok(name)
}

impl VersionedCredentials {
    /// The gateway has already authorized and validated all pinned output keys
    /// under its workspace guard. Only the initial binding publication writes
    /// the provider; every subsequent refresh is issuer-local.
    pub async fn configure(
        &self,
        provider: &openshell_core::proto::Provider,
        state: RefreshState,
        storage_driver: &str,
        initial_expiration: Option<prost_types::Timestamp>,
        guard: impl Send + 'static,
    ) -> Result<RefreshState, Status> {
        let runtime = self.clone();
        let provider = provider.clone();
        let storage_driver = storage_driver.to_owned();
        tokio::spawn(async move {
            let _guard = guard;
            runtime
                .configure_inner(&provider, state, &storage_driver, initial_expiration)
                .await
        })
        .await
        .map_err(|_| Status::internal("credential configuration worker failed"))?
    }

    async fn reconcile_binding_publication(
        &self,
        candidate: &openshell_core::proto::Provider,
        publication: Result<(), PersistenceError>,
    ) -> Result<(), PersistenceError> {
        let Err(error) = publication else {
            return Ok(());
        };
        if error.is_expected() {
            return Err(error);
        }
        let current = self
            .store
            .get_message::<openshell_core::proto::Provider>(candidate.object_id())
            .await;
        if let Ok(Some(current)) = current {
            let expected = candidate.metadata.as_ref();
            let installed = current.metadata.as_ref();
            let same_binding = expected
                .zip(installed)
                .is_some_and(|(expected, installed)| {
                    expected.annotations.iter().all(|(key, value)| {
                        !key.starts_with("internal.openshell.ai/issuer-grant-")
                            || installed.annotations.get(key) == Some(value)
                    })
                });
            if same_binding
                && current.object_workspace() == candidate.object_workspace()
                && current.credential_handles == candidate.credential_handles
            {
                return Ok(());
            }
        }
        // A failed read or an unobserved switch is not evidence of loss. In
        // particular, never delete upstream-valid material on an unknown write.
        Err(error)
    }

    async fn configure_inner(
        &self,
        provider: &openshell_core::proto::Provider,
        mut state: RefreshState,
        storage_driver: &str,
        initial_expiration: Option<prost_types::Timestamp>,
    ) -> Result<RefreshState, Status> {
        use crate::persistence::{ObjectName, ObjectType};
        use openshell_credential_issuer::references::ReferenceProjection;
        use prost::Message as _;
        let _lease = self
            .store
            .acquire_refresh_guard(&state.provider_id, &state.credential_key)
            .await
            .map_err(|_| {
                Status::unavailable("credential configuration coordination unavailable")
            })?;
        // Every reference-changing mutation must settle a preceding winning
        // static publication before it can replace that transition's binding.
        Box::pin(static_updates::finish(self, provider)).await?;
        let previous = self
            .get(
                state.object_workspace(),
                &state.provider_id,
                &state.credential_key,
            )
            .await?;
        // Reconfiguration has a new issuer identity, not the historical row ID
        // retained by the legacy V2 adapter.
        let metadata = state
            .metadata
            .as_mut()
            .ok_or_else(|| Status::failed_precondition("grant identity is missing"))?;
        metadata.id = uuid::Uuid::new_v4().to_string();
        metadata.resource_version = 0;
        let epoch = effective_authorization_epoch(&state)?.to_owned();
        let keys: Vec<String> = std::iter::once(state.credential_key.clone())
            .chain(state.additional_output_keys.values().cloned())
            .collect();
        let identities = ReferenceRuntime::pending_handles(storage_driver, keys.clone())?;
        let source: Handles = keys
            .iter()
            .filter_map(|key| {
                provider
                    .credential_handles
                    .get(key)
                    .map(|h| (key.clone(), h.clone()))
            })
            .collect();
        let operation = format!("configure-references:{}", state.object_id());
        state.output_references = if source.len() == keys.len()
            && source.values().all(|handle| {
                ReferenceProjection::from_handle(handle)
                    .ok()
                    .flatten()
                    .is_some()
            }) {
            self.references
                .rebind_bundle(owner(&state), &epoch, &source, &identities, &operation)
                .await?
        } else {
            self.references
                .prepare_bundle(owner(&state), &epoch, &identities, &operation)
                .await?
        };
        state.reference_generation = self
            .references
            .manifest_generation(owner(&state), &epoch, &state.output_references)
            .await?;
        let prepared = self
            .references
            .prepare_grant(
                owner(&state),
                state.object_id(),
                &epoch,
                &persistence::encode(&state)?,
            )
            .await?;
        if let Some(expiration) = initial_expiration {
            self.references
                .set_prepared_grant_expiration(
                    owner(&state),
                    state.object_id(),
                    &state.credential_key,
                    Some(expiration),
                )
                .await?;
        }
        let transition = BindingTransition {
            grant_id: state.object_id().to_owned(),
            prepared_version: prepared.resource_version,
            old_grant_id: previous.as_ref().map(|old| old.object_id().to_owned()),
            old_grant_version: previous
                .as_ref()
                .and_then(|old| old.metadata.as_ref().map(|m| m.resource_version)),
            epoch: epoch.clone(),
            retired_references: if previous.is_none() {
                source
                    .iter()
                    .map(|(key, handle)| (key.clone(), handle.encode_to_vec()))
                    .collect()
            } else {
                std::collections::BTreeMap::new()
            },
        };
        let mut candidate = provider.clone();
        // The preceding exact static activation is durable; this new binding
        // no longer needs its provider-side recovery marker.
        if let Some(metadata) = candidate.metadata.as_mut() {
            metadata.annotations.remove(static_updates::ANNOTATION);
        }
        candidate
            .credential_handles
            .extend(state.output_references.clone());
        for key in &keys {
            candidate.credentials.remove(key);
            // The grant's expiry, not a stale copied timestamp, owns outputs.
            if previous.as_ref().is_some_and(|old| {
                candidate
                    .credential_expiration_times
                    .get(key)
                    .and_then(|t| openshell_core::time::timestamp_to_millis(t).ok())
                    == Some(old.expires_at_ms)
            }) {
                candidate.credential_expiration_times.remove(key);
            }
        }
        candidate
            .metadata
            .as_mut()
            .ok_or_else(|| Status::failed_precondition("provider identity is missing"))?
            .annotations
            .insert(
                annotation_key(&state.credential_key)?,
                serde_json::to_string(&transition)
                    .map_err(|_| Status::internal("encode issuer binding transition failed"))?,
            );
        candidate
            .metadata
            .as_mut()
            .expect("validated metadata")
            .annotations
            .remove(&disabled_annotation_key(&state.credential_key)?);
        let labels = provider_labels(&candidate)?;
        let expected = provider.metadata.as_ref().map_or(0, |m| m.resource_version);
        let publication = self
            .store
            .put_if(
                openshell_core::proto::Provider::object_type(),
                provider.object_id(),
                provider.object_name(),
                provider.object_workspace(),
                &candidate.encode_to_vec(),
                labels.as_deref(),
                WriteCondition::MatchResourceVersion(expected),
            )
            .await
            .map(|_| ());
        if let Err(error) = self
            .reconcile_binding_publication(&candidate, publication)
            .await
        {
            // Only an explicit CAS/uniqueness conflict proves the preparation
            // lost. Database failures may follow a committed provider switch;
            // retain that grant and its material until exact recovery can run.
            if !error.is_expected() {
                return Err(persistence_error(error));
            }
            let mut abandoned = state.clone();
            abandoned.status = "deleting".into();
            abandoned.pending_secret_deletions.clear(); // Still owned by the winning old grant.
            abandoned
                .metadata
                .as_mut()
                .expect("validated metadata")
                .deletion_time =
                openshell_core::time::timestamp_from_millis(openshell_core::time::now_ms()).ok();
            let tombstone = self
                .references
                .tombstone_grant(
                    owner(&state),
                    state.object_id(),
                    prepared.resource_version,
                    &persistence::encode(&abandoned)?,
                )
                .await?;
            let scope = openshell_credential_issuer::refresh::refresh_material_scope(&abandoned);
            if self
                .backend
                .delete_refresh_material_handles(scope, &abandoned.secret_material_handles)
                .await
                .is_ok()
            {
                self.delete(abandoned.object_id(), tombstone.resource_version)
                    .await?;
            }
            return Err(persistence_error(error));
        }
        // The durable transition remains if a response/CAS is lost. Startup
        // resumes this exact binding, never a grant selected only by name.
        let old = transition
            .old_grant_id
            .as_deref()
            .zip(transition.old_grant_version);
        let active = self
            .references
            .activate_grant(
                owner(&state),
                state.object_id(),
                prepared.resource_version,
                old,
            )
            .await?;
        if previous.is_none() && !source.is_empty() {
            // Configuring refresh transfers ownership from standalone static
            // references. Their old authority must not remain independently live.
            self.references.delete(owner(&state), &source).await?;
        }
        state
            .metadata
            .as_mut()
            .expect("validated metadata")
            .resource_version = active.resource_version;
        Ok(state)
    }
}

impl VersionedCredentials {
    pub async fn validate_provider_grants(
        &self,
        provider: &openshell_core::proto::Provider,
    ) -> Result<(), Status> {
        static_updates::validate(self, provider).await?;
        let metadata = provider
            .metadata
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("provider identity is required"))?;
        let owner = SecretOwner::provider(&metadata.workspace, &metadata.id, &metadata.name);
        for (key, encoded) in &metadata.annotations {
            if !key.starts_with("internal.openshell.ai/issuer-grant-") {
                continue;
            }
            let transition: BindingTransition = serde_json::from_str(encoded)
                .map_err(|_| Status::data_loss("invalid provider grant binding"))?;
            let grant = self
                .references
                .get_grant(owner, &transition.grant_id)
                .await?
                .ok_or_else(|| {
                    Status::failed_precondition("provider grant binding is not activated")
                })?;
            if !grant.active || grant.prepared || grant.epoch != transition.epoch {
                return Err(Status::failed_precondition(
                    "provider grant binding is pending or revoked",
                ));
            }
        }
        Ok(())
    }

    /// Disable refresh without deleting its last output values. The provider
    /// switch publishes static references; exact grant revocation follows and is
    /// recoverable from the deletion journal. No values are copied or reminted.
    pub async fn retain_static_outputs(
        &self,
        provider: &openshell_core::proto::Provider,
        grant: &RefreshState,
        storage_driver: &str,
    ) -> Result<(), Status> {
        use crate::persistence::{ObjectName, ObjectType};
        use prost::Message as _;
        let owner = owner(grant);
        let disabled_key = disabled_annotation_key(&grant.credential_key)?;
        if let Some(marker) = provider
            .metadata
            .as_ref()
            .and_then(|m| m.annotations.get(&disabled_key))
        {
            let transition: BindingTransition = serde_json::from_str(marker)
                .map_err(|_| Status::data_loss("invalid disabled issuer grant binding"))?;
            if transition.grant_id == grant.object_id() {
                return Ok(());
            }
        }
        let mut candidate = provider.clone();
        let mut identities = Handles::new();
        for (key, reference) in &grant.output_references {
            if candidate.credential_handles.get(key) != Some(reference) {
                return Err(Status::aborted(
                    "provider grant binding changed before refresh deletion",
                ));
            }
            let identity = serde_json::to_string(&("disabled-refresh", grant.object_id(), key))
                .map_err(|_| Status::internal("encode static reference identity failed"))?;
            identities.insert(
                key.clone(),
                openshell_core::proto::CredentialHandle {
                    driver: storage_driver.to_owned(),
                    handle: identity,
                    metadata: HashMap::new(),
                },
            );
        }
        let operation = format!("disable-refresh:{}", grant.object_id());
        let retained = self
            .references
            .rebind_static_bundle(owner, &grant.output_references, &identities, &operation)
            .await?;
        candidate.credential_handles.extend(retained);
        for key in grant.output_references.keys() {
            if candidate
                .credential_expiration_times
                .get(key)
                .and_then(|time| openshell_core::time::timestamp_to_millis(time).ok())
                == Some(grant.expires_at_ms)
            {
                candidate.credential_expiration_times.remove(key);
            }
        }
        let transition = BindingTransition {
            grant_id: grant.object_id().to_owned(),
            prepared_version: grant.metadata.as_ref().map_or(0, |m| m.resource_version),
            old_grant_id: None,
            old_grant_version: None,
            epoch: effective_authorization_epoch(grant)?.to_owned(),
            retired_references: std::collections::BTreeMap::new(),
        };
        let metadata = candidate
            .metadata
            .as_mut()
            .ok_or_else(|| Status::failed_precondition("provider identity is required"))?;
        metadata
            .annotations
            .remove(&annotation_key(&grant.credential_key)?);
        metadata.annotations.insert(
            disabled_key,
            serde_json::to_string(&transition)
                .map_err(|_| Status::internal("encode disabled issuer grant binding failed"))?,
        );
        let labels = provider_labels(&candidate)?;
        self.store
            .put_if(
                openshell_core::proto::Provider::object_type(),
                provider.object_id(),
                provider.object_name(),
                provider.object_workspace(),
                &candidate.encode_to_vec(),
                labels.as_deref(),
                WriteCondition::MatchResourceVersion(
                    provider.metadata.as_ref().map_or(0, |m| m.resource_version),
                ),
            )
            .await
            .map_err(persistence_error)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;

/// Restore only live issuer metadata for protected mutation replay. A frozen
/// V2 row is never authority after activation, even when it still exists.
pub async fn replay_state(
    store: &Store,
    provider: &openshell_core::proto::Provider,
    id: &str,
) -> Result<RefreshState, Status> {
    let adapter = ServerReferenceStateStore(Arc::new(store.clone()));
    let grants = openshell_credential_issuer::references::read_grants(
        &adapter,
        "embedded-v1",
        Some(provider.object_id()),
    )
    .await?;
    for (identity, grant_id, grant) in grants {
        if grant_id != id
            || identity.workspace != provider.object_workspace()
            || !grant.active
            || grant.prepared
        {
            continue;
        }
        let state = decode(&grant, id, &identity.workspace, &identity.id)?;
        let binding_key = annotation_key(&state.credential_key)?;
        let encoded = provider
            .metadata
            .as_ref()
            .and_then(|m| m.annotations.get(&binding_key))
            .ok_or_else(|| {
                Status::failed_precondition("replayed issuer grant is no longer bound")
            })?;
        let transition: BindingTransition = serde_json::from_str(encoded)
            .map_err(|_| Status::data_loss("invalid replayed issuer binding"))?;
        if transition.grant_id != id || transition.epoch != grant.epoch {
            return Err(Status::failed_precondition(
                "replayed issuer authorization changed",
            ));
        }
        return Ok(state);
    }
    Err(Status::not_found("replayed issuer grant is no longer live"))
}

#[cfg(test)]
mod postgres_tests;

fn provider_labels(provider: &openshell_core::proto::Provider) -> Result<Option<String>, Status> {
    provider
        .metadata
        .as_ref()
        .filter(|metadata| !metadata.labels.is_empty())
        .map(|metadata| {
            serde_json::to_string(&metadata.labels)
                .map_err(|_| Status::internal("encode provider labels failed"))
        })
        .transpose()
}
