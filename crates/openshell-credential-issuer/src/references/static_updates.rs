// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Static provider updates transfer staged immutable candidates only after the
//! gateway has committed its non-secret binding-transition marker.

use super::{
    ActivationReceipt, CandidateStatus, Manifest, ManifestStatus, Operation, OperationIntent,
    OwnerIdentity, OwnerState, RETRY_LIMIT, ReferenceProjection, ReferenceRuntime, SecretOwner,
    conflict, contention, corrupt,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use tonic::Status;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticReplacement {
    pub destination: ReferenceProjection,
    pub staged: ReferenceProjection,
    pub expected_generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticUpdate {
    pub operation_id: String,
    pub replacements: Vec<StaticReplacement>,
}

impl ReferenceRuntime {
    /// Check a provider marker without reading any backend values. An exact
    /// receipt, not the mere existence of staged references, proves activation.
    pub async fn static_update_committed(
        &self,
        owner: SecretOwner<'_>,
        update: &StaticUpdate,
    ) -> Result<bool, Status> {
        let (_, state) = self.load(owner).await?;
        let Some(operation) = state.operations.get(&update.operation_id) else {
            self.reject_archived_operation(owner, &update.operation_id)
                .await?;
            return Ok(false);
        };
        check_static_intent(operation, update)?;
        Ok(operation.result.is_some())
    }

    /// All destination manifests, their versions, and retirement of the staged
    /// aliases change in ONE owner-record CAS. Replaying an exact marker never
    /// increments a version twice, including after a lost successful response.
    pub async fn activate_static_update(
        &self,
        owner: SecretOwner<'_>,
        update: &StaticUpdate,
    ) -> Result<(), Status> {
        if update.operation_id.is_empty() || update.replacements.is_empty() {
            return Err(Status::invalid_argument(
                "static update requires identity and outputs",
            ));
        }
        let protected = serde_json::to_vec(update).map_err(|_| corrupt())?;
        for _ in 0..RETRY_LIMIT {
            let (version, mut state) = self.load(owner).await?;
            if let Some(operation) = state.operations.get(&update.operation_id) {
                check_static_intent(operation, update)?;
                if operation.result.is_some() {
                    return Ok(());
                }
                return Err(corrupt());
            }
            self.reject_archived_operation(owner, &update.operation_id)
                .await?;
            let mut destinations = BTreeSet::new();
            let mut destination_manifests = BTreeSet::new();
            let mut staged_manifests = BTreeSet::new();
            let mut outputs = Vec::new();
            for replacement in &update.replacements {
                let destination = &replacement.destination;
                let staged = &replacement.staged;
                for projection in [destination, staged] {
                    if projection.namespace != self.namespace
                        || projection.owner != OwnerIdentity::of(owner)
                        || state
                            .bindings
                            .get(&projection.reference_id)
                            .is_none_or(|binding| binding.projection != *projection)
                    {
                        return Err(Status::permission_denied(
                            "static update owner binding mismatch",
                        ));
                    }
                }
                if destination.credential_key != staged.credential_key
                    || !destinations.insert(destination.reference_id.clone())
                    || !staged_manifests.insert(staged.manifest_id.clone())
                {
                    return Err(Status::invalid_argument(
                        "static update output mapping mismatch",
                    ));
                }
                destination_manifests.insert(destination.manifest_id.clone());
                let live = static_manifest(&state, destination)?;
                let prepared = static_manifest(&state, staged)?;
                if live.generation != replacement.expected_generation {
                    return Err(Status::aborted("static update generation changed"));
                }
                let old = live
                    .outputs
                    .get(&destination.credential_key)
                    .ok_or_else(corrupt)?;
                let mut next = prepared
                    .outputs
                    .get(&staged.credential_key)
                    .ok_or_else(corrupt)?
                    .clone();
                if state
                    .candidates
                    .get(&next.candidate)
                    .is_none_or(|candidate| candidate.status != CandidateStatus::Available)
                {
                    return Err(Status::failed_precondition(
                        "static candidate is being reclaimed",
                    ));
                }
                let same = destination == staged;
                let generation = if same {
                    live.generation
                } else {
                    if next.candidate == old.candidate {
                        return Err(Status::failed_precondition(
                            "static update requires a new immutable candidate",
                        ));
                    }
                    next.version = old
                        .version
                        .checked_add(1)
                        .ok_or_else(|| Status::out_of_range("secret version exhausted"))?;
                    live.generation
                        .checked_add(1)
                        .ok_or_else(|| Status::out_of_range("activation generation exhausted"))?
                };
                outputs.push((replacement.clone(), next, generation));
            }
            // A staged alias cannot also be another output's live destination.
            for replacement in &update.replacements {
                if replacement.destination != replacement.staged
                    && destination_manifests.contains(&replacement.staged.manifest_id)
                {
                    return Err(Status::invalid_argument("static update aliases overlap"));
                }
            }
            let mut versions = BTreeMap::new();
            for (replacement, output, generation) in outputs {
                versions.insert(
                    replacement.destination.credential_key.clone(),
                    output.version,
                );
                let manifest = state
                    .manifests
                    .get_mut(&replacement.destination.manifest_id)
                    .ok_or_else(corrupt)?;
                manifest.generation = generation;
                manifest
                    .outputs
                    .insert(replacement.destination.credential_key.clone(), output);
                if replacement.destination != replacement.staged {
                    state
                        .manifests
                        .get_mut(&replacement.staged.manifest_id)
                        .ok_or_else(corrupt)?
                        .status = ManifestStatus::Revoked;
                }
            }
            state.operations.insert(
                update.operation_id.clone(),
                Operation {
                    intent: OperationIntent {
                        kind: "static-provider-update".to_owned(),
                        epoch: update.replacements[0].destination.epoch.clone(),
                        manifest_id: update.replacements[0].destination.manifest_id.clone(),
                        expected_generation: update.replacements[0].expected_generation,
                        references: BTreeMap::new(),
                        candidates: BTreeMap::new(),
                        expiration: None,
                        protected_intent: protected.clone(),
                        grant: None,
                    },
                    write_id: update.operation_id.clone(),
                    write_attempts: Vec::new(),
                    staged: BTreeMap::new(),
                    result: Some(ActivationReceipt {
                        manifest_id: update.replacements[0].destination.manifest_id.clone(),
                        epoch: update.replacements[0].destination.epoch.clone(),
                        generation: state.manifests
                            [&update.replacements[0].destination.manifest_id]
                            .generation,
                        versions,
                    }),
                    abandoned: false,
                },
            );
            match self.save(owner, version, &state).await {
                Ok(()) => return Ok(()),
                Err(error) if conflict(&error) => {}
                Err(error) => return Err(error),
            }
        }
        Err(contention())
    }
}

fn check_static_intent(operation: &Operation, update: &StaticUpdate) -> Result<(), Status> {
    if operation.abandoned
        || operation.intent.kind != "static-provider-update"
        || operation.intent.protected_intent != serde_json::to_vec(update).map_err(|_| corrupt())?
    {
        return Err(Status::already_exists(
            "static update identity reused for another intent",
        ));
    }
    Ok(())
}

fn static_manifest<'a>(
    state: &'a OwnerState,
    projection: &ReferenceProjection,
) -> Result<&'a Manifest, Status> {
    let manifest = state
        .manifests
        .get(&projection.manifest_id)
        .ok_or_else(corrupt)?;
    if manifest.status != ManifestStatus::Active
        || manifest.grant_id.is_some()
        || manifest.epoch != projection.epoch
        || manifest.references.get(&projection.credential_key) != Some(&projection.reference_id)
    {
        return Err(Status::failed_precondition(
            "static update binding is pending, revoked, or grant-owned",
        ));
    }
    Ok(manifest)
}
