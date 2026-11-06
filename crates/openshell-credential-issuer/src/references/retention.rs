// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Keep historical proof out of the hot owner record. Arbitrary operation IDs
//! and opaque backend identities have no safe ordered pruning watermark.

use super::{
    ActivationReceipt, CandidateStatus, OperationIntent, OwnerIdentity, OwnerState,
    ReferenceRuntime, SCHEMA_VERSION, SecretOwner, conflict, corrupt, encode_string,
};
use serde::{Deserialize, Serialize};
use tonic::Status;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EvidenceRecord {
    schema_version: u32,
    namespace: String,
    owner: OwnerIdentity,
    retention: Evidence,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Evidence {
    Activation {
        subject: String,
        intent: String,
        receipt: ActivationReceipt,
    },
    DeletedCandidate {
        subject: String,
    },
}

fn digest(domain: &str, value: &impl Serialize) -> Result<String, Status> {
    use std::fmt::Write as _;
    let bytes = serde_json::to_vec(&(domain, value)).map_err(|_| corrupt())?;
    let digest = openshell_crypto::sha256(&bytes)
        .map_err(|_| Status::internal("issuer retention evidence derivation failed"))?;
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(encoded)
}

impl EvidenceRecord {
    pub(super) fn validate(&self) -> Result<(), Status> {
        if self.schema_version != SCHEMA_VERSION
            || self.namespace.is_empty()
            || !matches!(
                self.owner.kind.as_str(),
                "provider" | "sandbox" | "supervisor-instance"
            )
        {
            return Err(corrupt());
        }
        let valid_digest = |value: &str| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        match &self.retention {
            Evidence::Activation {
                subject,
                intent,
                receipt,
            } if valid_digest(subject)
                && valid_digest(intent)
                && !receipt.manifest_id.is_empty()
                && !receipt.epoch.is_empty()
                && receipt.generation > 0
                && !receipt.versions.is_empty()
                && receipt.versions.values().all(|version| *version > 0) =>
            {
                Ok(())
            }
            Evidence::DeletedCandidate { subject } if valid_digest(subject) => Ok(()),
            _ => Err(corrupt()),
        }
    }
}

impl ReferenceRuntime {
    fn evidence_id(
        &self,
        owner: SecretOwner<'_>,
        kind: &str,
        subject: &str,
    ) -> Result<String, Status> {
        encode_string(&(
            "issuer-retention-v1",
            &self.namespace,
            OwnerIdentity::of(owner),
            kind,
            subject,
        ))
    }

    async fn evidence(
        &self,
        owner: SecretOwner<'_>,
        kind: &str,
        subject: &str,
    ) -> Result<Option<EvidenceRecord>, Status> {
        self.store
            .get_retention(&self.evidence_id(owner, kind, subject)?)
            .await?
            .map(|record| {
                let evidence: EvidenceRecord =
                    serde_json::from_slice(&record.payload).map_err(|_| corrupt())?;
                evidence.validate()?;
                if evidence.namespace != self.namespace
                    || evidence.owner != OwnerIdentity::of(owner)
                {
                    return Err(corrupt());
                }
                let matches = match &evidence.retention {
                    Evidence::Activation {
                        subject: actual, ..
                    } => kind == "operation" && actual == subject,
                    Evidence::DeletedCandidate { subject: actual } => {
                        kind == "candidate" && actual == subject
                    }
                };
                if !matches {
                    return Err(corrupt());
                }
                Ok(evidence)
            })
            .transpose()
    }

    async fn retain(
        &self,
        owner: SecretOwner<'_>,
        kind: &str,
        subject: &str,
        retention: Evidence,
    ) -> Result<(), Status> {
        let expected = EvidenceRecord {
            schema_version: SCHEMA_VERSION,
            namespace: self.namespace.clone(),
            owner: OwnerIdentity::of(owner),
            retention,
        };
        if let Some(actual) = self.evidence(owner, kind, subject).await? {
            return if actual == expected {
                Ok(())
            } else {
                Err(corrupt())
            };
        }
        match self
            .store
            .put_retention(
                &self.evidence_id(owner, kind, subject)?,
                serde_json::to_vec(&expected).map_err(|_| corrupt())?,
            )
            .await
        {
            Ok(()) => Ok(()),
            Err(error) if conflict(&error) => {
                if self.evidence(owner, kind, subject).await?.as_ref() == Some(&expected) {
                    Ok(())
                } else {
                    Err(error)
                }
            }
            Err(error) => Err(error),
        }
    }

    pub(super) async fn archived_activation(
        &self,
        owner: SecretOwner<'_>,
        operation_id: &str,
        intent: Option<&OperationIntent>,
    ) -> Result<Option<ActivationReceipt>, Status> {
        let subject = digest("issuer-operation-id-v1", &operation_id)?;
        let Some(record) = self.evidence(owner, "operation", &subject).await? else {
            return Ok(None);
        };
        let Evidence::Activation {
            intent: expected,
            receipt,
            ..
        } = record.retention
        else {
            return Err(corrupt());
        };
        if let Some(intent) = intent
            && digest("issuer-operation-intent-v1", intent)? != expected
        {
            return Err(Status::already_exists(
                "operation identity reused for different protected intent",
            ));
        }
        Ok(Some(receipt))
    }

    pub(super) async fn reject_archived_operation(
        &self,
        owner: SecretOwner<'_>,
        id: &str,
    ) -> Result<(), Status> {
        if self.archived_activation(owner, id, None).await?.is_some() {
            return Err(Status::already_exists(
                "operation identity belongs to a completed activation",
            ));
        }
        Ok(())
    }

    pub(super) async fn candidate_deleted(
        &self,
        owner: SecretOwner<'_>,
        id: &str,
    ) -> Result<bool, Status> {
        let subject = digest("issuer-deleted-candidate-v1", &id)?;
        Ok(self.evidence(owner, "candidate", &subject).await?.is_some())
    }

    /// Archive first, then remove hot-row copies in the owner's normal CAS.
    /// A conflict/crash only leaves duplicate evidence. Never archive an
    /// uncommitted success: only superseded activations can reach this branch.
    pub(super) async fn compact(
        &self,
        owner: SecretOwner<'_>,
        state: &OwnerState,
    ) -> Result<OwnerState, Status> {
        let mut compacted = state.clone();
        for (id, operation) in &state.operations {
            let Some(receipt) = &operation.result else {
                continue;
            };
            if operation.intent.kind != "activate"
                || !operation.write_attempts.is_empty()
                || operation.abandoned
                || state
                    .manifests
                    .get(&operation.intent.manifest_id)
                    .is_none_or(|manifest| manifest.generation <= receipt.generation)
            {
                continue;
            }
            let subject = digest("issuer-operation-id-v1", id)?;
            let intent = digest("issuer-operation-intent-v1", &operation.intent)?;
            self.retain(
                owner,
                "operation",
                &subject,
                Evidence::Activation {
                    subject: subject.clone(),
                    intent,
                    receipt: receipt.clone(),
                },
            )
            .await?;
            compacted.operations.remove(id);
        }
        for (id, candidate) in &state.candidates {
            if candidate.status == CandidateStatus::Deleted {
                let subject = digest("issuer-deleted-candidate-v1", id)?;
                self.retain(
                    owner,
                    "candidate",
                    &subject,
                    Evidence::DeletedCandidate {
                        subject: subject.clone(),
                    },
                )
                .await?;
                compacted.candidates.remove(id);
            }
        }
        Ok(compacted)
    }
}
