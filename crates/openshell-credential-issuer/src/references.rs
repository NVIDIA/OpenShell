// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Embedded, owner-qualified references and one-record output manifests.
//!
//! The embedding process supplies a durable namespace and a conditional object
//! store. An owner record contains its manifests, operation journal, candidate
//! links and reclamation claims: a single CAS therefore arbitrates activation,
//! revocation, adoption and last-link reclamation. Backend I/O never runs in a
//! database transaction. This is deliberately not a cross-owner transaction.
//!
//! `ReferenceRuntime` is not a replacement driver. Reference handles retain the
//! original driver and opaque handle bytes, and carry an explicit, validated
//! `ReferenceProjection` in non-secret metadata. Only this runtime interprets
//! that projection; backend calls always use the recorded candidate handles.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use async_trait::async_trait;
use openshell_core::proto::CredentialHandle;
use prost_types::Timestamp;
use serde::{Deserialize, Serialize};
use tonic::{Code, Status};
use uuid::Uuid;

use crate::{CredentialIssuer, Handles, SecretOwner, SecretOwnerKind, StoreSecrets};

pub mod backend_recovery;
mod retention;
pub mod static_updates;

const SCHEMA_VERSION: u32 = 1;
const RETRY_LIMIT: usize = 8;
const PROJECTION_KEY: &str = "openshell.issuer.reference.v1";
pub const REFERENCE_OBJECT_TYPE: &str = "credential.issuer-reference-owner.v1";
/// Cold, immutable intent receipts and deleted-candidate denial evidence.
pub const REFERENCE_RETENTION_OBJECT_TYPE: &str = "credential.issuer-reference-retention.v1";

/// A conditional persistence record. Payloads contain no credential values.
#[derive(Clone)]
pub struct ReferenceRecord {
    pub resource_version: u64,
    pub payload: Vec<u8>,
}

/// Minimal atomicity port.
///
/// `None` means create-only; `Some(v)` is update-only CAS.
/// A conflict MUST return `AlreadyExists` or `Aborted`, never upsert. Rows
/// must not be deleted: tombstones and reclamation claims survive restarts.
#[async_trait]
pub trait ReferenceStateStore: Send + Sync {
    async fn get(&self, id: &str) -> Result<Option<ReferenceRecord>, Status>;
    async fn put(&self, id: &str, expected: Option<u64>, payload: Vec<u8>) -> Result<(), Status>;
    /// Point lookup in a separate cold-proof collection, excluded from `list`.
    async fn get_retention(&self, id: &str) -> Result<Option<ReferenceRecord>, Status>;
    /// Create-only immutable proof. An existing ID MUST return a conflict;
    /// the runtime verifies its exact contents before accepting a retry.
    async fn put_retention(&self, id: &str, payload: Vec<u8>) -> Result<(), Status>;
    /// Enumerate ONLY hot owner records, never the cold retention collection.
    /// Embedding adapters reuse their existing object-type enumeration.
    async fn list(&self) -> Result<Vec<ReferenceRecord>, Status> {
        Err(Status::unimplemented(
            "reference enumeration requires an embedding adapter",
        ))
    }
}

/// Reuses the existing encrypted-object adapter's conditional row operations;
/// no SQL, new pool, or plaintext encryption implementation is introduced.
pub struct ObjectStoreReferenceStateStore {
    store: Arc<dyn crate::persistence::DbCredstoreObjectStore>,
}

impl ObjectStoreReferenceStateStore {
    pub fn new(store: Arc<dyn crate::persistence::DbCredstoreObjectStore>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl ReferenceStateStore for ObjectStoreReferenceStateStore {
    async fn get(&self, id: &str) -> Result<Option<ReferenceRecord>, Status> {
        Ok(self
            .store
            .get_credential_object(REFERENCE_OBJECT_TYPE, id, "read issuer references")
            .await?
            .map(|record| ReferenceRecord {
                resource_version: record.resource_version,
                payload: record.payload,
            }))
    }

    async fn get_retention(&self, id: &str) -> Result<Option<ReferenceRecord>, Status> {
        Ok(self
            .store
            .get_credential_object(
                REFERENCE_RETENTION_OBJECT_TYPE,
                id,
                "read issuer retention evidence",
            )
            .await?
            .map(|record| ReferenceRecord {
                resource_version: record.resource_version,
                payload: record.payload,
            }))
    }

    async fn put_retention(&self, id: &str, payload: Vec<u8>) -> Result<(), Status> {
        use crate::persistence::{CredentialObjectWrite, DbCredstoreWriteCondition};
        self.store
            .put_credential_object(
                CredentialObjectWrite {
                    object_type: REFERENCE_RETENTION_OBJECT_TYPE.to_owned(),
                    id: id.to_owned(),
                    name: id.to_owned(),
                    payload,
                    labels: None,
                    condition: DbCredstoreWriteCondition::MustCreate,
                },
                "write issuer retention evidence",
            )
            .await
    }

    async fn put(&self, id: &str, expected: Option<u64>, payload: Vec<u8>) -> Result<(), Status> {
        use crate::persistence::{CredentialObjectWrite, DbCredstoreWriteCondition};
        self.store
            .put_credential_object(
                CredentialObjectWrite {
                    object_type: REFERENCE_OBJECT_TYPE.to_owned(),
                    id: id.to_owned(),
                    name: id.to_owned(),
                    payload,
                    labels: None,
                    condition: expected.map_or(
                        DbCredstoreWriteCondition::MustCreate,
                        DbCredstoreWriteCondition::MatchResourceVersion,
                    ),
                },
                "write issuer references",
            )
            .await
    }
}

/// Stable identity excludes the mutable provider display name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerIdentity {
    pub workspace: String,
    pub kind: String,
    pub id: String,
}

impl OwnerIdentity {
    pub fn of(owner: SecretOwner<'_>) -> Self {
        let (kind, id) = match owner.kind {
            SecretOwnerKind::Provider { id, .. } => ("provider", id),
            SecretOwnerKind::Sandbox { id } => ("sandbox", id),
            SecretOwnerKind::SupervisorInstance { sandbox_id } => {
                ("supervisor-instance", sandbox_id)
            }
        };
        Self {
            workspace: owner.workspace.to_owned(),
            kind: kind.to_owned(),
            id: id.to_owned(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct BackendOwner {
    identity: OwnerIdentity,
    provider_name: Option<String>,
}

impl BackendOwner {
    fn of(owner: SecretOwner<'_>) -> Self {
        Self {
            identity: OwnerIdentity::of(owner),
            provider_name: match owner.kind {
                SecretOwnerKind::Provider { name, .. } => Some(name.to_owned()),
                _ => None,
            },
        }
    }

    fn borrowed(&self) -> Result<SecretOwner<'_>, Status> {
        let identity = &self.identity;
        match identity.kind.as_str() {
            "provider" => Ok(SecretOwner::provider(
                &identity.workspace,
                &identity.id,
                self.provider_name.as_deref().ok_or_else(corrupt)?,
            )),
            "sandbox" => Ok(SecretOwner::sandbox(&identity.workspace, &identity.id)),
            "supervisor-instance" => Ok(SecretOwner::supervisor_instance(
                &identity.workspace,
                &identity.id,
            )),
            _ => Err(corrupt()),
        }
    }
}

/// Explicit Rust projection, not a new meaning for the handle's driver field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceProjection {
    pub namespace: String,
    pub owner: OwnerIdentity,
    pub credential_key: String,
    pub epoch: String,
    pub manifest_id: String,
    pub reference_id: String,
}

impl ReferenceProjection {
    pub fn from_handle(handle: &CredentialHandle) -> Result<Option<Self>, Status> {
        handle
            .metadata
            .get(PROJECTION_KEY)
            .map(|encoded| {
                serde_json::from_str(encoded)
                    .map_err(|_| Status::invalid_argument("invalid issuer reference projection"))
            })
            .transpose()
    }

    fn attach(&self, mut handle: CredentialHandle) -> Result<CredentialHandle, Status> {
        handle
            .metadata
            .insert(PROJECTION_KEY.to_owned(), encode_string(self)?);
        Ok(handle)
    }
}

/// Transient secret-bearing result: intentionally neither Debug nor Serialize.
pub struct VersionedSecret {
    pub credential_key: String,
    pub reference: ReferenceProjection,
    pub version: u64,
    pub generation: u64,
    pub value: String,
    pub expiration_time: Option<Timestamp>,
}

/// Non-secret activation receipt, suitable for local invalidation hints.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivationReceipt {
    pub manifest_id: String,
    pub epoch: String,
    pub generation: u64,
    pub versions: BTreeMap<String, u64>,
}

pub struct ActivatedBundle {
    pub handles: Handles,
    pub receipt: ActivationReceipt,
}

/// Secret-bearing static-write input.
///
/// `protected_intent` MUST be an authenticated protected request-intent token
/// from the caller's existing mutation replay mechanism,
/// never plaintext or an unkeyed hash of low-entropy values. Retries must reuse
/// it; changed requests must produce a different token. The issuer also binds
/// the token to owner, epoch, output mapping and expected generation.
pub struct StoreReferenceSecrets<'a> {
    pub owner: SecretOwner<'a>,
    pub epoch: &'a str,
    pub write_id: &'a str,
    pub protected_intent: &'a [u8],
    pub values: &'a HashMap<String, String>,
    pub existing_handles: &'a Handles,
    pub expiration_time: Option<Timestamp>,
}

/// One manifest is the visibility boundary for every candidate in this bundle.
pub struct ActivateBundle<'a> {
    pub owner: SecretOwner<'a>,
    pub epoch: &'a str,
    pub references: &'a Handles,
    pub candidates: &'a Handles,
    pub operation_id: &'a str,
    pub expected_generation: u64,
    pub expiration_time: Option<Timestamp>,
    /// When present, grant finalization and output activation share this CAS.
    pub grant: Option<GrantTransition<'a>>,
}

/// Issuer-owned NONSECRET codec bytes, not a gateway-private protobuf. The
/// caller must keep refresh material in backend handles, never in `state`.
#[derive(Clone, Serialize, Deserialize)]
pub struct GrantRecord {
    pub resource_version: u64,
    pub epoch: String,
    pub state: Vec<u8>,
    pub active: bool,
    /// Prepared is not revoked: only `activate_grant` may authorize it.
    #[serde(default)]
    pub prepared: bool,
}

pub struct GrantTransition<'a> {
    pub grant_id: &'a str,
    pub expected_resource_version: u64,
    pub state: &'a [u8],
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
struct StoredGrantTransition {
    grant_id: String,
    expected_resource_version: u64,
    state: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
struct StoredHandle {
    driver: String,
    handle: String,
    metadata: BTreeMap<String, String>,
}

impl StoredHandle {
    fn of(handle: &CredentialHandle) -> Self {
        Self {
            driver: handle.driver.clone(),
            handle: handle.handle.clone(),
            metadata: handle
                .metadata
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        }
    }
    fn wire(&self) -> CredentialHandle {
        CredentialHandle {
            driver: self.driver.clone(),
            handle: self.handle.clone(),
            metadata: self
                .metadata
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Expiry {
    seconds: i64,
    nanos: i32,
}
impl Expiry {
    fn of(value: &Timestamp) -> Result<Self, Status> {
        if !(0..1_000_000_000).contains(&value.nanos) {
            return Err(Status::invalid_argument("invalid expiration timestamp"));
        }
        Ok(Self {
            seconds: value.seconds,
            nanos: value.nanos,
        })
    }
    fn wire(&self) -> Timestamp {
        Timestamp {
            seconds: self.seconds,
            nanos: self.nanos,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Binding {
    projection: ReferenceProjection,
    identity: StoredHandle,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
enum ManifestStatus {
    Prepared,
    Active,
    Revoked,
}
#[derive(Clone, Serialize, Deserialize)]
struct Manifest {
    epoch: String,
    status: ManifestStatus,
    generation: u64,
    references: BTreeMap<String, String>,
    outputs: BTreeMap<String, ActiveOutput>,
    grant_id: Option<String>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ActiveOutput {
    candidate: String,
    version: u64,
    expiration: Option<Expiry>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
enum CandidateStatus {
    Available,
    Reclaiming,
    Deleted,
}
#[derive(Clone, Serialize, Deserialize)]
struct Candidate {
    key: String,
    handle: StoredHandle,
    owner: BackendOwner,
    status: CandidateStatus,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
struct OperationIntent {
    kind: String,
    epoch: String,
    manifest_id: String,
    expected_generation: u64,
    references: BTreeMap<String, String>,
    candidates: BTreeMap<String, StoredHandle>,
    expiration: Option<Expiry>,
    protected_intent: Vec<u8>,
    grant: Option<StoredGrantTransition>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Operation {
    intent: OperationIntent,
    /// Recorded before backend I/O; callers retain this deterministic staging ID
    /// after an uncertain result. This does not promise exactly-once driver I/O.
    write_id: String,
    #[serde(default)]
    write_attempts: Vec<String>,
    staged: BTreeMap<String, String>,
    result: Option<ActivationReceipt>,
    abandoned: bool,
}
#[derive(Clone, Serialize, Deserialize)]
struct OwnerState {
    schema_version: u32,
    namespace: String,
    owner: OwnerIdentity,
    bindings: BTreeMap<String, Binding>,
    manifests: BTreeMap<String, Manifest>,
    candidates: BTreeMap<String, Candidate>,
    operations: BTreeMap<String, Operation>,
    grants: BTreeMap<String, GrantRecord>,
    #[serde(default)]
    grant_activations: BTreeMap<String, GrantActivationIntent>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GrantActivationIntent {
    expected_new_version: u64,
    old: Option<(String, u64)>,
}

/// Replica coordination uses durable CAS, not a process-local mutex.
///
/// Superseded activation journals and deleted candidates are compacted into
/// immutable intent receipts and denial evidence outside the hot owner record.
/// Unfinished recovery/reclamation debt and current grant state stay in place.
pub struct ReferenceRuntime {
    namespace: String,
    backend: Arc<dyn CredentialIssuer>,
    store: Arc<dyn ReferenceStateStore>,
}

impl std::fmt::Debug for ReferenceRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReferenceRuntime")
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl ReferenceRuntime {
    pub fn new(
        namespace: impl Into<String>,
        backend: Arc<dyn CredentialIssuer>,
        store: Arc<dyn ReferenceStateStore>,
    ) -> Result<Self, Status> {
        let namespace = namespace.into();
        if namespace.is_empty() {
            return Err(Status::invalid_argument(
                "durable issuer namespace is required",
            ));
        }
        Ok(Self {
            namespace,
            backend,
            store,
        })
    }

    fn state_id(&self, owner: SecretOwner<'_>) -> Result<String, Status> {
        encode_string(&(self.namespace.as_str(), OwnerIdentity::of(owner)))
    }

    async fn load(&self, owner: SecretOwner<'_>) -> Result<(Option<u64>, OwnerState), Status> {
        let record = self.store.get(&self.state_id(owner)?).await?;
        let identity = OwnerIdentity::of(owner);
        match record {
            Some(record) => {
                let state: OwnerState =
                    serde_json::from_slice(&record.payload).map_err(|_| corrupt())?;
                if state.schema_version != SCHEMA_VERSION
                    || state.namespace != self.namespace
                    || state.owner != identity
                {
                    return Err(corrupt());
                }
                Ok((Some(record.resource_version), state))
            }
            None => Ok((
                None,
                OwnerState {
                    schema_version: SCHEMA_VERSION,
                    namespace: self.namespace.clone(),
                    owner: identity,
                    bindings: BTreeMap::new(),
                    manifests: BTreeMap::new(),
                    candidates: BTreeMap::new(),
                    operations: BTreeMap::new(),
                    grants: BTreeMap::new(),
                    grant_activations: BTreeMap::new(),
                },
            )),
        }
    }

    async fn save(
        &self,
        owner: SecretOwner<'_>,
        version: Option<u64>,
        state: &OwnerState,
    ) -> Result<(), Status> {
        let state = self.compact(owner, state).await?;
        self.store
            .put(
                &self.state_id(owner)?,
                version,
                serde_json::to_vec(&state).map_err(|_| corrupt())?,
            )
            .await
    }
}

fn encode_string(value: &impl Serialize) -> Result<String, Status> {
    serde_json::to_string(value).map_err(|_| corrupt())
}
fn corrupt() -> Status {
    Status::data_loss("invalid issuer reference state")
}
fn conflict(error: &Status) -> bool {
    matches!(error.code(), Code::Aborted | Code::AlreadyExists)
}
fn contention() -> Status {
    Status::aborted("issuer reference state changed; retry operation")
}

impl ReferenceRuntime {
    /// Construct inactive new-epoch identities without selecting another
    /// driver. These opaque IDs are never sent to the driver as candidates.
    pub fn pending_handles(
        driver: &str,
        keys: impl IntoIterator<Item = String>,
    ) -> Result<Handles, Status> {
        if driver.is_empty() {
            return Err(Status::invalid_argument("reference driver is required"));
        }
        let mut handles = Handles::new();
        for key in keys {
            if key.is_empty() || handles.contains_key(&key) {
                return Err(Status::invalid_argument(
                    "invalid or duplicate reference key",
                ));
            }
            handles.insert(
                key,
                CredentialHandle {
                    driver: driver.to_owned(),
                    handle: format!("issuer-pending-{}", Uuid::new_v4()),
                    metadata: HashMap::new(),
                },
            );
        }
        Ok(handles)
    }

    /// Prepare an inactive fixed-output binding. For adoption, pass original
    /// handles: driver, opaque bytes and original metadata remain unchanged.
    pub async fn prepare_bundle(
        &self,
        owner: SecretOwner<'_>,
        epoch: &str,
        identities: &Handles,
        operation_id: &str,
    ) -> Result<Handles, Status> {
        validate_request(epoch, operation_id, identities)?;
        let manifest_id = encode_string(&("bundle", operation_id))?;
        let references = reference_ids(identities)?;
        let intent = OperationIntent {
            kind: "prepare".to_owned(),
            epoch: epoch.to_owned(),
            manifest_id: manifest_id.clone(),
            expected_generation: 0,
            references: references.clone(),
            candidates: identities
                .iter()
                .map(|(key, handle)| (key.clone(), StoredHandle::of(handle)))
                .collect(),
            expiration: None,
            protected_intent: Vec::new(),
            grant: None,
        };
        for _ in 0..RETRY_LIMIT {
            let (version, mut state) = self.load(owner).await?;
            if let Some(operation) = state.operations.get(operation_id) {
                check_intent(operation, &intent)?;
                return handles_for(&state, &references);
            }
            self.reject_archived_operation(owner, operation_id).await?;
            for (key, handle) in identities {
                if ReferenceProjection::from_handle(handle)?.is_some() {
                    return Err(Status::invalid_argument(
                        "prepare requires original handle identities",
                    ));
                }
                let reference_id = references.get(key).ok_or_else(corrupt)?;
                if state.bindings.contains_key(reference_id) {
                    return Err(Status::already_exists(
                        "reference identity already bound or tombstoned",
                    ));
                }
                let projection = ReferenceProjection {
                    namespace: self.namespace.clone(),
                    owner: OwnerIdentity::of(owner),
                    credential_key: key.clone(),
                    epoch: epoch.to_owned(),
                    manifest_id: manifest_id.clone(),
                    reference_id: reference_id.clone(),
                };
                state.bindings.insert(
                    reference_id.clone(),
                    Binding {
                        projection,
                        identity: StoredHandle::of(handle),
                    },
                );
            }
            let grant_id = state
                .grants
                .iter()
                .find(|(_, grant)| grant.epoch == epoch)
                .map(|(id, _)| id.clone());
            state.manifests.insert(
                manifest_id.clone(),
                Manifest {
                    epoch: epoch.to_owned(),
                    status: ManifestStatus::Prepared,
                    generation: 0,
                    references: references.clone(),
                    outputs: BTreeMap::new(),
                    grant_id,
                },
            );
            state.operations.insert(
                operation_id.to_owned(),
                Operation {
                    intent: intent.clone(),
                    write_id: operation_id.to_owned(),
                    write_attempts: Vec::new(),
                    staged: BTreeMap::new(),
                    result: None,
                    abandoned: false,
                },
            );
            match self.save(owner, version, &state).await {
                Ok(()) => return handles_for(&state, &references),
                Err(error) if conflict(&error) => {}
                Err(error) => return Err(error),
            }
        }
        Err(contention())
    }

    /// Legacy adoption does not rewrite a backend object. The deployment must
    /// exclude incompatible old writers before installing this binding.
    pub async fn adopt(
        &self,
        owner: SecretOwner<'_>,
        handles: &Handles,
        operation_id: &str,
    ) -> Result<Handles, Status> {
        self.adopt_with_expiration(owner, "legacy", handles, None, operation_id)
            .await
    }

    pub async fn adopt_with_expiration(
        &self,
        owner: SecretOwner<'_>,
        epoch: &str,
        handles: &Handles,
        expiration_time: Option<Timestamp>,
        operation_id: &str,
    ) -> Result<Handles, Status> {
        let prepare_id = encode_string(&("adopt-prepare", operation_id))?;
        let activate_id = encode_string(&("adopt-activate", operation_id))?;
        let references = self
            .prepare_bundle(owner, epoch, handles, &prepare_id)
            .await?;
        let (_, state) = self.load(owner).await?;
        if state
            .operations
            .get(&activate_id)
            .is_none_or(|operation| operation.result.is_none())
            && self
                .archived_activation(owner, &activate_id, None)
                .await?
                .is_none()
        {
            // A missing legacy output stays prepared/pending, never a fabricated
            // committed version-1 value. Values are dropped, not serialized.
            let resolved = self.backend.resolve(owner, handles).await?;
            let keys: BTreeSet<_> = resolved
                .iter()
                .map(|value| value.credential_key.as_str())
                .collect();
            if resolved.len() != handles.len()
                || keys.len() != handles.len()
                || handles.keys().any(|key| !keys.contains(key.as_str()))
            {
                return Err(Status::failed_precondition(
                    "legacy adoption has missing outputs",
                ));
            }
        }
        self.activate_bundle(ActivateBundle {
            owner,
            epoch,
            references: &references,
            candidates: handles,
            operation_id: &activate_id,
            expected_generation: 0,
            expiration_time,
            grant: None,
        })
        .await?;
        Ok(references)
    }

    /// CAS a non-secret issuer grant. A revoked record cannot be reactivated;
    /// reconfiguration must allocate a new grant identity and epoch.
    pub async fn put_grant(
        &self,
        owner: SecretOwner<'_>,
        grant_id: &str,
        expected: Option<u64>,
        epoch: &str,
        bytes: &[u8],
        active: bool,
    ) -> Result<GrantRecord, Status> {
        if grant_id.is_empty() || epoch.is_empty() {
            return Err(Status::invalid_argument(
                "grant identity and epoch are required",
            ));
        }
        for _ in 0..RETRY_LIMIT {
            let (version, mut state) = self.load(owner).await?;
            let current = state.grants.get(grant_id);
            if current.map(|g| g.resource_version) != expected {
                return Err(Status::aborted("issuer grant resource version changed"));
            }
            if let Some(current) = current
                && (current.epoch != epoch || (!current.active && active))
            {
                return Err(Status::failed_precondition(
                    "grant epoch is revoked or different",
                ));
            }
            let resource_version = expected
                .unwrap_or(0)
                .checked_add(1)
                .ok_or_else(|| Status::out_of_range("issuer grant version exhausted"))?;
            let grant = GrantRecord {
                resource_version,
                epoch: epoch.to_owned(),
                state: bytes.to_vec(),
                active,
                prepared: current.is_some_and(|record| record.prepared),
            };
            if current.is_some_and(|record| record.active) && !active {
                revoke_epoch(&mut state, epoch);
            }
            state.grants.insert(grant_id.to_owned(), grant.clone());
            match self.save(owner, version, &state).await {
                Ok(()) => return Ok(grant),
                Err(error) if conflict(&error) => {}
                Err(error) => return Err(error),
            }
        }
        Err(contention())
    }

    pub async fn get_grant(
        &self,
        owner: SecretOwner<'_>,
        grant_id: &str,
    ) -> Result<Option<GrantRecord>, Status> {
        Ok(self.load(owner).await?.1.grants.get(grant_id).cloned())
    }

    /// Durably stage candidate links, then activate all outputs and optional
    /// terminal grant state in one owner-record CAS. No provider callbacks.
    pub async fn activate_bundle(
        &self,
        request: ActivateBundle<'_>,
    ) -> Result<ActivatedBundle, Status> {
        let ActivateBundle {
            owner,
            epoch,
            references,
            candidates,
            operation_id,
            expected_generation,
            expiration_time,
            grant,
        } = request;
        validate_request(epoch, operation_id, references)?;
        if references.len() != candidates.len()
            || references.keys().any(|key| !candidates.contains_key(key))
        {
            return Err(Status::invalid_argument(
                "candidate output mapping differs from binding",
            ));
        }
        self.backend.validate_handles(candidates)?;
        let (manifest_id, reference_ids) = self.project_bundle(owner, epoch, references)?;
        let intent = OperationIntent {
            kind: "activate".to_owned(),
            epoch: epoch.to_owned(),
            manifest_id: manifest_id.clone(),
            expected_generation,
            references: reference_ids,
            candidates: candidates
                .iter()
                .map(|(k, v)| (k.clone(), StoredHandle::of(v)))
                .collect(),
            expiration: expiration_time.as_ref().map(Expiry::of).transpose()?,
            protected_intent: Vec::new(),
            grant: grant.map(|g| StoredGrantTransition {
                grant_id: g.grant_id.to_owned(),
                expected_resource_version: g.expected_resource_version,
                state: g.state.to_vec(),
            }),
        };
        // Staging is its own durable recovery point before visibility changes.
        for attempt in 0..RETRY_LIMIT {
            let (version, mut state) = self.load(owner).await?;
            validate_binding(&state, &intent)?;
            if let Some(operation) = state.operations.get(operation_id) {
                check_intent(operation, &intent)?;
                if let Some(receipt) = &operation.result {
                    return Ok(ActivatedBundle {
                        handles: handles_for(&state, &intent.references)?,
                        receipt: receipt.clone(),
                    });
                }
                break;
            }
            if let Some(receipt) = self
                .archived_activation(owner, operation_id, Some(&intent))
                .await?
            {
                return Ok(ActivatedBundle {
                    handles: handles_for(&state, &intent.references)?,
                    receipt,
                });
            }
            validate_activation(&state, &intent)?;
            let mut staged = BTreeMap::new();
            for (key, handle) in candidates {
                let candidate_id = link_candidate(self, &mut state, owner, key, handle).await?;
                // A candidate that was ever activated is immutable: refresh
                // must stage a different physical object, not overwrite live.
                let current = state
                    .manifests
                    .get(&manifest_id)
                    .and_then(|m| m.outputs.get(key));
                if current.is_some_and(|output| output.candidate == candidate_id) {
                    return Err(Status::failed_precondition(
                        "activation requires immutable replacement candidates",
                    ));
                }
                staged.insert(key.clone(), candidate_id);
            }
            state.operations.insert(
                operation_id.to_owned(),
                Operation {
                    intent: intent.clone(),
                    write_id: operation_id.to_owned(),
                    write_attempts: Vec::new(),
                    staged,
                    result: None,
                    abandoned: false,
                },
            );
            match self.save(owner, version, &state).await {
                Ok(()) => break,
                Err(error) if conflict(&error) && attempt + 1 < RETRY_LIMIT => {}
                Err(error) => return Err(error),
            }
        }
        for _ in 0..RETRY_LIMIT {
            let (version, mut state) = self.load(owner).await?;
            let Some(operation) = state.operations.get(operation_id).cloned() else {
                let receipt = self
                    .archived_activation(owner, operation_id, Some(&intent))
                    .await?
                    .ok_or_else(corrupt)?;
                return Ok(ActivatedBundle {
                    handles: handles_for(&state, &intent.references)?,
                    receipt,
                });
            };
            check_intent(&operation, &intent)?;
            if let Some(receipt) = operation.result {
                return Ok(ActivatedBundle {
                    handles: handles_for(&state, &intent.references)?,
                    receipt,
                });
            }
            validate_activation(&state, &intent)?;
            let manifest = state.manifests.get_mut(&manifest_id).ok_or_else(corrupt)?;
            let mut outputs = BTreeMap::new();
            for (key, candidate) in &operation.staged {
                if state
                    .candidates
                    .get(candidate)
                    .is_none_or(|c| c.status != CandidateStatus::Available)
                {
                    return Err(Status::failed_precondition("candidate is being reclaimed"));
                }
                let next = manifest.outputs.get(key).map_or(Ok(1), |old| {
                    old.version
                        .checked_add(1)
                        .ok_or_else(|| Status::out_of_range("secret version exhausted"))
                })?;
                outputs.insert(
                    key.clone(),
                    ActiveOutput {
                        candidate: candidate.clone(),
                        version: next,
                        expiration: intent.expiration.clone(),
                    },
                );
            }
            if outputs.len() != manifest.references.len() {
                return Err(corrupt());
            }
            let generation = manifest
                .generation
                .checked_add(1)
                .ok_or_else(|| Status::out_of_range("activation generation exhausted"))?;
            manifest.generation = generation;
            manifest.outputs = outputs;
            manifest.status = ManifestStatus::Active;
            if let Some(transition) = &intent.grant {
                manifest.grant_id = Some(transition.grant_id.clone());
            }
            let receipt = ActivationReceipt {
                manifest_id: manifest_id.clone(),
                epoch: epoch.to_owned(),
                generation,
                versions: manifest
                    .outputs
                    .iter()
                    .map(|(key, value)| (key.clone(), value.version))
                    .collect(),
            };
            if let Some(transition) = &intent.grant {
                let grant = state
                    .grants
                    .get_mut(&transition.grant_id)
                    .ok_or_else(corrupt)?;
                grant.resource_version = grant
                    .resource_version
                    .checked_add(1)
                    .ok_or_else(|| Status::out_of_range("issuer grant version exhausted"))?;
                grant.state.clone_from(&transition.state);
            }
            state
                .operations
                .get_mut(operation_id)
                .ok_or_else(corrupt)?
                .result = Some(receipt.clone());
            match self.save(owner, version, &state).await {
                Ok(()) => {
                    return Ok(ActivatedBundle {
                        handles: handles_for(&state, &intent.references)?,
                        receipt,
                    });
                }
                Err(error) if conflict(&error) => {}
                Err(error) => return Err(error),
            }
        }
        Err(contention())
    }

    fn project_bundle(
        &self,
        owner: SecretOwner<'_>,
        epoch: &str,
        handles: &Handles,
    ) -> Result<(String, BTreeMap<String, String>), Status> {
        let mut manifest_id = None;
        let mut ids = BTreeMap::new();
        for (key, handle) in handles {
            let projection = self.projection(owner, key, handle)?;
            if projection.epoch != epoch
                || manifest_id
                    .as_ref()
                    .is_some_and(|id| id != &projection.manifest_id)
            {
                return Err(Status::permission_denied(
                    "reference epoch or bundle mismatch",
                ));
            }
            manifest_id = Some(projection.manifest_id.clone());
            ids.insert(key.clone(), projection.reference_id);
        }
        Ok((
            manifest_id.ok_or_else(|| Status::invalid_argument("empty reference bundle"))?,
            ids,
        ))
    }

    fn projection(
        &self,
        owner: SecretOwner<'_>,
        key: &str,
        handle: &CredentialHandle,
    ) -> Result<ReferenceProjection, Status> {
        let projection = ReferenceProjection::from_handle(handle)?
            .ok_or_else(|| Status::failed_precondition("legacy handle has not been adopted"))?;
        if projection.namespace != self.namespace
            || projection.owner != OwnerIdentity::of(owner)
            || projection.credential_key != key
            || projection.reference_id != reference_id(key, handle)?
        {
            return Err(Status::permission_denied(
                "issuer reference owner or identity mismatch",
            ));
        }
        Ok(projection)
    }
}

fn validate_request(epoch: &str, operation_id: &str, handles: &Handles) -> Result<(), Status> {
    if epoch.is_empty()
        || operation_id.is_empty()
        || handles.is_empty()
        || handles.iter().any(|(key, handle)| {
            key.is_empty() || handle.driver.is_empty() || handle.handle.is_empty()
        })
    {
        return Err(Status::invalid_argument(
            "epoch, operation identity and nonempty handles are required",
        ));
    }
    Ok(())
}
fn reference_id(key: &str, handle: &CredentialHandle) -> Result<String, Status> {
    encode_string(&(key, &handle.driver, &handle.handle))
}
fn reference_ids(handles: &Handles) -> Result<BTreeMap<String, String>, Status> {
    handles
        .iter()
        .map(|(key, handle)| Ok((key.clone(), reference_id(key, handle)?)))
        .collect()
}
fn handles_for(
    state: &OwnerState,
    references: &BTreeMap<String, String>,
) -> Result<Handles, Status> {
    references
        .iter()
        .map(|(key, id)| {
            let binding = state.bindings.get(id).ok_or_else(corrupt)?;
            Ok((
                key.clone(),
                binding.projection.attach(binding.identity.wire())?,
            ))
        })
        .collect()
}
fn check_intent(operation: &Operation, intent: &OperationIntent) -> Result<(), Status> {
    if operation.intent != *intent {
        return Err(Status::already_exists(
            "operation identity reused for different protected intent",
        ));
    }
    if operation.abandoned {
        return Err(Status::failed_precondition("issuer operation is abandoned"));
    }
    Ok(())
}
fn validate_binding(state: &OwnerState, intent: &OperationIntent) -> Result<(), Status> {
    let manifest = state
        .manifests
        .get(&intent.manifest_id)
        .ok_or_else(|| Status::not_found("issuer manifest not found"))?;
    if manifest.epoch != intent.epoch || manifest.references != intent.references {
        return Err(Status::permission_denied("manifest binding mismatch"));
    }
    for (key, id) in &intent.references {
        let binding = state.bindings.get(id).ok_or_else(corrupt)?;
        if binding.projection.epoch != intent.epoch
            || binding.projection.credential_key != *key
            || binding.projection.manifest_id != intent.manifest_id
        {
            return Err(corrupt());
        }
    }
    Ok(())
}
fn validate_activation(state: &OwnerState, intent: &OperationIntent) -> Result<(), Status> {
    validate_binding(state, intent)?;
    let manifest = state
        .manifests
        .get(&intent.manifest_id)
        .ok_or_else(corrupt)?;
    if manifest.status == ManifestStatus::Revoked {
        return Err(Status::failed_precondition("reference epoch is revoked"));
    }
    if manifest.generation != intent.expected_generation {
        return Err(Status::aborted("activation generation changed"));
    }
    if manifest.grant_id.as_ref().is_some_and(|id| {
        intent
            .grant
            .as_ref()
            .is_none_or(|transition| &transition.grant_id != id)
    }) {
        return Err(Status::failed_precondition(
            "grant-owned output requires its grant transition",
        ));
    }
    if let Some(transition) = &intent.grant {
        let grant = state
            .grants
            .get(&transition.grant_id)
            .ok_or_else(|| Status::not_found("issuer grant not found"))?;
        if !grant.active || grant.epoch != intent.epoch {
            return Err(Status::failed_precondition(
                "grant epoch is revoked or different",
            ));
        }
        if grant.resource_version != transition.expected_resource_version {
            return Err(Status::aborted("issuer grant resource version changed"));
        }
    }
    Ok(())
}
async fn link_candidate(
    runtime: &ReferenceRuntime,
    state: &mut OwnerState,
    owner: SecretOwner<'_>,
    key: &str,
    handle: &CredentialHandle,
) -> Result<String, Status> {
    if ReferenceProjection::from_handle(handle)?.is_some() {
        return Err(Status::invalid_argument(
            "backend candidate must not be an issuer reference",
        ));
    }
    let id = reference_id(key, handle)?;
    match state.candidates.get(&id) {
        Some(candidate) if candidate.status != CandidateStatus::Available => {
            return Err(Status::failed_precondition(
                "candidate reclamation already claimed",
            ));
        }
        Some(candidate) if candidate.handle != StoredHandle::of(handle) => {
            return Err(Status::failed_precondition("candidate metadata changed"));
        }
        Some(_) => {}
        None => {
            if runtime.candidate_deleted(owner, &id).await? {
                return Err(Status::failed_precondition(
                    "candidate reclamation already claimed",
                ));
            }
            state.candidates.insert(
                id.clone(),
                Candidate {
                    key: key.to_owned(),
                    handle: StoredHandle::of(handle),
                    owner: BackendOwner::of(owner),
                    status: CandidateStatus::Available,
                },
            );
        }
    }
    Ok(id)
}

impl ReferenceRuntime {
    /// Resolve once per captured manifest, then revalidate after backend I/O.
    /// Cleanup may remove a replaced candidate during the read: a changed
    /// capture is retried, never relabelled with the old version. No backend
    /// error is converted into an apparently complete successful snapshot.
    pub async fn resolve(
        &self,
        owner: SecretOwner<'_>,
        handles: &Handles,
    ) -> Result<Vec<VersionedSecret>, Status> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Status::internal("system time precedes epoch"))?;
        let seconds = i64::try_from(now.as_secs())
            .map_err(|_| Status::internal("system time exceeds timestamp range"))?;
        self.resolve_at(
            owner,
            handles,
            Timestamp {
                seconds,
                nanos: i32::try_from(now.subsec_nanos())
                    .map_err(|_| Status::internal("system time nanoseconds exceed range"))?,
            },
        )
        .await
    }

    pub async fn resolve_at(
        &self,
        owner: SecretOwner<'_>,
        handles: &Handles,
        now: Timestamp,
    ) -> Result<Vec<VersionedSecret>, Status> {
        let now = Expiry::of(&now)?;
        let projections: BTreeMap<_, _> = handles
            .iter()
            .map(|(key, handle)| Ok((key.clone(), self.projection(owner, key, handle)?)))
            .collect::<Result<_, Status>>()?;
        if projections.is_empty() {
            return Ok(Vec::new());
        }
        for _ in 0..RETRY_LIMIT {
            let (_, state) = self.load(owner).await?;
            let capture = capture(&state, &projections)?;
            let mut resolved = Vec::new();
            let mut first_error = None;
            // Different captured candidates can retain different legacy owner
            // names; ownership identity still excludes those audit names.
            for (key, entry) in &capture {
                let candidate = state
                    .candidates
                    .get(&entry.output.candidate)
                    .ok_or_else(corrupt)?;
                let backend_handles = HashMap::from([(key.clone(), candidate.handle.wire())]);
                match self
                    .backend
                    .resolve(candidate.owner.borrowed()?, &backend_handles)
                    .await
                {
                    Ok(mut values) => {
                        if values.len() != 1 || values[0].credential_key != *key {
                            first_error = Some(Status::data_loss(
                                "backend returned an incomplete reference result",
                            ));
                            break;
                        }
                        let value = values.remove(0);
                        let backend_expiry =
                            value.expiration_time.as_ref().map(Expiry::of).transpose()?;
                        let expiration =
                            minimum_expiry(entry.output.expiration.clone(), backend_expiry);
                        if expiration.as_ref().is_some_and(|expiry| {
                            (expiry.seconds, expiry.nanos) <= (now.seconds, now.nanos)
                        }) {
                            first_error =
                                Some(Status::failed_precondition("issuer reference is expired"));
                            break;
                        }
                        resolved.push(VersionedSecret {
                            credential_key: key.clone(),
                            reference: projections.get(key).ok_or_else(corrupt)?.clone(),
                            version: entry.output.version,
                            generation: entry.generation,
                            value: value.value,
                            expiration_time: expiration.map(|e| e.wire()),
                        });
                    }
                    Err(error) => {
                        first_error = Some(error);
                        break;
                    }
                }
            }
            let (_, after) = self.load(owner).await?;
            match capture_matches(&after, &projections, &capture) {
                Ok(true) => return first_error.map_or(Ok(resolved), Err),
                Ok(false) => {}
                Err(error) => return Err(error),
            }
        }
        Err(contention())
    }

    /// Exact binding/epoch tombstones. Revocation creates cleanup debt; it
    /// never blindly deletes candidates shared by another live binding.
    pub async fn delete(&self, owner: SecretOwner<'_>, handles: &Handles) -> Result<(), Status> {
        self.revoke(owner, handles, None).await
    }

    /// The optional grant revocation shares the manifest tombstone CAS. All
    /// supplied references must be from that grant's exact epoch.
    pub async fn revoke(
        &self,
        owner: SecretOwner<'_>,
        handles: &Handles,
        grant_id: Option<&str>,
    ) -> Result<(), Status> {
        let projections: Vec<_> = handles
            .iter()
            .map(|(key, handle)| self.projection(owner, key, handle))
            .collect::<Result<_, _>>()?;
        if projections.is_empty() {
            return Ok(());
        }
        for _ in 0..RETRY_LIMIT {
            let (version, mut state) = self.load(owner).await?;
            let mut manifest_ids = BTreeSet::new();
            for projection in &projections {
                let binding = state
                    .bindings
                    .get(&projection.reference_id)
                    .ok_or_else(|| Status::not_found("issuer reference not found"))?;
                if binding.projection != *projection {
                    return Err(Status::permission_denied("reference binding changed"));
                }
                let manifest = state
                    .manifests
                    .get_mut(&projection.manifest_id)
                    .ok_or_else(corrupt)?;
                if manifest.epoch != projection.epoch {
                    return Err(Status::permission_denied("reference epoch mismatch"));
                }
                manifest.status = ManifestStatus::Revoked;
                manifest_ids.insert(projection.manifest_id.clone());
            }
            if let Some(grant_id) = grant_id {
                let grant = state
                    .grants
                    .get_mut(grant_id)
                    .ok_or_else(|| Status::not_found("issuer grant not found"))?;
                if projections
                    .iter()
                    .any(|projection| projection.epoch != grant.epoch)
                {
                    return Err(Status::permission_denied("grant epoch mismatch"));
                }
                if grant.active || grant.prepared {
                    grant.active = false;
                    grant.prepared = false;
                    grant.resource_version = grant
                        .resource_version
                        .checked_add(1)
                        .ok_or_else(|| Status::out_of_range("issuer grant version exhausted"))?;
                }
            }
            for operation in state.operations.values_mut() {
                if manifest_ids.contains(&operation.intent.manifest_id)
                    && operation.result.is_none()
                {
                    operation.abandoned = true;
                }
            }
            match self.save(owner, version, &state).await {
                Ok(()) => return Ok(()),
                Err(error) if conflict(&error) => {}
                Err(error) => return Err(error),
            }
        }
        Err(contention())
    }

    /// Explicitly release a failed/stale operation's staged links. Successful
    /// activations remain successful and cannot be abandoned retroactively.
    pub async fn abandon_operation(
        &self,
        owner: SecretOwner<'_>,
        operation_id: &str,
    ) -> Result<(), Status> {
        for _ in 0..RETRY_LIMIT {
            let (version, mut state) = self.load(owner).await?;
            if !state.operations.contains_key(operation_id)
                && self
                    .archived_activation(owner, operation_id, None)
                    .await?
                    .is_some()
            {
                return Err(Status::failed_precondition(
                    "committed activation cannot be abandoned",
                ));
            }
            let operation = state
                .operations
                .get_mut(operation_id)
                .ok_or_else(|| Status::not_found("issuer operation not found"))?;
            if operation.result.is_some() {
                return Err(Status::failed_precondition(
                    "committed activation cannot be abandoned",
                ));
            }
            operation.abandoned = true;
            match self.save(owner, version, &state).await {
                Ok(()) => return Ok(()),
                Err(error) if conflict(&error) => {}
                Err(error) => return Err(error),
            }
        }
        Err(contention())
    }

    /// Bounded cleanup. Last-link detection and the durable reclamation claim
    /// share the same CAS as every possible new link. Failed/uncertain deletes
    /// retain the claim; adoption cannot resurrect that physical candidate.
    pub async fn reclaim(&self, owner: SecretOwner<'_>, limit: usize) -> Result<usize, Status> {
        let mut completed = 0;
        for _ in 0..limit {
            let mut claimed = None;
            for _ in 0..RETRY_LIMIT {
                let (version, mut state) = self.load(owner).await?;
                let reachable = reachable_candidates(&state);
                let candidate_id = state
                    .candidates
                    .iter()
                    .find(|(id, candidate)| {
                        candidate.status == CandidateStatus::Reclaiming
                            || (candidate.status == CandidateStatus::Available
                                && !reachable.contains(*id))
                    })
                    .map(|(id, _)| id.clone());
                let Some(candidate_id) = candidate_id else {
                    return Ok(completed);
                };
                let candidate = state
                    .candidates
                    .get_mut(&candidate_id)
                    .ok_or_else(corrupt)?;
                candidate.status = CandidateStatus::Reclaiming;
                let candidate = candidate.clone();
                match self.save(owner, version, &state).await {
                    Ok(()) => {
                        claimed = Some((candidate_id, candidate));
                        break;
                    }
                    Err(error) if conflict(&error) => {}
                    Err(error) => return Err(error),
                }
            }
            let (candidate_id, candidate) = claimed.ok_or_else(contention)?;
            self.backend
                .delete(
                    candidate.owner.borrowed()?,
                    &HashMap::from([(candidate.key.clone(), candidate.handle.wire())]),
                )
                .await?;
            let mut marked = false;
            for _ in 0..RETRY_LIMIT {
                let (version, mut state) = self.load(owner).await?;
                let Some(current) = state.candidates.get_mut(&candidate_id) else {
                    if self.candidate_deleted(owner, &candidate_id).await? {
                        marked = true;
                        break;
                    }
                    return Err(corrupt());
                };
                if current.status == CandidateStatus::Deleted {
                    marked = true;
                    break;
                }
                if current.status != CandidateStatus::Reclaiming {
                    return Err(corrupt());
                }
                current.status = CandidateStatus::Deleted;
                match self.save(owner, version, &state).await {
                    Ok(()) => {
                        marked = true;
                        break;
                    }
                    Err(error) if conflict(&error) => {}
                    Err(error) => return Err(error),
                }
            }
            if !marked {
                return Err(contention());
            }
            completed += 1;
        }
        Ok(completed)
    }
}

#[derive(Clone, PartialEq, Eq)]
struct CapturedOutput {
    generation: u64,
    output: ActiveOutput,
}
fn capture(
    state: &OwnerState,
    projections: &BTreeMap<String, ReferenceProjection>,
) -> Result<BTreeMap<String, CapturedOutput>, Status> {
    projections
        .iter()
        .map(|(key, projection)| {
            let binding = state
                .bindings
                .get(&projection.reference_id)
                .ok_or_else(|| Status::not_found("issuer reference not found"))?;
            if binding.projection != *projection {
                return Err(Status::permission_denied(
                    "issuer reference binding mismatch",
                ));
            }
            let manifest = state
                .manifests
                .get(&projection.manifest_id)
                .ok_or_else(corrupt)?;
            if manifest.epoch != projection.epoch || manifest.status != ManifestStatus::Active {
                return Err(Status::failed_precondition(
                    "issuer reference is pending or revoked",
                ));
            }
            if let Some(grant_id) = &manifest.grant_id
                && state.grants.get(grant_id).is_none_or(|grant| {
                    !grant.active || grant.prepared || grant.epoch != projection.epoch
                })
            {
                return Err(Status::failed_precondition(
                    "issuer reference grant is pending or revoked",
                ));
            }
            let output = manifest.outputs.get(key).ok_or_else(|| {
                Status::failed_precondition("issuer reference has no active output")
            })?;
            if output.version == 0
                || state
                    .candidates
                    .get(&output.candidate)
                    .is_none_or(|c| c.status != CandidateStatus::Available)
            {
                return Err(corrupt());
            }
            Ok((
                key.clone(),
                CapturedOutput {
                    generation: manifest.generation,
                    output: output.clone(),
                },
            ))
        })
        .collect()
}
fn capture_matches(
    state: &OwnerState,
    projections: &BTreeMap<String, ReferenceProjection>,
    previous: &BTreeMap<String, CapturedOutput>,
) -> Result<bool, Status> {
    Ok(capture(state, projections)? == *previous)
}
fn minimum_expiry(left: Option<Expiry>, right: Option<Expiry>) -> Option<Expiry> {
    match (left, right) {
        (Some(left), Some(right)) => Some(
            if (left.seconds, left.nanos) <= (right.seconds, right.nanos) {
                left
            } else {
                right
            },
        ),
        (left, right) => left.or(right),
    }
}
fn reachable_candidates(state: &OwnerState) -> BTreeSet<String> {
    let mut reachable: BTreeSet<_> = state
        .manifests
        .values()
        .filter(|m| m.status == ManifestStatus::Active)
        .flat_map(|m| m.outputs.values().map(|o| o.candidate.clone()))
        .collect();
    for operation in state.operations.values() {
        if operation.result.is_none()
            && !operation.abandoned
            && state
                .manifests
                .get(&operation.intent.manifest_id)
                .is_some_and(|m| m.status != ManifestStatus::Revoked)
        {
            reachable.extend(operation.staged.values().cloned());
        }
    }
    reachable
}

/// Non-secret recovery evidence for backend writes with unknown outcomes.
///
/// A driver unable to look up these object IDs requires operator/backend
/// recovery; the runtime does not pretend that such orphans are safely deleted.
#[derive(Clone, Debug)]
pub struct WriteRecovery {
    pub operation_id: String,
    pub write_id: String,
    pub attempt_object_ids: Vec<String>,
    pub staged_keys: Vec<String>,
    pub committed: bool,
    pub abandoned: bool,
}

impl ReferenceRuntime {
    /// Static keys intentionally use independent single-output manifests.
    /// Pass existing references to preserve their identity within the binding.
    /// This method does not make unrelated static keys a transactional bundle.
    pub async fn store(&self, request: StoreReferenceSecrets<'_>) -> Result<Handles, Status> {
        if request.epoch.is_empty()
            || request.write_id.is_empty()
            || request.protected_intent.is_empty()
        {
            return Err(Status::invalid_argument(
                "static write requires epoch, write identity and protected intent",
            ));
        }
        let mut keys: Vec<_> = request.values.keys().cloned().collect();
        keys.sort();
        let mut result = Handles::new();
        for key in keys {
            let handle = self.store_one(&request, &key).await?;
            result.insert(key, handle);
        }
        Ok(result)
    }

    async fn store_one(
        &self,
        request: &StoreReferenceSecrets<'_>,
        key: &str,
    ) -> Result<CredentialHandle, Status> {
        let owner = request.owner;
        let operation_id = encode_string(&("static-write", request.write_id, key))?;
        let prepare_id = encode_string(&("static-prepare", request.write_id, key))?;
        let activate_id = encode_string(&("static-activate", request.write_id, key))?;
        let existing = request.existing_handles.get(key);
        let projection = existing
            .map(|handle| self.projection(owner, key, handle))
            .transpose()?;
        if projection
            .as_ref()
            .is_some_and(|p| p.epoch != request.epoch)
        {
            return Err(Status::permission_denied(
                "static write epoch differs from binding",
            ));
        }
        let manifest_id = projection
            .as_ref()
            .map_or(encode_string(&("bundle", &prepare_id))?, |p| {
                p.manifest_id.clone()
            });
        let references = projection
            .as_ref()
            .map(|p| BTreeMap::from([(key.to_owned(), p.reference_id.clone())]))
            .unwrap_or_default();
        let expiration = request
            .expiration_time
            .as_ref()
            .map(Expiry::of)
            .transpose()?;
        let mut journal = None;
        for _ in 0..RETRY_LIMIT {
            let (version, mut state) = self.load(owner).await?;
            if let Some(operation) = state.operations.get(&operation_id) {
                let intent = &operation.intent;
                if operation.abandoned {
                    return Err(Status::failed_precondition("static write is abandoned"));
                }
                if intent.kind != "static-write"
                    || intent.epoch != request.epoch
                    || intent.manifest_id != manifest_id
                    || intent.references != references
                    || intent.expiration != expiration
                    || intent.protected_intent != request.protected_intent
                {
                    return Err(Status::already_exists(
                        "write identity reused for different protected intent",
                    ));
                }
                journal = Some(operation.clone());
                break;
            }
            self.reject_archived_operation(owner, &operation_id).await?;
            let expected_generation = if let Some(projection) = &projection {
                let binding = state
                    .bindings
                    .get(&projection.reference_id)
                    .ok_or_else(|| Status::not_found("static reference not found"))?;
                if binding.projection != *projection {
                    return Err(Status::permission_denied("static binding mismatch"));
                }
                let manifest = state.manifests.get(&manifest_id).ok_or_else(corrupt)?;
                if manifest.status == ManifestStatus::Revoked {
                    return Err(Status::failed_precondition("static binding is revoked"));
                }
                if manifest.references.len() != 1 || manifest.grant_id.is_some() {
                    return Err(Status::failed_precondition(
                        "cannot independently write a grant-owned output",
                    ));
                }
                manifest.generation
            } else {
                0
            };
            let operation = Operation {
                intent: OperationIntent {
                    kind: "static-write".to_owned(),
                    epoch: request.epoch.to_owned(),
                    manifest_id: manifest_id.clone(),
                    expected_generation,
                    references: references.clone(),
                    candidates: BTreeMap::new(),
                    expiration: expiration.clone(),
                    protected_intent: request.protected_intent.to_vec(),
                    grant: None,
                },
                write_id: request.write_id.to_owned(),
                write_attempts: Vec::new(),
                staged: BTreeMap::new(),
                result: None,
                abandoned: false,
            };
            state
                .operations
                .insert(operation_id.clone(), operation.clone());
            match self.save(owner, version, &state).await {
                Ok(()) => {
                    journal = Some(operation);
                    break;
                }
                Err(error) if conflict(&error) => {}
                Err(error) => return Err(error),
            }
        }
        let mut journal = journal.ok_or_else(contention)?;
        let mut reference_handles = existing.map(|h| HashMap::from([(key.to_owned(), h.clone())]));
        if journal.staged.is_empty() {
            // Each physical execution has its own unique immutable object ID.
            // It is journalled BEFORE I/O. Concurrent retries cannot overwrite
            // a candidate that another execution has already made live.
            let attempt_id = format!("issuer-write-{}", Uuid::new_v4());
            let mut recorded = false;
            for _ in 0..RETRY_LIMIT {
                let (version, mut state) = self.load(owner).await?;
                let operation = state
                    .operations
                    .get_mut(&operation_id)
                    .ok_or_else(corrupt)?;
                if operation.abandoned {
                    return Err(Status::failed_precondition("static write is abandoned"));
                }
                if !operation.staged.is_empty() {
                    journal = operation.clone();
                    recorded = true;
                    break;
                }
                operation.write_attempts.push(attempt_id.clone());
                match self.save(owner, version, &state).await {
                    Ok(()) => {
                        recorded = true;
                        break;
                    }
                    Err(error) if conflict(&error) => {}
                    Err(error) => return Err(error),
                }
            }
            if !recorded {
                return Err(contention());
            }
            if journal.staged.is_empty() {
                let values = HashMap::from([(
                    key.to_owned(),
                    request.values.get(key).ok_or_else(corrupt)?.clone(),
                )]);
                let empty = Handles::new();
                let candidates = self
                    .backend
                    .store(StoreSecrets {
                        owner,
                        object_id: Some(&attempt_id),
                        values: &values,
                        existing_handles: &empty,
                    })
                    .await?;
                if candidates.len() != 1 || !candidates.contains_key(key) {
                    return Err(Status::data_loss(
                        "backend did not return the staged static output",
                    ));
                }
                self.backend.validate_handles(&candidates)?;
                if reference_handles.is_none() {
                    // A concurrent retry may have prepared a different physical
                    // candidate as the winning reference identity. Its binding
                    // is authoritative; never replace it with this execution's.
                    match self
                        .prepare_bundle(owner, request.epoch, &candidates, &prepare_id)
                        .await
                    {
                        Ok(handles) => reference_handles = Some(handles),
                        Err(error) if error.code() == Code::AlreadyExists => {
                            let (_, state) = self.load(owner).await?;
                            let manifest = state.manifests.get(&manifest_id).ok_or_else(corrupt)?;
                            reference_handles = Some(handles_for(&state, &manifest.references)?);
                        }
                        Err(error) => return Err(error),
                    }
                }
                let mut staged = false;
                for _ in 0..RETRY_LIMIT {
                    let (version, mut state) = self.load(owner).await?;
                    let candidate_id = link_candidate(
                        self,
                        &mut state,
                        owner,
                        key,
                        candidates.get(key).ok_or_else(corrupt)?,
                    )
                    .await?;
                    let operation = state
                        .operations
                        .get_mut(&operation_id)
                        .ok_or_else(corrupt)?;
                    if operation.abandoned {
                        return Err(Status::failed_precondition("static write is abandoned"));
                    }
                    // A losing physical candidate is retained as cleanup debt.
                    if operation.staged.is_empty() {
                        operation.staged.insert(key.to_owned(), candidate_id);
                    }
                    journal = operation.clone();
                    match self.save(owner, version, &state).await {
                        Ok(()) => {
                            staged = true;
                            break;
                        }
                        Err(error) if conflict(&error) => {}
                        Err(error) => return Err(error),
                    }
                }
                if !staged {
                    return Err(contention());
                }
            }
        }
        let (_, state) = self.load(owner).await?;
        // Static journals stay hot, but another retry may have completed this
        // one while its old candidates were superseded and reclaimed. Recheck
        // its exact durable intent and abandonment before replaying a receipt
        // or reconstructing candidates from this same owner snapshot.
        let current_journal = state.operations.get(&operation_id).ok_or_else(corrupt)?;
        check_intent(current_journal, &journal.intent)?;
        let journal = current_journal;
        let manifest = state.manifests.get(&manifest_id).ok_or_else(corrupt)?;
        let reference_handles =
            reference_handles.unwrap_or(handles_for(&state, &manifest.references)?);
        if let Some(receipt) = &journal.result {
            // A completed retry returns its original binding, not a new write.
            if receipt.manifest_id != manifest_id {
                return Err(corrupt());
            }
            return reference_handles.get(key).cloned().ok_or_else(corrupt);
        }
        let candidates: Handles = journal
            .staged
            .iter()
            .map(|(key, id)| {
                Ok((
                    key.clone(),
                    state.candidates.get(id).ok_or_else(corrupt)?.handle.wire(),
                ))
            })
            .collect::<Result<_, Status>>()?;
        let activated = self
            .activate_bundle(ActivateBundle {
                owner,
                epoch: request.epoch,
                references: &reference_handles,
                candidates: &candidates,
                operation_id: &activate_id,
                expected_generation: journal.intent.expected_generation,
                expiration_time: request.expiration_time,
                grant: None,
            })
            .await?;
        for _ in 0..RETRY_LIMIT {
            let (version, mut state) = self.load(owner).await?;
            state
                .operations
                .get_mut(&operation_id)
                .ok_or_else(corrupt)?
                .result = Some(activated.receipt.clone());
            match self.save(owner, version, &state).await {
                Ok(()) => return activated.handles.get(key).cloned().ok_or_else(corrupt),
                Err(error) if conflict(&error) => {}
                Err(error) => return Err(error),
            }
        }
        Err(contention())
    }

    pub async fn write_recovery(
        &self,
        owner: SecretOwner<'_>,
    ) -> Result<Vec<WriteRecovery>, Status> {
        let (_, state) = self.load(owner).await?;
        Ok(state
            .operations
            .iter()
            .filter(|(_, operation)| !operation.write_attempts.is_empty())
            .map(|(id, operation)| WriteRecovery {
                operation_id: id.clone(),
                write_id: operation.write_id.clone(),
                attempt_object_ids: operation.write_attempts.clone(),
                staged_keys: operation.staged.keys().cloned().collect(),
                committed: operation.result.is_some(),
                abandoned: operation.abandoned,
            })
            .collect())
    }
}

impl ReferenceRuntime {
    /// Enumerate issuer-owned grant journals, including inactive tombstones.
    /// The embedding adapter must provide durable object-type enumeration.
    pub async fn list_grants(
        &self,
        provider_id: Option<&str>,
    ) -> Result<Vec<(OwnerIdentity, String, GrantRecord)>, Status> {
        read_grants(self.store.as_ref(), &self.namespace, provider_id).await
    }

    /// Prepared references return generation zero; revoked epochs fail closed.
    pub async fn manifest_generation(
        &self,
        owner: SecretOwner<'_>,
        epoch: &str,
        handles: &Handles,
    ) -> Result<u64, Status> {
        let (manifest_id, references) = self.project_bundle(owner, epoch, handles)?;
        let (_, state) = self.load(owner).await?;
        let manifest = state
            .manifests
            .get(&manifest_id)
            .ok_or_else(|| Status::not_found("issuer manifest not found"))?;
        if manifest.epoch != epoch || manifest.references != references {
            return Err(Status::permission_denied("manifest binding mismatch"));
        }
        if manifest.status == ManifestStatus::Revoked {
            return Err(Status::failed_precondition("reference epoch is revoked"));
        }
        Ok(manifest.generation)
    }

    /// Revalidate delivery metadata without resolving values again. A false
    /// result requires rebuilding the entire captured snapshot, not relabelling
    /// existing values with the latest versions.
    pub async fn validate_resolution(
        &self,
        owner: SecretOwner<'_>,
        handles: &Handles,
        resolved: &[VersionedSecret],
    ) -> Result<bool, Status> {
        let projections: BTreeMap<_, _> = handles
            .iter()
            .map(|(key, handle)| Ok((key.clone(), self.projection(owner, key, handle)?)))
            .collect::<Result<_, Status>>()?;
        let (_, state) = self.load(owner).await?;
        let captured = capture(&state, &projections)?;
        if captured.len() != resolved.len() {
            return Ok(false);
        }
        let mut seen = BTreeSet::new();
        for value in resolved {
            if !seen.insert(&value.credential_key) {
                return Ok(false);
            }
            let Some(expected) = captured.get(&value.credential_key) else {
                return Ok(false);
            };
            if expected.generation != value.generation
                || expected.output.version != value.version
                || projections.get(&value.credential_key) != Some(&value.reference)
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl ReferenceRuntime {
    /// Read only the issuer expiration of committed outputs from one owner
    /// snapshot, without consulting a potentially ahead-of-activation grant
    /// journal or doing backend I/O. Pending bindings are omitted; active
    /// outputs with no issuer expiration have an explicit `None`. Revoked or
    /// mismatched bindings fail closed. Backend expiry is not discovered here.
    pub async fn committed_expirations(
        &self,
        owner: SecretOwner<'_>,
        handles: &Handles,
    ) -> Result<HashMap<String, Option<Timestamp>>, Status> {
        let projections: BTreeMap<_, _> = handles
            .iter()
            .map(|(key, handle)| Ok((key.clone(), self.projection(owner, key, handle)?)))
            .collect::<Result<_, Status>>()?;
        let (_, state) = self.load(owner).await?;
        let mut active = BTreeMap::new();
        for (key, projection) in projections {
            let binding = state
                .bindings
                .get(&projection.reference_id)
                .ok_or_else(|| Status::not_found("issuer reference not found"))?;
            if binding.projection != projection {
                return Err(Status::permission_denied(
                    "issuer reference binding mismatch",
                ));
            }
            let manifest = state
                .manifests
                .get(&projection.manifest_id)
                .ok_or_else(corrupt)?;
            if manifest.epoch != projection.epoch || manifest.status == ManifestStatus::Revoked {
                return Err(Status::failed_precondition("issuer reference is revoked"));
            }
            let mut pending = manifest.status == ManifestStatus::Prepared;
            if let Some(grant_id) = &manifest.grant_id {
                let grant = state.grants.get(grant_id).ok_or_else(corrupt)?;
                if grant.epoch != projection.epoch || (!grant.active && !grant.prepared) {
                    return Err(Status::failed_precondition(
                        "issuer reference grant is revoked",
                    ));
                }
                if grant.active && grant.prepared {
                    return Err(corrupt());
                }
                pending |= grant.prepared;
            }
            if !pending {
                active.insert(key, projection);
            }
        }
        Ok(capture(&state, &active)?
            .into_iter()
            .map(|(key, captured)| (key, captured.output.expiration.map(|expiry| expiry.wire())))
            .collect())
    }

    /// Metadata-only authorization revalidation. Ordinary rotations do not
    /// invalidate a coherently captured older generation; pending or revoked
    /// bindings do. No backend read or latest-version relabelling occurs.
    pub async fn validate_bindings(
        &self,
        owner: SecretOwner<'_>,
        handles: &Handles,
    ) -> Result<bool, Status> {
        let projections = handles
            .iter()
            .map(|(key, handle)| self.projection(owner, key, handle))
            .collect::<Result<Vec<_>, _>>()?;
        let (_, state) = self.load(owner).await?;
        for projection in projections {
            let Some(binding) = state.bindings.get(&projection.reference_id) else {
                return Ok(false);
            };
            if binding.projection != projection {
                return Ok(false);
            }
            let Some(manifest) = state.manifests.get(&projection.manifest_id) else {
                return Ok(false);
            };
            if manifest.status != ManifestStatus::Active
                || manifest.epoch != projection.epoch
                || !manifest.outputs.contains_key(&projection.credential_key)
            {
                return Ok(false);
            }
            if let Some(grant_id) = &manifest.grant_id
                && state.grants.get(grant_id).is_none_or(|grant| {
                    !grant.active || grant.prepared || grant.epoch != projection.epoch
                })
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Prepare a non-mintable grant before the gateway provider CAS. Failure of
    /// that CAS leaves only an inactive candidate, never a losing live grant.
    pub async fn prepare_grant(
        &self,
        owner: SecretOwner<'_>,
        grant_id: &str,
        epoch: &str,
        bytes: &[u8],
    ) -> Result<GrantRecord, Status> {
        if grant_id.is_empty() || epoch.is_empty() {
            return Err(Status::invalid_argument(
                "grant identity and epoch are required",
            ));
        }
        for _ in 0..RETRY_LIMIT {
            let (version, mut state) = self.load(owner).await?;
            if let Some(current) = state.grants.get(grant_id) {
                if current.prepared
                    && !current.active
                    && current.epoch == epoch
                    && current.state == bytes
                {
                    return Ok(current.clone());
                }
                return Err(Status::already_exists(
                    "grant identity is already prepared, active or tombstoned for different intent",
                ));
            }
            let grant = GrantRecord {
                resource_version: 1,
                epoch: epoch.to_owned(),
                state: bytes.to_vec(),
                active: false,
                prepared: true,
            };
            for manifest in state
                .manifests
                .values_mut()
                .filter(|manifest| manifest.epoch == epoch)
            {
                if manifest
                    .grant_id
                    .as_ref()
                    .is_some_and(|existing| existing != grant_id)
                {
                    return Err(Status::already_exists(
                        "authorization epoch already belongs to another grant",
                    ));
                }
                manifest.grant_id = Some(grant_id.to_owned());
            }
            state.grants.insert(grant_id.to_owned(), grant.clone());
            match self.save(owner, version, &state).await {
                Ok(()) => return Ok(grant),
                Err(error) if conflict(&error) => {}
                Err(error) => return Err(error),
            }
        }
        Err(contention())
    }

    /// Complete the recoverable gateway binding saga AFTER the provider CAS.
    /// New authorization, exact old-grant revocation and old output tombstones
    /// share this owner-record CAS. The gateway still owns verifying its bound
    /// provider identity before calling (or resuming) this operation.
    pub async fn activate_grant(
        &self,
        owner: SecretOwner<'_>,
        new_id: &str,
        expected_new_version: u64,
        old: Option<(&str, u64)>,
    ) -> Result<GrantRecord, Status> {
        let intent = GrantActivationIntent {
            expected_new_version,
            old: old.map(|(id, version)| (id.to_owned(), version)),
        };
        if old.is_some_and(|(old_id, _)| old_id == new_id) {
            return Err(Status::invalid_argument(
                "replacement grant must have a new identity",
            ));
        }
        for _ in 0..RETRY_LIMIT {
            let (version, mut state) = self.load(owner).await?;
            let new = state
                .grants
                .get(new_id)
                .ok_or_else(|| Status::not_found("prepared issuer grant not found"))?
                .clone();
            if let Some(previous) = state.grant_activations.get(new_id) {
                if !new.active || new.prepared {
                    return Err(Status::failed_precondition(
                        "activated grant has since been revoked",
                    ));
                }
                if previous != &intent {
                    return Err(Status::already_exists(
                        "grant activation identity reused for a different transition",
                    ));
                }
                return Ok(new);
            }
            if !new.prepared || new.active {
                return Err(Status::failed_precondition(
                    "grant is not prepared or was revoked",
                ));
            }
            if new.resource_version != expected_new_version {
                return Err(Status::aborted("prepared grant resource version changed"));
            }
            if let Some((old_id, expected_old_version)) = old {
                let previous = state
                    .grants
                    .get(old_id)
                    .ok_or_else(|| Status::not_found("old issuer grant not found"))?;
                if previous.resource_version != expected_old_version {
                    return Err(Status::aborted("old grant resource version changed"));
                }
                if !previous.active || previous.prepared {
                    return Err(Status::failed_precondition("old grant is not active"));
                }
                if previous.epoch == new.epoch {
                    return Err(Status::failed_precondition(
                        "replacement grant must have a new authorization epoch",
                    ));
                }
                let old_epoch = previous.epoch.clone();
                let previous = state.grants.get_mut(old_id).ok_or_else(corrupt)?;
                previous.resource_version = previous
                    .resource_version
                    .checked_add(1)
                    .ok_or_else(|| Status::out_of_range("issuer grant version exhausted"))?;
                previous.active = false;
                previous.prepared = false;
                revoke_epoch(&mut state, &old_epoch);
            }
            let mut activated = new;
            activated.resource_version = activated
                .resource_version
                .checked_add(1)
                .ok_or_else(|| Status::out_of_range("issuer grant version exhausted"))?;
            activated.prepared = false;
            activated.active = true;
            state.grants.insert(new_id.to_owned(), activated.clone());
            state
                .grant_activations
                .insert(new_id.to_owned(), intent.clone());
            match self.save(owner, version, &state).await {
                Ok(()) => return Ok(activated),
                Err(error) if conflict(&error) => {}
                Err(error) => return Err(error),
            }
        }
        Err(contention())
    }

    /// Atomically persist the deletion/recovery journal, advance its logical
    /// counter, and revoke the immutable grant epoch and every output manifest.
    /// Encoded state may carry a new *domain* revocation marker; the durable
    /// grant epoch remains the original immutable authorization identity.
    pub async fn tombstone_grant(
        &self,
        owner: SecretOwner<'_>,
        grant_id: &str,
        expected: u64,
        bytes: &[u8],
    ) -> Result<GrantRecord, Status> {
        for _ in 0..RETRY_LIMIT {
            let (version, mut state) = self.load(owner).await?;
            let current = state
                .grants
                .get(grant_id)
                .ok_or_else(|| Status::not_found("issuer grant not found"))?
                .clone();
            if current.resource_version != expected {
                if !current.active
                    && !current.prepared
                    && expected.checked_add(1) == Some(current.resource_version)
                    && current.state == bytes
                {
                    return Ok(current);
                }
                return Err(Status::aborted("issuer grant resource version changed"));
            }
            let mut tombstone = current;
            tombstone.resource_version = tombstone
                .resource_version
                .checked_add(1)
                .ok_or_else(|| Status::out_of_range("issuer grant version exhausted"))?;
            tombstone.active = false;
            tombstone.prepared = false;
            tombstone.state = bytes.to_vec();
            revoke_epoch(&mut state, &tombstone.epoch);
            state.grants.insert(grant_id.to_owned(), tombstone.clone());
            match self.save(owner, version, &state).await {
                Ok(()) => return Ok(tombstone),
                Err(error) if conflict(&error) => {}
                Err(error) => return Err(error),
            }
        }
        Err(contention())
    }

    /// Cleanup completion is another tombstone journal update, never row
    /// deletion. Late mint/adoption/replay cannot recreate the old grant ID.
    pub async fn finish_grant_cleanup(
        &self,
        owner: SecretOwner<'_>,
        grant_id: &str,
        expected: u64,
        bytes: &[u8],
    ) -> Result<GrantRecord, Status> {
        let grant = self
            .get_grant(owner, grant_id)
            .await?
            .ok_or_else(|| Status::not_found("issuer grant not found"))?;
        if grant.active || grant.prepared {
            return Err(Status::failed_precondition(
                "cannot finish cleanup for a live or prepared grant",
            ));
        }
        self.put_grant(owner, grant_id, Some(expected), &grant.epoch, bytes, false)
            .await
    }
}

#[cfg(test)]
mod tests;

fn revoke_epoch(state: &mut OwnerState, epoch: &str) {
    let mut revoked = BTreeSet::new();
    for (id, manifest) in &mut state.manifests {
        if manifest.epoch == epoch {
            manifest.status = ManifestStatus::Revoked;
            revoked.insert(id.clone());
        }
    }
    for operation in state.operations.values_mut() {
        if operation.result.is_none() && revoked.contains(&operation.intent.manifest_id) {
            operation.abandoned = true;
        }
    }
}

impl ReferenceRuntime {
    /// Prepare new-epoch identities and retain the exact captured candidates
    /// without copying or writing backend secrets. Each expiration is preserved
    /// independently. The gateway must authorize/bind these new references
    /// before exposing them; it then revokes the old grant in its binding saga.
    /// If any source is pending, the whole new bundle remains pending.
    pub async fn rebind_bundle(
        &self,
        owner: SecretOwner<'_>,
        new_epoch: &str,
        source: &Handles,
        new_identities: &Handles,
        operation_id: &str,
    ) -> Result<Handles, Status> {
        self.rebind_internal(
            owner,
            new_epoch,
            source,
            new_identities,
            operation_id,
            false,
        )
        .await
    }

    /// Retain a single static key while removing only issuer/refresh-owned
    /// expiration. Backend expiration and gateway-authored limits are untouched.
    pub async fn rebind_static(
        &self,
        owner: SecretOwner<'_>,
        source: &Handles,
        new_identities: &Handles,
        operation_id: &str,
    ) -> Result<Handles, Status> {
        if source.len() != 1 {
            return Err(Status::invalid_argument(
                "static retention requires one key per manifest",
            ));
        }
        self.rebind_internal(owner, "static", source, new_identities, operation_id, true)
            .await
    }

    /// Retain one complete fixed-output source bundle as independently writable
    /// static references. All source candidates are captured and all destination
    /// manifests are installed in ONE owner CAS: even a source mint continuing
    /// after lease loss cannot interleave between individual output transfers.
    /// Pending sources produce only pending destinations, never a partial set.
    /// Issuer expiration is cleared; backend expiration remains authoritative.
    pub async fn rebind_static_bundle(
        &self,
        owner: SecretOwner<'_>,
        source: &Handles,
        new_identities: &Handles,
        operation_id: &str,
    ) -> Result<Handles, Status> {
        validate_request("static", operation_id, new_identities)?;
        if source.len() != new_identities.len()
            || source.keys().any(|key| !new_identities.contains_key(key))
        {
            return Err(Status::invalid_argument("rebind output mappings differ"));
        }
        let sources: BTreeMap<_, _> = source
            .iter()
            .map(|(key, handle)| Ok((key.clone(), self.projection(owner, key, handle)?)))
            .collect::<Result<_, Status>>()?;
        let source_epoch = &sources.values().next().ok_or_else(corrupt)?.epoch;
        let (source_manifest_id, source_references) =
            self.project_bundle(owner, source_epoch, source)?;
        let references = reference_ids(new_identities)?;
        for handle in new_identities.values() {
            if ReferenceProjection::from_handle(handle)?.is_some() {
                return Err(Status::invalid_argument(
                    "prepare requires original handle identities",
                ));
            }
        }
        let operation_id = encode_string(&("rebind-static-bundle", operation_id))?;
        let intent = OperationIntent {
            kind: "rebind-static-bundle".to_owned(),
            epoch: "static".to_owned(),
            manifest_id: operation_id.clone(),
            expected_generation: 0,
            references: references.clone(),
            candidates: new_identities
                .iter()
                .map(|(key, handle)| (key.clone(), StoredHandle::of(handle)))
                .collect(),
            expiration: None,
            protected_intent: serde_json::to_vec(&sources).map_err(|_| corrupt())?,
            grant: None,
        };
        for _ in 0..RETRY_LIMIT {
            let (version, mut state) = self.load(owner).await?;
            if let Some(operation) = state.operations.get(&operation_id) {
                check_intent(operation, &intent)?;
                if operation.result.is_none() {
                    return Err(corrupt());
                }
                return handles_for(&state, &references);
            }
            self.reject_archived_operation(owner, &operation_id).await?;
            for projection in sources.values() {
                let binding = state
                    .bindings
                    .get(&projection.reference_id)
                    .ok_or_else(|| Status::not_found("source reference not found"))?;
                if binding.projection != *projection {
                    return Err(Status::permission_denied("source binding mismatch"));
                }
            }
            let manifest = state
                .manifests
                .get(&source_manifest_id)
                .ok_or_else(corrupt)?;
            if manifest.epoch != *source_epoch
                || manifest.references != source_references
                || manifest.status == ManifestStatus::Revoked
            {
                return Err(Status::failed_precondition(
                    "static retention requires a complete non-revoked source bundle",
                ));
            }
            let mut pending = manifest.status == ManifestStatus::Prepared;
            if let Some(grant_id) = &manifest.grant_id {
                let grant = state.grants.get(grant_id).ok_or_else(corrupt)?;
                if (!grant.active && !grant.prepared) || grant.epoch != *source_epoch {
                    return Err(Status::failed_precondition(
                        "cannot retain a revoked source grant",
                    ));
                }
                pending |= grant.prepared;
            }
            let captured = if pending {
                BTreeMap::new()
            } else {
                // One immutable in-memory source capture. A later activation
                // changes the owner resource version, forcing the entire copy
                // to retry rather than combining captures from two generations.
                capture(&state, &sources)?
            };
            let mut versions = BTreeMap::new();
            let mut staged = BTreeMap::new();
            for (key, reference_id) in &references {
                if state.bindings.contains_key(reference_id) {
                    return Err(Status::already_exists(
                        "reference identity already bound or tombstoned",
                    ));
                }
                let manifest_id = encode_string(&("static-retained", &operation_id, key))?;
                if state.manifests.contains_key(&manifest_id) {
                    return Err(Status::already_exists(
                        "static retention manifest already exists",
                    ));
                }
                state.bindings.insert(
                    reference_id.clone(),
                    Binding {
                        projection: ReferenceProjection {
                            namespace: self.namespace.clone(),
                            owner: OwnerIdentity::of(owner),
                            credential_key: key.clone(),
                            epoch: "static".to_owned(),
                            manifest_id: manifest_id.clone(),
                            reference_id: reference_id.clone(),
                        },
                        identity: StoredHandle::of(new_identities.get(key).ok_or_else(corrupt)?),
                    },
                );
                let outputs = captured.get(key).map_or_else(BTreeMap::new, |output| {
                    staged.insert(key.clone(), output.output.candidate.clone());
                    versions.insert(key.clone(), 1);
                    BTreeMap::from([(
                        key.clone(),
                        ActiveOutput {
                            candidate: output.output.candidate.clone(),
                            version: 1,
                            expiration: None,
                        },
                    )])
                });
                state.manifests.insert(
                    manifest_id,
                    Manifest {
                        epoch: "static".to_owned(),
                        status: if pending {
                            ManifestStatus::Prepared
                        } else {
                            ManifestStatus::Active
                        },
                        generation: u64::from(!pending),
                        references: BTreeMap::from([(key.clone(), reference_id.clone())]),
                        outputs,
                        grant_id: None,
                    },
                );
            }
            state.operations.insert(
                operation_id.clone(),
                Operation {
                    intent: intent.clone(),
                    write_id: operation_id.clone(),
                    write_attempts: Vec::new(),
                    staged,
                    result: Some(ActivationReceipt {
                        manifest_id: operation_id.clone(),
                        epoch: "static".to_owned(),
                        generation: u64::from(!pending),
                        versions,
                    }),
                    abandoned: false,
                },
            );
            match self.save(owner, version, &state).await {
                Ok(()) => return handles_for(&state, &references),
                Err(error) if conflict(&error) => {}
                Err(error) => return Err(error),
            }
        }
        Err(contention())
    }

    /// Explicit bundle form for callers that supply the destination epoch.
    /// This retains a shared destination manifest. Use `rebind_static_bundle`
    /// to transfer one coherent source bundle into independent static keys.
    pub async fn rebind_bundle_without_expiration(
        &self,
        owner: SecretOwner<'_>,
        new_epoch: &str,
        source: &Handles,
        new_identities: &Handles,
        operation_id: &str,
    ) -> Result<Handles, Status> {
        self.rebind_internal(owner, new_epoch, source, new_identities, operation_id, true)
            .await
    }

    async fn rebind_internal(
        &self,
        owner: SecretOwner<'_>,
        new_epoch: &str,
        source: &Handles,
        new_identities: &Handles,
        operation_id: &str,
        clear_expiration: bool,
    ) -> Result<Handles, Status> {
        if source.len() != new_identities.len()
            || source.keys().any(|key| !new_identities.contains_key(key))
        {
            return Err(Status::invalid_argument("rebind output mappings differ"));
        }
        let sources: BTreeMap<_, _> = source
            .iter()
            .map(|(key, handle)| Ok((key.clone(), self.projection(owner, key, handle)?)))
            .collect::<Result<_, Status>>()?;
        let prepare_id = encode_string(&("rebind-prepare", operation_id))?;
        let operation_id = encode_string(&("rebind-activate", operation_id))?;
        let references = self
            .prepare_bundle(owner, new_epoch, new_identities, &prepare_id)
            .await?;
        let (manifest_id, reference_ids) = self.project_bundle(owner, new_epoch, &references)?;
        let source_intent =
            serde_json::to_vec(&(&sources, clear_expiration)).map_err(|_| corrupt())?;
        for _ in 0..RETRY_LIMIT {
            let (version, mut state) = self.load(owner).await?;
            if let Some(operation) = state.operations.get(&operation_id) {
                if operation.intent.kind != "rebind"
                    || operation.intent.epoch != new_epoch
                    || operation.intent.manifest_id != manifest_id
                    || operation.intent.references != reference_ids
                    || operation.intent.protected_intent != source_intent
                {
                    return Err(Status::already_exists(
                        "rebind identity reused for different source intent",
                    ));
                }
                if operation.abandoned {
                    return Err(Status::failed_precondition("rebind was abandoned"));
                }
                if operation.result.is_none() {
                    return Err(corrupt());
                }
                return Ok(references);
            }
            self.reject_archived_operation(owner, &operation_id).await?;
            let mut outputs = BTreeMap::new();
            let mut pending = false;
            let mut candidates = BTreeMap::new();
            let mut staged = BTreeMap::new();
            for (key, projection) in &sources {
                let binding = state
                    .bindings
                    .get(&projection.reference_id)
                    .ok_or_else(|| Status::not_found("source reference not found"))?;
                if binding.projection != *projection {
                    return Err(Status::permission_denied("source binding mismatch"));
                }
                let manifest = state
                    .manifests
                    .get(&projection.manifest_id)
                    .ok_or_else(corrupt)?;
                if manifest.epoch != projection.epoch || manifest.status == ManifestStatus::Revoked
                {
                    return Err(Status::failed_precondition(
                        "cannot retain a revoked source epoch",
                    ));
                }
                if let Some(grant_id) = &manifest.grant_id {
                    let grant = state.grants.get(grant_id).ok_or_else(corrupt)?;
                    if (!grant.active && !grant.prepared) || grant.epoch != projection.epoch {
                        return Err(Status::failed_precondition(
                            "cannot retain a revoked source grant",
                        ));
                    }
                    if grant.prepared {
                        pending = true;
                        continue;
                    }
                }
                if manifest.status == ManifestStatus::Prepared {
                    pending = true;
                    continue;
                }
                let Some(output) = manifest.outputs.get(key) else {
                    pending = true;
                    continue;
                };
                let candidate = state
                    .candidates
                    .get(&output.candidate)
                    .ok_or_else(corrupt)?;
                if candidate.status != CandidateStatus::Available {
                    return Err(Status::failed_precondition(
                        "source candidate is being reclaimed",
                    ));
                }
                candidates.insert(key.clone(), candidate.handle.clone());
                staged.insert(key.clone(), output.candidate.clone());
                outputs.insert(
                    key.clone(),
                    ActiveOutput {
                        candidate: output.candidate.clone(),
                        version: 1,
                        expiration: if clear_expiration {
                            None
                        } else {
                            output.expiration.clone()
                        },
                    },
                );
            }
            let manifest = state.manifests.get_mut(&manifest_id).ok_or_else(corrupt)?;
            if manifest.status != ManifestStatus::Prepared
                || manifest.generation != 0
                || manifest.references != reference_ids
            {
                return Err(Status::failed_precondition(
                    "new rebind manifest is already active or revoked",
                ));
            }
            if !pending {
                manifest.outputs = outputs;
                manifest.generation = 1;
                manifest.status = ManifestStatus::Active;
            }
            let receipt = ActivationReceipt {
                manifest_id: manifest_id.clone(),
                epoch: new_epoch.to_owned(),
                generation: manifest.generation,
                versions: manifest
                    .outputs
                    .iter()
                    .map(|(key, output)| (key.clone(), output.version))
                    .collect(),
            };
            state.operations.insert(
                operation_id.clone(),
                Operation {
                    intent: OperationIntent {
                        kind: "rebind".to_owned(),
                        epoch: new_epoch.to_owned(),
                        manifest_id: manifest_id.clone(),
                        expected_generation: 0,
                        references: reference_ids.clone(),
                        candidates,
                        expiration: None,
                        protected_intent: source_intent.clone(),
                        grant: None,
                    },
                    write_id: operation_id.clone(),
                    write_attempts: Vec::new(),
                    staged,
                    result: Some(receipt),
                    abandoned: false,
                },
            );
            match self.save(owner, version, &state).await {
                Ok(()) => return Ok(references),
                Err(error) if conflict(&error) => {}
                Err(error) => return Err(error),
            }
        }
        Err(contention())
    }
}

/// Enumerate non-secret grant journals without a credential backend.
///
/// Replay/status readers still must authorize the returned owner and current
/// provider binding/epoch before exposing a status. Enumeration is not proof of
/// a currently authorized provider binding and includes prepared/revoked state.
pub async fn read_grants(
    store: &dyn ReferenceStateStore,
    namespace: &str,
    provider_id: Option<&str>,
) -> Result<Vec<(OwnerIdentity, String, GrantRecord)>, Status> {
    if namespace.is_empty() {
        return Err(Status::invalid_argument(
            "durable issuer namespace is required",
        ));
    }
    let mut grants = Vec::new();
    for record in store.list().await? {
        let state: OwnerState = serde_json::from_slice(&record.payload).map_err(|_| corrupt())?;
        if state.schema_version != SCHEMA_VERSION {
            return Err(corrupt());
        }
        if state.namespace != namespace {
            continue;
        }
        if !matches!(
            state.owner.kind.as_str(),
            "provider" | "sandbox" | "supervisor-instance"
        ) {
            return Err(corrupt());
        }
        if provider_id.is_some_and(|id| state.owner.kind != "provider" || state.owner.id != id) {
            continue;
        }
        for (id, grant) in state.grants {
            grants.push((state.owner.clone(), id, grant));
        }
    }
    grants.sort_by(|left, right| {
        (&left.0.workspace, &left.0.kind, &left.0.id, &left.1).cmp(&(
            &right.0.workspace,
            &right.0.kind,
            &right.0.id,
            &right.1,
        ))
    });
    Ok(grants)
}

impl ReferenceRuntime {
    /// Set initial issuer-owned expiration before a prepared grant is exposed.
    ///
    /// Only a retained primary output is changed. Pending outputs stay pending,
    /// other keys and backend expirations are untouched, and secret versions and
    /// activation generations do not advance. Prepared authorization is checked
    /// in the same owner CAS as the manifest update.
    pub async fn set_prepared_grant_expiration(
        &self,
        owner: SecretOwner<'_>,
        grant_id: &str,
        credential_key: &str,
        expiration: Option<Timestamp>,
    ) -> Result<(), Status> {
        if credential_key.is_empty() {
            return Err(Status::invalid_argument("credential key is required"));
        }
        let expiration = expiration.as_ref().map(Expiry::of).transpose()?;
        for _ in 0..RETRY_LIMIT {
            let (version, mut state) = self.load(owner).await?;
            let grant = state
                .grants
                .get(grant_id)
                .ok_or_else(|| Status::not_found("prepared issuer grant not found"))?;
            if !grant.prepared || grant.active {
                return Err(Status::failed_precondition(
                    "expiration can only be set on a prepared grant",
                ));
            }
            let epoch = grant.epoch.clone();
            for manifest in state.manifests.values_mut().filter(|manifest| {
                manifest.epoch == epoch && manifest.grant_id.as_deref() == Some(grant_id)
            }) {
                if manifest.status == ManifestStatus::Revoked {
                    return Err(Status::failed_precondition(
                        "prepared grant manifest is revoked",
                    ));
                }
                if let Some(output) = manifest.outputs.get_mut(credential_key) {
                    output.expiration.clone_from(&expiration);
                }
            }
            match self.save(owner, version, &state).await {
                Ok(()) => return Ok(()),
                Err(error) if conflict(&error) => {}
                Err(error) => return Err(error),
            }
        }
        Err(contention())
    }
}
