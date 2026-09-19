// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Explicitly opted-in unary mutations. This is an admission fence, not a lease:
//! an owner that cannot persist success leaves an unresolved claim forever.
//! Each adapter explicitly approves its authorization and replay representation.

#![allow(clippy::result_large_err)]

use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock};

use hmac::{Hmac, Mac};
use openshell_core::proto::{
    AddWorkspaceMemberRequest, AddWorkspaceMemberResponse, CreateSandboxTemplateRequest,
    CreateWorkspaceRequest, CreateWorkspaceResponse, DeleteSandboxTemplateRequest,
    DeleteSandboxTemplateResponse, DeleteWorkspaceRequest, DeleteWorkspaceResponse,
    RemoveWorkspaceMemberRequest, RemoveWorkspaceMemberResponse, SandboxTemplateResponse,
    Workspace, WorkspaceSelector,
};
use openshell_core::{GetResourceVersion, ObjectId, rpc_error};
use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use tonic::{Request, Response, Status};

use super::{sandbox, workspace};
use crate::ServerState;
use crate::auth::identity::IdentityProvider;
use crate::auth::principal::Principal;
use crate::auth::workspace_authz::{
    MinWorkspaceRole, authorize_workspace, require_platform_admin, selected_workspace_name,
};
use crate::persistence::{
    ObjectType, PersistenceError, SetResourceVersion, Store, WriteCondition, current_time_ms,
};

const OBJECT_TYPE: &str = "mutation_admission_v1";
const SUCCESS_TTL_MS: i64 = 24 * 60 * 60 * 1000;
const MAX_ADMISSIONS_PER_CALLER: u32 = 1000;
// Bound work detached from request cancellation across all service instances.
static EXECUTORS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(64)));
static DESCRIPTORS: LazyLock<DescriptorPool> = LazyLock::new(|| {
    DescriptorPool::decode(openshell_core::FILE_DESCRIPTOR_SET)
        .expect("compiled protobuf descriptor set")
});

#[derive(Serialize, Deserialize)]
struct Admission {
    // Version the canonicalization separately from the namespace. A future
    // change must reject incompatible records, not admit the old key again.
    format_version: u32,
    payload_hash: String,
    #[serde(default)]
    protection: Option<Protection>,
    workspace_id: Option<String>,
    success: Option<Success>,
    completed_at_ms: Option<i64>,
}

#[derive(Serialize, Deserialize, PartialEq)]
struct Protection {
    key_id: String,
    effective_payload_hash: String,
    effective_workspace_id: Option<String>,
}

/// Gateway-owned, in-memory input before hydration and interceptor modification.
/// Never populated from HTTP metadata and never written to the admission store.
#[derive(Clone)]
pub struct OriginalMutation(pub(crate) Vec<u8>);

/// Deliberately no serialized requests, responses, tokens, or error messages.
#[derive(Serialize, Deserialize)]
pub(super) enum Success {
    Resource { id: String, version: u64 },
    Deletion { outcome: i32 },
    Ordinary(ordinary::Outcome),
}

pub(super) struct Scope {
    name: String,
    workspace_id: Option<String>,
}

#[tonic::async_trait]
pub(super) trait Mutation: Message + Default + Send + Sync + 'static {
    type Output: Message + Default + Send + 'static;
    const METHOD: &'static str;
    const PROTECTED: bool = false;
    fn request_id(&self) -> &str;
    async fn authorize(&self, state: &ServerState, principal: &Principal) -> Result<Scope, Status>;
    async fn execute(
        state: &Arc<ServerState>,
        request: Request<Self>,
    ) -> Result<Response<Self::Output>, Status>;
    fn capture(response: &Response<Self::Output>) -> Result<Success, Status>;
    async fn restore(store: &Store, success: Success) -> Result<Self::Output, Status>;
}

/// Empty IDs preserve the existing RPC contract, including cancellation.
pub(super) async fn run<M: Mutation>(
    state: &Arc<ServerState>,
    request: Request<M>,
) -> Result<Response<M::Output>, Status> {
    let original = request
        .extensions()
        .get::<OriginalMutation>()
        .map(|original| M::decode(original.0.as_slice()))
        .transpose()
        .map_err(|_| Status::internal("decode original mutation request"))?;
    let original = original.as_ref().unwrap_or_else(|| request.get_ref());
    if original.request_id() != request.get_ref().request_id() {
        return Err(rpc_error::invalid_argument(
            "request_id",
            "interceptors must preserve the original request_id",
        ));
    }
    if original.request_id().is_empty() {
        return M::execute(state, request).await;
    }
    if request.get_ref().encoded_len() > 4 * 1024 * 1024 {
        return Err(Status::resource_exhausted("mutation request exceeds 4 MiB"));
    }
    let request_id = validate_request_id(request.get_ref().request_id())?;
    let principal = super::extract_principal(&request)?;
    let Principal::User(user) = &principal else {
        return Err(Status::permission_denied(
            "request admission requires a user principal",
        ));
    };
    let scope = original.authorize(state, &principal).await?;
    let effective_scope = request.get_ref().authorize(state, &principal).await?;
    let (payload_hash, protection) = if M::PROTECTED {
        let key = fingerprint_key(state).await?;
        (
            key.fingerprint(original)?,
            Some(Protection {
                key_id: key.id(),
                effective_payload_hash: key.fingerprint(request.get_ref())?,
                effective_workspace_id: effective_scope.workspace_id,
            }),
        )
    } else {
        (fingerprint(original)?, None)
    };
    let (provider, issuer) = match user.identity.provider {
        IdentityProvider::Oidc => (
            "oidc",
            state
                .config
                .oidc
                .as_ref()
                .map_or("", |config| config.issuer.as_str()),
        ),
        IdentityProvider::Mtls => ("mtls", ""),
        IdentityProvider::CloudflareAccess => ("cloudflare_access", ""),
        IdentityProvider::LocalDev => ("local_dev", ""),
    };
    let caller = hash_json(&serde_json::json!([
        provider,
        issuer,
        user.identity.subject,
    ]))?;
    // Not a valid user workspace name; ordinary workspace cleanup cannot touch
    // these records. The bucket supports an atomic per-caller storage quota.
    let bucket = format!("_mutation/{caller}");
    let key = hash_json(&serde_json::json!([
        caller,
        M::METHOD,
        scope.name,
        request_id
    ]))?;
    let permit = EXECUTORS.clone().try_acquire_owned().map_err(|_| {
        Status::resource_exhausted(
            "mutation admission workers are busy; no work was started by this call",
        )
    })?;
    let state = Arc::clone(state);
    // Spawn BEFORE attempting MustCreate. Cancellation during the database write
    // must not drop the owner between durable admission and execution.
    tokio::spawn(async move {
        let _permit = permit;
        execute_owned(
            &state,
            request,
            &key,
            &bucket,
            payload_hash,
            protection,
            scope,
        )
        .await
    })
    .await
    .map_err(|_| uncertain())?
}

async fn execute_owned<M: Mutation>(
    state: &Arc<ServerState>,
    mut request: Request<M>,
    key: &str,
    bucket: &str,
    payload_hash: String,
    protection: Option<Protection>,
    scope: Scope,
) -> Result<Response<M::Output>, Status> {
    let mut admission = Admission {
        format_version: 1,
        payload_hash,
        protection,
        workspace_id: scope.workspace_id,
        success: None,
        completed_at_ms: None,
    };
    // Contention is bounded. Losing a race never authorizes execution.
    for _ in 0..8 {
        if let Some(row) = state
            .store
            .get_by_name(OBJECT_TYPE, bucket, key)
            .await
            .map_err(storage_error)?
        {
            let previous: Admission = serde_json::from_slice(&row.payload)
                .map_err(|_| Status::internal("invalid durable mutation admission"))?;
            if previous.format_version != 1 {
                return Err(replay_unavailable());
            }
            if previous.success.is_some()
                && previous.completed_at_ms.is_some_and(|completed| {
                    current_time_ms() >= completed.saturating_add(SUCCESS_TTL_MS)
                })
            {
                match state
                    .store
                    .delete_if(OBJECT_TYPE, &row.id, row.resource_version)
                    .await
                {
                    Ok(_) | Err(PersistenceError::Conflict { .. }) => continue,
                    Err(error) => return Err(storage_error(error)),
                }
            }
            // A rotated/unavailable protection key must never turn the old ID
            // into a new admission, or report a misleading payload mismatch.
            if previous.protection.as_ref().map(|p| &p.key_id)
                != admission.protection.as_ref().map(|p| &p.key_id)
            {
                return Err(replay_unavailable());
            }
            if previous.payload_hash != admission.payload_hash {
                return Err(rpc_error::failed_precondition(
                    "REQUEST_ID_PAYLOAD_MISMATCH",
                    "request_id was already used with a different payload",
                ));
            }
            if previous.workspace_id != admission.workspace_id
                || previous.protection != admission.protection
            {
                return Err(replay_unavailable());
            }
            let success = previous.success.ok_or_else(uncertain)?;
            let mut response = Response::new(M::restore(&state.store, success).await?);
            response.metadata_mut().insert(
                "openshell-replayed",
                "true".parse().expect("static metadata"),
            );
            return Ok(response);
        }
        let payload = serde_json::to_vec(&admission)
            .map_err(|_| Status::internal("encode mutation admission"))?;
        // A new incarnation needs a new row ID. Versions reset after deletion;
        // an expiry cleaner holding an old snapshot must not delete a new claim.
        let claim_id = uuid::Uuid::new_v4().to_string();
        let write = state
            .store
            .create_if_workspace_count_below(
                OBJECT_TYPE,
                &claim_id,
                key,
                bucket,
                &payload,
                None,
                u64::from(MAX_ADMISSIONS_PER_CALLER),
            )
            .await;
        let version = match write {
            Ok(Some(write)) => write.resource_version,
            Ok(None) => {
                if prune_expired(&state.store, bucket).await? {
                    continue;
                }
                return Err(Status::resource_exhausted(
                    "caller has reached the durable mutation admission limit; unresolved requests require reconciliation",
                ));
            }
            Err(PersistenceError::UniqueViolation { .. } | PersistenceError::Conflict { .. }) => {
                continue;
            }
            Err(error) => return Err(storage_error(error)),
        };
        // Any error or panic from here leaves the claim unresolved. Status codes
        // do not establish that a handler performed no effects.
        let facts = ordinary::Facts::default();
        request.extensions_mut().insert(facts.clone());
        let mut response = M::execute(state, request).await?;
        response.extensions_mut().insert(facts);
        admission.success = Some(M::capture(&response)?);
        admission.completed_at_ms = Some(current_time_ms());
        let payload = serde_json::to_vec(&admission).map_err(|_| uncertain())?;
        if payload.len() > 64 * 1024 {
            return Err(uncertain());
        }
        state
            .store
            .put_if(
                OBJECT_TYPE,
                &claim_id,
                key,
                bucket,
                &payload,
                None,
                WriteCondition::MatchResourceVersion(version),
            )
            .await
            .map_err(|_| uncertain())?;
        return Ok(response);
    }
    Err(uncertain())
}

async fn prune_expired(store: &Store, bucket: &str) -> Result<bool, Status> {
    // The bucket is atomically bounded, so this scan cannot grow without limit.
    let rows = store
        .list(OBJECT_TYPE, bucket, MAX_ADMISSIONS_PER_CALLER, 0)
        .await
        .map_err(storage_error)?;
    let mut removed = false;
    for row in rows {
        let Ok(admission) = serde_json::from_slice::<Admission>(&row.payload) else {
            continue;
        };
        if admission.format_version == 1
            && admission.success.is_some()
            && admission.completed_at_ms.is_some_and(|completed| {
                current_time_ms() >= completed.saturating_add(SUCCESS_TTL_MS)
            })
        {
            match store
                .delete_if(OBJECT_TYPE, &row.id, row.resource_version)
                .await
            {
                Ok(deleted) => removed |= deleted,
                Err(PersistenceError::Conflict { .. }) => {}
                Err(error) => return Err(storage_error(error)),
            }
        }
    }
    Ok(removed)
}

fn validate_request_id(value: &str) -> Result<String, Status> {
    let invalid = || {
        rpc_error::invalid_argument(
            "request_id",
            "must be a nonzero hyphenated UUID (36 characters)",
        )
    };
    if value.len() != 36 {
        return Err(invalid());
    }
    let id = uuid::Uuid::parse_str(value).map_err(|_| invalid())?;
    if id.is_nil() || !value.eq_ignore_ascii_case(&id.hyphenated().to_string()) {
        return Err(invalid());
    }
    Ok(id.hyphenated().to_string())
}

fn fingerprint<M: Mutation>(request: &M) -> Result<String, Status> {
    let descriptor = DESCRIPTORS
        .get_message_by_name(&format!("openshell.v1.{}Request", M::METHOD))
        .ok_or_else(|| Status::internal("mutation request descriptor missing"))?;
    let mut message = DynamicMessage::decode(descriptor, request.encode_to_vec().as_slice())
        .map_err(|_| Status::internal("decode mutation request"))?;
    message.clear_field_by_name("request_id");
    if M::METHOD == "UpdateConfig" {
        // Waiting changes response timing, never the admitted mutation identity.
        message.clear_field_by_name("consistency");
        message.clear_field_by_name("wait_timeout");
    }
    let value = serde_json::to_value(message)
        .map_err(|_| Status::internal("canonicalize mutation request"))?;
    hash_json(&value)
}

struct FingerprintKey([u8; 32]);

impl FingerprintKey {
    fn id(&self) -> String {
        format!("{:x}", Sha256::digest(self.0))
    }

    fn fingerprint<M: Mutation>(&self, request: &M) -> Result<String, Status> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0)
            .map_err(|_| Status::internal("initialize mutation fingerprint"))?;
        mac.update(fingerprint(request)?.as_bytes());
        Ok(format!("{:x}", mac.finalize().into_bytes()))
    }
}

// New adapters can contain credentials or arbitrary sandbox environment values.
// A plain database hash would permit offline guesses. Reuse existing private
// gateway material without introducing a database-stored key or new deployment
// configuration. HA replicas must share that material; rotation fails closed.
async fn fingerprint_key(state: &ServerState) -> Result<FingerprintKey, Status> {
    let path = state
        .config
        .gateway_jwt
        .as_ref()
        .map(|jwt| &jwt.signing_key_path)
        .or_else(|| state.config.tls.as_ref().map(|tls| &tls.key_path));
    let unavailable = || {
        rpc_error::failed_precondition(
            "REQUEST_REPLAY_UNAVAILABLE",
            "request_id on this method requires readable, stable gateway JWT or TLS private key material; no work was started by this call",
        )
    };
    let bytes = tokio::fs::read(path.ok_or_else(unavailable)?)
        .await
        .map_err(|_| unavailable())?;
    if bytes.is_empty() {
        return Err(unavailable());
    }
    let mut hash = Sha256::new();
    hash.update(b"openshell/mutation-fingerprint/v1\0");
    hash.update(bytes);
    Ok(FingerprintKey(hash.finalize().into()))
}

// Sort every map explicitly; do not depend on serde_json's preserve_order feature.
fn hash_json(value: &serde_json::Value) -> Result<String, Status> {
    struct Canonical<'a>(&'a serde_json::Value);
    impl Serialize for Canonical<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            match self.0 {
                serde_json::Value::Object(map) => map
                    .iter()
                    .map(|(key, value)| (key, Canonical(value)))
                    .collect::<BTreeMap<_, _>>()
                    .serialize(serializer),
                serde_json::Value::Array(values) => values
                    .iter()
                    .map(Canonical)
                    .collect::<Vec<_>>()
                    .serialize(serializer),
                value => value.serialize(serializer),
            }
        }
    }
    let bytes = serde_json::to_vec(&Canonical(value))
        .map_err(|_| Status::internal("canonicalize mutation payload"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn uncertain() -> Status {
    rpc_error::failed_precondition(
        "REQUEST_OUTCOME_UNCERTAIN",
        "request is admitted but has no confirmed replayable success; reconcile effects before starting a new request",
    )
}

fn replay_unavailable() -> Status {
    rpc_error::failed_precondition(
        "REQUEST_REPLAY_UNAVAILABLE",
        "the original scope, protected payload, or result is no longer replayable; this request was not executed again",
    )
}

fn storage_error(error: PersistenceError) -> Status {
    tracing::warn!(%error, "mutation admission storage failed");
    Status::internal("mutation admission storage failed")
}

async fn named_scope(state: &ServerState, name: &str) -> Result<Scope, Status> {
    let name = if name.is_empty() {
        workspace::DEFAULT_WORKSPACE_NAME
    } else {
        name
    };
    let resource: Workspace = state
        .store
        .get_message_by_name("", name)
        .await
        .map_err(storage_error)?
        .ok_or_else(|| Status::not_found("workspace not found"))?;
    Ok(Scope {
        name: name.into(),
        workspace_id: Some(resource.object_id().into()),
    })
}

fn global_scope(state: &ServerState, principal: &Principal) -> Result<Scope, Status> {
    require_platform_admin(&state.admin_role, principal)?;
    Ok(Scope {
        name: String::new(),
        workspace_id: None,
    })
}

async fn template_scope(
    state: &ServerState,
    principal: &Principal,
    workspace_scope: Option<&WorkspaceSelector>,
) -> Result<Scope, Status> {
    let workspace = selected_workspace_name(workspace_scope)?;
    let authz = authorize_workspace(
        &state.store,
        &state.admin_role,
        principal,
        workspace,
        MinWorkspaceRole::Admin,
    )
    .await?;
    named_scope(state, &authz.workspace).await
}

async fn member_scope(
    state: &ServerState,
    principal: &Principal,
    name: &str,
    role: Option<i32>,
) -> Result<Scope, Status> {
    let authz = authorize_workspace(
        &state.store,
        &state.admin_role,
        principal,
        name,
        MinWorkspaceRole::Admin,
    )
    .await?;
    if let Some(role) = role {
        workspace::authorize_member_role(role, authz.grant)?;
    }
    named_scope(state, &authz.workspace).await
}

fn resource_success<T: ObjectId + GetResourceVersion>(
    resource: Option<&T>,
) -> Result<Success, Status> {
    let resource = resource.ok_or_else(uncertain)?;
    Ok(Success::Resource {
        id: resource.object_id().into(),
        version: resource.get_resource_version(),
    })
}

async fn restore_resource<
    T: Message + Default + ObjectType + SetResourceVersion + GetResourceVersion,
>(
    store: &Store,
    success: Success,
) -> Result<T, Status> {
    let Success::Resource { id, version } = success else {
        return Err(replay_unavailable());
    };
    let resource: T = store
        .get_message(&id)
        .await
        .map_err(storage_error)?
        .ok_or_else(replay_unavailable)?;
    if resource.get_resource_version() != version {
        return Err(replay_unavailable());
    }
    Ok(resource)
}

macro_rules! resource_mutation {
    ($req:ty, $resp:ident, $method:literal, $handler:path, $field:ident, $auth:expr) => {
        #[tonic::async_trait]
        impl Mutation for $req {
            type Output = $resp;
            const METHOD: &'static str = $method;
            fn request_id(&self) -> &str {
                &self.request_id
            }
            async fn authorize(
                &self,
                state: &ServerState,
                principal: &Principal,
            ) -> Result<Scope, Status> {
                ($auth)(self, state, principal).await
            }
            async fn execute(
                state: &Arc<ServerState>,
                request: Request<Self>,
            ) -> Result<Response<Self::Output>, Status> {
                $handler(state, request).await
            }
            fn capture(response: &Response<Self::Output>) -> Result<Success, Status> {
                resource_success(response.get_ref().$field.as_ref())
            }
            async fn restore(store: &Store, success: Success) -> Result<Self::Output, Status> {
                Ok($resp {
                    $field: Some(restore_resource(store, success).await?),
                })
            }
        }
    };
}

macro_rules! deletion_mutation {
    ($req:ty, $resp:ident, $method:literal, $handler:path, $auth:expr) => {
        #[tonic::async_trait]
        impl Mutation for $req {
            type Output = $resp;
            const METHOD: &'static str = $method;
            fn request_id(&self) -> &str {
                &self.request_id
            }
            async fn authorize(
                &self,
                state: &ServerState,
                principal: &Principal,
            ) -> Result<Scope, Status> {
                ($auth)(self, state, principal).await
            }
            async fn execute(
                state: &Arc<ServerState>,
                request: Request<Self>,
            ) -> Result<Response<Self::Output>, Status> {
                $handler(state, request).await
            }
            fn capture(response: &Response<Self::Output>) -> Result<Success, Status> {
                Ok(Success::Deletion {
                    outcome: response.get_ref().outcome,
                })
            }
            async fn restore(_store: &Store, success: Success) -> Result<Self::Output, Status> {
                let Success::Deletion { outcome } = success else {
                    return Err(replay_unavailable());
                };
                Ok($resp { outcome })
            }
        }
    };
}

resource_mutation!(
    CreateWorkspaceRequest,
    CreateWorkspaceResponse,
    "CreateWorkspace",
    workspace::handle_create_workspace,
    workspace,
    async |req: &CreateWorkspaceRequest, state: &ServerState, principal: &Principal| {
        let mut scope = global_scope(state, principal)?;
        scope.name.clone_from(&req.name);
        Ok(scope)
    }
);
deletion_mutation!(
    DeleteWorkspaceRequest,
    DeleteWorkspaceResponse,
    "DeleteWorkspace",
    workspace::handle_delete_workspace,
    async |req: &DeleteWorkspaceRequest, state: &ServerState, principal: &Principal| {
        let mut scope = global_scope(state, principal)?;
        scope.name.clone_from(&req.name);
        Ok(scope)
    }
);
resource_mutation!(
    CreateSandboxTemplateRequest,
    SandboxTemplateResponse,
    "CreateSandboxTemplate",
    sandbox::handle_create_sandbox_template,
    template,
    async |req: &CreateSandboxTemplateRequest, state: &ServerState, principal: &Principal| {
        template_scope(state, principal, req.workspace_scope.as_ref()).await
    }
);
deletion_mutation!(
    DeleteSandboxTemplateRequest,
    DeleteSandboxTemplateResponse,
    "DeleteSandboxTemplate",
    sandbox::handle_delete_sandbox_template,
    async |req: &DeleteSandboxTemplateRequest, state: &ServerState, principal: &Principal| {
        template_scope(state, principal, req.workspace_scope.as_ref()).await
    }
);
resource_mutation!(
    AddWorkspaceMemberRequest,
    AddWorkspaceMemberResponse,
    "AddWorkspaceMember",
    workspace::handle_add_workspace_member,
    member,
    async |req: &AddWorkspaceMemberRequest, state: &ServerState, principal: &Principal| {
        member_scope(
            state,
            principal,
            selected_workspace_name(req.workspace_scope.as_ref())?,
            Some(req.role),
        )
        .await
    }
);
deletion_mutation!(
    RemoveWorkspaceMemberRequest,
    RemoveWorkspaceMemberResponse,
    "RemoveWorkspaceMember",
    workspace::handle_remove_workspace_member,
    async |req: &RemoveWorkspaceMemberRequest, state: &ServerState, principal: &Principal| {
        member_scope(
            state,
            principal,
            selected_workspace_name(req.workspace_scope.as_ref())?,
            None,
        )
        .await
    }
);

#[cfg(test)]
mod tests;

pub(super) mod ordinary;
