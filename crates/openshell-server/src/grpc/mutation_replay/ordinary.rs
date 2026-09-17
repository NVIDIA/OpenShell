// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Explicit replay recipes. Never serialize a whole public request or response:
//! sandbox specs, provider credentials and refresh material can contain secrets.

#[cfg(test)]
pub(super) mod tests;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use openshell_core::proto::{
    ApproveAllDraftChunksRequest, ApproveAllDraftChunksResponse, ApproveDraftChunkRequest,
    ApproveDraftChunkResponse, AttachSandboxProviderRequest, AttachSandboxProviderResponse,
    ClearDraftChunksRequest, ClearDraftChunksResponse, ConfigureProviderRefreshRequest,
    ConfigureProviderRefreshResponse, CreateProviderRequest, CreateSandboxRequest,
    DeleteProviderProfileRequest, DeleteProviderProfileResponse, DeleteProviderRefreshRequest,
    DeleteProviderRefreshResponse, DeleteProviderRequest, DeleteProviderResponse,
    DeleteSandboxRequest, DeleteSandboxResponse, DeleteServiceRequest, DeleteServiceResponse,
    DetachSandboxProviderRequest, DetachSandboxProviderResponse, EditDraftChunkRequest,
    EditDraftChunkResponse, ExposeServiceRequest, ImportProviderProfilesRequest,
    ImportProviderProfilesResponse, Provider, ProviderMutationReceipt, ProviderProfile,
    ProviderProfileDiagnostic, ProviderResponse, RejectDraftChunkRequest, RejectDraftChunkResponse,
    RotateProviderCredentialRequest, RotateProviderCredentialResponse, Sandbox, SandboxResponse,
    ServiceEndpointResponse, StartSandboxRequest, StopSandboxRequest, UndoDraftChunkRequest,
    UndoDraftChunkResponse, UpdateConfigRequest, UpdateConfigResponse,
    UpdateProviderProfilesRequest, UpdateProviderProfilesResponse, UpdateProviderRequest,
};
use openshell_core::{GetResourceVersion, ObjectId};
use prost::Message;
use serde::{Deserialize, Serialize};
use tonic::{Request, Response, Status};

use super::{
    Mutation, Scope, Success, global_scope, named_scope, replay_unavailable, restore_resource,
    storage_error, uncertain,
};
use crate::auth::principal::Principal;
use crate::auth::workspace_authz::{MinWorkspaceRole, authorize_workspace};
use crate::grpc::{policy, provider, sandbox, service};
use crate::persistence::{ObjectType, SetResourceVersion, Store};
use crate::storage_proto::{
    StoredProviderCredentialRefreshStateV2 as StoredProviderCredentialRefreshState,
    StoredProviderProfile,
};
use crate::{ServerState, config_update_operation};

#[derive(Clone, Serialize, Deserialize)]
pub(in crate::grpc) struct Reference {
    id: String,
    version: u64,
}

impl Reference {
    fn new(resource: &(impl ObjectId + GetResourceVersion)) -> Self {
        Self {
            id: resource.object_id().into(),
            version: resource.get_resource_version(),
        }
    }

    async fn restore<
        T: Message + Default + ObjectType + SetResourceVersion + GetResourceVersion,
    >(
        &self,
        store: &Store,
    ) -> Result<T, Status> {
        restore_resource(
            store,
            Success::Resource {
                id: self.id.clone(),
                version: self.version,
            },
        )
        .await
    }
}

/// Facts come from the handler's actual resource/write, never a later lookup by
/// mutable name. The collector only exists in the owner task and is not metadata.
#[derive(Clone, Default)]
pub struct Facts(Arc<Mutex<WriteFacts>>);

#[derive(Clone, Default)]
struct WriteFacts {
    references: Vec<Reference>,
    refresh: Option<Refresh>,
    global: bool,
}

impl Facts {
    pub(crate) fn global(&self) -> Result<(), Status> {
        self.0.lock().map_err(|_| uncertain())?.global = true;
        Ok(())
    }
    pub(crate) fn from_request<T>(request: &Request<T>) -> Self {
        request
            .extensions()
            .get::<Self>()
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn resource(
        &self,
        resource: &(impl ObjectId + GetResourceVersion),
    ) -> Result<(), Status> {
        self.0
            .lock()
            .map_err(|_| uncertain())?
            .references
            .push(Reference::new(resource));
        Ok(())
    }

    pub(crate) fn refresh(
        &self,
        state: &StoredProviderCredentialRefreshState,
    ) -> Result<(), Status> {
        self.0.lock().map_err(|_| uncertain())?.refresh = Some(Refresh {
            id: state.object_id().into(),
            provider_id: state.provider_id.clone(),
            epoch: crate::provider_refresh::effective_authorization_epoch(state)?.into(),
        });
        Ok(())
    }
}

fn facts<T>(response: &Response<T>) -> Result<WriteFacts, Status> {
    Ok(response
        .extensions()
        .get::<Facts>()
        .ok_or_else(uncertain)?
        .0
        .lock()
        .map_err(|_| uncertain())?
        .clone())
}

fn parent<T>(response: &Response<T>) -> Result<String, Status> {
    let facts = facts(response)?;
    if facts.references.len() != 1 {
        return Err(uncertain());
    }
    Ok(facts.references[0].id.clone())
}

#[derive(Serialize, Deserialize)]
pub(in crate::grpc) enum Outcome {
    Sandbox {
        id: String,
        changed: bool,
    },
    SandboxDeletion {
        id: String,
        outcome: i32,
    },
    Attachment {
        id: String,
        changed: bool,
        receipt: ProviderReceiptReference,
    },
    Provider {
        reference: Reference,
        mutation_id: String,
        target_receipts: Vec<ProviderReceiptReference>,
    },
    Service {
        reference: Reference,
        sandbox_id: String,
        url: String,
    },
    Profiles {
        references: Vec<Reference>,
        diagnostics: Vec<Diagnostic>,
        changed: bool,
    },
    Config {
        sandbox_id: Option<String>,
        version: u32,
        policy_hash: String,
        settings_revision: u64,
        deleted: bool,
        annotations: HashMap<String, String>,
    },
    Policy {
        sandbox_id: String,
        version: u32,
        hash: String,
        approved: u32,
        skipped: u32,
        cleared: u32,
    },
    Refresh(Refresh),
}

/// Replay retains immutable operation identities, never a fresh target snapshot
/// or a serialized provider response that could carry credential material.
#[derive(Serialize, Deserialize)]
pub(in crate::grpc) struct ProviderReceiptReference {
    id: String,
    workspace: String,
}

impl ProviderReceiptReference {
    fn new(receipt: &ProviderMutationReceipt) -> Self {
        Self {
            id: receipt.receipt_id.clone(),
            workspace: receipt.workspace.clone(),
        }
    }

    async fn restore(self, store: &Store) -> Result<ProviderMutationReceipt, Status> {
        // The original operation is authoritative even after readiness changes.
        // A missing operation cannot authorize replaying the mutation itself.
        config_update_operation::get_provider_operation(store, &self.id, &self.workspace)
            .await
            .map(|operation| operation.receipt)
            .map_err(|_| replay_unavailable())
    }
}

/// Public profile declarations and diagnostics have a nonsecret contract. These
/// fields may echo declaration text; they are not arbitrary sanitized payloads.
#[derive(Serialize, Deserialize)]
pub(in crate::grpc) struct Diagnostic {
    source: String,
    profile_id: String,
    field: String,
    message: String,
    severity: String,
}

impl From<&ProviderProfileDiagnostic> for Diagnostic {
    fn from(value: &ProviderProfileDiagnostic) -> Self {
        Self {
            source: value.source.clone(),
            profile_id: value.profile_id.clone(),
            field: value.field.clone(),
            message: value.message.clone(),
            severity: value.severity.clone(),
        }
    }
}
impl From<Diagnostic> for ProviderProfileDiagnostic {
    fn from(value: Diagnostic) -> Self {
        Self {
            source: value.source,
            profile_id: value.profile_id,
            field: value.field,
            message: value.message,
            severity: value.severity,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(in crate::grpc) struct Refresh {
    id: String,
    provider_id: String,
    epoch: String,
}

fn outcome(success: Success) -> Result<Outcome, Status> {
    match success {
        Success::Ordinary(value) => Ok(value),
        _ => Err(replay_unavailable()),
    }
}

async fn live<T: Message + Default + ObjectType + SetResourceVersion>(
    store: &Store,
    id: &str,
) -> Result<T, Status> {
    store
        .get_message(id)
        .await
        .map_err(storage_error)?
        .ok_or_else(replay_unavailable)
}

async fn selected_scope(
    state: &ServerState,
    principal: &Principal,
    workspace: &str,
    role: MinWorkspaceRole,
) -> Result<Scope, Status> {
    let authz =
        authorize_workspace(&state.store, &state.admin_role, principal, workspace, role).await?;
    named_scope(state, &authz.workspace).await
}

async fn profile_scope(
    state: &ServerState,
    principal: &Principal,
    workspace: &str,
) -> Result<Scope, Status> {
    if workspace.is_empty() {
        return global_scope(state, principal);
    }
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

macro_rules! mutation {
    ($req:ty, $resp:ty, $method:literal, $handler:path, $auth:expr, $capture:expr, $restore:expr) => {
        #[tonic::async_trait]
        impl Mutation for $req {
            type Output = $resp;
            const METHOD: &'static str = $method;
            const PROTECTED: bool = true;
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
                ($capture)(response).map(Success::Ordinary)
            }
            async fn restore(store: &Store, success: Success) -> Result<Self::Output, Status> {
                ($restore)(store, outcome(success)?).await
            }
        }
    };
}

macro_rules! scoped_mutation {
    ($req:ty, $resp:ty, $method:literal, $handler:path, $role:ident, $capture:expr, $restore:expr) => {
        mutation!(
            $req,
            $resp,
            $method,
            $handler,
            async |req: &$req, state: &ServerState, principal: &Principal| {
                selected_scope(state, principal, &req.workspace, MinWorkspaceRole::$role).await
            },
            $capture,
            $restore
        );
    };
}

fn sandbox_receipt(sandbox: Option<&Sandbox>, changed: bool) -> Result<Outcome, Status> {
    Ok(Outcome::Sandbox {
        id: sandbox.ok_or_else(uncertain)?.object_id().into(),
        changed,
    })
}

macro_rules! sandbox_mutation {
    ($req:ty, $method:literal, $handler:path) => {
        scoped_mutation!(
            $req,
            SandboxResponse,
            $method,
            $handler,
            User,
            |response: &Response<SandboxResponse>| sandbox_receipt(
                response.get_ref().sandbox.as_ref(),
                false
            ),
            async |store: &Store, outcome: Outcome| {
                let Outcome::Sandbox { id, .. } = outcome else {
                    return Err(replay_unavailable());
                };
                Ok(SandboxResponse {
                    sandbox: Some(live(store, &id).await?),
                })
            }
        );
    };
}
sandbox_mutation!(
    CreateSandboxRequest,
    "CreateSandbox",
    sandbox::handle_create_sandbox
);
sandbox_mutation!(
    StartSandboxRequest,
    "StartSandbox",
    sandbox::handle_start_sandbox
);
sandbox_mutation!(
    StopSandboxRequest,
    "StopSandbox",
    sandbox::handle_stop_sandbox
);

macro_rules! attachment_mutation {
    ($req:ty, $resp:ident, $method:literal, $handler:path, $field:ident) => {
        scoped_mutation!(
            $req,
            $resp,
            $method,
            $handler,
            User,
            |response: &Response<$resp>| {
                let response = response.get_ref();
                Ok(Outcome::Attachment {
                    id: response
                        .sandbox
                        .as_ref()
                        .ok_or_else(uncertain)?
                        .object_id()
                        .into(),
                    changed: response.$field,
                    receipt: ProviderReceiptReference::new(
                        response.receipt.as_ref().ok_or_else(uncertain)?,
                    ),
                })
            },
            async |store: &Store, outcome: Outcome| {
                let Outcome::Attachment {
                    id,
                    changed,
                    receipt,
                } = outcome
                else {
                    return Err(replay_unavailable());
                };
                Ok($resp {
                    sandbox: Some(live(store, &id).await?),
                    $field: changed,
                    receipt: Some(receipt.restore(store).await?),
                })
            }
        );
    };
}
attachment_mutation!(
    AttachSandboxProviderRequest,
    AttachSandboxProviderResponse,
    "AttachSandboxProvider",
    sandbox::handle_attach_sandbox_provider,
    attached
);
attachment_mutation!(
    DetachSandboxProviderRequest,
    DetachSandboxProviderResponse,
    "DetachSandboxProvider",
    sandbox::handle_detach_sandbox_provider,
    detached
);

scoped_mutation!(
    DeleteSandboxRequest,
    DeleteSandboxResponse,
    "DeleteSandbox",
    sandbox::handle_delete_sandbox,
    User,
    |response: &Response<DeleteSandboxResponse>| Ok(Outcome::SandboxDeletion {
        id: response.get_ref().sandbox_id.clone(),
        outcome: response.get_ref().outcome
    }),
    async |_store: &Store, value: Outcome| {
        let Outcome::SandboxDeletion { id, outcome } = value else {
            return Err(replay_unavailable());
        };
        Ok(DeleteSandboxResponse {
            sandbox_id: id,
            outcome,
        })
    }
);

scoped_mutation!(
    ExposeServiceRequest,
    ServiceEndpointResponse,
    "ExposeService",
    service::handle_expose_service,
    User,
    |response: &Response<ServiceEndpointResponse>| {
        let value = response.get_ref();
        let endpoint = value.endpoint.as_ref().ok_or_else(uncertain)?;
        Ok(Outcome::Service {
            reference: Reference::new(endpoint),
            sandbox_id: endpoint.sandbox_id.clone(),
            url: value.url.clone(),
        })
    },
    async |store: &Store, outcome: Outcome| {
        let Outcome::Service {
            reference,
            sandbox_id,
            url,
        } = outcome
        else {
            return Err(replay_unavailable());
        };
        let _: Sandbox = live(store, &sandbox_id).await?;
        Ok(ServiceEndpointResponse {
            endpoint: Some(reference.restore(store).await?),
            url,
        })
    }
);

macro_rules! provider_mutation {
    ($req:ty, $method:literal, $handler:path) => {
        scoped_mutation!(
            $req,
            ProviderResponse,
            $method,
            $handler,
            Admin,
            |response: &Response<ProviderResponse>| {
                let response = response.get_ref();
                Ok(Outcome::Provider {
                    reference: Reference::new(response.provider.as_ref().ok_or_else(uncertain)?),
                    mutation_id: response.mutation_id.clone(),
                    target_receipts: response
                        .target_receipts
                        .iter()
                        .map(ProviderReceiptReference::new)
                        .collect(),
                })
            },
            async |store: &Store, outcome: Outcome| {
                let Outcome::Provider {
                    reference,
                    mutation_id,
                    target_receipts,
                } = outcome
                else {
                    return Err(replay_unavailable());
                };
                let mut receipts = Vec::with_capacity(target_receipts.len());
                for receipt in target_receipts {
                    receipts.push(receipt.restore(store).await?);
                }
                Ok(ProviderResponse {
                    provider: Some(provider::redact_provider_credentials(
                        reference.restore(store).await?,
                    )),
                    mutation_id,
                    target_receipts: receipts,
                })
            }
        );
    };
}
provider_mutation!(
    CreateProviderRequest,
    "CreateProvider",
    provider::handle_create_provider
);
provider_mutation!(
    UpdateProviderRequest,
    "UpdateProvider",
    provider::handle_update_provider
);

// Terminal receipts deliberately do not resolve a deleted parent or replacement.
macro_rules! ordinary_deletion {
    ($req:ty, $resp:ident, $method:literal, $handler:path, $auth:expr) => {
        #[tonic::async_trait]
        impl Mutation for $req {
            type Output = $resp;
            const METHOD: &'static str = $method;
            const PROTECTED: bool = true;
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
ordinary_deletion!(
    DeleteServiceRequest,
    DeleteServiceResponse,
    "DeleteService",
    service::handle_delete_service,
    async |req: &DeleteServiceRequest, state: &ServerState, principal: &Principal| {
        selected_scope(state, principal, &req.workspace, MinWorkspaceRole::User).await
    }
);
ordinary_deletion!(
    DeleteProviderRequest,
    DeleteProviderResponse,
    "DeleteProvider",
    provider::handle_delete_provider,
    async |req: &DeleteProviderRequest, state: &ServerState, principal: &Principal| {
        selected_scope(state, principal, &req.workspace, MinWorkspaceRole::Admin).await
    }
);
ordinary_deletion!(
    DeleteProviderRefreshRequest,
    DeleteProviderRefreshResponse,
    "DeleteProviderRefresh",
    provider::handle_delete_provider_refresh,
    async |req: &DeleteProviderRefreshRequest, state: &ServerState, principal: &Principal| {
        selected_scope(state, principal, &req.workspace, MinWorkspaceRole::Admin).await
    }
);
ordinary_deletion!(
    DeleteProviderProfileRequest,
    DeleteProviderProfileResponse,
    "DeleteProviderProfile",
    provider::handle_delete_provider_profile,
    async |req: &DeleteProviderProfileRequest, state: &ServerState, principal: &Principal| {
        profile_scope(state, principal, &req.workspace).await
    }
);

async fn restore_profiles(
    store: &Store,
    references: Vec<Reference>,
) -> Result<Vec<ProviderProfile>, Status> {
    let mut profiles = Vec::with_capacity(references.len());
    for reference in references {
        let stored: StoredProviderProfile = reference.restore(store).await?;
        profiles.push(crate::provider_profile_sources::profile_response_payload(
            stored.profile.ok_or_else(replay_unavailable)?,
            reference.version,
        ));
    }
    Ok(profiles)
}

mutation!(
    ImportProviderProfilesRequest,
    ImportProviderProfilesResponse,
    "ImportProviderProfiles",
    provider::handle_import_provider_profiles,
    async |req: &ImportProviderProfilesRequest, state: &ServerState, principal: &Principal| {
        profile_scope(state, principal, &req.workspace).await
    },
    |response: &Response<ImportProviderProfilesResponse>| {
        let value = response.get_ref();
        let references = facts(response)?.references;
        if references.len() != value.profiles.len() {
            return Err(uncertain());
        }
        Ok(Outcome::Profiles {
            references,
            diagnostics: value.diagnostics.iter().map(Diagnostic::from).collect(),
            changed: value.imported,
        })
    },
    async |store: &Store, outcome: Outcome| {
        let Outcome::Profiles {
            references,
            diagnostics,
            changed,
        } = outcome
        else {
            return Err(replay_unavailable());
        };
        Ok(ImportProviderProfilesResponse {
            profiles: restore_profiles(store, references).await?,
            diagnostics: diagnostics.into_iter().map(Into::into).collect(),
            imported: changed,
        })
    }
);

mutation!(
    UpdateProviderProfilesRequest,
    UpdateProviderProfilesResponse,
    "UpdateProviderProfiles",
    provider::handle_update_provider_profiles,
    async |req: &UpdateProviderProfilesRequest, state: &ServerState, principal: &Principal| {
        profile_scope(state, principal, &req.workspace).await
    },
    |response: &Response<UpdateProviderProfilesResponse>| {
        let value = response.get_ref();
        let references = facts(response)?.references;
        if references.len() != usize::from(value.profile.is_some()) {
            return Err(uncertain());
        }
        Ok(Outcome::Profiles {
            references,
            diagnostics: value.diagnostics.iter().map(Diagnostic::from).collect(),
            changed: value.updated,
        })
    },
    async |store: &Store, outcome: Outcome| {
        let Outcome::Profiles {
            references,
            diagnostics,
            changed,
        } = outcome
        else {
            return Err(replay_unavailable());
        };
        let mut profiles = restore_profiles(store, references).await?;
        Ok(UpdateProviderProfilesResponse {
            profile: profiles.pop(),
            diagnostics: diagnostics.into_iter().map(Into::into).collect(),
            updated: changed,
        })
    }
);

macro_rules! refresh_mutation {
    ($req:ty, $resp:ident, $method:literal, $handler:path) => {
        scoped_mutation!(
            $req,
            $resp,
            $method,
            $handler,
            Admin,
            |response: &Response<$resp>| Ok(Outcome::Refresh(
                facts(response)?.refresh.ok_or_else(uncertain)?
            )),
            async |store: &Store, outcome: Outcome| {
                let Outcome::Refresh(reference) = outcome else {
                    return Err(replay_unavailable());
                };
                let state: StoredProviderCredentialRefreshState =
                    live(store, &reference.id).await?;
                let _: Provider = live(store, &reference.provider_id).await?;
                if state
                    .metadata
                    .as_ref()
                    .is_some_and(|metadata| metadata.deletion_time.is_some())
                    || state.provider_id != reference.provider_id
                    || crate::provider_refresh::effective_authorization_epoch(&state)?
                        != reference.epoch
                {
                    return Err(replay_unavailable());
                }
                Ok($resp {
                    status: Some(crate::provider_refresh::refresh_status_from_state(&state)),
                })
            }
        );
    };
}
refresh_mutation!(
    ConfigureProviderRefreshRequest,
    ConfigureProviderRefreshResponse,
    "ConfigureProviderRefresh",
    provider::handle_configure_provider_refresh
);
refresh_mutation!(
    RotateProviderCredentialRequest,
    RotateProviderCredentialResponse,
    "RotateProviderCredential",
    provider::handle_rotate_provider_credential
);

mutation!(
    UpdateConfigRequest,
    UpdateConfigResponse,
    "UpdateConfig",
    policy::handle_update_config,
    async |req: &UpdateConfigRequest, state: &ServerState, principal: &Principal| {
        if req.global {
            if !req.workspace.is_empty() {
                return Err(Status::invalid_argument(
                    "workspace must be omitted when global is true",
                ));
            }
            global_scope(state, principal)
        } else {
            selected_scope(state, principal, &req.workspace, MinWorkspaceRole::Admin).await
        }
    },
    |response: &Response<UpdateConfigResponse>| {
        let value = response.get_ref();
        let facts = facts(response)?;
        let references = facts.references;
        if references.len() != usize::from(!facts.global) {
            return Err(uncertain());
        }
        Ok(Outcome::Config {
            sandbox_id: references.first().map(|r| r.id.clone()),
            version: value.version,
            policy_hash: value.policy_hash.clone(),
            settings_revision: value.settings_revision,
            deleted: value.deleted,
            annotations: value.annotations.clone(),
        })
    },
    async |store: &Store, outcome: Outcome| {
        let Outcome::Config {
            sandbox_id,
            version,
            policy_hash,
            settings_revision,
            deleted,
            annotations,
        } = outcome
        else {
            return Err(replay_unavailable());
        };
        if let Some(id) = sandbox_id {
            let _: Sandbox = live(store, &id).await?;
        }
        Ok(UpdateConfigResponse {
            version,
            policy_hash,
            settings_revision,
            deleted,
            annotations,
        })
    }
);

macro_rules! policy_mutation {
    ($req:ty, $resp:ty, $method:literal, $handler:path, $values:expr, $restore:expr) => {
        scoped_mutation!(
            $req,
            $resp,
            $method,
            $handler,
            Admin,
            |response: &Response<$resp>| {
                let (version, hash, approved, skipped, cleared) = ($values)(response.get_ref());
                Ok(Outcome::Policy {
                    sandbox_id: parent(response)?,
                    version,
                    hash,
                    approved,
                    skipped,
                    cleared,
                })
            },
            async |store: &Store, outcome: Outcome| {
                let Outcome::Policy {
                    sandbox_id,
                    version,
                    hash,
                    approved,
                    skipped,
                    cleared,
                } = outcome
                else {
                    return Err(replay_unavailable());
                };
                let _: Sandbox = live(store, &sandbox_id).await?;
                Ok(($restore)(version, hash, approved, skipped, cleared))
            }
        );
    };
}
policy_mutation!(
    ApproveDraftChunkRequest,
    ApproveDraftChunkResponse,
    "ApproveDraftChunk",
    policy::handle_approve_draft_chunk,
    |v: &ApproveDraftChunkResponse| (v.policy_version, v.policy_hash.clone(), 0, 0, 0),
    |version, hash, _, _, _| ApproveDraftChunkResponse {
        policy_version: version,
        policy_hash: hash
    }
);
policy_mutation!(
    UndoDraftChunkRequest,
    UndoDraftChunkResponse,
    "UndoDraftChunk",
    policy::handle_undo_draft_chunk,
    |v: &UndoDraftChunkResponse| (v.policy_version, v.policy_hash.clone(), 0, 0, 0),
    |version, hash, _, _, _| UndoDraftChunkResponse {
        policy_version: version,
        policy_hash: hash
    }
);
policy_mutation!(
    ApproveAllDraftChunksRequest,
    ApproveAllDraftChunksResponse,
    "ApproveAllDraftChunks",
    policy::handle_approve_all_draft_chunks,
    |v: &ApproveAllDraftChunksResponse| (
        v.policy_version,
        v.policy_hash.clone(),
        v.chunks_approved,
        v.chunks_skipped,
        0
    ),
    |version, hash, approved, skipped, _| ApproveAllDraftChunksResponse {
        policy_version: version,
        policy_hash: hash,
        chunks_approved: approved,
        chunks_skipped: skipped
    }
);
policy_mutation!(
    ClearDraftChunksRequest,
    ClearDraftChunksResponse,
    "ClearDraftChunks",
    policy::handle_clear_draft_chunks,
    |v: &ClearDraftChunksResponse| (0, String::new(), 0, 0, v.chunks_cleared),
    |_, _, _, _, cleared| ClearDraftChunksResponse {
        chunks_cleared: cleared
    }
);
policy_mutation!(
    RejectDraftChunkRequest,
    RejectDraftChunkResponse,
    "RejectDraftChunk",
    policy::handle_reject_draft_chunk,
    |_: &RejectDraftChunkResponse| (0, String::new(), 0, 0, 0),
    |_, _, _, _, _| RejectDraftChunkResponse {}
);
policy_mutation!(
    EditDraftChunkRequest,
    EditDraftChunkResponse,
    "EditDraftChunk",
    policy::handle_edit_draft_chunk,
    |_: &EditDraftChunkResponse| (0, String::new(), 0, 0, 0),
    |_, _, _, _, _| EditDraftChunkResponse {}
);
