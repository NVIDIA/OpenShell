// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Additive creation and inspection APIs for gateway-owned policy freezing.

use super::{OpenShellService, extract_principal, mutation_replay, policy, sandbox};
use crate::ServerState;
use crate::auth::workspace_authz::{MinWorkspaceRole, selected_workspace_name};
use openshell_core::ObjectId;
use openshell_core::proto::{
    CreateFrozenSandboxRequest, CreateSandboxRequest, FrozenSandboxConfigResponse,
    FrozenSandboxPolicyState, FrozenSandboxResponse, GetFrozenSandboxConfigRequest,
    GetFrozenSandboxPolicyRequest, GetSandboxConfigRequest, UpdateConfigRequest,
    UpdateFrozenGlobalConfigRequest, UpdateFrozenGlobalConfigResponse,
};
use std::sync::Arc;
use tonic::{Request, Response, Status};

#[derive(Clone)]
pub(super) struct FrozenSandboxes(pub Vec<String>);

pub(super) async fn state_for(
    store: &crate::persistence::Store,
    sandbox_id: &str,
) -> Result<FrozenSandboxPolicyState, Status> {
    let state = store
        .get_sandbox_frozen_policy(sandbox_id)
        .await
        .map_err(|error| Status::internal(format!("fetch frozen policy failed: {error}")))?;
    Ok(FrozenSandboxPolicyState {
        requested: state.is_some(),
        policy: state.and_then(|state| state.policy),
    })
}

#[tonic::async_trait]
impl openshell_core::proto::frozen_sandbox_policies_server::FrozenSandboxPolicies
    for OpenShellService
{
    async fn create_sandbox(
        &self,
        request: Request<CreateFrozenSandboxRequest>,
    ) -> Result<Response<FrozenSandboxResponse>, Status> {
        mutation_replay::run(&self.state, request).await
    }

    async fn get_policy(
        &self,
        request: Request<GetFrozenSandboxPolicyRequest>,
    ) -> Result<Response<FrozenSandboxPolicyState>, Status> {
        let principal = extract_principal(&request)?;
        let request = request.into_inner();
        let sandbox = sandbox::resolve_and_authorize_sandbox_name(
            &self.state,
            &principal,
            &request.name,
            selected_workspace_name(request.workspace_scope.as_ref())?,
            MinWorkspaceRole::User,
        )
        .await?;
        Ok(Response::new(
            state_for(self.state.store.as_ref(), sandbox.object_id()).await?,
        ))
    }

    async fn get_config(
        &self,
        request: Request<GetFrozenSandboxConfigRequest>,
    ) -> Result<Response<FrozenSandboxConfigResponse>, Status> {
        let (response, frozen, frozen_requested) = policy::handle_get_sandbox_config_with_frozen(
            &self.state,
            request.map(|request| GetSandboxConfigRequest {
                name: request.name,
                workspace_scope: request.workspace_scope,
            }),
        )
        .await?;
        Ok(response.map(|config| FrozenSandboxConfigResponse {
            config: Some(config),
            frozen,
            frozen_requested,
        }))
    }

    async fn update_global_config(
        &self,
        request: Request<UpdateFrozenGlobalConfigRequest>,
    ) -> Result<Response<UpdateFrozenGlobalConfigResponse>, Status> {
        mutation_replay::run(&self.state, request).await
    }
}

pub(super) async fn handle_create(
    state: &Arc<ServerState>,
    request: Request<CreateFrozenSandboxRequest>,
) -> Result<Response<FrozenSandboxResponse>, Status> {
    let request = request.map(|request| CreateSandboxRequest {
        workspace_scope: request.workspace_scope,
        spec: request.spec,
        name: request.name,
        labels: request.labels,
        annotations: request.annotations,
        await_main_process_attachment: request.await_main_process_attachment,
        workload_template: request.workload_template,
        request_id: request.request_id,
        service_exposures: request.service_exposures,
    });
    let response = sandbox::handle_create_sandbox_with_mode(state, request, true).await?;
    let sandbox = response
        .get_ref()
        .sandbox
        .as_ref()
        .ok_or_else(|| Status::internal("created sandbox is missing"))?;
    let frozen_policy = state_for(state.store.as_ref(), sandbox.object_id()).await?;
    Ok(response.map(|response| FrozenSandboxResponse {
        sandbox: response.sandbox,
        frozen_policy: Some(frozen_policy),
        service_urls: response.service_urls,
    }))
}

pub(super) fn validate_global_request(
    request: &UpdateFrozenGlobalConfigRequest,
) -> Result<(), Status> {
    if !request.global {
        return Err(Status::invalid_argument("global must be true"));
    }
    if request.workspace_scope.is_some()
        || !request.sandbox.is_empty()
        || !request.merge_operations.is_empty()
        || !request.annotations.is_empty()
        || request.expected_resource_version != 0
    {
        return Err(Status::invalid_argument(
            "sandbox, workspace_scope, merge_operations, annotations, and expected_resource_version are unsupported for global configuration",
        ));
    }
    Ok(())
}

pub(super) async fn handle_update_global(
    state: &Arc<ServerState>,
    request: Request<UpdateFrozenGlobalConfigRequest>,
) -> Result<Response<UpdateFrozenGlobalConfigResponse>, Status> {
    validate_global_request(request.get_ref())?;
    let response = policy::handle_update_config(
        state,
        request.map(|request| UpdateConfigRequest {
            workspace_scope: request.workspace_scope,
            policy: request.policy,
            setting_key: request.setting_key,
            setting_value: request.setting_value,
            delete_setting: request.delete_setting,
            global: request.global,
            merge_operations: request.merge_operations,
            expected_resource_version: request.expected_resource_version,
            annotations: request.annotations,
            sandbox: request.sandbox,
            request_id: request.request_id,
        }),
    )
    .await?;
    let names = response
        .extensions()
        .get::<FrozenSandboxes>()
        .map_or_else(Vec::new, |names| names.0.clone());
    Ok(response.map(|update| UpdateFrozenGlobalConfigResponse {
        update: Some(update),
        frozen_sandboxes: names,
    }))
}
