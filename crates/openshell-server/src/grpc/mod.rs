// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! gRPC service implementation.

pub mod policy;
mod provider;
mod sandbox;
mod validation;

use openshell_core::proto::{
    ApproveAllDraftChunksRequest, ApproveAllDraftChunksResponse, ApproveDraftChunkRequest,
    ApproveDraftChunkResponse, ClearDraftChunksRequest, ClearDraftChunksResponse,
    CreateProviderRequest, CreateSandboxRequest, CreateSshSessionRequest, CreateSshSessionResponse,
    DeleteProviderProfileRequest, DeleteProviderProfileResponse, DeleteProviderRequest,
    DeleteProviderResponse, DeleteSandboxRequest, DeleteSandboxResponse, EditDraftChunkRequest,
    EditDraftChunkResponse, ExecSandboxEvent, ExecSandboxRequest, GatewayMessage,
    GetDraftHistoryRequest, GetDraftHistoryResponse, GetDraftPolicyRequest, GetDraftPolicyResponse,
    GetGatewayConfigRequest, GetGatewayConfigResponse, GetProviderProfileRequest,
    GetProviderRequest, GetSandboxConfigRequest, GetSandboxConfigResponse, GetSandboxLogsRequest,
    GetSandboxLogsResponse, GetSandboxPolicyStatusRequest, GetSandboxPolicyStatusResponse,
    GetSandboxProviderEnvironmentRequest, GetSandboxProviderEnvironmentResponse, GetSandboxRequest,
    HealthRequest, HealthResponse, ImportProviderProfilesRequest, ImportProviderProfilesResponse,
    LintProviderProfilesRequest, LintProviderProfilesResponse, ListProviderProfilesRequest,
    ListProviderProfilesResponse, ListProvidersRequest, ListProvidersResponse,
    ListSandboxPoliciesRequest, ListSandboxPoliciesResponse, ListSandboxesRequest,
    ListSandboxesResponse, ProviderProfileResponse, ProviderResponse, PushSandboxLogsRequest,
    PushSandboxLogsResponse, RejectDraftChunkRequest, RejectDraftChunkResponse, RelayFrame,
    ReportPolicyStatusRequest, ReportPolicyStatusResponse, RevokeSshSessionRequest,
    RevokeSshSessionResponse, SandboxResponse, SandboxStreamEvent, ServiceStatus,
    SubmitPolicyAnalysisRequest, SubmitPolicyAnalysisResponse, SupervisorMessage,
    UndoDraftChunkRequest, UndoDraftChunkResponse, UpdateConfigRequest, UpdateConfigResponse,
    UpdateProviderRequest, WatchSandboxRequest, open_shell_server::OpenShell,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::ServerState;

// ---------------------------------------------------------------------------
// Public re-exports
// ---------------------------------------------------------------------------

/// Maximum number of records a single list RPC may return.
///
/// Client-provided `limit` values are clamped to this ceiling to prevent
/// unbounded memory allocation from an excessively large page request.
pub const MAX_PAGE_SIZE: u32 = 1000;

/// Clamp a client-provided page `limit`.
///
/// Returns `default` when `raw` is 0 (the protobuf zero-value convention),
/// otherwise returns the smaller of `raw` and `max`.
pub fn clamp_limit(raw: u32, default: u32, max: u32) -> u32 {
    if raw == 0 { default } else { raw.min(max) }
}

// ---------------------------------------------------------------------------
// Field-level size limits (shared across submodules)
// ---------------------------------------------------------------------------

/// Maximum length for a sandbox or provider name (Kubernetes name limit).
const MAX_NAME_LEN: usize = 253;
/// Maximum number of providers that can be attached to a sandbox.
const MAX_PROVIDERS: usize = 32;
/// Maximum length for the `log_level` field.
const MAX_LOG_LEVEL_LEN: usize = 32;
/// Maximum number of entries in `spec.environment`.
const MAX_ENVIRONMENT_ENTRIES: usize = 128;
/// Maximum length for an environment map key (bytes).
const MAX_MAP_KEY_LEN: usize = 256;
/// Maximum length for an environment map value (bytes).
const MAX_MAP_VALUE_LEN: usize = 8192;
/// Maximum length for template string fields.
const MAX_TEMPLATE_STRING_LEN: usize = 1024;
/// Maximum number of entries in template map fields.
const MAX_TEMPLATE_MAP_ENTRIES: usize = 128;
/// Maximum serialized size (bytes) for template Struct fields.
const MAX_TEMPLATE_STRUCT_SIZE: usize = 65_536;
/// Maximum serialized size (bytes) for the policy field.
const MAX_POLICY_SIZE: usize = 262_144;
/// Maximum length for a provider type slug.
const MAX_PROVIDER_TYPE_LEN: usize = 64;
/// Maximum number of entries in the provider `credentials` map.
const MAX_PROVIDER_CREDENTIALS_ENTRIES: usize = 32;
/// Maximum number of entries in the provider `config` map.
const MAX_PROVIDER_CONFIG_ENTRIES: usize = 64;

// ---------------------------------------------------------------------------
// Shared types (used by the policy/settings submodule)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct StoredSettings {
    revision: u64,
    settings: BTreeMap<String, StoredSettingValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "value")]
enum StoredSettingValue {
    String(String),
    Bool(bool),
    Int(i64),
    /// Hex-encoded binary payload.
    Bytes(String),
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

fn current_time_ms() -> Result<i64, std::time::SystemTimeError> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    Ok(i64::try_from(now.as_millis()).unwrap_or(i64::MAX))
}

/// Validate that object metadata is present and contains required fields.
///
/// This is a crate-level helper that wraps the validation module's implementation.
/// Use this from modules outside of `grpc` that need to validate metadata.
// `tonic::Status` is large but is the API surface of gRPC handlers.
#[allow(clippy::result_large_err)]
pub fn validate_object_metadata(
    metadata: Option<&openshell_core::proto::datamodel::v1::ObjectMeta>,
    resource_type: &str,
) -> Result<(), Status> {
    validation::validate_object_metadata(metadata, resource_type)
}

// ---------------------------------------------------------------------------
// Service struct
// ---------------------------------------------------------------------------

/// `OpenShell` gRPC service implementation.
#[derive(Debug, Clone)]
pub struct OpenShellService {
    state: Arc<ServerState>,
}

impl OpenShellService {
    /// Create a new `OpenShell` service.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }
}

// ---------------------------------------------------------------------------
// Trait impl — thin delegation to submodules
// ---------------------------------------------------------------------------

#[tonic::async_trait]
impl OpenShell for OpenShellService {
    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            status: ServiceStatus::Healthy.into(),
            version: openshell_core::VERSION.to_string(),
        }))
    }

    // --- Sandbox lifecycle ---

    async fn create_sandbox(
        &self,
        request: Request<CreateSandboxRequest>,
    ) -> Result<Response<SandboxResponse>, Status> {
        sandbox::handle_create_sandbox(&self.state, request).await
    }

    type WatchSandboxStream = ReceiverStream<Result<SandboxStreamEvent, Status>>;

    async fn watch_sandbox(
        &self,
        request: Request<WatchSandboxRequest>,
    ) -> Result<Response<Self::WatchSandboxStream>, Status> {
        sandbox::handle_watch_sandbox(&self.state, request).await
    }

    async fn get_sandbox(
        &self,
        request: Request<GetSandboxRequest>,
    ) -> Result<Response<SandboxResponse>, Status> {
        sandbox::handle_get_sandbox(&self.state, request).await
    }

    async fn list_sandboxes(
        &self,
        request: Request<ListSandboxesRequest>,
    ) -> Result<Response<ListSandboxesResponse>, Status> {
        sandbox::handle_list_sandboxes(&self.state, request).await
    }

    async fn delete_sandbox(
        &self,
        request: Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
        sandbox::handle_delete_sandbox(&self.state, request).await
    }

    // --- Exec ---

    type ExecSandboxStream = ReceiverStream<Result<ExecSandboxEvent, Status>>;

    async fn exec_sandbox(
        &self,
        request: Request<ExecSandboxRequest>,
    ) -> Result<Response<Self::ExecSandboxStream>, Status> {
        sandbox::handle_exec_sandbox(&self.state, request).await
    }

    // --- SSH sessions ---

    async fn create_ssh_session(
        &self,
        request: Request<CreateSshSessionRequest>,
    ) -> Result<Response<CreateSshSessionResponse>, Status> {
        sandbox::handle_create_ssh_session(&self.state, request).await
    }

    async fn revoke_ssh_session(
        &self,
        request: Request<RevokeSshSessionRequest>,
    ) -> Result<Response<RevokeSshSessionResponse>, Status> {
        sandbox::handle_revoke_ssh_session(&self.state, request).await
    }

    // --- Providers ---

    async fn create_provider(
        &self,
        request: Request<CreateProviderRequest>,
    ) -> Result<Response<ProviderResponse>, Status> {
        provider::handle_create_provider(&self.state, request).await
    }

    async fn get_provider(
        &self,
        request: Request<GetProviderRequest>,
    ) -> Result<Response<ProviderResponse>, Status> {
        provider::handle_get_provider(&self.state, request).await
    }

    async fn list_providers(
        &self,
        request: Request<ListProvidersRequest>,
    ) -> Result<Response<ListProvidersResponse>, Status> {
        provider::handle_list_providers(&self.state, request).await
    }

    async fn list_provider_profiles(
        &self,
        request: Request<ListProviderProfilesRequest>,
    ) -> Result<Response<ListProviderProfilesResponse>, Status> {
        provider::handle_list_provider_profiles(&self.state, request).await
    }

    async fn get_provider_profile(
        &self,
        request: Request<GetProviderProfileRequest>,
    ) -> Result<Response<ProviderProfileResponse>, Status> {
        provider::handle_get_provider_profile(&self.state, request).await
    }

    async fn import_provider_profiles(
        &self,
        request: Request<ImportProviderProfilesRequest>,
    ) -> Result<Response<ImportProviderProfilesResponse>, Status> {
        provider::handle_import_provider_profiles(&self.state, request).await
    }

    async fn lint_provider_profiles(
        &self,
        request: Request<LintProviderProfilesRequest>,
    ) -> Result<Response<LintProviderProfilesResponse>, Status> {
        provider::handle_lint_provider_profiles(&self.state, request).await
    }

    async fn update_provider(
        &self,
        request: Request<UpdateProviderRequest>,
    ) -> Result<Response<ProviderResponse>, Status> {
        provider::handle_update_provider(&self.state, request).await
    }

    async fn delete_provider(
        &self,
        request: Request<DeleteProviderRequest>,
    ) -> Result<Response<DeleteProviderResponse>, Status> {
        provider::handle_delete_provider(&self.state, request).await
    }

    async fn delete_provider_profile(
        &self,
        request: Request<DeleteProviderProfileRequest>,
    ) -> Result<Response<DeleteProviderProfileResponse>, Status> {
        provider::handle_delete_provider_profile(&self.state, request).await
    }

    // --- Config / Policy ---

    async fn get_sandbox_config(
        &self,
        request: Request<GetSandboxConfigRequest>,
    ) -> Result<Response<GetSandboxConfigResponse>, Status> {
        policy::handle_get_sandbox_config(&self.state, request).await
    }

    async fn get_gateway_config(
        &self,
        request: Request<GetGatewayConfigRequest>,
    ) -> Result<Response<GetGatewayConfigResponse>, Status> {
        policy::handle_get_gateway_config(&self.state, request).await
    }

    async fn get_sandbox_provider_environment(
        &self,
        request: Request<GetSandboxProviderEnvironmentRequest>,
    ) -> Result<Response<GetSandboxProviderEnvironmentResponse>, Status> {
        policy::handle_get_sandbox_provider_environment(&self.state, request).await
    }

    async fn update_config(
        &self,
        request: Request<UpdateConfigRequest>,
    ) -> Result<Response<UpdateConfigResponse>, Status> {
        policy::handle_update_config(&self.state, request).await
    }

    async fn get_sandbox_policy_status(
        &self,
        request: Request<GetSandboxPolicyStatusRequest>,
    ) -> Result<Response<GetSandboxPolicyStatusResponse>, Status> {
        policy::handle_get_sandbox_policy_status(&self.state, request).await
    }

    async fn list_sandbox_policies(
        &self,
        request: Request<ListSandboxPoliciesRequest>,
    ) -> Result<Response<ListSandboxPoliciesResponse>, Status> {
        policy::handle_list_sandbox_policies(&self.state, request).await
    }

    async fn report_policy_status(
        &self,
        request: Request<ReportPolicyStatusRequest>,
    ) -> Result<Response<ReportPolicyStatusResponse>, Status> {
        policy::handle_report_policy_status(&self.state, request).await
    }

    // --- Sandbox logs ---

    async fn get_sandbox_logs(
        &self,
        request: Request<GetSandboxLogsRequest>,
    ) -> Result<Response<GetSandboxLogsResponse>, Status> {
        policy::handle_get_sandbox_logs(&self.state, request).await
    }

    async fn push_sandbox_logs(
        &self,
        request: Request<tonic::Streaming<PushSandboxLogsRequest>>,
    ) -> Result<Response<PushSandboxLogsResponse>, Status> {
        policy::handle_push_sandbox_logs(&self.state, request).await
    }

    // --- Draft policy recommendations ---

    async fn submit_policy_analysis(
        &self,
        request: Request<SubmitPolicyAnalysisRequest>,
    ) -> Result<Response<SubmitPolicyAnalysisResponse>, Status> {
        policy::handle_submit_policy_analysis(&self.state, request).await
    }

    async fn get_draft_policy(
        &self,
        request: Request<GetDraftPolicyRequest>,
    ) -> Result<Response<GetDraftPolicyResponse>, Status> {
        policy::handle_get_draft_policy(&self.state, request).await
    }

    async fn approve_draft_chunk(
        &self,
        request: Request<ApproveDraftChunkRequest>,
    ) -> Result<Response<ApproveDraftChunkResponse>, Status> {
        policy::handle_approve_draft_chunk(&self.state, request).await
    }

    async fn reject_draft_chunk(
        &self,
        request: Request<RejectDraftChunkRequest>,
    ) -> Result<Response<RejectDraftChunkResponse>, Status> {
        policy::handle_reject_draft_chunk(&self.state, request).await
    }

    async fn approve_all_draft_chunks(
        &self,
        request: Request<ApproveAllDraftChunksRequest>,
    ) -> Result<Response<ApproveAllDraftChunksResponse>, Status> {
        policy::handle_approve_all_draft_chunks(&self.state, request).await
    }

    async fn edit_draft_chunk(
        &self,
        request: Request<EditDraftChunkRequest>,
    ) -> Result<Response<EditDraftChunkResponse>, Status> {
        policy::handle_edit_draft_chunk(&self.state, request).await
    }

    async fn undo_draft_chunk(
        &self,
        request: Request<UndoDraftChunkRequest>,
    ) -> Result<Response<UndoDraftChunkResponse>, Status> {
        policy::handle_undo_draft_chunk(&self.state, request).await
    }

    async fn clear_draft_chunks(
        &self,
        request: Request<ClearDraftChunksRequest>,
    ) -> Result<Response<ClearDraftChunksResponse>, Status> {
        policy::handle_clear_draft_chunks(&self.state, request).await
    }

    async fn get_draft_history(
        &self,
        request: Request<GetDraftHistoryRequest>,
    ) -> Result<Response<GetDraftHistoryResponse>, Status> {
        policy::handle_get_draft_history(&self.state, request).await
    }

    // --- Supervisor session ---

    type ConnectSupervisorStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<GatewayMessage, Status>> + Send + 'static>>;

    async fn connect_supervisor(
        &self,
        request: Request<tonic::Streaming<SupervisorMessage>>,
    ) -> Result<Response<Self::ConnectSupervisorStream>, Status> {
        crate::supervisor_session::handle_connect_supervisor(&self.state, request).await
    }

    type RelayStreamStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<RelayFrame, Status>> + Send + 'static>>;

    async fn relay_stream(
        &self,
        request: Request<tonic::Streaming<RelayFrame>>,
    ) -> Result<Response<Self::RelayStreamStream>, Status> {
        crate::supervisor_session::handle_relay_stream(&self.state.supervisor_sessions, request)
            .await
    }
}

// ---------------------------------------------------------------------------
// Tests for mod-level utilities
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_limit_zero_returns_default() {
        assert_eq!(clamp_limit(0, 100, MAX_PAGE_SIZE), 100);
        assert_eq!(clamp_limit(0, 50, MAX_PAGE_SIZE), 50);
    }

    #[test]
    fn clamp_limit_within_range_passes_through() {
        assert_eq!(clamp_limit(1, 100, MAX_PAGE_SIZE), 1);
        assert_eq!(clamp_limit(500, 100, MAX_PAGE_SIZE), 500);
        assert_eq!(
            clamp_limit(MAX_PAGE_SIZE, 100, MAX_PAGE_SIZE),
            MAX_PAGE_SIZE
        );
    }

    #[test]
    fn clamp_limit_exceeding_max_is_capped() {
        assert_eq!(
            clamp_limit(MAX_PAGE_SIZE + 1, 100, MAX_PAGE_SIZE),
            MAX_PAGE_SIZE
        );
        assert_eq!(clamp_limit(u32::MAX, 100, MAX_PAGE_SIZE), MAX_PAGE_SIZE);
    }
}
