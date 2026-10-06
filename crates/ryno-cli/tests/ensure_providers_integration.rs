// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `ensure_required_providers` — verifies that explicit
//! `--provider` names are auto-created when they match a known provider type,
//! pass through when they already exist, and error for unrecognised names.

mod helpers;

use helpers::{EnvVarGuard, build_ca, build_client_cert, build_server_cert};
use ryno_cli::run;
use ryno_cli::tls::TlsOptions;
use ryno_core::proto::ryno_server::{Ryno, RynoServer};
use ryno_core::proto::{
    AttachSandboxProviderRequest, AttachSandboxProviderResponse, CreateProviderRequest,
    CreateSandboxRequest, CreateSshSessionRequest, CreateSshSessionResponse, DeleteProviderRequest,
    DeleteProviderResponse, DeleteSandboxRequest, DeleteSandboxResponse,
    DetachSandboxProviderRequest, DetachSandboxProviderResponse,
    ExchangeProviderSubjectTokenRequest, ExchangeProviderSubjectTokenResponse, ExecSandboxEvent,
    ExecSandboxInput, ExecSandboxRequest, GatewayMessage, GetGatewayConfigRequest,
    GetGatewayConfigResponse, GetProviderRequest, GetSandboxConfigRequest,
    GetSandboxConfigResponse, GetSandboxProviderEnvironmentRequest,
    GetSandboxProviderEnvironmentResponse, GetSandboxRequest, HealthRequest, HealthResponse,
    ListProvidersRequest, ListProvidersResponse, ListSandboxProvidersRequest,
    ListSandboxProvidersResponse, ListSandboxesRequest, ListSandboxesResponse, Provider,
    ProviderResponse, RevokeSshSessionRequest, RevokeSshSessionResponse, SandboxResponse,
    SandboxStreamEvent, ServiceStatus, SupervisorMessage, UpdateProviderRequest,
    WatchSandboxRequest,
};
use ryno_core::{ObjectId, ObjectName};
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, mpsc};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Certificate as TlsCertificate, Identity, Server, ServerTlsConfig};
use tonic::{Response, Status};

// ── mock Ryno server ─────────────────────────────────────────────

#[derive(Clone, Default)]
struct ProviderState {
    providers: Arc<Mutex<HashMap<String, Provider>>>,
}

#[derive(Clone, Default)]
struct TestRyno {
    state: ProviderState,
}

impl TestRyno {
    /// Seed the mock with an existing provider.
    async fn seed_provider(&self, name: &str, provider_type: &str) {
        let mut providers = self.state.providers.lock().await;
        providers.insert(
            name.to_string(),
            Provider {
                metadata: Some(ryno_core::proto::datamodel::v1::ObjectMeta {
                    id: format!("id-{name}"),
                    name: name.to_string(),
                    created_time: None,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: String::new(),
                    deletion_time: None,
                }),
                r#type: provider_type.to_string(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expiration_times: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        );
    }
}

#[tonic::async_trait]
impl Ryno for TestRyno {
    async fn peer_report_provider_readiness(
        &self,
        _request: tonic::Request<ryno_core::proto::ReportProviderReadinessRequest>,
    ) -> Result<Response<ryno_core::proto::ReportProviderReadinessResponse>, Status> {
        Err(Status::unimplemented("not used by this test server"))
    }

    async fn peer_report_endpoint_status(
        &self,
        _request: tonic::Request<ryno_core::proto::ReportEndpointStatusRequest>,
    ) -> Result<Response<ryno_core::proto::ReportEndpointStatusResponse>, Status> {
        Err(Status::unimplemented("not used by this test server"))
    }

    async fn peer_get_sandbox_provider_status(
        &self,
        _request: tonic::Request<ryno_core::proto::GetSandboxProviderStatusRequest>,
    ) -> Result<Response<ryno_core::proto::GetSandboxProviderStatusResponse>, Status> {
        Err(Status::unimplemented("not used by this test server"))
    }

    async fn report_endpoint_status(
        &self,
        _request: tonic::Request<ryno_core::proto::ReportEndpointStatusRequest>,
    ) -> Result<Response<ryno_core::proto::ReportEndpointStatusResponse>, Status> {
        Ok(Response::new(
            ryno_core::proto::ReportEndpointStatusResponse {},
        ))
    }

    async fn begin_rootfs_tar_staging(
        &self,
        _request: tonic::Request<ryno_core::proto::BeginRootfsTarStagingRequest>,
    ) -> Result<Response<ryno_core::proto::BeginRootfsTarStagingResponse>, Status> {
        Err(Status::unimplemented("not used by this test server"))
    }

    async fn report_main_process_exit(
        &self,
        _request: tonic::Request<ryno_core::proto::ReportMainProcessExitRequest>,
    ) -> Result<Response<ryno_core::proto::ReportMainProcessExitResponse>, Status> {
        Err(Status::unimplemented("not used by this test server"))
    }

    async fn finalize_main_process_exit(
        &self,
        _request: tonic::Request<ryno_core::proto::FinalizeMainProcessExitRequest>,
    ) -> Result<Response<ryno_core::proto::FinalizeMainProcessExitResponse>, Status> {
        Err(Status::unimplemented("not used by this test server"))
    }

    async fn get_current_user(
        &self,
        _request: tonic::Request<ryno_core::proto::GetCurrentUserRequest>,
    ) -> Result<Response<ryno_core::proto::GetCurrentUserResponse>, Status> {
        Err(Status::unimplemented("not used by this test server"))
    }

    async fn health(
        &self,
        _request: tonic::Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            status: ServiceStatus::Healthy.into(),
            version: "test".to_string(),
        }))
    }

    async fn get_gateway_info(
        &self,
        _request: tonic::Request<ryno_core::proto::GetGatewayInfoRequest>,
    ) -> Result<Response<ryno_core::proto::GetGatewayInfoResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn create_sandbox(
        &self,
        _request: tonic::Request<CreateSandboxRequest>,
    ) -> Result<Response<SandboxResponse>, Status> {
        Ok(Response::new(SandboxResponse::default()))
    }

    async fn stop_sandbox(
        &self,
        _request: tonic::Request<ryno_core::proto::StopSandboxRequest>,
    ) -> Result<Response<SandboxResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn start_sandbox(
        &self,
        _request: tonic::Request<ryno_core::proto::StartSandboxRequest>,
    ) -> Result<Response<SandboxResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn get_sandbox(
        &self,
        _request: tonic::Request<GetSandboxRequest>,
    ) -> Result<Response<SandboxResponse>, Status> {
        Ok(Response::new(SandboxResponse::default()))
    }

    async fn list_sandboxes(
        &self,
        _request: tonic::Request<ListSandboxesRequest>,
    ) -> Result<Response<ListSandboxesResponse>, Status> {
        Ok(Response::new(ListSandboxesResponse::default()))
    }

    unimplemented_sandbox_template_rpcs!();

    async fn list_sandbox_providers(
        &self,
        _request: tonic::Request<ListSandboxProvidersRequest>,
    ) -> Result<Response<ListSandboxProvidersResponse>, Status> {
        Ok(Response::new(ListSandboxProvidersResponse::default()))
    }

    async fn attach_sandbox_provider(
        &self,
        _request: tonic::Request<AttachSandboxProviderRequest>,
    ) -> Result<Response<AttachSandboxProviderResponse>, Status> {
        Ok(Response::new(AttachSandboxProviderResponse::default()))
    }

    async fn detach_sandbox_provider(
        &self,
        _request: tonic::Request<DetachSandboxProviderRequest>,
    ) -> Result<Response<DetachSandboxProviderResponse>, Status> {
        Ok(Response::new(DetachSandboxProviderResponse::default()))
    }

    async fn delete_sandbox(
        &self,
        _request: tonic::Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
        Ok(Response::new(DeleteSandboxResponse {
            sandbox_id: String::new(),
            outcome: ryno_core::proto::DeletionOutcome::Completed.into(),
        }))
    }

    async fn get_sandbox_config(
        &self,
        _request: tonic::Request<GetSandboxConfigRequest>,
    ) -> Result<Response<GetSandboxConfigResponse>, Status> {
        Ok(Response::new(GetSandboxConfigResponse::default()))
    }

    async fn get_gateway_config(
        &self,
        _request: tonic::Request<GetGatewayConfigRequest>,
    ) -> Result<Response<GetGatewayConfigResponse>, Status> {
        Ok(Response::new(GetGatewayConfigResponse::default()))
    }

    async fn get_sandbox_provider_status(
        &self,
        _request: tonic::Request<ryno_core::proto::GetSandboxProviderStatusRequest>,
    ) -> Result<Response<ryno_core::proto::GetSandboxProviderStatusResponse>, Status> {
        Err(Status::unimplemented(
            "provider readiness is not exercised by this mock",
        ))
    }

    async fn report_provider_readiness(
        &self,
        _request: tonic::Request<ryno_core::proto::ReportProviderReadinessRequest>,
    ) -> Result<Response<ryno_core::proto::ReportProviderReadinessResponse>, Status> {
        Err(Status::unimplemented(
            "provider installation reports are not exercised by this mock",
        ))
    }

    async fn get_sandbox_provider_environment(
        &self,
        _request: tonic::Request<GetSandboxProviderEnvironmentRequest>,
    ) -> Result<Response<GetSandboxProviderEnvironmentResponse>, Status> {
        Ok(Response::new(
            GetSandboxProviderEnvironmentResponse::default(),
        ))
    }

    async fn create_ssh_session(
        &self,
        _request: tonic::Request<CreateSshSessionRequest>,
    ) -> Result<Response<CreateSshSessionResponse>, Status> {
        Ok(Response::new(CreateSshSessionResponse::default()))
    }

    async fn expose_service(
        &self,
        _request: tonic::Request<ryno_core::proto::ExposeServiceRequest>,
    ) -> Result<Response<ryno_core::proto::ServiceEndpointResponse>, Status> {
        Ok(Response::new(
            ryno_core::proto::ServiceEndpointResponse::default(),
        ))
    }

    async fn get_service(
        &self,
        _: tonic::Request<ryno_core::proto::GetServiceRequest>,
    ) -> Result<Response<ryno_core::proto::ServiceEndpointResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn list_services(
        &self,
        _: tonic::Request<ryno_core::proto::ListServicesRequest>,
    ) -> Result<Response<ryno_core::proto::ListServicesResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn delete_service(
        &self,
        _: tonic::Request<ryno_core::proto::DeleteServiceRequest>,
    ) -> Result<Response<ryno_core::proto::DeleteServiceResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn revoke_ssh_session(
        &self,
        _request: tonic::Request<RevokeSshSessionRequest>,
    ) -> Result<Response<RevokeSshSessionResponse>, Status> {
        Ok(Response::new(RevokeSshSessionResponse::default()))
    }

    async fn exchange_provider_subject_token(
        &self,
        _request: tonic::Request<ExchangeProviderSubjectTokenRequest>,
    ) -> Result<Response<ExchangeProviderSubjectTokenResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn create_provider(
        &self,
        request: tonic::Request<CreateProviderRequest>,
    ) -> Result<Response<ProviderResponse>, Status> {
        let mut provider = request
            .into_inner()
            .provider
            .ok_or_else(|| Status::invalid_argument("provider is required"))?;
        let mut providers = self.state.providers.lock().await;
        let provider_name = provider.object_name().to_string();
        if providers.contains_key(&provider_name) {
            return Err(Status::already_exists("provider already exists"));
        }
        if provider.object_id().is_empty()
            && let Some(metadata) = &mut provider.metadata
        {
            metadata.id = format!("id-{provider_name}");
        }
        providers.insert(provider_name, provider.clone());
        Ok(Response::new(ProviderResponse {
            provider: Some(provider),
            ..Default::default()
        }))
    }

    async fn get_provider(
        &self,
        request: tonic::Request<GetProviderRequest>,
    ) -> Result<Response<ProviderResponse>, Status> {
        let name = request.into_inner().name;
        let providers = self.state.providers.lock().await;
        let provider = providers
            .get(&name)
            .cloned()
            .ok_or_else(|| Status::not_found("provider not found"))?;
        Ok(Response::new(ProviderResponse {
            provider: Some(provider),
            ..Default::default()
        }))
    }

    async fn list_providers(
        &self,
        _request: tonic::Request<ListProvidersRequest>,
    ) -> Result<Response<ListProvidersResponse>, Status> {
        let providers = self
            .state
            .providers
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        Ok(Response::new(ListProvidersResponse {
            providers,
            next_page_token: String::new(),
        }))
    }

    async fn list_provider_profiles(
        &self,
        _request: tonic::Request<ryno_core::proto::ListProviderProfilesRequest>,
    ) -> Result<Response<ryno_core::proto::ListProviderProfilesResponse>, Status> {
        let profiles = helpers::example_profiles()
            .iter()
            .map(ryno_providers::ProviderTypeProfile::to_proto)
            .collect();
        Ok(Response::new(
            ryno_core::proto::ListProviderProfilesResponse {
                profiles,
                next_page_token: String::new(),
            },
        ))
    }

    async fn get_provider_profile(
        &self,
        request: tonic::Request<ryno_core::proto::GetProviderProfileRequest>,
    ) -> Result<Response<ryno_core::proto::ProviderProfileResponse>, Status> {
        let id = request.into_inner().id;
        let profile = helpers::example_profiles()
            .iter()
            .find(|profile| profile.id == id)
            .ok_or_else(|| Status::not_found("provider profile not found"))?
            .to_proto();
        Ok(Response::new(ryno_core::proto::ProviderProfileResponse {
            profile: Some(profile),
        }))
    }

    async fn import_provider_profiles(
        &self,
        _request: tonic::Request<ryno_core::proto::ImportProviderProfilesRequest>,
    ) -> Result<Response<ryno_core::proto::ImportProviderProfilesResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn update_provider_profiles(
        &self,
        _request: tonic::Request<ryno_core::proto::UpdateProviderProfilesRequest>,
    ) -> Result<Response<ryno_core::proto::UpdateProviderProfilesResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn lint_provider_profiles(
        &self,
        _request: tonic::Request<ryno_core::proto::LintProviderProfilesRequest>,
    ) -> Result<Response<ryno_core::proto::LintProviderProfilesResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn delete_provider_profile(
        &self,
        _request: tonic::Request<ryno_core::proto::DeleteProviderProfileRequest>,
    ) -> Result<Response<ryno_core::proto::DeleteProviderProfileResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn update_provider(
        &self,
        request: tonic::Request<UpdateProviderRequest>,
    ) -> Result<Response<ProviderResponse>, Status> {
        let provider = request
            .into_inner()
            .provider
            .ok_or_else(|| Status::invalid_argument("provider is required"))?;

        let mut providers = self.state.providers.lock().await;
        let existing = providers
            .get(provider.object_name())
            .cloned()
            .ok_or_else(|| Status::not_found("provider not found"))?;
        // Merge semantics: empty map = no change, empty value = delete key.
        let merge = |mut base: HashMap<String, String>,
                     incoming: HashMap<String, String>|
         -> HashMap<String, String> {
            if incoming.is_empty() {
                return base;
            }
            for (k, v) in incoming {
                if v.is_empty() {
                    base.remove(&k);
                } else {
                    base.insert(k, v);
                }
            }
            base
        };
        let merge_expiry =
            |mut base: HashMap<String, prost_types::Timestamp>,
             incoming: HashMap<String, prost_types::Timestamp>| {
                if incoming.is_empty() {
                    return base;
                }
                base.extend(incoming);
                base
            };
        let existing_metadata = existing.metadata.clone().unwrap_or_default();
        let provider_metadata = provider.metadata.clone().unwrap_or_default();
        let updated = Provider {
            metadata: Some(ryno_core::proto::datamodel::v1::ObjectMeta {
                id: existing_metadata.id,
                name: provider_metadata.name,
                created_time: existing_metadata.created_time,
                labels: existing_metadata.labels,
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: String::new(),
                deletion_time: None,
            }),
            r#type: existing.r#type,
            credentials: merge(existing.credentials, provider.credentials),
            config: merge(existing.config, provider.config),
            credential_expiration_times: merge_expiry(
                existing.credential_expiration_times,
                provider.credential_expiration_times,
            ),
            profile_workspace: existing.profile_workspace,
            credential_handles: if provider.credential_handles.is_empty() {
                existing.credential_handles
            } else {
                provider.credential_handles
            },
        };
        let updated_name = updated.object_name().to_string();
        providers.insert(updated_name, updated.clone());
        Ok(Response::new(ProviderResponse {
            provider: Some(updated),
            ..Default::default()
        }))
    }
    async fn get_provider_refresh_status(
        &self,
        _: tonic::Request<ryno_core::proto::GetProviderRefreshStatusRequest>,
    ) -> Result<Response<ryno_core::proto::GetProviderRefreshStatusResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn configure_provider_refresh(
        &self,
        _: tonic::Request<ryno_core::proto::ConfigureProviderRefreshRequest>,
    ) -> Result<Response<ryno_core::proto::ConfigureProviderRefreshResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn rotate_provider_credential(
        &self,
        _: tonic::Request<ryno_core::proto::RotateProviderCredentialRequest>,
    ) -> Result<Response<ryno_core::proto::RotateProviderCredentialResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn delete_provider_refresh(
        &self,
        _: tonic::Request<ryno_core::proto::DeleteProviderRefreshRequest>,
    ) -> Result<Response<ryno_core::proto::DeleteProviderRefreshResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn delete_provider(
        &self,
        request: tonic::Request<DeleteProviderRequest>,
    ) -> Result<Response<DeleteProviderResponse>, Status> {
        let name = request.into_inner().name;
        let deleted = self.state.providers.lock().await.remove(&name).is_some();
        Ok(Response::new(DeleteProviderResponse {
            outcome: if deleted {
                ryno_core::proto::DeletionOutcome::Completed.into()
            } else {
                ryno_core::proto::DeletionOutcome::AlreadyAbsent.into()
            },
        }))
    }

    type WatchSandboxStream =
        tokio_stream::wrappers::ReceiverStream<Result<SandboxStreamEvent, Status>>;
    type ExecSandboxStream =
        tokio_stream::wrappers::ReceiverStream<Result<ExecSandboxEvent, Status>>;
    type ConnectSupervisorStream =
        tokio_stream::wrappers::ReceiverStream<Result<GatewayMessage, Status>>;

    async fn watch_sandbox(
        &self,
        _request: tonic::Request<WatchSandboxRequest>,
    ) -> Result<Response<Self::WatchSandboxStream>, Status> {
        let (_tx, rx) = mpsc::channel(1);
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    async fn exec_sandbox(
        &self,
        _request: tonic::Request<ExecSandboxRequest>,
    ) -> Result<Response<Self::ExecSandboxStream>, Status> {
        let (_tx, rx) = mpsc::channel(1);
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    type ExecSandboxInteractiveStream =
        tokio_stream::wrappers::ReceiverStream<Result<ExecSandboxEvent, Status>>;
    async fn exec_sandbox_interactive(
        &self,
        _request: tonic::Request<tonic::Streaming<ExecSandboxInput>>,
    ) -> Result<Response<Self::ExecSandboxInteractiveStream>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn update_config(
        &self,
        _request: tonic::Request<ryno_core::proto::UpdateConfigRequest>,
    ) -> Result<Response<ryno_core::proto::UpdateConfigResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn get_sandbox_policy_status(
        &self,
        _request: tonic::Request<ryno_core::proto::GetSandboxPolicyStatusRequest>,
    ) -> Result<Response<ryno_core::proto::GetSandboxPolicyStatusResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn list_sandbox_policies(
        &self,
        _request: tonic::Request<ryno_core::proto::ListSandboxPoliciesRequest>,
    ) -> Result<Response<ryno_core::proto::ListSandboxPoliciesResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn report_sandbox_configuration(
        &self,
        _request: tonic::Request<ryno_core::proto::ReportSandboxConfigurationRequest>,
    ) -> Result<Response<ryno_core::proto::ReportSandboxConfigurationResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn report_policy_status(
        &self,
        _request: tonic::Request<ryno_core::proto::ReportPolicyStatusRequest>,
    ) -> Result<Response<ryno_core::proto::ReportPolicyStatusResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn get_sandbox_logs(
        &self,
        _request: tonic::Request<ryno_core::proto::GetSandboxLogsRequest>,
    ) -> Result<Response<ryno_core::proto::GetSandboxLogsResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn push_sandbox_logs(
        &self,
        _request: tonic::Request<tonic::Streaming<ryno_core::proto::PushSandboxLogsRequest>>,
    ) -> Result<Response<ryno_core::proto::PushSandboxLogsResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn submit_policy_analysis(
        &self,
        _request: tonic::Request<ryno_core::proto::SubmitPolicyAnalysisRequest>,
    ) -> Result<Response<ryno_core::proto::SubmitPolicyAnalysisResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn get_draft_policy(
        &self,
        _request: tonic::Request<ryno_core::proto::GetDraftPolicyRequest>,
    ) -> Result<Response<ryno_core::proto::GetDraftPolicyResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn approve_draft_chunk(
        &self,
        _request: tonic::Request<ryno_core::proto::ApproveDraftChunkRequest>,
    ) -> Result<Response<ryno_core::proto::ApproveDraftChunkResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn reject_draft_chunk(
        &self,
        _request: tonic::Request<ryno_core::proto::RejectDraftChunkRequest>,
    ) -> Result<Response<ryno_core::proto::RejectDraftChunkResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn approve_all_draft_chunks(
        &self,
        _request: tonic::Request<ryno_core::proto::ApproveAllDraftChunksRequest>,
    ) -> Result<Response<ryno_core::proto::ApproveAllDraftChunksResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn edit_draft_chunk(
        &self,
        _request: tonic::Request<ryno_core::proto::EditDraftChunkRequest>,
    ) -> Result<Response<ryno_core::proto::EditDraftChunkResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn undo_draft_chunk(
        &self,
        _request: tonic::Request<ryno_core::proto::UndoDraftChunkRequest>,
    ) -> Result<Response<ryno_core::proto::UndoDraftChunkResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn clear_draft_chunks(
        &self,
        _request: tonic::Request<ryno_core::proto::ClearDraftChunksRequest>,
    ) -> Result<Response<ryno_core::proto::ClearDraftChunksResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn get_draft_history(
        &self,
        _request: tonic::Request<ryno_core::proto::GetDraftHistoryRequest>,
    ) -> Result<Response<ryno_core::proto::GetDraftHistoryResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn issue_sandbox_token(
        &self,
        _request: tonic::Request<ryno_core::proto::IssueSandboxTokenRequest>,
    ) -> Result<Response<ryno_core::proto::IssueSandboxTokenResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn refresh_sandbox_token(
        &self,
        _request: tonic::Request<ryno_core::proto::RefreshSandboxTokenRequest>,
    ) -> Result<Response<ryno_core::proto::RefreshSandboxTokenResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn connect_supervisor(
        &self,
        _request: tonic::Request<tonic::Streaming<SupervisorMessage>>,
    ) -> Result<Response<Self::ConnectSupervisorStream>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    type RelayStreamStream =
        tokio_stream::wrappers::ReceiverStream<Result<ryno_core::proto::RelayFrame, Status>>;

    async fn relay_stream(
        &self,
        _request: tonic::Request<tonic::Streaming<ryno_core::proto::RelayFrame>>,
    ) -> Result<Response<Self::RelayStreamStream>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    type PeerRelayStream =
        tokio_stream::wrappers::ReceiverStream<Result<ryno_core::proto::PeerRelayFrame, Status>>;

    async fn peer_relay(
        &self,
        _request: tonic::Request<tonic::Streaming<ryno_core::proto::PeerRelayFrame>>,
    ) -> Result<Response<Self::PeerRelayStream>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    type ForwardTcpStream =
        tokio_stream::wrappers::ReceiverStream<Result<ryno_core::proto::TcpForwardFrame, Status>>;

    async fn forward_tcp(
        &self,
        _request: tonic::Request<tonic::Streaming<ryno_core::proto::TcpForwardFrame>>,
    ) -> Result<Response<Self::ForwardTcpStream>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn create_workspace(
        &self,
        _request: tonic::Request<ryno_core::proto::CreateWorkspaceRequest>,
    ) -> Result<Response<ryno_core::proto::CreateWorkspaceResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn get_workspace(
        &self,
        _request: tonic::Request<ryno_core::proto::GetWorkspaceRequest>,
    ) -> Result<Response<ryno_core::proto::GetWorkspaceResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn list_workspaces(
        &self,
        _request: tonic::Request<ryno_core::proto::ListWorkspacesRequest>,
    ) -> Result<Response<ryno_core::proto::ListWorkspacesResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn delete_workspace(
        &self,
        _request: tonic::Request<ryno_core::proto::DeleteWorkspaceRequest>,
    ) -> Result<Response<ryno_core::proto::DeleteWorkspaceResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn add_workspace_member(
        &self,
        _request: tonic::Request<ryno_core::proto::AddWorkspaceMemberRequest>,
    ) -> Result<Response<ryno_core::proto::AddWorkspaceMemberResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn remove_workspace_member(
        &self,
        _request: tonic::Request<ryno_core::proto::RemoveWorkspaceMemberRequest>,
    ) -> Result<Response<ryno_core::proto::RemoveWorkspaceMemberResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn list_workspace_members(
        &self,
        _request: tonic::Request<ryno_core::proto::ListWorkspaceMembersRequest>,
    ) -> Result<Response<ryno_core::proto::ListWorkspaceMembersResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }
}

// ── test server fixture ──────────────────────────────────────────────

struct TestServer {
    endpoint: String,
    tls: TlsOptions,
    ryno: TestRyno,
    _dir: TempDir,
}

async fn run_server() -> TestServer {
    let (ca, ca_key) = build_ca();
    let (server_cert, server_key) = build_server_cert(&ca, &ca_key);
    let (client_cert, client_key) = build_client_cert(&ca, &ca_key);
    let ca_cert = ca.pem();

    let identity = Identity::from_pem(server_cert, server_key);
    let client_ca = TlsCertificate::from_pem(ca_cert.clone());
    let tls_config = ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(client_ca);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = TcpListenerStream::new(listener);

    let ryno = TestRyno::default();
    let svc_ryno = ryno.clone();

    tokio::spawn(async move {
        Server::builder()
            .tls_config(tls_config)
            .unwrap()
            .add_service(RynoServer::new(svc_ryno))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("ca.crt");
    let cert_path = dir.path().join("tls.crt");
    let key_path = dir.path().join("tls.key");
    std::fs::write(&ca_path, ca_cert).unwrap();
    std::fs::write(&cert_path, client_cert).unwrap();
    std::fs::write(&key_path, client_key).unwrap();

    let tls = TlsOptions::new(Some(ca_path), Some(cert_path), Some(key_path));
    let endpoint = format!("https://localhost:{}", addr.port());

    TestServer {
        endpoint,
        tls,
        ryno,
        _dir: dir,
    }
}

// ── tests ────────────────────────────────────────────────────────────

/// When `--provider nvidia` is passed and a provider named "nvidia" already
/// exists, `ensure_required_providers` should return it directly without
/// creating anything new.
#[tokio::test]
async fn explicit_provider_name_passes_through_when_it_exists() {
    let ts = run_server().await;
    ts.ryno.seed_provider("nvidia", "nvidia").await;

    let mut client = ryno_cli::tls::grpc_client(&ts.endpoint, &ts.tls)
        .await
        .expect("grpc client");

    let result = run::ensure_required_providers(
        &mut client,
        &["nvidia".to_string()],
        Some(true), // --auto-providers (should not matter here)
        "default",
    )
    .await
    .expect("should succeed");

    assert_eq!(result, vec!["nvidia".to_string()]);

    // Verify no extra providers were created.
    let providers = ts.ryno.state.providers.lock().await;
    assert_eq!(providers.len(), 1, "no new providers should be created");
}

/// When `--provider nvidia` is passed, no provider named "nvidia" exists, and
/// "nvidia" is a valid provider type, the CLI should auto-create a provider
/// named "nvidia" of type "nvidia" using discovered local credentials.
#[tokio::test]
async fn explicit_provider_name_auto_creates_when_valid_type() {
    let ts = run_server().await;
    let _guard = EnvVarGuard::set(&[("NVIDIA_API_KEY", "nvapi-test-key")]);

    let mut client = ryno_cli::tls::grpc_client(&ts.endpoint, &ts.tls)
        .await
        .expect("grpc client");

    let result = run::ensure_required_providers(
        &mut client,
        &["nvidia".to_string()],
        Some(true), // --auto-providers to skip interactive prompt
        "default",
    )
    .await
    .expect("should auto-create the provider");

    assert_eq!(result, vec!["nvidia".to_string()]);

    // Verify the provider was created on the server with the right type.
    let providers = ts.ryno.state.providers.lock().await;
    let provider = providers
        .get("nvidia")
        .expect("nvidia provider should exist");
    assert_eq!(provider.r#type, "nvidia");
    assert_eq!(
        provider.credentials.get("NVIDIA_API_KEY"),
        Some(&"nvapi-test-key".to_string()),
    );
}

/// When `--provider my-custom-thing` is passed and "my-custom-thing" is not a
/// known provider type, the CLI should return an error.
#[tokio::test]
async fn explicit_provider_name_errors_for_unrecognised_name() {
    let ts = run_server().await;

    let mut client = ryno_cli::tls::grpc_client(&ts.endpoint, &ts.tls)
        .await
        .expect("grpc client");

    let err = run::ensure_required_providers(
        &mut client,
        &["my-custom-thing".to_string()],
        Some(true),
        "default",
    )
    .await
    .expect_err("should fail for unrecognised provider name");

    let msg = err.to_string();
    assert!(
        msg.contains("my-custom-thing"),
        "error should mention the name: {msg}"
    );
    assert!(
        msg.contains("no provider profile"),
        "error should explain why it failed: {msg}"
    );
}

/// When `--no-auto-providers` is set, missing explicit providers that would
/// otherwise be auto-created should be silently skipped.
#[tokio::test]
async fn no_auto_providers_skips_missing_explicit_provider() {
    let ts = run_server().await;
    let _guard = EnvVarGuard::set(&[("NVIDIA_API_KEY", "nvapi-skip-test")]);

    let mut client = ryno_cli::tls::grpc_client(&ts.endpoint, &ts.tls)
        .await
        .expect("grpc client");

    let result = run::ensure_required_providers(
        &mut client,
        &["nvidia".to_string()],
        Some(false), // --no-auto-providers
        "default",
    )
    .await
    .expect("should succeed with empty list");

    assert!(
        result.is_empty(),
        "skipped providers should not appear in the result"
    );

    let providers = ts.ryno.state.providers.lock().await;
    assert!(
        providers.is_empty(),
        "no providers should be created when --no-auto-providers is set"
    );
}

/// Several explicit providers are all resolved and created.
#[tokio::test]
async fn multiple_explicit_providers_combined() {
    let ts = run_server().await;
    let _guard = EnvVarGuard::set(&[
        ("NVIDIA_API_KEY", "nvapi-combo"),
        ("ANTHROPIC_API_KEY", "sk-ant-combo"),
    ]);

    let mut client = ryno_cli::tls::grpc_client(&ts.endpoint, &ts.tls)
        .await
        .expect("grpc client");

    let result = run::ensure_required_providers(
        &mut client,
        &["nvidia".to_string(), "claude-code".to_string()],
        Some(true),
        "default",
    )
    .await
    .expect("should create both providers");

    assert_eq!(result.len(), 2);
    assert!(result.contains(&"nvidia".to_string()));
    assert!(result.contains(&"claude-code".to_string()));

    let providers = ts.ryno.state.providers.lock().await;
    assert_eq!(providers.len(), 2);
    assert!(providers.contains_key("nvidia"));
    assert!(providers.contains_key("claude-code"));
}

/// A provider named twice appears only once in the result.
#[tokio::test]
async fn repeated_explicit_provider_deduplicates() {
    let ts = run_server().await;
    let _guard = EnvVarGuard::set(&[("NVIDIA_API_KEY", "nvapi-dedup")]);

    let mut client = ryno_cli::tls::grpc_client(&ts.endpoint, &ts.tls)
        .await
        .expect("grpc client");

    let result = run::ensure_required_providers(
        &mut client,
        &["nvidia".to_string(), "nvidia".to_string()],
        Some(true),
        "default",
    )
    .await
    .expect("should succeed");

    assert_eq!(
        result,
        vec!["nvidia".to_string()],
        "nvidia should appear exactly once"
    );

    let providers = ts.ryno.state.providers.lock().await;
    assert_eq!(
        providers.len(),
        1,
        "only one provider should be created on the server"
    );
}
