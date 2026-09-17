// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

mod helpers;

use helpers::{EnvVarGuard, build_ca, build_client_cert, build_server_cert};
use openshell_cli::run;
use openshell_cli::tls::TlsOptions;
use openshell_core::proto::open_shell_server::{OpenShell, OpenShellServer};
use openshell_core::proto::{
    AttachSandboxProviderRequest, AttachSandboxProviderResponse, CreateProviderRequest,
    CreateSandboxRequest, CreateSshSessionRequest, CreateSshSessionResponse,
    DeleteProviderRefreshRequest, DeleteProviderRefreshResponse, DeleteProviderRequest,
    DeleteProviderResponse, DeleteSandboxRequest, DeleteSandboxResponse,
    DetachSandboxProviderRequest, DetachSandboxProviderResponse,
    ExchangeProviderSubjectTokenRequest, ExchangeProviderSubjectTokenResponse, ExecSandboxEvent,
    ExecSandboxInput, ExecSandboxRequest, GatewayMessage, GetGatewayConfigRequest,
    GetGatewayConfigResponse, GetProviderRefreshStatusRequest, GetProviderRefreshStatusResponse,
    GetProviderRequest, GetSandboxConfigRequest, GetSandboxConfigResponse,
    GetSandboxProviderEnvironmentRequest, GetSandboxProviderEnvironmentResponse,
    GetSandboxProviderStatusRequest, GetSandboxProviderStatusResponse, GetSandboxRequest,
    HealthRequest, HealthResponse, ListProvidersRequest, ListProvidersResponse,
    ListSandboxProvidersRequest, ListSandboxProvidersResponse, ListSandboxesRequest,
    ListSandboxesResponse, Provider, ProviderCredentialRefresh, ProviderCredentialRefreshStatus,
    ProviderCredentialRefreshStrategy, ProviderCredentialTokenGrant,
    ProviderCredentialTokenGrantSubjectToken, ProviderCredentialTokenGrantType,
    ProviderDesiredIdentity, ProviderMutationKind, ProviderMutationReceipt, ProviderProfile,
    ProviderProfileCredential, ProviderProfileDiscovery, ProviderReadinessObservation,
    ProviderReadinessReason, ProviderReadinessState, ProviderReadinessStatus, ProviderResponse,
    RevokeSshSessionRequest, RevokeSshSessionResponse, RotateProviderCredentialRequest,
    RotateProviderCredentialResponse, Sandbox, SandboxResponse, SandboxStreamEvent, ServiceStatus,
    SettingValue, SupervisorMessage, UpdateProviderRequest, WatchSandboxRequest,
};
use openshell_core::rpc_error::{ERROR_DOMAIN, ErrorDetails, StatusExt};
use openshell_core::{ObjectId, ObjectName};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, mpsc};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Certificate as TlsCertificate, Identity, Server, ServerTlsConfig};
use tonic::{Code, Response, Status};

type ReadinessScript = HashMap<String, VecDeque<ReadinessReply>>;
type ReceiptCorruption = fn(&mut ProviderMutationReceipt);

#[derive(Clone)]
enum ReadinessReply {
    Status(Box<ProviderReadinessStatus>),
    DelayedStatus(Duration, Box<ProviderReadinessStatus>),
    Error(Code),
    Hung,
}

const READINESS_PROVIDER: &str = "readiness-provider";
const SYNTHETIC_READINESS_CREDENTIAL: &str = "fixture-provider-credential";
const SYNTHETIC_READINESS_BACKEND_ERROR: &str = "fixture-backend-authorization-details";
const SYNTHETIC_PROFILE_BACKEND_ERROR: &str = "TESTLEAK";
const SYNTHETIC_MUTATION_ERROR_METADATA: &str = "fixture-mutation-error-metadata";
const STORAGE_UNCERTAIN_REASON: &str = "CONFIG_OPERATION_STORAGE_UNCERTAIN";

fn selected_workspace(scope: &Option<openshell_core::proto::WorkspaceSelector>) -> Option<&str> {
    scope
        .as_ref()
        .and_then(|scope| match scope.selection.as_ref() {
            Some(openshell_core::proto::workspace_selector::Selection::Workspace(name)) => {
                Some(name.as_str())
            }
            _ => None,
        })
}

#[derive(Clone, Default)]
struct ProviderState {
    providers: Arc<Mutex<HashMap<String, Provider>>>,
    profiles: Arc<Mutex<HashMap<String, ProviderProfile>>>,
    scoped_profiles: Arc<Mutex<HashMap<(String, String), ProviderProfile>>>,
    refresh_statuses: Arc<Mutex<HashMap<(String, String), ProviderCredentialRefreshStatus>>>,
    refresh_requests: Arc<Mutex<Vec<ProviderRefreshRequestLog>>>,
    provider_create_requests: Arc<AtomicU64>,
    provider_update_requests: Arc<Mutex<Vec<Provider>>>,
    deny_provider_reads: Arc<AtomicBool>,
    fail_provider_reads: Arc<AtomicBool>,
    fail_sandbox_reads: Arc<AtomicBool>,
    profile_read_errors: Arc<Mutex<HashMap<String, Code>>>,
    profile_read_requests: Arc<Mutex<Vec<String>>>,
    delete_provider_requests: Arc<Mutex<Vec<String>>>,
    delete_provider_profile_requests: Arc<Mutex<Vec<String>>>,
    fail_configure_refresh_message: Arc<Mutex<Option<String>>>,
    fail_rotate_refresh_message: Arc<Mutex<Option<String>>>,
    fail_delete_provider_message: Arc<Mutex<Option<String>>>,
    fail_delete_provider_profile_message: Arc<Mutex<Option<String>>>,
    sandbox_providers: Arc<Mutex<HashMap<String, Vec<String>>>>,
    sandbox_provider_requests: Arc<Mutex<Vec<SandboxProviderRequestLog>>>,
    readiness_receipts: Arc<Mutex<HashMap<String, ProviderMutationReceipt>>>,
    readiness_scripts: Arc<Mutex<ReadinessScript>>,
    readiness_requests: Arc<Mutex<Vec<GetSandboxProviderStatusRequest>>>,
    readiness_sequence: Arc<AtomicU64>,
    corrupt_mutation_receipt: Arc<Mutex<Option<ReceiptCorruption>>>,
    fail_mutation_after_save: Arc<Mutex<Option<Status>>>,
    global_settings: Arc<Mutex<HashMap<String, SettingValue>>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ProviderRefreshRequestLog {
    Status {
        provider: String,
        credential_key: String,
    },
    Configure {
        provider: String,
        credential_key: String,
        material: HashMap<String, String>,
        secret_material_keys: Vec<String>,
        expires_at_ms: Option<i64>,
    },
    Rotate {
        provider: String,
        credential_key: String,
    },
    Delete {
        provider: String,
        credential_key: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SandboxProviderRequestLog {
    List {
        sandbox_name: String,
    },
    Attach {
        sandbox_name: String,
        provider: String,
    },
    Detach {
        sandbox_name: String,
        provider: String,
    },
}

#[derive(Clone, Default)]
struct TestOpenShell {
    state: ProviderState,
}

impl TestOpenShell {
    // A durable mutation can fail before its receipt is stored. Keep the failure
    // active for every call so a client replay remains visible in request logs.
    async fn check_mutation_receipt_storage(&self) -> Result<(), Status> {
        let failure = self.state.fail_mutation_after_save.lock().await.clone();
        failure.map_or(Ok(()), Err)
    }

    async fn provider_receipt(
        &self,
        sandbox_name: &str,
        provider_name: &str,
        workspace: &str,
        kind: ProviderMutationKind,
        mutation_id: Option<&str>,
    ) -> ProviderMutationReceipt {
        let sequence = self.state.readiness_sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let provider = self
            .state
            .providers
            .lock()
            .await
            .get(provider_name)
            .cloned();
        let detached = kind == ProviderMutationKind::Detach;
        let mut receipt = ProviderMutationReceipt {
            receipt_id: format!("receipt-{sequence}"),
            mutation_id: mutation_id.map_or_else(|| format!("mutation-{sequence}"), str::to_string),
            provider: provider_name.to_string(),
            workspace: workspace.to_string(),
            kind: kind.into(),
            desired: Some(ProviderDesiredIdentity {
                sandbox_id: format!("sb-{sandbox_name}"),
                sandbox: sandbox_name.to_string(),
                attachment_epoch: format!("attachment-{sandbox_name}"),
                provider_id: if detached {
                    String::new()
                } else {
                    provider
                        .as_ref()
                        .map_or_else(String::new, |provider| provider.object_id().to_string())
                },
                provider_resource_version: if detached {
                    0
                } else {
                    provider
                        .as_ref()
                        .and_then(|provider| provider.metadata.as_ref())
                        .map_or(0, |metadata| metadata.resource_version)
                },
                provider_env_revision: sequence,
                config_revision: 17,
                policy_hash: "effective-policy".to_string(),
            }),
            persisted_time: Some(
                openshell_core::time::timestamp_from_millis(i64::try_from(sequence).unwrap())
                    .unwrap(),
            ),
        };
        let corrupt = *self.state.corrupt_mutation_receipt.lock().await;
        if let Some(corrupt) = corrupt {
            corrupt(&mut receipt);
        }
        self.state
            .readiness_receipts
            .lock()
            .await
            .insert(receipt.receipt_id.clone(), receipt.clone());
        receipt
    }
}

#[tonic::async_trait]
impl OpenShell for TestOpenShell {
    async fn report_endpoint_status(
        &self,
        _request: tonic::Request<openshell_core::proto::ReportEndpointStatusRequest>,
    ) -> Result<Response<openshell_core::proto::ReportEndpointStatusResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::ReportEndpointStatusResponse {},
        ))
    }

    async fn begin_rootfs_tar_staging(
        &self,
        _request: tonic::Request<openshell_core::proto::BeginRootfsTarStagingRequest>,
    ) -> Result<Response<openshell_core::proto::BeginRootfsTarStagingResponse>, Status> {
        Err(Status::unimplemented("not used by this test server"))
    }

    async fn report_main_process_exit(
        &self,
        _request: tonic::Request<openshell_core::proto::ReportMainProcessExitRequest>,
    ) -> Result<Response<openshell_core::proto::ReportMainProcessExitResponse>, Status> {
        Err(Status::unimplemented("not used by this test server"))
    }

    async fn finalize_main_process_exit(
        &self,
        _request: tonic::Request<openshell_core::proto::FinalizeMainProcessExitRequest>,
    ) -> Result<Response<openshell_core::proto::FinalizeMainProcessExitResponse>, Status> {
        Err(Status::unimplemented("not used by this test server"))
    }

    async fn get_current_user(
        &self,
        _request: tonic::Request<openshell_core::proto::GetCurrentUserRequest>,
    ) -> Result<Response<openshell_core::proto::GetCurrentUserResponse>, Status> {
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
        _request: tonic::Request<openshell_core::proto::GetGatewayInfoRequest>,
    ) -> Result<Response<openshell_core::proto::GetGatewayInfoResponse>, Status> {
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
        _request: tonic::Request<openshell_core::proto::StopSandboxRequest>,
    ) -> Result<Response<SandboxResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn start_sandbox(
        &self,
        _request: tonic::Request<openshell_core::proto::StartSandboxRequest>,
    ) -> Result<Response<SandboxResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn get_sandbox(
        &self,
        request: tonic::Request<GetSandboxRequest>,
    ) -> Result<Response<SandboxResponse>, Status> {
        if self.state.fail_sandbox_reads.load(Ordering::SeqCst) {
            return Err(Status::internal(SYNTHETIC_READINESS_BACKEND_ERROR));
        }
        let request = request.into_inner();
        let name = request.name;
        // Return a minimal sandbox with metadata for CAS operations
        Ok(Response::new(SandboxResponse {
            sandbox: Some(Sandbox {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: format!("sb-{name}"),
                    name,
                    created_time: None,
                    labels: HashMap::new(),
                    resource_version: 1,
                    annotations: HashMap::new(),
                    workspace: String::new(),
                    deletion_time: None,
                }),
                spec: None,
                status: None,
                ..Sandbox::default()
            }),
            service_urls: HashMap::new(),
        }))
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
        request: tonic::Request<ListSandboxProvidersRequest>,
    ) -> Result<Response<ListSandboxProvidersResponse>, Status> {
        let request = request.into_inner();
        let sandbox_name = request.sandbox.clone();
        self.state
            .sandbox_provider_requests
            .lock()
            .await
            .push(SandboxProviderRequestLog::List {
                sandbox_name: sandbox_name.clone(),
            });
        let provider_names = self
            .state
            .sandbox_providers
            .lock()
            .await
            .get(&sandbox_name)
            .cloned()
            .unwrap_or_default();
        let providers_by_name = self.state.providers.lock().await;
        let providers = provider_names
            .iter()
            .filter_map(|name| providers_by_name.get(name).cloned())
            .collect();
        Ok(Response::new(ListSandboxProvidersResponse { providers }))
    }

    async fn attach_sandbox_provider(
        &self,
        request: tonic::Request<AttachSandboxProviderRequest>,
    ) -> Result<Response<AttachSandboxProviderResponse>, Status> {
        let request = request.into_inner();
        let workspace = selected_workspace(&request.workspace_scope).unwrap_or_default();
        let sandbox_name = request.sandbox.clone();
        self.state
            .sandbox_provider_requests
            .lock()
            .await
            .push(SandboxProviderRequestLog::Attach {
                sandbox_name: sandbox_name.clone(),
                provider: request.provider.clone(),
            });
        if !self
            .state
            .providers
            .lock()
            .await
            .contains_key(&request.provider)
        {
            return Err(Status::failed_precondition("provider not found"));
        }
        let mut sandbox_providers = self.state.sandbox_providers.lock().await;
        let providers = sandbox_providers.entry(sandbox_name.clone()).or_default();
        let attached = if providers.contains(&request.provider) {
            false
        } else {
            providers.push(request.provider.clone());
            true
        };
        let provider_names = providers.clone();
        drop(sandbox_providers);
        self.check_mutation_receipt_storage().await?;
        let receipt = self
            .provider_receipt(
                &sandbox_name,
                &request.provider,
                workspace,
                ProviderMutationKind::Attach,
                None,
            )
            .await;
        let sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                name: sandbox_name,
                ..Default::default()
            }),
            spec: Some(openshell_core::proto::SandboxSpec {
                providers: provider_names,
                ..Default::default()
            }),
            ..Default::default()
        };
        Ok(Response::new(AttachSandboxProviderResponse {
            sandbox: Some(sandbox),
            attached,
            receipt: Some(receipt),
        }))
    }

    async fn detach_sandbox_provider(
        &self,
        request: tonic::Request<DetachSandboxProviderRequest>,
    ) -> Result<Response<DetachSandboxProviderResponse>, Status> {
        let request = request.into_inner();
        let workspace = selected_workspace(&request.workspace_scope).unwrap_or_default();
        let sandbox_name = request.sandbox.clone();
        self.state
            .sandbox_provider_requests
            .lock()
            .await
            .push(SandboxProviderRequestLog::Detach {
                sandbox_name: sandbox_name.clone(),
                provider: request.provider.clone(),
            });
        let mut sandbox_providers = self.state.sandbox_providers.lock().await;
        let providers = sandbox_providers.entry(sandbox_name.clone()).or_default();
        let before_len = providers.len();
        providers.retain(|name| name != &request.provider);
        let detached = providers.len() != before_len;
        let provider_names = providers.clone();
        drop(sandbox_providers);
        self.check_mutation_receipt_storage().await?;
        let receipt = self
            .provider_receipt(
                &sandbox_name,
                &request.provider,
                workspace,
                ProviderMutationKind::Detach,
                None,
            )
            .await;
        let sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                name: sandbox_name,
                ..Default::default()
            }),
            spec: Some(openshell_core::proto::SandboxSpec {
                providers: provider_names,
                ..Default::default()
            }),
            ..Default::default()
        };
        Ok(Response::new(DetachSandboxProviderResponse {
            sandbox: Some(sandbox),
            detached,
            receipt: Some(receipt),
        }))
    }

    async fn delete_sandbox(
        &self,
        _request: tonic::Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
        Ok(Response::new(DeleteSandboxResponse {
            sandbox_id: String::new(),
            outcome: openshell_core::proto::DeletionOutcome::Completed.into(),
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
        Ok(Response::new(GetGatewayConfigResponse {
            settings: self.state.global_settings.lock().await.clone(),
            settings_revision: 1,
        }))
    }

    async fn get_sandbox_provider_environment(
        &self,
        _request: tonic::Request<GetSandboxProviderEnvironmentRequest>,
    ) -> Result<Response<GetSandboxProviderEnvironmentResponse>, Status> {
        Ok(Response::new(
            GetSandboxProviderEnvironmentResponse::default(),
        ))
    }

    async fn get_sandbox_provider_status(
        &self,
        request: tonic::Request<GetSandboxProviderStatusRequest>,
    ) -> Result<Response<GetSandboxProviderStatusResponse>, Status> {
        let request = request.into_inner();
        let workspace = selected_workspace(&request.workspace_scope).unwrap_or_default();
        self.state
            .readiness_requests
            .lock()
            .await
            .push(request.clone());
        let receipts = self.state.readiness_receipts.lock().await;
        let receipt = if request.receipt_id.is_empty() {
            receipts
                .values()
                .filter(|receipt| {
                    receipt.workspace == workspace
                        && receipt.provider == request.provider
                        && receipt
                            .desired
                            .as_ref()
                            .is_some_and(|desired| desired.sandbox == request.sandbox)
                })
                .max_by_key(|receipt| {
                    receipt
                        .persisted_time
                        .as_ref()
                        .map(|time| (time.seconds, time.nanos))
                })
        } else {
            receipts
                .get(&request.receipt_id)
                .filter(|receipt| receipt.workspace == workspace)
        }
        .cloned()
        .ok_or_else(|| Status::not_found("provider receipt not found"))?;
        drop(receipts);
        let scripted = self
            .state
            .readiness_scripts
            .lock()
            .await
            .get_mut(&request.sandbox)
            .and_then(|script| {
                if script.len() > 1 {
                    script.pop_front()
                } else {
                    script.front().cloned()
                }
            });
        let mut status = match scripted {
            Some(ReadinessReply::Status(status)) => *status,
            // The last scripted reply repeats its delay after cancellation,
            // matching a gateway whose status calls are consistently slow.
            Some(ReadinessReply::DelayedStatus(delay, status)) => {
                tokio::time::sleep(delay).await;
                *status
            }
            Some(ReadinessReply::Error(code)) => {
                return Err(Status::new(code, SYNTHETIC_READINESS_BACKEND_ERROR));
            }
            // No mock lock survives this await; the client deadline must cancel
            // the request while retaining its previously observed status.
            Some(ReadinessReply::Hung) => std::future::pending().await,
            None => ProviderReadinessStatus {
                state: ProviderReadinessState::Persisted.into(),
                reason: ProviderReadinessReason::WaitingForSupervisor.into(),
                ..Default::default()
            },
        };
        let response_receipt = status.receipt.get_or_insert(receipt);
        if let Some(observed) = status.observed.as_mut() {
            let desired = response_receipt.desired.as_ref().unwrap();
            observed
                .attachment_epoch
                .clone_from(&desired.attachment_epoch);
            observed.provider_env_revision = desired.provider_env_revision;
            observed.config_revision = desired.config_revision;
            observed.policy_hash.clone_from(&desired.policy_hash);
        }
        Ok(Response::new(GetSandboxProviderStatusResponse {
            status: Some(status),
        }))
    }

    async fn report_provider_readiness(
        &self,
        _request: tonic::Request<openshell_core::proto::ReportProviderReadinessRequest>,
    ) -> Result<Response<openshell_core::proto::ReportProviderReadinessResponse>, Status> {
        Err(Status::unimplemented(
            "provider installation reports are not exercised by this mock",
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
        _request: tonic::Request<openshell_core::proto::ExposeServiceRequest>,
    ) -> Result<Response<openshell_core::proto::ServiceEndpointResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::ServiceEndpointResponse::default(),
        ))
    }

    async fn get_service(
        &self,
        _: tonic::Request<openshell_core::proto::GetServiceRequest>,
    ) -> Result<Response<openshell_core::proto::ServiceEndpointResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn list_services(
        &self,
        _: tonic::Request<openshell_core::proto::ListServicesRequest>,
    ) -> Result<Response<openshell_core::proto::ListServicesResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn delete_service(
        &self,
        _: tonic::Request<openshell_core::proto::DeleteServiceRequest>,
    ) -> Result<Response<openshell_core::proto::DeleteServiceResponse>, Status> {
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
        self.state
            .provider_create_requests
            .fetch_add(1, Ordering::SeqCst);
        let mut provider = request
            .into_inner()
            .provider
            .ok_or_else(|| Status::invalid_argument("provider is required"))?;
        if provider.credentials.is_empty() && provider.credential_handles.is_empty() {
            let bootstrap_allowed = if let Some(profile) = helpers::example_profiles()
                .iter()
                .find(|p| p.id.eq_ignore_ascii_case(&provider.r#type))
            {
                profile.allows_empty_provider_credentials()
            } else {
                self.state
                    .profiles
                    .lock()
                    .await
                    .get(&provider.r#type)
                    .cloned()
                    .is_some_and(|profile| {
                        openshell_providers::ProviderTypeProfile::from_proto(&profile)
                            .allows_empty_provider_credentials()
                    })
            };
            if !bootstrap_allowed {
                return Err(Status::invalid_argument(
                    "provider.credentials must not be empty",
                ));
            }
        }
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
        if self.state.fail_provider_reads.load(Ordering::SeqCst) {
            return Err(Status::internal(SYNTHETIC_READINESS_BACKEND_ERROR));
        }
        if self.state.deny_provider_reads.load(Ordering::SeqCst) {
            return Err(Status::permission_denied("scope 'provider:read' required"));
        }
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
        _request: tonic::Request<openshell_core::proto::ListProviderProfilesRequest>,
    ) -> Result<Response<openshell_core::proto::ListProviderProfilesResponse>, Status> {
        let mut profiles = helpers::example_profiles()
            .iter()
            .map(openshell_providers::ProviderTypeProfile::to_proto)
            .collect::<Vec<_>>();
        profiles.extend(self.state.profiles.lock().await.values().cloned());
        Ok(Response::new(
            openshell_core::proto::ListProviderProfilesResponse {
                profiles,
                next_page_token: String::new(),
            },
        ))
    }

    async fn get_provider_profile(
        &self,
        request: tonic::Request<openshell_core::proto::GetProviderProfileRequest>,
    ) -> Result<Response<openshell_core::proto::ProviderProfileResponse>, Status> {
        let request = request.into_inner();
        let id = request.id;
        self.state
            .profile_read_requests
            .lock()
            .await
            .push(id.clone());
        let error_code = self
            .state
            .profile_read_errors
            .lock()
            .await
            .get(&id)
            .copied();
        if let Some(code) = error_code {
            return Err(Status::new(code, SYNTHETIC_PROFILE_BACKEND_ERROR));
        }
        let scoped_profile = self
            .state
            .scoped_profiles
            .lock()
            .await
            .get(&(
                selected_workspace(&request.workspace_scope)
                    .unwrap_or_default()
                    .to_string(),
                id.clone(),
            ))
            .cloned();
        let profile = if let Some(profile) = scoped_profile {
            profile
        } else if let Some(profile) = helpers::example_profiles()
            .iter()
            .find(|profile| profile.id == id)
        {
            profile.to_proto()
        } else {
            self.state
                .profiles
                .lock()
                .await
                .get(&id)
                .cloned()
                .ok_or_else(|| Status::not_found("provider profile not found"))?
        };
        Ok(Response::new(
            openshell_core::proto::ProviderProfileResponse {
                profile: Some(profile),
            },
        ))
    }

    async fn import_provider_profiles(
        &self,
        request: tonic::Request<openshell_core::proto::ImportProviderProfilesRequest>,
    ) -> Result<Response<openshell_core::proto::ImportProviderProfilesResponse>, Status> {
        let mut profiles = self.state.profiles.lock().await;
        let imported = request
            .into_inner()
            .profiles
            .into_iter()
            .filter_map(|item| item.profile)
            .map(|mut profile| {
                profile.resource_version = 1;
                profile
            })
            .inspect(|profile| {
                profiles.insert(profile.id.clone(), profile.clone());
            })
            .collect::<Vec<_>>();
        Ok(Response::new(
            openshell_core::proto::ImportProviderProfilesResponse {
                diagnostics: Vec::new(),
                profiles: imported,
                imported: true,
            },
        ))
    }

    async fn update_provider_profiles(
        &self,
        request: tonic::Request<openshell_core::proto::UpdateProviderProfilesRequest>,
    ) -> Result<Response<openshell_core::proto::UpdateProviderProfilesResponse>, Status> {
        let mut profiles = self.state.profiles.lock().await;
        let request = request.into_inner();
        let mut profile = request
            .profile
            .and_then(|item| item.profile)
            .ok_or_else(|| Status::invalid_argument("provider profile is required"))?;
        let target_id = request.id;
        if target_id != profile.id {
            return Ok(Response::new(
                openshell_core::proto::UpdateProviderProfilesResponse {
                    diagnostics: vec![openshell_core::proto::ProviderProfileDiagnostic {
                        source: target_id.clone(),
                        profile_id: profile.id.clone(),
                        field: "id".to_string(),
                        message: format!(
                            "provider profile update target '{}' does not match payload id '{}'",
                            target_id, profile.id
                        ),
                        severity: "error".to_string(),
                    }],
                    profile: None,
                    updated: false,
                },
            ));
        }
        let Some(current) = profiles.get(&target_id) else {
            return Ok(Response::new(
                openshell_core::proto::UpdateProviderProfilesResponse {
                    diagnostics: vec![openshell_core::proto::ProviderProfileDiagnostic {
                        source: target_id.clone(),
                        profile_id: target_id.clone(),
                        field: "id".to_string(),
                        message: format!("custom provider profile '{target_id}' does not exist"),
                        severity: "error".to_string(),
                    }],
                    profile: None,
                    updated: false,
                },
            ));
        };
        let expected_resource_version = if request.expected_resource_version != 0 {
            request.expected_resource_version
        } else {
            profile.resource_version
        };
        if expected_resource_version == 0 || expected_resource_version != current.resource_version {
            return Err(Status::aborted(format!(
                "provider profile was modified concurrently (current resource_version: {})",
                current.resource_version
            )));
        }
        profile.resource_version = current.resource_version + 1;
        profiles.insert(profile.id.clone(), profile.clone());
        Ok(Response::new(
            openshell_core::proto::UpdateProviderProfilesResponse {
                diagnostics: Vec::new(),
                profile: Some(profile),
                updated: true,
            },
        ))
    }

    async fn lint_provider_profiles(
        &self,
        _request: tonic::Request<openshell_core::proto::LintProviderProfilesRequest>,
    ) -> Result<Response<openshell_core::proto::LintProviderProfilesResponse>, Status> {
        Ok(Response::new(
            openshell_core::proto::LintProviderProfilesResponse {
                diagnostics: Vec::new(),
                valid: true,
            },
        ))
    }

    async fn update_provider(
        &self,
        request: tonic::Request<UpdateProviderRequest>,
    ) -> Result<Response<ProviderResponse>, Status> {
        let request = request.into_inner();
        let workspace = selected_workspace(&request.workspace_scope).unwrap_or_default();
        let provider = request
            .provider
            .ok_or_else(|| Status::invalid_argument("provider is required"))?;
        self.state
            .provider_update_requests
            .lock()
            .await
            .push(provider.clone());

        let mut targets = self
            .state
            .sandbox_providers
            .lock()
            .await
            .iter()
            .filter(|(_, attached)| attached.iter().any(|name| name == provider.object_name()))
            .map(|(sandbox_name, _)| sandbox_name.clone())
            .collect::<Vec<_>>();
        targets.sort();
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
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: existing_metadata.id,
                name: provider_metadata.name,
                created_time: existing_metadata.created_time,
                labels: existing_metadata.labels,
                resource_version: existing_metadata.resource_version + 1,
                annotations: HashMap::new(),
                workspace: workspace.to_string(),
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
        providers.insert(updated_name.clone(), updated.clone());
        drop(providers);
        self.check_mutation_receipt_storage().await?;
        let mutation_id = format!(
            "update-{}",
            self.state.readiness_sequence.fetch_add(1, Ordering::SeqCst) + 1
        );
        let mut target_receipts = Vec::with_capacity(targets.len());
        for sandbox_name in targets {
            target_receipts.push(
                self.provider_receipt(
                    &sandbox_name,
                    &updated_name,
                    workspace,
                    ProviderMutationKind::Update,
                    Some(&mutation_id),
                )
                .await,
            );
        }
        Ok(Response::new(ProviderResponse {
            provider: Some(updated),
            target_receipts,
            mutation_id,
        }))
    }
    async fn get_provider_refresh_status(
        &self,
        request: tonic::Request<GetProviderRefreshStatusRequest>,
    ) -> Result<Response<GetProviderRefreshStatusResponse>, Status> {
        let request = request.into_inner();
        self.state
            .refresh_requests
            .lock()
            .await
            .push(ProviderRefreshRequestLog::Status {
                provider: request.provider.clone(),
                credential_key: request.credential_key.clone(),
            });
        let refresh_statuses = self.state.refresh_statuses.lock().await;
        let credentials = if request.credential_key.is_empty() {
            refresh_statuses
                .values()
                .filter(|status| status.provider == request.provider)
                .cloned()
                .collect()
        } else {
            refresh_statuses
                .get(&(request.provider, request.credential_key))
                .cloned()
                .into_iter()
                .collect()
        };
        Ok(Response::new(GetProviderRefreshStatusResponse {
            credentials,
        }))
    }

    async fn configure_provider_refresh(
        &self,
        request: tonic::Request<openshell_core::proto::ConfigureProviderRefreshRequest>,
    ) -> Result<Response<openshell_core::proto::ConfigureProviderRefreshResponse>, Status> {
        let request = request.into_inner();
        self.state
            .refresh_requests
            .lock()
            .await
            .push(ProviderRefreshRequestLog::Configure {
                provider: request.provider.clone(),
                credential_key: request.credential_key.clone(),
                material: request.material.clone(),
                secret_material_keys: request.secret_material_keys.clone(),
                expires_at_ms: request
                    .expiration_time
                    .as_ref()
                    .and_then(|value| openshell_core::time::timestamp_to_millis(value).ok()),
            });
        let configure_failure = self
            .state
            .fail_configure_refresh_message
            .lock()
            .await
            .take();
        if let Some(message) = configure_failure {
            return Err(Status::internal(message));
        }
        let providers = self.state.providers.lock().await;
        let provider = providers
            .get(&request.provider)
            .ok_or_else(|| Status::not_found("provider not found"))?;
        let status = ProviderCredentialRefreshStatus {
            provider: request.provider.clone(),
            provider_id: provider.object_id().to_string(),
            credential_key: request.credential_key.clone(),
            strategy: request.strategy,
            status: "configured".to_string(),
            expiration_time: request.expiration_time,
            next_refresh_time: None,
            last_refresh_time: None,
            last_error: String::new(),
            recovery_action: 0,
            failure_code: String::new(),
            provider_error_subtype: String::new(),
            last_error_time: None,
        };
        drop(providers);
        self.state
            .refresh_statuses
            .lock()
            .await
            .insert((request.provider, request.credential_key), status.clone());
        Ok(Response::new(
            openshell_core::proto::ConfigureProviderRefreshResponse {
                status: Some(status),
            },
        ))
    }

    async fn rotate_provider_credential(
        &self,
        request: tonic::Request<RotateProviderCredentialRequest>,
    ) -> Result<Response<RotateProviderCredentialResponse>, Status> {
        let request = request.into_inner();
        let provider_name = request.provider.clone();
        let credential_key = request.credential_key.clone();
        self.state
            .refresh_requests
            .lock()
            .await
            .push(ProviderRefreshRequestLog::Rotate {
                provider: provider_name.clone(),
                credential_key: credential_key.clone(),
            });
        let rotate_failure = self.state.fail_rotate_refresh_message.lock().await.take();
        if let Some(message) = rotate_failure {
            return Err(Status::internal(message));
        }
        let mut refresh_statuses = self.state.refresh_statuses.lock().await;
        let status = refresh_statuses
            .get_mut(&(provider_name.clone(), credential_key.clone()))
            .ok_or_else(|| Status::not_found("provider refresh state not found"))?;
        status.status = "refreshed".to_string();
        status.last_refresh_time = openshell_core::time::timestamp_from_millis(1).ok();
        status.next_refresh_time = openshell_core::time::timestamp_from_millis(3_600_000).ok();
        status.expiration_time = openshell_core::time::timestamp_from_millis(3_600_000).ok();
        let status = status.clone();
        drop(refresh_statuses);
        let mut providers = self.state.providers.lock().await;
        let provider = providers
            .get_mut(&provider_name)
            .ok_or_else(|| Status::not_found("provider not found"))?;
        provider
            .credentials
            .insert(credential_key.clone(), format!("minted-{credential_key}"));
        provider.credential_expiration_times.insert(
            credential_key,
            openshell_core::time::timestamp_from_millis(3_600_000).unwrap(),
        );
        Ok(Response::new(RotateProviderCredentialResponse {
            status: Some(status),
        }))
    }

    async fn delete_provider_refresh(
        &self,
        request: tonic::Request<DeleteProviderRefreshRequest>,
    ) -> Result<Response<DeleteProviderRefreshResponse>, Status> {
        let request = request.into_inner();
        self.state
            .refresh_requests
            .lock()
            .await
            .push(ProviderRefreshRequestLog::Delete {
                provider: request.provider.clone(),
                credential_key: request.credential_key.clone(),
            });
        let deleted = self
            .state
            .refresh_statuses
            .lock()
            .await
            .remove(&(request.provider, request.credential_key))
            .is_some();
        Ok(Response::new(DeleteProviderRefreshResponse {
            outcome: if deleted {
                openshell_core::proto::DeletionOutcome::Completed.into()
            } else {
                openshell_core::proto::DeletionOutcome::AlreadyAbsent.into()
            },
        }))
    }

    async fn delete_provider(
        &self,
        request: tonic::Request<DeleteProviderRequest>,
    ) -> Result<Response<DeleteProviderResponse>, Status> {
        let name = request.into_inner().name;
        self.state
            .delete_provider_requests
            .lock()
            .await
            .push(name.clone());
        let delete_failure = self.state.fail_delete_provider_message.lock().await.take();
        if let Some(message) = delete_failure {
            return Err(Status::internal(message));
        }
        let deleted = self.state.providers.lock().await.remove(&name).is_some();
        Ok(Response::new(DeleteProviderResponse {
            outcome: if deleted {
                openshell_core::proto::DeletionOutcome::Completed.into()
            } else {
                openshell_core::proto::DeletionOutcome::AlreadyAbsent.into()
            },
        }))
    }

    async fn delete_provider_profile(
        &self,
        request: tonic::Request<openshell_core::proto::DeleteProviderProfileRequest>,
    ) -> Result<Response<openshell_core::proto::DeleteProviderProfileResponse>, Status> {
        let id = request.into_inner().id;
        self.state
            .delete_provider_profile_requests
            .lock()
            .await
            .push(id.clone());
        let delete_failure = self
            .state
            .fail_delete_provider_profile_message
            .lock()
            .await
            .take();
        if let Some(message) = delete_failure {
            return Err(Status::internal(message));
        }
        let deleted = self.state.profiles.lock().await.remove(&id).is_some();
        Ok(Response::new(
            openshell_core::proto::DeleteProviderProfileResponse {
                outcome: if deleted {
                    openshell_core::proto::DeletionOutcome::Completed.into()
                } else {
                    openshell_core::proto::DeletionOutcome::AlreadyAbsent.into()
                },
            },
        ))
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
        _request: tonic::Request<openshell_core::proto::UpdateConfigRequest>,
    ) -> Result<Response<openshell_core::proto::UpdateConfigResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn get_sandbox_policy_status(
        &self,
        _request: tonic::Request<openshell_core::proto::GetSandboxPolicyStatusRequest>,
    ) -> Result<Response<openshell_core::proto::GetSandboxPolicyStatusResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn list_sandbox_policies(
        &self,
        _request: tonic::Request<openshell_core::proto::ListSandboxPoliciesRequest>,
    ) -> Result<Response<openshell_core::proto::ListSandboxPoliciesResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn report_sandbox_configuration(
        &self,
        _request: tonic::Request<openshell_core::proto::ReportSandboxConfigurationRequest>,
    ) -> Result<Response<openshell_core::proto::ReportSandboxConfigurationResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn report_policy_status(
        &self,
        _request: tonic::Request<openshell_core::proto::ReportPolicyStatusRequest>,
    ) -> Result<Response<openshell_core::proto::ReportPolicyStatusResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn get_sandbox_logs(
        &self,
        _request: tonic::Request<openshell_core::proto::GetSandboxLogsRequest>,
    ) -> Result<Response<openshell_core::proto::GetSandboxLogsResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn push_sandbox_logs(
        &self,
        _request: tonic::Request<tonic::Streaming<openshell_core::proto::PushSandboxLogsRequest>>,
    ) -> Result<Response<openshell_core::proto::PushSandboxLogsResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn submit_policy_analysis(
        &self,
        _request: tonic::Request<openshell_core::proto::SubmitPolicyAnalysisRequest>,
    ) -> Result<Response<openshell_core::proto::SubmitPolicyAnalysisResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn get_draft_policy(
        &self,
        _request: tonic::Request<openshell_core::proto::GetDraftPolicyRequest>,
    ) -> Result<Response<openshell_core::proto::GetDraftPolicyResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn approve_draft_chunk(
        &self,
        _request: tonic::Request<openshell_core::proto::ApproveDraftChunkRequest>,
    ) -> Result<Response<openshell_core::proto::ApproveDraftChunkResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn reject_draft_chunk(
        &self,
        _request: tonic::Request<openshell_core::proto::RejectDraftChunkRequest>,
    ) -> Result<Response<openshell_core::proto::RejectDraftChunkResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn approve_all_draft_chunks(
        &self,
        _request: tonic::Request<openshell_core::proto::ApproveAllDraftChunksRequest>,
    ) -> Result<Response<openshell_core::proto::ApproveAllDraftChunksResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn edit_draft_chunk(
        &self,
        _request: tonic::Request<openshell_core::proto::EditDraftChunkRequest>,
    ) -> Result<Response<openshell_core::proto::EditDraftChunkResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn undo_draft_chunk(
        &self,
        _request: tonic::Request<openshell_core::proto::UndoDraftChunkRequest>,
    ) -> Result<Response<openshell_core::proto::UndoDraftChunkResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn clear_draft_chunks(
        &self,
        _request: tonic::Request<openshell_core::proto::ClearDraftChunksRequest>,
    ) -> Result<Response<openshell_core::proto::ClearDraftChunksResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn get_draft_history(
        &self,
        _request: tonic::Request<openshell_core::proto::GetDraftHistoryRequest>,
    ) -> Result<Response<openshell_core::proto::GetDraftHistoryResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn issue_sandbox_token(
        &self,
        _request: tonic::Request<openshell_core::proto::IssueSandboxTokenRequest>,
    ) -> Result<Response<openshell_core::proto::IssueSandboxTokenResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn refresh_sandbox_token(
        &self,
        _request: tonic::Request<openshell_core::proto::RefreshSandboxTokenRequest>,
    ) -> Result<Response<openshell_core::proto::RefreshSandboxTokenResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn connect_supervisor(
        &self,
        _request: tonic::Request<tonic::Streaming<SupervisorMessage>>,
    ) -> Result<Response<Self::ConnectSupervisorStream>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    type RelayStreamStream =
        tokio_stream::wrappers::ReceiverStream<Result<openshell_core::proto::RelayFrame, Status>>;

    async fn relay_stream(
        &self,
        _request: tonic::Request<tonic::Streaming<openshell_core::proto::RelayFrame>>,
    ) -> Result<Response<Self::RelayStreamStream>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    type ForwardTcpStream = tokio_stream::wrappers::ReceiverStream<
        Result<openshell_core::proto::TcpForwardFrame, Status>,
    >;

    async fn forward_tcp(
        &self,
        _request: tonic::Request<tonic::Streaming<openshell_core::proto::TcpForwardFrame>>,
    ) -> Result<Response<Self::ForwardTcpStream>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn create_workspace(
        &self,
        _request: tonic::Request<openshell_core::proto::CreateWorkspaceRequest>,
    ) -> Result<Response<openshell_core::proto::CreateWorkspaceResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn get_workspace(
        &self,
        _request: tonic::Request<openshell_core::proto::GetWorkspaceRequest>,
    ) -> Result<Response<openshell_core::proto::GetWorkspaceResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn list_workspaces(
        &self,
        _request: tonic::Request<openshell_core::proto::ListWorkspacesRequest>,
    ) -> Result<Response<openshell_core::proto::ListWorkspacesResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn delete_workspace(
        &self,
        _request: tonic::Request<openshell_core::proto::DeleteWorkspaceRequest>,
    ) -> Result<Response<openshell_core::proto::DeleteWorkspaceResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn add_workspace_member(
        &self,
        _request: tonic::Request<openshell_core::proto::AddWorkspaceMemberRequest>,
    ) -> Result<Response<openshell_core::proto::AddWorkspaceMemberResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn remove_workspace_member(
        &self,
        _request: tonic::Request<openshell_core::proto::RemoveWorkspaceMemberRequest>,
    ) -> Result<Response<openshell_core::proto::RemoveWorkspaceMemberResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }

    async fn list_workspace_members(
        &self,
        _request: tonic::Request<openshell_core::proto::ListWorkspaceMembersRequest>,
    ) -> Result<Response<openshell_core::proto::ListWorkspaceMembersResponse>, Status> {
        Err(Status::unimplemented("not implemented in test"))
    }
}

/// Test fixture: TLS-enabled server with matching client certs.
struct TestServer {
    endpoint: String,
    tls: TlsOptions,
    state: ProviderState,
    tls_materials_dir: TempDir,
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
    let state = ProviderState::default();
    let service = TestOpenShell {
        state: state.clone(),
    };
    tokio::spawn(async move {
        Server::builder()
            .tls_config(tls_config)
            .unwrap()
            .add_service(OpenShellServer::new(service))
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
        state,
        tls_materials_dir: dir,
    }
}

async fn seed_readiness_provider(server: &TestServer) {
    server.state.providers.lock().await.insert(
        READINESS_PROVIDER.to_string(),
        Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: format!("id-{READINESS_PROVIDER}"),
                name: READINESS_PROVIDER.to_string(),
                workspace: "default".to_string(),
                resource_version: 1,
                ..Default::default()
            }),
            r#type: "openai".to_string(),
            credentials: HashMap::from([(
                "OPENAI_API_KEY".to_string(),
                SYNTHETIC_READINESS_CREDENTIAL.to_string(),
            )]),
            ..Default::default()
        },
    );
}

fn readiness_status(
    state: ProviderReadinessState,
    reason: ProviderReadinessReason,
    process_installed: bool,
) -> ProviderReadinessStatus {
    ProviderReadinessStatus {
        state: state.into(),
        reason: reason.into(),
        observed: Some(ProviderReadinessObservation {
            session_id: "network-session".to_string(),
            sequence: 1,
            credentials_installed: true,
            policy_active: true,
            launch_environment_installed: process_installed,
            process_instance_id: if process_installed {
                "process-instance".to_string()
            } else {
                String::new()
            },
            reason: reason.into(),
            ..Default::default()
        }),
        network_instance_id: "network-instance".to_string(),
        observed_time: Some(openshell_core::time::timestamp_from_millis(1000).unwrap()),
        evaluated_time: Some(openshell_core::time::timestamp_from_millis(1000).unwrap()),
        ..Default::default()
    }
}

async fn script_readiness(
    server: &TestServer,
    sandbox_name: &str,
    responses: Vec<Result<ProviderReadinessStatus, Code>>,
) {
    server.state.readiness_scripts.lock().await.insert(
        sandbox_name.to_string(),
        responses
            .into_iter()
            .map(|response| match response {
                Ok(status) => ReadinessReply::Status(Box::new(status)),
                Err(code) => ReadinessReply::Error(code),
            })
            .collect(),
    );
}

async fn script_readiness_then_hang(
    server: &TestServer,
    sandbox_name: &str,
    first_status: ProviderReadinessStatus,
) {
    server.state.readiness_scripts.lock().await.insert(
        sandbox_name.to_string(),
        VecDeque::from([
            ReadinessReply::Status(Box::new(first_status)),
            ReadinessReply::Hung,
        ]),
    );
}

async fn seed_readiness_receipt(
    server: &TestServer,
    sandbox_name: &str,
    kind: ProviderMutationKind,
) -> ProviderMutationReceipt {
    seed_readiness_provider(server).await;
    TestOpenShell {
        state: server.state.clone(),
    }
    .provider_receipt(sandbox_name, READINESS_PROVIDER, "default", kind, None)
    .await
}

async fn latest_readiness_receipt(
    server: &TestServer,
    sandbox_name: &str,
) -> ProviderMutationReceipt {
    server
        .state
        .readiness_receipts
        .lock()
        .await
        .values()
        .filter(|receipt| {
            receipt
                .desired
                .as_ref()
                .is_some_and(|desired| desired.sandbox == sandbox_name)
        })
        .max_by_key(|receipt| {
            receipt
                .persisted_time
                .as_ref()
                .map(|time| (time.seconds, time.nanos))
        })
        .cloned()
        .expect("sandbox mutation receipt")
}

fn provider_wait_options() -> run::ProviderWaitOptions<'static> {
    run::ProviderWaitOptions {
        wait: true,
        timeout: Duration::from_secs(2),
        output: "json",
    }
}

// A separate CLI process provides isolated stdout/stderr without redirecting
// the test runner's descriptors or sharing the user's gateway configuration.
async fn run_readiness_cli(server: &TestServer, args: &[&str]) -> std::process::Output {
    let config_dir = tempfile::tempdir().unwrap();
    let tls_dir = config_dir
        .path()
        .join("openshell/gateways/provider-readiness/mtls");
    std::fs::create_dir_all(&tls_dir).unwrap();
    for filename in ["ca.crt", "tls.crt", "tls.key"] {
        std::fs::copy(
            server.tls_materials_dir.path().join(filename),
            tls_dir.join(filename),
        )
        .unwrap();
    }
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_openshell"));
    for (key, _) in std::env::vars().filter(|(key, _)| key.starts_with("OPENSHELL_")) {
        command.env_remove(key);
    }
    command
        .args([
            "--gateway",
            "provider-readiness",
            "--gateway-endpoint",
            &server.endpoint,
            "--color",
            "never",
        ])
        .args(args)
        .env("XDG_CONFIG_HOME", config_dir.path())
        .kill_on_drop(true);
    tokio::time::timeout(Duration::from_secs(8), command.output())
        .await
        .expect("bounded readiness CLI process")
        .expect("readiness CLI output")
}

fn assert_readiness_output_redacted(output: &std::process::Output) {
    for bytes in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(bytes);
        assert!(!text.contains(SYNTHETIC_READINESS_CREDENTIAL));
        assert!(!text.contains(SYNTHETIC_READINESS_BACKEND_ERROR));
        assert!(!text.contains(SYNTHETIC_PROFILE_BACKEND_ERROR));
        assert!(!text.contains(SYNTHETIC_MUTATION_ERROR_METADATA));
    }
}

fn mutation_error_status(code: Code, reason: &str, domain: &str) -> Status {
    Status::with_error_details(
        code,
        SYNTHETIC_READINESS_BACKEND_ERROR,
        ErrorDetails::with_error_info(
            reason,
            domain,
            HashMap::from([(
                "backend".to_string(),
                SYNTHETIC_MUTATION_ERROR_METADATA.to_string(),
            )]),
        ),
    )
}

// Exercise the actual CLI process and establish that the mock saved exactly one
// mutation before returning the error, without producing or polling a receipt.
async fn run_saved_provider_mutation_error(
    server: &TestServer,
    action: &str,
    status: Status,
    wait: bool,
) -> String {
    let sandbox_name = "storage-uncertain";
    seed_readiness_provider(server).await;
    server.state.sandbox_providers.lock().await.insert(
        sandbox_name.to_string(),
        if action == "attach" {
            Vec::new()
        } else {
            vec![READINESS_PROVIDER.to_string()]
        },
    );
    server.state.sandbox_provider_requests.lock().await.clear();
    server.state.provider_update_requests.lock().await.clear();
    *server.state.fail_mutation_after_save.lock().await = Some(status);
    let mut args = if action == "update" {
        vec![
            "provider",
            "update",
            READINESS_PROVIDER,
            "--config",
            "region=changed",
        ]
    } else {
        vec![
            "sandbox",
            "provider",
            action,
            sandbox_name,
            READINESS_PROVIDER,
        ]
    };
    args.extend(["--output", "json"]);
    if wait {
        args.extend(["--wait", "--timeout", "1"]);
    }
    let output = run_readiness_cli(server, &args).await;
    assert!(!output.status.success(), "{action}, wait={wait}");
    assert!(output.stdout.is_empty(), "failed mutation printed a result");
    assert_readiness_output_redacted(&output);
    assert!(server.state.readiness_receipts.lock().await.is_empty());
    assert!(server.state.readiness_requests.lock().await.is_empty());

    let attachment_requests = server.state.sandbox_provider_requests.lock().await;
    let update_requests = server.state.provider_update_requests.lock().await;
    if action == "update" {
        assert!(attachment_requests.is_empty());
        assert_eq!(update_requests.len(), 1, "update was replayed");
        let providers = server.state.providers.lock().await;
        let provider = providers.get(READINESS_PROVIDER).unwrap();
        assert_eq!(
            provider.config.get("region").map(String::as_str),
            Some("changed")
        );
        assert_eq!(provider.metadata.as_ref().unwrap().resource_version, 2);
    } else {
        assert!(update_requests.is_empty());
        let expected_request = if action == "attach" {
            SandboxProviderRequestLog::Attach {
                sandbox_name: sandbox_name.to_string(),
                provider: READINESS_PROVIDER.to_string(),
            }
        } else {
            SandboxProviderRequestLog::Detach {
                sandbox_name: sandbox_name.to_string(),
                provider: READINESS_PROVIDER.to_string(),
            }
        };
        assert_eq!(
            *attachment_requests,
            vec![expected_request],
            "mutation was replayed"
        );
        let attachments = server.state.sandbox_providers.lock().await;
        assert_eq!(
            attachments
                .get(sandbox_name)
                .unwrap()
                .contains(&READINESS_PROVIDER.to_string()),
            action == "attach",
            "attachment mutation was not saved"
        );
    }
    String::from_utf8(output.stderr).unwrap()
}

#[tokio::test]
async fn provider_readiness_storage_uncertainty_preserves_safe_recovery_guidance() {
    let server = run_server().await;
    for action in ["attach", "detach", "update"] {
        for wait in [false, true] {
            // Structured uncertainty takes precedence over the ordinary Aborted
            // conflict hint: this saved mutation must not invite a blind retry.
            for code in [Code::Unavailable, Code::Aborted] {
                let stderr = run_saved_provider_mutation_error(
                    &server,
                    action,
                    mutation_error_status(code, STORAGE_UNCERTAIN_REASON, ERROR_DOMAIN),
                    wait,
                )
                .await;
                for expected in [
                    STORAGE_UNCERTAIN_REASON,
                    "may already be saved",
                    "Do not blindly retry",
                    "reconcile",
                ] {
                    assert!(
                        stderr.contains(expected),
                        "{action}, wait={wait}, {code:?}: {stderr}"
                    );
                }
                assert!(!stderr.contains("Please retry the command"));
            }
        }
    }
}

#[tokio::test]
async fn provider_readiness_storage_uncertainty_requires_trusted_error_info() {
    let server = run_server().await;
    let valid = mutation_error_status(Code::Unavailable, STORAGE_UNCERTAIN_REASON, ERROR_DOMAIN);
    let mut malformed_error_info = valid.details().to_vec();
    let reason_offset = malformed_error_info
        .windows(STORAGE_UNCERTAIN_REASON.len())
        .position(|bytes| bytes == STORAGE_UNCERTAIN_REASON.as_bytes())
        .unwrap();
    // Invalid UTF-8 breaks only the nested ErrorInfo reason; its outer status
    // envelope remains valid and cannot authorize the special recovery hint.
    malformed_error_info[reason_offset] = 0xff;
    let cases = [
        (
            "unrelated",
            mutation_error_status(Code::Unavailable, "OTHER_REASON", ERROR_DOMAIN),
        ),
        (
            "wrong domain",
            mutation_error_status(Code::Unavailable, STORAGE_UNCERTAIN_REASON, "other.example"),
        ),
        (
            "reason case",
            mutation_error_status(
                Code::Unavailable,
                "config_operation_storage_uncertain",
                ERROR_DOMAIN,
            ),
        ),
        (
            "domain case",
            mutation_error_status(
                Code::Unavailable,
                STORAGE_UNCERTAIN_REASON,
                "OPENSHELL.NVIDIA.COM",
            ),
        ),
        (
            "missing ErrorInfo",
            Status::with_error_details(
                Code::Unavailable,
                SYNTHETIC_READINESS_BACKEND_ERROR,
                ErrorDetails::new(),
            ),
        ),
        (
            "message only",
            Status::unavailable(format!(
                "{STORAGE_UNCERTAIN_REASON}: {SYNTHETIC_READINESS_BACKEND_ERROR}"
            )),
        ),
        (
            "malformed ErrorInfo",
            Status::with_details(
                Code::Unavailable,
                SYNTHETIC_READINESS_BACKEND_ERROR,
                malformed_error_info.into(),
            ),
        ),
        (
            "malformed envelope",
            Status::with_details(
                Code::Unavailable,
                SYNTHETIC_READINESS_BACKEND_ERROR,
                vec![0xff].into(),
            ),
        ),
        (
            "mismatched envelope message",
            Status::with_details(
                Code::Unavailable,
                "different message",
                valid.details().to_vec().into(),
            ),
        ),
    ];
    for action in ["attach", "detach", "update"] {
        let error_prefix = match action {
            "attach" => "provider attachment failed",
            "detach" => "provider detachment failed",
            _ => "provider update failed",
        };
        for (case, status) in &cases {
            let stderr =
                run_saved_provider_mutation_error(&server, action, status.clone(), true).await;
            assert!(stderr.contains(error_prefix), "{action}, {case}: {stderr}");
            assert!(
                stderr.contains(&Code::Unavailable.to_string()),
                "{action}, {case}: {stderr}"
            );
            assert!(
                !stderr.contains(STORAGE_UNCERTAIN_REASON),
                "{action}, {case}: {stderr}"
            );
            assert!(
                !stderr.contains("may already be saved"),
                "{action}, {case}: {stderr}"
            );
        }
    }
}

#[tokio::test]
async fn provider_readiness_mutations_reject_unbound_receipts_before_output_or_polling() {
    let server = run_server().await;
    seed_readiness_provider(&server).await;
    let corruptions: &[(&str, ReceiptCorruption)] = &[
        ("empty", |receipt| {
            *receipt = ProviderMutationReceipt::default();
        }),
        ("receipt_id", |receipt| receipt.receipt_id.clear()),
        ("mutation_id", |receipt| receipt.mutation_id.clear()),
        ("workspace", |receipt| {
            receipt.workspace = "other".to_string();
        }),
        ("provider", |receipt| {
            receipt.provider = "other".to_string();
        }),
        ("kind", |receipt| {
            receipt.kind = ProviderMutationKind::Observe.into();
        }),
        ("sandbox", |receipt| {
            receipt.desired.as_mut().expect("desired identity").sandbox = "other".to_string();
        }),
        ("sandbox_id", |receipt| {
            receipt
                .desired
                .as_mut()
                .expect("desired identity")
                .sandbox_id = "other-id".to_string();
        }),
        ("desired", |receipt| receipt.desired = None),
        ("timestamp", |receipt| receipt.persisted_time = None),
        ("provider_presence", |receipt| {
            let detached = receipt.kind == i32::from(ProviderMutationKind::Detach);
            receipt
                .desired
                .as_mut()
                .expect("desired identity")
                .provider_id = if detached {
                "unexpected-provider".to_string()
            } else {
                String::new()
            };
        }),
    ];
    for action in ["attach", "detach"] {
        let state = if action == "attach" {
            ProviderReadinessState::Ready
        } else {
            ProviderReadinessState::Revoked
        };
        script_readiness(
            &server,
            "receipt-target",
            vec![Ok(readiness_status(
                state,
                ProviderReadinessReason::Unspecified,
                true,
            ))],
        )
        .await;
        for wait in [false, true] {
            for (field, corrupt) in corruptions {
                *server.state.corrupt_mutation_receipt.lock().await = Some(*corrupt);
                let mut args = vec![
                    "sandbox",
                    "provider",
                    action,
                    "receipt-target",
                    READINESS_PROVIDER,
                    "--timeout",
                    "1",
                    "--output",
                    "json",
                ];
                if wait {
                    args.push("--wait");
                }
                let output = run_readiness_cli(&server, &args).await;
                assert!(!output.status.success(), "{action}: {field}, wait={wait}");
                assert!(
                    output.stdout.is_empty(),
                    "invalid receipt was printed: {field}"
                );
                assert_readiness_output_redacted(&output);
                assert!(server.state.readiness_requests.lock().await.is_empty());
            }
        }
    }
}

#[tokio::test]
async fn provider_readiness_update_rejects_unbound_batch_identity() {
    let server = run_server().await;
    seed_readiness_provider(&server).await;
    server.state.sandbox_providers.lock().await.insert(
        "update-target".to_string(),
        vec![READINESS_PROVIDER.to_string()],
    );
    script_readiness(
        &server,
        "update-target",
        vec![Ok(readiness_status(
            ProviderReadinessState::Ready,
            ProviderReadinessReason::Unspecified,
            true,
        ))],
    )
    .await;
    let corruptions: &[(&str, ReceiptCorruption)] = &[
        ("mutation_id", |receipt| {
            receipt.mutation_id = "another-update".to_string();
        }),
        ("workspace", |receipt| {
            receipt.workspace = "other".to_string();
        }),
        ("provider_name", |receipt| {
            receipt.provider = "other".to_string();
        }),
        ("kind", |receipt| {
            receipt.kind = ProviderMutationKind::Observe.into();
        }),
        ("provider_id", |receipt| {
            receipt
                .desired
                .as_mut()
                .expect("desired identity")
                .provider_id = "other-id".to_string();
        }),
        ("provider_revision", |receipt| {
            receipt
                .desired
                .as_mut()
                .expect("desired identity")
                .provider_resource_version = u64::MAX;
        }),
    ];
    for wait in [false, true] {
        for (field, corrupt) in corruptions {
            *server.state.corrupt_mutation_receipt.lock().await = Some(*corrupt);
            let mut args = vec![
                "provider",
                "update",
                READINESS_PROVIDER,
                "--credential",
                "OPENAI_API_KEY=updated-fixture",
                "--timeout",
                "1",
                "--output",
                "json",
            ];
            if wait {
                args.push("--wait");
            }
            let output = run_readiness_cli(&server, &args).await;
            assert!(!output.status.success(), "{field}, wait={wait}");
            assert!(
                output.stdout.is_empty(),
                "invalid batch was printed: {field}"
            );
            assert_readiness_output_redacted(&output);
            assert!(server.state.readiness_requests.lock().await.is_empty());
        }
    }
}

#[tokio::test]
async fn provider_readiness_update_with_no_targets_preserves_saved_success() {
    let server = run_server().await;
    seed_readiness_provider(&server).await;
    for wait in [false, true] {
        let mut args = vec![
            "provider",
            "update",
            READINESS_PROVIDER,
            "--credential",
            "OPENAI_API_KEY=updated-fixture",
            "--output",
            "json",
        ];
        if wait {
            args.push("--wait");
        }
        let output = run_readiness_cli(&server, &args).await;
        assert!(output.status.success());
        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("saved update JSON");
        assert_eq!(value["targets"], serde_json::json!([]));
        assert!(
            !value["mutation_id"]
                .as_str()
                .expect("mutation ID")
                .is_empty()
        );
        assert!(server.state.readiness_requests.lock().await.is_empty());
    }
}

#[tokio::test]
async fn provider_profile_permission_denial_preserves_safe_workspace_guidance() {
    let server = run_server().await;
    seed_readiness_provider(&server).await;
    for (profile, failed_lookup, expected_lookups) in [
        ("openai", "openai", vec!["openai"]),
        ("github", "github", vec!["github"]),
    ] {
        server
            .state
            .providers
            .lock()
            .await
            .get_mut(READINESS_PROVIDER)
            .expect("seeded provider")
            .r#type = profile.to_string();
        let mut errors = server.state.profile_read_errors.lock().await;
        errors.clear();
        errors.insert(failed_lookup.to_string(), Code::PermissionDenied);
        drop(errors);
        for args in [
            vec![
                "provider",
                "create",
                "--name",
                "denied-new-provider",
                "--type",
                profile,
                "--credential",
                "OPENAI_API_KEY=fixture-provider-credential",
            ],
            vec![
                "provider",
                "update",
                READINESS_PROVIDER,
                "--from-existing",
                "--wait",
                "--output",
                "json",
            ],
        ] {
            server.state.profile_read_requests.lock().await.clear();
            let output = run_readiness_cli(&server, &args).await;
            assert!(!output.status.success(), "{args:?}");
            assert!(output.stdout.is_empty());
            assert_readiness_output_redacted(&output);
            let diagnostic = String::from_utf8_lossy(&output.stderr);
            let compact: String = diagnostic
                .chars()
                .filter(|character| !character.is_whitespace() && *character != '│')
                .collect();
            assert!(
                compact.contains("providerprofilelookupdenied"),
                "{diagnostic}"
            );
            // The permission code supports recovery guidance without revealing
            // backend text or inferring which membership or role check failed.
            assert!(compact.contains("PERMISSION_DENIED"), "{diagnostic}");
            assert!(
                compact.contains("verifyworkspacemembershipandrequiredpermissions"),
                "{diagnostic}"
            );
            assert!(!diagnostic.contains("unsupported provider type or profile"));
            assert_eq!(
                *server.state.profile_read_requests.lock().await,
                expected_lookups
            );
            assert!(
                !server
                    .state
                    .providers
                    .lock()
                    .await
                    .contains_key("denied-new-provider")
            );
            assert_eq!(
                server.state.provider_create_requests.load(Ordering::SeqCst),
                0
            );
            assert!(
                server
                    .state
                    .provider_update_requests
                    .lock()
                    .await
                    .is_empty()
            );
            assert!(server.state.readiness_requests.lock().await.is_empty());
        }
    }
}

#[tokio::test]
async fn provider_readiness_update_redacts_exact_profile_lookup_errors() {
    let server = run_server().await;
    seed_readiness_provider(&server).await;
    for (profile, failed_lookup, expected_lookups) in [
        ("openai", "openai", vec!["openai"]),
        ("github", "github", vec!["github"]),
    ] {
        server
            .state
            .providers
            .lock()
            .await
            .get_mut(READINESS_PROVIDER)
            .expect("seeded provider")
            .r#type = profile.to_string();
        let mut errors = server.state.profile_read_errors.lock().await;
        errors.clear();
        errors.insert(failed_lookup.to_string(), Code::Internal);
        drop(errors);
        for source in ["--from-existing", "--from-oidc-token"] {
            server.state.profile_read_requests.lock().await.clear();
            let output = run_readiness_cli(
                &server,
                &[
                    "provider",
                    "update",
                    READINESS_PROVIDER,
                    source,
                    "--wait",
                    "--output",
                    "json",
                ],
            )
            .await;
            assert!(!output.status.success());
            assert_readiness_output_redacted(&output);
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("provider profile lookup failed")
            );
            assert_eq!(
                *server.state.profile_read_requests.lock().await,
                expected_lookups
            );
            assert!(
                server
                    .state
                    .provider_update_requests
                    .lock()
                    .await
                    .is_empty()
            );
        }
    }
}

async fn assert_later_readiness_targets_are_polled(
    blocked_targets: usize,
    blocked_reply: ReadinessReply,
    expected_state: &str,
) {
    let server = run_server().await;
    seed_readiness_provider(&server).await;
    for index in 0..17 {
        let sandbox = format!("sandbox-{index:02}");
        server
            .state
            .sandbox_providers
            .lock()
            .await
            .insert(sandbox.clone(), vec![READINESS_PROVIDER.to_string()]);
        script_readiness(
            &server,
            &sandbox,
            vec![Ok(readiness_status(
                ProviderReadinessState::Ready,
                ProviderReadinessReason::Unspecified,
                true,
            ))],
        )
        .await;
    }
    for index in 0..blocked_targets {
        server.state.readiness_scripts.lock().await.insert(
            format!("sandbox-{index:02}"),
            VecDeque::from([blocked_reply.clone()]),
        );
    }
    let started = std::time::Instant::now();
    let output = run_readiness_cli(
        &server,
        &[
            "provider",
            "update",
            READINESS_PROVIDER,
            "--credential",
            "OPENAI_API_KEY=updated-fixture",
            "--wait",
            "--timeout",
            "1",
            "--output",
            "json",
        ],
    )
    .await;
    assert!(!output.status.success());
    assert!(started.elapsed() < Duration::from_secs(4));
    assert_readiness_output_redacted(&output);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("target outcomes");
    let targets = value["targets"].as_array().expect("target array");
    assert_eq!(targets.len(), 17);
    let requests = server.state.readiness_requests.lock().await;
    for (index, target) in targets.iter().enumerate() {
        let sandbox = format!("sandbox-{index:02}");
        assert_eq!(target["receipt"]["desired"]["sandbox"], sandbox);
        if index < blocked_targets {
            assert_eq!(target["wait_outcome"], "timed_out");
            assert_eq!(target["state"], expected_state);
        } else {
            assert_eq!(target["wait_outcome"], "complete");
        }
        let target_requests = requests
            .iter()
            .filter(|request| request.sandbox == sandbox)
            .collect::<Vec<_>>();
        assert!(!target_requests.is_empty(), "{sandbox} was never queried");
        if index >= blocked_targets {
            assert_eq!(
                target_requests.len(),
                1,
                "completed targets leave the queue"
            );
        }
        for request in target_requests {
            assert_eq!(
                request.receipt_id,
                target["receipt"]["receipt_id"]
                    .as_str()
                    .expect("receipt ID")
            );
            assert_eq!(request.provider, READINESS_PROVIDER);
            assert_eq!(
                selected_workspace(&request.workspace_scope),
                Some("default")
            );
        }
    }
}

#[tokio::test]
async fn provider_readiness_update_polls_later_targets_while_first_is_hung() {
    assert_later_readiness_targets_are_polled(1, ReadinessReply::Hung, "persisted").await;
}

#[tokio::test]
async fn provider_readiness_update_polls_later_targets_while_first_batch_is_pending() {
    assert_later_readiness_targets_are_polled(
        16,
        ReadinessReply::Status(Box::new(readiness_status(
            ProviderReadinessState::Pending,
            ProviderReadinessReason::WaitingForProcess,
            false,
        ))),
        "pending",
    )
    .await;
}

#[tokio::test]
async fn provider_readiness_update_polls_later_targets_while_first_batch_is_hung() {
    assert_later_readiness_targets_are_polled(16, ReadinessReply::Hung, "persisted").await;
}

async fn assert_slow_readiness_targets_complete(target_count: usize, delay: Duration) {
    let server = run_server().await;
    seed_readiness_provider(&server).await;
    for index in 0..target_count {
        let sandbox = format!("slow-sandbox-{index:02}");
        server
            .state
            .sandbox_providers
            .lock()
            .await
            .insert(sandbox.clone(), vec![READINESS_PROVIDER.to_string()]);
        server.state.readiness_scripts.lock().await.insert(
            sandbox,
            VecDeque::from([ReadinessReply::DelayedStatus(
                delay,
                Box::new(readiness_status(
                    ProviderReadinessState::Ready,
                    ProviderReadinessReason::Unspecified,
                    true,
                )),
            )]),
        );
    }
    let started = std::time::Instant::now();
    let output = run_readiness_cli(
        &server,
        &[
            "provider",
            "update",
            READINESS_PROVIDER,
            "--credential",
            "OPENAI_API_KEY=updated-fixture",
            "--wait",
            "--timeout",
            "2",
            "--output",
            "json",
        ],
    )
    .await;
    assert!(
        output.status.success(),
        "healthy status replies that fit the shared deadline must complete: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(started.elapsed() < Duration::from_secs(4));
    assert_readiness_output_redacted(&output);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("target outcomes");
    let targets = value["targets"].as_array().expect("target array");
    assert_eq!(targets.len(), target_count);
    let requests = server.state.readiness_requests.lock().await;
    for (index, target) in targets.iter().enumerate() {
        let sandbox = format!("slow-sandbox-{index:02}");
        assert_eq!(target["receipt"]["desired"]["sandbox"], sandbox);
        assert_eq!(target["wait_outcome"], "complete");
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.sandbox == sandbox)
                .count(),
            1,
            "a healthy response must not be discarded and retried"
        );
    }
}

#[tokio::test]
async fn provider_readiness_update_wait_allows_slow_single_target() {
    assert_slow_readiness_targets_complete(1, Duration::from_millis(1200)).await;
}

#[tokio::test]
async fn provider_readiness_update_wait_allows_slow_queued_targets() {
    assert_slow_readiness_targets_complete(17, Duration::from_millis(700)).await;
}

#[tokio::test]
async fn provider_readiness_attach_wait_observes_pending_then_ready() {
    let server = run_server().await;
    seed_readiness_provider(&server).await;
    script_readiness(
        &server,
        "pending-sandbox",
        vec![
            Ok(readiness_status(
                ProviderReadinessState::Pending,
                ProviderReadinessReason::WaitingForProcess,
                false,
            )),
            Ok(readiness_status(
                ProviderReadinessState::Ready,
                ProviderReadinessReason::Unspecified,
                true,
            )),
        ],
    )
    .await;

    run::sandbox_provider_attach(
        &server.endpoint,
        "pending-sandbox",
        READINESS_PROVIDER,
        "default",
        &server.tls,
        provider_wait_options(),
    )
    .await
    .expect("attachment waits through pending state");

    let requests = server.state.readiness_requests.lock().await;
    assert_eq!(requests.len(), 2);
    assert!(!requests[0].receipt_id.is_empty());
    assert!(
        requests
            .iter()
            .all(|request| request.receipt_id == requests[0].receipt_id)
    );
    assert!(
        requests
            .iter()
            .all(|request| selected_workspace(&request.workspace_scope) == Some("default"))
    );
}

#[tokio::test]
async fn provider_readiness_attach_wait_times_out_without_process_ack() {
    let server = run_server().await;
    seed_readiness_provider(&server).await;
    script_readiness(
        &server,
        "missing-process",
        vec![Ok(readiness_status(
            ProviderReadinessState::Pending,
            ProviderReadinessReason::WaitingForProcess,
            false,
        ))],
    )
    .await;

    let output = run_readiness_cli(
        &server,
        &[
            "sandbox",
            "provider",
            "attach",
            "missing-process",
            READINESS_PROVIDER,
            "--wait",
            "--timeout",
            "1",
            "--output",
            "json",
        ],
    )
    .await;

    assert!(!output.status.success());
    assert_readiness_output_redacted(&output);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("readiness JSON");
    let target = &value["targets"][0];
    assert_eq!(target["state"], "pending");
    assert_eq!(target["reason"], "waiting_for_process");
    assert_eq!(target["wait_outcome"], "timed_out");
    assert_eq!(target["observed"]["launch_environment_installed"], false);
    assert!(!server.state.readiness_requests.lock().await.is_empty());
}

#[tokio::test]
async fn provider_readiness_status_wait_supersedes_changed_desired_authority() {
    let server = run_server().await;
    seed_readiness_provider(&server).await;
    run::sandbox_provider_attach(
        &server.endpoint,
        "changed-authority",
        READINESS_PROVIDER,
        "default",
        &server.tls,
        run::ProviderWaitOptions::default(),
    )
    .await
    .unwrap();
    let original = latest_readiness_receipt(&server, "changed-authority").await;
    let mut newer = original.clone();
    newer.desired.as_mut().unwrap().provider_env_revision += 1;
    let mut newer_status = readiness_status(
        ProviderReadinessState::Ready,
        ProviderReadinessReason::Unspecified,
        true,
    );
    newer_status.receipt = Some(newer);
    script_readiness(
        &server,
        "changed-authority",
        vec![
            Ok(readiness_status(
                ProviderReadinessState::Pending,
                ProviderReadinessReason::WaitingForProcess,
                false,
            )),
            Ok(newer_status),
        ],
    )
    .await;

    let output = run_readiness_cli(
        &server,
        &[
            "sandbox",
            "provider",
            "status",
            "changed-authority",
            READINESS_PROVIDER,
            "--receipt",
            &original.receipt_id,
            "--wait",
            "--output",
            "json",
        ],
    )
    .await;

    assert!(!output.status.success());
    assert_readiness_output_redacted(&output);
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("superseded readiness JSON");
    let target = &value["targets"][0];
    assert_eq!(target["state"], "superseded");
    assert_eq!(target["reason"], "desired_state_changed");
    assert_eq!(target["wait_outcome"], "terminal");
    assert_eq!(target["receipt"]["receipt_id"], original.receipt_id);
    assert_eq!(
        target["receipt"]["desired"]["provider_env_revision"],
        original
            .desired
            .as_ref()
            .unwrap()
            .provider_env_revision
            .to_string()
    );
    let requests = server.state.readiness_requests.lock().await;
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|request| request.receipt_id == original.receipt_id)
    );
}

#[tokio::test]
async fn provider_readiness_status_without_wait_rejects_missing_process_ack() {
    let server = run_server().await;
    let receipt =
        seed_readiness_receipt(&server, "unproved-ready", ProviderMutationKind::Attach).await;
    script_readiness(
        &server,
        "unproved-ready",
        vec![Ok(readiness_status(
            ProviderReadinessState::Ready,
            ProviderReadinessReason::Unspecified,
            false,
        ))],
    )
    .await;

    let output = run_readiness_cli(
        &server,
        &[
            "sandbox",
            "provider",
            "status",
            "unproved-ready",
            READINESS_PROVIDER,
            "--receipt",
            &receipt.receipt_id,
            "--output",
            "json",
        ],
    )
    .await;

    assert!(!output.status.success());
    assert_readiness_output_redacted(&output);
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid provider readiness status"));
    assert_eq!(server.state.readiness_requests.lock().await.len(), 1);
}

#[tokio::test]
async fn provider_readiness_status_without_wait_rejects_ready_for_detach() {
    let server = run_server().await;
    let receipt =
        seed_readiness_receipt(&server, "unrevoked-detach", ProviderMutationKind::Detach).await;
    script_readiness(
        &server,
        "unrevoked-detach",
        vec![Ok(readiness_status(
            ProviderReadinessState::Ready,
            ProviderReadinessReason::Unspecified,
            true,
        ))],
    )
    .await;

    let output = run_readiness_cli(
        &server,
        &[
            "sandbox",
            "provider",
            "status",
            "unrevoked-detach",
            READINESS_PROVIDER,
            "--receipt",
            &receipt.receipt_id,
            "--output",
            "json",
        ],
    )
    .await;

    assert!(!output.status.success());
    assert_readiness_output_redacted(&output);
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid provider readiness status"));
    assert_eq!(server.state.readiness_requests.lock().await.len(), 1);
}

#[tokio::test]
async fn provider_readiness_status_wait_completes_from_first_ready_response() {
    let server = run_server().await;
    let receipt =
        seed_readiness_receipt(&server, "first-ready", ProviderMutationKind::Attach).await;
    script_readiness_then_hang(
        &server,
        "first-ready",
        readiness_status(
            ProviderReadinessState::Ready,
            ProviderReadinessReason::Unspecified,
            true,
        ),
    )
    .await;

    let output = run_readiness_cli(
        &server,
        &[
            "sandbox",
            "provider",
            "status",
            "first-ready",
            READINESS_PROVIDER,
            "--receipt",
            &receipt.receipt_id,
            "--wait",
            "--timeout",
            "1",
            "--output",
            "json",
        ],
    )
    .await;

    assert!(output.status.success());
    assert_readiness_output_redacted(&output);
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("completed readiness JSON");
    let target = &value["targets"][0];
    assert_eq!(target["state"], "ready");
    assert_eq!(target["wait_outcome"], "complete");
    assert_eq!(target["receipt"]["receipt_id"], receipt.receipt_id);
    assert_eq!(target["observed"]["launch_environment_installed"], true);
    assert_eq!(server.state.readiness_requests.lock().await.len(), 1);
}

#[tokio::test]
async fn provider_readiness_status_wait_timeout_preserves_first_pending_response() {
    let server = run_server().await;
    let receipt =
        seed_readiness_receipt(&server, "first-pending", ProviderMutationKind::Attach).await;
    script_readiness_then_hang(
        &server,
        "first-pending",
        readiness_status(
            ProviderReadinessState::Pending,
            ProviderReadinessReason::WaitingForProcess,
            false,
        ),
    )
    .await;

    let output = run_readiness_cli(
        &server,
        &[
            "sandbox",
            "provider",
            "status",
            "first-pending",
            READINESS_PROVIDER,
            "--receipt",
            &receipt.receipt_id,
            "--wait",
            "--timeout",
            "1",
            "--output",
            "json",
        ],
    )
    .await;

    assert!(!output.status.success());
    assert_readiness_output_redacted(&output);
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("timed-out readiness JSON");
    let target = &value["targets"][0];
    assert_eq!(target["state"], "pending");
    assert_eq!(target["reason"], "waiting_for_process");
    assert_eq!(target["wait_outcome"], "timed_out");
    assert_eq!(target["receipt"]["receipt_id"], receipt.receipt_id);
    assert_eq!(target["observed"]["session_id"], "network-session");
    assert_eq!(target["observed"]["launch_environment_installed"], false);
    let requests = server.state.readiness_requests.lock().await;
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|request| request.receipt_id == receipt.receipt_id)
    );
}

#[tokio::test]
async fn provider_readiness_mutations_redact_sandbox_lookup_errors() {
    let server = run_server().await;
    seed_readiness_provider(&server).await;
    server
        .state
        .fail_sandbox_reads
        .store(true, Ordering::SeqCst);

    for operation in ["attach", "detach"] {
        let output = run_readiness_cli(
            &server,
            &[
                "sandbox",
                "provider",
                operation,
                "read-failed",
                READINESS_PROVIDER,
                "--wait",
                "--output",
                "json",
            ],
        )
        .await;

        assert!(!output.status.success());
        assert_readiness_output_redacted(&output);
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .to_ascii_lowercase()
                .contains("internal")
        );
    }
    assert!(
        server
            .state
            .sandbox_provider_requests
            .lock()
            .await
            .is_empty()
    );
    assert!(server.state.readiness_requests.lock().await.is_empty());
}

#[tokio::test]
async fn provider_readiness_update_redacts_provider_lookup_errors() {
    let server = run_server().await;
    seed_readiness_provider(&server).await;
    server
        .state
        .fail_provider_reads
        .store(true, Ordering::SeqCst);

    let output = run_readiness_cli(
        &server,
        &[
            "provider",
            "update",
            READINESS_PROVIDER,
            "--config",
            "region=test",
            "--wait",
            "--output",
            "json",
        ],
    )
    .await;

    assert!(!output.status.success());
    assert_readiness_output_redacted(&output);
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .to_ascii_lowercase()
            .contains("internal")
    );
    assert!(
        server
            .state
            .provider_update_requests
            .lock()
            .await
            .is_empty()
    );
    assert!(server.state.readiness_requests.lock().await.is_empty());
}

#[tokio::test]
async fn provider_readiness_status_rejects_wrong_first_receipt() {
    let server = run_server().await;
    seed_readiness_provider(&server).await;
    run::sandbox_provider_attach(
        &server.endpoint,
        "wrong-receipt",
        READINESS_PROVIDER,
        "default",
        &server.tls,
        run::ProviderWaitOptions::default(),
    )
    .await
    .unwrap();
    let original = latest_readiness_receipt(&server, "wrong-receipt").await;
    let mut replacement = original.clone();
    replacement.receipt_id = "another-mutation-receipt".to_string();
    replacement.mutation_id = "another-mutation".to_string();
    let mut status = readiness_status(
        ProviderReadinessState::Ready,
        ProviderReadinessReason::Unspecified,
        true,
    );
    status.receipt = Some(replacement);
    script_readiness(&server, "wrong-receipt", vec![Ok(status)]).await;

    let error = run::sandbox_provider_status(
        &server.endpoint,
        "wrong-receipt",
        READINESS_PROVIDER,
        &original.receipt_id,
        "default",
        &server.tls,
        provider_wait_options(),
    )
    .await
    .expect_err("a replacement receipt cannot satisfy the requested receipt");

    assert!(
        error
            .to_string()
            .contains("invalid provider readiness status")
    );
    assert_eq!(server.state.readiness_requests.lock().await.len(), 1);
}

#[tokio::test]
async fn provider_readiness_detach_wait_requires_revoked() {
    let server = run_server().await;
    seed_readiness_provider(&server).await;
    server.state.sandbox_providers.lock().await.insert(
        "detach-sandbox".to_string(),
        vec![READINESS_PROVIDER.to_string()],
    );
    script_readiness(
        &server,
        "detach-sandbox",
        vec![Ok(readiness_status(
            ProviderReadinessState::Ready,
            ProviderReadinessReason::Unspecified,
            true,
        ))],
    )
    .await;

    let error = run::sandbox_provider_detach(
        &server.endpoint,
        "detach-sandbox",
        READINESS_PROVIDER,
        "default",
        &server.tls,
        provider_wait_options(),
    )
    .await
    .expect_err("READY cannot establish detachment completion");
    assert!(
        error
            .to_string()
            .contains("readiness wait did not complete")
    );
    script_readiness(
        &server,
        "detach-sandbox",
        vec![
            Ok(readiness_status(
                ProviderReadinessState::Pending,
                ProviderReadinessReason::WaitingForProcess,
                false,
            )),
            Ok(readiness_status(
                ProviderReadinessState::Revoked,
                ProviderReadinessReason::Unspecified,
                true,
            )),
        ],
    )
    .await;

    // A repeated detach still returns a receipt and waits for revoked authority.
    run::sandbox_provider_detach(
        &server.endpoint,
        "detach-sandbox",
        READINESS_PROVIDER,
        "default",
        &server.tls,
        provider_wait_options(),
    )
    .await
    .expect("revoked receipt completes detachment");
    let requests = server.state.readiness_requests.lock().await;
    assert_eq!(requests.len(), 3);
    assert!(
        requests
            .iter()
            .all(|request| selected_workspace(&request.workspace_scope) == Some("default"))
    );
}

#[tokio::test]
async fn provider_readiness_update_reports_every_target_failure() {
    let server = run_server().await;
    seed_readiness_provider(&server).await;
    for sandbox in ["network-failed", "unsupported", "transport-failed"] {
        server
            .state
            .sandbox_providers
            .lock()
            .await
            .insert(sandbox.to_string(), vec![READINESS_PROVIDER.to_string()]);
    }
    script_readiness(
        &server,
        "network-failed",
        vec![Ok(readiness_status(
            ProviderReadinessState::Failed,
            ProviderReadinessReason::CredentialInstallFailed,
            false,
        ))],
    )
    .await;
    script_readiness(
        &server,
        "unsupported",
        vec![Ok(readiness_status(
            ProviderReadinessState::Withheld,
            ProviderReadinessReason::UnsupportedSupervisor,
            false,
        ))],
    )
    .await;
    script_readiness(&server, "transport-failed", vec![Err(Code::Internal)]).await;

    let output = run_readiness_cli(
        &server,
        &[
            "provider",
            "update",
            READINESS_PROVIDER,
            "--config",
            "region=test",
            "--wait",
            "--timeout",
            "1",
            "--output",
            "json",
        ],
    )
    .await;

    assert!(!output.status.success());
    assert_readiness_output_redacted(&output);
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("multi-target readiness JSON");
    let targets: HashMap<_, _> = value["targets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|target| {
            (
                target["receipt"]["desired"]["sandbox"].as_str().unwrap(),
                target,
            )
        })
        .collect();
    assert_eq!(targets.len(), 3);
    assert_eq!(targets["network-failed"]["state"], "failed");
    assert_eq!(
        targets["network-failed"]["reason"],
        "credential_install_failed"
    );
    assert_eq!(targets["unsupported"]["state"], "withheld");
    assert_eq!(targets["unsupported"]["reason"], "unsupported_supervisor");
    assert_eq!(
        targets["transport-failed"]["wait_outcome"],
        "observation_error"
    );
    assert!(!value["mutation_id"].as_str().unwrap().is_empty());
    assert!(
        targets
            .values()
            .all(|target| target["receipt"]["mutation_id"] == value["mutation_id"])
    );
    let requests = server.state.readiness_requests.lock().await;
    assert_eq!(requests.len(), 3);
    assert!(
        requests
            .iter()
            .all(|request| selected_workspace(&request.workspace_scope) == Some("default"))
    );
}

async fn install_test_profile(ts: &TestServer, id: &str, credential_key: &str) {
    ts.state.profiles.lock().await.insert(
        id.to_string(),
        ProviderProfile {
            id: id.to_string(),
            display_name: id.to_string(),
            credentials: vec![ProviderProfileCredential {
                name: "access_token".to_string(),
                env_vars: vec![credential_key.to_string()],
                required: true,
                ..Default::default()
            }],
            ..Default::default()
        },
    );
}

/// A readable provider must carry its stored type and profile workspace into
/// the update request. Policy interceptors evaluate the request before the
/// gateway merges it with stored state, so an update that omits them cannot be
/// authorized against the profile that owns the provider.
///
/// The stored `profile_workspace` is forwarded verbatim rather than recomputed
/// from the request workspace. The gateway treats it as immutable, so deriving
/// it here would look like a change and be rejected.
#[tokio::test]
async fn provider_update_preserves_stored_type_and_profile_workspace_when_readable() {
    let ts = run_server().await;

    run::provider_create(
        &ts.endpoint,
        "my-claude",
        "claude-code",
        false,
        &["API_KEY=abc".to_string()],
        false,
        &[],
        "default",
        &ts.tls,
    )
    .await
    .expect("provider create");

    run::provider_update(run::ProviderUpdateOptions {
        server: &ts.endpoint,
        name: "my-claude",
        from_existing: false,
        from_oidc_token: false,
        credentials: &["API_KEY=rotated".to_string()],
        config: &[],
        credential_expires_at: &[],
        workspace: "default",
        tls: &ts.tls,
        readiness: run::ProviderWaitOptions::default(),
    })
    .await
    .expect("provider update");

    let requests = ts.state.provider_update_requests.lock().await;
    let request = requests.last().expect("provider update request");
    // `claude` normalizes to the canonical `claude-code` at creation, so the
    // update carries the stored type rather than the alias the caller typed.
    assert_eq!(request.r#type, "claude-code");
    // Forwarded verbatim rather than recomputed. The gateway treats
    // profile_workspace as immutable, so any substitution here would look like
    // a change and be rejected.
    let stored = ts.state.providers.lock().await;
    let stored = stored.get("my-claude").expect("stored provider");
    assert_eq!(request.profile_workspace, stored.profile_workspace);
}

#[tokio::test]
async fn provider_delete_continues_after_entry_failure() {
    let ts = run_server().await;
    *ts.state.fail_delete_provider_message.lock().await =
        Some("simulated provider delete failure".to_string());

    let err = run::provider_delete(
        &ts.endpoint,
        &["failing-provider".to_string(), "later-provider".to_string()],
        "default",
        &ts.tls,
    )
    .await
    .expect_err("provider delete should report aggregate failure");

    let msg = err.to_string();
    assert!(
        msg.contains("failed to delete 1 provider: failing-provider"),
        "unexpected error: {msg}"
    );
    assert_eq!(
        ts.state.delete_provider_requests.lock().await.clone(),
        vec!["failing-provider".to_string(), "later-provider".to_string()]
    );
}

#[tokio::test]
async fn provider_profile_delete_continues_after_entry_failure() {
    let ts = run_server().await;
    *ts.state.fail_delete_provider_profile_message.lock().await =
        Some("simulated provider profile delete failure".to_string());

    let err = run::provider_profile_delete(
        &ts.endpoint,
        &["failing-profile".to_string(), "later-profile".to_string()],
        "default",
        &ts.tls,
    )
    .await
    .expect_err("provider profile delete should report aggregate failure");

    let msg = err.to_string();
    assert!(
        msg.contains("failed to delete 1 provider profile: failing-profile"),
        "unexpected error: {msg}"
    );
    assert_eq!(
        ts.state
            .delete_provider_profile_requests
            .lock()
            .await
            .clone(),
        vec!["failing-profile".to_string(), "later-profile".to_string()]
    );
}

#[tokio::test]
async fn provider_cli_run_functions_support_full_crud_flow() {
    let ts = run_server().await;

    run::provider_create(
        &ts.endpoint,
        "my-claude",
        "claude-code",
        false,
        &["API_KEY=abc".to_string()],
        false,
        &["profile=dev".to_string()],
        "default",
        &ts.tls,
    )
    .await
    .expect("provider create");

    run::provider_get(&ts.endpoint, "my-claude", "default", &ts.tls)
        .await
        .expect("provider get");
    run::provider_list(
        &ts.endpoint,
        100,
        "",
        false,
        "table",
        "default",
        false,
        &ts.tls,
    )
    .await
    .expect("provider list");

    // A credential-only update must remain available to callers that have
    // provider:write but not provider:read.
    ts.state.deny_provider_reads.store(true, Ordering::SeqCst);

    run::provider_update(run::ProviderUpdateOptions {
        server: &ts.endpoint,
        name: "my-claude",
        from_existing: false,
        from_oidc_token: false,
        credentials: &["API_KEY=rotated".to_string()],
        config: &["profile=prod".to_string()],
        credential_expires_at: &[],
        workspace: "default",
        tls: &ts.tls,
        readiness: run::ProviderWaitOptions::default(),
    })
    .await
    .expect("provider update");

    let requests = ts.state.provider_update_requests.lock().await;
    let request = requests.last().expect("provider update request");
    assert!(request.r#type.is_empty());
    assert!(request.profile_workspace.is_empty());
    drop(requests);

    run::provider_delete(&ts.endpoint, &["my-claude".to_string()], "default", &ts.tls)
        .await
        .expect("provider delete");
}

#[tokio::test]
async fn provider_list_profiles_cli_uses_profile_browsing_rpc() {
    let ts = run_server().await;

    run::provider_list_profiles(&ts.endpoint, "table", "default", &ts.tls)
        .await
        .expect("provider list-profiles");
}

#[tokio::test]
async fn provider_list_json_output() {
    let ts = run_server().await;

    // Create a provider with credentials and config
    run::provider_create(
        &ts.endpoint,
        "test-provider",
        "anthropic",
        false,
        &["ANTHROPIC_API_KEY=test-key".to_string()],
        false,
        &["region=us-west".to_string()],
        "default",
        &ts.tls,
    )
    .await
    .expect("provider create");

    // Test JSON output (verifies it doesn't error)
    run::provider_list(
        &ts.endpoint,
        100,
        "",
        false,
        "json",
        "default",
        false,
        &ts.tls,
    )
    .await
    .expect("provider list json should succeed");

    run::provider_delete(
        &ts.endpoint,
        &["test-provider".to_string()],
        "default",
        &ts.tls,
    )
    .await
    .expect("provider delete");
}

#[tokio::test]
async fn provider_list_yaml_output() {
    let ts = run_server().await;

    // Create a provider with credentials and config
    run::provider_create(
        &ts.endpoint,
        "test-provider",
        "anthropic",
        false,
        &["ANTHROPIC_API_KEY=test-key".to_string()],
        false,
        &["region=us-west".to_string()],
        "default",
        &ts.tls,
    )
    .await
    .expect("provider create");

    // Test YAML output (verifies it doesn't error)
    run::provider_list(
        &ts.endpoint,
        100,
        "",
        false,
        "yaml",
        "default",
        false,
        &ts.tls,
    )
    .await
    .expect("provider list yaml should succeed");

    run::provider_delete(
        &ts.endpoint,
        &["test-provider".to_string()],
        "default",
        &ts.tls,
    )
    .await
    .expect("provider delete");
}

#[tokio::test]
async fn provider_list_json_empty() {
    let ts = run_server().await;

    // Test JSON output with no providers (verifies it doesn't error on empty list)
    run::provider_list(
        &ts.endpoint,
        100,
        "",
        false,
        "json",
        "default",
        false,
        &ts.tls,
    )
    .await
    .expect("provider list json empty should succeed");
}

#[tokio::test]
async fn provider_refresh_cli_run_functions_wire_requests() {
    let ts = run_server().await;
    install_test_profile(&ts, "custom-graph", "MS_GRAPH_ACCESS_TOKEN").await;

    run::provider_create(
        &ts.endpoint,
        "my-graph",
        "custom-graph",
        false,
        &["MS_GRAPH_ACCESS_TOKEN=token".to_string()],
        false,
        &[],
        "default",
        &ts.tls,
    )
    .await
    .expect("provider create");

    run::provider_refresh_config(
        &ts.endpoint,
        run::ProviderRefreshConfigInput {
            name: "my-graph",
            credential_key: "MS_GRAPH_ACCESS_TOKEN",
            strategy: "oauth2_client_credentials",
            material: &["tenant_id=tenant".to_string()],
            secret_material_env: &[],
            secret_material_keys: &["client_secret".to_string()],
            credential_expires_at_ms: Some(1_767_225_600_000),
        },
        "default",
        &ts.tls,
    )
    .await
    .expect("provider refresh configure");
    run::provider_refresh_status(
        &ts.endpoint,
        "my-graph",
        Some("MS_GRAPH_ACCESS_TOKEN"),
        "default",
        &ts.tls,
    )
    .await
    .expect("provider refresh status");
    run::provider_rotate(
        &ts.endpoint,
        "my-graph",
        "MS_GRAPH_ACCESS_TOKEN",
        "default",
        &ts.tls,
    )
    .await
    .expect("provider refresh rotate");
    run::provider_refresh_delete(
        &ts.endpoint,
        "my-graph",
        "MS_GRAPH_ACCESS_TOKEN",
        "default",
        &ts.tls,
    )
    .await
    .expect("provider refresh delete");

    let requests = ts.state.refresh_requests.lock().await.clone();
    assert_eq!(
        requests,
        vec![
            ProviderRefreshRequestLog::Configure {
                provider: "my-graph".to_string(),
                credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
                material: HashMap::from([("tenant_id".to_string(), "tenant".to_string())]),
                secret_material_keys: vec!["client_secret".to_string()],
                expires_at_ms: Some(1_767_225_600_000),
            },
            ProviderRefreshRequestLog::Status {
                provider: "my-graph".to_string(),
                credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
            },
            ProviderRefreshRequestLog::Rotate {
                provider: "my-graph".to_string(),
                credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
            },
            ProviderRefreshRequestLog::Delete {
                provider: "my-graph".to_string(),
                credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
            },
        ]
    );
}

#[tokio::test]
async fn provider_refresh_configure_reads_secret_material_from_env_off_argv() {
    let ts = run_server().await;
    install_test_profile(&ts, "custom-chat", "GOOGLE_CHAT_ACCESS_TOKEN").await;

    run::provider_create(
        &ts.endpoint,
        "gc-bridge",
        "custom-chat",
        false,
        &["GOOGLE_CHAT_ACCESS_TOKEN=pending".to_string()],
        false,
        &[],
        "default",
        &ts.tls,
    )
    .await
    .expect("provider create");

    // The env value reaches the request and is auto-marked secret.
    let guard = EnvVarGuard::set(&[("OPENSHELL_ITEST_SME_PRIVATE_KEY", "pem-from-env")]);
    run::provider_refresh_config(
        &ts.endpoint,
        run::ProviderRefreshConfigInput {
            name: "gc-bridge",
            credential_key: "GOOGLE_CHAT_ACCESS_TOKEN",
            strategy: "google_service_account_jwt",
            material: &["client_email=bot@p.iam.gserviceaccount.com".to_string()],
            secret_material_env: &["private_key=OPENSHELL_ITEST_SME_PRIVATE_KEY".to_string()],
            secret_material_keys: &[],
            credential_expires_at_ms: None,
        },
        "default",
        &ts.tls,
    )
    .await
    .expect("provider refresh configure");
    drop(guard);

    let requests = ts.state.refresh_requests.lock().await.clone();
    assert_eq!(
        requests,
        vec![ProviderRefreshRequestLog::Configure {
            provider: "gc-bridge".to_string(),
            credential_key: "GOOGLE_CHAT_ACCESS_TOKEN".to_string(),
            material: HashMap::from([
                (
                    "client_email".to_string(),
                    "bot@p.iam.gserviceaccount.com".to_string()
                ),
                ("private_key".to_string(), "pem-from-env".to_string()),
            ]),
            secret_material_keys: vec!["private_key".to_string()],
            expires_at_ms: None,
        }]
    );
}

#[tokio::test]
async fn provider_refresh_configure_rejects_key_supplied_via_both_material_and_env() {
    let ts = run_server().await;

    let guard = EnvVarGuard::set(&[("OPENSHELL_ITEST_SME_DUP_KEY", "pem-from-env")]);
    let err = run::provider_refresh_config(
        &ts.endpoint,
        run::ProviderRefreshConfigInput {
            name: "gc-bridge",
            credential_key: "GOOGLE_CHAT_ACCESS_TOKEN",
            strategy: "google_service_account_jwt",
            material: &["private_key=argv-value".to_string()],
            secret_material_env: &["private_key=OPENSHELL_ITEST_SME_DUP_KEY".to_string()],
            secret_material_keys: &[],
            credential_expires_at_ms: None,
        },
        "default",
        &ts.tls,
    )
    .await
    .expect_err("duplicate key across --material and --secret-material-env should fail");
    drop(guard);

    assert!(
        err.to_string()
            .contains("duplicate material key 'private_key'")
    );
    // Rejected client-side: nothing reached the gateway.
    assert!(ts.state.refresh_requests.lock().await.is_empty());
}

#[tokio::test]
async fn provider_refresh_configure_fails_closed_when_secret_material_env_is_unset() {
    let ts = run_server().await;

    let err = run::provider_refresh_config(
        &ts.endpoint,
        run::ProviderRefreshConfigInput {
            name: "gc-bridge",
            credential_key: "GOOGLE_CHAT_ACCESS_TOKEN",
            strategy: "google_service_account_jwt",
            material: &[],
            secret_material_env: &["private_key=OPENSHELL_ITEST_SME_DEFINITELY_UNSET".to_string()],
            secret_material_keys: &[],
            credential_expires_at_ms: None,
        },
        "default",
        &ts.tls,
    )
    .await
    .expect_err("unset env should fail before any request is sent");

    assert!(err.to_string().contains(
        "requires local env var 'OPENSHELL_ITEST_SME_DEFINITELY_UNSET' to be set to a non-empty value"
    ));
    // Fails closed on the client side: nothing reached the gateway.
    assert!(ts.state.refresh_requests.lock().await.is_empty());
}

#[tokio::test]
async fn provider_create_allows_empty_credentials_for_gateway_refresh_profiles() {
    let ts = run_server().await;
    ts.state.profiles.lock().await.insert(
        "custom-refresh".to_string(),
        ProviderProfile {
            id: "custom-refresh".to_string(),
            display_name: "Custom Refresh".to_string(),
            credentials: vec![ProviderProfileCredential {
                name: "ACCESS_TOKEN".to_string(),
                required: true,
                refresh: Some(ProviderCredentialRefresh {
                    strategy: ProviderCredentialRefreshStrategy::Oauth2RefreshToken as i32,
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        },
    );

    run::provider_create_with_options(run::ProviderCreateOptions {
        server: &ts.endpoint,
        name: "custom-refresh-provider",
        provider_type: "custom-refresh",
        credentials: &[],
        credential_source: run::ProviderCreateCredentialSource::Runtime,
        config: &[],
        workspace: "default",
        profile_workspace: "default",
        tls: &ts.tls,
    })
    .await
    .expect("provider create");

    let stored = ts.state.providers.lock().await;
    let provider = stored.get("custom-refresh-provider").expect("provider");
    assert_eq!(provider.r#type, "custom-refresh");
    assert!(provider.credentials.is_empty());
}

#[tokio::test]
async fn provider_create_allows_no_source_for_runtime_resolved_profiles() {
    let ts = run_server().await;
    ts.state.profiles.lock().await.insert(
        "custom-refresh".to_string(),
        ProviderProfile {
            id: "custom-refresh".to_string(),
            display_name: "Custom Refresh".to_string(),
            credentials: vec![ProviderProfileCredential {
                name: "ACCESS_TOKEN".to_string(),
                required: true,
                refresh: Some(ProviderCredentialRefresh {
                    strategy: ProviderCredentialRefreshStrategy::Oauth2RefreshToken as i32,
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        },
    );

    run::provider_create(
        &ts.endpoint,
        "custom-refresh-provider",
        "custom-refresh",
        false,
        &[],
        false,
        &[],
        "default",
        &ts.tls,
    )
    .await
    .expect("runtime-resolved provider should not require a credential source");

    assert!(
        ts.state
            .providers
            .lock()
            .await
            .contains_key("custom-refresh-provider")
    );
}

#[tokio::test]
async fn provider_create_allows_credentialless_policy_profile() {
    let ts = run_server().await;

    run::provider_create(
        &ts.endpoint,
        "pypi",
        "pypi",
        false,
        &[],
        false,
        &[],
        "default",
        &ts.tls,
    )
    .await
    .expect("credential-less provider create");

    let provider = ts
        .state
        .providers
        .lock()
        .await
        .get("pypi")
        .cloned()
        .expect("pypi provider");
    assert!(provider.credentials.is_empty());
    assert_eq!(provider.r#type, "pypi");
}

#[tokio::test]
async fn sandbox_provider_cli_run_functions_wire_requests_and_idempotent_results() {
    let ts = run_server().await;

    run::provider_create(
        &ts.endpoint,
        "work-github",
        "github",
        false,
        &["GITHUB_TOKEN=ghp-test".to_string()],
        false,
        &[],
        "default",
        &ts.tls,
    )
    .await
    .expect("provider create");

    run::sandbox_provider_attach(
        &ts.endpoint,
        "dev-sandbox",
        "work-github",
        "default",
        &ts.tls,
        run::ProviderWaitOptions::default(),
    )
    .await
    .expect("sandbox provider attach");
    run::sandbox_provider_attach(
        &ts.endpoint,
        "dev-sandbox",
        "work-github",
        "default",
        &ts.tls,
        run::ProviderWaitOptions::default(),
    )
    .await
    .expect("sandbox provider attach is idempotent");
    run::sandbox_provider_list(&ts.endpoint, "dev-sandbox", "table", "default", &ts.tls)
        .await
        .expect("sandbox provider list");
    run::sandbox_provider_detach(
        &ts.endpoint,
        "dev-sandbox",
        "work-github",
        "default",
        &ts.tls,
        run::ProviderWaitOptions::default(),
    )
    .await
    .expect("sandbox provider detach");
    run::sandbox_provider_detach(
        &ts.endpoint,
        "dev-sandbox",
        "work-github",
        "default",
        &ts.tls,
        run::ProviderWaitOptions::default(),
    )
    .await
    .expect("sandbox provider detach is idempotent");

    let requests = ts.state.sandbox_provider_requests.lock().await.clone();
    assert_eq!(
        requests,
        vec![
            SandboxProviderRequestLog::Attach {
                sandbox_name: "dev-sandbox".to_string(),
                provider: "work-github".to_string(),
            },
            SandboxProviderRequestLog::Attach {
                sandbox_name: "dev-sandbox".to_string(),
                provider: "work-github".to_string(),
            },
            SandboxProviderRequestLog::List {
                sandbox_name: "dev-sandbox".to_string(),
            },
            SandboxProviderRequestLog::Detach {
                sandbox_name: "dev-sandbox".to_string(),
                provider: "work-github".to_string(),
            },
            SandboxProviderRequestLog::Detach {
                sandbox_name: "dev-sandbox".to_string(),
                provider: "work-github".to_string(),
            },
        ]
    );

    let providers = ts.state.sandbox_providers.lock().await;
    assert!(providers.get("dev-sandbox").is_none_or(Vec::is_empty));
}

#[tokio::test]
async fn sandbox_provider_attach_cli_surfaces_server_errors() {
    let ts = run_server().await;

    let err = run::sandbox_provider_attach(
        &ts.endpoint,
        "dev-sandbox",
        "missing-provider",
        "default",
        &ts.tls,
        run::ProviderWaitOptions::default(),
    )
    .await
    .expect_err("missing provider should fail");

    assert!(err.to_string().contains("provider attachment failed"));
    assert_eq!(
        ts.state.sandbox_provider_requests.lock().await.as_slice(),
        [SandboxProviderRequestLog::Attach {
            sandbox_name: "dev-sandbox".to_string(),
            provider: "missing-provider".to_string(),
        }]
    );
}

#[tokio::test]
async fn provider_profile_cli_run_functions_support_custom_profiles() {
    let ts = run_server().await;
    let dir = tempfile::tempdir().unwrap();
    let profile_path = dir.path().join("custom-api.yaml");
    std::fs::write(
        &profile_path,
        r"
id: custom-api
display_name: Custom API
category: other
credentials:
  - name: api_key
    env_vars: [CUSTOM_API_KEY]
    auth_style: bearer
    header_name: authorization
discovery:
  credentials: [api_key]
endpoints:
  - host: api.custom.example
    port: 443
binaries: [/usr/bin/custom]
",
    )
    .unwrap();

    run::provider_profile_lint(&ts.endpoint, Some(&profile_path), None, "default", &ts.tls)
        .await
        .expect("profile lint");
    run::provider_profile_import(&ts.endpoint, Some(&profile_path), None, "default", &ts.tls)
        .await
        .expect("profile import");
    let exported_yaml =
        run::provider_profile_export_text(&ts.endpoint, "custom-api", "yaml", "default", &ts.tls)
            .await
            .expect("profile export text");
    assert!(exported_yaml.contains("resource_version: 1"));
    let updated_yaml = exported_yaml
        .replace(
            "display_name: Custom API",
            "display_name: Custom API Updated",
        )
        .replace("host: api.custom.example", "host: api.updated.example");
    std::fs::write(&profile_path, updated_yaml).unwrap();
    run::provider_profile_update(
        &ts.endpoint,
        "custom-api",
        &profile_path,
        "default",
        &ts.tls,
    )
    .await
    .expect("profile update");
    assert_eq!(
        ts.state
            .profiles
            .lock()
            .await
            .get("custom-api")
            .and_then(|profile| profile.endpoints.first())
            .map(|endpoint| endpoint.host.as_str()),
        Some("api.updated.example")
    );
    run::provider_profile_export(&ts.endpoint, "custom-api", "yaml", "default", &ts.tls)
        .await
        .expect("profile export");
    run::provider_list_profiles(&ts.endpoint, "json", "default", &ts.tls)
        .await
        .expect("provider list-profiles json");
    run::provider_create(
        &ts.endpoint,
        "custom-provider",
        "custom-api",
        false,
        &["CUSTOM_API_KEY=abc".to_string()],
        false,
        &[],
        "default",
        &ts.tls,
    )
    .await
    .expect("custom profile provider create");

    let provider = ts
        .state
        .providers
        .lock()
        .await
        .get("custom-provider")
        .cloned()
        .expect("custom provider should be stored");
    assert_eq!(provider.r#type, "custom-api");

    let mut custom_alt_profile = ts
        .state
        .profiles
        .lock()
        .await
        .get("custom-api")
        .cloned()
        .expect("custom-api profile should be stored");
    custom_alt_profile.id = "custom-alt".to_string();
    ts.state
        .profiles
        .lock()
        .await
        .insert("custom-alt".to_string(), custom_alt_profile);

    run::provider_delete(
        &ts.endpoint,
        &["custom-provider".to_string()],
        "default",
        &ts.tls,
    )
    .await
    .expect("custom provider delete");
    run::provider_profile_delete(
        &ts.endpoint,
        &["custom-api".to_string(), "custom-alt".to_string()],
        "default",
        &ts.tls,
    )
    .await
    .expect("profile delete");
    let profiles = ts.state.profiles.lock().await;
    assert!(!profiles.contains_key("custom-api"));
    assert!(!profiles.contains_key("custom-alt"));
}

#[tokio::test]
async fn provider_create_from_existing_uses_profile_discovery() {
    let ts = run_server().await;
    ts.state.profiles.lock().await.insert(
        "custom-discovery".to_string(),
        ProviderProfile {
            id: "custom-discovery".to_string(),
            display_name: "Custom Discovery".to_string(),
            credentials: vec![ProviderProfileCredential {
                name: "api_key".to_string(),
                env_vars: vec!["CUSTOM_DISCOVERY_API_KEY".to_string()],
                required: true,
                ..Default::default()
            }],
            discovery: Some(ProviderProfileDiscovery {
                credentials: vec!["api_key".to_string()],
            }),
            ..Default::default()
        },
    );
    let _env = EnvVarGuard::set(&[("CUSTOM_DISCOVERY_API_KEY", "profile-secret")]);

    run::provider_create(
        &ts.endpoint,
        "custom-discovered",
        "custom-discovery",
        true,
        &[],
        false,
        &[],
        "default",
        &ts.tls,
    )
    .await
    .expect("profile-backed provider create --from-existing");

    let provider = ts
        .state
        .providers
        .lock()
        .await
        .get("custom-discovered")
        .cloned()
        .expect("custom provider should be stored");
    assert_eq!(provider.r#type, "custom-discovery");
    assert_eq!(
        provider.credentials.get("CUSTOM_DISCOVERY_API_KEY"),
        Some(&"profile-secret".to_string())
    );
}

#[tokio::test]
async fn provider_create_from_existing_uses_builtin_profile_discovery() {
    let ts = run_server().await;
    let _env = EnvVarGuard::set(&[("OPENAI_API_KEY", "legacy-openai-secret")]);

    run::provider_create(
        &ts.endpoint,
        "legacy-openai",
        "openai",
        true,
        &[],
        false,
        &[],
        "default",
        &ts.tls,
    )
    .await
    .expect("legacy provider create --from-existing");

    let provider = ts
        .state
        .providers
        .lock()
        .await
        .get("legacy-openai")
        .cloned()
        .expect("legacy provider should be stored");
    assert_eq!(provider.r#type, "openai");
    assert_eq!(
        provider.credentials.get("OPENAI_API_KEY"),
        Some(&"legacy-openai-secret".to_string())
    );
}

#[tokio::test]
async fn provider_create_from_existing_vertex_discovers_credentials_and_config() {
    let ts = run_server().await;
    let _env = EnvVarGuard::set(&[
        ("VERTEX_AI_TOKEN", "ya29.vertex-v2-fallback"),
        ("VERTEX_AI_PROJECT_ID", "vertex-v2-project"),
        ("VERTEX_AI_REGION", "europe-west4"),
        (
            "GOOGLE_VERTEX_AI_BASE_URL",
            "https://aiplatform.googleapis.com/v1beta1/projects/vertex-v2-project/locations/global/endpoints/openapi",
        ),
        ("VERTEX_AI_PUBLISHER", "anthropic"),
    ]);

    run::provider_create(
        &ts.endpoint,
        "vertex-v2-discovered",
        "google-vertex-ai",
        true,
        &[],
        false,
        &[],
        "default",
        &ts.tls,
    )
    .await
    .expect("vertex provider create --from-existing with v2 enabled");

    let provider = ts
        .state
        .providers
        .lock()
        .await
        .get("vertex-v2-discovered")
        .cloned()
        .expect("vertex provider should be stored");
    assert_eq!(provider.r#type, "google-vertex-ai");
    assert_eq!(
        provider.credentials.get("VERTEX_AI_TOKEN"),
        Some(&"ya29.vertex-v2-fallback".to_string())
    );
    assert_eq!(
        provider.config.get("VERTEX_AI_PROJECT_ID"),
        Some(&"vertex-v2-project".to_string())
    );
    assert_eq!(
        provider.config.get("VERTEX_AI_REGION"),
        Some(&"europe-west4".to_string())
    );
    assert_eq!(
        provider.config.get("GOOGLE_VERTEX_AI_BASE_URL"),
        Some(
            &"https://aiplatform.googleapis.com/v1beta1/projects/vertex-v2-project/locations/global/endpoints/openapi"
                .to_string()
        )
    );
    assert_eq!(
        provider.config.get("VERTEX_AI_PUBLISHER"),
        Some(&"anthropic".to_string())
    );
}

#[tokio::test]
async fn provider_create_from_existing_requires_profile() {
    let ts = run_server().await;
    // Use "generic" which is a normalised type but has no built-in provider
    // profile, so v2 profile-based discovery fails with the expected message.
    let _env = EnvVarGuard::set(&[("GENERIC_API_KEY", "some-secret")]);

    let err = run::provider_create(
        &ts.endpoint,
        "v2-generic",
        "generic",
        true,
        &[],
        false,
        &[],
        "default",
        &ts.tls,
    )
    .await
    .expect_err("v2 discovery without a profile should fail");

    assert!(
        err.to_string()
            .contains("import a matching profile before using this provider type"),
        "unexpected error: {err}"
    );
    assert!(!ts.state.providers.lock().await.contains_key("v2-generic"));
}

#[tokio::test]
async fn provider_create_from_existing_fails_when_profile_discovery_finds_nothing() {
    let ts = run_server().await;
    ts.state.profiles.lock().await.insert(
        "empty-discovery".to_string(),
        ProviderProfile {
            id: "empty-discovery".to_string(),
            display_name: "Empty Discovery".to_string(),
            credentials: vec![ProviderProfileCredential {
                name: "api_key".to_string(),
                env_vars: vec!["CUSTOM_DISCOVERY_TOKEN_NOT_SET_1460".to_string()],
                required: false,
                ..Default::default()
            }],
            discovery: Some(ProviderProfileDiscovery {
                credentials: vec!["api_key".to_string()],
            }),
            ..Default::default()
        },
    );

    let err = run::provider_create(
        &ts.endpoint,
        "empty-discovered",
        "empty-discovery",
        true,
        &[],
        false,
        &[],
        "default",
        &ts.tls,
    )
    .await
    .expect_err("empty profile-backed discovery should fail");

    assert!(
        err.to_string()
            .contains("no existing local credentials/config found"),
        "unexpected error: {err}"
    );
    assert!(
        !ts.state
            .providers
            .lock()
            .await
            .contains_key("empty-discovered")
    );
}

#[tokio::test]
async fn provider_update_from_existing_uses_profile_discovery() {
    let ts = run_server().await;
    ts.state.profiles.lock().await.insert(
        "custom-update-discovery".to_string(),
        ProviderProfile {
            id: "custom-update-discovery".to_string(),
            display_name: "Custom Update Discovery".to_string(),
            credentials: vec![ProviderProfileCredential {
                name: "api_key".to_string(),
                env_vars: vec!["CUSTOM_UPDATE_DISCOVERY_API_KEY".to_string()],
                required: true,
                ..Default::default()
            }],
            discovery: Some(ProviderProfileDiscovery {
                credentials: vec!["api_key".to_string()],
            }),
            ..Default::default()
        },
    );
    ts.state.providers.lock().await.insert(
        "custom-update".to_string(),
        Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "id-custom-update".to_string(),
                name: "custom-update".to_string(),
                ..Default::default()
            }),
            r#type: "custom-update-discovery".to_string(),
            credentials: HashMap::new(),
            config: HashMap::new(),
            credential_expiration_times: HashMap::new(),
            profile_workspace: "default".to_string(),
            credential_handles: HashMap::new(),
        },
    );
    let _env = EnvVarGuard::set(&[("CUSTOM_UPDATE_DISCOVERY_API_KEY", "updated-profile-secret")]);

    run::provider_update(run::ProviderUpdateOptions {
        server: &ts.endpoint,
        name: "custom-update",
        from_existing: true,
        from_oidc_token: false,
        credentials: &[],
        config: &[],
        credential_expires_at: &[],
        workspace: "default",
        tls: &ts.tls,
        readiness: run::ProviderWaitOptions::default(),
    })
    .await
    .expect("profile-backed provider update --from-existing");

    let provider = ts
        .state
        .providers
        .lock()
        .await
        .get("custom-update")
        .cloned()
        .expect("custom provider should still be stored");
    assert_eq!(
        provider.credentials.get("CUSTOM_UPDATE_DISCOVERY_API_KEY"),
        Some(&"updated-profile-secret".to_string())
    );
}

#[tokio::test]
async fn provider_update_from_existing_preserves_global_profile_scope() {
    let ts = run_server().await;
    let profile_id = "shadowed-update-discovery";
    for (profile_workspace, env_var) in [
        ("", "GLOBAL_UPDATE_DISCOVERY_API_KEY"),
        ("default", "WORKSPACE_UPDATE_DISCOVERY_API_KEY"),
    ] {
        ts.state.scoped_profiles.lock().await.insert(
            (profile_workspace.to_string(), profile_id.to_string()),
            ProviderProfile {
                id: profile_id.to_string(),
                credentials: vec![ProviderProfileCredential {
                    name: "api_key".to_string(),
                    env_vars: vec![env_var.to_string()],
                    required: true,
                    ..Default::default()
                }],
                discovery: Some(ProviderProfileDiscovery {
                    credentials: vec!["api_key".to_string()],
                }),
                ..Default::default()
            },
        );
    }
    ts.state.providers.lock().await.insert(
        "global-update".to_string(),
        Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "id-global-update".to_string(),
                name: "global-update".to_string(),
                workspace: "default".to_string(),
                ..Default::default()
            }),
            r#type: profile_id.to_string(),
            profile_workspace: String::new(),
            ..Default::default()
        },
    );
    let _env = EnvVarGuard::set(&[
        ("GLOBAL_UPDATE_DISCOVERY_API_KEY", "global-secret"),
        ("WORKSPACE_UPDATE_DISCOVERY_API_KEY", "workspace-secret"),
    ]);

    run::provider_update(run::ProviderUpdateOptions {
        server: &ts.endpoint,
        name: "global-update",
        from_existing: true,
        from_oidc_token: false,
        credentials: &[],
        config: &[],
        credential_expires_at: &[],
        workspace: "default",
        tls: &ts.tls,
        readiness: run::ProviderWaitOptions::default(),
    })
    .await
    .expect("global profile-backed provider update --from-existing");

    let provider = ts
        .state
        .providers
        .lock()
        .await
        .get("global-update")
        .cloned()
        .expect("global provider should still be stored");
    assert_eq!(
        provider.credentials.get("GLOBAL_UPDATE_DISCOVERY_API_KEY"),
        Some(&"global-secret".to_string())
    );
    assert!(
        !provider
            .credentials
            .contains_key("WORKSPACE_UPDATE_DISCOVERY_API_KEY")
    );
}

#[tokio::test]
async fn provider_update_from_oidc_token_preserves_global_profile_scope() {
    let ts = run_server().await;
    let profile_id = "shadowed-oidc-update";
    for (profile_workspace, subject_credential) in [
        ("", "GLOBAL_SUBJECT_TOKEN"),
        ("default", "WORKSPACE_SUBJECT_TOKEN"),
    ] {
        ts.state.scoped_profiles.lock().await.insert(
            (profile_workspace.to_string(), profile_id.to_string()),
            ProviderProfile {
                id: profile_id.to_string(),
                credentials: vec![ProviderProfileCredential {
                    name: "dynamic_token".to_string(),
                    token_grant: Some(ProviderCredentialTokenGrant {
                        grant_type: ProviderCredentialTokenGrantType::TokenExchange as i32,
                        subject_token: Some(ProviderCredentialTokenGrantSubjectToken {
                            source: "provider_credential".to_string(),
                            credential: subject_credential.to_string(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
    }
    ts.state.providers.lock().await.insert(
        "global-oidc-update".to_string(),
        Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "id-global-oidc-update".to_string(),
                name: "global-oidc-update".to_string(),
                workspace: "default".to_string(),
                ..Default::default()
            }),
            r#type: profile_id.to_string(),
            profile_workspace: String::new(),
            ..Default::default()
        },
    );

    let err = run::provider_update(run::ProviderUpdateOptions {
        server: &ts.endpoint,
        name: "global-oidc-update",
        from_existing: false,
        from_oidc_token: true,
        credentials: &["GLOBAL_SUBJECT_TOKEN".to_string()],
        config: &[],
        credential_expires_at: &[],
        workspace: "default",
        tls: &ts.tls,
        readiness: run::ProviderWaitOptions::default(),
    })
    .await
    .expect_err("unnamed test gateway should stop after profile validation");

    assert!(
        err.to_string().contains("active named OIDC gateway"),
        "global profile should accept GLOBAL_SUBJECT_TOKEN before OIDC loading: {err}"
    );
}

#[tokio::test]
async fn provider_profile_import_from_directory_imports_supported_profile_files() {
    let ts = run_server().await;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("custom-yaml.yaml"),
        r"
id: custom-yaml
display_name: Custom YAML
category: other
endpoints:
  - host: api.yaml.example
    port: 443
binaries: [/usr/bin/yaml-client]
",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("custom-json.json"),
        r#"{
  "id": "custom-json",
  "display_name": "Custom JSON",
  "description": "",
  "category": "other",
  "credentials": [],
  "endpoints": [{"host": "api.json.example", "port": 443}],
  "binaries": ["/usr/bin/json-client"],
  "inference_capable": false
}"#,
    )
    .unwrap();
    std::fs::write(dir.path().join("notes.txt"), "ignored").unwrap();

    run::provider_profile_import(&ts.endpoint, None, Some(dir.path()), "default", &ts.tls)
        .await
        .expect("profile import --from");

    run::provider_profile_export(&ts.endpoint, "custom-yaml", "yaml", "default", &ts.tls)
        .await
        .expect("custom-yaml should be imported");
    run::provider_profile_export(&ts.endpoint, "custom-json", "json", "default", &ts.tls)
        .await
        .expect("custom-json should be imported");
}

#[tokio::test]
async fn provider_profile_import_preserves_advanced_network_policy_fields() {
    let ts = run_server().await;
    let dir = tempfile::tempdir().unwrap();
    let profile_path = dir.path().join("advanced-api.yaml");
    std::fs::write(
        &profile_path,
        r"
id: advanced-api
display_name: Advanced API
category: other
endpoints:
  - host: api.advanced.example
    ports: [443, 8443]
    protocol: rest
    tls: terminate
    enforcement: enforce
    rules:
      - allow:
          method: GET
          path: /v1/**
    allowed_ips: [10.0.0.0/24]
    deny_rules:
      - method: POST
        path: /admin/**
    allow_encoded_slash: true
    path: /v1
binaries:
  - path: /usr/bin/advanced
",
    )
    .unwrap();

    run::provider_profile_import(&ts.endpoint, Some(&profile_path), None, "default", &ts.tls)
        .await
        .expect("profile import");

    let mut client = openshell_cli::tls::grpc_client(&ts.endpoint, &ts.tls)
        .await
        .expect("grpc client should connect");
    let profile = client
        .get_provider_profile(openshell_core::proto::GetProviderProfileRequest {
            id: "advanced-api".to_string(),
            workspace_scope: None,
        })
        .await
        .expect("get provider profile")
        .into_inner()
        .profile
        .expect("profile should exist");
    let endpoint = profile.endpoints.first().expect("endpoint should exist");
    assert_eq!(endpoint.ports, vec![443, 8443]);
    assert_eq!(endpoint.rules.len(), 1);
    assert_eq!(endpoint.deny_rules.len(), 1);
    assert_eq!(endpoint.allowed_ips, vec!["10.0.0.0/24"]);
    assert!(endpoint.allow_encoded_slash);
    assert_eq!(endpoint.path, "/v1");
    assert_eq!(profile.binaries[0].path, "/usr/bin/advanced");
}

#[tokio::test]
async fn provider_profile_import_from_directory_parse_error_prevents_partial_import() {
    let ts = run_server().await;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("custom-good.yaml"),
        r"
id: custom-good
display_name: Custom Good
category: other
endpoints:
  - host: api.good.example
    port: 443
",
    )
    .unwrap();
    std::fs::write(dir.path().join("broken.yaml"), "id: [\n").unwrap();

    let err =
        run::provider_profile_import(&ts.endpoint, None, Some(dir.path()), "default", &ts.tls)
            .await
            .expect_err("profile import --from should fail on parse errors");
    assert!(
        err.to_string().contains("provider profile import failed"),
        "unexpected error: {err}"
    );

    run::provider_profile_export(&ts.endpoint, "custom-good", "yaml", "default", &ts.tls)
        .await
        .expect_err("valid profiles should not be partially imported after local parse errors");
}

#[tokio::test]
async fn provider_profile_lint_from_directory_reports_parse_errors_without_importing() {
    let ts = run_server().await;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("custom-good.yaml"),
        r"
id: custom-good
display_name: Custom Good
category: other
endpoints:
  - host: api.good.example
    port: 443
",
    )
    .unwrap();
    std::fs::write(dir.path().join("broken.yaml"), "id: [\n").unwrap();

    let err = run::provider_profile_lint(&ts.endpoint, None, Some(dir.path()), "default", &ts.tls)
        .await
        .expect_err("profile lint --from should fail on parse errors");
    assert!(
        err.to_string().contains("provider profile lint failed"),
        "unexpected error: {err}"
    );

    run::provider_profile_export(&ts.endpoint, "custom-good", "yaml", "default", &ts.tls)
        .await
        .expect_err("lint should not import valid profiles");
}

#[tokio::test]
async fn provider_create_rejects_key_only_credentials_without_local_env_value() {
    let ts = run_server().await;

    let err = run::provider_create(
        &ts.endpoint,
        "bad-provider",
        "claude-code",
        false,
        &["INVALID_PAIR".to_string()],
        false,
        &[],
        "default",
        &ts.tls,
    )
    .await
    .expect_err("invalid key=value should fail");

    assert!(
        err.to_string()
            .contains("requires local env var 'INVALID_PAIR' to be set to a non-empty value"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn provider_create_rejects_profileless_generic_type() {
    let ts = run_server().await;
    let _guard = EnvVarGuard::set(&[("NAV_GENERIC_TEST_KEY", "generic-value")]);

    let err = run::provider_create(
        &ts.endpoint,
        "my-generic",
        "generic",
        false,
        &["NAV_GENERIC_TEST_KEY".to_string()],
        false,
        &[],
        "default",
        &ts.tls,
    )
    .await
    .expect_err("profileless generic provider creation should fail");

    assert!(
        err.to_string()
            .contains("provider profile 'generic' not found"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn provider_create_sends_inline_credentials() {
    let ts = run_server().await;

    run::provider_create_with_options(run::ProviderCreateOptions {
        server: &ts.endpoint,
        name: "openai-inline",
        provider_type: "openai",
        credentials: &["OPENAI_API_KEY=sk-test".to_string()],
        credential_source: run::ProviderCreateCredentialSource::ExplicitCredentials,
        config: &[],
        workspace: "default",
        profile_workspace: "default",
        tls: &ts.tls,
    })
    .await
    .expect("provider create with inline credential");

    let stored = ts.state.providers.lock().await;
    assert_eq!(
        stored
            .get("openai-inline")
            .and_then(|provider| provider.credentials.get("OPENAI_API_KEY"))
            .map(String::as_str),
        Some("sk-test")
    );
    assert!(
        stored
            .get("openai-inline")
            .expect("provider")
            .credential_handles
            .is_empty()
    );
}

#[tokio::test]
async fn provider_create_prefers_exact_imported_alias_profile() {
    let ts = run_server().await;
    install_test_profile(&ts, "gh", "GITHUB_TOKEN").await;

    run::provider_create_with_options(run::ProviderCreateOptions {
        server: &ts.endpoint,
        name: "enterprise-github",
        provider_type: "gh",
        credentials: &["GITHUB_TOKEN=test-token".to_string()],
        credential_source: run::ProviderCreateCredentialSource::ExplicitCredentials,
        config: &[],
        workspace: "default",
        profile_workspace: "default",
        tls: &ts.tls,
    })
    .await
    .expect("create provider from exact imported alias profile");

    let stored = ts.state.providers.lock().await;
    let provider = stored.get("enterprise-github").expect("provider");
    assert_eq!(provider.r#type, "gh");
    assert_eq!(
        provider.credentials.get("GITHUB_TOKEN").map(String::as_str),
        Some("test-token")
    );
}

#[tokio::test]
async fn provider_create_rejects_combined_from_existing_and_credentials() {
    let ts = run_server().await;

    let err = run::provider_create(
        &ts.endpoint,
        "bad-provider",
        "claude-code",
        true,
        &["API_KEY=abc".to_string()],
        false,
        &[],
        "default",
        &ts.tls,
    )
    .await
    .expect_err("from-existing and credentials should be mutually exclusive");

    assert!(
        err.to_string()
            .contains("--from-existing cannot be combined with --credential"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn provider_create_rejects_combined_from_gcloud_adc_and_from_existing() {
    let ts = run_server().await;

    let err = run::provider_create(
        &ts.endpoint,
        "bad-vertex-provider",
        "google-vertex-ai",
        true,
        &[],
        true,
        &[],
        "default",
        &ts.tls,
    )
    .await
    .expect_err("from-gcloud-adc and from-existing should be mutually exclusive");

    assert!(
        err.to_string()
            .contains("--from-gcloud-adc cannot be combined with --from-existing, --from-oidc-token, or --credential"),
        "unexpected error: {err}"
    );
    assert!(ts.state.providers.lock().await.is_empty());
}

#[tokio::test]
async fn provider_create_rejects_combined_from_gcloud_adc_and_credentials() {
    let ts = run_server().await;

    let err = run::provider_create(
        &ts.endpoint,
        "bad-vertex-provider",
        "google-vertex-ai",
        false,
        &["GOOGLE_VERTEX_AI_TOKEN=token".to_string()],
        true,
        &[],
        "default",
        &ts.tls,
    )
    .await
    .expect_err("from-gcloud-adc and credentials should be mutually exclusive");

    assert!(
        err.to_string()
            .contains("--from-gcloud-adc cannot be combined with --from-existing, --from-oidc-token, or --credential"),
        "unexpected error: {err}"
    );
    assert!(ts.state.providers.lock().await.is_empty());
}

#[tokio::test]
async fn provider_create_rejects_empty_env_var_for_key_only_credential() {
    let ts = run_server().await;
    let _guard = EnvVarGuard::set(&[("NVIDIA_API_KEY", "")]);

    let err = run::provider_create(
        &ts.endpoint,
        "bad-provider",
        "nvidia",
        false,
        &["NVIDIA_API_KEY".to_string()],
        false,
        &[],
        "default",
        &ts.tls,
    )
    .await
    .expect_err("empty env var should be rejected");

    assert!(
        err.to_string()
            .contains("requires local env var 'NVIDIA_API_KEY' to be set to a non-empty value"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn provider_create_supports_nvidia_type_with_nvidia_api_key() {
    let ts = run_server().await;
    let _guard = EnvVarGuard::set(&[("NVIDIA_API_KEY", "nvapi-live-test")]);

    run::provider_create(
        &ts.endpoint,
        "my-nvidia",
        "nvidia",
        false,
        &["NVIDIA_API_KEY".to_string()],
        false,
        &[],
        "default",
        &ts.tls,
    )
    .await
    .expect("provider create");

    let mut client = openshell_cli::tls::grpc_client(&ts.endpoint, &ts.tls)
        .await
        .expect("grpc client should connect");
    let response = client
        .get_provider(GetProviderRequest {
            name: "my-nvidia".to_string(),
            workspace_scope: Some(openshell_core::proto::workspace_selector(
                "default".to_string(),
            )),
        })
        .await
        .expect("get provider should succeed")
        .into_inner();
    let provider = response.provider.expect("provider should exist");
    assert_eq!(provider.r#type, "nvidia");
    assert_eq!(
        provider.credentials.get("NVIDIA_API_KEY"),
        Some(&"nvapi-live-test".to_string())
    );
}

// ── --from-gcloud-adc tests ───────────────────────────────────────────────────

#[tokio::test]
async fn provider_create_from_gcloud_adc_happy_path() {
    let ts = run_server().await;

    // Write a temp ADC file simulating a valid authorized_user credential.
    let adc_content = serde_json::json!({
        "type": "authorized_user",
        "client_id": "test-client-id.apps.googleusercontent.com",
        "client_secret": "test-client-secret",
        "refresh_token": "1//test-refresh-token"
    });
    let adc_file = tempfile::NamedTempFile::new().unwrap();
    serde_json::to_writer(&adc_file, &adc_content).unwrap();

    // Point GOOGLE_APPLICATION_CREDENTIALS at the temp file so read_gcloud_adc
    // picks it up without touching the real ~/.config/gcloud/ path.
    let adc_path = adc_file.path().to_str().unwrap().to_string();
    let _guard = EnvVarGuard::set(&[("GOOGLE_APPLICATION_CREDENTIALS", &adc_path)]);

    run::provider_create(
        &ts.endpoint,
        "my-vertex",
        "google-vertex-ai",
        false,
        &[],  // no explicit credentials; refresh bootstrap covers it
        true, // from_gcloud_adc
        &[],
        "default",
        &ts.tls,
    )
    .await
    .expect("provider_create with --from-gcloud-adc should succeed");

    // Provider must exist in the server state.
    let providers = ts.state.providers.lock().await;
    let provider = providers
        .get("my-vertex")
        .expect("provider should be stored after create");
    assert_eq!(provider.r#type, "google-vertex-ai");
    assert_eq!(
        provider
            .credentials
            .get("GOOGLE_VERTEX_AI_TOKEN")
            .map(String::as_str),
        Some("minted-GOOGLE_VERTEX_AI_TOKEN"),
        "initial rotate should materialize a usable access token"
    );
    drop(providers);

    // ADC bootstrap must configure refresh and immediately mint the first token.
    let requests = ts.state.refresh_requests.lock().await.clone();
    assert_eq!(
        requests.len(),
        2,
        "expected configure + rotate refresh requests"
    );
    assert!(matches!(
        &requests[0],
        ProviderRefreshRequestLog::Configure {
            provider,
            credential_key,
            expires_at_ms: None,
            ..
        } if provider == "my-vertex" && credential_key == "GOOGLE_VERTEX_AI_TOKEN"
    ));
    assert_eq!(
        requests[1],
        ProviderRefreshRequestLog::Rotate {
            provider: "my-vertex".to_string(),
            credential_key: "GOOGLE_VERTEX_AI_TOKEN".to_string(),
        }
    );

    // The refresh status must record the ADC material keys.
    let refresh_statuses = ts.state.refresh_statuses.lock().await;
    let status = refresh_statuses
        .get(&(
            "my-vertex".to_string(),
            "GOOGLE_VERTEX_AI_TOKEN".to_string(),
        ))
        .expect("refresh status should be stored");
    assert_eq!(
        status.strategy,
        ProviderCredentialRefreshStrategy::Oauth2RefreshToken as i32
    );
}

#[tokio::test]
async fn provider_create_from_gcloud_adc_rejects_service_account() {
    let ts = run_server().await;

    // Write a temp ADC file with type=service_account.
    let adc_content = serde_json::json!({
        "type": "service_account",
        "project_id": "my-project",
        "private_key_id": "key-id",
        "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...",
        "client_email": "sa@my-project.iam.gserviceaccount.com"
    });
    let adc_file = tempfile::NamedTempFile::new().unwrap();
    serde_json::to_writer(&adc_file, &adc_content).unwrap();

    let adc_path = adc_file.path().to_str().unwrap().to_string();
    let _guard = EnvVarGuard::set(&[("GOOGLE_APPLICATION_CREDENTIALS", &adc_path)]);

    let err = run::provider_create(
        &ts.endpoint,
        "my-vertex-sa",
        "google-vertex-ai",
        false,
        &[],
        true,
        &[],
        "default",
        &ts.tls,
    )
    .await
    .expect_err("service_account ADC should be rejected");

    assert!(
        err.to_string()
            .contains("GOOGLE_VERTEX_AI_SERVICE_ACCOUNT_TOKEN"),
        "error should mention the service-account token key, got: {err}"
    );

    // create_provider must NOT have been called — no provider stored.
    let providers = ts.state.providers.lock().await;
    assert!(
        providers.is_empty(),
        "no provider should have been created on pre-flight failure"
    );
}

#[tokio::test]
async fn provider_create_from_gcloud_adc_missing_file() {
    let ts = run_server().await;

    // Point to a path that does not exist.
    let _guard = EnvVarGuard::set(&[(
        "GOOGLE_APPLICATION_CREDENTIALS",
        "/tmp/nonexistent-adc-file-openshell-test.json",
    )]);

    let err = run::provider_create(
        &ts.endpoint,
        "my-vertex-missing",
        "google-vertex-ai",
        false,
        &[],
        true,
        &[],
        "default",
        &ts.tls,
    )
    .await
    .expect_err("missing ADC file should produce an error");

    // Error must mention the file path or the read failure.
    let msg = err.to_string();
    assert!(
        msg.contains("nonexistent-adc-file-openshell-test.json")
            || msg.contains("failed to read gcloud ADC file"),
        "error should reference the missing file, got: {msg}"
    );

    // create_provider must NOT have been called — no provider stored.
    let providers = ts.state.providers.lock().await;
    assert!(
        providers.is_empty(),
        "no provider should have been created on pre-flight failure"
    );
}

#[tokio::test]
async fn provider_create_from_gcloud_adc_rejects_wrong_provider_type_before_credential_check() {
    let ts = run_server().await;

    let err = run::provider_create(
        &ts.endpoint,
        "my-openai-adc",
        "openai",
        false,
        &[],
        true,
        &[],
        "default",
        &ts.tls,
    )
    .await
    .expect_err("wrong provider type should fail before generic credential validation");

    assert!(
        err.to_string().contains("--from-gcloud-adc"),
        "unexpected error: {err}"
    );
    assert!(ts.state.providers.lock().await.is_empty());
}

#[tokio::test]
async fn provider_create_from_gcloud_adc_rolls_back_provider_when_refresh_configure_fails() {
    let ts = run_server().await;
    *ts.state.fail_configure_refresh_message.lock().await =
        Some("simulated configure failure".to_string());

    let adc_content = serde_json::json!({
        "type": "authorized_user",
        "client_id": "test-client-id.apps.googleusercontent.com",
        "client_secret": "test-client-secret",
        "refresh_token": "1//test-refresh-token"
    });
    let adc_file = tempfile::NamedTempFile::new().unwrap();
    serde_json::to_writer(&adc_file, &adc_content).unwrap();
    let adc_path = adc_file.path().to_str().unwrap().to_string();
    let _guard = EnvVarGuard::set(&[("GOOGLE_APPLICATION_CREDENTIALS", &adc_path)]);

    let err = run::provider_create(
        &ts.endpoint,
        "vertex-rollback",
        "google-vertex-ai",
        false,
        &[],
        true,
        &[],
        "default",
        &ts.tls,
    )
    .await
    .expect_err("configure_provider_refresh failure should bubble up");

    assert!(
        err.to_string().contains("simulated configure failure"),
        "unexpected error: {err}"
    );
    assert!(
        !ts.state
            .providers
            .lock()
            .await
            .contains_key("vertex-rollback"),
        "provider should be deleted on rollback"
    );
    assert_eq!(
        ts.state.delete_provider_requests.lock().await.clone(),
        vec!["vertex-rollback".to_string()]
    );
}

#[tokio::test]
async fn provider_create_from_gcloud_adc_warn_path_keeps_provider_when_rollback_delete_fails() {
    let ts = run_server().await;
    *ts.state.fail_configure_refresh_message.lock().await =
        Some("simulated configure failure".to_string());
    *ts.state.fail_delete_provider_message.lock().await =
        Some("simulated delete failure".to_string());

    let adc_content = serde_json::json!({
        "type": "authorized_user",
        "client_id": "test-client-id.apps.googleusercontent.com",
        "client_secret": "test-client-secret",
        "refresh_token": "1//test-refresh-token"
    });
    let adc_file = tempfile::NamedTempFile::new().unwrap();
    serde_json::to_writer(&adc_file, &adc_content).unwrap();
    let adc_path = adc_file.path().to_str().unwrap().to_string();
    let _guard = EnvVarGuard::set(&[("GOOGLE_APPLICATION_CREDENTIALS", &adc_path)]);

    let err = run::provider_create(
        &ts.endpoint,
        "vertex-cleanup-warning",
        "google-vertex-ai",
        false,
        &[],
        true,
        &[],
        "default",
        &ts.tls,
    )
    .await
    .expect_err("cleanup failure path should still return configure error");

    assert!(
        err.to_string().contains("simulated configure failure"),
        "unexpected error: {err}"
    );
    assert!(
        ts.state
            .providers
            .lock()
            .await
            .contains_key("vertex-cleanup-warning"),
        "provider should remain when rollback deletion fails"
    );
    assert_eq!(
        ts.state.delete_provider_requests.lock().await.clone(),
        vec!["vertex-cleanup-warning".to_string()]
    );
}

#[tokio::test]
async fn provider_create_from_gcloud_adc_rolls_back_provider_when_initial_rotate_fails() {
    let ts = run_server().await;
    *ts.state.fail_rotate_refresh_message.lock().await =
        Some("simulated rotate failure".to_string());

    let adc_content = serde_json::json!({
        "type": "authorized_user",
        "client_id": "test-client-id.apps.googleusercontent.com",
        "client_secret": "test-client-secret",
        "refresh_token": "1//test-refresh-token"
    });
    let adc_file = tempfile::NamedTempFile::new().unwrap();
    serde_json::to_writer(&adc_file, &adc_content).unwrap();
    let adc_path = adc_file.path().to_str().unwrap().to_string();
    let _guard = EnvVarGuard::set(&[("GOOGLE_APPLICATION_CREDENTIALS", &adc_path)]);

    let err = run::provider_create(
        &ts.endpoint,
        "vertex-rotate-rollback",
        "google-vertex-ai",
        false,
        &[],
        true,
        &[],
        "default",
        &ts.tls,
    )
    .await
    .expect_err("initial rotate failure should roll back the provider");

    assert!(
        err.to_string().contains("simulated rotate failure"),
        "unexpected error: {err}"
    );
    assert!(
        !ts.state
            .providers
            .lock()
            .await
            .contains_key("vertex-rotate-rollback"),
        "provider should be deleted on initial-rotate rollback"
    );
    assert_eq!(
        ts.state.delete_provider_requests.lock().await.clone(),
        vec!["vertex-rotate-rollback".to_string()]
    );
}

#[tokio::test]
async fn provider_create_from_existing_vertex_config_only_reports_missing_vertex_credentials() {
    let ts = run_server().await;
    let _env = EnvVarGuard::set(&[
        ("VERTEX_AI_PROJECT_ID", "vertex-config-only-project"),
        ("VERTEX_AI_REGION", "us-central1"),
    ]);

    let err = run::provider_create(
        &ts.endpoint,
        "vertex-config-only",
        "google-vertex-ai",
        true,
        &[],
        false,
        &[],
        "default",
        &ts.tls,
    )
    .await
    .expect_err("config-only discovery should surface missing credential guidance");

    let msg = err.to_string();
    assert!(
        msg.contains("GOOGLE_VERTEX_AI_TOKEN") && msg.contains("VERTEX_AI_SERVICE_ACCOUNT_TOKEN"),
        "unexpected error: {msg}"
    );
    assert!(
        !ts.state
            .providers
            .lock()
            .await
            .contains_key("vertex-config-only")
    );
}

#[tokio::test]
async fn provider_create_from_gcloud_adc_with_config_keys() {
    let ts = run_server().await;

    // Write a valid authorized_user ADC file.
    let adc_content = serde_json::json!({
        "type": "authorized_user",
        "client_id": "test-client-id.apps.googleusercontent.com",
        "client_secret": "test-client-secret",
        "refresh_token": "1//test-refresh-token"
    });
    let adc_file = tempfile::NamedTempFile::new().unwrap();
    serde_json::to_writer(&adc_file, &adc_content).unwrap();
    let adc_path = adc_file.path().to_str().unwrap().to_string();
    let _guard = EnvVarGuard::set(&[("GOOGLE_APPLICATION_CREDENTIALS", &adc_path)]);

    run::provider_create(
        &ts.endpoint,
        "vertex-with-config",
        "google-vertex-ai",
        false,
        &[],  // no explicit credentials; ADC flow
        true, // from_gcloud_adc
        &[
            "VERTEX_AI_PROJECT_ID=my-gcp-project".to_string(),
            "VERTEX_AI_REGION=us-east1".to_string(),
        ],
        "default",
        &ts.tls,
    )
    .await
    .expect("provider_create with --from-gcloud-adc and --config keys should succeed");

    // Verify provider was created with the config keys.
    let providers = ts.state.providers.lock().await;
    let provider = providers
        .get("vertex-with-config")
        .expect("provider should be stored after create");
    assert_eq!(provider.r#type, "google-vertex-ai");
    assert_eq!(
        provider
            .config
            .get("VERTEX_AI_PROJECT_ID")
            .map(String::as_str),
        Some("my-gcp-project"),
        "VERTEX_AI_PROJECT_ID must be stored in provider config"
    );
    assert_eq!(
        provider.config.get("VERTEX_AI_REGION").map(String::as_str),
        Some("us-east1"),
        "VERTEX_AI_REGION must be stored in provider config"
    );
    drop(providers);

    // ADC flow should configure refresh and eagerly mint the initial token.
    let refresh_requests = ts.state.refresh_requests.lock().await.clone();
    assert_eq!(
        refresh_requests.len(),
        2,
        "exactly one configure call and one rotate call expected"
    );
    assert!(matches!(
        &refresh_requests[0],
        ProviderRefreshRequestLog::Configure {
            provider,
            credential_key,
            expires_at_ms: None,
            ..
        } if provider == "vertex-with-config" && credential_key == "GOOGLE_VERTEX_AI_TOKEN"
    ));
    assert_eq!(
        refresh_requests[1],
        ProviderRefreshRequestLog::Rotate {
            provider: "vertex-with-config".to_string(),
            credential_key: "GOOGLE_VERTEX_AI_TOKEN".to_string(),
        }
    );
}

#[tokio::test]
async fn provider_create_from_gcloud_adc_missing_refresh_token() {
    let ts = run_server().await;

    // ADC file is valid authorized_user type but missing refresh_token.
    let adc_content = serde_json::json!({
        "type": "authorized_user",
        "client_id": "test-client-id.apps.googleusercontent.com",
        "client_secret": "test-client-secret"
    });
    let adc_file = tempfile::NamedTempFile::new().unwrap();
    serde_json::to_writer(&adc_file, &adc_content).unwrap();
    let adc_path = adc_file.path().to_str().unwrap().to_string();
    let _guard = EnvVarGuard::set(&[("GOOGLE_APPLICATION_CREDENTIALS", &adc_path)]);

    let err = run::provider_create(
        &ts.endpoint,
        "vertex-missing-refresh",
        "google-vertex-ai",
        false,
        &[],
        true,
        &[],
        "default",
        &ts.tls,
    )
    .await
    .expect_err("missing refresh_token should produce an error");

    let err_msg = err.to_string();
    assert!(
        err_msg.contains("refresh_token"),
        "error must mention 'refresh_token', got: {err_msg}"
    );

    // No provider should have been created.
    let providers = ts.state.providers.lock().await;
    assert!(
        providers.is_empty(),
        "no provider must be created when ADC validation fails"
    );
}

#[tokio::test]
async fn provider_create_from_gcloud_adc_missing_client_secret() {
    let ts = run_server().await;

    // ADC file is valid authorized_user type but missing client_secret.
    let adc_content = serde_json::json!({
        "type": "authorized_user",
        "client_id": "test-client-id.apps.googleusercontent.com",
        "refresh_token": "1//test-refresh-token"
    });
    let adc_file = tempfile::NamedTempFile::new().unwrap();
    serde_json::to_writer(&adc_file, &adc_content).unwrap();
    let adc_path = adc_file.path().to_str().unwrap().to_string();
    let _guard = EnvVarGuard::set(&[("GOOGLE_APPLICATION_CREDENTIALS", &adc_path)]);

    let err = run::provider_create(
        &ts.endpoint,
        "vertex-missing-secret",
        "google-vertex-ai",
        false,
        &[],
        true,
        &[],
        "default",
        &ts.tls,
    )
    .await
    .expect_err("missing client_secret should produce an error");

    let err_msg = err.to_string();
    assert!(
        err_msg.contains("client_secret"),
        "error must mention 'client_secret', got: {err_msg}"
    );

    // No provider should have been created.
    let providers = ts.state.providers.lock().await;
    assert!(
        providers.is_empty(),
        "no provider must be created when ADC validation fails"
    );
}
