// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

mod helpers;

use helpers::{
    EnvVarGuard, build_ca, build_client_cert, build_server_cert, install_rustls_provider,
};
use openshell_cli::run;
use openshell_cli::tls::TlsOptions;
use openshell_core::proto::open_shell_server::{OpenShell, OpenShellServer};
use openshell_core::proto::{
    AttachSandboxProviderRequest, AttachSandboxProviderResponse, CreateProviderRequest,
    CreateSandboxRequest, CreateSshSessionRequest, CreateSshSessionResponse,
    DeleteProviderRefreshRequest, DeleteProviderRefreshResponse, DeleteProviderRequest,
    DeleteProviderResponse, DeleteSandboxRequest, DeleteSandboxResponse,
    DetachSandboxProviderRequest, DetachSandboxProviderResponse, ExecSandboxEvent,
    ExecSandboxInput, ExecSandboxRequest, GatewayMessage, GetGatewayConfigRequest,
    GetGatewayConfigResponse, GetProviderRefreshStatusRequest, GetProviderRefreshStatusResponse,
    GetProviderRequest, GetSandboxConfigRequest, GetSandboxConfigResponse,
    GetSandboxProviderEnvironmentRequest, GetSandboxProviderEnvironmentResponse, GetSandboxRequest,
    HealthRequest, HealthResponse, ListProvidersRequest, ListProvidersResponse,
    ListSandboxProvidersRequest, ListSandboxProvidersResponse, ListSandboxesRequest,
    ListSandboxesResponse, Provider, ProviderCredentialRefresh, ProviderCredentialRefreshStatus,
    ProviderCredentialRefreshStrategy, ProviderProfile, ProviderProfileCredential,
    ProviderProfileDiscovery, ProviderResponse, RevokeSshSessionRequest, RevokeSshSessionResponse,
    RotateProviderCredentialRequest, RotateProviderCredentialResponse, Sandbox, SandboxResponse,
    SandboxStreamEvent, ServiceStatus, SettingValue, SupervisorMessage, UpdateProviderRequest,
    WatchSandboxRequest, setting_value,
};
use openshell_core::{ObjectId, ObjectName};
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, mpsc};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Certificate as TlsCertificate, Identity, Server, ServerTlsConfig};
use tonic::{Response, Status};

#[derive(Clone, Default)]
struct ProviderState {
    providers: Arc<Mutex<HashMap<String, Provider>>>,
    profiles: Arc<Mutex<HashMap<String, ProviderProfile>>>,
    refresh_statuses: Arc<Mutex<HashMap<(String, String), ProviderCredentialRefreshStatus>>>,
    refresh_requests: Arc<Mutex<Vec<ProviderRefreshRequestLog>>>,
    delete_provider_requests: Arc<Mutex<Vec<String>>>,
    fail_configure_refresh_message: Arc<Mutex<Option<String>>>,
    fail_rotate_refresh_message: Arc<Mutex<Option<String>>>,
    fail_delete_provider_message: Arc<Mutex<Option<String>>>,
    sandbox_providers: Arc<Mutex<HashMap<String, Vec<String>>>>,
    sandbox_provider_requests: Arc<Mutex<Vec<SandboxProviderRequestLog>>>,
    global_settings: Arc<Mutex<HashMap<String, SettingValue>>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ProviderRefreshRequestLog {
    Status {
        provider_name: String,
        credential_key: String,
    },
    Configure {
        provider_name: String,
        credential_key: String,
        expires_at_ms: Option<i64>,
    },
    Rotate {
        provider_name: String,
        credential_key: String,
    },
    Delete {
        provider_name: String,
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
        provider_name: String,
    },
    Detach {
        sandbox_name: String,
        provider_name: String,
    },
}

#[derive(Clone, Default)]
struct TestOpenShell {
    state: ProviderState,
}

#[tonic::async_trait]
impl OpenShell for TestOpenShell {
    async fn health(
        &self,
        _request: tonic::Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            status: ServiceStatus::Healthy.into(),
            version: "test".to_string(),
        }))
    }

    async fn create_sandbox(
        &self,
        _request: tonic::Request<CreateSandboxRequest>,
    ) -> Result<Response<SandboxResponse>, Status> {
        Ok(Response::new(SandboxResponse::default()))
    }

    async fn get_sandbox(
        &self,
        request: tonic::Request<GetSandboxRequest>,
    ) -> Result<Response<SandboxResponse>, Status> {
        let name = request.into_inner().name;
        // Return a minimal sandbox with metadata for CAS operations
        Ok(Response::new(SandboxResponse {
            sandbox: Some(Sandbox {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: format!("sb-{name}"),
                    name,
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 1,
                    annotations: HashMap::new(),
                }),
                spec: None,
                status: None,
            }),
        }))
    }

    async fn list_sandboxes(
        &self,
        _request: tonic::Request<ListSandboxesRequest>,
    ) -> Result<Response<ListSandboxesResponse>, Status> {
        Ok(Response::new(ListSandboxesResponse::default()))
    }

    async fn list_sandbox_providers(
        &self,
        request: tonic::Request<ListSandboxProvidersRequest>,
    ) -> Result<Response<ListSandboxProvidersResponse>, Status> {
        let sandbox_name = request.into_inner().sandbox_name;
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
        self.state
            .sandbox_provider_requests
            .lock()
            .await
            .push(SandboxProviderRequestLog::Attach {
                sandbox_name: request.sandbox_name.clone(),
                provider_name: request.provider_name.clone(),
            });
        if !self
            .state
            .providers
            .lock()
            .await
            .contains_key(&request.provider_name)
        {
            return Err(Status::failed_precondition("provider not found"));
        }
        let mut sandbox_providers = self.state.sandbox_providers.lock().await;
        let providers = sandbox_providers
            .entry(request.sandbox_name.clone())
            .or_default();
        let attached = if providers.contains(&request.provider_name) {
            false
        } else {
            providers.push(request.provider_name.clone());
            true
        };
        let sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                name: request.sandbox_name,
                ..Default::default()
            }),
            spec: Some(openshell_core::proto::SandboxSpec {
                providers: providers.clone(),
                ..Default::default()
            }),
            ..Default::default()
        };
        Ok(Response::new(AttachSandboxProviderResponse {
            sandbox: Some(sandbox),
            attached,
        }))
    }

    async fn detach_sandbox_provider(
        &self,
        request: tonic::Request<DetachSandboxProviderRequest>,
    ) -> Result<Response<DetachSandboxProviderResponse>, Status> {
        let request = request.into_inner();
        self.state
            .sandbox_provider_requests
            .lock()
            .await
            .push(SandboxProviderRequestLog::Detach {
                sandbox_name: request.sandbox_name.clone(),
                provider_name: request.provider_name.clone(),
            });
        let mut sandbox_providers = self.state.sandbox_providers.lock().await;
        let providers = sandbox_providers
            .entry(request.sandbox_name.clone())
            .or_default();
        let before_len = providers.len();
        providers.retain(|name| name != &request.provider_name);
        let detached = providers.len() != before_len;
        let sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                name: request.sandbox_name,
                ..Default::default()
            }),
            spec: Some(openshell_core::proto::SandboxSpec {
                providers: providers.clone(),
                ..Default::default()
            }),
            ..Default::default()
        };
        Ok(Response::new(DetachSandboxProviderResponse {
            sandbox: Some(sandbox),
            detached,
        }))
    }

    async fn delete_sandbox(
        &self,
        _request: tonic::Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
        Ok(Response::new(DeleteSandboxResponse { deleted: true }))
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

    async fn create_provider(
        &self,
        request: tonic::Request<CreateProviderRequest>,
    ) -> Result<Response<ProviderResponse>, Status> {
        let mut provider = request
            .into_inner()
            .provider
            .ok_or_else(|| Status::invalid_argument("provider is required"))?;
        if provider.credentials.is_empty() {
            let bootstrap_allowed = if let Some(profile) = openshell_providers::builtin_profiles()
                .iter()
                .find(|profile| profile.id == provider.r#type)
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
        Ok(Response::new(ListProvidersResponse { providers }))
    }

    async fn list_provider_profiles(
        &self,
        _request: tonic::Request<openshell_core::proto::ListProviderProfilesRequest>,
    ) -> Result<Response<openshell_core::proto::ListProviderProfilesResponse>, Status> {
        let mut profiles = openshell_providers::builtin_profiles()
            .iter()
            .map(openshell_providers::ProviderTypeProfile::to_proto)
            .collect::<Vec<_>>();
        profiles.extend(self.state.profiles.lock().await.values().cloned());
        Ok(Response::new(
            openshell_core::proto::ListProviderProfilesResponse { profiles },
        ))
    }

    async fn get_provider_profile(
        &self,
        request: tonic::Request<openshell_core::proto::GetProviderProfileRequest>,
    ) -> Result<Response<openshell_core::proto::ProviderProfileResponse>, Status> {
        let id = request.into_inner().id;
        let profile = if let Some(profile) = openshell_providers::builtin_profiles()
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
        let merge_expiry = |mut base: HashMap<String, i64>, incoming: HashMap<String, i64>| {
            if incoming.is_empty() {
                return base;
            }
            for (k, v) in incoming {
                if v <= 0 {
                    base.remove(&k);
                } else {
                    base.insert(k, v);
                }
            }
            base
        };
        let existing_metadata = existing.metadata.clone().unwrap_or_default();
        let provider_metadata = provider.metadata.clone().unwrap_or_default();
        let updated = Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: existing_metadata.id,
                name: provider_metadata.name,
                created_at_ms: existing_metadata.created_at_ms,
                labels: existing_metadata.labels,
                resource_version: 0,
                annotations: HashMap::new(),
            }),
            r#type: existing.r#type,
            credentials: merge(existing.credentials, provider.credentials),
            config: merge(existing.config, provider.config),
            credential_expires_at_ms: merge_expiry(
                existing.credential_expires_at_ms,
                provider.credential_expires_at_ms,
            ),
        };
        let updated_name = updated.object_name().to_string();
        providers.insert(updated_name, updated.clone());
        Ok(Response::new(ProviderResponse {
            provider: Some(updated),
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
                provider_name: request.provider.clone(),
                credential_key: request.credential_key.clone(),
            });
        let refresh_statuses = self.state.refresh_statuses.lock().await;
        let credentials = if request.credential_key.is_empty() {
            refresh_statuses
                .values()
                .filter(|status| status.provider_name == request.provider)
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
                provider_name: request.provider.clone(),
                credential_key: request.credential_key.clone(),
                expires_at_ms: request.expires_at_ms,
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
            provider_name: request.provider.clone(),
            provider_id: provider.object_id().to_string(),
            credential_key: request.credential_key.clone(),
            strategy: request.strategy,
            status: "configured".to_string(),
            expires_at_ms: request.expires_at_ms.unwrap_or_default(),
            next_refresh_at_ms: 0,
            last_refresh_at_ms: 0,
            last_error: String::new(),
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
                provider_name: provider_name.clone(),
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
        status.last_refresh_at_ms = 1;
        status.next_refresh_at_ms = 3_600_000;
        status.expires_at_ms = 3_600_000;
        let status = status.clone();
        drop(refresh_statuses);
        let mut providers = self.state.providers.lock().await;
        let provider = providers
            .get_mut(&provider_name)
            .ok_or_else(|| Status::not_found("provider not found"))?;
        provider
            .credentials
            .insert(credential_key.clone(), format!("minted-{credential_key}"));
        provider
            .credential_expires_at_ms
            .insert(credential_key, 3_600_000);
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
                provider_name: request.provider.clone(),
                credential_key: request.credential_key.clone(),
            });
        let deleted = self
            .state
            .refresh_statuses
            .lock()
            .await
            .remove(&(request.provider, request.credential_key))
            .is_some();
        Ok(Response::new(DeleteProviderRefreshResponse { deleted }))
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
        Ok(Response::new(DeleteProviderResponse { deleted }))
    }

    async fn delete_provider_profile(
        &self,
        request: tonic::Request<openshell_core::proto::DeleteProviderProfileRequest>,
    ) -> Result<Response<openshell_core::proto::DeleteProviderProfileResponse>, Status> {
        let id = request.into_inner().id;
        let deleted = self.state.profiles.lock().await.remove(&id).is_some();
        Ok(Response::new(
            openshell_core::proto::DeleteProviderProfileResponse { deleted },
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
}

/// Test fixture: TLS-enabled server with matching client certs.
struct TestServer {
    endpoint: String,
    tls: TlsOptions,
    state: ProviderState,
    _dir: TempDir,
}

async fn run_server() -> TestServer {
    install_rustls_provider();

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
        _dir: dir,
    }
}

async fn enable_providers_v2(ts: &TestServer) {
    ts.state.global_settings.lock().await.insert(
        openshell_core::settings::PROVIDERS_V2_ENABLED_KEY.to_string(),
        SettingValue {
            value: Some(setting_value::Value::BoolValue(true)),
        },
    );
}

#[tokio::test]
async fn provider_cli_run_functions_support_full_crud_flow() {
    let ts = run_server().await;

    run::provider_create(
        &ts.endpoint,
        "my-claude",
        "claude",
        false,
        &["API_KEY=abc".to_string()],
        false,
        &["profile=dev".to_string()],
        &ts.tls,
    )
    .await
    .expect("provider create");

    run::provider_get(&ts.endpoint, "my-claude", &ts.tls)
        .await
        .expect("provider get");
    run::provider_list(&ts.endpoint, 100, 0, false, "table", &ts.tls)
        .await
        .expect("provider list");

    run::provider_update(
        &ts.endpoint,
        "my-claude",
        false,
        &["API_KEY=rotated".to_string()],
        &["profile=prod".to_string()],
        &[],
        &ts.tls,
    )
    .await
    .expect("provider update");

    run::provider_delete(&ts.endpoint, &["my-claude".to_string()], &ts.tls)
        .await
        .expect("provider delete");
}

#[tokio::test]
async fn provider_list_profiles_cli_uses_profile_browsing_rpc() {
    let ts = run_server().await;

    run::provider_list_profiles(&ts.endpoint, "table", &ts.tls)
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
        &ts.tls,
    )
    .await
    .expect("provider create");

    // Test JSON output (verifies it doesn't error)
    run::provider_list(&ts.endpoint, 100, 0, false, "json", &ts.tls)
        .await
        .expect("provider list json should succeed");

    run::provider_delete(&ts.endpoint, &["test-provider".to_string()], &ts.tls)
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
        &ts.tls,
    )
    .await
    .expect("provider create");

    // Test YAML output (verifies it doesn't error)
    run::provider_list(&ts.endpoint, 100, 0, false, "yaml", &ts.tls)
        .await
        .expect("provider list yaml should succeed");

    run::provider_delete(&ts.endpoint, &["test-provider".to_string()], &ts.tls)
        .await
        .expect("provider delete");
}

#[tokio::test]
async fn provider_list_json_empty() {
    let ts = run_server().await;

    // Test JSON output with no providers (verifies it doesn't error on empty list)
    run::provider_list(&ts.endpoint, 100, 0, false, "json", &ts.tls)
        .await
        .expect("provider list json empty should succeed");
}

#[tokio::test]
async fn provider_refresh_cli_run_functions_wire_requests() {
    let ts = run_server().await;

    run::provider_create(
        &ts.endpoint,
        "my-graph",
        "outlook",
        false,
        &["MS_GRAPH_ACCESS_TOKEN=token".to_string()],
        false,
        &[],
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
            secret_material_keys: &["client_secret".to_string()],
            credential_expires_at_ms: Some(1_767_225_600_000),
        },
        &ts.tls,
    )
    .await
    .expect("provider refresh configure");
    run::provider_refresh_status(
        &ts.endpoint,
        "my-graph",
        Some("MS_GRAPH_ACCESS_TOKEN"),
        &ts.tls,
    )
    .await
    .expect("provider refresh status");
    run::provider_rotate(&ts.endpoint, "my-graph", "MS_GRAPH_ACCESS_TOKEN", &ts.tls)
        .await
        .expect("provider refresh rotate");
    run::provider_refresh_delete(&ts.endpoint, "my-graph", "MS_GRAPH_ACCESS_TOKEN", &ts.tls)
        .await
        .expect("provider refresh delete");

    let requests = ts.state.refresh_requests.lock().await.clone();
    assert_eq!(
        requests,
        vec![
            ProviderRefreshRequestLog::Configure {
                provider_name: "my-graph".to_string(),
                credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
                expires_at_ms: Some(1_767_225_600_000),
            },
            ProviderRefreshRequestLog::Status {
                provider_name: "my-graph".to_string(),
                credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
            },
            ProviderRefreshRequestLog::Rotate {
                provider_name: "my-graph".to_string(),
                credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
            },
            ProviderRefreshRequestLog::Delete {
                provider_name: "my-graph".to_string(),
                credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
            },
        ]
    );
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

    run::provider_create_with_options(
        &ts.endpoint,
        "custom-refresh-provider",
        "custom-refresh",
        false,
        &[],
        false,
        true,
        &[],
        &ts.tls,
    )
    .await
    .expect("provider create");

    let stored = ts.state.providers.lock().await;
    let provider = stored.get("custom-refresh-provider").expect("provider");
    assert_eq!(provider.r#type, "custom-refresh");
    assert!(provider.credentials.is_empty());
}

#[tokio::test]
async fn provider_create_requires_runtime_credentials_for_empty_gateway_refresh_profiles() {
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

    let err = run::provider_create(
        &ts.endpoint,
        "custom-refresh-provider",
        "custom-refresh",
        false,
        &[],
        false,
        &[],
        &ts.tls,
    )
    .await
    .expect_err("empty runtime-resolved providers should require an explicit source");

    assert!(err.to_string().contains("--runtime-credentials"));
    assert!(
        !ts.state
            .providers
            .lock()
            .await
            .contains_key("custom-refresh-provider")
    );
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
        &ts.tls,
    )
    .await
    .expect("provider create");

    run::sandbox_provider_attach(&ts.endpoint, "dev-sandbox", "work-github", &ts.tls)
        .await
        .expect("sandbox provider attach");
    run::sandbox_provider_attach(&ts.endpoint, "dev-sandbox", "work-github", &ts.tls)
        .await
        .expect("sandbox provider attach is idempotent");
    run::sandbox_provider_list(&ts.endpoint, "dev-sandbox", &ts.tls)
        .await
        .expect("sandbox provider list");
    run::sandbox_provider_detach(&ts.endpoint, "dev-sandbox", "work-github", &ts.tls)
        .await
        .expect("sandbox provider detach");
    run::sandbox_provider_detach(&ts.endpoint, "dev-sandbox", "work-github", &ts.tls)
        .await
        .expect("sandbox provider detach is idempotent");

    let requests = ts.state.sandbox_provider_requests.lock().await.clone();
    assert_eq!(
        requests,
        vec![
            SandboxProviderRequestLog::Attach {
                sandbox_name: "dev-sandbox".to_string(),
                provider_name: "work-github".to_string(),
            },
            SandboxProviderRequestLog::Attach {
                sandbox_name: "dev-sandbox".to_string(),
                provider_name: "work-github".to_string(),
            },
            SandboxProviderRequestLog::List {
                sandbox_name: "dev-sandbox".to_string(),
            },
            SandboxProviderRequestLog::Detach {
                sandbox_name: "dev-sandbox".to_string(),
                provider_name: "work-github".to_string(),
            },
            SandboxProviderRequestLog::Detach {
                sandbox_name: "dev-sandbox".to_string(),
                provider_name: "work-github".to_string(),
            },
        ]
    );

    let providers = ts.state.sandbox_providers.lock().await;
    assert!(providers.get("dev-sandbox").is_none_or(Vec::is_empty));
}

#[tokio::test]
async fn sandbox_provider_attach_cli_surfaces_server_errors() {
    let ts = run_server().await;

    let err =
        run::sandbox_provider_attach(&ts.endpoint, "dev-sandbox", "missing-provider", &ts.tls)
            .await
            .expect_err("missing provider should fail");

    assert!(
        err.to_string().contains("provider not found"),
        "unexpected error: {err}"
    );
    assert_eq!(
        ts.state.sandbox_provider_requests.lock().await.as_slice(),
        [SandboxProviderRequestLog::Attach {
            sandbox_name: "dev-sandbox".to_string(),
            provider_name: "missing-provider".to_string(),
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

    run::provider_profile_lint(&ts.endpoint, Some(&profile_path), None, &ts.tls)
        .await
        .expect("profile lint");
    run::provider_profile_import(&ts.endpoint, Some(&profile_path), None, &ts.tls)
        .await
        .expect("profile import");
    let exported_yaml =
        run::provider_profile_export_text(&ts.endpoint, "custom-api", "yaml", &ts.tls)
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
    run::provider_profile_update(&ts.endpoint, "custom-api", &profile_path, &ts.tls)
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
    run::provider_profile_export(&ts.endpoint, "custom-api", "yaml", &ts.tls)
        .await
        .expect("profile export");
    run::provider_list_profiles(&ts.endpoint, "json", &ts.tls)
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

    run::provider_delete(&ts.endpoint, &["custom-provider".to_string()], &ts.tls)
        .await
        .expect("custom provider delete");
    run::provider_profile_delete(&ts.endpoint, "custom-api", &ts.tls)
        .await
        .expect("profile delete");
}

#[tokio::test]
async fn provider_create_from_existing_uses_profile_discovery_when_v2_enabled() {
    let ts = run_server().await;
    enable_providers_v2(&ts).await;
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
async fn provider_create_from_existing_uses_registry_discovery_when_v2_disabled() {
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
async fn provider_create_from_existing_vertex_discovers_credentials_and_config_when_v2_enabled() {
    let ts = run_server().await;
    enable_providers_v2(&ts).await;
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
async fn provider_create_from_existing_requires_profile_when_v2_enabled() {
    let ts = run_server().await;
    enable_providers_v2(&ts).await;
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
        &ts.tls,
    )
    .await
    .expect_err("v2 discovery without a profile should fail");

    assert!(
        err.to_string()
            .contains("providers v2 discovery requires a provider profile"),
        "unexpected error: {err}"
    );
    assert!(!ts.state.providers.lock().await.contains_key("v2-generic"));
}

#[tokio::test]
async fn provider_create_from_existing_fails_when_profile_discovery_finds_nothing() {
    let ts = run_server().await;
    enable_providers_v2(&ts).await;
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
async fn provider_update_from_existing_uses_profile_discovery_when_v2_enabled() {
    let ts = run_server().await;
    enable_providers_v2(&ts).await;
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
            credential_expires_at_ms: HashMap::new(),
        },
    );
    let _env = EnvVarGuard::set(&[("CUSTOM_UPDATE_DISCOVERY_API_KEY", "updated-profile-secret")]);

    run::provider_update(&ts.endpoint, "custom-update", true, &[], &[], &[], &ts.tls)
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

    run::provider_profile_import(&ts.endpoint, None, Some(dir.path()), &ts.tls)
        .await
        .expect("profile import --from");

    run::provider_profile_export(&ts.endpoint, "custom-yaml", "yaml", &ts.tls)
        .await
        .expect("custom-yaml should be imported");
    run::provider_profile_export(&ts.endpoint, "custom-json", "json", &ts.tls)
        .await
        .expect("custom-json should be imported");
}

#[tokio::test]
#[allow(deprecated)]
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
    harness: true
",
    )
    .unwrap();

    run::provider_profile_import(&ts.endpoint, Some(&profile_path), None, &ts.tls)
        .await
        .expect("profile import");

    let mut client = openshell_cli::tls::grpc_client(&ts.endpoint, &ts.tls)
        .await
        .expect("grpc client should connect");
    let profile = client
        .get_provider_profile(openshell_core::proto::GetProviderProfileRequest {
            id: "advanced-api".to_string(),
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
    assert!(profile.binaries[0].harness);
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

    let err = run::provider_profile_import(&ts.endpoint, None, Some(dir.path()), &ts.tls)
        .await
        .expect_err("profile import --from should fail on parse errors");
    assert!(
        err.to_string().contains("provider profile import failed"),
        "unexpected error: {err}"
    );

    run::provider_profile_export(&ts.endpoint, "custom-good", "yaml", &ts.tls)
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

    let err = run::provider_profile_lint(&ts.endpoint, None, Some(dir.path()), &ts.tls)
        .await
        .expect_err("profile lint --from should fail on parse errors");
    assert!(
        err.to_string().contains("provider profile lint failed"),
        "unexpected error: {err}"
    );

    run::provider_profile_export(&ts.endpoint, "custom-good", "yaml", &ts.tls)
        .await
        .expect_err("lint should not import valid profiles");
}

#[tokio::test]
async fn provider_create_rejects_key_only_credentials_without_local_env_value() {
    let ts = run_server().await;

    let err = run::provider_create(
        &ts.endpoint,
        "bad-provider",
        "claude",
        false,
        &["INVALID_PAIR".to_string()],
        false,
        &[],
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
async fn provider_create_supports_generic_type_and_env_lookup_credentials() {
    let ts = run_server().await;
    let _guard = EnvVarGuard::set(&[("NAV_GENERIC_TEST_KEY", "generic-value")]);

    run::provider_create(
        &ts.endpoint,
        "my-generic",
        "generic",
        false,
        &["NAV_GENERIC_TEST_KEY".to_string()],
        false,
        &[],
        &ts.tls,
    )
    .await
    .expect("provider create");

    let mut client = openshell_cli::tls::grpc_client(&ts.endpoint, &ts.tls)
        .await
        .expect("grpc client should connect");
    let response = client
        .get_provider(GetProviderRequest {
            name: "my-generic".to_string(),
        })
        .await
        .expect("get provider should succeed")
        .into_inner();
    let provider = response.provider.expect("provider should exist");
    assert_eq!(provider.r#type, "generic");
    assert_eq!(
        provider.credentials.get("NAV_GENERIC_TEST_KEY"),
        Some(&"generic-value".to_string())
    );
}

#[tokio::test]
async fn provider_create_rejects_combined_from_existing_and_credentials() {
    let ts = run_server().await;

    let err = run::provider_create(
        &ts.endpoint,
        "bad-provider",
        "claude",
        true,
        &["API_KEY=abc".to_string()],
        false,
        &[],
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
        &ts.tls,
    )
    .await
    .expect_err("from-gcloud-adc and from-existing should be mutually exclusive");

    assert!(
        err.to_string()
            .contains("--from-gcloud-adc cannot be combined with --from-existing or --credential"),
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
        &ts.tls,
    )
    .await
    .expect_err("from-gcloud-adc and credentials should be mutually exclusive");

    assert!(
        err.to_string()
            .contains("--from-gcloud-adc cannot be combined with --from-existing or --credential"),
        "unexpected error: {err}"
    );
    assert!(ts.state.providers.lock().await.is_empty());
}

#[tokio::test]
async fn provider_create_rejects_empty_env_var_for_key_only_credential() {
    let ts = run_server().await;
    let _guard = EnvVarGuard::set(&[("NAV_EMPTY_ENV_KEY", "")]);

    let err = run::provider_create(
        &ts.endpoint,
        "bad-provider",
        "generic",
        false,
        &["NAV_EMPTY_ENV_KEY".to_string()],
        false,
        &[],
        &ts.tls,
    )
    .await
    .expect_err("empty env var should be rejected");

    assert!(
        err.to_string()
            .contains("requires local env var 'NAV_EMPTY_ENV_KEY' to be set to a non-empty value"),
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
    assert_eq!(
        requests[0],
        ProviderRefreshRequestLog::Configure {
            provider_name: "my-vertex".to_string(),
            credential_key: "GOOGLE_VERTEX_AI_TOKEN".to_string(),
            expires_at_ms: None,
        }
    );
    assert_eq!(
        requests[1],
        ProviderRefreshRequestLog::Rotate {
            provider_name: "my-vertex".to_string(),
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
    enable_providers_v2(&ts).await;
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
    assert_eq!(
        refresh_requests[0],
        ProviderRefreshRequestLog::Configure {
            provider_name: "vertex-with-config".to_string(),
            credential_key: "GOOGLE_VERTEX_AI_TOKEN".to_string(),
            expires_at_ms: None,
        }
    );
    assert_eq!(
        refresh_requests[1],
        ProviderRefreshRequestLog::Rotate {
            provider_name: "vertex-with-config".to_string(),
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
