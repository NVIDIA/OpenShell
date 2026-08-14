// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Credential driver backed by Kubernetes Secret objects.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{DeleteParams, Patch, PatchParams, PostParams, Preconditions};
use kube::{Api, Client};
use openshell_core::VERSION;
use openshell_core::proto::CredentialHandle;
use openshell_core::proto::credentials::v1::{
    DeleteCredentialRequest, DeleteCredentialResponse, GetCredentialDriverCapabilitiesRequest,
    GetCredentialDriverCapabilitiesResponse, ListCredentialsRequest, ListCredentialsResponse,
    ResolveCredentialRequest, ResolveCredentialsRequest, ResolveCredentialsResponse,
    ResolvedCredential, StoreCredentialRequest, StoreCredentialResponse,
    credential_driver_server::CredentialDriver,
};
use openshell_core::{Error, Result as CoreResult};
use sha2::{Digest, Sha256};
use tonic::{Request, Response, Status};

const SERVICE_ACCOUNT_NAMESPACE_PATH: &str =
    "/var/run/secrets/kubernetes.io/serviceaccount/namespace";
const HANDLE_VERSION: &str = "v1";
const OBJECT_ID_METADATA_KEY: &str = "openshell.storage_object_id";
const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";
const MANAGED_BY_VALUE: &str = "openshell";
const OWNER_ANNOTATION: &str = "openshell.nvidia.com/provider-credential-id";
const CONFLICT_RETRY_LIMIT: u32 = 3;

pub struct KubernetesSecretsCredentialDriver {
    client: Client,
    settings: KubernetesSecretsDriverSettings,
}

#[derive(Debug, Clone)]
pub struct CredentialDriverService {
    driver: KubernetesSecretsCredentialDriver,
}

impl CredentialDriverService {
    #[must_use]
    pub fn new(driver: KubernetesSecretsCredentialDriver) -> Self {
        Self { driver }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum WorkspaceMode {
    #[default]
    Shared,
    Managed,
    Operator,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KubernetesSecretsDriverSettings {
    namespace: String,
    allow_reference_namespace: bool,
    workspace_mode: WorkspaceMode,
    gateway_id: String,
}

impl KubernetesSecretsDriverSettings {
    fn target_namespace(&self, workspace: &str) -> String {
        match self.workspace_mode {
            WorkspaceMode::Shared => self.namespace.clone(),
            WorkspaceMode::Managed => {
                format!("openshell-{}-{}", self.gateway_id, workspace)
            }
            WorkspaceMode::Operator => workspace.to_string(),
        }
    }
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
struct KubernetesSecretsDriverConfig {
    namespace: Option<String>,
    allow_reference_namespace: bool,
    workspace_mode: WorkspaceMode,
    gateway_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KubernetesSecretReference {
    namespace: String,
    secret_name: String,
    key: String,
}

impl KubernetesSecretsCredentialDriver {
    pub const NAME: &'static str = "kubernetes-secrets";

    pub async fn from_config(config: &toml::Table) -> CoreResult<Self> {
        let settings = KubernetesSecretsDriverSettings::from_table(config)?;
        let client = Client::try_default().await.map_err(|err| {
            Error::config(format!(
                "failed to configure kubernetes-secrets credential driver: {err}"
            ))
        })?;
        Ok(Self { client, settings })
    }

    fn handle_from_request(
        request_id: &str,
        handle: Option<CredentialHandle>,
    ) -> Result<CredentialHandle, Status> {
        handle.ok_or_else(|| {
            Status::invalid_argument(format!(
                "kubernetes-secrets credential request '{request_id}' is missing handle"
            ))
        })
    }

    fn parse_handle(
        handle: &CredentialHandle,
        credential_key: &str,
    ) -> Result<KubernetesSecretReference, Status> {
        let parts = handle.handle.split(':').collect::<Vec<_>>();
        if parts.len() != 3 || parts[0] != HANDLE_VERSION {
            return Err(Status::invalid_argument(
                "kubernetes-secrets credential handle is malformed",
            ));
        }
        let namespace = required_handle_component("namespace", parts[1])?;
        if !is_dns_label(namespace) {
            return Err(Status::invalid_argument(
                "kubernetes-secrets credential handle namespace is invalid",
            ));
        }
        let secret_name = required_handle_component("secret", parts[2])?;
        if !is_dns_subdomain(secret_name) {
            return Err(Status::invalid_argument(
                "kubernetes-secrets credential handle Secret name is invalid",
            ));
        }
        let key = required_handle_component("credential_key", credential_key)?;
        if !is_secret_data_key(key) {
            return Err(Status::invalid_argument(
                "kubernetes-secrets credential key must be a valid Kubernetes Secret data key",
            ));
        }

        Ok(KubernetesSecretReference {
            namespace: namespace.to_string(),
            secret_name: secret_name.to_string(),
            key: key.to_string(),
        })
    }

    fn resolve_handle(
        &self,
        handle: &CredentialHandle,
        credential_key: &str,
    ) -> Result<KubernetesSecretReference, Status> {
        let reference = Self::parse_handle(handle, credential_key)?;
        // In managed/operator modes secrets live in workspace-specific
        // namespaces so cross-namespace handles are expected.
        if self.settings.workspace_mode == WorkspaceMode::Shared
            && reference.namespace != self.settings.namespace
            && !self.settings.allow_reference_namespace
        {
            return Err(Status::permission_denied(format!(
                "kubernetes-secrets credential handle references namespace '{}' but the driver is \
                 configured for namespace '{}'; set allow_reference_namespace = true to allow \
                 cross-namespace references",
                reference.namespace, self.settings.namespace
            )));
        }
        Ok(reference)
    }

    pub async fn store_credential(
        &self,
        request: StoreCredentialRequest,
    ) -> Result<CredentialHandle, Status> {
        let owner_id = credential_owner_id(
            &request.workspace,
            &request.provider_id,
            &request.provider_name,
            &request.credential_key,
        );
        let object_id = if let Some(existing_handle) = request.existing_handle.as_ref() {
            object_id_from_handle(existing_handle, &request.provider_id)?
        } else {
            requested_object_id(&request.object_id, &request.provider_id)?.to_string()
        };
        let reference = if let Some(existing_handle) = request.existing_handle.as_ref() {
            let reference = self.resolve_handle(existing_handle, &request.credential_key)?;
            validate_expected_secret_name(
                &request.workspace,
                &request.provider_id,
                &request.provider_name,
                &request.credential_key,
                &object_id,
                &reference.secret_name,
            )?;
            reference
        } else {
            KubernetesSecretReference {
                namespace: self.settings.target_namespace(&request.workspace),
                secret_name: managed_secret_name(
                    &request.workspace,
                    &request.provider_id,
                    &request.provider_name,
                    &request.credential_key,
                    &object_id,
                ),
                key: required_handle_component("credential_key", &request.credential_key)?
                    .to_string(),
            }
        };
        if !is_secret_data_key(&reference.key) {
            return Err(Status::invalid_argument(
                "kubernetes-secrets credential key must be a valid Kubernetes Secret data key",
            ));
        }
        if request.existing_handle.is_some() {
            self.overwrite_secret_value(&reference, &owner_id, &request.value)
                .await?;
        } else {
            self.create_secret_value(&reference, &owner_id, &request.value)
                .await?;
        }
        Ok(CredentialHandle {
            driver: Self::NAME.to_string(),
            handle: format!(
                "{HANDLE_VERSION}:{}:{}",
                reference.namespace, reference.secret_name
            ),
            metadata: std::collections::HashMap::from([(
                OBJECT_ID_METADATA_KEY.to_string(),
                object_id,
            )]),
        })
    }

    pub async fn delete_credential(&self, request: DeleteCredentialRequest) -> Result<(), Status> {
        let handle = Self::handle_from_request("delete", request.handle)?;
        let reference = self.resolve_handle(&handle, &request.credential_key)?;
        let object_id = object_id_from_handle(&handle, &request.provider_id)?;
        validate_expected_secret_name(
            &request.workspace,
            &request.provider_id,
            &request.provider_name,
            &request.credential_key,
            &object_id,
            &reference.secret_name,
        )?;
        let owner_id = credential_owner_id(
            &request.workspace,
            &request.provider_id,
            &request.provider_name,
            &request.credential_key,
        );
        let api: Api<Secret> = Api::namespaced(self.client.clone(), &reference.namespace);
        for _attempt in 0..CONFLICT_RETRY_LIMIT {
            let secret = match api.get(&reference.secret_name).await {
                Ok(secret) => secret,
                Err(kube::Error::Api(api_err)) if api_err.code == 404 => return Ok(()),
                Err(err) => {
                    return Err(kube_error_to_status(
                        &reference.namespace,
                        &reference.secret_name,
                        err,
                    ));
                }
            };
            ensure_secret_is_managed_for(&secret, &reference, &owner_id)?;
            let delete_params = DeleteParams {
                preconditions: Some(Preconditions {
                    uid: secret.metadata.uid.clone(),
                    resource_version: secret.metadata.resource_version.clone(),
                }),
                ..Default::default()
            };
            match api.delete(&reference.secret_name, &delete_params).await {
                Ok(_) => return Ok(()),
                Err(kube::Error::Api(api_err)) if api_err.code == 404 => return Ok(()),
                Err(kube::Error::Api(api_err)) if api_err.code == 409 => {}
                Err(kube::Error::Api(api_err)) if api_err.code == 403 => {
                    return Err(Status::permission_denied(format!(
                        "gateway is not allowed to delete Kubernetes Secret '{}' in namespace '{}'",
                        reference.secret_name, reference.namespace
                    )));
                }
                Err(err) => {
                    return Err(Status::unavailable(format!(
                        "failed to delete Kubernetes Secret '{}' in namespace '{}': {err}",
                        reference.secret_name, reference.namespace
                    )));
                }
            }
        }
        Err(Status::aborted(format!(
            "Kubernetes Secret '{}' in namespace '{}' was modified concurrently; exceeded retry limit",
            reference.secret_name, reference.namespace
        )))
    }

    pub async fn resolve_credentials(
        &self,
        requests: Vec<ResolveCredentialRequest>,
    ) -> Result<Vec<ResolvedCredential>, Status> {
        let futures = requests.into_iter().map(|request| async move {
            let handle = Self::handle_from_request(&request.request_id, request.handle)?;
            let reference = self.resolve_handle(&handle, &request.credential_key)?;
            let object_id = object_id_from_handle(&handle, &request.provider_id)?;
            validate_expected_secret_name(
                &request.workspace,
                &request.provider_id,
                &request.provider_name,
                &request.credential_key,
                &object_id,
                &reference.secret_name,
            )?;
            let owner_id = credential_owner_id(
                &request.workspace,
                &request.provider_id,
                &request.provider_name,
                &request.credential_key,
            );
            let value = self.resolve_secret_value(&reference, &owner_id).await?;
            Ok::<_, Status>(ResolvedCredential {
                request_id: request.request_id,
                value,
                expires_at_ms: 0,
            })
        });
        futures::future::try_join_all(futures).await
    }

    async fn create_secret_value(
        &self,
        reference: &KubernetesSecretReference,
        owner_id: &str,
        value: &str,
    ) -> Result<(), Status> {
        let api: Api<Secret> = Api::namespaced(self.client.clone(), &reference.namespace);
        let secret = managed_secret(&reference.secret_name, &reference.key, owner_id, value);
        match api.create(&PostParams::default(), &secret).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(api_err)) if api_err.code == 409 => {
                Err(Status::already_exists(format!(
                    "Kubernetes Secret '{}' in namespace '{}' already exists; refusing to overwrite a Secret not created for this provider credential",
                    reference.secret_name, reference.namespace
                )))
            }
            Err(err) => Err(kube_write_error_to_status(
                &reference.namespace,
                &reference.secret_name,
                err,
            )),
        }
    }

    async fn overwrite_secret_value(
        &self,
        reference: &KubernetesSecretReference,
        owner_id: &str,
        value: &str,
    ) -> Result<(), Status> {
        let api: Api<Secret> = Api::namespaced(self.client.clone(), &reference.namespace);
        for _attempt in 0..CONFLICT_RETRY_LIMIT {
            let secret = match api.get(&reference.secret_name).await {
                Ok(secret) => secret,
                Err(kube::Error::Api(api_err)) if api_err.code == 404 => {
                    return self.create_secret_value(reference, owner_id, value).await;
                }
                Err(err) => {
                    return Err(kube_error_to_status(
                        &reference.namespace,
                        &reference.secret_name,
                        err,
                    ));
                }
            };
            ensure_secret_is_managed_for(&secret, reference, owner_id)?;

            let mut patch = managed_secret(&reference.secret_name, &reference.key, owner_id, value);
            patch.metadata.resource_version = secret.metadata.resource_version.clone();
            match api
                .patch(
                    &reference.secret_name,
                    &PatchParams::default(),
                    &Patch::Merge(&patch),
                )
                .await
            {
                Ok(_) => return Ok(()),
                Err(kube::Error::Api(api_err)) if api_err.code == 409 => {}
                Err(err) => {
                    return Err(kube_write_error_to_status(
                        &reference.namespace,
                        &reference.secret_name,
                        err,
                    ));
                }
            }
        }
        Err(Status::aborted(format!(
            "Kubernetes Secret '{}' in namespace '{}' was modified concurrently; exceeded retry limit",
            reference.secret_name, reference.namespace
        )))
    }

    async fn resolve_secret_value(
        &self,
        reference: &KubernetesSecretReference,
        owner_id: &str,
    ) -> Result<String, Status> {
        let api: Api<Secret> = Api::namespaced(self.client.clone(), &reference.namespace);
        let secret = api.get(&reference.secret_name).await.map_err(|err| {
            kube_error_to_status(&reference.namespace, &reference.secret_name, err)
        })?;
        ensure_secret_is_managed_for(&secret, reference, owner_id)?;
        let data = secret.data.ok_or_else(|| {
            Status::not_found(format!(
                "Kubernetes Secret '{}' in namespace '{}' has no data",
                reference.secret_name, reference.namespace
            ))
        })?;
        let value = data.get(&reference.key).ok_or_else(|| {
            Status::not_found(format!(
                "Kubernetes Secret '{}' in namespace '{}' does not contain key '{}'",
                reference.secret_name, reference.namespace, reference.key
            ))
        })?;
        String::from_utf8(value.0.clone()).map_err(|_| {
            Status::invalid_argument(format!(
                "Kubernetes Secret '{}' in namespace '{}' key '{}' is not valid UTF-8",
                reference.secret_name, reference.namespace, reference.key
            ))
        })
    }
}

impl std::fmt::Debug for KubernetesSecretsCredentialDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KubernetesSecretsCredentialDriver")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl Clone for KubernetesSecretsCredentialDriver {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            settings: self.settings.clone(),
        }
    }
}

#[tonic::async_trait]
impl CredentialDriver for CredentialDriverService {
    async fn get_capabilities(
        &self,
        _request: Request<GetCredentialDriverCapabilitiesRequest>,
    ) -> Result<Response<GetCredentialDriverCapabilitiesResponse>, Status> {
        Ok(Response::new(GetCredentialDriverCapabilitiesResponse {
            driver_name: KubernetesSecretsCredentialDriver::NAME.to_string(),
            driver_version: VERSION.to_string(),
            backend_kind: KubernetesSecretsCredentialDriver::NAME.to_string(),
            supports_list: false,
            supports_expires_at: false,
        }))
    }

    async fn store_credential(
        &self,
        request: Request<StoreCredentialRequest>,
    ) -> Result<Response<StoreCredentialResponse>, Status> {
        let handle = self.driver.store_credential(request.into_inner()).await?;
        Ok(Response::new(StoreCredentialResponse {
            handle: Some(handle),
        }))
    }

    async fn delete_credential(
        &self,
        request: Request<DeleteCredentialRequest>,
    ) -> Result<Response<DeleteCredentialResponse>, Status> {
        self.driver.delete_credential(request.into_inner()).await?;
        Ok(Response::new(DeleteCredentialResponse {}))
    }

    async fn resolve_credentials(
        &self,
        request: Request<ResolveCredentialsRequest>,
    ) -> Result<Response<ResolveCredentialsResponse>, Status> {
        let credentials = self
            .driver
            .resolve_credentials(request.into_inner().credentials)
            .await?;
        Ok(Response::new(ResolveCredentialsResponse { credentials }))
    }

    async fn list_credentials(
        &self,
        _request: Request<ListCredentialsRequest>,
    ) -> Result<Response<ListCredentialsResponse>, Status> {
        Err(Status::unimplemented(
            "kubernetes-secrets credential driver does not support listing credentials",
        ))
    }
}

impl KubernetesSecretsDriverSettings {
    fn from_table(config: &toml::Table) -> CoreResult<Self> {
        let config: KubernetesSecretsDriverConfig = toml::Value::Table(config.clone())
            .try_into()
            .map_err(|err| {
            Error::config(format!(
                "invalid [openshell.credential_drivers.kubernetes-secrets]: {err}"
            ))
        })?;
        let namespace = match config.namespace {
            Some(namespace) => {
                let namespace = trimmed_config_string("namespace", &namespace)?;
                if !is_dns_label(namespace) {
                    return Err(Error::config(
                        "[openshell.credential_drivers.kubernetes-secrets] namespace must be a Kubernetes namespace name",
                    ));
                }
                namespace.to_string()
            }
            None => default_namespace(),
        };
        let gateway_id = config.gateway_id.unwrap_or_default();
        if config.workspace_mode == WorkspaceMode::Managed {
            let gateway_id = trimmed_config_string("gateway_id", &gateway_id)?;
            if !is_dns_label(gateway_id) {
                return Err(Error::config(
                    "[openshell.credential_drivers.kubernetes-secrets] gateway_id must be a DNS-1123 label in managed workspace mode",
                ));
            }
            // Workspace names are limited to 19 characters by the gateway.
            // Keep the longest generated namespace within Kubernetes' 63-char
            // DNS label limit, matching the Kubernetes compute driver.
            if "openshell-".len() + gateway_id.len() + 1 + 19 > 63 {
                return Err(Error::config(
                    "[openshell.credential_drivers.kubernetes-secrets] gateway_id is too long for managed workspace mode",
                ));
            }
        }

        Ok(Self {
            namespace,
            allow_reference_namespace: config.allow_reference_namespace,
            workspace_mode: config.workspace_mode,
            gateway_id,
        })
    }
}

fn kube_error_to_status(namespace: &str, secret_name: &str, err: kube::Error) -> Status {
    match err {
        kube::Error::Api(api_err) if api_err.code == 404 => Status::not_found(format!(
            "Kubernetes Secret '{secret_name}' in namespace '{namespace}' was not found"
        )),
        kube::Error::Api(api_err) if api_err.code == 403 => Status::permission_denied(format!(
            "gateway is not allowed to read Kubernetes Secret '{secret_name}' in namespace '{namespace}'"
        )),
        other => Status::unavailable(format!(
            "failed to read Kubernetes Secret '{secret_name}' in namespace '{namespace}': {other}"
        )),
    }
}

fn default_namespace() -> String {
    std::fs::read_to_string(SERVICE_ACCOUNT_NAMESPACE_PATH)
        .ok()
        .map(|namespace| namespace.trim().to_string())
        .filter(|namespace| !namespace.is_empty() && is_dns_label(namespace))
        .unwrap_or_else(|| "default".to_string())
}

fn kube_write_error_to_status(namespace: &str, secret_name: &str, err: kube::Error) -> Status {
    match err {
        kube::Error::Api(api_err) if api_err.code == 403 => Status::permission_denied(format!(
            "gateway is not allowed to write Kubernetes Secret '{secret_name}' in namespace '{namespace}'"
        )),
        other => Status::unavailable(format!(
            "failed to write Kubernetes Secret '{secret_name}' in namespace '{namespace}': {other}"
        )),
    }
}

fn managed_secret(secret_name: &str, key: &str, owner_id: &str, value: &str) -> Secret {
    let labels = BTreeMap::from([(MANAGED_BY_LABEL.to_string(), MANAGED_BY_VALUE.to_string())]);
    let annotations = BTreeMap::from([(OWNER_ANNOTATION.to_string(), owner_id.to_string())]);
    Secret {
        metadata: ObjectMeta {
            name: Some(secret_name.to_string()),
            labels: Some(labels),
            annotations: Some(annotations),
            ..Default::default()
        },
        string_data: Some(BTreeMap::from([(key.to_string(), value.to_string())])),
        type_: Some("Opaque".to_string()),
        ..Default::default()
    }
}

fn credential_owner_id(
    workspace: &str,
    provider_id: &str,
    provider_name: &str,
    credential_key: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(workspace.as_bytes());
    hasher.update([0]);
    hasher.update(provider_id.as_bytes());
    hasher.update([0]);
    hasher.update(provider_name.as_bytes());
    hasher.update([0]);
    hasher.update(credential_key.as_bytes());
    let digest = hasher.finalize();
    format!("{digest:x}")
}

fn managed_secret_name(
    workspace: &str,
    provider_id: &str,
    provider_name: &str,
    credential_key: &str,
    object_id: &str,
) -> String {
    let mut hex = credential_owner_id(workspace, provider_id, provider_name, credential_key);
    if object_id != provider_id {
        let mut hasher = Sha256::new();
        hasher.update(hex.as_bytes());
        hasher.update([0]);
        hasher.update(object_id.as_bytes());
        hex = format!("{:x}", hasher.finalize());
    }
    format!("openshell-cred-{}", &hex[..40])
}

fn validate_expected_secret_name(
    workspace: &str,
    provider_id: &str,
    provider_name: &str,
    credential_key: &str,
    object_id: &str,
    secret_name: &str,
) -> Result<(), Status> {
    let expected = managed_secret_name(
        workspace,
        provider_id,
        provider_name,
        credential_key,
        object_id,
    );
    if secret_name != expected {
        return Err(Status::invalid_argument(format!(
            "kubernetes-secrets credential handle Secret name '{secret_name}' does not match the managed Secret for provider credential '{credential_key}'"
        )));
    }
    Ok(())
}

fn requested_object_id<'a>(object_id: &'a str, provider_id: &'a str) -> Result<&'a str, Status> {
    let object_id = if object_id.is_empty() {
        provider_id
    } else {
        object_id
    };
    if object_id.trim() != object_id || object_id.is_empty() {
        return Err(Status::invalid_argument(
            "kubernetes-secrets credential object_id must not be empty or contain surrounding whitespace",
        ));
    }
    Ok(object_id)
}

fn object_id_from_handle(handle: &CredentialHandle, provider_id: &str) -> Result<String, Status> {
    requested_object_id(
        handle
            .metadata
            .get(OBJECT_ID_METADATA_KEY)
            .map_or("", String::as_str),
        provider_id,
    )
    .map(str::to_string)
}

fn ensure_secret_is_managed_for(
    secret: &Secret,
    reference: &KubernetesSecretReference,
    owner_id: &str,
) -> Result<(), Status> {
    let managed_by = secret
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(MANAGED_BY_LABEL))
        .map(String::as_str);
    let owner = secret
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(OWNER_ANNOTATION))
        .map(String::as_str);
    if managed_by == Some(MANAGED_BY_VALUE) && owner == Some(owner_id) {
        return Ok(());
    }
    Err(Status::failed_precondition(format!(
        "Kubernetes Secret '{}' in namespace '{}' is not managed by OpenShell for this provider credential",
        reference.secret_name, reference.namespace
    )))
}

fn trimmed_config_string<'a>(field_name: &str, value: &'a str) -> CoreResult<&'a str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Error::config(format!(
            "[openshell.credential_drivers.kubernetes-secrets] {field_name} must not be empty"
        )));
    }
    if trimmed.len() != value.len() {
        return Err(Error::config(format!(
            "[openshell.credential_drivers.kubernetes-secrets] {field_name} must not contain leading or trailing whitespace"
        )));
    }
    Ok(trimmed)
}

fn required_handle_component<'a>(field_name: &str, value: &'a str) -> Result<&'a str, Status> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Status::invalid_argument(format!(
            "kubernetes-secrets credential handle {field_name} is required"
        )));
    }
    if trimmed.len() != value.len() {
        return Err(Status::invalid_argument(format!(
            "kubernetes-secrets credential handle {field_name} must not contain leading or trailing whitespace"
        )));
    }
    Ok(trimmed)
}

fn is_dns_subdomain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(is_dns_label)
        && !value.contains("..")
}

fn is_dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn is_secret_data_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::Code;

    fn handle(value: &str) -> CredentialHandle {
        CredentialHandle {
            driver: "kubernetes-secrets".to_string(),
            handle: value.to_string(),
            metadata: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn settings_parse_configured_namespace() {
        let settings = KubernetesSecretsDriverSettings::from_table(&toml::toml! {
            namespace = "openshell"
            allow_reference_namespace = true
        })
        .unwrap();

        assert_eq!(settings.namespace, "openshell");
        assert!(settings.allow_reference_namespace);
    }

    #[test]
    fn settings_reject_unknown_fields() {
        let err = KubernetesSecretsDriverSettings::from_table(&toml::toml! {
            namespace = "openshell"
            unknown = "value"
        })
        .unwrap_err();

        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn settings_reject_invalid_namespace() {
        let err = KubernetesSecretsDriverSettings::from_table(&toml::toml! {
            namespace = "OpenShell"
        })
        .unwrap_err();

        assert!(err.to_string().contains("namespace"));
    }

    #[test]
    fn settings_managed_mode_requires_gateway_id() {
        let err = KubernetesSecretsDriverSettings::from_table(&toml::toml! {
            workspace_mode = "managed"
        })
        .unwrap_err();

        assert!(err.to_string().contains("gateway_id"));
    }

    #[test]
    fn settings_managed_mode_rejects_invalid_gateway_id() {
        let err = KubernetesSecretsDriverSettings::from_table(&toml::toml! {
            workspace_mode = "managed"
            gateway_id = "Invalid_Gateway"
        })
        .unwrap_err();

        assert!(err.to_string().contains("DNS-1123"));
    }

    #[test]
    fn settings_managed_mode_rejects_gateway_id_that_is_too_long() {
        let gateway_id = "a".repeat(35);
        let err = KubernetesSecretsDriverSettings::from_table(&toml::toml! {
            workspace_mode = "managed"
            gateway_id = gateway_id
        })
        .unwrap_err();

        assert!(err.to_string().contains("too long"));
    }

    #[test]
    fn settings_managed_mode_accepts_valid_gateway_id() {
        let settings = KubernetesSecretsDriverSettings::from_table(&toml::toml! {
            workspace_mode = "managed"
            gateway_id = "gateway-1"
        })
        .unwrap();

        assert_eq!(settings.gateway_id, "gateway-1");
    }

    #[test]
    fn handle_resolves_secret_reference() {
        let reference = KubernetesSecretsCredentialDriver::parse_handle(
            &handle("v1:openshell:provider-secret"),
            "API_KEY",
        )
        .unwrap();

        assert_eq!(reference.namespace, "openshell");
        assert_eq!(reference.secret_name, "provider-secret");
        assert_eq!(reference.key, "API_KEY");
    }

    #[test]
    fn handle_rejects_malformed_value() {
        let err =
            KubernetesSecretsCredentialDriver::parse_handle(&handle("provider-secret"), "API_KEY")
                .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("malformed"));
    }

    #[test]
    fn handle_rejects_invalid_namespace() {
        let err = KubernetesSecretsCredentialDriver::parse_handle(
            &handle("v1:OpenShell:provider-secret"),
            "API_KEY",
        )
        .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("namespace"));
    }

    #[test]
    fn handle_rejects_invalid_secret_name() {
        let err = KubernetesSecretsCredentialDriver::parse_handle(
            &handle("v1:openshell:ProviderSecret"),
            "API_KEY",
        )
        .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("Secret name"));
    }

    #[test]
    fn handle_rejects_invalid_credential_key() {
        let err = KubernetesSecretsCredentialDriver::parse_handle(
            &handle("v1:openshell:provider-secret"),
            "api/key",
        )
        .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("data key"));
    }

    #[test]
    fn handle_rejects_cross_namespace_when_not_allowed() {
        let settings = KubernetesSecretsDriverSettings {
            namespace: "openshell".to_string(),
            allow_reference_namespace: false,
            workspace_mode: WorkspaceMode::Shared,
            gateway_id: String::new(),
        };
        let reference = KubernetesSecretsCredentialDriver::parse_handle(
            &handle("v1:other-namespace:provider-secret"),
            "API_KEY",
        )
        .unwrap();

        assert_eq!(reference.namespace, "other-namespace");

        let result =
            if reference.namespace != settings.namespace && !settings.allow_reference_namespace {
                Err(Status::permission_denied("cross-namespace"))
            } else {
                Ok(reference)
            };
        assert_eq!(result.unwrap_err().code(), Code::PermissionDenied);
    }

    #[test]
    fn handle_allows_cross_namespace_when_configured() {
        let settings = KubernetesSecretsDriverSettings {
            namespace: "openshell".to_string(),
            allow_reference_namespace: true,
            workspace_mode: WorkspaceMode::Shared,
            gateway_id: String::new(),
        };
        let reference = KubernetesSecretsCredentialDriver::parse_handle(
            &handle("v1:other-namespace:provider-secret"),
            "API_KEY",
        )
        .unwrap();

        let result =
            if reference.namespace != settings.namespace && !settings.allow_reference_namespace {
                Err(Status::permission_denied("cross-namespace"))
            } else {
                Ok(reference)
            };
        assert!(result.is_ok());
    }

    #[test]
    fn handle_allows_same_namespace() {
        let reference = KubernetesSecretsCredentialDriver::parse_handle(
            &handle("v1:openshell:provider-secret"),
            "API_KEY",
        )
        .unwrap();

        assert_eq!(reference.namespace, "openshell");
    }

    #[test]
    fn managed_secret_names_are_stable_dns_subdomains() {
        let name = managed_secret_name(
            "default",
            "prov-123",
            "openai-prod",
            "OPENAI_API_KEY",
            "prov-123",
        );

        assert!(name.starts_with("openshell-cred-"));
        assert!(is_dns_subdomain(&name));
        assert_eq!(
            name,
            managed_secret_name(
                "default",
                "prov-123",
                "openai-prod",
                "OPENAI_API_KEY",
                "prov-123",
            )
        );
    }

    #[test]
    fn staged_secret_names_keep_provider_ownership_and_use_distinct_object_identity() {
        let committed = managed_secret_name(
            "default",
            "prov-123",
            "openai-prod",
            "OPENAI_API_KEY",
            "prov-123",
        );
        let staged = managed_secret_name(
            "default",
            "prov-123",
            "openai-prod",
            "OPENAI_API_KEY",
            "refresh-456",
        );

        assert_ne!(committed, staged);
        validate_expected_secret_name(
            "default",
            "prov-123",
            "openai-prod",
            "OPENAI_API_KEY",
            "refresh-456",
            &staged,
        )
        .unwrap();
        assert!(
            validate_expected_secret_name(
                "default",
                "other-provider",
                "openai-prod",
                "OPENAI_API_KEY",
                "refresh-456",
                &staged,
            )
            .is_err()
        );
    }

    #[test]
    fn managed_secret_carries_owner_metadata() {
        let owner_id = credential_owner_id("default", "prov-123", "openai-prod", "OPENAI_API_KEY");
        let secret = managed_secret("provider-secret", "OPENAI_API_KEY", &owner_id, "sk-test");

        assert_eq!(
            secret
                .metadata
                .labels
                .as_ref()
                .and_then(|labels| labels.get(MANAGED_BY_LABEL))
                .map(String::as_str),
            Some(MANAGED_BY_VALUE)
        );
        assert_eq!(
            secret
                .metadata
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.get(OWNER_ANNOTATION))
                .map(String::as_str),
            Some(owner_id.as_str())
        );
    }

    #[test]
    fn expected_secret_name_rejects_arbitrary_handle_names() {
        let err = validate_expected_secret_name(
            "default",
            "prov-123",
            "openai-prod",
            "OPENAI_API_KEY",
            "prov-123",
            "preexisting-secret",
        )
        .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("does not match"));
    }

    #[test]
    fn ownership_check_accepts_matching_managed_secret() {
        let owner_id = credential_owner_id("default", "prov-123", "openai-prod", "OPENAI_API_KEY");
        let secret_name = managed_secret_name(
            "default",
            "prov-123",
            "openai-prod",
            "OPENAI_API_KEY",
            "prov-123",
        );
        let reference = KubernetesSecretReference {
            namespace: "openshell".to_string(),
            secret_name: secret_name.clone(),
            key: "OPENAI_API_KEY".to_string(),
        };
        let secret = managed_secret(&secret_name, "OPENAI_API_KEY", &owner_id, "sk-test");

        ensure_secret_is_managed_for(&secret, &reference, &owner_id).unwrap();
    }

    #[test]
    fn ownership_check_rejects_unmanaged_secret() {
        let owner_id = credential_owner_id("default", "prov-123", "openai-prod", "OPENAI_API_KEY");
        let reference = KubernetesSecretReference {
            namespace: "openshell".to_string(),
            secret_name: "provider-secret".to_string(),
            key: "OPENAI_API_KEY".to_string(),
        };
        let secret = Secret {
            metadata: ObjectMeta {
                name: Some("provider-secret".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        let err = ensure_secret_is_managed_for(&secret, &reference, &owner_id).unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("is not managed by OpenShell"));
    }

    #[test]
    fn ownership_check_rejects_different_provider_credential() {
        let owner_id = credential_owner_id("default", "prov-123", "openai-prod", "OPENAI_API_KEY");
        let other_owner_id = credential_owner_id(
            "other-workspace",
            "prov-456",
            "other-provider",
            "OPENAI_API_KEY",
        );
        let secret_name = managed_secret_name(
            "default",
            "prov-123",
            "openai-prod",
            "OPENAI_API_KEY",
            "prov-123",
        );
        let reference = KubernetesSecretReference {
            namespace: "openshell".to_string(),
            secret_name: secret_name.clone(),
            key: "OPENAI_API_KEY".to_string(),
        };
        let secret = managed_secret(&secret_name, "OPENAI_API_KEY", &other_owner_id, "sk-test");

        let err = ensure_secret_is_managed_for(&secret, &reference, &owner_id).unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("is not managed by OpenShell"));
    }

    #[test]
    fn target_namespace_shared_returns_static_namespace() {
        let settings = KubernetesSecretsDriverSettings {
            namespace: "openshell".to_string(),
            allow_reference_namespace: false,
            workspace_mode: WorkspaceMode::Shared,
            gateway_id: String::new(),
        };
        assert_eq!(settings.target_namespace("team-a"), "openshell");
        assert_eq!(settings.target_namespace("team-b"), "openshell");
    }

    #[test]
    fn target_namespace_managed_computes_from_workspace() {
        let settings = KubernetesSecretsDriverSettings {
            namespace: "openshell".to_string(),
            allow_reference_namespace: false,
            workspace_mode: WorkspaceMode::Managed,
            gateway_id: "gw1".to_string(),
        };
        assert_eq!(settings.target_namespace("team-a"), "openshell-gw1-team-a");
        assert_eq!(settings.target_namespace("team-b"), "openshell-gw1-team-b");
    }

    #[test]
    fn target_namespace_operator_uses_workspace_name() {
        let settings = KubernetesSecretsDriverSettings {
            namespace: "openshell".to_string(),
            allow_reference_namespace: false,
            workspace_mode: WorkspaceMode::Operator,
            gateway_id: String::new(),
        };
        assert_eq!(settings.target_namespace("team-a"), "team-a");
        assert_eq!(settings.target_namespace("prod-ns"), "prod-ns");
    }
}
