// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Credential driver backed by a Vault-compatible HTTP API.

use std::path::{Path, PathBuf};
use std::time::Duration;

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
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tonic::{Request, Response, Status};

const DEFAULT_MOUNT: &str = "secret";
const DEFAULT_AUTH_METHOD: &str = "kubernetes";
const DEFAULT_KUBERNETES_AUTH_MOUNT: &str = "kubernetes";
const DEFAULT_SERVICE_ACCOUNT_TOKEN_PATH: &str =
    "/var/run/secrets/kubernetes.io/serviceaccount/token";
const DEFAULT_TIMEOUT_SECS: u64 = 10;
const HANDLE_VERSION: &str = "v1";
const STORED_VALUE_KEY: &str = "value";

pub struct VaultCredentialDriver {
    client: reqwest::Client,
    settings: VaultDriverSettings,
}

#[derive(Debug, Clone)]
pub struct CredentialDriverService {
    driver: VaultCredentialDriver,
}

impl CredentialDriverService {
    #[must_use]
    pub fn new(driver: VaultCredentialDriver) -> Self {
        Self { driver }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VaultDriverSettings {
    address: Url,
    mount: String,
    kv_version: KvVersion,
    auth: VaultAuthSettings,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VaultAuthSettings {
    Kubernetes {
        role: String,
        auth_mount: String,
        service_account_token_path: PathBuf,
    },
    TokenFile {
        token_path: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KvVersion {
    V1,
    V2,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct VaultDriverConfig {
    address: Option<String>,
    mount: Option<String>,
    kv_version: Option<String>,
    auth_method: Option<String>,
    role: Option<String>,
    kubernetes_auth_mount: Option<String>,
    service_account_token_path: Option<PathBuf>,
    token_path: Option<PathBuf>,
    timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VaultSecretReference {
    api_path: String,
    key: String,
    kv_version: KvVersion,
}

#[derive(Debug, Serialize)]
struct KubernetesLoginRequest<'a> {
    role: &'a str,
    jwt: &'a str,
}

#[derive(Debug, Deserialize)]
struct KubernetesLoginResponse {
    auth: Option<KubernetesLoginAuth>,
}

#[derive(Debug, Deserialize)]
struct KubernetesLoginAuth {
    client_token: String,
}

impl VaultCredentialDriver {
    pub const NAME: &'static str = "vault";

    pub fn from_config(config: &toml::Table) -> CoreResult<Self> {
        let settings = VaultDriverSettings::from_table(config)?;
        let timeout_secs = timeout_secs(config)?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .map_err(|err| {
                Error::config(format!(
                    "failed to configure vault credential driver: {err}"
                ))
            })?;
        Ok(Self { client, settings })
    }

    pub async fn store_credential(
        &self,
        request: StoreCredentialRequest,
    ) -> Result<CredentialHandle, Status> {
        let logical_path = if let Some(existing_handle) = request.existing_handle.as_ref() {
            Self::logical_path_from_handle(existing_handle)?
        } else {
            managed_secret_path(&request.provider_name, &request.credential_key)
        };
        validate_secret_path(&logical_path).map_err(Status::invalid_argument)?;
        validate_managed_secret_path(
            &request.provider_name,
            &request.credential_key,
            &logical_path,
        )?;
        let token = self.auth_token().await?;
        let reference = VaultSecretReference {
            api_path: api_path_for_reference(
                &self.settings.mount,
                self.settings.kv_version,
                &logical_path,
            ),
            key: STORED_VALUE_KEY.to_string(),
            kv_version: self.settings.kv_version,
        };
        self.store_secret_value(&reference, &request.value, &token)
            .await?;
        Ok(CredentialHandle {
            driver: Self::NAME.to_string(),
            handle: format!("{HANDLE_VERSION}:{logical_path}"),
            metadata: std::collections::HashMap::new(),
        })
    }

    pub async fn delete_credential(&self, request: DeleteCredentialRequest) -> Result<(), Status> {
        let handle = Self::handle_from_request("delete", request.handle)?;
        let logical_path = Self::logical_path_from_handle(&handle)?;
        validate_managed_secret_path(
            &request.provider_name,
            &request.credential_key,
            &logical_path,
        )?;
        let token = self.auth_token().await?;
        let api_path = delete_api_path_for_reference(
            &self.settings.mount,
            self.settings.kv_version,
            &logical_path,
        );
        self.delete_secret_value(&api_path, &token).await
    }

    pub async fn resolve_credentials(
        &self,
        requests: Vec<ResolveCredentialRequest>,
    ) -> Result<Vec<ResolvedCredential>, Status> {
        let mut responses = Vec::with_capacity(requests.len());
        let mut resolved_requests = Vec::with_capacity(requests.len());
        for request in requests {
            let handle = Self::handle_from_request(&request.request_id, request.handle)?;
            let logical_path = Self::logical_path_from_handle(&handle)?;
            validate_managed_secret_path(
                &request.provider_name,
                &request.credential_key,
                &logical_path,
            )?;
            let reference = VaultSecretReference {
                api_path: api_path_for_reference(
                    &self.settings.mount,
                    self.settings.kv_version,
                    &logical_path,
                ),
                key: STORED_VALUE_KEY.to_string(),
                kv_version: self.settings.kv_version,
            };
            resolved_requests.push((request.request_id, reference));
        }

        let token = self.auth_token().await?;
        for (request_id, reference) in resolved_requests {
            let value = self.resolve_secret_value(&reference, &token).await?;
            responses.push(ResolvedCredential {
                request_id,
                value,
                expires_at_ms: 0,
            });
        }
        Ok(responses)
    }

    fn handle_from_request(
        request_id: &str,
        handle: Option<CredentialHandle>,
    ) -> Result<CredentialHandle, Status> {
        handle.ok_or_else(|| {
            Status::invalid_argument(format!(
                "vault credential request '{request_id}' is missing handle"
            ))
        })
    }

    fn logical_path_from_handle(handle: &CredentialHandle) -> Result<String, Status> {
        let logical_path = handle
            .handle
            .strip_prefix(&format!("{HANDLE_VERSION}:"))
            .ok_or_else(|| Status::invalid_argument("vault credential handle is malformed"))?;
        validate_secret_path(logical_path).map_err(Status::invalid_argument)?;
        Ok(logical_path.to_string())
    }

    async fn auth_token(&self) -> Result<String, Status> {
        match &self.settings.auth {
            VaultAuthSettings::TokenFile { token_path } => {
                read_secret_file(token_path, "Vault token file").await
            }
            VaultAuthSettings::Kubernetes {
                role,
                auth_mount,
                service_account_token_path,
            } => {
                let jwt = read_secret_file(
                    service_account_token_path,
                    "Kubernetes service account token",
                )
                .await?;
                self.login_kubernetes(role, auth_mount, &jwt).await
            }
        }
    }

    async fn login_kubernetes(
        &self,
        role: &str,
        auth_mount: &str,
        jwt: &str,
    ) -> Result<String, Status> {
        let path = format!("auth/{auth_mount}/login");
        let url = self.url_for_path(&path)?;
        let response = self
            .client
            .post(url)
            .json(&KubernetesLoginRequest { role, jwt })
            .send()
            .await
            .map_err(|err| {
                Status::unavailable(format!("Vault Kubernetes auth request failed: {err}"))
            })?;
        let status = response.status();
        if !status.is_success() {
            return Err(vault_auth_status(status));
        }

        let body = response
            .json::<KubernetesLoginResponse>()
            .await
            .map_err(|_| {
                Status::failed_precondition("Vault Kubernetes auth returned invalid JSON")
            })?;
        let token = body
            .auth
            .map(|auth| auth.client_token)
            .unwrap_or_default()
            .trim()
            .to_string();
        if token.is_empty() {
            return Err(Status::failed_precondition(
                "Vault Kubernetes auth returned an empty client token",
            ));
        }
        Ok(token)
    }

    async fn resolve_secret_value(
        &self,
        reference: &VaultSecretReference,
        token: &str,
    ) -> Result<String, Status> {
        let url = self.url_for_path(&reference.api_path)?;
        let response = self
            .client
            .get(url)
            .header("X-Vault-Token", token)
            .send()
            .await
            .map_err(|err| {
                Status::unavailable(format!(
                    "Vault secret read failed for path '{}': {err}",
                    reference.api_path
                ))
            })?;
        let status = response.status();
        if !status.is_success() {
            return Err(vault_secret_status(status, &reference.api_path));
        }

        let body = response.json::<serde_json::Value>().await.map_err(|_| {
            Status::failed_precondition(format!(
                "Vault secret path '{}' returned invalid JSON",
                reference.api_path
            ))
        })?;
        extract_secret_value(&body, reference)
    }

    async fn store_secret_value(
        &self,
        reference: &VaultSecretReference,
        value: &str,
        token: &str,
    ) -> Result<(), Status> {
        let url = self.url_for_path(&reference.api_path)?;
        let body = match reference.kv_version {
            KvVersion::V1 => serde_json::json!({ &reference.key: value }),
            KvVersion::V2 => serde_json::json!({ "data": { &reference.key: value } }),
        };
        let response = self
            .client
            .post(url)
            .header("X-Vault-Token", token)
            .json(&body)
            .send()
            .await
            .map_err(|err| {
                Status::unavailable(format!(
                    "Vault secret write failed for path '{}': {err}",
                    reference.api_path
                ))
            })?;
        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(vault_secret_status(status, &reference.api_path))
        }
    }

    async fn delete_secret_value(&self, api_path: &str, token: &str) -> Result<(), Status> {
        let url = self.url_for_path(api_path)?;
        let response = self
            .client
            .delete(url)
            .header("X-Vault-Token", token)
            .send()
            .await
            .map_err(|err| {
                Status::unavailable(format!(
                    "Vault secret delete failed for path '{api_path}': {err}"
                ))
            })?;
        let status = response.status();
        if status.is_success() || status == StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(vault_secret_status(status, api_path))
        }
    }

    fn url_for_path(&self, path: &str) -> Result<Url, Status> {
        self.settings
            .address
            .join(&format!("v1/{path}"))
            .map_err(|err| Status::internal(format!("failed to build Vault URL: {err}")))
    }
}

impl std::fmt::Debug for VaultCredentialDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultCredentialDriver")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl Clone for VaultCredentialDriver {
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
            driver_name: VaultCredentialDriver::NAME.to_string(),
            driver_version: VERSION.to_string(),
            backend_kind: VaultCredentialDriver::NAME.to_string(),
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
            "vault credential driver does not support listing credentials",
        ))
    }
}

impl VaultDriverSettings {
    fn from_table(config: &toml::Table) -> CoreResult<Self> {
        let config: VaultDriverConfig =
            toml::Value::Table(config.clone())
                .try_into()
                .map_err(|err| {
                    Error::config(format!(
                        "invalid [openshell.credential_drivers.vault]: {err}"
                    ))
                })?;
        let address = config
            .address
            .as_deref()
            .ok_or_else(|| {
                Error::config("[openshell.credential_drivers.vault] address is required")
            })
            .and_then(vault_address)?;
        let mount = config
            .mount
            .as_deref()
            .map_or_else(|| Ok(DEFAULT_MOUNT.to_string()), mount_config)?;
        let kv_version = config
            .kv_version
            .as_deref()
            .map_or_else(|| Ok(KvVersion::V2), KvVersion::parse_config)?;
        let auth_method = config
            .auth_method
            .as_deref()
            .unwrap_or(DEFAULT_AUTH_METHOD)
            .trim();
        let auth = match auth_method {
            "kubernetes" => {
                if config.token_path.is_some() {
                    return Err(Error::config(
                        "[openshell.credential_drivers.vault] token_path requires auth_method = 'token_file'",
                    ));
                }
                let role = config.role.as_deref().ok_or_else(|| {
                    Error::config(
                        "[openshell.credential_drivers.vault] role is required for auth_method = 'kubernetes'",
                    )
                })?;
                let role = trimmed_config_string("role", role)?.to_string();
                let auth_mount = config.kubernetes_auth_mount.as_deref().map_or_else(
                    || Ok(DEFAULT_KUBERNETES_AUTH_MOUNT.to_string()),
                    |mount| path_config("kubernetes_auth_mount", mount),
                )?;
                let service_account_token_path = config
                    .service_account_token_path
                    .unwrap_or_else(|| PathBuf::from(DEFAULT_SERVICE_ACCOUNT_TOKEN_PATH));
                VaultAuthSettings::Kubernetes {
                    role,
                    auth_mount,
                    service_account_token_path,
                }
            }
            "token_file" => {
                if config.role.is_some()
                    || config.kubernetes_auth_mount.is_some()
                    || config.service_account_token_path.is_some()
                {
                    return Err(Error::config(
                        "[openshell.credential_drivers.vault] Kubernetes auth fields require auth_method = 'kubernetes'",
                    ));
                }
                let token_path = config.token_path.ok_or_else(|| {
                    Error::config(
                        "[openshell.credential_drivers.vault] token_path is required for auth_method = 'token_file'",
                    )
                })?;
                VaultAuthSettings::TokenFile { token_path }
            }
            other => {
                return Err(Error::config(format!(
                    "[openshell.credential_drivers.vault] auth_method must be 'kubernetes' or 'token_file', got '{other}'"
                )));
            }
        };

        Ok(Self {
            address,
            mount,
            kv_version,
            auth,
        })
    }
}

impl KvVersion {
    fn parse_config(value: &str) -> CoreResult<Self> {
        match trimmed_config_string("kv_version", value)? {
            "1" => Ok(Self::V1),
            "2" => Ok(Self::V2),
            other => Err(Error::config(format!(
                "[openshell.credential_drivers.vault] kv_version must be '1' or '2', got '{other}'"
            ))),
        }
    }
}

fn vault_address(value: &str) -> CoreResult<Url> {
    let value = trimmed_config_string("address", value)?;
    let mut url = Url::parse(value).map_err(|_| {
        Error::config("[openshell.credential_drivers.vault] address must be an absolute URL")
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(Error::config(
            "[openshell.credential_drivers.vault] address must use http or https",
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::config(
            "[openshell.credential_drivers.vault] address must not include credentials",
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(Error::config(
            "[openshell.credential_drivers.vault] address must not include query or fragment",
        ));
    }
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path().trim_end_matches('/'));
        url.set_path(&path);
    }
    Ok(url)
}

fn timeout_secs(table: &toml::Table) -> CoreResult<u64> {
    let Some(value) = table.get("timeout_secs") else {
        return Ok(DEFAULT_TIMEOUT_SECS);
    };
    let timeout = value.as_integer().ok_or_else(|| {
        Error::config(
            "[openshell.credential_drivers.vault] timeout_secs must be a positive integer",
        )
    })?;
    if timeout <= 0 {
        return Err(Error::config(
            "[openshell.credential_drivers.vault] timeout_secs must be a positive integer",
        ));
    }
    u64::try_from(timeout).map_err(|_| {
        Error::config("[openshell.credential_drivers.vault] timeout_secs is too large")
    })
}

fn mount_config(value: &str) -> CoreResult<String> {
    path_config("mount", value)
}

fn path_config(field_name: &str, value: &str) -> CoreResult<String> {
    let value = trimmed_config_string(field_name, value)?;
    validate_secret_path(value).map_err(|message| {
        Error::config(format!(
            "[openshell.credential_drivers.vault] {field_name} {message}"
        ))
    })?;
    Ok(value.to_string())
}

fn trimmed_config_string<'a>(field_name: &str, value: &'a str) -> CoreResult<&'a str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Error::config(format!(
            "[openshell.credential_drivers.vault] {field_name} must not be empty"
        )));
    }
    if trimmed.len() != value.len() {
        return Err(Error::config(format!(
            "[openshell.credential_drivers.vault] {field_name} must not contain leading or trailing whitespace"
        )));
    }
    Ok(trimmed)
}

fn validate_secret_path(value: &str) -> Result<(), &'static str> {
    if value.is_empty() {
        return Err("must not be empty");
    }
    if value.len() > 1024 {
        return Err("must be 1024 bytes or fewer");
    }
    if value.starts_with('/') || value.ends_with('/') {
        return Err("must be a relative path without leading or trailing slash");
    }
    if value.contains("//") {
        return Err("must not contain empty path segments");
    }
    for segment in value.split('/') {
        if matches!(segment, "." | "..") {
            return Err("must not contain '.' or '..' path segments");
        }
        if !segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err("may only contain ASCII letters, digits, '-', '_', '.', and '/'");
        }
    }
    Ok(())
}

fn api_path_for_reference(mount: &str, kv_version: KvVersion, target: &str) -> String {
    match kv_version {
        KvVersion::V1 => {
            if target == mount || target.starts_with(&format!("{mount}/")) {
                target.to_string()
            } else {
                format!("{mount}/{target}")
            }
        }
        KvVersion::V2 => {
            let data_prefix = format!("{mount}/data/");
            if target.starts_with(&data_prefix) {
                target.to_string()
            } else {
                let logical_path = target.strip_prefix(&format!("{mount}/")).unwrap_or(target);
                format!("{mount}/data/{logical_path}")
            }
        }
    }
}

fn delete_api_path_for_reference(mount: &str, kv_version: KvVersion, target: &str) -> String {
    match kv_version {
        KvVersion::V1 => api_path_for_reference(mount, kv_version, target),
        KvVersion::V2 => {
            let metadata_prefix = format!("{mount}/metadata/");
            if target.starts_with(&metadata_prefix) {
                target.to_string()
            } else {
                let logical_path = target.strip_prefix(&format!("{mount}/")).unwrap_or(target);
                format!("{mount}/metadata/{logical_path}")
            }
        }
    }
}

fn managed_secret_path(provider_name: &str, credential_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(provider_name.as_bytes());
    hasher.update([0]);
    hasher.update(credential_key.as_bytes());
    let digest = hasher.finalize();
    let hex = format!("{digest:x}");
    format!("openshell/provider-credentials/{}", &hex[..40])
}

fn validate_managed_secret_path(
    provider_name: &str,
    credential_key: &str,
    logical_path: &str,
) -> Result<(), Status> {
    let expected = managed_secret_path(provider_name, credential_key);
    if logical_path == expected {
        return Ok(());
    }
    Err(Status::invalid_argument(format!(
        "vault credential handle path does not match the managed path for provider credential '{credential_key}'"
    )))
}

async fn read_secret_file(path: &Path, description: &str) -> Result<String, Status> {
    let contents = tokio::fs::read_to_string(path).await.map_err(|err| {
        Status::unauthenticated(format!(
            "failed to read {description} '{}': {err}",
            path.display()
        ))
    })?;
    let value = contents.trim().to_string();
    if value.is_empty() {
        return Err(Status::unauthenticated(format!(
            "{description} '{}' is empty",
            path.display()
        )));
    }
    Ok(value)
}

fn vault_auth_status(status: StatusCode) -> Status {
    match status {
        StatusCode::UNAUTHORIZED => {
            Status::unauthenticated("Vault Kubernetes auth rejected the service account token")
        }
        StatusCode::FORBIDDEN => {
            Status::permission_denied("Vault Kubernetes auth denied the configured role")
        }
        other => Status::unavailable(format!("Vault Kubernetes auth returned HTTP {other}")),
    }
}

fn vault_secret_status(status: StatusCode, path: &str) -> Status {
    match status {
        StatusCode::UNAUTHORIZED => {
            Status::unauthenticated("Vault rejected the credential driver token")
        }
        StatusCode::FORBIDDEN => Status::permission_denied(format!(
            "Vault token is not allowed to read secret path '{path}'"
        )),
        StatusCode::NOT_FOUND => {
            Status::not_found(format!("Vault secret path '{path}' was not found"))
        }
        other => Status::unavailable(format!("Vault secret path '{path}' returned HTTP {other}")),
    }
}

fn extract_secret_value(
    body: &serde_json::Value,
    reference: &VaultSecretReference,
) -> Result<String, Status> {
    let data = body
        .get("data")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            Status::failed_precondition(format!(
                "Vault secret path '{}' response is missing data",
                reference.api_path
            ))
        })?;
    let fields = match reference.kv_version {
        KvVersion::V1 => data,
        KvVersion::V2 => data
            .get("data")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                Status::failed_precondition(format!(
                    "Vault KV v2 secret path '{}' response is missing data.data",
                    reference.api_path
                ))
            })?,
    };
    let value = fields.get(&reference.key).ok_or_else(|| {
        Status::not_found(format!(
            "Vault secret path '{}' does not contain key '{}'",
            reference.api_path, reference.key
        ))
    })?;
    value.as_str().map(str::to_string).ok_or_else(|| {
        Status::failed_precondition(format!(
            "Vault secret path '{}' key '{}' is not a string",
            reference.api_path, reference.key
        ))
    })
}

#[cfg(test)]
mod tests {
    use openshell_core::proto::CredentialHandle;
    use tonic::Code;
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn handle(value: &str) -> CredentialHandle {
        CredentialHandle {
            driver: "vault".to_string(),
            handle: value.to_string(),
            metadata: std::collections::HashMap::new(),
        }
    }

    fn table(values: &[(&str, toml::Value)]) -> toml::Table {
        values
            .iter()
            .map(|(key, value)| ((*key).to_string(), value.clone()))
            .collect()
    }

    fn token_file(token: &str) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), token).unwrap();
        file
    }

    #[test]
    fn settings_parse_kubernetes_auth() {
        let settings = VaultDriverSettings::from_table(&table(&[
            (
                "address",
                toml::Value::String("http://vault:8200".to_string()),
            ),
            ("mount", toml::Value::String("team-secret".to_string())),
            ("kv_version", toml::Value::String("1".to_string())),
            ("auth_method", toml::Value::String("kubernetes".to_string())),
            ("role", toml::Value::String("openshell-gateway".to_string())),
        ]))
        .unwrap();

        assert_eq!(settings.mount, "team-secret");
        assert_eq!(settings.kv_version, KvVersion::V1);
        assert!(matches!(
            settings.auth,
            VaultAuthSettings::Kubernetes { .. }
        ));
    }

    #[test]
    fn settings_parse_token_file_auth() {
        let settings = VaultDriverSettings::from_table(&table(&[
            (
                "address",
                toml::Value::String("http://vault:8200".to_string()),
            ),
            ("auth_method", toml::Value::String("token_file".to_string())),
            (
                "token_path",
                toml::Value::String("/run/secrets/vault-token".to_string()),
            ),
        ]))
        .unwrap();

        assert!(matches!(settings.auth, VaultAuthSettings::TokenFile { .. }));
        assert_eq!(settings.kv_version, KvVersion::V2);
    }

    #[test]
    fn settings_reject_unknown_fields() {
        let err = VaultDriverSettings::from_table(&table(&[
            (
                "address",
                toml::Value::String("http://vault:8200".to_string()),
            ),
            ("auth_method", toml::Value::String("token_file".to_string())),
            (
                "token_path",
                toml::Value::String("/run/secrets/vault-token".to_string()),
            ),
            ("token", toml::Value::String("literal-secret".to_string())),
        ]))
        .unwrap_err();

        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn settings_reject_token_file_without_token_path() {
        let err = VaultDriverSettings::from_table(&table(&[
            (
                "address",
                toml::Value::String("http://vault:8200".to_string()),
            ),
            ("auth_method", toml::Value::String("token_file".to_string())),
        ]))
        .unwrap_err();

        assert!(err.to_string().contains("token_path is required"));
    }

    #[test]
    fn api_path_builds_kv2_api_path_from_logical_path() {
        assert_eq!(
            api_path_for_reference(
                "secret",
                KvVersion::V2,
                "openshell/provider-credentials/abc"
            ),
            "secret/data/openshell/provider-credentials/abc"
        );
    }

    #[test]
    fn delete_api_path_builds_kv2_metadata_path_from_logical_path() {
        assert_eq!(
            delete_api_path_for_reference(
                "secret",
                KvVersion::V2,
                "openshell/provider-credentials/abc"
            ),
            "secret/metadata/openshell/provider-credentials/abc"
        );
    }

    #[test]
    fn handle_rejects_malformed_value() {
        let err = VaultCredentialDriver::logical_path_from_handle(&handle("providers/nvidia"))
            .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("malformed"));
    }

    #[test]
    fn handle_rejects_invalid_path() {
        let err =
            VaultCredentialDriver::logical_path_from_handle(&handle("v1:../providers/nvidia"))
                .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("path segments"));
    }

    #[test]
    fn handle_rejects_unexpected_managed_path() {
        let err = validate_managed_secret_path(
            "nvidia-prod",
            "NVIDIA_API_KEY",
            "openshell/provider-credentials/other",
        )
        .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("managed path"));
    }

    #[tokio::test]
    async fn store_and_resolve_token_file_kv2_secret() {
        let mock_server = MockServer::start().await;
        let logical_path = managed_secret_path("nvidia-prod", "NVIDIA_API_KEY");
        let api_path = format!("/v1/secret/data/{logical_path}");
        Mock::given(method("POST"))
            .and(path(api_path.as_str()))
            .and(header("x-vault-token", "dev-token"))
            .and(body_string_contains("nvapi-test"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path(api_path.as_str()))
            .and(header("x-vault-token", "dev-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "data": {
                        "value": "nvapi-test"
                    },
                    "metadata": {
                        "version": 1
                    }
                }
            })))
            .mount(&mock_server)
            .await;
        let token_file = token_file("dev-token\n");
        let driver = VaultCredentialDriver::from_config(&table(&[
            ("address", toml::Value::String(mock_server.uri())),
            ("auth_method", toml::Value::String("token_file".to_string())),
            (
                "token_path",
                toml::Value::String(token_file.path().display().to_string()),
            ),
        ]))
        .unwrap();

        let stored = driver
            .store_credential(StoreCredentialRequest {
                provider_name: "nvidia-prod".to_string(),
                credential_key: "NVIDIA_API_KEY".to_string(),
                value: "nvapi-test".to_string(),
                existing_handle: None,
            })
            .await
            .unwrap();
        assert_eq!(stored.handle, format!("v1:{logical_path}"));

        let resolved = driver
            .resolve_credentials(vec![ResolveCredentialRequest {
                request_id: "credential-0".to_string(),
                provider_name: "nvidia-prod".to_string(),
                credential_key: "NVIDIA_API_KEY".to_string(),
                handle: Some(stored),
            }])
            .await
            .unwrap();

        assert_eq!(resolved[0].value, "nvapi-test");
    }

    #[tokio::test]
    async fn store_with_existing_handle_reuses_logical_path() {
        let mock_server = MockServer::start().await;
        let logical_path = managed_secret_path("nvidia-prod", "NVIDIA_API_KEY");
        Mock::given(method("POST"))
            .and(path(format!("/v1/secret/data/{logical_path}")))
            .and(header("x-vault-token", "dev-token"))
            .and(body_string_contains("updated-secret"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;
        let token_file = token_file("dev-token\n");
        let driver = VaultCredentialDriver::from_config(&table(&[
            ("address", toml::Value::String(mock_server.uri())),
            ("auth_method", toml::Value::String("token_file".to_string())),
            (
                "token_path",
                toml::Value::String(token_file.path().display().to_string()),
            ),
        ]))
        .unwrap();

        let stored = driver
            .store_credential(StoreCredentialRequest {
                provider_name: "nvidia-prod".to_string(),
                credential_key: "NVIDIA_API_KEY".to_string(),
                value: "updated-secret".to_string(),
                existing_handle: Some(handle(&format!("v1:{logical_path}"))),
            })
            .await
            .unwrap();

        assert_eq!(stored.handle, format!("v1:{logical_path}"));
    }

    #[tokio::test]
    async fn delete_token_file_kv2_secret() {
        let mock_server = MockServer::start().await;
        let logical_path = managed_secret_path("nvidia-prod", "NVIDIA_API_KEY");
        Mock::given(method("DELETE"))
            .and(path(format!("/v1/secret/metadata/{logical_path}")))
            .and(header("x-vault-token", "dev-token"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&mock_server)
            .await;
        let token_file = token_file("dev-token\n");
        let driver = VaultCredentialDriver::from_config(&table(&[
            ("address", toml::Value::String(mock_server.uri())),
            ("auth_method", toml::Value::String("token_file".to_string())),
            (
                "token_path",
                toml::Value::String(token_file.path().display().to_string()),
            ),
        ]))
        .unwrap();

        driver
            .delete_credential(DeleteCredentialRequest {
                provider_name: "nvidia-prod".to_string(),
                credential_key: "NVIDIA_API_KEY".to_string(),
                handle: Some(handle(&format!("v1:{logical_path}"))),
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn resolve_kubernetes_auth_kv2_secret() {
        let mock_server = MockServer::start().await;
        let logical_path = managed_secret_path("github-prod", "GITHUB_TOKEN");
        Mock::given(method("POST"))
            .and(path("/v1/auth/kubernetes/login"))
            .and(body_string_contains("openshell-gateway"))
            .and(body_string_contains("jwt-test"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "auth": {
                    "client_token": "bao-token"
                }
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/secret/data/{logical_path}")))
            .and(header("x-vault-token", "bao-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "data": {
                        "value": "ghp-test"
                    }
                }
            })))
            .mount(&mock_server)
            .await;
        let jwt_file = token_file("jwt-test\n");
        let driver = VaultCredentialDriver::from_config(&table(&[
            ("address", toml::Value::String(mock_server.uri())),
            ("auth_method", toml::Value::String("kubernetes".to_string())),
            ("role", toml::Value::String("openshell-gateway".to_string())),
            (
                "service_account_token_path",
                toml::Value::String(jwt_file.path().display().to_string()),
            ),
        ]))
        .unwrap();

        let resolved = driver
            .resolve_credentials(vec![ResolveCredentialRequest {
                request_id: "credential-0".to_string(),
                provider_name: "github-prod".to_string(),
                credential_key: "GITHUB_TOKEN".to_string(),
                handle: Some(handle(&format!("v1:{logical_path}"))),
            }])
            .await
            .unwrap();

        assert_eq!(resolved[0].value, "ghp-test");
    }

    #[tokio::test]
    async fn resolve_maps_missing_key() {
        let mock_server = MockServer::start().await;
        let logical_path = managed_secret_path("nvidia-prod", "NVIDIA_API_KEY");
        Mock::given(method("GET"))
            .and(path(format!("/v1/secret/data/{logical_path}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "data": {}
                }
            })))
            .mount(&mock_server)
            .await;
        let token_file = token_file("dev-token\n");
        let driver = VaultCredentialDriver::from_config(&table(&[
            ("address", toml::Value::String(mock_server.uri())),
            ("auth_method", toml::Value::String("token_file".to_string())),
            (
                "token_path",
                toml::Value::String(token_file.path().display().to_string()),
            ),
        ]))
        .unwrap();

        let err = driver
            .resolve_credentials(vec![ResolveCredentialRequest {
                request_id: "credential-0".to_string(),
                provider_name: "nvidia-prod".to_string(),
                credential_key: "NVIDIA_API_KEY".to_string(),
                handle: Some(handle(&format!("v1:{logical_path}"))),
            }])
            .await
            .unwrap_err();

        assert_eq!(err.code(), Code::NotFound);
        assert!(err.message().contains("does not contain key"));
    }

    #[tokio::test]
    async fn resolve_maps_permission_denied() {
        let mock_server = MockServer::start().await;
        let logical_path = managed_secret_path("nvidia-prod", "NVIDIA_API_KEY");
        Mock::given(method("GET"))
            .and(path(format!("/v1/secret/data/{logical_path}")))
            .respond_with(ResponseTemplate::new(403))
            .mount(&mock_server)
            .await;
        let token_file = token_file("dev-token\n");
        let driver = VaultCredentialDriver::from_config(&table(&[
            ("address", toml::Value::String(mock_server.uri())),
            ("auth_method", toml::Value::String("token_file".to_string())),
            (
                "token_path",
                toml::Value::String(token_file.path().display().to_string()),
            ),
        ]))
        .unwrap();

        let err = driver
            .resolve_credentials(vec![ResolveCredentialRequest {
                request_id: "credential-0".to_string(),
                provider_name: "nvidia-prod".to_string(),
                credential_key: "NVIDIA_API_KEY".to_string(),
                handle: Some(handle(&format!("v1:{logical_path}"))),
            }])
            .await
            .unwrap_err();

        assert_eq!(err.code(), Code::PermissionDenied);
    }
}
