// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypted database-backed credential storage driver.
//!
//! The driver persists encrypted credential envelopes through a caller-provided
//! object store. `openshell-server` supplies the object-store adapter for the
//! gateway database, while this crate owns the credential driver behavior and
//! envelope cryptography.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as BASE64, STANDARD_NO_PAD as BASE64_NO_PAD},
};
use openshell_core::proto::CredentialHandle;
use openshell_core::proto::credentials::v1::{
    DeleteCredentialRequest, ResolveCredentialRequest, ResolvedCredential, StoreCredentialRequest,
};
use openshell_core::{Error, Result as CoreResult};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tonic::Status;

const HANDLE_VERSION: &str = "v1";
const ENVELOPE_VERSION: u32 = 1;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const HANDLE_ID_LEN: usize = 64;
const ALGORITHM: &str = "AES-256-GCM";
const DEFAULT_KEY_ENCRYPTION_KEY_FILE: &str = "key-encryption-key.bin";

pub const DRIVER_NAME: &str = "openshell-driver-db-credstore";
pub const OBJECT_TYPE: &str = "credential.gateway-encrypted";

#[derive(Debug, Clone)]
pub struct DbCredstoreCredentialDriver {
    store: Arc<dyn DbCredstoreObjectStore>,
    crypto: EncryptedGatewayCredentialStoreCrypto,
}

#[async_trait]
pub trait DbCredstoreObjectStore: std::fmt::Debug + Send + Sync {
    async fn get_credential_object(
        &self,
        object_type: &str,
        id: &str,
        operation: &'static str,
    ) -> Result<Option<StoredCredentialObject>, Status>;

    async fn put_credential_object(
        &self,
        write: CredentialObjectWrite,
        operation: &'static str,
    ) -> Result<(), Status>;

    async fn delete_credential_object(
        &self,
        object_type: &str,
        id: &str,
        expected_resource_version: u64,
        operation: &'static str,
    ) -> Result<(), Status>;
}

#[derive(Debug, Clone)]
pub struct StoredCredentialObject {
    pub object_type: String,
    pub id: String,
    pub payload: Vec<u8>,
    pub resource_version: u64,
}

#[derive(Debug, Clone)]
pub struct CredentialObjectWrite {
    pub object_type: String,
    pub id: String,
    pub name: String,
    pub payload: Vec<u8>,
    pub labels: Option<String>,
    pub condition: DbCredstoreWriteCondition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbCredstoreWriteCondition {
    MustCreate,
    MatchResourceVersion(u64),
}

#[derive(Clone)]
pub struct EncryptedGatewayCredentialStoreCrypto {
    state: EncryptedGatewayCredentialState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EncryptedGatewayCredentialSettings {
    key_encryption_key_path: Option<PathBuf>,
    key_encryption_key_env: Option<String>,
}

#[derive(Clone)]
struct EncryptedGatewayCredentialState {
    settings: EncryptedGatewayCredentialSettings,
    key_encryption_key: [u8; KEY_LEN],
    key_encryption_key_id: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct EncryptedGatewayCredentialConfig {
    key_encryption_key_path: Option<PathBuf>,
    key_encryption_key_env: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedCredentialEnvelope {
    version: u32,
    id: String,
    provider_name: String,
    credential_key: String,
    algorithm: String,
    key_encryption_key_id: String,
    wrapped_dek: EncryptedBytes,
    value: EncryptedBytes,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedBytes {
    nonce: String,
    ciphertext: String,
}

impl DbCredstoreCredentialDriver {
    pub const NAME: &'static str = DRIVER_NAME;
    pub const OBJECT_TYPE: &'static str = OBJECT_TYPE;

    pub fn from_config(
        store: Arc<dyn DbCredstoreObjectStore>,
        config: &toml::Table,
    ) -> CoreResult<Self> {
        Ok(Self {
            store,
            crypto: EncryptedGatewayCredentialStoreCrypto::from_config(config)?,
        })
    }

    pub async fn store_credential(
        &self,
        request: StoreCredentialRequest,
    ) -> Result<CredentialHandle, Status> {
        let credential_key = EncryptedGatewayCredentialStoreCrypto::validate_credential_key(
            &request.credential_key,
        )?
        .to_string();
        let provider_name =
            EncryptedGatewayCredentialStoreCrypto::validate_provider_name(&request.provider_name)?
                .to_string();

        if let Some(existing_handle) = request.existing_handle.as_ref() {
            let id = EncryptedGatewayCredentialStoreCrypto::id_from_handle(existing_handle)?;
            let existing = self
                .store
                .get_credential_object(OBJECT_TYPE, &id, "load existing credential")
                .await?;
            if let Some(record) = existing {
                let envelope = deserialize_credential_envelope(&record)?;
                EncryptedGatewayCredentialStoreCrypto::ensure_envelope_owner(
                    &envelope,
                    &id,
                    &provider_name,
                    &credential_key,
                )?;
                self.write_envelope(
                    &id,
                    &provider_name,
                    &credential_key,
                    &request.value,
                    DbCredstoreWriteCondition::MatchResourceVersion(record.resource_version),
                )
                .await?;
            } else {
                self.write_envelope(
                    &id,
                    &provider_name,
                    &credential_key,
                    &request.value,
                    DbCredstoreWriteCondition::MustCreate,
                )
                .await?;
            }
            return self.crypto.credential_handle(&id);
        }

        for _ in 0..16 {
            let id = EncryptedGatewayCredentialStoreCrypto::new_handle_id()?;
            match self
                .write_envelope(
                    &id,
                    &provider_name,
                    &credential_key,
                    &request.value,
                    DbCredstoreWriteCondition::MustCreate,
                )
                .await
            {
                Ok(()) => return self.crypto.credential_handle(&id),
                Err(err) if err.code() == tonic::Code::AlreadyExists => {}
                Err(err) => return Err(err),
            }
        }

        Err(Status::unavailable(
            "failed to allocate unused default credential handle",
        ))
    }

    pub async fn delete_credential(&self, request: DeleteCredentialRequest) -> Result<(), Status> {
        let handle =
            EncryptedGatewayCredentialStoreCrypto::handle_from_request("delete", request.handle)?;
        let id = EncryptedGatewayCredentialStoreCrypto::id_from_handle(&handle)?;
        let record = self
            .store
            .get_credential_object(OBJECT_TYPE, &id, "load credential for deletion")
            .await?;
        let Some(record) = record else {
            return Ok(());
        };

        let envelope = deserialize_credential_envelope(&record)?;
        EncryptedGatewayCredentialStoreCrypto::ensure_envelope_owner(
            &envelope,
            &id,
            EncryptedGatewayCredentialStoreCrypto::validate_provider_name(&request.provider_name)?,
            EncryptedGatewayCredentialStoreCrypto::validate_credential_key(
                &request.credential_key,
            )?,
        )?;

        self.store
            .delete_credential_object(
                OBJECT_TYPE,
                &id,
                record.resource_version,
                "delete credential",
            )
            .await
    }

    pub async fn resolve_credentials(
        &self,
        requests: Vec<ResolveCredentialRequest>,
    ) -> Result<Vec<ResolvedCredential>, Status> {
        let mut responses = Vec::with_capacity(requests.len());
        for request in requests {
            let handle = EncryptedGatewayCredentialStoreCrypto::handle_from_request(
                &request.request_id,
                request.handle,
            )?;
            let id = EncryptedGatewayCredentialStoreCrypto::id_from_handle(&handle)?;
            let record = self
                .store
                .get_credential_object(OBJECT_TYPE, &id, "load credential")
                .await?
                .ok_or_else(|| {
                    Status::not_found(format!("default credential '{id}' was not found"))
                })?;
            let envelope = deserialize_credential_envelope(&record)?;
            EncryptedGatewayCredentialStoreCrypto::ensure_envelope_owner(
                &envelope,
                &id,
                EncryptedGatewayCredentialStoreCrypto::validate_provider_name(
                    &request.provider_name,
                )?,
                EncryptedGatewayCredentialStoreCrypto::validate_credential_key(
                    &request.credential_key,
                )?,
            )?;
            let value = self.crypto.decrypt_envelope(&envelope)?;
            responses.push(ResolvedCredential {
                request_id: request.request_id,
                value,
                expires_at_ms: 0,
            });
        }

        Ok(responses)
    }

    async fn write_envelope(
        &self,
        id: &str,
        provider_name: &str,
        credential_key: &str,
        value: &str,
        condition: DbCredstoreWriteCondition,
    ) -> Result<(), Status> {
        let envelope = self
            .crypto
            .encrypt_envelope(id, provider_name, credential_key, value)?;
        let payload = EncryptedGatewayCredentialStoreCrypto::serialize_envelope(&envelope)?;
        let labels = credential_labels(provider_name, credential_key)?;

        self.store
            .put_credential_object(
                CredentialObjectWrite {
                    object_type: OBJECT_TYPE.to_string(),
                    id: id.to_string(),
                    name: id.to_string(),
                    payload,
                    labels: Some(labels),
                    condition,
                },
                "persist credential",
            )
            .await
    }
}

impl EncryptedGatewayCredentialStoreCrypto {
    pub fn from_config(config: &toml::Table) -> CoreResult<Self> {
        let settings = EncryptedGatewayCredentialSettings::from_table(config)?;
        Ok(Self {
            state: EncryptedGatewayCredentialState::from_settings(settings)?,
        })
    }

    pub fn new_handle_id() -> Result<String, Status> {
        new_handle_id()
    }

    pub fn credential_handle(&self, id: &str) -> Result<CredentialHandle, Status> {
        validate_handle_id(id)?;
        Ok(credential_handle(&self.state, id))
    }

    pub fn handle_from_request(
        request_id: &str,
        handle: Option<CredentialHandle>,
    ) -> Result<CredentialHandle, Status> {
        let handle = handle.ok_or_else(|| {
            Status::invalid_argument(format!(
                "default credential storage request '{request_id}' is missing handle"
            ))
        })?;
        validate_handle_owner(&handle)?;
        Ok(handle)
    }

    pub fn id_from_handle(handle: &CredentialHandle) -> Result<String, Status> {
        validate_handle_owner(handle)?;
        let id = handle
            .handle
            .strip_prefix(&format!("{HANDLE_VERSION}:"))
            .ok_or_else(|| {
                Status::invalid_argument("default credential storage handle is malformed")
            })?;
        validate_handle_id(id)?;
        Ok(id.to_string())
    }

    pub fn encrypt_envelope(
        &self,
        id: &str,
        provider_name: &str,
        credential_key: &str,
        value: &str,
    ) -> Result<EncryptedCredentialEnvelope, Status> {
        encrypt_envelope(&self.state, id, provider_name, credential_key, value)
    }

    pub fn decrypt_envelope(
        &self,
        envelope: &EncryptedCredentialEnvelope,
    ) -> Result<String, Status> {
        decrypt_envelope(&self.state, envelope)
    }

    pub fn ensure_envelope_owner(
        envelope: &EncryptedCredentialEnvelope,
        id: &str,
        provider_name: &str,
        credential_key: &str,
    ) -> Result<(), Status> {
        ensure_envelope_owner(envelope, id, provider_name, credential_key)
    }

    pub fn validate_provider_name(value: &str) -> Result<&str, Status> {
        validate_provider_name(value)
    }

    pub fn validate_credential_key(value: &str) -> Result<&str, Status> {
        validate_credential_key(value)
    }

    pub fn serialize_envelope(envelope: &EncryptedCredentialEnvelope) -> Result<Vec<u8>, Status> {
        serialize_envelope(envelope)
    }

    pub fn deserialize_envelope(
        bytes: &[u8],
        description: impl std::fmt::Display,
    ) -> Result<EncryptedCredentialEnvelope, Status> {
        serde_json::from_slice(bytes).map_err(|err| {
            Status::data_loss(format!(
                "default credential storage object '{description}' has invalid envelope JSON: {err}"
            ))
        })
    }
}

impl std::fmt::Debug for EncryptedGatewayCredentialStoreCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedGatewayCredentialStoreCrypto")
            .field("settings", &self.state.settings)
            .field("key_encryption_key_id", &self.state.key_encryption_key_id)
            .finish_non_exhaustive()
    }
}

impl EncryptedGatewayCredentialSettings {
    fn from_table(config: &toml::Table) -> CoreResult<Self> {
        let config: EncryptedGatewayCredentialConfig = toml::Value::Table(config.clone())
            .try_into()
            .map_err(|err| {
                Error::config(format!(
                    "invalid [openshell.gateway.credential_storage]: {err}"
                ))
            })?;

        if config.key_encryption_key_path.is_some() && config.key_encryption_key_env.is_some() {
            return Err(Error::config(
                "[openshell.gateway.credential_storage] set only one of key_encryption_key_path or key_encryption_key_env",
            ));
        }

        let key_encryption_key_path = match config.key_encryption_key_path {
            Some(path) => Some(validate_path("key_encryption_key_path", path)?),
            None if config.key_encryption_key_env.is_some() => None,
            None => Some(default_key_encryption_key_path()?),
        };
        let key_encryption_key_env = config
            .key_encryption_key_env
            .map(|name| validate_env_name("key_encryption_key_env", &name))
            .transpose()?;

        Ok(Self {
            key_encryption_key_path,
            key_encryption_key_env,
        })
    }
}

impl EncryptedGatewayCredentialState {
    fn from_settings(settings: EncryptedGatewayCredentialSettings) -> CoreResult<Self> {
        let key_encryption_key = load_key_encryption_key(&settings)?;
        let key_encryption_key_id = key_id(&key_encryption_key);
        Ok(Self {
            settings,
            key_encryption_key,
            key_encryption_key_id,
        })
    }
}

fn default_key_encryption_key_path() -> CoreResult<PathBuf> {
    let state_dir = openshell_core::paths::openshell_state_dir().map_err(|err| {
        Error::config(format!(
            "failed to resolve default credential storage key-encryption key path: {err}"
        ))
    })?;
    Ok(state_dir
        .join("gateway")
        .join("credentials")
        .join(DEFAULT_KEY_ENCRYPTION_KEY_FILE))
}

fn validate_path(field_name: &str, path: PathBuf) -> CoreResult<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(Error::config(format!(
            "[openshell.gateway.credential_storage] {field_name} must not be empty"
        )));
    }
    if !path.is_absolute() {
        return Err(Error::config(format!(
            "[openshell.gateway.credential_storage] {field_name} must be absolute"
        )));
    }
    Ok(path)
}

fn validate_env_name(field_name: &str, value: &str) -> CoreResult<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() != value.len() {
        return Err(Error::config(format!(
            "[openshell.gateway.credential_storage] {field_name} must not be empty or contain surrounding whitespace"
        )));
    }
    if !trimmed
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(Error::config(format!(
            "[openshell.gateway.credential_storage] {field_name} must name an environment variable using only letters, digits, and underscores"
        )));
    }
    Ok(trimmed.to_string())
}

fn load_key_encryption_key(
    settings: &EncryptedGatewayCredentialSettings,
) -> CoreResult<[u8; KEY_LEN]> {
    if let Some(env_name) = &settings.key_encryption_key_env {
        let value = std::env::var(env_name).map_err(|_| {
            Error::config(format!(
                "[openshell.gateway.credential_storage] environment variable '{env_name}' is not set"
            ))
        })?;
        return decode_key_encryption_key_base64(&value).map_err(Error::config);
    }
    let path = settings
        .key_encryption_key_path
        .as_ref()
        .expect("settings always has key_encryption_key_path unless key_encryption_key_env is set");
    load_or_create_file_key_encryption_key(path)
}

fn decode_key_encryption_key_base64(value: &str) -> Result<[u8; KEY_LEN], String> {
    let trimmed = value.trim();
    let bytes = BASE64
        .decode(trimmed)
        .or_else(|_| BASE64_NO_PAD.decode(trimmed))
        .map_err(|err| {
            format!("key_encryption_key_env value must be base64-encoded 32-byte key: {err}")
        })?;
    fixed_bytes::<KEY_LEN>(&bytes)
        .map_err(|()| "key_encryption_key_env value must decode to exactly 32 bytes".to_string())
}

fn load_or_create_file_key_encryption_key(path: &Path) -> CoreResult<[u8; KEY_LEN]> {
    match fs::read(path) {
        Ok(bytes) => {
            openshell_core::paths::set_file_owner_only(path).map_err(|err| {
                Error::config(format!(
                    "failed to restrict default credential storage key-encryption key '{}': {err}",
                    path.display()
                ))
            })?;
            return fixed_bytes::<KEY_LEN>(&bytes).map_err(|()| {
                Error::config(format!(
                    "[openshell.gateway.credential_storage] key_encryption_key_path '{}' must contain exactly 32 bytes",
                    path.display()
                ))
            });
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(Error::config(format!(
                "failed to read default credential storage key-encryption key '{}': {err}",
                path.display()
            )));
        }
    }

    openshell_core::paths::ensure_parent_dir_restricted(path).map_err(|err| {
        Error::config(format!(
            "failed to prepare default credential storage key-encryption key directory '{}': {err}",
            path.display()
        ))
    })?;
    let key_encryption_key = random_bytes_core::<KEY_LEN>()?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    match options.open(path) {
        Ok(mut file) => {
            if let Err(err) = file.write_all(&key_encryption_key) {
                let _ = fs::remove_file(path);
                return Err(Error::config(format!(
                    "failed to write default credential storage key-encryption key '{}': {err}",
                    path.display()
                )));
            }
            openshell_core::paths::set_file_owner_only(path).map_err(|err| {
                Error::config(format!(
                    "failed to restrict default credential storage key-encryption key '{}': {err}",
                    path.display()
                ))
            })?;
            Ok(key_encryption_key)
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            load_or_create_file_key_encryption_key(path)
        }
        Err(err) => Err(Error::config(format!(
            "failed to create default credential storage key-encryption key '{}': {err}",
            path.display()
        ))),
    }
}

fn new_handle_id() -> Result<String, Status> {
    Ok(hex_encode(&random_bytes_status::<KEY_LEN>()?))
}

fn credential_handle(state: &EncryptedGatewayCredentialState, id: &str) -> CredentialHandle {
    CredentialHandle {
        driver: DRIVER_NAME.to_string(),
        handle: format!("{HANDLE_VERSION}:{id}"),
        metadata: [
            ("algorithm".to_string(), ALGORITHM.to_string()),
            (
                "key_encryption_key_id".to_string(),
                state.key_encryption_key_id.clone(),
            ),
        ]
        .into_iter()
        .collect(),
    }
}

fn validate_handle_owner(handle: &CredentialHandle) -> Result<(), Status> {
    if handle.driver.trim() == DRIVER_NAME {
        return Ok(());
    }
    Err(Status::invalid_argument(format!(
        "default credential storage cannot use handle owned by '{}'",
        handle.driver
    )))
}

fn encrypt_envelope(
    state: &EncryptedGatewayCredentialState,
    id: &str,
    provider_name: &str,
    credential_key: &str,
    value: &str,
) -> Result<EncryptedCredentialEnvelope, Status> {
    let dek = random_bytes_status::<KEY_LEN>()?;
    let wrapped_dek = encrypt_bytes(
        &state.key_encryption_key,
        &dek_aad(id, provider_name, credential_key),
        &dek,
    )?;
    let encrypted_value = encrypt_bytes(
        &dek,
        &value_aad(id, provider_name, credential_key),
        value.as_bytes(),
    )?;

    Ok(EncryptedCredentialEnvelope {
        version: ENVELOPE_VERSION,
        id: id.to_string(),
        provider_name: provider_name.to_string(),
        credential_key: credential_key.to_string(),
        algorithm: ALGORITHM.to_string(),
        key_encryption_key_id: state.key_encryption_key_id.clone(),
        wrapped_dek,
        value: encrypted_value,
    })
}

fn decrypt_envelope(
    state: &EncryptedGatewayCredentialState,
    envelope: &EncryptedCredentialEnvelope,
) -> Result<String, Status> {
    validate_envelope_metadata(envelope)?;
    if envelope.key_encryption_key_id != state.key_encryption_key_id {
        return Err(Status::failed_precondition(
            "default credential storage object was encrypted with a different key-encryption key",
        ));
    }
    let dek = decrypt_bytes(
        &state.key_encryption_key,
        &dek_aad(
            &envelope.id,
            &envelope.provider_name,
            &envelope.credential_key,
        ),
        &envelope.wrapped_dek,
    )?;
    let dek = fixed_bytes::<KEY_LEN>(&dek)
        .map_err(|()| Status::data_loss("default credential storage DEK has invalid length"))?;
    let plaintext = decrypt_bytes(
        &dek,
        &value_aad(
            &envelope.id,
            &envelope.provider_name,
            &envelope.credential_key,
        ),
        &envelope.value,
    )?;
    String::from_utf8(plaintext)
        .map_err(|_| Status::data_loss("default credential storage value is not valid UTF-8"))
}

fn encrypt_bytes(
    key_bytes: &[u8; KEY_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<EncryptedBytes, Status> {
    let nonce = random_bytes_status::<NONCE_LEN>()?;
    let key = aead_key(key_bytes)?;
    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad),
        &mut in_out,
    )
    .map_err(|_| Status::internal("failed to encrypt default credential storage value"))?;
    Ok(EncryptedBytes {
        nonce: BASE64.encode(nonce),
        ciphertext: BASE64.encode(in_out),
    })
}

fn decrypt_bytes(
    key_bytes: &[u8; KEY_LEN],
    aad: &[u8],
    encrypted: &EncryptedBytes,
) -> Result<Vec<u8>, Status> {
    let nonce = decode_b64_array::<NONCE_LEN>("nonce", &encrypted.nonce)?;
    let mut in_out = decode_b64_vec("ciphertext", &encrypted.ciphertext)?;
    let key = aead_key(key_bytes)?;
    let plaintext = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut in_out,
        )
        .map_err(|_| Status::data_loss("failed to decrypt default credential storage value"))?;
    Ok(plaintext.to_vec())
}

fn aead_key(key_bytes: &[u8; KEY_LEN]) -> Result<LessSafeKey, Status> {
    let unbound = UnboundKey::new(&AES_256_GCM, key_bytes).map_err(|_| {
        Status::internal("failed to initialize default credential storage AEAD key")
    })?;
    Ok(LessSafeKey::new(unbound))
}

fn dek_aad(id: &str, provider_name: &str, credential_key: &str) -> Vec<u8> {
    format!("openshell:gateway-credential-storage:v1:dek:{id}:{provider_name}:{credential_key}")
        .into_bytes()
}

fn value_aad(id: &str, provider_name: &str, credential_key: &str) -> Vec<u8> {
    format!("openshell:gateway-credential-storage:v1:value:{id}:{provider_name}:{credential_key}")
        .into_bytes()
}

fn serialize_envelope(envelope: &EncryptedCredentialEnvelope) -> Result<Vec<u8>, Status> {
    serde_json::to_vec(envelope).map_err(|err| {
        Status::internal(format!(
            "failed to serialize default credential storage envelope: {err}"
        ))
    })
}

fn deserialize_credential_envelope(
    record: &StoredCredentialObject,
) -> Result<EncryptedCredentialEnvelope, Status> {
    EncryptedGatewayCredentialStoreCrypto::deserialize_envelope(
        &record.payload,
        format!("{}/{}", record.object_type, record.id),
    )
}

fn credential_labels(provider_name: &str, credential_key: &str) -> Result<String, Status> {
    serde_json::to_string(&HashMap::from([
        ("provider_name", provider_name),
        ("credential_key", credential_key),
    ]))
    .map_err(|err| {
        Status::internal(format!(
            "failed to serialize default credential labels: {err}"
        ))
    })
}

fn validate_envelope_metadata(envelope: &EncryptedCredentialEnvelope) -> Result<(), Status> {
    if envelope.version != ENVELOPE_VERSION {
        return Err(Status::data_loss(format!(
            "default credential storage envelope version {} is unsupported",
            envelope.version
        )));
    }
    validate_handle_id(&envelope.id)?;
    if envelope.algorithm != ALGORITHM {
        return Err(Status::data_loss(format!(
            "default credential storage algorithm '{}' is unsupported",
            envelope.algorithm
        )));
    }
    validate_provider_name(&envelope.provider_name)?;
    validate_credential_key(&envelope.credential_key)?;
    Ok(())
}

fn ensure_envelope_owner(
    envelope: &EncryptedCredentialEnvelope,
    id: &str,
    provider_name: &str,
    credential_key: &str,
) -> Result<(), Status> {
    validate_envelope_metadata(envelope)?;
    if envelope.id == id
        && envelope.provider_name == provider_name
        && envelope.credential_key == credential_key
    {
        return Ok(());
    }
    Err(Status::failed_precondition(
        "default credential storage handle is not managed for this provider credential",
    ))
}

fn validate_handle_id(id: &str) -> Result<(), Status> {
    if id.len() == HANDLE_ID_LEN
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Ok(());
    }
    Err(Status::invalid_argument(
        "default credential storage handle id is invalid",
    ))
}

fn validate_provider_name(value: &str) -> Result<&str, Status> {
    validate_request_component("provider_name", value)
}

fn validate_credential_key(value: &str) -> Result<&str, Status> {
    validate_request_component("credential_key", value)
}

fn validate_request_component<'a>(field_name: &str, value: &'a str) -> Result<&'a str, Status> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Status::invalid_argument(format!(
            "default credential storage request {field_name} is required"
        )));
    }
    if trimmed.len() != value.len() {
        return Err(Status::invalid_argument(format!(
            "default credential storage request {field_name} must not contain leading or trailing whitespace"
        )));
    }
    Ok(trimmed)
}

fn decode_b64_array<const N: usize>(field_name: &str, value: &str) -> Result<[u8; N], Status> {
    let bytes = decode_b64_vec(field_name, value)?;
    fixed_bytes::<N>(&bytes).map_err(|()| {
        Status::data_loss(format!(
            "default credential storage envelope {field_name} has invalid length"
        ))
    })
}

fn decode_b64_vec(field_name: &str, value: &str) -> Result<Vec<u8>, Status> {
    BASE64.decode(value).map_err(|err| {
        Status::data_loss(format!(
            "default credential storage envelope {field_name} is invalid base64: {err}"
        ))
    })
}

fn fixed_bytes<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ()> {
    bytes.try_into().map_err(|_| ())
}

fn random_bytes_core<const N: usize>() -> CoreResult<[u8; N]> {
    let mut bytes = [0_u8; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| Error::config("failed to generate default credential storage key material"))?;
    Ok(bytes)
}

fn random_bytes_status<const N: usize>() -> Result<[u8; N], Status> {
    let mut bytes = [0_u8; N];
    SystemRandom::new().fill(&mut bytes).map_err(|_| {
        Status::internal("failed to generate default credential storage randomness")
    })?;
    Ok(bytes)
}

fn key_id(key: &[u8; KEY_LEN]) -> String {
    let digest = Sha256::digest(key);
    format!("sha256:{}", hex_encode(&digest))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tonic::Code;

    #[derive(Debug, Default)]
    struct MemoryObjectStore {
        objects: Mutex<HashMap<String, StoredCredentialObject>>,
    }

    #[async_trait]
    impl DbCredstoreObjectStore for MemoryObjectStore {
        async fn get_credential_object(
            &self,
            _object_type: &str,
            id: &str,
            _operation: &'static str,
        ) -> Result<Option<StoredCredentialObject>, Status> {
            Ok(self.objects.lock().unwrap().get(id).cloned())
        }

        async fn put_credential_object(
            &self,
            write: CredentialObjectWrite,
            _operation: &'static str,
        ) -> Result<(), Status> {
            let mut objects = self.objects.lock().unwrap();
            match write.condition {
                DbCredstoreWriteCondition::MustCreate if objects.contains_key(&write.id) => {
                    return Err(Status::already_exists("object already exists"));
                }
                DbCredstoreWriteCondition::MatchResourceVersion(expected) => {
                    let Some(current) = objects.get(&write.id) else {
                        return Err(Status::not_found("object not found"));
                    };
                    if current.resource_version != expected {
                        return Err(Status::aborted("resource version conflict"));
                    }
                }
                DbCredstoreWriteCondition::MustCreate => {}
            }

            let resource_version = objects
                .get(&write.id)
                .map_or(1, |current| current.resource_version + 1);
            objects.insert(
                write.id.clone(),
                StoredCredentialObject {
                    object_type: write.object_type,
                    id: write.id,
                    payload: write.payload,
                    resource_version,
                },
            );
            Ok(())
        }

        async fn delete_credential_object(
            &self,
            _object_type: &str,
            id: &str,
            expected_resource_version: u64,
            _operation: &'static str,
        ) -> Result<(), Status> {
            let mut objects = self.objects.lock().unwrap();
            let Some(current) = objects.get(id) else {
                return Ok(());
            };
            if current.resource_version != expected_resource_version {
                return Err(Status::aborted("resource version conflict"));
            }
            objects.remove(id);
            Ok(())
        }
    }

    fn crypto_for_key_encryption_key_path(path: &Path) -> EncryptedGatewayCredentialStoreCrypto {
        let mut config = toml::Table::new();
        config.insert(
            "key_encryption_key_path".to_string(),
            toml::Value::String(path.to_string_lossy().to_string()),
        );
        EncryptedGatewayCredentialStoreCrypto::from_config(&config).unwrap()
    }

    fn driver_config_for_key_encryption_key_path(path: &Path) -> toml::Table {
        let mut config = toml::Table::new();
        config.insert(
            "key_encryption_key_path".to_string(),
            toml::Value::String(path.to_string_lossy().to_string()),
        );
        config
    }

    fn request(
        provider_name: &str,
        credential_key: &str,
        value: &str,
        existing_handle: Option<CredentialHandle>,
    ) -> StoreCredentialRequest {
        StoreCredentialRequest {
            provider_name: provider_name.to_string(),
            credential_key: credential_key.to_string(),
            value: value.to_string(),
            existing_handle,
        }
    }

    fn resolve_request(
        request_id: &str,
        provider_name: &str,
        credential_key: &str,
        handle: CredentialHandle,
    ) -> ResolveCredentialRequest {
        ResolveCredentialRequest {
            request_id: request_id.to_string(),
            provider_name: provider_name.to_string(),
            credential_key: credential_key.to_string(),
            handle: Some(handle),
        }
    }

    #[tokio::test]
    async fn driver_stores_resolves_updates_and_deletes_encrypted_objects() {
        let tmp = tempfile::tempdir().unwrap();
        let config = driver_config_for_key_encryption_key_path(
            &tmp.path().join(DEFAULT_KEY_ENCRYPTION_KEY_FILE),
        );
        let store = Arc::new(MemoryObjectStore::default());
        let object_store: Arc<dyn DbCredstoreObjectStore> = store.clone();
        let driver = DbCredstoreCredentialDriver::from_config(object_store, &config).unwrap();

        let first = driver
            .store_credential(request(
                "openai-local",
                "OPENAI_API_KEY",
                "sk-original",
                None,
            ))
            .await
            .unwrap();
        assert_eq!(first.driver, DbCredstoreCredentialDriver::NAME);
        let handle_id = first.handle.strip_prefix("v1:").unwrap();
        let payload = store
            .objects
            .lock()
            .unwrap()
            .get(handle_id)
            .unwrap()
            .payload
            .clone();
        assert!(!String::from_utf8_lossy(&payload).contains("sk-original"));

        let resolved = driver
            .resolve_credentials(vec![resolve_request(
                "credential-0",
                "openai-local",
                "OPENAI_API_KEY",
                first.clone(),
            )])
            .await
            .unwrap();
        assert_eq!(resolved[0].value, "sk-original");

        let updated = driver
            .store_credential(request(
                "openai-local",
                "OPENAI_API_KEY",
                "sk-updated",
                Some(first.clone()),
            ))
            .await
            .unwrap();
        assert_eq!(updated.handle, first.handle);

        let resolved = driver
            .resolve_credentials(vec![resolve_request(
                "credential-0",
                "openai-local",
                "OPENAI_API_KEY",
                updated.clone(),
            )])
            .await
            .unwrap();
        assert_eq!(resolved[0].value, "sk-updated");

        driver
            .delete_credential(DeleteCredentialRequest {
                provider_name: "openai-local".to_string(),
                credential_key: "OPENAI_API_KEY".to_string(),
                handle: Some(updated.clone()),
            })
            .await
            .unwrap();

        let err = driver
            .resolve_credentials(vec![resolve_request(
                "credential-0",
                "openai-local",
                "OPENAI_API_KEY",
                updated,
            )])
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::NotFound);
    }

    #[test]
    fn encrypts_decrypts_and_serializes_envelope() {
        let tmp = tempfile::tempdir().unwrap();
        let crypto =
            crypto_for_key_encryption_key_path(&tmp.path().join(DEFAULT_KEY_ENCRYPTION_KEY_FILE));
        let id = EncryptedGatewayCredentialStoreCrypto::new_handle_id().unwrap();
        let envelope = crypto
            .encrypt_envelope(&id, "openai-local", "OPENAI_API_KEY", "sk-original")
            .unwrap();
        let serialized =
            EncryptedGatewayCredentialStoreCrypto::serialize_envelope(&envelope).unwrap();
        assert!(!String::from_utf8_lossy(&serialized).contains("sk-original"));

        let envelope =
            EncryptedGatewayCredentialStoreCrypto::deserialize_envelope(&serialized, "test")
                .unwrap();
        assert_eq!(crypto.decrypt_envelope(&envelope).unwrap(), "sk-original");
    }

    #[test]
    fn file_key_encryption_key_is_reused_across_instances() {
        let tmp = tempfile::tempdir().unwrap();
        let key_encryption_key_path = tmp.path().join(DEFAULT_KEY_ENCRYPTION_KEY_FILE);
        let crypto = crypto_for_key_encryption_key_path(&key_encryption_key_path);
        let id = EncryptedGatewayCredentialStoreCrypto::new_handle_id().unwrap();
        let envelope = crypto
            .encrypt_envelope(&id, "openai-local", "OPENAI_API_KEY", "sk-persisted")
            .unwrap();

        let restarted = crypto_for_key_encryption_key_path(&key_encryption_key_path);
        assert_eq!(
            restarted.decrypt_envelope(&envelope).unwrap(),
            "sk-persisted"
        );
    }

    #[test]
    fn rejects_handle_for_different_provider() {
        let tmp = tempfile::tempdir().unwrap();
        let crypto =
            crypto_for_key_encryption_key_path(&tmp.path().join(DEFAULT_KEY_ENCRYPTION_KEY_FILE));
        let id = EncryptedGatewayCredentialStoreCrypto::new_handle_id().unwrap();
        let envelope = crypto
            .encrypt_envelope(&id, "openai-local", "OPENAI_API_KEY", "sk-original")
            .unwrap();

        let err = EncryptedGatewayCredentialStoreCrypto::ensure_envelope_owner(
            &envelope,
            &id,
            "other-provider",
            "OPENAI_API_KEY",
        )
        .unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
    }

    #[test]
    fn env_key_encryption_key_must_decode_to_32_bytes() {
        let err = decode_key_encryption_key_base64(&BASE64.encode([1_u8; 31])).unwrap_err();
        assert!(err.contains("32 bytes"));
        assert!(decode_key_encryption_key_base64(&BASE64.encode([1_u8; KEY_LEN])).is_ok());
        assert!(decode_key_encryption_key_base64(&BASE64_NO_PAD.encode([1_u8; KEY_LEN])).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn generated_key_encryption_key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let key_encryption_key_path = tmp.path().join(DEFAULT_KEY_ENCRYPTION_KEY_FILE);
        let _crypto = crypto_for_key_encryption_key_path(&key_encryption_key_path);
        let key_encryption_key_mode = fs::metadata(key_encryption_key_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(key_encryption_key_mode, 0o600);
    }
}
