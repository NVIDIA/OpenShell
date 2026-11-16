// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The launch credentials the gateway hands to a driver, as protobuf messages.
//!
//! `launch_credentials.proto` defines [`compute::SandboxLaunchCredentials`] and
//! [`compute::SupervisorAuthBundle`]. This module converts between them and the
//! JWT types of this crate, which hold the credentials as secret values and
//! validate them, and implements the contract crate's [`Codec`] for the
//! supervisor auth bundle so that it is written and read like the other
//! contract documents.

use openshell_driver_contract::Codec;
use openshell_driver_contract::convert::{
    CONTRACT_VERSION, ContractConversionError, check_version, session_id,
};

use crate::jwt::{
    CredentialEpoch, OtlpClientIdentity, OtlpTlsMaterial, SandboxLaunchAuthentication, SecretJwt,
    SecretOtlpHeaders, SecretPrivateKeyPem, SecretSshHostKey, SessionRotation,
    SessionVerificationKey, SupervisorAuthBundle,
};
use crate::proto::compute::v1 as compute;
use crate::sandbox_generation::SandboxGenerationId;

type Result<T> = std::result::Result<T, ContractConversionError>;

fn otlp_tls_to_pb(material: &OtlpTlsMaterial) -> compute::OtlpTlsMaterial {
    compute::OtlpTlsMaterial {
        ca_pem: material.ca_pem.clone(),
        client: material
            .client
            .as_ref()
            .map(|client| compute::OtlpClientIdentity {
                cert_pem: client.cert_pem.clone(),
                key_pem: client.key_pem.expose_secret().to_string(),
            }),
    }
}

fn otlp_tls_from_pb(material: compute::OtlpTlsMaterial) -> OtlpTlsMaterial {
    OtlpTlsMaterial {
        ca_pem: material.ca_pem,
        client: material.client.map(|client| OtlpClientIdentity {
            cert_pem: client.cert_pem,
            key_pem: SecretPrivateKeyPem::new(client.key_pem),
        }),
    }
}

impl From<&SupervisorAuthBundle> for compute::SupervisorAuthBundle {
    fn from(bundle: &SupervisorAuthBundle) -> Self {
        // A legacy bundle holds the indexes as `usize` values that its own
        // validation bounds by the list length, so they fit in 32 bits.
        let index = |value: Option<usize>| value.and_then(|value| u32::try_from(value).ok());
        Self {
            contract_version: CONTRACT_VERSION.to_string(),
            session_id: bundle.session_id.to_string(),
            runtime_generation: bundle.runtime_generation.to_string(),
            session_rotation: bundle.session_rotation.get(),
            auth_epoch: bundle.auth_epoch.get(),
            gateway_token: bundle.gateway_token.expose_secret().to_string(),
            gateway_expires_at: bundle.gateway_expires_at,
            sandbox_token: bundle.sandbox_token.expose_secret().to_string(),
            sandbox_expires_at: bundle.sandbox_expires_at,
            ssh_host_private_key: bundle
                .ssh_host_private_key
                .as_ref()
                .map(|key| key.expose_secret().to_string()),
            traces_otlp_headers: bundle
                .traces_otlp_headers
                .as_ref()
                .map(|headers| headers.expose_secret().to_string()),
            ocsf_otlp_headers: bundle
                .ocsf_otlp_headers
                .as_ref()
                .map(|headers| headers.expose_secret().to_string()),
            agent_otlp_headers: bundle
                .agent_otlp_headers
                .as_ref()
                .map(|headers| headers.expose_secret().to_string()),
            otlp_tls: bundle.otlp_tls.iter().map(otlp_tls_to_pb).collect(),
            traces_otlp_tls: index(bundle.traces_otlp_tls),
            ocsf_otlp_tls: index(bundle.ocsf_otlp_tls),
            agent_otlp_tls: index(bundle.agent_otlp_tls),
        }
    }
}

impl TryFrom<compute::SupervisorAuthBundle> for SupervisorAuthBundle {
    type Error = ContractConversionError;

    fn try_from(value: compute::SupervisorAuthBundle) -> Result<Self> {
        check_version(&value.contract_version, false)?;
        let token = |value: String| {
            SecretJwt::parse(value).map_err(|_| {
                ContractConversionError::new("a token is empty or contains whitespace")
            })
        };
        let bundle = Self {
            session_id: session_id(&value.session_id)?,
            runtime_generation: SandboxGenerationId::parse(value.runtime_generation)
                .map_err(|_| ContractConversionError::new("runtime_generation is not valid"))?,
            session_rotation: SessionRotation::new(value.session_rotation)
                .map_err(|_| ContractConversionError::new("session_rotation must be nonzero"))?,
            auth_epoch: CredentialEpoch::new(value.auth_epoch)
                .map_err(|_| ContractConversionError::new("auth_epoch must be nonzero"))?,
            gateway_token: token(value.gateway_token)?,
            gateway_expires_at: value.gateway_expires_at,
            sandbox_token: token(value.sandbox_token)?,
            sandbox_expires_at: value.sandbox_expires_at,
            ssh_host_private_key: value.ssh_host_private_key.map(SecretSshHostKey::new),
            traces_otlp_headers: value.traces_otlp_headers.map(SecretOtlpHeaders::new),
            ocsf_otlp_headers: value.ocsf_otlp_headers.map(SecretOtlpHeaders::new),
            agent_otlp_headers: value.agent_otlp_headers.map(SecretOtlpHeaders::new),
            otlp_tls: value.otlp_tls.into_iter().map(otlp_tls_from_pb).collect(),
            traces_otlp_tls: value.traces_otlp_tls.map(|index| index as usize),
            ocsf_otlp_tls: value.ocsf_otlp_tls.map(|index| index as usize),
            agent_otlp_tls: value.agent_otlp_tls.map(|index| index as usize),
        };
        bundle
            .validate()
            .map_err(|error| ContractConversionError::new(error.to_string()))?;
        Ok(bundle)
    }
}

impl From<&SandboxLaunchAuthentication> for compute::SandboxLaunchCredentials {
    fn from(authentication: &SandboxLaunchAuthentication) -> Self {
        let mut supervisor: compute::SupervisorAuthBundle = (&authentication.supervisor).into();
        // The version belongs to the enclosing document.
        supervisor.contract_version = String::new();
        Self {
            contract_version: CONTRACT_VERSION.to_string(),
            supervisor: Some(supervisor),
            gateway_id: authentication.gateway_id.clone(),
            verification_keys: authentication
                .verification_keys
                .iter()
                .map(|key| compute::LaunchVerificationKey {
                    key_id: key.key_id.clone(),
                    public_key_pem: key.public_key_pem.clone(),
                })
                .collect(),
        }
    }
}

impl TryFrom<compute::SandboxLaunchCredentials> for SandboxLaunchAuthentication {
    type Error = ContractConversionError;

    fn try_from(value: compute::SandboxLaunchCredentials) -> Result<Self> {
        check_version(&value.contract_version, true)?;
        let authentication = Self {
            supervisor: value
                .supervisor
                .ok_or_else(|| ContractConversionError::new("a supervisor bundle is required"))?
                .try_into()?,
            gateway_id: value.gateway_id,
            verification_keys: value
                .verification_keys
                .into_iter()
                .map(|key| SessionVerificationKey {
                    key_id: key.key_id,
                    public_key_pem: key.public_key_pem,
                })
                .collect(),
        };
        authentication
            .validate()
            .map_err(|error| ContractConversionError::new(error.to_string()))?;
        Ok(authentication)
    }
}

/// The typed form of the launch authentication the gateway sends beside the
/// opaque JSON bytes.
///
/// Returns `None` when there are no bytes, which is how a gateway without a
/// launch signer marks the field absent.
///
/// # Errors
///
/// Returns an error when `encoded` is not a valid launch authentication.
pub fn launch_credentials_from_bytes(
    encoded: &[u8],
) -> Result<Option<compute::SandboxLaunchCredentials>> {
    if encoded.is_empty() {
        return Ok(None);
    }
    let authentication: SandboxLaunchAuthentication = serde_json::from_slice(encoded)
        .map_err(|error| ContractConversionError::new(error.to_string()))?;
    Ok(Some((&authentication).into()))
}

/// The launch authentication a driver acts on.
///
/// The typed field wins when the gateway set it; an older gateway sets only the
/// JSON bytes, which are decoded as before. Returns `None` when neither is
/// present. The result is validated.
///
/// # Errors
///
/// Returns an error when the field that is used is not a valid launch
/// authentication. A set typed field is never bypassed for the bytes.
pub fn resolve_launch_authentication(
    typed: Option<&compute::SandboxLaunchCredentials>,
    encoded: &[u8],
) -> Result<Option<SandboxLaunchAuthentication>> {
    if let Some(typed) = typed {
        return typed.clone().try_into().map(Some);
    }
    if encoded.is_empty() {
        return Ok(None);
    }
    let authentication: SandboxLaunchAuthentication = serde_json::from_slice(encoded)
        .map_err(|error| ContractConversionError::new(error.to_string()))?;
    authentication
        .validate()
        .map_err(|error| ContractConversionError::new(error.to_string()))?;
    Ok(Some(authentication))
}

/// The two forms of the launch authentication on a driver request: the typed
/// message newer gateways fill, and the JSON bytes every gateway has sent.
#[derive(Debug, Clone, Copy, Default)]
pub struct LaunchAuthenticationFields<'a> {
    pub typed: Option<&'a compute::SandboxLaunchCredentials>,
    pub encoded: &'a [u8],
}

impl<'a> LaunchAuthenticationFields<'a> {
    #[must_use]
    pub fn new(typed: Option<&'a compute::SandboxLaunchCredentials>, encoded: &'a [u8]) -> Self {
        Self { typed, encoded }
    }

    /// Whether the gateway sent no launch authentication in either form.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.typed.is_none() && self.encoded.is_empty()
    }

    /// The validated launch authentication, preferring the typed field. `None`
    /// when neither form is present.
    ///
    /// # Errors
    ///
    /// See [`resolve_launch_authentication`].
    pub fn resolve(&self) -> Result<Option<SandboxLaunchAuthentication>> {
        resolve_launch_authentication(self.typed, self.encoded)
    }
}

impl Codec for SupervisorAuthBundle {
    const LEGACY_FILE_NAME: &'static str = "supervisor-auth.json";

    fn validate(&self) -> Result<()> {
        Self::validate(self).map_err(|error| ContractConversionError::new(error.to_string()))
    }

    fn to_binary(&self) -> Vec<u8> {
        prost::Message::encode_to_vec(&compute::SupervisorAuthBundle::from(self))
    }

    fn from_binary(bytes: &[u8]) -> Result<Self> {
        let message =
            <compute::SupervisorAuthBundle as prost::Message>::decode(bytes).map_err(|error| {
                ContractConversionError::new(format!("not a valid document: {error}"))
            })?;
        Self::try_from(message)
    }
}
