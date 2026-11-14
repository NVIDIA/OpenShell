// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The launch-dependent values a driver remembers for one sandbox.
//!
//! A driver that regenerates its boundary documents on every start keeps a
//! private record of what those documents need. The fields that change with
//! each launch authentication are the same for every driver, so they live here
//! as plain values: no I/O, no driver-specific fields, and no dependence on the
//! encoding of a contract document.

use serde::{Deserialize, Serialize};

use super::{CredentialEpoch, SandboxLaunchAuthentication, SessionRotation};
use crate::SandboxSessionId;

/// Supervisor-side TLS server authentication for one launch.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchTls {
    pub server_name: String,
    pub trust_anchor_pem: String,
}

impl std::fmt::Debug for LaunchTls {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LaunchTls")
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

/// Public gateway verification key as UTF-8 PEM.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchVerificationKey {
    pub key_id: String,
    pub public_key_pem: String,
}

/// A launch authentication carried a value a binding cannot hold.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LaunchBindingError {
    #[error("verification key {key_id} is not UTF-8 PEM")]
    VerificationKeyNotUtf8 { key_id: String },
}

/// The values that bind one sandbox launch to the gateway that authorized it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchBinding {
    pub session_id: SandboxSessionId,
    pub generation: String,
    pub session_rotation: SessionRotation,
    pub auth_epoch: CredentialEpoch,
    pub gateway_id: String,
    pub verification_keys: Vec<LaunchVerificationKey>,
    pub supervisor_tls: LaunchTls,
}

impl LaunchBinding {
    /// The binding for a launch authenticated by `authentication`, with the
    /// supervisor TLS material generated for that launch.
    pub fn from_authentication(
        authentication: &SandboxLaunchAuthentication,
        tls: LaunchTls,
    ) -> Result<Self, LaunchBindingError> {
        Ok(Self {
            session_id: authentication.supervisor.session_id,
            generation: authentication.supervisor.runtime_generation.to_string(),
            session_rotation: authentication.supervisor.session_rotation,
            auth_epoch: authentication.supervisor.auth_epoch,
            gateway_id: authentication.gateway_id.clone(),
            verification_keys: verification_keys(authentication)?,
            supervisor_tls: tls,
        })
    }

    /// Replace exactly the launch-dependent fields with those of a new launch.
    /// On error the binding is unchanged.
    pub fn rebind(
        &mut self,
        authentication: &SandboxLaunchAuthentication,
        tls: LaunchTls,
    ) -> Result<(), LaunchBindingError> {
        *self = Self::from_authentication(authentication, tls)?;
        Ok(())
    }
}

fn verification_keys(
    authentication: &SandboxLaunchAuthentication,
) -> Result<Vec<LaunchVerificationKey>, LaunchBindingError> {
    authentication
        .verification_keys
        .iter()
        .map(|key| {
            String::from_utf8(key.public_key_pem.clone())
                .map(|public_key_pem| LaunchVerificationKey {
                    key_id: key.key_id.clone(),
                    public_key_pem,
                })
                .map_err(|_| LaunchBindingError::VerificationKeyNotUtf8 {
                    key_id: key.key_id.clone(),
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::{SecretJwt, SessionVerificationKey, SupervisorAuthBundle};
    use crate::sandbox_generation::SandboxGenerationId;

    fn authentication(generation: &str, epoch: u64, key: &[u8]) -> SandboxLaunchAuthentication {
        SandboxLaunchAuthentication {
            supervisor: SupervisorAuthBundle {
                session_id: SandboxSessionId::new(),
                runtime_generation: SandboxGenerationId::parse(generation).unwrap(),
                session_rotation: SessionRotation::new(epoch).unwrap(),
                auth_epoch: CredentialEpoch::new(epoch).unwrap(),
                gateway_token: SecretJwt::parse("gateway.token.value").unwrap(),
                gateway_expires_at: i64::MAX,
                sandbox_token: SecretJwt::parse("sandbox.token.value").unwrap(),
                sandbox_expires_at: i64::MAX,
                ssh_host_private_key: None,
                traces_otlp_headers: None,
                ocsf_otlp_headers: None,
                agent_otlp_headers: None,
                otlp_tls: Vec::new(),
                traces_otlp_tls: None,
                ocsf_otlp_tls: None,
                agent_otlp_tls: None,
            },
            gateway_id: format!("gateway-{epoch}"),
            verification_keys: vec![SessionVerificationKey {
                key_id: format!("key-{epoch}"),
                public_key_pem: key.to_vec(),
            }],
        }
    }

    fn tls(name: &str) -> LaunchTls {
        LaunchTls {
            server_name: name.to_string(),
            trust_anchor_pem: format!("anchor-{name}"),
        }
    }

    #[test]
    fn binding_takes_every_field_from_the_launch() {
        let launch = authentication("generation-1", 1, b"public-key");
        let binding = LaunchBinding::from_authentication(&launch, tls("one")).unwrap();
        assert_eq!(binding.session_id, launch.supervisor.session_id);
        assert_eq!(binding.generation, "generation-1");
        assert_eq!(binding.session_rotation.get(), 1);
        assert_eq!(binding.auth_epoch.get(), 1);
        assert_eq!(binding.gateway_id, "gateway-1");
        assert_eq!(
            binding.verification_keys,
            [LaunchVerificationKey {
                key_id: "key-1".to_string(),
                public_key_pem: "public-key".to_string(),
            }]
        );
        assert_eq!(binding.supervisor_tls, tls("one"));
    }

    #[test]
    fn rebind_equals_a_binding_built_from_the_new_launch() {
        let mut binding =
            LaunchBinding::from_authentication(&authentication("g1", 1, b"k1"), tls("one"))
                .unwrap();
        let next = authentication("g2", 2, b"k2");
        binding.rebind(&next, tls("two")).unwrap();
        assert_eq!(
            binding,
            LaunchBinding::from_authentication(&next, tls("two")).unwrap()
        );
    }

    #[test]
    fn failed_rebind_leaves_the_binding_unchanged() {
        let mut binding =
            LaunchBinding::from_authentication(&authentication("g1", 1, b"k1"), tls("one"))
                .unwrap();
        let before = binding.clone();
        let error = binding
            .rebind(&authentication("g2", 2, &[0xff, 0xfe]), tls("two"))
            .unwrap_err();
        assert_eq!(
            error,
            LaunchBindingError::VerificationKeyNotUtf8 {
                key_id: "key-2".to_string()
            }
        );
        assert_eq!(binding, before);
    }

    #[test]
    fn binding_round_trips_through_json() {
        let binding =
            LaunchBinding::from_authentication(&authentication("g1", 1, b"k1"), tls("one"))
                .unwrap();
        let decoded: LaunchBinding =
            serde_json::from_slice(&serde_json::to_vec(&binding).unwrap()).unwrap();
        assert_eq!(decoded, binding);
    }
}
