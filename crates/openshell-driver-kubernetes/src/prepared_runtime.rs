// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Immutable bootstrap material for an unassigned Kubernetes runtime.
//!
//! The caller admits the physical Sandbox and gated Pod, observes their UIDs and
//! network fences, and supplies a provisioning function over those observations.
//! This module persists the runtime's own TLS identity before reserving capacity.
//! It never releases the Pod's scheduling gate or creates workload credentials.

use std::collections::BTreeMap;

use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::Api;
use kube::api::{ObjectMeta, PostParams};
use openshell_core::SandboxSessionId;
use openshell_isolation_interface::contract::BackendError;
use openshell_sandbox_backend::boundary_protocol::{
    BoundaryConfig, BoundaryListener, SandboxTlsClientConfig, SandboxTlsMaterial, SandboxTransport,
    generate_sandbox_tls_material,
};
use openshell_supervisor_control::{
    PreparationRequest, PreparedRuntimeRegistration, SharedSupervision,
};

use crate::driver::KubernetesDriverError;
use crate::isolation::KubernetesSandboxRuntimeBoundaryProvisioning;
use crate::sandbox_runtime::{
    BOUNDARY_CERTIFICATE_KEY, BOUNDARY_CERTIFICATE_PATH, BOUNDARY_CONFIG_KEY, BOUNDARY_PRIVATE_KEY,
    BOUNDARY_PRIVATE_KEY_PATH,
};

const REGISTRATION_KEY: &str = "prepared-runtime.json";
const WORKSPACE_ANNOTATION: &str = "openshell.ai/prepared-runtime-workspace";
const MAX_BOOTSTRAP_BYTES: usize = 512 * 1024;

/// Coordinates persisted by the provisioning controller before creating material.
///
/// `secret_name` must already be mounted only by this Pod's trusted bootstrap init
/// container. The session ID must survive controller restarts. A replacement Pod
/// gets a fresh Secret name, session, generation, and route, even if its name is
/// reused. These are physical resource coordinates, not a logical Sandbox ID.
#[derive(Clone, Debug)]
pub struct PreparedRuntimeBootstrap {
    pub workspace: String,
    pub namespace: String,
    pub pod_name: String,
    pub pod_uid: String,
    pub secret_name: String,
    pub session_id: SandboxSessionId,
}

impl PreparedRuntimeBootstrap {
    /// Persist (or recover) per-Pod bootstrap material, then reserve host capacity.
    ///
    /// `provision` builds both protocol endpoints using the supplied TLS pin and
    /// freshly verified Kubernetes resource coordinates. It must be deterministic
    /// for those inputs and call `provision_prepared`. After a concurrent Secret
    /// creation it may be called again with the winner's pin.
    ///
    /// This operation never removes the Pod's gate. Retry with the same coordinates: an API
    /// timeout may have committed either the Secret or the reservation. Never
    /// delete material or withdraw a route unconditionally on an error. Only the
    /// controller may release the gate, after revalidating the current Pod UID,
    /// admission and fences. The returned registration contains no private key.
    pub async fn prepare<F>(
        &self,
        client: kube::Client,
        supervision: &SharedSupervision,
        provision: F,
    ) -> Result<PreparedRuntimeRegistration, KubernetesDriverError>
    where
        F: Fn(
            SandboxTlsClientConfig,
        ) -> Result<KubernetesSandboxRuntimeBoundaryProvisioning, BackendError>,
    {
        self.validate()?;
        let secrets = Api::<Secret>::namespaced(client, &self.namespace);
        let secret = if let Some(secret) = secrets
            .get_opt(&self.secret_name)
            .await
            .map_err(KubernetesDriverError::from_kube)?
        {
            secret
        } else {
            let material = generate_sandbox_tls_material(self.session_id).map_err(backend_error)?;
            let provisioning = provision(tls_pin(&material)).map_err(backend_error)?;
            let request = self.request(&provisioning)?;
            let candidate = self.secret(&provisioning, &request.registration, material)?;
            match secrets.create(&PostParams::default(), &candidate).await {
                Ok(secret) => secret,
                // Another replica won. Its key is authoritative; never replace it.
                Err(kube::Error::Api(error)) if error.code == 409 => secrets
                    .get(&self.secret_name)
                    .await
                    .map_err(KubernetesDriverError::from_kube)?,
                Err(error) => return Err(KubernetesDriverError::from_kube(error)),
            }
        };
        let registration = self.read_registration(&secret)?;
        let expected =
            provision(registration.runtime_descriptor.tls.clone()).map_err(backend_error)?;
        let request = self.request(&expected)?;
        let stored_config: BoundaryConfig =
            serde_json::from_slice(secret_value(&secret, BOUNDARY_CONFIG_KEY)?)
                .map_err(|_| invalid("invalid prepared boundary configuration"))?;
        if request.registration != registration
            || serde_json::to_value(stored_config)
                .map_err(|_| invalid("invalid boundary configuration"))?
                != serde_json::to_value(&expected.boundary_config)
                    .map_err(|_| invalid("invalid boundary configuration"))?
        {
            return Err(invalid(
                "prepared bootstrap no longer matches observed runtime coordinates",
            ));
        }
        supervision
            .prepare(request)
            .await
            .map_err(KubernetesDriverError::Precondition)?;
        Ok(registration)
    }

    fn validate(&self) -> Result<(), KubernetesDriverError> {
        if [
            &self.workspace,
            &self.namespace,
            &self.pod_name,
            &self.pod_uid,
            &self.secret_name,
        ]
        .iter()
        .any(|value| value.is_empty() || value.trim() != value.as_str())
        {
            return Err(invalid(
                "prepared bootstrap requires workspace and physical Pod coordinates",
            ));
        }
        Ok(())
    }

    fn request(
        &self,
        provisioning: &KubernetesSandboxRuntimeBoundaryProvisioning,
    ) -> Result<PreparationRequest, KubernetesDriverError> {
        let config = &provisioning.boundary_config;
        let descriptor = &provisioning.runtime_descriptor;
        let BoundaryListener::RuntimeInitiatedTlsTcp {
            authority,
            route: Some(route),
            tls,
            ..
        } = &config.listener
        else {
            return Err(invalid(
                "prepared bootstrap requires a routed runtime connection",
            ));
        };
        if !config.boundary_id.is_empty()
            || config.session_id != self.session_id
            || descriptor.session_id != config.session_id
            || descriptor.generation != config.generation
            || descriptor.resource_claims != config.resource_claims
            || descriptor.workload_identity != config.workload_identity
            || descriptor.provisioning_evidence != config.provisioning_evidence
            || !matches!(&descriptor.transport,
                SandboxTransport::RuntimeInitiatedRouted { authority: target, .. }
                if target == authority)
            || config.resource_claims.get("kubernetes.workload_pod_uid") != Some(&self.pod_uid)
            || !config
                .resource_claim_files
                .contains_key("kubernetes.workload_pod_uid")
            || tls.certificate_chain_path.to_str() != Some(BOUNDARY_CERTIFICATE_PATH)
            || tls.private_key_path.to_str() != Some(BOUNDARY_PRIVATE_KEY_PATH)
            || descriptor.tls.server_name
                != format!("sandbox.{}.openshell.internal", self.session_id)
        {
            return Err(invalid(
                "prepared bootstrap does not bind the expected physical runtime",
            ));
        }
        let registration = PreparedRuntimeRegistration {
            route: route.clone(),
            runtime_descriptor: descriptor.clone(),
        };
        registration
            .to_assignment()
            .map_err(|_| invalid("invalid prepared runtime registration"))?;
        Ok(PreparationRequest {
            workspace: self.workspace.clone(),
            auth_epoch: config.auth_epoch,
            registration,
        })
    }

    fn owner(&self) -> OwnerReference {
        OwnerReference {
            api_version: "v1".into(),
            kind: "Pod".into(),
            name: self.pod_name.clone(),
            uid: self.pod_uid.clone(),
            controller: Some(false),
            block_owner_deletion: Some(false),
        }
    }

    fn secret(
        &self,
        provisioning: &KubernetesSandboxRuntimeBoundaryProvisioning,
        registration: &PreparedRuntimeRegistration,
        material: SandboxTlsMaterial,
    ) -> Result<Secret, KubernetesDriverError> {
        if registration.runtime_descriptor.tls != tls_pin(&material) {
            return Err(invalid(
                "provisioning did not preserve the generated TLS identity",
            ));
        }
        let secret = Secret {
            metadata: ObjectMeta {
                namespace: Some(self.namespace.clone()),
                name: Some(self.secret_name.clone()),
                owner_references: Some(vec![self.owner()]),
                annotations: Some(BTreeMap::from([(
                    WORKSPACE_ANNOTATION.into(),
                    self.workspace.clone(),
                )])),
                ..Default::default()
            },
            immutable: Some(true),
            type_: Some("Opaque".into()),
            data: Some(BTreeMap::from([
                (
                    BOUNDARY_CONFIG_KEY.into(),
                    ByteString(
                        provisioning
                            .boundary_config
                            .encode()
                            .map_err(backend_error)?,
                    ),
                ),
                (
                    REGISTRATION_KEY.into(),
                    ByteString(
                        serde_json::to_vec(registration)
                            .map_err(|_| invalid("cannot encode prepared registration"))?,
                    ),
                ),
                (
                    BOUNDARY_CERTIFICATE_KEY.into(),
                    ByteString(material.certificate_chain_pem.into_bytes()),
                ),
                (
                    BOUNDARY_PRIVATE_KEY.into(),
                    ByteString(material.private_key_pem.into_bytes()),
                ),
            ])),
            ..Default::default()
        };
        self.read_registration(&secret)?;
        Ok(secret)
    }

    fn read_registration(
        &self,
        secret: &Secret,
    ) -> Result<PreparedRuntimeRegistration, KubernetesDriverError> {
        if secret.metadata.namespace.as_ref() != Some(&self.namespace)
            || secret.metadata.name.as_ref() != Some(&self.secret_name)
            || secret.metadata.deletion_timestamp.is_some()
            || secret.metadata.owner_references.as_deref() != Some(&[self.owner()])
            || secret
                .metadata
                .annotations
                .as_ref()
                .and_then(|a| a.get(WORKSPACE_ANNOTATION))
                != Some(&self.workspace)
            || secret.immutable != Some(true)
            || secret.type_.as_deref() != Some("Opaque")
        {
            return Err(invalid(
                "prepared bootstrap Secret ownership or immutability changed",
            ));
        }
        let data = secret
            .data
            .as_ref()
            .ok_or_else(|| invalid("prepared bootstrap Secret is empty"))?;
        if data.len() != 4 || data.values().map(|v| v.0.len()).sum::<usize>() > MAX_BOOTSTRAP_BYTES
        {
            return Err(invalid("invalid prepared bootstrap Secret size or keys"));
        }
        for key in [
            BOUNDARY_CONFIG_KEY,
            BOUNDARY_CERTIFICATE_KEY,
            BOUNDARY_PRIVATE_KEY,
        ] {
            secret_value(secret, key)?;
        }
        let registration: PreparedRuntimeRegistration =
            serde_json::from_slice(secret_value(secret, REGISTRATION_KEY)?)
                .map_err(|_| invalid("invalid stored prepared runtime registration"))?;
        registration
            .validate()
            .map_err(|_| invalid("invalid stored prepared runtime registration"))?;
        validate_server_key(secret)?;
        Ok(registration)
    }
}

fn validate_server_key(secret: &Secret) -> Result<(), KubernetesDriverError> {
    // PEM is a parsing type; all key loading and matching use the crypto facade's
    // TLS provider, just as they do when the runtime starts its listener.
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    let certs = CertificateDer::pem_slice_iter(secret_value(secret, BOUNDARY_CERTIFICATE_KEY)?)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid("invalid prepared TLS certificate"))?;
    let key = PrivateKeyDer::from_pem_slice(secret_value(secret, BOUNDARY_PRIVATE_KEY)?)
        .map_err(|_| invalid("invalid prepared TLS key"))?;
    openshell_crypto::tls::try_server_builder()
        .map_err(|_| invalid("cannot configure prepared runtime TLS"))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| invalid("prepared TLS certificate and key do not match"))?;
    Ok(())
}

fn secret_value<'a>(secret: &'a Secret, key: &str) -> Result<&'a [u8], KubernetesDriverError> {
    secret
        .data
        .as_ref()
        .and_then(|data| data.get(key))
        .filter(|v| !v.0.is_empty())
        .map(|v| v.0.as_slice())
        .ok_or_else(|| invalid("prepared bootstrap Secret is incomplete"))
}

fn tls_pin(material: &SandboxTlsMaterial) -> SandboxTlsClientConfig {
    SandboxTlsClientConfig {
        server_name: material.server_name.clone(),
        trust_anchor_pem: material.trust_anchor_pem.clone(),
    }
}

fn invalid(message: &str) -> KubernetesDriverError {
    KubernetesDriverError::Precondition(message.into())
}

fn backend_error(error: BackendError) -> KubernetesDriverError {
    KubernetesDriverError::Message(error.to_string())
}

#[cfg(test)]
mod tests;
