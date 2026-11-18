// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Workspace-secret references and endpoint constraints in refresh state.
//!
//! Both live in refresh-state metadata annotations rather than new protobuf
//! fields: older gateways decode refresh state into a struct that drops unknown
//! fields and rewrite it with compare-and-swap, but they preserve annotations.

use std::collections::BTreeMap;

use openshell_core::proto::datamodel::v1::{CredentialHandle, ObjectMeta};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tonic::Status;

/// Material key to the workspace secret that supplies it.
pub const MATERIAL_SECRETS_ANNOTATION: &str = "openshell.nvidia.com/refresh-material-secrets";
/// Material key to the token endpoints its value may be sent to. Set when a
/// referenced secret's value is copied into provider-owned material.
pub const MATERIAL_ENDPOINTS_ANNOTATION: &str = "openshell.nvidia.com/refresh-material-endpoints";
/// Logical key of the single value each workspace secret stores.
pub const WORKSPACE_SECRET_VALUE_KEY: &str = "value";

/// A binding from one material key to a workspace secret. The ID is
/// authoritative; the name is recorded for status reads and messages.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterialSecretBinding {
    pub id: String,
    pub name: String,
}

pub type MaterialSecretBindings = BTreeMap<String, MaterialSecretBinding>;
pub type MaterialEndpointConstraints = BTreeMap<String, Vec<String>>;

/// The current storage handle and endpoint constraint of a live workspace
/// secret, as the embedding gateway stores them.
pub struct WorkspaceSecretMaterial {
    pub handle: CredentialHandle,
    pub allowed_endpoints: Vec<String>,
}

/// Bindings recorded on a refresh state. A malformed annotation fails closed.
///
/// # Errors
///
/// Returns `FAILED_PRECONDITION` when the annotation is not valid JSON.
pub fn material_secret_bindings(
    metadata: Option<&ObjectMeta>,
) -> Result<MaterialSecretBindings, Status> {
    parse_annotation(metadata, MATERIAL_SECRETS_ANNOTATION)
}

/// Endpoint constraints recorded on a refresh state. A malformed annotation
/// fails closed.
///
/// # Errors
///
/// Returns `FAILED_PRECONDITION` when the annotation is not valid JSON.
pub fn material_endpoint_constraints(
    metadata: Option<&ObjectMeta>,
) -> Result<MaterialEndpointConstraints, Status> {
    parse_annotation(metadata, MATERIAL_ENDPOINTS_ANNOTATION)
}

/// Record bindings, removing the annotation when there are none.
pub fn set_material_secret_bindings(metadata: &mut ObjectMeta, bindings: &MaterialSecretBindings) {
    set_annotation(
        metadata,
        MATERIAL_SECRETS_ANNOTATION,
        bindings,
        bindings.is_empty(),
    );
}

/// Record endpoint constraints, removing the annotation when there are none.
pub fn set_material_endpoint_constraints(
    metadata: &mut ObjectMeta,
    constraints: &MaterialEndpointConstraints,
) {
    set_annotation(
        metadata,
        MATERIAL_ENDPOINTS_ANNOTATION,
        constraints,
        constraints.is_empty(),
    );
}

fn parse_annotation<T: DeserializeOwned + Default>(
    metadata: Option<&ObjectMeta>,
    key: &str,
) -> Result<T, Status> {
    let Some(raw) = metadata.and_then(|metadata| metadata.annotations.get(key)) else {
        return Ok(T::default());
    };
    serde_json::from_str(raw).map_err(|_| {
        Status::failed_precondition(format!(
            "provider refresh annotation {key} is malformed; reconfigure the refresh grant"
        ))
    })
}

fn set_annotation<T: Serialize>(metadata: &mut ObjectMeta, key: &str, value: &T, empty: bool) {
    if empty {
        metadata.annotations.remove(key);
        return;
    }
    // Serializing a map of strings cannot fail.
    if let Ok(encoded) = serde_json::to_string(value) {
        metadata.annotations.insert(key.to_string(), encoded);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bindings_round_trip_and_clear() {
        let mut metadata = ObjectMeta::default();
        let bindings = MaterialSecretBindings::from([(
            "client_secret".to_string(),
            MaterialSecretBinding {
                id: "secret-id".to_string(),
                name: "acme".to_string(),
            },
        )]);
        set_material_secret_bindings(&mut metadata, &bindings);
        assert_eq!(material_secret_bindings(Some(&metadata)).unwrap(), bindings);

        set_material_secret_bindings(&mut metadata, &MaterialSecretBindings::new());
        assert!(
            !metadata
                .annotations
                .contains_key(MATERIAL_SECRETS_ANNOTATION)
        );
        assert!(
            material_secret_bindings(Some(&metadata))
                .unwrap()
                .is_empty()
        );
        assert!(material_secret_bindings(None).unwrap().is_empty());
    }

    #[test]
    fn malformed_annotations_fail_closed() {
        let mut metadata = ObjectMeta::default();
        metadata
            .annotations
            .insert(MATERIAL_SECRETS_ANNOTATION.to_string(), "{".to_string());
        metadata
            .annotations
            .insert(MATERIAL_ENDPOINTS_ANNOTATION.to_string(), "[]".to_string());
        assert!(material_secret_bindings(Some(&metadata)).is_err());
        assert!(material_endpoint_constraints(Some(&metadata)).is_err());
    }
}
