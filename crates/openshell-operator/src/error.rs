// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Error types for the operator.
//!
//! Follows the pattern established by `KubernetesDriverError` in
//! `openshell-driver-kubernetes/src/driver.rs`.

/// Errors that can occur during operator reconciliation.
#[derive(Debug, thiserror::Error)]
pub enum OperatorError {
    /// Kubernetes API error.
    #[error("kubernetes API error: {0}")]
    Kube(#[from] kube::Error),

    /// Serialization/deserialization error.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// The reconciled object is missing expected fields.
    #[error("missing field: {0}")]
    MissingField(String),

    /// A finalizer operation failed.
    #[error("finalizer error: {0}")]
    Finalizer(#[source] Box<kube::runtime::finalizer::Error<OperatorError>>),

    /// Status update failed.
    #[error("status update failed: {0}")]
    StatusUpdate(String),
}

/// Result type alias for operator operations.
pub type Result<T> = std::result::Result<T, OperatorError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kube_error_display() {
        let err = OperatorError::Kube(kube::Error::Api(kube::core::ErrorResponse {
            code: 404,
            message: "not found".into(),
            reason: "NotFound".into(),
            status: "Failure".into(),
        }));
        let msg = err.to_string();
        assert!(msg.contains("kubernetes API error"), "got: {msg}");
    }

    #[test]
    fn missing_field_display() {
        let err = OperatorError::MissingField("metadata.name".into());
        assert!(
            err.to_string().contains("missing field: metadata.name"),
            "got: {}",
            err
        );
    }

    #[test]
    fn serialization_error_display() {
        let serde_err = serde_json::from_str::<String>("invalid").unwrap_err();
        let err = OperatorError::Serialization(serde_err);
        assert!(
            err.to_string().contains("serialization error"),
            "got: {}",
            err
        );
    }

    #[test]
    fn status_update_display() {
        let err = OperatorError::StatusUpdate("conflict".into());
        assert!(
            err.to_string().contains("status update failed: conflict"),
            "got: {}",
            err
        );
    }

    #[test]
    fn kube_error_from_conversion() {
        let kube_err = kube::Error::Api(kube::core::ErrorResponse {
            code: 500,
            message: "internal".into(),
            reason: "InternalError".into(),
            status: "Failure".into(),
        });
        let err: OperatorError = kube_err.into();
        assert!(matches!(err, OperatorError::Kube(_)));
    }
}
