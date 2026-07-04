// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Label and annotation constants for operator-managed resources.
//!
//! Maps Kagenti's label taxonomy (`kagenti.io/*`) to OpenShell's
//! conventions (`openshell.io/*`), plus standard Kubernetes labels.

// -- Standard Kubernetes labels -----------------------------------------------

/// Label key: managed-by identifier.
pub const MANAGED_BY_KEY: &str = "app.kubernetes.io/managed-by";

/// Label key: application name.
pub const APP_NAME_KEY: &str = "app.kubernetes.io/name";

/// Label key: component type.
pub const COMPONENT_KEY: &str = "app.kubernetes.io/component";

// -- OpenShell-specific labels ------------------------------------------------

/// Label key: runtime type (agent, tool).
pub const RUNTIME_TYPE_KEY: &str = "openshell.io/runtime-type";

/// Label key: workload type (deployment, statefulset, sandbox).
pub const WORKLOAD_TYPE_KEY: &str = "openshell.io/workload-type";

// -- Label values -------------------------------------------------------------

/// Value for the managed-by label on operator-created resources.
pub const MANAGER_NAME: &str = "openshell-operator";

/// Default component label value.
pub const COMPONENT_SANDBOX: &str = "sandbox";

// -- Finalizer ----------------------------------------------------------------

/// Finalizer name registered on `SandboxRuntime` resources.
pub const FINALIZER_NAME: &str = "openshell.io/sandbox-runtime-finalizer";

// -- Defaults -----------------------------------------------------------------

/// Default container name in generated workloads.
pub const DEFAULT_CONTAINER_NAME: &str = "agent";

/// Default image pull policy.
pub const DEFAULT_IMAGE_PULL_POLICY: &str = "Always";

/// Default CPU request.
pub const DEFAULT_CPU_REQUEST: &str = "100m";

/// Default memory request.
pub const DEFAULT_MEMORY_REQUEST: &str = "256Mi";

/// Default CPU limit.
pub const DEFAULT_CPU_LIMIT: &str = "500m";

/// Default memory limit.
pub const DEFAULT_MEMORY_LIMIT: &str = "1Gi";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_by_label_key() {
        assert_eq!(MANAGED_BY_KEY, "app.kubernetes.io/managed-by");
    }

    #[test]
    fn managed_by_value() {
        assert_eq!(MANAGER_NAME, "openshell-operator");
    }

    #[test]
    fn app_name_label_key() {
        assert_eq!(APP_NAME_KEY, "app.kubernetes.io/name");
    }

    #[test]
    fn component_label_key() {
        assert_eq!(COMPONENT_KEY, "app.kubernetes.io/component");
    }

    #[test]
    fn runtime_type_label_key() {
        assert_eq!(RUNTIME_TYPE_KEY, "openshell.io/runtime-type");
    }

    #[test]
    fn workload_type_label_key() {
        assert_eq!(WORKLOAD_TYPE_KEY, "openshell.io/workload-type");
    }

    #[test]
    fn finalizer_name_is_fqdn() {
        assert!(FINALIZER_NAME.contains("openshell.io"));
        assert!(FINALIZER_NAME.contains("sandbox-runtime"));
    }

    #[test]
    fn default_container_name() {
        assert_eq!(DEFAULT_CONTAINER_NAME, "agent");
    }

    #[test]
    fn default_resource_values() {
        assert_eq!(DEFAULT_CPU_REQUEST, "100m");
        assert_eq!(DEFAULT_MEMORY_REQUEST, "256Mi");
        assert_eq!(DEFAULT_CPU_LIMIT, "500m");
        assert_eq!(DEFAULT_MEMORY_LIMIT, "1Gi");
    }
}
