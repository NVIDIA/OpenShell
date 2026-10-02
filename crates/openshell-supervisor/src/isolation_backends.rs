// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Binary composition of platform isolation-backend implementations.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use openshell_isolation_interface::contract::IsolationBackend;

pub fn sandbox_backend(
    ca_file_paths: Arc<Mutex<Option<(PathBuf, PathBuf)>>>,
    provider_credentials: openshell_core::provider_credentials::ProviderCredentialState,
    sandbox_bearer: openshell_core::jwt::SessionBearerTokenSlot,
) -> Arc<dyn IsolationBackend> {
    #[cfg(not(target_os = "windows"))]
    let backend = openshell_sandbox_backend::OpenShellRuntimeBackend::new(
        ca_file_paths,
        provider_credentials,
        sandbox_bearer,
    );
    #[cfg(target_os = "windows")]
    let backend = openshell_mxc_boundary::backend::MxcRuntimeBackend::new(
        ca_file_paths,
        provider_credentials,
        sandbox_bearer,
    );
    Arc::new(backend)
}
