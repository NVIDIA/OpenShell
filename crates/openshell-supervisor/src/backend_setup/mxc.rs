// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Trusted Windows composition of the MXC isolation backend.

use super::{BackendServices, BackendSetup, BuiltBackend, LaunchIdentity, PreparedBackend};
use openshell_core::jwt::SessionBearerTokenSlot;
use openshell_isolation_interface::contract::BackendError;
use openshell_mxc_boundary::backend::{MxcReverseTcpConnector, MxcRuntimeBackend};
use openshell_mxc_boundary::launch::MxcLaunchDescriptor;
use openshell_supervisor_network::run::ProxyListenerConfig;
use std::sync::Arc;

pub(super) struct MxcBackendSetup;

impl BackendSetup for MxcBackendSetup {
    fn backend_name(&self) -> &str {
        openshell_mxc_boundary::BACKEND_NAME
    }

    fn decode(
        &self,
        payload: &[u8],
    ) -> Result<(LaunchIdentity, Box<dyn PreparedBackend>), BackendError> {
        let descriptor = MxcLaunchDescriptor::decode(payload)?;
        let identity = LaunchIdentity {
            sandbox_id: descriptor.runtime.boundary_id.clone(),
            generation: descriptor.runtime.generation.clone(),
            session_id: descriptor.runtime.session_id,
            workload_identity: descriptor.runtime.workload_identity.clone(),
            vm_policy_identity: None,
        };
        Ok((
            identity,
            Box::new(MxcLaunch {
                descriptor,
                connector: Arc::new(MxcReverseTcpConnector::default()),
            }),
        ))
    }
}

struct MxcLaunch {
    descriptor: MxcLaunchDescriptor,
    // Retain the same listener across discovery, attachment, and reconnects.
    connector: Arc<MxcReverseTcpConnector>,
}

#[tonic::async_trait]
impl PreparedBackend for MxcLaunch {
    async fn discover_policy(
        &self,
        bearer: SessionBearerTokenSlot,
    ) -> Result<(Option<String>, bool), BackendError> {
        openshell_sandbox_backend::OpenShellRuntimeBackend::discover_policy_with_connector(
            self.descriptor.runtime.clone(),
            bearer,
            Some(self.connector.clone()),
        )
        .await
    }

    fn build(self: Box<Self>, services: BackendServices) -> Result<BuiltBackend, BackendError> {
        let payload = self.descriptor.runtime.backend_descriptor()?.payload;
        let proxy = self.descriptor.proxy;
        let binary_identity = proxy.binary_identity()?;
        Ok(BuiltBackend {
            payload,
            proxy_listener: Some(ProxyListenerConfig {
                bind_addr: proxy.bind_addr,
                authorization: proxy.authorization.into(),
                binary_identity,
            }),
            backend: Arc::new(MxcRuntimeBackend::new(
                services.ca_file_paths,
                services.provider_credentials,
                services.sandbox_bearer,
                self.connector,
            )),
        })
    }
}
