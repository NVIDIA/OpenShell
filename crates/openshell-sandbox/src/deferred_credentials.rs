// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use miette::{IntoDiagnostic, Result};
use openshell_core::proto::open_shell_client::OpenShellClient;
use openshell_core::proto::{ResolveCredentialRequest, ResolveCredentialResponse};
use tonic::transport::Channel;
use tracing::debug;

use crate::secrets::SecretResolver;

/// Handle for resolving deferred credentials via gRPC callback to the gateway,
/// which relays to the CLI credential authority.
#[derive(Clone)]
pub struct DeferredCredentialResolver {
    client: OpenShellClient<Channel>,
    sandbox_id: String,
}

impl DeferredCredentialResolver {
    pub fn new(client: OpenShellClient<Channel>, sandbox_id: String) -> Self {
        Self { client, sandbox_id }
    }

    /// Resolve a deferred placeholder by calling the gateway.
    ///
    /// The gateway relays the request to the CLI's bidirectional
    /// `RegisterCredentialAuthority` stream, where the user approves/denies
    /// via an OS-native dialog. This call blocks until a response arrives
    /// or the RPC times out.
    pub async fn resolve(
        &self,
        placeholder: &str,
        destination_host: &str,
    ) -> Result<String> {
        let env_key = SecretResolver::env_key_for_placeholder(placeholder)
            .unwrap_or(placeholder)
            .to_string();

        debug!(
            sandbox_id = %self.sandbox_id,
            env_key = %env_key,
            destination_host = %destination_host,
            "Requesting deferred credential from CLI"
        );

        let response: ResolveCredentialResponse = self
            .client
            .clone()
            .resolve_credential(ResolveCredentialRequest {
                sandbox_id: self.sandbox_id.clone(),
                env_key,
                destination_host: destination_host.to_string(),
            })
            .await
            .into_diagnostic()?
            .into_inner();

        if response.approved {
            Ok(response.value)
        } else {
            Err(miette::miette!("credential request denied by user"))
        }
    }
}
