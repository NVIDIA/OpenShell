// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway-owned sandbox identities obtained through the SPIFFE Broker API.

mod broker;

use openshell_core::config::SpiffeBrokerConfig;
use openshell_core::token_grant_failure::{
    TokenGrantFailure, TokenGrantFailureKind, TokenGrantStage,
};
use openshell_spiffe::{SandboxIdentityProvider, SandboxJwtSvid, SandboxSpiffeIdPrefix};

/// SPIRE Broker API adapter. Each acquisition gets current Workload API
/// credentials and verifies an exact sandbox identity and audience.
#[derive(Debug)]
pub struct SpireSandboxIdentity {
    config: SpiffeBrokerConfig,
    prefix: SandboxSpiffeIdPrefix,
    endpoint: String,
}

impl SpireSandboxIdentity {
    /// Parse the stable identity prefix; startup also validates the transport.
    ///
    /// # Errors
    /// Rejects an invalid SPIFFE ID prefix or missing/invalid node address.
    pub fn new(config: &SpiffeBrokerConfig) -> Result<Self, String> {
        Ok(Self {
            config: config.clone(),
            prefix: SandboxSpiffeIdPrefix::parse(&config.spiffe_id_prefix)?,
            endpoint: config
                .endpoint_for_node(std::env::var("OPENSHELL_NODE_IP").ok().as_deref())?,
        })
    }
}

#[async_trait::async_trait]
impl SandboxIdentityProvider for SpireSandboxIdentity {
    type Error = TokenGrantFailure;

    async fn fetch_jwt_svid(
        &self,
        gateway_id: &str,
        sandbox_id: &str,
        audience: &str,
        runtime_identity: &str,
    ) -> Result<SandboxJwtSvid, TokenGrantFailure> {
        let expected = self
            .prefix
            .sandbox_spiffe_id(gateway_id, sandbox_id)
            .map_err(|_| configuration_failure())?;
        broker::fetch(
            &self.config,
            &self.endpoint,
            runtime_identity,
            &expected,
            audience,
        )
        .await
    }
}

fn configuration_failure() -> TokenGrantFailure {
    TokenGrantFailure::new(
        TokenGrantFailureKind::Configuration,
        TokenGrantStage::Configuration,
    )
}
fn identity_rejected() -> TokenGrantFailure {
    TokenGrantFailure::new(
        TokenGrantFailureKind::WorkloadIdentityRejected,
        TokenGrantStage::WorkloadIdentity,
    )
}
