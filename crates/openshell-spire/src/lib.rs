// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! SPIRE delegated issuance owned by the gateway, never by a supervisor or sandbox.
//!
//! [`SpireDelegatedIdentity`] implements
//! [`SandboxIdentityProvider`] with the SPIRE agent's Delegated Identity API.

mod client;
mod wire;

use std::path::PathBuf;

use openshell_core::config::SpiffeDelegationConfig;
use openshell_core::token_grant_failure::{
    TokenGrantFailure, TokenGrantFailureKind, TokenGrantStage,
};
use openshell_spiffe::{SandboxIdentityProvider, SandboxJwtSvid, SandboxSpiffeIdPrefix};

use client::AdminClient;

/// Validated, immutable settings of gateway-owned SPIRE delegation.
///
/// The gateway builds this once at startup. Requests reuse the parsed socket,
/// sandbox SPIFFE ID prefix, and trust domain, but fetch each SVID and the
/// agent's current JWT bundle afresh.
#[derive(Debug)]
pub struct SpireDelegatedIdentity {
    admin_socket: PathBuf,
    prefix: SandboxSpiffeIdPrefix,
    trust_domain: spiffe::TrustDomain,
}

impl SpireDelegatedIdentity {
    /// Parse settings that [`SpiffeDelegationConfig::validate`] accepted.
    ///
    /// # Errors
    ///
    /// Rejects an invalid SPIFFE ID prefix or trust domain.
    pub fn new(config: &SpiffeDelegationConfig) -> Result<Self, String> {
        let prefix = SandboxSpiffeIdPrefix::parse(&config.spiffe_id_prefix)?;
        let trust_domain = openshell_spiffe::trust_domain(prefix.as_str())
            .and_then(|name| spiffe::TrustDomain::new(name).ok())
            .ok_or("spiffe_delegation prefix has no valid trust domain")?;
        Ok(Self {
            admin_socket: PathBuf::from(&config.admin_socket_path),
            prefix,
            trust_domain,
        })
    }
}

#[async_trait::async_trait]
impl SandboxIdentityProvider for SpireDelegatedIdentity {
    type Error = TokenGrantFailure;

    async fn fetch_jwt_svid(
        &self,
        gateway_id: &str,
        sandbox_id: &str,
        audience: &str,
    ) -> Result<SandboxJwtSvid, TokenGrantFailure> {
        let expected = self
            .prefix
            .sandbox_spiffe_id(gateway_id, sandbox_id)
            .map_err(|_| configuration_failure())?;
        let mut agent = AdminClient::connect(&self.admin_socket).await?;
        let response = agent
            .fetch_jwt_svids(wire::FetchJwtSvidsRequest {
                audience: vec![audience.to_string()],
                selectors: vec![wire::Selector {
                    r#type: "openshell".into(),
                    value: format!("sandbox:{gateway_id}:{sandbox_id}"),
                }],
                pid: 0,
            })
            .await?;
        let [svid] = response.svids.as_slice() else {
            return Err(identity_rejected());
        };
        let reported = svid
            .id
            .as_ref()
            .map(|id| format!("spiffe://{}{}", id.trust_domain, id.path));
        if reported.as_deref() != Some(expected.as_str()) {
            return Err(identity_rejected());
        }
        let bundles = agent.jwt_bundles(&self.trust_domain).await?;
        openshell_crypto::install_jwt_provider();
        let verified = spiffe::JwtSvid::parse_and_validate(&svid.token, &bundles, &[audience])
            .map_err(|_| identity_rejected())?;
        if verified.spiffe_id().to_string() != expected {
            return Err(identity_rejected());
        }
        Ok(SandboxJwtSvid {
            spiffe_id: expected,
            token: svid.token.clone(),
            expires_at: verified.claims().exp(),
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn delegation(admin_socket_path: &str) -> SpireDelegatedIdentity {
        SpireDelegatedIdentity::new(&SpiffeDelegationConfig {
            admin_socket_path: admin_socket_path.into(),
            spiffe_id_prefix: "spiffe://example.org/openshell".into(),
            admin_socket_group: None,
        })
        .unwrap()
    }

    #[tokio::test]
    async fn rejects_ids_outside_the_stable_identity_before_contacting_the_agent() {
        let absent = delegation("/nonexistent-openshell-spire/admin.sock");
        let audience = "https://sts.example.org";
        for (gateway, sandbox) in [("gw/x", "sb"), ("gw", "sb/x"), ("gw", ".."), ("", "sb")] {
            let failure = absent
                .fetch_jwt_svid(gateway, sandbox, audience)
                .await
                .unwrap_err();
            assert_eq!(failure, configuration_failure());
        }
        // Valid IDs reach the agent, which is unavailable here.
        #[cfg(unix)]
        assert_eq!(
            absent
                .fetch_jwt_svid("gw", "sb", audience)
                .await
                .unwrap_err(),
            TokenGrantFailure::new(
                TokenGrantFailureKind::Unavailable,
                TokenGrantStage::WorkloadIdentity
            )
        );
        // The agent can attest the gateway only over a local socket path.
        assert_eq!(
            delegation("relative/admin.sock")
                .fetch_jwt_svid("gw", "sb", audience)
                .await
                .unwrap_err(),
            configuration_failure()
        );
    }

    #[tokio::test]
    #[ignore = "requires the real SPIRE fixture; run mise run test:spire-delegation"]
    async fn gateway_obtains_only_the_expected_sandbox_identity() {
        let env = |key| std::env::var(key).expect("SPIRE fixture variable");
        let config = SpiffeDelegationConfig {
            admin_socket_path: env("OPENSHELL_TEST_SPIRE_ADMIN_SOCKET"),
            spiffe_id_prefix: env("OPENSHELL_TEST_SPIRE_ID_PREFIX"),
            admin_socket_group: None,
        };
        let gateway = env("OPENSHELL_TEST_SPIRE_GATEWAY_ID");
        config.validate(&gateway).unwrap();
        let delegation = SpireDelegatedIdentity::new(&config).unwrap();
        let audience = "https://sts.openshell.test";
        let alpha = env("OPENSHELL_TEST_SPIRE_SANDBOX_ALPHA");
        let beta = env("OPENSHELL_TEST_SPIRE_SANDBOX_BETA");
        let first = delegation
            .fetch_jwt_svid(&gateway, &alpha, audience)
            .await
            .unwrap();
        let second = delegation
            .fetch_jwt_svid(&gateway, &beta, audience)
            .await
            .unwrap();
        assert_ne!(first.token, second.token);
        assert_eq!(
            first.spiffe_id,
            format!(
                "{}/gateway/{gateway}/sandbox/{alpha}",
                config.spiffe_id_prefix
            )
        );
        assert!(first.expires_at > 0);
        for key in [
            "OPENSHELL_TEST_SPIRE_SANDBOX_UNREGISTERED",
            "OPENSHELL_TEST_SPIRE_SANDBOX_MISREGISTERED",
            "OPENSHELL_TEST_SPIRE_SANDBOX_AMBIGUOUS",
        ] {
            assert!(
                delegation
                    .fetch_jwt_svid(&gateway, &env(key), audience)
                    .await
                    .is_err()
            );
        }
    }
}
