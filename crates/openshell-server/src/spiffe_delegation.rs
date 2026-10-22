// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! SPIRE delegated issuance owned by the gateway, never by a supervisor or sandbox.
use openshell_core::config::{Config, ExperimentalSpiffeDelegationConfig};
use openshell_core::spiffe::SandboxSpiffeIdPrefix;
use openshell_core::token_grant_failure::{
    TokenGrantFailure, TokenGrantFailureKind, TokenGrantStage,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
const AGENT_CALL_TIMEOUT: Duration = Duration::from_secs(10);

/// Validated, immutable settings of gateway-owned SPIRE delegation.
///
/// Gateway state parses these once when it is constructed. Requests reuse the parsed
/// socket, sandbox SPIFFE ID prefix, trust domain, and gateway identity, but
/// fetch each SVID and the agent's current JWT bundle afresh.
#[derive(Debug)]
pub struct SpiffeDelegation {
    admin_socket: PathBuf,
    prefix: SandboxSpiffeIdPrefix,
    trust_domain: spiffe::TrustDomain,
    gateway_id: String,
}

impl SpiffeDelegation {
    /// Check the delegation settings `config` enables without building them.
    ///
    /// # Errors
    ///
    /// Rejects delegation without gateway session JWTs and a positive session
    /// TTL, and settings [`ExperimentalSpiffeDelegationConfig::validate`]
    /// rejects.
    pub fn validate_config(config: &Config) -> Result<(), String> {
        enabled(config).map(drop)
    }

    /// The delegation `config` enables, if any.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::validate_config`] rejects.
    pub fn from_config(config: &Config) -> Result<Option<Self>, String> {
        enabled(config)?
            .map(|(delegation, gateway_id)| Self::new(delegation, gateway_id))
            .transpose()
    }

    /// Parse `config`, already validated for the gateway `gateway_id`.
    fn new(config: &ExperimentalSpiffeDelegationConfig, gateway_id: &str) -> Result<Self, String> {
        let prefix = SandboxSpiffeIdPrefix::parse(&config.spiffe_id_prefix)?;
        let trust_domain = openshell_core::spiffe::trust_domain(prefix.as_str())
            .and_then(|name| spiffe::TrustDomain::new(name).ok())
            .ok_or("experimental_spiffe_delegation prefix has no valid trust domain")?;
        Ok(Self {
            admin_socket: PathBuf::from(&config.admin_socket_path),
            prefix,
            trust_domain,
            gateway_id: gateway_id.to_string(),
        })
    }

    pub fn gateway_id(&self) -> &str {
        &self.gateway_id
    }

    /// Stable SPIFFE ID of `sandbox_id` under this gateway.
    pub fn sandbox_spiffe_id(&self, sandbox_id: &str) -> Result<String, TokenGrantFailure> {
        self.prefix
            .sandbox_spiffe_id(&self.gateway_id, sandbox_id)
            .map_err(|_| configuration_failure())
    }

    /// The caller must authorize the current sandbox session before requesting issuance.
    pub async fn fetch_jwt_svid(
        &self,
        sandbox_id: &str,
        audience: &str,
    ) -> Result<(String, i64), TokenGrantFailure> {
        let expected = self.sandbox_spiffe_id(sandbox_id)?;
        let mut agent = AdminClient::connect(&self.admin_socket).await?;
        let response = agent
            .fetch_jwt_svids(wire::FetchJwtSvidsRequest {
                audience: vec![audience.to_string()],
                selectors: vec![wire::Selector {
                    r#type: "openshell".into(),
                    value: format!("sandbox:{}:{sandbox_id}", self.gateway_id),
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
        Ok((svid.token.clone(), verified.claims().exp()))
    }
}

/// Validated delegation settings and gateway ID, when delegation is enabled.
fn enabled(config: &Config) -> Result<Option<(&ExperimentalSpiffeDelegationConfig, &str)>, String> {
    let Some(delegation) = &config.experimental_spiffe_delegation else {
        return Ok(None);
    };
    let jwt = config
        .gateway_jwt
        .as_ref()
        .ok_or("experimental_spiffe_delegation requires gateway session JWTs")?;
    delegation.validate(&jwt.gateway_id)?;
    if jwt.ttl_secs.is_none() {
        return Err(
            "experimental_spiffe_delegation requires a positive gateway_jwt.ttl_secs".into(),
        );
    }
    Ok(Some((delegation, &jwt.gateway_id)))
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

fn agent_failure(kind: TokenGrantFailureKind) -> TokenGrantFailure {
    TokenGrantFailure::new(kind, TokenGrantStage::WorkloadIdentity)
}

fn status_failure(status: &tonic::Status) -> TokenGrantFailure {
    // Classify only by code; the agent's message is not retained.
    agent_failure(match status.code() {
        tonic::Code::PermissionDenied | tonic::Code::Unauthenticated => {
            TokenGrantFailureKind::WorkloadIdentityRejected
        }
        tonic::Code::DeadlineExceeded => TokenGrantFailureKind::Timeout,
        tonic::Code::Unavailable => TokenGrantFailureKind::Unavailable,
        tonic::Code::InvalidArgument | tonic::Code::Unimplemented => {
            TokenGrantFailureKind::Configuration
        }
        _ => TokenGrantFailureKind::Unclassified,
    })
}

/// Client for the SPIRE agent's Delegated Identity API.
struct AdminClient {
    grpc: tonic::client::Grpc<tonic::transport::Channel>,
}

impl AdminClient {
    async fn connect(socket: &std::path::Path) -> Result<Self, TokenGrantFailure> {
        // Delegation is authorized by the agent attesting this process over
        // a local socket; a TCP endpoint could not attest it.
        if !socket.is_absolute() {
            return Err(configuration_failure());
        }
        let endpoint =
            spiffe::transport::endpoint::Endpoint::parse(&format!("unix:{}", socket.display()))
                .map_err(|_| configuration_failure())?;
        let channel = tokio::time::timeout(
            AGENT_CALL_TIMEOUT,
            spiffe::transport::connector::connect(&endpoint),
        )
        .await
        .map_err(|_| agent_failure(TokenGrantFailureKind::Timeout))?
        .map_err(|_| agent_failure(TokenGrantFailureKind::Unavailable))?;
        Ok(Self {
            grpc: tonic::client::Grpc::new(channel),
        })
    }

    async fn fetch_jwt_svids(
        &mut self,
        request: wire::FetchJwtSvidsRequest,
    ) -> Result<wire::FetchJwtSvidsResponse, TokenGrantFailure> {
        tokio::time::timeout(AGENT_CALL_TIMEOUT, async {
            self.ready().await?;
            self.grpc
                .unary(
                    tonic::Request::new(request),
                    http::uri::PathAndQuery::from_static(wire::FETCH_JWT_SVIDS),
                    tonic_prost::ProstCodec::default(),
                )
                .await
                .map(tonic::Response::into_inner)
                .map_err(|status| status_failure(&status))
        })
        .await
        .map_err(|_| agent_failure(TokenGrantFailureKind::Timeout))?
    }

    /// The agent's current JWT bundle for `trust_domain` only.
    async fn jwt_bundles(
        &mut self,
        trust_domain: &spiffe::TrustDomain,
    ) -> Result<spiffe::JwtBundleSet, TokenGrantFailure> {
        let response: wire::SubscribeToJwtBundlesResponse =
            tokio::time::timeout(AGENT_CALL_TIMEOUT, async {
                self.ready().await?;
                let mut stream = self
                    .grpc
                    .server_streaming(
                        tonic::Request::new(wire::SubscribeToJwtBundlesRequest {}),
                        http::uri::PathAndQuery::from_static(wire::SUBSCRIBE_TO_JWT_BUNDLES),
                        tonic_prost::ProstCodec::default(),
                    )
                    .await
                    .map_err(|status| status_failure(&status))?
                    .into_inner();
                stream
                    .message()
                    .await
                    .map_err(|status| status_failure(&status))?
                    .ok_or_else(|| agent_failure(TokenGrantFailureKind::Unavailable))
            })
            .await
            .map_err(|_| agent_failure(TokenGrantFailureKind::Timeout))??;
        let jwks = response
            .bundles
            .get(&trust_domain.id_string())
            .ok_or_else(identity_rejected)?;
        let bundle = spiffe::JwtBundle::from_jwt_authorities(trust_domain.clone(), jwks)
            .map_err(|_| identity_rejected())?;
        let mut bundles = spiffe::JwtBundleSet::new();
        bundles.add_bundle(bundle);
        Ok(bundles)
    }

    async fn ready(&mut self) -> Result<(), TokenGrantFailure> {
        self.grpc
            .ready()
            .await
            .map_err(|_| agent_failure(TokenGrantFailureKind::Unavailable))
    }
}

/// Wire messages of the SPIRE agent Delegated Identity API.
///
/// Transcribed from `proto/spire/api/agent/delegatedidentity/v1/delegatedidentity.proto`
/// and `proto/spire/api/types/{selector,jwtsvid,spiffeid}.proto` of
/// <https://github.com/spiffe/spire-api-sdk> at tag `v1.15.3` (commit
/// `adb81b3b0fb87a881693d1d42eaf8b2fa1223e42`), Copyright The SPIFFE Authors,
/// licensed under the Apache License, Version 2.0. Only the messages for
/// `FetchJWTSVIDs` and `SubscribeToJWTBundles` are reproduced; field numbers
/// and types are unchanged.
mod wire {
    use super::HashMap;

    pub(super) const FETCH_JWT_SVIDS: &str =
        "/spire.api.agent.delegatedidentity.v1.DelegatedIdentity/FetchJWTSVIDs";
    pub(super) const SUBSCRIBE_TO_JWT_BUNDLES: &str =
        "/spire.api.agent.delegatedidentity.v1.DelegatedIdentity/SubscribeToJWTBundles";

    /// `spire.api.types.Selector`
    #[derive(Clone, PartialEq, prost::Message)]
    pub(super) struct Selector {
        #[prost(string, tag = "1")]
        pub r#type: String,
        #[prost(string, tag = "2")]
        pub value: String,
    }

    /// `spire.api.types.SPIFFEID`
    #[derive(Clone, PartialEq, prost::Message)]
    pub(super) struct SpiffeId {
        #[prost(string, tag = "1")]
        pub trust_domain: String,
        #[prost(string, tag = "2")]
        pub path: String,
    }

    /// `spire.api.types.JWTSVID`
    #[derive(Clone, PartialEq, prost::Message)]
    pub(super) struct JwtSvid {
        #[prost(string, tag = "1")]
        pub token: String,
        #[prost(message, optional, tag = "2")]
        pub id: Option<SpiffeId>,
        #[prost(int64, tag = "3")]
        pub expires_at: i64,
        #[prost(int64, tag = "4")]
        pub issued_at: i64,
        #[prost(string, tag = "5")]
        pub hint: String,
    }

    /// `spire.api.agent.delegatedidentity.v1.FetchJWTSVIDsRequest`
    #[derive(Clone, PartialEq, prost::Message)]
    pub(super) struct FetchJwtSvidsRequest {
        #[prost(string, repeated, tag = "1")]
        pub audience: Vec<String>,
        #[prost(message, repeated, tag = "2")]
        pub selectors: Vec<Selector>,
        #[prost(int32, tag = "3")]
        pub pid: i32,
    }

    /// `spire.api.agent.delegatedidentity.v1.FetchJWTSVIDsResponse`
    #[derive(Clone, PartialEq, prost::Message)]
    pub(super) struct FetchJwtSvidsResponse {
        #[prost(message, repeated, tag = "1")]
        pub svids: Vec<JwtSvid>,
    }

    /// `spire.api.agent.delegatedidentity.v1.SubscribeToJWTBundlesRequest`
    #[derive(Clone, PartialEq, prost::Message)]
    pub(super) struct SubscribeToJwtBundlesRequest {}

    /// `spire.api.agent.delegatedidentity.v1.SubscribeToJWTBundlesResponse`
    #[derive(Clone, PartialEq, prost::Message)]
    pub(super) struct SubscribeToJwtBundlesResponse {
        #[prost(map = "string, bytes", tag = "1")]
        pub bundles: HashMap<String, Vec<u8>>,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires the real SPIRE fixture; run mise run test:spire-delegation"]
    async fn gateway_obtains_only_the_expected_sandbox_identity() {
        let env = |key| std::env::var(key).expect("SPIRE fixture variable");
        let config = ExperimentalSpiffeDelegationConfig {
            admin_socket_path: env("OPENSHELL_TEST_SPIRE_ADMIN_SOCKET"),
            spiffe_id_prefix: env("OPENSHELL_TEST_SPIRE_ID_PREFIX"),
            admin_socket_group: None,
        };
        let gateway = env("OPENSHELL_TEST_SPIRE_GATEWAY_ID");
        config.validate(&gateway).unwrap();
        let delegation = SpiffeDelegation::new(&config, &gateway).unwrap();
        let audience = "https://sts.openshell.test";
        let alpha = env("OPENSHELL_TEST_SPIRE_SANDBOX_ALPHA");
        let beta = env("OPENSHELL_TEST_SPIRE_SANDBOX_BETA");
        let (first, expiry) = delegation.fetch_jwt_svid(&alpha, audience).await.unwrap();
        let (second, _) = delegation.fetch_jwt_svid(&beta, audience).await.unwrap();
        assert_ne!(first, second);
        assert!(expiry > 0);
        for key in [
            "OPENSHELL_TEST_SPIRE_SANDBOX_UNREGISTERED",
            "OPENSHELL_TEST_SPIRE_SANDBOX_MISREGISTERED",
            "OPENSHELL_TEST_SPIRE_SANDBOX_AMBIGUOUS",
        ] {
            assert!(
                delegation
                    .fetch_jwt_svid(&env(key), audience)
                    .await
                    .is_err()
            );
        }
    }
}
