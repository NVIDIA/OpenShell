// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! SPIFFE Broker API JWT profile with attested Kubernetes object references.

use crate::{configuration_failure, identity_rejected};
use hyper_util::rt::TokioIo;
use openshell_core::config::SpiffeBrokerConfig;
use openshell_core::token_grant_failure::{
    TokenGrantFailure, TokenGrantFailureKind, TokenGrantStage, WORKLOAD_IDENTITY_CALL_TIMEOUT,
};
use openshell_spiffe::SandboxJwtSvid;
use prost::Message;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};
use std::{collections::HashMap, sync::Arc};
use tonic::{
    Request,
    transport::{Channel, Endpoint},
};

// Wire fields from spiffe/spiffe standards/brokerapi.proto. This probe uses
// only the JWT profile and KubernetesObjectReference, never PID references.
#[derive(Clone, PartialEq, Message)]
struct AnyReference {
    #[prost(string, tag = "1")]
    type_url: String,
    #[prost(bytes = "vec", tag = "2")]
    value: Vec<u8>,
}
#[derive(Clone, PartialEq, Message)]
struct WorkloadReference {
    #[prost(message, optional, tag = "1")]
    reference: Option<AnyReference>,
}
#[derive(Clone, PartialEq, Message)]
struct ObjectType {
    #[prost(string, tag = "1")]
    plural: String,
    #[prost(string, tag = "2")]
    group: String,
}
#[derive(Clone, PartialEq, Message)]
struct ObjectKey {
    #[prost(string, tag = "1")]
    namespace: String,
    #[prost(string, tag = "2")]
    name: String,
}
#[derive(Clone, PartialEq, Message)]
struct ObjectReference {
    #[prost(message, optional, tag = "1")]
    r#type: Option<ObjectType>,
    #[prost(message, optional, tag = "2")]
    key: Option<ObjectKey>,
    #[prost(string, tag = "3")]
    uid: String,
}
#[derive(Clone, PartialEq, Message)]
struct FetchRequest {
    #[prost(message, optional, tag = "1")]
    reference: Option<WorkloadReference>,
    #[prost(string, repeated, tag = "2")]
    audience: Vec<String>,
    #[prost(string, tag = "3")]
    spiffe_id: String,
}
#[derive(Clone, PartialEq, Message)]
struct JwtSvid {
    #[prost(string, tag = "1")]
    spiffe_id: String,
    #[prost(string, tag = "2")]
    svid: String,
    #[prost(string, tag = "3")]
    hint: String,
}
#[derive(Clone, PartialEq, Message)]
struct FetchResponse {
    #[prost(message, repeated, tag = "1")]
    svids: Vec<JwtSvid>,
}
#[derive(Clone, PartialEq, Message)]
struct BundlesRequest {
    #[prost(message, optional, tag = "1")]
    reference: Option<WorkloadReference>,
}
#[derive(Clone, PartialEq, Message)]
struct BundlesResponse {
    #[prost(map = "string, bytes", tag = "1")]
    bundles: HashMap<String, Vec<u8>>,
}

fn failure(kind: TokenGrantFailureKind) -> TokenGrantFailure {
    TokenGrantFailure::new(kind, TokenGrantStage::WorkloadIdentity)
}
fn status_failure(status: tonic::Status) -> TokenGrantFailure {
    failure(match status.code() {
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
fn request<T>(message: T) -> Request<T> {
    let mut request = Request::new(message);
    request
        .metadata_mut()
        .insert("broker.spiffe.io", "true".parse().expect("static metadata"));
    request
}

/// The reference is derived only from the driver's immutable identity retained
/// by the gateway, not mutable workload labels or caller-provided selectors.
fn reference(runtime: &str) -> Result<WorkloadReference, TokenGrantFailure> {
    let parts: Vec<_> = runtime
        .strip_prefix("kubernetes://")
        .ok_or_else(configuration_failure)?
        .split('/')
        .collect();
    let [namespace, uid, component] = parts.as_slice() else {
        return Err(configuration_failure());
    };
    if namespace.is_empty() || component.is_empty() || uid.parse::<uuid::Uuid>().is_err() {
        return Err(configuration_failure());
    }
    Ok(WorkloadReference {
        reference: Some(AnyReference {
            type_url: "type.googleapis.com/spiffe.broker.KubernetesObjectReference".into(),
            value: ObjectReference {
                r#type: Some(ObjectType {
                    plural: "sandboxes".into(),
                    group: "agents.x-k8s.io".into(),
                }),
                // Kubernetes UIDs are cluster-unique. SPIRE resolves this UID itself;
                // an object recreated with the same name cannot satisfy the reference.
                key: None,
                uid: (*uid).to_string(),
            }
            .encode_to_vec(),
        }),
    })
}

async fn channel(config: &SpiffeBrokerConfig) -> Result<Channel, TokenGrantFailure> {
    let endpoint = format!("unix:{}", config.workload_api_socket_path);
    let workload = spiffe::WorkloadApiClient::connect_to(endpoint)
        .await
        .map_err(|_| failure(TokenGrantFailureKind::Unavailable))?;
    // Fetch afresh at every acquisition. Neither client credentials nor trust
    // bundles are pinned across their Workload API rotation.
    let context = workload
        .fetch_x509_context()
        .await
        .map_err(|_| failure(TokenGrantFailureKind::Unavailable))?;
    let svid = context.default_svid().ok_or_else(identity_rejected)?;
    let domain = spiffe::TrustDomain::new(
        openshell_spiffe::trust_domain(&config.server_spiffe_id)
            .ok_or_else(configuration_failure)?,
    )
    .map_err(|_| configuration_failure())?;
    let bundle = context
        .bundle_set()
        .get(&domain)
        .ok_or_else(identity_rejected)?;
    let mut roots = RootCertStore::empty();
    for cert in bundle.authorities() {
        roots
            .add(CertificateDer::from(cert.as_ref().to_vec()))
            .map_err(|_| identity_rejected())?;
    }
    let chain = svid
        .cert_chain()
        .iter()
        .map(|cert| CertificateDer::from(cert.as_ref().to_vec()))
        .collect();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        svid.private_key().as_ref().to_vec(),
    ));
    let mut tls = openshell_crypto::tls::try_client_builder()
        .map_err(|_| configuration_failure())?
        .dangerous()
        .with_custom_certificate_verifier(openshell_crypto::tls::spiffe::server_verifier(
            roots,
            config.server_spiffe_id.clone(),
        ))
        .with_client_auth_cert(chain, key)
        .map_err(|_| configuration_failure())?;
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls));
    let uri: http::Uri = config
        .endpoint
        .parse()
        .map_err(|_| configuration_failure())?;
    let host = uri
        .host()
        .ok_or_else(configuration_failure)?
        .trim_matches(['[', ']'])
        .to_string();
    let port = uri.port_u16().unwrap_or(443);
    Endpoint::from_static("http://broker.invalid")
        .connect_with_connector(tower::service_fn(move |_| {
            let connector = connector.clone();
            let host = host.clone();
            async move {
                let tcp =
                    openshell_core::net::connect_tcp_nodelay_best_effort((host.as_str(), port))
                        .await?;
                let stream = connector
                    .connect(
                        ServerName::try_from("broker.invalid").expect("static name"),
                        tcp,
                    )
                    .await?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }))
        .await
        .map_err(|_| failure(TokenGrantFailureKind::Unavailable))
}

pub async fn fetch(
    config: &SpiffeBrokerConfig,
    runtime: &str,
    expected: &str,
    audience: &str,
) -> Result<SandboxJwtSvid, TokenGrantFailure> {
    let reference = reference(runtime)?;
    tokio::time::timeout(WORKLOAD_IDENTITY_CALL_TIMEOUT, async {
        let mut grpc = tonic::client::Grpc::new(channel(config).await?);
        grpc.ready()
            .await
            .map_err(|_| failure(TokenGrantFailureKind::Unavailable))?;
        let response: tonic::Response<FetchResponse> = grpc
            .unary(
                request(FetchRequest {
                    reference: Some(reference.clone()),
                    audience: vec![audience.to_string()],
                    spiffe_id: expected.to_string(),
                }),
                http::uri::PathAndQuery::from_static("/spiffe.broker.API/FetchJWTSVID"),
                tonic_prost::ProstCodec::default(),
            )
            .await
            .map_err(status_failure)?;
        let response = response.into_inner();
        let [svid] = response.svids.as_slice() else {
            return Err(identity_rejected());
        };
        if svid.spiffe_id != expected {
            return Err(identity_rejected());
        }
        grpc.ready()
            .await
            .map_err(|_| failure(TokenGrantFailureKind::Unavailable))?;
        let mut stream: tonic::Streaming<BundlesResponse> = grpc
            .server_streaming(
                request(BundlesRequest {
                    reference: Some(reference),
                }),
                http::uri::PathAndQuery::from_static("/spiffe.broker.API/SubscribeToJWTBundles"),
                tonic_prost::ProstCodec::default(),
            )
            .await
            .map_err(status_failure)?
            .into_inner();
        let bundles = stream
            .message()
            .await
            .map_err(status_failure)?
            .ok_or_else(identity_rejected)?;
        let domain = spiffe::TrustDomain::new(
            openshell_spiffe::trust_domain(expected).ok_or_else(configuration_failure)?,
        )
        .map_err(|_| configuration_failure())?;
        let bundle = spiffe::JwtBundle::from_jwt_authorities(
            domain.clone(),
            bundles
                .bundles
                .get(&domain.id_string())
                .ok_or_else(identity_rejected)?,
        )
        .map_err(|_| identity_rejected())?;
        let mut set = spiffe::JwtBundleSet::new();
        set.add_bundle(bundle);
        openshell_crypto::install_jwt_provider();
        let verified = spiffe::JwtSvid::parse_and_validate(&svid.svid, &set, &[audience])
            .map_err(|_| identity_rejected())?;
        if verified.spiffe_id().to_string() != expected {
            return Err(identity_rejected());
        }
        Ok(SandboxJwtSvid {
            spiffe_id: expected.to_string(),
            token: svid.svid.clone(),
            expires_at: verified.claims().exp(),
        })
    })
    .await
    .map_err(|_| failure(TokenGrantFailureKind::Timeout))?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_driver_authenticated_kubernetes_uid_references_are_accepted() {
        for runtime in [
            "",
            "docker://container",
            "kubernetes://ns/not-a-uid/component",
            "kubernetes://ns/3d185166-01ad-4696-8d7c-ac315d4c01e3/",
        ] {
            assert!(reference(runtime).is_err());
        }
        let reference = reference("kubernetes://ns/3d185166-01ad-4696-8d7c-ac315d4c01e3/component")
            .unwrap()
            .reference
            .unwrap();
        let object = ObjectReference::decode(reference.value.as_slice()).unwrap();
        assert_eq!(object.uid, "3d185166-01ad-4696-8d7c-ac315d4c01e3");
        assert!(object.key.is_none());
    }
}
