// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Local SPIFFE Broker API experiment. See e2e/kubernetes/spiffe-broker/README.md.
//! Credentials are short-lived test artifacts; no token or key is printed.

use std::{collections::HashMap, error::Error, path::PathBuf, sync::Arc, time::Duration};

use hyper_util::rt::TokioIo;
use prost::Message;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
};
use tonic::{
    Request,
    transport::{Channel, Endpoint},
};

type ProbeResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

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

fn env(name: &str) -> ProbeResult<String> {
    Ok(std::env::var(name)?)
}
fn request<T>(message: T) -> Request<T> {
    let mut request = Request::new(message);
    if std::env::var_os("BROKER_OMIT_HEADER").is_none() {
        request
            .metadata_mut()
            .insert("broker.spiffe.io", "true".parse().expect("static metadata"));
    }
    request
}

async fn channel() -> ProbeResult<Channel> {
    let directory = PathBuf::from(env("BROKER_CREDENTIALS")?);
    let certificates = CertificateDer::pem_file_iter(directory.join("svid.0.pem"))?
        .collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(directory.join("svid.0.key"))?;
    let mut roots = RootCertStore::empty();
    if std::env::var_os("BROKER_EMPTY_TRUST").is_none() {
        for certificate in CertificateDer::pem_file_iter(directory.join("bundle.0.pem"))? {
            roots.add(certificate?)?;
        }
    }
    let mut tls = openshell_crypto::tls::try_client_builder()?
        .dangerous()
        .with_custom_certificate_verifier(openshell_crypto::tls::spiffe::server_verifier(
            roots,
            env("BROKER_AGENT_ID")?,
        ))
        .with_client_auth_cert(certificates, key)?;
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls));
    let address = env("BROKER_ADDRESS")?;
    Ok(Endpoint::from_static("http://broker.invalid")
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(10))
        .connect_with_connector(tower::service_fn(move |_| {
            let connector = connector.clone();
            let address = address.clone();
            async move {
                let tcp = openshell_core::net::connect_tcp_nodelay_best_effort(address).await?;
                let stream = connector
                    .connect(
                        ServerName::try_from("broker.invalid").expect("static name"),
                        tcp,
                    )
                    .await?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }))
        .await?)
}

async fn probe() -> ProbeResult<()> {
    let reference = WorkloadReference {
        reference: Some(AnyReference {
            type_url: "type.googleapis.com/spiffe.broker.KubernetesObjectReference".into(),
            value: ObjectReference {
                r#type: Some(ObjectType {
                    plural: env("BROKER_RESOURCE")?,
                    group: env("BROKER_GROUP")?,
                }),
                key: if std::env::var_os("BROKER_UID_ONLY").is_some() {
                    None
                } else {
                    Some(ObjectKey {
                        namespace: env("BROKER_NAMESPACE")?,
                        name: env("BROKER_NAME")?,
                    })
                },
                uid: env("BROKER_UID")?,
            }
            .encode_to_vec(),
        }),
    };
    let expected = env("BROKER_SANDBOX_ID")?;
    let audience = "openshell-broker-probe";
    let mut grpc = tonic::client::Grpc::new(channel().await?);
    grpc.ready()
        .await
        .map_err(|_| "broker channel unavailable")?;
    let response: Result<tonic::Response<FetchResponse>, _> = grpc
        .unary(
            request(FetchRequest {
                reference: Some(reference.clone()),
                audience: vec![audience.into()],
                spiffe_id: expected.clone(),
            }),
            http::uri::PathAndQuery::from_static("/spiffe.broker.API/FetchJWTSVID"),
            tonic_prost::ProstCodec::default(),
        )
        .await;
    if let Ok(code) = std::env::var("BROKER_EXPECT_ERROR") {
        match response {
            Err(status) if format!("{:?}", status.code()) == code => {
                println!("PASS: request rejected with {code}");
                return Ok(());
            }
            Err(status) => {
                return Err(format!("expected {code}; received {:?}", status.code()).into());
            }
            Ok(_) => return Err("expected rejection; issuance succeeded".into()),
        }
    }
    let response = response
        .map_err(|status| format!("issuance failed: {:?}", status.code()))?
        .into_inner();
    let [svid] = response.svids.as_slice() else {
        return Err("expected exactly one JWT-SVID".into());
    };
    if svid.spiffe_id != expected {
        return Err("unexpected response identity".into());
    }
    grpc.ready()
        .await
        .map_err(|_| "broker channel unavailable")?;
    let mut stream: tonic::Streaming<BundlesResponse> = grpc
        .server_streaming(
            request(BundlesRequest {
                reference: Some(reference),
            }),
            http::uri::PathAndQuery::from_static("/spiffe.broker.API/SubscribeToJWTBundles"),
            tonic_prost::ProstCodec::default(),
        )
        .await
        .map_err(|status| format!("bundles failed: {:?}", status.code()))?
        .into_inner();
    let bundles = stream
        .message()
        .await
        .map_err(|status| format!("bundles failed: {:?}", status.code()))?
        .ok_or("empty bundle stream")?;
    let domain = spiffe::TrustDomain::new(
        openshell_spiffe::trust_domain(&expected).ok_or("invalid expected identity")?,
    )?;
    let bundle = spiffe::JwtBundle::from_jwt_authorities(
        domain.clone(),
        bundles
            .bundles
            .get(&domain.id_string())
            .ok_or("missing trust-domain bundle")?,
    )?;
    let mut bundle_set = spiffe::JwtBundleSet::new();
    bundle_set.add_bundle(bundle);
    openshell_crypto::install_jwt_provider();
    let verified = spiffe::JwtSvid::parse_and_validate(&svid.svid, &bundle_set, &[audience])?;
    if verified.spiffe_id().to_string() != expected {
        return Err("unexpected verified identity".into());
    }
    println!(
        "PASS: verified sandbox JWT-SVID {expected}; expires_at={}",
        verified.claims().exp()
    );
    Ok(())
}

#[tokio::main]
async fn main() -> ProbeResult<()> {
    tokio::time::timeout(Duration::from_secs(30), probe()).await?
}
