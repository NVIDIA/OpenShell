// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::credentials::ResolvedCredentialVersion;

fn key(provider: &Provider, version: Option<&ResolvedCredentialVersion>) -> String {
    intermediate_token_cache_key(IntermediateTokenCacheKeyInput {
        provider,
        dynamic_credential: "access_token",
        subject_credential: "subject_token",
        subject_version: version,
        token_endpoint: "https://identity.example.test/token",
        client_assertion_type: "jwt-bearer",
        subject_token_type: "access_token",
        audience: "supervisor",
        requested_token_type: "access_token",
        supervisor_subject: "supervisor",
        gateway_subject: "gateway",
    })
}

#[test]
fn subject_rotation_with_unchanged_provider_row_misses_previous_cache_entry() {
    let provider = Provider::default();
    let old = ResolvedCredentialVersion {
        reference: "subject-reference".into(),
        version: 1,
        authorization_epoch: "authorization-a".into(),
    };
    let token = oauth::OAuthTokenResponse {
        access_token: "intermediate".into(),
        expires_in: 300,
        token_type: "Bearer".into(),
    };
    let cache = IntermediateTokenCache::new();
    cache.set(
        key(&provider, Some(&old)),
        &token,
        crate::persistence::current_time_ms() + 300_000,
    );
    assert!(cache.get(&key(&provider, Some(&old))).is_some());
    let new = ResolvedCredentialVersion {
        version: 2,
        ..old.clone()
    };
    assert!(cache.get(&key(&provider, Some(&new))).is_none());
    let new_epoch = ResolvedCredentialVersion {
        authorization_epoch: "authorization-b".into(),
        ..old
    };
    assert!(cache.get(&key(&provider, Some(&new_epoch))).is_none());
}

#[test]
fn captured_subject_expiration_caps_intermediate_token_cache() {
    let subject_expiry = crate::persistence::current_time_ms() + 45_000;
    let token = oauth::OAuthTokenResponse {
        access_token: "opaque-intermediate".into(),
        expires_in: 300,
        token_type: "Bearer".into(),
    };
    assert!(
        intermediate_token_cache_expires_at_ms(&token, None, subject_expiry, 0) <= subject_expiry
    );
}

const IDENTITY_CHILD: &str = "OPENSHELL_SUBJECT_QUALIFICATION_CHILD";
const SUPERVISOR_SVID: &str = "OPENSHELL_SUBJECT_QUALIFICATION_SVID";
const AUDIENCE: &str = "subject-consumer-qualification";
const GATEWAY_ID: &str = "spiffe://qualification.test/gateway";
const SUPERVISOR_ID: &str = "spiffe://qualification.test/supervisor";

// Minimal SPIFFE Workload API wire messages. The spiffe crate keeps its generated
// bindings private; these protocol fixtures exercise its real client/verification
// rather than replacing identity acquisition or adding a production bypass.
#[derive(prost::Message)]
struct JwtSvidWire {
    #[prost(string, tag = "1")]
    spiffe_id: String,
    #[prost(string, tag = "2")]
    svid: String,
}
#[derive(prost::Message)]
struct JwtSvidsWire {
    #[prost(message, repeated, tag = "1")]
    svids: Vec<JwtSvidWire>,
}
#[derive(prost::Message)]
struct JwtBundlesWire {
    #[prost(map = "string, bytes", tag = "1")]
    bundles: HashMap<String, Vec<u8>>,
}

fn grpc_response(message: &impl Message) -> wiremock::ResponseTemplate {
    let payload = message.encode_to_vec();
    let mut frame = vec![0]; // uncompressed gRPC message
    frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(&payload);
    wiremock::ResponseTemplate::new(200)
        .insert_header("grpc-status", "0")
        .set_body_raw(frame, "application/grpc")
}

/// Environment configuration is isolated in a subprocess, not mutated in a
/// multithreaded test runner. Both SPIFFE RPCs and token exchange use wiremock's
/// real HTTP/2/HTTP listeners; supervisor JWT signatures are really verified.
async fn with_test_identity(test: &str, expected_identity_requests: u64) {
    use base64::Engine as _;
    use wiremock::{
        Mock, MockServer,
        matchers::{method, path},
    };
    let identity = MockServer::start().await;
    let key = openshell_crypto::pki::generate_keypair().unwrap();
    let public = key.public_key_der();
    let point = &public[public.len() - 65..];
    assert_eq!(point[0], 4);
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let jwks = serde_json::to_vec(&serde_json::json!({"keys":[{
        "kty":"EC", "crv":"P-256", "alg":"ES256", "use":"jwt-svid",
        "kid":"qualification-key", "x":b64.encode(&point[1..33]),
        "y":b64.encode(&point[33..65]),
    }]}))
    .unwrap();
    let encoding =
        jsonwebtoken::EncodingKey::from_ec_pem(key.serialize_pem().unwrap().as_bytes()).unwrap();
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some("qualification-key".into());
    let sign = |subject: &str| {
        openshell_crypto::jwt::encode(
            &header,
            &serde_json::json!({
                "iss":"qualification-issuer", "sub":subject, "aud":[AUDIENCE],
                "exp":crate::persistence::current_time_ms() / 1000 + 3600,
            }),
            &encoding,
        )
        .unwrap()
    };
    Mock::given(method("POST"))
        .and(path("/SpiffeWorkloadAPI/FetchJWTSVID"))
        .respond_with(grpc_response(&JwtSvidsWire {
            svids: vec![JwtSvidWire {
                spiffe_id: GATEWAY_ID.into(),
                svid: sign(GATEWAY_ID),
            }],
        }))
        .expect(expected_identity_requests)
        .mount(&identity)
        .await;
    Mock::given(method("POST"))
        .and(path("/SpiffeWorkloadAPI/FetchJWTBundles"))
        .respond_with(grpc_response(&JwtBundlesWire {
            bundles: HashMap::from([("spiffe://qualification.test".into(), jwks)]),
        }))
        .expect(expected_identity_requests)
        .mount(&identity)
        .await;
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(75),
        tokio::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &format!("grpc::provider::subject_version_tests::{test}"),
                "--nocapture",
            ])
            .env(IDENTITY_CHILD, "1")
            .env(
                GATEWAY_SPIFFE_WORKLOAD_API_SOCKET,
                identity.uri().replacen("http:", "tcp:", 1),
            )
            .env(SUPERVISOR_SVID, sign(SUPERVISOR_ID))
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        output.status.success(),
        "identity child failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    identity.verify().await;
    assert_eq!(
        identity.received_requests().await.unwrap().len(),
        usize::try_from(expected_identity_requests * 2).unwrap()
    );
}

struct ActivatedSubject {
    _directory: tempfile::TempDir,
    state: Arc<ServerState>,
    provider: Provider,
    endpoint: wiremock::MockServer,
}

impl ActivatedSubject {
    async fn new(expiration_ms: Option<i64>) -> Self {
        use openshell_core::proto::{
            ObjectMeta, ProviderProfile, ProviderProfileCredential, SandboxSpec,
        };
        use openshell_credential_issuer::{Handles, SecretOwner, StoreSecrets};
        let (directory, state) = crate::config_delivery::versioned_tests::versioned_state().await;
        let endpoint = wiremock::MockServer::start().await;
        state.store.put_message(&crate::provider_profile_sources::stored_provider_profile(
            ProviderProfile {
                id: "activated-subject".into(),
                credentials: vec![
                    ProviderProfileCredential { name: "subject_token".into(), ..Default::default() },
                    ProviderProfileCredential {
                        name: "access_token".into(),
                        token_grant: Some(openshell_core::proto::ProviderCredentialTokenGrant {
                            grant_type: ProviderCredentialTokenGrantType::TokenExchange as i32,
                            token_endpoint: endpoint.uri(), jwt_svid_audience: AUDIENCE.into(),
                            cache_ttl: Some(prost_types::Duration {
                                seconds: INTERMEDIATE_TOKEN_CACHE_EXPIRY_SKEW_SECONDS + 2,
                                nanos: 0,
                            }),
                            subject_token: Some(openshell_core::proto::ProviderCredentialTokenGrantSubjectToken {
                                source: "provider_credential".into(), credential: "subject_token".into(),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
        )).await.unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let owner = SecretOwner::provider("default", &id, "subject-provider");
        let raw = state
            .credentials
            .issuer()
            .store(StoreSecrets {
                owner,
                object_id: Some("initial-subject"),
                values: &HashMap::from([("subject_token".into(), "subject-version-one".into())]),
                existing_handles: &Handles::new(),
            })
            .await
            .unwrap();
        let handles = state
            .credentials
            .versioned()
            .unwrap()
            .references
            .adopt_with_expiration(
                owner,
                "subject-epoch",
                &raw,
                expiration_ms
                    .map(|expiry| openshell_core::time::timestamp_from_millis(expiry).unwrap()),
                "adopt-subject",
            )
            .await
            .unwrap();
        state
            .store
            .put_message(&Provider {
                metadata: Some(ObjectMeta {
                    id: id.clone(),
                    name: "subject-provider".into(),
                    workspace: "default".into(),
                    ..Default::default()
                }),
                r#type: "activated-subject".into(),
                credential_handles: handles,
                ..Default::default()
            })
            .await
            .unwrap();
        let provider = state
            .store
            .get_message::<Provider>(&id)
            .await
            .unwrap()
            .unwrap();
        state
            .store
            .put_message(&Sandbox {
                metadata: Some(ObjectMeta {
                    id: "subject-sandbox".into(),
                    name: "subject-sandbox".into(),
                    workspace: "default".into(),
                    ..Default::default()
                }),
                spec: Some(SandboxSpec {
                    providers: vec!["subject-provider".into()],
                    ..Default::default()
                }),
                ..Default::default()
            })
            .await
            .unwrap();
        Self {
            _directory: directory,
            state,
            provider,
            endpoint,
        }
    }

    async fn exchange(&self) -> Result<ExchangeProviderSubjectTokenResponse, Status> {
        use crate::auth::principal::{SandboxIdentitySource, SandboxPrincipal};
        let mut request = Request::new(ExchangeProviderSubjectTokenRequest {
            sandbox_id: "subject-sandbox".into(),
            provider: "subject-provider".into(),
            credential_key: "access_token".into(),
            supervisor_jwt_svid: std::env::var(SUPERVISOR_SVID).unwrap(),
        });
        request
            .extensions_mut()
            .insert(Principal::Sandbox(SandboxPrincipal {
                sandbox_id: "subject-sandbox".into(),
                source: SandboxIdentitySource::BootstrapJwt {
                    issuer: "test".into(),
                    auth_epoch: None,
                },
                trust_domain: None,
            }));
        handle_exchange_provider_subject_token(&self.state, request)
            .await
            .map(Response::into_inner)
    }

    async fn upstream(&self, subject: &str, token: &str, expected: u64) {
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::body_string_contains(format!(
                "subject_token={subject}"
            )))
            .and(wiremock::matchers::body_string_contains(
                "audience=spiffe%3A%2F%2Fqualification.test%2Fsupervisor",
            ))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"access_token":token, "expires_in":3600, "token_type":"Bearer"}),
            ))
            .expect(expected)
            .mount(&self.endpoint)
            .await;
    }

    async fn unchanged(&self) {
        assert_eq!(
            self.state
                .store
                .get_message::<Provider>(self.provider.object_id())
                .await
                .unwrap()
                .unwrap(),
            self.provider
        );
    }
}

#[tokio::test]
async fn activated_subject_exchange_uses_new_version_with_unchanged_provider_and_cache_hits() {
    use openshell_credential_issuer::{SecretOwner, references::StoreReferenceSecrets};
    let test = "activated_subject_exchange_uses_new_version_with_unchanged_provider_and_cache_hits";
    if std::env::var_os(IDENTITY_CHILD).is_none() {
        return with_test_identity(test, 5).await;
    }
    let f = ActivatedSubject::new(None).await;
    f.upstream("subject-version-one", "intermediate-one", 1)
        .await;
    assert_eq!(f.exchange().await.unwrap().access_token, "intermediate-one");
    assert_eq!(f.exchange().await.unwrap().access_token, "intermediate-one");
    let before = f
        .state
        .credentials
        .resolve_provider_handles(&f.provider, crate::persistence::current_time_ms())
        .await
        .unwrap();
    let handles = f
        .state
        .credentials
        .versioned()
        .unwrap()
        .references
        .store(StoreReferenceSecrets {
            owner: SecretOwner::provider("default", f.provider.object_id(), "subject-provider"),
            epoch: "subject-epoch",
            write_id: "rotate-subject",
            protected_intent: b"test-protected-intent",
            values: &HashMap::from([("subject_token".into(), "subject-version-two".into())]),
            existing_handles: &f.provider.credential_handles,
            expiration_time: None,
        })
        .await
        .unwrap();
    assert_eq!(handles, f.provider.credential_handles);
    f.unchanged().await;
    let rotated = f
        .state
        .credentials
        .resolve_provider_handles(&f.provider, crate::persistence::current_time_ms())
        .await
        .unwrap();
    assert_eq!(
        rotated.versions["subject_token"].version,
        before.versions["subject_token"].version + 1
    );
    f.upstream("subject-version-two", "intermediate-two", 2)
        .await;
    assert_eq!(f.exchange().await.unwrap().access_token, "intermediate-two");
    assert_eq!(f.exchange().await.unwrap().access_token, "intermediate-two");
    // The same unexpired issuer version must also miss after the actual
    // intermediate-cache TTL, rather than reusing an otherwise long-lived token.
    tokio::time::sleep(std::time::Duration::from_millis(2_100)).await;
    assert_eq!(f.exchange().await.unwrap().access_token, "intermediate-two");
    f.unchanged().await;
    f.endpoint.verify().await;
    assert_eq!(f.endpoint.received_requests().await.unwrap().len(), 3);
}

#[tokio::test]
async fn activated_subject_exchange_cached_tokens_cannot_outlive_expiry_or_reference_revocation() {
    use openshell_credential_issuer::SecretOwner;
    let test =
        "activated_subject_exchange_cached_tokens_cannot_outlive_expiry_or_reference_revocation";
    if std::env::var_os(IDENTITY_CHILD).is_none() {
        return with_test_identity(test, 3).await;
    }
    // First populate a real intermediate cache entry, then expire the captured
    // issuer subject while the Provider and the intermediate remain unchanged.
    let expiry = crate::persistence::current_time_ms()
        + (INTERMEDIATE_TOKEN_CACHE_EXPIRY_SKEW_SECONDS + 5) * 1_000;
    let f = ActivatedSubject::new(Some(expiry)).await;
    f.upstream("subject-version-one", "intermediate-expiring", 1)
        .await;
    assert_eq!(
        f.exchange().await.unwrap().access_token,
        "intermediate-expiring"
    );
    assert_eq!(
        f.exchange().await.unwrap().access_token,
        "intermediate-expiring",
        "the valid subject must first support a real intermediate-cache hit"
    );
    tokio::time::sleep(std::time::Duration::from_millis(
        u64::try_from((expiry - crate::persistence::current_time_ms()).max(0)).unwrap() + 10,
    ))
    .await;
    let error = f.exchange().await.unwrap_err();
    assert!(matches!(
        error.code(),
        tonic::Code::FailedPrecondition | tonic::Code::PermissionDenied
    ));
    f.unchanged().await;
    f.endpoint.verify().await;
    assert_eq!(f.endpoint.received_requests().await.unwrap().len(), 1);

    let f = ActivatedSubject::new(None).await;
    f.upstream("subject-version-one", "intermediate-revoked", 1)
        .await;
    assert_eq!(
        f.exchange().await.unwrap().access_token,
        "intermediate-revoked"
    );
    // Reference-only revocation: no Provider write, raw backend deletion, cache
    // invalidation, or grant mutation can accidentally make this test pass.
    f.state
        .credentials
        .versioned()
        .unwrap()
        .references
        .revoke(
            SecretOwner::provider("default", f.provider.object_id(), "subject-provider"),
            &f.provider.credential_handles,
            None,
        )
        .await
        .unwrap();
    let error = f.exchange().await.unwrap_err();
    assert!(matches!(
        error.code(),
        tonic::Code::FailedPrecondition | tonic::Code::PermissionDenied | tonic::Code::NotFound
    ));
    f.unchanged().await;
    f.endpoint.verify().await;
    assert_eq!(f.endpoint.received_requests().await.unwrap().len(), 1);
}
