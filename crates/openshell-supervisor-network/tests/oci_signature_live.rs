// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Live interoperability tests for proxy-side OCI request signing.
//!
//! These sign raw HTTP requests with [`openshell_supervisor_network::oci_signature`]
//! exactly as the sandbox proxy does and send them to real OCI endpoints, so
//! they prove the signing string, header set, and `Authorization` format are
//! what OCI accepts. They are ignored by default and need an OCI identity:
//!
//! ```text
//! OCI_TEST_KEY_ID=<tenancy-ocid>/<user-ocid>/<fingerprint>   # or ST$<token>
//! OCI_TEST_PRIVATE_KEY_FILE=~/.oci/oci_api_key.pem            # unencrypted PEM file
//! OCI_TEST_REGION=us-chicago-1
//! OCI_TEST_COMPARTMENT_ID=ocid1.compartment.oc1..…            # for Generative AI
//! cargo test -p openshell-supervisor-network --test oci_signature_live -- --ignored
//! ```

use openshell_supervisor_network::oci_signature::{OciSigningKey, sign_headers_only, sign_request};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set for live OCI tests"))
}

fn signing_key() -> OciSigningKey {
    let path = shellexpand_home(&env("OCI_TEST_PRIVATE_KEY_FILE"));
    let pem = std::fs::read_to_string(&path).expect("read OCI private key file");
    OciSigningKey::from_credentials(&env("OCI_TEST_KEY_ID"), &pem).expect("parse OCI signing key")
}

fn shellexpand_home(path: &str) -> String {
    path.strip_prefix("~/").map_or_else(
        || path.to_string(),
        |rest| format!("{}/{rest}", std::env::var("HOME").unwrap_or_default()),
    )
}

async fn send_tls(host: &str, raw: &[u8]) -> (u16, String) {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        roots.add(cert).expect("add native root");
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect((host, 443))
        .await
        .expect("connect to OCI endpoint");
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string()).expect("SNI");
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS handshake");
    tls.write_all(raw).await.expect("write request");
    tls.flush().await.expect("flush");
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.ok();
    let text = String::from_utf8_lossy(&response).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    (status, text)
}

#[tokio::test]
#[ignore = "requires OCI_TEST_* credentials and network access to OCI"]
async fn oci_signed_get_object_storage_namespace() {
    let key = signing_key();
    let host = format!("objectstorage.{}.oraclecloud.com", env("OCI_TEST_REGION"));
    let raw = format!(
        "GET /n/ HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAccept: application/json\r\n\r\n"
    );
    let signed = sign_headers_only(raw.as_bytes(), &host, &key).expect("sign GET");
    let (status, body) = send_tls(&host, &signed).await;
    assert_eq!(
        status, 200,
        "GET /n/ must succeed with a proxy-style signature: {body}"
    );
    let payload = body.split("\r\n\r\n").nth(1).unwrap_or("");
    assert!(
        payload.trim().starts_with('"'),
        "namespace response should be a JSON string: {payload}"
    );
}

#[tokio::test]
#[ignore = "requires OCI_TEST_* credentials and network access to OCI"]
async fn oci_signed_post_generative_ai_native_chat() {
    let key = signing_key();
    let host = format!(
        "inference.generativeai.{}.oci.oraclecloud.com",
        env("OCI_TEST_REGION")
    );
    let body = format!(
        r#"{{"compartmentId":"{}","servingMode":{{"servingType":"ON_DEMAND","modelId":"meta.llama-3.3-70b-instruct"}},"chatRequest":{{"apiFormat":"GENERIC","messages":[{{"role":"USER","content":[{{"type":"TEXT","text":"Reply with exactly: OK from OCI"}}]}}],"maxTokens":20}}}}"#,
        env("OCI_TEST_COMPARTMENT_ID")
    );
    let mut raw = format!(
        "POST /20231130/actions/chat HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccept: application/json\r\n\r\n",
        body.len()
    )
    .into_bytes();
    raw.extend_from_slice(body.as_bytes());
    let signed = sign_request(&raw, &host, &key).expect("sign POST");
    let (status, response) = send_tls(&host, &signed).await;
    assert_eq!(
        status, 200,
        "native Generative AI chat must accept the proxy signature: {response}"
    );
    assert!(
        response.contains("chatResponse"),
        "response should carry a chatResponse: {response}"
    );
}

/// A 64x64 solid red PNG, base64-encoded, for the vision request.
const RED_PNG_BASE64: &str = "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAIAAAAlC+aJAAAAS0lEQVR42u3PQQkAAAgAsetfWiP4FgYrsKZeS0BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEDgsqnc8OJg6Ln3AAAAAElFTkSuQmCC";

#[tokio::test]
#[ignore = "requires OCI_TEST_* credentials and network access to OCI"]
async fn oci_signed_post_generative_ai_native_vision() {
    let key = signing_key();
    let host = format!(
        "inference.generativeai.{}.oci.oraclecloud.com",
        env("OCI_TEST_REGION")
    );
    // Multimodal GENERIC chat: the image travels in the body, so this also
    // exercises body hashing on a larger payload than the text tests.
    let body = format!(
        r#"{{"compartmentId":"{}","servingMode":{{"servingType":"ON_DEMAND","modelId":"meta.llama-4-maverick-17b-128e-instruct-fp8"}},"chatRequest":{{"apiFormat":"GENERIC","messages":[{{"role":"USER","content":[{{"type":"TEXT","text":"What color is this image? Answer with one word."}},{{"type":"IMAGE","imageUrl":{{"url":"data:image/png;base64,{}"}}}}]}}],"maxTokens":10}}}}"#,
        env("OCI_TEST_COMPARTMENT_ID"),
        RED_PNG_BASE64
    );
    let mut raw = format!(
        "POST /20231130/actions/chat HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccept: application/json\r\n\r\n",
        body.len()
    )
    .into_bytes();
    raw.extend_from_slice(body.as_bytes());
    let signed = sign_request(&raw, &host, &key).expect("sign vision POST");
    let (status, response) = send_tls(&host, &signed).await;
    assert_eq!(
        status, 200,
        "native Generative AI vision chat must accept the proxy signature: {response}"
    );
    assert!(
        response.to_ascii_lowercase().contains("red"),
        "model should identify the red image: {response}"
    );
}
