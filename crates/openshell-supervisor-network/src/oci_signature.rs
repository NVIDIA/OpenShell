// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Proxy-side Oracle Cloud Infrastructure request signing.
//!
//! Like `SigV4`, OCI's RSA-SHA256 HTTP `Signature` scheme is incompatible
//! with placeholder substitution: a placeholder private key produces a
//! signature nothing can fix by header replacement. When an endpoint sets
//! `credential_signing: oci`, the proxy strips whatever signature the client
//! attempted, resolves `OCI_KEY_ID` and `OCI_PRIVATE_KEY` from the
//! endpoint-bound provider, and signs the request itself before forwarding
//! it. The sandbox never holds the key.
//!
//! The signing primitives live in [`openshell_core::oci_signature`], shared
//! with the gateway's principal federation. This module adds the raw HTTP
//! framing the proxy works with: header stripping, request parsing, and
//! rebuilding the header block around the signed values.

use miette::{Result, miette};
use std::time::SystemTime;

pub use openshell_core::oci_signature::{
    KEY_ID_ENV, OciSigningKey, PRIVATE_KEY_ENV, imf_fixdate, method_signs_body,
};
use openshell_core::oci_signature::{SigningInput, sign_headers};

/// Headers the proxy owns on the signing path. The client's attempt at any
/// of them is discarded: `authorization` because it embeds a placeholder
/// signature, `date`/`x-date` because the proxy signs its own timestamp,
/// `x-content-sha256` because the proxy hashes the body it forwards, and
/// `expect` because the proxy answers `100-continue` itself.
const STRIP_HEADERS: [&str; 5] = [
    "authorization",
    "date",
    "x-date",
    "x-content-sha256",
    "expect",
];

/// Strip the client's signing headers from raw HTTP request bytes so the
/// request can pass the proxy's fail-closed placeholder scan before the proxy
/// signs it. Mirrors [`crate::sigv4::strip_aws_headers`].
///
/// Returns `Err` if the header block is not valid UTF-8. Failing closed
/// prevents non-UTF-8 requests from passing through with their original
/// authorization header intact.
pub fn strip_oci_headers(raw: &[u8]) -> Result<Vec<u8>> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(raw.len(), |p| p + 4);
    let header_str = std::str::from_utf8(&raw[..header_end])
        .map_err(|e| miette!("strip_oci_headers: header block is not valid UTF-8: {e}"))?;

    let mut output = Vec::with_capacity(raw.len());
    for (i, line) in header_str.split("\r\n").enumerate() {
        if i == 0 {
            output.extend_from_slice(line.as_bytes());
            output.extend_from_slice(b"\r\n");
            continue;
        }
        if line.is_empty() {
            break;
        }
        if is_stripped_header(line) {
            continue;
        }
        output.extend_from_slice(line.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(b"\r\n");
    if header_end < raw.len() {
        output.extend_from_slice(&raw[header_end..]);
    }
    Ok(output)
}

fn is_stripped_header(line: &str) -> bool {
    let name = line.split_once(':').map_or(line, |(k, _)| k).trim();
    STRIP_HEADERS
        .iter()
        .any(|stripped| name.eq_ignore_ascii_case(stripped))
}

struct RequestParts<'a> {
    method: &'a str,
    path: &'a str,
    request_line: &'a str,
    /// Lowercased header names paired with trimmed values, minus the headers
    /// the proxy owns on the signing path.
    headers: Vec<(String, String)>,
}

fn parse_request_parts(header_str: &str) -> RequestParts<'_> {
    let lines: Vec<&str> = header_str.split("\r\n").collect();
    let (method, path, request_line) =
        lines
            .first()
            .map_or(("GET", "/", "GET / HTTP/1.1"), |first_line| {
                let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
                if parts.len() >= 2 {
                    (parts[0], parts[1], *first_line)
                } else {
                    ("GET", "/", *first_line)
                }
            });

    let mut headers = Vec::new();
    for line in lines.iter().skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let lower = k.trim().to_ascii_lowercase();
            if STRIP_HEADERS.contains(&lower.as_str()) {
                continue;
            }
            headers.push((lower, v.trim().to_string()));
        }
    }

    RequestParts {
        method,
        path,
        request_line,
        headers,
    }
}

/// Output of signing: the rebuilt header block and the exact string that was
/// signed, kept so tests and diagnostics can verify the signature.
pub struct SignedHeaders {
    /// Rebuilt request line and headers, terminated by `\r\n\r\n`.
    pub header_block: Vec<u8>,
    /// The newline-joined `name: value` lines the signature covers.
    pub signing_string: String,
}

/// Sign a request whose body, if the method carries one, is fully available.
///
/// `body` is `Some` for POST, PUT, and PATCH and is hashed into the
/// signature. For every other method pass `None`; the body streams through
/// unsigned, which is what the OCI SDKs do too.
pub fn build_signed_headers_at(
    raw_headers: &[u8],
    body: Option<&[u8]>,
    host: &str,
    key: &OciSigningKey,
    now: SystemTime,
) -> Result<SignedHeaders> {
    let header_end = raw_headers
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(raw_headers.len(), |p| p + 4);
    let header_str = std::str::from_utf8(&raw_headers[..header_end])
        .map_err(|e| miette!("OCI signing: request headers are not valid UTF-8: {e}"))?;
    let parts = parse_request_parts(header_str);
    let signs_body = method_signs_body(parts.method);

    let host_value = parts
        .headers
        .iter()
        .find(|(k, _)| k == "host")
        .map_or_else(|| host.to_string(), |(_, v)| v.clone());
    let content_type = parts
        .headers
        .iter()
        .find(|(k, _)| k == "content-type")
        .map(|(_, v)| v.as_str());

    let signed = sign_headers(
        SigningInput {
            method: parts.method,
            request_target_path: parts.path,
            host: Some(&host_value),
            body: body.filter(|_| signs_body),
            content_type,
            now,
        },
        key,
    )?;

    let mut header_block = Vec::with_capacity(header_end + 512);
    header_block.extend_from_slice(parts.request_line.as_bytes());
    header_block.extend_from_slice(b"\r\n");
    // Forward the client's headers, minus the ones re-emitted with signed values.
    for (k, v) in &parts.headers {
        if signs_body && (k == "content-length" || k == "content-type") {
            continue;
        }
        header_block.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    if let Some(len) = signed.content_length {
        header_block.extend_from_slice(format!("content-length: {len}\r\n").as_bytes());
    }
    if let Some(ct) = &signed.content_type {
        header_block.extend_from_slice(format!("content-type: {ct}\r\n").as_bytes());
    }
    if let Some(hash) = &signed.x_content_sha256 {
        header_block.extend_from_slice(format!("x-content-sha256: {hash}\r\n").as_bytes());
    }
    header_block.extend_from_slice(format!("date: {}\r\n", signed.date).as_bytes());
    header_block
        .extend_from_slice(format!("authorization: {}\r\n", signed.authorization).as_bytes());
    header_block.extend_from_slice(b"\r\n");

    Ok(SignedHeaders {
        header_block,
        signing_string: signed.signing_string,
    })
}

/// Sign a complete buffered request (headers and body) and return the bytes
/// to forward upstream. Use for POST, PUT, and PATCH.
pub fn sign_request(raw: &[u8], host: &str, key: &OciSigningKey) -> Result<Vec<u8>> {
    sign_request_at(raw, host, key, SystemTime::now())
}

/// [`sign_request`] with an explicit timestamp.
pub fn sign_request_at(
    raw: &[u8],
    host: &str,
    key: &OciSigningKey,
    now: SystemTime,
) -> Result<Vec<u8>> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(raw.len(), |p| p + 4);
    let body: &[u8] = if header_end < raw.len() {
        &raw[header_end..]
    } else {
        &[]
    };
    let signed = build_signed_headers_at(&raw[..header_end], Some(body), host, key, now)?;
    let mut output = signed.header_block;
    output.extend_from_slice(body);
    Ok(output)
}

/// Sign the headers of a request whose body, if any, streams through
/// unsigned. Use for GET, HEAD, DELETE, and OPTIONS. Returns a header block
/// terminated by `\r\n\r\n`.
pub fn sign_headers_only(raw_headers: &[u8], host: &str, key: &OciSigningKey) -> Result<Vec<u8>> {
    sign_headers_only_at(raw_headers, host, key, SystemTime::now())
}

/// [`sign_headers_only`] with an explicit timestamp.
pub fn sign_headers_only_at(
    raw_headers: &[u8],
    host: &str,
    key: &OciSigningKey,
    now: SystemTime,
) -> Result<Vec<u8>> {
    Ok(build_signed_headers_at(raw_headers, None, host, key, now)?.header_block)
}

#[cfg(test)]
pub mod test_support {
    /// A fresh 2048-bit RSA key as unencrypted PKCS#8 PEM. Generated per test
    /// run so no key material is checked into the repository.
    pub fn fresh_private_key_pem() -> String {
        openshell_core::oci_signature::SessionKeyPair::generate()
            .expect("generate RSA key")
            .private_key_pem
    }

    pub const TEST_KEY_ID: &str =
        "ocid1.tenancy.oc1..aaaaaaaatest/ocid1.user.oc1..aaaaaaaatest/aa:bb:cc:dd:ee:ff";
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
    use base64::Engine;
    use base64::prelude::BASE64_STANDARD;
    use sha2::{Digest, Sha256};
    use std::time::{Duration, UNIX_EPOCH};

    const HOST: &str = "inference.generativeai.us-chicago-1.oci.oraclecloud.com";

    fn test_key() -> OciSigningKey {
        OciSigningKey::from_credentials(
            test_support::TEST_KEY_ID,
            &test_support::fresh_private_key_pem(),
        )
        .expect("test key parses")
    }

    fn fixed_now() -> SystemTime {
        // 2026-09-30T12:00:00Z = 497_436 hours after the epoch
        UNIX_EPOCH + Duration::from_hours(497_436)
    }

    fn header_value<'a>(block: &'a str, name: &str) -> Option<&'a str> {
        block.split("\r\n").skip(1).find_map(|line| {
            let (k, v) = line.split_once(':')?;
            k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
        })
    }

    fn signature_param<'a>(authorization: &'a str, param: &str) -> Option<&'a str> {
        let needle = format!("{param}=\"");
        let start = authorization.find(&needle)? + needle.len();
        let end = authorization[start..].find('"')? + start;
        Some(&authorization[start..end])
    }

    fn verify(key: &OciSigningKey, signing_string: &str, signature_b64: &str) -> bool {
        let signature = BASE64_STANDARD
            .decode(signature_b64)
            .expect("base64 signature");
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key.public_key_der())
            .verify(signing_string.as_bytes(), &signature)
            .is_ok()
    }

    #[test]
    fn strip_removes_client_signing_headers_and_keeps_the_rest() {
        let raw = b"GET /n/ns/b/bucket/o HTTP/1.1\r\nHost: objectstorage.us-chicago-1.oraclecloud.com\r\nAuthorization: Signature version=\"1\",keyId=\"x\"\r\nDate: Mon, 01 Jan 2024 00:00:00 GMT\r\nX-Date: whatever\r\nx-content-sha256: abc\r\nExpect: 100-continue\r\nAccept: */*\r\n\r\nbody";
        let stripped = strip_oci_headers(raw).unwrap();
        let text = String::from_utf8(stripped).unwrap();
        assert!(text.starts_with("GET /n/ns/b/bucket/o HTTP/1.1\r\n"));
        assert!(text.contains("Host: objectstorage.us-chicago-1.oraclecloud.com\r\n"));
        assert!(text.contains("Accept: */*\r\n"));
        for gone in [
            "Authorization:",
            "Date:",
            "X-Date:",
            "x-content-sha256:",
            "Expect:",
        ] {
            assert!(!text.contains(gone), "{gone} should be stripped: {text}");
        }
        assert!(text.ends_with("\r\n\r\nbody"));
    }

    #[test]
    fn strip_rejects_non_utf8_header_block() {
        assert!(strip_oci_headers(b"GET / HTTP/1.1\r\nX: \xff\xfe\r\n\r\n").is_err());
    }

    #[test]
    fn post_rebuilds_headers_with_signed_body_values() {
        let key = test_key();
        let body = br#"{"compartmentId":"ocid1.compartment.oc1..example"}"#;
        let raw = format!(
            "POST /20231130/actions/chat HTTP/1.1\r\nHost: {HOST}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAuthorization: Signature keyId=\"placeholder\"\r\nAccept: application/json\r\n\r\n",
            body.len()
        );
        let mut raw = raw.into_bytes();
        raw.extend_from_slice(body);

        let signed = sign_request_at(&raw, HOST, &key, fixed_now()).unwrap();
        let header_end = signed.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let block = std::str::from_utf8(&signed[..header_end]).unwrap();
        assert_eq!(&signed[header_end..], body, "body forwarded unchanged");

        let authorization = header_value(block, "authorization").expect("authorization header");
        assert_eq!(
            signature_param(authorization, "headers").unwrap(),
            "date (request-target) host content-length content-type x-content-sha256"
        );
        let expected_hash = BASE64_STANDARD.encode(Sha256::digest(body));
        assert_eq!(
            header_value(block, "x-content-sha256"),
            Some(expected_hash.as_str())
        );
        assert_eq!(
            header_value(block, "date"),
            Some("Wed, 30 Sep 2026 12:00:00 GMT")
        );
        assert_eq!(
            header_value(block, "content-length"),
            Some(body.len().to_string().as_str())
        );
        assert_eq!(header_value(block, "accept"), Some("application/json"));
        assert_eq!(
            block.matches("authorization:").count(),
            1,
            "client authorization must be replaced, not duplicated"
        );
        assert_eq!(block.matches("content-length:").count(), 1);

        let expected_signing_string = format!(
            "date: Wed, 30 Sep 2026 12:00:00 GMT\n(request-target): post /20231130/actions/chat\nhost: {HOST}\ncontent-length: {}\ncontent-type: application/json\nx-content-sha256: {expected_hash}",
            body.len()
        );
        assert!(verify(
            &key,
            &expected_signing_string,
            signature_param(authorization, "signature").unwrap()
        ));
    }

    #[test]
    fn get_signs_generic_headers_only_and_keeps_query_in_request_target() {
        let key = test_key();
        let host = "objectstorage.us-chicago-1.oraclecloud.com";
        let raw = format!(
            "GET /n/ns/b/bucket/o?prefix=a%20b&limit=10 HTTP/1.1\r\nHost: {host}\r\nAccept: */*\r\n\r\n"
        );
        let signed = sign_headers_only_at(raw.as_bytes(), host, &key, fixed_now()).unwrap();
        let block = std::str::from_utf8(&signed).unwrap();
        assert!(block.ends_with("\r\n\r\n"));
        let authorization = header_value(block, "authorization").unwrap();
        assert_eq!(
            signature_param(authorization, "headers").unwrap(),
            "date (request-target) host"
        );
        assert!(header_value(block, "x-content-sha256").is_none());
        let signing_string = format!(
            "date: Wed, 30 Sep 2026 12:00:00 GMT\n(request-target): get /n/ns/b/bucket/o?prefix=a%20b&limit=10\nhost: {host}"
        );
        assert!(verify(
            &key,
            &signing_string,
            signature_param(authorization, "signature").unwrap()
        ));
    }

    #[test]
    fn post_without_content_type_defaults_to_json_like_the_sdk() {
        let key = test_key();
        let raw = format!("POST /20231130/actions/chat HTTP/1.1\r\nHost: {HOST}\r\n\r\n{{}}");
        let signed = sign_request_at(raw.as_bytes(), HOST, &key, fixed_now()).unwrap();
        let block = std::str::from_utf8(&signed[..signed.len() - 2]).unwrap();
        assert_eq!(
            header_value(block, "content-type"),
            Some("application/json")
        );
        assert_eq!(header_value(block, "content-length"), Some("2"));
    }

    #[test]
    fn body_method_without_buffered_body_is_rejected() {
        let key = test_key();
        let raw = format!("PUT /n/ns/b/bucket/o/x HTTP/1.1\r\nHost: {HOST}\r\n\r\n");
        let err = sign_headers_only_at(raw.as_bytes(), HOST, &key, fixed_now()).unwrap_err();
        assert!(err.to_string().contains("must be buffered"), "{err}");
    }

    #[test]
    fn host_header_value_is_signed_as_sent() {
        let key = test_key();
        let raw = "GET /20160918/users/me HTTP/1.1\r\nHost: identity.us-chicago-1.oraclecloud.com:443\r\n\r\n";
        let signed = build_signed_headers_at(
            raw.as_bytes(),
            None,
            "identity.us-chicago-1.oraclecloud.com",
            &key,
            fixed_now(),
        )
        .unwrap();
        assert!(
            signed
                .signing_string
                .contains("host: identity.us-chicago-1.oraclecloud.com:443")
        );
    }
}
