// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Proxy-side Oracle Cloud Infrastructure request signing.
//!
//! OCI authenticates API requests with an RSA-SHA256 HTTP `Signature` header
//! (the draft-cavage HTTP signatures profile) over a fixed header set:
//! `date (request-target) host`, plus `content-length content-type
//! x-content-sha256` for POST, PUT, and PATCH. Like `SigV4`, the scheme is
//! incompatible with placeholder substitution: a placeholder private key
//! produces a signature nothing can fix by header replacement. When an
//! endpoint sets `credential_signing: oci`, the proxy strips whatever
//! signature the client attempted, resolves `OCI_KEY_ID` and
//! `OCI_PRIVATE_KEY` from the endpoint-bound provider, and signs the request
//! itself before forwarding it. The sandbox never holds the key.
//!
//! `OCI_KEY_ID` is either `<tenancy>/<user>/<fingerprint>` for an API key or
//! `ST$<security-token>` for a session, instance, resource, or workload
//! principal, so one signing path serves every OCI principal type.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{KeyPair as _, RSA_PKCS1_SHA256, RsaKeyPair};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use miette::{Result, miette};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Provider credential key holding the OCI signing key id.
pub const KEY_ID_ENV: &str = "OCI_KEY_ID";
/// Provider credential key holding the PEM-encoded RSA private key.
pub const PRIVATE_KEY_ENV: &str = "OCI_PRIVATE_KEY";

const SIGNATURE_VERSION: &str = "1";
const GENERIC_HEADERS: [&str; 3] = ["date", "(request-target)", "host"];
const BODY_HEADERS: [&str; 3] = ["content-length", "content-type", "x-content-sha256"];
/// The OCI SDKs default a missing `content-type` to JSON before signing.
const DEFAULT_BODY_CONTENT_TYPE: &str = "application/json";

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

/// A parsed OCI signing identity: the key id OCI expects in `keyId` and the
/// RSA private key that pairs with it.
pub struct OciSigningKey {
    key_id: String,
    key_pair: RsaKeyPair,
}

impl std::fmt::Debug for OciSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the key id: for principals it is the security token.
        f.debug_struct("OciSigningKey").finish_non_exhaustive()
    }
}

impl OciSigningKey {
    /// Build a signing key from the provider credentials.
    ///
    /// Provider credential values must be single-line, so `OCI_PRIVATE_KEY`
    /// is accepted in any of these forms:
    ///
    /// - standard base64 of the PEM file (`base64 -w0 < oci_api_key.pem`),
    ///   the recommended form;
    /// - standard base64 of the raw PKCS#8 or PKCS#1 DER;
    /// - the PEM text with newlines written as the two characters `\n`;
    /// - the PEM text itself, for callers that are not bound by the
    ///   single-line rule.
    ///
    /// Unencrypted PKCS#1 (`BEGIN RSA PRIVATE KEY`) and PKCS#8 (`BEGIN PRIVATE
    /// KEY`) RSA keys are supported. Passphrase-protected keys are rejected
    /// with a message that says so, since the proxy has nowhere safe to source
    /// the passphrase from.
    pub fn from_credentials(key_id: &str, private_key: &str) -> Result<Self> {
        let key_id = key_id.trim();
        if key_id.is_empty() {
            return Err(miette!("OCI signing: {KEY_ID_ENV} is empty"));
        }
        let key_pair = match normalize_private_key_material(private_key)? {
            PrivateKeyMaterial::Pem(pem) => {
                if pem.contains("ENCRYPTED") {
                    return Err(miette!(
                        "OCI signing: {PRIVATE_KEY_ENV} is passphrase-protected; store the \
                         decrypted PKCS#1 or PKCS#8 key instead"
                    ));
                }
                let (item, _rest) = rustls_pemfile::read_one_from_slice(pem.as_bytes())
                    .map_err(|e| miette!("OCI signing: {PRIVATE_KEY_ENV} is not valid PEM: {e:?}"))?
                    .ok_or_else(|| {
                        miette!("OCI signing: {PRIVATE_KEY_ENV} contains no PEM block")
                    })?;
                match item {
                    rustls_pemfile::Item::Pkcs1Key(key) => {
                        RsaKeyPair::from_der(key.secret_pkcs1_der())
                    }
                    rustls_pemfile::Item::Pkcs8Key(key) => {
                        RsaKeyPair::from_pkcs8(key.secret_pkcs8_der())
                    }
                    _ => {
                        return Err(miette!(
                            "OCI signing: {PRIVATE_KEY_ENV} must be an RSA private key in \
                             PKCS#1 or PKCS#8 form"
                        ));
                    }
                }
            }
            PrivateKeyMaterial::Der(der) => {
                RsaKeyPair::from_pkcs8(&der).or_else(|_| RsaKeyPair::from_der(&der))
            }
        }
        .map_err(|e| miette!("OCI signing: {PRIVATE_KEY_ENV} is not a usable RSA key: {e}"))?;
        Ok(Self {
            key_id: key_id.to_string(),
            key_pair,
        })
    }

    /// The `keyId` value OCI will see.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// PKCS#1 `RSAPublicKey` DER of the signing key, for verification.
    pub fn public_key_der(&self) -> Vec<u8> {
        self.key_pair.public_key().as_ref().to_vec()
    }

    fn sign_base64(&self, signing_string: &[u8]) -> Result<String> {
        let mut signature = vec![0u8; self.key_pair.public_modulus_len()];
        self.key_pair
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                signing_string,
                &mut signature,
            )
            .map_err(|e| miette!("OCI signing: RSA-SHA256 signature failed: {e}"))?;
        Ok(BASE64_STANDARD.encode(signature))
    }
}

enum PrivateKeyMaterial {
    Pem(String),
    Der(Vec<u8>),
}

/// Turn the single-line credential value back into PEM or DER bytes.
fn normalize_private_key_material(value: &str) -> Result<PrivateKeyMaterial> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(miette!("OCI signing: {PRIVATE_KEY_ENV} is empty"));
    }
    if trimmed.contains("-----BEGIN") {
        // PEM, possibly with `\n` escape sequences instead of real newlines.
        return Ok(PrivateKeyMaterial::Pem(trimmed.replace("\\n", "\n")));
    }
    let decoded = BASE64_STANDARD.decode(trimmed).map_err(|_| {
        miette!(
            "OCI signing: {PRIVATE_KEY_ENV} must be a PEM private key or its standard base64 \
             encoding on a single line"
        )
    })?;
    if decoded.starts_with(b"-----BEGIN") {
        let pem = String::from_utf8(decoded).map_err(|_| {
            miette!("OCI signing: base64-decoded {PRIVATE_KEY_ENV} is not UTF-8 PEM text")
        })?;
        return Ok(PrivateKeyMaterial::Pem(pem));
    }
    Ok(PrivateKeyMaterial::Der(decoded))
}

/// True for methods whose body OCI includes in the signature.
///
/// The OCI SDKs sign `content-length`, `content-type`, and
/// `x-content-sha256` for POST, PUT, and PATCH only; every other method is
/// signed over the generic headers and its body, if any, streams through.
pub fn method_signs_body(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "POST" | "PUT" | "PATCH"
    )
}

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
    if signs_body && body.is_none() {
        return Err(miette!(
            "OCI signing: {} requests must be buffered so the body can be hashed",
            parts.method
        ));
    }

    let date = imf_fixdate(now);
    let request_target = format!("{} {}", parts.method.to_ascii_lowercase(), parts.path);
    let host_value = parts
        .headers
        .iter()
        .find(|(k, _)| k == "host")
        .map_or_else(|| host.to_string(), |(_, v)| v.clone());

    // Headers forwarded upstream, minus the ones re-emitted with signed values.
    let mut forwarded: Vec<(String, String)> = parts
        .headers
        .iter()
        .filter(|(k, _)| !(signs_body && (k == "content-length" || k == "content-type")))
        .cloned()
        .collect();

    let mut signed: Vec<(String, String)> = vec![
        ("date".to_string(), date.clone()),
        ("(request-target)".to_string(), request_target),
        ("host".to_string(), host_value),
    ];

    if let Some(body) = body.filter(|_| signs_body) {
        let content_type = parts
            .headers
            .iter()
            .find(|(k, _)| k == "content-type")
            .map_or_else(|| DEFAULT_BODY_CONTENT_TYPE.to_string(), |(_, v)| v.clone());
        let body_hash = BASE64_STANDARD.encode(Sha256::digest(body));
        signed.push(("content-length".to_string(), body.len().to_string()));
        signed.push(("content-type".to_string(), content_type.clone()));
        signed.push(("x-content-sha256".to_string(), body_hash.clone()));
        forwarded.push(("content-length".to_string(), body.len().to_string()));
        forwarded.push(("content-type".to_string(), content_type));
        forwarded.push(("x-content-sha256".to_string(), body_hash));
    }

    let signing_string = signed
        .iter()
        .map(|(k, v)| format!("{k}: {v}"))
        .collect::<Vec<_>>()
        .join("\n");
    let signature = key.sign_base64(signing_string.as_bytes())?;
    // The `headers` parameter lists the signed names in the SDK's fixed order.
    let header_names = if signs_body {
        [GENERIC_HEADERS.as_slice(), BODY_HEADERS.as_slice()]
            .concat()
            .join(" ")
    } else {
        GENERIC_HEADERS.join(" ")
    };
    debug_assert_eq!(
        header_names,
        signed
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    );
    let authorization = format!(
        "Signature algorithm=\"rsa-sha256\",headers=\"{header_names}\",keyId=\"{key_id}\",\
         signature=\"{signature}\",version=\"{SIGNATURE_VERSION}\"",
        key_id = key.key_id(),
    );

    let mut header_block = Vec::with_capacity(header_end + 512);
    header_block.extend_from_slice(parts.request_line.as_bytes());
    header_block.extend_from_slice(b"\r\n");
    for (k, v) in &forwarded {
        header_block.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    header_block.extend_from_slice(format!("date: {date}\r\n").as_bytes());
    header_block.extend_from_slice(format!("authorization: {authorization}\r\n").as_bytes());
    header_block.extend_from_slice(b"\r\n");

    Ok(SignedHeaders {
        header_block,
        signing_string,
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

/// Format a timestamp as an RFC 7231 IMF-fixdate, for example
/// `Tue, 30 Sep 2026 12:00:00 GMT`, which is what OCI expects in `date`.
pub fn imf_fixdate(now: SystemTime) -> String {
    const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let secs = now
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // 1970-01-01 was a Thursday.
    let weekday = usize::try_from((days + 4).rem_euclid(7)).unwrap_or(0);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        WEEKDAYS[weekday],
        day,
        MONTHS[usize::try_from(month - 1).unwrap_or(0)],
        year,
        hour,
        minute,
        second
    )
}

/// Days since 1970-01-01 to a proleptic Gregorian (year, month, day).
/// Howard Hinnant's `civil_from_days`.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
pub(crate) mod test_support {
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rsa::KeySize;
    use aws_lc_rs::signature::RsaKeyPair;
    use base64::Engine;
    use base64::prelude::BASE64_STANDARD;

    /// A fresh 2048-bit RSA key as unencrypted PKCS#8 PEM. Generated per test
    /// run so no key material is checked into the repository.
    pub fn fresh_private_key_pem() -> String {
        let key_pair = RsaKeyPair::generate(KeySize::Rsa2048).expect("generate RSA key");
        let der = key_pair.as_der().expect("export PKCS#8");
        let b64 = BASE64_STANDARD.encode(der.as_ref());
        let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END PRIVATE KEY-----\n");
        pem
    }

    pub const TEST_KEY_ID: &str =
        "ocid1.tenancy.oc1..aaaaaaaatest/ocid1.user.oc1..aaaaaaaatest/aa:bb:cc:dd:ee:ff";
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
    use std::time::Duration;

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
    fn imf_fixdate_matches_rfc7231() {
        assert_eq!(imf_fixdate(fixed_now()), "Wed, 30 Sep 2026 12:00:00 GMT");
        assert_eq!(imf_fixdate(UNIX_EPOCH), "Thu, 01 Jan 1970 00:00:00 GMT");
        // 2000-02-29 leap day, 23:59:59
        assert_eq!(
            imf_fixdate(UNIX_EPOCH + Duration::from_secs(951_868_799)),
            "Tue, 29 Feb 2000 23:59:59 GMT"
        );
    }

    #[test]
    fn body_methods_are_post_put_patch() {
        for m in ["POST", "post", "PUT", "PATCH"] {
            assert!(method_signs_body(m), "{m}");
        }
        for m in ["GET", "HEAD", "DELETE", "OPTIONS"] {
            assert!(!method_signs_body(m), "{m}");
        }
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
    fn post_signs_generic_and_body_headers_in_sdk_order() {
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
        assert!(authorization.starts_with("Signature algorithm=\"rsa-sha256\",headers=\""));
        assert_eq!(
            signature_param(authorization, "headers").unwrap(),
            "date (request-target) host content-length content-type x-content-sha256"
        );
        assert_eq!(
            signature_param(authorization, "keyId").unwrap(),
            test_support::TEST_KEY_ID
        );
        assert_eq!(signature_param(authorization, "version").unwrap(), "1");

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

        let expected_signing_string = format!(
            "date: Wed, 30 Sep 2026 12:00:00 GMT\n(request-target): post /20231130/actions/chat\nhost: {HOST}\ncontent-length: {}\ncontent-type: application/json\nx-content-sha256: {expected_hash}",
            body.len()
        );
        assert!(
            verify(
                &key,
                &expected_signing_string,
                signature_param(authorization, "signature").unwrap()
            ),
            "signature must verify over the SDK-shaped signing string"
        );
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

    #[test]
    fn encrypted_and_non_rsa_pems_are_rejected() {
        let encrypted =
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB\n-----END ENCRYPTED PRIVATE KEY-----\n";
        let err = OciSigningKey::from_credentials("k", encrypted).unwrap_err();
        assert!(err.to_string().contains("passphrase-protected"), "{err}");

        let empty = OciSigningKey::from_credentials("", &test_support::fresh_private_key_pem())
            .unwrap_err();
        assert!(empty.to_string().contains("is empty"), "{empty}");

        let garbage =
            OciSigningKey::from_credentials("k", "-----BEGIN PRIVATE KEY-----\nnot base64\n")
                .unwrap_err();
        assert!(
            garbage.to_string().contains("not valid PEM")
                || garbage.to_string().contains("no PEM block"),
            "{garbage}"
        );
    }

    #[test]
    fn private_key_is_accepted_in_every_single_line_form() {
        let pem = test_support::fresh_private_key_pem();
        let body = b"{}";
        let raw = format!("POST /x HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: 2\r\n\r\n{{}}");
        let expected = {
            let key = OciSigningKey::from_credentials(test_support::TEST_KEY_ID, &pem).unwrap();
            let der = key.public_key_der();
            let signed = sign_request_at(raw.as_bytes(), HOST, &key, fixed_now()).unwrap();
            (der, signed)
        };
        let _ = body;

        let base64_pem = BASE64_STANDARD.encode(pem.as_bytes());
        let escaped_pem = pem.trim_end().replace('\n', "\\n");
        let pkcs8_der = {
            let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
            body
        };
        for (label, material) in [
            ("base64 of PEM", base64_pem),
            ("PEM with \\n escapes", escaped_pem),
            ("base64 of PKCS#8 DER", pkcs8_der),
        ] {
            assert!(!material.contains('\n'), "{label} must be single-line");
            let key = OciSigningKey::from_credentials(test_support::TEST_KEY_ID, &material)
                .unwrap_or_else(|e| panic!("{label}: {e}"));
            assert_eq!(key.public_key_der(), expected.0, "{label}: same key");
            let signed = sign_request_at(raw.as_bytes(), HOST, &key, fixed_now()).unwrap();
            // RSA PKCS#1 v1.5 is deterministic, so identical inputs sign identically.
            assert_eq!(signed, expected.1, "{label}: same signature");
        }

        let err = OciSigningKey::from_credentials("k", "not base64 and not pem").unwrap_err();
        assert!(err.to_string().contains("standard base64"), "{err}");
    }

    #[test]
    fn debug_never_prints_the_key_id() {
        let key = test_key();
        let printed = format!("{key:?}");
        assert!(!printed.contains(test_support::TEST_KEY_ID));
    }
}
