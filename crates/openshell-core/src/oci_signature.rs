// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Oracle Cloud Infrastructure request-signing primitives.
//!
//! OCI authenticates API requests with an RSA-SHA256 HTTP `Signature` header
//! (the draft-cavage HTTP signatures profile) over a fixed header set:
//! `date (request-target) host`, plus `content-length content-type
//! x-content-sha256` for POST, PUT, and PATCH. The `keyId` is either
//! `<tenancy>/<user>/<fingerprint>` for an API key or `ST$<security-token>`
//! for a session, instance, resource, or workload principal.
//!
//! This module holds the parts shared by the sandbox proxy, which re-signs
//! workload requests, and the gateway, which signs its own requests to OCI
//! identity endpoints when it federates a principal into a security token.
//! It knows nothing about raw HTTP framing; the proxy layers that on top.

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{KeyPair as _, RSA_PKCS1_SHA256, RsaKeyPair};
use base64::Engine;
use base64::prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD};
use miette::{Result, miette};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Provider credential key holding the OCI signing key id.
pub const KEY_ID_ENV: &str = "OCI_KEY_ID";
/// Provider credential key holding the RSA private key that pairs with it.
pub const PRIVATE_KEY_ENV: &str = "OCI_PRIVATE_KEY";
/// Prefix OCI uses for security-token key ids.
pub const SECURITY_TOKEN_KEY_ID_PREFIX: &str = "ST$";

const SIGNATURE_VERSION: &str = "1";
/// Headers every OCI signature covers, in the order the OCI SDKs use.
pub const GENERIC_HEADERS: [&str; 3] = ["date", "(request-target)", "host"];
/// Headers added to the signature for requests that carry a body.
pub const BODY_HEADERS: [&str; 3] = ["content-length", "content-type", "x-content-sha256"];
/// The OCI SDKs default a missing `content-type` to JSON before signing.
pub const DEFAULT_BODY_CONTENT_TYPE: &str = "application/json";

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
    /// Build a signing key from credential values.
    ///
    /// Provider credential values must be single-line, so the private key is
    /// accepted in any of these forms:
    ///
    /// - standard base64 of the PEM file (`base64 -w0 < oci_api_key.pem`),
    ///   the recommended form;
    /// - standard base64 of the raw PKCS#8 or PKCS#1 DER;
    /// - the PEM text with newlines written as the two characters `\n`;
    /// - the PEM text itself, for callers not bound by the single-line rule.
    ///
    /// Unencrypted PKCS#1 (`BEGIN RSA PRIVATE KEY`) and PKCS#8 (`BEGIN PRIVATE
    /// KEY`) RSA keys are supported. Passphrase-protected keys are rejected
    /// with a message that says so.
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
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// PKCS#1 `RSAPublicKey` DER of the signing key, for verification.
    #[must_use]
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

/// Turn a single-line credential value back into PEM or DER bytes.
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
/// signed over the generic headers and its body, if any, is not covered.
#[must_use]
pub fn method_signs_body(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "POST" | "PUT" | "PATCH"
    )
}

/// What to sign. The caller supplies the request line pieces and, for body
/// methods, the full body; this module derives the covered headers.
#[derive(Debug, Clone, Copy)]
pub struct SigningInput<'a> {
    /// HTTP method as sent.
    pub method: &'a str,
    /// Path plus query string, exactly as it appears in the request line.
    pub request_target_path: &'a str,
    /// `host` header value to sign, or `None` to leave `host` out of the
    /// signature. The OCI SDKs omit it only for the identity federation
    /// endpoints; ordinary API calls always sign it.
    pub host: Option<&'a str>,
    /// Full body for POST, PUT, and PATCH. Ignored for other methods.
    pub body: Option<&'a [u8]>,
    /// `content-type` as sent, when the request has one.
    pub content_type: Option<&'a str>,
    /// Timestamp for the `date` header.
    pub now: SystemTime,
}

/// The headers a signature adds or pins, plus the exact string that was
/// signed so tests and diagnostics can verify it.
#[derive(Debug, Clone)]
pub struct SignedHeaderSet {
    /// RFC 7231 `date` value that was signed.
    pub date: String,
    /// Complete `authorization` header value.
    pub authorization: String,
    /// `content-length` that was signed, for body methods.
    pub content_length: Option<usize>,
    /// `content-type` that was signed, for body methods.
    pub content_type: Option<String>,
    /// Base64 SHA-256 of the body that was signed, for body methods.
    pub x_content_sha256: Option<String>,
    /// The newline-joined `name: value` lines the signature covers.
    pub signing_string: String,
}

/// Compute an OCI signature for a request.
///
/// Returns an error when a body method is signed without its body, since the
/// signature would not match what the server receives.
pub fn sign_headers(input: SigningInput<'_>, key: &OciSigningKey) -> Result<SignedHeaderSet> {
    let signs_body = method_signs_body(input.method);
    if signs_body && input.body.is_none() {
        return Err(miette!(
            "OCI signing: {} requests must be buffered so the body can be hashed",
            input.method
        ));
    }

    let date = imf_fixdate(input.now);
    let request_target = format!(
        "{} {}",
        input.method.to_ascii_lowercase(),
        input.request_target_path
    );

    let mut signed: Vec<(&str, String)> =
        vec![("date", date.clone()), ("(request-target)", request_target)];
    if let Some(host) = input.host {
        signed.push(("host", host.to_string()));
    }

    let (content_length, content_type, x_content_sha256) = input
        .body
        .filter(|_| signs_body)
        .map_or((None, None, None), |body| {
            let content_type = input
                .content_type
                .map_or_else(|| DEFAULT_BODY_CONTENT_TYPE.to_string(), str::to_string);
            let body_hash = BASE64_STANDARD.encode(Sha256::digest(body));
            signed.push(("content-length", body.len().to_string()));
            signed.push(("content-type", content_type.clone()));
            signed.push(("x-content-sha256", body_hash.clone()));
            (Some(body.len()), Some(content_type), Some(body_hash))
        });

    let signing_string = signed
        .iter()
        .map(|(k, v)| format!("{k}: {v}"))
        .collect::<Vec<_>>()
        .join("\n");
    let signature = key.sign_base64(signing_string.as_bytes())?;
    let header_names = signed.iter().map(|(k, _)| *k).collect::<Vec<_>>().join(" ");
    let authorization = format!(
        "Signature algorithm=\"rsa-sha256\",headers=\"{header_names}\",keyId=\"{key_id}\",\
         signature=\"{signature}\",version=\"{SIGNATURE_VERSION}\"",
        key_id = key.key_id(),
    );

    Ok(SignedHeaderSet {
        date,
        authorization,
        content_length,
        content_type,
        x_content_sha256,
        signing_string,
    })
}

/// An ephemeral RSA key pair the gateway generates when it federates a
/// principal: OCI binds the issued security token to this public key, and the
/// private key becomes the `OCI_PRIVATE_KEY` credential.
#[derive(Debug, Clone)]
pub struct SessionKeyPair {
    /// Unencrypted PKCS#8 PEM of the private key.
    pub private_key_pem: String,
    /// `SubjectPublicKeyInfo` PEM of the public key.
    pub public_key_pem: String,
}

impl SessionKeyPair {
    /// Generate a fresh 2048-bit RSA key pair.
    pub fn generate() -> Result<Self> {
        let key_pair = RsaKeyPair::generate(KeySize::Rsa2048)
            .map_err(|e| miette!("OCI signing: generate session key failed: {e}"))?;
        let private_der = key_pair
            .as_der()
            .map_err(|e| miette!("OCI signing: export session key failed: {e}"))?;
        let public_der = key_pair
            .public_key()
            .as_der()
            .map_err(|e| miette!("OCI signing: export session public key failed: {e}"))?;
        Ok(Self {
            private_key_pem: pem_encode("PRIVATE KEY", private_der.as_ref()),
            public_key_pem: pem_encode("PUBLIC KEY", public_der.as_ref()),
        })
    }

    /// The private key as the single-line base64 form the proxy accepts in
    /// `OCI_PRIVATE_KEY`.
    #[must_use]
    pub fn private_key_credential(&self) -> String {
        BASE64_STANDARD.encode(self.private_key_pem.as_bytes())
    }
}

/// Wrap DER bytes in a PEM block with 64-column base64 lines.
#[must_use]
pub fn pem_encode(label: &str, der: &[u8]) -> String {
    let b64 = BASE64_STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END ");
    pem.push_str(label);
    pem.push_str("-----\n");
    pem
}

/// Reduce a PEM block to its bare base64 body, the form OCI identity
/// endpoints expect for certificates and public keys in JSON payloads.
#[must_use]
pub fn sanitize_pem(pem: &str) -> String {
    pem.lines()
        .filter(|line| !line.starts_with("-----"))
        .map(str::trim)
        .collect::<String>()
}

/// Expiry of an OCI security token in Unix milliseconds, read from the JWT
/// `exp` claim. Returns `None` when the token is not a JWT with a numeric
/// `exp`.
#[must_use]
pub fn security_token_expiry_ms(token: &str) -> Option<i64> {
    let token = token
        .strip_prefix(SECURITY_TOKEN_KEY_ID_PREFIX)
        .unwrap_or(token);
    let payload = token.split('.').nth(1)?;
    let decoded = BASE64_URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    let exp = claims.get("exp")?;
    // `exp` is integral seconds per RFC 7519; a fractional value is truncated.
    #[allow(clippy::cast_possible_truncation)]
    let exp_secs = exp
        .as_i64()
        .or_else(|| exp.as_f64().filter(|f| f.is_finite()).map(|f| f as i64))?;
    exp_secs.checked_mul(1000)
}

/// Format a timestamp as an RFC 7231 IMF-fixdate, for example
/// `Wed, 30 Sep 2026 12:00:00 GMT`, which is what OCI expects in `date`.
#[must_use]
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
mod tests {
    use super::*;
    use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
    use std::time::Duration;

    const TEST_KEY_ID: &str =
        "ocid1.tenancy.oc1..aaaaaaaatest/ocid1.user.oc1..aaaaaaaatest/aa:bb:cc:dd:ee:ff";

    fn fixed_now() -> SystemTime {
        // 2026-09-30T12:00:00Z = 497_436 hours after the epoch
        UNIX_EPOCH + Duration::from_hours(497_436)
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
    fn session_key_round_trips_through_every_single_line_form() {
        let session = SessionKeyPair::generate().unwrap();
        assert!(
            session
                .private_key_pem
                .starts_with("-----BEGIN PRIVATE KEY-----\n")
        );
        assert!(
            session
                .public_key_pem
                .starts_with("-----BEGIN PUBLIC KEY-----\n")
        );
        let reference = OciSigningKey::from_credentials(TEST_KEY_ID, &session.private_key_pem)
            .unwrap()
            .public_key_der();

        let der_b64: String = sanitize_pem(&session.private_key_pem);
        for (label, material) in [
            ("base64 of PEM", session.private_key_credential()),
            (
                "PEM with \\n escapes",
                session.private_key_pem.trim_end().replace('\n', "\\n"),
            ),
            ("base64 of PKCS#8 DER", der_b64),
        ] {
            assert!(!material.contains('\n'), "{label} must be single-line");
            let key = OciSigningKey::from_credentials(TEST_KEY_ID, &material)
                .unwrap_or_else(|e| panic!("{label}: {e}"));
            assert_eq!(key.public_key_der(), reference, "{label}: same key");
        }
    }

    #[test]
    fn bad_key_material_is_rejected_with_specific_messages() {
        let session = SessionKeyPair::generate().unwrap();
        let encrypted =
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB\n-----END ENCRYPTED PRIVATE KEY-----\n";
        assert!(
            OciSigningKey::from_credentials("k", encrypted)
                .unwrap_err()
                .to_string()
                .contains("passphrase-protected")
        );
        assert!(
            OciSigningKey::from_credentials("", &session.private_key_pem)
                .unwrap_err()
                .to_string()
                .contains("is empty")
        );
        assert!(
            OciSigningKey::from_credentials("k", "not base64 and not pem")
                .unwrap_err()
                .to_string()
                .contains("standard base64")
        );
    }

    #[test]
    fn post_signature_covers_generic_and_body_headers_in_sdk_order() {
        let session = SessionKeyPair::generate().unwrap();
        let key = OciSigningKey::from_credentials(TEST_KEY_ID, &session.private_key_pem).unwrap();
        let body = br#"{"compartmentId":"ocid1.compartment.oc1..example"}"#;
        let host = "inference.generativeai.us-chicago-1.oci.oraclecloud.com";
        let signed = sign_headers(
            SigningInput {
                method: "POST",
                request_target_path: "/20231130/actions/chat",
                host: Some(host),
                body: Some(body),
                content_type: Some("application/json"),
                now: fixed_now(),
            },
            &key,
        )
        .unwrap();
        let expected_hash = BASE64_STANDARD.encode(Sha256::digest(body));
        assert_eq!(signed.date, "Wed, 30 Sep 2026 12:00:00 GMT");
        assert_eq!(signed.content_length, Some(body.len()));
        assert_eq!(signed.content_type.as_deref(), Some("application/json"));
        assert_eq!(
            signed.x_content_sha256.as_deref(),
            Some(expected_hash.as_str())
        );
        assert_eq!(
            signature_param(&signed.authorization, "headers").unwrap(),
            "date (request-target) host content-length content-type x-content-sha256"
        );
        assert_eq!(
            signature_param(&signed.authorization, "keyId").unwrap(),
            TEST_KEY_ID
        );
        assert_eq!(
            signature_param(&signed.authorization, "version").unwrap(),
            "1"
        );
        assert!(
            signed
                .authorization
                .starts_with("Signature algorithm=\"rsa-sha256\",")
        );
        assert_eq!(
            signed.signing_string,
            format!(
                "date: Wed, 30 Sep 2026 12:00:00 GMT\n(request-target): post /20231130/actions/chat\nhost: {host}\ncontent-length: {}\ncontent-type: application/json\nx-content-sha256: {expected_hash}",
                body.len()
            )
        );
        assert!(verify(
            &key,
            &signed.signing_string,
            signature_param(&signed.authorization, "signature").unwrap()
        ));
    }

    #[test]
    fn federation_shape_omits_host_and_defaults_content_type() {
        let session = SessionKeyPair::generate().unwrap();
        let key =
            OciSigningKey::from_credentials("tenancy/fed-x509/AA:BB", &session.private_key_pem)
                .unwrap();
        let signed = sign_headers(
            SigningInput {
                method: "POST",
                request_target_path: "/v1/x509",
                host: None,
                body: Some(b"{}"),
                content_type: None,
                now: fixed_now(),
            },
            &key,
        )
        .unwrap();
        assert_eq!(
            signature_param(&signed.authorization, "headers").unwrap(),
            "date (request-target) content-length content-type x-content-sha256"
        );
        assert_eq!(
            signed.content_type.as_deref(),
            Some(DEFAULT_BODY_CONTENT_TYPE)
        );
        assert!(!signed.signing_string.contains("host:"));
        assert!(verify(
            &key,
            &signed.signing_string,
            signature_param(&signed.authorization, "signature").unwrap()
        ));
    }

    #[test]
    fn get_signature_covers_generic_headers_only_and_keeps_the_query() {
        let session = SessionKeyPair::generate().unwrap();
        let key = OciSigningKey::from_credentials(TEST_KEY_ID, &session.private_key_pem).unwrap();
        let signed = sign_headers(
            SigningInput {
                method: "GET",
                request_target_path: "/n/ns/b/bucket/o?prefix=a%20b&limit=10",
                host: Some("objectstorage.us-chicago-1.oraclecloud.com"),
                body: None,
                content_type: None,
                now: fixed_now(),
            },
            &key,
        )
        .unwrap();
        assert_eq!(
            signature_param(&signed.authorization, "headers").unwrap(),
            "date (request-target) host"
        );
        assert!(signed.x_content_sha256.is_none());
        assert!(
            signed
                .signing_string
                .contains("(request-target): get /n/ns/b/bucket/o?prefix=a%20b&limit=10")
        );
    }

    #[test]
    fn body_method_without_body_is_rejected() {
        let session = SessionKeyPair::generate().unwrap();
        let key = OciSigningKey::from_credentials(TEST_KEY_ID, &session.private_key_pem).unwrap();
        let err = sign_headers(
            SigningInput {
                method: "PUT",
                request_target_path: "/x",
                host: Some("h"),
                body: None,
                content_type: None,
                now: fixed_now(),
            },
            &key,
        )
        .unwrap_err();
        assert!(err.to_string().contains("must be buffered"), "{err}");
    }

    #[test]
    fn sanitize_pem_strips_armor_and_newlines() {
        let pem = pem_encode("PUBLIC KEY", &[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let bare = sanitize_pem(&pem);
        assert_eq!(bare, BASE64_STANDARD.encode([1, 2, 3, 4, 5, 6, 7, 8, 9]));
        assert!(!bare.contains('\n'));
    }

    #[test]
    fn security_token_expiry_reads_the_jwt_exp_claim() {
        let payload = BASE64_URL_SAFE_NO_PAD.encode(br#"{"sub":"x","exp":1790769600}"#);
        let token = format!("eyJhbGciOiJSUzI1NiJ9.{payload}.sig");
        assert_eq!(security_token_expiry_ms(&token), Some(1_790_769_600_000));
        assert_eq!(
            security_token_expiry_ms(&format!("ST${token}")),
            Some(1_790_769_600_000)
        );
        assert_eq!(security_token_expiry_ms("not-a-jwt"), None);
        let no_exp = BASE64_URL_SAFE_NO_PAD.encode(br#"{"sub":"x"}"#);
        assert_eq!(security_token_expiry_ms(&format!("a.{no_exp}.b")), None);
    }

    #[test]
    fn debug_never_prints_the_key_id() {
        let session = SessionKeyPair::generate().unwrap();
        let key = OciSigningKey::from_credentials(TEST_KEY_ID, &session.private_key_pem).unwrap();
        assert!(!format!("{key:?}").contains(TEST_KEY_ID));
    }
}
