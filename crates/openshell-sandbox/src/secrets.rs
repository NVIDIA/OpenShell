// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use base64::Engine as _;
use std::collections::HashMap;
use std::fmt;

const PLACEHOLDER_PREFIX: &str = "openshell:resolve:env:";

/// Public access to the placeholder prefix for fail-closed scanning in other modules.
pub(crate) const PLACEHOLDER_PREFIX_PUBLIC: &str = PLACEHOLDER_PREFIX;

/// Characters that are valid in an env var key name (used to extract
/// placeholder boundaries within concatenated strings like path segments).
fn is_env_key_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

// ---------------------------------------------------------------------------
// Error and result types
// ---------------------------------------------------------------------------

/// Error returned when a placeholder cannot be resolved or a resolved secret
/// contains prohibited characters.
#[derive(Debug)]
pub(crate) struct UnresolvedPlaceholderError {
    pub location: &'static str, // "header", "query_param", "path"
}

impl fmt::Display for UnresolvedPlaceholderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unresolved credential placeholder in {}: detected openshell:resolve:env:* token that could not be resolved",
            self.location
        )
    }
}

/// Result of rewriting an HTTP header block with credential resolution.
#[derive(Debug)]
pub(crate) struct RewriteResult {
    /// The rewritten HTTP bytes (headers + body overflow).
    pub rewritten: Vec<u8>,
    /// A redacted version of the request target for logging.
    /// Contains `[CREDENTIAL]` in place of resolved credential values.
    /// `None` if the target was not modified.
    pub redacted_target: Option<String>,
}

/// Result of rewriting a request target for OPA evaluation.
#[derive(Debug)]
pub(crate) struct RewriteTargetResult {
    /// The resolved target (real secrets) — for upstream forwarding only.
    pub resolved: String,
    /// The redacted target (`[CREDENTIAL]` in place of secrets) — for OPA + logs.
    pub redacted: String,
}

// ---------------------------------------------------------------------------
// SecretResolver
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct SecretResolver {
    by_placeholder: HashMap<String, String>,
}

impl SecretResolver {
    pub(crate) fn from_provider_env(
        provider_env: HashMap<String, String>,
    ) -> (HashMap<String, String>, Option<Self>) {
        if provider_env.is_empty() {
            return (HashMap::new(), None);
        }

        let mut child_env = HashMap::with_capacity(provider_env.len());
        let mut by_placeholder = HashMap::with_capacity(provider_env.len());

        for (key, value) in provider_env {
            let placeholder = placeholder_for_env_key(&key);
            child_env.insert(key, placeholder.clone());
            by_placeholder.insert(placeholder, value);
        }

        (child_env, Some(Self { by_placeholder }))
    }

    /// Resolve a placeholder string to the real secret value.
    ///
    /// Returns `None` if the placeholder is unknown or the resolved value
    /// contains prohibited control characters (CRLF, null byte).
    pub(crate) fn resolve_placeholder(&self, value: &str) -> Option<&str> {
        let secret = self.by_placeholder.get(value).map(String::as_str)?;
        match validate_resolved_secret(secret) {
            Ok(s) => Some(s),
            Err(reason) => {
                tracing::warn!(
                    location = "resolve_placeholder",
                    reason,
                    "credential resolution rejected: resolved value contains prohibited characters"
                );
                None
            }
        }
    }

    pub(crate) fn rewrite_header_value(&self, value: &str) -> Option<String> {
        // Direct placeholder match: `x-api-key: openshell:resolve:env:KEY`
        if let Some(secret) = self.resolve_placeholder(value.trim()) {
            return Some(secret.to_string());
        }

        let trimmed = value.trim();

        // Basic auth decoding: `Basic <base64>` where the decoded content
        // contains a placeholder (e.g. `user:openshell:resolve:env:PASS`).
        if let Some(encoded) = trimmed
            .strip_prefix("Basic ")
            .or_else(|| trimmed.strip_prefix("basic "))
            .map(str::trim)
        {
            if let Some(rewritten) = self.rewrite_basic_auth_token(encoded) {
                return Some(format!("Basic {rewritten}"));
            }
        }

        // Prefixed placeholder: `Bearer openshell:resolve:env:KEY`
        let split_at = trimmed.find(char::is_whitespace)?;
        let prefix = &trimmed[..split_at];
        let candidate = trimmed[split_at..].trim();
        let secret = self.resolve_placeholder(candidate)?;
        Some(format!("{prefix} {secret}"))
    }

    /// Decode a Base64-encoded Basic auth token, resolve any placeholders in
    /// the decoded `username:password` string, and re-encode.
    ///
    /// Returns `None` if decoding fails or no placeholders are found.
    fn rewrite_basic_auth_token(&self, encoded: &str) -> Option<String> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let decoded_bytes = b64.decode(encoded.trim()).ok()?;
        let decoded = std::str::from_utf8(&decoded_bytes).ok()?;

        // Check if the decoded string contains any placeholder
        if !decoded.contains(PLACEHOLDER_PREFIX) {
            return None;
        }

        // Rewrite all placeholder occurrences in the decoded string
        let mut rewritten = decoded.to_string();
        for (placeholder, secret) in &self.by_placeholder {
            if rewritten.contains(placeholder.as_str()) {
                // Validate the resolved secret for control characters
                if validate_resolved_secret(secret).is_err() {
                    tracing::warn!(
                        location = "basic_auth",
                        "credential resolution rejected: resolved value contains prohibited characters"
                    );
                    return None;
                }
                rewritten = rewritten.replace(placeholder.as_str(), secret);
            }
        }

        // Only return if we actually changed something
        if rewritten == decoded {
            return None;
        }

        Some(b64.encode(rewritten.as_bytes()))
    }
}

pub(crate) fn placeholder_for_env_key(key: &str) -> String {
    format!("{PLACEHOLDER_PREFIX}{key}")
}

// ---------------------------------------------------------------------------
// Secret validation (F1 — CWE-113)
// ---------------------------------------------------------------------------

/// Validate that a resolved secret value does not contain characters that
/// could enable HTTP header injection or request splitting.
fn validate_resolved_secret(value: &str) -> Result<&str, &'static str> {
    if value
        .bytes()
        .any(|b| b == b'\r' || b == b'\n' || b == b'\0')
    {
        return Err("resolved secret contains prohibited control characters (CR, LF, or NUL)");
    }
    Ok(value)
}

// ---------------------------------------------------------------------------
// Percent encoding/decoding (RFC 3986)
// ---------------------------------------------------------------------------

/// Percent-encode a string for safe use in URL query parameter values.
///
/// Encodes all characters except unreserved characters (RFC 3986 Section 2.3):
/// ALPHA / DIGIT / "-" / "." / "_" / "~"
fn percent_encode_query(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                use fmt::Write;
                let _ = write!(encoded, "%{byte:02X}");
            }
        }
    }
    encoded
}

/// Percent-encode a string for safe use in URL path segments.
///
/// RFC 3986 §3.3: pchar = unreserved / pct-encoded / sub-delims / ":" / "@"
/// sub-delims = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
///
/// Must encode: `/`, `?`, `#`, space, and other non-pchar characters.
fn percent_encode_path_segment(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            // unreserved
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char);
            }
            // sub-delims + ":" + "@"
            b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' | b':'
            | b'@' => {
                encoded.push(byte as char);
            }
            _ => {
                use fmt::Write;
                let _ = write!(encoded, "%{byte:02X}");
            }
        }
    }
    encoded
}

/// Percent-decode a URL-encoded string.
fn percent_decode(input: &str) -> String {
    let mut decoded = Vec::with_capacity(input.len());
    let mut bytes = input.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hi = bytes.next();
            let lo = bytes.next();
            if let (Some(h), Some(l)) = (hi, lo) {
                let hex = [h, l];
                if let Ok(s) = std::str::from_utf8(&hex) {
                    if let Ok(val) = u8::from_str_radix(s, 16) {
                        decoded.push(val);
                        continue;
                    }
                }
                // Invalid percent encoding — preserve verbatim
                decoded.push(b'%');
                decoded.push(h);
                decoded.push(l);
            } else {
                decoded.push(b'%');
                if let Some(h) = hi {
                    decoded.push(h);
                }
            }
        } else {
            decoded.push(b);
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

// ---------------------------------------------------------------------------
// Path credential validation (F3 — CWE-22)
// ---------------------------------------------------------------------------

/// Validate that a resolved credential value is safe for use in a URL path segment.
///
/// Operates on the raw (decoded) credential value before percent-encoding.
/// Rejects values that could enable path traversal, request splitting, or
/// URI structure breakage.
fn validate_credential_for_path(value: &str) -> Result<(), String> {
    if value.contains("../") || value.contains("..\\") || value == ".." {
        return Err("credential contains path traversal sequence".into());
    }
    if value.contains('\0') || value.contains('\r') || value.contains('\n') {
        return Err("credential contains control character".into());
    }
    if value.contains('/') || value.contains('\\') {
        return Err("credential contains path separator".into());
    }
    if value.contains('?') || value.contains('#') {
        return Err("credential contains URI delimiter".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// URI rewriting
// ---------------------------------------------------------------------------

/// Result of rewriting the request line.
struct RewriteLineResult {
    /// The rewritten request line.
    line: String,
    /// Redacted target for logging (if any rewriting occurred).
    redacted_target: Option<String>,
}

/// Rewrite credential placeholders in the request line's URL.
///
/// Given a request line like `GET /bot{TOKEN}/path?key={APIKEY} HTTP/1.1`,
/// resolves placeholders in both path segments and query parameter values.
fn rewrite_request_line(
    line: &str,
    resolver: &SecretResolver,
) -> Result<RewriteLineResult, UnresolvedPlaceholderError> {
    // Request line format: METHOD SP REQUEST-URI SP HTTP-VERSION
    let mut parts = line.splitn(3, ' ');
    let method = match parts.next() {
        Some(m) => m,
        None => {
            return Ok(RewriteLineResult {
                line: line.to_string(),
                redacted_target: None,
            });
        }
    };
    let uri = match parts.next() {
        Some(u) => u,
        None => {
            return Ok(RewriteLineResult {
                line: line.to_string(),
                redacted_target: None,
            });
        }
    };
    let version = match parts.next() {
        Some(v) => v,
        None => {
            return Ok(RewriteLineResult {
                line: line.to_string(),
                redacted_target: None,
            });
        }
    };

    // Only rewrite if the URI contains a placeholder
    if !uri.contains(PLACEHOLDER_PREFIX) {
        return Ok(RewriteLineResult {
            line: line.to_string(),
            redacted_target: None,
        });
    }

    // Split URI into path and query
    let (path, query) = match uri.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (uri, None),
    };

    // Rewrite path segments
    let (resolved_path, redacted_path) = match rewrite_uri_path(path, resolver)? {
        Some((resolved, redacted)) => (resolved, redacted),
        None => (path.to_string(), path.to_string()),
    };

    // Rewrite query params
    let (resolved_query, redacted_query) = match query {
        Some(q) => match rewrite_uri_query_params(q, resolver)? {
            Some((resolved, redacted)) => (Some(resolved), Some(redacted)),
            None => (Some(q.to_string()), Some(q.to_string())),
        },
        None => (None, None),
    };

    // Reassemble
    let resolved_uri = match &resolved_query {
        Some(q) => format!("{resolved_path}?{q}"),
        None => resolved_path.clone(),
    };
    let redacted_uri = match &redacted_query {
        Some(q) => format!("{redacted_path}?{q}"),
        None => redacted_path,
    };

    Ok(RewriteLineResult {
        line: format!("{method} {resolved_uri} {version}"),
        redacted_target: Some(redacted_uri),
    })
}

/// Rewrite placeholders in URL path segments.
///
/// Handles substring matching for cases like Telegram's `/bot{TOKEN}/method`
/// where the placeholder is concatenated with literal text in a segment.
///
/// Returns `Some((resolved_path, redacted_path))` if any placeholders were found,
/// `None` if no placeholders exist in the path.
fn rewrite_uri_path(
    path: &str,
    resolver: &SecretResolver,
) -> Result<Option<(String, String)>, UnresolvedPlaceholderError> {
    if !path.contains(PLACEHOLDER_PREFIX) {
        return Ok(None);
    }

    let segments: Vec<&str> = path.split('/').collect();
    let mut resolved_segments = Vec::with_capacity(segments.len());
    let mut redacted_segments = Vec::with_capacity(segments.len());
    let mut any_rewritten = false;

    for segment in &segments {
        let decoded = percent_decode(segment);
        if !decoded.contains(PLACEHOLDER_PREFIX) {
            resolved_segments.push(segment.to_string());
            redacted_segments.push(segment.to_string());
            continue;
        }

        let (resolved, redacted) = rewrite_path_segment(&decoded, resolver)?;
        // Percent-encode the resolved segment for path context
        resolved_segments.push(percent_encode_path_segment(&resolved));
        redacted_segments.push(redacted);
        any_rewritten = true;
    }

    if !any_rewritten {
        return Ok(None);
    }

    Ok(Some((
        resolved_segments.join("/"),
        redacted_segments.join("/"),
    )))
}

/// Rewrite placeholders within a single path segment (already percent-decoded).
///
/// Uses the placeholder grammar `openshell:resolve:env:[A-Za-z_][A-Za-z0-9_]*`
/// to determine placeholder boundaries within concatenated text.
fn rewrite_path_segment(
    segment: &str,
    resolver: &SecretResolver,
) -> Result<(String, String), UnresolvedPlaceholderError> {
    let mut resolved = String::with_capacity(segment.len());
    let mut redacted = String::with_capacity(segment.len());
    let mut pos = 0;
    let bytes = segment.as_bytes();

    while pos < bytes.len() {
        if let Some(start) = segment[pos..].find(PLACEHOLDER_PREFIX) {
            let abs_start = pos + start;
            // Copy literal prefix before the placeholder
            resolved.push_str(&segment[pos..abs_start]);
            redacted.push_str(&segment[pos..abs_start]);

            // Extract the key name using the env var grammar: [A-Za-z_][A-Za-z0-9_]*
            let key_start = abs_start + PLACEHOLDER_PREFIX.len();
            let key_end = segment[key_start..]
                .bytes()
                .position(|b| !is_env_key_char(b))
                .map_or(segment.len(), |p| key_start + p);

            if key_end == key_start {
                // Empty key — not a valid placeholder, copy literally
                resolved.push_str(&segment[abs_start..abs_start + PLACEHOLDER_PREFIX.len()]);
                redacted.push_str(&segment[abs_start..abs_start + PLACEHOLDER_PREFIX.len()]);
                pos = abs_start + PLACEHOLDER_PREFIX.len();
                continue;
            }

            let full_placeholder = &segment[abs_start..key_end];
            if let Some(secret) = resolver.resolve_placeholder(full_placeholder) {
                validate_credential_for_path(secret).map_err(|reason| {
                    tracing::warn!(
                        location = "path",
                        %reason,
                        "credential resolution rejected: resolved value unsafe for path"
                    );
                    UnresolvedPlaceholderError { location: "path" }
                })?;
                resolved.push_str(secret);
                redacted.push_str("[CREDENTIAL]");
            } else {
                return Err(UnresolvedPlaceholderError { location: "path" });
            }
            pos = key_end;
        } else {
            // No more placeholders in remainder
            resolved.push_str(&segment[pos..]);
            redacted.push_str(&segment[pos..]);
            break;
        }
    }

    Ok((resolved, redacted))
}

/// Rewrite placeholders in query parameter values.
///
/// Returns `Some((resolved_query, redacted_query))` if any placeholders were found.
fn rewrite_uri_query_params(
    query: &str,
    resolver: &SecretResolver,
) -> Result<Option<(String, String)>, UnresolvedPlaceholderError> {
    if !query.contains(PLACEHOLDER_PREFIX) {
        return Ok(None);
    }

    let mut resolved_params = Vec::new();
    let mut redacted_params = Vec::new();
    let mut any_rewritten = false;

    for param in query.split('&') {
        if let Some((key, value)) = param.split_once('=') {
            let decoded_value = percent_decode(value);
            if let Some(secret) = resolver.resolve_placeholder(&decoded_value) {
                resolved_params.push(format!("{key}={}", percent_encode_query(secret)));
                redacted_params.push(format!("{key}=[CREDENTIAL]"));
                any_rewritten = true;
            } else if decoded_value.contains(PLACEHOLDER_PREFIX) {
                // Placeholder detected but not resolved
                return Err(UnresolvedPlaceholderError {
                    location: "query_param",
                });
            } else {
                resolved_params.push(param.to_string());
                redacted_params.push(param.to_string());
            }
        } else {
            resolved_params.push(param.to_string());
            redacted_params.push(param.to_string());
        }
    }

    if !any_rewritten {
        return Ok(None);
    }

    Ok(Some((resolved_params.join("&"), redacted_params.join("&"))))
}

// ---------------------------------------------------------------------------
// Public rewrite API
// ---------------------------------------------------------------------------

/// Rewrite credential placeholders in an HTTP header block.
///
/// Resolves `openshell:resolve:env:*` placeholders in the request line
/// (path segments and query parameter values), header values (including
/// Basic auth tokens), and returns a `RewriteResult` with the rewritten
/// bytes and a redacted target for logging.
///
/// Returns `Err` if any placeholder is detected but cannot be resolved
/// (fail-closed behavior).
pub(crate) fn rewrite_http_header_block(
    raw: &[u8],
    resolver: Option<&SecretResolver>,
) -> Result<RewriteResult, UnresolvedPlaceholderError> {
    let Some(resolver) = resolver else {
        return Ok(RewriteResult {
            rewritten: raw.to_vec(),
            redacted_target: None,
        });
    };

    let Some(header_end) = raw.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4) else {
        return Ok(RewriteResult {
            rewritten: raw.to_vec(),
            redacted_target: None,
        });
    };

    let header_str = String::from_utf8_lossy(&raw[..header_end]);
    let mut lines = header_str.split("\r\n");
    let Some(request_line) = lines.next() else {
        return Ok(RewriteResult {
            rewritten: raw.to_vec(),
            redacted_target: None,
        });
    };

    // Rewrite request line (path + query params)
    let rl_result = rewrite_request_line(request_line, resolver)?;

    let mut output = Vec::with_capacity(raw.len());
    output.extend_from_slice(rl_result.line.as_bytes());
    output.extend_from_slice(b"\r\n");

    for line in lines {
        if line.is_empty() {
            break;
        }

        output.extend_from_slice(rewrite_header_line(line, resolver).as_bytes());
        output.extend_from_slice(b"\r\n");
    }

    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(&raw[header_end..]);

    // Fail-closed scan: check for any remaining unresolved placeholders
    // in both raw form and percent-decoded form of the output header block.
    let output_header = String::from_utf8_lossy(&output[..output.len().min(header_end + 256)]);
    if output_header.contains(PLACEHOLDER_PREFIX) {
        return Err(UnresolvedPlaceholderError { location: "header" });
    }

    // Also check percent-decoded form of the request line (F5 — encoded placeholder bypass)
    let rewritten_rl = output_header.split("\r\n").next().unwrap_or("");
    let decoded_rl = percent_decode(rewritten_rl);
    if decoded_rl.contains(PLACEHOLDER_PREFIX) {
        return Err(UnresolvedPlaceholderError { location: "path" });
    }

    Ok(RewriteResult {
        rewritten: output,
        redacted_target: rl_result.redacted_target,
    })
}

pub(crate) fn rewrite_header_line(line: &str, resolver: &SecretResolver) -> String {
    let Some((name, value)) = line.split_once(':') else {
        return line.to_string();
    };

    match resolver.rewrite_header_value(value.trim()) {
        Some(rewritten) => format!("{name}: {rewritten}"),
        None => line.to_string(),
    }
}

/// Resolve placeholders in a request target (path + query) for OPA evaluation.
///
/// Returns the resolved target (real secrets, for upstream) and a redacted
/// version (`[CREDENTIAL]` in place of secrets, for OPA input and logs).
pub(crate) fn rewrite_target_for_eval(
    target: &str,
    resolver: &SecretResolver,
) -> Result<RewriteTargetResult, UnresolvedPlaceholderError> {
    if !target.contains(PLACEHOLDER_PREFIX) {
        // Also check percent-decoded form
        let decoded = percent_decode(target);
        if decoded.contains(PLACEHOLDER_PREFIX) {
            return Err(UnresolvedPlaceholderError { location: "path" });
        }
        return Ok(RewriteTargetResult {
            resolved: target.to_string(),
            redacted: target.to_string(),
        });
    }

    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (target, None),
    };

    // Rewrite path
    let (resolved_path, redacted_path) = match rewrite_uri_path(path, resolver)? {
        Some((resolved, redacted)) => (resolved, redacted),
        None => (path.to_string(), path.to_string()),
    };

    // Rewrite query
    let (resolved_query, redacted_query) = match query {
        Some(q) => match rewrite_uri_query_params(q, resolver)? {
            Some((resolved, redacted)) => (Some(resolved), Some(redacted)),
            None => (Some(q.to_string()), Some(q.to_string())),
        },
        None => (None, None),
    };

    let resolved = match &resolved_query {
        Some(q) => format!("{resolved_path}?{q}"),
        None => resolved_path,
    };
    let redacted = match &redacted_query {
        Some(q) => format!("{redacted_path}?{q}"),
        None => redacted_path,
    };

    Ok(RewriteTargetResult { resolved, redacted })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // === Existing tests (preserved) ===

    #[test]
    fn provider_env_is_replaced_with_placeholders() {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            [("ANTHROPIC_API_KEY".to_string(), "sk-test".to_string())]
                .into_iter()
                .collect(),
        );

        assert_eq!(
            child_env.get("ANTHROPIC_API_KEY"),
            Some(&"openshell:resolve:env:ANTHROPIC_API_KEY".to_string())
        );
        assert_eq!(
            resolver
                .as_ref()
                .and_then(|resolver| resolver
                    .resolve_placeholder("openshell:resolve:env:ANTHROPIC_API_KEY")),
            Some("sk-test")
        );
    }

    #[test]
    fn rewrites_exact_placeholder_header_values() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("CUSTOM_TOKEN".to_string(), "secret-token".to_string())]
                .into_iter()
                .collect(),
        );
        let resolver = resolver.expect("resolver");

        assert_eq!(
            rewrite_header_line("x-api-key: openshell:resolve:env:CUSTOM_TOKEN", &resolver),
            "x-api-key: secret-token"
        );
    }

    #[test]
    fn rewrites_bearer_placeholder_header_values() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("ANTHROPIC_API_KEY".to_string(), "sk-test".to_string())]
                .into_iter()
                .collect(),
        );
        let resolver = resolver.expect("resolver");

        assert_eq!(
            rewrite_header_line(
                "Authorization: Bearer openshell:resolve:env:ANTHROPIC_API_KEY",
                &resolver,
            ),
            "Authorization: Bearer sk-test"
        );
    }

    #[test]
    fn rewrites_http_header_blocks_and_preserves_body() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("CUSTOM_TOKEN".to_string(), "secret-token".to_string())]
                .into_iter()
                .collect(),
        );

        let raw = b"POST /v1 HTTP/1.1\r\nAuthorization: Bearer openshell:resolve:env:CUSTOM_TOKEN\r\nContent-Length: 5\r\n\r\nhello";
        let result = rewrite_http_header_block(raw, resolver.as_ref()).expect("should succeed");
        let rewritten = String::from_utf8(result.rewritten).expect("utf8");

        assert!(rewritten.contains("Authorization: Bearer secret-token\r\n"));
        assert!(rewritten.ends_with("\r\n\r\nhello"));
    }

    #[test]
    fn full_round_trip_child_env_to_rewritten_headers() {
        let provider_env: HashMap<String, String> = [
            (
                "ANTHROPIC_API_KEY".to_string(),
                "sk-real-key-12345".to_string(),
            ),
            (
                "CUSTOM_SERVICE_TOKEN".to_string(),
                "tok-real-svc-67890".to_string(),
            ),
        ]
        .into_iter()
        .collect();

        let (child_env, resolver) = SecretResolver::from_provider_env(provider_env);

        let auth_value = child_env.get("ANTHROPIC_API_KEY").unwrap();
        let token_value = child_env.get("CUSTOM_SERVICE_TOKEN").unwrap();
        assert!(auth_value.starts_with(PLACEHOLDER_PREFIX));
        assert!(token_value.starts_with(PLACEHOLDER_PREFIX));

        let raw = format!(
            "GET /v1/messages HTTP/1.1\r\n\
             Host: api.example.com\r\n\
             Authorization: Bearer {auth_value}\r\n\
             x-api-key: {token_value}\r\n\
             Content-Length: 0\r\n\r\n"
        );

        let result =
            rewrite_http_header_block(raw.as_bytes(), resolver.as_ref()).expect("should succeed");
        let rewritten = String::from_utf8(result.rewritten).expect("utf8");

        assert!(
            rewritten.contains("Authorization: Bearer sk-real-key-12345\r\n"),
            "Expected rewritten Authorization header, got: {rewritten}"
        );
        assert!(
            rewritten.contains("x-api-key: tok-real-svc-67890\r\n"),
            "Expected rewritten x-api-key header, got: {rewritten}"
        );
        assert!(
            !rewritten.contains("openshell:resolve:env:"),
            "Placeholder leaked into rewritten request: {rewritten}"
        );
        assert!(rewritten.starts_with("GET /v1/messages HTTP/1.1\r\n"));
        assert!(rewritten.contains("Host: api.example.com\r\n"));
        assert!(rewritten.contains("Content-Length: 0\r\n"));
    }

    #[test]
    fn non_secret_headers_are_not_modified() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("API_KEY".to_string(), "secret".to_string())]
                .into_iter()
                .collect(),
        );

        let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: application/json\r\nContent-Type: text/plain\r\n\r\n";
        let result = rewrite_http_header_block(raw, resolver.as_ref()).expect("should succeed");
        assert_eq!(raw.as_slice(), result.rewritten.as_slice());
    }

    #[test]
    fn empty_provider_env_produces_no_resolver() {
        let (child_env, resolver) = SecretResolver::from_provider_env(HashMap::new());
        assert!(child_env.is_empty());
        assert!(resolver.is_none());
    }

    #[test]
    fn rewrite_with_no_resolver_returns_original() {
        let raw = b"GET / HTTP/1.1\r\nAuthorization: Bearer my-token\r\n\r\n";
        let result = rewrite_http_header_block(raw, None).expect("should succeed");
        assert_eq!(raw.as_slice(), result.rewritten.as_slice());
    }

    // === Secret validation tests (F1 — CWE-113) ===

    #[test]
    fn resolve_placeholder_rejects_crlf() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("BAD_KEY".to_string(), "value\r\nEvil: header".to_string())]
                .into_iter()
                .collect(),
        );
        let resolver = resolver.expect("resolver");
        assert!(
            resolver
                .resolve_placeholder("openshell:resolve:env:BAD_KEY")
                .is_none()
        );
    }

    #[test]
    fn resolve_placeholder_rejects_null() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("BAD_KEY".to_string(), "value\0rest".to_string())]
                .into_iter()
                .collect(),
        );
        let resolver = resolver.expect("resolver");
        assert!(
            resolver
                .resolve_placeholder("openshell:resolve:env:BAD_KEY")
                .is_none()
        );
    }

    #[test]
    fn resolve_placeholder_accepts_normal_values() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("KEY".to_string(), "sk-abc123_DEF.456~xyz".to_string())]
                .into_iter()
                .collect(),
        );
        let resolver = resolver.expect("resolver");
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:KEY"),
            Some("sk-abc123_DEF.456~xyz")
        );
    }

    // === Query parameter rewriting tests (absorbed from PR #631) ===

    #[test]
    fn rewrites_query_param_placeholder_in_request_line() {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            [("YOUTUBE_API_KEY".to_string(), "AIzaSy-secret".to_string())]
                .into_iter()
                .collect(),
        );
        let placeholder = child_env.get("YOUTUBE_API_KEY").unwrap();

        let raw = format!(
            "GET /youtube/v3/search?part=snippet&key={placeholder} HTTP/1.1\r\n\
             Host: www.googleapis.com\r\n\r\n"
        );
        let result =
            rewrite_http_header_block(raw.as_bytes(), resolver.as_ref()).expect("should succeed");
        let rewritten = String::from_utf8(result.rewritten).expect("utf8");

        assert!(
            rewritten
                .starts_with("GET /youtube/v3/search?part=snippet&key=AIzaSy-secret HTTP/1.1\r\n"),
            "Expected query param rewritten, got: {rewritten}"
        );
        assert!(!rewritten.contains("openshell:resolve:env:"));
    }

    #[test]
    fn rewrites_query_param_with_special_chars_percent_encoded() {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            [(
                "API_KEY".to_string(),
                "key with spaces&symbols=yes".to_string(),
            )]
            .into_iter()
            .collect(),
        );
        let placeholder = child_env.get("API_KEY").unwrap();

        let raw = format!("GET /api?token={placeholder} HTTP/1.1\r\nHost: x\r\n\r\n");
        let result =
            rewrite_http_header_block(raw.as_bytes(), resolver.as_ref()).expect("should succeed");
        let rewritten = String::from_utf8(result.rewritten).expect("utf8");

        assert!(
            rewritten.contains("token=key%20with%20spaces%26symbols%3Dyes"),
            "Expected percent-encoded secret, got: {rewritten}"
        );
    }

    #[test]
    fn rewrites_query_param_only_placeholder_first_param() {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            [("KEY".to_string(), "secret123".to_string())]
                .into_iter()
                .collect(),
        );
        let placeholder = child_env.get("KEY").unwrap();

        let raw = format!("GET /api?key={placeholder}&format=json HTTP/1.1\r\nHost: x\r\n\r\n");
        let result =
            rewrite_http_header_block(raw.as_bytes(), resolver.as_ref()).expect("should succeed");
        let rewritten = String::from_utf8(result.rewritten).expect("utf8");

        assert!(
            rewritten.starts_with("GET /api?key=secret123&format=json HTTP/1.1"),
            "Expected first param rewritten, got: {rewritten}"
        );
    }

    #[test]
    fn no_query_param_rewrite_without_placeholder() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("KEY".to_string(), "secret".to_string())]
                .into_iter()
                .collect(),
        );

        let raw = b"GET /api?key=normalvalue HTTP/1.1\r\nHost: x\r\n\r\n";
        let result = rewrite_http_header_block(raw, resolver.as_ref()).expect("should succeed");
        assert_eq!(raw.as_slice(), result.rewritten.as_slice());
    }

    // === Basic Authorization header encoding tests (absorbed from PR #631) ===

    #[test]
    fn rewrites_basic_auth_placeholder_in_decoded_token() {
        let b64 = base64::engine::general_purpose::STANDARD;

        let (child_env, resolver) = SecretResolver::from_provider_env(
            [("DB_PASSWORD".to_string(), "s3cret!".to_string())]
                .into_iter()
                .collect(),
        );
        let resolver = resolver.expect("resolver");
        let placeholder = child_env.get("DB_PASSWORD").unwrap();

        let credentials = format!("admin:{placeholder}");
        let encoded = b64.encode(credentials.as_bytes());

        let header_line = format!("Authorization: Basic {encoded}");
        let rewritten = rewrite_header_line(&header_line, &resolver);

        let rewritten_token = rewritten.strip_prefix("Authorization: Basic ").unwrap();
        let decoded = b64.decode(rewritten_token).unwrap();
        let decoded_str = std::str::from_utf8(&decoded).unwrap();

        assert_eq!(decoded_str, "admin:s3cret!");
        assert!(!rewritten.contains("openshell:resolve:env:"));
    }

    #[test]
    fn basic_auth_without_placeholder_unchanged() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("KEY".to_string(), "secret".to_string())]
                .into_iter()
                .collect(),
        );
        let resolver = resolver.expect("resolver");

        let b64 = base64::engine::general_purpose::STANDARD;
        let encoded = b64.encode(b"user:password");
        let header_line = format!("Authorization: Basic {encoded}");

        let rewritten = rewrite_header_line(&header_line, &resolver);
        assert_eq!(
            rewritten, header_line,
            "Should not modify non-placeholder Basic auth"
        );
    }

    #[test]
    fn basic_auth_full_round_trip_header_block() {
        let b64 = base64::engine::general_purpose::STANDARD;

        let (child_env, resolver) = SecretResolver::from_provider_env(
            [("REGISTRY_PASS".to_string(), "hunter2".to_string())]
                .into_iter()
                .collect(),
        );
        let placeholder = child_env.get("REGISTRY_PASS").unwrap();
        let credentials = format!("deploy:{placeholder}");
        let encoded = b64.encode(credentials.as_bytes());

        let raw = format!(
            "GET /v2/_catalog HTTP/1.1\r\n\
             Host: registry.example.com\r\n\
             Authorization: Basic {encoded}\r\n\
             Accept: application/json\r\n\r\n"
        );

        let result =
            rewrite_http_header_block(raw.as_bytes(), resolver.as_ref()).expect("should succeed");
        let rewritten = String::from_utf8(result.rewritten).expect("utf8");

        let auth_line = rewritten
            .lines()
            .find(|l| l.starts_with("Authorization:"))
            .unwrap();
        let token = auth_line.strip_prefix("Authorization: Basic ").unwrap();
        let decoded = b64.decode(token).unwrap();
        assert_eq!(std::str::from_utf8(&decoded).unwrap(), "deploy:hunter2");

        assert!(rewritten.contains("Host: registry.example.com\r\n"));
        assert!(rewritten.contains("Accept: application/json\r\n"));
        assert!(!rewritten.contains("openshell:resolve:env:"));
    }

    // === Percent encoding tests (absorbed from PR #631) ===

    #[test]
    fn percent_encode_preserves_unreserved() {
        assert_eq!(percent_encode_query("abc123-._~"), "abc123-._~");
    }

    #[test]
    fn percent_encode_encodes_special_chars() {
        assert_eq!(percent_encode_query("a b"), "a%20b");
        assert_eq!(percent_encode_query("key=val&x"), "key%3Dval%26x");
    }

    #[test]
    fn percent_decode_round_trips() {
        let original = "hello world & more=stuff";
        let encoded = percent_encode_query(original);
        let decoded = percent_decode(&encoded);
        assert_eq!(decoded, original);
    }

    // === URL path rewriting tests ===

    #[test]
    fn rewrite_path_single_segment_placeholder() {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            [("TOKEN".to_string(), "abc123".to_string())]
                .into_iter()
                .collect(),
        );
        let resolver = resolver.expect("resolver");
        let placeholder = child_env.get("TOKEN").unwrap();

        let raw = format!("GET /api/{placeholder}/data HTTP/1.1\r\nHost: x\r\n\r\n");
        let result =
            rewrite_http_header_block(raw.as_bytes(), Some(&resolver)).expect("should succeed");
        let rewritten = String::from_utf8(result.rewritten).expect("utf8");

        assert!(
            rewritten.starts_with("GET /api/abc123/data HTTP/1.1"),
            "Expected path rewritten, got: {rewritten}"
        );
        assert_eq!(
            result.redacted_target.as_deref(),
            Some("/api/[CREDENTIAL]/data")
        );
    }

    #[test]
    fn rewrite_path_telegram_style_concatenated() {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            [(
                "TELEGRAM_TOKEN".to_string(),
                "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11".to_string(),
            )]
            .into_iter()
            .collect(),
        );
        let resolver = resolver.expect("resolver");
        let placeholder = child_env.get("TELEGRAM_TOKEN").unwrap();

        let raw = format!(
            "POST /bot{placeholder}/sendMessage HTTP/1.1\r\nHost: api.telegram.org\r\n\r\n"
        );
        let result =
            rewrite_http_header_block(raw.as_bytes(), Some(&resolver)).expect("should succeed");
        let rewritten = String::from_utf8(result.rewritten).expect("utf8");

        assert!(
            rewritten.starts_with(
                "POST /bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11/sendMessage HTTP/1.1"
            ),
            "Expected Telegram-style path rewritten, got: {rewritten}"
        );
        assert_eq!(
            result.redacted_target.as_deref(),
            Some("/bot[CREDENTIAL]/sendMessage")
        );
    }

    #[test]
    fn rewrite_path_multiple_placeholders_in_separate_segments() {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            [
                ("ORG_ID".to_string(), "org-123".to_string()),
                ("API_KEY".to_string(), "key-456".to_string()),
            ]
            .into_iter()
            .collect(),
        );
        let resolver = resolver.expect("resolver");
        let org_ph = child_env.get("ORG_ID").unwrap();
        let key_ph = child_env.get("API_KEY").unwrap();

        let raw = format!("GET /orgs/{org_ph}/keys/{key_ph} HTTP/1.1\r\nHost: x\r\n\r\n");
        let result =
            rewrite_http_header_block(raw.as_bytes(), Some(&resolver)).expect("should succeed");
        let rewritten = String::from_utf8(result.rewritten).expect("utf8");

        assert!(
            rewritten.starts_with("GET /orgs/org-123/keys/key-456 HTTP/1.1"),
            "Expected both path segments rewritten, got: {rewritten}"
        );
    }

    #[test]
    fn rewrite_path_no_placeholders_unchanged() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("KEY".to_string(), "secret".to_string())]
                .into_iter()
                .collect(),
        );

        let raw = b"GET /v1/chat/completions HTTP/1.1\r\nHost: x\r\n\r\n";
        let result = rewrite_http_header_block(raw, resolver.as_ref()).expect("should succeed");
        assert_eq!(raw.as_slice(), result.rewritten.as_slice());
        assert!(result.redacted_target.is_none());
    }

    #[test]
    fn rewrite_path_preserves_query_params() {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            [("TOKEN".to_string(), "tok123".to_string())]
                .into_iter()
                .collect(),
        );
        let resolver = resolver.expect("resolver");
        let placeholder = child_env.get("TOKEN").unwrap();

        let raw = format!("GET /bot{placeholder}/method?format=json HTTP/1.1\r\nHost: x\r\n\r\n");
        let result =
            rewrite_http_header_block(raw.as_bytes(), Some(&resolver)).expect("should succeed");
        let rewritten = String::from_utf8(result.rewritten).expect("utf8");

        assert!(
            rewritten.starts_with("GET /bottok123/method?format=json HTTP/1.1"),
            "Expected path rewritten and query preserved, got: {rewritten}"
        );
    }

    #[test]
    fn rewrite_path_credential_traversal_rejected() {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            [("BAD".to_string(), "../admin".to_string())]
                .into_iter()
                .collect(),
        );
        let resolver = resolver.expect("resolver");
        let placeholder = child_env.get("BAD").unwrap();

        let raw = format!("GET /api/{placeholder}/data HTTP/1.1\r\nHost: x\r\n\r\n");
        let result = rewrite_http_header_block(raw.as_bytes(), Some(&resolver));
        assert!(
            result.is_err(),
            "Path traversal credential should be rejected"
        );
    }

    #[test]
    fn rewrite_path_credential_backslash_rejected() {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            [("BAD".to_string(), "foo\\bar".to_string())]
                .into_iter()
                .collect(),
        );
        let resolver = resolver.expect("resolver");
        let placeholder = child_env.get("BAD").unwrap();

        let raw = format!("GET /api/{placeholder} HTTP/1.1\r\nHost: x\r\n\r\n");
        let result = rewrite_http_header_block(raw.as_bytes(), Some(&resolver));
        assert!(
            result.is_err(),
            "Backslash in credential should be rejected"
        );
    }

    #[test]
    fn rewrite_path_credential_slash_rejected() {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            [("BAD".to_string(), "foo/bar".to_string())]
                .into_iter()
                .collect(),
        );
        let resolver = resolver.expect("resolver");
        let placeholder = child_env.get("BAD").unwrap();

        let raw = format!("GET /api/{placeholder} HTTP/1.1\r\nHost: x\r\n\r\n");
        let result = rewrite_http_header_block(raw.as_bytes(), Some(&resolver));
        assert!(
            result.is_err(),
            "Slash in path credential should be rejected"
        );
    }

    #[test]
    fn rewrite_path_credential_null_rejected() {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            [("BAD".to_string(), "foo\0bar".to_string())]
                .into_iter()
                .collect(),
        );
        let resolver = resolver.expect("resolver");
        let placeholder = child_env.get("BAD").unwrap();

        let raw = format!("GET /api/{placeholder} HTTP/1.1\r\nHost: x\r\n\r\n");
        // The null byte in the credential is caught by resolve_placeholder's
        // validate_resolved_secret, which returns None. This triggers the
        // unresolved placeholder path in rewrite_path_segment → fail-closed.
        let result = rewrite_http_header_block(raw.as_bytes(), Some(&resolver));
        assert!(
            result.is_err(),
            "Null byte in credential should be rejected"
        );
    }

    #[test]
    fn rewrite_path_percent_encodes_special_chars() {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            [("TOKEN".to_string(), "hello world".to_string())]
                .into_iter()
                .collect(),
        );
        let resolver = resolver.expect("resolver");
        let placeholder = child_env.get("TOKEN").unwrap();

        // Space in the credential should trigger path validation rejection
        // since space is safe to encode but the credential also doesn't
        // contain path-unsafe chars. Actually, space IS allowed (just encoded).
        // Let's test with a safe value that just needs encoding.
        let raw = format!("GET /api/{placeholder}/data HTTP/1.1\r\nHost: x\r\n\r\n");
        let result =
            rewrite_http_header_block(raw.as_bytes(), Some(&resolver)).expect("should succeed");
        let rewritten = String::from_utf8(result.rewritten).expect("utf8");

        assert!(
            rewritten.contains("/api/hello%20world/data"),
            "Expected percent-encoded path segment, got: {rewritten}"
        );
    }

    // === Fail-closed tests ===

    #[test]
    fn unresolved_header_placeholder_returns_error() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("KEY".to_string(), "secret".to_string())]
                .into_iter()
                .collect(),
        );

        let raw = b"GET / HTTP/1.1\r\nx-api-key: openshell:resolve:env:UNKNOWN_KEY\r\n\r\n";
        let result = rewrite_http_header_block(raw, resolver.as_ref());
        assert!(result.is_err(), "Unresolved header placeholder should fail");
    }

    #[test]
    fn unresolved_query_param_returns_error() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("KEY".to_string(), "secret".to_string())]
                .into_iter()
                .collect(),
        );

        let raw = b"GET /api?token=openshell:resolve:env:UNKNOWN HTTP/1.1\r\nHost: x\r\n\r\n";
        let result = rewrite_http_header_block(raw, resolver.as_ref());
        assert!(
            result.is_err(),
            "Unresolved query param placeholder should fail"
        );
    }

    #[test]
    fn unresolved_path_placeholder_returns_error() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("KEY".to_string(), "secret".to_string())]
                .into_iter()
                .collect(),
        );

        let raw = b"GET /api/openshell:resolve:env:UNKNOWN/data HTTP/1.1\r\nHost: x\r\n\r\n";
        let result = rewrite_http_header_block(raw, resolver.as_ref());
        assert!(result.is_err(), "Unresolved path placeholder should fail");
    }

    #[test]
    fn percent_encoded_placeholder_in_path_caught() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("KEY".to_string(), "secret".to_string())]
                .into_iter()
                .collect(),
        );

        // Percent-encode "openshell:resolve:env:UNKNOWN" in the path
        let encoded_placeholder = "openshell%3Aresolve%3Aenv%3AUNKNOWN";
        let raw = format!("GET /api/{encoded_placeholder}/data HTTP/1.1\r\nHost: x\r\n\r\n");
        let result = rewrite_http_header_block(raw.as_bytes(), resolver.as_ref());
        assert!(
            result.is_err(),
            "Percent-encoded placeholder should be caught by fail-closed scan"
        );
    }

    #[test]
    fn all_resolved_succeeds() {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            [
                ("KEY1".to_string(), "secret1".to_string()),
                ("KEY2".to_string(), "secret2".to_string()),
            ]
            .into_iter()
            .collect(),
        );
        let ph1 = child_env.get("KEY1").unwrap();
        let ph2 = child_env.get("KEY2").unwrap();

        let raw = format!(
            "GET /api/{ph1}?token={ph2} HTTP/1.1\r\n\
             x-auth: {ph1}\r\n\r\n"
        );
        let result =
            rewrite_http_header_block(raw.as_bytes(), resolver.as_ref()).expect("should succeed");
        let rewritten = String::from_utf8(result.rewritten).expect("utf8");

        assert!(!rewritten.contains("openshell:resolve:env:"));
        assert!(rewritten.contains("secret1"));
        assert!(rewritten.contains("secret2"));
    }

    #[test]
    fn no_resolver_passes_through_without_scanning() {
        // Even if placeholders are present, None resolver means no scanning
        let raw = b"GET /api/openshell:resolve:env:KEY HTTP/1.1\r\nHost: x\r\n\r\n";
        let result = rewrite_http_header_block(raw, None).expect("should succeed");
        assert_eq!(raw.as_slice(), result.rewritten.as_slice());
    }

    // === Redaction tests ===

    #[test]
    fn redacted_target_replaces_path_secrets_with_credential_marker() {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            [("TOKEN".to_string(), "real-secret".to_string())]
                .into_iter()
                .collect(),
        );
        let resolver = resolver.expect("resolver");
        let placeholder = child_env.get("TOKEN").unwrap();

        let result = rewrite_target_for_eval(&format!("/bot{placeholder}/sendMessage"), &resolver)
            .expect("should succeed");

        assert_eq!(result.redacted, "/bot[CREDENTIAL]/sendMessage");
        assert!(result.resolved.contains("real-secret"));
        assert!(!result.redacted.contains("real-secret"));
    }

    #[test]
    fn redacted_target_replaces_query_secrets_with_credential_marker() {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            [("KEY".to_string(), "secret123".to_string())]
                .into_iter()
                .collect(),
        );
        let resolver = resolver.expect("resolver");
        let placeholder = child_env.get("KEY").unwrap();

        let result =
            rewrite_target_for_eval(&format!("/api?key={placeholder}&format=json"), &resolver)
                .expect("should succeed");

        assert_eq!(result.redacted, "/api?key=[CREDENTIAL]&format=json");
        assert!(result.resolved.contains("secret123"));
        assert!(!result.redacted.contains("secret123"));
    }

    #[test]
    fn redacted_target_preserves_non_secret_segments() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("KEY".to_string(), "secret".to_string())]
                .into_iter()
                .collect(),
        );
        let resolver = resolver.expect("resolver");

        let result = rewrite_target_for_eval("/v1/chat/completions?format=json", &resolver)
            .expect("should succeed");

        assert_eq!(result.resolved, "/v1/chat/completions?format=json");
        assert_eq!(result.redacted, "/v1/chat/completions?format=json");
    }

    #[test]
    fn rewrite_target_for_eval_roundtrip() {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            [
                ("TOKEN".to_string(), "tok123".to_string()),
                ("KEY".to_string(), "key456".to_string()),
            ]
            .into_iter()
            .collect(),
        );
        let resolver = resolver.expect("resolver");
        let tok_ph = child_env.get("TOKEN").unwrap();
        let key_ph = child_env.get("KEY").unwrap();

        let target = format!("/bot{tok_ph}/method?key={key_ph}");
        let result = rewrite_target_for_eval(&target, &resolver).expect("should succeed");

        assert_eq!(result.resolved, "/bottok123/method?key=key456");
        assert_eq!(result.redacted, "/bot[CREDENTIAL]/method?key=[CREDENTIAL]");
    }
}
