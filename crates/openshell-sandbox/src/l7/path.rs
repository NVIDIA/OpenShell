// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP request-target canonicalization for L7 policy enforcement.
//!
//! The L7 REST proxy evaluates OPA rules against the request path and
//! forwards the raw request line to the upstream server. If the path the
//! policy sees is not the path the upstream dispatches on, any path-based
//! allow rule can be bypassed with non-canonical encodings (`..`, `%2e%2e`,
//! `//`, `;params`). This module resolves that divergence by producing a
//! single canonical path that is both the input to policy evaluation and
//! the bytes written onto the wire.
//!
//! Behavior for v1:
//! - Percent-decode unreserved path bytes; preserve the rest as uppercase
//!   `%HH`.
//! - Resolve `.` and `..` segments per RFC 3986 Section 5.2.4. `..` that
//!   would escape the root is rejected rather than silently clamped to
//!   `/` — non-canonical input is almost always adversarial.
//! - Collapse repeated slashes.
//! - Reject control bytes (`0x00..=0x1F`, `0x7F`), fragments in the
//!   request-target, raw non-ASCII bytes, and paths that cannot be parsed
//!   as origin-form.
//! - Strip trailing `;params` from each segment by default (Tomcat-class
//!   `;jsessionid` ACL-bypass mitigation).
//! - Reject `%2F` (encoded slash) inside a segment by default. Operators
//!   can opt in per-endpoint for APIs that rely on encoded slashes in
//!   slugs.

use thiserror::Error;

/// Reasons a request-target can be rejected at the canonicalization boundary.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CanonicalizeError {
    #[error("request-target contains a null or control byte")]
    NullOrControlByte,
    #[error("request-target contains an invalid percent-encoded sequence")]
    InvalidPercentEncoding,
    #[error("request-target contains an encoded '/' (%2F) which is not allowed on this endpoint")]
    EncodedSlashNotAllowed,
    #[error("request-target contains a fragment")]
    FragmentInRequestTarget,
    #[error("request-target contains raw non-ASCII bytes; non-ASCII must be percent-encoded")]
    NonAscii,
    #[error("request-target's `..` segment would escape the path root")]
    TraversalAboveRoot,
    #[error("request-target exceeds the configured maximum length")]
    PathTooLong,
    #[error("request-target is not a valid origin-form path")]
    MalformedTarget,
}

/// Options controlling canonicalization strictness.
///
/// Produced by the endpoint configuration. Defaults are intentionally strict:
/// operators opt in to looser behavior per-endpoint when the upstream API
/// requires it.
#[derive(Debug, Clone, Copy)]
pub struct CanonicalizeOptions {
    /// When `true`, `%2F` inside a segment is preserved (re-emitted as
    /// `%2F` on the wire) rather than rejected. Defaults to `false`.
    pub allow_encoded_slash: bool,
    /// When `true`, RFC 3986 path parameters (`;param`) are stripped from
    /// each segment before policy evaluation and before forwarding.
    /// Defaults to `true`: path parameters are an ambiguity surface
    /// historically used to bypass ACLs and are not part of any policy
    /// we author.
    pub strip_path_parameters: bool,
}

impl Default for CanonicalizeOptions {
    fn default() -> Self {
        Self {
            allow_encoded_slash: false,
            strip_path_parameters: true,
        }
    }
}

/// Result of a successful canonicalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalPath {
    /// The canonical path. Always starts with `/`. Contains no `.`/`..`
    /// segments, no doubled slashes, and no `;params` (when stripping is
    /// enabled).
    pub path: String,
    /// `true` if the canonical form differs from the input. Callers use
    /// this to decide whether to rewrite the outbound request line.
    pub rewritten: bool,
}

/// Maximum accepted length of an origin-form path (bytes).
pub(crate) const MAX_PATH_LEN: usize = 4 * 1024;

/// Sentinel byte used to represent a `%2F`-decoded slash inside a segment.
/// Chosen from the C0 control range so no legitimate decoded byte collides
/// with it; any raw `0x01` in the input is rejected up front.
const ENCODED_SLASH_SENTINEL: u8 = 0x01;

/// Canonicalize an HTTP request-target's path component.
///
/// Accepts origin-form (`"/a/b?q=1"`) or absolute-form (`"http://h/a/b"`)
/// targets. Asterisk-form (`"*"`, used only for `OPTIONS *`) is rejected
/// because the L7 enforcement pipeline does not handle it.
///
/// Returns the canonical path plus the original query suffix (byte-for-byte
/// as supplied by the client). Query-parameter parsing is left to the
/// caller — this function only operates on the path component.
pub fn canonicalize_request_target(
    target: &str,
    opts: &CanonicalizeOptions,
) -> Result<(CanonicalPath, Option<String>), CanonicalizeError> {
    // 1. Reject control bytes and raw non-ASCII outright. These tests also
    //    cover CR/LF which are never legal in a single-line request-target.
    for &b in target.as_bytes() {
        if b == 0 || b == b'\n' || b == b'\r' || b == b'\t' || b == 0x7F {
            return Err(CanonicalizeError::NullOrControlByte);
        }
        if b < 0x20 {
            return Err(CanonicalizeError::NullOrControlByte);
        }
        if b >= 0x80 {
            return Err(CanonicalizeError::NonAscii);
        }
    }

    // 2. Reject fragments — forbidden in request-target per RFC 7230.
    if target.contains('#') {
        return Err(CanonicalizeError::FragmentInRequestTarget);
    }

    // 3. Split off query at the first `?`. Query is preserved verbatim.
    let (path_part, query_part) = match target.split_once('?') {
        Some((p, q)) => (p, Some(q.to_string())),
        None => (target, None),
    };

    // 4. Handle absolute-form by stripping scheme://authority.
    let raw_path = if let Some(idx) = path_part.find("://") {
        let after_scheme = &path_part[idx + 3..];
        match after_scheme.find('/') {
            Some(slash) => &after_scheme[slash..],
            None => "/",
        }
    } else {
        path_part
    };

    // 5. Empty is equivalent to "/".
    let raw_path = if raw_path.is_empty() { "/" } else { raw_path };

    // 6. Must begin with '/' (origin-form).
    if !raw_path.starts_with('/') {
        return Err(CanonicalizeError::MalformedTarget);
    }

    // 7. Length bound.
    if raw_path.len() > MAX_PATH_LEN {
        return Err(CanonicalizeError::PathTooLong);
    }

    // 8. Percent-decode the path into bytes. `%2F` is replaced by a
    //    sentinel byte so that subsequent `/` splitting cannot confuse it
    //    with a real path separator.
    let decoded = percent_decode_with_sentinel(raw_path.as_bytes(), opts.allow_encoded_slash)?;

    // 9. Split on literal `/` and resolve dot-segments.
    let segments = split_path_segments(&decoded);
    let resolved = resolve_dot_segments(segments)?;

    // 10. Reconstruct. Strip `;params` per segment if requested; re-encode
    //     any byte that must be percent-encoded in the pchar set.
    let canonical = build_canonical_path(&resolved, decoded.last().copied() == Some(b'/'), opts);

    let rewritten = canonical != raw_path;
    Ok((
        CanonicalPath {
            path: canonical,
            rewritten,
        },
        query_part,
    ))
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn percent_decode_with_sentinel(
    raw: &[u8],
    allow_encoded_slash: bool,
) -> Result<Vec<u8>, CanonicalizeError> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let b = raw[i];
        if b == ENCODED_SLASH_SENTINEL {
            // Raw sentinel byte in input — already rejected by the C0
            // control-byte sweep above, but double-check here to avoid
            // collisions in case the sweep is ever relaxed.
            return Err(CanonicalizeError::NullOrControlByte);
        }
        if b == b'%' {
            if i + 2 >= raw.len() {
                return Err(CanonicalizeError::InvalidPercentEncoding);
            }
            let decoded = match (decode_hex(raw[i + 1]), decode_hex(raw[i + 2])) {
                (Some(hi), Some(lo)) => (hi << 4) | lo,
                _ => return Err(CanonicalizeError::InvalidPercentEncoding),
            };
            if decoded == b'/' {
                if !allow_encoded_slash {
                    return Err(CanonicalizeError::EncodedSlashNotAllowed);
                }
                out.push(ENCODED_SLASH_SENTINEL);
            } else if decoded == 0 || decoded == 0x7F || (decoded < 0x20 && decoded != b'\t') {
                return Err(CanonicalizeError::NullOrControlByte);
            } else if decoded == b'\n' || decoded == b'\r' || decoded == b'\t' {
                // %-encoded CR/LF/TAB are still control bytes; reject.
                return Err(CanonicalizeError::NullOrControlByte);
            } else {
                out.push(decoded);
            }
            i += 3;
        } else {
            out.push(b);
            i += 1;
        }
    }
    Ok(out)
}

fn split_path_segments(decoded: &[u8]) -> Vec<&[u8]> {
    // decoded is guaranteed to start with `/`. Skip the leading `/` and
    // split on subsequent `/` bytes. The sentinel byte for encoded slashes
    // never matches, so it stays inside its segment.
    decoded[1..].split(|&b| b == b'/').collect()
}

fn resolve_dot_segments(segments: Vec<&[u8]>) -> Result<Vec<Vec<u8>>, CanonicalizeError> {
    let mut stack: Vec<Vec<u8>> = Vec::with_capacity(segments.len());
    let last = segments.len().saturating_sub(1);
    for (idx, seg) in segments.into_iter().enumerate() {
        if seg == b".." {
            if stack.pop().is_none() {
                return Err(CanonicalizeError::TraversalAboveRoot);
            }
            if idx == last {
                // A trailing `..` leaves a "directory" (trailing slash).
                stack.push(Vec::new());
            }
            continue;
        }
        if seg == b"." {
            if idx == last {
                stack.push(Vec::new());
            }
            continue;
        }
        if seg.is_empty() && idx != last {
            // Collapse repeated slashes except at the very end, where an
            // empty trailing segment encodes a trailing `/`.
            continue;
        }
        stack.push(seg.to_vec());
    }
    Ok(stack)
}

fn build_canonical_path(
    segments: &[Vec<u8>],
    _trailing_slash_hint: bool,
    opts: &CanonicalizeOptions,
) -> String {
    let mut out = String::from("/");
    for (idx, seg) in segments.iter().enumerate() {
        if idx > 0 {
            out.push('/');
        }
        let trimmed: &[u8] = if opts.strip_path_parameters {
            match seg.iter().position(|&b| b == b';') {
                Some(pos) => &seg[..pos],
                None => seg,
            }
        } else {
            seg
        };
        for &b in trimmed {
            if b == ENCODED_SLASH_SENTINEL {
                out.push_str("%2F");
            } else if is_pchar_unreserved(b) {
                out.push(b as char);
            } else {
                out.push('%');
                out.push(upper_hex_nibble(b >> 4));
                out.push(upper_hex_nibble(b & 0x0F));
            }
        }
    }
    out
}

fn is_pchar_unreserved(b: u8) -> bool {
    // RFC 3986 pchar without the percent-encoded slot — i.e. bytes we emit
    // literally. Unreserved plus RFC 3986 sub-delims plus `:` and `@`.
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
        )
}

fn decode_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn upper_hex_nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'A' + (n - 10)) as char,
        _ => unreachable!("nibble out of range"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(input: &str) -> Result<String, CanonicalizeError> {
        let opts = CanonicalizeOptions::default();
        canonicalize_request_target(input, &opts).map(|(p, _)| p.path)
    }

    fn canon_with(input: &str, opts: CanonicalizeOptions) -> Result<String, CanonicalizeError> {
        canonicalize_request_target(input, &opts).map(|(p, _)| p.path)
    }

    #[test]
    fn literal_dot_segments_resolve() {
        assert_eq!(canon("/a/./b").unwrap(), "/a/b");
        assert_eq!(canon("/a/b/.").unwrap(), "/a/b/");
        assert_eq!(canon("/a/../b").unwrap(), "/b");
        assert_eq!(canon("/a/b/..").unwrap(), "/a/");
    }

    #[test]
    fn percent_encoded_dot_segments_resolve_the_same_way() {
        assert_eq!(canon("/public/%2e%2e/secret").unwrap(), "/secret");
        assert_eq!(canon("/public/%2E%2E/secret").unwrap(), "/secret");
        assert_eq!(canon("/public/%2e/secret").unwrap(), "/public/secret");
    }

    #[test]
    fn traversal_above_root_is_rejected() {
        assert_eq!(canon("/.."), Err(CanonicalizeError::TraversalAboveRoot));
        assert_eq!(
            canon("/a/../.."),
            Err(CanonicalizeError::TraversalAboveRoot)
        );
        assert_eq!(
            canon("/a/%2e%2e/%2e%2e"),
            Err(CanonicalizeError::TraversalAboveRoot)
        );
    }

    #[test]
    fn doubled_slashes_collapse() {
        assert_eq!(canon("//").unwrap(), "/");
        assert_eq!(canon("//public//../secret").unwrap(), "/secret");
        assert_eq!(canon("/public//secret").unwrap(), "/public/secret");
    }

    #[test]
    fn encoded_slash_rejected_by_default() {
        assert_eq!(
            canon("/a/%2f/b"),
            Err(CanonicalizeError::EncodedSlashNotAllowed)
        );
        assert_eq!(
            canon("/public/..%2fsecret"),
            Err(CanonicalizeError::EncodedSlashNotAllowed)
        );
    }

    #[test]
    fn encoded_slash_preserved_when_opted_in() {
        let opts = CanonicalizeOptions {
            allow_encoded_slash: true,
            ..CanonicalizeOptions::default()
        };
        assert_eq!(canon_with("/a/%2f/b", opts).unwrap(), "/a/%2F/b");
        assert_eq!(canon_with("/a/%2F/b", opts).unwrap(), "/a/%2F/b");
    }

    #[test]
    fn null_and_control_bytes_rejected() {
        assert_eq!(canon("/a%00b"), Err(CanonicalizeError::NullOrControlByte));
        assert_eq!(canon("/a%0Ab"), Err(CanonicalizeError::NullOrControlByte));
        assert_eq!(canon("/a%0Db"), Err(CanonicalizeError::NullOrControlByte));
        assert_eq!(canon("/a%7Fb"), Err(CanonicalizeError::NullOrControlByte));
        // Raw CR/LF/TAB in input should also fail. Build strings via
        // byte-level concatenation since the literals in the source are
        // otherwise flagged as control bytes in CI.
        let mut raw = String::from("/a");
        raw.push('\n');
        raw.push('b');
        assert_eq!(canon(&raw), Err(CanonicalizeError::NullOrControlByte));
    }

    #[test]
    fn fragment_rejected() {
        assert_eq!(
            canon("/a#b"),
            Err(CanonicalizeError::FragmentInRequestTarget)
        );
    }

    #[test]
    fn absolute_form_strips_authority() {
        assert_eq!(canon("http://host/a/../b").unwrap(), "/b");
        assert_eq!(canon("https://host").unwrap(), "/");
        assert_eq!(canon("http://host:443/foo").unwrap(), "/foo");
    }

    #[test]
    fn legitimate_percent_encoded_bytes_round_trip() {
        assert_eq!(
            canon("/files/hello%20world.txt").unwrap(),
            "/files/hello%20world.txt"
        );
        assert_eq!(canon("/search/a%3Fb").unwrap(), "/search/a%3Fb");
        assert_eq!(canon("/users/%40alice").unwrap(), "/users/@alice");
    }

    #[test]
    fn path_parameters_stripped_by_default() {
        assert_eq!(canon("/a;jsessionid=xyz/b").unwrap(), "/a/b");
        assert_eq!(canon("/public;x=1/../secret").unwrap(), "/secret");
    }

    #[test]
    fn path_parameters_preserved_when_disabled() {
        let opts = CanonicalizeOptions {
            strip_path_parameters: false,
            ..CanonicalizeOptions::default()
        };
        assert_eq!(
            canon_with("/a;jsessionid=xyz/b", opts).unwrap(),
            "/a;jsessionid=xyz/b"
        );
    }

    #[test]
    fn non_ascii_raw_byte_rejected() {
        let mut raw = String::from("/a");
        raw.push('é');
        assert_eq!(canon(&raw), Err(CanonicalizeError::NonAscii));
    }

    #[test]
    fn percent_encoded_non_ascii_bytes_round_trip() {
        // `é` in UTF-8 is 0xC3 0xA9. The proxy treats the path as opaque
        // bytes; percent-encoded high bytes pass through unchanged.
        assert_eq!(canon("/users/caf%C3%A9").unwrap(), "/users/caf%C3%A9");
    }

    #[test]
    fn empty_and_root_equivalent() {
        assert_eq!(canon("").unwrap(), "/");
        assert_eq!(canon("/").unwrap(), "/");
    }

    #[test]
    fn path_too_long_rejected() {
        let long = format!("/{}", "a".repeat(MAX_PATH_LEN));
        assert_eq!(canon(&long), Err(CanonicalizeError::PathTooLong));
    }

    #[test]
    fn mixed_case_percent_normalizes_to_uppercase() {
        // Request comes in with lowercase %c3 — after canonicalization we
        // emit %C3 so policy authors don't need to enumerate both cases.
        assert_eq!(canon("/a/caf%c3%a9").unwrap(), "/a/caf%C3%A9");
    }

    #[test]
    fn rewritten_flag_reflects_transformation() {
        let (canon, _) =
            canonicalize_request_target("/a", &CanonicalizeOptions::default()).unwrap();
        assert!(!canon.rewritten);
        let (canon, _) =
            canonicalize_request_target("/a/../b", &CanonicalizeOptions::default()).unwrap();
        assert!(canon.rewritten);
    }

    #[test]
    fn query_suffix_is_returned_separately() {
        let (canon, query) =
            canonicalize_request_target("/a?q=1&r=2", &CanonicalizeOptions::default()).unwrap();
        assert_eq!(canon.path, "/a");
        assert_eq!(query.as_deref(), Some("q=1&r=2"));
    }

    // ---------------------------------------------------------------------
    // Regression tests for the documented attack payloads. Every one of
    // these used to bypass a `/public/**` allow rule because the proxy and
    // the OPA policy never agreed with the upstream on what path was being
    // dispatched.
    // ---------------------------------------------------------------------

    #[test]
    fn regression_public_slash_dotdot_secret() {
        assert_eq!(canon("/public/../secret").unwrap(), "/secret");
    }

    #[test]
    fn regression_public_slash_percent_dotdot_secret() {
        assert_eq!(canon("/public/%2e%2e/secret").unwrap(), "/secret");
        assert_eq!(canon("/public/%2E%2E/secret").unwrap(), "/secret");
    }

    #[test]
    fn regression_percent_encoded_slash_in_dotdot_rejected() {
        assert_eq!(
            canon("/public/%2E%2E%2Fsecret"),
            Err(CanonicalizeError::EncodedSlashNotAllowed)
        );
    }

    #[test]
    fn regression_double_slash_prefix() {
        assert_eq!(canon("//public/../secret").unwrap(), "/secret");
    }

    #[test]
    fn regression_dot_slash_dotdot() {
        assert_eq!(canon("/public/./../secret").unwrap(), "/secret");
    }
}
