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
//!   `;jsessionid` ACL-bypass mitigation). Stripping happens *before*
//!   dot-segment resolution so that `..;` cannot evade the traversal guard
//!   and then revert to `..` on the way out.
//! - Reject any `.`/`..` that survives to the end of canonicalization. The
//!   policy engine trusts this function to have removed them.
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
    #[error("request-target still contains a `.`/`..` segment after canonicalization")]
    ResidualDotSegment,
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

    // 4. Handle absolute-form by stripping the URI authority. Origin-form
    // targets may legitimately embed `://` in a path segment, so only a URI
    // with a scheme is absolute-form.
    let absolute_form_uri = path_part
        .parse::<http::Uri>()
        .ok()
        .filter(|uri| uri.scheme().is_some());
    let raw_path = absolute_form_uri
        .as_ref()
        .map(http::Uri::path)
        .filter(|path| !path.is_empty())
        .unwrap_or_else(|| {
            if absolute_form_uri.is_some() {
                "/"
            } else {
                path_part
            }
        });

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

    // 9. Split on literal `/`, then strip `;params` *before* resolving
    //    dot-segments. Stripping afterwards would let a `..;` segment slip
    //    past the traversal guard (it is not byte-equal to `..`) and then
    //    revert to a bare `..` during reconstruction.
    let segments = split_path_segments(&decoded);
    let segments: Vec<&[u8]> = if opts.strip_path_parameters {
        segments.into_iter().map(strip_path_parameters).collect()
    } else {
        segments
    };
    let resolved = resolve_dot_segments(segments)?;

    // 9b. Defense in depth: no `.`/`..` may survive canonicalization. The
    //     policy engine trusts this function to have removed them, so a
    //     residual dot-segment is always a bug or an attack. This also
    //     catches a `..` hidden behind a `%2F` sentinel on endpoints that
    //     opted into `allow_encoded_slash`, where the sentinel keeps the
    //     dot-segment inside its segment and out of `resolve_dot_segments`.
    for seg in &resolved {
        for part in seg.split(|&b| b == ENCODED_SLASH_SENTINEL) {
            if part == b".." || part == b"." {
                return Err(CanonicalizeError::ResidualDotSegment);
            }
        }
    }

    // 10. Reconstruct. Strip `;params` per segment if requested; re-encode
    //     any byte that must be percent-encoded in the pchar set.
    let canonical = build_canonical_path(&resolved, decoded.last().copied() == Some(b'/'), *opts);

    let rewritten = canonical != raw_path;
    Ok((
        CanonicalPath {
            path: canonical,
            rewritten,
        },
        query_part,
    ))
}

/// Report whether a canonical path carries a `%2F` that survived
/// canonicalization.
///
/// Callers that canonicalize before they know which endpoint config applies
/// use this to re-check the result against the config that actually matched.
///
/// The test is exact: [`build_canonical_path`] emits the literal `%2F` only
/// for the encoded-slash sentinel, and percent-encodes any other `%` byte as
/// `%25`, so no `%2F` substring can reach the output by another route.
#[must_use]
pub fn canonical_path_has_encoded_slash(canonical_path: &str) -> bool {
    canonical_path.contains("%2F")
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

/// Drop a trailing `;params` suffix from a single path segment.
fn strip_path_parameters(seg: &[u8]) -> &[u8] {
    seg.iter()
        .position(|&b| b == b';')
        .map_or(seg, |pos| &seg[..pos])
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
    opts: CanonicalizeOptions,
) -> String {
    let mut out = String::from("/");
    for (idx, seg) in segments.iter().enumerate() {
        if idx > 0 {
            out.push('/');
        }
        let trimmed: &[u8] = if opts.strip_path_parameters {
            strip_path_parameters(seg)
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
    fn origin_form_with_embedded_url_is_not_stripped_as_absolute_form() {
        let (path, query) = canonicalize_request_target(
            "/fetch/http://example.test?next=http://other.test",
            &CanonicalizeOptions::default(),
        )
        .expect("origin-form target with embedded URLs must be accepted");
        // Repeated slashes are canonicalized everywhere, but the embedded
        // URL must remain part of the origin-form path rather than being
        // treated as a new absolute-form authority.
        assert_eq!(path.path, "/fetch/http:/example.test");
        assert_eq!(query.as_deref(), Some("next=http://other.test"));
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

    // ---------------------------------------------------------------------
    // A `;params` suffix on the dot segment itself must not let the segment
    // slip past the traversal guard. Stripping used to run after dot-segment
    // resolution, so `..;` was not byte-equal to `..` when the guard looked
    // at it, and reverted to a bare `..` during reconstruction — handing the
    // policy engine and the upstream a path that still escaped its prefix.
    // ---------------------------------------------------------------------

    #[test]
    fn regression_dotdot_with_path_parameter_is_resolved_not_smuggled() {
        assert_eq!(canon("/public/..;/secret").unwrap(), "/secret");
        assert_eq!(canon("/public/..;x/secret").unwrap(), "/secret");
        assert_eq!(
            canon("/public/..;jsessionid=xyz/secret").unwrap(),
            "/secret"
        );
        assert_eq!(canon("/public/.;/secret").unwrap(), "/public/secret");
        assert_eq!(canon("/public/.;x/secret").unwrap(), "/public/secret");
    }

    #[test]
    fn regression_percent_encoded_dotdot_with_path_parameter() {
        // `%2e%2e;` and `..%3B` both decode to `..;` before segmentation.
        assert_eq!(canon("/public/%2e%2e;/secret").unwrap(), "/secret");
        assert_eq!(canon("/public/..%3B/secret").unwrap(), "/secret");
        assert_eq!(canon("/public/..%3b/secret").unwrap(), "/secret");
    }

    #[test]
    fn regression_chained_dotdot_with_path_parameters_hits_root_guard() {
        assert_eq!(
            canon("/public/..;/..;/secret"),
            Err(CanonicalizeError::TraversalAboveRoot)
        );
        assert_eq!(
            canon("/api/v1/..;/..;/..;/admin/keys"),
            Err(CanonicalizeError::TraversalAboveRoot)
        );
        assert_eq!(canon("/..;"), Err(CanonicalizeError::TraversalAboveRoot));
    }

    #[test]
    fn regression_dotdot_behind_encoded_slash_is_rejected_when_opted_in() {
        // With `allow_encoded_slash`, the `%2F` sentinel keeps the dot-segment
        // inside its segment, so `resolve_dot_segments` never sees it. The
        // residual guard is what closes this.
        let opts = CanonicalizeOptions {
            allow_encoded_slash: true,
            ..CanonicalizeOptions::default()
        };
        assert_eq!(
            canon_with("/public/..%2fsecret", opts),
            Err(CanonicalizeError::ResidualDotSegment)
        );
        assert_eq!(
            canon_with("/public/..%2f..%2fsecret", opts),
            Err(CanonicalizeError::ResidualDotSegment)
        );
        assert_eq!(
            canon_with("/public/.%2fsecret", opts),
            Err(CanonicalizeError::ResidualDotSegment)
        );
        // A legitimate encoded-slash slug still round-trips.
        assert_eq!(
            canon_with("/repos/group%2fproject/issues", opts).unwrap(),
            "/repos/group%2Fproject/issues"
        );
    }

    #[test]
    fn encoded_slash_detection_on_canonical_paths_is_exact() {
        let opts = CanonicalizeOptions {
            allow_encoded_slash: true,
            ..CanonicalizeOptions::default()
        };

        // A surviving sentinel is detected.
        let slug = canon_with("/repos/group%2fproject/issues", opts).unwrap();
        assert_eq!(slug, "/repos/group%2Fproject/issues");
        assert!(canonical_path_has_encoded_slash(&slug));

        // Ordinary paths are not.
        assert!(!canonical_path_has_encoded_slash(
            &canon("/public/secret").unwrap()
        ));

        // A literal `%` in the input is re-emitted as `%25`, so it cannot
        // fabricate a `%2F` substring — including when the input spells out
        // `%252F`, which decodes to the three characters `%`, `2`, `F`.
        let escaped = canon("/a/%252F/b").unwrap();
        assert_eq!(escaped, "/a/%252F/b");
        assert!(!canonical_path_has_encoded_slash(&escaped));

        let percent = canon("/a/100%25/b").unwrap();
        assert_eq!(percent, "/a/100%25/b");
        assert!(!canonical_path_has_encoded_slash(&percent));
    }

    #[test]
    fn canonical_output_never_contains_dot_segments() {
        // The contract the policy engine relies on: whatever comes back is
        // free of `.`/`..`, so rego never has to defend against them.
        for target in [
            "/public/..;/secret",
            "/public/.;/secret",
            "/public/%2e%2e;/secret",
            "/a;jsessionid=xyz/b",
            "/public//../secret",
            "/a/b/..",
            "/a/b/.",
        ] {
            if let Ok(path) = canon(target) {
                assert!(
                    !path.split('/').any(|seg| seg == ".." || seg == "."),
                    "{target} canonicalized to {path}, which still has a dot-segment"
                );
            }
        }
    }
}
