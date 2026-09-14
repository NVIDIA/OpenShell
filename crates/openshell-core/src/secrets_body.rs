// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Metadata-only classification for REST bodies whose credential rewrite is disabled.

use super::{
    CREDENTIAL_MARKER_SCAN_TAIL_BYTES, PLACEHOLDER_PREFIX, PROVIDER_ALIAS_MARKER, SecretResolver,
    alias_env_key, is_alias_token_char, is_env_key_char, now_ms, placeholder_env_key,
    placeholder_for_env_key, revisioned_placeholder_parts, split_revisioned_env_key,
    stable_placeholder_parts, validate_resolved_secret,
};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

/// Why a reserved body token cannot be forwarded. Contains no request data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, miette::Diagnostic)]
pub enum BodyCredentialError {
    KnownUnavailable,
    ClassificationUnavailable,
    InvalidToken,
    TokenTooLong,
    Trailer,
}

impl BodyCredentialError {
    pub const fn reason(self) -> &'static str {
        match self {
            Self::KnownUnavailable => "known_unavailable",
            Self::ClassificationUnavailable => "classification_unavailable",
            Self::InvalidToken => "invalid_token",
            Self::TokenTooLong => "token_too_long",
            Self::Trailer => "trailer",
        }
    }
}

impl fmt::Display for BodyCredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "request body credential placeholder denied because rewrite is disabled ({})",
            self.reason()
        )
    }
}
impl std::error::Error for BodyCredentialError {}

#[derive(Clone, Copy)]
struct ValueStatus {
    valid: bool,
    expires_at_ms: i64,
}

/// Immutable classification snapshot. It deliberately contains no secret values.
#[derive(Clone, Default)]
pub struct BodyCredentialClassifier {
    values: HashMap<String, ValueStatus>,
    known: HashSet<String>,
    bound: HashSet<String>,
    revisions: HashMap<String, Arc<HashSet<u64>>>,
}

impl fmt::Debug for BodyCredentialClassifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BodyCredentialClassifier")
            .finish_non_exhaustive()
    }
}

impl BodyCredentialClassifier {
    pub(crate) fn new(
        resolver: Option<&SecretResolver>,
        known: HashSet<String>,
        bound: HashSet<String>,
        revisions: HashMap<String, Arc<HashSet<u64>>>,
    ) -> Self {
        let mut result = Self {
            known,
            bound,
            revisions,
            ..Self::default()
        };
        if let Some(resolver) = resolver {
            for (token, value) in &resolver.by_placeholder {
                if let Some(key) = placeholder_env_key(token) {
                    result.known.insert(key.to_owned());
                }
                result.values.insert(
                    token.clone(),
                    ValueStatus {
                        valid: validate_resolved_secret(&value.value).is_ok(),
                        expires_at_ms: value.expires_at_ms,
                    },
                );
            }
        }
        result
    }

    /// Authorize forwarding a complete token unchanged; never resolve it.
    pub fn check(&self, token: &str) -> Result<(), BodyCredentialError> {
        // Provider-shaped aliases use canonical-key fallback in the resolver.
        // Normalize that spelling here too, including revision/handle suffixes.
        if let Some(key) = alias_env_key(token) {
            return self.check(&placeholder_for_env_key(key));
        }
        let key = placeholder_env_key(token).ok_or(BodyCredentialError::InvalidToken)?;
        if key.is_empty() || !key.bytes().all(is_env_key_char) {
            return Err(BodyCredentialError::InvalidToken);
        }
        // Reserved identity namespaces must parse completely, including u64 overflow.
        if let Some(suffix) = token.strip_prefix(PLACEHOLDER_PREFIX)
            && split_revisioned_env_key(suffix).is_some()
            && revisioned_placeholder_parts(token).is_none()
        {
            return Err(BodyCredentialError::InvalidToken);
        }
        if let Some(suffix) = token.strip_prefix(PLACEHOLDER_PREFIX)
            && let Some((identity, underlying)) = suffix.split_once('_')
            && (identity.starts_with('v') || identity.starts_with('s'))
            && self.known.contains(underlying)
            && revisioned_placeholder_parts(token).is_none()
            && stable_placeholder_parts(token).is_none()
        {
            return Err(BodyCredentialError::KnownUnavailable);
        }
        if !self.known.contains(key) {
            return Ok(());
        }
        // A tombstone or a legacy unbound key is not a currently issued credential.
        // Destination membership does not matter: this guard never resolves body text.
        if !self.bound.contains(key) {
            return Err(BodyCredentialError::KnownUnavailable);
        }
        let revision = revisioned_placeholder_parts(token);
        if revision.is_none() && stable_placeholder_parts(token).is_none() {
            return Err(BodyCredentialError::KnownUnavailable);
        }
        if let Some((revision, _)) = revision
            && self
                .revisions
                .get(key)
                .is_none_or(|allowed| !allowed.contains(&revision))
        {
            return Err(BodyCredentialError::KnownUnavailable);
        }
        let value = self
            .values
            .get(token)
            .or_else(|| revision.and_then(|_| self.values.get(&placeholder_for_env_key(key))))
            .ok_or(BodyCredentialError::KnownUnavailable)?;
        if !value.valid || (value.expires_at_ms > 0 && value.expires_at_ms <= now_ms()) {
            return Err(BodyCredentialError::KnownUnavailable);
        }
        Ok(())
    }
}

/// Maximum retained candidate on the wire, including percent encoding.
const MAX_BODY_TOKEN_BYTES: usize = 4096;

/// Withholds complete reserved candidates while streaming unrelated body bytes.
#[derive(Default)]
pub struct BodyPlaceholderGuard<'a> {
    pending: Vec<u8>,
    classifier: Option<&'a BodyCredentialClassifier>,
    previous_decoded: Option<u8>,
}

impl<'a> BodyPlaceholderGuard<'a> {
    pub fn new(classifier: Option<&'a BodyCredentialClassifier>) -> Self {
        Self {
            classifier,
            ..Self::default()
        }
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<u8>, BodyCredentialError> {
        let mut output = Vec::new();
        // Bound pending storage even if the caller supplies an entire large body.
        for block in bytes.chunks(MAX_BODY_TOKEN_BYTES) {
            self.pending.extend_from_slice(block);
            output.extend(self.release(false)?);
        }
        Ok(output)
    }

    pub fn finish(mut self) -> Result<Vec<u8>, BodyCredentialError> {
        self.release(true)
    }

    fn release(&mut self, eof: bool) -> Result<Vec<u8>, BodyCredentialError> {
        // Track wire offsets so permitted bytes are released without normalization.
        let mut decoded = Vec::new();
        let mut offsets = Vec::new();
        let mut wire = 0;
        while wire < self.pending.len() {
            offsets.push(wire);
            if self.pending[wire] == b'%' {
                if wire + 2 >= self.pending.len() && !eof {
                    offsets.pop();
                    break;
                }
                if let Some(pair) = self.pending.get(wire + 1..wire + 3)
                    && let (Some(hi), Some(lo)) = (
                        (pair[0] as char).to_digit(16),
                        (pair[1] as char).to_digit(16),
                    )
                {
                    decoded.push(u8::try_from(hi * 16 + lo).expect("two hex digits fit a byte"));
                    wire += 3;
                    continue;
                }
            }
            decoded.push(self.pending[wire]);
            wire += 1;
        }
        offsets.push(wire);
        let mut safe = if eof {
            wire
        } else {
            wire.saturating_sub(CREDENTIAL_MARKER_SCAN_TAIL_BYTES)
        };
        let mut pos = 0;
        while pos < decoded.len() {
            let canonical = decoded[pos..].starts_with(PLACEHOLDER_PREFIX.as_bytes());
            let alias = decoded[pos..].starts_with(PROVIDER_ALIAS_MARKER.as_bytes());
            if !canonical && !alias {
                pos += 1;
                continue;
            }
            let start = pos;
            let key_start = pos
                + if canonical {
                    PLACEHOLDER_PREFIX.len()
                } else {
                    PROVIDER_ALIAS_MARKER.len()
                };
            let mut end = key_start;
            while end < decoded.len() && is_env_key_char(decoded[end]) {
                // Adjacent canonical references are separate tokens.
                if end > key_start && decoded[end..].starts_with(PLACEHOLDER_PREFIX.as_bytes()) {
                    break;
                }
                end += 1;
            }
            if offsets[end] - offsets[start] > MAX_BODY_TOKEN_BYTES {
                return Err(BodyCredentialError::TokenTooLong);
            }
            if end == decoded.len() && !eof {
                // Without metadata, preserve the prefix-only fail-closed behavior.
                if self.classifier.is_none() {
                    return Err(BodyCredentialError::ClassificationUnavailable);
                }
                safe = safe.min(offsets[start]);
                break;
            }
            if end == key_start {
                return Err(BodyCredentialError::InvalidToken);
            }
            let mut token = String::new();
            if alias {
                if decoded
                    .get(end)
                    .is_some_and(|byte| is_alias_token_char(*byte))
                {
                    return Err(BodyCredentialError::InvalidToken);
                }
                let previous = start
                    .checked_sub(1)
                    .map(|i| decoded[i])
                    .or(self.previous_decoded);
                if previous.is_none_or(|byte| !is_alias_token_char(byte)) {
                    return Err(BodyCredentialError::InvalidToken);
                }
                // Alias prefix spelling does not select the env key.
                token.push('x');
            }
            token.push_str(
                std::str::from_utf8(&decoded[start..end])
                    .map_err(|_| BodyCredentialError::InvalidToken)?,
            );
            self.classifier
                .ok_or(BodyCredentialError::ClassificationUnavailable)?
                .check(&token)?;
            safe = safe.max(offsets[end]);
            pos = end;
        }
        // Never split a percent triplet, which would change the next scan's view.
        let index = offsets
            .partition_point(|offset| *offset <= safe)
            .saturating_sub(1);
        safe = offsets[index];
        if index > 0 {
            self.previous_decoded = Some(decoded[index - 1]);
        }
        Ok(self.pending.drain(..safe).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_all(token: &str) -> String {
        use std::fmt::Write as _;
        let mut encoded = String::new();
        for byte in token.bytes() {
            write!(encoded, "%{byte:02X}").unwrap();
        }
        encoded
    }

    #[test]
    fn unknown_conversation_tokens_survive_every_wire_split() {
        let classifier = BodyCredentialClassifier::default();
        for token in [
            "openshell:resolve:env:KEY",
            "sk-OPENSHELL-RESOLVE-ENV-KEY",
            "openshell:resolve:env:v42_KEY",
            "openshell:resolve:env:s0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef_KEY",
        ] {
            for encoded in [false, true] {
                let token = if encoded {
                    encode_all(token)
                } else {
                    token.to_owned()
                };
                let body = format!("{{\"tool_output\":\"{} {token}\"}}", "a".repeat(100));
                for split in 0..=body.len() {
                    let mut guard = BodyPlaceholderGuard::new(Some(&classifier));
                    let mut output = guard.push(&body.as_bytes()[..split]).unwrap();
                    output.extend(guard.push(&body.as_bytes()[split..]).unwrap());
                    output.extend(guard.finish().unwrap());
                    assert_eq!(output, body.as_bytes(), "split {split}");
                }
            }
        }
    }

    #[test]
    fn issued_tokens_survive_every_wire_split_without_secret_substitution() {
        use crate::proto::{StaticCredentialBinding, StaticCredentialEndpointBinding};
        use crate::provider_credentials::ProviderCredentialState;
        for handle in [String::new(), "a".repeat(64)] {
            let state = ProviderCredentialState::from_bound_environment(
                42,
                HashMap::from([("KEY".into(), "private-test-secret".into())]),
                HashMap::new(),
                HashMap::new(),
                HashMap::from([(
                    "KEY".into(),
                    StaticCredentialBinding {
                        credential_identity: "provider".into(),
                        workload_credential_handle: handle,
                        endpoints: vec![StaticCredentialEndpointBinding {
                            host: "api.example.com".into(),
                            port: 443,
                            path: "/**".into(),
                        }],
                    },
                )]),
                vec![],
            )
            .unwrap();
            let token = state.snapshot().child_env["KEY"].clone();
            let alias = format!(
                "sk-OPENSHELL-RESOLVE-ENV-{}",
                token.strip_prefix(PLACEHOLDER_PREFIX).unwrap()
            );
            for host in ["api.example.com", "other.example.com"] {
                let (_, classifier, _) =
                    state.resolver_and_body_classifier_for_endpoint(host, 443, "/chat");
                for token in [&token, &alias] {
                    for wire_token in [token.clone(), encode_all(token), token.replace(':', "%3a")]
                    {
                        // JSON, arbitrary binary, and EOF-terminated tokens use the same streaming contract.
                        for body in [
                            format!(r#"{{"output":"{wire_token}"}}"#).into_bytes(),
                            [b"\xff\0".as_slice(), wire_token.as_bytes()].concat(),
                        ] {
                            for split in 0..=body.len() {
                                let mut guard = BodyPlaceholderGuard::new(classifier.as_deref());
                                let mut output = guard.push(&body[..split]).unwrap();
                                output.extend(guard.push(&body[split..]).unwrap());
                                output.extend(guard.finish().unwrap());
                                assert_eq!(output, body, "host {host}, split {split}");
                                assert!(
                                    !String::from_utf8_lossy(&output)
                                        .contains("private-test-secret")
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn unavailable_tokens_never_release_the_marker_at_any_split() {
        let classifier = BodyCredentialClassifier {
            known: HashSet::from(["KEY".to_owned()]),
            ..BodyCredentialClassifier::default()
        };
        for token in ["openshell:resolve:env:KEY", "sk-OPENSHELL-RESOLVE-ENV-KEY"] {
            for token in [token.to_owned(), encode_all(token)] {
                let body = format!("{} {token}!", "safe ".repeat(100));
                for split in 0..body.len() {
                    let mut guard = BodyPlaceholderGuard::new(Some(&classifier));
                    match guard.push(&body.as_bytes()[..split]) {
                        Err(error) => assert_eq!(error, BodyCredentialError::KnownUnavailable),
                        Ok(output) => {
                            assert!(!super::super::contains_reserved_credential_marker_bytes(
                                &output
                            ));
                            assert_eq!(
                                guard.push(&body.as_bytes()[split..]).unwrap_err(),
                                BodyCredentialError::KnownUnavailable
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn eof_adjacent_tokens_and_binary_surroundings_preserve_bytes() {
        let classifier = BodyCredentialClassifier::default();
        for body in [
            b"\xff\0openshell:resolve:env:KEY".as_slice(),
            b"openshell:resolve:env:KEYopenshell:resolve:env:OTHER",
            b"partial openshell:res",
            b"openshell%3Aresolve:env:KEY%21",
        ] {
            let mut guard = BodyPlaceholderGuard::new(Some(&classifier));
            let mut output = Vec::new();
            for byte in body {
                output.extend(guard.push(&[*byte]).unwrap());
            }
            output.extend(guard.finish().unwrap());
            assert_eq!(output, body);
        }
    }

    #[test]
    fn malformed_and_oversized_candidates_fail_closed() {
        let classifier = BodyCredentialClassifier::default();
        for token in [
            "openshell:resolve:env:",
            "OPENSHELL-RESOLVE-ENV-KEY",
            "sk-OPENSHELL-RESOLVE-ENV-KEY-suffix",
        ] {
            let mut guard = BodyPlaceholderGuard::new(Some(&classifier));
            let result = guard.push(token.as_bytes()).and_then(|_| guard.finish());
            assert_eq!(result.unwrap_err(), BodyCredentialError::InvalidToken);
        }
        let mut guard = BodyPlaceholderGuard::new(Some(&classifier));
        let oversized = format!("openshell:resolve:env:{}", "A".repeat(MAX_BODY_TOKEN_BYTES));
        assert_eq!(
            guard.push(oversized.as_bytes()).unwrap_err(),
            BodyCredentialError::TokenTooLong
        );
        let mut guard = BodyPlaceholderGuard::new(Some(&classifier));
        for _ in 0..1000 {
            guard.push(&[b'x'; 1000]).unwrap();
            assert!(guard.pending.len() <= CREDENTIAL_MARKER_SCAN_TAIL_BYTES);
        }
    }

    #[test]
    fn missing_metadata_denies_without_releasing_marker() {
        let mut guard = BodyPlaceholderGuard::default();
        assert!(guard.push(b"openshell:res").unwrap().is_empty());
        assert_eq!(
            guard.push(b"olve:env:KEY").unwrap_err(),
            BodyCredentialError::ClassificationUnavailable
        );
    }
}
