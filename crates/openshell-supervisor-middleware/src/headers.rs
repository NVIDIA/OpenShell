// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Validation and logical application of HTTP middleware header mutations.

use openshell_core::{
    proto::{ExistingHeaderAction, HeaderMutation, HttpHeader, header_mutation},
    secrets::header_value_contains_reserved_credential_marker,
};

pub const MAX_HEADER_MUTATIONS: usize = 64;
pub const MAX_HEADER_MUTATION_BYTES: usize = 32 * 1024;

/// Selects the protected-header rules for the HTTP message being mutated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderAuthority {
    Request,
    Response,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderMutationError {
    TooMany { count: usize },
    InvalidName { name: String },
    Protected { name: String },
    HopByHop { name: String },
    UnsafeValue { name: String },
    CredentialPlaceholder { name: String },
    TooLarge,
    InvalidExistingAction,
    MissingExistingAction { name: String },
    UnsupportedExistingAction,
    Empty,
}

impl HeaderMutationError {
    /// Stable platform-owned reason suitable for untrusted middleware failures.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::TooMany { .. } => "header_mutation_count_over_capacity",
            Self::InvalidName { .. } => "header_mutation_invalid_name",
            Self::Protected { .. } => "header_mutation_protected_header",
            Self::HopByHop { .. } => "header_mutation_hop_by_hop_header",
            Self::UnsafeValue { .. } => "header_mutation_unsafe_value",
            Self::CredentialPlaceholder { .. } => "header_mutation_credential_placeholder",
            Self::TooLarge => "header_mutation_bytes_over_capacity",
            Self::InvalidExistingAction => "header_mutation_invalid_existing_action",
            Self::MissingExistingAction { .. } => "header_mutation_missing_existing_action",
            Self::UnsupportedExistingAction => "header_mutation_unsupported_existing_action",
            Self::Empty => "header_mutation_empty",
        }
    }
}

impl std::fmt::Display for HeaderMutationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooMany { count } => write!(
                formatter,
                "middleware returned too many header mutations: {count} exceeds {MAX_HEADER_MUTATIONS}"
            ),
            Self::InvalidName { name } => {
                write!(
                    formatter,
                    "middleware returned invalid header name '{name}'"
                )
            }
            Self::Protected { name } => {
                write!(
                    formatter,
                    "middleware cannot mutate protected header '{name}'"
                )
            }
            Self::HopByHop { name } => {
                write!(
                    formatter,
                    "middleware cannot mutate hop-by-hop header '{name}'"
                )
            }
            Self::UnsafeValue { name } => {
                write!(
                    formatter,
                    "middleware cannot write header '{name}' with an unsafe value"
                )
            }
            Self::CredentialPlaceholder { name } => write!(
                formatter,
                "middleware cannot write credential placeholder in header '{name}'"
            ),
            Self::TooLarge => write!(
                formatter,
                "middleware header mutations exceed {MAX_HEADER_MUTATION_BYTES} bytes"
            ),
            Self::InvalidExistingAction => {
                write!(formatter, "middleware returned invalid on_existing action")
            }
            Self::MissingExistingAction { name } => write!(
                formatter,
                "middleware must specify on_existing for header '{name}'"
            ),
            Self::UnsupportedExistingAction => {
                write!(
                    formatter,
                    "middleware returned unsupported on_existing action"
                )
            }
            Self::Empty => write!(formatter, "middleware returned an empty header mutation"),
        }
    }
}

impl std::error::Error for HeaderMutationError {}

/// Validate and atomically apply one middleware response to the logical header
/// state observed by the next middleware. Repeated values and wire order are
/// preserved; comparisons are case-insensitive.
pub fn apply(
    authority: HeaderAuthority,
    existing_headers: &[HttpHeader],
    connection_nominated_headers: &[String],
    mutations: &[HeaderMutation],
) -> Result<Vec<HttpHeader>, HeaderMutationError> {
    if mutations.len() > MAX_HEADER_MUTATIONS {
        return Err(HeaderMutationError::TooMany {
            count: mutations.len(),
        });
    }

    let mut headers = existing_headers.to_vec();
    let mut mutation_bytes = 0usize;
    for mutation in mutations {
        match mutation.operation.as_ref() {
            Some(header_mutation::Operation::Write(write)) => {
                let name = validate_name(&write.name)?;
                validate_authority(authority, MutationKind::Write, &write.name, &name)?;
                if is_connection_nominated(connection_nominated_headers, &name) {
                    return Err(HeaderMutationError::HopByHop {
                        name: write.name.clone(),
                    });
                }
                if !is_safe_value(&write.value) {
                    return Err(HeaderMutationError::UnsafeValue {
                        name: write.name.clone(),
                    });
                }
                if header_value_contains_reserved_credential_marker(&write.value) {
                    return Err(HeaderMutationError::CredentialPlaceholder {
                        name: write.name.clone(),
                    });
                }
                mutation_bytes = mutation_bytes
                    .saturating_add(name.len())
                    .saturating_add(write.value.len());
                enforce_size_limit(mutation_bytes)?;

                let action = ExistingHeaderAction::try_from(write.on_existing)
                    .map_err(|_| HeaderMutationError::InvalidExistingAction)?;
                if action == ExistingHeaderAction::Unspecified {
                    return Err(HeaderMutationError::MissingExistingAction {
                        name: write.name.clone(),
                    });
                }
                let exists = headers.iter().any(|existing| existing.name == name);
                if !exists || action == ExistingHeaderAction::Append {
                    headers.push(HttpHeader {
                        name,
                        value: write.value.clone(),
                    });
                } else if action == ExistingHeaderAction::Overwrite {
                    headers.retain(|existing| existing.name != name);
                    headers.push(HttpHeader {
                        name,
                        value: write.value.clone(),
                    });
                } else if action != ExistingHeaderAction::Skip {
                    return Err(HeaderMutationError::UnsupportedExistingAction);
                }
            }
            Some(header_mutation::Operation::Remove(remove)) => {
                let name = validate_name(&remove.name)?;
                validate_authority(authority, MutationKind::Remove, &remove.name, &name)?;
                if is_connection_nominated(connection_nominated_headers, &name) {
                    return Err(HeaderMutationError::HopByHop {
                        name: remove.name.clone(),
                    });
                }
                mutation_bytes = mutation_bytes.saturating_add(name.len());
                enforce_size_limit(mutation_bytes)?;
                headers.retain(|existing| existing.name != name);
            }
            None => return Err(HeaderMutationError::Empty),
        }
    }
    Ok(headers)
}

fn enforce_size_limit(mutation_bytes: usize) -> Result<(), HeaderMutationError> {
    if mutation_bytes > MAX_HEADER_MUTATION_BYTES {
        return Err(HeaderMutationError::TooLarge);
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<String, HeaderMutationError> {
    let lower = name.to_ascii_lowercase();
    if lower.is_empty() || !lower.bytes().all(is_name_token_byte) {
        return Err(HeaderMutationError::InvalidName {
            name: name.to_string(),
        });
    }
    Ok(lower)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MutationKind {
    Write,
    Remove,
}

fn validate_authority(
    authority: HeaderAuthority,
    kind: MutationKind,
    original_name: &str,
    normalized_name: &str,
) -> Result<(), HeaderMutationError> {
    let protected = match authority {
        HeaderAuthority::Request => is_request_protected(normalized_name),
        HeaderAuthority::Response => {
            is_response_protected(normalized_name)
                || (kind == MutationKind::Write && is_response_remove_only(normalized_name))
        }
    };
    if protected {
        return Err(HeaderMutationError::Protected {
            name: original_name.to_string(),
        });
    }
    Ok(())
}

fn is_name_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// A header value is safe to write only if it contains no control characters.
/// Horizontal tab, printable ASCII, and obs-text (>= 0x80) are permitted; CR, LF,
/// NUL, and other control bytes are rejected.
fn is_safe_value(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte) || byte >= 0x80)
}

fn is_request_protected(name: &str) -> bool {
    matches!(
        name,
        "authorization"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "cookie"
            | "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "proxy-connection"
            | "keep-alive"
            | "te"
            | "trailer"
            | "upgrade"
    ) || name.starts_with("x-amz-")
        || name.starts_with("x-openshell-credential")
}

fn is_response_protected(name: &str) -> bool {
    matches!(
        name,
        "authentication-info"
            | "connection"
            | "content-encoding"
            | "content-length"
            | "content-range"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authentication-info"
            | "proxy-authorization"
            | "proxy-connection"
            | "set-cookie"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "www-authenticate"
    ) || name.starts_with("x-openshell-credential")
}

fn is_response_remove_only(name: &str) -> bool {
    matches!(
        name,
        "accept-ranges"
            | "etag"
            | "content-md5"
            | "digest"
            | "content-digest"
            | "repr-digest"
            | "signature"
            | "signature-input"
    )
}

fn is_connection_nominated(connection_nominated_headers: &[String], name: &str) -> bool {
    connection_nominated_headers
        .iter()
        .any(|nominated| nominated.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{RemoveHeader, WriteHeader};

    fn write(name: &str, value: &str, on_existing: ExistingHeaderAction) -> HeaderMutation {
        HeaderMutation {
            operation: Some(header_mutation::Operation::Write(WriteHeader {
                name: name.into(),
                value: value.into(),
                on_existing: on_existing as i32,
            })),
        }
    }

    fn remove(name: &str) -> HeaderMutation {
        HeaderMutation {
            operation: Some(header_mutation::Operation::Remove(RemoveHeader {
                name: name.into(),
            })),
        }
    }

    fn header(name: &str, value: &str) -> HttpHeader {
        HttpHeader {
            name: name.into(),
            value: value.into(),
        }
    }

    #[test]
    fn protected_header_write_is_rejected() {
        let error = apply(
            HeaderAuthority::Request,
            &[],
            &[],
            &[write(
                "Authorization",
                "Bearer nope",
                ExistingHeaderAction::Overwrite,
            )],
        )
        .expect_err("protected header");
        assert!(
            error
                .to_string()
                .contains("protected header 'Authorization'")
        );
    }

    #[test]
    fn unsafe_header_value_is_rejected() {
        let error = apply(
            HeaderAuthority::Request,
            &[],
            &[],
            &[write(
                "x-openshell-middleware-inject",
                "ok\r\nAuthorization: Bearer evil",
                ExistingHeaderAction::Append,
            )],
        )
        .expect_err("CRLF value");
        assert!(error.to_string().contains("unsafe value"));
    }

    #[test]
    fn credential_placeholder_header_values_are_rejected() {
        for value in [
            "openshell:resolve:env:API_KEY",
            "Bearer openshell:resolve:env:API_KEY",
            "provider-OPENSHELL-RESOLVE-ENV-API_KEY",
            "openshell%3Aresolve%3Aenv%3AAPI_KEY",
            "Basic dXNlcjpvcGVuc2hlbGw6cmVzb2x2ZTplbnY6QVBJX0tFWQ==",
        ] {
            for authority in [HeaderAuthority::Request, HeaderAuthority::Response] {
                let error = apply(
                    authority,
                    &[],
                    &[],
                    &[write("x-api-key", value, ExistingHeaderAction::Overwrite)],
                )
                .expect_err("credential placeholder write");
                assert_eq!(
                    error,
                    HeaderMutationError::CredentialPlaceholder {
                        name: "x-api-key".to_string()
                    }
                );
            }
        }
    }

    #[test]
    fn existing_credential_placeholder_header_value_is_preserved() {
        let existing = [header("x-api-key", "openshell:resolve:env:API_KEY")];
        let updated = apply(
            HeaderAuthority::Request,
            &existing,
            &[],
            &[write(
                "cache-control",
                "no-store",
                ExistingHeaderAction::Overwrite,
            )],
        )
        .expect("ordinary mutation beside an existing placeholder");

        assert_eq!(
            updated,
            vec![
                header("x-api-key", "openshell:resolve:env:API_KEY"),
                header("cache-control", "no-store"),
            ]
        );
    }

    #[test]
    fn existing_header_write_obeys_collision_action() {
        let existing = [
            header("x-openshell-middleware-tag", "one"),
            header("accept", "application/json"),
        ];
        let appended = apply(
            HeaderAuthority::Request,
            &existing,
            &[],
            &[write(
                "X-OpenShell-Middleware-Tag",
                "two",
                ExistingHeaderAction::Append,
            )],
        )
        .expect("append existing header");
        assert_eq!(
            appended,
            vec![
                header("x-openshell-middleware-tag", "one"),
                header("accept", "application/json"),
                header("x-openshell-middleware-tag", "two"),
            ]
        );

        let overwritten = apply(
            HeaderAuthority::Request,
            &existing,
            &[],
            &[write(
                "X-OpenShell-Middleware-Tag",
                "two",
                ExistingHeaderAction::Overwrite,
            )],
        )
        .expect("overwrite existing header");
        assert_eq!(
            overwritten,
            vec![
                header("accept", "application/json"),
                header("x-openshell-middleware-tag", "two"),
            ]
        );

        let skipped = apply(
            HeaderAuthority::Request,
            &existing,
            &[],
            &[write(
                "X-OpenShell-Middleware-Tag",
                "two",
                ExistingHeaderAction::Skip,
            )],
        )
        .expect("skip existing header");
        assert_eq!(skipped, existing);
    }

    #[test]
    fn remove_drops_every_case_insensitive_value() {
        let existing = [
            header("x-trace", "one"),
            header("accept", "application/json"),
            header("x-trace", "two"),
        ];
        let updated = apply(
            HeaderAuthority::Request,
            &existing,
            &[],
            &[remove("X-Trace")],
        )
        .expect("remove visible header");
        assert_eq!(updated, vec![header("accept", "application/json")]);
    }

    #[test]
    fn protected_header_remove_is_rejected_even_when_not_visible() {
        let error = apply(
            HeaderAuthority::Request,
            &[],
            &[],
            &[remove("Authorization")],
        )
        .expect_err("protected removal");
        assert!(
            error
                .to_string()
                .contains("protected header 'Authorization'")
        );
    }

    #[test]
    fn connection_nominated_header_is_protected() {
        let nominated = vec!["x-openshell-middleware-tag".to_string()];
        let write_error = apply(
            HeaderAuthority::Request,
            &[],
            &nominated,
            &[write(
                "X-OpenShell-Middleware-Tag",
                "value",
                ExistingHeaderAction::Append,
            )],
        )
        .expect_err("hop-by-hop write");
        assert!(
            write_error
                .to_string()
                .contains("hop-by-hop header 'X-OpenShell-Middleware-Tag'")
        );

        let remove_error = apply(
            HeaderAuthority::Request,
            &[],
            &nominated,
            &[remove("X-OpenShell-Middleware-Tag")],
        )
        .expect_err("hop-by-hop removal");
        assert!(
            remove_error
                .to_string()
                .contains("hop-by-hop header 'X-OpenShell-Middleware-Tag'")
        );
    }

    #[test]
    fn request_write_accepts_end_to_end_header_without_namespace() {
        let updated = apply(
            HeaderAuthority::Request,
            &[],
            &[],
            &[write(
                "Cache-Control",
                "no-store",
                ExistingHeaderAction::Overwrite,
            )],
        )
        .expect("ordinary end-to-end request header");

        assert_eq!(updated, vec![header("cache-control", "no-store")]);
    }

    #[test]
    fn response_authority_allows_end_to_end_writes_and_integrity_removal() {
        let existing = [header("etag", "old"), header("content-type", "text/plain")];
        let updated = apply(
            HeaderAuthority::Response,
            &existing,
            &[],
            &[
                write("Cache-Control", "private", ExistingHeaderAction::Overwrite),
                remove("ETag"),
            ],
        )
        .expect("permitted response mutations");

        assert_eq!(
            updated,
            vec![
                header("content-type", "text/plain"),
                header("cache-control", "private"),
            ]
        );
    }

    #[test]
    fn response_authority_rejects_framing_and_integrity_writes() {
        for mutation in [
            remove("Content-Length"),
            write("ETag", "new", ExistingHeaderAction::Overwrite),
        ] {
            let error = apply(HeaderAuthority::Response, &[], &[], &[mutation])
                .expect_err("protected response mutation");
            assert!(matches!(error, HeaderMutationError::Protected { .. }));
        }
    }

    #[test]
    fn response_authority_protects_credential_headers_from_writes_and_removals() {
        let existing = [header("set-cookie", "session=upstream")];
        for name in [
            "Set-Cookie",
            "WWW-Authenticate",
            "Authentication-Info",
            "Proxy-Authentication-Info",
            "X-OpenShell-Credential-Token",
        ] {
            for mutation in [
                write(name, "planted", ExistingHeaderAction::Overwrite),
                remove(name),
            ] {
                let error = apply(HeaderAuthority::Response, &existing, &[], &[mutation])
                    .expect_err("credential response header mutation");
                assert_eq!(
                    error,
                    HeaderMutationError::Protected {
                        name: name.to_string()
                    }
                );
            }
        }
    }
}
