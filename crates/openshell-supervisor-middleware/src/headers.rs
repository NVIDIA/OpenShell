// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Validation and logical application of middleware request-header mutations.

use openshell_core::proto::{ExistingHeaderAction, HeaderMutation, header_mutation};

pub const MAX_HEADER_MUTATIONS: usize = 64;
pub const MAX_HEADER_MUTATION_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderMutationError {
    TooMany { count: usize },
    InvalidName { name: String },
    Protected { name: String },
    HopByHop { name: String },
    WriteNamespace { name: String },
    UnsafeValue { name: String },
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
            Self::WriteNamespace { .. } => "header_mutation_write_namespace",
            Self::UnsafeValue { .. } => "header_mutation_unsafe_value",
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
            Self::WriteNamespace { name } => write!(
                formatter,
                "middleware can only write request headers prefixed with x-openshell-middleware- and cannot write '{name}'"
            ),
            Self::UnsafeValue { name } => {
                write!(
                    formatter,
                    "middleware cannot write header '{name}' with an unsafe value"
                )
            }
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
    existing_headers: &[(String, String)],
    connection_nominated_headers: &[String],
    mutations: &[HeaderMutation],
) -> Result<Vec<(String, String)>, HeaderMutationError> {
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
                if is_connection_nominated(connection_nominated_headers, &name) {
                    return Err(HeaderMutationError::HopByHop {
                        name: write.name.clone(),
                    });
                }
                if !name.starts_with("x-openshell-middleware-") {
                    return Err(HeaderMutationError::WriteNamespace {
                        name: write.name.clone(),
                    });
                }
                if !is_safe_value(&write.value) {
                    return Err(HeaderMutationError::UnsafeValue {
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
                let exists = headers.iter().any(|(existing, _)| *existing == name);
                if !exists || action == ExistingHeaderAction::Append {
                    headers.push((name, write.value.clone()));
                } else if action == ExistingHeaderAction::Overwrite {
                    headers.retain(|(existing, _)| *existing != name);
                    headers.push((name, write.value.clone()));
                } else if action != ExistingHeaderAction::Skip {
                    return Err(HeaderMutationError::UnsupportedExistingAction);
                }
            }
            Some(header_mutation::Operation::Remove(remove)) => {
                let name = validate_name(&remove.name)?;
                if is_connection_nominated(connection_nominated_headers, &name) {
                    return Err(HeaderMutationError::HopByHop {
                        name: remove.name.clone(),
                    });
                }
                mutation_bytes = mutation_bytes.saturating_add(name.len());
                enforce_size_limit(mutation_bytes)?;
                headers.retain(|(existing, _)| *existing != name);
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
    if is_protected(&lower) {
        return Err(HeaderMutationError::Protected {
            name: name.to_string(),
        });
    }
    Ok(lower)
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

fn is_protected(name: &str) -> bool {
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

    #[test]
    fn protected_header_write_is_rejected() {
        let error = apply(
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
    fn existing_header_write_obeys_collision_action() {
        let existing = [
            ("x-openshell-middleware-tag".to_string(), "one".to_string()),
            ("accept".to_string(), "application/json".to_string()),
        ];
        let appended = apply(
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
                ("x-openshell-middleware-tag".into(), "one".into()),
                ("accept".into(), "application/json".into()),
                ("x-openshell-middleware-tag".into(), "two".into()),
            ]
        );

        let overwritten = apply(
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
                ("accept".into(), "application/json".into()),
                ("x-openshell-middleware-tag".into(), "two".into()),
            ]
        );

        let skipped = apply(
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
            ("x-trace".to_string(), "one".to_string()),
            ("accept".to_string(), "application/json".to_string()),
            ("x-trace".to_string(), "two".to_string()),
        ];
        let updated = apply(&existing, &[], &[remove("X-Trace")]).expect("remove visible header");
        assert_eq!(updated, vec![("accept".into(), "application/json".into())]);
    }

    #[test]
    fn protected_header_remove_is_rejected_even_when_not_visible() {
        let error = apply(&[], &[], &[remove("Authorization")]).expect_err("protected removal");
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

        let remove_error = apply(&[], &nominated, &[remove("X-OpenShell-Middleware-Tag")])
            .expect_err("hop-by-hop removal");
        assert!(
            remove_error
                .to_string()
                .contains("hop-by-hop header 'X-OpenShell-Middleware-Tag'")
        );
    }
}
