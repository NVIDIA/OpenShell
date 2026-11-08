// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! gRPC authentication interceptor shared by CLI and TUI.

use miette::Result;

/// Interceptor that injects authentication headers into every outgoing gRPC request.
///
/// Supports application-layer Bearer tokens (standard `authorization`
/// header) and Cloudflare Access tokens (custom headers). When no token is
/// set, acts as a no-op. OIDC takes precedence over edge tokens.
#[derive(Clone)]
#[allow(clippy::struct_field_names)]
pub struct EdgeAuthInterceptor {
    bearer_value: Option<tonic::metadata::MetadataValue<tonic::metadata::Ascii>>,
    header_value: Option<tonic::metadata::MetadataValue<tonic::metadata::Ascii>>,
    cookie_value: Option<tonic::metadata::MetadataValue<tonic::metadata::Ascii>>,
}

impl EdgeAuthInterceptor {
    /// Create an interceptor from optional token strings.
    ///
    /// OIDC bearer tokens take precedence over edge tokens. Returns a no-op
    /// interceptor when no token is provided.
    pub fn new(oidc_token: Option<&str>, edge_token: Option<&str>) -> Result<Self> {
        if let Some(token) = oidc_token {
            let bearer: tonic::metadata::MetadataValue<tonic::metadata::Ascii> =
                format!("Bearer {token}")
                    .parse()
                    .map_err(|_| miette::miette!("invalid bearer token value"))?;
            return Ok(Self {
                bearer_value: Some(bearer),
                header_value: None,
                cookie_value: None,
            });
        }

        let (header_value, cookie_value) = match edge_token {
            Some(t) => {
                let hv: tonic::metadata::MetadataValue<tonic::metadata::Ascii> = t
                    .parse()
                    .map_err(|_| miette::miette!("invalid edge token value"))?;
                let cv: tonic::metadata::MetadataValue<tonic::metadata::Ascii> =
                    format!("CF_Authorization={t}")
                        .parse()
                        .map_err(|_| miette::miette!("invalid edge token value for cookie"))?;
                (Some(hv), Some(cv))
            }
            None => (None, None),
        };
        Ok(Self {
            bearer_value: None,
            header_value,
            cookie_value,
        })
    }

    /// No-op interceptor that passes requests through without modification.
    pub fn noop() -> Self {
        Self {
            bearer_value: None,
            header_value: None,
            cookie_value: None,
        }
    }
}

impl tonic::service::Interceptor for EdgeAuthInterceptor {
    fn call(
        &mut self,
        mut req: tonic::Request<()>,
    ) -> std::result::Result<tonic::Request<()>, tonic::Status> {
        if let Some(ref val) = self.bearer_value {
            req.metadata_mut().insert("authorization", val.clone());
        }
        if let Some(ref val) = self.header_value {
            req.metadata_mut()
                .insert("cf-access-jwt-assertion", val.clone());
        }
        if let Some(ref val) = self.cookie_value {
            req.metadata_mut().insert("cookie", val.clone());
        }
        Ok(req)
    }
}

/// Return the credential from an `authorization` header value that uses the
/// `Bearer` scheme.
///
/// The scheme is matched ASCII case-insensitively and may be followed by more
/// than one space (RFC 9110 section 11.1). The credential is returned
/// verbatim, so callers keep their own validation.
#[must_use]
pub fn strip_bearer_scheme(value: &str) -> Option<&str> {
    let (scheme, credential) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("Bearer")
        .then(|| credential.trim_start_matches(' '))
}

#[cfg(test)]
mod tests {
    use super::strip_bearer_scheme;

    #[test]
    fn bearer_scheme_is_case_insensitive() {
        for scheme in ["Bearer", "bearer", "BEARER", "bEaReR"] {
            assert_eq!(strip_bearer_scheme(&format!("{scheme} abc")), Some("abc"));
        }
    }

    #[test]
    fn bearer_scheme_allows_repeated_spaces() {
        assert_eq!(strip_bearer_scheme("Bearer   abc"), Some("abc"));
    }

    #[test]
    fn bearer_scheme_returns_credential_verbatim() {
        assert_eq!(strip_bearer_scheme("Bearer "), Some(""));
        assert_eq!(strip_bearer_scheme("Bearer a b"), Some("a b"));
        assert_eq!(strip_bearer_scheme("Bearer abc "), Some("abc "));
    }

    #[test]
    fn other_schemes_are_not_bearer() {
        for value in ["Basic abc", "Bearerabc", "Bearer", "", "Bearer\tabc", "abc"] {
            assert_eq!(strip_bearer_scheme(value), None, "{value:?}");
        }
    }
}
