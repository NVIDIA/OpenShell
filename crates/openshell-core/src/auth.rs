// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! gRPC authentication interceptor shared by CLI and TUI.

use miette::Result;

/// Interceptor that injects authentication headers into every outgoing gRPC request.
///
/// Supports OIDC Bearer tokens (standard `authorization` header) and
/// Cloudflare Access tokens (custom headers). When no token is set, acts
/// as a no-op. OIDC takes precedence over edge tokens.
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
    /// OIDC bearer token takes precedence over edge token. Returns a no-op
    /// interceptor when neither token is provided.
    pub fn new(oidc_token: Option<&str>, edge_token: Option<&str>) -> Result<Self> {
        if let Some(token) = oidc_token {
            let bearer: tonic::metadata::MetadataValue<tonic::metadata::Ascii> =
                format!("Bearer {token}")
                    .parse()
                    .map_err(|_| miette::miette!("invalid OIDC token value"))?;
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
