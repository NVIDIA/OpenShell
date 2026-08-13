// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor middleware in-process contracts and platform-wide limits.

use std::time::Duration;

use miette::Result;

use crate::proto::{
    HttpHeader, HttpRequestResult, HttpRequestTarget, MiddlewareManifest, RequestContext,
    SupervisorMiddlewarePhase,
};

/// Borrowed request state exposed to one in-process middleware invocation.
///
/// The view reflects every transformation applied by earlier stages. It is valid
/// only for the current invocation and cannot be retained by the middleware.
#[derive(Clone, Copy)]
pub struct HttpRequestView<'a> {
    phase: SupervisorMiddlewarePhase,
    context: &'a RequestContext,
    config: &'a prost_types::Struct,
    target: &'a HttpRequestTarget,
    headers: &'a [HttpHeader],
    body: &'a [u8],
    middleware_name: &'a str,
}

impl<'a> HttpRequestView<'a> {
    /// Create a view over the chain's current request state for one stage.
    #[must_use]
    pub fn new(
        phase: SupervisorMiddlewarePhase,
        context: &'a RequestContext,
        config: &'a prost_types::Struct,
        target: &'a HttpRequestTarget,
        headers: &'a [HttpHeader],
        body: &'a [u8],
        middleware_name: &'a str,
    ) -> Self {
        Self {
            phase,
            context,
            config,
            target,
            headers,
            body,
            middleware_name,
        }
    }

    /// Return the typed middleware phase selected for this invocation.
    #[must_use]
    pub fn phase(self) -> SupervisorMiddlewarePhase {
        self.phase
    }

    /// Return the request and sandbox identity shared by every chain stage.
    #[must_use]
    pub fn context(self) -> &'a RequestContext {
        self.context
    }

    /// Return the validated configuration for this policy-selected stage.
    #[must_use]
    pub fn config(self) -> &'a prost_types::Struct {
        self.config
    }

    /// Return the admitted destination and HTTP request target.
    #[must_use]
    pub fn target(self) -> &'a HttpRequestTarget {
        self.target
    }

    /// Return visible request headers in wire order, including repeated names.
    #[must_use]
    pub fn headers(self) -> &'a [HttpHeader] {
        self.headers
    }

    /// Return the current body, including replacements made by earlier stages.
    #[must_use]
    pub fn body(self) -> &'a [u8] {
        self.body
    }

    /// Return the in-process middleware manifest or attachment name selected by
    /// policy, including custom implementation names.
    #[must_use]
    pub fn middleware_name(self) -> &'a str {
        self.middleware_name
    }
}

/// Asynchronous contract for supervisor middleware that runs in the process.
///
/// Remote services use the protobuf `SupervisorMiddleware` contract instead.
/// The borrowed view remains valid for the evaluation future, so implementations
/// can yield without constructing an owned protobuf request envelope.
///
/// Downstream implementations must apply `#[async_trait::async_trait]` to each
/// `impl InProcessMiddleware` block. The macro's default expansion creates
/// `Send` futures, matching this trait's generated method signatures; do not
/// use the `?Send` form.
///
/// An implementing crate must declare `async-trait` as a direct dependency
/// because `openshell-core`'s dependency does not make the procedural macro
/// available in downstream source. The example also names `miette` and
/// `prost-types`, so standalone crates must declare those dependencies when
/// using those paths.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
///
/// use miette::Result;
/// use openshell_core::middleware::{HttpRequestView, InProcessMiddleware};
/// use openshell_core::proto::{
///     Decision, HttpRequestResult, MiddlewareBinding, MiddlewareManifest,
///     SupervisorMiddlewareOperation, SupervisorMiddlewarePhase,
/// };
/// use prost_types::Struct;
///
/// struct Service;
///
/// #[async_trait::async_trait]
/// impl InProcessMiddleware for Service {
///     async fn describe(&self) -> MiddlewareManifest {
///         MiddlewareManifest {
///             name: "example/audit".into(),
///             service_version: "1".into(),
///             bindings: vec![MiddlewareBinding {
///                 operation: SupervisorMiddlewareOperation::HttpRequest as i32,
///                 phase: SupervisorMiddlewarePhase::PreCredentials as i32,
///                 max_body_bytes: 1024,
///                 timeout: String::new(),
///             }],
///             expected_audience: String::new(),
///         }
///     }
///
///     async fn validate_config(
///         &self,
///         _middleware_name: &str,
///         _config: &Struct,
///     ) -> Result<()> {
///         Ok(())
///     }
///
///     async fn evaluate_http_request(
///         &self,
///         _request: HttpRequestView<'_>,
///     ) -> Result<HttpRequestResult> {
///         Ok(HttpRequestResult {
///             decision: Decision::Allow as i32,
///             ..Default::default()
///         })
///     }
/// }
///
/// let service: Arc<dyn InProcessMiddleware> = Arc::new(Service);
/// assert_eq!(Arc::strong_count(&service), 1);
/// ```
#[async_trait::async_trait]
pub trait InProcessMiddleware: Send + Sync {
    /// Return the immutable manifest describing this implementation.
    async fn describe(&self) -> MiddlewareManifest;

    /// Validate implementation-owned configuration for one policy attachment.
    ///
    /// # Errors
    ///
    /// Returns an error when the implementation name is unknown or the
    /// configuration is malformed or unsupported.
    async fn validate_config(
        &self,
        middleware_name: &str,
        config: &prost_types::Struct,
    ) -> Result<()>;

    /// Evaluate one request using borrowed chain state.
    ///
    /// # Errors
    ///
    /// Returns an error when the selected implementation cannot evaluate the
    /// request or its validated configuration.
    async fn evaluate_http_request(
        &self,
        request: HttpRequestView<'_>,
    ) -> Result<HttpRequestResult>;
}

/// Default timeout for one supervisor middleware RPC.
pub const DEFAULT_MIDDLEWARE_TIMEOUT: Duration = Duration::from_millis(500);
/// Smallest operator-configured supervisor middleware RPC timeout.
pub const MIN_MIDDLEWARE_TIMEOUT: Duration = Duration::from_millis(10);
/// Largest operator-configured supervisor middleware RPC timeout.
pub const MAX_MIDDLEWARE_TIMEOUT: Duration = Duration::from_secs(30);

/// Largest number of middleware configurations accepted in one sandbox policy.
pub const MAX_MIDDLEWARE_CONFIGS: usize = 10;
/// Largest number of middleware stages selected for one request.
pub const MAX_MIDDLEWARE_CHAIN_STAGES: usize = MAX_MIDDLEWARE_CONFIGS;
/// Largest combined number of include and exclude patterns in one selector.
pub const MAX_MIDDLEWARE_SELECTOR_PATTERNS: usize = 32;
/// Largest number of findings accepted from one middleware stage.
pub const MAX_MIDDLEWARE_FINDINGS_PER_STAGE: usize = 32;
/// Largest number of findings retained and emitted for one complete chain.
pub const MAX_MIDDLEWARE_CHAIN_FINDINGS: usize =
    MAX_MIDDLEWARE_CHAIN_STAGES * MAX_MIDDLEWARE_FINDINGS_PER_STAGE;

/// Parse the middleware timeout syntax shared by gateway configuration and
/// supervisor runtime registrations.
///
/// Values use the same compact duration form as gateway interceptors: an
/// integer followed by `ms` or `s`.
pub fn parse_middleware_timeout(value: &str) -> Result<Duration, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("timeout must not be empty".to_string());
    }
    let timeout = if let Some(milliseconds) = value.strip_suffix("ms") {
        let milliseconds = milliseconds
            .parse::<u64>()
            .map_err(|_| format!("invalid timeout '{value}'"))?;
        Duration::from_millis(milliseconds)
    } else if let Some(seconds) = value.strip_suffix('s') {
        let seconds = seconds
            .parse::<u64>()
            .map_err(|_| format!("invalid timeout '{value}'"))?;
        Duration::from_secs(seconds)
    } else {
        return Err(format!(
            "invalid timeout '{value}'; expected suffix ms or s"
        ));
    };

    if timeout < MIN_MIDDLEWARE_TIMEOUT || timeout > MAX_MIDDLEWARE_TIMEOUT {
        return Err(format!("timeout '{value}' must be between 10ms and 30s"));
    }
    Ok(timeout)
}

/// Resolve an optional wire/config timeout, using the platform default when
/// the value is empty.
pub fn middleware_timeout_or_default(value: &str) -> Result<Duration, String> {
    if value.trim().is_empty() {
        Ok(DEFAULT_MIDDLEWARE_TIMEOUT)
    } else {
        parse_middleware_timeout(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_parser_matches_gateway_interceptor_duration_syntax() {
        assert_eq!(
            parse_middleware_timeout("500ms").unwrap(),
            Duration::from_millis(500)
        );
        assert_eq!(
            parse_middleware_timeout("2s").unwrap(),
            Duration::from_secs(2)
        );
        assert!(parse_middleware_timeout("2").is_err());
    }

    #[test]
    fn timeout_parser_enforces_inclusive_platform_bounds() {
        assert_eq!(
            parse_middleware_timeout("10ms").unwrap(),
            MIN_MIDDLEWARE_TIMEOUT
        );
        assert_eq!(
            parse_middleware_timeout("30s").unwrap(),
            MAX_MIDDLEWARE_TIMEOUT
        );
        assert!(parse_middleware_timeout("9ms").is_err());
        assert!(parse_middleware_timeout("30001ms").is_err());
    }

    #[test]
    fn empty_wire_timeout_uses_platform_default() {
        assert_eq!(
            middleware_timeout_or_default(""),
            Ok(DEFAULT_MIDDLEWARE_TIMEOUT)
        );
    }
}
