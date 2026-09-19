// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor middleware contracts and platform-wide limits.

use std::pin::Pin;
use std::time::Duration;

use miette::Result;
use tokio::sync::mpsc;
use tonic::{Request, Response, Status};

use crate::proto::{
    HttpEvent, HttpResult, MiddlewareManifest, ValidateConfigRequest, ValidateConfigResponse,
    WebSocketSessionEvent, WebSocketSessionEventResult,
};

/// Transport-neutral result stream for one HTTP middleware stage.
pub type HttpResultStream =
    Pin<Box<dyn tokio_stream::Stream<Item = Result<HttpResult, Status>> + Send + 'static>>;

/// Transport-neutral response stream for one WebSocket middleware stage.
pub type WebSocketResponseStream = Pin<
    Box<
        dyn tokio_stream::Stream<Item = Result<WebSocketSessionEventResult, Status>>
            + Send
            + 'static,
    >,
>;

/// A middleware implementation reachable either in-process or over a transport.
///
/// Capability is defined by the implementation's manifest. The endpoint hides
/// whether invocations are direct calls or serialized gRPC requests.
#[tonic::async_trait]
pub trait SupervisorMiddlewareEndpoint: Send + Sync {
    async fn describe(&self, request: Request<()>) -> Result<Response<MiddlewareManifest>, Status>;

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status>;

    async fn open_http_request_pre_credentials(
        &self,
        _requests: mpsc::Receiver<HttpEvent>,
    ) -> Result<HttpResultStream, Status> {
        Err(Status::unimplemented(
            "middleware does not implement HTTP request pre-credentials evaluation",
        ))
    }

    async fn open_websocket_session(
        &self,
        _requests: mpsc::Receiver<WebSocketSessionEvent>,
    ) -> Result<WebSocketResponseStream, Status> {
        Err(Status::unimplemented(
            "middleware does not implement WebSocket sessions",
        ))
    }

    async fn open_http_response_pre_return(
        &self,
        _requests: mpsc::Receiver<HttpEvent>,
    ) -> Result<HttpResultStream, Status> {
        Err(Status::unimplemented(
            "middleware does not implement HTTP response pre-return evaluation",
        ))
    }
}

/// Asynchronous contract for supervisor middleware that runs in-process.
///
/// Remote services use the protobuf `SupervisorMiddleware` contract instead.
/// HTTP and WebSocket operations use bounded channels and streams shared with
/// the transport-neutral endpoint contract.
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
/// use openshell_core::middleware::InProcessMiddleware;
/// use openshell_core::proto::{
///     HttpBodyMode, MiddlewareBinding, MiddlewareManifest, SupervisorMiddlewareOperation,
///     SupervisorMiddlewarePhase,
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
///                 max_payload_bytes: 1024,
///                 request_timeout: None,
///                 http_protocol_version: 1,
///                 supported_http_body_modes: vec![HttpBodyMode::Buffered as i32],
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

    /// Open one HTTP request pre-credentials stream.
    async fn open_http_request_pre_credentials(
        &self,
        _requests: mpsc::Receiver<HttpEvent>,
    ) -> std::result::Result<HttpResultStream, Status> {
        Err(Status::unimplemented(
            "middleware does not implement HTTP request pre-credentials evaluation",
        ))
    }

    /// Open one persistent WebSocket middleware session.
    ///
    /// HTTP-only implementations may keep the default unsupported response.
    async fn open_websocket_session(
        &self,
        _requests: mpsc::Receiver<WebSocketSessionEvent>,
    ) -> std::result::Result<WebSocketResponseStream, Status> {
        Err(Status::unimplemented(
            "middleware does not implement WebSocket sessions",
        ))
    }

    /// Open one HTTP response pre-return stream.
    ///
    /// Request-only implementations may keep the default unsupported response.
    async fn open_http_response_pre_return(
        &self,
        _requests: mpsc::Receiver<HttpEvent>,
    ) -> std::result::Result<HttpResultStream, Status> {
        Err(Status::unimplemented(
            "middleware does not implement HTTP response pre-return evaluation",
        ))
    }
}

/// Default timeout for one supervisor middleware RPC.
pub const DEFAULT_MIDDLEWARE_TIMEOUT: Duration = Duration::from_millis(500);
/// Smallest operator-configured supervisor middleware RPC timeout.
pub const MIN_MIDDLEWARE_TIMEOUT: Duration = Duration::from_millis(10);
/// Largest operator-configured supervisor middleware RPC timeout.
pub const MAX_MIDDLEWARE_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum time a complete message may spend in all middleware stages.
pub const MAX_MIDDLEWARE_CHAIN_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum time WebSocket preflight may delay an upstream handshake.
pub const MAX_MIDDLEWARE_PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(1);
/// Process-wide safety valve for concurrently buffered middleware work.
pub const MAX_CONCURRENT_MIDDLEWARE_WORK: usize = 32;
/// Process-wide safety valve for retained streaming middleware sessions.
///
/// A session consumes one permit regardless of its protocol or stage fan-out.
/// Persistent middleware protocols must acquire from this shared budget before
/// opening streams and retain the permit while any stage remains active.
pub const MAX_CONCURRENT_MIDDLEWARE_SESSIONS: usize = 32;

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
