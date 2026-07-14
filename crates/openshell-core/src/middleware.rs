// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Platform-wide supervisor middleware limits.

use std::time::Duration;

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
