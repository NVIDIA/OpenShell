// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Privacy scanner provider for outbound HTTP request bodies.
//!
//! The default provider is an in-process, dependency-light regex scanner. A
//! deployment can also configure a remote HTTP provider for custom scanning
//! logic. Either way, this module returns the exact body bytes the proxy should
//! relay upstream.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use regex::{Regex, RegexBuilder};
use serde_json::Value;
use tracing::{debug, warn};

const MAX_CUSTOM_PATTERNS: usize = 128;
const MAX_CUSTOM_LABEL_BYTES: usize = 64;
const MAX_CUSTOM_REGEX_BYTES: usize = 4096;
const MAX_CUSTOM_CONTENT_TYPES: usize = 16;
const MAX_CUSTOM_CONTENT_TYPE_BYTES: usize = 128;
const CREDIT_CARD_LABEL: &str = "credit_card";
const BUILTIN_REGEX_BACKEND: &str = "builtin_regex";
const REMOTE_HTTP_BACKEND: &str = "remote_http";
const FAIL_OPEN_BACKEND: &str = "fail_open";
const DEFAULT_REMOTE_TIMEOUT_MS: u64 = 2_000;
const MAX_REMOTE_TIMEOUT_MS: u64 = 30_000;
const REMOTE_FAILURE_THRESHOLD: usize = 5;
const REMOTE_FAILURE_WINDOW: Duration = Duration::from_secs(30);
const REMOTE_OPEN_DURATION: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
struct Entity {
    label: String,
    start: usize,
    end: usize,
}

#[derive(Debug, Clone)]
struct Pattern {
    label: String,
    regex: Regex,
    content_types: Vec<String>,
}

#[derive(Debug, Clone)]
struct ContextPattern {
    label: String,
    path_regex: Regex,
    value_regex: Regex,
    content_types: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct CompiledCustomPatterns {
    regex_patterns: Vec<Pattern>,
    context_patterns: Vec<ContextPattern>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScannerConfig {
    backend: ScannerBackend,
    fallback: ScannerFallback,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ScannerBackend {
    BuiltinRegex,
    RemoteHttp(RemoteHttpScannerConfig),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteHttpScannerConfig {
    url: String,
    timeout_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScannerFallback {
    BuiltinRegex,
    FailOpen,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerConfigSummary {
    pub backend: String,
    pub remote_url: Option<String>,
    pub fallback: String,
}

#[derive(Debug, Clone, Copy)]
pub struct PrivacyScanRequestContext<'a> {
    pub method: &'a str,
    pub scheme: &'a str,
    pub host: &'a str,
    pub port: u16,
    pub path: &'a str,
}

#[derive(Debug, Default)]
struct RemoteCircuitBreaker {
    failures: Vec<Instant>,
    opened_until: Option<Instant>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyScanConfigError {
    message: String,
}

impl PrivacyScanConfigError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for PrivacyScanConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(f)
    }
}

impl std::error::Error for PrivacyScanConfigError {}

type ConfigResult<T> = Result<T, PrivacyScanConfigError>;

/// Result of an embedded privacy scan.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub replacement_body: Vec<u8>,
    pub redacted: bool,
    pub matches: Vec<String>,
    pub match_count: usize,
    pub elapsed_ms: f64,
    pub backend: String,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            backend: ScannerBackend::BuiltinRegex,
            fallback: ScannerFallback::BuiltinRegex,
        }
    }
}

impl ScannerConfig {
    fn summary(&self) -> ScannerConfigSummary {
        match &self.backend {
            ScannerBackend::BuiltinRegex => ScannerConfigSummary {
                backend: BUILTIN_REGEX_BACKEND.to_string(),
                remote_url: None,
                fallback: self.fallback.as_str().to_string(),
            },
            ScannerBackend::RemoteHttp(remote) => ScannerConfigSummary {
                backend: REMOTE_HTTP_BACKEND.to_string(),
                remote_url: Some(remote.url.clone()),
                fallback: self.fallback.as_str().to_string(),
            },
        }
    }
}

impl ScannerFallback {
    const fn as_str(self) -> &'static str {
        match self {
            Self::BuiltinRegex => BUILTIN_REGEX_BACKEND,
            Self::FailOpen => FAIL_OPEN_BACKEND,
        }
    }
}

impl RemoteCircuitBreaker {
    fn allow_request(&mut self, now: Instant) -> bool {
        if let Some(opened_until) = self.opened_until {
            if opened_until > now {
                return false;
            }
            self.opened_until = None;
            self.failures.clear();
        }
        true
    }

    fn record_success(&mut self) {
        self.failures.clear();
        self.opened_until = None;
    }

    fn record_failure(&mut self, now: Instant) {
        self.failures
            .retain(|failure| now.duration_since(*failure) <= REMOTE_FAILURE_WINDOW);
        self.failures.push(now);
        if self.failures.len() >= REMOTE_FAILURE_THRESHOLD {
            self.opened_until = Some(now + REMOTE_OPEN_DURATION);
            self.failures.clear();
        }
    }

    fn reset(&mut self) {
        self.failures.clear();
        self.opened_until = None;
    }
}

/// Replace the process-wide custom regex set.
///
/// `None` or an empty string clears the custom set. Invalid config is returned
/// as an error and does not change the last-known-good compiled set.
pub fn set_custom_patterns_from_json(raw: Option<&str>) -> ConfigResult<usize> {
    let compiled = match raw.map(str::trim).filter(|value| !value.is_empty()) {
        Some(raw) => compile_custom_patterns_from_json(raw)?,
        None => CompiledCustomPatterns::default(),
    };
    let count = compiled.len();
    let mut guard = custom_patterns_store()
        .write()
        .map_err(|_| PrivacyScanConfigError::new("custom privacy scan pattern lock poisoned"))?;
    *guard = Arc::new(compiled);
    Ok(count)
}

/// Replace the process-wide Privacy Scanner provider config.
///
/// `None` or an empty string restores the built-in regex scanner. Invalid
/// config is returned as an error and does not change the last-known-good
/// provider config.
pub fn set_scanner_config_from_json(raw: Option<&str>) -> ConfigResult<ScannerConfigSummary> {
    let config = match raw.map(str::trim).filter(|value| !value.is_empty()) {
        Some(raw) => compile_scanner_config_from_json(raw)?,
        None => ScannerConfig::default(),
    };
    let summary = config.summary();
    let mut guard = scanner_config_store()
        .write()
        .map_err(|_| PrivacyScanConfigError::new("privacy scanner config lock poisoned"))?;
    *guard = Arc::new(config);
    reset_remote_circuit();
    Ok(summary)
}

/// Scan and redact a request body. JSON bodies are parsed recursively and only
/// string values are redacted. Non-JSON bodies are treated as UTF-8 text.
pub fn scan_body(content_type: &str, raw: &[u8]) -> ScanResult {
    let custom = custom_patterns_snapshot();
    scan_body_with_custom_patterns(content_type, raw, custom.as_ref())
}

/// Scan and redact a request body with the configured scanner provider.
///
/// The default provider is the built-in regex scanner. When a remote HTTP
/// provider is configured, the supervisor posts the body to that provider and
/// uses the returned body. Remote failures are bounded by a timeout and circuit
/// breaker, then fall back according to the configured fallback mode.
pub async fn scan_body_for_request(
    context: PrivacyScanRequestContext<'_>,
    content_type: &str,
    raw: &[u8],
) -> ScanResult {
    let started = Instant::now();
    let config = scanner_config_snapshot();

    match &config.backend {
        ScannerBackend::BuiltinRegex => {
            let mut result = scan_body(content_type, raw);
            result.elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
            result
        }
        ScannerBackend::RemoteHttp(remote) => {
            if !remote_circuit_allows_request() {
                debug!(
                    scanner_url = %remote.url,
                    "Privacy scanner remote HTTP circuit is open; using fallback"
                );
                return fallback_scan(content_type, raw, config.fallback, started);
            }

            match scan_remote_http(remote, context, content_type, raw).await {
                Ok(mut result) => {
                    record_remote_success();
                    result.elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
                    result
                }
                Err(error) => {
                    record_remote_failure();
                    warn!(
                        scanner_url = %remote.url,
                        error = %error,
                        "Privacy scanner remote HTTP provider failed; using fallback"
                    );
                    fallback_scan(content_type, raw, config.fallback, started)
                }
            }
        }
    }
}

fn scan_body_with_custom_patterns(
    content_type: &str,
    raw: &[u8],
    custom: &CompiledCustomPatterns,
) -> ScanResult {
    let started = Instant::now();
    let mut entities = Vec::new();
    let replacement_body = if content_type
        .to_ascii_lowercase()
        .contains("application/json")
    {
        match scan_json(content_type, raw, custom, &mut entities) {
            Some(body) => body,
            None => scan_text(content_type, raw, custom, &mut entities),
        }
    } else {
        scan_text(content_type, raw, custom, &mut entities)
    };

    let matches = entities
        .iter()
        .map(|entity| entity.label.to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let match_count = entities.len();
    let redacted = match_count > 0;

    ScanResult {
        replacement_body,
        redacted,
        matches,
        match_count,
        elapsed_ms: started.elapsed().as_secs_f64() * 1000.0,
        backend: BUILTIN_REGEX_BACKEND.to_string(),
    }
}

fn custom_patterns_store() -> &'static RwLock<Arc<CompiledCustomPatterns>> {
    static CUSTOM_PATTERNS: OnceLock<RwLock<Arc<CompiledCustomPatterns>>> = OnceLock::new();
    CUSTOM_PATTERNS.get_or_init(|| RwLock::new(Arc::new(CompiledCustomPatterns::default())))
}

fn custom_patterns_snapshot() -> Arc<CompiledCustomPatterns> {
    custom_patterns_store().read().map_or_else(
        |_| Arc::new(CompiledCustomPatterns::default()),
        |guard| guard.clone(),
    )
}

fn scanner_config_store() -> &'static RwLock<Arc<ScannerConfig>> {
    static SCANNER_CONFIG: OnceLock<RwLock<Arc<ScannerConfig>>> = OnceLock::new();
    SCANNER_CONFIG.get_or_init(|| RwLock::new(Arc::new(ScannerConfig::default())))
}

fn scanner_config_snapshot() -> Arc<ScannerConfig> {
    scanner_config_store().read().map_or_else(
        |_| Arc::new(ScannerConfig::default()),
        |guard| guard.clone(),
    )
}

fn remote_circuit_store() -> &'static Mutex<RemoteCircuitBreaker> {
    static REMOTE_CIRCUIT: OnceLock<Mutex<RemoteCircuitBreaker>> = OnceLock::new();
    REMOTE_CIRCUIT.get_or_init(|| Mutex::new(RemoteCircuitBreaker::default()))
}

fn reset_remote_circuit() {
    if let Ok(mut guard) = remote_circuit_store().lock() {
        guard.reset();
    }
}

fn remote_circuit_allows_request() -> bool {
    remote_circuit_store()
        .lock()
        .map(|mut guard| guard.allow_request(Instant::now()))
        .unwrap_or(true)
}

fn record_remote_success() {
    if let Ok(mut guard) = remote_circuit_store().lock() {
        guard.record_success();
    }
}

fn record_remote_failure() {
    if let Ok(mut guard) = remote_circuit_store().lock() {
        guard.record_failure(Instant::now());
    }
}

fn privacy_scan_http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(reqwest::Client::new)
}

impl CompiledCustomPatterns {
    fn len(&self) -> usize {
        self.regex_patterns.len() + self.context_patterns.len()
    }
}

fn compile_custom_patterns_from_json(raw: &str) -> ConfigResult<CompiledCustomPatterns> {
    let value = serde_json::from_str::<Value>(raw)
        .map_err(|err| PrivacyScanConfigError::new(format!("invalid JSON: {err}")))?;

    let patterns = match &value {
        Value::Array(items) => items,
        Value::Object(map) => map
            .get("patterns")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                PrivacyScanConfigError::new("custom pattern config must contain a patterns array")
            })?,
        _ => {
            return Err(PrivacyScanConfigError::new(
                "custom pattern config must be an object or array",
            ));
        }
    };

    if patterns.len() > MAX_CUSTOM_PATTERNS {
        return Err(PrivacyScanConfigError::new(format!(
            "custom pattern config has {} patterns; maximum is {}",
            patterns.len(),
            MAX_CUSTOM_PATTERNS,
        )));
    }

    let mut compiled = CompiledCustomPatterns::default();
    for (index, pattern_value) in patterns.iter().enumerate() {
        let object = pattern_value.as_object().ok_or_else(|| {
            PrivacyScanConfigError::new(format!("pattern {index} must be a JSON object"))
        })?;

        let label = normalize_label(required_string(object, "label", index)?, index)?;
        let regex = required_string(object, "regex", index)?;
        if regex.len() > MAX_CUSTOM_REGEX_BYTES {
            return Err(PrivacyScanConfigError::new(format!(
                "pattern {index} regex is too long; maximum is {MAX_CUSTOM_REGEX_BYTES} bytes"
            )));
        }

        let case_insensitive = optional_bool(object, "case_insensitive", false, index)?;
        let content_types = optional_content_types(object, index)?;
        let value_regex = RegexBuilder::new(regex)
            .case_insensitive(case_insensitive)
            .build()
            .map_err(|err| {
                PrivacyScanConfigError::new(format!("pattern {index} has invalid regex: {err}"))
            })?;

        if let Some(path_regex) = optional_string(object, "json_path_regex", index)?
            .or(optional_string(object, "path_regex", index)?)
        {
            if path_regex.len() > MAX_CUSTOM_REGEX_BYTES {
                return Err(PrivacyScanConfigError::new(format!(
                    "pattern {index} json_path_regex is too long; maximum is {MAX_CUSTOM_REGEX_BYTES} bytes"
                )));
            }
            let path_regex = RegexBuilder::new(path_regex)
                .case_insensitive(true)
                .build()
                .map_err(|err| {
                    PrivacyScanConfigError::new(format!(
                        "pattern {index} has invalid json_path_regex: {err}"
                    ))
                })?;
            compiled.context_patterns.push(ContextPattern {
                label,
                path_regex,
                value_regex,
                content_types,
            });
        } else {
            compiled.regex_patterns.push(Pattern {
                label,
                regex: value_regex,
                content_types,
            });
        }
    }

    Ok(compiled)
}

fn compile_scanner_config_from_json(raw: &str) -> ConfigResult<ScannerConfig> {
    let value = serde_json::from_str::<Value>(raw)
        .map_err(|err| PrivacyScanConfigError::new(format!("invalid JSON: {err}")))?;
    let object = value.as_object().ok_or_else(|| {
        PrivacyScanConfigError::new("privacy scanner config must be a JSON object")
    })?;

    let backend = config_optional_string(object, "backend")?.unwrap_or_else(|| {
        if object.contains_key("remote_http") || object.contains_key("url") {
            REMOTE_HTTP_BACKEND.to_string()
        } else {
            BUILTIN_REGEX_BACKEND.to_string()
        }
    });
    let fallback = parse_scanner_fallback(config_optional_string(object, "fallback")?.as_deref())?;

    let backend = match backend.trim().to_ascii_lowercase().as_str() {
        "builtin" | BUILTIN_REGEX_BACKEND => ScannerBackend::BuiltinRegex,
        REMOTE_HTTP_BACKEND | "http" => {
            ScannerBackend::RemoteHttp(parse_remote_http_config(object)?)
        }
        other => {
            return Err(PrivacyScanConfigError::new(format!(
                "unsupported privacy scanner backend '{other}'"
            )));
        }
    };

    Ok(ScannerConfig { backend, fallback })
}

fn parse_remote_http_config(
    object: &serde_json::Map<String, Value>,
) -> ConfigResult<RemoteHttpScannerConfig> {
    let remote_object = match object.get("remote_http") {
        Some(Value::Object(map)) => Some(map),
        Some(_) => {
            return Err(PrivacyScanConfigError::new(
                "privacy scanner remote_http field must be an object",
            ));
        }
        None => None,
    };

    let url = if let Some(remote_object) = remote_object {
        config_optional_string(remote_object, "url")?
            .or(config_optional_string(object, "url")?)
            .ok_or_else(|| {
                PrivacyScanConfigError::new("privacy scanner remote_http.url is required")
            })?
    } else {
        config_optional_string(object, "url")?
            .ok_or_else(|| PrivacyScanConfigError::new("privacy scanner url is required"))?
    };
    validate_remote_url(&url)?;

    let timeout_ms = if let Some(remote_object) = remote_object {
        config_optional_u64(remote_object, "timeout_ms")?
            .or(config_optional_u64(object, "timeout_ms")?)
            .unwrap_or(DEFAULT_REMOTE_TIMEOUT_MS)
    } else {
        config_optional_u64(object, "timeout_ms")?.unwrap_or(DEFAULT_REMOTE_TIMEOUT_MS)
    };
    if timeout_ms == 0 || timeout_ms > MAX_REMOTE_TIMEOUT_MS {
        return Err(PrivacyScanConfigError::new(format!(
            "privacy scanner timeout_ms must be between 1 and {MAX_REMOTE_TIMEOUT_MS}"
        )));
    }

    Ok(RemoteHttpScannerConfig { url, timeout_ms })
}

fn validate_remote_url(url: &str) -> ConfigResult<()> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|err| PrivacyScanConfigError::new(format!("invalid scanner url: {err}")))?;
    match parsed.scheme() {
        "http" | "https" => Ok(()),
        scheme => Err(PrivacyScanConfigError::new(format!(
            "unsupported scanner url scheme '{scheme}'"
        ))),
    }
}

fn parse_scanner_fallback(raw: Option<&str>) -> ConfigResult<ScannerFallback> {
    match raw
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        None | Some("builtin") | Some(BUILTIN_REGEX_BACKEND) => Ok(ScannerFallback::BuiltinRegex),
        Some("passthrough") | Some("fail-open") | Some(FAIL_OPEN_BACKEND) => {
            Ok(ScannerFallback::FailOpen)
        }
        Some(other) => Err(PrivacyScanConfigError::new(format!(
            "unsupported privacy scanner fallback '{other}'"
        ))),
    }
}

fn config_optional_string(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> ConfigResult<Option<String>> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.trim().to_string())),
        Some(_) => Err(PrivacyScanConfigError::new(format!(
            "privacy scanner field '{key}' must be a string"
        ))),
    }
}

fn config_optional_u64(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> ConfigResult<Option<u64>> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => value.as_u64().map(Some).ok_or_else(|| {
            PrivacyScanConfigError::new(format!(
                "privacy scanner field '{key}' must be an unsigned integer"
            ))
        }),
        Some(Value::String(value)) => value.trim().parse::<u64>().map(Some).map_err(|_| {
            PrivacyScanConfigError::new(format!(
                "privacy scanner field '{key}' must be an unsigned integer"
            ))
        }),
        Some(_) => Err(PrivacyScanConfigError::new(format!(
            "privacy scanner field '{key}' must be an unsigned integer"
        ))),
    }
}

async fn scan_remote_http(
    remote: &RemoteHttpScannerConfig,
    context: PrivacyScanRequestContext<'_>,
    content_type: &str,
    raw: &[u8],
) -> Result<ScanResult, String> {
    let request = serde_json::json!({
        "version": 1,
        "content_type": content_type,
        "method": context.method,
        "scheme": context.scheme,
        "host": context.host,
        "port": context.port,
        "path": context.path,
        "body_base64": BASE64_STANDARD.encode(raw),
    });

    let response = privacy_scan_http_client()
        .post(&remote.url)
        .timeout(Duration::from_millis(remote.timeout_ms))
        .json(&request)
        .send()
        .await
        .map_err(|err| format!("request failed: {err}"))?;

    let status = response.status();
    if !status.is_success() {
        return Err(format!("scanner returned HTTP {status}"));
    }

    let value = response
        .json::<Value>()
        .await
        .map_err(|err| format!("invalid JSON response: {err}"))?;
    parse_remote_scan_response(value, raw)
}

fn parse_remote_scan_response(value: Value, raw: &[u8]) -> Result<ScanResult, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "scanner response must be a JSON object".to_string())?;

    let replacement_body = match object.get("body_base64") {
        Some(Value::String(encoded)) => BASE64_STANDARD
            .decode(encoded)
            .map_err(|err| format!("invalid body_base64: {err}"))?,
        Some(_) => return Err("scanner response body_base64 must be a string".to_string()),
        None => {
            if object
                .get("redacted")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                return Err("scanner redacted response is missing body_base64".to_string());
            }
            raw.to_vec()
        }
    };

    let (matches, parsed_count) = parse_remote_matches(
        object
            .get("matches")
            .or_else(|| object.get("labels"))
            .unwrap_or(&Value::Null),
    )?;
    let match_count = object
        .get("match_count")
        .and_then(Value::as_u64)
        .map(|value| value as usize)
        .unwrap_or(parsed_count);
    let redacted = object
        .get("redacted")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| match_count > 0 || replacement_body != raw);

    Ok(ScanResult {
        replacement_body,
        redacted,
        matches,
        match_count,
        elapsed_ms: 0.0,
        backend: REMOTE_HTTP_BACKEND.to_string(),
    })
}

fn parse_remote_matches(value: &Value) -> Result<(Vec<String>, usize), String> {
    let Some(items) = value.as_array() else {
        if value.is_null() {
            return Ok((Vec::new(), 0));
        }
        return Err("scanner response matches must be an array".to_string());
    };

    let mut labels = BTreeSet::new();
    let mut count = 0usize;
    for item in items {
        match item {
            Value::String(label) => {
                if !label.trim().is_empty() {
                    labels.insert(label.trim().to_ascii_lowercase());
                    count += 1;
                }
            }
            Value::Object(map) => {
                let label = map
                    .get("label")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "scanner match object is missing label".to_string())?;
                if !label.trim().is_empty() {
                    labels.insert(label.trim().to_ascii_lowercase());
                }
                count += map
                    .get("count")
                    .and_then(Value::as_u64)
                    .map(|value| value as usize)
                    .unwrap_or(1);
            }
            _ => return Err("scanner matches entries must be strings or objects".to_string()),
        }
    }

    Ok((labels.into_iter().collect(), count))
}

fn fallback_scan(
    content_type: &str,
    raw: &[u8],
    fallback: ScannerFallback,
    started: Instant,
) -> ScanResult {
    match fallback {
        ScannerFallback::BuiltinRegex => {
            let mut result = scan_body(content_type, raw);
            result.elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
            result
        }
        ScannerFallback::FailOpen => ScanResult {
            replacement_body: raw.to_vec(),
            redacted: false,
            matches: Vec::new(),
            match_count: 0,
            elapsed_ms: started.elapsed().as_secs_f64() * 1000.0,
            backend: FAIL_OPEN_BACKEND.to_string(),
        },
    }
}

fn required_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
    index: usize,
) -> ConfigResult<&'a str> {
    optional_string(object, key, index)?.ok_or_else(|| {
        PrivacyScanConfigError::new(format!("pattern {index} is missing string field '{key}'"))
    })
}

fn optional_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
    index: usize,
) -> ConfigResult<Option<&'a str>> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.as_str())),
        Some(_) => Err(PrivacyScanConfigError::new(format!(
            "pattern {index} field '{key}' must be a string"
        ))),
    }
}

fn optional_bool(
    object: &serde_json::Map<String, Value>,
    key: &str,
    default: bool,
    index: usize,
) -> ConfigResult<bool> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(PrivacyScanConfigError::new(format!(
            "pattern {index} field '{key}' must be a boolean"
        ))),
    }
}

fn optional_content_types(
    object: &serde_json::Map<String, Value>,
    index: usize,
) -> ConfigResult<Vec<String>> {
    let Some(value) = object.get("content_types") else {
        return Ok(Vec::new());
    };
    let Value::Array(items) = value else {
        return Err(PrivacyScanConfigError::new(format!(
            "pattern {index} field 'content_types' must be an array"
        )));
    };
    if items.len() > MAX_CUSTOM_CONTENT_TYPES {
        return Err(PrivacyScanConfigError::new(format!(
            "pattern {index} has too many content types; maximum is {MAX_CUSTOM_CONTENT_TYPES}"
        )));
    }

    let mut output = Vec::with_capacity(items.len());
    for (content_index, item) in items.iter().enumerate() {
        let Some(raw) = item.as_str() else {
            return Err(PrivacyScanConfigError::new(format!(
                "pattern {index} content_types[{content_index}] must be a string"
            )));
        };
        let normalized = raw.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            return Err(PrivacyScanConfigError::new(format!(
                "pattern {index} content_types[{content_index}] must not be empty"
            )));
        }
        if normalized.len() > MAX_CUSTOM_CONTENT_TYPE_BYTES {
            return Err(PrivacyScanConfigError::new(format!(
                "pattern {index} content_types[{content_index}] is too long; maximum is {MAX_CUSTOM_CONTENT_TYPE_BYTES} bytes"
            )));
        }
        output.push(normalized);
    }
    Ok(output)
}

fn normalize_label(label: &str, index: usize) -> ConfigResult<String> {
    let trimmed = label.trim();
    if trimmed.is_empty() {
        return Err(PrivacyScanConfigError::new(format!(
            "pattern {index} label must not be empty"
        )));
    }
    if trimmed.len() > MAX_CUSTOM_LABEL_BYTES {
        return Err(PrivacyScanConfigError::new(format!(
            "pattern {index} label is too long; maximum is {MAX_CUSTOM_LABEL_BYTES} bytes"
        )));
    }
    if !trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return Err(PrivacyScanConfigError::new(format!(
            "pattern {index} label must contain only ASCII letters, numbers, and underscores"
        )));
    }
    Ok(trimmed.to_ascii_lowercase())
}

fn scan_json(
    content_type: &str,
    raw: &[u8],
    custom: &CompiledCustomPatterns,
    entities: &mut Vec<Entity>,
) -> Option<Vec<u8>> {
    let mut body = serde_json::from_slice::<Value>(raw).ok()?;
    let pairs = extract_strings(&body, "");
    let detected = detect_regex(content_type, &pairs, custom);
    if detected.is_empty() {
        return Some(raw.to_vec());
    }

    let by_path = entities_by_path(&detected);
    redact_json_strings(&mut body, &by_path, "");
    entities.extend(detected.into_iter().map(|item| item.entity));
    serde_json::to_vec(&body)
        .ok()
        .or_else(|| Some(raw.to_vec()))
}

fn scan_text(
    content_type: &str,
    raw: &[u8],
    custom: &CompiledCustomPatterns,
    entities: &mut Vec<Entity>,
) -> Vec<u8> {
    let text = String::from_utf8_lossy(raw);
    let detected = detect_regex(content_type, &[("".to_string(), text.to_string())], custom);
    if detected.is_empty() {
        return raw.to_vec();
    }
    let text_entities = detected
        .iter()
        .map(|item| item.entity.clone())
        .collect::<Vec<_>>();
    let redacted = replace_spans(&text, &text_entities);
    entities.extend(text_entities);
    redacted.into_bytes()
}

fn extract_strings(value: &Value, path: &str) -> Vec<(String, String)> {
    match value {
        Value::String(s) => vec![(path.to_string(), s.clone())],
        Value::Array(items) => items
            .iter()
            .enumerate()
            .flat_map(|(index, item)| extract_strings(item, &format!("{path}[{index}]")))
            .collect(),
        Value::Object(map) => map
            .iter()
            .flat_map(|(key, value)| {
                let child = if path.is_empty() {
                    key.to_string()
                } else {
                    format!("{path}.{key}")
                };
                extract_strings(value, &child)
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn entities_by_path(entities: &[EntityWithPath]) -> HashMap<String, Vec<Entity>> {
    let mut grouped = HashMap::new();
    for item in entities {
        grouped
            .entry(item.path.clone())
            .or_insert_with(Vec::new)
            .push(item.entity.clone());
    }
    grouped
}

#[derive(Debug, Clone)]
struct EntityWithPath {
    path: String,
    entity: Entity,
}

fn detect_regex(
    content_type: &str,
    pairs: &[(String, String)],
    custom: &CompiledCustomPatterns,
) -> Vec<EntityWithPath> {
    let mut entities = Vec::new();
    let mut claimed_spans: Vec<(String, usize, usize)> = Vec::new();

    for pattern in context_patterns()
        .iter()
        .chain(custom.context_patterns.iter())
    {
        if !content_type_matches(&pattern.content_types, content_type) {
            continue;
        }
        for (path, text) in pairs {
            if path.is_empty() || text.trim().is_empty() || !pattern.path_regex.is_match(path) {
                continue;
            }
            for matched in pattern.value_regex.find_iter(text) {
                append_entity(
                    &mut entities,
                    &mut claimed_spans,
                    path,
                    &pattern.label,
                    matched.start(),
                    matched.end(),
                );
            }
        }
    }

    for (path, text) in pairs {
        if text.trim().is_empty() {
            continue;
        }
        for pattern in regex_patterns().iter().chain(custom.regex_patterns.iter()) {
            if !content_type_matches(&pattern.content_types, content_type) {
                continue;
            }
            for matched in pattern.regex.find_iter(text) {
                if pattern.label == CREDIT_CARD_LABEL && !looks_like_credit_card(matched.as_str()) {
                    continue;
                }
                append_entity(
                    &mut entities,
                    &mut claimed_spans,
                    path,
                    &pattern.label,
                    matched.start(),
                    matched.end(),
                );
            }
        }
    }

    entities
}

fn append_entity(
    entities: &mut Vec<EntityWithPath>,
    claimed_spans: &mut Vec<(String, usize, usize)>,
    path: &str,
    label: &str,
    start: usize,
    end: usize,
) {
    if claimed_spans
        .iter()
        .any(|(existing_path, existing_start, existing_end)| {
            existing_path == path && start < *existing_end && *existing_start < end
        })
    {
        return;
    }
    claimed_spans.push((path.to_string(), start, end));
    entities.push(EntityWithPath {
        path: path.to_string(),
        entity: Entity {
            label: label.to_string(),
            start,
            end,
        },
    });
}

fn redact_json_strings(
    value: &mut Value,
    entities_by_path: &HashMap<String, Vec<Entity>>,
    path: &str,
) {
    match value {
        Value::String(text) => {
            if let Some(entities) = entities_by_path.get(path) {
                *text = replace_spans(text, entities);
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter_mut().enumerate() {
                redact_json_strings(item, entities_by_path, &format!("{path}[{index}]"));
            }
        }
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                let child_path = if path.is_empty() {
                    key.to_string()
                } else {
                    format!("{path}.{key}")
                };
                redact_json_strings(child, entities_by_path, &child_path);
            }
        }
        _ => {}
    }
}

fn replace_spans(text: &str, entities: &[Entity]) -> String {
    let mut output = text.to_string();
    let mut sorted = entities.to_vec();
    sorted.sort_by_key(|entity| std::cmp::Reverse(entity.start));
    for entity in sorted {
        let replacement = format!("[{}]", entity.label.to_ascii_uppercase());
        output.replace_range(entity.start..entity.end, &replacement);
    }
    output
}

fn content_type_matches(pattern_content_types: &[String], request_content_type: &str) -> bool {
    if pattern_content_types.is_empty() {
        return true;
    }
    let request_type = request_content_type
        .split(';')
        .next()
        .unwrap_or(request_content_type)
        .trim()
        .to_ascii_lowercase();
    pattern_content_types
        .iter()
        .any(|allowed| allowed == "*" || allowed == &request_type)
}

fn looks_like_credit_card(value: &str) -> bool {
    let digits = value
        .chars()
        .filter(|ch| ch.is_ascii_digit())
        .filter_map(|ch| ch.to_digit(10))
        .collect::<Vec<_>>();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let mut checksum = 0;
    let mut should_double = false;
    for digit in digits.iter().rev().copied() {
        let mut value = digit;
        if should_double {
            value *= 2;
            if value > 9 {
                value -= 9;
            }
        }
        checksum += value;
        should_double = !should_double;
    }
    checksum % 10 == 0
}

fn regex_patterns() -> &'static [Pattern] {
    static PATTERNS: OnceLock<Vec<Pattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            pattern("aws_access_key_id", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", false),
            pattern(
                "aws_secret_access_key",
                r#"\b(?:aws[_-]?)?(?:secret[_-]?)?access[_-]?key(?:[_-]?id)?\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}['"]?"#,
                true,
            ),
            pattern(
                "aws_session_token",
                r#"\b(?:aws[_-]?)?(?:session[_-]?token|security[_-]?token)\s*[:=]\s*['"]?[A-Za-z0-9/+=]{80,}['"]?"#,
                true,
            ),
            pattern("openai_api_key", r"\bsk-(?:proj-[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{20,})\b", false),
            pattern("anthropic_api_key", r"\bsk-ant-[A-Za-z0-9_-]{20,}\b", false),
            pattern("github_token", r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b", false),
            pattern("slack_token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", false),
            pattern("huggingface_token", r"\bhf_[A-Za-z0-9]{20,}\b", false),
            pattern(
                "azure_storage_connection_string",
                r#"\bDefaultEndpointsProtocol\s*=\s*https?;[^\s"']{0,4096}\bAccountKey\s*=\s*[A-Za-z0-9+/]{86}==[^\s"']*"#,
                true,
            ),
            pattern(
                "azure_storage_account_key",
                r#"\b(?:account[_-]?key|azure[_-]?(?:storage[_-]?)?key)\s*[:=]\s*['"]?[A-Za-z0-9+/]{86}==['"]?"#,
                true,
            ),
            pattern(
                "azure_sas_token",
                r#"(?:^|[?&;\s])(?:sv|se|sp|sr|spr|skoid|sktid|skt|ske|sks|skv)=[^\s"']{0,2048}\bsig=[A-Za-z0-9%+/]{20,}(?:%3[Dd]|=)?[^\s"']*"#,
                true,
            ),
            pattern(
                "azure_entra_client_secret",
                r#"\b(?:azure[_-]?(?:ad|entra)?[_-]?)?(?:client[_-]?secret|app[_-]?secret|application[_-]?secret)\s*[:=]\s*['"]?[A-Za-z0-9._~+/=-]{20,200}['"]?"#,
                true,
            ),
            pattern(
                "azure_ai_search_key",
                r#"\b(?:azure[_-]?search(?:[_-]?(?:admin|query))?[_-]?key|search[_-]?(?:admin|query)?[_-]?key)\s*[:=]\s*['"]?[A-Za-z0-9]{52}['"]?"#,
                true,
            ),
            pattern("gcp_api_key", r"\bAIza[0-9A-Za-z_-]{35}\b", false),
            pattern("gcp_oauth_client_secret", r"\bGOCSPX-[A-Za-z0-9_-]{20,}\b", false),
            pattern("gcp_oauth_access_token", r"\bya29\.[0-9A-Za-z_-]{20,}\b", false),
            pattern(
                "gcp_oauth_refresh_token",
                r#"\b(?:google[_-]?)?(?:refresh[_-]?token|oauth[_-]?refresh[_-]?token)\s*[:=]\s*['"]?(?:1//|1/)[0-9A-Za-z_-]{20,}['"]?"#,
                true,
            ),
            pattern(
                "private_key",
                r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
                false,
            ),
            pattern("email", r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", true),
            pattern("phone_number", r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b", false),
            pattern("ssn", r"\b\d{3}-\d{2}-\d{4}\b", false),
            pattern("credit_card", r"\b(?:\d[ -]*?){13,19}\b", false),
            pattern(
                "api_key",
                r#"\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*['"]?[A-Za-z0-9_\-]{12,}"#,
                true,
            ),
            pattern("ip_address", r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", false),
            pattern(
                "address",
                r"\b\d{1,6}\s+[A-Z][A-Za-z0-9.-]*(?:\s+[A-Z][A-Za-z0-9.-]*){0,4}\s+(?:Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Drive|Dr|Boulevard|Blvd|Way|Court|Ct)\b",
                true,
            ),
            pattern("date_of_birth", r"\b(?:dob|date of birth)\s*[:=]?\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b", true),
        ]
    })
}

fn context_patterns() -> &'static [ContextPattern] {
    static PATTERNS: OnceLock<Vec<ContextPattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            context_pattern("aws_secret_access_key", r"(?:aws.*secret.*access.*key|secret.*access.*key)", r"^[A-Za-z0-9/+=]{40}$"),
            context_pattern("aws_session_token", r"(?:aws.*session.*token|aws.*security.*token|session[_-]?token)", r"^[A-Za-z0-9/+=]{80,}$"),
            context_pattern("openai_api_key", r"(?:openai.*(?:api.*)?key|api[_-]?key)", r"^sk-(?:proj-[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{20,})$"),
            context_pattern("anthropic_api_key", r"(?:anthropic|claude).*(?:api.*)?key|api[_-]?key", r"^sk-ant-[A-Za-z0-9_-]{20,}$"),
            context_pattern("github_token", r"(?:github|gh).*(?:token|key)|token", r"^(?:gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{20,255})$"),
            context_pattern("slack_token", r"slack.*token|token", r"^xox[baprs]-[A-Za-z0-9-]{10,}$"),
            context_pattern("huggingface_token", r"(?:huggingface|hf).*(?:token|key)|token", r"^hf_[A-Za-z0-9]{20,}$"),
            context_pattern("azure_storage_account_key", r"(?:^|[._-])(?:account[_-]?key|azure.*storage.*key)(?:$|[._-])", r"^[A-Za-z0-9+/]{86}==$"),
            context_pattern("azure_entra_client_secret", r"(?:azure.*(?:client|app|application).*secret|(?:client|app|application).*secret.*azure)", r"^[A-Za-z0-9._~+/=-]{20,200}$"),
            context_pattern("azure_ai_search_key", r"(?:azure.*search.*key|search.*(?:admin|query)?.*key)", r"^[A-Za-z0-9]{52}$"),
            context_pattern("gcp_api_key", r"(?:gcp|google).*api.*key|api[_-]?key", r"^AIza[0-9A-Za-z_-]{35}$"),
            context_pattern("gcp_oauth_client_secret", r"(?:gcp|google|oauth).*client.*secret|client[_-]?secret", r"^GOCSPX-[A-Za-z0-9_-]{20,}$"),
            context_pattern("gcp_oauth_refresh_token", r"(?:gcp|google|oauth).*refresh.*token|refresh[_-]?token", r"^(?:1//|1/)[0-9A-Za-z_-]{20,}$"),
            context_pattern("gcp_service_account_key", r"(?:^|[._-])private[_-]?key(?:$|[._-])", r"^-----BEGIN PRIVATE KEY-----[\s\S]*-----END PRIVATE KEY-----$"),
        ]
    })
}

fn pattern(label: &str, regex: &str, case_insensitive: bool) -> Pattern {
    Pattern {
        label: label.to_string(),
        regex: RegexBuilder::new(regex)
            .case_insensitive(case_insensitive)
            .build()
            .unwrap_or_else(|err| panic!("invalid privacy scan regex {label}: {err}")),
        content_types: Vec::new(),
    }
}

fn context_pattern(label: &str, path_regex: &str, value_regex: &str) -> ContextPattern {
    ContextPattern {
        label: label.to_string(),
        path_regex: RegexBuilder::new(path_regex)
            .case_insensitive(true)
            .build()
            .unwrap_or_else(|err| panic!("invalid privacy scan path regex {label}: {err}")),
        value_regex: Regex::new(value_regex)
            .unwrap_or_else(|err| panic!("invalid privacy scan value regex {label}: {err}")),
        content_types: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regex_scan_redacts_known_secrets_and_pii() {
        let aws_secret = "a".repeat(40);
        let private_key = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----";
        let text = [
            "aws_access_key_id=AKIA1234567890ABCDEF",
            &format!("aws_secret_access_key={aws_secret}"),
            "openai_api_key=sk-proj-abcdefghijklmnopqrstuvwxyz123456",
            "ssn=123-45-6789",
            "phone=415-555-2671",
            "email=user@example.com",
            "card=4111 1111 1111 1111",
            "token=abcdefghijklmnop",
            private_key,
        ]
        .join("\n");

        let result = scan_body("text/plain", text.as_bytes());
        let redacted = String::from_utf8(result.replacement_body).unwrap();

        assert!(result.redacted);
        assert!(!redacted.contains("AKIA1234567890ABCDEF"));
        assert!(!redacted.contains("sk-proj-abcdefghijklmnopqrstuvwxyz123456"));
        assert!(!redacted.contains("user@example.com"));
        assert!(redacted.contains("[OPENAI_API_KEY]"));
        assert!(redacted.contains("[AWS_ACCESS_KEY_ID]"));
        assert!(redacted.contains("[SSN]"));
        assert!(redacted.contains("[PHONE_NUMBER]"));
        assert!(redacted.contains("[EMAIL]"));
        assert!(redacted.contains("[PRIVATE_KEY]"));
        assert!(redacted.contains("[API_KEY]"));
        assert!(redacted.contains("[CREDIT_CARD]"));
        for label in [
            "aws_access_key_id",
            "aws_secret_access_key",
            "openai_api_key",
            "ssn",
            "phone_number",
            "email",
            "private_key",
            "api_key",
            "credit_card",
        ] {
            assert!(result.matches.contains(&label.to_string()), "{label}");
        }
    }

    #[test]
    fn regex_scan_redacts_json_strings_recursively() {
        let payload = serde_json::json!({
            "messages": [{"content": "contact user@example.com"}],
            "nested": {"openai_key": "sk-proj-abcdefghijklmnopqrstuvwxyz123456"},
            "count": 2,
            "unchanged": "hello"
        });

        let result = scan_body("application/json", payload.to_string().as_bytes());
        let redacted = serde_json::from_slice::<Value>(&result.replacement_body).unwrap();

        assert!(result.redacted);
        assert_eq!(redacted["messages"][0]["content"], "contact [EMAIL]");
        assert_eq!(redacted["nested"]["openai_key"], "[OPENAI_API_KEY]");
        assert_eq!(redacted["count"], 2);
        assert_eq!(redacted["unchanged"], "hello");
    }

    #[test]
    fn no_match_json_returns_original_bytes() {
        let raw = br#"{"message":"hello","count":2}"#;
        let result = scan_body("application/json", raw);

        assert!(!result.redacted);
        assert_eq!(result.replacement_body, raw);
        assert!(result.matches.is_empty());
        assert_eq!(result.match_count, 0);
    }

    #[test]
    fn invalid_json_falls_back_to_text_scanning() {
        let raw = br#"{"message":"user@example.com""#;
        let result = scan_body("application/json", raw);

        assert!(result.redacted);
        assert_eq!(
            String::from_utf8(result.replacement_body).unwrap(),
            r#"{"message":"[EMAIL]""#,
        );
    }

    #[test]
    fn custom_regex_redacts_text() {
        let custom = compile_custom_patterns_from_json(
            r#"{"patterns":[{"label":"employee_id","regex":"\\bEMP-[0-9]{6}\\b"}]}"#,
        )
        .unwrap();

        let result = scan_body_with_custom_patterns(
            "text/plain",
            b"employee EMP-123456 opened a case",
            &custom,
        );
        let redacted = String::from_utf8(result.replacement_body).unwrap();

        assert!(result.redacted);
        assert_eq!(redacted, "employee [EMPLOYEE_ID] opened a case");
        assert_eq!(result.matches, vec!["employee_id".to_string()]);
    }

    #[test]
    fn custom_json_path_regex_limits_where_pattern_applies() {
        let custom = compile_custom_patterns_from_json(
            r#"{"patterns":[{"label":"internal_account","json_path_regex":"customer\\.account_id$","regex":"^ACCT-[0-9]{4}$"}]}"#,
        )
        .unwrap();
        let payload = serde_json::json!({
            "customer": {"account_id": "ACCT-1234"},
            "message": "ACCT-9999",
            "count": 1
        });

        let result = scan_body_with_custom_patterns(
            "application/json",
            payload.to_string().as_bytes(),
            &custom,
        );
        let redacted = serde_json::from_slice::<Value>(&result.replacement_body).unwrap();

        assert!(result.redacted);
        assert_eq!(redacted["customer"]["account_id"], "[INTERNAL_ACCOUNT]");
        assert_eq!(redacted["message"], "ACCT-9999");
        assert_eq!(redacted["count"], 1);
    }

    #[test]
    fn custom_content_type_filter_is_respected() {
        let custom = compile_custom_patterns_from_json(
            r#"{"patterns":[{"label":"ticket_id","regex":"TICKET-[0-9]+","content_types":["application/json"]}]}"#,
        )
        .unwrap();

        let text = scan_body_with_custom_patterns("text/plain", b"TICKET-123", &custom);
        assert!(!text.redacted);
        assert_eq!(text.replacement_body, b"TICKET-123");

        let json = scan_body_with_custom_patterns(
            "application/json; charset=utf-8",
            br#"{"ticket":"TICKET-123"}"#,
            &custom,
        );
        let redacted = serde_json::from_slice::<Value>(&json.replacement_body).unwrap();

        assert!(json.redacted);
        assert_eq!(redacted["ticket"], "[TICKET_ID]");
    }

    #[test]
    fn custom_pattern_config_rejects_invalid_regex() {
        let error = compile_custom_patterns_from_json(
            r#"{"patterns":[{"label":"employee_id","regex":"("}]}"#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("invalid regex"));
    }

    #[test]
    fn scanner_config_accepts_remote_http_provider() {
        let config = compile_scanner_config_from_json(
            r#"{"backend":"remote_http","remote_http":{"url":"http://privacy-scanner.default.svc.cluster.local:8080/scan","timeout_ms":1500},"fallback":"builtin_regex"}"#,
        )
        .unwrap();

        assert_eq!(config.fallback, ScannerFallback::BuiltinRegex);
        match config.backend {
            ScannerBackend::RemoteHttp(remote) => {
                assert_eq!(
                    remote.url,
                    "http://privacy-scanner.default.svc.cluster.local:8080/scan"
                );
                assert_eq!(remote.timeout_ms, 1500);
            }
            ScannerBackend::BuiltinRegex => panic!("expected remote HTTP backend"),
        }
    }

    #[test]
    fn remote_response_parser_preserves_raw_body_when_not_redacted() {
        let raw = b"plain request";
        let result = parse_remote_scan_response(
            serde_json::json!({
                "redacted": false,
                "matches": []
            }),
            raw,
        )
        .unwrap();

        assert!(!result.redacted);
        assert_eq!(result.replacement_body, raw);
        assert_eq!(result.backend, REMOTE_HTTP_BACKEND);
    }

    #[tokio::test]
    async fn configured_remote_http_scanner_replaces_body() {
        let _guard = test_scanner_config_lock().lock().await;
        let response_body = serde_json::json!({
            "redacted": true,
            "body_base64": BASE64_STANDARD.encode(b"remote redacted body"),
            "matches": [{"label": "enterprise_secret", "count": 1}]
        })
        .to_string();
        let url = serve_one_json_response(response_body).await;
        let config = serde_json::json!({
            "backend": "remote_http",
            "remote_http": {
                "url": url,
                "timeout_ms": 2_000
            },
            "fallback": "builtin_regex"
        })
        .to_string();

        set_scanner_config_from_json(Some(&config)).unwrap();
        let result = scan_body_for_request(
            PrivacyScanRequestContext {
                method: "POST",
                scheme: "https",
                host: "api.example.com",
                port: 443,
                path: "/v1/chat",
            },
            "text/plain",
            b"original body",
        )
        .await;
        set_scanner_config_from_json(None).unwrap();

        assert!(result.redacted);
        assert_eq!(result.replacement_body, b"remote redacted body");
        assert_eq!(result.matches, vec!["enterprise_secret".to_string()]);
        assert_eq!(result.match_count, 1);
        assert_eq!(result.backend, REMOTE_HTTP_BACKEND);
    }

    #[tokio::test]
    async fn remote_http_failure_uses_builtin_fallback() {
        let _guard = test_scanner_config_lock().lock().await;
        let config = serde_json::json!({
            "backend": "remote_http",
            "remote_http": {
                "url": "http://127.0.0.1:9/scan",
                "timeout_ms": 50
            },
            "fallback": "builtin_regex"
        })
        .to_string();

        set_scanner_config_from_json(Some(&config)).unwrap();
        let result = scan_body_for_request(
            PrivacyScanRequestContext {
                method: "POST",
                scheme: "https",
                host: "api.example.com",
                port: 443,
                path: "/v1/chat",
            },
            "text/plain",
            b"email=user@example.com",
        )
        .await;
        set_scanner_config_from_json(None).unwrap();

        assert!(result.redacted);
        assert_eq!(result.replacement_body, b"email=[EMAIL]");
        assert_eq!(result.backend, BUILTIN_REGEX_BACKEND);
    }

    async fn serve_one_json_response(response_body: String) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
                if let Some(total_len) = http_request_total_len(&request) {
                    if request.len() >= total_len {
                        break;
                    }
                }
            }

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        format!("http://{addr}/scan")
    }

    fn test_scanner_config_lock() -> &'static tokio::sync::Mutex<()> {
        static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    fn http_request_total_len(request: &[u8]) -> Option<usize> {
        let header_end = request.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
        let header = std::str::from_utf8(&request[..header_end]).ok()?;
        let content_length = header
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .or_else(|| {
                header
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length:"))
            })
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        Some(header_end + content_length)
    }
}
