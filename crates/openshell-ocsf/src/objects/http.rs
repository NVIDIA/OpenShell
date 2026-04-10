// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `http_request`, `http_response`, and `url` objects.

use serde::{Deserialize, Serialize};

use crate::enums::HttpMethod;

/// OCSF HTTP Request object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequest {
    /// HTTP method (e.g., "GET", "POST").
    pub http_method: HttpMethod,

    /// Request URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<Url>,
}

/// OCSF HTTP Response object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpResponse {
    /// HTTP status code.
    pub code: u16,
}

/// OCSF URL object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Url {
    /// URL scheme (e.g., "https").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,

    /// Hostname.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    /// URL path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// Port number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

impl Url {
    /// Create a URL from its components.
    #[must_use]
    pub fn new(scheme: &str, hostname: &str, path: &str, port: u16) -> Self {
        Self {
            scheme: Some(scheme.to_string()),
            hostname: Some(hostname.to_string()),
            path: Some(path.to_string()),
            port: Some(port),
        }
    }

    /// Format as a display string.
    ///
    /// Includes the port when it is present and differs from the scheme default
    /// (443 for `https`, 80 for `http`).
    #[must_use]
    pub fn to_display_string(&self) -> String {
        let scheme = self.scheme.as_deref().unwrap_or("https");
        let hostname = self.hostname.as_deref().unwrap_or("unknown");
        let path = self.path.as_deref().unwrap_or("/");
        let port_suffix = match self.port {
            Some(443) if scheme == "https" => String::new(),
            Some(80) if scheme == "http" => String::new(),
            Some(p) => format!(":{p}"),
            None => String::new(),
        };
        format!("{scheme}://{hostname}{port_suffix}{path}")
    }
}

impl HttpRequest {
    /// Create a new HTTP request.
    #[must_use]
    pub fn new(method: &str, url: Url) -> Self {
        Self {
            http_method: method.parse().unwrap(),
            url: Some(url),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_request_serialization() {
        let req = HttpRequest::new("GET", Url::new("https", "api.example.com", "/v1/data", 443));
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["http_method"], "GET");
        assert_eq!(json["url"]["scheme"], "https");
        assert_eq!(json["url"]["hostname"], "api.example.com");
        assert_eq!(json["url"]["path"], "/v1/data");
        assert_eq!(json["url"]["port"], 443);
    }

    #[test]
    fn test_url_display_string_default_port() {
        let url = Url::new("https", "api.example.com", "/v1/data", 443);
        assert_eq!(url.to_display_string(), "https://api.example.com/v1/data");

        let url = Url::new("http", "example.com", "/index", 80);
        assert_eq!(url.to_display_string(), "http://example.com/index");
    }

    #[test]
    fn test_url_display_string_non_default_port() {
        let url = Url::new("http", "172.20.0.1", "/test", 9876);
        assert_eq!(url.to_display_string(), "http://172.20.0.1:9876/test");

        let url = Url::new("https", "api.example.com", "/v1/data", 8443);
        assert_eq!(
            url.to_display_string(),
            "https://api.example.com:8443/v1/data"
        );

        // HTTP on 443 is non-default — should show port
        let url = Url::new("http", "example.com", "/path", 443);
        assert_eq!(url.to_display_string(), "http://example.com:443/path");
    }

    #[test]
    fn test_url_display_string_no_port() {
        let url = Url {
            scheme: Some("https".to_string()),
            hostname: Some("example.com".to_string()),
            path: Some("/path".to_string()),
            port: None,
        };
        assert_eq!(url.to_display_string(), "https://example.com/path");
    }

    #[test]
    fn test_http_response() {
        let resp = HttpResponse { code: 200 };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["code"], 200);
    }
}
