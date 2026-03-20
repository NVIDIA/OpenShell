// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `http_method` enum — the 9 OCSF-defined HTTP methods.

use serde::{Deserialize, Serialize};

/// HTTP method as defined in the OCSF v1.7.0 `http_request` object schema.
///
/// The 9 standard methods are typed variants. Non-standard methods use
/// `Other(String)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HttpMethod {
    /// OPTIONS
    Options,
    /// GET
    Get,
    /// HEAD
    Head,
    /// POST
    Post,
    /// PUT
    Put,
    /// DELETE
    Delete,
    /// TRACE
    Trace,
    /// CONNECT
    Connect,
    /// PATCH
    Patch,
    /// Non-standard method.
    Other(String),
}

impl HttpMethod {
    /// Return the canonical uppercase string representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Options => "OPTIONS",
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Trace => "TRACE",
            Self::Connect => "CONNECT",
            Self::Patch => "PATCH",
            Self::Other(s) => s,
        }
    }
}

impl std::str::FromStr for HttpMethod {
    type Err = std::convert::Infallible;

    /// Parse a method string into a typed variant (case-insensitive).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_uppercase().as_str() {
            "OPTIONS" => Self::Options,
            "GET" => Self::Get,
            "HEAD" => Self::Head,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "DELETE" => Self::Delete,
            "TRACE" => Self::Trace,
            "CONNECT" => Self::Connect,
            "PATCH" => Self::Patch,
            _ => Self::Other(s.to_string()),
        })
    }
}

impl Serialize for HttpMethod {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for HttpMethod {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(s.parse().unwrap())
    }
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_str_standard_methods() {
        assert_eq!("GET".parse::<HttpMethod>().unwrap(), HttpMethod::Get);
        assert_eq!("get".parse::<HttpMethod>().unwrap(), HttpMethod::Get);
        assert_eq!("Post".parse::<HttpMethod>().unwrap(), HttpMethod::Post);
        assert_eq!("DELETE".parse::<HttpMethod>().unwrap(), HttpMethod::Delete);
        assert_eq!(
            "CONNECT".parse::<HttpMethod>().unwrap(),
            HttpMethod::Connect
        );
        assert_eq!("PATCH".parse::<HttpMethod>().unwrap(), HttpMethod::Patch);
    }

    #[test]
    fn test_from_str_non_standard() {
        let method: HttpMethod = "PROPFIND".parse().unwrap();
        assert_eq!(method, HttpMethod::Other("PROPFIND".to_string()));
        assert_eq!(method.as_str(), "PROPFIND");
    }

    #[test]
    fn test_json_roundtrip() {
        let method = HttpMethod::Get;
        let json = serde_json::to_value(&method).unwrap();
        assert_eq!(json, serde_json::json!("GET"));

        let deserialized: HttpMethod = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized, HttpMethod::Get);
    }

    #[test]
    fn test_json_roundtrip_other() {
        let method = HttpMethod::Other("PROPFIND".to_string());
        let json = serde_json::to_value(&method).unwrap();
        assert_eq!(json, serde_json::json!("PROPFIND"));

        let deserialized: HttpMethod = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized, HttpMethod::Other("PROPFIND".to_string()));
    }
}
