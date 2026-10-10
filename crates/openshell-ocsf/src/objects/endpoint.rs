// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `network_endpoint` object.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// OCSF Network Endpoint object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    /// Domain name (e.g., "api.example.com").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,

    /// Fully qualified name of the endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    /// IP address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,

    /// Port number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,

    /// Short name of the endpoint, such as a Unix socket path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Name of the service the endpoint provides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub svc_name: Option<String>,
}

impl Endpoint {
    /// Create an endpoint from a domain name and port.
    #[must_use]
    pub fn from_domain(name: &str, port: u16) -> Self {
        Self {
            domain: Some(name.to_string()),
            hostname: Some(name.to_string()),
            ip: None,
            port: Some(port),
            name: None,
            svc_name: None,
        }
    }

    /// Create an endpoint from an IP address and port.
    #[must_use]
    pub fn from_ip(addr: IpAddr, port: u16) -> Self {
        Self {
            domain: None,
            hostname: None,
            ip: Some(addr.to_string()),
            port: Some(port),
            name: None,
            svc_name: None,
        }
    }

    /// Create an endpoint from an IP string and port.
    #[must_use]
    pub fn from_ip_str(addr: &str, port: u16) -> Self {
        Self {
            domain: None,
            hostname: None,
            ip: Some(addr.to_string()),
            port: Some(port),
            name: None,
            svc_name: None,
        }
    }

    /// Create an endpoint for a local service with no network address, such as
    /// a server on a Unix socket.
    #[must_use]
    pub fn local_service(svc_name: &str, name: Option<&str>) -> Self {
        Self {
            domain: None,
            hostname: None,
            ip: None,
            port: None,
            name: name.map(str::to_string),
            svc_name: Some(svc_name.to_string()),
        }
    }

    /// Returns the domain or IP for display purposes.
    #[must_use]
    pub fn domain_or_ip(&self) -> &str {
        self.domain
            .as_deref()
            .or(self.ip.as_deref())
            .unwrap_or("unknown")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_service_endpoint_names_the_service_and_socket() {
        let json = serde_json::to_value(Endpoint::local_service(
            "ssh",
            Some("/run/openshell/ssh.sock"),
        ))
        .unwrap();
        assert_eq!(
            json,
            serde_json::json!({"name": "/run/openshell/ssh.sock", "svc_name": "ssh"})
        );
        let json = serde_json::to_value(Endpoint::local_service("ssh", None)).unwrap();
        assert_eq!(json, serde_json::json!({"svc_name": "ssh"}));
    }

    #[test]
    fn test_endpoint_domain() {
        let ep = Endpoint::from_domain("api.example.com", 443);
        assert_eq!(ep.domain_or_ip(), "api.example.com");
        let json = serde_json::to_value(&ep).unwrap();
        assert_eq!(json["domain"], "api.example.com");
        // OCSF 1.1 and 1.3 accept only `hostname` as the endpoint's name.
        assert_eq!(json["hostname"], "api.example.com");
        assert_eq!(json["port"], 443);
        assert!(json.get("ip").is_none());
    }

    #[test]
    fn test_endpoint_ip() {
        let ep = Endpoint::from_ip("10.42.0.1".parse().unwrap(), 3128);
        assert_eq!(ep.domain_or_ip(), "10.42.0.1");
        let json = serde_json::to_value(&ep).unwrap();
        assert_eq!(json["ip"], "10.42.0.1");
        assert!(json.get("domain").is_none());
    }
}
