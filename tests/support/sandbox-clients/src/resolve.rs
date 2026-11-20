// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runs [`scripts::RESOLVE_PROBE`] in a sandbox and turns its JSON line into
//! a typed result.

use std::net::IpAddr;

use serde::Deserialize;
use testkit::{Result, ResultExt as _, Sandbox};

use crate::python::Python;
use crate::scripts;

/// What `getaddrinfo` returned for a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolve {
    /// The distinct addresses, sorted.
    Addresses(Vec<IpAddr>),
    /// The lookup failed. `error` is Python's description of it.
    Failed { error: String },
}

impl Resolve {
    /// The addresses, or none if the lookup failed.
    pub fn addresses(&self) -> &[IpAddr] {
        match self {
            Self::Addresses(addresses) => addresses,
            Self::Failed { .. } => &[],
        }
    }
}

/// Resolve `host` for TCP port `port` with `getaddrinfo` in `sandbox`, as a
/// client connecting to it would. A failed lookup is a result, not an error.
pub async fn resolve(sandbox: &Sandbox, host: &str, port: u16) -> Result<Resolve> {
    Python::default().resolve(sandbox, host, port).await
}

pub(crate) async fn resolve_with(
    python: &Python,
    sandbox: &Sandbox,
    host: &str,
    port: u16,
) -> Result<Resolve> {
    let output = python
        .run(sandbox, scripts::RESOLVE_PROBE, &[host, &port.to_string()])
        .await
        .context(format!("resolve {host} in sandbox {}", sandbox.name()))?;
    parse_resolve(output.last_json()?)
}

#[derive(Deserialize)]
struct ResolveJson {
    addresses: Vec<String>,
    error: Option<String>,
}

fn parse_resolve(value: serde_json::Value) -> Result<Resolve> {
    let json: ResolveJson = serde_json::from_value(value.clone())
        .context(format!("read the resolve probe's result {value}"))?;
    if let Some(error) = json.error {
        return Ok(Resolve::Failed { error });
    }
    let addresses = json
        .addresses
        .iter()
        .map(|address| {
            // An IPv6 link-local address may carry a `%<zone>` suffix.
            let bare = address.split('%').next().unwrap_or(address);
            bare.parse().map_err(|_| {
                testkit::Error::msg(format!(
                    "the resolve probe returned {address:?}, which isn't an IP address"
                ))
            })
        })
        .collect::<Result<Vec<IpAddr>>>()?;
    Ok(Resolve::Addresses(addresses))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_addresses() {
        let resolve = parse_resolve(serde_json::json!({
            "addresses": ["198.18.0.7", "::ffff:198.18.0.7", "fe80::1%eth0"],
            "error": null,
        }))
        .unwrap();
        assert_eq!(
            resolve.addresses(),
            [
                "198.18.0.7".parse::<IpAddr>().unwrap(),
                "::ffff:198.18.0.7".parse().unwrap(),
                "fe80::1".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn a_resolver_error_is_a_result() {
        let resolve = parse_resolve(serde_json::json!({
            "addresses": [],
            "error": "gaierror(-2, 'Name or service not known')",
        }))
        .unwrap();
        assert!(matches!(resolve, Resolve::Failed { .. }));
        assert!(resolve.addresses().is_empty());
    }

    #[test]
    fn rejects_a_non_address() {
        let error = parse_resolve(serde_json::json!({
            "addresses": ["not-an-ip"],
            "error": null,
        }))
        .unwrap_err();
        assert!(error.to_string().contains("not-an-ip"), "{error}");
    }
}
