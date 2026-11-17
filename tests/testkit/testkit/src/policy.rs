// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox policies for tests: [`base`], read from `base-policy.yaml`, plus
//! [`allow`] and the [`Endpoint`] settings for the network access a test
//! needs.
//!
//! ```ignore
//! let mut policy = testkit::policy::base();
//! testkit::policy::allow(&mut policy, "upstream", "host.openshell.internal", port, PYTHON_BINARIES)
//!     .rest(Access::Full)
//!     .credential_binding(&provider);
//! ```

use openshell_sdk::raw::proto;

use crate::error::{Error, Result, ResultExt as _};

pub use proto::NetworkAccessPreset as Access;

const BASE: &str = include_str!("base-policy.yaml");

/// The policy in `base-policy.yaml`. It allows no network access.
pub fn base() -> proto::SandboxPolicy {
    openshell_policy::parse_sandbox_policy(BASE).expect("base-policy.yaml is a valid policy")
}

/// Let `binaries` connect to `host:port` under the network policy `name`,
/// adding the policy if it doesn't exist. Returns the new endpoint, which
/// [`Endpoint`] configures further.
///
/// A policy's binaries apply to all its endpoints, so calling this again with
/// the same `name` adds `binaries` to the existing ones, and every endpoint
/// under `name` allows all of them. Use a different `name` to keep them apart.
pub fn allow<'a>(
    policy: &'a mut proto::SandboxPolicy,
    name: &str,
    host: &str,
    port: u16,
    binaries: &[&str],
) -> &'a mut proto::NetworkEndpoint {
    let rule = policy
        .network_policies
        .entry(name.to_string())
        .or_insert_with(|| proto::NetworkPolicyRule {
            name: name.to_string(),
            ..proto::NetworkPolicyRule::default()
        });
    for binary in binaries {
        if !rule
            .binaries
            .iter()
            .any(|existing| existing.path == *binary)
        {
            rule.binaries.push(proto::NetworkBinary {
                path: (*binary).to_string(),
            });
        }
    }
    rule.endpoints.push(proto::NetworkEndpoint {
        host: host.to_string(),
        port: port.into(),
        ports: vec![port.into()],
        ..proto::NetworkEndpoint::default()
    });
    rule.endpoints
        .last_mut()
        .expect("an endpoint was just added")
}

/// The policy as YAML, for CLI commands such as `policy set`.
pub fn to_yaml(policy: &proto::SandboxPolicy) -> Result<String> {
    openshell_policy::serialize_sandbox_policy(policy)
        .map_err(|error| Error::msg(format!("{error:?}")))
        .context("serialize the policy")
}

/// Settings for an endpoint from [`allow`], named as in policy YAML.
pub trait Endpoint {
    /// `protocol: rest` with `access`.
    fn rest(&mut self, access: Access) -> &mut Self;
    /// `protocol: websocket` with `access`.
    fn websocket(&mut self, access: Access) -> &mut Self;
    /// `tls: skip`.
    fn tls_skip(&mut self) -> &mut Self;
    /// `request_body_credential_rewrite`.
    fn request_body_credential_rewrite(&mut self, rewrite: bool) -> &mut Self;
    /// `credential_binding: {provider: <provider>}`.
    fn credential_binding(&mut self, provider: &str) -> &mut Self;
    /// `allow_uninspected_credentials: true`.
    fn allow_uninspected_credentials(&mut self) -> &mut Self;
}

impl Endpoint for proto::NetworkEndpoint {
    fn rest(&mut self, access: Access) -> &mut Self {
        self.protocol = "rest".to_string();
        self.access = access as i32;
        self
    }

    fn websocket(&mut self, access: Access) -> &mut Self {
        self.protocol = "websocket".to_string();
        self.access = access as i32;
        self
    }

    fn tls_skip(&mut self) -> &mut Self {
        self.tls = proto::NetworkTlsMode::Skip as i32;
        self
    }

    fn request_body_credential_rewrite(&mut self, rewrite: bool) -> &mut Self {
        self.request_body_credential_rewrite = rewrite;
        self
    }

    fn credential_binding(&mut self, provider: &str) -> &mut Self {
        self.credential_binding = Some(proto::NetworkCredentialBinding {
            provider: provider.to_string(),
        });
        self
    }

    fn allow_uninspected_credentials(&mut self) -> &mut Self {
        self.allow_uninspected_credentials = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each helper builds what the YAML it is named after parses to, so the
    /// gateway can't tell the two apart.
    #[test]
    fn helpers_match_the_yaml_they_name() {
        let mut policy = base();
        allow(
            &mut policy,
            "upstream",
            "example.test",
            8080,
            &["/usr/bin/python*"],
        )
        .rest(Access::Full)
        .tls_skip()
        .request_body_credential_rewrite(true)
        .credential_binding("provider");
        allow(
            &mut policy,
            "upstream",
            "example.test",
            8081,
            &["/usr/bin/python*"],
        )
        .websocket(Access::ReadWrite)
        .allow_uninspected_credentials();

        let yaml = format!(
            "{BASE}network_policies:
  upstream:
    name: upstream
    endpoints:
      - host: example.test
        port: 8080
        protocol: rest
        access: full
        tls: skip
        request_body_credential_rewrite: true
        credential_binding: {{provider: provider}}
      - host: example.test
        port: 8081
        protocol: websocket
        access: read-write
        allow_uninspected_credentials: true
    binaries:
      - path: /usr/bin/python*
"
        );
        let expected = openshell_policy::parse_sandbox_policy(&yaml).expect("the YAML parses");
        assert_eq!(policy, expected);
        let round_trip =
            openshell_policy::parse_sandbox_policy(&to_yaml(&policy).expect("serializes"))
                .expect("the serialized policy parses");
        assert_eq!(round_trip, expected);
    }
}
