// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provider profiles for tests, built in Rust and rendered as the YAML that
//! [`Context::import_profile`](crate::Context::import_profile) and
//! [`Context::install_provider`](crate::Context::install_provider) take.
//!
//! ```ignore
//! use testkit::policy::{Access, Endpoint as _};
//!
//! let profile = testkit::Profile::new(&cx.name("auto"))
//!     .credential(
//!         testkit::Credential::new("api_key")
//!             .env_var("API_KEY")
//!             .required()
//!             .auth_style("header")
//!             .header_name("x-api-key"),
//!     )
//!     .endpoint("api.example.test", 443, |ep| {
//!         ep.rest(Access::ReadWrite).enforce();
//!     })
//!     .binaries(["/usr/bin/curl"]);
//! cx.import_profile(&profile.to_yaml()?).await?;
//! ```
//!
//! Profile endpoints are policy endpoints, so [`policy::Endpoint`] configures
//! them. Setters are named after the YAML fields they set.
//!
//! [`policy::Endpoint`]: crate::policy::Endpoint

use openshell_providers::{ProviderTypeProfile, profile_to_yaml};
use openshell_sdk::raw::proto;

use crate::error::{Error, Result, ResultExt as _};

pub use proto::ProviderProfileCategory as Category;

/// A provider profile. Its display name defaults to its id, and its category
/// to `other`.
#[derive(Clone, Debug)]
#[must_use]
pub struct Profile {
    profile: proto::ProviderProfile,
}

impl Profile {
    /// A profile with `id`, the provider type it defines.
    pub fn new(id: &str) -> Self {
        Self {
            profile: proto::ProviderProfile {
                id: id.to_string(),
                display_name: id.to_string(),
                category: Category::Other as i32,
                ..proto::ProviderProfile::default()
            },
        }
    }

    /// The profile's `id`.
    pub fn id(&self) -> &str {
        &self.profile.id
    }

    /// `display_name`.
    pub fn display_name(mut self, name: &str) -> Self {
        self.profile.display_name = name.to_string();
        self
    }

    /// `category`.
    pub fn category(mut self, category: Category) -> Self {
        self.profile.category = category as i32;
        self
    }

    /// Add `credential` to `credentials`.
    pub fn credential(mut self, credential: Credential) -> Self {
        self.profile.credentials.push(credential.credential);
        self
    }

    /// `discovery: {credentials: [..]}`: the credentials the CLI looks for in
    /// its environment when it creates the provider itself.
    pub fn discover<I, S>(mut self, credentials: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.profile
            .discovery
            .get_or_insert_with(proto::ProviderProfileDiscovery::default)
            .credentials
            .extend(credentials.into_iter().map(Into::into));
        self
    }

    /// Add an endpoint for `host:port` to `endpoints`, configured by
    /// `configure` with [`policy::Endpoint`](crate::policy::Endpoint).
    pub fn endpoint(
        mut self,
        host: &str,
        port: u16,
        configure: impl FnOnce(&mut proto::NetworkEndpoint),
    ) -> Self {
        let mut endpoint = proto::NetworkEndpoint {
            host: host.to_string(),
            port: port.into(),
            ..proto::NetworkEndpoint::default()
        };
        configure(&mut endpoint);
        self.profile.endpoints.push(endpoint);
        self
    }

    /// Add `paths` to `binaries`.
    pub fn binaries<I, S>(mut self, paths: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.profile.binaries.extend(
            paths
                .into_iter()
                .map(|path| proto::NetworkBinary { path: path.into() }),
        );
        self
    }

    /// The profile as YAML, as `profile export` writes it.
    pub fn to_yaml(&self) -> Result<String> {
        profile_to_yaml(&ProviderTypeProfile::from_proto(&self.profile))
            .map_err(Error::from_display)
            .context(format!("render provider profile {}", self.profile.id))
    }
}

/// A credential in a [`Profile`].
#[derive(Clone, Debug)]
#[must_use]
pub struct Credential {
    credential: proto::ProviderProfileCredential,
}

impl Credential {
    /// A credential called `name`.
    pub fn new(name: &str) -> Self {
        Self {
            credential: proto::ProviderProfileCredential {
                name: name.to_string(),
                ..proto::ProviderProfileCredential::default()
            },
        }
    }

    /// Add `var` to `env_vars`.
    pub fn env_var(mut self, var: &str) -> Self {
        self.credential.env_vars.push(var.to_string());
        self
    }

    /// `required: true`.
    pub fn required(mut self) -> Self {
        self.credential.required = true;
        self
    }

    /// `auth_style`, such as `bearer` or `header`.
    pub fn auth_style(mut self, style: &str) -> Self {
        self.credential.auth_style = style.to_string();
        self
    }

    /// `header_name`.
    pub fn header_name(mut self, name: &str) -> Self {
        self.credential.header_name = name.to_string();
        self
    }

    /// `refresh`, for a credential the gateway refreshes.
    pub fn refresh(mut self, refresh: proto::ProviderCredentialRefresh) -> Self {
        self.credential.refresh = Some(refresh);
        self
    }
}

#[cfg(test)]
mod tests {
    use openshell_providers::parse_profile_yaml;

    use super::*;
    use crate::policy::{Access, Endpoint as _};

    fn parsed(yaml: &str) -> ProviderTypeProfile {
        parse_profile_yaml(yaml).expect("the YAML parses")
    }

    /// Each setter sets the YAML field it is named after, so the gateway
    /// can't tell a built profile from the YAML.
    #[test]
    fn setters_match_the_yaml_they_name() {
        let profile = Profile::new("example")
            .display_name("Example")
            .category(Category::Inference)
            .credential(
                Credential::new("api_key")
                    .env_var("API_KEY")
                    .env_var("OTHER_KEY")
                    .required()
                    .auth_style("header")
                    .header_name("x-api-key"),
            )
            .discover(["api_key"])
            .endpoint("api.example.test", 443, |ep| {
                ep.rest(Access::ReadWrite).enforce().path("/v1/**");
            })
            .endpoint("ws.example.test", 8443, |ep| {
                ep.websocket(Access::ReadOnly);
            })
            .binaries(["/usr/bin/curl", "/usr/bin/python*"]);

        let expected = parsed(
            "id: example
display_name: Example
category: inference
credentials:
  - name: api_key
    env_vars: [API_KEY, OTHER_KEY]
    required: true
    auth_style: header
    header_name: x-api-key
discovery:
  credentials: [api_key]
endpoints:
  - host: api.example.test
    port: 443
    path: /v1/**
    protocol: rest
    access: read-write
    enforcement: enforce
  - host: ws.example.test
    port: 8443
    protocol: websocket
    access: read-only
binaries: [/usr/bin/curl, /usr/bin/python*]
",
        );
        let yaml = profile.to_yaml().expect("renders");
        assert_eq!(parsed(&yaml), expected, "rendered:\n{yaml}");
    }

    /// A profile with only an id has the display name and category the
    /// gateway requires.
    #[test]
    fn defaults() {
        let yaml = Profile::new("bare").to_yaml().expect("renders");
        assert_eq!(
            parsed(&yaml),
            parsed("id: bare\ndisplay_name: bare\ncategory: other\n"),
            "rendered:\n{yaml}"
        );
    }

    #[test]
    fn refresh() {
        let refresh = proto::ProviderCredentialRefresh {
            strategy: proto::ProviderCredentialRefreshStrategy::Oauth2RefreshToken as i32,
            token_url: "https://issuer.example.test/token".to_string(),
            scopes: vec!["openid".to_string()],
            refresh_before: Some(prost_types::Duration {
                seconds: 60,
                nanos: 0,
            }),
            material: vec![proto::ProviderCredentialRefreshMaterial {
                name: "refresh_token".to_string(),
                required: true,
                secret: true,
                ..proto::ProviderCredentialRefreshMaterial::default()
            }],
            ..proto::ProviderCredentialRefresh::default()
        };
        let yaml = Profile::new("refreshing")
            .credential(Credential::new("token").refresh(refresh))
            .to_yaml()
            .expect("renders");
        assert_eq!(
            parsed(&yaml),
            parsed(
                "id: refreshing
display_name: refreshing
category: other
credentials:
  - name: token
    refresh:
      strategy: oauth2_refresh_token
      token_url: https://issuer.example.test/token
      scopes: [openid]
      refresh_before: 60s
      material:
        - name: refresh_token
          required: true
          secret: true
"
            ),
            "rendered:\n{yaml}"
        );
    }
}
