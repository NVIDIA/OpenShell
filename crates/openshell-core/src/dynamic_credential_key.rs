// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Keys for endpoint-bound dynamic credentials.
//!
//! The gateway encodes one key per credential, endpoint selector, and owning
//! endpoint. The supervisor matches requests against the endpoint selector,
//! tells credentials apart by their trailing identity, and scopes each key to
//! one credential generation. Keeping all three operations here means the key
//! layout is defined in one place.
//!
//! Layout: `host \t port \t path \t owner \t provider:credential`. A scoped key
//! inserts `rev:<revision> \t installation:<id>` before the trailing identity.

use crate::provider_credentials::ProviderCredentialSnapshot;

/// A validated endpoint-bound credential key. Fields cannot contain control
/// characters, including the tab used to separate encoded components.
pub struct DynamicCredentialKey<'a> {
    host: &'a str,
    port: u32,
    path: &'a str,
    owner: &'a str,
    provider_name: &'a str,
    credential_name: &'a str,
}

impl<'a> DynamicCredentialKey<'a> {
    /// Validates components before they can be encoded into a map or cache key.
    ///
    /// # Errors
    /// Returns an error for control characters, empty required fields, invalid
    /// ports, or a provider name containing the credential identity separator.
    pub fn new(
        host: &'a str,
        port: u32,
        path: &'a str,
        owner: &'a str,
        provider_name: &'a str,
        credential_name: &'a str,
    ) -> miette::Result<Self> {
        for (field, value) in [
            ("host", host),
            ("path", path),
            ("owner", owner),
            ("provider name", provider_name),
            ("credential name", credential_name),
        ] {
            if value.chars().any(char::is_control) {
                return Err(miette::miette!(
                    "dynamic credential key {field} contains a control character"
                ));
            }
            if field != "path" && value.is_empty() {
                return Err(miette::miette!("dynamic credential key {field} is empty"));
            }
        }
        if provider_name.contains(':') || !(1..=u32::from(u16::MAX)).contains(&port) {
            return Err(miette::miette!(
                "dynamic credential key has an invalid provider name or port"
            ));
        }
        Ok(Self {
            host,
            port,
            path,
            owner,
            provider_name,
            credential_name,
        })
    }

    /// Encodes the key. Host matching is case-insensitive, so the host is
    /// lowercased to keep equal selectors on equal keys.
    #[must_use]
    pub fn encode(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}:{}",
            self.host.to_ascii_lowercase(),
            self.port,
            self.path,
            self.owner,
            self.provider_name,
            self.credential_name
        )
    }
}

/// The endpoint selector at the front of a key, as written in the key.
pub struct EndpointSelector<'a> {
    pub host: &'a str,
    pub port: &'a str,
    pub path: &'a str,
}

/// Reads an endpoint selector from a supported key layout. Malformed keys and
/// keys without an endpoint selector return `None`.
#[must_use]
pub fn endpoint_selector(key: &str) -> Option<EndpointSelector<'_>> {
    decode(key)?.0
}

/// Reads the trailing `provider:credential` identity of a valid key.
///
/// Endpoint and generation fields do not change the credential's identity.
/// Malformed keys return `None`.
#[must_use]
pub fn credential_identity(key: &str) -> Option<&str> {
    Some(decode(key)?.1)
}

fn decode(key: &str) -> Option<(Option<EndpointSelector<'_>>, &str)> {
    // A stack buffer bounds parsing and avoids allocating on each request.
    let mut fields = [""; 7];
    let mut count = 0;
    for field in key.split('\t') {
        if count == fields.len() || field.chars().any(char::is_control) {
            return None;
        }
        fields[count] = field;
        count += 1;
    }
    let (identity, prefix) = fields[..count].split_last()?;
    let (provider, credential) = identity.split_once(':')?;
    if provider.is_empty() || credential.is_empty() {
        return None;
    }
    let valid_revision = |value: &str| {
        value
            .strip_prefix("rev:")
            .is_some_and(|revision| revision.parse::<u64>().is_ok())
    };
    let valid_installation = |value: &str| {
        value
            .strip_prefix("installation:")
            .is_some_and(|id| !id.is_empty())
    };
    match prefix {
        [] => Some((None, identity)),
        [revision, installation]
            if valid_revision(revision) && valid_installation(installation) =>
        {
            Some((None, identity))
        }
        [host, port, path, rest @ ..] => {
            // Accept legacy selector-only keys and revision-only cache keys,
            // as well as keys carrying endpoint ownership and installation ID.
            let valid_suffix = match rest {
                [] => true,
                [owner_or_revision] => !owner_or_revision.is_empty(),
                [revision, installation] => {
                    valid_revision(revision) && valid_installation(installation)
                }
                [owner, revision, installation] => {
                    !owner.is_empty()
                        && valid_revision(revision)
                        && valid_installation(installation)
                }
                _ => false,
            };
            if host.is_empty()
                || port.parse::<u16>().ok().is_none_or(|port| port == 0)
                || !valid_suffix
            {
                return None;
            }
            Some((Some(EndpointSelector { host, port, path }), identity))
        }
        _ => None,
    }
}

impl ProviderCredentialSnapshot {
    /// Scopes `key` to this snapshot's revision and installation, so cached
    /// tokens never cross a credential generation. A key without a tab has no
    /// endpoint selector and is scoped as a whole.
    #[must_use]
    pub fn scoped_key(&self, key: &str) -> String {
        match key.rsplit_once('\t') {
            Some((selector, identity)) => format!(
                "{selector}\trev:{}\tinstallation:{}\t{identity}",
                self.revision, self.installation_id
            ),
            None => format!(
                "rev:{}\tinstallation:{}\t{key}",
                self.revision, self.installation_id
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> String {
        DynamicCredentialKey::new(
            "API.Example.com",
            443,
            "/v1/**",
            "owner-a",
            "provider",
            "access_token",
        )
        .expect("valid components")
        .encode()
    }

    #[test]
    fn encoding_round_trips_selector_and_identity() {
        assert_eq!(
            key(),
            "api.example.com\t443\t/v1/**\towner-a\tprovider:access_token"
        );
        let key = key();
        let selector = endpoint_selector(&key).expect("encoded key has a selector");
        assert_eq!(
            (selector.host, selector.port, selector.path),
            ("api.example.com", "443", "/v1/**")
        );
        assert_eq!(credential_identity(&key), Some("provider:access_token"));
    }

    #[test]
    fn construction_rejects_unsafe_components() {
        for invalid in ["a\tshared", "a\nshared", "a\rshared", "a\0shared"] {
            for position in 0..5 {
                let mut fields = ["api.example.com", "/v1/**", "owner", "provider", "access"];
                fields[position] = invalid;
                assert!(
                    DynamicCredentialKey::new(
                        fields[0], 443, fields[1], fields[2], fields[3], fields[4]
                    )
                    .is_err(),
                    "field {position}"
                );
            }
        }
        for port in [0, 65_536] {
            assert!(
                DynamicCredentialKey::new(
                    "api.example.com",
                    port,
                    "",
                    "owner",
                    "provider",
                    "access"
                )
                .is_err()
            );
        }
        assert!(
            DynamicCredentialKey::new(
                "api.example.com",
                443,
                "",
                "owner",
                "provider:other",
                "access"
            )
            .is_err()
        );
    }

    #[test]
    fn decoding_preserves_supported_layouts_and_rejects_malformed_keys() {
        for key in [
            "provider:access",
            "rev:7\tinstallation:id\tprovider:access",
            "api.example.com\t443\t\tprovider:access",
            "api.example.com\t443\t/v1/**\trev:7\tprovider:access",
            "api.example.com\t443\t/v1/**\trev:7\tinstallation:id\tprovider:access",
            "api.example.com\t443\t/v1/**\towner\tprovider:access",
            "api.example.com\t443\t/v1/**\towner\trev:7\tinstallation:id\tprovider:access",
        ] {
            assert_eq!(credential_identity(key), Some("provider:access"), "{key:?}");
            assert_eq!(
                endpoint_selector(key).is_some(),
                key.starts_with("api.example.com")
            );
        }
        for key in [
            "host\t443\t/v1/**",
            "provider:",
            ":access",
            "api.example.com\t0\t\tprovider:access",
            "api.example.com\t443\t/v1/**\towner\tprovider:a\tshared",
            "api.example.com\t443\t/v1/**\towner\tprovider:a\tother:access",
            "api.example.com\t443\t/v1/**\towner\trev:no\tinstallation:id\tprovider:access",
            "api.example.com\t443\t/v1/**\towner\trev:7\tinstallation:\tprovider:access",
            "api.example.com\t443\t/v1/**\towner\trev:7\tinstallation:id\tprovider:a\tshared",
            "api.example.com\t443\t/v1/**\towner\tprovider:a\nshared",
        ] {
            assert!(credential_identity(key).is_none(), "{key:?}");
            assert!(endpoint_selector(key).is_none(), "{key:?}");
        }
    }

    #[test]
    fn scoping_inserts_the_generation_before_the_identity() {
        let snapshot = ProviderCredentialSnapshot {
            installation_id: "install".into(),
            revision: 7,
            ..Default::default()
        };
        let scoped = snapshot.scoped_key(&key());
        assert_eq!(
            scoped,
            "api.example.com\t443\t/v1/**\towner-a\trev:7\tinstallation:install\tprovider:access_token"
        );
        // Scoping must not disturb selector parsing or credential identity.
        assert_eq!(
            endpoint_selector(&scoped).map(|selector| selector.path),
            Some("/v1/**")
        );
        assert_eq!(credential_identity(&scoped), Some("provider:access_token"));
        assert_eq!(
            snapshot.scoped_key("provider:access_token"),
            "rev:7\tinstallation:install\tprovider:access_token"
        );
        // A leading tab is an empty selector, not a missing one.
        assert_eq!(
            snapshot.scoped_key("\tprovider:access_token"),
            "\trev:7\tinstallation:install\tprovider:access_token"
        );
    }
}
