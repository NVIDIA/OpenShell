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

/// Fields of one dynamic credential key.
///
/// Every field must be tab-free. The layout uses tab as its separator and
/// `encode` does not check, so callers must supply fields that profile and
/// provider validation already keep free of tabs.
pub struct DynamicCredentialKey<'a> {
    pub host: &'a str,
    pub port: u32,
    pub path: &'a str,
    pub owner: &'a str,
    pub provider_name: &'a str,
    pub credential_name: &'a str,
}

impl DynamicCredentialKey<'_> {
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

/// Reads the endpoint selector of `key`. Returns `None` when the key has no
/// credential segment after the selector.
#[must_use]
pub fn endpoint_selector(key: &str) -> Option<EndpointSelector<'_>> {
    let mut parts = key.splitn(4, '\t');
    let host = parts.next()?;
    let port = parts.next()?;
    let path = parts.next()?;
    parts.next()?;
    Some(EndpointSelector { host, port, path })
}

/// The trailing `provider:credential` identity of `key`. Two keys name the
/// same credential exactly when their identities are equal, whatever endpoint
/// or generation they are bound to.
#[must_use]
pub fn credential_identity(key: &str) -> &str {
    key.rsplit('\t').next().unwrap_or(key)
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
        DynamicCredentialKey {
            host: "API.Example.com",
            port: 443,
            path: "/v1/**",
            owner: "owner-a",
            provider_name: "provider",
            credential_name: "access_token",
        }
        .encode()
    }

    #[test]
    fn encode_lowercases_host_and_keeps_layout() {
        assert_eq!(
            key(),
            "api.example.com\t443\t/v1/**\towner-a\tprovider:access_token"
        );
    }

    #[test]
    fn selector_and_identity_read_the_encoded_fields() {
        let key = key();
        let selector = endpoint_selector(&key).expect("encoded key has a selector");
        assert_eq!(
            (selector.host, selector.port, selector.path),
            ("api.example.com", "443", "/v1/**")
        );
        assert_eq!(credential_identity(&key), "provider:access_token");
    }

    #[test]
    fn selector_requires_a_credential_segment() {
        assert!(endpoint_selector("host\t443\t/v1/**").is_none());
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
        assert_eq!(credential_identity(&scoped), "provider:access_token");
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
