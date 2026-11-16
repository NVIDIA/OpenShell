// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configuration types and defaults shared by the gateway, the supervisor, and
//! the compute drivers.

use serde::{Deserialize, Deserializer, Serialize, de};
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
/// Default gateway server port.
pub const DEFAULT_SERVER_PORT: u16 = 17670;

/// Default container stop timeout in seconds (SIGTERM → SIGKILL).
pub const DEFAULT_STOP_TIMEOUT_SECS: u32 = 10;

/// Default OCI repository for the supervisor image (no tag).
pub const DEFAULT_SUPERVISOR_IMAGE_REPO: &str = "ghcr.io/nvidia/openshell/supervisor";

/// Default OCI repository for the sandbox runtime image (no tag).
pub const DEFAULT_SANDBOX_RUNTIME_IMAGE_REPO: &str = "ghcr.io/nvidia/openshell/sandbox";

/// Process-level default for the trusted sandbox runtime image.
pub const SANDBOX_RUNTIME_IMAGE_ENV: &str = "OPENSHELL_SANDBOX_RUNTIME_IMAGE";

/// Process-level default for the trusted supervisor image.
pub const SUPERVISOR_IMAGE_ENV: &str = "OPENSHELL_SUPERVISOR_IMAGE";

fn compiled_sandbox_runtime_image() -> String {
    format!(
        "{DEFAULT_SANDBOX_RUNTIME_IMAGE_REPO}:{}",
        default_supervisor_image_tag()
    )
}

fn compiled_supervisor_image() -> String {
    format!(
        "{DEFAULT_SUPERVISOR_IMAGE_REPO}:{}",
        default_supervisor_image_tag()
    )
}

fn runtime_image_default(environment_value: Option<String>, compiled_default: String) -> String {
    environment_value.unwrap_or(compiled_default)
}

/// Return the process-configured sandbox runtime image, or the compiled default.
#[must_use]
pub fn default_sandbox_runtime_image() -> String {
    runtime_image_default(
        std::env::var(SANDBOX_RUNTIME_IMAGE_ENV).ok(),
        compiled_sandbox_runtime_image(),
    )
}

/// Return the process-configured supervisor image, or the compiled default.
#[must_use]
pub fn default_supervisor_image() -> String {
    runtime_image_default(
        std::env::var(SUPERVISOR_IMAGE_ENV).ok(),
        compiled_supervisor_image(),
    )
}

fn default_supervisor_image_tag() -> String {
    resolve_supervisor_image_tag(&[
        option_env!("OPENSHELL_IMAGE_TAG").unwrap_or(""),
        option_env!("IMAGE_TAG").unwrap_or(""),
        env!("CARGO_PKG_VERSION"),
    ])
}

/// Resolve the supervisor image tag from an ordered list of candidates.
///
/// Returns the first non-empty, non-`"0.0.0"` candidate, falling back to
/// `"dev"` when none qualifies. Replaces `+` with `-` for OCI tag
/// compatibility.
#[must_use]
pub fn resolve_supervisor_image_tag(candidates: &[&str]) -> String {
    candidates
        .iter()
        .copied()
        .find(|t| !t.is_empty() && *t != "0.0.0")
        .unwrap_or("dev")
        .replace('+', "-")
}

/// Canonical policy controlling when a driver pulls a sandbox image.
///
/// Backends translate this shared vocabulary to their runtime API. `newer` is
/// supported only by Podman; other backends reject it during configuration.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImagePullPolicy {
    /// Always pull, even if a local image is available.
    Always,
    /// Pull only when a local image is unavailable.
    #[default]
    IfNotPresent,
    /// Never pull; fail when a local image is unavailable.
    Never,
    /// Pull only when the registry image is newer than the local copy.
    Newer,
}

impl ImagePullPolicy {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::IfNotPresent => "if_not_present",
            Self::Never => "never",
            Self::Newer => "newer",
        }
    }
}

impl fmt::Display for ImagePullPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ImagePullPolicy {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "always" => Ok(Self::Always),
            "if_not_present" => Ok(Self::IfNotPresent),
            "never" => Ok(Self::Never),
            "newer" => Ok(Self::Newer),
            other => Err(format!(
                "invalid image pull policy '{other}'; expected one of: always, if_not_present, never, newer"
            )),
        }
    }
}

/// Canonical `AppArmor` confinement requested for a sandbox container.
///
/// Drivers translate this model to their runtime API. An omitted value leaves
/// the runtime default unchanged; `Unconfined` is explicit because the
/// supervisor needs mount operations that the default Docker/Podman profile
/// commonly denies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppArmorProfile {
    RuntimeDefault,
    Unconfined,
    Localhost(String),
}

impl AppArmorProfile {
    #[must_use]
    pub const fn kubernetes_type(&self) -> &'static str {
        match self {
            Self::RuntimeDefault => "RuntimeDefault",
            Self::Unconfined => "Unconfined",
            Self::Localhost(_) => "Localhost",
        }
    }

    #[must_use]
    pub fn localhost_profile(&self) -> Option<&str> {
        match self {
            Self::Localhost(profile) => Some(profile),
            Self::RuntimeDefault | Self::Unconfined => None,
        }
    }

    /// Translate to the OCI `apparmor=<profile>` security option.
    ///
    /// `RuntimeDefault` deliberately returns `None`: omitting an OCI option
    /// asks Docker/Podman to apply their runtime default profile.
    #[must_use]
    pub fn oci_security_opt(&self) -> Option<String> {
        match self {
            Self::RuntimeDefault => None,
            Self::Unconfined => Some("apparmor=unconfined".to_string()),
            Self::Localhost(profile) => Some(format!("apparmor={profile}")),
        }
    }
}

impl fmt::Display for AppArmorProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuntimeDefault => f.write_str("RuntimeDefault"),
            Self::Unconfined => f.write_str("Unconfined"),
            Self::Localhost(profile) => write!(f, "Localhost/{profile}"),
        }
    }
}

impl FromStr for AppArmorProfile {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "RuntimeDefault" => Ok(Self::RuntimeDefault),
            "Unconfined" => Ok(Self::Unconfined),
            other => match other.strip_prefix("Localhost/") {
                Some("") => Err(
                    "invalid AppArmor profile 'Localhost/'; expected non-empty profile name"
                        .to_string(),
                ),
                Some(profile) if !profile.contains(char::is_whitespace) => {
                    Ok(Self::Localhost(profile.to_string()))
                }
                Some(_) => {
                    Err("invalid AppArmor localhost profile; whitespace is not allowed".to_string())
                }
                None => Err(format!(
                    "unknown AppArmor profile '{other}'; expected 'RuntimeDefault', 'Unconfined', or 'Localhost/<profile-name>'"
                )),
            },
        }
    }
}

impl Serialize for AppArmorProfile {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

/// Common local-driver corporate forward-proxy settings.
///
/// This type is `flatten`ed by local compute-driver tables, preserving the
/// established TOML field names while keeping their safety contract shared.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamProxyConfig {
    pub https_proxy: Option<String>,
    pub no_proxy: Option<String>,
    pub proxy_auth_file: Option<PathBuf>,
    pub proxy_auth_allow_insecure: Option<bool>,
    pub proxy_connect_by_hostname: Option<bool>,
}

impl UpstreamProxyConfig {
    /// Validate relationships that are independent of the container backend.
    /// Credential contents are intentionally not read here and are never put
    /// in an error message; drivers validate and stage them per sandbox.
    pub fn validate(&self) -> Result<(), String> {
        use crate::driver_utils::{UpstreamProxyUrlError, parse_upstream_proxy_url};

        let proxy_secure = if let Some(url) = self.https_proxy.as_deref() {
            parse_upstream_proxy_url(url)
                .map_err(|err| match err {
                    UpstreamProxyUrlError::Empty => "https_proxy must not be empty when set".to_string(),
                    UpstreamProxyUrlError::InlineCredentials => "https_proxy must not embed credentials; supply them with proxy_auth_file so they are not stored in configuration or runtime metadata".to_string(),
                    err => format!("https_proxy {err}"),
                })?
                .secure
        } else {
            false
        };

        if self
            .no_proxy
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err("no_proxy must not be empty when set; omit it instead".to_string());
        }
        if self.no_proxy.is_some() && self.https_proxy.is_none() {
            return Err("no_proxy is set but no https_proxy is configured".to_string());
        }
        if let Some(path) = self.proxy_auth_file.as_ref() {
            if path.as_os_str().is_empty() {
                return Err("proxy_auth_file must not be empty when set".to_string());
            }
            if self.https_proxy.is_none() {
                return Err("proxy_auth_file is set but no https_proxy is configured".to_string());
            }
            if !proxy_secure && self.proxy_auth_allow_insecure != Some(true) {
                return Err("proxy_auth_file sends a cleartext Basic credential to an http:// proxy; set proxy_auth_allow_insecure = true to acknowledge that exposure".to_string());
            }
        } else if self.proxy_auth_allow_insecure.is_some() {
            return Err(
                "proxy_auth_allow_insecure is set but no proxy_auth_file is configured".to_string(),
            );
        }
        if self.proxy_connect_by_hostname.is_some() && self.https_proxy.is_none() {
            return Err(
                "proxy_connect_by_hostname is set but no https_proxy is configured".to_string(),
            );
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for AppArmorProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_pull_policy_uses_canonical_vocabulary() {
        for (value, expected) in [
            ("always", ImagePullPolicy::Always),
            ("if_not_present", ImagePullPolicy::IfNotPresent),
            ("never", ImagePullPolicy::Never),
            ("newer", ImagePullPolicy::Newer),
        ] {
            assert_eq!(value.parse::<ImagePullPolicy>(), Ok(expected));
            assert_eq!(expected.to_string(), value);
            assert_eq!(serde_json::to_value(expected).unwrap(), value);
        }
        assert!("missing".parse::<ImagePullPolicy>().is_err());
        assert!("IfNotPresent".parse::<ImagePullPolicy>().is_err());
    }

    #[test]
    fn app_armor_profiles_round_trip_and_translate_for_each_backend() {
        for (value, expected, kubernetes_type, localhost_profile, oci_security_opt) in [
            (
                "RuntimeDefault",
                AppArmorProfile::RuntimeDefault,
                "RuntimeDefault",
                None,
                None,
            ),
            (
                "Unconfined",
                AppArmorProfile::Unconfined,
                "Unconfined",
                None,
                Some("apparmor=unconfined"),
            ),
            (
                "Localhost/openshell-supervisor",
                AppArmorProfile::Localhost("openshell-supervisor".to_string()),
                "Localhost",
                Some("openshell-supervisor"),
                Some("apparmor=openshell-supervisor"),
            ),
        ] {
            let parsed = value.parse::<AppArmorProfile>().expect("valid profile");
            assert_eq!(parsed, expected);
            assert_eq!(parsed.to_string(), value);
            assert_eq!(parsed.kubernetes_type(), kubernetes_type);
            assert_eq!(parsed.localhost_profile(), localhost_profile);
            assert_eq!(parsed.oci_security_opt().as_deref(), oci_security_opt);

            let json = serde_json::to_value(&parsed).expect("profile serializes");
            assert_eq!(json, value);
            assert_eq!(
                serde_json::from_value::<AppArmorProfile>(json).expect("profile deserializes"),
                parsed
            );
        }

        for invalid in [
            "Localhost/",
            "Localhost/openshell profile",
            "runtimeDefault",
            "unconfined",
            "Unknown",
        ] {
            assert!(
                invalid.parse::<AppArmorProfile>().is_err(),
                "{invalid} should be rejected"
            );
        }
    }

    #[test]
    fn upstream_proxy_validation_enforces_cross_field_contract() {
        let auth_file = Some("/run/secrets/proxy-auth".into());
        let cases = [
            ("default", UpstreamProxyConfig::default(), None),
            (
                "https auth",
                UpstreamProxyConfig {
                    https_proxy: Some("https://proxy.example:8443".to_string()),
                    proxy_auth_file: auth_file.clone(),
                    ..Default::default()
                },
                None,
            ),
            (
                "acknowledged http auth",
                UpstreamProxyConfig {
                    https_proxy: Some("http://proxy.example:8080".to_string()),
                    proxy_auth_file: auth_file.clone(),
                    proxy_auth_allow_insecure: Some(true),
                    ..Default::default()
                },
                None,
            ),
            (
                "unacknowledged http auth",
                UpstreamProxyConfig {
                    https_proxy: Some("http://proxy.example:8080".to_string()),
                    proxy_auth_file: auth_file.clone(),
                    ..Default::default()
                },
                Some("proxy_auth_allow_insecure"),
            ),
            (
                "no_proxy without proxy",
                UpstreamProxyConfig {
                    no_proxy: Some("localhost".to_string()),
                    ..Default::default()
                },
                Some("no_proxy"),
            ),
            (
                "blank no_proxy",
                UpstreamProxyConfig {
                    https_proxy: Some("https://proxy.example:8443".to_string()),
                    no_proxy: Some("  ".to_string()),
                    ..Default::default()
                },
                Some("no_proxy"),
            ),
            (
                "auth file without proxy",
                UpstreamProxyConfig {
                    proxy_auth_file: auth_file,
                    ..Default::default()
                },
                Some("proxy_auth_file"),
            ),
            (
                "ack without auth file",
                UpstreamProxyConfig {
                    https_proxy: Some("http://proxy.example:8080".to_string()),
                    proxy_auth_allow_insecure: Some(true),
                    ..Default::default()
                },
                Some("proxy_auth_allow_insecure"),
            ),
            (
                "hostname mode without proxy",
                UpstreamProxyConfig {
                    proxy_connect_by_hostname: Some(true),
                    ..Default::default()
                },
                Some("proxy_connect_by_hostname"),
            ),
            (
                "empty proxy",
                UpstreamProxyConfig {
                    https_proxy: Some(String::new()),
                    ..Default::default()
                },
                Some("https_proxy"),
            ),
            (
                "inline credentials",
                UpstreamProxyConfig {
                    https_proxy: Some(
                        "https://secret-user:secret-password@proxy.example:8443".to_string(),
                    ),
                    ..Default::default()
                },
                Some("must not embed credentials"),
            ),
        ];

        for (name, config, expected_error) in cases {
            match expected_error {
                None => config
                    .validate()
                    .unwrap_or_else(|error| panic!("{name}: {error}")),
                Some(expected) => {
                    let error = match config.validate() {
                        Ok(()) => panic!("{name} should fail validation"),
                        Err(error) => error,
                    };
                    assert!(error.contains(expected), "{name}: {error}");
                    assert!(!error.contains("secret-user"), "{name}: {error}");
                    assert!(!error.contains("secret-password"), "{name}: {error}");
                }
            }
        }
    }

    #[test]
    fn supervisor_image_tag_prefers_explicit_build_tags() {
        use super::resolve_supervisor_image_tag;
        assert_eq!(
            resolve_supervisor_image_tag(&["1.2.3", "sha", "0.0.0"]),
            "1.2.3"
        );
        assert_eq!(resolve_supervisor_image_tag(&["", "sha", "0.0.0"]), "sha");
        assert_eq!(resolve_supervisor_image_tag(&["", "", "1.2.3"]), "1.2.3");
        assert_eq!(resolve_supervisor_image_tag(&["", "", "0.0.0"]), "dev");
        assert_eq!(
            resolve_supervisor_image_tag(&["latest", "", "1.2.3"]),
            "latest"
        );
    }

    #[test]
    fn supervisor_image_tag_sanitizes_build_metadata_for_oci() {
        use super::resolve_supervisor_image_tag;
        assert_eq!(
            resolve_supervisor_image_tag(&["", "", "0.0.37-dev.156+g1d3b741ee"]),
            "0.0.37-dev.156-g1d3b741ee",
        );
        assert_eq!(
            resolve_supervisor_image_tag(&["0.0.37-dev.156+g1d3b741ee", "", "0.0.0"]),
            "0.0.37-dev.156-g1d3b741ee",
        );
    }

    #[test]
    fn default_supervisor_image_is_version_pinned() {
        use super::{compiled_sandbox_runtime_image, compiled_supervisor_image};
        let image = compiled_supervisor_image();
        assert!(image.starts_with("ghcr.io/nvidia/openshell/supervisor:"));
        let tag = image.rsplit_once(':').unwrap().1;
        assert!(!tag.is_empty());

        let sandbox_image = compiled_sandbox_runtime_image();
        assert!(sandbox_image.starts_with("ghcr.io/nvidia/openshell/sandbox:"));
        let sandbox_tag = sandbox_image.rsplit_once(':').unwrap().1;
        assert!(!sandbox_tag.is_empty());
    }

    #[test]
    fn runtime_image_environment_value_replaces_compiled_default() {
        use super::runtime_image_default;

        let digest = format!("registry.example.com/sandbox@sha256:{}", "a".repeat(64));
        assert_eq!(
            runtime_image_default(Some(digest.clone()), "compiled:default".to_string()),
            digest
        );
        assert_eq!(
            runtime_image_default(None, "compiled:default".to_string()),
            "compiled:default"
        );
    }
}
