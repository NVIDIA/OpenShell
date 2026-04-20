// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Thin wrapper around [`oci_client::Client`] that pulls a public image for a
//! specific guest platform and normalizes the response into data our pipeline
//! can consume.

use std::collections::BTreeMap;
use std::str::FromStr;

use oci_client::client::{ClientConfig, ImageLayer};
use oci_client::manifest::{
    IMAGE_CONFIG_MEDIA_TYPE, IMAGE_DOCKER_CONFIG_MEDIA_TYPE, IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE,
    IMAGE_LAYER_GZIP_MEDIA_TYPE, IMAGE_LAYER_MEDIA_TYPE, IMAGE_MANIFEST_LIST_MEDIA_TYPE,
    IMAGE_MANIFEST_MEDIA_TYPE, ImageIndexEntry, OCI_IMAGE_INDEX_MEDIA_TYPE, OCI_IMAGE_MEDIA_TYPE,
};
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};

use super::metadata::{ImageConfig, Platform};

/// Image pulled from a registry, with the normalized subset our pipeline needs.
#[derive(Debug)]
pub struct PulledImage {
    /// Manifest digest (`sha256:...`), used as the cache key.
    pub manifest_digest: String,
    /// Layers in application order (lower → upper), already filtered for
    /// supported media types.
    pub layers: Vec<ImageLayer>,
    /// Normalized OCI image config.
    pub image_config: ImageConfig,
}

/// Pulls public OCI images for a fixed guest platform.
pub struct OciPuller {
    client: Client,
    platform: Platform,
}

impl OciPuller {
    #[must_use]
    pub fn new(platform: Platform) -> Self {
        let config = ClientConfig {
            platform_resolver: Some(Box::new(move |entries: &[ImageIndexEntry]| {
                pick_platform(entries, platform)
            })),
            ..Default::default()
        };
        Self {
            client: Client::new(config),
            platform,
        }
    }

    /// Pull `image_ref` (e.g. `docker.io/library/alpine:3.20`) anonymously.
    ///
    /// Returns the manifest digest + layer bytes + normalized config. Any
    /// error from the registry or the config decoder is surfaced verbatim.
    pub async fn pull(&self, image_ref: &str) -> Result<PulledImage, PullError> {
        let reference = Reference::from_str(image_ref)
            .map_err(|err| PullError::InvalidReference(err.to_string()))?;

        let accepted = vec![
            IMAGE_LAYER_MEDIA_TYPE,
            IMAGE_LAYER_GZIP_MEDIA_TYPE,
            IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE,
            IMAGE_MANIFEST_MEDIA_TYPE,
            OCI_IMAGE_MEDIA_TYPE,
            IMAGE_MANIFEST_LIST_MEDIA_TYPE,
            OCI_IMAGE_INDEX_MEDIA_TYPE,
            IMAGE_CONFIG_MEDIA_TYPE,
            IMAGE_DOCKER_CONFIG_MEDIA_TYPE,
        ];

        let image = self
            .client
            .pull(&reference, &RegistryAuth::Anonymous, accepted)
            .await
            .map_err(|err| PullError::Registry(err.to_string()))?;

        let manifest_digest = image.digest.ok_or_else(|| {
            PullError::Registry("registry did not return a manifest digest".into())
        })?;

        let image_config = parse_image_config(&image.config.data)?;

        Ok(PulledImage {
            manifest_digest,
            layers: image.layers,
            image_config,
        })
    }

    #[must_use]
    pub fn platform(&self) -> Platform {
        self.platform
    }
}

/// Pick the first index entry matching the requested platform.
fn pick_platform(entries: &[ImageIndexEntry], platform: Platform) -> Option<String> {
    entries
        .iter()
        .find(|entry| {
            entry
                .platform
                .as_ref()
                .is_some_and(|p| p.os == platform.os() && p.architecture == platform.arch())
        })
        .map(|entry| entry.digest.clone())
}

/// Deserialize the OCI image config JSON into our minimal view.
fn parse_image_config(config_bytes: &[u8]) -> Result<ImageConfig, PullError> {
    #[derive(serde::Deserialize)]
    struct RawConfig {
        config: Option<InnerConfig>,
    }
    #[derive(serde::Deserialize, Default)]
    #[serde(default)]
    struct InnerConfig {
        #[serde(rename = "Entrypoint")]
        entrypoint: Option<Vec<String>>,
        #[serde(rename = "Cmd")]
        cmd: Option<Vec<String>>,
        #[serde(rename = "Env")]
        env: Option<Vec<String>>,
        #[serde(rename = "WorkingDir")]
        working_dir: Option<String>,
        #[serde(rename = "Labels")]
        labels: Option<BTreeMap<String, String>>,
        #[serde(rename = "StopSignal")]
        stop_signal: Option<String>,
    }

    let raw: RawConfig = serde_json::from_slice(config_bytes)
        .map_err(|err| PullError::MalformedConfig(err.to_string()))?;
    let inner = raw.config.unwrap_or_default();
    Ok(ImageConfig {
        entrypoint: inner.entrypoint.unwrap_or_default(),
        cmd: inner.cmd.unwrap_or_default(),
        env: inner.env.unwrap_or_default(),
        working_dir: inner.working_dir.unwrap_or_default(),
        labels: inner.labels.unwrap_or_default(),
        stop_signal: inner.stop_signal.unwrap_or_default(),
    })
}

/// Errors raised during image pull or normalization.
#[derive(Debug, thiserror::Error)]
pub enum PullError {
    #[error("invalid image reference: {0}")]
    InvalidReference(String),
    #[error("registry error: {0}")]
    Registry(String),
    #[error("malformed OCI image config: {0}")]
    MalformedConfig(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use oci_client::manifest::Platform as SpecPlatform;

    fn entry(os: &str, arch: &str, digest: &str) -> ImageIndexEntry {
        ImageIndexEntry {
            media_type: OCI_IMAGE_MEDIA_TYPE.to_string(),
            digest: digest.to_string(),
            size: 0,
            platform: Some(SpecPlatform {
                architecture: arch.to_string(),
                os: os.to_string(),
                os_version: None,
                os_features: None,
                variant: None,
                features: None,
            }),
            annotations: None,
        }
    }

    #[test]
    fn pick_platform_selects_matching_entry() {
        let entries = vec![
            entry("linux", "amd64", "sha256:amd"),
            entry("linux", "arm64", "sha256:arm"),
        ];
        assert_eq!(
            pick_platform(&entries, Platform::LinuxAmd64),
            Some("sha256:amd".to_string())
        );
        assert_eq!(
            pick_platform(&entries, Platform::LinuxArm64),
            Some("sha256:arm".to_string())
        );
    }

    #[test]
    fn pick_platform_returns_none_when_unsupported() {
        let entries = vec![entry("windows", "amd64", "sha256:win")];
        assert!(pick_platform(&entries, Platform::LinuxAmd64).is_none());
    }

    #[test]
    fn parse_image_config_handles_entrypoint_and_cmd_fields() {
        let json = br#"{
            "architecture": "amd64",
            "os": "linux",
            "config": {
                "Entrypoint": ["/bin/sh", "-c"],
                "Cmd": ["echo hello"],
                "Env": ["PATH=/usr/bin"],
                "WorkingDir": "/app",
                "Labels": {"k": "v"},
                "StopSignal": "SIGTERM"
            }
        }"#;
        let cfg = parse_image_config(json).unwrap();
        assert_eq!(cfg.entrypoint, vec!["/bin/sh", "-c"]);
        assert_eq!(cfg.cmd, vec!["echo hello"]);
        assert_eq!(cfg.env, vec!["PATH=/usr/bin"]);
        assert_eq!(cfg.working_dir, "/app");
        assert_eq!(cfg.labels.get("k"), Some(&"v".to_string()));
        assert_eq!(cfg.stop_signal, "SIGTERM");
    }

    #[test]
    fn parse_image_config_tolerates_missing_config_block() {
        let json = br#"{"architecture":"amd64","os":"linux"}"#;
        let cfg = parse_image_config(json).unwrap();
        assert!(cfg.entrypoint.is_empty());
        assert!(cfg.cmd.is_empty());
        assert_eq!(cfg.working_dir, "");
    }

    #[test]
    fn parse_image_config_rejects_malformed_json() {
        let err = parse_image_config(b"not json").expect_err("should fail");
        assert!(matches!(err, PullError::MalformedConfig(_)));
    }
}
