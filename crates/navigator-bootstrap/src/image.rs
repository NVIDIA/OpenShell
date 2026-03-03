// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Image pull helpers for remote deployments.

use crate::docker::{HostPlatform, get_host_platform};
use bollard::Docker;
use bollard::auth::DockerCredentials;
use bollard::query_parameters::{CreateImageOptions, TagImageOptionsBuilder};
use futures::StreamExt;
use miette::{IntoDiagnostic, Result, WrapErr};
use tracing::{debug, info};

/// Default tag to pull from the distribution registry.
const PULL_REGISTRY_DEFAULT_TAG: &str = "latest";

// ---------------------------------------------------------------------------
// XOR-obfuscated registry credentials
// ---------------------------------------------------------------------------
// The credentials below are XOR-encoded so they don't appear as plaintext in
// the compiled binary. This is a lightweight deterrent against casual
// inspection — it is NOT a security boundary. The read-only credentials give
// access to the public distribution registry only.

/// XOR key used to decode all credential constants.
const XOR_KEY: [u8; 32] = [
    0x5d, 0x23, 0x9c, 0x9c, 0xf2, 0xda, 0x18, 0x0d, 0x87, 0x7c, 0x48, 0x3f, 0x1c, 0xcf, 0x5f, 0x12,
    0xaf, 0x9b, 0x10, 0x53, 0x63, 0xd6, 0xa0, 0x12, 0x02, 0x9b, 0x8d, 0x72, 0x7b, 0x54, 0xa6, 0xfe,
];

/// XOR-encoded distribution registry host.
const PULL_REGISTRY_ENC: [u8; 29] = [
    0x39, 0x12, 0xf5, 0xac, 0x9c, 0xbe, 0x6d, 0x78, 0xb5, 0x1a, 0x7e, 0x4e, 0x64, 0xa4, 0x71, 0x71,
    0xc3, 0xf4, 0x65, 0x37, 0x05, 0xa4, 0xcf, 0x7c, 0x76, 0xb5, 0xe3, 0x17, 0x0f,
];

/// XOR-encoded full image path on the distribution registry (without tag).
const PULL_REGISTRY_IMAGE_ENC: [u8; 47] = [
    0x39, 0x12, 0xf5, 0xac, 0x9c, 0xbe, 0x6d, 0x78, 0xb5, 0x1a, 0x7e, 0x4e, 0x64, 0xa4, 0x71, 0x71,
    0xc3, 0xf4, 0x65, 0x37, 0x05, 0xa4, 0xcf, 0x7c, 0x76, 0xb5, 0xe3, 0x17, 0x0f, 0x7b, 0xc8, 0x9f,
    0x2b, 0x4a, 0xfb, 0xfd, 0x86, 0xb5, 0x6a, 0x22, 0xe4, 0x10, 0x3d, 0x4c, 0x68, 0xaa, 0x2d,
];

/// XOR-encoded read-only username for the distribution registry.
const PULL_REGISTRY_USERNAME_ENC: [u8; 6] = [0x39, 0x4c, 0xff, 0xf7, 0x97, 0xa8];

/// XOR-encoded read-only password for the distribution registry.
const PULL_REGISTRY_PASSWORD_ENC: [u8; 18] = [
    0x2d, 0x56, 0xf1, 0xec, 0x99, 0xb3, 0x76, 0x20, 0xfd, 0x09, 0x24, 0x4a, 0x31, 0xbc, 0x30, 0x70,
    0xca, 0xe9,
];

/// Decode an XOR-encoded byte slice using [`XOR_KEY`].
fn xor_decode(encoded: &[u8]) -> String {
    encoded
        .iter()
        .enumerate()
        .map(|(i, b)| (b ^ XOR_KEY[i % XOR_KEY.len()]) as char)
        .collect()
}

/// Distribution registry host, decoded at runtime.
pub(crate) fn pull_registry() -> String {
    xor_decode(&PULL_REGISTRY_ENC)
}

/// Full image path on the distribution registry (without tag), decoded at runtime.
pub(crate) fn pull_registry_image() -> String {
    xor_decode(&PULL_REGISTRY_IMAGE_ENC)
}

/// Read-only username for the distribution registry, decoded at runtime.
pub(crate) fn pull_registry_username() -> String {
    xor_decode(&PULL_REGISTRY_USERNAME_ENC)
}

/// Read-only password for the distribution registry, decoded at runtime.
pub(crate) fn pull_registry_password() -> String {
    xor_decode(&PULL_REGISTRY_PASSWORD_ENC)
}

/// Parse an image reference into (repository, tag).
///
/// Examples:
/// - `nginx:latest` -> ("nginx", "latest")
/// - `nginx` -> ("nginx", "latest")
/// - `ghcr.io/org/repo:v1.0` -> ("ghcr.io/org/repo", "v1.0")
pub fn parse_image_ref(image_ref: &str) -> (String, String) {
    // Handle digest references (sha256:...)
    if image_ref.contains('@') {
        // For digest references, don't split - return the whole thing
        return (image_ref.to_string(), String::new());
    }

    // Find the last colon that's after any registry/path separators
    // This handles cases like "registry.io:5000/image:tag"
    if let Some(last_colon) = image_ref.rfind(':') {
        let before_colon = &image_ref[..last_colon];
        let after_colon = &image_ref[last_colon + 1..];

        // If there's a slash after this colon, it's a port not a tag
        if !after_colon.contains('/') {
            return (before_colon.to_string(), after_colon.to_string());
        }
    }

    // No tag found, default to "latest"
    (image_ref.to_string(), "latest".to_string())
}

/// Pull an image from a registry to the local Docker daemon.
///
/// If `platform` is provided (e.g., `"linux/arm64"`), the pull will request that specific
/// platform variant. This is essential when the local host architecture differs from the
/// target deployment architecture.
pub async fn pull_image(
    docker: &Docker,
    image_ref: &str,
    platform: Option<&HostPlatform>,
) -> Result<()> {
    let (repo, tag) = parse_image_ref(image_ref);
    let platform_str = platform
        .map(HostPlatform::platform_string)
        .unwrap_or_default();

    if platform_str.is_empty() {
        info!("Pulling image {}:{}", repo, tag);
    } else {
        info!(
            "Pulling image {}:{} for platform {}",
            repo, tag, platform_str
        );
    }

    let options = CreateImageOptions {
        from_image: Some(repo.clone()),
        tag: Some(tag.clone()),
        platform: platform_str,
        ..Default::default()
    };

    let mut stream = docker.create_image(Some(options), None, None);
    while let Some(result) = stream.next().await {
        let info = result.into_diagnostic().wrap_err("failed to pull image")?;
        if let Some(status) = info.status {
            debug!("Pull status: {}", status);
        }
    }

    Ok(())
}

/// Pull the cluster image directly on a remote Docker daemon from the distribution
/// registry, authenticating with the built-in distribution credentials.
///
/// After pulling, the image is tagged to the expected local image ref (e.g.,
/// `navigator/cluster:dev`) so that all downstream container creation logic works
/// without changes.
///
/// The remote host's platform is queried so the correct architecture variant is
/// explicitly requested from the registry (avoids pulling the wrong arch when the
/// registry manifest list defaults differ from the host).
///
/// Progress is reported via `on_progress` with `[status]`-prefixed messages.
pub async fn pull_remote_image(
    remote: &Docker,
    image_ref: &str,
    mut on_progress: impl FnMut(String) + Send + 'static,
) -> Result<()> {
    // Query the remote host's platform so we pull the correct architecture.
    let remote_platform = get_host_platform(remote).await?;
    let platform_str = remote_platform.platform_string();
    info!(
        "Remote host platform: {} — will pull matching image variant",
        platform_str
    );

    // Determine the registry tag to pull.  If NAVIGATOR_CLUSTER_IMAGE is set
    // and already points at a registry image, honour its tag.  Otherwise use
    // the distribution registry default tag — the local build tag (e.g. "dev")
    // is a build-time convention that doesn't exist in the registry.
    let registry = pull_registry();
    let registry_image_base = pull_registry_image();

    let tag = if is_local_image_ref(image_ref) {
        PULL_REGISTRY_DEFAULT_TAG.to_string()
    } else {
        let (_repo, t) = parse_image_ref(image_ref);
        t
    };
    let registry_image = format!("{registry_image_base}:{tag}");

    info!(
        "Pulling image {} on remote host from {}",
        registry_image, registry
    );
    on_progress(format!(
        "[status] Pulling navigator/cluster:{tag} ({platform_str}) on remote host"
    ));

    let credentials = DockerCredentials {
        username: Some(pull_registry_username()),
        password: Some(pull_registry_password()),
        serveraddress: Some(registry),
        ..Default::default()
    };

    let options = CreateImageOptions {
        from_image: Some(registry_image_base),
        tag: Some(tag.clone()),
        platform: platform_str,
        ..Default::default()
    };

    let mut stream = remote.create_image(Some(options), None, Some(credentials));
    while let Some(result) = stream.next().await {
        let info = result
            .into_diagnostic()
            .wrap_err("failed to pull image on remote host")?;
        if let Some(ref status) = info.status {
            debug!("Remote pull: {}", status);
        }
        // Report layer progress
        if let Some(ref status) = info.status
            && let Some(ref detail) = info.progress_detail
            && let (Some(current), Some(total)) = (detail.current, detail.total)
        {
            let current_mb = current / (1024 * 1024);
            let total_mb = total / (1024 * 1024);
            on_progress(format!("[status] {status}: {current_mb}/{total_mb} MB"));
        }
    }

    // Tag the pulled image to the expected local image ref so downstream code
    // (container creation, image ID checks) works unchanged.
    // e.g., tag "d1i0nduu2f6qxk.cloudfront.net/navigator/cluster:dev" as "navigator/cluster:dev"
    let (target_repo, target_tag) = parse_image_ref(image_ref);
    info!(
        "Tagging {} as {}:{}",
        registry_image, target_repo, target_tag
    );
    remote
        .tag_image(
            &registry_image,
            Some(
                TagImageOptionsBuilder::default()
                    .repo(target_repo.as_ref())
                    .tag(target_tag.as_ref())
                    .build(),
            ),
        )
        .await
        .into_diagnostic()
        .wrap_err_with(|| {
            format!("failed to tag {registry_image} as {target_repo}:{target_tag} on remote")
        })?;

    // Verify that the pulled image matches the expected architecture.
    // This catches cases where the registry returned the wrong platform
    // variant (e.g., amd64 on an arm64 host) which would cause an
    // "exec format error" at container start time.
    let inspect = remote
        .inspect_image(image_ref)
        .await
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to inspect pulled image {image_ref} on remote"))?;

    let actual_arch = inspect.architecture.as_deref().unwrap_or("unknown");
    if actual_arch != remote_platform.arch {
        return Err(miette::miette!(
            "architecture mismatch: pulled image {image_ref} is {actual_arch} but remote host is {expected}; \
             try removing stale images on the remote host and re-deploying",
            expected = remote_platform.arch,
        ));
    }
    info!(
        "Verified image architecture: {} matches remote host",
        actual_arch
    );

    on_progress(format!("[status] Image {image_ref} ready on remote host"));
    info!("Remote image pull and tag complete: {}", image_ref);

    Ok(())
}

/// Check whether an image reference looks like a locally-built image (no registry prefix).
///
/// An image reference is considered "local-only" when the repository portion contains no `/`,
/// meaning it has no registry or namespace prefix (e.g., `cluster-local:dev` vs
/// `ghcr.io/org/image:tag` or `docker.io/library/nginx:latest`).
pub(crate) fn is_local_image_ref(image_ref: &str) -> bool {
    let (repo, _tag) = parse_image_ref(image_ref);
    !repo.contains('/')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_image() {
        let (repo, tag) = parse_image_ref("nginx:latest");
        assert_eq!(repo, "nginx");
        assert_eq!(tag, "latest");
    }

    #[test]
    fn parse_image_no_tag() {
        let (repo, tag) = parse_image_ref("nginx");
        assert_eq!(repo, "nginx");
        assert_eq!(tag, "latest");
    }

    #[test]
    fn parse_image_with_registry() {
        let (repo, tag) = parse_image_ref("ghcr.io/org/repo:v1.0");
        assert_eq!(repo, "ghcr.io/org/repo");
        assert_eq!(tag, "v1.0");
    }

    #[test]
    fn parse_image_with_registry_port() {
        let (repo, tag) = parse_image_ref("registry.io:5000/image:v1");
        assert_eq!(repo, "registry.io:5000/image");
        assert_eq!(tag, "v1");
    }

    #[test]
    fn parse_image_with_registry_port_no_tag() {
        let (repo, tag) = parse_image_ref("registry.io:5000/image");
        assert_eq!(repo, "registry.io:5000/image");
        assert_eq!(tag, "latest");
    }

    #[test]
    fn parse_image_with_digest() {
        let (repo, tag) = parse_image_ref("nginx@sha256:abc123");
        assert_eq!(repo, "nginx@sha256:abc123");
        assert_eq!(tag, "");
    }

    #[test]
    fn xor_decode_registry_credentials() {
        // Verify all encoded constants decode to valid, non-empty ASCII strings.
        let registry = pull_registry();
        assert!(!registry.is_empty());
        assert!(registry.contains('.'), "registry should be a domain name");

        let image = pull_registry_image();
        assert!(
            image.starts_with(&registry),
            "image path should start with the registry host"
        );

        let username = pull_registry_username();
        assert!(!username.is_empty());

        let password = pull_registry_password();
        assert!(!password.is_empty());
        assert!(password.len() > 8, "password should be non-trivial length");
    }
}
