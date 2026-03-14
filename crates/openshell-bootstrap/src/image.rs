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

/// Image tag baked in at compile time.
///
/// Set via `OPENSHELL_IMAGE_TAG` env var during `cargo build`:
/// - Defaults to `"dev"` when unset (local builds, `mise run docker:build`).
/// - CI sets this explicitly: `"dev"` for main-branch builds, the version
///   string (e.g. `"0.6.0"`) for tagged releases.
pub const DEFAULT_IMAGE_TAG: &str = match option_env!("OPENSHELL_IMAGE_TAG") {
    Some(tag) => tag,
    None => "dev",
};

// ---------------------------------------------------------------------------
// GHCR registry defaults
// ---------------------------------------------------------------------------

/// Default registry host for pulling images.
pub const DEFAULT_REGISTRY: &str = "ghcr.io";

/// Default image repository base on GHCR (without component name or tag).
pub const DEFAULT_IMAGE_REPO_BASE: &str = "ghcr.io/nvidia/openshell";

/// Default full gateway image path on GHCR (without tag).
pub const DEFAULT_GATEWAY_IMAGE: &str = "ghcr.io/nvidia/openshell/cluster";

/// Default username for token-based GHCR authentication.
///
/// GHCR accepts any non-empty username when authenticating with a PAT;
/// `__token__` is a common convention for token-based OCI registry auth.
const DEFAULT_REGISTRY_USERNAME: &str = "__token__";

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

/// Build [`DockerCredentials`] for ghcr.io from explicit credentials.
///
/// Returns `None` when `token` is `None` or empty — the default GHCR repos
/// are public and do not require authentication. When a token is provided,
/// uses the given `username` (falling back to `__token__` if `None`/empty).
pub(crate) fn ghcr_credentials(
    username: Option<&str>,
    token: Option<&str>,
) -> Option<DockerCredentials> {
    let token = token.filter(|t| !t.is_empty())?;
    let username = username
        .filter(|u| !u.is_empty())
        .unwrap_or(DEFAULT_REGISTRY_USERNAME);
    Some(DockerCredentials {
        username: Some(username.to_string()),
        password: Some(token.to_string()),
        serveraddress: Some(DEFAULT_REGISTRY.to_string()),
        ..Default::default()
    })
}

/// Pull the gateway image directly on a remote Docker daemon from ghcr.io,
/// authenticating with the provided registry token.
///
/// After pulling, the image is tagged to the expected local image ref (e.g.,
/// `openshell/cluster:dev`) so that all downstream container creation logic works
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
    registry_username: Option<&str>,
    registry_token: Option<&str>,
    mut on_progress: impl FnMut(String) + Send + 'static,
) -> Result<()> {
    // Query the remote host's platform so we pull the correct architecture.
    let remote_platform = get_host_platform(remote).await?;
    let platform_str = remote_platform.platform_string();
    info!(
        "Remote host platform: {} — will pull matching image variant",
        platform_str
    );

    // Determine the registry tag to pull.  If OPENSHELL_CLUSTER_IMAGE is set
    // and already points at a registry image, honour its tag.  Otherwise use
    // the distribution registry default tag — the local build tag (e.g. "dev")
    // is a build-time convention that doesn't exist in the registry.
    let registry_image_base = DEFAULT_GATEWAY_IMAGE.to_string();

    let tag = if is_local_image_ref(image_ref) {
        PULL_REGISTRY_DEFAULT_TAG.to_string()
    } else {
        let (_repo, t) = parse_image_ref(image_ref);
        t
    };
    let registry_image = format!("{registry_image_base}:{tag}");

    info!(
        "Pulling image {} on remote host from {}",
        registry_image, DEFAULT_REGISTRY
    );
    on_progress(format!("[progress] Pulling {platform_str} image"));

    let credentials = ghcr_credentials(registry_username, registry_token);

    let options = CreateImageOptions {
        from_image: Some(registry_image_base),
        tag: Some(tag.clone()),
        platform: platform_str,
        ..Default::default()
    };

    let mut stream = remote.create_image(Some(options), None, credentials);
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
            on_progress(format!("[progress] {status}: {current_mb}/{total_mb} MB"));
        }
    }

    // Tag the pulled image to the expected local image ref so downstream code
    // (container creation, image ID checks) works unchanged.
    // e.g., tag "ghcr.io/nvidia/openshell/cluster:latest" as "openshell/cluster:dev"
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

    on_progress("[progress] Image ready".to_string());
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
    fn ghcr_credentials_with_token_default_username() {
        let creds = ghcr_credentials(None, Some("ghp_test123"));
        assert!(creds.is_some());
        let creds = creds.unwrap();
        assert_eq!(creds.username.as_deref(), Some("__token__"));
        assert_eq!(creds.password.as_deref(), Some("ghp_test123"));
        assert_eq!(creds.serveraddress.as_deref(), Some("ghcr.io"));
    }

    #[test]
    fn ghcr_credentials_with_custom_username() {
        let creds = ghcr_credentials(Some("myuser"), Some("ghp_test123"));
        assert!(creds.is_some());
        let creds = creds.unwrap();
        assert_eq!(creds.username.as_deref(), Some("myuser"));
        assert_eq!(creds.password.as_deref(), Some("ghp_test123"));
        assert_eq!(creds.serveraddress.as_deref(), Some("ghcr.io"));
    }

    #[test]
    fn ghcr_credentials_without_token_returns_none() {
        // No token means unauthenticated (public repos).
        assert!(ghcr_credentials(None, None).is_none());
        assert!(ghcr_credentials(None, Some("")).is_none());
        assert!(ghcr_credentials(Some("myuser"), None).is_none());
    }

    #[test]
    fn default_constants_are_consistent() {
        assert!(
            DEFAULT_GATEWAY_IMAGE.starts_with(DEFAULT_IMAGE_REPO_BASE),
            "gateway image should be under the default repo base"
        );
        assert!(
            DEFAULT_IMAGE_REPO_BASE.starts_with(DEFAULT_REGISTRY),
            "repo base should start with the registry host"
        );
    }
}
