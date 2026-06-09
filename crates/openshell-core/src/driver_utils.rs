// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Utility helpers shared across compute-driver crates.

use std::path::PathBuf;

use crate::proto::compute::v1::{DriverSandbox, GetCapabilitiesResponse};

// ---------------------------------------------------------------------------
// Sandbox container/pod label keys (openshell.ai/ namespace)
// ---------------------------------------------------------------------------

/// Container/pod label that identifies this resource as managed by `OpenShell`.
/// Value should be `"openshell"`.
pub const LABEL_MANAGED_BY: &str = "openshell.ai/managed-by";

/// Expected value for [`LABEL_MANAGED_BY`].
pub const LABEL_MANAGED_BY_VALUE: &str = "openshell";

/// Container/pod label carrying the sandbox ID.
pub const LABEL_SANDBOX_ID: &str = "openshell.ai/sandbox-id";

/// Container/pod label carrying the sandbox name.
pub const LABEL_SANDBOX_NAME: &str = "openshell.ai/sandbox-name";

/// Container/pod label carrying the sandbox namespace.
pub const LABEL_SANDBOX_NAMESPACE: &str = "openshell.ai/sandbox-namespace";

// ---------------------------------------------------------------------------

/// Path to the sandbox supervisor binary inside the container image.
///
/// All compute drivers must launch this binary as the container entrypoint to
/// start the sandboxed environment.  The value must be kept in sync with the
/// path used when building the `openshell-sandbox` image layer.
pub const SUPERVISOR_IMAGE_BINARY_PATH: &str = "/openshell-sandbox";

/// Directory inside sandbox containers where the supervisor binary is mounted.
///
/// Compute drivers that side-load the supervisor into a shared volume mount
/// the binary here so the sandbox container can execute it from a fixed path.
pub const SUPERVISOR_CONTAINER_DIR: &str = "/opt/openshell/bin";

/// Full path to the supervisor binary inside sandbox containers.
///
/// Equals `SUPERVISOR_CONTAINER_DIR + "/openshell-sandbox"`. Use this when
/// the full executable path is needed (Docker entrypoint, Podman entrypoint,
/// VM rootfs injection). Use `SUPERVISOR_CONTAINER_DIR` when only the
/// directory mount-point is needed (Kubernetes emptyDir volume mount).
pub const SUPERVISOR_CONTAINER_BINARY: &str = "/opt/openshell/bin/openshell-sandbox";

// ---------------------------------------------------------------------------
// In-container mount paths for guest TLS materials and the sandbox token.
//
// All container-based drivers (Docker, Podman, Kubernetes) mount the gateway's
// mTLS client credentials at these fixed paths inside every sandbox container.
// The supervisor reads these paths on startup to establish its gRPC-over-mTLS
// connection back to the gateway. The paths must remain stable across driver
// versions since the supervisor binary is built and packaged separately.
// ---------------------------------------------------------------------------

/// Container-side mount path for the guest mTLS CA certificate.
pub const TLS_CA_MOUNT_PATH: &str = "/etc/openshell/tls/client/ca.crt";

/// Container-side mount path for the guest mTLS client certificate.
pub const TLS_CERT_MOUNT_PATH: &str = "/etc/openshell/tls/client/tls.crt";

/// Container-side mount path for the guest mTLS client private key.
pub const TLS_KEY_MOUNT_PATH: &str = "/etc/openshell/tls/client/tls.key";

/// Container-side mount path for the per-sandbox JWT token.
pub const SANDBOX_TOKEN_MOUNT_PATH: &str = "/etc/openshell/auth/sandbox.jwt";

/// Return the XDG state path for a driver's sandbox JWT token file.
///
/// The resulting path is `$XDG_STATE_HOME/openshell/<driver_subdir>[/<namespace>]/<sandbox_id>/sandbox.jwt`.
///
/// `driver_subdir` is driver-specific, e.g. `"docker-sandbox-tokens"` or
/// `"podman-sandbox-tokens"`.  When `namespace` is `Some`, it is appended as
/// an additional path component (with `/` and `\` replaced by `-`).
///
/// # Errors
/// Returns an error if the XDG state directory cannot be resolved.
pub fn sandbox_token_path(
    driver_subdir: &str,
    namespace: Option<&str>,
    sandbox_id: &str,
) -> miette::Result<PathBuf> {
    let mut path = crate::paths::xdg_state_dir()?
        .join("openshell")
        .join(driver_subdir);
    if let Some(ns) = namespace {
        path = path.join(ns.replace(['/', '\\'], "-"));
    }
    Ok(path.join(sandbox_id).join("sandbox.jwt"))
}

/// Build a [`GetCapabilitiesResponse`] from the common driver capability fields.
///
/// Every compute driver constructs this response with the same fields. Shared
/// here to avoid repeating the struct literal in each driver crate.
pub fn build_capabilities_response(
    driver_name: &str,
    driver_version: impl Into<String>,
    default_image: impl Into<String>,
) -> GetCapabilitiesResponse {
    GetCapabilitiesResponse {
        driver_name: driver_name.to_string(),
        driver_version: driver_version.into(),
        default_image: default_image.into(),
    }
}

/// Return the effective log level for a sandbox.
///
/// Uses the level from the sandbox spec when non-empty, falling back to
/// `default_level` otherwise.
pub fn sandbox_log_level(sandbox: &DriverSandbox, default_level: &str) -> String {
    sandbox
        .spec
        .as_ref()
        .map(|spec| spec.log_level.as_str())
        .filter(|level| !level.is_empty())
        .unwrap_or(default_level)
        .to_string()
}

// ---------------------------------------------------------------------------
// Supervisor image helpers (shared by Docker and Podman drivers)
// ---------------------------------------------------------------------------

/// Return the tag portion of a supervisor image reference, or `None` if the
/// reference uses a digest (`@sha256:...`).
///
/// Examples:
/// - `"ghcr.io/org/image:1.2.3"` → `Some("1.2.3")`
/// - `"ghcr.io/org/image:latest"` → `Some("latest")`
/// - `"ghcr.io/org/image"` → `Some("latest")`  (implied tag)
/// - `"ghcr.io/org/image@sha256:abc"` → `None`  (pinned by digest)
/// - `"ghcr.io/org/image:"` → `None`  (empty tag)
pub fn supervisor_image_tag(image: &str) -> Option<&str> {
    if image.contains('@') {
        return None;
    }

    let image_name = image.rsplit('/').next().unwrap_or(image);
    image_name
        .rsplit_once(':')
        .map_or(Some("latest"), |(_, tag)| {
            if tag.is_empty() { None } else { Some(tag) }
        })
}

/// Return `true` if the supervisor image should be refreshed before each use.
///
/// Mutable tags (`dev`, `latest`) are always re-pulled so that the running
/// container tracks the latest pushed version.  Digest-pinned references and
/// all other versioned tags are treated as immutable and pulled at most once.
pub fn supervisor_image_should_refresh(image: &str) -> bool {
    matches!(supervisor_image_tag(image), Some("dev" | "latest"))
}
