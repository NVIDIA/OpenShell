// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Utility helpers shared across compute-driver crates.

use std::path::{Path, PathBuf};

/// Container/pod label carrying the sandbox namespace.
pub const LABEL_SANDBOX_NAMESPACE: &str = "openshell.ai/sandbox-namespace";

/// Ready-condition reason when the supervisor rejects an image-provided OCI
/// working directory because the sandbox identity lacks the required access.
pub const CONDITION_WORKSPACE_VALIDATION_FAILED: &str = "WorkspaceValidationFailed";

/// Driver condition message for [`CONDITION_WORKSPACE_VALIDATION_FAILED`].
/// Fixed text, because supervisor output may contain secrets.
pub const WORKSPACE_VALIDATION_FAILED_MESSAGE: &str =
    "OCI WorkingDir is not usable by the sandbox identity";

// ---------------------------------------------------------------------------

/// Path to the sandbox supervisor binary inside the container image.
///
/// All compute drivers must launch this binary as the container entrypoint to
/// start the sandboxed environment.  The value must be kept in sync with the
/// path used when building the `openshell-sandbox` image layer.
pub const SANDBOX_RUNTIME_IMAGE_BINARY_PATH: &str = "/openshell-sandbox";

/// Legacy name for [`SANDBOX_RUNTIME_IMAGE_BINARY_PATH`].
pub const SUPERVISOR_IMAGE_BINARY_PATH: &str = SANDBOX_RUNTIME_IMAGE_BINARY_PATH;

/// Container-side mount path for the corporate proxy CA bundle.
///
/// Drivers with a `proxy_ca_bundle` operator setting bind-mount the host PEM
/// file here (read-only) and pass the path on the supervisor's argv via
/// `--upstream-proxy-ca-bundle`. The supervisor trusts it for the TLS
/// handshake with an `https://` corporate egress proxy and for server
/// certificates re-signed by a TLS-intercepting proxy. Unlike the proxy
/// credential, a CA certificate is not secret, so a plain read-only bind
/// mount is used rather than a driver secret.
pub const PROXY_CA_MOUNT_PATH: &str = "/etc/openshell/tls/proxy/ca-bundle.pem";

/// Container-side directory where the provider SPIFFE Workload API socket is mounted.
pub const PROVIDER_SPIFFE_WORKLOAD_API_SOCKET_MOUNT_DIR: &str = "/spiffe-workload-api";

/// Validate a host UNIX socket selected for provider SPIFFE projection.
///
/// Local container drivers bind-mount the socket's dedicated parent directory,
/// not a broad host root. TCP endpoints are deliberately rejected here: a
/// container projection must be a filesystem socket, while VM guest TCP
/// exposure has its own explicit acknowledgement contract.
pub fn validate_provider_spiffe_unix_socket(path: &Path) -> Result<(), String> {
    let raw = path
        .to_str()
        .ok_or_else(|| "provider_spiffe_workload_api_socket must be valid UTF-8".to_string())?;
    if raw.trim() != raw || raw.is_empty() {
        return Err("provider_spiffe_workload_api_socket must not be empty or contain surrounding whitespace".to_string());
    }
    if raw.starts_with("tcp:") || raw.starts_with("unix:") {
        return Err("provider_spiffe_workload_api_socket must be an absolute host UNIX socket path, not a URI".to_string());
    }
    if !path.is_absolute() || path.parent().is_none_or(|parent| parent == Path::new("/")) {
        return Err("provider_spiffe_workload_api_socket must be an absolute UNIX socket path below a dedicated parent directory".to_string());
    }
    Ok(())
}

/// Return the guest/container path for a projected provider SPIFFE socket.
pub fn projected_provider_spiffe_socket_path(path: &Path) -> Result<String, String> {
    validate_provider_spiffe_unix_socket(path)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| "provider_spiffe_workload_api_socket must name a socket file".to_string())?;
    Ok(format!(
        "{PROVIDER_SPIFFE_WORKLOAD_API_SOCKET_MOUNT_DIR}/{file_name}"
    ))
}

/// Return the XDG state path for a driver's sandbox JWT token file.
///
/// The resulting path is `$XDG_STATE_HOME/openshell/<driver_subdir>[/<namespace>]/<sandbox_id>/sandbox.jwt`.
///
/// `driver_subdir` is driver-specific. When `namespace` is `Some`, it is
/// appended as an additional path component (with `/` and `\` replaced by
/// `-`).
///
/// # Errors
/// Returns an error if the XDG state directory cannot be resolved.
pub fn sandbox_token_path(
    driver_subdir: &str,
    namespace: Option<&str>,
    sandbox_id: &str,
) -> miette::Result<PathBuf> {
    let mut path = openshell_driver_sdk::paths::xdg_state_dir()?
        .join("openshell")
        .join(driver_subdir);
    if let Some(ns) = namespace {
        path = path.join(ns.replace(['/', '\\'], "-"));
    }
    Ok(path.join(sandbox_id).join("sandbox.jwt"))
}

// ---------------------------------------------------------------------------
// Supervisor image helpers shared by container-backed drivers
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

// ---------------------------------------------------------------------------
// Supervisor binary extraction helpers shared by container-backed drivers
// ---------------------------------------------------------------------------

/// Extract the payload of the first regular-file entry in a tar archive.
///
/// Container archive endpoints return a single-file tar when `path` points to
/// a file, so only the first entry is consumed. Returns an error when the
/// archive is empty, the first entry is not a regular file, or the payload is
/// empty.
pub fn extract_first_tar_entry(tar_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut archive = tar::Archive::new(std::io::Cursor::new(tar_bytes));
    let mut entries = archive
        .entries()
        .map_err(|err| format!("open tar archive: {err}"))?;
    let mut entry = entries
        .next()
        .ok_or_else(|| "tar archive was empty".to_string())?
        .map_err(|err| format!("read tar entry: {err}"))?;
    let kind = entry.header().entry_type();
    if !kind.is_file() {
        return Err(format!(
            "expected a regular file in tar archive, got type {kind:?}"
        ));
    }
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut entry, &mut bytes)
        .map_err(|err| format!("read tar entry payload: {err}"))?;
    if bytes.is_empty() {
        return Err("tar entry payload was empty".to_string());
    }
    Ok(bytes)
}

/// Atomically write `bytes` to `final_path` via a sibling temp file.
///
/// Creates parent directories as needed. The temp file is synced, `chmod 755`
/// (on Unix), and renamed into place so concurrent readers never observe a
/// partial write. Returns a human-readable error string on failure.
pub fn write_cache_binary_atomic(final_path: &Path, bytes: &[u8]) -> Result<(), String> {
    let dir = final_path
        .parent()
        .ok_or_else(|| format!("cache path '{}' has no parent", final_path.display()))?;
    std::fs::create_dir_all(dir)
        .map_err(|err| format!("failed to create cache dir '{}': {err}", dir.display()))?;

    let mut temp = tempfile::Builder::new()
        .prefix(".openshell-sandbox-")
        .tempfile_in(dir)
        .map_err(|err| format!("failed to create temp file in '{}': {err}", dir.display()))?;
    std::io::Write::write_all(&mut temp, bytes)
        .map_err(|err| format!("failed to write supervisor binary: {err}"))?;
    temp.as_file()
        .sync_all()
        .map_err(|err| format!("failed to sync supervisor binary: {err}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755))
            .map_err(|err| format!("failed to chmod supervisor binary: {err}"))?;
    }

    temp.persist(final_path).map_err(|err| {
        format!(
            "failed to persist supervisor binary to '{}': {}",
            final_path.display(),
            err.error,
        )
    })?;
    Ok(())
}

/// Return the host-side cache path for an extracted supervisor binary.
///
/// The path is `$XDG_DATA_HOME/openshell/<driver_subdir>/<sanitized-digest>/openshell-sandbox`.
/// `driver_subdir` distinguishes caches across drivers.
pub fn supervisor_cache_path(driver_subdir: &str, digest: &str) -> Result<PathBuf, String> {
    let base = openshell_driver_sdk::paths::xdg_data_dir()
        .map_err(|err| format!("failed to resolve XDG data dir: {err}"))?;
    Ok(supervisor_cache_path_with_base(
        &base,
        driver_subdir,
        digest,
    ))
}

/// [`supervisor_cache_path`] with an explicit base directory (for testing).
pub fn supervisor_cache_path_with_base(base: &Path, driver_subdir: &str, digest: &str) -> PathBuf {
    let sanitized = digest.replace(':', "-");
    base.join("openshell")
        .join(driver_subdir)
        .join(sanitized)
        .join("openshell-sandbox")
}

/// Generate a unique container name for supervisor binary extraction.
///
/// Uses the process ID and an atomic counter to avoid collisions across
/// concurrent gateway starts.
pub fn temp_extract_container_name() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let pid = std::process::id();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    format!("openshell-supervisor-extract-{pid}-{seq}")
}

/// Validate that the file at `path` starts with the ELF magic bytes (`\x7fELF`).
///
/// Returns a human-readable error when the file cannot be read or is not a
/// Linux ELF binary.
pub fn validate_linux_elf_binary(path: &Path) -> Result<(), String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(|err| {
        format!(
            "failed to open supervisor binary '{}': {err}",
            path.display()
        )
    })?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).map_err(|err| {
        format!(
            "failed to read supervisor binary '{}': {err}",
            path.display()
        )
    })?;
    if magic != [0x7f, b'E', b'L', b'F'] {
        return Err(format!(
            "supervisor binary '{}' is not a Linux ELF executable",
            path.display(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn projected_spiffe_socket_requires_dedicated_absolute_unix_path() {
        assert_eq!(
            projected_provider_spiffe_socket_path(Path::new("/run/spire/agent.sock")).unwrap(),
            "/spiffe-workload-api/agent.sock"
        );
        for path in ["relative.sock", "/agent.sock", "tcp:127.0.0.1:8081"] {
            assert!(
                validate_provider_spiffe_unix_socket(Path::new(path)).is_err(),
                "{path}"
            );
        }
    }
}
