// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Build and export container images for gateway runtimes.
//!
//! This module wraps bollard's `build_image()` API to build a container image
//! from a Dockerfile and build context. Kubernetes deployments reuse the
//! existing push pipeline to import the image into the gateway's containerd
//! runtime, while the VM backend can export the built image as a rootfs tar.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use bollard::Docker;
use bollard::models::ContainerCreateBody;
use bollard::query_parameters::{
    BuildImageOptionsBuilder, CreateContainerOptionsBuilder, RemoveContainerOptionsBuilder,
};
use futures::StreamExt;
use miette::{IntoDiagnostic, Result, WrapErr};
use tokio::io::AsyncWriteExt;
use url::{Position, Url};

use crate::constants::container_name;
use crate::push::push_local_images;

/// Pseudo-image URI scheme used to hand a local rootfs tar artifact to the VM driver.
pub const ROOTFS_TAR_IMAGE_REF_SCHEME: &str = "openshell-rootfs-tar";

/// Build a container image from a Dockerfile using the local Docker daemon.
///
/// This is used by `openshell sandbox create --from <Dockerfile>` for both the
/// Kubernetes and VM backends. The image remains available in the local Docker
/// daemon so the caller can either hand the resulting tag directly to the VM
/// backend or import it into a local gateway containerd runtime.
#[allow(clippy::implicit_hasher)]
pub async fn build_local_image(
    dockerfile_path: &Path,
    tag: &str,
    context_dir: &Path,
    build_args: &HashMap<String, String>,
    on_log: &mut impl FnMut(String),
) -> Result<()> {
    on_log(format!(
        "Building image {tag} from {}",
        dockerfile_path.display()
    ));
    build_image(dockerfile_path, tag, context_dir, build_args, on_log).await?;
    on_log(format!("Built image {tag}"));
    Ok(())
}

/// Encode a local rootfs tar path as an internal image reference understood by the VM driver.
pub fn encode_rootfs_tar_image_ref(path: &Path) -> Result<String> {
    let canonical = path
        .canonicalize()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to resolve rootfs tar path {}", path.display()))?;
    let file_url = Url::from_file_path(&canonical)
        .map_err(|_| miette::miette!("failed to encode rootfs tar path {}", canonical.display()))?;
    Ok(format!(
        "{ROOTFS_TAR_IMAGE_REF_SCHEME}:{}",
        &file_url[Position::BeforePath..]
    ))
}

/// Decode a VM-driver rootfs tar image reference back to a local filesystem path.
pub fn decode_rootfs_tar_image_ref(image_ref: &str) -> Option<PathBuf> {
    let remainder = image_ref.strip_prefix(&format!("{ROOTFS_TAR_IMAGE_REF_SCHEME}:"))?;
    let file_url = format!("file:{remainder}");
    Url::parse(&file_url).ok()?.to_file_path().ok()
}

/// Export a locally-built Docker image as a persistent rootfs tar artifact for the VM driver.
pub async fn export_local_image_rootfs(
    image_ref: &str,
    on_log: &mut impl FnMut(String),
) -> Result<PathBuf> {
    let temp = tempfile::Builder::new()
        .prefix("openshell-vm-rootfs-")
        .suffix(".tar")
        .tempfile()
        .into_diagnostic()
        .wrap_err("failed to allocate temporary VM rootfs artifact")?;
    let temp_path = temp.path().to_path_buf();
    let (_file, output_path) = temp.keep().into_diagnostic().wrap_err_with(|| {
        format!(
            "failed to persist temporary VM rootfs artifact {}",
            temp_path.display()
        )
    })?;

    on_log(format!(
        "Exporting built image {image_ref} as VM rootfs artifact {}",
        output_path.display()
    ));
    export_local_image_rootfs_to_path(image_ref, &output_path).await?;
    on_log(format!(
        "Exported VM rootfs artifact {}",
        output_path.display()
    ));
    Ok(output_path)
}

/// Push a locally-built image into the gateway's containerd runtime.
#[allow(clippy::implicit_hasher)]
pub async fn push_image_into_gateway(
    tag: &str,
    gateway_name: &str,
    on_log: &mut impl FnMut(String),
) -> Result<()> {
    on_log(format!(
        "Pushing image {tag} into gateway \"{gateway_name}\""
    ));
    let local_docker = crate::docker::connect_local_for_large_transfers()
        .into_diagnostic()
        .wrap_err("failed to connect to local Docker daemon")?;
    let container = container_name(gateway_name);
    let images: Vec<&str> = vec![tag];
    push_local_images(&local_docker, &local_docker, &container, &images, on_log).await?;

    on_log(format!("Image {tag} is available in the gateway."));
    Ok(())
}

/// Build a container image from a Dockerfile and push it into the gateway.
///
/// This is used by `openshell sandbox create --from <Dockerfile>` when the
/// active gateway is the local Kubernetes deployment. It:
/// 1. Creates a tar archive of the build context directory.
/// 2. Sends it to the local Docker daemon via `build_image()`.
/// 3. Pushes the resulting image into the gateway's containerd via the
///    existing `push_local_images()` pipeline.
#[allow(clippy::implicit_hasher)]
pub async fn build_and_push_image(
    dockerfile_path: &Path,
    tag: &str,
    context_dir: &Path,
    gateway_name: &str,
    build_args: &HashMap<String, String>,
    on_log: &mut impl FnMut(String),
) -> Result<()> {
    build_local_image(dockerfile_path, tag, context_dir, build_args, on_log).await?;
    push_image_into_gateway(tag, gateway_name, on_log).await?;
    Ok(())
}

/// Build a container image using the local Docker daemon.
///
/// Creates a tar archive of `context_dir`, sends it to Docker with the
/// specified Dockerfile path and tag, and streams build output to `on_log`.
async fn build_image(
    dockerfile_path: &Path,
    tag: &str,
    context_dir: &Path,
    build_args: &HashMap<String, String>,
    on_log: &mut impl FnMut(String),
) -> Result<()> {
    let docker = Docker::connect_with_local_defaults()
        .into_diagnostic()
        .wrap_err("failed to connect to local Docker daemon")?;

    // Compute the relative path of the Dockerfile within the context.
    let dockerfile_relative = dockerfile_path
        .strip_prefix(context_dir)
        .unwrap_or(dockerfile_path);
    let dockerfile_str = dockerfile_relative
        .to_str()
        .ok_or_else(|| miette::miette!("Dockerfile path is not valid UTF-8"))?;

    // Create a tar archive of the build context, respecting .dockerignore.
    let context_tar = create_build_context_tar(context_dir)?;

    let mut builder = BuildImageOptionsBuilder::default()
        .dockerfile(dockerfile_str)
        .t(tag)
        .rm(true);

    // Pass build args to Docker.
    if !build_args.is_empty() {
        builder = builder.buildargs(build_args);
    }

    let options = builder.build();

    let body = bollard::body_full(bytes::Bytes::from(context_tar));
    let mut stream = docker.build_image(options, None, Some(body));

    while let Some(result) = stream.next().await {
        let info = result
            .into_diagnostic()
            .wrap_err("Docker build stream error")?;

        // Forward build output lines.
        if let Some(stream_line) = &info.stream {
            let trimmed = stream_line.trim_end();
            if !trimmed.is_empty() {
                on_log(trimmed.to_string());
            }
        }

        // Check for build errors.
        if let Some(error_detail) = &info.error_detail {
            let msg = error_detail
                .message
                .as_deref()
                .unwrap_or("unknown build error");
            return Err(miette::miette!("Docker build failed: {msg}"));
        }
    }

    Ok(())
}

async fn export_local_image_rootfs_to_path(image_ref: &str, tar_path: &Path) -> Result<()> {
    let docker = Docker::connect_with_local_defaults()
        .into_diagnostic()
        .wrap_err("failed to connect to local Docker daemon")?;
    let container_name = format!(
        "openshell-rootfs-export-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let create_options = CreateContainerOptionsBuilder::default()
        .name(container_name.as_str())
        .build();
    let container = docker
        .create_container(
            Some(create_options),
            ContainerCreateBody {
                image: Some(image_ref.to_string()),
                ..Default::default()
            },
        )
        .await
        .into_diagnostic()
        .wrap_err_with(|| {
            format!("failed to create temporary export container for image {image_ref}")
        })?;
    let container_id = container.id;

    let export_result = async {
        if let Some(parent) = tar_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to create {}", parent.display()))?;
        }
        let mut file = tokio::fs::File::create(tar_path)
            .await
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to create {}", tar_path.display()))?;
        let mut stream = docker.export_container(&container_id);
        while let Some(chunk) = stream.next().await {
            let chunk = chunk
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to export image {image_ref}"))?;
            file.write_all(&chunk)
                .await
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to write {}", tar_path.display()))?;
        }
        file.flush()
            .await
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to flush {}", tar_path.display()))
    }
    .await;

    let cleanup_result = docker
        .remove_container(
            &container_id,
            Some(RemoveContainerOptionsBuilder::default().force(true).build()),
        )
        .await;

    match (export_result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(err), _) => Err(err),
        (Ok(()), Err(err)) => Err(err).into_diagnostic().wrap_err_with(|| {
            format!("failed to remove temporary export container for {image_ref}")
        }),
    }
}

/// Create a tar archive of a directory for use as a Docker build context.
///
/// Walks `context_dir` recursively, respects a `.dockerignore` file if present,
/// and adds matching files with paths relative to the context root.
fn create_build_context_tar(context_dir: &Path) -> Result<Vec<u8>> {
    let ignore_patterns = load_dockerignore(context_dir);

    let mut builder = tar::Builder::new(Vec::new());

    // Walk the directory tree and add entries, skipping ignored paths.
    walk_and_add(context_dir, context_dir, &ignore_patterns, &mut builder)?;

    builder
        .into_inner()
        .into_diagnostic()
        .wrap_err("failed to finalize build context tar")
}

/// Recursively walk a directory and add entries to a tar archive,
/// skipping paths that match `.dockerignore` patterns.
fn walk_and_add(
    root: &Path,
    current: &Path,
    ignore_patterns: &[IgnorePattern],
    builder: &mut tar::Builder<Vec<u8>>,
) -> Result<()> {
    let entries = std::fs::read_dir(current)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read directory: {}", current.display()))?;

    for entry in entries {
        let entry = entry
            .into_diagnostic()
            .wrap_err("failed to read directory entry")?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .to_string();

        // Normalize to forward slashes for pattern matching.
        let relative_normalized = relative.replace('\\', "/");

        if is_ignored(&relative_normalized, path.is_dir(), ignore_patterns) {
            continue;
        }

        if path.is_dir() {
            walk_and_add(root, &path, ignore_patterns, builder)?;
        } else {
            // Use append_path_with_name which handles GNU LongName extensions
            // for paths exceeding 100 bytes (the POSIX tar name field limit).
            builder
                .append_path_with_name(&path, &relative_normalized)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to add file to tar: {relative_normalized}"))?;
        }
    }

    Ok(())
}

/// A parsed `.dockerignore` pattern.
#[derive(Debug, Clone)]
struct IgnorePattern {
    /// The glob pattern (may contain `*`, `**`, `?`).
    pattern: String,
    /// Whether this is a negation pattern (starts with `!`).
    negated: bool,
}

/// Load and parse a `.dockerignore` file from the context directory.
///
/// Returns an empty list if no `.dockerignore` exists.
fn load_dockerignore(context_dir: &Path) -> Vec<IgnorePattern> {
    let dockerignore_path = context_dir.join(".dockerignore");
    let Ok(contents) = std::fs::read_to_string(&dockerignore_path) else {
        return Vec::new();
    };

    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            line.strip_prefix('!').map_or_else(
                || IgnorePattern {
                    pattern: line.to_string(),
                    negated: false,
                },
                |rest| IgnorePattern {
                    pattern: rest.trim().to_string(),
                    negated: true,
                },
            )
        })
        .collect()
}

/// Check whether a relative path should be ignored based on `.dockerignore` patterns.
///
/// Uses a simple glob-matching approach: patterns are matched against the
/// full relative path. A leading `/` anchors to the context root. The last
/// matching pattern wins (negation patterns re-include files).
fn is_ignored(relative_path: &str, is_dir: bool, patterns: &[IgnorePattern]) -> bool {
    let mut ignored = false;

    for pat in patterns {
        let pattern = pat.pattern.trim_start_matches('/');

        // Check if the pattern matches.
        let matches = glob_match(pattern, relative_path, is_dir);

        if matches {
            ignored = !pat.negated;
        }
    }

    ignored
}

/// Simple glob matching supporting `*`, `**`, and `?`.
///
/// This is intentionally simple — it covers the common `.dockerignore` cases
/// without pulling in a full glob crate. For complex patterns, Docker's own
/// builder handles them during the build step anyway; this is just for
/// reducing the context tar size.
fn glob_match(pattern: &str, path: &str, is_dir: bool) -> bool {
    // Handle ** prefix (match any number of directories)
    if let Some(rest) = pattern.strip_prefix("**/") {
        // Match against the path itself and any suffix after a /
        if glob_match(rest, path, is_dir) {
            return true;
        }
        for (idx, _) in path.match_indices('/') {
            if glob_match(rest, &path[idx + 1..], is_dir) {
                return true;
            }
        }
        return false;
    }

    // Handle pattern that is just a name (no slashes) — match against any
    // path component or as a prefix directory match.
    if !pattern.contains('/') {
        // Match the final component of the path.
        let basename = path.rsplit('/').next().unwrap_or(path);
        if simple_glob_match(pattern, basename) {
            return true;
        }
        // Also match as a directory prefix: pattern "node_modules" should
        // match "node_modules/foo/bar".
        if let Some(first) = path.split('/').next()
            && simple_glob_match(pattern, first)
        {
            return true;
        }
        return false;
    }

    // Pattern contains slashes — match against the full path.
    simple_glob_match(pattern, path) || (is_dir && path.starts_with(pattern.trim_end_matches('/')))
}

/// Match a simple glob pattern (with `*` and `?` but not `**`) against a string.
fn simple_glob_match(pattern: &str, text: &str) -> bool {
    let mut p_star: Option<usize> = None;
    let mut t_star: Option<usize> = None;

    let p_bytes: Vec<char> = pattern.chars().collect();
    let t_bytes: Vec<char> = text.chars().collect();
    let mut pi = 0;
    let mut ti = 0;

    while ti < t_bytes.len() {
        if pi < p_bytes.len() && (p_bytes[pi] == '?' || p_bytes[pi] == t_bytes[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p_bytes.len() && p_bytes[pi] == '*' {
            p_star = Some(pi);
            t_star = Some(ti);
            pi += 1;
        } else if let Some(ps) = p_star {
            pi = ps + 1;
            t_star = Some(t_star.unwrap() + 1);
            ti = t_star.unwrap();
        } else {
            return false;
        }
    }

    while pi < p_bytes.len() && p_bytes[pi] == '*' {
        pi += 1;
    }

    pi == p_bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_create_build_context_tar() {
        let dir = tempfile::tempdir().unwrap();
        let dir_path = dir.path();

        // Create a simple Dockerfile and a file.
        fs::write(dir_path.join("Dockerfile"), "FROM ubuntu:24.04\n").unwrap();
        fs::write(dir_path.join("hello.txt"), "hello world\n").unwrap();
        fs::create_dir(dir_path.join("subdir")).unwrap();
        fs::write(dir_path.join("subdir/nested.txt"), "nested\n").unwrap();

        let tar_bytes = create_build_context_tar(dir_path).unwrap();
        assert!(!tar_bytes.is_empty());

        // Verify the tar contains the expected entries.
        let mut archive = tar::Archive::new(tar_bytes.as_slice());
        let entries: Vec<String> = archive
            .entries()
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|e| e.path().unwrap().to_string_lossy().to_string())
            .collect();

        assert!(entries.iter().any(|e| e.contains("Dockerfile")));
        assert!(entries.iter().any(|e| e.contains("hello.txt")));
        assert!(entries.iter().any(|e| e.contains("subdir/nested.txt")));
    }

    #[test]
    fn test_dockerignore_excludes_files() {
        let dir = tempfile::tempdir().unwrap();
        let dir_path = dir.path();

        fs::write(dir_path.join("Dockerfile"), "FROM ubuntu:24.04\n").unwrap();
        fs::write(dir_path.join("hello.txt"), "hello\n").unwrap();
        fs::write(dir_path.join("secret.env"), "SECRET=foo\n").unwrap();
        fs::create_dir(dir_path.join("node_modules")).unwrap();
        fs::write(dir_path.join("node_modules/pkg.js"), "module\n").unwrap();
        fs::write(dir_path.join(".dockerignore"), "*.env\nnode_modules\n").unwrap();

        let tar_bytes = create_build_context_tar(dir_path).unwrap();
        let mut archive = tar::Archive::new(tar_bytes.as_slice());
        let entries: Vec<String> = archive
            .entries()
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|e| e.path().unwrap().to_string_lossy().to_string())
            .collect();

        assert!(entries.iter().any(|e| e.contains("Dockerfile")));
        assert!(entries.iter().any(|e| e.contains("hello.txt")));
        assert!(!entries.iter().any(|e| e.contains("secret.env")));
        assert!(!entries.iter().any(|e| e.contains("node_modules")));
    }

    #[test]
    fn test_dockerignore_negation() {
        let dir = tempfile::tempdir().unwrap();
        let dir_path = dir.path();

        fs::write(dir_path.join("Dockerfile"), "FROM ubuntu:24.04\n").unwrap();
        fs::write(dir_path.join("a.log"), "log\n").unwrap();
        fs::write(dir_path.join("important.log"), "keep\n").unwrap();
        fs::write(dir_path.join(".dockerignore"), "*.log\n!important.log\n").unwrap();

        let tar_bytes = create_build_context_tar(dir_path).unwrap();
        let mut archive = tar::Archive::new(tar_bytes.as_slice());
        let entries: Vec<String> = archive
            .entries()
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|e| e.path().unwrap().to_string_lossy().to_string())
            .collect();

        assert!(!entries.iter().any(|e| e.contains("a.log")));
        assert!(entries.iter().any(|e| e.contains("important.log")));
    }

    #[test]
    fn test_long_path_exceeding_100_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let dir_path = dir.path();

        // Build a nested path that exceeds 100 bytes when relative to root.
        let deep_dir = dir_path.join(
            "a/deeply/nested/directory/path/that/exceeds/one/hundred/bytes/total/from/the/build/context/root",
        );
        fs::create_dir_all(&deep_dir).unwrap();
        fs::write(deep_dir.join("file.txt"), "deep content\n").unwrap();
        fs::write(dir_path.join("Dockerfile"), "FROM ubuntu:24.04\n").unwrap();

        let tar_bytes = create_build_context_tar(dir_path).unwrap();
        let mut archive = tar::Archive::new(tar_bytes.as_slice());
        let entries: Vec<String> = archive
            .entries()
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|e| e.path().unwrap().to_string_lossy().to_string())
            .collect();

        let long_entry = entries.iter().find(|e| e.contains("file.txt"));
        assert!(
            long_entry.is_some(),
            "tar should contain deeply nested file; entries: {entries:?}"
        );
        assert!(
            long_entry.unwrap().len() > 100,
            "path should exceed 100 bytes to exercise GNU LongName handling"
        );
    }

    #[test]
    fn test_simple_glob_match() {
        assert!(simple_glob_match("*.txt", "hello.txt"));
        assert!(!simple_glob_match("*.txt", "hello.rs"));
        assert!(simple_glob_match("test?", "test1"));
        assert!(!simple_glob_match("test?", "test12"));
        assert!(simple_glob_match("*", "anything"));
        assert!(simple_glob_match("foo*bar", "fooXYZbar"));
    }

    #[test]
    fn test_glob_match_double_star() {
        assert!(glob_match("**/*.log", "a/b/c.log", false));
        assert!(glob_match("**/*.log", "c.log", false));
        assert!(!glob_match("**/*.log", "c.txt", false));
    }

    #[test]
    fn test_is_ignored_directory_prefix() {
        let patterns = vec![IgnorePattern {
            pattern: "node_modules".to_string(),
            negated: false,
        }];
        assert!(is_ignored("node_modules", true, &patterns));
        assert!(is_ignored("node_modules/foo.js", false, &patterns));
    }

    #[test]
    fn encode_and_decode_rootfs_tar_image_ref_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let tar_path = dir.path().join("rootfs tar.tar");
        fs::write(&tar_path, "rootfs").unwrap();

        let encoded = encode_rootfs_tar_image_ref(&tar_path).unwrap();
        let decoded = decode_rootfs_tar_image_ref(&encoded).unwrap();

        assert_eq!(decoded, tar_path.canonicalize().unwrap());
    }
}
