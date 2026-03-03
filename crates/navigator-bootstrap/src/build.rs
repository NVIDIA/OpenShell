// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Build and push container images into a k3s cluster.
//!
//! This module wraps bollard's `build_image()` API to build a container image
//! from a Dockerfile and build context, then reuses the existing push pipeline
//! to import the image into the cluster's containerd runtime.

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

use bollard::Docker;
use bollard::query_parameters::BuildImageOptionsBuilder;
use futures::StreamExt;
use miette::{IntoDiagnostic, Result, WrapErr};

use crate::constants::container_name;
use crate::push::push_local_images;

/// Build a container image from a Dockerfile and push it into the cluster.
///
/// This is the primary entry point for `nav sandbox image push`. It:
/// 1. Creates a tar archive of the build context directory.
/// 2. Sends it to the local Docker daemon via `build_image()`.
/// 3. Pushes the resulting image into the cluster's containerd via the
///    existing `push_local_images()` pipeline.
#[allow(clippy::implicit_hasher)]
pub async fn build_and_push_image(
    dockerfile_path: &Path,
    tag: &str,
    context_dir: &Path,
    cluster_name: &str,
    build_args: &HashMap<String, String>,
    on_log: &mut impl FnMut(String),
) -> Result<()> {
    // 1. Build the image locally.
    on_log(format!(
        "Building image {tag} from {}",
        dockerfile_path.display()
    ));
    build_image(dockerfile_path, tag, context_dir, build_args, on_log).await?;
    on_log(format!("Built image {tag}"));

    // 2. Push into the cluster.
    on_log(format!(
        "Pushing image {tag} into cluster \"{cluster_name}\""
    ));
    let local_docker = Docker::connect_with_local_defaults()
        .into_diagnostic()
        .wrap_err("failed to connect to local Docker daemon")?;
    let container = container_name(cluster_name);
    let images: Vec<&str> = vec![tag];
    push_local_images(&local_docker, &local_docker, &container, &images, on_log).await?;

    on_log(format!("Image {tag} is available in the cluster."));
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
            let mut file = std::fs::File::open(&path)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to open file: {}", path.display()))?;
            let metadata = file
                .metadata()
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to read metadata: {}", path.display()))?;

            let mut header = tar::Header::new_gnu();
            header.set_size(metadata.len());
            header.set_mode(0o644);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                header.set_mode(metadata.permissions().mode());
            }
            header
                .set_path(&relative_normalized)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to set tar entry path: {relative_normalized}"))?;
            header.set_cksum();

            #[allow(clippy::cast_possible_truncation)]
            let mut contents = Vec::with_capacity(metadata.len() as usize);
            file.read_to_end(&mut contents)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to read file: {}", path.display()))?;

            builder
                .append(&header, contents.as_slice())
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
}
