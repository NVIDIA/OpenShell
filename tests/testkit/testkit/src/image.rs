// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The images tests create sandboxes from or build their images on.

/// Overrides [`DEFAULT_BASE_IMAGE`], e.g. with a mirror.
const BASE_IMAGE_ENV: &str = "OPENSHELL_TEST_BASE_IMAGE";
/// OpenShell's built-in default sandbox image. Pulling it needs access to
/// nvcr.io.
const DEFAULT_BASE_IMAGE: &str = "nvcr.io/nvidia/base/ubuntu:24.04";

/// Overrides [`DEFAULT_PYTHON_IMAGE`]. The image must run `python3` from one
/// of [`PYTHON_BINARIES`]; otherwise policies that allow those paths don't
/// match it, and its connections are denied.
const PYTHON_IMAGE_ENV: &str = "OPENSHELL_TEST_PYTHON_IMAGE";
/// The workload image for tests that run `python3`, curl, git or openssl in a
/// sandbox, built from `e2e/python/Dockerfile.workload`. It isn't published:
/// the tmachine installers load it into every environment, and
/// `mise run e2e:workload:build` builds it locally.
const DEFAULT_PYTHON_IMAGE: &str = "openshell/e2e-python:dev";

/// The paths `python3` runs from in [`python_image`] images, as network
/// policy binaries: the system Python, the pullable uv image's Python, and the
/// workload image's uv-installed Python behind its virtualenv. Add a path
/// here for an image that installs Python elsewhere.
pub const PYTHON_BINARIES: &[&str] = &[
    "/usr/bin/python*",
    "/usr/local/bin/python*",
    "/sandbox/.uv/python/*/bin/python*",
];

/// The image named by [`BASE_IMAGE_ENV`], or [`DEFAULT_BASE_IMAGE`].
pub fn base_image() -> String {
    image_from_env(BASE_IMAGE_ENV, DEFAULT_BASE_IMAGE)
}

/// The image named by [`PYTHON_IMAGE_ENV`], or [`DEFAULT_PYTHON_IMAGE`].
pub fn python_image() -> String {
    image_from_env(PYTHON_IMAGE_ENV, DEFAULT_PYTHON_IMAGE)
}

fn image_from_env(var: &str, default: &str) -> String {
    std::env::var(var)
        .ok()
        .filter(|image| !image.trim().is_empty())
        .unwrap_or_else(|| default.to_string())
}
