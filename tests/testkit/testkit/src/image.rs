// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The images tests create sandboxes from or build their images on.

/// Overrides [`DEFAULT_BASE_IMAGE`], e.g. with a mirror.
const BASE_IMAGE_ENV: &str = "OPENSHELL_TEST_BASE_IMAGE";
/// OpenShell's built-in default sandbox image. Pulling it needs access to
/// nvcr.io.
const DEFAULT_BASE_IMAGE: &str = "nvcr.io/nvidia/base/ubuntu:24.04";

/// Overrides [`DEFAULT_PYTHON_IMAGE`].
const PYTHON_IMAGE_ENV: &str = "OPENSHELL_TEST_PYTHON_IMAGE";
/// The image for tests that run `python3` in a sandbox. It is public and
/// pinned by digest so any gateway can pull it, and has the Python standard
/// library only: no curl, git or openssl.
const DEFAULT_PYTHON_IMAGE: &str = "ghcr.io/astral-sh/uv:0.12.17-python3.12-trixie-slim@sha256:9a59bb7206905ccaae4f7dab222fbac47c125a21e5fc16f43f427cd6c940ade3";

/// The paths `python3` runs from in [`python_image`] images, as network
/// policy binaries: the system Python, the pullable uv image's Python, and the
/// workload image's uv-installed Python behind its virtualenv.
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
