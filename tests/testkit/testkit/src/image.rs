// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The base image tests create sandboxes from or build their images on.

/// Overrides [`DEFAULT_BASE_IMAGE`], e.g. with a mirror.
pub const BASE_IMAGE_ENV: &str = "OPENSHELL_TEST_BASE_IMAGE";
/// OpenShell's built-in default sandbox image. Pulling it needs access to
/// nvcr.io.
pub const DEFAULT_BASE_IMAGE: &str = "nvcr.io/nvidia/base/ubuntu:24.04";

/// The image named by [`BASE_IMAGE_ENV`], or [`DEFAULT_BASE_IMAGE`].
pub fn base_image() -> String {
    std::env::var(BASE_IMAGE_ENV)
        .ok()
        .filter(|image| !image.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_BASE_IMAGE.to_string())
}
