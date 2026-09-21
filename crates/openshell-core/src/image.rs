// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Default sandbox image.
//!
//! Provides the fallback image used by all compute drivers when a sandbox spec
//! does not specify one. User-supplied `--from` values are explicit OCI image
//! references passed through unchanged by the CLI and TUI.

/// Default sandbox base image reference.
///
/// A generic, version-qualified official Alpine image so a fresh install does
/// not depend on the community image catalog.
pub const DEFAULT_SANDBOX_BASE_IMAGE: &str = "docker.io/library/alpine:3.22";

/// Return the default sandbox image reference.
///
/// Used by all compute drivers as the fallback image when none is specified in
/// the sandbox spec.
#[must_use]
pub fn default_sandbox_image() -> String {
    DEFAULT_SANDBOX_BASE_IMAGE.to_string()
}
