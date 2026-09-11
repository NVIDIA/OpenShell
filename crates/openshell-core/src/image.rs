// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Default sandbox image.
//!
//! Provides the fallback image used by all compute drivers when a sandbox spec
//! does not specify one. User-supplied `--from` values are explicit OCI image
//! references passed through unchanged by the CLI and TUI.

/// Return the default sandbox image reference.
///
/// Used by all compute drivers as the fallback image when none is specified in
/// the sandbox spec. Defaults to a generic, version-qualified official Alpine
/// image so a fresh install does not depend on the community image catalog.
#[must_use]
pub fn default_sandbox_image() -> String {
    "docker.io/library/alpine:3.22".to_string()
}
