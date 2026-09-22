// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Test-only access to the example provider profiles in `providers/`.
//!
//! `OpenShell` does not compile any provider profile into a release binary. The
//! YAML under `providers/` is reviewable example data that an operator imports
//! explicitly with `openshell provider profile import`.
//!
//! Tests still need those files: they are the fixtures that keep the examples
//! honest, and they stand in for "what an operator imported" in gateway and CLI
//! tests. This module reads them from the source checkout at run time, so it
//! works only where the repository is present. It is gated behind the
//! `example-profiles` feature, which is enabled from `[dev-dependencies]` only.

use std::path::{Path, PathBuf};

use crate::profiles::{
    ProfileError, ProviderTypeProfile, parse_profile_catalog_yamls, parse_profile_yaml,
};

/// Absolute path of the repository's `providers/` directory.
#[must_use]
pub fn directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../providers")
}

/// Absolute path of one example profile file.
#[must_use]
pub fn path(id: &str) -> PathBuf {
    directory().join(format!("{id}.yaml"))
}

/// Parse a single example profile by its file stem.
///
/// # Panics
///
/// Panics if the file is missing or does not parse. Both are bugs in the
/// checkout, not conditions a caller can handle.
#[must_use]
pub fn load(id: &str) -> ProviderTypeProfile {
    let file = path(id);
    let yaml = std::fs::read_to_string(&file)
        .unwrap_or_else(|err| panic!("read example provider profile {}: {err}", file.display()));
    parse_profile_yaml(&yaml)
        .unwrap_or_else(|err| panic!("parse example provider profile {}: {err}", file.display()))
}

/// Parse every example profile as one validated, id-sorted catalog.
///
/// # Panics
///
/// Panics if `providers/` cannot be read or the set fails validation.
#[must_use]
pub fn load_all() -> Vec<ProviderTypeProfile> {
    try_load_all().unwrap_or_else(|err| panic!("load example provider profiles: {err}"))
}

/// Fallible form of [`load_all`], for tests that assert on validation failure.
///
/// # Errors
///
/// Returns the first parse or validation error in the example set.
///
/// # Panics
///
/// Panics if `providers/` cannot be listed.
pub fn try_load_all() -> Result<Vec<ProviderTypeProfile>, ProfileError> {
    let dir = directory();
    let mut files = std::fs::read_dir(&dir)
        .unwrap_or_else(|err| panic!("read directory {}: {err}", dir.display()))
        .map(|entry| {
            entry
                .unwrap_or_else(|err| panic!("read directory entry in {}: {err}", dir.display()))
                .path()
        })
        .filter(|path| path.extension().is_some_and(|ext| ext == "yaml"))
        .collect::<Vec<_>>();
    files.sort();

    let yamls = files
        .iter()
        .map(|file| {
            std::fs::read_to_string(file)
                .unwrap_or_else(|err| panic!("read {}: {err}", file.display()))
        })
        .collect::<Vec<_>>();
    let inputs = yamls.iter().map(String::as_str).collect::<Vec<_>>();
    parse_profile_catalog_yamls(&inputs)
}
