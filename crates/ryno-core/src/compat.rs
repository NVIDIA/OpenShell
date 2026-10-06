// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! One-release compatibility shims for the `OpenShell` -> `Ryno` rename.
//!
//! First-party binaries call [`apply_legacy_env`] as the first statement of
//! `main`, before CLI parsing. Each legacy `OPENSHELL_*` variable is copied
//! to its `RYNO_*` counterpart only when the new variable is unset, so
//! explicit new configuration always wins. These shims are removed after one
//! release cycle.

/// Legacy environment prefix honored for one release cycle.
const LEGACY_PREFIX: &str = "OPENSHELL_";

/// Current environment prefix.
const CURRENT_PREFIX: &str = "RYNO_";

/// Copy legacy `OPENSHELL_*` variables to `RYNO_*` when the new name is unset.
///
/// Prints a single warning to stderr listing the bridged variables. Safe to
/// call concurrently: bridging the same value twice is idempotent.
#[allow(unsafe_code)]
pub fn apply_legacy_env() {
    let mut bridged: Vec<(String, String)> = Vec::new();
    for (key, value) in std::env::vars_os() {
        let Some(key) = key.to_str() else { continue };
        let Some(suffix) = key.strip_prefix(LEGACY_PREFIX) else {
            continue;
        };
        let current = format!("{CURRENT_PREFIX}{suffix}");
        if std::env::var_os(&current).is_none() {
            // SAFETY: each derived `RYNO_*` key is written at most once per
            // process (guarded by the `is_none` check above), and concurrent
            // writers store the same value, so no data race on distinct keys
            // and no conflicting values on the same key.
            unsafe { std::env::set_var(&current, &value) };
            bridged.push((key.to_owned(), current));
        }
    }
    if bridged.is_empty() {
        return;
    }
    bridged.sort();
    let pairs = bridged
        .iter()
        .map(|(old, new)| format!("{old} -> {new}"))
        .collect::<Vec<_>>()
        .join(", ");
    eprintln!(
        "ryno: warning: honoring legacy variable(s) ({pairs}); rename them to RYNO_* (legacy support ends after one release cycle)"
    );
}
