// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared metadata keys for driver-provided sandbox provisioning progress.

use std::collections::HashMap;
use std::hash::BuildHasher;

pub const PROGRESS_COMPLETE_STEP_KEY: &str = "openshell.progress.complete_step";
pub const PROGRESS_COMPLETE_LABEL_KEY: &str = "openshell.progress.complete_label";
pub const PROGRESS_ACTIVE_STEP_KEY: &str = "openshell.progress.active_step";
pub const PROGRESS_ACTIVE_DETAIL_KEY: &str = "openshell.progress.active_detail";

pub const PROGRESS_STEP_REQUESTING_SANDBOX: &str = "requesting_sandbox";
pub const PROGRESS_STEP_PULLING_IMAGE: &str = "pulling_image";
pub const PROGRESS_STEP_STARTING_SANDBOX: &str = "starting_sandbox";

pub fn mark_progress_complete<S: BuildHasher>(
    metadata: &mut HashMap<String, String, S>,
    step: &'static str,
    label: impl Into<String>,
) {
    metadata.insert(PROGRESS_COMPLETE_STEP_KEY.to_string(), step.to_string());
    metadata.insert(PROGRESS_COMPLETE_LABEL_KEY.to_string(), label.into());
}

pub fn mark_progress_active<S: BuildHasher>(
    metadata: &mut HashMap<String, String, S>,
    step: &'static str,
) {
    metadata.insert(PROGRESS_ACTIVE_STEP_KEY.to_string(), step.to_string());
}

pub fn mark_progress_detail<S: BuildHasher>(
    metadata: &mut HashMap<String, String, S>,
    detail: impl Into<String>,
) {
    metadata.insert(PROGRESS_ACTIVE_DETAIL_KEY.to_string(), detail.into());
}

/// Format a byte count as a human-readable string (B / KB / MB / GB).
///
/// Used by compute drivers when reporting image pull progress.
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        #[allow(clippy::cast_precision_loss)]
        let gb = bytes as f64 / GB as f64;
        format!("{gb:.1} GB")
    } else if bytes >= MB {
        format!("{} MB", bytes / MB)
    } else if bytes >= KB {
        format!("{} KB", bytes / KB)
    } else {
        format!("{bytes} B")
    }
}
