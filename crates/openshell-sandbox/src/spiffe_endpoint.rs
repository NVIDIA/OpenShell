// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

/// Convert a path to a SPIFFE Workload API endpoint URL.
///
/// If the path already has a scheme (`unix:` or `tcp:`), use it as-is.
/// Otherwise, assume it is a Unix socket path and prepend `unix:`.
pub fn workload_api_endpoint(path: &Path) -> String {
    let path = path.to_string_lossy();
    if path.starts_with("unix:") || path.starts_with("tcp:") {
        path.into_owned()
    } else {
        format!("unix:{path}")
    }
}
