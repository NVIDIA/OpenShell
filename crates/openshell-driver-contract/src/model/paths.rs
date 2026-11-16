// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

/// Whether `path` is absolute under POSIX rules, whatever the host platform.
pub fn is_posix_absolute(path: &Path) -> bool {
    path.to_str().is_some_and(|path| path.starts_with('/'))
}
