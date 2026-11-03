// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Strict `/proc/<tid>/status` identity lookups.
//!
//! Signal and scheduling mediation both need the thread group a numeric TID
//! belongs to. The status file names it without following a path the workload
//! can replace. A missing file is reported as ESRCH so callers keep the native
//! "no such process" result for a target that has already exited.

use std::io;

/// Resolve the thread group ID that owns `tid`.
///
/// Returns ESRCH when the task is gone or its status file carries no usable
/// `Tgid:` line, since either case means no live thread group answers for it.
pub(crate) fn thread_group_id(tid: u32) -> io::Result<u32> {
    let status = std::fs::read_to_string(format!("/proc/{tid}/status")).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            io::Error::from_raw_os_error(libc::ESRCH)
        } else {
            error
        }
    })?;
    status
        .lines()
        .find_map(|line| {
            line.strip_prefix("Tgid:")
                .and_then(|value| value.trim().parse::<u32>().ok())
        })
        .ok_or_else(|| io::Error::from_raw_os_error(libc::ESRCH))
}
