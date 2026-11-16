// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Landlock ABI probing for the sandbox boundary.

#![allow(unsafe_code)]
use std::io;

const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;

/// Query the Landlock ABI admitted by the active kernel and outer seccomp
/// profile without installing a ruleset.
pub fn abi_version() -> io::Result<u32> {
    // SAFETY: the VERSION operation requires a null ruleset pointer and zero
    // size and returns one scalar ABI version.
    let result = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        u32::try_from(result).map_err(|_| io::Error::other("Landlock ABI does not fit u32"))
    }
}
