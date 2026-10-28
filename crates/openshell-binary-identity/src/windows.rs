// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Trusted Windows runtime-path attributes for executable policy matching.

use std::path::Path;

#[allow(unsafe_code)]
fn windows_directory_case_sensitive(path: &Path) -> Option<bool> {
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        FILE_CASE_SENSITIVE_INFO, FileCaseSensitiveInfo, GetFileInformationByHandleEx,
    };

    let handle = open_windows_directory_for_attributes(path)?;
    let mut info = FILE_CASE_SENSITIVE_INFO::default();
    let info_size = u32::try_from(size_of::<FILE_CASE_SENSITIVE_INFO>()).ok()?;
    // SAFETY: `handle` stays alive for the call and `info` is the exact buffer
    // type and size required by `FileCaseSensitiveInfo`.
    unsafe {
        GetFileInformationByHandleEx(
            HANDLE(handle.as_raw_handle()),
            FileCaseSensitiveInfo,
            (&raw mut info).cast(),
            info_size,
        )
    }
    .ok()?;
    Some(info.Flags & 1 != 0)
}

/// Check every parent of a trusted, ordinary absolute executable path.
///
/// Returns `None` for namespace paths or when any directory cannot be queried.
/// Callers must retain exact case matching unless this returns `Some(true)`.
/// Never call this with policy-authored paths.
#[must_use]
pub fn path_components_case_insensitive(path: &Path) -> Option<bool> {
    let text = path.to_string_lossy();
    let bytes = text.as_bytes();
    if text.contains(['*', '?'])
        || (bytes.len() >= 2
            && matches!(bytes[0], b'/' | b'\\')
            && matches!(bytes[1], b'/' | b'\\'))
        || bytes.len() < 3
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || !matches!(bytes[2], b'/' | b'\\')
    {
        return None;
    }

    let parent = path.parent()?;
    for directory in parent.ancestors().filter(|p| !p.as_os_str().is_empty()) {
        if windows_directory_case_sensitive(directory)? {
            return Some(false);
        }
    }
    Some(true)
}

fn open_windows_directory_for_attributes(path: &Path) -> Option<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    };

    std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES.0)
        .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
        .open(path)
        .ok()
}
