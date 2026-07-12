// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Unix-socket address helpers shared by the SSH server and relay client.

use std::borrow::Cow;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

/// Return whether a configured socket name denotes a Linux abstract socket.
///
/// Environment variables cannot contain the leading NUL byte used by the
/// kernel ABI, so configuration uses the conventional `@name` spelling.
pub fn is_abstract(path: &Path) -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().starts_with(b"@")
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        false
    }
}

/// Translate the configured `@name` spelling into Tokio's NUL-prefixed Linux
/// abstract-socket path representation.
pub fn runtime_path(path: &Path) -> Cow<'_, Path> {
    #[cfg(target_os = "linux")]
    {
        use std::ffi::OsString;
        use std::os::unix::ffi::{OsStrExt, OsStringExt};

        let bytes = path.as_os_str().as_bytes();
        if let Some(name) = bytes.strip_prefix(b"@") {
            let mut abstract_name = Vec::with_capacity(name.len() + 1);
            abstract_name.push(0);
            abstract_name.extend_from_slice(name);
            return Cow::Owned(PathBuf::from(OsString::from_vec(abstract_name)));
        }
    }
    Cow::Borrowed(path)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn at_name_maps_to_abstract_socket_path() {
        use std::os::unix::ffi::OsStrExt;

        let configured = Path::new("@openshell-test");
        let runtime = runtime_path(configured);
        assert!(is_abstract(configured));
        assert_eq!(runtime.as_os_str().as_bytes(), b"\0openshell-test");
    }
}
