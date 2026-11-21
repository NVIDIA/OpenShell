// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Unix domain socket pathname limit.

use std::io;
use std::path::Path;

/// Longest Unix socket pathname, in bytes, without the terminating NUL.
///
/// `sockaddr_un.sun_path` holds 108 bytes on Linux and 104 on macOS.
/// Abstract socket addresses have different limits and are not pathnames.
pub const MAX_LEN: usize = if cfg!(target_os = "linux") { 107 } else { 103 };

/// Reject a socket pathname that does not fit in `sockaddr_un.sun_path`.
///
/// Call it before creating directories, removing a stale socket or retrying a
/// connection. The error names the path and its length. The kernel error says
/// only that the path must be shorter than `SUN_LEN`.
pub fn check(path: &Path) -> io::Result<()> {
    let len = path.as_os_str().len();
    if len <= MAX_LEN {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "Unix socket path '{}' is {len} bytes, over the {MAX_LEN}-byte limit on this platform",
            path.display()
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_limit_and_rejects_one_byte_more() {
        let at_limit = format!("/{}", "a".repeat(MAX_LEN - 1));
        check(Path::new(&at_limit)).unwrap();

        let over = format!("{at_limit}a");
        let error = check(Path::new(&over)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains(&over), "{error}");
        assert!(
            error.to_string().contains(&format!(
                "{} bytes, over the {MAX_LEN}-byte limit",
                MAX_LEN + 1
            )),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn limit_matches_what_the_platform_binds() {
        // macOS TMPDIR is too long to leave room for the probe name.
        let dir = tempfile::Builder::new()
            .prefix("os-sock-len-")
            .tempdir_in("/tmp")
            .unwrap();
        let prefix = dir.path().join("s");
        let fill = MAX_LEN - prefix.as_os_str().len();
        let at_limit = format!("{}{}", prefix.display(), "a".repeat(fill));
        let bound = std::os::unix::net::UnixListener::bind(&at_limit);
        let over = std::os::unix::net::UnixListener::bind(format!("{at_limit}b"));
        bound.unwrap();
        over.unwrap_err();
    }
}
