// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Login-shell resolution for sandbox images.
//!
//! The default sandbox command and the interactive SSH session need a shell,
//! but not every base image ships the same one. Debian-based images provide
//! `bash`; minimal images such as Alpine only provide `/bin/sh` (`BusyBox`
//! `ash`). Hard-coding `/bin/bash` makes sandbox startup fail on those images
//! with an opaque `No such file or directory`.
//!
//! These helpers resolve a shell that actually exists in the current root
//! filesystem. They must run inside the sandbox (i.e. in the supervisor), not
//! on the gateway, because the answer depends on the sandbox image's contents.

/// Preferred interactive shell when the image provides it.
pub const BASH: &str = "/bin/bash";

/// Preferred interactive shell on `usr`-merged images where `/bin` is not a
/// top-level directory.
pub const USR_BASH: &str = "/usr/bin/bash";

/// POSIX shell. Guaranteed on virtually every image, including Alpine/`BusyBox`.
/// Used as the ultimate fallback.
pub const POSIX_SH: &str = "/bin/sh";

/// Shell paths tried, in preference order, by [`detect_login_shell`].
pub const SHELL_CANDIDATES: &[&str] = &[BASH, USR_BASH, POSIX_SH];

/// Return `true` if `path` is a regular, executable file in the current root
/// filesystem.
#[must_use]
pub fn is_executable(path: &str) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Resolve a login shell that exists in the current root filesystem.
///
/// Tries [`SHELL_CANDIDATES`] in order and falls back to [`POSIX_SH`]. Because
/// this inspects the filesystem, call it from the supervisor (inside the
/// sandbox), never on the gateway.
///
/// `$SHELL` is intentionally not consulted: it is image/user-controlled, the
/// result is later invoked with `-lc`, and an executable that is not a
/// compatible shell (e.g. `SHELL=/bin/false`) would pass the executable check
/// yet break command execution. Resolving only from known shell paths avoids
/// that footgun.
#[must_use]
pub fn detect_login_shell() -> String {
    SHELL_CANDIDATES
        .iter()
        .find(|candidate| is_executable(candidate))
        .map_or_else(
            || POSIX_SH.to_string(),
            |candidate| (*candidate).to_string(),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    // These assume a Unix root filesystem (`/bin/sh`, POSIX permission bits) and
    // are skipped on the Windows workspace lane where openshell-core also builds.
    #[cfg(unix)]
    #[test]
    fn posix_sh_exists_on_test_host() {
        // /bin/sh is present on all supported Unix CI hosts (Linux and macOS).
        assert!(is_executable(POSIX_SH));
    }

    #[test]
    fn missing_path_is_not_executable() {
        assert!(!is_executable("/nonexistent/definitely/not/here"));
    }

    #[cfg(unix)]
    #[test]
    fn non_file_is_not_executable() {
        // A directory is not an executable shell.
        assert!(!is_executable("/"));
    }

    #[cfg(unix)]
    #[test]
    fn detect_returns_an_executable_shell() {
        let shell = detect_login_shell();
        assert!(
            is_executable(&shell),
            "detected shell {shell} is not executable"
        );
    }
}
