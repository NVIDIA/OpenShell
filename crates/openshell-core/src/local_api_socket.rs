// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generic discovery and probing for local HTTP APIs over Unix sockets.

use std::path::{Path, PathBuf};

/// Return the first candidate whose HTTP ping response is accepted.
#[must_use]
pub fn first_responsive_socket(
    candidates: &[PathBuf],
    accepts_response: impl Fn(&[u8]) -> bool,
) -> Option<PathBuf> {
    candidates
        .iter()
        .find(|path| socket_responds(path, &accepts_response))
        .cloned()
}

/// Return whether a byte slice contains another, ignoring ASCII case.
#[must_use]
pub fn contains_ascii(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

/// Return whether an HTTP response starts with a successful status line.
#[must_use]
pub fn http_response_is_success(response: &[u8]) -> bool {
    response.starts_with(b"HTTP/1.1 200") || response.starts_with(b"HTTP/1.0 200")
}

#[cfg(unix)]
fn socket_responds(path: &Path, accepts_response: &impl Fn(&[u8]) -> bool) -> bool {
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::FileTypeExt as _;
    use std::time::Duration;

    const PROBE_TIMEOUT: Duration = Duration::from_secs(1);
    const PING_REQUEST: &[u8] =
        b"GET /_ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";

    if !path
        .metadata()
        .is_ok_and(|metadata| metadata.file_type().is_socket())
    {
        return false;
    }
    let Ok(mut stream) = std::os::unix::net::UnixStream::connect(path) else {
        return false;
    };
    if stream.set_read_timeout(Some(PROBE_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(PROBE_TIMEOUT)).is_err()
        || stream.write_all(PING_REQUEST).is_err()
    {
        return false;
    }

    let mut response = [0_u8; 512];
    let mut total = 0;
    while total < response.len() {
        let Ok(read) = stream.read(&mut response[total..]) else {
            return false;
        };
        if read == 0 {
            break;
        }
        total += read;
        if contains_ascii(&response[..total], b"\r\n\r\n") {
            break;
        }
    }
    total > 0 && accepts_response(&response[..total])
}

#[cfg(not(unix))]
fn socket_responds(path: &Path, accepts_response: &impl Fn(&[u8]) -> bool) -> bool {
    let _ = (path, accepts_response);
    false
}
