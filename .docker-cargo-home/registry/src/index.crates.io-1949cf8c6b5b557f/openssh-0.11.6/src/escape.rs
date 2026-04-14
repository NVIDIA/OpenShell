//! Escape characters that may have special meaning in a shell, including spaces.
//! This is a modified version of the [`shell-escape::unix`] module of [`shell-escape`] crate.
//!
//! [`shell-escape`]: https://crates.io/crates/shell-escape
//! [`shell-escape::unix`]: https://docs.rs/shell-escape/latest/src/shell_escape/lib.rs.html#101

use std::{
    borrow::Cow,
    ffi::{OsStr, OsString},
    os::unix::ffi::OsStrExt,
    os::unix::ffi::OsStringExt,
};

fn allowed(byte: u8) -> bool {
    matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'=' | b'/' | b',' | b'.' | b'+')
}

/// Escape characters that may have special meaning in a shell, including spaces.
///
/// **Note**: This function is an adaptation of [`shell-escape::unix::escape`].
/// This function exists only for type compatibility and the implementation is
/// almost exactly the same as [`shell-escape::unix::escape`].
///
/// [`shell-escape::unix::escape`]: https://docs.rs/shell-escape/latest/src/shell_escape/lib.rs.html#101
///
pub(crate) fn escape(s: &OsStr) -> Cow<'_, OsStr> {
    let as_bytes = s.as_bytes();
    let all_allowed = as_bytes.iter().copied().all(allowed);

    if !as_bytes.is_empty() && all_allowed {
        return Cow::Borrowed(s);
    }

    let mut escaped = Vec::with_capacity(as_bytes.len() + 2);
    escaped.push(b'\'');

    for &b in as_bytes {
        match b {
            b'\'' | b'!' => {
                escaped.reserve(4);
                escaped.push(b'\'');
                escaped.push(b'\\');
                escaped.push(b);
                escaped.push(b'\'');
            }
            _ => escaped.push(b),
        }
    }
    escaped.push(b'\'');
    OsString::from_vec(escaped).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_escape_case(input: &str, expected: &str) {
        test_escape_from_bytes(input.as_bytes(), expected.as_bytes())
    }

    fn test_escape_from_bytes(input: &[u8], expected: &[u8]) {
        let input_os_str = OsStr::from_bytes(input);
        let observed_os_str = escape(input_os_str);
        let expected_os_str = OsStr::from_bytes(expected);
        assert_eq!(observed_os_str, expected_os_str);
    }

    // These tests are courtesy of the `shell-escape` crate.
    #[test]
    fn test_escape() {
        test_escape_case(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_=/,.+",
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_=/,.+",
        );
        test_escape_case("--aaa=bbb-ccc", "--aaa=bbb-ccc");
        test_escape_case(
            "linker=gcc -L/foo -Wl,bar",
            r#"'linker=gcc -L/foo -Wl,bar'"#,
        );
        test_escape_case(r#"--features="default""#, r#"'--features="default"'"#);
        test_escape_case(r#"'!\$`\\\n "#, r#"''\'''\!'\$`\\\n '"#);
        test_escape_case("", r#"''"#);
        test_escape_case(" ", r#"' '"#);
        test_escape_case("*", r#"'*'"#);

        test_escape_from_bytes(
            &[0x66, 0x6f, 0x80, 0x6f],
            &[b'\'', 0x66, 0x6f, 0x80, 0x6f, b'\''],
        );
    }
}
