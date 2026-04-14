//! Functions for common string operations.

use core::ops::{self, RangeFrom, RangeTo};

pub(crate) use self::maybe_pct_encoded::{
    process_percent_encoded_best_effort, PctEncodedFragments,
};
use crate::parser::trusted as trusted_parser;

mod maybe_pct_encoded;

/// Returns the inner string if wrapped.
#[must_use]
pub(crate) fn get_wrapped_inner(s: &str, open: u8, close: u8) -> Option<&str> {
    let (prefix, suffix) = match s.as_bytes() {
        [prefix, suffix] | [prefix, .., suffix] => (*prefix, *suffix),
        _ => return None,
    };
    if (prefix == open) && (suffix == close) {
        Some(&s[1..(s.len() - 1)])
    } else {
        None
    }
}

/// Returns the byte that appears first.
#[cfg(not(feature = "memchr"))]
#[inline]
#[must_use]
pub(crate) fn prior_byte2(haystack: &[u8], needle1: u8, needle2: u8) -> Option<u8> {
    haystack
        .iter()
        .copied()
        .find(|&b| b == needle1 || b == needle2)
}

/// Returns the byte that appears first.
#[cfg(feature = "memchr")]
#[inline]
#[must_use]
pub(crate) fn prior_byte2(haystack: &[u8], needle1: u8, needle2: u8) -> Option<u8> {
    memchr::memchr2(needle1, needle2, haystack).map(|pos| haystack[pos])
}

/// (Possibly) faster version of `haystack.rfind(needle)` when `needle` is an ASCII character.
#[cfg(not(feature = "memchr"))]
#[inline]
#[must_use]
pub(crate) fn rfind(haystack: &[u8], needle: u8) -> Option<usize> {
    haystack.iter().rposition(|&b| b == needle)
}

/// (Possibly) faster version of `haystack.rfind(needle)` when `needle` is an ASCII character.
#[cfg(feature = "memchr")]
#[inline]
#[must_use]
pub(crate) fn rfind(haystack: &[u8], needle: u8) -> Option<usize> {
    memchr::memrchr(needle, haystack)
}

/// Finds the first needle, and returns the string before it and the rest.
///
/// If `needle` is not found, returns `None`.
#[cfg(not(feature = "memchr"))]
#[must_use]
pub(crate) fn find_split(haystack: &str, needle: u8) -> Option<(&str, &str)> {
    haystack
        .bytes()
        .position(|b| b == needle)
        .map(|pos| haystack.split_at(pos))
}

/// Finds the first needle, and returns the string before it and the rest.
///
/// If `needle` is not found, returns `None`.
#[cfg(feature = "memchr")]
#[must_use]
pub(crate) fn find_split(haystack: &str, needle: u8) -> Option<(&str, &str)> {
    memchr::memchr(needle, haystack.as_bytes()).map(|pos| haystack.split_at(pos))
}

/// Finds the last needle, and returns the string before it and the rest.
///
/// If no needles are found, returns `None`.
#[cfg(not(feature = "memchr"))]
#[must_use]
pub(crate) fn rfind_split2(haystack: &str, needle1: u8, needle2: u8) -> Option<(&str, &str)> {
    haystack
        .bytes()
        .rposition(|b| b == needle1 || b == needle2)
        .map(|pos| haystack.split_at(pos))
}

/// Finds the last needle, and returns the string before it and the rest.
///
/// If no needles are found, returns `None`.
#[cfg(feature = "memchr")]
#[must_use]
pub(crate) fn rfind_split2(haystack: &str, needle1: u8, needle2: u8) -> Option<(&str, &str)> {
    memchr::memrchr2(needle1, needle2, haystack.as_bytes()).map(|pos| haystack.split_at(pos))
}

/// Finds the first needle, and returns the string before it and the rest.
///
/// If no needles are found, returns `None`.
#[cfg(not(feature = "memchr"))]
#[must_use]
pub(crate) fn find_split2(haystack: &str, needle1: u8, needle2: u8) -> Option<(&str, &str)> {
    haystack
        .bytes()
        .position(|b| b == needle1 || b == needle2)
        .map(|pos| haystack.split_at(pos))
}

/// Finds the first needle, and returns the string before it and the rest.
///
/// If no needles are found, returns `None`.
#[cfg(feature = "memchr")]
#[must_use]
pub(crate) fn find_split2(haystack: &str, needle1: u8, needle2: u8) -> Option<(&str, &str)> {
    memchr::memchr2(needle1, needle2, haystack.as_bytes()).map(|pos| haystack.split_at(pos))
}

/// Finds the first needle, and returns the string before it and the rest.
///
/// If no needles are found, returns `None`.
#[cfg(not(feature = "memchr"))]
#[must_use]
pub(crate) fn find_split3(
    haystack: &str,
    needle1: u8,
    needle2: u8,
    needle3: u8,
) -> Option<(&str, &str)> {
    haystack
        .bytes()
        .position(|b| b == needle1 || b == needle2 || b == needle3)
        .map(|pos| haystack.split_at(pos))
}

/// Finds the first needle, and returns the string before it and the rest.
///
/// If no needles are found, returns `None`.
#[cfg(feature = "memchr")]
#[must_use]
pub(crate) fn find_split3(
    haystack: &str,
    needle1: u8,
    needle2: u8,
    needle3: u8,
) -> Option<(&str, &str)> {
    memchr::memchr3(needle1, needle2, needle3, haystack.as_bytes())
        .map(|pos| haystack.split_at(pos))
}

/// Finds the first needle, and returns the string before it and after it.
///
/// If `needle` is not found, returns `None`.
#[cfg(not(feature = "memchr"))]
#[must_use]
pub(crate) fn find_split_hole<T>(haystack: &T, needle: u8) -> Option<(&T, &T)>
where
    T: ?Sized
        + AsRef<[u8]>
        + ops::Index<RangeFrom<usize>, Output = T>
        + ops::Index<RangeTo<usize>, Output = T>,
{
    haystack
        .as_ref()
        .iter()
        .position(|&b| b == needle)
        .map(|pos| (&haystack[..pos], &haystack[(pos + 1)..]))
}

/// Finds the first needle, and returns the string before it and after it.
///
/// If `needle` is not found, returns `None`.
#[cfg(feature = "memchr")]
#[must_use]
pub(crate) fn find_split_hole<T>(haystack: &T, needle: u8) -> Option<(&T, &T)>
where
    T: ?Sized
        + AsRef<[u8]>
        + ops::Index<RangeFrom<usize>, Output = T>
        + ops::Index<RangeTo<usize>, Output = T>,
{
    memchr::memchr(needle, haystack.as_ref()).map(|pos| (&haystack[..pos], &haystack[(pos + 1)..]))
}

/// Finds the first needle, and returns the string before it, the needle, and the string after it.
///
/// If no needles are found, returns `None`.
#[cfg(not(feature = "memchr"))]
#[must_use]
pub(crate) fn find_split2_hole(
    haystack: &str,
    needle1: u8,
    needle2: u8,
) -> Option<(&str, u8, &str)> {
    haystack
        .bytes()
        .position(|b| b == needle1 || b == needle2)
        .map(|pos| {
            (
                &haystack[..pos],
                haystack.as_bytes()[pos],
                &haystack[(pos + 1)..],
            )
        })
}

/// Finds the first needle, and returns the string before it, the needle, and the string after it.
///
/// If no needles are found, returns `None`.
#[cfg(feature = "memchr")]
#[must_use]
pub(crate) fn find_split2_hole(
    haystack: &str,
    needle1: u8,
    needle2: u8,
) -> Option<(&str, u8, &str)> {
    memchr::memchr2(needle1, needle2, haystack.as_bytes()).map(|pos| {
        (
            &haystack[..pos],
            haystack.as_bytes()[pos],
            &haystack[(pos + 1)..],
        )
    })
}

/// Finds the first needle, and returns the string before it, the needle, and the string after it.
///
/// If no needles are found, returns `None`.
#[cfg(not(feature = "memchr"))]
#[must_use]
pub(crate) fn find_split4_hole(
    haystack: &str,
    needle1: u8,
    needle2: u8,
    needle3: u8,
    needle4: u8,
) -> Option<(&str, u8, &str)> {
    haystack
        .bytes()
        .position(|b| b == needle1 || b == needle2 || b == needle3 || b == needle4)
        .map(|pos| {
            (
                &haystack[..pos],
                haystack.as_bytes()[pos],
                &haystack[(pos + 1)..],
            )
        })
}

/// Finds the first needle, and returns the string before it, the needle, and the string after it.
///
/// If no needles are found, returns `None`.
#[cfg(feature = "memchr")]
#[must_use]
pub(crate) fn find_split4_hole(
    haystack: &str,
    needle1: u8,
    needle2: u8,
    needle3: u8,
    needle4: u8,
) -> Option<(&str, u8, &str)> {
    let bytes = haystack.as_bytes();
    let pos = match memchr::memchr3(needle1, needle2, needle3, bytes) {
        Some(prefix_len) => memchr::memchr(needle4, &bytes[..prefix_len]).or(Some(prefix_len)),
        None => memchr::memchr(needle4, bytes),
    };
    pos.map(|pos| {
        (
            &haystack[..pos],
            haystack.as_bytes()[pos],
            &haystack[(pos + 1)..],
        )
    })
}

/// Finds the last needle, and returns the string before it and after it.
///
/// If `needle` is not found, returns `None`.
#[cfg(not(feature = "memchr"))]
#[must_use]
pub(crate) fn rfind_split_hole(haystack: &str, needle: u8) -> Option<(&str, &str)> {
    haystack
        .bytes()
        .rposition(|b| b == needle)
        .map(|pos| (&haystack[..pos], &haystack[(pos + 1)..]))
}

/// Finds the last needle, and returns the string before it and after it.
///
/// If `needle` is not found, returns `None`.
#[cfg(feature = "memchr")]
#[must_use]
pub(crate) fn rfind_split_hole(haystack: &str, needle: u8) -> Option<(&str, &str)> {
    memchr::memrchr(needle, haystack.as_bytes())
        .map(|pos| (&haystack[..pos], &haystack[(pos + 1)..]))
}

/// Returns `true` if the string only contains the allowed characters and percent-encoded char.
#[must_use]
pub(crate) fn satisfy_chars_with_pct_encoded<F, G>(s: &str, pred_ascii: F, pred_nonascii: G) -> bool
where
    F: Copy + Fn(u8) -> bool,
    G: Copy + Fn(char) -> bool,
{
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c.is_ascii() {
            if c == '%' {
                // Percent-encoded triplet.
                // TODO: `Option::is_none_or` is available since Rust 1.82.0.
                if chars.next().filter(|c| c.is_ascii_hexdigit()).is_none() {
                    // Upper nibble.
                    return false;
                }
                if chars.next().filter(|c| c.is_ascii_hexdigit()).is_none() {
                    // Lower nibble.
                    return false;
                }
            } else if !pred_ascii(c as u8) {
                // Unacceptable ASCII char.
                return false;
            }
        } else if !pred_nonascii(c) {
            // Unacceptable non-ASCII char.
            return false;
        }
    }

    true
}

/// Returns `true` if the given string starts with two hexadecimal digits.
#[must_use]
pub(crate) fn starts_with_double_hexdigits(s: &[u8]) -> bool {
    match s {
        [x, y] | [x, y, ..] => x.is_ascii_hexdigit() && y.is_ascii_hexdigit(),
        _ => false,
    }
}

/// Decodes the starting two hexdigits if available, and returns the byte and the rest.
#[must_use]
pub(crate) fn strip_decode_xdigits2<T>(s: &T) -> (Option<u8>, &T)
where
    T: ?Sized + AsRef<[u8]> + ops::Index<RangeFrom<usize>, Output = T>,
{
    if starts_with_double_hexdigits(s.as_ref()) {
        let (decoded, rest) = trusted_parser::take_xdigits2(s);
        (Some(decoded), rest)
    } else {
        (None, s)
    }
}

/// Strips the first character if it is the given ASCII character, and returns the rest.
///
/// # Precondition
///
/// The given ASCII character (`prefix`) should be an ASCII character.
#[must_use]
pub(crate) fn strip_ascii_char_prefix(s: &str, prefix: u8) -> Option<&str> {
    debug_assert!(prefix.is_ascii());
    if s.as_bytes().first().copied() == Some(prefix) {
        Some(&s[1..])
    } else {
        None
    }
}

/// Splits the given string into the first character and the rest.
///
/// Returns `(first_char, rest_str)`.
#[must_use]
pub(crate) fn take_first_char(s: &str) -> Option<(char, &str)> {
    let mut chars = s.chars();
    let c = chars.next()?;
    let rest = chars.as_str();
    Some((c, rest))
}
