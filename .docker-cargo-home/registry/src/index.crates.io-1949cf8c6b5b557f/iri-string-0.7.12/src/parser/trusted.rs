//! Fast parsers for trusted (already validated) input.
//!
//! Using this in wrong way will lead to unexpected wrong result.

pub(crate) mod authority;

use core::num::NonZeroUsize;
use core::ops::{self, RangeFrom};

use crate::components::{RiReferenceComponents, Splitter};
use crate::format::eq_str_display;
use crate::normalize::{is_pct_case_normalized, NormalizedAsciiOnlyHost, NormalizednessCheckMode};
use crate::parser::str::{find_split2, find_split3, find_split4_hole, find_split_hole};
use crate::spec::Spec;
use crate::types::RiReferenceStr;

/// Eats a `scheme` and a following colon, and returns the rest and the scheme.
///
/// Returns `(rest, scheme)`.
///
/// This should be called at the head of an absolute IRIs/URIs.
#[must_use]
fn scheme_colon(i: &str) -> (&str, &str) {
    let (scheme, rest) =
        find_split_hole(i, b':').expect("[precondition] absolute IRIs must have `scheme` part");
    (rest, scheme)
}

/// Eats a `scheme` and a following colon if available, and returns the rest and the scheme.
///
/// This should be called at the head of an `IRI-reference` or similar.
#[must_use]
fn scheme_colon_opt(i: &str) -> (&str, Option<&str>) {
    match find_split4_hole(i, b':', b'/', b'?', b'#') {
        Some((scheme, b':', rest)) => (rest, Some(scheme)),
        _ => (i, None),
    }
}

/// Eats double slash and the following authority if available, and returns the authority.
///
/// This should be called at the head of an `IRI-reference`, or at the result of `scheme_colon`.
#[must_use]
fn slash_slash_authority_opt(i: &str) -> (&str, Option<&str>) {
    let s = match i.strip_prefix("//") {
        Some(rest) => rest,
        None => return (i, None),
    };
    // `i` might match `path-abempty` (which can start with `//`), but it is not
    // allowed as `relative-part`, so no need to care `path-abempty` rule here.
    // A slash, question mark, and hash character won't appear in `authority`.
    match find_split3(s, b'/', b'?', b'#') {
        Some((authority, rest)) => (rest, Some(authority)),
        None => ("", Some(s)),
    }
}

/// Eats a string until the query, and returns that part (excluding `?` for the query).
#[must_use]
fn until_query(i: &str) -> (&str, &str) {
    // `?` won't appear before the query part.
    match find_split2(i, b'?', b'#') {
        Some((before_query, rest)) => (rest, before_query),
        None => ("", i),
    }
}

/// Decomposes query and fragment, if available.
///
/// The string must starts with `?`, or `#`, or be empty.
#[must_use]
fn decompose_query_and_fragment(i: &str) -> (Option<&str>, Option<&str>) {
    match i.as_bytes().first().copied() {
        None => (None, None),
        Some(b'?') => {
            let rest = &i[1..];
            match find_split_hole(rest, b'#') {
                Some((query, fragment)) => (Some(query), Some(fragment)),
                None => (Some(rest), None),
            }
        }
        Some(c) => {
            debug_assert_eq!(c, b'#');
            (None, Some(&i[1..]))
        }
    }
}

/// Decomposes the given valid `IRI-reference`.
#[must_use]
pub(crate) fn decompose_iri_reference<S: Spec>(
    i: &RiReferenceStr<S>,
) -> RiReferenceComponents<'_, S> {
    /// Inner function to avoid unnecessary monomorphizations on `S`.
    fn decompose(i: &str) -> Splitter {
        let len = i.len();

        let (i, scheme_end) = {
            let (i, scheme) = scheme_colon_opt(i);
            let end = scheme.and_then(|s| NonZeroUsize::new(s.len()));
            (i, end)
        };
        let (i, authority_end) = {
            // 2: "//".len()
            let start = len - i.len() + 2;
            // `authority` does not contain the two slashes of `://'.
            let (i, authority) = slash_slash_authority_opt(i);
            let end = authority.and_then(|s| NonZeroUsize::new(start + s.len()));
            (i, end)
        };
        let (i, _path) = until_query(i);

        let (query_start, fragment_start) = {
            // This could theoretically be zero if `len` is `usize::MAX` and
            // `i` has neither a query nor a fragment. However, this is
            // practically impossible.
            let after_first_prefix = NonZeroUsize::new((len - i.len()).wrapping_add(1));

            let (query, fragment) = decompose_query_and_fragment(i);
            match (query.is_some(), fragment) {
                (true, Some(fragment)) => {
                    (after_first_prefix, NonZeroUsize::new(len - fragment.len()))
                }
                (true, None) => (after_first_prefix, None),
                (false, Some(_fragment)) => (None, after_first_prefix),
                (false, None) => (None, None),
            }
        };

        Splitter::new(scheme_end, authority_end, query_start, fragment_start)
    }

    RiReferenceComponents {
        iri: i,
        splitter: decompose(i.as_str()),
    }
}

/// Extracts `scheme` part from an IRI reference.
///
/// # Precondition
///
/// The given string must be a valid IRI reference.
#[inline]
#[must_use]
pub(crate) fn extract_scheme(i: &str) -> Option<&str> {
    scheme_colon_opt(i).1
}

/// Extracts `scheme` part from an absolute IRI.
///
/// # Precondition
///
/// The given string must be a valid absolute IRI.
#[inline]
#[must_use]
pub(crate) fn extract_scheme_absolute(i: &str) -> &str {
    scheme_colon(i).1
}

/// Extracts `authority` part from an IRI reference.
///
/// # Precondition
///
/// The given string must be a valid IRI reference.
#[inline]
#[must_use]
pub(crate) fn extract_authority(i: &str) -> Option<&str> {
    let (i, _scheme) = scheme_colon_opt(i);
    slash_slash_authority_opt(i).1
}

/// Extracts `authority` part from an absolute IRI.
///
/// # Precondition
///
/// The given string must be a valid absolute IRI.
#[inline]
#[must_use]
pub(crate) fn extract_authority_absolute(i: &str) -> Option<&str> {
    let (i, _scheme) = scheme_colon(i);
    slash_slash_authority_opt(i).1
}

/// Extracts `authority` part from a relative IRI.
///
/// # Precondition
///
/// The given string must be a valid relative IRI.
#[inline]
#[must_use]
pub(crate) fn extract_authority_relative(i: &str) -> Option<&str> {
    slash_slash_authority_opt(i).1
}

/// Extracts `authority` part and its position from an IRI reference.
///
/// # Precondition
///
/// The given string must be a valid IRI reference.
#[cfg(feature = "alloc")]
#[must_use]
pub(crate) fn extract_authority_and_offset(i: &str) -> Option<(&str, usize)> {
    let (i, scheme) = scheme_colon_opt(i);
    let authority = slash_slash_authority_opt(i).1?;
    // 2: `"//".len()`
    // +3: `"://".len()`
    let offset = scheme.map_or(2, |s| s.len() + 3);
    Some((authority, offset))
}

/// Extracts `path` part from an IRI reference.
///
/// # Precondition
///
/// The given string must be a valid IRI reference.
#[inline]
#[must_use]
pub(crate) fn extract_path(i: &str) -> &str {
    let (i, _scheme) = scheme_colon_opt(i);
    let (i, _authority) = slash_slash_authority_opt(i);
    until_query(i).1
}

/// Extracts `path` part from an absolute IRI.
///
/// # Precondition
///
/// The given string must be a valid absolute IRI.
#[inline]
#[must_use]
pub(crate) fn extract_path_absolute(i: &str) -> &str {
    let (i, _scheme) = scheme_colon(i);
    let (i, _authority) = slash_slash_authority_opt(i);
    until_query(i).1
}

/// Extracts `path` part from a relative IRI.
///
/// # Precondition
///
/// The given string must be a valid relative IRI.
#[inline]
#[must_use]
pub(crate) fn extract_path_relative(i: &str) -> &str {
    let (i, _authority) = slash_slash_authority_opt(i);
    until_query(i).1
}

/// Extracts `query` part from an IRI reference.
///
/// # Precondition
///
/// The given string must be a valid IRI reference.
#[inline]
#[must_use]
pub(crate) fn extract_query(i: &str) -> Option<&str> {
    let (i, _before_query) = until_query(i);
    decompose_query_and_fragment(i).0
}

/// Extracts `query` part from an `absolute-IRI` string.
///
/// # Precondition
///
/// The given string must be a valid `absolute-IRI` string.
#[must_use]
pub(crate) fn extract_query_absolute_iri(i: &str) -> Option<&str> {
    let (i, _before_query) = until_query(i);
    if i.is_empty() {
        None
    } else {
        debug_assert_eq!(
            i.as_bytes().first(),
            Some(&b'?'),
            "`absolute-IRI` string must not have `fragment part"
        );
        Some(&i[1..])
    }
}

/// Splits an IRI string into the prefix and the fragment part.
///
/// A leading `#` character is truncated if the fragment part exists.
///
/// # Precondition
///
/// The given string must be a valid IRI reference.
#[inline]
#[must_use]
pub(crate) fn split_fragment(iri: &str) -> (&str, Option<&str>) {
    // It is completely OK to find the first `#` character from valid IRI to get fragment part,
    // because the spec says that there are no `#` characters before the fragment part.
    //
    // > ```
    // > scheme      = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
    // > ```
    // >
    // > --- [RFC 3986, section 3.1. Scheme](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.1)
    //
    // > The authority component is preceded by a double slash ("//") and is terminated by the
    // > next slash ("/"), question mark ("?"), or number sign ("#") character, or by the end
    // > of the URI.
    // >
    // > --- [RFC 3986, section 3.2. Authority](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2)
    //
    // > The path is terminated by the first question mark ("?") or number sign ("#")
    // > character, or by the end of the URI.
    // >
    // > --- [RFC 3986, section 3.3. Path](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.3)
    //
    // > The query component is indicated by the first question mark ("?") character and
    // > terminated by a number sign ("#") character or by the end of the URI.
    // >
    // > --- [RFC 3986, section 3.4. Query](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.4)
    match find_split_hole(iri, b'#') {
        Some((prefix, fragment)) => (prefix, Some(fragment)),
        None => (iri, None),
    }
}

/// Returns the fragment part of the given IRI.
///
/// A leading `#` character of the fragment is truncated.
#[inline]
#[must_use]
pub(crate) fn extract_fragment(iri: &str) -> Option<&str> {
    split_fragment(iri).1
}

/// Returns `Ok(_)` if the string is normalized.
///
/// If this function returns `true`, normalization input and output will be identical.
///
/// In this function, "normalized" means that any of the normalization below
/// won't change the input on normalization:
///
/// * syntax-based normalization,
/// * case normalization,
/// * percent-encoding normalization, and
/// * path segment normalizaiton.
///
/// Note that scheme-based normalization is not considered.
#[must_use]
pub(crate) fn is_normalized<S: Spec>(i: &str, mode: NormalizednessCheckMode) -> bool {
    let (i, scheme) = scheme_colon(i);
    let (after_authority, authority) = slash_slash_authority_opt(i);
    let (_after_path, path) = until_query(after_authority);

    // Syntax-based normalization: uppercase chars in `scheme` should be
    // converted to lowercase.
    if scheme.bytes().any(|b| b.is_ascii_uppercase()) {
        return false;
    }

    // Case normalization: ASCII alphabets in US-ASCII only `host` should be
    // normalized to lowercase.
    // Case normalization: ASCII alphabets in percent-encoding triplet should be
    // normalized to uppercase.
    // Percent-encoding normalization: unresreved characters should be decoded
    // in `userinfo`, `host`, `path`, `query`, and `fragments`.
    // Path segment normalization: the path should not have dot segments (`.`
    // and/or `..`).
    //
    // Note that `authority` can have percent-encoded `userinfo`.
    if let Some(authority) = authority {
        let authority_components = authority::decompose_authority(authority);

        // Check `host`.
        let host = authority_components.host();
        let host_is_normalized = if is_ascii_only_host(host) {
            eq_str_display(host, &NormalizedAsciiOnlyHost::new(host))
        } else {
            // If the host is not ASCII-only, conversion to lowercase is not performed.
            is_pct_case_normalized::<S>(host)
        };
        if !host_is_normalized {
            return false;
        }

        // Check pencent encodings in `userinfo`.
        if let Some(userinfo) = authority_components.userinfo() {
            if !is_pct_case_normalized::<S>(userinfo) {
                return false;
            }
        }
    }

    // Check `path`.
    //
    // Syntax-based normalization: Dot segments might be removed.
    // Note that we don't have to care `%2e` and `%2E` since `.` is unreserved
    // and they will be decoded if not normalized.
    // Also note that WHATWG serialization will use `/.//` as a path prefix if
    // the path is absolute and won't modify the path if the path is relative.
    //
    // Percent-encoding normalization: unresreved characters should be decoded
    // in `path`, `query`, and `fragments`.
    let path_span_no_dot_segments = if authority.is_some() {
        Some(path)
    } else {
        match mode {
            NormalizednessCheckMode::Default => Some(path.strip_prefix("/.//").unwrap_or(path)),
            NormalizednessCheckMode::Rfc3986 => Some(path),
            NormalizednessCheckMode::PreserveAuthoritylessRelativePath => {
                if path.starts_with('/') {
                    // Absolute.
                    Some(path.strip_prefix("/.//").unwrap_or(path))
                } else {
                    // Relative. Treat the path as "opaque". No span to check.
                    None
                }
            }
        }
    };
    if let Some(path_span_no_dot_segments) = path_span_no_dot_segments {
        if path_span_no_dot_segments
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
        {
            return false;
        }
    }
    is_pct_case_normalized::<S>(after_authority)
}

/// Decodes two hexdigits into a byte.
///
/// # Preconditions
///
/// The parameters `upper` and `lower` should be an ASCII hexadecimal digit.
#[must_use]
pub(crate) fn hexdigits_to_byte([upper, lower]: [u8; 2]) -> u8 {
    // 'A'..='F' (0x41..=0x46) | 'a'..='f' (0x61..=0x66) => add 9 to the nibble.
    // '0'..='9' (0x30..=0x39) => use the nibble as is.
    let upper_offset = if upper >= 0x40 { 9 << 4 } else { 0 };
    let lower_offset = if lower >= 0x40 { 9 } else { 0 };
    (upper << 4) + upper_offset + (lower & 0x0f) + lower_offset
}

/// Converts the first two hexdigit bytes in the buffer into a byte.
///
/// # Panics
///
/// Panics if the string does not start with two hexdigits.
#[must_use]
pub(crate) fn take_xdigits2<T>(s: &T) -> (u8, &T)
where
    T: ?Sized + AsRef<[u8]> + ops::Index<RangeFrom<usize>, Output = T>,
{
    let (upper_xdigit, lower_xdigit) = match s.as_ref() {
        [upper, lower, ..] => (*upper, *lower),
        _ => panic!("at least two bytes should follow the `%` in a valid IRI reference"),
    };
    let v = hexdigits_to_byte([upper_xdigit, lower_xdigit]);
    (v, &s[2..])
}

/// Returns true if the given `host`/`ihost` string consists of only US-ASCII characters.
///
/// # Precondition
///
/// The given string should be valid `host` or `host ":" port` string.
#[must_use]
pub(crate) fn is_ascii_only_host(mut host: &str) -> bool {
    while let Some(pos) = host.find(|c: char| !c.is_ascii() || c == '%') {
        if host.as_bytes()[pos] != b'%' {
            // Non-ASCII character found.
            return false;
        }
        let after_pct = &host[(pos + 1)..];
        let (byte, rest) = take_xdigits2(after_pct);
        if !byte.is_ascii() {
            return false;
        }
        host = rest;
    }

    // Neither non-ASCII characters nor percent-encoded characters found.
    true
}
