//! Decoders for percent-encoding.

use core::fmt;

#[cfg(feature = "alloc")]
use alloc::borrow::Cow;
#[cfg(feature = "alloc")]
use alloc::string::{FromUtf8Error, String};

use crate::parser::str::strip_decode_xdigits2;

/// Returns the result of [`percent-decode`] algorithm in the WHATWG URL Standard.
///
/// [`percent-decode`]: https://url.spec.whatwg.org/#percent-decode
///
/// # Examples
///
/// ```
/// use iri_string::percent_encode::decode::decode_whatwg_bytes;
///
/// let decoded = decode_whatwg_bytes(b"hello%20world");
///
/// assert_eq!(decoded.not_yet_decoded(), &b"hello%20world"[..]);
///
/// // This requires `alloc` feature since
/// // `into_bytes()` returns `Cow<'_, [u8]>`.
/// # #[cfg(feature = "alloc")]
/// assert_eq!(decoded.into_bytes(), &b"hello world"[..]);
/// ```
#[inline]
#[must_use]
pub fn decode_whatwg_bytes(bytes: &[u8]) -> PercentDecodedWhatwgBytes<'_> {
    PercentDecodedWhatwgBytes::from_raw(bytes)
}

/// A percent-decoded string based on [`percent-decode`] algorithm of the WHATWG URL standard.
///
/// Note that this type does not guarantee that the string is valid
/// percent-encoded string. The raw string may have stray percent character or
/// the following digits may be invalid as hexadecimal digits.
///
/// Note that comparisons and hashing via std traits (such as `Eq` and `Hash`)
/// will use the raw value, not the content after decoding.
///
/// [`percent-decode`]: https://url.spec.whatwg.org/#percent-decode
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PercentDecodedWhatwgBytes<'a> {
    /// Not-yet-decoded string.
    not_yet_decoded: &'a [u8],
}

impl<'a> PercentDecodedWhatwgBytes<'a> {
    /// Creates a `PercentDecodedWhatwgBytes` from the possibly non-decoded raw bytes.
    #[inline]
    #[must_use]
    fn from_raw(not_yet_decoded: &'a [u8]) -> Self {
        Self { not_yet_decoded }
    }

    /// Returns the not-yet-decoded input bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use iri_string::percent_encode::decode::decode_whatwg_bytes;
    ///
    /// let decoded = decode_whatwg_bytes(b"hello%20world");
    ///
    /// assert_eq!(decoded.not_yet_decoded(), &b"hello%20world"[..]);
    /// ```
    #[inline]
    #[must_use]
    pub fn not_yet_decoded(&self) -> &'a [u8] {
        self.not_yet_decoded
    }

    /// Decodes the bytes as much as possible.
    ///
    /// If the string contains a decodable percent-encoded triplet, returns
    /// a tuple of:
    ///
    /// 1. the length of the prefix that contains no percent-encoded triplets,
    /// 1. the first decoded byte, and
    /// 1. the suffix after the decoded percent-encoded triplet.
    #[must_use]
    fn try_non_allocating_decode(&self) -> Option<(usize, u8, &'a [u8])> {
        let mut len_before_pct;
        let mut rest = self.not_yet_decoded;

        while !rest.is_empty() {
            #[cfg(feature = "memchr")]
            let pct_pos = memchr::memchr(b'%', rest);
            #[cfg(not(feature = "memchr"))]
            let pct_pos = rest.iter().position(|&b| b == b'%');

            let after_pct;
            (len_before_pct, after_pct) = match pct_pos {
                None => return None,
                Some(pos) => (pos, &rest[(pos + 1)..]),
            };

            let decoded;
            (decoded, rest) = strip_decode_xdigits2(after_pct);
            if let Some(decoded) = decoded {
                return Some((len_before_pct, decoded, rest));
            }
            rest = after_pct;
        }

        None
    }

    /// Returns the decoded bytes as a slice if no memory allocation is needed.
    ///
    /// # Examples
    ///
    /// ```
    /// use iri_string::percent_encode::decode::decode_whatwg_bytes;
    ///
    /// let no_alloc = decode_whatwg_bytes(b"99% unsafe");
    /// assert_eq!(no_alloc.to_bytes(), Some(&b"99% unsafe"[..]));
    ///
    /// let alloc_needed = decode_whatwg_bytes(b"hello%20world");
    /// assert_eq!(alloc_needed.to_bytes(), None);
    /// ```
    #[inline]
    #[must_use]
    pub fn to_bytes(&self) -> Option<&'a [u8]> {
        match self.try_non_allocating_decode() {
            None => Some(self.not_yet_decoded),
            _ => None,
        }
    }

    /// Decodes the bytes, based on [`percent-decode`] algorithm of the WHATWG URL standard.
    ///
    /// # Examples
    ///
    /// ```
    /// use iri_string::percent_encode::decode::decode_whatwg_bytes;
    ///
    /// let decoded = decode_whatwg_bytes(b"hello%20world");
    /// assert_eq!(decoded.into_bytes(), &b"hello world"[..]);
    /// ```
    ///
    /// [`percent-decode`]: https://url.spec.whatwg.org/#percent-decode
    #[cfg(feature = "alloc")]
    #[inline]
    #[must_use]
    pub fn into_bytes(&self) -> Cow<'a, [u8]> {
        use crate::parser::str::find_split_hole;

        let (mut result, mut rest) = match self.try_non_allocating_decode() {
            Some((prefix_len, decoded, rest)) => {
                let mut prefix = alloc::vec::Vec::from(&self.not_yet_decoded[..prefix_len]);
                prefix.push(decoded);
                (prefix, rest)
            }
            None => return Cow::Borrowed(self.not_yet_decoded),
        };

        while !rest.is_empty() {
            let after_pct = if let Some((no_pct, after_pct)) = find_split_hole(rest, b'%') {
                result.extend(no_pct);
                after_pct
            } else {
                result.extend(core::mem::take(&mut rest));
                break;
            };

            let decoded;
            (decoded, rest) = strip_decode_xdigits2(after_pct);
            result.extend(decoded);
        }

        Cow::Owned(result)
    }

    /// Decodes the bytes into a string, based on [`percent-decode`] algorithm
    /// of the WHATWG URL standard.
    ///
    /// # Examples
    ///
    /// ```
    /// use iri_string::percent_encode::decode::decode_whatwg_bytes;
    ///
    /// let decoded = decode_whatwg_bytes(b"hello%20world");
    /// assert_eq!(
    ///     decoded.into_string(),
    ///     Ok("hello world".to_owned())
    /// );
    /// ```
    ///
    /// [`percent-decode`]: https://url.spec.whatwg.org/#percent-decode
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn into_string(&self) -> Result<String, FromUtf8Error> {
        String::from_utf8(self.into_bytes().into_owned())
    }

    /// Returns an iterator of decoded fragments.
    ///
    /// # Examples
    ///
    /// ```
    /// use iri_string::percent_encode::decode::{
    ///     decode_whatwg_bytes, DecodedFragment,
    /// };
    ///
    /// let mut i = decode_whatwg_bytes(b"100% hello%20world")
    ///     .bytes_fragments();
    ///
    /// assert_eq!(i.next(), Some(DecodedFragment::Direct(b"100")));
    /// assert_eq!(i.next(), Some(DecodedFragment::StrayPercent));
    /// assert_eq!(i.next(), Some(DecodedFragment::Direct(b" hello")));
    /// assert_eq!(i.next(), Some(DecodedFragment::DecodedByte(b' ')));
    /// assert_eq!(i.next(), Some(DecodedFragment::Direct(b"world")));
    /// assert_eq!(i.next(), None);
    /// ```
    #[inline]
    #[must_use]
    pub fn bytes_fragments(&self) -> PercentDecodedBytesFragments<'a> {
        PercentDecodedBytesFragments {
            rest: self.not_yet_decoded,
        }
    }
}

impl fmt::Debug for PercentDecodedWhatwgBytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_struct("PercentDecodedWhatwgBytes");
        // Print as a string if possible.
        match core::str::from_utf8(self.not_yet_decoded) {
            Ok(s) => f.field("not_yet_decoded", &s),
            Err(_) => f.field("not_yet_decoded", &self.not_yet_decoded),
        };
        f.finish()
    }
}

/// Fragments in a percent-decodable byte sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecodedFragment<'a> {
    /// Bytes without percent characters nor percent-encoded triplets.
    Direct(&'a [u8]),
    /// A decoded byte from a percent-encoded triplet.
    DecodedByte(u8),
    /// A percent character that does not form a valid percent-encoded triplet.
    StrayPercent,
}

/// An iterator of fragments in a percent-decodable byte sequence.
//
// NOTE: Do not implement `Copy` since an iterator type with `Copy` is a foot-gun.
#[derive(Clone)]
pub struct PercentDecodedBytesFragments<'a> {
    /// Remaining string to decode.
    rest: &'a [u8],
}

impl fmt::Debug for PercentDecodedBytesFragments<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_struct("PercentDecodedBytesFragments");
        // Print as a string if possible.
        match core::str::from_utf8(self.rest) {
            Ok(s) => f.field("rest", &s),
            Err(_) => f.field("rest", &self.rest),
        };
        f.finish()
    }
}

impl<'a> PercentDecodedBytesFragments<'a> {
    /// Returns the remaining not-yet-decoded bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use iri_string::percent_encode::decode::{
    ///     decode_whatwg_bytes, DecodedFragment,
    /// };
    ///
    /// let mut i = decode_whatwg_bytes(b"hello%20world")
    ///     .bytes_fragments();
    ///
    /// assert_eq!(i.next(), Some(DecodedFragment::Direct(b"hello")));
    /// assert_eq!(i.not_yet_decoded(), &b"%20world"[..]);
    /// ```
    #[inline]
    #[must_use]
    pub fn not_yet_decoded(&self) -> &'a [u8] {
        self.rest
    }
}

impl<'a> Iterator for PercentDecodedBytesFragments<'a> {
    type Item = DecodedFragment<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut rest = self.rest;

        match rest {
            [] => None,
            [b'%', after_pct @ ..] => {
                let decoded;
                (decoded, rest) = strip_decode_xdigits2(after_pct);
                if let Some(decoded) = decoded {
                    self.rest = rest;
                    Some(DecodedFragment::DecodedByte(decoded))
                } else {
                    self.rest = after_pct;
                    Some(DecodedFragment::StrayPercent)
                }
            }
            [_, after_first @ ..] => {
                #[cfg(feature = "memchr")]
                let pct_pos_minus_one = memchr::memchr(b'%', after_first);
                #[cfg(not(feature = "memchr"))]
                let pct_pos_minus_one = after_first.iter().position(|&b| b == b'%');

                let before_pct;
                (before_pct, self.rest) = match pct_pos_minus_one {
                    None => (rest, &rest[rest.len()..]),
                    Some(pct_pos_minus_one) => rest.split_at(pct_pos_minus_one + 1),
                };
                Some(DecodedFragment::Direct(before_pct))
            }
        }
    }
}
