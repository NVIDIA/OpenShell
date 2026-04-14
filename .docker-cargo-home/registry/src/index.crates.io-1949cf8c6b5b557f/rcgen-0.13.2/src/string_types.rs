use std::{fmt, str::FromStr};

use crate::{Error, InvalidAsn1String};

/// ASN.1 `PrintableString` type.
///
/// Supports a subset of the ASCII printable characters (described below).
///
/// For the full ASCII character set, use
/// [`Ia5String`][`crate::Ia5String`].
///
/// # Examples
///
/// You can create a `PrintableString` from [a literal string][`&str`] with [`PrintableString::try_from`]:
///
/// ```
/// use rcgen::PrintableString;
/// let hello = PrintableString::try_from("hello").unwrap();
/// ```
///
/// # Supported characters
///
/// PrintableString is a subset of the [ASCII printable characters].
/// For instance, `'@'` is a printable character as per ASCII but can't be part of [ASN.1's `PrintableString`].
///
/// The following ASCII characters/ranges are supported:
///
/// - `A..Z`
/// - `a..z`
/// - `0..9`
/// - "` `" (i.e. space)
/// - `\`
/// - `(`
/// - `)`
/// - `+`
/// - `,`
/// - `-`
/// - `.`
/// - `/`
/// - `:`
/// - `=`
/// - `?`
///
/// [ASCII printable characters]: https://en.wikipedia.org/wiki/ASCII#Printable_characters
/// [ASN.1's `PrintableString`]: https://en.wikipedia.org/wiki/PrintableString
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct PrintableString(String);

impl PrintableString {
	/// Extracts a string slice containing the entire `PrintableString`.
	pub fn as_str(&self) -> &str {
		&self.0
	}
}

impl TryFrom<&str> for PrintableString {
	type Error = Error;

	/// Converts a `&str` to a [`PrintableString`].
	///
	/// Any character not in the [`PrintableString`] charset will be rejected.
	/// See [`PrintableString`] documentation for more information.
	///
	/// The result is allocated on the heap.
	fn try_from(input: &str) -> Result<Self, Error> {
		input.to_string().try_into()
	}
}

impl TryFrom<String> for PrintableString {
	type Error = Error;

	/// Converts a [`String`][`std::string::String`] into a [`PrintableString`]
	///
	/// Any character not in the [`PrintableString`] charset will be rejected.
	/// See [`PrintableString`] documentation for more information.
	///
	/// This conversion does not allocate or copy memory.
	fn try_from(value: String) -> Result<Self, Self::Error> {
		for &c in value.as_bytes() {
			match c {
				b'A'..=b'Z'
				| b'a'..=b'z'
				| b'0'..=b'9'
				| b' '
				| b'\''
				| b'('
				| b')'
				| b'+'
				| b','
				| b'-'
				| b'.'
				| b'/'
				| b':'
				| b'='
				| b'?' => (),
				_ => {
					return Err(Error::InvalidAsn1String(
						InvalidAsn1String::PrintableString(value),
					))
				},
			}
		}
		Ok(Self(value))
	}
}

impl FromStr for PrintableString {
	type Err = Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		s.try_into()
	}
}

impl AsRef<str> for PrintableString {
	fn as_ref(&self) -> &str {
		&self.0
	}
}

impl fmt::Display for PrintableString {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Display::fmt(self.as_str(), f)
	}
}

impl PartialEq<str> for PrintableString {
	fn eq(&self, other: &str) -> bool {
		self.as_str() == other
	}
}

impl PartialEq<String> for PrintableString {
	fn eq(&self, other: &String) -> bool {
		self.as_str() == other.as_str()
	}
}

impl PartialEq<&str> for PrintableString {
	fn eq(&self, other: &&str) -> bool {
		self.as_str() == *other
	}
}

impl PartialEq<&String> for PrintableString {
	fn eq(&self, other: &&String) -> bool {
		self.as_str() == other.as_str()
	}
}

/// ASN.1 `IA5String` type.
///
/// # Examples
///
/// You can create a `Ia5String` from [a literal string][`&str`] with [`Ia5String::try_from`]:
///
/// ```
/// use rcgen::Ia5String;
/// let hello = Ia5String::try_from("hello").unwrap();
/// ```
///
/// # Supported characters
///
/// Supports the [International Alphabet No. 5 (IA5)] character encoding, i.e.
/// the 128 characters of the ASCII alphabet. (Note: IA5 is now
/// technically known as the International Reference Alphabet or IRA as
/// specified in the ITU-T's T.50 recommendation).
///
/// For UTF-8, use [`String`][`std::string::String`].
///
/// [International Alphabet No. 5 (IA5)]: https://en.wikipedia.org/wiki/T.50_(standard)
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Ia5String(String);

impl Ia5String {
	/// Extracts a string slice containing the entire `Ia5String`.
	pub fn as_str(&self) -> &str {
		&self.0
	}
}

impl TryFrom<&str> for Ia5String {
	type Error = Error;

	/// Converts a `&str` to a [`Ia5String`].
	///
	/// Any character not in the [`Ia5String`] charset will be rejected.
	/// See [`Ia5String`] documentation for more information.
	///
	/// The result is allocated on the heap.
	fn try_from(input: &str) -> Result<Self, Error> {
		input.to_string().try_into()
	}
}

impl TryFrom<String> for Ia5String {
	type Error = Error;

	/// Converts a [`String`][`std::string::String`] into a [`Ia5String`]
	///
	/// Any character not in the [`Ia5String`] charset will be rejected.
	/// See [`Ia5String`] documentation for more information.
	fn try_from(input: String) -> Result<Self, Error> {
		if !input.is_ascii() {
			return Err(Error::InvalidAsn1String(InvalidAsn1String::Ia5String(
				input,
			)));
		}
		Ok(Self(input))
	}
}

impl FromStr for Ia5String {
	type Err = Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		s.try_into()
	}
}

impl AsRef<str> for Ia5String {
	fn as_ref(&self) -> &str {
		&self.0
	}
}

impl fmt::Display for Ia5String {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Display::fmt(self.as_str(), f)
	}
}

impl PartialEq<str> for Ia5String {
	fn eq(&self, other: &str) -> bool {
		self.as_str() == other
	}
}

impl PartialEq<String> for Ia5String {
	fn eq(&self, other: &String) -> bool {
		self.as_str() == other.as_str()
	}
}

impl PartialEq<&str> for Ia5String {
	fn eq(&self, other: &&str) -> bool {
		self.as_str() == *other
	}
}

impl PartialEq<&String> for Ia5String {
	fn eq(&self, other: &&String) -> bool {
		self.as_str() == other.as_str()
	}
}

/// ASN.1 `TeletexString` type.
///
/// # Examples
///
/// You can create a `TeletexString` from [a literal string][`&str`] with [`TeletexString::try_from`]:
///
/// ```
/// use rcgen::TeletexString;
/// let hello = TeletexString::try_from("hello").unwrap();
/// ```
///
/// # Supported characters
///
/// The standard defines a complex character set allowed in this type. However, quoting the ASN.1
/// [mailing list], "a sizable volume of software in the world treats TeletexString (T61String) as a
/// simple 8-bit string with mostly Windows Latin 1 (superset of iso-8859-1) encoding".
///
/// `TeletexString` is included for backward compatibility, [RFC 5280] say it
/// SHOULD NOT be used for certificates for new subjects.
///
/// [mailing list]: https://www.mail-archive.com/asn1@asn1.org/msg00460.html
/// [RFC 5280]: https://datatracker.ietf.org/doc/html/rfc5280#page-25
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct TeletexString(String);

impl TeletexString {
	/// Extracts a string slice containing the entire `TeletexString`.
	pub fn as_str(&self) -> &str {
		&self.0
	}

	/// Returns a byte slice of this `TeletexString`’s contents.
	pub fn as_bytes(&self) -> &[u8] {
		self.0.as_bytes()
	}
}

impl TryFrom<&str> for TeletexString {
	type Error = Error;

	/// Converts a `&str` to a [`TeletexString`].
	///
	/// Any character not in the [`TeletexString`] charset will be rejected.
	/// See [`TeletexString`] documentation for more information.
	///
	/// The result is allocated on the heap.
	fn try_from(input: &str) -> Result<Self, Error> {
		input.to_string().try_into()
	}
}

impl TryFrom<String> for TeletexString {
	type Error = Error;

	/// Converts a [`String`][`std::string::String`] into a [`TeletexString`]
	///
	/// Any character not in the [`TeletexString`] charset will be rejected.
	/// See [`TeletexString`] documentation for more information.
	///
	/// This conversion does not allocate or copy memory.
	fn try_from(input: String) -> Result<Self, Error> {
		// Check all bytes are visible
		if !input.as_bytes().iter().all(|b| (0x20..=0x7f).contains(b)) {
			return Err(Error::InvalidAsn1String(InvalidAsn1String::TeletexString(
				input,
			)));
		}
		Ok(Self(input))
	}
}

impl FromStr for TeletexString {
	type Err = Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		s.try_into()
	}
}

impl AsRef<str> for TeletexString {
	fn as_ref(&self) -> &str {
		&self.0
	}
}

impl fmt::Display for TeletexString {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Display::fmt(self.as_str(), f)
	}
}

impl PartialEq<str> for TeletexString {
	fn eq(&self, other: &str) -> bool {
		self.as_str() == other
	}
}

impl PartialEq<String> for TeletexString {
	fn eq(&self, other: &String) -> bool {
		self.as_str() == other.as_str()
	}
}

impl PartialEq<&str> for TeletexString {
	fn eq(&self, other: &&str) -> bool {
		self.as_str() == *other
	}
}

impl PartialEq<&String> for TeletexString {
	fn eq(&self, other: &&String) -> bool {
		self.as_str() == other.as_str()
	}
}

/// ASN.1 `BMPString` type.
///
/// # Examples
///
/// You can create a `BmpString` from [a literal string][`&str`] with [`BmpString::try_from`]:
///
/// ```
/// use rcgen::BmpString;
/// let hello = BmpString::try_from("hello").unwrap();
/// ```
///
/// # Supported characters
///
/// Encodes Basic Multilingual Plane (BMP) subset of Unicode (ISO 10646),
/// a.k.a. UCS-2.
///
/// Bytes are encoded as UTF-16 big-endian.
///
/// `BMPString` is included for backward compatibility, [RFC 5280] say it
/// SHOULD NOT be used for certificates for new subjects.
///
/// [RFC 5280]: https://datatracker.ietf.org/doc/html/rfc5280#page-25
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct BmpString(Vec<u8>);

impl BmpString {
	/// Returns a byte slice of this `BmpString`'s contents.
	///
	/// The inverse of this method is [`from_utf16be`].
	///
	/// [`from_utf16be`]: BmpString::from_utf16be
	///
	/// # Examples
	///
	/// ```
	/// use rcgen::BmpString;
	/// let s = BmpString::try_from("hello").unwrap();
	///
	/// assert_eq!(&[0, 104, 0, 101, 0, 108, 0, 108, 0, 111], s.as_bytes());
	/// ```
	pub fn as_bytes(&self) -> &[u8] {
		&self.0
	}

	/// Decode a UTF-16BE–encoded vector `vec` into a `BmpString`, returning [Err](`std::result::Result::Err`) if `vec` contains any invalid data.
	pub fn from_utf16be(vec: Vec<u8>) -> Result<Self, Error> {
		if vec.len() % 2 != 0 {
			return Err(Error::InvalidAsn1String(InvalidAsn1String::BmpString(
				"Invalid UTF-16 encoding".to_string(),
			)));
		}

		// FIXME: Update this when `array_chunks` is stabilized.
		for maybe_char in char::decode_utf16(
			vec.chunks_exact(2)
				.map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]])),
		) {
			// We check we only use the BMP subset of Unicode (the first 65 536 code points)
			match maybe_char {
				// Character is in the Basic Multilingual Plane
				Ok(c) if (c as u64) < u64::from(u16::MAX) => (),
				// Characters outside Basic Multilingual Plane or unpaired surrogates
				_ => {
					return Err(Error::InvalidAsn1String(InvalidAsn1String::BmpString(
						"Invalid UTF-16 encoding".to_string(),
					)));
				},
			}
		}
		Ok(Self(vec.to_vec()))
	}
}

impl TryFrom<&str> for BmpString {
	type Error = Error;

	/// Converts a `&str` to a [`BmpString`].
	///
	/// Any character not in the [`BmpString`] charset will be rejected.
	/// See [`BmpString`] documentation for more information.
	///
	/// The result is allocated on the heap.
	fn try_from(value: &str) -> Result<Self, Self::Error> {
		let capacity = value.len().checked_mul(2).ok_or_else(|| {
			Error::InvalidAsn1String(InvalidAsn1String::BmpString(value.to_string()))
		})?;

		let mut bytes = Vec::with_capacity(capacity);

		for code_point in value.encode_utf16() {
			bytes.extend(code_point.to_be_bytes());
		}

		BmpString::from_utf16be(bytes)
	}
}

impl TryFrom<String> for BmpString {
	type Error = Error;

	/// Converts a [`String`][`std::string::String`] into a [`BmpString`]
	///
	/// Any character not in the [`BmpString`] charset will be rejected.
	/// See [`BmpString`] documentation for more information.
	///
	/// Parsing a `BmpString` allocates memory since the UTF-8 to UTF-16 conversion requires a memory allocation.
	fn try_from(value: String) -> Result<Self, Self::Error> {
		value.as_str().try_into()
	}
}

impl FromStr for BmpString {
	type Err = Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		s.try_into()
	}
}

/// ASN.1 `UniversalString` type.
///
/// # Examples
///
/// You can create a `UniversalString` from [a literal string][`&str`] with [`UniversalString::try_from`]:
///
/// ```
/// use rcgen::UniversalString;
/// let hello = UniversalString::try_from("hello").unwrap();
/// ```
///
/// # Supported characters
///
/// The characters which can appear in the `UniversalString` type are any of the characters allowed by
/// ISO/IEC 10646 (Unicode).
///
/// Bytes are encoded like UTF-32 big-endian.
///
/// `UniversalString` is included for backward compatibility, [RFC 5280] say it
/// SHOULD NOT be used for certificates for new subjects.
///
/// [RFC 5280]: https://datatracker.ietf.org/doc/html/rfc5280#page-25
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct UniversalString(Vec<u8>);

impl UniversalString {
	/// Returns a byte slice of this `UniversalString`'s contents.
	///
	/// The inverse of this method is [`from_utf32be`].
	///
	/// [`from_utf32be`]: UniversalString::from_utf32be
	///
	/// # Examples
	///
	/// ```
	/// use rcgen::UniversalString;
	/// let s = UniversalString::try_from("hello").unwrap();
	///
	/// assert_eq!(&[0, 0, 0, 104, 0, 0, 0, 101, 0, 0, 0, 108, 0, 0, 0, 108, 0, 0, 0, 111], s.as_bytes());
	/// ```
	pub fn as_bytes(&self) -> &[u8] {
		&self.0
	}

	/// Decode a UTF-32BE–encoded vector `vec` into a `UniversalString`, returning [Err](`std::result::Result::Err`) if `vec` contains any invalid data.
	pub fn from_utf32be(vec: Vec<u8>) -> Result<UniversalString, Error> {
		if vec.len() % 4 != 0 {
			return Err(Error::InvalidAsn1String(
				InvalidAsn1String::UniversalString("Invalid UTF-32 encoding".to_string()),
			));
		}

		// FIXME: Update this when `array_chunks` is stabilized.
		for maybe_char in vec
			.chunks_exact(4)
			.map(|chunk| u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
		{
			if core::char::from_u32(maybe_char).is_none() {
				return Err(Error::InvalidAsn1String(
					InvalidAsn1String::UniversalString("Invalid UTF-32 encoding".to_string()),
				));
			}
		}

		Ok(Self(vec))
	}
}

impl TryFrom<&str> for UniversalString {
	type Error = Error;

	/// Converts a `&str` to a [`UniversalString`].
	///
	/// Any character not in the [`UniversalString`] charset will be rejected.
	/// See [`UniversalString`] documentation for more information.
	///
	/// The result is allocated on the heap.
	fn try_from(value: &str) -> Result<Self, Self::Error> {
		let capacity = value.len().checked_mul(4).ok_or_else(|| {
			Error::InvalidAsn1String(InvalidAsn1String::UniversalString(value.to_string()))
		})?;

		let mut bytes = Vec::with_capacity(capacity);

		// A `char` is any ‘Unicode code point’ other than a surrogate code point.
		// The code units for UTF-32 correspond exactly to Unicode code points.
		// (https://www.unicode.org/reports/tr19/tr19-9.html#Introduction)
		// So any `char` is a valid UTF-32, we just cast it to perform the convertion.
		for char in value.chars().map(|char| char as u32) {
			bytes.extend(char.to_be_bytes())
		}

		UniversalString::from_utf32be(bytes)
	}
}

impl TryFrom<String> for UniversalString {
	type Error = Error;

	/// Converts a [`String`][`std::string::String`] into a [`UniversalString`]
	///
	/// Any character not in the [`UniversalString`] charset will be rejected.
	/// See [`UniversalString`] documentation for more information.
	///
	/// Parsing a `UniversalString` allocates memory since the UTF-8 to UTF-32 conversion requires a memory allocation.
	fn try_from(value: String) -> Result<Self, Self::Error> {
		value.as_str().try_into()
	}
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {

	use crate::{BmpString, Ia5String, PrintableString, TeletexString, UniversalString};

	#[test]
	fn printable_string() {
		const EXAMPLE_UTF8: &str = "CertificateTemplate";
		let printable_string = PrintableString::try_from(EXAMPLE_UTF8).unwrap();
		assert_eq!(printable_string, EXAMPLE_UTF8);
		assert!(PrintableString::try_from("@").is_err());
		assert!(PrintableString::try_from("*").is_err());
	}

	#[test]
	fn ia5_string() {
		const EXAMPLE_UTF8: &str = "CertificateTemplate";
		let ia5_string = Ia5String::try_from(EXAMPLE_UTF8).unwrap();
		assert_eq!(ia5_string, EXAMPLE_UTF8);
		assert!(Ia5String::try_from(String::from('\u{7F}')).is_ok());
		assert!(Ia5String::try_from(String::from('\u{8F}')).is_err());
	}

	#[test]
	fn teletext_string() {
		const EXAMPLE_UTF8: &str = "CertificateTemplate";
		let teletext_string = TeletexString::try_from(EXAMPLE_UTF8).unwrap();
		assert_eq!(teletext_string, EXAMPLE_UTF8);
		assert!(Ia5String::try_from(String::from('\u{7F}')).is_ok());
		assert!(Ia5String::try_from(String::from('\u{8F}')).is_err());
	}

	#[test]
	fn bmp_string() {
		const EXPECTED_BYTES: &[u8] = &[
			0x00, 0x43, 0x00, 0x65, 0x00, 0x72, 0x00, 0x74, 0x00, 0x69, 0x00, 0x66, 0x00, 0x69,
			0x00, 0x63, 0x00, 0x61, 0x00, 0x74, 0x00, 0x65, 0x00, 0x54, 0x00, 0x65, 0x00, 0x6d,
			0x00, 0x70, 0x00, 0x6c, 0x00, 0x61, 0x00, 0x74, 0x00, 0x65,
		];
		const EXAMPLE_UTF8: &str = "CertificateTemplate";
		let bmp_string = BmpString::try_from(EXAMPLE_UTF8).unwrap();
		assert_eq!(bmp_string.as_bytes(), EXPECTED_BYTES);
		assert!(BmpString::try_from(String::from('\u{FFFE}')).is_ok());
		assert!(BmpString::try_from(String::from('\u{FFFF}')).is_err());
	}

	#[test]
	fn universal_string() {
		const EXPECTED_BYTES: &[u8] = &[
			0x00, 0x00, 0x00, 0x43, 0x00, 0x00, 0x00, 0x65, 0x00, 0x00, 0x00, 0x72, 0x00, 0x00,
			0x00, 0x74, 0x00, 0x00, 0x00, 0x69, 0x00, 0x00, 0x00, 0x66, 0x00, 0x00, 0x00, 0x69,
			0x00, 0x00, 0x00, 0x63, 0x00, 0x00, 0x00, 0x61, 0x00, 0x00, 0x00, 0x74, 0x00, 0x00,
			0x00, 0x65, 0x00, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00, 0x65, 0x00, 0x00, 0x00, 0x6d,
			0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x6c, 0x00, 0x00, 0x00, 0x61, 0x00, 0x00,
			0x00, 0x74, 0x00, 0x00, 0x00, 0x65,
		];
		const EXAMPLE_UTF8: &str = "CertificateTemplate";
		let universal_string = UniversalString::try_from(EXAMPLE_UTF8).unwrap();
		assert_eq!(universal_string.as_bytes(), EXPECTED_BYTES);
	}
}
