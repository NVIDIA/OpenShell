//! Validators.
//!
//! Validators are functions that receive the string and checks if the entire
//! string is syntactically valid.

use core::fmt;

#[cfg(feature = "std")]
use std::error;

use crate::parser::validate as parser;
use crate::spec::Spec;

/// Resource identifier validation error.
// Note that this type should implement `Copy` trait.
// To return additional non-`Copy` data as an error, use wrapper type
// (as `std::string::FromUtf8Error` contains `std::str::Utf8Error`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    /// Error kind.
    kind: ErrorKind,
}

impl Error {
    /// Creates a new `Error` from the given error kind.
    #[inline]
    #[must_use]
    pub(crate) fn with_kind(kind: ErrorKind) -> Self {
        Self { kind }
    }
}

impl fmt::Display for Error {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid IRI: {}", self.kind.description())
    }
}

#[cfg(feature = "std")]
impl error::Error for Error {}

/// Error kind.
///
/// This type may be reorganized between minor version bumps, so users should
/// not expect specific error kind (or specific error message) to be returned
/// for a specific error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum ErrorKind {
    /// Invalid scheme.
    InvalidScheme,
    /// Invalid userinfo.
    InvalidUserInfo,
    /// Invalid host.
    InvalidHost,
    /// Invalid `reg-name`.
    InvalidRegName,
    /// Invalid port.
    InvalidPort,
    /// Invalid path character.
    InvalidPath,
    /// Invalid query.
    InvalidQuery,
    /// Invalid fragment.
    InvalidFragment,
    /// Got an unexpected fragment.
    UnexpectedFragment,
    /// Expected a relative IRI but got an absolute IRI.
    UnexpectedAbsolute,
    /// Expected an absolute IRI but got a relative IRI.
    UnexpectedRelative,
    /// Invalid UTF-8 bytes.
    InvalidUtf8,
}

impl ErrorKind {
    /// Returns the human-friendly description for the error kind.
    #[must_use]
    fn description(self) -> &'static str {
        match self {
            Self::InvalidScheme => "invalid scheme",
            Self::InvalidUserInfo => "invalid userinfo",
            Self::InvalidHost => "invalid host",
            Self::InvalidRegName => "invalid reg-name",
            Self::InvalidPort => "invalid port",
            Self::InvalidPath => "invalid path",
            Self::InvalidQuery => "invalid query",
            Self::InvalidFragment => "invalid fragment",
            Self::UnexpectedFragment => "unexpected fragment",
            Self::UnexpectedAbsolute => "expected a relative IRI but got an absolute IRI",
            Self::UnexpectedRelative => "expected an absolute IRI but got a relative IRI",
            Self::InvalidUtf8 => "invalid utf-8 bytes",
        }
    }
}

/// Validates [IRI][uri].
///
/// This validator corresponds to [`RiStr`] and [`RiString`] types.
///
/// # Examples
///
/// This type can have an IRI (which is absolute, and may have fragment part).
///
/// ```
/// use iri_string::{spec::UriSpec, validate::iri};
/// assert!(iri::<UriSpec>("https://user:pass@example.com:8080").is_ok());
/// assert!(iri::<UriSpec>("https://example.com/").is_ok());
/// assert!(iri::<UriSpec>("https://example.com/foo?bar=baz").is_ok());
/// assert!(iri::<UriSpec>("https://example.com/foo?bar=baz#qux").is_ok());
/// assert!(iri::<UriSpec>("foo:bar").is_ok());
/// assert!(iri::<UriSpec>("foo:").is_ok());
/// // `foo://.../` below are all allowed. See the crate documentation for detail.
/// assert!(iri::<UriSpec>("foo:/").is_ok());
/// assert!(iri::<UriSpec>("foo://").is_ok());
/// assert!(iri::<UriSpec>("foo:///").is_ok());
/// assert!(iri::<UriSpec>("foo:////").is_ok());
/// assert!(iri::<UriSpec>("foo://///").is_ok());
/// ```
///
/// Relative IRI reference is not allowed.
///
/// ```
/// use iri_string::{spec::UriSpec, validate::iri};
/// // This is relative path.
/// assert!(iri::<UriSpec>("foo/bar").is_err());
/// // `/foo/bar` is an absolute path, but it is authority-relative.
/// assert!(iri::<UriSpec>("/foo/bar").is_err());
/// // `//foo/bar` is termed "network-path reference",
/// // or usually called "protocol-relative reference".
/// assert!(iri::<UriSpec>("//foo/bar").is_err());
/// // Same-document reference is relative.
/// assert!(iri::<UriSpec>("#foo").is_err());
/// // Empty string is not a valid absolute IRI.
/// assert!(iri::<UriSpec>("").is_err());
/// ```
///
/// Some characters and sequences cannot used in an IRI.
///
/// ```
/// use iri_string::{spec::UriSpec, validate::iri};
/// // `<` and `>` cannot directly appear in an IRI.
/// assert!(iri::<UriSpec>("<not allowed>").is_err());
/// // Broken percent encoding cannot appear in an IRI.
/// assert!(iri::<UriSpec>("%").is_err());
/// assert!(iri::<UriSpec>("%GG").is_err());
/// ```
///
/// [uri]: https://www.rfc-editor.org/rfc/rfc3986.html#section-3
/// [`RiStr`]: ../types/struct.RiStr.html
/// [`RiString`]: ../types/struct.RiString.html
pub fn iri<S: Spec>(s: &str) -> Result<(), Error> {
    parser::validate_uri::<S>(s)
}

/// Validates [IRI reference][uri-reference].
///
/// This validator corresponds to [`RiReferenceStr`] and [`RiReferenceString`] types.
///
/// # Examples
///
/// This type can have an IRI reference (which can be absolute or relative).
///
/// ```
/// use iri_string::{spec::UriSpec, validate::iri_reference};
/// assert!(iri_reference::<UriSpec>("https://user:pass@example.com:8080").is_ok());
/// assert!(iri_reference::<UriSpec>("https://example.com/").is_ok());
/// assert!(iri_reference::<UriSpec>("https://example.com/foo?bar=baz").is_ok());
/// assert!(iri_reference::<UriSpec>("https://example.com/foo?bar=baz#qux").is_ok());
/// assert!(iri_reference::<UriSpec>("foo:bar").is_ok());
/// assert!(iri_reference::<UriSpec>("foo:").is_ok());
/// // `foo://.../` below are all allowed. See the crate documentation for detail.
/// assert!(iri_reference::<UriSpec>("foo:/").is_ok());
/// assert!(iri_reference::<UriSpec>("foo://").is_ok());
/// assert!(iri_reference::<UriSpec>("foo:///").is_ok());
/// assert!(iri_reference::<UriSpec>("foo:////").is_ok());
/// assert!(iri_reference::<UriSpec>("foo://///").is_ok());
/// assert!(iri_reference::<UriSpec>("foo/bar").is_ok());
/// assert!(iri_reference::<UriSpec>("/foo/bar").is_ok());
/// assert!(iri_reference::<UriSpec>("//foo/bar").is_ok());
/// assert!(iri_reference::<UriSpec>("#foo").is_ok());
/// ```
///
/// Some characters and sequences cannot used in an IRI reference.
///
/// ```
/// use iri_string::{spec::UriSpec, validate::iri_reference};
/// // `<` and `>` cannot directly appear in an IRI reference.
/// assert!(iri_reference::<UriSpec>("<not allowed>").is_err());
/// // Broken percent encoding cannot appear in an IRI reference.
/// assert!(iri_reference::<UriSpec>("%").is_err());
/// assert!(iri_reference::<UriSpec>("%GG").is_err());
/// ```
///
/// [uri-reference]: https://www.rfc-editor.org/rfc/rfc3986.html#section-4.1
/// [`RiReferenceStr`]: ../types/struct.RiReferenceStr.html
/// [`RiReferenceString`]: ../types/struct.RiReferenceString.html
pub fn iri_reference<S: Spec>(s: &str) -> Result<(), Error> {
    parser::validate_uri_reference::<S>(s)
}

/// Validates [absolute IRI][absolute-uri].
///
/// This validator corresponds to [`RiAbsoluteStr`] and [`RiAbsoluteString`] types.
///
/// # Examples
///
/// This type can have an absolute IRI without fragment part.
///
/// ```
/// use iri_string::{spec::UriSpec, validate::absolute_iri};
/// assert!(absolute_iri::<UriSpec>("https://example.com/foo?bar=baz").is_ok());
/// assert!(absolute_iri::<UriSpec>("foo:bar").is_ok());
/// // Scheme `foo` and empty path.
/// assert!(absolute_iri::<UriSpec>("foo:").is_ok());
/// // `foo://.../` below are all allowed. See the crate documentation for detail.
/// assert!(absolute_iri::<UriSpec>("foo:/").is_ok());
/// assert!(absolute_iri::<UriSpec>("foo://").is_ok());
/// assert!(absolute_iri::<UriSpec>("foo:///").is_ok());
/// assert!(absolute_iri::<UriSpec>("foo:////").is_ok());
/// assert!(absolute_iri::<UriSpec>("foo://///").is_ok());
///
/// ```
///
/// Relative IRI is not allowed.
///
/// ```
/// use iri_string::{spec::UriSpec, validate::absolute_iri};
/// // This is relative path.
/// assert!(absolute_iri::<UriSpec>("foo/bar").is_err());
/// // `/foo/bar` is an absolute path, but it is authority-relative.
/// assert!(absolute_iri::<UriSpec>("/foo/bar").is_err());
/// // `//foo/bar` is termed "network-path reference",
/// // or usually called "protocol-relative reference".
/// assert!(absolute_iri::<UriSpec>("//foo/bar").is_err());
/// // Empty string is not a valid absolute IRI.
/// assert!(absolute_iri::<UriSpec>("").is_err());
/// ```
///
/// Fragment part (such as trailing `#foo`) is not allowed.
///
/// ```
/// use iri_string::{spec::UriSpec, validate::absolute_iri};
/// // Fragment part is not allowed.
/// assert!(absolute_iri::<UriSpec>("https://example.com/foo?bar=baz#qux").is_err());
/// ```
///
/// Some characters and sequences cannot used in an absolute IRI.
///
/// ```
/// use iri_string::{spec::UriSpec, validate::absolute_iri};
/// // `<` and `>` cannot directly appear in an absolute IRI.
/// assert!(absolute_iri::<UriSpec>("<not allowed>").is_err());
/// // Broken percent encoding cannot appear in an absolute IRI.
/// assert!(absolute_iri::<UriSpec>("%").is_err());
/// assert!(absolute_iri::<UriSpec>("%GG").is_err());
/// ```
///
/// [absolute-uri]: https://www.rfc-editor.org/rfc/rfc3986.html#section-4.3
/// [`RiAbsoluteStr`]: ../types/struct.RiAbsoluteStr.html
/// [`RiAbsoluteString`]: ../types/struct.RiAbsoluteString.html
pub fn absolute_iri<S: Spec>(s: &str) -> Result<(), Error> {
    parser::validate_absolute_uri::<S>(s)
}

/// Validates [relative reference][relative-ref].
///
/// This validator corresponds to [`RiRelativeStr`] and [`RiRelativeString`] types.
///
/// # Valid values
///
/// This type can have a relative IRI reference.
///
/// ```
/// use iri_string::{spec::UriSpec, validate::relative_ref};
/// assert!(relative_ref::<UriSpec>("foo").is_ok());
/// assert!(relative_ref::<UriSpec>("foo/bar").is_ok());
/// assert!(relative_ref::<UriSpec>("/foo").is_ok());
/// assert!(relative_ref::<UriSpec>("//foo/bar").is_ok());
/// assert!(relative_ref::<UriSpec>("?foo").is_ok());
/// assert!(relative_ref::<UriSpec>("#foo").is_ok());
/// assert!(relative_ref::<UriSpec>("foo/bar?baz#qux").is_ok());
/// // The first path component can have colon if the path is absolute.
/// assert!(relative_ref::<UriSpec>("/foo:bar/").is_ok());
/// // Second or following path components can have colon.
/// assert!(relative_ref::<UriSpec>("foo/bar://baz/").is_ok());
/// assert!(relative_ref::<UriSpec>("./foo://bar").is_ok());
/// ```
///
/// Absolute form of a reference is not allowed.
///
/// ```
/// use iri_string::{spec::UriSpec, validate::relative_ref};
/// assert!(relative_ref::<UriSpec>("https://example.com/").is_err());
/// // The first path component cannot have colon, if the path is not absolute.
/// assert!(relative_ref::<UriSpec>("foo:bar").is_err());
/// assert!(relative_ref::<UriSpec>("foo:").is_err());
/// assert!(relative_ref::<UriSpec>("foo:/").is_err());
/// assert!(relative_ref::<UriSpec>("foo://").is_err());
/// assert!(relative_ref::<UriSpec>("foo:///").is_err());
/// assert!(relative_ref::<UriSpec>("foo:////").is_err());
/// assert!(relative_ref::<UriSpec>("foo://///").is_err());
/// ```
///
/// Some characters and sequences cannot used in an IRI reference.
///
/// ```
/// use iri_string::{spec::UriSpec, validate::relative_ref};
/// // `<` and `>` cannot directly appear in a relative IRI reference.
/// assert!(relative_ref::<UriSpec>("<not allowed>").is_err());
/// // Broken percent encoding cannot appear in a relative IRI reference.
/// assert!(relative_ref::<UriSpec>("%").is_err());
/// assert!(relative_ref::<UriSpec>("%GG").is_err());
/// ```
///
/// [relative-ref]: https://www.rfc-editor.org/rfc/rfc3986.html#section-4.2
/// [`RiRelativeStr`]: ../types/struct.RiRelativeStr.html
/// [`RiRelativeString`]: ../types/struct.RiRelativeString.html
pub fn relative_ref<S: Spec>(s: &str) -> Result<(), Error> {
    parser::validate_relative_ref::<S>(s)
}

/// Validates [IRI scheme][scheme].
///
/// Note that this function does not accept a trailing colon.
///
/// Also note that the syntax of the scheme is common between RFC 3986 (URIs)
/// and RFC 3987 (IRIs).
///
/// # Examples
///
/// ```
/// use iri_string::validate::scheme;
/// assert!(scheme("https").is_ok());
/// assert!(scheme("file").is_ok());
/// assert!(scheme("git+ssh").is_ok());
///
/// // Colon is syntactically not part of the scheme.
/// assert!(scheme("colon:").is_err());
/// // Scheme cannot be empty.
/// assert!(scheme("").is_err());
/// // The first character should be alphabetic character.
/// assert!(scheme("0abc").is_err());
/// assert!(scheme("+a").is_err());
/// assert!(scheme("-a").is_err());
/// ```
///
/// [scheme]: https://www.rfc-editor.org/rfc/rfc3986.html#section-3.1
pub fn scheme(s: &str) -> Result<(), Error> {
    parser::validate_scheme(s)
}

/// Validates [IRI authority][authority].
///
/// # Examples
///
/// ```
/// use iri_string::{spec::UriSpec, validate::authority};
/// assert!(authority::<UriSpec>("example.com").is_ok());
/// assert!(authority::<UriSpec>("subdomain.example.com").is_ok());
/// assert!(authority::<UriSpec>("no-period").is_ok());
/// // Though strongly discouraged, this percent-encoded reg-name with
/// // non-UTF-8 bytes is considered syntactically valid.
/// assert!(authority::<UriSpec>("non-%99-utf-8").is_ok());
/// // Empty authority is valid. Remember `file:///` has empty authority.
/// assert!(authority::<UriSpec>("").is_ok());
/// assert!(authority::<UriSpec>("127.0.0.1:8080").is_ok());
/// assert!(authority::<UriSpec>("[::127.0.0.1]:8088").is_ok());
/// // URI/IRI syntax itself does not have limit on the port number.
/// assert!(authority::<UriSpec>("[::1]:9999999999").is_ok());
/// // Syntax for future versions of IP addresses.
/// assert!(authority::<UriSpec>("[v89ab.1+2,3(4)5&6]").is_ok());
/// assert!(authority::<UriSpec>("user:password@host").is_ok());
/// assert!(authority::<UriSpec>("co%3Alon:at%40sign@host:8888").is_ok());
/// // Percent-encoded non-UTF8 (or even non-ASCII) bytes are valid.
/// // Users are responsible to validate or reject such unusual input if needed.
/// assert!(authority::<UriSpec>("not-a-%80-utf8@host").is_ok());
///
/// // Invalid percent encodings.
/// assert!(authority::<UriSpec>("invalid%GGescape@host").is_err());
/// // Invalid characters.
/// assert!(authority::<UriSpec>("foo@bar@host").is_err());
/// assert!(authority::<UriSpec>("slash/is-not-allowed").is_err());
/// ```
///
/// [authority]: https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2
pub fn authority<S: Spec>(s: &str) -> Result<(), Error> {
    parser::validate_authority::<S>(s)
}

/// Validates [IRI host][host].
///
/// # Examples
///
/// ```
/// use iri_string::{spec::UriSpec, validate::host};
/// assert!(host::<UriSpec>("example.com").is_ok());
/// assert!(host::<UriSpec>("subdomain.example.com").is_ok());
/// assert!(host::<UriSpec>("no-period").is_ok());
/// // Though strongly discouraged, this percent-encoded reg-name with
/// // non-UTF-8 bytes is considered syntactically valid.
/// assert!(host::<UriSpec>("non-%99-utf-8").is_ok());
/// // Empty host is valid. Remember `file:///` has empty authority (and empty host).
/// assert!(host::<UriSpec>("").is_ok());
/// assert!(host::<UriSpec>("127.0.0.1").is_ok());
/// assert!(host::<UriSpec>("[::1]").is_ok());
/// assert!(host::<UriSpec>("[::127.0.0.1]").is_ok());
/// // Syntax for future versions of IP addresses.
/// assert!(host::<UriSpec>("[v89ab.1+2,3(4)5&6]").is_ok());
///
/// // `port` is not a part of the host.
/// assert!(host::<UriSpec>("host:8080").is_err());
/// // `userinfo` is not a part of the host.
/// assert!(host::<UriSpec>("user:password@host").is_err());
/// ```
///
/// [host]: https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.2
pub fn host<S: Spec>(s: &str) -> Result<(), Error> {
    parser::validate_host::<S>(s)
}

/// Validates [reg-name].
///
/// # Examples
///
/// ```
/// use iri_string::{spec::UriSpec, validate::reg_name};
/// assert!(reg_name::<UriSpec>("example.com").is_ok());
/// assert!(reg_name::<UriSpec>("subdomain.example.com").is_ok());
/// assert!(reg_name::<UriSpec>("no-period").is_ok());
/// // Though strongly discouraged, this percent-encoded reg-name with
/// // non-UTF-8 bytes is considered syntactically valid.
/// assert!(reg_name::<UriSpec>("non-%99-utf-8").is_ok());
/// // Empty host is valid. Remember `file:///` has empty authority (and empty host).
/// assert!(reg_name::<UriSpec>("").is_ok());
///
/// // Even if this looks similar to `IPv4address`, it's not,
/// // and this matches `reg-name` rule.
/// assert!(reg_name::<UriSpec>("127.0.0.256").is_ok());
///
/// // IP addresses are not a `reg-name`.
/// assert!(reg_name::<UriSpec>("127.0.0.1").is_err());
/// assert!(reg_name::<UriSpec>("[::1]").is_err());
/// assert!(reg_name::<UriSpec>("[::127.0.0.1]").is_err());
/// // Syntax for future versions of IP addresses.
/// assert!(reg_name::<UriSpec>("[v89ab.1+2,3(4)5&6]").is_err());
///
/// // `port` is not a part of the host.
/// assert!(reg_name::<UriSpec>("host:8080").is_err());
/// // `userinfo` is not a part of the host.
/// assert!(reg_name::<UriSpec>("user:password@host").is_err());
/// ```
///
/// [reg-name]: https://www.rfc-editor.org/rfc/rfc3986.html#page-21
pub fn reg_name<S: Spec>(s: &str) -> Result<(), Error> {
    parser::validate_reg_name::<S>(s)
}

/// Validates [IRI port][port].
///
/// Note that the syntax of the port is common between RFC 3986 (URIs) and
/// RFC 3987 (IRIs).
///
/// Also note that this function does not accept a leading colon.
///
/// [host]: https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.3
///
/// # Examples
///
/// ```
/// use iri_string::validate::port;
/// assert!(port("0").is_ok());
/// assert!(port("8080").is_ok());
/// assert!(port("0000080").is_ok());
/// // URI/IRI syntax itself does not have limit on the port number.
/// assert!(port("999999999").is_ok());
///
/// // The leading colon is not a part of the `port`.
/// assert!(port(":443").is_err());
/// ```
pub fn port(s: &str) -> Result<(), Error> {
    if s.bytes().all(|b| b.is_ascii_digit()) {
        Ok(())
    } else {
        Err(Error::with_kind(ErrorKind::InvalidPort))
    }
}

/// Validates [IRI userinfo][userinfo].
///
/// # Examples
///
/// ```
/// use iri_string::{spec::UriSpec, validate::userinfo};
/// assert!(userinfo::<UriSpec>("user").is_ok());
/// assert!(userinfo::<UriSpec>("user:password").is_ok());
/// assert!(userinfo::<UriSpec>("non-%99-utf-8").is_ok());
/// // Special characters can be included if they are percent-encoded.
/// assert!(userinfo::<UriSpec>("co%3Alon:at%40sign").is_ok());
///
/// // The trailing atsign is not a part of the userinfo.
/// assert!(userinfo::<UriSpec>("user:password@").is_err());
/// // Invalid characters.
/// assert!(userinfo::<UriSpec>("foo@bar").is_err());
/// assert!(userinfo::<UriSpec>("slash/is-not-allowed").is_err());
/// ```
///
/// [authority]: https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.1
pub fn userinfo<S: Spec>(s: &str) -> Result<(), Error> {
    parser::validate_userinfo::<S>(s)
}

/// Validates [IRI path][path].
///
/// # Examples
///
/// ```
/// use iri_string::{spec::UriSpec, validate::path};
/// assert!(path::<UriSpec>("").is_ok());
/// assert!(path::<UriSpec>("foo/bar").is_ok());
/// assert!(path::<UriSpec>("foo/bar/").is_ok());
/// assert!(path::<UriSpec>("/foo/bar").is_ok());
/// assert!(path::<UriSpec>("non-%99-utf-8").is_ok());
/// // Be careful! This is completely valid (absolute) path, but may be confused
/// // with an protocol-relative URI, with the authority `foo` and the path `/bar`.
/// assert!(path::<UriSpec>("//foo/bar").is_ok());
/// // Be careful! This is completely valid (relative) path, but may be confused
/// // with an absolute URI, with the scheme `foo` and the path `bar`.
/// assert!(path::<UriSpec>("foo:bar").is_ok());
///
/// // Invalid characters.
/// assert!(path::<UriSpec>("foo?bar").is_err());
/// assert!(path::<UriSpec>("foo#bar").is_err());
/// ```
///
/// [path]: https://www.rfc-editor.org/rfc/rfc3986.html#section-3.3
pub fn path<S: Spec>(s: &str) -> Result<(), Error> {
    parser::validate_path::<S>(s)
}

/// Validates [IRI path segment][segment].
///
/// # Examples
///
/// ```
/// use iri_string::{spec::UriSpec, validate::path_segment};
/// assert!(path_segment::<UriSpec>("").is_ok());
/// assert!(path_segment::<UriSpec>("escaped-%2F-slash").is_ok());
/// assert!(path_segment::<UriSpec>("non-%99-utf-8").is_ok());
///
/// // A path segment itself cannot contain an unescaped slash.
/// assert!(path_segment::<UriSpec>("foo/bar").is_err());
/// ```
///
/// [segment]: https://www.rfc-editor.org/rfc/rfc3986.html#section-3.3
pub fn path_segment<S: Spec>(s: &str) -> Result<(), Error> {
    parser::validate_path_segment::<S>(s)
}

/// Validates [IRI query][query].
///
/// This validator corresponds to [`RiQueryStr`] and [`RiQueryString`] types.
///
/// Note that the first `?` character in an IRI is not a part of a query.
/// For example, `https://example.com/?foo#bar` has a query `foo`, **not** `?foo`.
///
/// # Examples
///
/// This type can have an IRI query.
/// Note that the IRI `foo://bar/baz?qux#quux` has the query `qux`, **not** `?qux`.
///
/// ```
/// use iri_string::{spec::UriSpec, validate::query};
/// assert!(query::<UriSpec>("").is_ok());
/// assert!(query::<UriSpec>("foo").is_ok());
/// assert!(query::<UriSpec>("foo/bar").is_ok());
/// assert!(query::<UriSpec>("/foo/bar").is_ok());
/// assert!(query::<UriSpec>("//foo/bar").is_ok());
/// assert!(query::<UriSpec>("https://user:pass@example.com:8080").is_ok());
/// assert!(query::<UriSpec>("https://example.com/").is_ok());
/// // Question sign `?` can appear in an IRI query.
/// assert!(query::<UriSpec>("query?again").is_ok());
/// ```
///
/// Some characters and sequences cannot used in a query.
///
/// ```
/// use iri_string::{spec::UriSpec, validate::query};
/// // `<` and `>` cannot directly appear in an IRI reference.
/// assert!(query::<UriSpec>("<not allowed>").is_err());
/// // Broken percent encoding cannot appear in an IRI reference.
/// assert!(query::<UriSpec>("%").is_err());
/// assert!(query::<UriSpec>("%GG").is_err());
/// // Hash sign `#` cannot appear in an IRI query.
/// assert!(query::<UriSpec>("#hash").is_err());
/// ```
///
/// [query]: https://www.rfc-editor.org/rfc/rfc3986.html#section-3.4
/// [`RiQueryStr`]: ../types/struct.RiQueryStr.html
/// [`RiQueryString`]: ../types/struct.RiQueryString.html
pub fn query<S: Spec>(s: &str) -> Result<(), Error> {
    parser::validate_query::<S>(s)
}

/// Validates [IRI fragment][fragment].
///
/// This validator corresponds to [`RiFragmentStr`] and [`RiFragmentString`] types.
///
/// Note that the first `#` character in an IRI is not a part of a fragment.
/// For example, `https://example.com/#foo` has a fragment `foo`, **not** `#foo`.
///
/// # Examples
///
/// This type can have an IRI fragment.
/// Note that the IRI `foo://bar/baz#qux` has the fragment `qux`, **not** `#qux`.
///
/// ```
/// use iri_string::{spec::UriSpec, validate::fragment};
/// assert!(fragment::<UriSpec>("").is_ok());
/// assert!(fragment::<UriSpec>("foo").is_ok());
/// assert!(fragment::<UriSpec>("foo/bar").is_ok());
/// assert!(fragment::<UriSpec>("/foo/bar").is_ok());
/// assert!(fragment::<UriSpec>("//foo/bar").is_ok());
/// assert!(fragment::<UriSpec>("https://user:pass@example.com:8080").is_ok());
/// assert!(fragment::<UriSpec>("https://example.com/").is_ok());
/// ```
///
/// Some characters and sequences cannot used in a fragment.
///
/// ```
/// use iri_string::{spec::UriSpec, validate::fragment};
/// // `<` and `>` cannot directly appear in an IRI reference.
/// assert!(fragment::<UriSpec>("<not allowed>").is_err());
/// // Broken percent encoding cannot appear in an IRI reference.
/// assert!(fragment::<UriSpec>("%").is_err());
/// assert!(fragment::<UriSpec>("%GG").is_err());
/// // Hash sign `#` cannot appear in an IRI fragment.
/// assert!(fragment::<UriSpec>("#hash").is_err());
/// ```
///
/// [fragment]: https://www.rfc-editor.org/rfc/rfc3986.html#section-3.5
/// [`RiFragmentStr`]: ../types/struct.RiFragmentStr.html
/// [`RiFragmentString`]: ../types/struct.RiFragmentString.html
pub fn fragment<S: Spec>(s: &str) -> Result<(), Error> {
    parser::validate_fragment::<S>(s)
}
