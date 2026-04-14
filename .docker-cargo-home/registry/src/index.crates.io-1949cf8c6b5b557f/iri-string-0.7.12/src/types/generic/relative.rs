//! Relative IRI reference.

#[cfg(feature = "alloc")]
use alloc::collections::TryReserveError;

use crate::components::AuthorityComponents;
#[cfg(feature = "alloc")]
use crate::mask_password::password_range_to_hide;
use crate::mask_password::PasswordMasked;
use crate::normalize::Normalized;
use crate::parser::trusted as trusted_parser;
#[cfg(feature = "alloc")]
use crate::raw;
use crate::resolve::FixedBaseResolver;
use crate::spec::Spec;
#[cfg(feature = "alloc")]
use crate::types::RiReferenceString;
use crate::types::{RiAbsoluteStr, RiFragmentStr, RiQueryStr, RiReferenceStr, RiStr};
use crate::validate::relative_ref;

define_custom_string_slice! {
    /// A borrowed slice of a relative IRI reference.
    ///
    /// This corresponds to [`irelative-ref` rule] in [RFC 3987]
    /// (and [`relative-ref` rule] in [RFC 3986]).
    /// The rule for `irelative-ref` is `irelative-part [ "?" iquery ] [ "#" ifragment ]`.
    ///
    /// # Valid values
    ///
    /// This type can have a relative IRI reference.
    ///
    /// ```
    /// # use iri_string::types::IriRelativeStr;
    /// assert!(IriRelativeStr::new("foo").is_ok());
    /// assert!(IriRelativeStr::new("foo/bar").is_ok());
    /// assert!(IriRelativeStr::new("/foo").is_ok());
    /// assert!(IriRelativeStr::new("//foo/bar").is_ok());
    /// assert!(IriRelativeStr::new("?foo").is_ok());
    /// assert!(IriRelativeStr::new("#foo").is_ok());
    /// assert!(IriRelativeStr::new("foo/bar?baz#qux").is_ok());
    /// // The first path component can have colon if the path is absolute.
    /// assert!(IriRelativeStr::new("/foo:bar/").is_ok());
    /// // Second or following path components can have colon.
    /// assert!(IriRelativeStr::new("foo/bar://baz/").is_ok());
    /// assert!(IriRelativeStr::new("./foo://bar").is_ok());
    /// ```
    ///
    /// Absolute form of a reference is not allowed.
    ///
    /// ```
    /// # use iri_string::types::IriRelativeStr;
    /// assert!(IriRelativeStr::new("https://example.com/").is_err());
    /// // The first path component cannot have colon, if the path is not absolute.
    /// assert!(IriRelativeStr::new("foo:bar").is_err());
    /// assert!(IriRelativeStr::new("foo:").is_err());
    /// assert!(IriRelativeStr::new("foo:/").is_err());
    /// assert!(IriRelativeStr::new("foo://").is_err());
    /// assert!(IriRelativeStr::new("foo:///").is_err());
    /// assert!(IriRelativeStr::new("foo:////").is_err());
    /// assert!(IriRelativeStr::new("foo://///").is_err());
    /// ```
    ///
    /// Some characters and sequences cannot used in an IRI reference.
    ///
    /// ```
    /// # use iri_string::types::IriRelativeStr;
    /// // `<` and `>` cannot directly appear in a relative IRI reference.
    /// assert!(IriRelativeStr::new("<not allowed>").is_err());
    /// // Broken percent encoding cannot appear in a relative IRI reference.
    /// assert!(IriRelativeStr::new("%").is_err());
    /// assert!(IriRelativeStr::new("%GG").is_err());
    /// ```
    ///
    /// [RFC 3986]: https://www.rfc-editor.org/rfc/rfc3986.html
    /// [RFC 3987]: https://www.rfc-editor.org/rfc/rfc3987.html
    /// [`irelative-ref` rule]: https://www.rfc-editor.org/rfc/rfc3987.html#section-2.2
    /// [`relative-ref` rule]: https://www.rfc-editor.org/rfc/rfc3986.html#section-4.2
    struct RiRelativeStr {
        validator = relative_ref,
        expecting_msg = "Relative IRI reference string",
    }
}

#[cfg(feature = "alloc")]
define_custom_string_owned! {
    /// An owned string of a relative IRI reference.
    ///
    /// This corresponds to [`irelative-ref` rule] in [RFC 3987]
    /// (and [`relative-ref` rule] in [RFC 3986]).
    /// The rule for `irelative-ref` is `irelative-part [ "?" iquery ] [ "#" ifragment ]`.
    ///
    /// For details, see the document for [`RiRelativeStr`].
    ///
    /// Enabled by `alloc` or `std` feature.
    ///
    /// [RFC 3986]: https://www.rfc-editor.org/rfc/rfc3986.html
    /// [RFC 3987]: https://www.rfc-editor.org/rfc/rfc3987.html
    /// [`irelative-ref` rule]: https://www.rfc-editor.org/rfc/rfc3987.html#section-2.2
    /// [`relative-ref` rule]: https://www.rfc-editor.org/rfc/rfc3986.html#section-4.2
    /// [`RiRelativeString`]: struct.RiRelativeString.html
    struct RiRelativeString {
        validator = relative_ref,
        slice = RiRelativeStr,
        expecting_msg = "Relative IRI reference string",
    }
}

impl<S: Spec> RiRelativeStr<S> {
    /// Returns resolved IRI against the given base IRI.
    ///
    /// For IRI reference resolution output examples, see [RFC 3986 section 5.4].
    ///
    /// If you are going to resolve multiple references against the common base,
    /// consider using [`FixedBaseResolver`].
    ///
    /// # Strictness
    ///
    /// The IRI parsers provided by this crate is strict (e.g. `http:g` is
    /// always interpreted as a composition of the scheme `http` and the path
    /// `g`), so backward compatible parsing and resolution are not provided.
    /// About parser and resolver strictness, see [RFC 3986 section 5.4.2]:
    ///
    /// > Some parsers allow the scheme name to be present in a relative
    /// > reference if it is the same as the base URI scheme. This is considered
    /// > to be a loophole in prior specifications of partial URI
    /// > [RFC1630](https://www.rfc-editor.org/rfc/rfc1630.html). Its use should be
    /// > avoided but is allowed for backward compatibility.
    /// >
    /// > --- <https://www.rfc-editor.org/rfc/rfc3986.html#section-5.4.2>
    ///
    /// # Failures
    ///
    /// This method itself does not fail, but IRI resolution without WHATWG URL
    /// Standard serialization can fail in some minor cases.
    ///
    /// To see examples of such unresolvable IRIs, visit the documentation
    /// for [`normalize`][`crate::normalize`] module.
    ///
    /// [RFC 3986 section 5.4]: https://www.rfc-editor.org/rfc/rfc3986.html#section-5.4
    /// [RFC 3986 section 5.4.2]: https://www.rfc-editor.org/rfc/rfc3986.html#section-5.4.2
    pub fn resolve_against<'a>(&'a self, base: &'a RiAbsoluteStr<S>) -> Normalized<'a, RiStr<S>> {
        FixedBaseResolver::new(base).resolve(self.as_ref())
    }

    /// Returns the proxy to the IRI with password masking feature.
    ///
    /// # Examples
    ///
    /// ```
    /// # use iri_string::validate::Error;
    /// # #[cfg(feature = "alloc")] {
    /// use iri_string::format::ToDedicatedString;
    /// use iri_string::types::IriRelativeStr;
    ///
    /// let iri = IriRelativeStr::new("//user:password@example.com/path?query")?;
    /// let masked = iri.mask_password();
    /// assert_eq!(masked.to_dedicated_string(), "//user:@example.com/path?query");
    ///
    /// assert_eq!(
    ///     masked.replace_password("${password}").to_string(),
    ///     "//user:${password}@example.com/path?query"
    /// );
    /// # }
    /// # Ok::<_, Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub fn mask_password(&self) -> PasswordMasked<'_, Self> {
        PasswordMasked::new(self)
    }
}

/// Components getters.
impl<S: Spec> RiRelativeStr<S> {
    /// Returns the authority.
    ///
    /// The leading `//` is truncated.
    ///
    /// # Examples
    ///
    /// ```
    /// # use iri_string::validate::Error;
    /// use iri_string::types::IriRelativeStr;
    ///
    /// let iri = IriRelativeStr::new("//example.com/pathpath?queryquery#fragfrag")?;
    /// assert_eq!(iri.authority_str(), Some("example.com"));
    /// # Ok::<_, Error>(())
    /// ```
    ///
    /// ```
    /// # use iri_string::validate::Error;
    /// use iri_string::types::IriRelativeStr;
    ///
    /// let iri = IriRelativeStr::new("foo//bar:baz")?;
    /// assert_eq!(iri.authority_str(), None);
    /// # Ok::<_, Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub fn authority_str(&self) -> Option<&str> {
        trusted_parser::extract_authority_relative(self.as_str())
    }

    /// Returns the path.
    ///
    /// # Examples
    ///
    /// ```
    /// # use iri_string::validate::Error;
    /// use iri_string::types::IriRelativeStr;
    ///
    /// let iri = IriRelativeStr::new("//example.com/pathpath?queryquery#fragfrag")?;
    /// assert_eq!(iri.path_str(), "/pathpath");
    /// # Ok::<_, Error>(())
    /// ```
    ///
    /// ```
    /// # use iri_string::validate::Error;
    /// use iri_string::types::IriRelativeStr;
    ///
    /// let iri = IriRelativeStr::new("foo//bar:baz")?;
    /// assert_eq!(iri.path_str(), "foo//bar:baz");
    /// # Ok::<_, Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub fn path_str(&self) -> &str {
        trusted_parser::extract_path_relative(self.as_str())
    }

    /// Returns the query.
    ///
    /// The leading question mark (`?`) is truncated.
    ///
    /// # Examples
    ///
    /// ```
    /// # use iri_string::validate::Error;
    /// use iri_string::types::{IriQueryStr, IriRelativeStr};
    ///
    /// let iri = IriRelativeStr::new("//example.com/pathpath?queryquery#fragfrag")?;
    /// let query = IriQueryStr::new("queryquery")?;
    /// assert_eq!(iri.query(), Some(query));
    /// # Ok::<_, Error>(())
    /// ```
    ///
    /// ```
    /// # use iri_string::validate::Error;
    /// use iri_string::types::{IriQueryStr, IriRelativeStr};
    ///
    /// let iri = IriRelativeStr::new("foo//bar:baz?")?;
    /// let query = IriQueryStr::new("")?;
    /// assert_eq!(iri.query(), Some(query));
    /// # Ok::<_, Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub fn query(&self) -> Option<&RiQueryStr<S>> {
        trusted_parser::extract_query(self.as_str()).map(|query| {
            // SAFETY: `extract_query` returns the query part of an IRI, and the
            // returned string should have only valid characters since is the
            // substring of the source IRI.
            unsafe {
                RiQueryStr::new_unchecked_justified(
                    query,
                    "query in a valid relative IRI reference must also be valid",
                )
            }
        })
    }

    /// Returns the query in a raw string slice.
    ///
    /// The leading question mark (`?`) is truncated.
    ///
    /// # Examples
    ///
    /// ```
    /// # use iri_string::validate::Error;
    /// use iri_string::types::IriRelativeStr;
    ///
    /// let iri = IriRelativeStr::new("//example.com/pathpath?queryquery#fragfrag")?;
    /// assert_eq!(iri.query_str(), Some("queryquery"));
    /// # Ok::<_, Error>(())
    /// ```
    ///
    /// ```
    /// # use iri_string::validate::Error;
    /// use iri_string::types::IriRelativeStr;
    ///
    /// let iri = IriRelativeStr::new("foo//bar:baz?")?;
    /// assert_eq!(iri.query_str(), Some(""));
    /// # Ok::<_, Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub fn query_str(&self) -> Option<&str> {
        trusted_parser::extract_query(self.as_str())
    }

    /// Returns the fragment part if exists.
    ///
    /// A leading `#` character is truncated if the fragment part exists.
    ///
    /// # Examples
    ///
    /// If the IRI has a fragment part, `Some(_)` is returned.
    ///
    /// ```
    /// # use iri_string::{spec::IriSpec, types::{IriFragmentStr, IriRelativeStr}, validate::Error};
    /// let iri = IriRelativeStr::new("?foo#bar")?;
    /// let fragment = IriFragmentStr::new("bar")?;
    /// assert_eq!(iri.fragment(), Some(fragment));
    /// # Ok::<_, Error>(())
    /// ```
    ///
    /// ```
    /// # use iri_string::{spec::IriSpec, types::{IriFragmentStr, IriRelativeStr}, validate::Error};
    /// let iri = IriRelativeStr::new("#foo")?;
    /// let fragment = IriFragmentStr::new("foo")?;
    /// assert_eq!(iri.fragment(), Some(fragment));
    /// # Ok::<_, Error>(())
    /// ```
    ///
    /// When the fragment part exists but is empty string, `Some(_)` is returned.
    ///
    /// ```
    /// # use iri_string::{spec::IriSpec, types::{IriFragmentStr, IriRelativeStr}, validate::Error};
    /// let iri = IriRelativeStr::new("#")?;
    /// let fragment = IriFragmentStr::new("")?;
    /// assert_eq!(iri.fragment(), Some(fragment));
    /// # Ok::<_, Error>(())
    /// ```
    ///
    /// If the IRI has no fragment, `None` is returned.
    ///
    /// ```
    /// # use iri_string::{spec::IriSpec, types::IriRelativeStr, validate::Error};
    /// let iri = IriRelativeStr::new("")?;
    /// assert_eq!(iri.fragment(), None);
    /// # Ok::<_, Error>(())
    /// ```
    #[must_use]
    pub fn fragment(&self) -> Option<&RiFragmentStr<S>> {
        trusted_parser::extract_fragment(self.as_str()).map(|fragment| {
            // SAFETY: `extract_fragment` returns the fragment part of an IRI,
            // and the returned string should have only valid characters since
            // is the substring of the source IRI.
            unsafe {
                RiFragmentStr::new_unchecked_justified(
                    fragment,
                    "fragment in a valid relative IRI reference must also be valid",
                )
            }
        })
    }

    /// Returns the fragment part as a raw string slice if exists.
    ///
    /// A leading `#` character is truncated if the fragment part exists.
    ///
    /// # Examples
    ///
    /// If the IRI has a fragment part, `Some(_)` is returned.
    ///
    /// ```
    /// # use iri_string::{spec::IriSpec, types::IriRelativeStr, validate::Error};
    /// let iri = IriRelativeStr::new("?foo#bar")?;
    /// assert_eq!(iri.fragment_str(), Some("bar"));
    /// # Ok::<_, Error>(())
    /// ```
    ///
    /// ```
    /// # use iri_string::{spec::IriSpec, types::IriRelativeStr, validate::Error};
    /// let iri = IriRelativeStr::new("#foo")?;
    /// assert_eq!(iri.fragment_str(), Some("foo"));
    /// # Ok::<_, Error>(())
    /// ```
    ///
    /// When the fragment part exists but is empty string, `Some(_)` is returned.
    ///
    /// ```
    /// # use iri_string::{spec::IriSpec, types::IriRelativeStr, validate::Error};
    /// let iri = IriRelativeStr::new("#")?;
    /// assert_eq!(iri.fragment_str(), Some(""));
    /// # Ok::<_, Error>(())
    /// ```
    ///
    /// If the IRI has no fragment, `None` is returned.
    ///
    /// ```
    /// # use iri_string::{spec::IriSpec, types::IriRelativeStr, validate::Error};
    /// let iri = IriRelativeStr::new("")?;
    /// assert_eq!(iri.fragment(), None);
    /// # Ok::<_, Error>(())
    /// ```
    #[must_use]
    pub fn fragment_str(&self) -> Option<&str> {
        trusted_parser::extract_fragment(self.as_str())
    }

    /// Returns the authority components.
    ///
    /// # Examples
    ///
    /// ```
    /// # use iri_string::validate::Error;
    /// use iri_string::types::IriRelativeStr;
    ///
    /// let iri = IriRelativeStr::new("//user:pass@example.com:8080/pathpath?queryquery")?;
    /// let authority = iri.authority_components()
    ///     .expect("authority is available");
    /// assert_eq!(authority.userinfo(), Some("user:pass"));
    /// assert_eq!(authority.host(), "example.com");
    /// assert_eq!(authority.port(), Some("8080"));
    /// # Ok::<_, Error>(())
    /// ```
    ///
    /// ```
    /// # use iri_string::validate::Error;
    /// use iri_string::types::IriRelativeStr;
    ///
    /// let iri = IriRelativeStr::new("foo//bar:baz")?;
    /// assert_eq!(iri.authority_str(), None);
    /// # Ok::<_, Error>(())
    /// ```
    #[inline]
    #[must_use]
    pub fn authority_components(&self) -> Option<AuthorityComponents<'_>> {
        AuthorityComponents::from_iri(self.as_ref())
    }
}

#[cfg(feature = "alloc")]
impl<S: Spec> RiRelativeString<S> {
    /// Sets the fragment part to the given string.
    ///
    /// Removes fragment part (and following `#` character) if `None` is given.
    ///
    /// # Examples
    ///
    /// ```
    /// # use iri_string::validate::Error;
    /// # #[cfg(feature = "alloc")] {
    /// use iri_string::types::{IriFragmentStr, IriRelativeString};
    ///
    /// let mut iri = IriRelativeString::try_from("//user:password@example.com/path?query#frag.old")?;
    /// assert_eq!(iri.fragment_str(), Some("frag.old"));
    ///
    /// iri.set_fragment(None);
    /// assert_eq!(iri.fragment(), None);
    ///
    /// let frag_new = IriFragmentStr::new("frag-new")?;
    /// iri.set_fragment(Some(frag_new));
    /// assert_eq!(iri.fragment_str(), Some("frag-new"));
    /// # }
    /// # Ok::<_, Error>(())
    /// ```
    ///
    /// Fragment can be empty, and it is distinguished from the absense of a fragment.
    ///
    /// ```
    /// # use iri_string::validate::Error;
    /// # #[cfg(feature = "alloc")] {
    /// use iri_string::types::IriRelativeString;
    ///
    /// let mut iri = IriRelativeString::try_from("/path#")?;
    /// assert_eq!(iri, "/path#");
    /// assert_eq!(iri.fragment_str(), Some(""), "Fragment is present and empty");
    ///
    /// iri.set_fragment(None);
    /// assert_eq!(iri, "/path", "Note that # is now removed");
    /// assert_eq!(iri.fragment_str(), None, "Fragment is absent");
    /// # }
    /// # Ok::<_, Error>(())
    /// ```
    pub fn set_fragment(&mut self, fragment: Option<&RiFragmentStr<S>>) {
        raw::set_fragment(&mut self.inner, fragment.map(AsRef::as_ref));
        debug_assert_eq!(Self::validate(&self.inner), Ok(()));
    }

    /// Removes the password completely (including separator colon) from `self` even if it is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// # use iri_string::validate::Error;
    /// # #[cfg(feature = "alloc")] {
    /// use iri_string::types::IriRelativeString;
    ///
    /// let mut iri = IriRelativeString::try_from("//user:password@example.com/path?query")?;
    /// iri.remove_password_inline();
    /// assert_eq!(iri, "//user@example.com/path?query");
    /// # }
    /// # Ok::<_, Error>(())
    /// ```
    ///
    /// Even if the password is empty, the password and separator will be removed.
    ///
    /// ```
    /// # use iri_string::validate::Error;
    /// # #[cfg(feature = "alloc")] {
    /// use iri_string::types::IriRelativeString;
    ///
    /// let mut iri = IriRelativeString::try_from("//user:@example.com/path?query")?;
    /// iri.remove_password_inline();
    /// assert_eq!(iri, "//user@example.com/path?query");
    /// # }
    /// # Ok::<_, Error>(())
    /// ```
    pub fn remove_password_inline(&mut self) {
        let pw_range = match password_range_to_hide(self.as_slice().as_ref()) {
            Some(v) => v,
            None => return,
        };
        let separator_colon = pw_range.start - 1;
        // SAFETY: removing password component and the leading colon preserves
        // the IRI still syntactically valid.
        unsafe {
            let buf = self.as_inner_mut();
            buf.drain(separator_colon..pw_range.end);
            debug_assert_eq!(
                Self::validate(buf),
                Ok(()),
                "the IRI must be valid after the password component is removed"
            );
        }
    }

    /// Replaces the non-empty password in `self` to the empty password.
    ///
    /// This leaves the separator colon if the password part was available.
    ///
    /// # Examples
    ///
    /// ```
    /// # use iri_string::validate::Error;
    /// # #[cfg(feature = "alloc")] {
    /// use iri_string::types::IriRelativeString;
    ///
    /// let mut iri = IriRelativeString::try_from("//user:password@example.com/path?query")?;
    /// iri.remove_nonempty_password_inline();
    /// assert_eq!(iri, "//user:@example.com/path?query");
    /// # }
    /// # Ok::<_, Error>(())
    /// ```
    ///
    /// If the password is empty, it is left as is.
    ///
    /// ```
    /// # use iri_string::validate::Error;
    /// # #[cfg(feature = "alloc")] {
    /// use iri_string::types::IriRelativeString;
    ///
    /// let mut iri = IriRelativeString::try_from("//user:@example.com/path?query")?;
    /// iri.remove_nonempty_password_inline();
    /// assert_eq!(iri, "//user:@example.com/path?query");
    /// # }
    /// # Ok::<_, Error>(())
    /// ```
    pub fn remove_nonempty_password_inline(&mut self) {
        let pw_range = match password_range_to_hide(self.as_slice().as_ref()) {
            Some(v) if !v.is_empty() => v,
            _ => return,
        };
        debug_assert_eq!(
            self.as_str().as_bytes().get(pw_range.start - 1).copied(),
            Some(b':'),
            "the password component must be prefixed with a separator colon"
        );
        // SAFETY: the IRI must be valid after the password component is
        // replaced with the empty password.
        unsafe {
            let buf = self.as_inner_mut();
            buf.drain(pw_range);
            debug_assert_eq!(
                Self::validate(buf),
                Ok(()),
                "the IRI must be valid after the password component \
                 is replaced with the empty password"
            );
        }
    }

    /// Replaces the host in-place and returns the new host, if authority is not empty.
    ///
    /// If the IRI has no authority, returns `None` without doing nothing. Note
    /// that an empty host is distinguished from the absence of an authority.
    ///
    /// If the new host is invalid (i.e., [`validate::validate_host`][`crate::validate::host`]
    /// returns `Err(_)`), also returns `None` without doing anything.
    fn try_replace_host_impl(
        &mut self,
        new_host: &'_ str,
        replace_only_reg_name: bool,
    ) -> Result<Option<&str>, TryReserveError> {
        use crate::types::generic::replace_domain_impl;

        let result: Result<Option<core::ops::Range<usize>>, TryReserveError>;
        {
            // SAFETY: Replacing the (already existing) host part with another
            // valid host does not change the class of an IRI.
            let strbuf = unsafe { self.as_inner_mut() };
            result = replace_domain_impl::<S>(strbuf, new_host, replace_only_reg_name);
            debug_assert_eq!(
                RiRelativeStr::<S>::validate(strbuf),
                Ok(()),
                "replacing a host with another valid host must keep an IRI valid: raw={strbuf:?}",
            );
        }
        result.map(|opt| opt.map(|range| &self.as_str()[range]))
    }

    /// Replaces the host in-place and returns the new host, if authority is not empty.
    ///
    /// If the IRI has no authority, returns `None` without doing nothing. Note
    /// that an empty host is distinguished from the absence of an authority.
    ///
    /// If the new host is invalid (i.e., [`validate::validate_host`][`crate::validate::host`]
    /// returns `Err(_)`), also returns `None` without doing anything.
    ///
    /// If you need to replace only when the host is `reg-name` (for example
    /// when you attempt to apply IDNA encoding), use
    /// [`try_replace_host_reg_name`][`Self::try_replace_host_reg_name`] method
    /// instead.
    ///
    /// # Examples
    ///
    /// ```
    /// # use iri_string::types::UriRelativeString;
    /// let mut iri =
    ///     UriRelativeString::try_from("//user:pass@example.com:443/").unwrap();
    /// let new_host_opt = iri.replace_host("www.example.com");
    /// assert_eq!(new_host_opt, Some("www.example.com"));
    /// assert_eq!(iri.authority_components().unwrap().host(), "www.example.com");
    /// assert_eq!(iri, "//user:pass@www.example.com:443/");
    /// ```
    pub fn replace_host(&mut self, new_host: &'_ str) -> Option<&str> {
        self.try_replace_host(new_host)
            .expect("failed to allocate memory when replacing the host part of an IRI")
    }

    /// Replaces the host in-place and returns the new host, if authority is not empty.
    ///
    /// This returns `TryReserveError` on memory allocation failure, instead of
    /// panicking. Otherwise, this method behaves same as
    /// [`replace_host`][`Self::replace_host`] method.
    pub fn try_replace_host(&mut self, new_host: &'_ str) -> Result<Option<&str>, TryReserveError> {
        self.try_replace_host_impl(new_host, false)
    }

    /// Replaces the domain name (`reg-name`) in-place and returns the new host,
    /// if authority is not empty.
    ///
    /// If the IRI has no authority or the host is not a reg-name (i.e., is
    /// neither an IP-address nor empty), returns `None` without doing nothing.
    /// Note that an empty host is distinguished from the absence of an authority.
    ///
    /// If the new host is invalid (i.e., [`validate::validate_host`][`crate::validate::host`]
    /// returns `Err(_)`), also returns `None` without doing anything.
    ///
    /// # Examples
    ///
    /// ```
    /// # use iri_string::types::UriRelativeString;
    /// let mut iri =
    ///     UriRelativeString::try_from("//user:pass@example.com:443/").unwrap();
    /// let new_host_opt = iri.replace_host("www.example.com");
    /// assert_eq!(new_host_opt, Some("www.example.com"));
    /// assert_eq!(iri.authority_components().unwrap().host(), "www.example.com");
    /// assert_eq!(iri, "//user:pass@www.example.com:443/");
    /// ```
    ///
    /// ```
    /// # use iri_string::types::UriRelativeString;
    /// let mut iri =
    ///     UriRelativeString::try_from("//192.168.0.1/").unwrap();
    /// let new_host_opt = iri.replace_host_reg_name("localhost");
    /// assert_eq!(new_host_opt, None, "IPv4 address is not a reg-name");
    /// assert_eq!(iri, "//192.168.0.1/", "won't be changed");
    /// ```
    ///
    /// To apply IDNA conversion, get the domain by [`AuthorityComponents::reg_name`]
    /// method, convert the domain, and then set it by this
    /// `replace_host_reg_name` method.
    ///
    /// ```
    /// # extern crate alloc;
    /// # use alloc::string::String;
    /// # use iri_string::types::IriRelativeString;
    /// /// Converts the given into IDNA encoding.
    /// fn conv_idna(domain: &str) -> String {
    ///     /* ... */
    /// #   if domain == "\u{03B1}.example.com" {
    /// #       "xn--mxa.example.com".into()
    /// #   } else {
    /// #       unimplemented!()
    /// #   }
    /// }
    ///
    /// // U+03B1: GREEK SMALL LETTER ALPHA
    /// let mut iri =
    ///     IriRelativeString::try_from("//\u{03B1}.example.com/").unwrap();
    ///
    /// let old_domain = iri
    ///     .authority_components()
    ///     .expect("authority is not empty")
    ///     .reg_name()
    ///     .expect("the host is reg-name");
    /// assert_eq!(old_domain, "\u{03B1}.example.com");
    ///
    /// // Get the new host by your own.
    /// let new_domain: String = conv_idna(old_domain);
    /// assert_eq!(new_domain, "xn--mxa.example.com");
    ///
    /// let new_host_opt = iri.replace_host(&new_domain);
    /// assert_eq!(new_host_opt, Some("xn--mxa.example.com"));
    /// assert_eq!(iri.authority_components().unwrap().host(), "xn--mxa.example.com");
    /// assert_eq!(iri, "//xn--mxa.example.com/");
    /// ```
    pub fn replace_host_reg_name(&mut self, new_host: &'_ str) -> Option<&str> {
        self.try_replace_host_reg_name(new_host)
            .expect("failed to allocate memory when replacing the host part of an IRI")
    }

    /// Replaces the domain name (`reg-name`) in-place and returns the new host,
    /// if authority is not empty.
    ///
    /// This returns `TryReserveError` on memory allocation failure, instead of
    /// panicking. Otherwise, this method behaves same as
    /// [`replace_host_reg_name`][`Self::replace_host_reg_name`] method.
    pub fn try_replace_host_reg_name(
        &mut self,
        new_host: &'_ str,
    ) -> Result<Option<&str>, TryReserveError> {
        self.try_replace_host_impl(new_host, true)
    }
}

impl_trivial_conv_between_iri! {
    from_slice: RiRelativeStr,
    from_owned: RiRelativeString,
    to_slice: RiReferenceStr,
    to_owned: RiReferenceString,
}
