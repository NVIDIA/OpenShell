//! Generic resource identifier types.
//!
//! ```text
//! IRI           = scheme ":" ihier-part [ "?" iquery ] [ "#" ifragment ]
//! IRI-reference = IRI / irelative-ref
//! absolute-IRI  = scheme ":" ihier-part [ "?" iquery ]
//! irelative-ref = irelative-part [ "?" iquery ] [ "#" ifragment ]
//!     (`irelative-part` is roughly same as `ihier-part`.)
//! ```
//!
//! Hierarchy:
//!
//! ```text
//! RiReferenceStr
//! |-- RiStr
//! |   `-- RiAbsoluteStr
//! `-- RiRelativeStr
//! ```
//!
//! Therefore, the conversions below are safe and cheap:
//!
//! * `RiStr -> RiReferenceStr`
//! * `RiAbsoluteStr -> RiStr`
//! * `RiAbsoluteStr -> RiReferenceStr`
//! * `RiRelativeStr -> RiReferenceStr`
//!
//! For safely convertible types (consider `FooStr -> BarStr` is safe), traits
//! below are implemented:
//!
//! * `AsRef<BarStr> for FooStr`
//! * `AsRef<BarStr> for FooString`
//! * `From<FooString> for BarString`
//! * `PartialEq<FooStr> for BarStr` and lots of impls like that
//!     + `PartialEq` and `ParitalOrd`.
//!     + Slice, owned, `Cow`, reference, etc...
//!
//! # IDNA encoding
//!
//! This crate does not have built-in IDNA converter, but the user can provide
//! such conversion function and replace the domain part of IRIs.
//!
//! ## Slice IRI types
//!
//! 1. Get host by `authority_components()?.host()`.
//! 2. Process the name.
//! 3. Create a builder by `Builder::from(&...)`.
//! 4. Overwrite the domain by `.host(...)`.
//! 5. Build the new IRI by `.build()`.
//!
//! ```
//! # #[cfg(feature = "alloc")] extern crate alloc;
//! # #[cfg(feature = "alloc")] use alloc::string::ToString;
//! use iri_string::build::Builder;
//! use iri_string::types::{IriStr, UriStr};
//!
//! struct IdnaEncodedDomain<'a> {
//!     /* ... */
//! #   raw: &'a str,
//! }
//! impl IdnaEncodedDomain<'_> {
//!     pub fn as_str(&self) -> &str {
//!         /* ... */
//! #       match self.raw {
//! #           "alpha.\u{03B1}.example.com" => "alpha.xn--mxa.example.com",
//! #           _ => unimplemented!(),
//! #       }
//!     }
//! }
//! // Usually IDNA conversion requires dynamic memory allocation, but
//! // `iri-string` itself does not require or assume that. It is enough if the
//! // conversion result can be retrieved as `&str`, so users can do whatever
//! // such as limiting the possible input and/or using statically allocated buffer.
//! fn apply_idna(s: &str) -> IdnaEncodedDomain<'_> {
//!     /* ... */
//! #   IdnaEncodedDomain { raw: s }
//! }
//!
//! let orig_iri = IriStr::new("https://alpha.\u{03B1}.example.com").unwrap();
//!
//! // 1. Get the host.
//! let orig_host = orig_iri.authority_components()
//!     .expect("orig_iri has a host")
//!     .host();
//! debug_assert_eq!(orig_host, "alpha.\u{03B1}.example.com");
//!
//! // 2. Process the name.
//! let new_domain = apply_idna(orig_host);
//!
//! // 3. Create a builder.
//! let mut builder = Builder::from(orig_iri);
//!
//! // 4. Overwrite the domain.
//! builder.host(new_domain.as_str());
//!
//! // 5. Build the new IRI.
//! let new_iri = builder.build::<UriStr>()
//!     .expect("the new host is a valid domain and now they are US-ASCII only");
//!
//! // Note that `ToString::to_string()` requires `alloc` feature.
//! #[cfg(feature = "alloc")]
//! debug_assert_eq!(new_iri.to_string(), "https://alpha.xn--mxa.example.com");
//! ```
//!
//! ## Allocated IRI types
//!
//! For allocated types such as `IriString`, you can use
//! `{,try_}replace_host{,_reg_name}` methods.
//!
//! 1. Get host by `authority_components()?.host()`.
//! 2. Process the name.
//! 3. Replace the host by the new result.
//!
//! ```
//! # #[cfg(feature = "alloc")] {
//! # extern crate alloc;
//! # use alloc::string::String;
//! use iri_string::types::IriString;
//!
//! fn apply_idna(s: &str) -> String {
//!     /* ... */
//! #   match s {
//! #       "alpha.\u{03B1}.example.com" => "alpha.xn--mxa.example.com".to_owned(),
//! #       _ => unimplemented!(),
//! #   }
//! }
//!
//! let mut iri =
//!     IriString::try_from("https://alpha.\u{03B1}.example.com")
//!         .unwrap();
//!
//! // 1. Get the host.
//! let orig_host = iri.authority_components()
//!     .expect("orig_iri has a host")
//!     .host();
//! debug_assert_eq!(orig_host, "alpha.\u{03B1}.example.com");
//!
//! // 2. Process the name.
//! let new_domain = apply_idna(orig_host);
//!
//! // 3. Replace the host.
//! iri.replace_host(&new_domain);
//! debug_assert_eq!(iri, "https://alpha.xn--mxa.example.com");
//! # }
//! ```

pub use self::{
    absolute::RiAbsoluteStr, fragment::RiFragmentStr, normal::RiStr, query::RiQueryStr,
    reference::RiReferenceStr, relative::RiRelativeStr,
};
#[cfg(feature = "alloc")]
pub use self::{
    absolute::RiAbsoluteString, error::CreationError, fragment::RiFragmentString, normal::RiString,
    query::RiQueryString, reference::RiReferenceString, relative::RiRelativeString,
};

#[macro_use]
mod macros;

mod absolute;
#[cfg(feature = "alloc")]
mod error;
mod fragment;
mod normal;
mod query;
mod reference;
mod relative;

/// Replaces the host in-place and returns the range of the new host, if authority is not empty.
///
/// If the IRI has no authority, returns `None` without doing nothing. Note
/// that an empty host is distinguished from the absence of an authority.
///
/// If the new host is invalid (i.e., [`validate::validate_host`][`crate::validate::host`]
/// returns `Err(_)`), also returns `None` without doing anything.
#[cfg(feature = "alloc")]
fn replace_domain_impl<S: crate::spec::Spec>(
    iri_ref: &mut alloc::string::String,
    new_host: &str,
    replace_only_reg_name: bool,
) -> Result<Option<core::ops::Range<usize>>, alloc::collections::TryReserveError> {
    use crate::components::AuthorityComponents;
    use crate::parser::trusted as trusted_parser;
    use crate::parser::validate::validate_host;

    // Validation of `new_host` needs some parsing, so do this authority
    // presence first to avoid that cost when possible. Extracting authority
    // should be faster because it essentially checks the length of the
    // scheme (which is known to be valid if available) and the presence of
    // the fixed string `://`.
    let (old_host, host_start) = match AuthorityComponents::from_iri_get_offset(iri_ref) {
        Some((authority, offset)) => (authority.host(), offset + authority.host_start),
        None => return Ok(None),
    };
    let old_host_end = host_start + old_host.len();

    if validate_host::<S>(new_host).is_err() {
        return Ok(None);
    }

    if replace_only_reg_name && !trusted_parser::authority::is_host_reg_name(old_host) {
        // Host in the IRI is not a reg-name. Avoid replacing.
        return Ok(None);
    }

    if let Some(additional) = new_host.len().checked_sub(old_host.len()) {
        iri_ref.try_reserve(additional)?;
    }
    iri_ref.replace_range(host_start..old_host_end, new_host);

    let new_host_end = host_start + new_host.len();
    Ok(Some(host_start..new_host_end))
}
