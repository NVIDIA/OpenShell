//! IRI specs.

use core::fmt;

// Note that this MUST be private module.
// See <https://rust-lang.github.io/api-guidelines/future-proofing.html> about
// sealed trait.
mod internal;

/// A trait for spec types.
///
/// This trait is not intended to be implemented by crate users.
// Note that all types which implement `Spec` also implement `SpecInternal`.
pub trait Spec: internal::Sealed + Copy + fmt::Debug {}

/// A type that represents specification of IRI.
///
/// About IRI, see [RFC 3987].
///
/// [RFC 3987]: https://www.rfc-editor.org/rfc/rfc3987.html
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IriSpec {}

impl Spec for IriSpec {}

/// A type that represents specification of URI.
///
/// About URI, see [RFC 3986].
///
/// [RFC 3986]: https://www.rfc-editor.org/rfc/rfc3986.html
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UriSpec {}

impl Spec for UriSpec {}
