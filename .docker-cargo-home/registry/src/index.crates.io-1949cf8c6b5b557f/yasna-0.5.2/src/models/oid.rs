// Copyright 2016 Masaki Hara
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use core::fmt::{self, Display};
#[cfg(feature = "std")]
use std::error::Error;
use alloc::str::FromStr;
use alloc::vec::Vec;

/// A type that represents object identifiers.
///
/// This is actually a thin wrapper of `Vec<u64>`.
///
/// # Examples
///
/// ```
/// use yasna::models::ObjectIdentifier;
/// let sha384WithRSAEncryption = ObjectIdentifier::from_slice(&
///     [1, 2, 840, 113549, 1, 1, 12]);
/// println!("{}", sha384WithRSAEncryption);
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ObjectIdentifier {
    components: Vec<u64>,
}

impl ObjectIdentifier {
    /// Constructs a new `ObjectIdentifier` from `Vec<u64>`.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna::models::ObjectIdentifier;
    /// let pkcs1 = ObjectIdentifier::new(
    ///     [1, 2, 840, 113549, 1, 1].to_vec());
    /// println!("{}", pkcs1);
    /// ```
    pub fn new(components: Vec<u64>) -> Self {
        return ObjectIdentifier {
            components,
        };
    }

    /// Constructs a new `ObjectIdentifier` from `&[u64]`.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna::models::ObjectIdentifier;
    /// let pkcs1 = ObjectIdentifier::from_slice(&
    ///     [1, 2, 840, 113549, 1, 1]);
    /// println!("{}", pkcs1);
    /// ```
    pub fn from_slice(components: &[u64]) -> Self {
        return ObjectIdentifier {
            components: components.to_vec(),
        };
    }

    /// Borrows its internal vector of components.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna::models::ObjectIdentifier;
    /// let pkcs1 = ObjectIdentifier::from_slice(&
    ///     [1, 2, 840, 113549, 1, 1]);
    /// let components : &Vec<u64> = pkcs1.components();
    /// ```
    pub fn components(&self) -> &Vec<u64> {
        &self.components
    }

    /// Mutably borrows its internal vector of components.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna::models::ObjectIdentifier;
    /// let mut pkcs1 = ObjectIdentifier::from_slice(&
    ///     [1, 2, 840, 113549, 1, 1]);
    /// let components : &mut Vec<u64> = pkcs1.components_mut();
    /// ```
    pub fn components_mut(&mut self) -> &mut Vec<u64> {
        &mut self.components
    }

    /// Extracts its internal vector of components.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna::models::ObjectIdentifier;
    /// let pkcs1 = ObjectIdentifier::from_slice(&
    ///     [1, 2, 840, 113549, 1, 1]);
    /// let mut components : Vec<u64> = pkcs1.into_components();
    /// ```
    pub fn into_components(self) -> Vec<u64> {
        self.components
    }
}

impl Display for ObjectIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let mut fst = true;
        for &component in &self.components {
            if fst {
                write!(f, "{}", component)?;
            } else {
                write!(f, ".{}", component)?;
            }
            fst = false;
        }
        return Ok(());
    }
}

#[derive(Debug, Clone)]
/// An error indicating failure to parse an Object identifier
pub struct ParseOidError(());

#[cfg(feature = "std")]
impl Error for ParseOidError {}

impl Display for ParseOidError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.write_str("Failed to parse OID")
    }
}


impl FromStr for ObjectIdentifier {
    type Err = ParseOidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.split(".")
            .map(|s| s.parse().map_err(|_| ParseOidError(()) ))
            .collect::<Result<_, _>>()
            .map(ObjectIdentifier::new)
    }
}

impl AsRef<[u64]> for ObjectIdentifier {
    fn as_ref(&self) -> &[u64] {
        &self.components
    }
}

impl From<Vec<u64>> for ObjectIdentifier {
    fn from(components: Vec<u64>) -> ObjectIdentifier {
        Self::new(components)
    }
}

#[test]
fn test_display_oid() {
    use alloc::format;
    let pkcs1 = ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1]);
    assert_eq!(format!("{}", pkcs1), "1.2.840.113549.1.1");
}

#[test]
fn parse_oid() {
    assert_eq!("1.2.840.113549.1.1".parse::<ObjectIdentifier>().unwrap().components(), &[1, 2, 840, 113549, 1, 1]);
    "1.2.840.113549.1.1.".parse::<ObjectIdentifier>().unwrap_err();
    "1.2.840.113549.1.1x".parse::<ObjectIdentifier>().unwrap_err();
    "".parse::<ObjectIdentifier>().unwrap_err();
}
