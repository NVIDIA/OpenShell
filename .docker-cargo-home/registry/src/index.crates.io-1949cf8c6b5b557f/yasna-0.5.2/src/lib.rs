// Copyright 2016 Masaki Hara
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! A library for reading and writing ASN.1 data.
//!
//! # Examples
//!
//! ## Encoding/decoding simple data
//!
//! A type implementing [`DEREncodable`] can be easily encoded:
//!
//! ```
//! fn main() {
//!     let der = yasna::encode_der(&(10, true));
//!     println!("(10, true) = {:?}", der);
//! }
//! ```
//!
//! Similarly, a type implementing [`BERDecodable`] can be
//! easily decoded:
//!
//! ```
//! fn main() {
//!     let asn: (i64, bool) = yasna::decode_der(
//!         &[48, 6, 2, 1, 10, 1, 1, 255]).unwrap();
//!     println!("{:?} = [48, 6, 2, 1, 10, 1, 1, 255]", asn);
//! }
//! ```
//!
//! ## Encoding/decoding by hand
//!
//! The default [`DEREncodable`]/[`BERDecodable`] implementations can't handle
//! all ASN.1 types. In many cases you have to write your reader/writer
//! by hand.
//!
//! To serialize ASN.1 data, you can use [`construct_der`].
//!
//! ```
//! fn main() {
//!     let der = yasna::construct_der(|writer| {
//!         writer.write_sequence(|writer| {
//!             writer.next().write_i64(10);
//!             writer.next().write_bool(true);
//!         })
//!     });
//!     println!("(10, true) = {:?}", der);
//! }
//! ```
//!
//! To deserialize ASN.1 data, you can use [`parse_ber`] or [`parse_der`].
//!
//! ```
//! fn main() {
//!     let asn = yasna::parse_der(&[48, 6, 2, 1, 10, 1, 1, 255], |reader| {
//!         reader.read_sequence(|reader| {
//!             let i = reader.next().read_i64()?;
//!             let b = reader.next().read_bool()?;
//!             return Ok((i, b));
//!         })
//!     }).unwrap();
//!     println!("{:?} = [48, 6, 2, 1, 10, 1, 1, 255]", asn);
//! }
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![no_std]

extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate std;

pub mod tags;
pub mod models;
mod writer;
mod reader;
mod deserializer;
mod serializer;

pub use crate::writer::{construct_der,try_construct_der};
pub use crate::writer::{construct_der_seq,try_construct_der_seq};
pub use crate::writer::{DERWriter,DERWriterSeq,DERWriterSet};
pub use crate::reader::{parse_ber_general,parse_ber,parse_der,BERMode};
pub use crate::reader::{BERReader,BERReaderSeq,BERReaderSet};
pub use crate::reader::{ASN1Error,ASN1ErrorKind,ASN1Result};
pub use crate::deserializer::{BERDecodable,decode_ber_general,decode_ber,decode_der};
pub use crate::serializer::{DEREncodable,encode_der};

/// A value of the ASN.1 primitive/constructed ("P/C") bit.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum PCBit {
    /// The bit's value is "Primitive"
    Primitive = 0,
    /// The bit's value is "Constructed"
    Constructed = 1,
}

/// An ASN.1 tag class, used in [`Tag`].
///
/// A tag class is one of:
///
/// - UNIVERSAL
/// - APPLICATION
/// - context specific
/// - PRIVATE
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum TagClass {
    /// The UNIVERSAL tag class
    Universal = 0,
    /// The APPLICATION tag class
    Application = 1,
    /// The CONTEXT-SPECIFIC tag class
    ContextSpecific = 2,
    /// The PRIVATE tag class
    Private = 3,
}

const TAG_CLASSES : [TagClass; 4] = [
    TagClass::Universal,
    TagClass::Application,
    TagClass::ContextSpecific,
    TagClass::Private,
];

/// An ASN.1 tag.
///
/// An ASN.1 tag is a pair of a tag class and a tag number.
///
/// - A tag class is one of:
///   - UNIVERSAL
///   - APPLICATION
///   - context specific
///   - PRIVATE
/// - A tag number is a nonnegative integer.
///   In this library, tag numbers are assumed to fit into `u64`.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Tag {
    /// The tag class
    pub tag_class: TagClass,
    /// The tag number
    pub tag_number: u64,
}

impl Tag {
    /// Constructs an APPLICATION tag, namely \[APPLICATION n\].
    pub fn application(tag_number: u64) -> Tag {
        return Tag {
            tag_class: TagClass::Application,
            tag_number,
        }
    }
    /// Constructs a context specific tag, namely \[n\].
    pub fn context(tag_number: u64) -> Tag {
        return Tag {
            tag_class: TagClass::ContextSpecific,
            tag_number,
        }
    }
    /// Constructs a PRIVATE tag, namely \[PRIVATE n\].
    pub fn private(tag_number: u64) -> Tag {
        return Tag {
            tag_class: TagClass::Private,
            tag_number,
        }
    }
}
