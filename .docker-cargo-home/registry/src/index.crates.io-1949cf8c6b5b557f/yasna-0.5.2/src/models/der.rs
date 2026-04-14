// Copyright 2017 Fortanix, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use alloc::vec::Vec;
use super::super::{PCBit, Tag};
use super::super::tags::*;

/// Container for a tag and arbitrary DER value.
///
/// When obtained by `BERReader::read_tagged_der` in DER mode,
/// the reader verifies that the payload is actually valid DER.
/// When constructed from bytes, the caller is responsible for
/// providing valid DER.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TaggedDerValue {
    tag: Tag,
    pcbit: PCBit,
    value: Vec<u8>,
}

impl TaggedDerValue {
    /// Constructs a new `TaggedDerValue` as an octet string
    pub fn from_octetstring(bytes: Vec<u8>) -> Self {
        TaggedDerValue {
            tag: TAG_OCTETSTRING,
            pcbit: PCBit::Primitive,
            value: bytes,
        }
    }

    /// Constructs a new `TaggedDerValue` from its tag and content
    pub fn from_tag_and_bytes(tag: Tag, bytes: Vec<u8>) -> Self {
        let pcbit = match tag {
            TAG_SEQUENCE | TAG_SET => PCBit::Constructed,
            _ => PCBit::Primitive,
        };
        TaggedDerValue {
            tag,
            pcbit,
            value: bytes,
        }
    }

    /// Constructs a new `TaggedDerValue` from its tag,
    /// primitive/constructed bit, and content
    pub fn from_tag_pc_and_bytes(tag: Tag, pcbit: PCBit, bytes: Vec<u8>) -> Self {
        TaggedDerValue {
            tag,
            pcbit,
            value: bytes,
        }
    }

    /// Returns the tag
    pub fn tag(&self) -> Tag {
        self.tag
    }

    /// Returns the primitive/constructed bit
    pub fn pcbit(&self) -> PCBit {
        self.pcbit
    }

    /// Returns the value
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// If the value is something that contains raw bytes,
    /// returns its content.
    ///
    /// # Examples
    /// ```
    /// use yasna::models::TaggedDerValue;
    /// let value = TaggedDerValue::from_octetstring(vec![1, 2, 3, 4, 5, 6]);
    /// assert!(value.as_bytes() == Some(&[1, 2, 3, 4, 5, 6]));
    /// ```
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match (self.tag, self.pcbit) {
            (TAG_BITSTRING, PCBit::Primitive) => {
                // First byte of bitstring value is number of unused bits.
                // We only accept bitstrings that are multiples of bytes.
                if let Some(&0) = self.value.first() {
                    Some(&self.value[1..])
                } else {
                    None
                }
            },
            (TAG_OCTETSTRING, PCBit::Primitive) => Some(&self.value),
            _ => None
        }
    }

    /// If the value is something string-like, returns it as string.
    pub fn as_str(&self) -> Option<&str> {
        use alloc::str::from_utf8;

        match (self.tag, self.pcbit) {
            (TAG_IA5STRING, PCBit::Primitive) => from_utf8(&self.value).ok(),
            (TAG_PRINTABLESTRING, PCBit::Primitive) => from_utf8(&self.value).ok(),
            (TAG_UTF8STRING, PCBit::Primitive) => from_utf8(&self.value).ok(),
            _ => None
        }
    }
}
