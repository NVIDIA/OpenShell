// Copyright 2016 Masaki Hara
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![forbid(missing_docs)]

use alloc::vec::Vec;
use alloc::string::String;

#[cfg(feature = "num-bigint")]
use num_bigint::{BigInt,BigUint};
#[cfg(feature = "bit-vec")]
use bit_vec::BitVec;

use super::{DERWriter,construct_der};
use super::models::ObjectIdentifier;
#[cfg(feature = "time")]
use super::models::{UTCTime,GeneralizedTime};

/// Types encodable in DER.
///
/// # Examples
///
/// ```
/// use yasna;
/// let der = yasna::encode_der::<i64>(&65535);
/// assert_eq!(&der, &[2, 3, 0, 255, 255]);
/// ```
///
/// # Limitations
///
/// Rust types don't correspond to ASN.1 types one-to-one. Not all kinds
/// of ASN.1 types can be encoded via default `DEREncodable` implementation.
///
/// If you want to encode ASN.1, you may implement `DEREncodable` for your
/// own types or use [`construct_der`].
///
/// # Default implementations
///
/// - The encoder for `Vec<T>`/`[T]` is implemented as SEQUENCE OF encoder.
/// - `()` as NULL encoder.
/// - Tuples (except `()`) as SEQUENCE encoder.
/// - `Vec<u8>`/`[u8]` as OCTETSTRING encoder.
/// - `BitVec` as BITSTRING encoder.
/// - `String`/`str` as UTF8String encoder.
/// - `i64`, `u64`, `i32`, `u32`, `i16`, `u16`, `BigInt`, `BigUint`
///   as INTEGER encoder. (`u8` is avoided because of confliction.)
/// - `bool` as BOOLEAN encoder.
/// - `ObjectIdentifier` as OBJECTT IDENTIFIER encoder.
/// - `UTCTime`/`GeneralizedTime` as UTCTime/GeneralizedTime encoder.
pub trait DEREncodable {
    /// Writes the value as an DER-encoded ASN.1 value.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna::{DEREncodable,DERWriter};
    /// struct Entry {
    ///     name: String,
    ///     age: i64,
    /// }
    ///
    /// impl DEREncodable for Entry {
    ///     fn encode_der(&self, writer: DERWriter) {
    ///         writer.write_sequence(|writer| {
    ///             writer.next().write_visible_string(&self.name);
    ///             writer.next().write_i64(self.age);
    ///         })
    ///     }
    /// }
    /// fn main() {
    ///     let entry = Entry {
    ///         name: String::from("John"),
    ///         age: 32,
    ///     };
    ///     let der = yasna::encode_der(&entry);
    ///     assert_eq!(&der, &[48, 9, 26, 4, 74, 111, 104, 110, 2, 1, 32]);
    /// }
    /// ```
    fn encode_der<'a>(&self, writer: DERWriter<'a>);
}

/// Encodes a value to DER-encoded ASN.1 data.
pub fn encode_der<T:DEREncodable>(value: &T) -> Vec<u8> {
    construct_der(|writer| {
        value.encode_der(writer)
    })
}

impl<T> DEREncodable for Vec<T> where T: DEREncodable {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            for elem in self.iter() {
                elem.encode_der(writer.next());
            }
        })
    }
}

impl<T> DEREncodable for [T] where T: DEREncodable {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            for elem in self.iter() {
                elem.encode_der(writer.next());
            }
        })
    }
}

impl DEREncodable for i64 {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_i64(*self)
    }
}

impl DEREncodable for u64 {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_u64(*self)
    }
}

impl DEREncodable for i32 {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_i32(*self)
    }
}

impl DEREncodable for u32 {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_u32(*self)
    }
}

impl DEREncodable for i16 {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_i16(*self)
    }
}

impl DEREncodable for u16 {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_u16(*self)
    }
}

#[cfg(feature = "num-bigint")]
impl DEREncodable for BigInt {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_bigint(self)
    }
}

#[cfg(feature = "num-bigint")]
impl DEREncodable for BigUint {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_biguint(self)
    }
}

impl DEREncodable for bool {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_bool(*self)
    }
}

#[cfg(feature = "bit-vec")]
impl DEREncodable for BitVec {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_bitvec(self)
    }
}

impl DEREncodable for Vec<u8> {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_bytes(self)
    }
}

impl DEREncodable for [u8] {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_bytes(self)
    }
}

impl DEREncodable for String {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_utf8string(self)
    }
}

impl DEREncodable for str {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_utf8string(self)
    }
}

impl DEREncodable for ObjectIdentifier {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_oid(self)
    }
}

#[cfg(feature = "time")]
impl DEREncodable for UTCTime {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_utctime(self)
    }
}

#[cfg(feature = "time")]
impl DEREncodable for GeneralizedTime{
    fn encode_der(&self, writer: DERWriter) {
        writer.write_generalized_time(self)
    }
}

impl DEREncodable for () {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_null()
    }
}

impl<T0> DEREncodable for (T0,) where T0: DEREncodable {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            self.0.encode_der(writer.next());
        })
    }
}

impl<T0, T1> DEREncodable for (T0, T1)
        where T0: DEREncodable, T1: DEREncodable {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            self.0.encode_der(writer.next());
            self.1.encode_der(writer.next());
        })
    }
}

impl<T0, T1, T2> DEREncodable for (T0, T1, T2)
        where T0: DEREncodable, T1: DEREncodable, T2: DEREncodable {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            self.0.encode_der(writer.next());
            self.1.encode_der(writer.next());
            self.2.encode_der(writer.next());
        })
    }
}

impl<T0, T1, T2, T3> DEREncodable for (T0, T1, T2, T3)
        where T0: DEREncodable, T1: DEREncodable, T2: DEREncodable,
            T3: DEREncodable {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            self.0.encode_der(writer.next());
            self.1.encode_der(writer.next());
            self.2.encode_der(writer.next());
            self.3.encode_der(writer.next());
        })
    }
}

impl<T0, T1, T2, T3, T4> DEREncodable for (T0, T1, T2, T3, T4)
        where T0: DEREncodable, T1: DEREncodable, T2: DEREncodable,
            T3: DEREncodable, T4: DEREncodable {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            self.0.encode_der(writer.next());
            self.1.encode_der(writer.next());
            self.2.encode_der(writer.next());
            self.3.encode_der(writer.next());
            self.4.encode_der(writer.next());
        })
    }
}

impl<T0, T1, T2, T3, T4, T5> DEREncodable for (T0, T1, T2, T3, T4, T5)
        where T0: DEREncodable, T1: DEREncodable, T2: DEREncodable,
            T3: DEREncodable, T4: DEREncodable, T5: DEREncodable {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            self.0.encode_der(writer.next());
            self.1.encode_der(writer.next());
            self.2.encode_der(writer.next());
            self.3.encode_der(writer.next());
            self.4.encode_der(writer.next());
            self.5.encode_der(writer.next());
        })
    }
}

impl<T0, T1, T2, T3, T4, T5, T6> DEREncodable for (T0, T1, T2, T3, T4, T5, T6)
        where T0: DEREncodable, T1: DEREncodable, T2: DEREncodable,
            T3: DEREncodable, T4: DEREncodable, T5: DEREncodable,
            T6: DEREncodable {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            self.0.encode_der(writer.next());
            self.1.encode_der(writer.next());
            self.2.encode_der(writer.next());
            self.3.encode_der(writer.next());
            self.4.encode_der(writer.next());
            self.5.encode_der(writer.next());
            self.6.encode_der(writer.next());
        })
    }
}

impl<T0, T1, T2, T3, T4, T5, T6, T7> DEREncodable
        for (T0, T1, T2, T3, T4, T5, T6, T7)
        where T0: DEREncodable, T1: DEREncodable, T2: DEREncodable,
            T3: DEREncodable, T4: DEREncodable, T5: DEREncodable,
            T6: DEREncodable, T7: DEREncodable {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            self.0.encode_der(writer.next());
            self.1.encode_der(writer.next());
            self.2.encode_der(writer.next());
            self.3.encode_der(writer.next());
            self.4.encode_der(writer.next());
            self.5.encode_der(writer.next());
            self.6.encode_der(writer.next());
            self.7.encode_der(writer.next());
        })
    }
}

impl<T0, T1, T2, T3, T4, T5, T6, T7, T8> DEREncodable
        for (T0, T1, T2, T3, T4, T5, T6, T7, T8)
        where T0: DEREncodable, T1: DEREncodable, T2: DEREncodable,
            T3: DEREncodable, T4: DEREncodable, T5: DEREncodable,
            T6: DEREncodable, T7: DEREncodable, T8: DEREncodable {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            self.0.encode_der(writer.next());
            self.1.encode_der(writer.next());
            self.2.encode_der(writer.next());
            self.3.encode_der(writer.next());
            self.4.encode_der(writer.next());
            self.5.encode_der(writer.next());
            self.6.encode_der(writer.next());
            self.7.encode_der(writer.next());
            self.8.encode_der(writer.next());
        })
    }
}

impl<T0, T1, T2, T3, T4, T5, T6, T7, T8, T9> DEREncodable
        for (T0, T1, T2, T3, T4, T5, T6, T7, T8, T9)
        where T0: DEREncodable, T1: DEREncodable, T2: DEREncodable,
            T3: DEREncodable, T4: DEREncodable, T5: DEREncodable,
            T6: DEREncodable, T7: DEREncodable, T8: DEREncodable,
            T9: DEREncodable {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            self.0.encode_der(writer.next());
            self.1.encode_der(writer.next());
            self.2.encode_der(writer.next());
            self.3.encode_der(writer.next());
            self.4.encode_der(writer.next());
            self.5.encode_der(writer.next());
            self.6.encode_der(writer.next());
            self.7.encode_der(writer.next());
            self.8.encode_der(writer.next());
            self.9.encode_der(writer.next());
        })
    }
}

impl<T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10> DEREncodable
        for (T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10)
        where T0: DEREncodable, T1: DEREncodable, T2: DEREncodable,
            T3: DEREncodable, T4: DEREncodable, T5: DEREncodable,
            T6: DEREncodable, T7: DEREncodable, T8: DEREncodable,
            T9: DEREncodable, T10: DEREncodable {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            self.0.encode_der(writer.next());
            self.1.encode_der(writer.next());
            self.2.encode_der(writer.next());
            self.3.encode_der(writer.next());
            self.4.encode_der(writer.next());
            self.5.encode_der(writer.next());
            self.6.encode_der(writer.next());
            self.7.encode_der(writer.next());
            self.8.encode_der(writer.next());
            self.9.encode_der(writer.next());
            self.10.encode_der(writer.next());
        })
    }
}

impl<T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11> DEREncodable
        for (T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11)
        where T0: DEREncodable, T1: DEREncodable, T2: DEREncodable,
            T3: DEREncodable, T4: DEREncodable, T5: DEREncodable,
            T6: DEREncodable, T7: DEREncodable, T8: DEREncodable,
            T9: DEREncodable, T10: DEREncodable, T11: DEREncodable {
    fn encode_der(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            self.0.encode_der(writer.next());
            self.1.encode_der(writer.next());
            self.2.encode_der(writer.next());
            self.3.encode_der(writer.next());
            self.4.encode_der(writer.next());
            self.5.encode_der(writer.next());
            self.6.encode_der(writer.next());
            self.7.encode_der(writer.next());
            self.8.encode_der(writer.next());
            self.9.encode_der(writer.next());
            self.10.encode_der(writer.next());
            self.11.encode_der(writer.next());
        })
    }
}
