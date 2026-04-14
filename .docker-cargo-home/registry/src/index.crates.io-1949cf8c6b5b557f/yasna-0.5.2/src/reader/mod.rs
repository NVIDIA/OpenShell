// Copyright 2016 Masaki Hara
// Copyright 2017,2019 Fortanix, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(missing_docs)]

use alloc::vec::Vec;
use alloc::string::String;
use alloc::borrow::ToOwned;

mod error;

#[cfg(feature = "num-bigint")]
use num_bigint::{BigInt,BigUint,Sign};
#[cfg(feature = "bit-vec")]
use bit_vec::BitVec;

use super::{PCBit,Tag,TAG_CLASSES};
use super::tags::{TAG_EOC,TAG_BOOLEAN,TAG_INTEGER,TAG_OCTETSTRING};
use super::tags::{TAG_NULL,TAG_OID,TAG_UTF8STRING,TAG_SEQUENCE,TAG_SET,TAG_ENUM};
use super::tags::{TAG_NUMERICSTRING,TAG_PRINTABLESTRING,TAG_VISIBLESTRING,TAG_IA5STRING,TAG_BMPSTRING};
use super::models::{ObjectIdentifier,TaggedDerValue};
#[cfg(feature = "time")]
use super::models::{UTCTime,GeneralizedTime};
pub use self::error::*;

/// Parses DER/BER-encoded data.
///
/// [`parse_ber`] and [`parse_der`] are shorthands
/// for this function.
pub fn parse_ber_general<'a, T, F>(buf: &'a [u8], mode: BERMode, callback: F)
        -> ASN1Result<T>
        where F: for<'b> FnOnce(BERReader<'a, 'b>) -> ASN1Result<T> {
    let mut reader_impl = BERReaderImpl::new(buf, mode);
    let result;
    {
        result = callback(BERReader::new(&mut reader_impl))?;
    }
    reader_impl.end_of_buf()?;
    return Ok(result);
}

/// Parses BER-encoded data.
///
/// This function uses the loan pattern: `callback` is called back with
/// a [`BERReader`], from which the ASN.1 value is read.
///
/// If you want to accept only DER-encoded data, use [`parse_der`].
///
/// # Examples
///
/// ```
/// use yasna;
/// let data = &[48, 128, 2, 1, 10, 1, 1, 255, 0, 0];
/// let asn = yasna::parse_ber(data, |reader| {
///     reader.read_sequence(|reader| {
///         let i = reader.next().read_i64()?;
///         let b = reader.next().read_bool()?;
///         return Ok((i, b));
///     })
/// }).unwrap();
/// println!("{:?} = [48, 128, 2, 1, 10, 1, 1, 255, 0, 0]", asn);
/// ```
pub fn parse_ber<'a, T, F>(buf: &'a [u8], callback: F)
        -> ASN1Result<T>
        where F: for<'b> FnOnce(BERReader<'a, 'b>) -> ASN1Result<T> {
    parse_ber_general(buf, BERMode::Ber, callback)
}

/// Parses DER-encoded data.
///
/// This function uses the loan pattern: `callback` is called back with
/// a [`BERReader`], from which the ASN.1 value is read.
///
/// If you want to parse BER-encoded data in general,
/// use [`parse_ber`].
///
/// # Examples
///
/// ```
/// use yasna;
/// let data = &[48, 6, 2, 1, 10, 1, 1, 255];
/// let asn = yasna::parse_der(data, |reader| {
///     reader.read_sequence(|reader| {
///         let i = reader.next().read_i64()?;
///         let b = reader.next().read_bool()?;
///         return Ok((i, b));
///     })
/// }).unwrap();
/// println!("{:?} = [48, 6, 2, 1, 10, 1, 1, 255]", asn);
/// ```
pub fn parse_der<'a, T, F>(buf: &'a [u8], callback: F)
        -> ASN1Result<T>
        where F: for<'b> FnOnce(BERReader<'a, 'b>) -> ASN1Result<T> {
    parse_ber_general(buf, BERMode::Der, callback)
}

/// Used by [`BERReader`] to determine whether or not to enforce
/// DER restrictions when parsing.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum BERMode {
    /// Use BER (Basic Encoding Rules).
    Ber,
    /// Use DER (Distinguished Encoding Rules).
    Der,
}

#[derive(Debug)]
struct BERReaderImpl<'a> {
    buf: &'a [u8],
    pos: usize,
    mode: BERMode,
    depth: usize,
}

const PC_BITS : [PCBit; 2] = [PCBit::Primitive, PCBit::Constructed];

#[derive(Debug)]
enum Contents<'a, 'b> where 'a: 'b {
    Primitive(&'a [u8]),
    Constructed(&'b mut BERReaderImpl<'a>),
}

const BER_READER_STACK_DEPTH : usize = 100;

impl<'a> BERReaderImpl<'a> {
    fn new(buf: &'a [u8], mode: BERMode) -> Self {
        return BERReaderImpl {
            buf,
            pos: 0,
            mode,
            depth: 0,
        };
    }

    fn with_pos(buf: &'a [u8], pos: usize, mode: BERMode) -> Self {
        return BERReaderImpl {
            buf,
            pos,
            mode,
            depth: 0,
        };
    }

    fn read_u8(&mut self) -> ASN1Result<u8> {
        if self.pos < self.buf.len() {
            let ret = self.buf[self.pos];
            self.pos += 1;
            return Ok(ret);
        } else {
            return Err(ASN1Error::new(ASN1ErrorKind::Eof));
        }
    }

    fn end_of_buf(&mut self) -> ASN1Result<()> {
        if self.pos != self.buf.len() {
            return Err(ASN1Error::new(ASN1ErrorKind::Extra));
        }
        return Ok(());
    }

    fn end_of_contents(&mut self) -> ASN1Result<()> {
        let (tag, pcbit) = self.read_identifier()?;
        if tag != TAG_EOC || pcbit != PCBit::Primitive {
            return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
        }
        let b = self.read_u8()?;
        if b != 0 {
            return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
        }
        return Ok(());
    }

    fn read_identifier(&mut self) -> ASN1Result<(Tag, PCBit)> {
        let tagbyte = self.read_u8()?;
        let tag_class = TAG_CLASSES[(tagbyte >> 6) as usize];
        let pcbit = PC_BITS[((tagbyte >> 5) & 1) as usize];
        let mut tag_number = (tagbyte & 31) as u64;
        if tag_number == 31 {
            tag_number = 0;
            loop {
                let b = self.read_u8()? as u64;
                let x =
                    tag_number.checked_mul(128).ok_or(
                        ASN1Error::new(ASN1ErrorKind::IntegerOverflow))?;
                tag_number = x + (b & 127);
                if (b & 128) == 0 {
                    break;
                }
            }
            if tag_number < 31 {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            }
        }
        let tag = Tag {
            tag_class,
            tag_number,
        };
        return Ok((tag, pcbit));
    }

    fn lookahead_tag(&self) -> ASN1Result<Tag> {
        let mut pos = self.pos;
        let mut read_u8 = || {
            if pos < self.buf.len() {
                let ret = self.buf[pos];
                pos += 1;
                return Ok(ret);
            } else {
                return Err(ASN1Error::new(ASN1ErrorKind::Eof));
            }
        };
        let tagbyte = read_u8()?;
        let tag_class = TAG_CLASSES[(tagbyte >> 6) as usize];
        let mut tag_number = (tagbyte & 31) as u64;
        if tag_number == 31 {
            tag_number = 0;
            loop {
                let b = read_u8()? as u64;
                let x =
                    tag_number.checked_mul(128).ok_or(
                        ASN1Error::new(ASN1ErrorKind::IntegerOverflow))?;
                tag_number = x + (b & 127);
                if (b & 128) == 0 {
                    break;
                }
            }
            if tag_number < 31 {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            }
        }
        let tag = Tag {
            tag_class,
            tag_number,
        };
        return Ok(tag);
    }

    fn read_length(&mut self) -> ASN1Result<Option<usize>> {
        let lbyte = self.read_u8()? as usize;
        if lbyte == 128 {
            return Ok(None);
        }
        if lbyte == 255 {
            return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
        }
        if (lbyte & 128) == 0 {
            return Ok(Some(lbyte));
        }
        let mut length : usize = 0;
        for _ in 0..(lbyte & 127) {
            let x = length.checked_mul(256).ok_or(
                ASN1Error::new(ASN1ErrorKind::Eof))?;
            length = x + (self.read_u8()? as usize);
        }
        if self.mode == BERMode::Der && length < 128 {
            return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
        }
        return Ok(Some(length));
    }

    fn read_general<T, F>(&mut self, tag: Tag, callback: F) -> ASN1Result<T>
            where F: for<'b> FnOnce(Contents<'a, 'b>) -> ASN1Result<T> {
        if self.depth > BER_READER_STACK_DEPTH {
            return Err(ASN1Error::new(ASN1ErrorKind::StackOverflow));
        }
        let old_pos = self.pos;
        let (tag2, pcbit) = self.read_identifier()?;
        if tag2 != tag {
            self.pos = old_pos;
            return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
        }
        let length_spec = self.read_length()?;
        let old_buf = self.buf;
        match length_spec {
            Some(length) => {
                let limit = match self.pos.checked_add(length) {
                    Some(l) => l,
                    None => return Err(ASN1Error::new(ASN1ErrorKind::IntegerOverflow)),
                };

                if old_buf.len() < limit {
                    return Err(ASN1Error::new(ASN1ErrorKind::Eof));
                }
                self.buf = &old_buf[..limit];
            },
            None => {
                if pcbit != PCBit::Constructed {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                }
                if self.mode == BERMode::Der {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                }
            },
        };
        self.depth += 1;
        let result = callback(match pcbit {
            PCBit::Primitive => {
                let buf = &self.buf[self.pos..];
                self.pos = self.buf.len();
                Contents::Primitive(&buf)
            },
            PCBit::Constructed => Contents::Constructed(self),
        })?;
        self.depth -= 1;
        match length_spec {
            Some(_) => {
                self.end_of_buf()?;
            },
            None => {
                self.end_of_contents()?;
            },
        };
        self.buf = old_buf;
        return Ok(result);
    }

    fn skip_general(&mut self) -> ASN1Result<(Tag, PCBit, usize)> {
        let mut skip_depth = 0;
        let mut skip_tag = None;
        let mut data_pos = None;
        while skip_depth > 0 || skip_tag == None {
            let old_pos = self.pos;
            let (tag, pcbit) = self.read_identifier()?;
            if tag == TAG_EOC {
                if skip_depth == 0 {
                    self.pos = old_pos;
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                }
                skip_depth -= 1;
                // EOC is a pair of zero bytes, consume the second.
                if self.read_u8()? != 0 {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                }
                continue;
            }
            if skip_depth == 0 {
                skip_tag = Some((tag, pcbit));
            }
            if let Some(length) = self.read_length()? {
                if skip_depth == 0 {
                    data_pos = Some(self.pos);
                }
                let limit = self.pos+length;
                if self.buf.len() < limit {
                    return Err(ASN1Error::new(ASN1ErrorKind::Eof));
                }
                self.pos = limit;
            } else {
                if skip_depth == 0 {
                    data_pos = Some(self.pos);
                }
                if pcbit != PCBit::Constructed || self.mode == BERMode::Der {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                }
                skip_depth += 1;
            }
        }
        return Ok((skip_tag.unwrap().0, skip_tag.unwrap().1, data_pos.unwrap()));
    }

    fn read_with_buffer<'b, T, F>(&'b mut self, callback: F)
            -> ASN1Result<(T, &'a [u8])>
            where F: FnOnce(&mut Self) -> ASN1Result<T> {
        let old_pos = self.pos;
        let result = callback(self)?;
        let new_pos = self.pos;
        let buf = &self.buf[old_pos..new_pos];
        return Ok((result, buf));
    }

    fn read_optional<T, F>(&mut self, callback: F) -> ASN1Result<Option<T>>
            where F: FnOnce(&mut Self) -> ASN1Result<T> {
        let old_pos = self.pos;
        match callback(self) {
            Ok(result) => Ok(Some(result)),
            Err(e) =>
                if old_pos == self.pos {
                    Ok(None)
                } else {
                    Err(e)
                },
        }
    }

}

/// A reader object for BER/DER-encoded ASN.1 data.
///
/// The two main sources of `BERReaderSeq` are:
///
/// - The [`parse_ber`]/[`parse_der`] function,
///   the starting point of DER serialization.
/// - The [`next`](BERReaderSeq::next) method of [`BERReaderSeq`].
///
/// # Examples
///
/// ```
/// use yasna;
/// let data = &[2, 1, 10];
/// let asn = yasna::parse_der(data, |reader| {
///     reader.read_i64()
/// }).unwrap();
/// assert_eq!(asn, 10);
/// ```
#[derive(Debug)]
pub struct BERReader<'a, 'b> where 'a: 'b {
    inner: &'b mut BERReaderImpl<'a>,
    implicit_tag: Option<Tag>,
}

impl<'a, 'b> BERReader<'a, 'b> {
    fn new(inner: &'b mut BERReaderImpl<'a>) -> Self {
        BERReader {
            inner,
            implicit_tag: None,
        }
    }

    fn read_general<T, F>(self, tag: Tag, callback: F) -> ASN1Result<T>
            where F: for<'c> FnOnce(Contents<'a, 'c>) -> ASN1Result<T> {
        let tag = self.implicit_tag.unwrap_or(tag);
        self.inner.read_general(tag, callback)
    }

    /// Tells which format we are parsing, BER or DER.
    pub fn mode(&self) -> BERMode {
        self.inner.mode
    }

    /// Reads an ASN.1 BOOLEAN value as `bool`.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna;
    /// let data = &[1, 1, 255];
    /// let asn = yasna::parse_der(data, |reader| {
    ///     reader.read_bool()
    /// }).unwrap();
    /// assert_eq!(asn, true);
    /// ```
    pub fn read_bool(self) -> ASN1Result<bool> {
        let mode = self.mode();
        self.read_general(TAG_BOOLEAN, |contents| {
            let buf = match contents {
                Contents::Primitive(buf) => buf,
                Contents::Constructed(_) => {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                },
            };
            if buf.len() != 1 {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            }
            let b = buf[0];
            if mode == BERMode::Der && b != 0 && b != 255 {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            }
            return Ok(b != 0);
        })
    }

    fn read_integer(self, tag: Tag) -> ASN1Result<i64> {
        self.read_general(tag, |contents| {
            let buf = match contents {
                Contents::Primitive(buf) => buf,
                Contents::Constructed(_) => {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                },
            };
            if buf.len() == 0 {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            } else if buf.len() == 1 {
                return Ok(buf[0] as i8 as i64);
            }
            let mut x = ((buf[0] as i8 as i64) << 8) + (buf[1] as i64);
            if -128 <= x && x < 128 {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            }
            if buf.len() > 8 {
                return Err(ASN1Error::new(
                    ASN1ErrorKind::IntegerOverflow));
            }
            for &b in buf[2..].iter() {
                x = (x << 8) | (b as i64);
            }
            return Ok(x);
        })
    }

    /// Reads an ASN.1 ENUMERATED value as `i64`.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna;
    /// let data = &[10, 1, 13];
    /// let asn = yasna::parse_der(data, |reader| {
    ///     reader.read_enum()
    /// }).unwrap();
    /// assert_eq!(asn, 13);
    /// ```
    ///
    /// # Errors
    ///
    /// Except parse errors, it can raise integer overflow errors.
    pub fn read_enum(self) -> ASN1Result<i64> {
        self.read_integer(TAG_ENUM)
    }

    /// Reads an ASN.1 INTEGER value as `i64`.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna;
    /// let data = &[2, 4, 73, 150, 2, 210];
    /// let asn = yasna::parse_der(data, |reader| {
    ///     reader.read_i64()
    /// }).unwrap();
    /// assert_eq!(asn, 1234567890);
    /// ```
    ///
    /// # Errors
    ///
    /// Except parse errors, it can raise integer overflow errors.
    pub fn read_i64(self) -> ASN1Result<i64> {
        self.read_integer(TAG_INTEGER)
    }

    /// Reads an ASN.1 INTEGER value as `u64`.
    ///
    /// # Errors
    ///
    /// Except parse errors, it can raise integer overflow errors.
    pub fn read_u64(self) -> ASN1Result<u64> {
        self.read_general(TAG_INTEGER, |contents| {
            let buf = match contents {
                Contents::Primitive(buf) => buf,
                Contents::Constructed(_) => {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                },
            };
            if buf.len() == 0 {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            } else if buf[0] >= 128 {
                return Err(ASN1Error::new(ASN1ErrorKind::IntegerOverflow));
            } else if buf.len() == 1 {
                return Ok(buf[0] as u64);
            }
            let mut x = ((buf[0] as u64) << 8) + (buf[1] as u64);
            if x < 128 {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            }
            if buf.len() > 9 || (buf.len() == 9 && buf[0] != 0) {
                return Err(ASN1Error::new(
                    ASN1ErrorKind::IntegerOverflow));
            }
            for &b in buf[2..].iter() {
                x = (x << 8) | (b as u64);
            }
            return Ok(x);
        })
    }

    /// Reads an ASN.1 INTEGER value as `i32`.
    ///
    /// # Errors
    ///
    /// Except parse errors, it can raise integer overflow errors.
    pub fn read_i32(self) -> ASN1Result<i32> {
        let val = self.read_i64()?;
        if -(1 << 31) <= val && val < (1 << 31) {
            return Ok(val as i32);
        } else {
            return Err(ASN1Error::new(ASN1ErrorKind::IntegerOverflow));
        }
    }

    /// Reads an ASN.1 INTEGER value as `u32`.
    ///
    /// # Errors
    ///
    /// Except parse errors, it can raise integer overflow errors.
    pub fn read_u32(self) -> ASN1Result<u32> {
        let val = self.read_u64()?;
        if val < (1 << 32) {
            return Ok(val as u32);
        } else {
            return Err(ASN1Error::new(ASN1ErrorKind::IntegerOverflow));
        }
    }

    /// Reads an ASN.1 INTEGER value as `i16`.
    ///
    /// # Errors
    ///
    /// Except parse errors, it can raise integer overflow errors.
    pub fn read_i16(self) -> ASN1Result<i16> {
        let val = self.read_i64()?;
        if -(1 << 15) <= val && val < (1 << 15) {
            return Ok(val as i16);
        } else {
            return Err(ASN1Error::new(ASN1ErrorKind::IntegerOverflow));
        }
    }

    /// Reads an ASN.1 INTEGER value as `u16`.
    ///
    /// # Errors
    ///
    /// Except parse errors, it can raise integer overflow errors.
    pub fn read_u16(self) -> ASN1Result<u16> {
        let val = self.read_u64()?;
        if val < (1 << 16) {
            return Ok(val as u16);
        } else {
            return Err(ASN1Error::new(ASN1ErrorKind::IntegerOverflow));
        }
    }

    /// Reads an ASN.1 INTEGER value as `i8`.
    ///
    /// # Errors
    ///
    /// Except parse errors, it can raise integer overflow errors.
    pub fn read_i8(self) -> ASN1Result<i8> {
        let val = self.read_i64()?;
        if -(1 << 7) <= val && val < (1 << 7) {
            return Ok(val as i8);
        } else {
            return Err(ASN1Error::new(ASN1ErrorKind::IntegerOverflow));
        }
    }

    /// Reads an ASN.1 INTEGER value as `u8`.
    ///
    /// # Errors
    ///
    /// Except parse errors, it can raise integer overflow errors.
    pub fn read_u8(self) -> ASN1Result<u8> {
        let val = self.read_u64()?;
        if val < (1 << 8) {
            return Ok(val as u8);
        } else {
            return Err(ASN1Error::new(ASN1ErrorKind::IntegerOverflow));
        }
    }

    #[cfg(feature = "num-bigint")]
    /// Reads an ASN.1 INTEGER value as `BigInt`.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() {
    /// use yasna;
    /// use num_bigint::BigInt;
    /// let data = &[2, 4, 73, 150, 2, 210];
    /// let asn = yasna::parse_der(data, |reader| {
    ///     reader.read_bigint()
    /// }).unwrap();
    /// assert_eq!(&asn, &BigInt::parse_bytes(b"1234567890", 10).unwrap());
    /// # }
    /// ```
    ///
    /// # Features
    ///
    /// This method is enabled by `num` feature.
    ///
    /// ```toml
    /// [dependencies]
    /// yasna = { version = "*", features = ["num"] }
    /// ```
    pub fn read_bigint(self) -> ASN1Result<BigInt> {
        let (mut bytes, non_negative) = self.read_bigint_bytes()?;
        let sign = if non_negative {
            Sign::Plus
        } else {
            let mut carry: usize = 1;
            for b in bytes.iter_mut().rev() {
                let bval = 255 - (*b as usize);
                *b = (bval + carry) as u8;
                carry = (bval + carry) >> 8;
            }
            Sign::Minus
        };
        Ok(BigInt::from_bytes_be(sign, &bytes))
    }

    /// Reads an ASN.1 INTEGER value as `Vec<u8>` and a sign bit.
    ///
    /// The number given is in big endian byte ordering, and in two's
    /// complement.
    ///
    /// The sign bit is `true` if the number is positive,
    /// and false if it is negative.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() {
    /// use yasna;
    /// let data = &[2, 4, 73, 150, 2, 210];
    /// let (bytes, nonnegative) = yasna::parse_der(data, |reader| {
    ///     reader.read_bigint_bytes()
    /// }).unwrap();
    /// assert_eq!(&bytes, &[73, 150, 2, 210]);
    /// assert_eq!(nonnegative, true);
    /// # }
    /// ```
    pub fn read_bigint_bytes(self) -> ASN1Result<(Vec<u8>, bool)> {
        self.read_general(TAG_INTEGER, |contents| {
            let buf = match contents {
                Contents::Primitive(buf) => buf,
                Contents::Constructed(_) => {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                },
            };
            if buf.len() == 0 {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            } else if buf.len() == 1 {
                return Ok((buf.to_vec(), buf[0] & 128 == 0));
            }
            let x2 = ((buf[0] as i8 as i32) << 8) + (buf[1] as i32);
            if -128 <= x2 && x2 < 128 {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            }
            let sign = 0 <= x2;
            Ok((buf.to_vec(), sign))
        })
    }

    #[cfg(feature = "num-bigint")]
    /// Reads an ASN.1 INTEGER value as `BigUint`.
    ///
    /// # Errors
    ///
    /// Except parse errors, it can raise integer overflow errors.
    ///
    /// # Features
    ///
    /// This method is enabled by `num` feature.
    ///
    /// ```toml
    /// [dependencies]
    /// yasna = { version = "*", features = ["num"] }
    /// ```
    pub fn read_biguint(self) -> ASN1Result<BigUint> {
        self.read_general(TAG_INTEGER, |contents| {
            let buf = match contents {
                Contents::Primitive(buf) => buf,
                Contents::Constructed(_) => {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                },
            };
            if buf.len() == 0 {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            } else if buf[0] >= 128 {
                return Err(ASN1Error::new(ASN1ErrorKind::IntegerOverflow));
            } else if buf.len() == 1 {
                return Ok(BigUint::from(buf[0]));
            }
            let x2 = ((buf[0] as i8 as i32) << 8) + (buf[1] as i32);
            if -128 <= x2 && x2 < 128 {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            } else if x2 < 0 {
                return Err(ASN1Error::new(ASN1ErrorKind::IntegerOverflow));
            }
            return Ok(BigUint::from_bytes_be(buf));
        })
    }

    fn read_bitvec_impl(self, unused_bits: &mut usize, bytes: &mut Vec<u8>)
            -> ASN1Result<()> {
        use super::tags::TAG_BITSTRING;
        if *unused_bits != 0 {
            return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
        }
        let mode = self.inner.mode;
        self.read_general(TAG_BITSTRING, |contents| {
            match contents {
                Contents::Primitive(buf) => {
                    if buf.len() == 0 {
                        return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                    }
                    if buf[0] >= 8 {
                        return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                    }
                    if buf[0] > 0 {
                        if buf.len() == 1 {
                            return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                        }
                        if mode == BERMode::Der &&
                            (buf[buf.len()-1] & ((1<<buf[0]) - 1)) != 0 {
                            return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                        }
                    }
                    bytes.extend_from_slice(&buf[1..]);
                    *unused_bits = buf[0] as usize;
                    return Ok(());
                },
                Contents::Constructed(inner) => {
                    if mode == BERMode::Der {
                        return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                    }
                    loop {
                        let result = inner.read_optional(|inner| {
                            BERReader::new(inner)
                                .read_bitvec_impl(unused_bits, bytes)
                        })?;
                        match result {
                            Some(()) => {},
                            None => { break; },
                        }
                    }
                    return Ok(());
                },
            };
        })
    }

    #[cfg(feature = "bit-vec")]
    /// Reads an ASN.1 BITSTRING value as `BitVec`.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() {
    /// use yasna;
    /// use bit_vec::BitVec;
    /// let data = &[3, 5, 3, 206, 213, 116, 24];
    /// let asn = yasna::parse_der(data, |reader| {
    ///     reader.read_bitvec()
    /// }).unwrap();
    /// assert_eq!(
    ///     asn.into_iter().map(|b| b as usize).collect::<Vec<_>>(),
    ///     vec![1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1,
    ///         0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1]);
    /// # }
    /// ```
    ///
    /// # Features
    ///
    /// This method is enabled by `bit-vec` feature.
    ///
    /// ```toml
    /// [dependencies]
    /// yasna = { version = "*", features = ["bit-vec"] }
    /// ```
    pub fn read_bitvec(self) -> ASN1Result<BitVec> {
        let (bytes, len) = self.read_bitvec_bytes()?;
        let mut ret = BitVec::from_bytes(&bytes);
        ret.truncate(len);
        return Ok(ret);
    }

    /// Reads an ASN.1 BITSTRING value as `(Vec<u8>, usize)`.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() {
    /// use yasna;
    /// let data = &[3, 4, 6, 117, 13, 64];
    /// let asn = yasna::parse_der(data, |reader| {
    ///     reader.read_bitvec_bytes()
    /// }).unwrap();
    /// assert_eq!(asn, (vec![117, 13, 64], 18));
    /// # }
    /// ```
    ///
    /// # Features
    ///
    /// This method is enabled by `bit-vec` feature.
    ///
    /// ```toml
    /// [dependencies]
    /// yasna = { version = "*", features = ["bit-vec"] }
    /// ```
    pub fn read_bitvec_bytes(self) -> ASN1Result<(Vec<u8>, usize)> {
        let mut unused_bits = 0;
        let mut bytes = Vec::new();
        self.read_bitvec_impl(&mut unused_bits, &mut bytes)?;
        let len = bytes.len() * 8 - unused_bits;
        return Ok((bytes, len));
    }

    fn read_bytes_impl(self, vec: &mut Vec<u8>) -> ASN1Result<()> {
        self.read_general(TAG_OCTETSTRING, |contents| {
            match contents {
                Contents::Primitive(buf) => {
                    vec.extend(buf);
                    return Ok(());
                },
                Contents::Constructed(inner) => {
                    if inner.mode == BERMode::Der {
                        return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                    }
                    loop {
                        let result = inner.read_optional(|inner| {
                            BERReader::new(inner).read_bytes_impl(vec)
                        })?;
                        match result {
                            Some(()) => {},
                            None => { break; },
                        }
                    }
                    return Ok(());
                },
            };
        })
    }

    /// Reads an ASN.1 OCTETSTRING value as `Vec<u8>`.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna;
    /// let data = &[36, 128, 4, 2, 72, 101, 4, 4, 108, 108, 111, 33, 0, 0];
    /// let asn = yasna::parse_ber(data, |reader| {
    ///     reader.read_bytes()
    /// }).unwrap();
    /// assert_eq!(&asn, b"Hello!");
    /// ```
    pub fn read_bytes(self) -> ASN1Result<Vec<u8>> {
        let mut ret = Vec::new();
        self.read_bytes_impl(&mut ret)?;
        return Ok(ret);
    }

    /// Reads the ASN.1 NULL value.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna;
    /// let data = &[5, 0];
    /// let asn = yasna::parse_der(data, |reader| {
    ///     reader.read_null()
    /// }).unwrap();
    /// assert_eq!(asn, ());
    /// ```
    pub fn read_null(self) -> ASN1Result<()> {
        self.read_general(TAG_NULL, |contents| {
            let buf = match contents {
                Contents::Primitive(buf) => buf,
                Contents::Constructed(_) => {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                },
            };
            if buf.len() != 0 {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            }
            return Ok(());
        })
    }

    /// Reads an ASN.1 object identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna;
    /// let data = &[6, 8, 42, 134, 72, 134, 247, 13, 1, 1];
    /// let asn = yasna::parse_der(data, |reader| {
    ///     reader.read_oid()
    /// }).unwrap();
    /// assert_eq!(&*asn.components(), &[1, 2, 840, 113549, 1, 1]);
    /// ```
    pub fn read_oid(self) -> ASN1Result<ObjectIdentifier> {
        self.read_general(TAG_OID, |contents| {
            let buf = match contents {
                Contents::Primitive(buf) => buf,
                Contents::Constructed(_) => {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                },
            };
            let mut components = Vec::new();
            if buf.len() == 0 || buf[buf.len()-1] >= 128 {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            }
            let mut subid : u64 = 0;
            for &b in buf.iter() {
                if b == 128 {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                }
                subid = subid.checked_mul(128)
                    .ok_or(ASN1Error::new(
                        ASN1ErrorKind::IntegerOverflow))? + ((b & 127) as u64);
                if (b & 128) == 0 {
                    if components.len() == 0 {
                        let id0 = if subid < 40 {
                            0
                        } else if subid < 80 {
                            1
                        } else {
                            2
                        };
                        let id1 = subid - 40 * id0;
                        components.push(id0);
                        components.push(id1);
                    } else {
                        components.push(subid);
                    }
                    subid = 0;
                }
            }
            return Ok(ObjectIdentifier::new(components));
        })
    }

    /// Reads an ASN.1 UTF8String.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna;
    /// let data = &[
    ///     12, 29, 103, 110, 97, 119, 32, 207, 129, 206, 191, 206,
    ///     186, 206, 177, 206, 189, 206, 175, 206, 182, 207,
    ///     137, 32, 240, 170, 152, 130, 227, 130, 139];
    /// let asn = yasna::parse_der(data, |reader| {
    ///     reader.read_utf8string()
    /// }).unwrap();
    /// assert_eq!(&asn, "gnaw ροκανίζω 𪘂る");
    /// ```
    pub fn read_utf8string(self) -> ASN1Result<String> {
        self.read_tagged_implicit(TAG_UTF8STRING, |reader| {
            let bytes = reader.read_bytes()?;
            match String::from_utf8(bytes) {
                Ok(string) => Ok(string),
                Err(_) => Err(ASN1Error::new(ASN1ErrorKind::Invalid)),
            }
        })
    }

    /// Reads an ASN.1 SEQUENCE value.
    ///
    /// This function uses the loan pattern: `callback` is called back with
    /// a [`BERReaderSeq`], from which the contents of the
    /// SEQUENCE is read.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna;
    /// let data = &[48, 6, 2, 1, 10, 1, 1, 255];
    /// let asn = yasna::parse_der(data, |reader| {
    ///     reader.read_sequence(|reader| {
    ///         let i = reader.next().read_i64()?;
    ///         let b = reader.next().read_bool()?;
    ///         return Ok((i, b));
    ///     })
    /// }).unwrap();
    /// assert_eq!(asn, (10, true));
    /// ```
    pub fn read_sequence<T, F>(self, callback: F) -> ASN1Result<T>
            where F: for<'c> FnOnce(
                &mut BERReaderSeq<'a, 'c>) -> ASN1Result<T> {
        self.read_general(TAG_SEQUENCE, |contents| {
            let inner = match contents {
                Contents::Primitive(_) => {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                },
                Contents::Constructed(inner) => inner,
            };
            return callback(&mut BERReaderSeq { inner, });
        })
    }

    /// Reads an ASN.1 SEQUENCE OF value.
    ///
    /// This function uses the loan pattern: `callback` is called back with
    /// a [`BERReader`], from which the contents of the
    /// SEQUENCE OF is read.
    ///
    /// This function doesn't return values. Instead, use mutable values to
    /// maintain read values. `collect_set_of` can be an alternative.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna;
    /// let data = &[48, 7, 2, 1, 10, 2, 2, 255, 127];
    /// let asn = yasna::parse_der(data, |reader| {
    ///     let mut numbers = Vec::new();
    ///     reader.read_sequence_of(|reader| {
    ///         numbers.push(reader.read_i64()?);
    ///         return Ok(());
    ///     })?;
    ///     return Ok(numbers);
    /// }).unwrap();
    /// assert_eq!(&asn, &[10, -129]);
    /// ```
    pub fn read_sequence_of<F>(self, mut callback: F) -> ASN1Result<()>
            where F: for<'c> FnMut(BERReader<'a, 'c>) -> ASN1Result<()> {
        self.read_sequence(|reader| {
            loop {
                if let None = reader.read_optional(|reader| {
                    callback(reader)
                })? {
                    break;
                }
            }
            return Ok(());
        })
    }

    /// Collects an ASN.1 SEQUENCE OF value.
    ///
    /// This function uses the loan pattern: `callback` is called back with
    /// a [`BERReader`], from which the contents of the
    /// SEQUENCE OF is read.
    ///
    /// If you don't like `Vec`, you can use `read_sequence_of` instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna;
    /// let data = &[48, 7, 2, 1, 10, 2, 2, 255, 127];
    /// let asn = yasna::parse_der(data, |reader| {
    ///     reader.collect_sequence_of(|reader| {
    ///         reader.read_i64()
    ///     })
    /// }).unwrap();
    /// assert_eq!(&asn, &[10, -129]);
    /// ```
    pub fn collect_sequence_of<T, F>(self, mut callback: F)
            -> ASN1Result<Vec<T>>
            where F: for<'c> FnMut(BERReader<'a, 'c>) -> ASN1Result<T> {
        let mut collection = Vec::new();
        self.read_sequence_of(|reader| {
            collection.push(callback(reader)?);
            return Ok(());
        })?;
        return Ok(collection);
    }

    /// Reads an ASN.1 SET value.
    ///
    /// This function uses the loan pattern: `callback` is called back with
    /// a [`BERReaderSet`], from which the contents of the
    /// SET are read.
    ///
    /// For SET OF values, use `read_set_of` instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna;
    /// use yasna::tags::{TAG_INTEGER,TAG_BOOLEAN};
    /// let data = &[49, 6, 1, 1, 255, 2, 1, 10];
    /// let asn = yasna::parse_der(data, |reader| {
    ///     reader.read_set(|reader| {
    ///         let i = reader.next(&[TAG_INTEGER])?.read_i64()?;
    ///         let b = reader.next(&[TAG_BOOLEAN])?.read_bool()?;
    ///         return Ok((i, b));
    ///     })
    /// }).unwrap();
    /// assert_eq!(asn, (10, true));
    /// ```
    pub fn read_set<T, F>(self, callback: F) -> ASN1Result<T>
            where F: for<'c> FnOnce(
                &mut BERReaderSet<'a, 'c>) -> ASN1Result<T> {
        self.read_general(TAG_SET, |contents| {
            let inner = match contents {
                Contents::Primitive(_) => {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                },
                Contents::Constructed(inner) => inner,
            };
            let mut elements = Vec::new();
            loop {
                let old_pos = inner.pos;
                if let Some(tag) = inner.read_optional(|inner| {
                    inner.skip_general().map(|t| t.0)
                })? {
                    let new_pos = inner.pos;
                    // TODO: this should store the P/C bit as well
                    elements.push((tag, &inner.buf[..new_pos], old_pos));
                } else {
                    break;
                }
            }
            if inner.mode == BERMode::Der {
                for i in 1..elements.len() {
                    if elements[i] <= elements[i-1] {
                        return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                    }
                }
            }
            let mut new_impl = BERReaderImpl::new(&[], inner.mode);
            let result = callback(&mut BERReaderSet {
                impl_ref: &mut new_impl,
                elements: &mut elements,
            })?;
            if elements.len() > 0 {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            }
            return Ok(result);
        })
    }

    /// Reads an ASN.1 SET OF value.
    ///
    /// This function uses the loan pattern: `callback` is called back with
    /// a [`BERReader`], from which the contents of the
    /// SET OF are read.
    ///
    /// This function doesn't return values. Instead, use mutable values to
    /// maintain read values. `collect_set_of` can be an alternative.
    ///
    /// This function doesn't sort the elements. In DER, it is assumed that
    /// the elements occur in an order determined by DER encodings of them.
    ///
    /// For SET values, use `read_set` instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna;
    /// let data = &[49, 7, 2, 1, 10, 2, 2, 255, 127];
    /// let asn = yasna::parse_der(data, |reader| {
    ///     let mut numbers = Vec::new();
    ///     reader.read_set_of(|reader| {
    ///         numbers.push(reader.read_i64()?);
    ///         return Ok(());
    ///     })?;
    ///     return Ok(numbers);
    /// }).unwrap();
    /// assert_eq!(asn, vec![10, -129]);
    /// ```
    pub fn read_set_of<F>(self, mut callback: F) -> ASN1Result<()>
            where F: for<'c> FnMut(BERReader<'a, 'c>) -> ASN1Result<()> {
        self.read_general(TAG_SET, |contents| {
            let inner = match contents {
                Contents::Primitive(_) => {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                },
                Contents::Constructed(inner) => inner,
            };
            let mut last_buf = None;
            while let Some((_, buf)) = inner.read_optional(|inner| {
                    inner.read_with_buffer(|inner| {
                        callback(BERReader::new(inner))
                    })
            })? {
                if let Some(last_buf) = last_buf {
                    if inner.mode == BERMode::Der && buf < last_buf {
                        return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                    }
                }
                last_buf = Some(buf);
            }
            return Ok(());
        })
    }

    /// Collects an ASN.1 SET OF value.
    ///
    /// This function uses the loan pattern: `callback` is called back with
    /// a [`BERReader`], from which the contents of the
    /// SET OF is read.
    ///
    /// If you don't like `Vec`, you can use `read_set_of` instead.
    ///
    /// This function doesn't sort the elements. In DER, it is assumed that
    /// the elements occur in an order determined by DER encodings of them.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna;
    /// let data = &[49, 7, 2, 1, 10, 2, 2, 255, 127];
    /// let asn = yasna::parse_der(data, |reader| {
    ///     reader.collect_set_of(|reader| {
    ///         reader.read_i64()
    ///     })
    /// }).unwrap();
    /// assert_eq!(asn, vec![10, -129]);
    /// ```
    pub fn collect_set_of<T, F>(self, mut callback: F) -> ASN1Result<Vec<T>>
            where F: for<'c> FnMut(BERReader<'a, 'c>) -> ASN1Result<T> {
        let mut collection = Vec::new();
        self.read_set_of(|reader| {
            collection.push(callback(reader)?);
            return Ok(());
        })?;
        return Ok(collection);
    }

    /// Reads an ASN.1 NumericString.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna;
    /// let data = &[18, 7, 49, 50, 56, 32, 50, 53, 54];
    /// let asn = yasna::parse_der(data, |reader| {
    ///     reader.read_numeric_string()
    /// }).unwrap();
    /// assert_eq!(&asn, "128 256");
    /// ```
    pub fn read_numeric_string(self) -> ASN1Result<String> {
        self.read_tagged_implicit(TAG_NUMERICSTRING, |reader| {
            let bytes = reader.read_bytes()?;
            for &byte in bytes.iter() {
                if !(byte == b' ' || (b'0' <= byte && byte <= b'9')) {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                }
            }
            return Ok(String::from_utf8(bytes).unwrap());
        })
    }

    /// Reads an ASN.1 PrintableString.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna;
    /// let data = &[19, 9, 67, 111, 46, 44, 32, 76, 116, 100, 46];
    /// let asn = yasna::parse_der(data, |reader| {
    ///     reader.read_printable_string()
    /// }).unwrap();
    /// assert_eq!(&asn, "Co., Ltd.");
    /// ```
    pub fn read_printable_string(self) -> ASN1Result<String> {
        self.read_tagged_implicit(TAG_PRINTABLESTRING, |reader| {
            let bytes = reader.read_bytes()?;
            for &byte in bytes.iter() {
                if !(
                    byte == b' ' ||
                    (b'\'' <= byte && byte <= b':' && byte != b'*') ||
                    byte == b'=' ||
                    (b'A' <= byte && byte <= b'Z') ||
                    (b'a' <= byte && byte <= b'z')) {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                }
            }
            return Ok(String::from_utf8(bytes).unwrap());
        })
    }

    /// Reads an ASN.1 IA5String.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna;
    /// let data = &[22, 9, 0x41, 0x53, 0x43, 0x49, 0x49, 0x20, 0x70, 0x6C, 0x7A];
    /// let asn = yasna::parse_der(data, |reader| {
    ///     reader.read_ia5_string()
    /// }).unwrap();
    /// assert_eq!(&asn, "ASCII plz");
    /// ```
    pub fn read_ia5_string(self) -> ASN1Result<String> {
        self.read_tagged_implicit(TAG_IA5STRING, |reader| {
            let bytes = reader.read_bytes()?;

            match String::from_utf8(bytes) {
                Ok(string) => {
                    if !string.is_ascii() {
                        return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                    }
                    Ok(string)
                }
                Err(_) => Err(ASN1Error::new(ASN1ErrorKind::Invalid))
            }
        })
    }

    /// Reads an ASN.1 BMPString.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna;
    /// let data = &[30, 14, 0x00, 0xA3, 0x03, 0xC0, 0x00, 0x20, 0x00, 0x71, 0x00, 0x75, 0x00, 0x75, 0x00, 0x78];
    /// let asn = yasna::parse_der(data, |reader| {
    ///     reader.read_bmp_string()
    /// }).unwrap();
    /// assert_eq!(&asn, "£π quux");
    /// ```
    pub fn read_bmp_string(self) -> ASN1Result<String> {
        self.read_tagged_implicit(TAG_BMPSTRING, |reader| {
            let bytes = reader.read_bytes()?;

            if bytes.len() % 2 != 0 {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            }

            let utf16 : Vec<u16> = bytes.chunks(2).map(|c| (c[0] as u16) * 256 + c[1] as u16).collect();

            Ok(String::from_utf16_lossy(&utf16))
        })
    }

    #[cfg(feature = "time")]
    /// Reads an ASN.1 UTCTime.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna;
    /// let data = &[
    ///     23, 15, 56, 50, 48, 49, 48, 50, 48,
    ///     55, 48, 48, 45, 48, 53, 48, 48];
    /// let asn = yasna::parse_ber(data, |reader| {
    ///     reader.read_utctime()
    /// }).unwrap();
    /// assert_eq!(asn.datetime().unix_timestamp(), 378820800);
    /// ```
    ///
    /// # Features
    ///
    /// This method is enabled by `time` feature.
    ///
    /// ```toml
    /// [dependencies]
    /// yasna = { version = "*", features = ["time"] }
    /// ```
    pub fn read_utctime(self) -> ASN1Result<UTCTime> {
        use super::tags::TAG_UTCTIME;
        let mode = self.inner.mode;
        self.read_tagged_implicit(TAG_UTCTIME, |reader| {
            let bytes = reader.read_bytes()?;
            let datetime = UTCTime::parse(&bytes).ok_or_else(
                || ASN1Error::new(ASN1ErrorKind::Invalid))?;
            if mode == BERMode::Der && &datetime.to_bytes() != &bytes {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            }
            return Ok(datetime);
        })
    }

    #[cfg(feature = "time")]
    /// Reads an ASN.1 GeneralizedTime.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna;
    /// let data = &[
    ///     24, 17, 49, 57, 56, 53, 49, 49, 48, 54,
    ///     50, 49, 46, 49, 52, 49, 53, 57, 90];
    /// let asn = yasna::parse_ber(data, |reader| {
    ///     reader.read_generalized_time()
    /// }).unwrap();
    /// assert_eq!(asn.datetime().unix_timestamp(), 500159309);
    /// ```
    ///
    /// # Features
    ///
    /// This method is enabled by `time` feature.
    ///
    /// ```toml
    /// [dependencies]
    /// yasna = { version = "*", features = ["time"] }
    /// ```
    pub fn read_generalized_time(self) -> ASN1Result<GeneralizedTime> {
        use super::tags::TAG_GENERALIZEDTIME;
        let mode = self.inner.mode;
        self.read_tagged_implicit(TAG_GENERALIZEDTIME, |reader| {
            let bytes = reader.read_bytes()?;
            let datetime = GeneralizedTime::parse(&bytes).ok_or_else(
                || ASN1Error::new(ASN1ErrorKind::Invalid))?;
            if mode == BERMode::Der && &datetime.to_bytes() != &bytes {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            }
            return Ok(datetime);
        })
    }

    /// Reads an ASN.1 VisibleString.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna;
    /// let data = &[26, 3, 72, 105, 33];
    /// let asn = yasna::parse_der(data, |reader| {
    ///     reader.read_visible_string()
    /// }).unwrap();
    /// assert_eq!(&asn, "Hi!");
    /// ```
    pub fn read_visible_string(self) -> ASN1Result<String> {
        self.read_tagged_implicit(TAG_VISIBLESTRING, |reader| {
            let bytes = reader.read_bytes()?;
            for &byte in bytes.iter() {
                if !(b' ' <= byte && byte <= b'~') {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                }
            }
            return Ok(String::from_utf8(bytes).unwrap());
        })
    }

    /// Reads a (explicitly) tagged value.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna::{self,Tag};
    /// let data = &[163, 3, 2, 1, 10];
    /// let asn = yasna::parse_der(data, |reader| {
    ///     reader.read_tagged(Tag::context(3), |reader| {
    ///         reader.read_i64()
    ///     })
    /// }).unwrap();
    /// assert_eq!(asn, 10);
    /// ```
    pub fn read_tagged<T, F>(self, tag: Tag, callback: F) -> ASN1Result<T>
            where F: for<'c> FnOnce(BERReader<'a, 'c>) -> ASN1Result<T> {
        self.read_general(tag, |contents| {
            let inner = match contents {
                Contents::Primitive(_) => {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                },
                Contents::Constructed(inner) => inner,
            };
            callback(BERReader::new(inner))
        })
    }

    /// Reads an implicitly tagged value.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna::{self,Tag};
    /// let data = &[131, 1, 10];
    /// let asn = yasna::parse_der(data, |reader| {
    ///     reader.read_tagged_implicit(Tag::context(3), |reader| {
    ///         reader.read_i64()
    ///     })
    /// }).unwrap();
    /// assert_eq!(asn, 10);
    /// ```
    pub fn read_tagged_implicit<T, F>(self, tag: Tag, callback: F)
            -> ASN1Result<T>
            where F: for<'c> FnOnce(BERReader<'a, 'c>) -> ASN1Result<T> {
        let tag = self.implicit_tag.unwrap_or(tag);
        return callback(BERReader {
            inner: self.inner,
            implicit_tag: Some(tag),
        });
    }

    /// Lookaheads the tag in the next value. Used to parse CHOICE values.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna;
    /// use yasna::tags::*;
    /// let data = &[48, 5, 2, 1, 10, 5, 0];
    /// let asn = yasna::parse_der(data, |reader| {
    ///     reader.collect_sequence_of(|reader| {
    ///         let tag = reader.lookahead_tag()?;
    ///         let choice;
    ///         if tag == TAG_INTEGER {
    ///             choice = Some(reader.read_i64()?);
    ///         } else {
    ///             reader.read_null()?;
    ///             choice = None;
    ///         }
    ///         return Ok(choice);
    ///     })
    /// }).unwrap();
    /// assert_eq!(&asn, &[Some(10), None]);
    /// ```
    pub fn lookahead_tag(&self) -> ASN1Result<Tag> {
        self.inner.lookahead_tag()
    }

    pub fn read_with_buffer<T, F>(self, callback: F)
            -> ASN1Result<(T, &'a [u8])>
            where F: for<'c> FnOnce(BERReader<'a, 'c>) -> ASN1Result<T> {
        let implicit_tag = self.implicit_tag;
        self.inner.read_with_buffer(|inner| {
            callback(BERReader {
                inner,
                implicit_tag,
            })
        })
    }

    /// Read an arbitrary (tag, value) pair as a TaggedDerValue.
    /// The length is not included in the returned payload. If the
    /// payload has indefinite-length encoding, the EOC bytes are
    /// included in the returned payload.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna;
    /// use yasna::models::TaggedDerValue;
    /// use yasna::tags::TAG_OCTETSTRING;
    /// let data = b"\x04\x06Hello!";
    /// let res = yasna::parse_der(data, |reader| reader.read_tagged_der()).unwrap();
    /// assert_eq!(res, TaggedDerValue::from_tag_and_bytes(TAG_OCTETSTRING, b"Hello!".to_vec()));
    /// ```
    pub fn read_tagged_der(self) -> ASN1Result<TaggedDerValue> {
        let (tag, pcbit, data_pos) = self.inner.skip_general()?;
        Ok(TaggedDerValue::from_tag_pc_and_bytes(
                tag,
                pcbit,
                self.inner.buf[data_pos..self.inner.pos].to_vec()))
    }

    /// Reads a DER object as raw bytes. Tag and length are included
    /// in the returned buffer. For indefinite length encoding, EOC bytes
    /// are included in the returned buffer as well.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna;
    /// let data = b"\x04\x06Hello!";
    /// let res = yasna::parse_der(data, |reader| reader.read_der()).unwrap();
    /// assert_eq!(res, data);
    /// ```
    pub fn read_der(self) -> ASN1Result<Vec<u8>> {
        Ok(self.inner.read_with_buffer(|inner| {
            inner.skip_general()
        })?.1.to_owned())
    }
}

/// A reader object for a sequence of BER/DER-encoded ASN.1 data.
///
/// The main source of this object is the [`read_sequence`] method from
/// [`BERReader`].
///
/// [`read_sequence`]: BERReader::read_sequence
///
/// # Examples
///
/// ```
/// use yasna;
/// let data = &[48, 6, 2, 1, 10, 1, 1, 255];
/// let asn = yasna::parse_der(data, |reader| {
///     reader.read_sequence(|reader| {
///         let i = reader.next().read_i64()?;
///         let b = reader.next().read_bool()?;
///         return Ok((i, b));
///     })
/// }).unwrap();
/// assert_eq!(asn, (10, true));
/// ```
#[derive(Debug)]
pub struct BERReaderSeq<'a, 'b> where 'a: 'b {
    inner: &'b mut BERReaderImpl<'a>,
}

impl<'a, 'b> BERReaderSeq<'a, 'b> {
    /// Tells which format we are parsing, BER or DER.
    pub fn mode(&self) -> BERMode {
        self.inner.mode
    }

    /// Generates a new [`BERReader`].
    pub fn next<'c>(&'c mut self) -> BERReader<'a, 'c> {
        BERReader::new(self.inner)
    }

    /// Tries to read an ASN.1 value. If it fails at the first tag,
    /// it doesn't consume buffer and returns `None`.
    ///
    /// Used to parse OPTIONAL elements.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna;
    /// let data = &[48, 3, 1, 1, 255];
    /// let asn = yasna::parse_der(data, |reader| {
    ///     reader.read_sequence(|reader| {
    ///         let i = reader.read_optional(|reader| {
    ///             reader.read_i64()
    ///         })?;
    ///         let b = reader.next().read_bool()?;
    ///         return Ok((i, b));
    ///     })
    /// }).unwrap();
    /// assert_eq!(asn, (None, true));
    /// ```
    pub fn read_optional<T, F>(&mut self, callback: F)
            -> ASN1Result<Option<T>>
            where F: for<'c> FnOnce(BERReader<'a, 'c>) -> ASN1Result<T> {
        self.inner.read_optional(|inner| {
            callback(BERReader::new(inner))
        })
    }

    /// Similar to [`read_optional`](Self::read_optional),
    /// but uses `default` if it fails.
    ///
    /// `T: Eq` is required because it fails in DER mode if the read value
    /// is equal to `default`.
    ///
    /// Used to parse DEFAULT elements.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna;
    /// let data = &[48, 3, 1, 1, 255];
    /// let asn = yasna::parse_der(data, |reader| {
    ///     reader.read_sequence(|reader| {
    ///         let i = reader.read_default(10, |reader| {
    ///             reader.read_i64()
    ///         })?;
    ///         let b = reader.next().read_bool()?;
    ///         return Ok((i, b));
    ///     })
    /// }).unwrap();
    /// assert_eq!(asn, (10, true));
    /// ```
    pub fn read_default<T, F>(&mut self, default: T, callback: F)
            -> ASN1Result<T>
            where F: for<'c> FnOnce(BERReader<'a, 'c>) -> ASN1Result<T>,
            T: Eq {
        match self.read_optional(callback)? {
            Some(result) => {
                if self.inner.mode == BERMode::Der && result == default {
                    return Err(
                        ASN1Error::new(ASN1ErrorKind::Invalid));
                }
                return Ok(result);
            },
            None => Ok(default),
        }
    }

    pub fn read_with_buffer<T, F>(&mut self, callback: F)
            -> ASN1Result<(T, &'a [u8])>
            where F: for<'c> FnOnce(
                &mut BERReaderSeq<'a, 'c>) -> ASN1Result<T> {
        self.inner.read_with_buffer(|inner| {
            callback(&mut BERReaderSeq { inner, })
        })
    }
}

/// A reader object for a set of BER/DER-encoded ASN.1 data.
///
/// The main source of this object is the [`read_set`](BERReader::read_set)
/// method from [`BERReader`].
///
/// # Examples
///
/// ```
/// use yasna;
/// use yasna::tags::{TAG_INTEGER,TAG_BOOLEAN};
/// let data = &[49, 6, 1, 1, 255, 2, 1, 10];
/// let asn = yasna::parse_der(data, |reader| {
///     reader.read_set(|reader| {
///         let i = reader.next(&[TAG_INTEGER])?.read_i64()?;
///         let b = reader.next(&[TAG_BOOLEAN])?.read_bool()?;
///         return Ok((i, b));
///     })
/// }).unwrap();
/// assert_eq!(asn, (10, true));
/// ```
#[derive(Debug)]
pub struct BERReaderSet<'a, 'b> where 'a: 'b {
    impl_ref: &'b mut BERReaderImpl<'a>,
    elements: &'b mut Vec<(Tag, &'a [u8], usize)>,
}

impl<'a, 'b> BERReaderSet<'a, 'b> {
    /// Tells which format we are parsing, BER or DER.
    pub fn mode(&self) -> BERMode {
        self.impl_ref.mode
    }

    /// Generates a new [`BERReader`].
    ///
    /// This method needs `tag_hint` to determine the position of the data.
    pub fn next<'c>(&'c mut self, tag_hint: &[Tag])
            -> ASN1Result<BERReader<'a, 'c>> {
        if let Some(elem_pos) = self.elements.iter().position(|&(tag,_,_)| {
            tag_hint.contains(&tag)
        }) {
            let (_, buf, pos) = self.elements.remove(elem_pos);
            *self.impl_ref = BERReaderImpl::with_pos(
                buf, pos, self.impl_ref.mode);
            return Ok(BERReader::new(self.impl_ref))
        } else {
            return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
        }
    }

    /// If there is a set element with a tag in `tag_hint`, reads an ASN.1
    /// value from that element and returns `Some(_)`.
    /// Otherwise, returns `None`.
    ///
    /// Used to parse OPTIONAL elements.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna;
    /// use yasna::tags::*;
    /// let data = &[49, 3, 1, 1, 255];
    /// let asn = yasna::parse_der(data, |reader| {
    ///     reader.read_set(|reader| {
    ///         let i = reader.read_optional(&[TAG_INTEGER], |reader| {
    ///             reader.read_i64()
    ///         })?;
    ///         let b = reader.next(&[TAG_BOOLEAN])?.read_bool()?;
    ///         return Ok((i, b));
    ///     })
    /// }).unwrap();
    /// assert_eq!(asn, (None, true));
    /// ```
    pub fn read_optional<T, F>(&mut self, tag_hint: &[Tag], callback: F)
            -> ASN1Result<Option<T>>
            where F: for<'c> FnOnce(BERReader<'a, 'c>) -> ASN1Result<T> {
        if let Some(elem_pos) = self.elements.iter().position(|&(tag,_,_)| {
            tag_hint.contains(&tag)
        }) {
            let (_, buf, pos) = self.elements.remove(elem_pos);
            let mut reader_impl = BERReaderImpl::with_pos(
                buf, pos, self.impl_ref.mode);
            let result = callback(BERReader::new(&mut reader_impl))?;
            reader_impl.end_of_buf()?;
            return Ok(Some(result));
        } else {
            return Ok(None);
        }
    }

    /// Similar to [`read_optional`](Self::read_optional),
    /// but uses `default` if it fails.
    ///
    /// `T: Eq` is required because it fails in DER mode if the read value
    /// is equal to `default`.
    ///
    /// Used to parse DEFAULT elements.
    ///
    /// # Examples
    ///
    /// ```
    /// use yasna;
    /// use yasna::tags::*;
    /// let data = &[49, 3, 1, 1, 255];
    /// let asn = yasna::parse_der(data, |reader| {
    ///     reader.read_set(|reader| {
    ///         let i = reader.read_default(&[TAG_INTEGER], 10, |reader| {
    ///             reader.read_i64()
    ///         })?;
    ///         let b = reader.next(&[TAG_BOOLEAN])?.read_bool()?;
    ///         return Ok((i, b));
    ///     })
    /// }).unwrap();
    /// assert_eq!(asn, (10, true));
    /// ```
    pub fn read_default<T, F>
            (&mut self, tag_hint: &[Tag], default: T, callback: F)
            -> ASN1Result<T>
            where F: for<'c> FnOnce(BERReader<'a, 'c>) -> ASN1Result<T>,
            T: Eq {
        let mode = self.impl_ref.mode;
        match self.read_optional(tag_hint, callback)? {
            Some(result) => {
                if mode == BERMode::Der && result == default {
                    return Err(
                        ASN1Error::new(ASN1ErrorKind::Invalid));
                }
                return Ok(result);
            },
            None => Ok(default),
        }
    }
}


#[cfg(test)]
mod tests;
