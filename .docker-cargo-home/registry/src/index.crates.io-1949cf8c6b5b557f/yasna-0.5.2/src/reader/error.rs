// Copyright 2016 Masaki Hara
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(feature = "std")]
use std::{error::Error, io};
use core::fmt::{self, Display};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ASN1Error {
    kind: ASN1ErrorKind,
}
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ASN1ErrorKind {
    Eof, Extra, IntegerOverflow, StackOverflow, Invalid,
}

pub type ASN1Result<T> = Result<T, ASN1Error>;

impl ASN1Error {
    pub fn new(kind: ASN1ErrorKind) -> Self {
        ASN1Error {
            kind,
        }
    }

    pub fn kind(&self) -> ASN1ErrorKind {
        self.kind
    }
}

impl Display for ASN1Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{:?}", self)?;
        return Ok(());
    }
}

#[cfg(feature = "std")]
impl Error for ASN1Error {
    fn description(&self) -> &str {
        match self.kind {
            ASN1ErrorKind::Eof => "End of file",
            ASN1ErrorKind::Extra => "Extra data in file",
            ASN1ErrorKind::IntegerOverflow => "Integer overflow",
            ASN1ErrorKind::StackOverflow => "Stack overflow",
            ASN1ErrorKind::Invalid => "Invalid data",
        }
    }
}

#[cfg(feature = "std")]
impl From<ASN1Error> for io::Error {
    fn from(e: ASN1Error) -> Self {
        return io::Error::new(io::ErrorKind::InvalidData, e);
    }
}
