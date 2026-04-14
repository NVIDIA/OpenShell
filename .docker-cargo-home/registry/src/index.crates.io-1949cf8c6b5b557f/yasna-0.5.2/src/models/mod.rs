// Copyright 2016 Masaki Hara
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Provides datatypes which correspond to ASN.1 types.

#![forbid(missing_docs)]

mod oid;
#[cfg(feature = "time")]
mod time;
mod der;

pub use self::oid::{ObjectIdentifier, ParseOidError};
#[cfg(feature = "time")]
pub use self::time::{UTCTime,GeneralizedTime};
pub use self::der::TaggedDerValue;
