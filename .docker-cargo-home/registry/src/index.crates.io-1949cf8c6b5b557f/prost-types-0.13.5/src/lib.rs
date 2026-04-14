#![doc(html_root_url = "https://docs.rs/prost-types/0.13.5")]

//! Protocol Buffers well-known types.
//!
//! Note that the documentation for the types defined in this crate are generated from the Protobuf
//! definitions, so code examples are not in Rust.
//!
//! See the [Protobuf reference][1] for more information about well-known types.
//!
//! ## Any
//!
//! The well-known [`Any`] type contains an arbitrary serialized message along with a URL that
//! describes the type of the serialized message. Every message that also implements [`Name`]
//! can be serialized to and deserialized from [`Any`].
//!
//! ### Serialization
//!
//! A message can be serialized using [`Any::from_msg`].
//!
//! ```rust
//! let message = Timestamp::date(2000, 1, 1).unwrap();
//! let any = Any::from_msg(&message).unwrap();
//! ```
//!
//! ### Deserialization
//!
//! A message can be deserialized using [`Any::to_msg`].
//!
//! ```rust
//! # let message = Timestamp::date(2000, 1, 1).unwrap();
//! # let any = Any::from_msg(&message).unwrap();
//! #
//! let message = any.to_msg::<Timestamp>().unwrap();
//! ```
//!
//! ## Feature Flags
//! - `std`: Enable integration with standard library. Disable this feature for `no_std` support. This feature is enabled by default.
//! - `arbitrary`: Enable integration with crate `arbitrary`. All types on this crate will implement `trait Arbitrary`.
//!
//! [1]: https://developers.google.com/protocol-buffers/docs/reference/google.protobuf

#![cfg_attr(not(feature = "std"), no_std)]

#[rustfmt::skip]
pub mod compiler;
mod datetime;
#[rustfmt::skip]
mod protobuf;

use core::convert::TryFrom;
use core::fmt;
use core::str::FromStr;
use core::time;

use prost::alloc::format;
use prost::alloc::string::String;
use prost::alloc::vec::Vec;
use prost::{DecodeError, EncodeError, Message, Name};

pub use protobuf::*;

// The Protobuf `Duration` and `Timestamp` types can't delegate to the standard library equivalents
// because the Protobuf versions are signed. To make them easier to work with, `From` conversions
// are defined in both directions.

const NANOS_PER_SECOND: i32 = 1_000_000_000;
const NANOS_MAX: i32 = NANOS_PER_SECOND - 1;

const PACKAGE: &str = "google.protobuf";

mod any;

mod duration;
pub use duration::DurationError;

mod timestamp;
pub use timestamp::TimestampError;

mod type_url;
pub(crate) use type_url::{type_url_for, TypeUrl};

mod conversions;
