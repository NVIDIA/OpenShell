use crate::{
    de,
    modules::error::{self, Error, ErrorImpl},
};
use serde::{
    de::{Unexpected, Visitor},
    forward_to_deserialize_any, Deserialize, Deserializer, Serialize,
    Serializer,
};
use std::{
    cmp::Ordering,
    fmt::{self, Display},
    hash::{Hash, Hasher},
    str::FromStr,
};

/// Represents a YAML number, whether integer or floating point.
#[derive(Copy, Clone, PartialEq, PartialOrd)]
pub struct Number {
    n: N,
}

/// Enum representing different variants of numbers.
#[derive(Copy, Clone, Debug)]
#[repr(C)]
enum N {
    /// Represents a positive integer.
    PositiveInteger(u64),
    /// Represents a negative integer.
    NegativeInteger(i64),
    /// Represents a floating point number.
    Float(f64),
}

impl Number {
    /// Returns true if the `Number` is an integer between `i64::MIN` and `i64::MAX`.
    ///
    /// For any Number on which `is_i64` returns true, `as_i64` is guaranteed to
    /// return the integer value.
    #[inline]
    #[allow(clippy::cast_sign_loss)]
    pub fn is_i64(&self) -> bool {
        match self.n {
            N::PositiveInteger(v) => v <= i64::MAX as u64,
            N::NegativeInteger(_) => true,
            N::Float(_) => false,
        }
    }

    /// Returns true if the `Number` is an integer between zero and `u64::MAX`.
    ///
    /// For any Number on which `is_u64` returns true, `as_u64` is guaranteed to
    /// return the integer value.
    #[inline]
    pub fn is_u64(&self) -> bool {
        match self.n {
            N::PositiveInteger(_) => true,
            N::NegativeInteger(_) | N::Float(_) => false,
        }
    }

    /// Returns true if the `Number` can be represented by f64.
    ///
    /// For any Number on which `is_f64` returns true, `as_f64` is guaranteed to
    /// return the floating point value.
    #[inline]
    pub fn is_f64(&self) -> bool {
        match self.n {
            N::Float(_) => true,
            N::PositiveInteger(_) | N::NegativeInteger(_) => false,
        }
    }

    /// If the `Number` is an integer, represent it as i64 if possible. Returns
    /// None otherwise.
    #[inline]
    pub fn as_i64(&self) -> Option<i64> {
        match self.n {
            N::PositiveInteger(n) => {
                if n <= i64::MAX as u64 {
                    Some(n as i64)
                } else {
                    None
                }
            }
            N::NegativeInteger(n) => Some(n),
            N::Float(_) => None,
        }
    }

    /// If the `Number` is an integer, represent it as u64 if possible. Returns
    /// None otherwise.
    #[inline]
    pub fn as_u64(&self) -> Option<u64> {
        match self.n {
            N::PositiveInteger(n) => Some(n),
            N::NegativeInteger(_) | N::Float(_) => None,
        }
    }

    /// Represents the number as f64 if possible. Returns None otherwise.
    #[inline]
    pub fn as_f64(&self) -> Option<f64> {
        match self.n {
            N::PositiveInteger(n) => Some(n as f64),
            N::NegativeInteger(n) => Some(n as f64),
            N::Float(n) => Some(n),
        }
    }

    /// Returns true if this value is NaN and false otherwise.
    #[inline]
    pub fn is_nan(&self) -> bool {
        match self.n {
            N::PositiveInteger(_) | N::NegativeInteger(_) => false,
            N::Float(f) => f.is_nan(),
        }
    }

    /// Returns true if this value is positive infinity or negative infinity and
    /// false otherwise.
    #[inline]
    pub fn is_infinite(&self) -> bool {
        match self.n {
            N::PositiveInteger(_) | N::NegativeInteger(_) => false,
            N::Float(f) => f.is_infinite(),
        }
    }

    /// Returns true if this number is neither infinite nor NaN.
    #[inline]
    pub fn is_finite(&self) -> bool {
        match self.n {
            N::PositiveInteger(_) | N::NegativeInteger(_) => true,
            N::Float(f) => f.is_finite(),
        }
    }
}

impl Display for Number {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.n {
            N::PositiveInteger(i) => write!(formatter, "{}", i),
            N::NegativeInteger(i) => write!(formatter, "{}", i),
            N::Float(f) if f.is_nan() => formatter.write_str(".nan"),
            N::Float(f) if f.is_infinite() => {
                if f.is_sign_negative() {
                    formatter.write_str("-.inf")
                } else {
                    formatter.write_str(".inf")
                }
            }
            N::Float(f) => {
                write!(formatter, "{}", ryu::Buffer::new().format(f))
            }
        }
    }
}

impl FromStr for Number {
    type Err = Error;

    fn from_str(repr: &str) -> Result<Self, Self::Err> {
        if let Ok(result) = de::visit_int(NumberVisitor, repr) {
            return result;
        }
        if !de::digits_but_not_number(repr) {
            if let Some(float) = de::parse_f64(repr) {
                return Ok(float.into());
            }
        }
        Err(error::new(ErrorImpl::FailedToParseNumber))
    }
}

impl PartialEq for N {
    fn eq(&self, other: &N) -> bool {
        match (*self, *other) {
            (N::PositiveInteger(a), N::PositiveInteger(b)) => a == b,
            (N::NegativeInteger(a), N::NegativeInteger(b)) => a == b,
            (N::Float(a), N::Float(b)) => {
                if a.is_nan() && b.is_nan() {
                    // YAML only has one NaN;
                    // the bit representation isn't preserved
                    true
                } else {
                    a == b
                }
            }
            _ => false,
        }
    }
}

impl PartialOrd for N {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (*self, *other) {
            (N::Float(a), N::Float(b)) => {
                if a.is_nan() && b.is_nan() {
                    // YAML only has one NaN
                    Some(Ordering::Equal)
                } else {
                    a.partial_cmp(&b)
                }
            }
            _ => Some(self.total_cmp(other)),
        }
    }
}

impl N {
    fn total_cmp(&self, other: &Self) -> Ordering {
        match (*self, *other) {
            (N::PositiveInteger(a), N::PositiveInteger(b)) => a.cmp(&b),
            (N::NegativeInteger(a), N::NegativeInteger(b)) => a.cmp(&b),
            // negint is always less than zero
            (N::NegativeInteger(_), N::PositiveInteger(_)) => {
                Ordering::Less
            }
            (N::PositiveInteger(_), N::NegativeInteger(_)) => {
                Ordering::Greater
            }
            (N::Float(a), N::Float(b)) => {
                a.partial_cmp(&b).unwrap_or_else(|| {
                    // arbitrarily sort the NaN last
                    if !a.is_nan() {
                        Ordering::Less
                    } else if !b.is_nan() {
                        Ordering::Greater
                    } else {
                        Ordering::Equal
                    }
                })
            }
            // arbitrarily sort integers below floats
            (_, N::Float(_)) => Ordering::Less,
            (N::Float(_), _) => Ordering::Greater,
        }
    }
}

impl Number {
    pub(crate) fn total_cmp(&self, other: &Self) -> Ordering {
        self.n.total_cmp(&other.n)
    }
}

impl Serialize for Number {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.n {
            N::PositiveInteger(i) => serializer.serialize_u64(i),
            N::NegativeInteger(i) => serializer.serialize_i64(i),
            N::Float(f) => serializer.serialize_f64(f),
        }
    }
}

struct NumberVisitor;

impl Visitor<'_> for NumberVisitor {
    type Value = Number;

    fn expecting(
        &self,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        formatter.write_str("a number")
    }

    #[inline]
    fn visit_i64<E>(self, value: i64) -> Result<Number, E> {
        Ok(value.into())
    }

    #[inline]
    fn visit_u64<E>(self, value: u64) -> Result<Number, E> {
        Ok(value.into())
    }

    #[inline]
    fn visit_f64<E>(self, value: f64) -> Result<Number, E> {
        Ok(value.into())
    }
}

impl<'de> Deserialize<'de> for Number {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Number, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(NumberVisitor)
    }
}

impl<'de> Deserializer<'de> for Number {
    type Error = Error;

    #[inline]
    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        match self.n {
            N::PositiveInteger(i) => visitor.visit_u64(i),
            N::NegativeInteger(i) => visitor.visit_i64(i),
            N::Float(f) => visitor.visit_f64(f),
        }
    }

    forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map struct enum identifier ignored_any
    }
}

impl<'de> Deserializer<'de> for &Number {
    type Error = Error;

    #[inline]
    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        match self.n {
            N::PositiveInteger(i) => visitor.visit_u64(i),
            N::NegativeInteger(i) => visitor.visit_i64(i),
            N::Float(f) => visitor.visit_f64(f),
        }
    }

    forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map struct enum identifier ignored_any
    }
}

macro_rules! from_signed {
    ($($signed_ty:ident)*) => {
        $(
            impl From<$signed_ty> for Number {
                #[inline]
                #[allow(clippy::cast_sign_loss)]
                fn from(i: $signed_ty) -> Self {
                    if i < 0 {
                        Number { n: N::NegativeInteger(i.try_into().unwrap()) }
                    } else {
                        Number { n: N::PositiveInteger(i as u64) }
                    }
                }
            }
        )*
    };
}

macro_rules! from_unsigned {
    ($($unsigned_ty:ident)*) => {
        $(
            impl From<$unsigned_ty> for Number {
                #[inline]
                fn from(u: $unsigned_ty) -> Self {
                    Number { n: N::PositiveInteger(u.try_into().unwrap()) }
                }
            }
        )*
    };
}

from_signed!(i8 i16 i32 i64 isize);
from_unsigned!(u8 u16 u32 u64 usize);

impl From<f32> for Number {
    fn from(f: f32) -> Self {
        Number::from(f as f64)
    }
}

impl From<f64> for Number {
    fn from(mut f: f64) -> Self {
        if f.is_nan() {
            // Destroy NaN sign, signalling, and payload. YAML only has one NaN.
            f = f64::NAN.copysign(1.0);
        }
        Number { n: N::Float(f) }
    }
}

impl Hash for Number {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match &self.n {
            N::PositiveInteger(u) => {
                u.hash(state);
            }
            N::NegativeInteger(i) => {
                i.hash(state);
            }
            N::Float(f) => {
                f.to_bits().hash(state);
            }
        }
    }
}

/// Returns an `Unexpected` variant based on the given `Number`.
pub(crate) fn unexpected(number: &Number) -> Unexpected<'_> {
    match number.n {
        N::PositiveInteger(u) => Unexpected::Unsigned(u),
        N::NegativeInteger(i) => Unexpected::Signed(i),
        N::Float(f) => Unexpected::Float(f),
    }
}
