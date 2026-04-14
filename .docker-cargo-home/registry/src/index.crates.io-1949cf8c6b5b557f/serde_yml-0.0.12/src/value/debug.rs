// debug.rs
// This module provides implementations of the `Debug` trait for various types in the `serde_yml` crate.
// It allows for customized formatting when debugging `Value`, `Number`, and `Mapping` types.

use crate::mapping::Mapping;
use crate::value::{Number, Value};
use std::fmt::{self, Debug, Display};

/// Implements the `Debug` trait for `Value`.
/// This allows for customized formatting when debugging `Value` instances.
///
/// # Examples
///
/// ```
/// use serde_yml::Value;
///
/// let value = Value::String("Hello, world!".to_string());
/// println!("{:?}", value);
/// // Output: String("Hello, world!")
/// ```
impl Debug for Value {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Null => formatter.write_str("Null"),
            Value::Bool(boolean) => {
                write!(formatter, "Bool({})", boolean)
            }
            Value::Number(number) => {
                write!(formatter, "Number({})", number)
            }
            Value::String(string) => {
                write!(formatter, "String({:?})", string)
            }
            Value::Sequence(sequence) => {
                formatter.write_str("Sequence ")?;
                formatter.debug_list().entries(sequence).finish()
            }
            Value::Mapping(mapping) => Debug::fmt(mapping, formatter),
            Value::Tagged(tagged) => Debug::fmt(tagged, formatter),
        }
    }
}

/// A wrapper type for `Number` that implements the `Display` trait.
/// This allows for customized formatting when displaying `Number` instances.
struct DisplayNumber<'a>(&'a Number);

/// Implements the `Display` trait for `DisplayNumber`.
/// This allows for customized formatting when displaying `Number` instances.
impl Debug for DisplayNumber<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(self.0, formatter)
    }
}

/// Implements the `Debug` trait for `Number`.
/// This allows for customized formatting when debugging `Number` instances.
///
/// # Examples
///
/// ```
/// use serde_yml::value::Number;
///
/// let number = Number::from(42);
/// println!("{:?}", number);
/// // Output: Number(42)
/// ```
impl Debug for Number {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Number({})", self)
    }
}

/// Implements the `Debug` trait for `Mapping`.
/// This allows for customized formatting when debugging `Mapping` instances.
///
/// # Examples
///
/// ```
/// use serde_yml::{Mapping, Value};
///
/// let mut mapping = Mapping::new();
/// mapping.insert(Value::String("name".to_string()), Value::String("John".to_string()));
/// mapping.insert(Value::String("age".to_string()), Value::Number(30.into()));
/// println!("{:?}", mapping);
/// // Output: Mapping {"name": String("John"), "age": Number(30)}
/// ```
impl Debug for Mapping {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Mapping ")?;
        let mut debug = formatter.debug_map();
        for (k, v) in self {
            let tmp;
            debug.entry(
                match k {
                    Value::Bool(boolean) => boolean,
                    Value::Number(number) => {
                        tmp = DisplayNumber(number);
                        &tmp
                    }
                    Value::String(string) => string,
                    _ => k,
                },
                v,
            );
        }
        debug.finish()
    }
}
