use crate::Value;

impl PartialEq<str> for Value {
    /// Compare `str` with YAML value
    ///
    /// # Examples
    ///
    /// ```
    /// # use serde_yml::Value;
    /// assert!(Value::String("lorem".into()) == *"lorem");
    /// ```
    fn eq(&self, other: &str) -> bool {
        self.as_str().map_or(false, |s| s == other)
    }
}

impl PartialEq<&str> for Value {
    /// Compare `&str` with YAML value
    ///
    /// # Examples
    ///
    /// ```
    /// # use serde_yml::Value;
    /// assert!(Value::String("lorem".into()) == "lorem");
    /// ```
    fn eq(&self, other: &&str) -> bool {
        self.as_str().map_or(false, |s| s == *other)
    }
}

impl PartialEq<String> for Value {
    /// Compare YAML value with String
    ///
    /// # Examples
    ///
    /// ```
    /// # use serde_yml::Value;
    /// assert!(Value::String("lorem".into()) == "lorem".to_string());
    /// ```
    fn eq(&self, other: &String) -> bool {
        self.as_str().map_or(false, |s| s == other)
    }
}

impl PartialEq<bool> for Value {
    /// Compare YAML value with bool
    ///
    /// # Examples
    ///
    /// ```
    /// # use serde_yml::Value;
    /// assert!(Value::Bool(true) == true);
    /// ```
    fn eq(&self, other: &bool) -> bool {
        self.as_bool().map_or(false, |b| b == *other)
    }
}

fn compare_numeric<T, U>(i: T, other: U) -> bool
where
    T: PartialEq<U>,
    U: Into<T>,
{
    i == other
}

/// A macro that generates implementations of the `PartialEq` trait for
/// primitive numeric types and `Value` based on the specified conversion
/// method and base type.
///
/// # Examples
///
/// ```
/// use serde_yml::Value;
///
/// let v1: Value = 10.into();
/// assert_eq!(v1, 10);
///
/// let v2: Value = serde_yml::from_str("10").unwrap();
/// assert_eq!(v2, 10);
/// ```
macro_rules! partialeq_numeric {
    ($([$($ty:ty)*], $conversion:ident, $base:ty)*) => {
        $($(
            impl PartialEq<$ty> for Value {
                fn eq(&self, other: &$ty) -> bool {
                    self.$conversion().map_or(false, |i| compare_numeric(i, (*other).try_into().unwrap()))
                }
            }

            impl PartialEq<$ty> for &Value {
                fn eq(&self, other: &$ty) -> bool {
                    self.$conversion().map_or(false, |i| compare_numeric(i, (*other).try_into().unwrap()))
                }
            }

            impl PartialEq<$ty> for &mut Value {
                fn eq(&self, other: &$ty) -> bool {
                    self.$conversion().map_or(false, |i| compare_numeric(i, (*other).try_into().unwrap()))
                }
            }
        )*)*
    }
}

partialeq_numeric! {
    [i8 i16 i32 i64 isize], as_i64, i64
    [u8 u16 u32 u64 usize], as_u64, u64
    [f32 f64], as_f64, f64
}
