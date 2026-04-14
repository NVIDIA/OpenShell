use crate::{Mapping, Value};
use std::borrow::Cow;
use std::iter::FromIterator;

use super::Number;

// Implement conversion from number types to `Value`.
impl<T> From<T> for Value
where
    T: Into<Number>,
{
    fn from(n: T) -> Self {
        Value::Number(n.into())
    }
}

impl From<bool> for Value {
    /// Convert boolean to `Value`
    ///
    /// # Examples
    ///
    /// ```
    /// use serde_yml::Value;
    ///
    /// let b = false;
    /// let x: Value = b.into();
    /// assert_eq!(x, Value::Bool(false));
    /// ```
    fn from(f: bool) -> Self {
        Value::Bool(f)
    }
}

impl From<String> for Value {
    /// Convert `String` to `Value`
    ///
    /// # Examples
    ///
    /// ```
    /// use serde_yml::Value;
    ///
    /// let s: String = "lorem".to_string();
    /// let x: Value = s.into();
    /// assert_eq!(x, Value::String("lorem".to_string()));
    /// ```
    fn from(f: String) -> Self {
        Value::String(f)
    }
}

impl From<&str> for Value {
    /// Convert string slice to `Value`
    ///
    /// # Examples
    ///
    /// ```
    /// use serde_yml::Value;
    ///
    /// let s: &str = "lorem";
    /// let x: Value = s.into();
    /// assert_eq!(x, Value::String("lorem".to_string()));
    /// ```
    fn from(f: &str) -> Self {
        Value::String(f.to_string())
    }
}

impl<'a> From<Cow<'a, str>> for Value {
    /// Convert copy-on-write string to `Value`
    ///
    /// # Examples
    ///
    /// ```
    /// use serde_yml::Value;
    /// use std::borrow::Cow;
    ///
    /// let s: Cow<str> = Cow::Borrowed("lorem");
    /// let x: Value = s.into();
    /// assert_eq!(x, Value::String("lorem".to_string()));
    /// ```
    ///
    /// ```
    /// use serde_yml::Value;
    /// use std::borrow::Cow;
    ///
    /// let s: Cow<str> = Cow::Owned("lorem".to_string());
    /// let x: Value = s.into();
    /// assert_eq!(x, Value::String("lorem".to_string()));
    /// ```
    fn from(f: Cow<'a, str>) -> Self {
        Value::String(f.into_owned())
    }
}

impl From<Mapping> for Value {
    /// Convert map (with string keys) to `Value`
    ///
    /// # Examples
    ///
    /// ```
    /// use serde_yml::{Mapping, Value};
    ///
    /// let mut m = Mapping::new();
    /// m.insert("Lorem".into(), "ipsum".into());
    /// let x: Value = m.into();
    /// assert_eq!(x, Value::Mapping(Mapping::from_iter(vec![("Lorem".into(), "ipsum".into())])));
    /// ```
    fn from(f: Mapping) -> Self {
        Value::Mapping(f)
    }
}

impl<T: Into<Value>> From<Vec<T>> for Value {
    /// Convert a `Vec` to `Value`
    ///
    /// # Examples
    ///
    /// ```
    /// use serde_yml::Value;
    ///
    /// let v = vec!["lorem", "ipsum", "dolor"];
    /// let x: Value = v.into();
    /// assert_eq!(x, Value::Sequence(vec!["lorem".into(), "ipsum".into(), "dolor".into()]));
    /// ```
    fn from(f: Vec<T>) -> Self {
        Value::Sequence(f.into_iter().map(Into::into).collect())
    }
}

impl<'a, T: Clone + Into<Value>> From<&'a [T]> for Value {
    /// Convert a slice to `Value`
    ///
    /// # Examples
    ///
    /// ```
    /// use serde_yml::Value;
    ///
    /// let v: &[&str] = &["lorem", "ipsum", "dolor"];
    /// let x: Value = v.into();
    /// assert_eq!(x, Value::Sequence(vec!["lorem".into(), "ipsum".into(), "dolor".into()]));
    /// ```
    fn from(f: &'a [T]) -> Self {
        Value::Sequence(f.iter().cloned().map(Into::into).collect())
    }
}

impl<T: Into<Value>> FromIterator<T> for Value {
    /// Convert an iteratable type to a YAML sequence
    ///
    /// # Examples
    ///
    /// ```
    /// use serde_yml::Value;
    ///
    /// let v = std::iter::repeat(42).take(5);
    /// let x: Value = v.collect();
    /// assert_eq!(x, Value::Sequence(vec![42.into(), 42.into(), 42.into(), 42.into(), 42.into()]));
    /// ```
    ///
    /// ```
    /// use serde_yml::Value;
    ///
    /// let v: Vec<_> = vec!["lorem", "ipsum", "dolor"];
    /// let x: Value = v.into_iter().collect();
    /// assert_eq!(x, Value::Sequence(vec!["lorem".into(), "ipsum".into(), "dolor".into()]));
    /// ```
    ///
    /// ```
    /// use std::iter::FromIterator;
    /// use serde_yml::Value;
    ///
    /// let x: Value = Value::from_iter(vec!["lorem", "ipsum", "dolor"]);
    /// assert_eq!(x, Value::Sequence(vec!["lorem".into(), "ipsum".into(), "dolor".into()]));
    /// ```
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let vec = iter.into_iter().map(T::into).collect();

        Value::Sequence(vec)
    }
}
