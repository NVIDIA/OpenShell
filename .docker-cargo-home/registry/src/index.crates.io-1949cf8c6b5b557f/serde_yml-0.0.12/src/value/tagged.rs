// Copyright notice and licensing information.
// SPDX-License-Identifier: Apache-2.0 OR MIT indicates dual licensing under Apache 2.0 or MIT licenses.
// Copyright © 2024 Serde YML, Seamless YAML Serialization for Rust. All rights reserved.

use crate::{
    modules::error::Error,
    value::{
        de::{MapDeserializer, SeqDeserializer},
        Value,
    },
};
use serde::{
    de::{
        value::StrDeserializer, Deserialize, DeserializeSeed,
        Deserializer, EnumAccess, Error as _, VariantAccess, Visitor,
    },
    forward_to_deserialize_any,
    ser::{Serialize, SerializeMap, Serializer},
};
use std::{
    cmp::Ordering,
    convert::TryFrom,
    fmt::{self, Debug, Display},
    hash::{Hash, Hasher},
    str::from_utf8,
};

/// A representation of YAML's `!Tag` syntax, used for enums.
#[derive(Clone)]
pub struct Tag {
    /// The string representation of the tag.
    pub string: String,
}

/// A `Tag` + `Value` representing a tagged YAML scalar, sequence, or mapping.
#[derive(Clone, PartialEq, PartialOrd, Hash, Debug)]
pub struct TaggedValue {
    /// The tag of the tagged value.
    pub tag: Tag,
    /// The value of the tagged value.
    pub value: Value,
}

impl TaggedValue {
    /// Creates a new `TaggedValue`.
    pub fn copy(&self) -> TaggedValue {
        TaggedValue {
            tag: self.tag.clone(),
            value: self.value.clone(),
        }
    }
}

impl Tag {
    /// Creates a new `Tag`.
    pub fn new(string: impl Into<String>) -> Self {
        let tag: String = string.into();
        assert!(!tag.is_empty(), "empty YAML tag is not allowed");
        Tag { string: tag }
    }
}

impl TryFrom<&[u8]> for Tag {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let tag_str = from_utf8(bytes)
            .map_err(|_| Error::custom("invalid UTF-8 sequence"))?;
        Ok(Tag::new(tag_str))
    }
}

impl Value {
    pub(crate) fn untag(self) -> Self {
        let mut cur = self;
        while let Value::Tagged(tagged) = cur {
            cur = tagged.value;
        }
        cur
    }

    pub(crate) fn untag_ref(&self) -> &Self {
        let mut cur = self;
        while let Value::Tagged(tagged) = cur {
            cur = &tagged.value;
        }
        cur
    }

    pub(crate) fn untag_mut(&mut self) -> &mut Self {
        let mut cur = self;
        while let Value::Tagged(tagged) = cur {
            cur = &mut tagged.value;
        }
        cur
    }
}

/// Returns the portion of a YAML tag after the exclamation mark, if any.
///
/// A YAML tag is denoted by a leading exclamation mark (`!`). If the input value is empty, it is considered not to be a tag. If the input value starts with an exclamation mark, it is considered to be a tag but not a bang tag (i.e., `!foo` is a tag, but `!bar` is not). If the input value does not start with an exclamation mark, it is considered not to be a tag.
///
/// # Examples
///
/// ```
/// use serde_yml::value::tagged::nobang;
///
/// let result = nobang("foo");
/// assert_eq!("foo", result);
///
/// let result = nobang("!bar");
/// assert_eq!("bar", result);
///
/// let result = nobang("");
/// assert_eq!("", result);
/// ```
pub fn nobang(maybe_banged: &str) -> &str {
    match maybe_banged.strip_prefix('!') {
        Some("") | None => maybe_banged,
        Some(unbanged) => unbanged,
    }
}

impl Eq for Tag {}

impl PartialEq for Tag {
    fn eq(&self, other: &Tag) -> bool {
        PartialEq::eq(nobang(&self.string), nobang(&other.string))
    }
}

impl<T> PartialEq<T> for Tag
where
    T: ?Sized + AsRef<str>,
{
    fn eq(&self, other: &T) -> bool {
        PartialEq::eq(nobang(&self.string), nobang(other.as_ref()))
    }
}

impl Ord for Tag {
    fn cmp(&self, other: &Self) -> Ordering {
        Ord::cmp(nobang(&self.string), nobang(&other.string))
    }
}

impl PartialOrd for Tag {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Hash for Tag {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        nobang(&self.string).hash(hasher);
    }
}

impl Display for Tag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "!{}", nobang(&self.string))
    }
}

impl Debug for Tag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(self, formatter)
    }
}

impl Serialize for TaggedValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        struct SerializeTag<'a>(&'a Tag);

        impl Serialize for SerializeTag<'_> {
            fn serialize<S>(
                &self,
                serializer: S,
            ) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.collect_str(self.0)
            }
        }

        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry(&SerializeTag(&self.tag), &self.value)?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for TaggedValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TaggedValueVisitor;

        impl<'de> Visitor<'de> for TaggedValueVisitor {
            type Value = TaggedValue;

            fn expecting(
                &self,
                formatter: &mut fmt::Formatter<'_>,
            ) -> fmt::Result {
                formatter.write_str("a YAML value with a !Tag")
            }

            fn visit_enum<A>(
                self,
                data: A,
            ) -> Result<Self::Value, A::Error>
            where
                A: EnumAccess<'de>,
            {
                let (tag, contents) =
                    data.variant_seed(TagStringVisitor)?;
                let value = contents.newtype_variant()?;
                Ok(TaggedValue { tag, value })
            }
        }

        deserializer.deserialize_any(TaggedValueVisitor)
    }
}

impl<'de> Deserializer<'de> for TaggedValue {
    type Error = Error;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_enum(self)
    }

    fn deserialize_ignored_any<V>(
        self,
        visitor: V,
    ) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        drop(self);
        visitor.visit_unit()
    }

    forward_to_deserialize_any! {
        bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string bytes
        byte_buf option unit unit_struct newtype_struct seq tuple tuple_struct
        map struct enum identifier
    }
}

impl<'de> EnumAccess<'de> for TaggedValue {
    type Error = Error;
    type Variant = Value;

    fn variant_seed<V>(
        self,
        seed: V,
    ) -> Result<(V::Value, Self::Variant), Error>
    where
        V: DeserializeSeed<'de>,
    {
        let tag =
            StrDeserializer::<Error>::new(nobang(&self.tag.string));
        let value = seed.deserialize(tag)?;
        Ok((value, self.value))
    }
}

impl<'de> VariantAccess<'de> for Value {
    type Error = Error;

    fn unit_variant(self) -> Result<(), Error> {
        Deserialize::deserialize(self)
    }

    fn newtype_variant_seed<T>(self, seed: T) -> Result<T::Value, Error>
    where
        T: DeserializeSeed<'de>,
    {
        seed.deserialize(self)
    }

    fn tuple_variant<V>(
        self,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        if let Value::Sequence(v) = self {
            Deserializer::deserialize_any(
                SeqDeserializer::new(v),
                visitor,
            )
        } else {
            Err(Error::invalid_type(
                self.unexpected(),
                &"tuple variant",
            ))
        }
    }

    fn struct_variant<V>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        if let Value::Mapping(v) = self {
            Deserializer::deserialize_any(
                MapDeserializer::new(v),
                visitor,
            )
        } else {
            Err(Error::invalid_type(
                self.unexpected(),
                &"struct variant",
            ))
        }
    }
}

pub(crate) struct TagStringVisitor;

impl Visitor<'_> for TagStringVisitor {
    type Value = Tag;

    fn expecting(
        &self,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        formatter.write_str("a YAML tag string")
    }

    fn visit_str<E>(self, string: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_string(string.to_owned())
    }

    fn visit_string<E>(self, string: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if string.is_empty() {
            return Err(E::custom("empty YAML tag is not allowed"));
        }
        Ok(Tag::new(string))
    }
}

impl<'de> DeserializeSeed<'de> for TagStringVisitor {
    type Value = Tag;

    fn deserialize<D>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_string(self)
    }
}

/// A tagged value with an optional tag.
#[derive(Debug)]
pub enum MaybeTag<T> {
    /// The tag.
    Tag(String),
    /// The value.
    NotTag(T),
}

/// Returns a `MaybeTag` enum indicating whether the input value is a YAML tag or not.
///
/// A YAML tag is denoted by a leading exclamation mark (`!`). If the input value is empty, it is considered not to be a tag. If the input value starts with an exclamation mark, it is considered to be a tag but not a bang tag (i.e., `!foo` is a tag, but `!bar` is not). If the input value does not start with an exclamation mark, it is considered not to be a tag.
///
/// # Examples
///
/// ```
/// use serde_yml::value::tagged::check_for_tag;
/// use serde_yml::value::tagged::MaybeTag;
///
/// let result = check_for_tag(&"foo".to_owned());
/// assert!(
///     matches!(result, MaybeTag::NotTag(_)),
///     "Expected MaybeTag::NotTag but got {:?}", result
/// );
/// ```
///
pub fn check_for_tag<T>(value: &T) -> MaybeTag<String>
where
    T: ?Sized + Display,
{
    enum CheckForTag {
        Empty,
        Bang,
        Tag(String),
        NotTag(String),
    }

    let check_for_tag = match format!("{}", value).as_str() {
        "" => CheckForTag::Empty,
        "!" => CheckForTag::Bang,
        tag => {
            if tag.starts_with('!') {
                CheckForTag::Tag(tag.to_owned())
            } else {
                CheckForTag::NotTag(tag.to_owned())
            }
        }
    };

    match check_for_tag {
        CheckForTag::Empty => MaybeTag::NotTag(String::new()),
        CheckForTag::Bang => MaybeTag::NotTag("!".to_owned()),
        CheckForTag::Tag(string) => MaybeTag::Tag(string),
        CheckForTag::NotTag(string) => MaybeTag::NotTag(string),
    }
}
