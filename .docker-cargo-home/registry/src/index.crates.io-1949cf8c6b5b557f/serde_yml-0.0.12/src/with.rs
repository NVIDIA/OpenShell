//! Customizations to use with Serde's `#[serde(with = …)]` attribute.

/// Serialize/deserialize an enum using a YAML map containing one entry in which
/// the key identifies the variant name.
///
/// # Example
///
/// ```
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize, PartialEq, Debug)]
/// enum Enum {
///     Unit,
///     Newtype(usize),
///     Tuple(usize, usize),
///     Struct { value: usize },
/// }
///
/// #[derive(Serialize, Deserialize, PartialEq, Debug)]
/// struct Struct {
///     #[serde(with = "serde_yml::with::singleton_map")]
///     w: Enum,
///     #[serde(with = "serde_yml::with::singleton_map")]
///     x: Enum,
///     #[serde(with = "serde_yml::with::singleton_map")]
///     y: Enum,
///     #[serde(with = "serde_yml::with::singleton_map")]
///     z: Enum,
/// }
///
///     let object = Struct {
///         w: Enum::Unit,
///         x: Enum::Newtype(1),
///         y: Enum::Tuple(1, 1),
///         z: Enum::Struct { value: 1 },
///     };
///
///     let yaml = serde_yml::to_string(&object).unwrap();
///     print!("{}", yaml);
///
///     let deserialized: Struct = serde_yml::from_str(&yaml).unwrap();
///     assert_eq!(object, deserialized);
/// ```
///
/// The representation using `singleton_map` on all the fields is:
///
/// ```yaml
/// w: Unit
/// x:
///   Newtype: 1
/// y:
///   Tuple:
///   - 1
///   - 1
/// z:
///   Struct:
///     value: 1
/// ```
///
/// Without `singleton_map`, the default behaviour would have been to serialize
/// as:
///
/// ```yaml
/// w: Unit
/// x: !Newtype 1
/// y: !Tuple
/// - 1
/// - 1
/// z: !Struct
///   value: 1
/// ```
pub mod singleton_map {
    use crate::value::{Mapping, Sequence, Value};
    use serde::de::{
        self, Deserialize, DeserializeSeed, Deserializer, EnumAccess,
        IgnoredAny, MapAccess, Unexpected, VariantAccess, Visitor,
    };
    use serde::ser::{
        self, Serialize, SerializeMap, SerializeStructVariant,
        SerializeTupleVariant, Serializer,
    };
    use std::fmt::{self, Display};

    /// Serializes a given value using a singleton map representation.
    ///
    /// This function wraps the given value in a singleton map structure before serialization.
    /// The singleton map representation uses the enum variant name as the key and the variant value as the value.
    ///
    /// # Arguments
    /// * `value` - A reference to the value to be serialized.
    /// * `serializer` - The serializer to use for serializing the value.
    ///
    /// # Returns
    /// A result containing the serialization output or an error in case of failure.
    ///
    pub fn serialize<T, S>(
        value: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        T: Serialize,
        S: Serializer,
    {
        value.serialize(SingletonMap {
            delegate: serializer,
        })
    }

    #[allow(missing_docs)]
    pub fn deserialize<'de, T, D>(
        deserializer: D,
    ) -> Result<T, D::Error>
    where
        T: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        T::deserialize(SingletonMap {
            delegate: deserializer,
        })
    }

    /// A wrapper struct that delegates serialization and deserialization to an underlying serializer or deserializer.
    ///
    /// This struct is used internally by the `singleton_map` module to wrap the serializer or deserializer
    /// and provide the necessary functionality for serializing and deserializing enums using the singleton map representation.
    ///
    /// The `SingletonMap` struct contains a single field, `delegate`, which holds the underlying serializer or deserializer.
    ///
    /// # Type Parameters
    ///
    /// * `D` - The type of the underlying serializer or deserializer.
    ///
    /// # Fields
    ///
    /// * `delegate` - The underlying serializer or deserializer to which serialization and deserialization are delegated.
    #[derive(Clone, Copy, Debug)]
    pub struct SingletonMap<D> {
        /// The underlying serializer or deserializer to which serialization and deserialization are delegated.
        pub delegate: D,
    }

    impl<D> Serialize for SingletonMap<D>
    where
        D: Serialize,
    {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            self.delegate.serialize(SingletonMap {
                delegate: serializer,
            })
        }
    }

    impl<D> Serializer for SingletonMap<D>
    where
        D: Serializer,
    {
        type Ok = D::Ok;
        type Error = D::Error;

        type SerializeSeq = D::SerializeSeq;
        type SerializeTuple = D::SerializeTuple;
        type SerializeTupleStruct = D::SerializeTupleStruct;
        type SerializeTupleVariant =
            SerializeTupleVariantAsSingletonMap<D::SerializeMap>;
        type SerializeMap = D::SerializeMap;
        type SerializeStruct = D::SerializeStruct;
        type SerializeStructVariant =
            SerializeStructVariantAsSingletonMap<D::SerializeMap>;

        fn serialize_bool(
            self,
            v: bool,
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_bool(v)
        }

        fn serialize_i8(self, v: i8) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_i8(v)
        }

        fn serialize_i16(
            self,
            v: i16,
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_i16(v)
        }

        fn serialize_i32(
            self,
            v: i32,
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_i32(v)
        }

        fn serialize_i64(
            self,
            v: i64,
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_i64(v)
        }

        fn serialize_i128(
            self,
            v: i128,
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_i128(v)
        }

        fn serialize_u8(self, v: u8) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_u8(v)
        }

        fn serialize_u16(
            self,
            v: u16,
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_u16(v)
        }

        fn serialize_u32(
            self,
            v: u32,
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_u32(v)
        }

        fn serialize_u64(
            self,
            v: u64,
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_u64(v)
        }

        fn serialize_u128(
            self,
            v: u128,
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_u128(v)
        }

        fn serialize_f32(
            self,
            v: f32,
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_f32(v)
        }

        fn serialize_f64(
            self,
            v: f64,
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_f64(v)
        }

        fn serialize_char(
            self,
            v: char,
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_char(v)
        }

        fn serialize_str(
            self,
            v: &str,
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_str(v)
        }

        fn serialize_bytes(
            self,
            v: &[u8],
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_bytes(v)
        }

        fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_unit()
        }

        fn serialize_unit_struct(
            self,
            name: &'static str,
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_unit_struct(name)
        }

        fn serialize_unit_variant(
            self,
            name: &'static str,
            variant_index: u32,
            variant: &'static str,
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_unit_variant(
                name,
                variant_index,
                variant,
            )
        }

        fn serialize_newtype_struct<T>(
            self,
            name: &'static str,
            value: &T,
        ) -> Result<Self::Ok, Self::Error>
        where
            T: ?Sized + Serialize,
        {
            self.delegate.serialize_newtype_struct(name, value)
        }

        fn serialize_newtype_variant<T>(
            self,
            _name: &'static str,
            _variant_index: u32,
            variant: &'static str,
            value: &T,
        ) -> Result<Self::Ok, Self::Error>
        where
            T: ?Sized + Serialize,
        {
            let mut map = self.delegate.serialize_map(Some(1))?;
            map.serialize_entry(variant, value)?;
            map.end()
        }

        fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_none()
        }

        fn serialize_some<V>(
            self,
            value: &V,
        ) -> Result<Self::Ok, Self::Error>
        where
            V: ?Sized + Serialize,
        {
            self.delegate
                .serialize_some(&SingletonMap { delegate: value })
        }

        fn serialize_seq(
            self,
            len: Option<usize>,
        ) -> Result<Self::SerializeSeq, Self::Error> {
            self.delegate.serialize_seq(len)
        }

        fn serialize_tuple(
            self,
            len: usize,
        ) -> Result<Self::SerializeTuple, Self::Error> {
            self.delegate.serialize_tuple(len)
        }

        fn serialize_tuple_struct(
            self,
            name: &'static str,
            len: usize,
        ) -> Result<Self::SerializeTupleStruct, Self::Error> {
            self.delegate.serialize_tuple_struct(name, len)
        }

        fn serialize_tuple_variant(
            self,
            _name: &'static str,
            _variant_index: u32,
            variant: &'static str,
            len: usize,
        ) -> Result<Self::SerializeTupleVariant, Self::Error> {
            let mut map = self.delegate.serialize_map(Some(1))?;
            map.serialize_key(variant)?;
            let sequence = Sequence::with_capacity(len);
            Ok(SerializeTupleVariantAsSingletonMap { map, sequence })
        }

        fn serialize_map(
            self,
            len: Option<usize>,
        ) -> Result<Self::SerializeMap, Self::Error> {
            self.delegate.serialize_map(len)
        }

        fn serialize_struct(
            self,
            name: &'static str,
            len: usize,
        ) -> Result<Self::SerializeStruct, Self::Error> {
            self.delegate.serialize_struct(name, len)
        }

        fn serialize_struct_variant(
            self,
            _name: &'static str,
            _variant_index: u32,
            variant: &'static str,
            len: usize,
        ) -> Result<Self::SerializeStructVariant, Self::Error> {
            let mut map = self.delegate.serialize_map(Some(1))?;
            map.serialize_key(variant)?;
            let mapping = Mapping::with_capacity(len);
            Ok(SerializeStructVariantAsSingletonMap { map, mapping })
        }

        fn collect_str<T>(
            self,
            value: &T,
        ) -> Result<Self::Ok, Self::Error>
        where
            T: ?Sized + Display,
        {
            self.delegate.collect_str(value)
        }

        fn is_human_readable(&self) -> bool {
            self.delegate.is_human_readable()
        }
    }

    /// A helper struct for serializing tuple variants as singleton maps.
    ///
    /// This struct is used internally by the `singleton_map` module to serialize tuple variants
    /// as YAML maps with a single key-value pair, where the key is the variant name and the value
    /// is a YAML sequence containing the tuple elements.
    ///
    /// # Type Parameters
    ///
    /// * `M` - The type of the underlying serializer map.
    #[derive(Clone, Debug)]
    pub struct SerializeTupleVariantAsSingletonMap<M> {
        /// The underlying serializer map to which the tuple variant is serialized.
        map: M,
        /// The YAML sequence that holds the tuple elements.
        sequence: Sequence,
    }

    impl<M> SerializeTupleVariant for SerializeTupleVariantAsSingletonMap<M>
    where
        M: SerializeMap,
    {
        type Ok = M::Ok;
        type Error = M::Error;

        fn serialize_field<T>(
            &mut self,
            field: &T,
        ) -> Result<(), Self::Error>
        where
            T: ?Sized + Serialize,
        {
            let value = field
                .serialize(crate::value::Serializer)
                .map_err(ser::Error::custom)?;
            self.sequence.push(value);
            Ok(())
        }

        fn end(mut self) -> Result<Self::Ok, Self::Error> {
            self.map.serialize_value(&self.sequence)?;
            self.map.end()
        }
    }

    /// A helper struct for serializing struct variants as singleton maps.
    ///
    /// This struct is used internally by the `singleton_map` module to serialize struct variants
    /// as YAML maps with a single key-value pair, where the key is the variant name and the value
    /// is a YAML mapping containing the struct fields.
    ///
    /// # Type Parameters
    ///
    /// * `M` - The type of the underlying serializer map.
    #[derive(Clone, Debug)]
    pub struct SerializeStructVariantAsSingletonMap<M> {
        /// The underlying serializer map to which the struct variant is serialized.
        map: M,
        /// The YAML mapping that holds the struct fields.
        mapping: Mapping,
    }

    impl<M> SerializeStructVariant
        for SerializeStructVariantAsSingletonMap<M>
    where
        M: SerializeMap,
    {
        type Ok = M::Ok;
        type Error = M::Error;

        fn serialize_field<T>(
            &mut self,
            name: &'static str,
            field: &T,
        ) -> Result<(), Self::Error>
        where
            T: ?Sized + Serialize,
        {
            let value = field
                .serialize(crate::value::Serializer)
                .map_err(ser::Error::custom)?;
            self.mapping.insert(Value::String(name.to_owned()), value);
            Ok(())
        }

        fn end(mut self) -> Result<Self::Ok, Self::Error> {
            self.map.serialize_value(&self.mapping)?;
            self.map.end()
        }
    }

    impl<'de, D> Deserializer<'de> for SingletonMap<D>
    where
        D: Deserializer<'de>,
    {
        type Error = D::Error;

        fn deserialize_any<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_any(visitor)
        }

        fn deserialize_bool<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_bool(visitor)
        }

        fn deserialize_i8<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_i8(visitor)
        }

        fn deserialize_i16<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_i16(visitor)
        }

        fn deserialize_i32<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_i32(visitor)
        }

        fn deserialize_i64<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_i64(visitor)
        }

        fn deserialize_i128<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_i128(visitor)
        }

        fn deserialize_u8<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_u8(visitor)
        }

        fn deserialize_u16<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_u16(visitor)
        }

        fn deserialize_u32<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_u32(visitor)
        }

        fn deserialize_u64<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_u64(visitor)
        }

        fn deserialize_u128<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_u128(visitor)
        }

        fn deserialize_f32<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_f32(visitor)
        }

        fn deserialize_f64<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_f64(visitor)
        }

        fn deserialize_char<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_char(visitor)
        }

        fn deserialize_str<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_str(visitor)
        }

        fn deserialize_string<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_string(visitor)
        }

        fn deserialize_bytes<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_bytes(visitor)
        }

        fn deserialize_byte_buf<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_byte_buf(visitor)
        }

        fn deserialize_option<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_option(SingletonMapAsEnum {
                name: "",
                delegate: visitor,
            })
        }

        fn deserialize_unit<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_unit(visitor)
        }

        fn deserialize_unit_struct<V>(
            self,
            name: &'static str,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_unit_struct(name, visitor)
        }

        fn deserialize_newtype_struct<V>(
            self,
            name: &'static str,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_newtype_struct(name, visitor)
        }

        fn deserialize_seq<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_seq(visitor)
        }

        fn deserialize_tuple<V>(
            self,
            len: usize,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_tuple(len, visitor)
        }

        fn deserialize_tuple_struct<V>(
            self,
            name: &'static str,
            len: usize,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_tuple_struct(name, len, visitor)
        }

        fn deserialize_map<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_map(visitor)
        }

        fn deserialize_struct<V>(
            self,
            name: &'static str,
            fields: &'static [&'static str],
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_struct(name, fields, visitor)
        }

        fn deserialize_enum<V>(
            self,
            name: &'static str,
            _variants: &'static [&'static str],
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_any(SingletonMapAsEnum {
                name,
                delegate: visitor,
            })
        }

        fn deserialize_identifier<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_identifier(visitor)
        }

        fn deserialize_ignored_any<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_ignored_any(visitor)
        }

        fn is_human_readable(&self) -> bool {
            self.delegate.is_human_readable()
        }
    }

    struct SingletonMapAsEnum<D> {
        name: &'static str,
        delegate: D,
    }

    impl<'de, V> Visitor<'de> for SingletonMapAsEnum<V>
    where
        V: Visitor<'de>,
    {
        type Value = V::Value;

        fn expecting(
            &self,
            formatter: &mut fmt::Formatter<'_>,
        ) -> fmt::Result {
            self.delegate.expecting(formatter)
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate.visit_enum(de::value::StrDeserializer::new(v))
        }

        fn visit_borrowed_str<E>(
            self,
            v: &'de str,
        ) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate
                .visit_enum(de::value::BorrowedStrDeserializer::new(v))
        }

        fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate
                .visit_enum(de::value::StringDeserializer::new(v))
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate.visit_none()
        }

        fn visit_some<D>(
            self,
            deserializer: D,
        ) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            self.delegate.visit_some(SingletonMap {
                delegate: deserializer,
            })
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate.visit_unit()
        }

        fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            self.delegate.visit_enum(SingletonMapAsEnum {
                name: self.name,
                delegate: map,
            })
        }
    }

    impl<'de, D> EnumAccess<'de> for SingletonMapAsEnum<D>
    where
        D: MapAccess<'de>,
    {
        type Error = D::Error;
        type Variant = Self;

        fn variant_seed<V>(
            mut self,
            seed: V,
        ) -> Result<(V::Value, Self::Variant), Self::Error>
        where
            V: DeserializeSeed<'de>,
        {
            match self.delegate.next_key_seed(seed)? {
                Some(value) => Ok((value, self)),
                None => Err(de::Error::invalid_value(
                    Unexpected::Map,
                    &"map with a single key",
                )),
            }
        }
    }

    impl<'de, D> VariantAccess<'de> for SingletonMapAsEnum<D>
    where
        D: MapAccess<'de>,
    {
        type Error = D::Error;

        fn unit_variant(self) -> Result<(), Self::Error> {
            Err(de::Error::invalid_type(
                Unexpected::Map,
                &"unit variant",
            ))
        }

        fn newtype_variant_seed<T>(
            mut self,
            seed: T,
        ) -> Result<T::Value, Self::Error>
        where
            T: DeserializeSeed<'de>,
        {
            let value = self.delegate.next_value_seed(seed)?;
            match self.delegate.next_key()? {
                None => Ok(value),
                Some(IgnoredAny) => Err(de::Error::invalid_value(
                    Unexpected::Map,
                    &"map with a single key",
                )),
            }
        }

        fn tuple_variant<V>(
            mut self,
            len: usize,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            let value = self
                .delegate
                .next_value_seed(TupleVariantSeed { len, visitor })?;
            match self.delegate.next_key()? {
                None => Ok(value),
                Some(IgnoredAny) => Err(de::Error::invalid_value(
                    Unexpected::Map,
                    &"map with a single key",
                )),
            }
        }

        fn struct_variant<V>(
            mut self,
            fields: &'static [&'static str],
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            let value =
                self.delegate.next_value_seed(StructVariantSeed {
                    name: self.name,
                    fields,
                    visitor,
                })?;
            match self.delegate.next_key()? {
                None => Ok(value),
                Some(IgnoredAny) => Err(de::Error::invalid_value(
                    Unexpected::Map,
                    &"map with a single key",
                )),
            }
        }
    }

    struct TupleVariantSeed<V> {
        len: usize,
        visitor: V,
    }

    impl<'de, V> DeserializeSeed<'de> for TupleVariantSeed<V>
    where
        V: Visitor<'de>,
    {
        type Value = V::Value;

        fn deserialize<D>(
            self,
            deserializer: D,
        ) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_tuple(self.len, self.visitor)
        }
    }

    struct StructVariantSeed<V> {
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    }

    impl<'de, V> DeserializeSeed<'de> for StructVariantSeed<V>
    where
        V: Visitor<'de>,
    {
        type Value = V::Value;

        fn deserialize<D>(
            self,
            deserializer: D,
        ) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_struct(
                self.name,
                self.fields,
                self.visitor,
            )
        }
    }
}

/// Serialize/deserialize an optional enum using a YAML map containing one entry in which
/// the key identifies the variant name.
///
/// This module is similar to `singleton_map`, but it works with optional (`Option`) fields.
/// If the field is `Some`, it will be serialized/deserialized using the `singleton_map` representation.
/// If the field is `None`, it will be serialized/deserialized as `null`.
///
/// # Example
///
/// ```
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize, PartialEq, Debug)]
/// enum MyEnum {
///     Variant1,
///     Variant2(String),
/// }
///
/// #[derive(Serialize, Deserialize, PartialEq, Debug)]
/// struct Example {
///     #[serde(with = "serde_yml::with::singleton_map_optional")]
///     field: Option<MyEnum>,
/// }
///
/// let example = Example {
///     field: Some(MyEnum::Variant2("value".to_string())),
/// };
///
/// let yaml = serde_yml::to_string(&example).unwrap();
/// assert_eq!(yaml, "field:\n  Variant2: value\n");
///
/// let deserialized: Example = serde_yml::from_str(&yaml).unwrap();
/// assert_eq!(example, deserialized);
/// ```
pub mod singleton_map_optional {

    use super::singleton_map;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serializes an optional value using the `singleton_map` representation.
    ///
    /// If the value is `Some`, it will be serialized using the `singleton_map` representation.
    /// If the value is `None`, it will be serialized as `null`.
    ///
    /// # Arguments
    ///
    /// * `value` - A reference to the optional value to be serialized.
    /// * `serializer` - The serializer to use for serializing the value.
    ///
    /// # Returns
    ///
    /// A result containing the serialization output or an error if serialization fails.
    pub fn serialize<T, S>(
        value: &Option<T>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        T: Serialize,
        S: Serializer,
    {
        match value {
            Some(v) => singleton_map::serialize(v, serializer),
            None => serializer.serialize_none(),
        }
    }

    /// Deserializes a value using the `singleton_map` representation.
    ///
    /// This function expects the input to be in the `singleton_map` representation.
    /// If the input is a YAML map with a single key-value pair, the value will be deserialized
    /// and wrapped in `Some`. If the input is `null`, it will be deserialized as `None`.
    ///
    /// # Arguments
    ///
    /// * `deserializer` - The deserializer to use for deserializing the value.
    ///
    /// # Returns
    ///
    /// A result containing the deserialized optional value or an error if deserialization fails.
    pub fn deserialize<'de, T, D>(
        deserializer: D,
    ) -> Result<Option<T>, D::Error>
    where
        T: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(singleton_map::SingletonMap {
            delegate: deserializer,
        })
    }
}

/// Serialize/deserialize an enum using a YAML map containing one entry in which
/// the key identifies the variant name, while allowing combination with other `serialize_with` attributes.
///
/// This module provides a way to use `singleton_map` in combination with other `serialize_with` attributes.
/// It simply forwards the serialization and deserialization calls to the `singleton_map` module.
///
/// # Example
///
/// ```
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize, PartialEq, Debug)]
/// enum MyEnum {
///     Variant1,
///     Variant2(String),
/// }
///
/// #[derive(Serialize, Deserialize, PartialEq, Debug)]
/// struct Example {
///     #[serde(with = "serde_yml::with::singleton_map_with")]
///     field: MyEnum,
/// }
///
/// // Assuming `some_other_module` is defined elsewhere
/// mod some_other_module {
///     use serde::{Deserialize, Deserializer, Serialize, Serializer};
///
///     pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
///     where
///         T: Serialize,
///         S: Serializer,
///     {
///         // Custom serialization logic
///         value.serialize(serializer)
///     }
///
///     pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
///     where
///         T: Deserialize<'de>,
///         D: Deserializer<'de>,
///     {
///         // Custom deserialization logic
///         T::deserialize(deserializer)
///     }
/// }
///
/// let example = Example {
///     field: MyEnum::Variant2("value".to_string()),
/// };
///
/// let yaml = serde_yml::to_string(&example).unwrap();
/// assert_eq!(yaml, "field:\n  Variant2: value\n");
///
/// let deserialized: Example = serde_yml::from_str(&yaml).unwrap();
/// assert_eq!(example, deserialized);
/// ```
pub mod singleton_map_with {

    use super::singleton_map;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serializes a value using the `singleton_map` representation.
    ///
    /// This function is a wrapper around `singleton_map::serialize` and allows using
    /// `singleton_map` in combination with other `serialize_with` attributes.
    ///
    /// # Arguments
    ///
    /// * `value` - A reference to the value to be serialized.
    /// * `serializer` - The serializer to use for serializing the value.
    ///
    /// # Returns
    ///
    /// A result containing the serialization output or an error if serialization fails.
    pub fn serialize<T, S>(
        value: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        T: Serialize,
        S: Serializer,
    {
        singleton_map::serialize(value, serializer)
    }

    /// Deserializes a value using the `singleton_map` representation.
    ///
    /// This function is a wrapper around `singleton_map::deserialize` and allows using
    /// `singleton_map` in combination with other `serialize_with` attributes.
    ///
    /// # Arguments
    ///
    /// * `deserializer` - The deserializer to use for deserializing the value.
    ///
    /// # Returns
    ///
    /// A result containing the deserialized value or an error if deserialization fails.
    pub fn deserialize<'de, T, D>(
        deserializer: D,
    ) -> Result<T, D::Error>
    where
        T: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        singleton_map::deserialize(deserializer)
    }
}

/// Apply [`singleton_map`] to *all* enums contained within the data structure.
///
/// # Example
///
/// ```
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize, PartialEq, Debug)]
/// enum Enum {
///     Int(i32),
/// }
///
/// #[derive(Serialize, Deserialize, PartialEq, Debug)]
/// struct Inner {
///     a: Enum,
///     bs: Vec<Enum>,
/// }
///
/// #[derive(Serialize, Deserialize, PartialEq, Debug)]
/// struct Outer {
///     tagged_style: Inner,
///
///     #[serde(with = "serde_yml::with::singleton_map_recursive")]
///     singleton_map_style: Inner,
/// }
///
///     let object = Outer {
///         tagged_style: Inner {
///             a: Enum::Int(0),
///             bs: vec![Enum::Int(1)],
///         },
///         singleton_map_style: Inner {
///             a: Enum::Int(2),
///             bs: vec![Enum::Int(3)],
///         },
///     };
///
///     let yaml = serde_yml::to_string(&object).unwrap();
///     print!("{}", yaml);
///
///     let deserialized: Outer = serde_yml::from_str(&yaml).unwrap();
///     assert_eq!(object, deserialized);
/// ```
///
/// The serialized output is:
///
/// ```yaml
/// tagged_style:
///   a: !Int 0
///   bs:
///   - !Int 1
/// singleton_map_style:
///   a:
///     Int: 2
///   bs:
///   - Int: 3
/// ```
///
/// This module can also be used for the top-level serializer or deserializer
/// call, without `serde(with = …)`, as follows.
///
/// ```
/// # use serde_derive::{Deserialize, Serialize};
/// #
/// # #[derive(Serialize, Deserialize, PartialEq, Debug)]
/// # enum Enum {
/// #     Int(i32),
/// # }
/// #
/// # #[derive(Serialize, Deserialize, PartialEq, Debug)]
/// # struct Inner {
/// #     a: Enum,
/// #     bs: Vec<Enum>,
/// # }
/// #
/// use std::io::{self, Write};
///
/// fn main() {
///     let object = Inner {
///         a: Enum::Int(0),
///         bs: vec![Enum::Int(1)],
///     };
///
///     let mut buf = Vec::new();
///     let mut serializer = serde_yml::Serializer::new(&mut buf);
///     serde_yml::with::singleton_map_recursive::serialize(&object, &mut serializer).unwrap();
///     io::stdout().write_all(&buf).unwrap();
///
///     let deserializer = serde_yml::Deserializer::from_slice(&buf);
///     let deserialized: Inner = serde_yml::with::singleton_map_recursive::deserialize(deserializer).unwrap();
///     assert_eq!(object, deserialized);
/// }
/// ```
pub mod singleton_map_recursive {
    use crate::value::{Mapping, Sequence, Value};
    use serde::de::{
        self, Deserialize, DeserializeSeed, Deserializer, EnumAccess,
        IgnoredAny, MapAccess, SeqAccess, Unexpected, VariantAccess,
        Visitor,
    };
    use serde::ser::{
        self, Serialize, SerializeMap, SerializeSeq, SerializeStruct,
        SerializeStructVariant, SerializeTuple, SerializeTupleStruct,
        SerializeTupleVariant, Serializer,
    };
    use std::fmt::{self, Display};

    #[allow(missing_docs)]
    pub fn serialize<T, S>(
        value: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        T: Serialize,
        S: Serializer,
    {
        value.serialize(SingletonMapRecursive {
            delegate: serializer,
        })
    }

    #[allow(missing_docs)]
    pub fn deserialize<'de, T, D>(
        deserializer: D,
    ) -> Result<T, D::Error>
    where
        T: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        T::deserialize(SingletonMapRecursive {
            delegate: deserializer,
        })
    }

    struct SingletonMapRecursive<D> {
        delegate: D,
    }

    impl<D> Serialize for SingletonMapRecursive<D>
    where
        D: Serialize,
    {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            self.delegate.serialize(SingletonMapRecursive {
                delegate: serializer,
            })
        }
    }

    impl<D> Serializer for SingletonMapRecursive<D>
    where
        D: Serializer,
    {
        type Ok = D::Ok;
        type Error = D::Error;

        type SerializeSeq = SingletonMapRecursive<D::SerializeSeq>;
        type SerializeTuple = SingletonMapRecursive<D::SerializeTuple>;
        type SerializeTupleStruct =
            SingletonMapRecursive<D::SerializeTupleStruct>;
        type SerializeTupleVariant =
            SerializeTupleVariantAsSingletonMapRecursive<
                D::SerializeMap,
            >;
        type SerializeMap = SingletonMapRecursive<D::SerializeMap>;
        type SerializeStruct =
            SingletonMapRecursive<D::SerializeStruct>;
        type SerializeStructVariant =
            SerializeStructVariantAsSingletonMapRecursive<
                D::SerializeMap,
            >;

        fn serialize_bool(
            self,
            v: bool,
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_bool(v)
        }

        fn serialize_i8(self, v: i8) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_i8(v)
        }

        fn serialize_i16(
            self,
            v: i16,
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_i16(v)
        }

        fn serialize_i32(
            self,
            v: i32,
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_i32(v)
        }

        fn serialize_i64(
            self,
            v: i64,
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_i64(v)
        }

        fn serialize_i128(
            self,
            v: i128,
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_i128(v)
        }

        fn serialize_u8(self, v: u8) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_u8(v)
        }

        fn serialize_u16(
            self,
            v: u16,
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_u16(v)
        }

        fn serialize_u32(
            self,
            v: u32,
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_u32(v)
        }

        fn serialize_u64(
            self,
            v: u64,
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_u64(v)
        }

        fn serialize_u128(
            self,
            v: u128,
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_u128(v)
        }

        fn serialize_f32(
            self,
            v: f32,
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_f32(v)
        }

        fn serialize_f64(
            self,
            v: f64,
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_f64(v)
        }

        fn serialize_char(
            self,
            v: char,
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_char(v)
        }

        fn serialize_str(
            self,
            v: &str,
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_str(v)
        }

        fn serialize_bytes(
            self,
            v: &[u8],
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_bytes(v)
        }

        fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_unit()
        }

        fn serialize_unit_struct(
            self,
            name: &'static str,
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_unit_struct(name)
        }

        fn serialize_unit_variant(
            self,
            name: &'static str,
            variant_index: u32,
            variant: &'static str,
        ) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_unit_variant(
                name,
                variant_index,
                variant,
            )
        }

        fn serialize_newtype_struct<T>(
            self,
            name: &'static str,
            value: &T,
        ) -> Result<Self::Ok, Self::Error>
        where
            T: ?Sized + Serialize,
        {
            self.delegate.serialize_newtype_struct(
                name,
                &SingletonMapRecursive { delegate: value },
            )
        }

        fn serialize_newtype_variant<T>(
            self,
            _name: &'static str,
            _variant_index: u32,
            variant: &'static str,
            value: &T,
        ) -> Result<Self::Ok, Self::Error>
        where
            T: ?Sized + Serialize,
        {
            let mut map = self.delegate.serialize_map(Some(1))?;
            map.serialize_entry(
                variant,
                &SingletonMapRecursive { delegate: value },
            )?;
            map.end()
        }

        fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
            self.delegate.serialize_none()
        }

        fn serialize_some<V>(
            self,
            value: &V,
        ) -> Result<Self::Ok, Self::Error>
        where
            V: ?Sized + Serialize,
        {
            self.delegate.serialize_some(&SingletonMapRecursive {
                delegate: value,
            })
        }

        fn serialize_seq(
            self,
            len: Option<usize>,
        ) -> Result<Self::SerializeSeq, Self::Error> {
            Ok(SingletonMapRecursive {
                delegate: self.delegate.serialize_seq(len)?,
            })
        }

        fn serialize_tuple(
            self,
            len: usize,
        ) -> Result<Self::SerializeTuple, Self::Error> {
            Ok(SingletonMapRecursive {
                delegate: self.delegate.serialize_tuple(len)?,
            })
        }

        fn serialize_tuple_struct(
            self,
            name: &'static str,
            len: usize,
        ) -> Result<Self::SerializeTupleStruct, Self::Error> {
            Ok(SingletonMapRecursive {
                delegate: self
                    .delegate
                    .serialize_tuple_struct(name, len)?,
            })
        }

        fn serialize_tuple_variant(
            self,
            _name: &'static str,
            _variant_index: u32,
            variant: &'static str,
            len: usize,
        ) -> Result<Self::SerializeTupleVariant, Self::Error> {
            let mut map = self.delegate.serialize_map(Some(1))?;
            map.serialize_key(variant)?;
            let sequence = Sequence::with_capacity(len);
            Ok(SerializeTupleVariantAsSingletonMapRecursive {
                map,
                sequence,
            })
        }

        fn serialize_map(
            self,
            len: Option<usize>,
        ) -> Result<Self::SerializeMap, Self::Error> {
            Ok(SingletonMapRecursive {
                delegate: self.delegate.serialize_map(len)?,
            })
        }

        fn serialize_struct(
            self,
            name: &'static str,
            len: usize,
        ) -> Result<Self::SerializeStruct, Self::Error> {
            Ok(SingletonMapRecursive {
                delegate: self.delegate.serialize_struct(name, len)?,
            })
        }

        fn serialize_struct_variant(
            self,
            _name: &'static str,
            _variant_index: u32,
            variant: &'static str,
            len: usize,
        ) -> Result<Self::SerializeStructVariant, Self::Error> {
            let mut map = self.delegate.serialize_map(Some(1))?;
            map.serialize_key(variant)?;
            let mapping = Mapping::with_capacity(len);
            Ok(SerializeStructVariantAsSingletonMapRecursive {
                map,
                mapping,
            })
        }

        fn collect_str<T>(
            self,
            value: &T,
        ) -> Result<Self::Ok, Self::Error>
        where
            T: ?Sized + Display,
        {
            self.delegate.collect_str(value)
        }

        fn is_human_readable(&self) -> bool {
            self.delegate.is_human_readable()
        }
    }

    impl<D> SerializeSeq for SingletonMapRecursive<D>
    where
        D: SerializeSeq,
    {
        type Ok = D::Ok;
        type Error = D::Error;

        fn serialize_element<T>(
            &mut self,
            elem: &T,
        ) -> Result<(), Self::Error>
        where
            T: ?Sized + Serialize,
        {
            self.delegate.serialize_element(&SingletonMapRecursive {
                delegate: elem,
            })
        }

        fn end(self) -> Result<Self::Ok, Self::Error> {
            self.delegate.end()
        }
    }

    impl<D> SerializeTuple for SingletonMapRecursive<D>
    where
        D: SerializeTuple,
    {
        type Ok = D::Ok;
        type Error = D::Error;

        fn serialize_element<T>(
            &mut self,
            elem: &T,
        ) -> Result<(), Self::Error>
        where
            T: ?Sized + Serialize,
        {
            self.delegate.serialize_element(&SingletonMapRecursive {
                delegate: elem,
            })
        }

        fn end(self) -> Result<Self::Ok, Self::Error> {
            self.delegate.end()
        }
    }

    impl<D> SerializeTupleStruct for SingletonMapRecursive<D>
    where
        D: SerializeTupleStruct,
    {
        type Ok = D::Ok;
        type Error = D::Error;

        fn serialize_field<V>(
            &mut self,
            value: &V,
        ) -> Result<(), Self::Error>
        where
            V: ?Sized + Serialize,
        {
            self.delegate.serialize_field(&SingletonMapRecursive {
                delegate: value,
            })
        }

        fn end(self) -> Result<Self::Ok, Self::Error> {
            self.delegate.end()
        }
    }

    struct SerializeTupleVariantAsSingletonMapRecursive<M> {
        map: M,
        sequence: Sequence,
    }

    impl<M> SerializeTupleVariant
        for SerializeTupleVariantAsSingletonMapRecursive<M>
    where
        M: SerializeMap,
    {
        type Ok = M::Ok;
        type Error = M::Error;

        fn serialize_field<T>(
            &mut self,
            field: &T,
        ) -> Result<(), Self::Error>
        where
            T: ?Sized + Serialize,
        {
            let value = field
                .serialize(SingletonMapRecursive {
                    delegate: crate::value::Serializer,
                })
                .map_err(ser::Error::custom)?;
            self.sequence.push(value);
            Ok(())
        }

        fn end(mut self) -> Result<Self::Ok, Self::Error> {
            self.map.serialize_value(&self.sequence)?;
            self.map.end()
        }
    }

    impl<D> SerializeMap for SingletonMapRecursive<D>
    where
        D: SerializeMap,
    {
        type Ok = D::Ok;
        type Error = D::Error;

        fn serialize_key<T>(
            &mut self,
            key: &T,
        ) -> Result<(), Self::Error>
        where
            T: ?Sized + Serialize,
        {
            self.delegate
                .serialize_key(&SingletonMapRecursive { delegate: key })
        }

        fn serialize_value<T>(
            &mut self,
            value: &T,
        ) -> Result<(), Self::Error>
        where
            T: ?Sized + Serialize,
        {
            self.delegate.serialize_value(&SingletonMapRecursive {
                delegate: value,
            })
        }

        fn serialize_entry<K, V>(
            &mut self,
            key: &K,
            value: &V,
        ) -> Result<(), Self::Error>
        where
            K: ?Sized + Serialize,
            V: ?Sized + Serialize,
        {
            self.delegate.serialize_entry(
                &SingletonMapRecursive { delegate: key },
                &SingletonMapRecursive { delegate: value },
            )
        }

        fn end(self) -> Result<Self::Ok, Self::Error> {
            self.delegate.end()
        }
    }

    impl<D> SerializeStruct for SingletonMapRecursive<D>
    where
        D: SerializeStruct,
    {
        type Ok = D::Ok;
        type Error = D::Error;

        fn serialize_field<V>(
            &mut self,
            key: &'static str,
            value: &V,
        ) -> Result<(), Self::Error>
        where
            V: ?Sized + Serialize,
        {
            self.delegate.serialize_field(
                key,
                &SingletonMapRecursive { delegate: value },
            )
        }

        fn end(self) -> Result<Self::Ok, Self::Error> {
            self.delegate.end()
        }
    }

    struct SerializeStructVariantAsSingletonMapRecursive<M> {
        map: M,
        mapping: Mapping,
    }

    impl<M> SerializeStructVariant
        for SerializeStructVariantAsSingletonMapRecursive<M>
    where
        M: SerializeMap,
    {
        type Ok = M::Ok;
        type Error = M::Error;

        fn serialize_field<T>(
            &mut self,
            name: &'static str,
            field: &T,
        ) -> Result<(), Self::Error>
        where
            T: ?Sized + Serialize,
        {
            let value = field
                .serialize(SingletonMapRecursive {
                    delegate: crate::value::Serializer,
                })
                .map_err(ser::Error::custom)?;
            self.mapping.insert(Value::String(name.to_owned()), value);
            Ok(())
        }

        fn end(mut self) -> Result<Self::Ok, Self::Error> {
            self.map.serialize_value(&self.mapping)?;
            self.map.end()
        }
    }

    impl<'de, D> Deserializer<'de> for SingletonMapRecursive<D>
    where
        D: Deserializer<'de>,
    {
        type Error = D::Error;

        fn deserialize_any<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_any(SingletonMapRecursive {
                delegate: visitor,
            })
        }

        fn deserialize_bool<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_bool(SingletonMapRecursive {
                delegate: visitor,
            })
        }

        fn deserialize_i8<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_i8(SingletonMapRecursive {
                delegate: visitor,
            })
        }

        fn deserialize_i16<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_i16(SingletonMapRecursive {
                delegate: visitor,
            })
        }

        fn deserialize_i32<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_i32(SingletonMapRecursive {
                delegate: visitor,
            })
        }

        fn deserialize_i64<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_i64(SingletonMapRecursive {
                delegate: visitor,
            })
        }

        fn deserialize_i128<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_i128(SingletonMapRecursive {
                delegate: visitor,
            })
        }

        fn deserialize_u8<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_u8(SingletonMapRecursive {
                delegate: visitor,
            })
        }

        fn deserialize_u16<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_u16(SingletonMapRecursive {
                delegate: visitor,
            })
        }

        fn deserialize_u32<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_u32(SingletonMapRecursive {
                delegate: visitor,
            })
        }

        fn deserialize_u64<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_u64(SingletonMapRecursive {
                delegate: visitor,
            })
        }

        fn deserialize_u128<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_u128(SingletonMapRecursive {
                delegate: visitor,
            })
        }

        fn deserialize_f32<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_f32(SingletonMapRecursive {
                delegate: visitor,
            })
        }

        fn deserialize_f64<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_f64(SingletonMapRecursive {
                delegate: visitor,
            })
        }

        fn deserialize_char<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_char(SingletonMapRecursive {
                delegate: visitor,
            })
        }

        fn deserialize_str<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_str(SingletonMapRecursive {
                delegate: visitor,
            })
        }

        fn deserialize_string<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_string(SingletonMapRecursive {
                delegate: visitor,
            })
        }

        fn deserialize_bytes<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_bytes(SingletonMapRecursive {
                delegate: visitor,
            })
        }

        fn deserialize_byte_buf<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_byte_buf(SingletonMapRecursive {
                delegate: visitor,
            })
        }

        fn deserialize_option<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_option(
                SingletonMapRecursiveAsEnum {
                    name: "",
                    delegate: visitor,
                },
            )
        }

        fn deserialize_unit<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_unit(SingletonMapRecursive {
                delegate: visitor,
            })
        }

        fn deserialize_unit_struct<V>(
            self,
            name: &'static str,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_unit_struct(
                name,
                SingletonMapRecursive { delegate: visitor },
            )
        }

        fn deserialize_newtype_struct<V>(
            self,
            name: &'static str,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_newtype_struct(
                name,
                SingletonMapRecursive { delegate: visitor },
            )
        }

        fn deserialize_seq<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_seq(SingletonMapRecursive {
                delegate: visitor,
            })
        }

        fn deserialize_tuple<V>(
            self,
            len: usize,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_tuple(
                len,
                SingletonMapRecursive { delegate: visitor },
            )
        }

        fn deserialize_tuple_struct<V>(
            self,
            name: &'static str,
            len: usize,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_tuple_struct(
                name,
                len,
                SingletonMapRecursive { delegate: visitor },
            )
        }

        fn deserialize_map<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_map(SingletonMapRecursive {
                delegate: visitor,
            })
        }

        fn deserialize_struct<V>(
            self,
            name: &'static str,
            fields: &'static [&'static str],
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_struct(
                name,
                fields,
                SingletonMapRecursive { delegate: visitor },
            )
        }

        fn deserialize_enum<V>(
            self,
            name: &'static str,
            _variants: &'static [&'static str],
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_any(SingletonMapRecursiveAsEnum {
                name,
                delegate: visitor,
            })
        }

        fn deserialize_identifier<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_identifier(
                SingletonMapRecursive { delegate: visitor },
            )
        }

        fn deserialize_ignored_any<V>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.delegate.deserialize_ignored_any(
                SingletonMapRecursive { delegate: visitor },
            )
        }

        fn is_human_readable(&self) -> bool {
            self.delegate.is_human_readable()
        }
    }

    impl<'de, V> Visitor<'de> for SingletonMapRecursive<V>
    where
        V: Visitor<'de>,
    {
        type Value = V::Value;

        fn expecting(
            &self,
            formatter: &mut fmt::Formatter<'_>,
        ) -> fmt::Result {
            self.delegate.expecting(formatter)
        }

        fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate.visit_bool(v)
        }

        fn visit_i8<E>(self, v: i8) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate.visit_i8(v)
        }

        fn visit_i16<E>(self, v: i16) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate.visit_i16(v)
        }

        fn visit_i32<E>(self, v: i32) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate.visit_i32(v)
        }

        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate.visit_i64(v)
        }

        fn visit_i128<E>(self, v: i128) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate.visit_i128(v)
        }

        fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate.visit_u8(v)
        }

        fn visit_u16<E>(self, v: u16) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate.visit_u16(v)
        }

        fn visit_u32<E>(self, v: u32) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate.visit_u32(v)
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate.visit_u64(v)
        }

        fn visit_u128<E>(self, v: u128) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate.visit_u128(v)
        }

        fn visit_f32<E>(self, v: f32) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate.visit_f32(v)
        }

        fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate.visit_f64(v)
        }

        fn visit_char<E>(self, v: char) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate.visit_char(v)
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate.visit_str(v)
        }

        fn visit_borrowed_str<E>(
            self,
            v: &'de str,
        ) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate.visit_borrowed_str(v)
        }

        fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate.visit_string(v)
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate.visit_bytes(v)
        }

        fn visit_borrowed_bytes<E>(
            self,
            v: &'de [u8],
        ) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate.visit_borrowed_bytes(v)
        }

        fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate.visit_byte_buf(v)
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate.visit_none()
        }

        fn visit_some<D>(
            self,
            deserializer: D,
        ) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            self.delegate.visit_some(SingletonMapRecursive {
                delegate: deserializer,
            })
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate.visit_unit()
        }

        fn visit_newtype_struct<D>(
            self,
            deserializer: D,
        ) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            self.delegate.visit_newtype_struct(SingletonMapRecursive {
                delegate: deserializer,
            })
        }

        fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            self.delegate
                .visit_seq(SingletonMapRecursive { delegate: seq })
        }

        fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            self.delegate
                .visit_map(SingletonMapRecursive { delegate: map })
        }
    }

    impl<'de, T> DeserializeSeed<'de> for SingletonMapRecursive<T>
    where
        T: DeserializeSeed<'de>,
    {
        type Value = T::Value;

        fn deserialize<D>(
            self,
            deserializer: D,
        ) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            self.delegate.deserialize(SingletonMapRecursive {
                delegate: deserializer,
            })
        }
    }

    impl<'de, S> SeqAccess<'de> for SingletonMapRecursive<S>
    where
        S: SeqAccess<'de>,
    {
        type Error = S::Error;

        fn next_element_seed<T>(
            &mut self,
            seed: T,
        ) -> Result<Option<T::Value>, Self::Error>
        where
            T: DeserializeSeed<'de>,
        {
            self.delegate.next_element_seed(SingletonMapRecursive {
                delegate: seed,
            })
        }
    }

    impl<'de, M> MapAccess<'de> for SingletonMapRecursive<M>
    where
        M: MapAccess<'de>,
    {
        type Error = M::Error;

        fn next_key_seed<K>(
            &mut self,
            seed: K,
        ) -> Result<Option<K::Value>, Self::Error>
        where
            K: DeserializeSeed<'de>,
        {
            self.delegate
                .next_key_seed(SingletonMapRecursive { delegate: seed })
        }

        fn next_value_seed<V>(
            &mut self,
            seed: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: DeserializeSeed<'de>,
        {
            self.delegate.next_value_seed(SingletonMapRecursive {
                delegate: seed,
            })
        }
    }

    struct SingletonMapRecursiveAsEnum<D> {
        name: &'static str,
        delegate: D,
    }

    impl<'de, V> Visitor<'de> for SingletonMapRecursiveAsEnum<V>
    where
        V: Visitor<'de>,
    {
        type Value = V::Value;

        fn expecting(
            &self,
            formatter: &mut fmt::Formatter<'_>,
        ) -> fmt::Result {
            self.delegate.expecting(formatter)
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate.visit_enum(de::value::StrDeserializer::new(v))
        }

        fn visit_borrowed_str<E>(
            self,
            v: &'de str,
        ) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate
                .visit_enum(de::value::BorrowedStrDeserializer::new(v))
        }

        fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate
                .visit_enum(de::value::StringDeserializer::new(v))
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate.visit_none()
        }

        fn visit_some<D>(
            self,
            deserializer: D,
        ) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            self.delegate.visit_some(SingletonMapRecursive {
                delegate: deserializer,
            })
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.delegate.visit_unit()
        }

        fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            self.delegate.visit_enum(SingletonMapRecursiveAsEnum {
                name: self.name,
                delegate: map,
            })
        }
    }

    impl<'de, D> EnumAccess<'de> for SingletonMapRecursiveAsEnum<D>
    where
        D: MapAccess<'de>,
    {
        type Error = D::Error;
        type Variant = Self;

        fn variant_seed<V>(
            mut self,
            seed: V,
        ) -> Result<(V::Value, Self::Variant), Self::Error>
        where
            V: DeserializeSeed<'de>,
        {
            match self.delegate.next_key_seed(seed)? {
                Some(value) => Ok((value, self)),
                None => Err(de::Error::invalid_value(
                    Unexpected::Map,
                    &"map with a single key",
                )),
            }
        }
    }

    impl<'de, D> VariantAccess<'de> for SingletonMapRecursiveAsEnum<D>
    where
        D: MapAccess<'de>,
    {
        type Error = D::Error;

        fn unit_variant(self) -> Result<(), Self::Error> {
            Err(de::Error::invalid_type(
                Unexpected::Map,
                &"unit variant",
            ))
        }

        fn newtype_variant_seed<T>(
            mut self,
            seed: T,
        ) -> Result<T::Value, Self::Error>
        where
            T: DeserializeSeed<'de>,
        {
            let value = self.delegate.next_value_seed(
                SingletonMapRecursive { delegate: seed },
            )?;
            match self.delegate.next_key()? {
                None => Ok(value),
                Some(IgnoredAny) => Err(de::Error::invalid_value(
                    Unexpected::Map,
                    &"map with a single key",
                )),
            }
        }

        fn tuple_variant<V>(
            mut self,
            len: usize,
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            let value =
                self.delegate.next_value_seed(TupleVariantSeed {
                    len,
                    visitor: SingletonMapRecursive {
                        delegate: visitor,
                    },
                })?;
            match self.delegate.next_key()? {
                None => Ok(value),
                Some(IgnoredAny) => Err(de::Error::invalid_value(
                    Unexpected::Map,
                    &"map with a single key",
                )),
            }
        }

        fn struct_variant<V>(
            mut self,
            fields: &'static [&'static str],
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            let value =
                self.delegate.next_value_seed(StructVariantSeed {
                    name: self.name,
                    fields,
                    visitor: SingletonMapRecursive {
                        delegate: visitor,
                    },
                })?;
            match self.delegate.next_key()? {
                None => Ok(value),
                Some(IgnoredAny) => Err(de::Error::invalid_value(
                    Unexpected::Map,
                    &"map with a single key",
                )),
            }
        }
    }

    struct TupleVariantSeed<V> {
        len: usize,
        visitor: V,
    }

    impl<'de, V> DeserializeSeed<'de> for TupleVariantSeed<V>
    where
        V: Visitor<'de>,
    {
        type Value = V::Value;

        fn deserialize<D>(
            self,
            deserializer: D,
        ) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_tuple(self.len, self.visitor)
        }
    }

    struct StructVariantSeed<V> {
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    }

    impl<'de, V> DeserializeSeed<'de> for StructVariantSeed<V>
    where
        V: Visitor<'de>,
    {
        type Value = V::Value;

        fn deserialize<D>(
            self,
            deserializer: D,
        ) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_struct(
                self.name,
                self.fields,
                self.visitor,
            )
        }
    }
}

/// Serialize/deserialize nested enums using a YAML map containing one entry in which
/// the key identifies the variant name.
///
/// This function is similar to `singleton_map`, but it applies the singleton map representation
/// recursively to all nested enums within the data structure.
///
/// # Example
///
/// ```
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize, PartialEq, Debug)]
/// enum InnerEnum {
///     Variant1,
///     Variant2(String),
/// }
///
/// #[derive(Serialize, Deserialize, PartialEq, Debug)]
/// enum OuterEnum {
///     Variant1(InnerEnum),
///     Variant2 {
///         inner: InnerEnum,
///     },
/// }
///
/// #[derive(Serialize, Deserialize, PartialEq, Debug)]
/// struct Example {
///     #[serde(with = "serde_yml::with::nested_singleton_map")]
///     field: OuterEnum,
/// }
///
/// let example = Example {
///     field: OuterEnum::Variant2 {
///         inner: InnerEnum::Variant2("value".to_string()),
///     },
/// };
///
/// let yaml = serde_yml::to_string(&example).unwrap();
/// assert_eq!(yaml, "field:\n  Variant2:\n    inner:\n      Variant2: value\n");
///
/// let deserialized: Example = serde_yml::from_str(&yaml).unwrap();
/// assert_eq!(example, deserialized);
/// ```
pub mod nested_singleton_map {
    use super::singleton_map_recursive;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serializes a value using the nested singleton map representation.
    ///
    /// This function applies the singleton map representation recursively to all nested enums
    /// within the value being serialized.
    ///
    /// # Arguments
    ///
    /// * `value` - A reference to the value to be serialized.
    /// * `serializer` - The serializer to use for serializing the value.
    ///
    /// # Returns
    ///
    /// A result containing the serialization output or an error if serialization fails.
    pub fn serialize<T, S>(
        value: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        T: Serialize,
        S: Serializer,
    {
        singleton_map_recursive::serialize(value, serializer)
    }

    /// Deserializes a value using the nested singleton map representation.
    ///
    /// This function expects the input to be in the nested singleton map representation, where
    /// all nested enums are represented as YAML maps with a single key-value pair.
    ///
    /// # Arguments
    ///
    /// * `deserializer` - The deserializer to use for deserializing the value.
    ///
    /// # Returns
    ///
    /// A result containing the deserialized value or an error if deserialization fails.
    pub fn deserialize<'de, T, D>(
        deserializer: D,
    ) -> Result<T, D::Error>
    where
        T: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        singleton_map_recursive::deserialize(deserializer)
    }
}
