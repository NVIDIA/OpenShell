//!
//! Example for using `singleton_map` within a struct that has custom `Serialize` and `Deserialize` implementations.
//!
//! This example demonstrates the usage of `singleton_map` within a struct that has custom serialization
//! and deserialization logic to serialize and deserialize an enum field.
//!

use serde::{
    de::{self, Deserializer, IgnoredAny, MapAccess, Visitor},
    ser::{SerializeMap, Serializer},
    Deserialize, Serialize,
};
use std::fmt;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
enum MyEnum {
    Variant1(String),
    Variant2 { field: i32 },
}

#[derive(PartialEq, Debug)]
struct MyStruct {
    field: MyEnum,
}

impl Serialize for MyStruct {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("field", &self.field)?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for MyStruct {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MyStructVisitor;

        impl<'de> Visitor<'de> for MyStructVisitor {
            type Value = MyStruct;

            fn expecting(
                &self,
                formatter: &mut fmt::Formatter,
            ) -> fmt::Result {
                formatter.write_str("a MyStruct")
            }

            fn visit_map<V>(
                self,
                mut map: V,
            ) -> Result<MyStruct, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut field = None;
                while let Some(key) = map.next_key::<String>()? {
                    if key == "field" {
                        field = Some(map.next_value()?);
                    } else {
                        map.next_value::<IgnoredAny>()?;
                    }
                }

                let field = field
                    .ok_or_else(|| de::Error::missing_field("field"))?;
                Ok(MyStruct { field })
            }
        }

        deserializer.deserialize_map(MyStructVisitor)
    }
}

pub(crate) fn main() {
    println!("\n❯ Executing examples/with/singleton_map_custom_serialize_deserialize.rs");

    let input = MyStruct {
        field: MyEnum::Variant2 { field: 42 },
    };

    let yaml = serde_yml::to_string(&input).unwrap();
    println!("\n✅ Serialized YAML:\n{}", yaml);

    let output: MyStruct = serde_yml::from_str(&yaml).unwrap();
    println!("\n✅ Deserialized YAML:\n{:#?}", output);

    assert_eq!(input, output);
}
