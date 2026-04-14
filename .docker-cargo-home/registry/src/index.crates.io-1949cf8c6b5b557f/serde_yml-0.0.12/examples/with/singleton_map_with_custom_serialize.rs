//!
//! Example for using `singleton_map_with` in combination with a custom `serialize_with` attribute.
//!
//! This example demonstrates the usage of `singleton_map_with` in combination with a custom
//! serialization function to serialize and deserialize an enum field within a struct.
//!

use serde::{Deserialize, Serialize};
use serde_yml::with::singleton_map_with;

fn custom_serialize<T, S>(
    value: &T,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    S: serde::Serializer,
{
    // Custom serialization logic
    singleton_map_with::serialize(value, serializer)
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
enum MyEnum {
    Variant1(String),
    Variant2 { field: i32 },
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct MyStruct {
    #[serde(
        serialize_with = "custom_serialize",
        deserialize_with = "singleton_map_with::deserialize"
    )]
    field: MyEnum,
}

pub(crate) fn main() {
    println!("\n❯ Executing examples/with/singleton_map_with_custom_serialize.rs");

    let input = MyStruct {
        field: MyEnum::Variant2 { field: 42 },
    };
    let yaml = serde_yml::to_string(&input).unwrap();
    println!("\n✅ Serialized YAML:\n{}", yaml);

    let output: MyStruct = serde_yml::from_str(&yaml).unwrap();
    println!("\n✅ Deserialized YAML:\n{:#?}", output);
    assert_eq!(input, output);
}
