//!
//! Example for using `singleton_map_with` to serialize and deserialize an enum field.
//!
//! This example demonstrates the usage of `singleton_map_with` to seamlessly serialize and
//! deserialize an enum field as a single YAML mapping entry with the key being the enum variant name.
//! The `singleton_map_with` attribute allows for additional customization of the serialization
//! and deserialization process through the use of helper functions.
//!

use serde::{Deserialize, Serialize};
use serde_yml::with::singleton_map_with;

pub(crate) fn main() {
    println!("\n❯ Executing examples/with/singleton_map_with.rs");

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    enum MyEnum {
        Variant1(String),
        Variant2 { field: i32 },
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct MyStruct {
        #[serde(with = "singleton_map_with")]
        field: MyEnum,
    }

    let input = MyStruct {
        field: MyEnum::Variant2 { field: 42 },
    };
    let yaml = serde_yml::to_string(&input).unwrap();
    println!("\n✅ Serialized YAML:\n{}", yaml);

    let output: MyStruct = serde_yml::from_str(&yaml).unwrap();
    println!("\n✅ Deserialized YAML:\n{:#?}", output);
    assert_eq!(input, output);
}
