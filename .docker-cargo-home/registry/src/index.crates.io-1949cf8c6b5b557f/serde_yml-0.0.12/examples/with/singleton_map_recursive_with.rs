//!
//! Example for using `singleton_map_recursive` to serialize and deserialize an enum field.
//!
//! This example demonstrates the usage of `singleton_map_recursive` to seamlessly serialize and
//! deserialize an enum field as a single YAML mapping entry with the key being the enum variant name.
//!

use serde::{Deserialize, Serialize};
use serde_yml::with::singleton_map_recursive;

pub(crate) fn main() {
    println!(
        "\n❯ Executing examples/with/singleton_map_recursive_with.rs"
    );

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    enum MyEnum {
        Variant1(String),
        Variant2 { field: i32 },
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct MyStruct {
        #[serde(with = "singleton_map_recursive")]
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
