//!
//! Example for the `singleton_map_enum_variants` function in the `with` module.
//!
//! This function is used to serialize a struct field that contains an enum with
//! multiple variants into a YAML map with a single key-value pair, where the key
//! is the enum variant name and the value is the inner value of the enum
//! variant.
//!

use serde::{Deserialize, Serialize};
use serde_yml::with::singleton_map;

pub(crate) fn main() {
    // Print a message to indicate the file being executed.
    println!(
        "\n❯ Executing examples/with/singleton_map_enum_variants.rs"
    );

    // Define an enum with multiple variants
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    enum MultiVariantEnum {
        Unit,
        Newtype(String),
        Tuple(i32, bool),
        Struct { field: f64 },
    }

    // Define a struct containing fields of the enum type
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct EnumStruct {
        #[serde(with = "singleton_map")]
        field1: MultiVariantEnum,
        #[serde(with = "singleton_map")]
        field2: MultiVariantEnum,
    }

    let input = EnumStruct {
        field1: MultiVariantEnum::Unit,
        field2: MultiVariantEnum::Struct {
            field: std::f64::consts::PI,
        },
    };

    let yaml = serde_yml::to_string(&input).unwrap();
    println!("\n✅ Serialized YAML:\n{}", yaml);

    let output: EnumStruct = serde_yml::from_str(&yaml).unwrap();
    println!("\n✅ Deserialized YAML:\n{:#?}", output);
    assert_eq!(input, output);
}
