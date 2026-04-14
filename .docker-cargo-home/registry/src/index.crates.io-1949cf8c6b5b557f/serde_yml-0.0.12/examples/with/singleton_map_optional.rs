//!
//! Example for using `singleton_map_optional` to serialize and deserialize an optional enum field.
//!
//! This example demonstrates the usage of `singleton_map_optional` to seamlessly serialize and
//! deserialize an `Option<Enum>` field as a single YAML mapping entry with the key being the enum
//! variant name.
//!

use serde::{Deserialize, Serialize};
use serde_yml::with::singleton_map_optional;

pub(crate) fn main() {
    println!("\n❯ Executing examples/with/singleton_map_optional.rs");

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    enum OptionalEnum {
        Variant1(String),
        Variant2 { field: i32 },
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct OptionalStruct {
        #[serde(with = "singleton_map_optional")]
        field: Option<OptionalEnum>,
    }

    let input = OptionalStruct {
        field: Some(OptionalEnum::Variant2 { field: 42 }),
    };
    let yaml = serde_yml::to_string(&input).unwrap();
    println!("\n✅ Serialized YAML:\n{}", yaml);

    let output: OptionalStruct = serde_yml::from_str(&yaml).unwrap();
    println!("\n✅ Deserialized YAML:\n{:#?}", output);
    assert_eq!(input, output);
}
