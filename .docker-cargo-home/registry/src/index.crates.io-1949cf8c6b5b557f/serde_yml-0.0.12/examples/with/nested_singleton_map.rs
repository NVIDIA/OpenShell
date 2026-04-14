//! Example for the `nested_singleton_map` function in the `with` module.
//!
//! This function is used to recursively serialize and deserialize nested enums
//! into a YAML map with a single key-value pair for each enum variant, where the
//! key is the enum variant name and the value is the inner value of the enum
//! variant.
//!

use serde::{Deserialize, Serialize};
use serde_yml::with::nested_singleton_map;

pub(crate) fn main() {
    // Print a message to indicate the file being executed.
    println!("\n❯ Executing examples/with/nested_singleton_map.rs");

    // Define the inner enum with different variants
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    enum InnerEnum {
        Variant1,
        Variant2(String),
        Variant3 { field1: i32, field2: bool },
    }

    // Define the outer enum that contains the inner enum as a field
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    enum OuterEnum {
        Variant1(InnerEnum),
        Variant2 { inner: InnerEnum },
    }

    // Define a struct that contains the outer enum as a field
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct NestedEnumStruct {
        #[serde(with = "nested_singleton_map")]
        field: OuterEnum,
    }

    // Example 1: OuterEnum::Variant1(InnerEnum::Variant1)
    let input1 = NestedEnumStruct {
        field: OuterEnum::Variant1(InnerEnum::Variant1),
    };
    let yaml1 = serde_yml::to_string(&input1).unwrap();
    println!("\n✅ Serialized YAML for Example 1:\n{}", yaml1);
    let output1: NestedEnumStruct =
        serde_yml::from_str(&yaml1).unwrap();
    println!("\n✅ Deserialized YAML for Example 1:\n{:#?}", output1);
    assert_eq!(input1, output1);

    // Example 2: OuterEnum::Variant1(InnerEnum::Variant2("value".to_string()))
    let input2 = NestedEnumStruct {
        field: OuterEnum::Variant1(InnerEnum::Variant2(
            "value".to_string(),
        )),
    };
    let yaml2 = serde_yml::to_string(&input2).unwrap();
    println!("\n✅ Serialized YAML for Example 2:\n{}", yaml2);
    let output2: NestedEnumStruct =
        serde_yml::from_str(&yaml2).unwrap();
    println!("\n✅ Deserialized YAML for Example 2:\n{:#?}", output2);
    assert_eq!(input2, output2);

    // Example 3: OuterEnum::Variant2 { inner: InnerEnum::Variant3 { field1: 42, field2: true } }
    let input3 = NestedEnumStruct {
        field: OuterEnum::Variant2 {
            inner: InnerEnum::Variant3 {
                field1: 42,
                field2: true,
            },
        },
    };
    let yaml3 = serde_yml::to_string(&input3).unwrap();
    println!("\n✅ Serialized YAML for Example 3:\n{}", yaml3);
    let output3: NestedEnumStruct =
        serde_yml::from_str(&yaml3).unwrap();
    println!("\n✅ Deserialized YAML for Example 3:\n{:#?}", output3);
    assert_eq!(input3, output3);

    // Example 4: OuterEnum::Variant1(InnerEnum::Variant3 { field1: 99, field2: false })
    let input4 = NestedEnumStruct {
        field: OuterEnum::Variant1(InnerEnum::Variant3 {
            field1: 99,
            field2: false,
        }),
    };
    let yaml4 = serde_yml::to_string(&input4).unwrap();
    println!("\n✅ Serialized YAML for Example 4:\n{}", yaml4);
    let output4: NestedEnumStruct =
        serde_yml::from_str(&yaml4).unwrap();
    println!("\n✅ Deserialized YAML for Example 4:\n{:#?}", output4);
    assert_eq!(input4, output4);

    // Example 5: OuterEnum::Variant2 { inner: InnerEnum::Variant2("another value".to_string()) }
    let input5 = NestedEnumStruct {
        field: OuterEnum::Variant2 {
            inner: InnerEnum::Variant2("another value".to_string()),
        },
    };
    let yaml5 = serde_yml::to_string(&input5).unwrap();
    println!("\n✅ Serialized YAML for Example 5:\n{}", yaml5);
    let output5: NestedEnumStruct =
        serde_yml::from_str(&yaml5).unwrap();
    println!("\n✅ Deserialized YAML for Example 5:\n{:#?}", output5);
    assert_eq!(input5, output5);
}
