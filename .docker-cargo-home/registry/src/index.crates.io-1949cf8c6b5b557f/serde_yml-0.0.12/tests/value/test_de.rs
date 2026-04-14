#[cfg(test)]
mod tests {
    use serde::Deserialize;
    use serde_yml::value::{Tag, TaggedValue, Value};

    /// Test deserialization of a `null` value into `Option<()>`.
    #[test]
    fn test_deserialize_null() {
        let value = Value::Null;
        let result: Option<()> = serde_yml::from_value(value).unwrap();
        assert_eq!(result, None);
    }

    /// Test deserialization of a `bool` value.
    #[test]
    fn test_deserialize_bool() {
        let value = Value::Bool(true);
        let result: bool = serde_yml::from_value(value).unwrap();
        assert!(result);
    }

    /// Test deserialization of an `i64` value.
    #[test]
    fn test_deserialize_i64() {
        let value = Value::Number(42.into());
        let result: i64 = serde_yml::from_value(value).unwrap();
        assert_eq!(result, 42);
    }

    /// Test deserialization of a `u64` value.
    #[test]
    fn test_deserialize_u64() {
        let value = Value::Number(42.into());
        let result: u64 = serde_yml::from_value(value).unwrap();
        assert_eq!(result, 42);
    }

    /// Test deserialization of a `f64` value.
    #[test]
    fn test_deserialize_f64() {
        let value = Value::Number(42.5.into());
        let result: f64 = serde_yml::from_value(value).unwrap();
        assert_eq!(result, 42.5);
    }

    /// Test deserialization of a `String` value.
    #[test]
    fn test_deserialize_string() {
        let value = Value::String("hello".to_string());
        let result: String = serde_yml::from_value(value).unwrap();
        assert_eq!(result, "hello");
    }

    /// Test deserialization of a sequence into a `Vec<i32>`.
    #[test]
    fn test_deserialize_sequence() {
        let value = Value::Sequence(vec![
            Value::Number(1.into()),
            Value::Number(2.into()),
        ]);
        let result: Vec<i32> = serde_yml::from_value(value).unwrap();
        assert_eq!(result, vec![1, 2]);
    }

    /// Test deserialization of a tagged enum variant.
    #[test]
    fn test_deserialize_enum() {
        let value = Value::Tagged(Box::new(TaggedValue {
            tag: Tag::new("B"),
            value: Value::Number(42.into()),
        }));
        #[derive(Deserialize, PartialEq, Debug)]
        enum E {
            A,
            B(i32),
            C { x: i32 },
        }
        let result: E = serde_yml::from_value(value).unwrap();
        assert_eq!(result, E::B(42));
    }

    /// Test deserialization of a newtype struct.
    #[test]
    fn test_deserialize_newtype_struct() {
        let value = Value::Number(42.into());
        #[derive(Deserialize, PartialEq, Debug)]
        struct Newtype(i32);
        let result: Newtype = serde_yml::from_value(value).unwrap();
        assert_eq!(result, Newtype(42));
    }

    /// Test deserialization of a tuple.
    #[test]
    fn test_deserialize_tuple() {
        let value = Value::Sequence(vec![
            Value::Number(1.into()),
            Value::Number(2.into()),
        ]);
        let result: (i32, i32) = serde_yml::from_value(value).unwrap();
        assert_eq!(result, (1, 2));
    }

    /// Test deserialization of a tuple struct.
    #[test]
    fn test_deserialize_tuple_struct() {
        let value = Value::Sequence(vec![
            Value::Number(1.into()),
            Value::Number(2.into()),
        ]);
        #[derive(Deserialize, PartialEq, Debug)]
        struct TupleStruct(i32, i32);
        let result: TupleStruct = serde_yml::from_value(value).unwrap();
        assert_eq!(result, TupleStruct(1, 2));
    }

    /// Test deserialization of a sequence into a `Vec<u8>`.
    #[test]
    fn test_deserialize_bytes() {
        let value = Value::Sequence(vec![
            Value::Number(1.into()),
            Value::Number(2.into()),
        ]);
        let result: Vec<u8> = serde_yml::from_value(value).unwrap();
        assert_eq!(result, vec![1, 2]);
    }

    /// Test deserialization of an identifier (string).
    #[test]
    fn test_deserialize_identifier() {
        let value = Value::String("hello".to_string());
        let result: String = serde_yml::from_value(value).unwrap();
        assert_eq!(result, "hello");
    }

    /// Test deserialization of a struct.
    #[test]
    fn test_deserialize_struct() {
        let value = Value::Mapping(
            vec![
                (
                    Value::String("x".to_string()),
                    Value::Number(1.into()),
                ),
                (
                    Value::String("y".to_string()),
                    Value::Number(2.into()),
                ),
            ]
            .into_iter()
            .collect(),
        );
        #[derive(Deserialize, PartialEq, Debug)]
        struct Point {
            x: i32,
            y: i32,
        }
        let result: Point = serde_yml::from_value(value).unwrap();
        assert_eq!(result, Point { x: 1, y: 2 });
    }

    /// Test deserialization of a map.
    #[test]
    fn test_deserialize_map() {
        let value = Value::Mapping(
            vec![
                (
                    Value::String("x".to_string()),
                    Value::Number(1.into()),
                ),
                (
                    Value::String("y".to_string()),
                    Value::Number(2.into()),
                ),
            ]
            .into_iter()
            .collect(),
        );
        let result: std::collections::HashMap<String, i32> =
            serde_yml::from_value(value).unwrap();
        let mut expected = std::collections::HashMap::new();
        expected.insert("x".to_string(), 1);
        expected.insert("y".to_string(), 2);
        assert_eq!(result, expected);
    }

    /// Test deserialization of `Option` with `Some` value.
    #[test]
    fn test_deserialize_option_some() {
        let value = Value::Number(42.into());
        let result: Option<i32> = serde_yml::from_value(value).unwrap();
        assert_eq!(result, Some(42));
    }

    /// Test deserialization of `Option` with `None` value.
    #[test]
    fn test_deserialize_option_none() {
        let value = Value::Null;
        let result: Option<i32> = serde_yml::from_value(value).unwrap();
        assert_eq!(result, None);
    }

    /// Test deserialization of a `char` value.
    #[test]
    fn test_deserialize_char() {
        let value = Value::String("a".to_string());
        let result: char = serde_yml::from_value(value).unwrap();
        assert_eq!(result, 'a');
    }

    /// Test deserialization of a unit value.
    #[test]
    fn test_deserialize_unit() {
        let value = Value::Null;
        let result: () = serde_yml::from_value(value).unwrap();
        println!(
            "✅ Deserialized unit value successfully. {:?}",
            result
        );
    }
    /// Test deserialization of a unit struct.
    #[test]
    fn test_deserialize_unit_struct() {
        let value = Value::Null;
        #[derive(Deserialize, PartialEq, Debug)]
        struct Unit;
        let result: Unit = serde_yml::from_value(value).unwrap();
        assert_eq!(result, Unit);
    }
    /// Test deserialization of an empty tuple struct.
    #[test]
    fn test_deserialize_empty_tuple_struct() {
        let yaml_str = "---";
        let value: Value = serde_yml::from_str(yaml_str).unwrap();

        #[derive(Deserialize, PartialEq, Debug)]
        struct Empty;

        let result: Empty = serde_yml::from_value(value).unwrap();
        println!("\n✅ Deserialized Empty tuple struct: {:?}", result);
    }

    /// Test deserialization of an empty tuple.
    #[test]
    fn test_deserialize_empty_tuple() {
        let yaml_str = "---";
        let value: Value = serde_yml::from_str(yaml_str).unwrap();

        let result: () = serde_yml::from_value(value).unwrap();
        println!("\n✅ Deserialized Empty tuple: {:?}", result);
    }

    /// Test deserialization of an empty struct.
    #[test]
    fn test_deserialize_empty_struct() {
        let value = Value::Null;
        #[derive(Deserialize, PartialEq, Debug)]
        struct Empty;
        let result: Empty = serde_yml::from_value(value).unwrap();
        assert_eq!(result, Empty);
    }
    /// Test deserialization of a unit variant.
    #[test]
    fn test_deserialize_unit_variant() {
        let value = Value::String("Variant".to_string());
        #[derive(Deserialize, PartialEq, Debug)]
        enum E {
            Variant,
        }
        let result: E = serde_yml::from_value(value).unwrap();
        assert_eq!(result, E::Variant);
    }
    /// Test deserialization of a newtype variant.
    #[test]
    fn test_deserialize_newtype_variant() {
        let yaml_str = "!Variant 0";
        let value: Value = serde_yml::from_str(yaml_str).unwrap();

        #[derive(Deserialize, PartialEq, Debug)]
        enum E {
            Variant(i32),
        }

        let result: E = serde_yml::from_value(value).unwrap();
        println!("\n✅ Deserialized newtype variant: {:?}", result);
    }

    /// Test deserialization of a tuple variant.
    #[test]
    fn test_deserialize_tuple_variant() {
        // YAML representation of the enum variant
        let yaml_str = "---\n!Variant\n- 1\n- 2\n";
        let value: Value = serde_yml::from_str(yaml_str).unwrap();
        #[derive(Deserialize, PartialEq, Debug)]
        enum E {
            Variant(i32, i32),
        }
        let result: E = serde_yml::from_value(value).unwrap();
        assert_eq!(result, E::Variant(1, 2));
    }

    /// Test deserialization of a struct variant.
    #[test]
    fn test_deserialize_struct_variant() {
        // YAML representation of the enum variant
        let yaml_str = "---\n!Variant\nx: 1\ny: 2\n";
        let value: Value = serde_yml::from_str(yaml_str).unwrap();
        #[derive(Deserialize, PartialEq, Debug)]
        enum E {
            Variant { x: i32, y: i32 },
        }
        let result: E = serde_yml::from_value(value).unwrap();
        assert_eq!(result, E::Variant { x: 1, y: 2 });
    }
    /// Test deserialization of a sequence variant.
    #[test]
    fn test_deserialize_sequence_variant() {
        // YAML representation of the enum variant
        let yaml_str = "---\n!Variant\n- 1\n- 2\n";
        let value: Value = serde_yml::from_str(yaml_str).unwrap();
        #[derive(Deserialize, PartialEq, Debug)]
        enum E {
            Variant(Vec<i32>),
        }
        let result: E = serde_yml::from_value(value).unwrap();
        assert_eq!(result, E::Variant(vec![1, 2]));
    }
    /// Test deserialization of a map variant.
    #[test]
    fn test_deserialize_map_variant() {
        // YAML representation of the enum variant
        let yaml_str = "---\n!Variant\nx: 1\ny: 2\n";
        let value: Value = serde_yml::from_str(yaml_str).unwrap();
        #[derive(Deserialize, PartialEq, Debug)]
        enum E {
            Variant(std::collections::HashMap<String, i32>),
        }
        let result: E = serde_yml::from_value(value).unwrap();
        let mut expected = std::collections::HashMap::new();
        expected.insert("x".to_string(), 1);
        expected.insert("y".to_string(), 2);
        assert_eq!(result, E::Variant(expected));
    }
    /// Test deserialization of a tagged unit variant.
    #[test]
    fn test_deserialize_tagged_unit_variant() {
        // YAML representation of the enum variant
        let yaml_str = "---\n!Variant\n";
        let value: Value = serde_yml::from_str(yaml_str).unwrap();
        #[derive(Deserialize, PartialEq, Debug)]
        enum E {
            Variant,
        }
        let result: E = serde_yml::from_value(value).unwrap();
        assert_eq!(result, E::Variant);
    }
    /// Test deserialization of a tagged newtype variant.
    #[test]
    fn test_deserialize_tagged_newtype_variant() {
        // YAML representation of the enum variant
        let yaml_str = "---\n!Variant 0\n";
        let value: Value = serde_yml::from_str(yaml_str).unwrap();
        #[derive(Deserialize, PartialEq, Debug)]
        enum E {
            Variant(i32),
        }
        let result: E = serde_yml::from_value(value).unwrap();
        assert_eq!(result, E::Variant(0));
    }
    /// Test deserialization of a tagged tuple variant.
    #[test]
    fn test_deserialize_tagged_tuple_variant() {
        // YAML representation of the enum variant
        let yaml_str = "---\n!Variant\n- 1\n- 2\n";
        let value: Value = serde_yml::from_str(yaml_str).unwrap();
        #[derive(Deserialize, PartialEq, Debug)]
        enum E {
            Variant(i32, i32),
        }
        let result: E = serde_yml::from_value(value).unwrap();
        assert_eq!(result, E::Variant(1, 2));
    }
    /// Test deserialization of a tagged struct variant.
    #[test]
    fn test_deserialize_tagged_struct_variant() {
        // YAML representation of the enum variant
        let yaml_str = "---\n!Variant\nx: 1\ny: 2\n";
        let value: Value = serde_yml::from_str(yaml_str).unwrap();
        #[derive(Deserialize, PartialEq, Debug)]
        enum E {
            Variant { x: i32, y: i32 },
        }
        let result: E = serde_yml::from_value(value).unwrap();
        assert_eq!(result, E::Variant { x: 1, y: 2 });
    }
    /// Test deserialization of a tagged sequence variant.
    #[test]
    fn test_deserialize_tagged_sequence_variant() {
        // YAML representation of the enum variant
        let yaml_str = "---\n!Variant\n- 1\n- 2\n";
        let value: Value = serde_yml::from_str(yaml_str).unwrap();
        #[derive(Deserialize, PartialEq, Debug)]
        enum E {
            Variant(Vec<i32>),
        }
        let result: E = serde_yml::from_value(value).unwrap();
        assert_eq!(result, E::Variant(vec![1, 2]));
    }
    /// Test deserialization of a `f32` value.
    #[test]
    fn test_deserialize_f32() {
        let value = Value::Number(serde_yml::Number::from(42.5f32));
        let result: f32 = serde_yml::from_value(value).unwrap();
        assert_eq!(result, 42.5f32);
    }
    /// Test deserialization of a `()` value.
    #[test]
    fn test_deserialize_unit_value() {
        let value = Value::Null;
        let result: () = serde_yml::from_value(value).unwrap();
        println!(
            "✅ Deserialized unit value successfully. {:?}",
            result
        );
    }

    /// Test deserialization of a byte array.
    #[test]
    fn test_deserialize_byte_array() {
        let value = Value::Sequence(vec![
            Value::Number(1.into()),
            Value::Number(2.into()),
            Value::Number(3.into()),
        ]);
        let result: [u8; 3] = serde_yml::from_value(value).unwrap();
        assert_eq!(result, [1, 2, 3]);
    }

    /// Test deserialization of an optional byte array.
    #[test]
    fn test_deserialize_optional_byte_array() {
        let value = Value::Sequence(vec![
            Value::Number(1.into()),
            Value::Number(2.into()),
            Value::Number(3.into()),
        ]);
        let result: Option<[u8; 3]> =
            serde_yml::from_value(value).unwrap();
        assert_eq!(result, Some([1, 2, 3]));
    }

    /// Test deserialization of a unit struct variant.
    #[test]
    fn test_deserialize_unit_struct_variant() {
        #[derive(Deserialize, PartialEq, Debug)]
        enum E {
            V,
        }
        let value = Value::String("V".to_string());
        let result: E = serde_yml::from_value(value).unwrap();
        assert_eq!(result, E::V);
    }

    /// Test deserialization of a newtype struct variant.
    #[test]
    fn test_deserialize_newtype_struct_variant() {
        #[derive(Deserialize, PartialEq, Debug)]
        enum E {
            V(i32),
        }
        let value = Value::Tagged(Box::new(TaggedValue {
            tag: Tag::new("V"),
            value: Value::Number(42.into()),
        }));
        let result: E = serde_yml::from_value(value).unwrap();
        assert_eq!(result, E::V(42));
    }

    /// Test deserialization of a tuple struct variant.
    #[test]
    fn test_deserialize_tuple_struct_variant() {
        #[derive(Deserialize, PartialEq, Debug)]
        enum E {
            V(i32, i32),
        }
        let value = Value::Tagged(Box::new(TaggedValue {
            tag: Tag::new("V"),
            value: Value::Sequence(vec![
                Value::Number(1.into()),
                Value::Number(2.into()),
            ]),
        }));
        let result: E = serde_yml::from_value(value).unwrap();
        assert_eq!(result, E::V(1, 2));
    }
}
