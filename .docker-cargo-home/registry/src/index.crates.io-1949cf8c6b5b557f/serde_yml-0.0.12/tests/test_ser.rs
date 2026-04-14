#[cfg(test)]
mod tests {
    use indoc::indoc;
    use serde::ser::{SerializeTuple, SerializeTupleStruct};
    use serde::{ser::Serializer as _, Serialize};
    use serde_yml::ser::SerializerConfig;
    use serde_yml::{
        libyml::emitter::{Scalar, ScalarStyle},
        Serializer, State,
    };
    use std::{collections::BTreeMap, fmt::Write};

    #[test]
    /// Tests the test scalar serialization.
    fn test_scalar_serialization() {
        // Arrange
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);
        let scalar_value = Scalar {
            tag: None,
            value: "test value",
            style: ScalarStyle::Plain,
        };

        // Act
        serializer.emit_scalar(scalar_value).unwrap();

        // Assert
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "test value\n",
            "Serialized scalar value doesn't match expected output"
        );
    }

    #[test]
    /// Tests the test sequence start serialization.
    fn test_sequence_start_serialization() {
        // Arrange
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);

        // Act
        serializer.emit_sequence_start().unwrap();

        // Assert
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "",
            "Serialized sequence start doesn't match expected output"
        );
    }

    #[test]
    /// Tests the test mapping start serialization.
    fn test_mapping_start_serialization() {
        // Arrange
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);

        // Act
        serializer.emit_mapping_start().unwrap();

        // Assert
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "",
            "Serialized mapping start doesn't match expected output"
        );
    }

    #[test]
    /// Tests the test flush mapping start.
    fn test_flush_mapping_start() {
        // Arrange
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);

        // Act
        serializer.emit_mapping_start().unwrap();
        serializer.flush().unwrap();

        // Assert
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "",
            "Flushed mapping start doesn't match expected output"
        );
    }

    #[test]
    /// Tests the serialization of an empty map.
    fn test_serialize_empty_map() {
        // Arrange
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);
        let map: BTreeMap<String, i32> = BTreeMap::new();

        // Act
        map.serialize(&mut serializer).unwrap();

        // Assert
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "{}\n",
            "Serialized empty map doesn't match expected output"
        );
    }

    #[test]
    /// Tests the test serialize simple map.
    fn test_serialize_simple_map() {
        // Arrange
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);
        let mut map = BTreeMap::new();
        map.insert("key".to_string(), 42);

        // Act
        map.serialize(&mut serializer).unwrap();

        // Assert
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "key: 42\n",
            "Serialized simple map doesn't match expected output"
        );
    }

    #[test]
    /// Tests the test serialize nested map.
    fn test_serialize_nested_map() {
        // Arrange
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);
        let mut inner_map = BTreeMap::new();
        inner_map
            .insert("inner_key".to_string(), "inner_value".to_string());
        let mut outer_map = BTreeMap::new();
        outer_map.insert("outer_key".to_string(), inner_map);

        // Act
        outer_map.serialize(&mut serializer).unwrap();

        // Assert
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "outer_key:\n  inner_key: inner_value\n",
            "Serialized nested map doesn't match expected output"
        );
    }

    /// Tests serializing a struct with custom fields.
    #[derive(Serialize)]
    struct CustomStruct {
        field1: String,
        field2: i32,
    }

    #[test]
    /// Tests the test serialize custom struct.
    fn test_serialize_custom_struct() {
        // Arrange
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);
        let custom_struct = CustomStruct {
            field1: "value1".to_string(),
            field2: 42,
        };

        // Act
        custom_struct.serialize(&mut serializer).unwrap();

        // Assert
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "field1: value1\nfield2: 42\n",
            "Serialized custom struct doesn't match expected output"
        );
    }

    #[test]
    // Test cases for taking tag with found tag state
    fn test_take_tag_with_found_tag_state() {
        // Arrange
        let mut serializer = Serializer::<Vec<u8>>::new(Vec::new());
        serializer.state = State::FoundTag("test tag".to_owned());

        // Act
        let tag = serializer.take_tag();

        // Assert
        assert_eq!(
            tag,
            Some("!test tag".to_owned()), // Found tag should be prefixed with '!'
            "Tag extraction output doesn't match expected output"
        );
    }

    #[test]
    // Test cases for taking tag with no state
    fn test_take_tag_with_no_state() {
        // Arrange
        let mut serializer = Serializer::<Vec<u8>>::new(Vec::new());

        // Act
        let tag = serializer.take_tag();

        // Assert
        assert_eq!(
            tag,
            None, // Since there was no specific state, tag extraction should return None
            "Tag extraction output doesn't match expected output"
        );
    }

    #[test]
    // Test cases for converting into inner
    fn test_into_inner() {
        // Arrange
        let mut buffer = Vec::new();
        let buffer_clone = buffer.clone();
        let serializer = Serializer::new(&mut buffer);

        // Act
        let result = serializer.into_inner().unwrap();

        // Assert
        assert_eq!(&*result, &buffer_clone);
    }

    #[test]
    // Test cases for serializing boolean values
    fn test_serialize_bool() {
        // Arrange
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);

        // Act
        serializer.serialize_bool(true).unwrap();
        serializer.serialize_bool(false).unwrap();

        // Assert
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "true\n--- false\n",
            "Serialized boolean values don't match expected output"
        );
    }

    #[test]
    /// Tests the test serialize i8.
    fn test_serialize_i8() {
        // Arrange
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);

        // Act
        serializer.serialize_i8(42).unwrap();
        serializer.serialize_i8(-100).unwrap();

        // Assert
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "42\n--- -100\n",
            "Serialized i8 values don't match expected output"
        );
    }

    #[test]
    /// Tests the test serialize i16.
    fn test_serialize_i16() {
        // Arrange
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);

        // Act
        serializer.serialize_i16(42).unwrap();
        serializer.serialize_i16(-100).unwrap();

        // Assert
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "42\n--- -100\n",
            "Serialized i16 values don't match expected output"
        );
    }

    #[test]
    /// Tests the test serialize i32.
    fn test_serialize_i32() {
        // Arrange
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);

        // Act
        serializer.serialize_i32(42).unwrap();
        serializer.serialize_i32(-100).unwrap();

        // Assert
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "42\n--- -100\n",
            "Serialized i32 values don't match expected output"
        );
    }

    #[test]
    /// Tests the test serialize i64.
    fn test_serialize_i64() {
        // Arrange
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);

        // Act
        serializer.serialize_i64(42).unwrap();
        serializer.serialize_i64(-100).unwrap();

        // Assert
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "42\n--- -100\n",
            "Serialized i64 values don't match expected output"
        );
    }

    #[test]
    /// Tests the test serialize i128.
    fn test_serialize_i128() {
        // Arrange
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);

        // Act
        let u64_max = u64::MAX as i128;
        let u64_max_plus_one = u64_max + 1;
        let i64_min = i64::MIN as i128;
        let i64_min_minus_one = i64_min - 1;

        serializer.serialize_i128(42).unwrap();
        serializer.serialize_i128(-100).unwrap();
        serializer.serialize_i128(u64_max).unwrap();
        serializer.serialize_i128(u64_max_plus_one).unwrap();
        serializer.serialize_i128(i64_min).unwrap();
        serializer.serialize_i128(i64_min_minus_one).unwrap();

        // Assert
        assert_eq!(
        String::from_utf8(buffer).unwrap(),
        "42\n--- -100\n--- 18446744073709551615\n--- 18446744073709551616\n--- -9223372036854775808\n--- -9223372036854775809\n",
        "Serialized i128 values don't match expected output"
    );
    }

    #[test]
    /// Tests the test serialize f64.
    fn test_serialize_f64() {
        // Arrange
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);

        // Act
        serializer.serialize_f64(std::f64::consts::PI).unwrap();
        serializer.serialize_f64(f64::INFINITY).unwrap();
        serializer.serialize_f64(f64::NEG_INFINITY).unwrap();
        serializer.serialize_f64(f64::NAN).unwrap();

        // Assert
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "3.141592653589793\n--- .inf\n--- -.inf\n--- .nan\n",
            "Serialized f64 values don't match expected output"
        );
    }

    #[test]
    /// Tests the test serialize char.
    fn test_serialize_char() {
        // Arrange
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);

        // Act
        serializer.serialize_char('a').unwrap();
        serializer.serialize_char('💻').unwrap();

        // Assert
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "'a'\n--- '💻'\n",
            "Serialized char values don't match expected output"
        );
    }

    #[test]
    /// Tests the test serialize bytes.
    fn test_serialize_bytes() {
        // Arrange
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);

        // Act
        let bytes = vec![1, 2, 3, 4, 5];

        let result = serializer.serialize_bytes(&bytes);

        // Assert
        assert!(result.is_err());
        assert_eq!(
        result.unwrap_err().to_string(),
        "serialization and deserialization of bytes in YAML is not implemented",
        "Unexpected error message"
    );
    }

    #[test]
    /// Tests the test serialize tuple.
    fn test_serialize_tuple() {
        // Arrange
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);

        // Act
        let mut tuple_serializer =
            serializer.serialize_tuple(3).unwrap();
        SerializeTuple::serialize_element(&mut tuple_serializer, &42)
            .unwrap();
        SerializeTuple::serialize_element(
            &mut tuple_serializer,
            &"hello",
        )
        .unwrap();
        SerializeTuple::serialize_element(&mut tuple_serializer, &true)
            .unwrap();
        SerializeTuple::end(tuple_serializer).unwrap();

        // Assert
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "- 42\n- hello\n- true\n",
            "Serialized tuple doesn't match expected output"
        );
    }

    #[test]
    /// Tests the test serialize tuple struct.
    fn test_serialize_tuple_struct() {
        // Arrange
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);

        // Act
        let mut tuple_struct_serializer = serializer
            .serialize_tuple_struct("MyTupleStruct", 2)
            .unwrap();
        SerializeTupleStruct::serialize_field(
            &mut tuple_struct_serializer,
            &42,
        )
        .unwrap();
        SerializeTupleStruct::serialize_field(
            &mut tuple_struct_serializer,
            &"hello",
        )
        .unwrap();
        SerializeTupleStruct::end(tuple_struct_serializer).unwrap();

        // Assert
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "- 42\n- hello\n",
            "Serialized tuple struct doesn't match expected output"
        );
    }

    #[test]
    /// Tests the test serialize option.
    fn test_serialize_option() {
        // Arrange
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);
        let some_value: Option<i32> = Some(42);
        let none_value: Option<i32> = None;

        // Act
        some_value.serialize(&mut serializer).unwrap();
        none_value.serialize(&mut serializer).unwrap();

        // Assert
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "42\n--- null\n",
            "Serialized Option values don't match expected output"
        );
    }

    #[test]
    /// Tests the test serialize enum.
    fn test_serialize_enum() {
        // Arrange
        #[derive(Serialize)]
        enum MyEnum {
            A,
            B(i32),
            C { x: i32, y: i32 },
        }

        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);

        // Act
        MyEnum::A.serialize(&mut serializer).unwrap();
        MyEnum::B(42).serialize(&mut serializer).unwrap();
        MyEnum::C { x: 1, y: 2 }.serialize(&mut serializer).unwrap();

        // Assert
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "A\n--- !B 42\n--- !C\nx: 1\n'y': 2\n",
            "Serialized enum values don't match expected output"
        );
    }

    #[test]
    /// Test cases for serializing sequences
    fn test_serialize_sequence() {
        // Arrange
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);
        let sequence = vec!["42", "hello", "true"];

        // Act
        sequence.serialize(&mut serializer).unwrap();

        // Assert
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "- '42'\n- hello\n- 'true'\n",
            "Serialized sequence doesn't match expected output"
        );
    }

    #[test]
    /// Tests the test serialize map.
    fn test_serialize_map() {
        // Arrange
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);
        let mut map = BTreeMap::new();
        map.insert("name", "John");
        map.insert("age", "30");

        // Act
        map.serialize(&mut serializer).unwrap();

        // Assert
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "age: '30'\nname: John\n",
            "Serialized map doesn't match expected output"
        );
    }

    #[test]
    /// Tests the test serialize nested struct.
    fn test_serialize_nested_struct() {
        // Arrange
        #[derive(Serialize)]
        struct Person {
            name: String,
            age: u32,
            address: Address,
        }

        #[derive(Serialize)]
        struct Address {
            street: String,
            city: String,
        }

        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);

        // Act
        let person = Person {
            name: "Alice".to_string(),
            age: 25,
            address: Address {
                street: "123 Main St".to_string(),
                city: "Anytown".to_string(),
            },
        };
        person.serialize(&mut serializer).unwrap();

        // Assert
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "name: Alice\nage: 25\naddress:\n  street: '123 Main St'\n  city: Anytown\n",
            "Serialized nested struct doesn't match expected output"
        );
    }

    #[test]
    /// Tests the test serialize optional fields.
    fn test_serialize_optional_fields() {
        // Arrange
        #[derive(Serialize)]
        struct User {
            name: String,
            email: Option<String>,
            age: Option<u32>,
        }

        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);

        // Act
        let user = User {
            name: "Bob".to_string(),
            email: Some("bob@example.com".to_string()),
            age: None,
        };
        user.serialize(&mut serializer).unwrap();

        // Assert
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "name: Bob\nemail: bob@example.com\nage: null\n",
            "Serialized optional fields don't match expected output"
        );
    }

    #[test]
    /// Tests the test serialize tagged value.
    fn test_serialize_tagged_value() {
        // Arrange
        #[derive(Serialize)]
        struct TaggedValue {
            #[serde(rename = "!tag")]
            value: String,
        }

        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);

        // Act
        let tagged_value = TaggedValue {
            value: "example".to_string(),
        };
        tagged_value.serialize(&mut serializer).unwrap();

        // Assert
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "'!tag': example\n",
            "Serialized tagged value doesn't match expected output"
        );
    }

    #[test]
    /// Tests the test serialize large data.
    fn test_serialize_large_data() {
        // Arrange
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);
        let large_sequence: Vec<_> = (0..1000).collect();

        // Act
        large_sequence.serialize(&mut serializer).unwrap();

        // Assert
        let mut expected_output = String::new(); // Create an empty String
        for i in &large_sequence {
            // Append to the String directly
            writeln!(&mut expected_output, "- {}", i).unwrap();
        }

        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            expected_output,
            "Serialized large data doesn't match expected output"
        );
    }

    #[test]
    /// Tests the test serialize nested sequences.
    fn test_serialize_nested_sequences() {
        // Arrange
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);
        let nested_sequences = vec![
            vec!["a", "b", "c"],
            vec!["d", "e", "f"],
            vec!["g", "h", "i"],
        ];

        // Act
        nested_sequences.serialize(&mut serializer).unwrap();

        // Assert
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "- - a\n  - b\n  - c\n- - d\n  - e\n  - f\n- - g\n  - h\n  - i\n",
            "Serialized nested sequences don't match expected output"
        );
    }

    #[test]
    /// Tests the test serialize nested maps.
    fn test_serialize_nested_maps() {
        // Arrange
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);
        let mut nested_maps = BTreeMap::new();
        let mut inner_map1 = BTreeMap::new();
        inner_map1.insert("key1", "value1");
        inner_map1.insert("key2", "value2");
        let mut inner_map2 = BTreeMap::new();
        inner_map2.insert("key3", "value3");
        inner_map2.insert("key4", "value4");
        nested_maps.insert("map1", inner_map1);
        nested_maps.insert("map2", inner_map2);

        // Act
        nested_maps.serialize(&mut serializer).unwrap();

        // Assert
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "map1:\n  key1: value1\n  key2: value2\nmap2:\n  key3: value3\n  key4: value4\n",
            "Serialized nested maps don't match expected output"
        );
    }

    #[test]
    /// Tests the test serialize mixed data types.
    fn test_serialize_mixed_data_types() {
        // Arrange
        #[derive(Serialize)]
        struct MixedData {
            name: String,
            age: u32,
            active: bool,
            scores: Vec<i32>,
            metadata: BTreeMap<String, String>,
        }

        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);

        // Act
        let mixed_data = MixedData {
            name: "Alice".to_string(),
            age: 30,
            active: true,
            scores: vec![80, 90, 95],
            metadata: {
                let mut map = BTreeMap::new();
                map.insert("key1".to_string(), "value1".to_string());
                map.insert("key2".to_string(), "value2".to_string());
                map
            },
        };
        mixed_data.serialize(&mut serializer).unwrap();

        // Assert
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "name: Alice\nage: 30\nactive: true\nscores:\n- 80\n- 90\n- 95\nmetadata:\n  key1: value1\n  key2: value2\n",
            "Serialized mixed data types don't match expected output"
        );
    }

    #[test]
    /// Tests the test serialize empty sequence and map.
    fn test_serialize_empty_sequence_and_map() {
        // Arrange
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);
        let empty_sequence: Vec<i32> = Vec::new();
        let empty_map: BTreeMap<String, i32> = BTreeMap::new();

        // Act
        empty_sequence.serialize(&mut serializer).unwrap();
        empty_map.serialize(&mut serializer).unwrap();

        // Assert
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "[]\n--- {}\n",
            "Serialized empty sequence and map don't match expected output"
        );
    }

    #[test]
    /// Tests the test serialize special characters.
    fn test_serialize_special_characters() {
        // Arrange
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);
        let special_string = "\"'\\n\t";

        // Act
        special_string.serialize(&mut serializer).unwrap();

        // Assert
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "\"\\\"'\\\\n\\t\"\n",
            "Serialized special characters don't match expected output"
        );
    }

    #[test]
    /// Tests the test serialize custom serializer.
    fn test_serialize_custom_serializer() {
        // Arrange
        use serde::ser::SerializeMap;

        #[derive(Serialize)]
        struct CustomStruct {
            #[serde(serialize_with = "custom_serialize")]
            value: String,
        }

        fn custom_serialize<S>(
            value: &String,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut map = serializer.serialize_map(Some(1))?;
            map.serialize_entry(
                "custom_value",
                &format!("<<{}>>", value),
            )?;
            map.end()
        }

        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);

        // Act
        let custom_struct = CustomStruct {
            value: "example".to_string(),
        };
        custom_struct.serialize(&mut serializer).unwrap();

        // Assert
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "value:\n  custom_value: <<example>>\n",
            "Serialized custom serializer doesn't match expected output"
        );
    }

    #[test]
    /// Tests the test default unit variants.
    fn test_default_unit_variants() {
        #[derive(Serialize)]
        enum Enum {
            Unit,
        }

        let mut buffer = vec![];

        let mut ser = Serializer::new(&mut buffer);
        Enum::Unit.serialize(&mut ser).unwrap();
        let output = String::from_utf8(buffer).unwrap();

        let expected = indoc! {"
        Unit
    "};

        assert_eq!(output, expected);
    }

    #[test]
    /// Tests the test tag unit variants.
    fn test_tag_unit_variants() {
        #[derive(Serialize)]
        enum Enum {
            Unit,
        }

        let mut buffer = vec![];
        let mut ser = Serializer::new_with_config(
            &mut buffer,
            SerializerConfig {
                tag_unit_variants: true,
            },
        );
        Enum::Unit.serialize(&mut ser).unwrap();
        let output = String::from_utf8(buffer).unwrap();

        let expected = indoc! {"
        !Unit
    "};

        assert_eq!(output, expected);
    }
    #[test]
    /// Tests the creation of a new Serializer with the default configuration.
    fn test_new() {
        let buffer = Vec::new();
        let serializer = Serializer::new(buffer);
        assert!(
            serializer.depth == 0,
            "Expected depth to be 0 after initialization"
        );
    }
    #[test]
    /// Tests the creation of a new Serializer with a custom configuration.
    /// /// Tests the test new with config.
    fn test_new_with_config() {
        let buffer = Vec::new();
        let config = SerializerConfig::default();
        let serializer = Serializer::new_with_config(buffer, config);
        assert!(serializer.depth == 0, "Expected depth to be 0 after initialization with custom config");
        // Additional assertions can be added as needed.
    }

    #[test]
    /// Tests the flush function to ensure all buffered data is written.
    fn test_flush() {
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);
        serializer.flush().unwrap();
        // Check if the buffer was properly flushed.
        assert!(
            buffer.is_empty(),
            "Buffer should be empty after flush"
        );
    }

    #[test]
    /// Tests the emit_scalar function to serialize a scalar value.
    fn test_emit_scalar() {
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);
        let scalar_value = Scalar {
            tag: None,
            value: "test value",
            style: ScalarStyle::Plain,
        };
        serializer.emit_scalar(scalar_value).unwrap();
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "test value\n",
            "Serialized scalar value doesn't match expected output"
        );
    }

    #[test]
    /// Tests the emit_sequence_start function. This test accounts for the fact that starting a sequence may not immediately produce output.
    fn test_emit_sequence_start() {
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);
        serializer.emit_sequence_start().unwrap();
        serializer
            .emit_scalar(Scalar {
                tag: None,
                value: "item",
                style: ScalarStyle::Plain,
            })
            .unwrap();
        serializer.emit_sequence_end().unwrap();
        assert!(!buffer.is_empty(), "Buffer should not be empty after emitting sequence start and a scalar");
    }

    #[test]
    /// Tests the emit_sequence_end function. This test ensures proper sequence handling.
    fn test_emit_sequence_end() {
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);
        serializer.emit_sequence_start().unwrap();
        serializer
            .emit_scalar(Scalar {
                tag: None,
                value: "item",
                style: ScalarStyle::Plain,
            })
            .unwrap();
        serializer.emit_sequence_end().unwrap();
        assert!(buffer.ends_with(b"item\n"), "Buffer should end with the scalar value and sequence end marker");
    }

    #[test]
    /// Tests the emit_mapping_start function. Similar to sequences, starting a mapping might not produce immediate output.
    fn test_emit_mapping_start() {
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);
        serializer.emit_mapping_start().unwrap();
        serializer
            .emit_scalar(Scalar {
                tag: None,
                value: "key",
                style: ScalarStyle::Plain,
            })
            .unwrap();
        serializer
            .emit_scalar(Scalar {
                tag: None,
                value: "value",
                style: ScalarStyle::Plain,
            })
            .unwrap();
        serializer.emit_mapping_end().unwrap();
        assert!(!buffer.is_empty(), "Buffer should not be empty after emitting mapping start and key-value pair");
    }

    #[test]
    /// Tests the emit_mapping_end function to ensure mappings are correctly finalized.
    fn test_emit_mapping_end() {
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);
        serializer.emit_mapping_start().unwrap();
        serializer
            .emit_scalar(Scalar {
                tag: None,
                value: "key",
                style: ScalarStyle::Plain,
            })
            .unwrap();
        serializer
            .emit_scalar(Scalar {
                tag: None,
                value: "value",
                style: ScalarStyle::Plain,
            })
            .unwrap();
        serializer.emit_mapping_end().unwrap();
        assert!(
            buffer.ends_with(b"value\n"),
            "Buffer should end with the value and mapping end marker"
        );
    }

    #[test]
    /// Tests the value_end function with proper sequence start.
    fn test_value_end() {
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);
        serializer.value_start().unwrap();
        serializer
            .emit_scalar(Scalar {
                tag: None,
                value: "scalar value",
                style: ScalarStyle::Plain,
            })
            .unwrap();
        serializer.value_end().unwrap();
        assert!(
            serializer.depth == 0,
            "Expected depth to decrease to 0 after value end"
        );
    }

    #[test]
    /// Tests the take_tag function to check if a tag can be taken from the state.
    fn test_take_tag() {
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);
        let tag = serializer.take_tag();
        assert!(
            tag.is_none(),
            "Expected no tag to be present initially"
        );
    }

    #[test]
    /// Test emitting a scalar with a tag.
    fn test_emit_scalar_with_tag() {
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);
        let scalar_value = Scalar {
            tag: Some("tag".to_string()),
            value: "test value",
            style: ScalarStyle::Plain,
        };
        serializer.emit_scalar(scalar_value).unwrap();
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "!<tag> test value\n",
            "Serialized scalar value with tag doesn't match expected output"
        );
    }

    #[test]
    /// Test emitting a scalar with a single quoted style.
    fn test_emit_scalar_with_quoted_style() {
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);
        let scalar_value = Scalar {
            tag: None,
            value: "test value",
            style: ScalarStyle::SingleQuoted,
        };
        serializer.emit_scalar(scalar_value).unwrap();
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "'test value'\n",
            "Serialized scalar value with quoted style doesn't match expected output"
        );
    }

    #[test]
    /// Test emitting a scalar with a double quoted style.
    fn test_emit_scalar_with_double_quoted_style() {
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);
        let scalar_value = Scalar {
            tag: None,
            value: "test value",
            style: ScalarStyle::DoubleQuoted,
        };
        serializer.emit_scalar(scalar_value).unwrap();
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "\"test value\"\n",
            "Serialized scalar value with double quoted style doesn't match expected output"
        );
    }

    #[test]
    /// Test emitting a scalar with a literal style.
    /// The literal style is used for multi-line strings.
    fn test_emit_scalar_with_literal_style() {
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);
        let scalar_value = Scalar {
            tag: None,
            value: "test\nvalue",
            style: ScalarStyle::Literal,
        };
        serializer.emit_scalar(scalar_value).unwrap();
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "|-\n  test\n  value\n",
            "Serialized scalar value with literal style doesn't match expected output"
        );
    }

    #[test]
    /// Test emitting a scalar with a folded style.
    fn test_emit_scalar_with_folded_style() {
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);
        let scalar_value = Scalar {
            tag: None,
            value: "test\nvalue",
            style: ScalarStyle::Folded,
        };
        serializer.emit_scalar(scalar_value).unwrap();
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            ">-\n  test\n\n  value\n",
            "Serialized scalar value with folded style doesn't match expected output"
        );
    }

    #[test]
    /// Test emitting a scalar with a plain style.
    fn test_emit_scalar_with_plain_style() {
        let mut buffer = Vec::new();
        let mut serializer = Serializer::new(&mut buffer);
        let scalar_value = Scalar {
            tag: None,
            value: "test value",
            style: ScalarStyle::Plain,
        };
        serializer.emit_scalar(scalar_value).unwrap();
        assert_eq!(
            String::from_utf8(buffer).unwrap(),
            "test value\n",
            "Serialized scalar value with plain style doesn't match expected output"
        );
    }
}
