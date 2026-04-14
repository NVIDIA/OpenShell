#[cfg(test)]
mod tests {
    use serde_yml::value::Index;
    use serde_yml::Value;

    /// Test for `index_into` method of `usize` implementation.
    /// This test verifies that `index_into` correctly indexes into a `Value::Sequence`.
    #[test]
    fn test_usize_index_into_sequence() {
        let sequence = Value::Sequence(vec![
            Value::Number(1.into()),
            Value::Number(2.into()),
        ]);
        let index = 1;
        assert_eq!(
            index.index_into(&sequence),
            Some(&Value::Number(2.into()))
        );
    }

    /// Test for `index_into` method of `usize` implementation with a `Value::Mapping`.
    /// This test verifies that `index_into` correctly indexes into a `Value::Mapping` with a numeric key.
    #[test]
    fn test_usize_index_into_mapping() {
        let mut mapping = serde_yml::Mapping::new();
        mapping.insert(
            Value::Number(1.into()),
            Value::String("one".into()),
        );
        let value = Value::Mapping(mapping);
        let index = 1;
        assert_eq!(
            index.index_into(&value),
            Some(&Value::String("one".into()))
        );
    }

    /// Test for `index_into` method of `usize` implementation with an out-of-bounds index in `Value::Sequence`.
    /// This test verifies that `index_into` returns None for an out-of-bounds index.
    #[test]
    fn test_usize_index_into_sequence_out_of_bounds() {
        let sequence = Value::Sequence(vec![
            Value::Number(1.into()),
            Value::Number(2.into()),
        ]);
        let index = 3;
        assert_eq!(index.index_into(&sequence), None);
    }

    /// Test for `index_into` method of `usize` implementation with a non-numeric key in `Value::Mapping`.
    /// This test verifies that `index_into` returns None for a non-numeric key.
    #[test]
    fn test_usize_index_into_mapping_non_numeric_key() {
        let mut mapping = serde_yml::Mapping::new();
        mapping.insert(
            Value::String("key".into()),
            Value::String("value".into()),
        );
        let value = Value::Mapping(mapping);
        let index = 1;
        assert_eq!(index.index_into(&value), None);
    }

    /// Test for `index_into_mut` method of `usize` implementation.
    /// This test verifies that `index_into_mut` correctly indexes into a mutable `Value::Sequence`.
    #[test]
    fn test_usize_index_into_mut_sequence() {
        let mut sequence = Value::Sequence(vec![
            Value::Number(1.into()),
            Value::Number(2.into()),
        ]);
        let index = 1;
        if let Some(value) = index.index_into_mut(&mut sequence) {
            *value = Value::Number(3.into());
        }
        assert_eq!(
            sequence,
            Value::Sequence(vec![
                Value::Number(1.into()),
                Value::Number(3.into())
            ])
        );
    }

    /// Test for `index_into_mut` method of `usize` implementation with a `Value::Mapping`.
    /// This test verifies that `index_into_mut` correctly indexes into a mutable `Value::Mapping` with a numeric key.
    #[test]
    fn test_usize_index_into_mut_mapping() {
        let mut mapping = serde_yml::Mapping::new();
        mapping.insert(
            Value::Number(1.into()),
            Value::String("one".into()),
        );
        let mut value = Value::Mapping(mapping);
        let index = 1;
        if let Some(value) = index.index_into_mut(&mut value) {
            *value = Value::String("two".into());
        }
        let mut expected_mapping = serde_yml::Mapping::new();
        expected_mapping.insert(
            Value::Number(1.into()),
            Value::String("two".into()),
        );
        assert_eq!(value, Value::Mapping(expected_mapping));
    }

    /// Test for `index_into_mut` method of `usize` implementation with an out-of-bounds index in `Value::Sequence`.
    /// This test verifies that `index_into_mut` returns None for an out-of-bounds index.
    #[test]
    fn test_usize_index_into_mut_sequence_out_of_bounds() {
        let mut sequence = Value::Sequence(vec![
            Value::Number(1.into()),
            Value::Number(2.into()),
        ]);
        let index = 3;
        assert_eq!(index.index_into_mut(&mut sequence), None);
    }

    /// Test for `index_into_mut` method of `usize` implementation with a non-numeric key in `Value::Mapping`.
    /// This test verifies that `index_into_mut` returns None for a non-numeric key.
    #[test]
    fn test_usize_index_into_mut_mapping_non_numeric_key() {
        let mut mapping = serde_yml::Mapping::new();
        mapping.insert(
            Value::String("key".into()),
            Value::String("value".into()),
        );
        let mut value = Value::Mapping(mapping);
        let index = 1;
        assert_eq!(index.index_into_mut(&mut value), None);
    }

    /// Test for `index_or_insert` method of `usize` implementation.
    /// This test verifies that `index_or_insert` correctly indexes or inserts into a `Value::Sequence`.
    #[test]
    fn test_usize_index_or_insert_sequence() {
        let mut sequence =
            Value::Sequence(vec![Value::Number(1.into())]);
        let index = 1;

        // Extend the sequence to ensure the index is in bounds
        if index >= sequence.as_sequence().unwrap().len() {
            for _ in sequence.as_sequence().unwrap().len()..=index {
                sequence.as_sequence_mut().unwrap().push(Value::Null);
            }
        }

        index
            .index_or_insert(&mut sequence)
            .clone_from(&Value::Number(2.into()));
        assert_eq!(
            sequence,
            Value::Sequence(vec![
                Value::Number(1.into()),
                Value::Number(2.into())
            ])
        );
    }

    /// Test for `index_or_insert` method of `usize` implementation with a `Value::Mapping`.
    /// This test verifies that `index_or_insert` correctly indexes or inserts into a `Value::Mapping` with a numeric key.
    #[test]
    fn test_usize_index_or_insert_mapping() {
        let mapping = serde_yml::Mapping::new();
        let mut value = Value::Mapping(mapping);
        let index = 1;
        index
            .index_or_insert(&mut value)
            .clone_from(&Value::String("one".into()));
        let mut expected_mapping = serde_yml::Mapping::new();
        expected_mapping.insert(
            Value::Number(1.into()),
            Value::String("one".into()),
        );
        assert_eq!(value, Value::Mapping(expected_mapping));
    }

    /// Test for `index_or_insert` method of `usize` implementation with an out-of-bounds index in `Value::Sequence`.
    /// This test verifies that `index_or_insert` inserts a default value for an out-of-bounds index without panicking.
    #[test]
    fn test_usize_index_or_insert_sequence_out_of_bounds() {
        let mut sequence =
            Value::Sequence(vec![Value::Number(1.into())]);
        let index = 1;
        if index >= sequence.as_sequence().unwrap().len() {
            for _ in sequence.as_sequence().unwrap().len()..=index {
                sequence.as_sequence_mut().unwrap().push(Value::Null);
            }
        }
        index
            .index_or_insert(&mut sequence)
            .clone_from(&Value::Number(2.into()));
        assert_eq!(
            sequence,
            Value::Sequence(vec![
                Value::Number(1.into()),
                Value::Number(2.into())
            ])
        );
    }

    /// Test for `index_into` method of `usize` implementation with a `Value` other than `Sequence` or `Mapping`.
    /// This test verifies that `index_into` returns None for a non-indexable `Value`.
    #[test]
    fn test_usize_index_into_non_indexable() {
        let value = Value::String("hello".into());
        let index = 1;
        assert_eq!(index.index_into(&value), None);
    }

    /// Test for `index_into_mut` method of `usize` implementation with a `Value` other than `Sequence` or `Mapping`.
    /// This test verifies that `index_into_mut` returns None for a non-indexable `Value`.
    #[test]
    fn test_usize_index_into_mut_non_indexable() {
        let mut value = Value::String("hello".into());
        let index = 1;
        assert_eq!(index.index_into_mut(&mut value), None);
    }

    /// Test for `index_or_insert` method of `usize` implementation with a `Value` other than `Sequence` or `Mapping`.
    /// This test verifies that `index_or_insert` panics for a non-indexable `Value`.
    #[test]
    #[should_panic(expected = "cannot access index 1 of YAML string")]
    fn test_usize_index_or_insert_non_indexable() {
        let mut value = Value::String("hello".into());
        let index = 1;
        index.index_or_insert(&mut value);
    }

    /// Test for `index_or_insert` method of `usize` implementation with a `Value::Null`.
    /// This test verifies that `index_or_insert` panics for a `Value::Null`.
    #[test]
    #[should_panic(expected = "cannot access index 1 of YAML null")]
    fn test_usize_index_or_insert_null() {
        let mut value = Value::Null;
        let index = 1;
        index.index_or_insert(&mut value);
    }

    /// Test `index_into` with a `Value::Mapping`.
    #[test]
    fn test_value_index_into_mapping() {
        let mut mapping = serde_yml::Mapping::new();
        mapping.insert(
            Value::String("key".into()),
            Value::String("value".into()),
        );
        let value = Value::Mapping(mapping);
        let index = Value::String("key".into());
        assert_eq!(
            index.index_into(&value),
            Some(&Value::String("value".into()))
        );
    }

    /// Test `index_into` with a `Value` other than `Mapping`.
    #[test]
    fn test_value_index_into_non_mapping() {
        let value = Value::String("hello".into());
        let index = Value::String("key".into());
        assert_eq!(index.index_into(&value), None);
    }

    /// Test `index_into_mut` with a `Value::Mapping`.
    #[test]
    fn test_value_index_into_mut_mapping() {
        let mut mapping = serde_yml::Mapping::new();
        mapping.insert(
            Value::String("key".into()),
            Value::String("value".into()),
        );
        let mut value = Value::Mapping(mapping);
        let index = Value::String("key".into());
        assert_eq!(
            index.index_into_mut(&mut value),
            Some(&mut Value::String("value".into()))
        );
    }

    /// Test `index_into_mut` with a `Value` other than `Mapping`.
    #[test]
    fn test_value_index_into_mut_non_mapping() {
        let mut value = Value::String("hello".into());
        let index = Value::String("key".into());
        assert_eq!(index.index_into_mut(&mut value), None);
    }

    /// Test `index_or_insert` with a `Value::Mapping`.
    #[test]
    fn test_value_index_or_insert_mapping() {
        let mut mapping = serde_yml::Mapping::new();
        mapping.insert(
            Value::String("key".into()),
            Value::String("value".into()),
        );
        let mut value = Value::Mapping(mapping);
        let index = Value::String("new_key".into());
        index
            .index_or_insert(&mut value)
            .clone_from(&Value::String("new_value".into()));
        assert_eq!(
            value.get(Value::String("new_key".into())),
            Some(&Value::String("new_value".into()))
        );
    }

    /// Test `index_or_insert` with a `Value` other than `Mapping`.
    #[test]
    #[should_panic(
        expected = "cannot access key String(\"key\") in YAML string"
    )]
    fn test_value_index_or_insert_non_mapping() {
        let mut value = Value::String("hello".into());
        let index = Value::String("key".into());
        index.index_or_insert(&mut value);
    }

    // Tests for the `str` implementation of `Index`

    /// Test `index_into` with a `Value::Mapping`.
    #[test]
    fn test_str_index_into_mapping() {
        let mut mapping = serde_yml::Mapping::new();
        mapping.insert(
            Value::String("key".into()),
            Value::String("value".into()),
        );
        let value = Value::Mapping(mapping);
        let index = "key";
        assert_eq!(
            index.index_into(&value),
            Some(&Value::String("value".into()))
        );
    }

    /// Test `index_into` with a `Value` other than `Mapping`.
    #[test]
    fn test_str_index_into_non_mapping() {
        let value = Value::String("hello".into());
        let index = "key";
        assert_eq!(index.index_into(&value), None);
    }

    /// Test `index_into_mut` with a `Value::Mapping`.
    #[test]
    fn test_str_index_into_mut_mapping() {
        let mut mapping = serde_yml::Mapping::new();
        mapping.insert(
            Value::String("key".into()),
            Value::String("value".into()),
        );
        let mut value = Value::Mapping(mapping);
        let index = "key";
        assert_eq!(
            index.index_into_mut(&mut value),
            Some(&mut Value::String("value".into()))
        );
    }

    /// Test `index_into_mut` with a `Value` other than `Mapping`.
    #[test]
    fn test_str_index_into_mut_non_mapping() {
        let mut value = Value::String("hello".into());
        let index = "key";
        assert_eq!(index.index_into_mut(&mut value), None);
    }

    /// Test `index_or_insert` with a `Value::Mapping`.
    #[test]
    fn test_str_index_or_insert_mapping() {
        let mut mapping = serde_yml::Mapping::new();
        mapping.insert(
            Value::String("key".into()),
            Value::String("value".into()),
        );
        let mut value = Value::Mapping(mapping);
        let index = "new_key";
        index
            .index_or_insert(&mut value)
            .clone_from(&Value::String("new_value".into()));
        assert_eq!(
            value.get(Value::String("new_key".into())),
            Some(&Value::String("new_value".into()))
        );
    }

    /// Test `index_or_insert` with a `Value` other than `Mapping`.
    #[test]
    #[should_panic(
        expected = "cannot access key \"key\" in YAML string"
    )]
    fn test_str_index_or_insert_non_mapping() {
        let mut value = Value::String("hello".into());
        let index = "key";
        index.index_or_insert(&mut value);
    }

    // Tests for the `String` implementation of `Index`

    /// Test `index_into` with a `Value::Mapping`.
    #[test]
    fn test_string_index_into_mapping() {
        let mut mapping = serde_yml::Mapping::new();
        mapping.insert(
            Value::String("key".into()),
            Value::String("value".into()),
        );
        let value = Value::Mapping(mapping);
        let index = String::from("key");
        assert_eq!(
            index.index_into(&value),
            Some(&Value::String("value".into()))
        );
    }

    /// Test `index_into` with a `Value` other than `Mapping`.
    #[test]
    fn test_string_index_into_non_mapping() {
        let value = Value::String("hello".into());
        let index = String::from("key");
        assert_eq!(index.index_into(&value), None);
    }

    /// Test `index_into_mut` with a `Value::Mapping`.
    #[test]
    fn test_string_index_into_mut_mapping() {
        let mut mapping = serde_yml::Mapping::new();
        mapping.insert(
            Value::String("key".into()),
            Value::String("value".into()),
        );
        let mut value = Value::Mapping(mapping);
        let index = String::from("key");
        assert_eq!(
            index.index_into_mut(&mut value),
            Some(&mut Value::String("value".into()))
        );
    }

    /// Test `index_into_mut` with a `Value` other than `Mapping`.
    #[test]
    fn test_string_index_into_mut_non_mapping() {
        let mut value = Value::String("hello".into());
        let index = String::from("key");
        assert_eq!(index.index_into_mut(&mut value), None);
    }

    /// Test `index_or_insert` with a `Value::Mapping`.
    #[test]
    fn test_string_index_or_insert_mapping() {
        let mut mapping = serde_yml::Mapping::new();
        mapping.insert(
            Value::String("key".into()),
            Value::String("value".into()),
        );
        let mut value = Value::Mapping(mapping);
        let index = String::from("new_key");
        index
            .index_or_insert(&mut value)
            .clone_from(&Value::String("new_value".into()));
        assert_eq!(
            value.get(Value::String("new_key".into())),
            Some(&Value::String("new_value".into()))
        );
    }

    /// Test `index_or_insert` with a `Value` other than `Mapping`.
    #[test]
    #[should_panic(
        expected = "cannot access key \"key\" in YAML string"
    )]
    fn test_string_index_or_insert_non_mapping() {
        let mut value = Value::String("hello".into());
        let index = String::from("key");
        index.index_or_insert(&mut value);
    }

    // Tests for the reference implementation of `Index`

    /// Test `index_into` with a reference to `usize`.
    #[test]
    fn test_ref_usize_index_into() {
        let sequence = Value::Sequence(vec![
            Value::Number(1.into()),
            Value::Number(2.into()),
        ]);
        let index = &1;
        assert_eq!(
            index.index_into(&sequence),
            Some(&Value::Number(2.into()))
        );
    }

    /// Test `index_into` with a reference to `Value`.
    #[test]
    fn test_ref_value_index_into() {
        let mut mapping = serde_yml::Mapping::new();
        mapping.insert(
            Value::String("key".into()),
            Value::String("value".into()),
        );
        let value = Value::Mapping(mapping);
        let index = &Value::String("key".into());
        assert_eq!(
            index.index_into(&value),
            Some(&Value::String("value".into()))
        );
    }

    /// Test `index_into` with a reference to `str`.
    #[test]
    fn test_ref_str_index_into() {
        let mut mapping = serde_yml::Mapping::new();
        mapping.insert(
            Value::String("key".into()),
            Value::String("value".into()),
        );
        let value = Value::Mapping(mapping);
        let index = &"key";
        assert_eq!(
            index.index_into(&value),
            Some(&Value::String("value".into()))
        );
    }

    /// Test `index_into` with a reference to `String`.
    #[test]
    fn test_ref_string_index_into() {
        let mut mapping = serde_yml::Mapping::new();
        mapping.insert(
            Value::String("key".into()),
            Value::String("value".into()),
        );
        let value = Value::Mapping(mapping);
        let index = &String::from("key");
        assert_eq!(
            index.index_into(&value),
            Some(&Value::String("value".into()))
        );
    }

    /// Test `index_into_mut` with a reference to `usize`.
    #[test]
    fn test_ref_usize_index_into_mut() {
        let mut sequence = Value::Sequence(vec![
            Value::Number(1.into()),
            Value::Number(2.into()),
        ]);
        let index = &1;
        assert_eq!(
            index.index_into_mut(&mut sequence),
            Some(&mut Value::Number(2.into()))
        );
    }

    /// Test `index_into_mut` with a reference to `Value`.
    #[test]
    fn test_ref_value_index_into_mut() {
        let mut mapping = serde_yml::Mapping::new();
        mapping.insert(
            Value::String("key".into()),
            Value::String("value".into()),
        );
        let mut value = Value::Mapping(mapping);
        let index = &Value::String("key".into());
        assert_eq!(
            index.index_into_mut(&mut value),
            Some(&mut Value::String("value".into()))
        );
    }

    /// Test `index_into_mut` with a reference to `str`.
    #[test]
    fn test_ref_str_index_into_mut() {
        let mut mapping = serde_yml::Mapping::new();
        mapping.insert(
            Value::String("key".into()),
            Value::String("value".into()),
        );
        let mut value = Value::Mapping(mapping);
        let index = &"key";
        assert_eq!(
            index.index_into_mut(&mut value),
            Some(&mut Value::String("value".into()))
        );
    }

    /// Test `index_into_mut` with a reference to `String`.
    #[test]
    fn test_ref_string_index_into_mut() {
        let mut mapping = serde_yml::Mapping::new();
        mapping.insert(
            Value::String("key".into()),
            Value::String("value".into()),
        );
        let mut value = Value::Mapping(mapping);
        let index = &String::from("key");
        assert_eq!(
            index.index_into_mut(&mut value),
            Some(&mut Value::String("value".into()))
        );
    }

    /// Test `index_or_insert` with a reference to `usize`.
    #[test]
    fn test_ref_usize_index_or_insert() {
        let mut sequence =
            Value::Sequence(vec![Value::Number(1.into())]);
        let index = &1;

        // Extend the sequence to ensure the index is in bounds
        if *index >= sequence.as_sequence().unwrap().len() {
            for _ in sequence.as_sequence().unwrap().len()..=*index {
                sequence.as_sequence_mut().unwrap().push(Value::Null);
            }
        }

        index
            .index_or_insert(&mut sequence)
            .clone_from(&Value::Number(2.into()));
        assert_eq!(
            sequence,
            Value::Sequence(vec![
                Value::Number(1.into()),
                Value::Number(2.into())
            ])
        );
    }

    /// Test `index_or_insert` with a reference to `Value`.
    #[test]
    fn test_ref_value_index_or_insert() {
        let mut mapping = serde_yml::Mapping::new();
        mapping.insert(
            Value::String("key".into()),
            Value::String("value".into()),
        );
        let mut value = Value::Mapping(mapping);
        let index = &Value::String("new_key".into());
        index
            .index_or_insert(&mut value)
            .clone_from(&Value::String("new_value".into()));
        assert_eq!(
            value.get(Value::String("new_key".into())),
            Some(&Value::String("new_value".into()))
        );
    }

    /// Test `index_or_insert` with a reference to `str`.
    #[test]
    fn test_ref_str_index_or_insert() {
        let mut mapping = serde_yml::Mapping::new();
        mapping.insert(
            Value::String("key".into()),
            Value::String("value".into()),
        );
        let mut value = Value::Mapping(mapping);
        let index = &"new_key";
        index
            .index_or_insert(&mut value)
            .clone_from(&Value::String("new_value".into()));
        assert_eq!(
            value.get(Value::String("new_key".into())),
            Some(&Value::String("new_value".into()))
        );
    }

    // Tests for the `ops::Index` implementation

    /// Test indexing with an invalid index.
    #[test]
    fn test_index_invalid_index() {
        let value = Value::Sequence(vec![Value::Number(1.into())]);
        assert_eq!(value[2], Value::Null);
    }

    /// Test indexing with an invalid key.
    #[test]
    fn test_index_invalid_key() {
        let mut mapping = serde_yml::Mapping::new();
        mapping.insert(
            Value::String("key".into()),
            Value::String("value".into()),
        );
        let value = Value::Mapping(mapping);
        assert_eq!(value["invalid"], Value::Null);
    }

    // Tests for the `ops::IndexMut` implementation

    /// Test mutating with an invalid index.
    #[test]
    #[should_panic(
        expected = "cannot access index 2 of YAML sequence of length 1"
    )]
    fn test_index_mut_invalid_index() {
        let mut value = Value::Sequence(vec![Value::Number(1.into())]);
        value[2] = Value::Number(2.into());
    }

    /// Test mutating with an invalid key.
    #[test]
    fn test_index_mut_invalid_key() {
        let mut mapping = serde_yml::Mapping::new();
        mapping.insert(
            Value::String("key".into()),
            Value::String("value".into()),
        );
        let mut value = Value::Mapping(mapping);
        value["invalid"] = Value::String("new_value".into());

        assert_eq!(
            value,
            Value::Mapping({
                let mut mapping = serde_yml::Mapping::new();
                mapping.insert(
                    Value::String("key".into()),
                    Value::String("value".into()),
                );
                mapping.insert(
                    Value::String("invalid".into()),
                    Value::String("new_value".into()),
                );
                mapping
            })
        );
    }
}
