#[cfg(test)]
mod tests {
    use serde_yml::mapping::*;
    use serde_yml::value::Value;

    /// Tests the creation of a new empty `Mapping`.
    #[test]
    fn test_mapping_new() {
        let map = Mapping::new();
        assert!(map.map.is_empty());
    }

    /// Tests creating a `Mapping` with a specified capacity.
    #[test]
    fn test_mapping_with_capacity() {
        let capacity = 10;
        let map = Mapping::with_capacity(capacity);
        assert!(map.map.is_empty());
        assert!(map.map.capacity() >= capacity);
    }

    /// Tests reserving additional capacity in the `Mapping`.
    #[test]
    fn test_mapping_reserve() {
        let mut map = Mapping::new();
        let additional = 10;
        map.reserve(additional);
        assert!(map.map.capacity() >= additional);
    }

    /// Tests shrinking the capacity of the `Mapping` to fit its content.
    #[test]
    fn test_mapping_shrink_to_fit() {
        let mut map = Mapping::with_capacity(100);
        map.shrink_to_fit();
        assert!(map.map.capacity() <= 100);
    }

    /// Tests inserting a key-value pair into the `Mapping`.
    #[test]
    fn test_mapping_insert() {
        let mut map = Mapping::new();
        let key = Value::String("key".to_string());
        let value = Value::String("value".to_string());
        assert!(map.insert(key.clone(), value.clone()).is_none());
        assert_eq!(map.get(&key), Some(&value));
    }

    /// Tests retrieving a mutable reference to a value in the `Mapping`.
    #[test]
    fn test_mapping_get_mut() {
        let mut map = Mapping::new();
        let key = Value::String("key".to_string());
        let value = Value::String("value".to_string());
        map.insert(key.clone(), value);
        assert!(map.get_mut(&key).is_some());
    }

    /// Tests getting the capacity of the `Mapping`.
    #[test]
    fn test_mapping_capacity() {
        let map = Mapping::with_capacity(10);
        assert_eq!(map.capacity(), 10);
    }

    /// Tests getting the length of the `Mapping`.
    #[test]
    fn test_mapping_len() {
        let mut map = Mapping::new();
        assert_eq!(map.len(), 0);
        map.insert(Value::String("key".to_string()), Value::Null);
        assert_eq!(map.len(), 1);
    }

    /// Tests checking if the `Mapping` is empty.
    #[test]
    fn test_mapping_is_empty() {
        let map = Mapping::new();
        assert!(map.is_empty());
    }

    /// Tests clearing the `Mapping`.
    #[test]
    fn test_mapping_clear() {
        let mut map = Mapping::new();
        map.insert(Value::String("key".to_string()), Value::Null);
        map.clear();
        assert!(map.is_empty());
    }

    /// Tests iterating over mutable references to the key-value pairs in the `Mapping`.
    #[test]
    fn test_mapping_iter_mut() {
        let mut map = Mapping::new();
        map.insert(
            Value::String("key".to_string()),
            Value::String("value".to_string()),
        );
        let mut iter = map.iter_mut();
        let (key, value) = iter.next().unwrap();
        assert_eq!(key, &Value::String("key".to_string()));
        assert_eq!(value, &mut Value::String("value".to_string()));
    }

    /// Tests iterating over the keys in the `Mapping`.
    #[test]
    fn test_mapping_keys() {
        let mut map = Mapping::new();
        map.insert(Value::String("key".to_string()), Value::Null);
        let mut keys = map.keys();
        assert_eq!(
            keys.next(),
            Some(&Value::String("key".to_string()))
        );
    }

    /// Tests consuming the `Mapping` and iterating over its keys.
    #[test]
    fn test_mapping_into_keys() {
        let mut map = Mapping::new();
        map.insert(Value::String("key".to_string()), Value::Null);
        let mut keys = map.into_keys();
        assert_eq!(keys.next(), Some(Value::String("key".to_string())));
    }

    /// Tests consuming the `Mapping` and iterating over its values.
    #[test]
    fn test_mapping_into_values() {
        let mut map = Mapping::new();
        map.insert(Value::String("key".to_string()), Value::Null);
        let mut values = map.into_values();
        assert_eq!(values.next(), Some(Value::Null));
    }

    /// Tests removing an entry from the `Mapping` and returning the key-value pair.
    #[test]
    fn test_swap_remove_entry_from() {
        let mut map = Mapping::new();
        let key = Value::String("key".to_string());
        let value = Value::String("value".to_string());
        map.insert(key.clone(), value.clone());
        let entry = key.swap_remove_entry_from(&mut map);
        assert_eq!(entry, Some((key, value)));
    }

    /// Tests removing a value from the `Mapping` by shifting following elements.
    #[test]
    fn test_shift_remove_from() {
        let mut map = Mapping::new();
        let key = Value::String("key".to_string());
        let value = Value::String("value".to_string());
        map.insert(key.clone(), value.clone());
        let removed_value = key.shift_remove_from(&mut map);
        assert_eq!(removed_value, Some(value));
    }

    /// Tests removing an entry from the `Mapping` by shifting following elements.
    #[test]
    fn test_shift_remove_entry_from() {
        let mut map = Mapping::new();
        let key = Value::String("key".to_string());
        let value = Value::String("value".to_string());
        map.insert(key.clone(), value.clone());
        let entry = key.shift_remove_entry_from(&mut map);
        assert_eq!(entry, Some((key, value)));
    }

    /// Tests checking if a string key exists in the `Mapping`.
    #[test]
    fn test_str_is_key_into() {
        let mut map = Mapping::new();
        let key = "key";
        map.insert(Value::String(key.to_string()), Value::Null);
        assert!(key.is_key_into(&map));
    }

    /// Tests retrieving a mutable reference to a value in the `Mapping` using a string key.
    #[test]
    fn test_str_index_into_mut() {
        let mut map = Mapping::new();
        let key = "key";
        let value = Value::String("value".to_string());
        map.insert(Value::String(key.to_string()), value);
        assert!(key.index_into_mut(&mut map).is_some());
    }

    /// Tests removing an entry from the `Mapping` using a string key and returning the key-value pair.
    #[test]
    fn test_str_swap_remove_entry_from() {
        let mut map = Mapping::new();
        let key = "key";
        let value = Value::String("value".to_string());
        map.insert(Value::String(key.to_string()), value.clone());
        let entry = key.swap_remove_entry_from(&mut map);
        assert_eq!(
            entry,
            Some((Value::String(key.to_string()), value))
        );
    }

    /// Tests removing a value from the `Mapping` using a string key by shifting following elements.
    #[test]
    fn test_str_shift_remove_from() {
        let mut map = Mapping::new();
        let key = "key";
        let value = Value::String("value".to_string());
        map.insert(Value::String(key.to_string()), value.clone());
        let removed_value = key.shift_remove_from(&mut map);
        assert_eq!(removed_value, Some(value));
    }

    /// Tests removing an entry from the `Mapping` using a string key by shifting following elements.
    #[test]
    fn test_str_shift_remove_entry_from() {
        let mut map = Mapping::new();
        let key = "key";
        let value = Value::String("value".to_string());
        map.insert(Value::String(key.to_string()), value.clone());
        let entry = key.shift_remove_entry_from(&mut map);
        assert_eq!(
            entry,
            Some((Value::String(key.to_string()), value))
        );
    }

    /// Tests checking if a `String` key exists in the `Mapping`.
    #[test]
    fn test_string_is_key_into() {
        let mut map = Mapping::new();
        let key = "key".to_string();
        map.insert(Value::String(key.clone()), Value::Null);
        assert!(key.is_key_into(&map));
    }

    /// Tests retrieving a reference to a value in the `Mapping` using a `String` key.
    #[test]
    fn test_string_index_into() {
        let mut map = Mapping::new();
        let key = "key".to_string();
        let value = Value::String("value".to_string());
        map.insert(Value::String(key.clone()), value.clone());
        assert_eq!(key.index_into(&map), Some(&value));
    }

    /// Tests retrieving a mutable reference to a value in the `Mapping` using a `String` key.
    #[test]
    fn test_string_index_into_mut() {
        let mut map = Mapping::new();
        let key = "key".to_string();
        let value = Value::String("value".to_string());
        map.insert(Value::String(key.clone()), value);
        assert!(key.index_into_mut(&mut map).is_some());
    }

    /// Tests removing a value from the `Mapping` using a `String` key.
    #[test]
    fn test_string_swap_remove_from() {
        let mut map = Mapping::new();
        let key = "key".to_string();
        let value = Value::String("value".to_string());
        map.insert(Value::String(key.clone()), value.clone());
        let removed_value = key.swap_remove_from(&mut map);
        assert_eq!(removed_value, Some(value));
    }

    /// Tests removing an entry from the `Mapping` using a `String` key and returning the key-value pair.
    #[test]
    fn test_string_swap_remove_entry_from() {
        let mut map = Mapping::new();
        let key = "key".to_string();
        let value = Value::String("value".to_string());
        map.insert(Value::String(key.clone()), value.clone());
        let entry = key.swap_remove_entry_from(&mut map);
        assert_eq!(entry, Some((Value::String(key), value)));
    }

    /// Tests removing a value from the `Mapping` using a `String` key by shifting following elements.
    #[test]
    fn test_string_shift_remove_from() {
        let mut map = Mapping::new();
        let key = "key".to_string();
        let value = Value::String("value".to_string());
        map.insert(Value::String(key.clone()), value.clone());
        let removed_value = key.shift_remove_from(&mut map);
        assert_eq!(removed_value, Some(value));
    }

    /// Tests removing an entry from the `Mapping` using a `String` key by shifting following elements.
    #[test]
    fn test_string_shift_remove_entry_from() {
        let mut map = Mapping::new();
        let key = "key".to_string();
        let value = Value::String("value".to_string());
        map.insert(Value::String(key.clone()), value.clone());
        let entry = key.shift_remove_entry_from(&mut map);
        assert_eq!(entry, Some((Value::String(key), value)));
    }

    /// Tests the `Entry` API for inserting a new key-value pair.
    #[test]
    fn test_mapping_entry_insert() {
        let mut map = Mapping::new();
        let key = Value::String("key".to_string());
        let value = Value::String("value".to_string());
        map.entry(key.clone()).or_insert(value.clone());
        assert_eq!(map.get(&key), Some(&value));
    }

    /// Tests the `Entry` API for updating an existing key-value pair.
    #[test]
    fn test_mapping_entry_update() {
        let mut map = Mapping::new();
        let key = Value::String("key".to_string());
        let value1 = Value::String("value1".to_string());
        let value2 = Value::String("value2".to_string());
        map.insert(key.clone(), value1.clone());
        map.entry(key.clone()).and_modify(|v| *v = value2.clone());
        assert_eq!(map.get(&key), Some(&value2));
    }

    /// Tests the `retain` method for removing key-value pairs based on a predicate.
    #[test]
    fn test_mapping_retain() {
        let mut map = Mapping::new();
        map.insert(
            Value::String("key1".to_string()),
            Value::Number(1.into()),
        );
        map.insert(
            Value::String("key2".to_string()),
            Value::Number(2.into()),
        );
        map.insert(
            Value::String("key3".to_string()),
            Value::Number(3.into()),
        );
        map.retain(|_, v| match v {
            Value::Number(n) => n.as_u64().unwrap() % 2 == 0,
            _ => false,
        });
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("key2"), Some(&Value::Number(2.into())));
    }

    /// Tests the `Ord` implementation for `Mapping`.
    #[test]
    fn test_mapping_ord() {
        let mut map1 = Mapping::new();
        map1.insert(
            Value::String("key1".to_string()),
            Value::Number(1.into()),
        );
        map1.insert(
            Value::String("key2".to_string()),
            Value::Number(2.into()),
        );
        let mut map2 = Mapping::new();
        map2.insert(
            Value::String("key1".to_string()),
            Value::Number(1.into()),
        );
        map2.insert(
            Value::String("key2".to_string()),
            Value::Number(3.into()),
        );
        assert!(map1 < map2);
    }

    /// Tests the `PartialOrd` implementation for `Mapping`.
    #[test]
    fn test_mapping_partial_ord() {
        let mut map1 = Mapping::new();
        map1.insert(
            Value::String("key1".to_string()),
            Value::Number(1.into()),
        );
        let mut map2 = Mapping::new();
        map2.insert(
            Value::String("key1".to_string()),
            Value::Number(1.into()),
        );
        map2.insert(
            Value::String("key2".to_string()),
            Value::Number(2.into()),
        );
        assert!(map1 <= map2);
    }

    /// Tests the `Hash` implementation for `Mapping`.
    #[test]
    fn test_mapping_hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut map1 = Mapping::new();
        map1.insert(
            Value::String("key1".to_string()),
            Value::Number(1.into()),
        );
        map1.insert(
            Value::String("key2".to_string()),
            Value::Number(2.into()),
        );
        let mut map2 = Mapping::new();
        map2.insert(
            Value::String("key2".to_string()),
            Value::Number(2.into()),
        );
        map2.insert(
            Value::String("key1".to_string()),
            Value::Number(1.into()),
        );

        let mut hasher1 = DefaultHasher::new();
        map1.hash(&mut hasher1);
        let hash1 = hasher1.finish();

        let mut hasher2 = DefaultHasher::new();
        map2.hash(&mut hasher2);
        let hash2 = hasher2.finish();

        assert_eq!(hash1, hash2);
    }

    /// Tests the `Index` trait implementation for `Mapping`.
    #[test]
    fn test_mapping_index() {
        let mut map = Mapping::new();
        let key = Value::String("key".to_string());
        let value = Value::String("value".to_string());
        map.insert(key.clone(), value.clone());
        assert_eq!(map[&key], value);
    }

    /// Tests the `IndexMut` trait implementation for `Mapping`.
    #[test]
    fn test_mapping_index_mut() {
        let mut map = Mapping::new();
        let key = Value::String("key".to_string());
        let value1 = Value::String("value1".to_string());
        let value2 = Value::String("value2".to_string());
        map.insert(key.clone(), value1.clone());
        map[&key] = value2.clone();
        assert_eq!(map[&key], value2);
    }

    /// Tests the `Extend` trait implementation for `Mapping`.
    #[test]
    fn test_mapping_extend() {
        let mut map = Mapping::new();
        let key1 = Value::String("key1".to_string());
        let value1 = Value::String("value1".to_string());
        let key2 = Value::String("key2".to_string());
        let value2 = Value::String("value2".to_string());
        map.extend(vec![
            (key1.clone(), value1.clone()),
            (key2.clone(), value2.clone()),
        ]);
        assert_eq!(map.len(), 2);
        assert_eq!(map.get(&key1), Some(&value1));
        assert_eq!(map.get(&key2), Some(&value2));
    }

    /// Tests the `FromIterator` trait implementation for `Mapping`.
    #[test]
    fn test_mapping_from_iterator() {
        let key1 = Value::String("key1".to_string());
        let value1 = Value::String("value1".to_string());
        let key2 = Value::String("key2".to_string());
        let value2 = Value::String("value2".to_string());
        let map: Mapping = vec![
            (key1.clone(), value1.clone()),
            (key2.clone(), value2.clone()),
        ]
        .into_iter()
        .collect();
        assert_eq!(map.len(), 2);
        assert_eq!(map.get(&key1), Some(&value1));
        assert_eq!(map.get(&key2), Some(&value2));
    }

    /// Tests the `Debug` trait implementation for `DuplicateKeyError`.
    #[test]
    fn test_duplicate_key_error_debug() {
        let mut map = Mapping::new();
        let key = Value::String("key".to_string());
        let value = Value::String("value".to_string());
        map.insert(key.clone(), value.clone());
        match map.entry(key.clone()) {
            Entry::Occupied(entry) => {
                let error = DuplicateKeyError { entry };
                let debug_str = format!("{:?}", error);
                assert_eq!(
                    debug_str,
                    "DuplicateKeyError { entry: OccupiedEntry { occupied: OccupiedEntry { key: String(\"key\"), value: String(\"value\") } } }"
                );
            }
            Entry::Vacant(_) => panic!("Expected occupied entry"),
        }
    }

    /// Tests the `Display` trait implementation for `DuplicateKeyError`.
    #[test]
    fn test_duplicate_key_error_display() {
        let mut map = Mapping::new();
        let key = Value::String("key".to_string());
        let value = Value::String("value".to_string());
        map.insert(key.clone(), value.clone());
        match map.entry(key.clone()) {
            Entry::Occupied(entry) => {
                let error = DuplicateKeyError { entry };
                let display_str = format!("{}", error);
                assert_eq!(
                    display_str,
                    "duplicate entry with key \"key\""
                );
            }
            Entry::Vacant(_) => panic!("Expected occupied entry"),
        }
    }
}
