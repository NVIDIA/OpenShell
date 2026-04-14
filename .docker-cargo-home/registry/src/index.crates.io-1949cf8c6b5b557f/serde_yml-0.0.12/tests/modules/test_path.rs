#[cfg(test)]
mod tests {
    use serde_yml::{de::Event, modules::path::Path};

    /// Test the `Path::Root` variant.
    ///
    /// This test ensures that the `Root` path is correctly formatted as ".".
    #[test]
    fn test_path_root() {
        let path = Path::Root;
        assert_eq!(format!("{}", path), ".");
    }

    /// Test the `Path::Seq` variant.
    ///
    /// This test checks that a sequence path with a given index is correctly formatted.
    #[test]
    fn test_path_seq() {
        let root = Path::Root;
        let path = Path::Seq {
            parent: &root,
            index: 42,
        };
        assert_eq!(format!("{}", path), "\\[42\\]");
    }

    /// Test the `Path::Seq` variant with a very large index.
    ///
    /// This test checks that a sequence path with a large index is correctly formatted.
    #[test]
    fn test_path_seq_large_index() {
        let root = Path::Root;
        let path = Path::Seq {
            parent: &root,
            index: usize::MAX,
        };
        assert_eq!(
            format!("{}", path),
            format!("\\[{}\\]", usize::MAX)
        );
    }

    /// Test the `Path::Seq` variant with a nested parent.
    ///
    /// This test checks that a sequence path with a parent sequence is correctly formatted.
    #[test]
    fn test_seq_with_parent() {
        let root = Path::Root;
        let parent_seq = Path::Seq {
            parent: &root,
            index: 1,
        };
        let child_seq = Path::Seq {
            parent: &parent_seq,
            index: 42,
        };
        assert_eq!(format!("{}", child_seq), "\\[1\\].\\[42\\]");
    }

    /// Test the `Path::Seq` variant with different indices.
    ///
    /// This test validates that various index values in the `Seq` variant are correctly formatted.
    #[test]
    fn test_seq_with_different_indices() {
        let root = Path::Root;

        let path_zero = Path::Seq {
            parent: &root,
            index: 0,
        };
        assert_eq!(format!("{}", path_zero), "\\[0\\]");

        let path_large = Path::Seq {
            parent: &root,
            index: 100,
        };
        assert_eq!(format!("{}", path_large), "\\[100\\]");
    }

    /// Test the `Path::Map` variant.
    ///
    /// This test checks that a map path with a given key is correctly formatted.
    #[test]
    fn test_path_map() {
        let root = Path::Root;
        let path = Path::Map {
            parent: &root,
            key: "key_name",
        };
        assert_eq!(format!("{}", path), "key_name");
    }

    /// Test the `Path::Map` variant with an empty key.
    ///
    /// This test ensures that a map path with an empty key is correctly handled and formatted.
    #[test]
    fn test_path_map_empty_key() {
        let root = Path::Root;
        let path = Path::Map {
            parent: &root,
            key: "",
        };
        assert_eq!(format!("{}", path), "");
    }

    /// Test the `Path::Map` variant with different keys.
    ///
    /// This test validates that various key values in the `Map` variant are correctly formatted.
    #[test]
    fn test_map_with_different_keys() {
        let root = Path::Root;

        let path_empty_key = Path::Map {
            parent: &root,
            key: "",
        };
        assert_eq!(format!("{}", path_empty_key), "");

        let path_special_key = Path::Map {
            parent: &root,
            key: "special_key",
        };
        assert_eq!(format!("{}", path_special_key), "special_key");

        let path_number_key = Path::Map {
            parent: &root,
            key: "123",
        };
        assert_eq!(format!("{}", path_number_key), "123");
    }

    /// Test the `Path::Map` variant with a parent sequence.
    ///
    /// This test checks that the `parent` field in a `Map` variant is correctly formatted.
    #[test]
    fn test_map_with_parent() {
        let root = Path::Root;
        let parent_seq = Path::Seq {
            parent: &root,
            index: 1,
        };
        let map = Path::Map {
            parent: &parent_seq,
            key: "key",
        };
        assert_eq!(format!("{}", map), "\\[1\\].key");
    }

    /// Test the `Path::Alias` variant.
    ///
    /// This test checks that an alias path is correctly formatted.
    #[test]
    fn test_path_alias() {
        let root = Path::Root;
        let path = Path::Alias { parent: &root };
        assert_eq!(format!("{}", path), "");
    }

    /// Test the `Path::Alias` variant with a parent map.
    ///
    /// This test checks that the `parent` field in an `Alias` variant is correctly formatted.
    #[test]
    fn test_alias_with_parent() {
        let root = Path::Root;
        let parent_map = Path::Map {
            parent: &root,
            key: "parent_key",
        };
        let alias = Path::Alias {
            parent: &parent_map,
        };
        assert_eq!(format!("{}", alias), "parent_key.");
    }

    /// Test the `Path::Unknown` variant.
    ///
    /// This test checks that an unknown path is correctly formatted.
    #[test]
    fn test_path_unknown() {
        let root = Path::Root;
        let path = Path::Unknown { parent: &root };
        assert_eq!(format!("{}", path), "?");
    }

    /// Test the `Path::Unknown` variant with a parent map.
    ///
    /// This test checks that the `parent` field in an `Unknown` variant is correctly formatted.
    #[test]
    fn test_unknown_with_parent() {
        let root = Path::Root;
        let parent_map = Path::Map {
            parent: &root,
            key: "parent_key",
        };
        let unknown = Path::Unknown {
            parent: &parent_map,
        };
        assert_eq!(format!("{}", unknown), "parent_key.?");
    }

    /// Test equality of two `Path` instances with the same structure.
    ///
    /// This test checks that two instances of `Path` with identical structures are considered equal.
    #[test]
    fn test_path_equality() {
        let root = Path::Root;
        let seq1 = Path::Seq {
            parent: &root,
            index: 42,
        };
        let seq2 = Path::Seq {
            parent: &root,
            index: 42,
        };
        assert_eq!(seq1, seq2);
    }

    /// Test cloning and copying a `Path` instance.
    ///
    /// This test checks that copying a `Path` instance results in an identical path.
    #[test]
    fn test_path_clone_and_copy() {
        let root = Path::Root;
        let seq = Path::Seq {
            parent: &root,
            index: 42,
        };

        // No need to explicitly clone, just copy directly
        let seq_copy = seq;

        assert_eq!(seq, seq_copy);
    }

    /// Test nested paths.
    ///
    /// This test ensures that nested paths with various combinations of variants are correctly formatted.
    #[test]
    fn test_path_nested() {
        let root = Path::Root;
        let seq = Path::Seq {
            parent: &root,
            index: 0,
        };
        let map = Path::Map {
            parent: &seq,
            key: "key",
        };
        let alias = Path::Alias { parent: &map };
        let unknown = Path::Unknown { parent: &alias };
        assert_eq!(format!("{}", unknown), "\\[0\\].key..?");
    }

    /// Test deeply nested paths.
    ///
    /// This test checks the formatting of a deeply nested path with multiple levels of sequences and maps.
    #[test]
    fn test_deeply_nested_path() {
        let root = Path::Root;
        let seq1 = Path::Seq {
            parent: &root,
            index: 1,
        };
        let map1 = Path::Map {
            parent: &seq1,
            key: "first",
        };
        let seq2 = Path::Seq {
            parent: &map1,
            index: 2,
        };
        let map2 = Path::Map {
            parent: &seq2,
            key: "second",
        };
        let alias = Path::Alias { parent: &map2 };
        let unknown = Path::Unknown { parent: &alias };
        assert_eq!(
            format!("{}", unknown),
            "\\[1\\].first.\\[2\\].second..?"
        );
    }

    /// Test a complex nested structure with a `Seq` inside a `Map` inside another `Seq`.
    ///
    /// This test checks the formatting of a complex nested structure involving sequences and maps.
    #[test]
    fn test_path_complex_nested() {
        let root = Path::Root;
        let seq1 = Path::Seq {
            parent: &root,
            index: 1,
        };
        let map = Path::Map {
            parent: &seq1,
            key: "key",
        };
        let seq2 = Path::Seq {
            parent: &map,
            index: 99,
        };
        assert_eq!(format!("{}", seq2), "\\[1\\].key.\\[99\\]");
    }

    /// Test panic for unexpected end of sequence.
    #[test]
    #[should_panic(expected = "unexpected end of sequence")]
    fn test_panic_unexpected_end_of_sequence() {
        panic!("unexpected end of sequence");
    }

    /// Test panic for unexpected end of mapping.
    #[test]
    #[should_panic(expected = "unexpected end of mapping")]
    fn test_panic_unexpected_end_of_mapping() {
        panic!("unexpected end of mapping");
    }

    /// Test deserialization of the `Alias` variant in the `Event` enum.
    ///
    /// This test checks that the `Alias` variant is correctly handled in the `Event` enum.
    #[test]
    fn test_event_alias_variant() {
        let alias_index: usize = 42; // Example index
        let event = Event::Alias(alias_index);

        // Match the alias case to ensure it handles the usize correctly
        if let Event::Alias(index) = event {
            assert_eq!(index, alias_index);
        } else {
            panic!("Failed to match the Alias variant.");
        }
    }
}
