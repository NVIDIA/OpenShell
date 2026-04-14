#[cfg(test)]
mod tests {
    use serde_yml::{
        de::{Event, Progress},
        loader::Loader,
        modules::error::ErrorImpl,
    };
    use std::io::Cursor;
    use std::str;
    use std::sync::Arc;

    #[test]
    // Tests for creating a new Loader instance and basic functionality
    fn test_loader_new() {
        // Arrange
        let input = "key: value";
        let progress = Progress::Str(input);

        // Act
        let loader = Loader::new(progress).unwrap();

        // Assert
        assert!(loader.parser.is_some());
        assert_eq!(loader.parsed_document_count, 0);
    }

    #[test]
    // Tests for handling multiple documents in the input
    fn test_loader_multiple_documents() {
        // Arrange
        let input = "---\nkey1: value1\n...\n---\nkey2: value2\n...";
        let progress = Progress::Str(input);
        let mut loader = Loader::new(progress).unwrap();

        // Act & Assert
        // Document 1
        let document1 = loader.next_document().unwrap();
        assert_eq!(document1.events.len(), 4);
        assert!(document1.error.is_none());
        assert_eq!(document1.anchor_event_map.len(), 0);

        // Document 2
        let document2 = loader.next_document().unwrap();
        assert_eq!(document2.events.len(), 4);
        assert!(document2.error.is_none());
        assert_eq!(document2.anchor_event_map.len(), 0);

        // No more documents
        assert!(loader.next_document().is_none());
    }

    #[test]
    // Tests for handling unknown anchor errors
    fn test_loader_unknown_anchor() {
        // Arrange
        let input = "*unknown";
        let progress = Progress::Str(input);
        let mut loader = Loader::new(progress).unwrap();

        // Act
        let document = loader.next_document().unwrap();

        // Assert
        assert_eq!(document.events.len(), 0);
        assert!(document.error.is_some());
        assert_eq!(document.anchor_event_map.len(), 0);

        let error = document.error.unwrap();
        assert!(matches!(*error, ErrorImpl::UnknownAnchor(_)));
    }

    #[test]
    // Tests for handling anchors and aliases
    fn test_loader_anchor_and_alias() {
        // Arrange
        let input = "---\nkey: &anchor value\nalias: *anchor\n...";
        let progress = Progress::Str(input);
        let mut loader = Loader::new(progress).unwrap();

        // Act
        let document = loader.next_document().unwrap();

        // Assert
        assert_eq!(document.events.len(), 6);
        assert!(document.error.is_none());
        assert_eq!(document.anchor_event_map.len(), 1);

        let (event, _) = &document.events[1];
        if let Event::Scalar(scalar) = event {
            assert_eq!(str::from_utf8(&scalar.value).unwrap(), "key");
            assert_eq!(scalar.anchor, None);
        } else {
            panic!("Expected Event::Scalar");
        }

        let (event, _) = &document.events[3];
        if let Event::Scalar(scalar) = event {
            assert_eq!(str::from_utf8(&scalar.value).unwrap(), "alias");
            assert_eq!(scalar.anchor, None);
        } else {
            panic!("Expected Event::Scalar");
        }

        let (event, _) = &document.events[4];
        assert!(matches!(event, Event::Alias(0)));
    }

    #[test]
    // Tests for handling empty documents
    fn test_loader_empty_document() {
        let input = "---\n...";
        let progress = Progress::Str(input);
        let mut loader = Loader::new(progress).unwrap();

        let document = loader.next_document().unwrap();
        assert_eq!(document.events.len(), 1);
        assert!(document.error.is_none());
        assert_eq!(document.anchor_event_map.len(), 0);

        let (event, _) = &document.events[0];
        assert!(matches!(event, Event::Scalar(_)));
    }

    #[test]
    // Tests for handling sequences
    fn test_loader_sequence() {
        // Arrange
        let input = "---\n- item1\n- item2\n...";
        let progress = Progress::Str(input);

        // Act
        let mut loader = Loader::new(progress).unwrap();
        let document = loader.next_document().unwrap();

        // Assert
        assert_eq!(document.events.len(), 4);
        assert!(document.error.is_none());
        assert_eq!(document.anchor_event_map.len(), 0);

        let (event, _) = &document.events[0];
        assert!(matches!(event, Event::SequenceStart(_)));

        let (event, _) = &document.events[1];
        if let Event::Scalar(scalar) = event {
            assert_eq!(str::from_utf8(&scalar.value).unwrap(), "item1");
        } else {
            panic!("Expected Event::Scalar");
        }

        let (event, _) = &document.events[2];
        if let Event::Scalar(scalar) = event {
            assert_eq!(str::from_utf8(&scalar.value).unwrap(), "item2");
        } else {
            panic!("Expected Event::Scalar");
        }

        let (event, _) = &document.events[3];
        assert!(matches!(event, Event::SequenceEnd));
    }

    #[test]
    /// Tests for loading mappings
    fn test_loader_mapping() {
        let input = "---\nkey1: value1\nkey2: value2\n...";
        let progress = Progress::Str(input);
        let mut loader = Loader::new(progress).unwrap();

        let document = loader.next_document().unwrap();
        assert_eq!(document.events.len(), 6);
        assert!(document.error.is_none());
        assert_eq!(document.anchor_event_map.len(), 0);

        let (event, _) = &document.events[0];
        assert!(matches!(event, Event::MappingStart(_)));

        let (event, _) = &document.events[1];
        if let Event::Scalar(scalar) = event {
            assert_eq!(str::from_utf8(&scalar.value).unwrap(), "key1");
        } else {
            panic!("Expected Event::Scalar");
        }

        let (event, _) = &document.events[2];
        if let Event::Scalar(scalar) = event {
            assert_eq!(
                str::from_utf8(&scalar.value).unwrap(),
                "value1"
            );
        } else {
            panic!("Expected Event::Scalar");
        }

        let (event, _) = &document.events[3];
        if let Event::Scalar(scalar) = event {
            assert_eq!(str::from_utf8(&scalar.value).unwrap(), "key2");
        } else {
            panic!("Expected Event::Scalar");
        }

        let (event, _) = &document.events[4];
        if let Event::Scalar(scalar) = event {
            assert_eq!(
                str::from_utf8(&scalar.value).unwrap(),
                "value2"
            );
        } else {
            panic!("Expected Event::Scalar");
        }

        let (event, _) = &document.events[5];
        assert!(matches!(event, Event::MappingEnd));
    }

    #[test]
    /// Tests for loading escaped characters
    fn test_loader_escaped_characters() {
        let input = "---\nkey: \"value with \\\"quotes\\\"\"\n...";
        let progress = Progress::Str(input);
        let mut loader = Loader::new(progress).unwrap();

        let document = loader.next_document().unwrap();
        assert_eq!(document.events.len(), 4);
        assert!(document.error.is_none());
        assert_eq!(document.anchor_event_map.len(), 0);

        let (event, _) = &document.events[1];
        if let Event::Scalar(scalar) = event {
            assert_eq!(str::from_utf8(&scalar.value).unwrap(), "key");
        } else {
            panic!("Expected Event::Scalar");
        }

        let (event, _) = &document.events[2];
        if let Event::Scalar(scalar) = event {
            assert_eq!(
                str::from_utf8(&scalar.value).unwrap(),
                "value with \"quotes\""
            );
        } else {
            panic!("Expected Event::Scalar");
        }
    }

    #[test]
    /// Tests for loader ignoring comments
    fn test_loader_ignored_comments() {
        let input = "---\n# This is a comment\nkey: value # Inline comment\n...";
        let progress = Progress::Str(input);
        let mut loader = Loader::new(progress).unwrap();

        let document = loader.next_document().unwrap();
        assert_eq!(document.events.len(), 4); // Including comments
        assert!(document.error.is_none());
        assert_eq!(document.anchor_event_map.len(), 0);

        let (event, _) = &document.events[1];
        if let Event::Scalar(scalar) = event {
            assert_eq!(str::from_utf8(&scalar.value).unwrap(), "key");
        } else {
            panic!("Expected Event::Scalar");
        }

        let (event, _) = &document.events[2];
        if let Event::Scalar(scalar) = event {
            assert_eq!(str::from_utf8(&scalar.value).unwrap(), "value");
        } else {
            panic!("Expected Event::Scalar");
        }
    }

    #[test]
    /// Tests for loading from a slice
    fn test_loader_new_from_slice() {
        let input = "key: value".as_bytes();
        let progress = Progress::Slice(input);
        let loader = Loader::new(progress).unwrap();
        assert!(loader.parser.is_some());
        assert_eq!(loader.parsed_document_count, 0);
    }

    #[test]
    /// Tests for loading from a reader
    fn test_loader_new_from_reader() {
        let input = Cursor::new("key: value".as_bytes());
        let progress = Progress::Read(Box::new(input));
        let loader = Loader::new(progress).unwrap();
        assert!(loader.parser.is_some());
        assert_eq!(loader.parsed_document_count, 0);
    }

    #[test]
    /// Tests for loading from a reader with an error
    fn test_loader_new_from_fail() {
        let error = ErrorImpl::IoError(std::io::Error::new(
            std::io::ErrorKind::Other,
            "test error",
        ));
        let progress = Progress::Fail(Arc::new(ErrorImpl::Shared(
            Arc::new(error),
        )));
        let loader_result = Loader::new(progress);
        assert!(loader_result.is_err());
    }

    #[test]
    /// Tests for next_document() with empty input
    fn test_loader_next_document_empty_input() {
        let input = "";
        let progress = Progress::Str(input);
        let mut loader = Loader::new(progress).unwrap();
        let document = loader.next_document().unwrap();
        assert_eq!(document.events.len(), 1);
        assert!(document.error.is_none());
        assert_eq!(document.anchor_event_map.len(), 0);
        assert!(loader.next_document().is_none());
    }

    #[test]
    /// Tests for comments only
    fn test_loader_comments_only() {
        let input = "---\n# Comment\n# Another comment\n...";
        let progress = Progress::Str(input);
        let mut loader = Loader::new(progress).unwrap();

        let document = loader.next_document().unwrap();
        assert_eq!(document.events.len(), 1);
        assert!(document.error.is_none());
        assert_eq!(document.anchor_event_map.len(), 0);
    }

    #[test]
    /// Tests for malformed YAML input
    fn test_loader_malformed_yaml() {
        let input = "---\nkey: value\nkey2 value2\n...";
        let progress = Progress::Str(input);
        let mut loader = Loader::new(progress).unwrap();

        let document = loader.next_document().unwrap();
        assert!(document.error.is_some());
    }

    #[test]
    /// Tests for nested structures
    fn test_loader_nested_structures() {
        let input = "---\nkey:\n  subkey: value\n  list:\n    - item1\n    - item2\n...";
        let progress = Progress::Str(input);
        let mut loader = Loader::new(progress).unwrap();

        let document = loader.next_document().unwrap();
        assert_eq!(document.events.len(), 12);
        assert!(document.error.is_none());
        assert_eq!(document.anchor_event_map.len(), 0);
    }

    #[test]
    /// Test for nested mappings
    fn test_loader_nested_mappings() {
        let input =
            "---\nkey:\n  subkey: value\n  subkey2: value2\n...";
        let progress = Progress::Str(input);
        let mut loader = Loader::new(progress).unwrap();

        let document = loader.next_document().unwrap();
        assert_eq!(document.events.len(), 9);
        assert!(document.error.is_none());
        assert_eq!(document.anchor_event_map.len(), 0);
    }
    #[test]
    /// Test for nested sequences
    fn test_loader_nested_sequences() {
        let input = "---\nkey:\n  - item1\n  - item2\n...";
        let progress = Progress::Str(input);
        let mut loader = Loader::new(progress).unwrap();

        let document = loader.next_document().unwrap();
        assert_eq!(document.events.len(), 7);
        assert!(document.error.is_none());
        assert_eq!(document.anchor_event_map.len(), 0);
    }
    #[test]
    /// Test for nested mappings and sequences
    fn test_loader_nested_mappings_and_sequences() {
        let input =
            "---\nkey:\n  - item1\n  - item2\n  subkey: value\n...";
        let progress = Progress::Str(input);
        let mut loader = Loader::new(progress).unwrap();

        let document = loader.next_document().unwrap();
        assert_eq!(document.events.len(), 5);
        assert_eq!(document.anchor_event_map.len(), 0);
    }
    #[test]
    // Tests performance for loading large YAML documents
    fn test_loader_performance() {
        // Generate a large YAML input
        let mut input = String::from("---\n");
        for i in 0..10000 {
            input.push_str(&format!("key{}: value{}\n", i, i));
        }
        input.push_str("...");

        let progress = Progress::Str(&input);
        let mut loader = Loader::new(progress).unwrap();

        // Measure the time to parse the document
        let start_time = std::time::Instant::now();
        let document = loader.next_document().unwrap();
        let elapsed = start_time.elapsed();

        // Assert that the document was parsed successfully
        assert!(document.error.is_none());

        // Assert that the time taken to parse is reasonable
        assert!(elapsed.as_secs() < 1, "Parsing took too long");
    }
    #[test]
    // Tests for handling documents with special characters
    fn test_loader_special_characters() {
        let input = "---\nkey: value!@#$%^&*()\n...";
        let progress = Progress::Str(input);
        let mut loader = Loader::new(progress).unwrap();

        let document = loader.next_document().unwrap();
        assert_eq!(document.events.len(), 4);
        assert!(document.error.is_none());
        assert_eq!(document.anchor_event_map.len(), 0);
    }
}
