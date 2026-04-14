#[cfg(test)]
mod tests {
    use serde_yml::libyml::parser::Event;
    use serde_yml::libyml::parser::Parser;
    use std::borrow::Cow;

    /// Tests the creation of a new `Parser` instance with valid input.
    /// Verifies that the parser is created successfully and initializes correctly.
    #[test]
    fn test_parser_creation() {
        let input = Cow::Borrowed(b"foo: bar\n");
        let mut parser = Parser::new(Cow::Borrowed(input.as_ref()));
        assert!(matches!(
            parser.parse_next_event().unwrap().0,
            Event::StreamStart
        ));
    }

    /// Tests the `parse_next_event` method for a stream start event.
    /// Verifies that the event is correctly parsed and returned.
    #[test]
    fn test_parse_stream_start_event() {
        let input = Cow::Borrowed(b"foo: bar\n");
        let mut parser = Parser::new(Cow::Borrowed(input.as_ref()));
        let (event, _mark) = parser.parse_next_event().unwrap();
        assert!(matches!(event, Event::StreamStart));
    }

    /// Tests the `parse_next_event` method for a stream end event.
    /// Verifies that the event is correctly parsed and returned.
    #[test]
    fn test_parse_stream_end_event() {
        let input = Cow::Borrowed(b"foo: bar\n").as_ref();
        let mut parser = Parser::new(Cow::Borrowed(input));
        let mut stream_end_reached = false;

        while let Ok((event, _mark)) = parser.parse_next_event() {
            if matches!(event, Event::StreamEnd) {
                stream_end_reached = true;
                break;
            }
        }

        assert!(stream_end_reached, "StreamEnd event was not reached");
    }

    /// Tests the `parse_next_event` method for a document start event.
    /// Verifies that the event is correctly parsed and returned.
    #[test]
    fn test_parse_document_start_event() {
        let input = Cow::Borrowed(b"---\nfoo: bar\n").as_ref();
        let mut parser = Parser::new(Cow::Borrowed(input));
        let mut found_start = false;
        while let Ok((event, _mark)) = parser.parse_next_event() {
            if matches!(event, Event::DocumentStart) {
                found_start = true;
                break;
            }
        }
        assert!(found_start);
    }

    /// Tests the `parse_next_event` method for a document end event.
    /// Verifies that the event is correctly parsed and returned.
    #[test]
    fn test_parse_document_end_event() {
        let input =
            Cow::Borrowed(b"foo: bar\n---\nbaz: qux\n").as_ref();
        let mut parser = Parser::new(Cow::Borrowed(input));
        let mut found_end = false;
        while let Ok((event, _mark)) = parser.parse_next_event() {
            if matches!(event, Event::DocumentEnd) {
                found_end = true;
                break;
            }
        }
        assert!(found_end);
    }

    /// Tests the `parse_next_event` method for a scalar event.
    /// Verifies that the event is correctly parsed and returned.
    #[test]
    fn test_parse_scalar_event() {
        let input = Cow::Borrowed(b"bar\n").as_ref();
        let mut parser = Parser::new(Cow::Borrowed(input));
        let mut found_scalar = false;
        while let Ok((event, _mark)) = parser.parse_next_event() {
            if let Event::Scalar(scalar) = event {
                assert_eq!(scalar.value.as_ref(), b"bar");
                found_scalar = true;
                break;
            }
        }
        assert!(found_scalar);
    }

    /// Tests the `parse_next_event` method for a sequence start event.
    /// Verifies that the event is correctly parsed and returned.
    #[test]
    fn test_parse_sequence_start_event() {
        let input = Cow::Borrowed(b"- item1\n- item2\n").as_ref();
        let mut parser = Parser::new(Cow::Borrowed(input));
        let mut found_start = false;
        while let Ok((event, _mark)) = parser.parse_next_event() {
            if matches!(event, Event::SequenceStart(_)) {
                found_start = true;
                break;
            }
        }
        assert!(found_start);
    }

    /// Tests the `parse_next_event` method for a sequence end event.
    /// Verifies that the event is correctly parsed and returned.
    #[test]
    fn test_parse_sequence_end_event() {
        let input = Cow::Borrowed(b"- item1\n- item2\n").as_ref();
        let mut parser = Parser::new(Cow::Borrowed(input));
        let mut found_end = false;
        while let Ok((event, _mark)) = parser.parse_next_event() {
            if matches!(event, Event::SequenceEnd) {
                found_end = true;
                break;
            }
        }
        assert!(found_end);
    }

    /// Tests the `parse_next_event` method for a mapping start event.
    /// Verifies that the event is correctly parsed and returned.
    #[test]
    fn test_parse_mapping_start_event() {
        let input = Cow::Borrowed(b"key: value\n").as_ref();
        let mut parser = Parser::new(Cow::Borrowed(input));
        let mut found_start = false;
        while let Ok((event, _mark)) = parser.parse_next_event() {
            if matches!(event, Event::MappingStart(_)) {
                found_start = true;
                break;
            }
        }
        assert!(found_start);
    }

    /// Tests the `parse_next_event` method for a mapping end event.
    /// Verifies that the event is correctly parsed and returned.
    #[test]
    fn test_parse_mapping_end_event() {
        let input = Cow::Borrowed(b"key: value\n").as_ref();
        let mut parser = Parser::new(Cow::Borrowed(input));
        let mut found_end = false;
        while let Ok((event, _mark)) = parser.parse_next_event() {
            if matches!(event, Event::MappingEnd) {
                found_end = true;
                break;
            }
        }
        assert!(found_end);
    }

    /// Tests the `parse_next_event` method for nested sequences.
    /// Verifies that the events are correctly parsed and returned.
    #[test]
    fn test_parse_nested_sequences() {
        let input =
            Cow::Borrowed(b"- item1\n- - nested1\n  - nested2\n")
                .as_ref();
        let mut parser = Parser::new(Cow::Borrowed(input));
        let mut found_nested_start = false;

        while let Ok((event, _mark)) = parser.parse_next_event() {
            if matches!(event, Event::SequenceStart(_)) {
                if found_nested_start {
                    // Found the nested sequence start
                    break;
                } else {
                    found_nested_start = true;
                }
            }
        }

        assert!(
            found_nested_start,
            "Nested sequence start event was not found"
        );
    }
}
