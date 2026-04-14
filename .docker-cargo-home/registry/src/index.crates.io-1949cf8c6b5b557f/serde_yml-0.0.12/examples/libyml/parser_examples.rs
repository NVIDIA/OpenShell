//! Examples for the `Parser` struct and its methods in the `parser` module.
//!
//! This file demonstrates the creation, usage, and event parsing of `Parser` instances,
//! as well as handling different types of YAML events and input scenarios.

use serde_yml::libyml::parser::{Event, Parser};
use std::borrow::Cow;

#[allow(clippy::single_match)]
pub(crate) fn main() {
    // Print a message to indicate the file being executed.
    println!("\n❯ Executing examples/libyml/parser_examples.rs");

    // Example 1: Creating a parser and parsing a stream start event
    {
        let input = Cow::Borrowed(b"foo: bar\n");
        let mut parser = Parser::new(Cow::Borrowed(input.as_ref()));
        match parser.parse_next_event() {
            Ok((event, _)) => {
                match event {
                    Event::StreamStart => {
                        println!("\n✅ Stream start event parsed successfully.")
                    }
                    _ => println!("\n❌ Unexpected event."),
                }
            }
            Err(err) => println!("Error parsing event: {:?}", err),
        }
    }

    // Example 2: Parsing a stream end event
    {
        let input = Cow::Borrowed(b"foo: bar\n").as_ref();
        let mut parser = Parser::new(Cow::Borrowed(input));
        while let Ok((event, _)) = parser.parse_next_event() {
            if matches!(event, Event::StreamEnd) {
                println!("\n✅ Stream end event parsed successfully.");
                break;
            }
        }
    }

    // Example 3: Parsing a document start event
    {
        let input = Cow::Borrowed(b"---\nfoo: bar\n").as_ref();
        let mut parser = Parser::new(Cow::Borrowed(input));
        while let Ok((event, _)) = parser.parse_next_event() {
            if matches!(event, Event::DocumentStart) {
                println!(
                    "\n✅ Document start event parsed successfully."
                );
                break;
            }
        }
    }

    // Example 4: Parsing a document end event
    {
        let input =
            Cow::Borrowed(b"foo: bar\n---\nbaz: qux\n").as_ref();
        let mut parser = Parser::new(Cow::Borrowed(input));
        while let Ok((event, _)) = parser.parse_next_event() {
            if matches!(event, Event::DocumentEnd) {
                println!(
                    "\n✅ Document end event parsed successfully."
                );
                break;
            }
        }
    }

    // Example 5: Parsing a scalar event
    {
        let input = Cow::Borrowed(b"bar\n").as_ref();
        let mut parser = Parser::new(Cow::Borrowed(input));
        while let Ok((event, _)) = parser.parse_next_event() {
            if let Event::Scalar(scalar) = event {
                println!(
                    "\n✅ Scalar event parsed successfully with value: {:?}",
                    scalar.value
                );
                break;
            }
        }
    }

    // Example 6: Parsing a sequence start event
    {
        let input = Cow::Borrowed(b"- item1\n- item2\n").as_ref();
        let mut parser = Parser::new(Cow::Borrowed(input));
        while let Ok((event, _)) = parser.parse_next_event() {
            if matches!(event, Event::SequenceStart(_)) {
                println!(
                    "\n✅ Sequence start event parsed successfully."
                );
                break;
            }
        }
    }

    // Example 7: Parsing a sequence end event
    {
        let input = Cow::Borrowed(b"- item1\n- item2\n").as_ref();
        let mut parser = Parser::new(Cow::Borrowed(input));
        while let Ok((event, _)) = parser.parse_next_event() {
            if matches!(event, Event::SequenceEnd) {
                println!(
                    "\n✅ Sequence end event parsed successfully."
                );
                break;
            }
        }
    }

    // Example 8: Parsing a mapping start event
    {
        let input = Cow::Borrowed(b"key: value\n").as_ref();
        let mut parser = Parser::new(Cow::Borrowed(input));
        while let Ok((event, _)) = parser.parse_next_event() {
            if matches!(event, Event::MappingStart(_)) {
                println!(
                    "\n✅ Mapping start event parsed successfully."
                );
                break;
            }
        }
    }

    // Example 9: Parsing a mapping end event
    {
        let input = Cow::Borrowed(b"key: value\n").as_ref();
        let mut parser = Parser::new(Cow::Borrowed(input));
        while let Ok((event, _)) = parser.parse_next_event() {
            if matches!(event, Event::MappingEnd) {
                println!("\n✅ Mapping end event parsed successfully.");
                break;
            }
        }
    }

    // Example 10: Handling unexpected input
    {
        let input = Cow::Borrowed(b"unexpected: [value").as_ref(); // Malformed YAML
        let mut parser = Parser::new(Cow::Borrowed(input));
        match parser.parse_next_event() {
            Ok(_) => println!(
                "\n❌ Unexpectedly parsed malformed input without error."
            ),
            Err(err) => {
                println!("\n❌ Error parsing malformed input: {:?}", err)
            }
        }
    }

    // Example 11: Handling empty input
    {
        let input = Cow::Borrowed(b"").as_ref();
        let mut parser = Parser::new(Cow::Borrowed(input));
        match parser.parse_next_event() {
            Ok((event, _)) => match event {
                Event::StreamEnd => println!("Stream end event parsed successfully for empty input."),
                _ => println!("Unexpected event for empty input."),
            },
            Err(err) => println!("Error parsing empty input: {:?}", err),
        }
    }

    // Example 12: Parsing nested sequences
    {
        let input =
            Cow::Borrowed(b"- item1\n- - nested1\n  - nested2\n")
                .as_ref();
        let mut parser = Parser::new(Cow::Borrowed(input));
        let mut found_nested_start = false;

        while let Ok((event, _)) = parser.parse_next_event() {
            if matches!(event, Event::SequenceStart(_)) {
                if found_nested_start {
                    println!("\n✅ Nested sequence start event parsed successfully.");
                    break;
                } else {
                    found_nested_start = true;
                }
            }
        }

        if !found_nested_start {
            println!("\n❌ Nested sequence start event was not found.");
        }
    }

    // Example 13: Parsing mixed content (sequence and mapping)
    {
        let input =
            Cow::Borrowed(b"- item1\nkey: value\n- item2\n").as_ref();
        let mut parser = Parser::new(Cow::Borrowed(input));
        let mut found_sequence = false;
        let mut found_mapping = false;

        while let Ok((event, _)) = parser.parse_next_event() {
            if matches!(event, Event::SequenceStart(_)) {
                found_sequence = true;
            }
            if matches!(event, Event::MappingStart(_)) {
                found_mapping = true;
            }
            if found_sequence && found_mapping {
                println!("\n✅ Mixed content parsed successfully (sequence and mapping).");
                break;
            }
        }

        if !found_sequence {
            println!("\n❌ Sequence start event was not found.");
        }
        if !found_mapping {
            println!("\n❌ Mapping start event was not found.");
        }
    }

    // Example 14: Error handling with invalid input
    {
        let input = Cow::Borrowed(b"invalid: [yaml").as_ref(); // Invalid YAML
        let mut parser = Parser::new(Cow::Borrowed(input));
        match parser.parse_next_event() {
            Ok(_) => println!(
                "\n❌ Unexpectedly parsed invalid input without error."
            ),
            Err(err) => println!(
                "\n✅ Correctly handled error for invalid input: {:?}",
                err
            ),
        }
    }

    // Example 15: Parser initialization check
    {
        let input = Cow::Borrowed(b"foo: bar\n").as_ref();
        let parser = Parser::new(Cow::Borrowed(input));
        if parser.is_ok() {
            println!("\n✅ Parser initialized successfully.");
        } else {
            println!("\n❌ Parser failed to initialize.");
        }
    }

    // Example 16: Parsing complex nested structures
    {
        let input = Cow::Borrowed(
            b"- item1\n- item2:\n  - nested1\n  - nested2\n- item3\n",
        )
        .as_ref();
        let mut parser = Parser::new(Cow::Borrowed(input));
        while let Ok((event, _)) = parser.parse_next_event() {
            match event {
                Event::SequenceStart(_) => {
                    println!("\n✅ Sequence start event found.")
                }
                Event::MappingStart(_) => {
                    println!("\n✅ Mapping start event found.")
                }
                Event::Scalar(scalar) => {
                    println!("\n✅ Scalar value: {:?}", scalar.value)
                }
                _ => {}
            }
        }
    }

    // Example 17: Handling comments in YAML (if supported)
    {
        let input =
            Cow::Borrowed(b"# This is a comment\nfoo: bar\n").as_ref();
        let mut parser = Parser::new(Cow::Borrowed(input));
        while let Ok((event, _)) = parser.parse_next_event() {
            match event {
                Event::Scalar(scalar) => {
                    println!("\n✅ Scalar value: {:?}", scalar.value)
                }
                // Event::Comment(comment) => println!("\n✅ Comment: {:?}", comment), // Uncomment if comments are supported
                _ => {}
            }
        }
    }
}
