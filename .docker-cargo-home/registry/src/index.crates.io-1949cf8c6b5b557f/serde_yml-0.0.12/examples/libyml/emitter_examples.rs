//! Examples for the `Emitter` struct and its methods in the `emitter` module.
//!
//! This file demonstrates the creation, usage, and various functionalities of the `Emitter` for emitting YAML events, including scalars, sequences, mappings, and document/stream events.

use serde_yml::libyml::emitter::{
    Emitter, Event, Mapping, Scalar, ScalarStyle, Sequence,
};
use std::io::Cursor;

pub(crate) fn main() {
    // Print a message to indicate the file being executed
    println!("\n❯ Executing examples/libyml/emitter_examples.rs");

    // Example: Emitting a stream start and end event
    let mut buffer = Cursor::new(Vec::new());
    {
        let mut emitter = Emitter::new(Box::new(&mut buffer));
        emitter.emit(Event::StreamStart).unwrap();
        emitter.emit(Event::StreamEnd).unwrap();
    }
    let output =
        String::from_utf8_lossy(&buffer.into_inner()).to_string();
    println!("\n✅ Emitted stream start and end: {}", output);

    // Example: Emitting a document start and end event with a scalar
    let mut buffer = Cursor::new(Vec::new());
    {
        let mut emitter = Emitter::new(Box::new(&mut buffer));
        emitter.emit(Event::StreamStart).unwrap();
        emitter.emit(Event::DocumentStart).unwrap();
        emitter
            .emit(Event::Scalar(Scalar {
                tag: None,
                value: "hello",
                style: ScalarStyle::Plain,
            }))
            .unwrap();
        emitter.emit(Event::DocumentEnd).unwrap();
        emitter.emit(Event::StreamEnd).unwrap();
    }
    let output =
        String::from_utf8_lossy(&buffer.into_inner()).to_string();
    println!("\n✅ Emitted document with scalar: {}", output);

    // Example: Emitting a sequence
    let mut buffer = Cursor::new(Vec::new());
    {
        let mut emitter = Emitter::new(Box::new(&mut buffer));
        emitter.emit(Event::StreamStart).unwrap();
        emitter.emit(Event::DocumentStart).unwrap();
        emitter
            .emit(Event::SequenceStart(Sequence { tag: None }))
            .unwrap();
        emitter
            .emit(Event::Scalar(Scalar {
                tag: None,
                value: "item1",
                style: ScalarStyle::Plain,
            }))
            .unwrap();
        emitter
            .emit(Event::Scalar(Scalar {
                tag: None,
                value: "item2",
                style: ScalarStyle::Plain,
            }))
            .unwrap();
        emitter.emit(Event::SequenceEnd).unwrap();
        emitter.emit(Event::DocumentEnd).unwrap();
        emitter.emit(Event::StreamEnd).unwrap();
    }
    let output =
        String::from_utf8_lossy(&buffer.into_inner()).to_string();
    println!("\n✅ Emitted sequence: {}", output);

    // Example: Emitting a mapping
    let mut buffer = Cursor::new(Vec::new());
    {
        let mut emitter = Emitter::new(Box::new(&mut buffer));
        emitter.emit(Event::StreamStart).unwrap();
        emitter.emit(Event::DocumentStart).unwrap();
        emitter
            .emit(Event::MappingStart(Mapping { tag: None }))
            .unwrap();
        emitter
            .emit(Event::Scalar(Scalar {
                tag: None,
                value: "key1",
                style: ScalarStyle::Plain,
            }))
            .unwrap();
        emitter
            .emit(Event::Scalar(Scalar {
                tag: None,
                value: "value1",
                style: ScalarStyle::Plain,
            }))
            .unwrap();
        emitter
            .emit(Event::Scalar(Scalar {
                tag: None,
                value: "key2",
                style: ScalarStyle::Plain,
            }))
            .unwrap();
        emitter
            .emit(Event::Scalar(Scalar {
                tag: None,
                value: "value2",
                style: ScalarStyle::Plain,
            }))
            .unwrap();
        emitter.emit(Event::MappingEnd).unwrap();
        emitter.emit(Event::DocumentEnd).unwrap();
        emitter.emit(Event::StreamEnd).unwrap();
    }
    let output =
        String::from_utf8_lossy(&buffer.into_inner()).to_string();
    println!("\n✅ Emitted mapping: {}", output);

    // Example: Flushing the emitter
    let mut buffer = Cursor::new(Vec::new());
    {
        let mut emitter = Emitter::new(Box::new(&mut buffer));
        emitter.emit(Event::StreamStart).unwrap();
        emitter.emit(Event::DocumentStart).unwrap();
        emitter
            .emit(Event::Scalar(Scalar {
                tag: None,
                value: "hello",
                style: ScalarStyle::Plain,
            }))
            .unwrap();
        emitter.flush().unwrap();
        emitter.emit(Event::DocumentEnd).unwrap();
        emitter.emit(Event::StreamEnd).unwrap();
    }
    let output =
        String::from_utf8_lossy(&buffer.into_inner()).to_string();
    println!("\n✅ Emitted and flushed: {}", output);

    // Example: Emitting scalar with tag
    let mut buffer = Cursor::new(Vec::new());
    {
        let mut emitter = Emitter::new(Box::new(&mut buffer));
        emitter.emit(Event::StreamStart).unwrap();
        emitter.emit(Event::DocumentStart).unwrap();
        emitter
            .emit(Event::Scalar(Scalar {
                tag: Some("!mytag".to_string()),
                value: "hello",
                style: ScalarStyle::Plain,
            }))
            .unwrap();
        emitter.emit(Event::DocumentEnd).unwrap();
        emitter.emit(Event::StreamEnd).unwrap();
    }
    let output =
        String::from_utf8_lossy(&buffer.into_inner()).to_string();
    println!("\n✅ Emitted scalar with tag: {}", output);

    // Example: Emitting sequence with tag
    let mut buffer = Cursor::new(Vec::new());
    {
        let mut emitter = Emitter::new(Box::new(&mut buffer));
        emitter.emit(Event::StreamStart).unwrap();
        emitter.emit(Event::DocumentStart).unwrap();
        emitter
            .emit(Event::SequenceStart(Sequence {
                tag: Some("!mytag".to_string()),
            }))
            .unwrap();
        emitter
            .emit(Event::Scalar(Scalar {
                tag: None,
                value: "item1",
                style: ScalarStyle::Plain,
            }))
            .unwrap();
        emitter
            .emit(Event::Scalar(Scalar {
                tag: None,
                value: "item2",
                style: ScalarStyle::Plain,
            }))
            .unwrap();
        emitter.emit(Event::SequenceEnd).unwrap();
        emitter.emit(Event::DocumentEnd).unwrap();
        emitter.emit(Event::StreamEnd).unwrap();
    }
    let output =
        String::from_utf8_lossy(&buffer.into_inner()).to_string();
    println!("\n✅ Emitted sequence with tag: {}", output);

    // Example: Emitting mapping with tag
    let mut buffer = Cursor::new(Vec::new());
    {
        let mut emitter = Emitter::new(Box::new(&mut buffer));
        emitter.emit(Event::StreamStart).unwrap();
        emitter.emit(Event::DocumentStart).unwrap();
        emitter
            .emit(Event::MappingStart(Mapping {
                tag: Some("!mytag".to_string()),
            }))
            .unwrap();
        emitter
            .emit(Event::Scalar(Scalar {
                tag: None,
                value: "key1",
                style: ScalarStyle::Plain,
            }))
            .unwrap();
        emitter
            .emit(Event::Scalar(Scalar {
                tag: None,
                value: "value1",
                style: ScalarStyle::Plain,
            }))
            .unwrap();
        emitter
            .emit(Event::Scalar(Scalar {
                tag: None,
                value: "key2",
                style: ScalarStyle::Plain,
            }))
            .unwrap();
        emitter
            .emit(Event::Scalar(Scalar {
                tag: None,
                value: "value2",
                style: ScalarStyle::Plain,
            }))
            .unwrap();
        emitter.emit(Event::MappingEnd).unwrap();
        emitter.emit(Event::DocumentEnd).unwrap();
        emitter.emit(Event::StreamEnd).unwrap();
    }
    let output =
        String::from_utf8_lossy(&buffer.into_inner()).to_string();
    println!("\n✅ Emitted mapping with tag: {}", output);

    // Example: Emitting an empty sequence
    let mut buffer = Cursor::new(Vec::new());
    {
        let mut emitter = Emitter::new(Box::new(&mut buffer));
        emitter.emit(Event::StreamStart).unwrap();
        emitter.emit(Event::DocumentStart).unwrap();
        emitter
            .emit(Event::SequenceStart(Sequence { tag: None }))
            .unwrap();
        emitter.emit(Event::SequenceEnd).unwrap();
        emitter.emit(Event::DocumentEnd).unwrap();
        emitter.emit(Event::StreamEnd).unwrap();
    }
    let output =
        String::from_utf8_lossy(&buffer.into_inner()).to_string();
    println!("\n✅ Emitted empty sequence: {}", output);

    // Example: Emitting an empty mapping
    let mut buffer = Cursor::new(Vec::new());
    {
        let mut emitter = Emitter::new(Box::new(&mut buffer));
        emitter.emit(Event::StreamStart).unwrap();
        emitter.emit(Event::DocumentStart).unwrap();
        emitter
            .emit(Event::MappingStart(Mapping { tag: None }))
            .unwrap();
        emitter.emit(Event::MappingEnd).unwrap();
        emitter.emit(Event::DocumentEnd).unwrap();
        emitter.emit(Event::StreamEnd).unwrap();
    }
    let output =
        String::from_utf8_lossy(&buffer.into_inner()).to_string();
    println!("\n✅ Emitted empty mapping: {}", output);

    // Example: Emitting a nested sequence
    let mut buffer = Cursor::new(Vec::new());
    {
        let mut emitter = Emitter::new(Box::new(&mut buffer));
        emitter.emit(Event::StreamStart).unwrap();
        emitter.emit(Event::DocumentStart).unwrap();
        emitter
            .emit(Event::SequenceStart(Sequence { tag: None }))
            .unwrap();
        emitter
            .emit(Event::SequenceStart(Sequence { tag: None }))
            .unwrap();
        emitter
            .emit(Event::Scalar(Scalar {
                tag: None,
                value: "nested",
                style: ScalarStyle::Plain,
            }))
            .unwrap();
        emitter.emit(Event::SequenceEnd).unwrap();
        emitter.emit(Event::SequenceEnd).unwrap();
        emitter.emit(Event::DocumentEnd).unwrap();
        emitter.emit(Event::StreamEnd).unwrap();
    }
    let output =
        String::from_utf8_lossy(&buffer.into_inner()).to_string();
    println!("\n✅ Emitted nested sequence: {}", output);

    // Example: Emitting a nested mapping
    let mut buffer = Cursor::new(Vec::new());
    {
        let mut emitter = Emitter::new(Box::new(&mut buffer));
        emitter.emit(Event::StreamStart).unwrap();
        emitter.emit(Event::DocumentStart).unwrap();
        emitter
            .emit(Event::MappingStart(Mapping { tag: None }))
            .unwrap();
        emitter
            .emit(Event::Scalar(Scalar {
                tag: None,
                value: "key",
                style: ScalarStyle::Plain,
            }))
            .unwrap();
        emitter
            .emit(Event::MappingStart(Mapping { tag: None }))
            .unwrap();
        emitter
            .emit(Event::Scalar(Scalar {
                tag: None,
                value: "nested_key",
                style: ScalarStyle::Plain,
            }))
            .unwrap();
        emitter
            .emit(Event::Scalar(Scalar {
                tag: None,
                value: "nested_value",
                style: ScalarStyle::Plain,
            }))
            .unwrap();
        emitter.emit(Event::MappingEnd).unwrap();
        emitter.emit(Event::MappingEnd).unwrap();
        emitter.emit(Event::DocumentEnd).unwrap();
        emitter.emit(Event::StreamEnd).unwrap();
    }
    let output =
        String::from_utf8_lossy(&buffer.into_inner()).to_string();
    println!("\n✅ Emitted nested mapping: {}", output);
}
