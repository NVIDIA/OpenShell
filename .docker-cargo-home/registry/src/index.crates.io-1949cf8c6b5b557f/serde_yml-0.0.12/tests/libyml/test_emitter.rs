#[cfg(test)]
mod tests {
    use serde_yml::libyml::emitter::{
        Emitter, Event, Mapping, Scalar, ScalarStyle, Sequence,
    };
    use std::io::Cursor;

    #[test]
    fn test_emitter_stream_start_end() {
        let mut buffer = Cursor::new(Vec::with_capacity(100));
        {
            let mut emitter = Emitter::new(Box::new(&mut buffer));
            emitter.emit(Event::StreamStart).unwrap();
            emitter.emit(Event::StreamEnd).unwrap();
        }

        let result =
            String::from_utf8_lossy(&buffer.into_inner()).to_string();
        assert_eq!(result, "");
    }

    #[test]
    fn test_emitter_document_start_end() {
        let mut buffer = Cursor::new(Vec::with_capacity(100));
        {
            let mut emitter = Emitter::new(Box::new(&mut buffer));
            emitter.emit(Event::StreamStart).unwrap();
            emitter.emit(Event::DocumentStart).unwrap();
            emitter
                .emit(Event::Scalar(Scalar {
                    tag: None,
                    value: "",
                    style: ScalarStyle::Plain,
                }))
                .unwrap();
            emitter.emit(Event::DocumentEnd).unwrap();
            emitter.emit(Event::StreamEnd).unwrap();
        }

        let result =
            String::from_utf8_lossy(&buffer.into_inner()).to_string();
        assert_eq!(result, "\n");
    }

    #[test]
    fn test_emitter_scalar() {
        let mut buffer = Cursor::new(Vec::with_capacity(100));
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
        buffer.set_position(0);

        let result =
            String::from_utf8_lossy(&buffer.into_inner()).to_string();
        assert_eq!(result, "hello\n");
    }

    #[test]
    fn test_emitter_sequence() {
        let mut buffer = Cursor::new(Vec::with_capacity(100));
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
        buffer.set_position(0);

        let result =
            String::from_utf8_lossy(&buffer.into_inner()).to_string();
        assert_eq!(result, "- item1\n- item2\n");
    }

    #[test]
    fn test_emitter_mapping() {
        let mut buffer = Cursor::new(Vec::with_capacity(100));
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
        buffer.set_position(0);

        let result =
            String::from_utf8_lossy(&buffer.into_inner()).to_string();
        assert_eq!(result, "key1: value1\nkey2: value2\n");
    }

    #[test]
    fn test_emitter_flush() {
        let mut buffer = Cursor::new(Vec::with_capacity(100));
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
        buffer.set_position(0);

        let result =
            String::from_utf8_lossy(&buffer.into_inner()).to_string();
        assert_eq!(result, "hello\n");
    }

    #[test]
    fn test_emitter_scalar_with_tag() {
        let mut buffer = Cursor::new(Vec::with_capacity(100));
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
        buffer.set_position(0);

        let result =
            String::from_utf8_lossy(&buffer.into_inner()).to_string();
        assert_eq!(result, "!mytag hello\n");
    }

    #[test]
    fn test_emitter_sequence_with_tag() {
        let mut buffer = Cursor::new(Vec::with_capacity(100));
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
        buffer.set_position(0);

        let result =
            String::from_utf8_lossy(&buffer.into_inner()).to_string();
        assert_eq!(result, "!mytag\n- item1\n- item2\n");
    }

    #[test]
    fn test_emitter_mapping_with_tag() {
        let mut buffer = Cursor::new(Vec::with_capacity(100));
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
        buffer.set_position(0);

        let result =
            String::from_utf8_lossy(&buffer.into_inner()).to_string();
        assert_eq!(result, "!mytag\nkey1: value1\nkey2: value2\n");
    }

    #[test]
    fn test_emitter_empty_sequence() {
        let mut buffer = Cursor::new(Vec::with_capacity(100));
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
        buffer.set_position(0);

        let result =
            String::from_utf8_lossy(&buffer.into_inner()).to_string();
        assert_eq!(result, "[]\n");
    }

    #[test]
    fn test_emitter_empty_mapping() {
        let mut buffer = Cursor::new(Vec::with_capacity(100));
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
        buffer.set_position(0);

        let result =
            String::from_utf8_lossy(&buffer.into_inner()).to_string();
        assert_eq!(result, "{}\n");
    }

    #[test]
    fn test_emitter_nested_sequence() {
        let mut buffer = Cursor::new(Vec::with_capacity(100));
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
        buffer.set_position(0);

        let result =
            String::from_utf8_lossy(&buffer.into_inner()).to_string();
        assert_eq!(result, "- - nested\n");
    }

    #[test]
    fn test_emitter_nested_mapping() {
        let mut buffer = Cursor::new(Vec::with_capacity(100));
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
        buffer.set_position(0);

        let result =
            String::from_utf8_lossy(&buffer.into_inner()).to_string();
        assert_eq!(result, "key:\n  nested_key: nested_value\n");
    }
}
