#[cfg(test)]
mod tests {
    use serde_yml::de::Event;
    use serde_yml::de::Progress;
    use serde_yml::loader::Loader;
    use std::str;

    #[test]
    fn test_document_loaded_successfully() {
        let input = "---\nkey: &anchor value\nalias: *anchor\n...";
        let progress = Progress::Str(input);
        let mut loader = Loader::new(progress).unwrap();
        let document = loader.next_document().unwrap();
        assert!(document.error.is_none());
    }

    #[test]
    fn test_document_events_count() {
        let input = "---\nkey: &anchor value\nalias: *anchor\n...";
        let progress = Progress::Str(input);
        let mut loader = Loader::new(progress).unwrap();
        let document = loader.next_document().unwrap();
        assert_eq!(document.events.len(), 6); // Update expected count to 6
    }

    #[test]
    fn test_document_anchor_event_map_count() {
        let input = "---\nkey: &anchor value\nalias: *anchor\n...";
        let progress = Progress::Str(input);
        let mut loader = Loader::new(progress).unwrap();
        let document = loader.next_document().unwrap();
        assert_eq!(document.anchor_event_map.len(), 1);
    }

    #[test]
    fn test_document_event_contents() {
        let input = "---\nkey: &anchor value\nalias: *anchor\n...";
        let progress = Progress::Str(input);
        let mut loader = Loader::new(progress).unwrap();
        let document = loader.next_document().unwrap();

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
}
