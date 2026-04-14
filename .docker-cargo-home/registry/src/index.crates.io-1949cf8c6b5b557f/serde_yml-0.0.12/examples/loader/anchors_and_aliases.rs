use serde_yml::{
    de::{Event, Progress},
    loader::Loader,
};
use std::str;

pub(crate) fn main() {
    // Print a message to indicate the file being executed.
    println!(
        "\n❯ Executing examples/loader/anchors_and_anchor_event_map.rs"
    );

    let input = "---\nkey: &anchor value\nalias: *anchor\n...";
    let progress = Progress::Str(input);
    let mut loader = Loader::new(progress).unwrap();

    let document = loader.next_document().unwrap();

    // Print a success message and present the results to the user.
    println!(
        "\n✅ Successfully loaded document with {} events:",
        document.events.len()
    );
    for (event, mark) in &document.events {
        println!("\tEvent: {:?}, Mark: {:?}", event, mark);
    }

    // Perform assertions to verify that the loader is working as expected.
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
