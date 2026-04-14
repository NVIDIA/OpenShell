use crate::{
    de::{Event, Progress},
    libyml::{
        error::Mark,
        parser::{Event as YamlEvent, Parser},
    },
    modules::error::{self, Error, ErrorImpl, Result},
};
use std::{borrow::Cow, collections::BTreeMap, io::Read, sync::Arc};

/// Represents a YAML loader.
#[derive(Debug)]
pub struct Loader<'input> {
    /// The YAML parser used to parse the input.
    ///
    /// The `Parser` type is defined in the `libyml` module and represents
    /// a low-level YAML parser.
    ///
    /// The `'input` lifetime parameter indicates the lifetime of the input data
    /// being parsed. It ensures that the `Loader` does not outlive the input data.
    pub parser: Option<Parser<'input>>,

    /// The count of documents parsed by the loader.
    ///
    /// This field keeps track of the number of YAML documents encountered during parsing.
    pub parsed_document_count: usize,
}

/// Represents a YAML document.
#[derive(Debug)]
pub struct Document<'input> {
    /// The parsed events of the document.
    ///
    /// This field contains a vector of `(Event<'input>, Mark)` tuples, where:
    /// - `Event<'input>` represents a parsed YAML event, such as a scalar, sequence, or mapping.
    ///   The `'input` lifetime parameter indicates the lifetime of the input data associated
    ///   with the event.
    /// - `Mark` represents the position in the input where the event was encountered.
    pub events: Vec<(Event<'input>, Mark)>,

    /// Any error encountered during parsing.
    ///
    /// This field is an optional `Arc<ErrorImpl>`, where:
    /// - `Arc` is a reference-counted smart pointer that allows multiple ownership of the error.
    /// - `ErrorImpl` is the underlying error type that holds the details of the parsing error.
    ///
    /// If an error occurs during parsing, this field will contain `Some(error)`. Otherwise, it
    /// will be `None`.
    pub error: Option<Arc<ErrorImpl>>,

    /// Map from alias id to index in events.
    ///
    /// This field is a `BTreeMap` that maps alias ids to their corresponding index in the
    /// `events` vector.
    ///
    /// In YAML, an alias is a reference to a previously defined anchor. When an alias is
    /// encountered during parsing, its id is used to look up the index of the corresponding
    /// event in the `events` vector.
    pub anchor_event_map: BTreeMap<usize, usize>,
}

impl<'input> Loader<'input> {
    /// Constructs a new `Loader` instance from the given progress.
    ///
    /// # Arguments
    ///
    /// * `progress` - The progress representing the YAML input.
    ///
    /// # Errors
    ///
    /// Returns an error if there is an issue reading the input.
    ///
    /// # Examples
    ///
    /// ```
    /// use serde_yml::loader::Loader;
    /// use serde_yml::de::Progress;
    ///
    /// let input = "---\nkey: value";
    /// let progress = Progress::Str(input);
    /// let loader_result = Loader::new(progress);
    ///
    /// assert!(loader_result.is_ok());
    /// ```
    pub fn new(progress: Progress<'input>) -> Result<Self> {
        let input = match progress {
            Progress::Str(s) => Cow::Borrowed(s.as_bytes()),
            Progress::Slice(bytes) => Cow::Borrowed(bytes),
            Progress::Read(mut rdr) => {
                let mut buffer = Vec::new();
                if let Err(io_error) = rdr.read_to_end(&mut buffer) {
                    return Err(error::new(ErrorImpl::IoError(
                        io_error,
                    )));
                }
                Cow::Owned(buffer)
            }
            Progress::Iterable(_) | Progress::Document(_) => {
                unreachable!()
            }
            Progress::Fail(err) => return Err(error::shared(err)),
        };

        Ok(Loader {
            parser: Some(Parser::new(input)),
            parsed_document_count: 0,
        })
    }

    /// Advances the loader to the next document and returns it.
    ///
    /// # Returns
    ///
    /// Returns `Some(Document)` if a document is successfully parsed, or `None` if there are no more documents.
    ///
    /// # Examples
    ///
    /// ```
    /// use serde_yml::loader::{Loader, Document};
    /// use serde_yml::de::Progress;
    ///
    /// let input = "---\nkey: value";
    /// let progress = Progress::Str(input);
    /// let mut loader = Loader::new(progress).unwrap();
    /// let document = loader.next_document().unwrap();
    ///
    /// assert_eq!(document.events.len(), 4);
    /// ```
    pub fn next_document(&mut self) -> Option<Document<'input>> {
        let parser = match &mut self.parser {
            Some(parser) => parser,
            None => return None,
        };

        let first = self.parsed_document_count == 0;
        self.parsed_document_count += 1;

        let mut anchors = BTreeMap::new();
        let mut document = Document {
            events: Vec::new(),
            error: None,
            anchor_event_map: BTreeMap::new(),
        };

        loop {
            let (event, mark) = match parser.parse_next_event() {
                Ok((event, mark)) => (event, mark),
                Err(err) => {
                    document.error = Some(Error::from(err).shared());
                    return Some(document);
                }
            };
            let event = match event {
                YamlEvent::StreamStart => continue,
                YamlEvent::StreamEnd => {
                    self.parser = None;
                    return if first {
                        if document.events.is_empty() {
                            document.events.push((Event::Void, mark));
                        }
                        Some(document)
                    } else {
                        None
                    };
                }
                YamlEvent::DocumentStart => continue,
                YamlEvent::DocumentEnd => return Some(document),
                YamlEvent::Alias(alias) => match anchors.get(&alias) {
                    Some(id) => Event::Alias(*id),
                    None => {
                        document.error = Some(
                            error::new(ErrorImpl::UnknownAnchor(mark))
                                .shared(),
                        );
                        return Some(document);
                    }
                },
                YamlEvent::Scalar(mut scalar) => {
                    if let Some(anchor) = scalar.anchor.take() {
                        let id = anchors.len();
                        anchors.insert(anchor, id);
                        document
                            .anchor_event_map
                            .insert(id, document.events.len());
                    }
                    Event::Scalar(scalar)
                }
                YamlEvent::SequenceStart(mut sequence_start) => {
                    if let Some(anchor) = sequence_start.anchor.take() {
                        let id = anchors.len();
                        anchors.insert(anchor, id);
                        document
                            .anchor_event_map
                            .insert(id, document.events.len());
                    }
                    Event::SequenceStart(sequence_start)
                }
                YamlEvent::SequenceEnd => Event::SequenceEnd,
                YamlEvent::MappingStart(mut mapping_start) => {
                    if let Some(anchor) = mapping_start.anchor.take() {
                        let id = anchors.len();
                        anchors.insert(anchor, id);
                        document
                            .anchor_event_map
                            .insert(id, document.events.len());
                    }
                    Event::MappingStart(mapping_start)
                }
                YamlEvent::MappingEnd => Event::MappingEnd,
            };
            document.events.push((event, mark));
        }
    }
}
