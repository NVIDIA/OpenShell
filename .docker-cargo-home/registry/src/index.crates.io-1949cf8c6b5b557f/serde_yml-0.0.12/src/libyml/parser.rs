use crate::libyml::{
    error::{Error, Mark, Result},
    safe_cstr::{self, CStr},
    tag::Tag,
    util::Owned,
};
#[allow(clippy::unsafe_removed_from_name)]
use libyml as sys;
use std::{
    borrow::Cow,
    fmt::{self, Debug},
    mem::MaybeUninit,
    ptr::{addr_of_mut, NonNull},
    slice,
};

/// Represents a YAML parser.
///
/// The `Parser` struct is responsible for parsing YAML input and generating a sequence
/// of YAML events. It wraps the underlying `libyml` parser and provides a safe and
/// convenient interface for parsing YAML documents.
///
/// The `'input` lifetime parameter indicates the lifetime of the input data being parsed.
/// It ensures that the `Parser` does not outlive the input data.
#[derive(Debug)]
pub struct Parser<'input> {
    /// The pinned parser state.
    ///
    /// The `Owned<ParserPinned<'input>>` type represents an owned instance of the
    /// `ParserPinned` struct. The `Owned` type is used to provide pinning and
    /// allows the `Parser` to be safely moved around.
    ///
    /// The `ParserPinned` struct contains the underlying `libyml` parser state
    /// and the input data being parsed.
    ///
    /// Pinning is used to ensure that the `Parser` remains at a fixed memory
    /// location, which is required for safe interaction with the `libyml` library.
    pub pin: Owned<ParserPinned<'input>>,
}

/// Represents a pinned parser for YAML deserialization.
///
/// The `ParserPinned` struct contains the necessary state and resources
/// for parsing YAML documents. It is pinned to a specific lifetime `'input`
/// to ensure that the borrowed input data remains valid throughout the
/// lifetime of the parser.
#[derive(Debug, Clone)]
pub struct ParserPinned<'input> {
    /// The underlying `YamlParserT` struct from the `libyml` library.
    pub sys: sys::YamlParserT,

    /// The input data being parsed.
    pub input: Cow<'input, [u8]>,
}

/// Represents a YAML event encountered during parsing.
#[derive(Debug)]
pub enum Event<'input> {
    /// Indicates the start of a YAML stream.
    StreamStart,
    /// Indicates the end of a YAML stream.
    StreamEnd,
    /// Indicates the start of a YAML document.
    DocumentStart,
    /// Indicates the end of a YAML document.
    DocumentEnd,
    /// Indicates an alias to an anchor in a YAML document.
    Alias(Anchor),
    /// Represents a scalar value in a YAML document.
    Scalar(Scalar<'input>),
    /// Indicates the start of a sequence in a YAML document.
    SequenceStart(SequenceStart),
    /// Indicates the end of a sequence in a YAML document.
    SequenceEnd,
    /// Indicates the start of a mapping in a YAML document.
    MappingStart(MappingStart),
    /// Indicates the end of a mapping in a YAML document.
    MappingEnd,
}

/// Represents a scalar value in a YAML document.
pub struct Scalar<'input> {
    /// The anchor associated with the scalar value.
    pub anchor: Option<Anchor>,
    /// The tag associated with the scalar value.
    pub tag: Option<Tag>,
    /// The value of the scalar as a byte slice.
    pub value: Box<[u8]>,
    /// The style of the scalar value.
    pub style: ScalarStyle,
    /// The representation of the scalar value as a byte slice.
    pub repr: Option<&'input [u8]>,
}

/// Represents the start of a sequence in a YAML document.
#[derive(Debug)]
pub struct SequenceStart {
    /// The anchor associated with the sequence.
    pub anchor: Option<Anchor>,
    /// The tag associated with the sequence.
    pub tag: Option<Tag>,
}

/// Represents the start of a mapping in a YAML document.
#[derive(Debug)]
pub struct MappingStart {
    /// The anchor associated with the mapping.
    pub anchor: Option<Anchor>,
    /// The tag associated with the mapping.
    pub tag: Option<Tag>,
}

/// Represents an anchor in a YAML document.
#[derive(Ord, PartialOrd, Eq, PartialEq)]
pub struct Anchor(Box<[u8]>);

/// Represents the style of a scalar value in a YAML document.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ScalarStyle {
    /// Indicates a plain scalar value.
    Plain,
    /// Indicates a single-quoted scalar value.
    SingleQuoted,
    /// Indicates a double-quoted scalar value.
    DoubleQuoted,
    /// Indicates a literal scalar value.
    Literal,
    /// Indicates a folded scalar value.
    Folded,
}

impl<'input> Parser<'input> {
    /// Creates a new `Parser` instance with the given input data.
    ///
    /// The `input` parameter is of type `Cow<'input, [u8]>`, which allows the parser
    /// to accept both borrowed slices and owned vectors of bytes as input.
    ///
    /// # Panics
    ///
    /// This function panics if there is an error initializing the underlying `libyml` parser.
    pub fn new(input: Cow<'input, [u8]>) -> Parser<'input> {
        let owned = Owned::<ParserPinned<'input>>::new_uninit();
        let pin = unsafe {
            let parser = addr_of_mut!((*owned.ptr).sys);
            if sys::yaml_parser_initialize(parser).fail {
                panic!(
                    "Failed to initialize YAML parser: {}",
                    Error::parse_error(parser)
                );
            }
            sys::yaml_parser_set_encoding(
                parser,
                sys::YamlUtf8Encoding,
            );
            sys::yaml_parser_set_input_string(
                parser,
                input.as_ptr(),
                input.len() as u64,
            );
            addr_of_mut!((*owned.ptr).input).write(input);
            Owned::assume_init(owned)
        };
        Parser { pin }
    }

    /// Parses the next YAML event from the input.
    ///
    /// Returns a `Result` containing the parsed `Event` and its corresponding `Mark` on success,
    /// or an `Error` if parsing fails.
    pub fn parse_next_event(
        &mut self,
    ) -> Result<(Event<'input>, Mark)> {
        let mut event = MaybeUninit::<sys::YamlEventT>::uninit();
        unsafe {
            let parser = addr_of_mut!((*self.pin.ptr).sys);
            if (*parser).error != sys::YamlNoError {
                return Err(Error::parse_error(parser));
            }
            let event = event.as_mut_ptr();
            if sys::yaml_parser_parse(parser, event).fail {
                return Err(Error::parse_error(parser));
            }

            let event_type = (*event).type_;

            // Handle specific cases
            if event_type == sys::YamlNoEvent
                || event_type == sys::YamlStreamEndEvent
            {
                let mark = Mark {
                    sys: (*event).start_mark,
                };
                sys::yaml_event_delete(event);
                return Ok((Event::StreamEnd, mark));
            }

            if event_type == sys::YamlScalarEvent
                && (*event).data.scalar.value.is_null()
            {
                let mark = Mark {
                    sys: (*event).start_mark,
                };
                sys::yaml_event_delete(event);
                return Ok((Event::StreamEnd, mark));
            }

            let ret = convert_event(&*event, &(*self.pin.ptr).input);
            let mark = Mark {
                sys: (*event).start_mark,
            };
            sys::yaml_event_delete(event);
            Ok((ret, mark))
        }
    }
    /// Checks if the parser is initialized and ready to parse YAML.
    ///
    /// This function returns `true` if the parser is initialized and ready to parse YAML, and `false` otherwise.
    pub fn is_ok(&self) -> bool {
        unsafe {
            let parser = addr_of_mut!((*self.pin.ptr).sys);
            if sys::yaml_parser_initialize(parser).fail {
                return false;
            }
            sys::yaml_parser_set_encoding(
                parser,
                sys::YamlUtf8Encoding,
            );
            let input_ptr = (*self.pin.ptr).input.as_ptr();
            let input_len = (*self.pin.ptr).input.len() as u64;
            sys::yaml_parser_set_input_string(
                parser, input_ptr, input_len,
            );
            true
        }
    }
}
unsafe fn convert_event<'input>(
    sys: &sys::YamlEventT,
    input: &'input Cow<'input, [u8]>,
) -> Event<'input> {
    match sys.type_ {
        sys::YamlStreamStartEvent => Event::StreamStart,
        sys::YamlStreamEndEvent => Event::StreamEnd,
        sys::YamlDocumentStartEvent => Event::DocumentStart,
        sys::YamlDocumentEndEvent => Event::DocumentEnd,
        sys::YamlAliasEvent => Event::Alias(
            optional_anchor(sys.data.alias.anchor).unwrap(),
        ),
        sys::YamlScalarEvent => {
            let value_slice = slice::from_raw_parts(
                sys.data.scalar.value,
                sys.data.scalar.length as usize,
            );
            let repr = optional_repr(sys, input);

            Event::Scalar(Scalar {
                anchor: optional_anchor(sys.data.scalar.anchor),
                tag: optional_tag(sys.data.scalar.tag),
                value: Box::from(value_slice),
                style: match sys.data.scalar.style {
                    sys::YamlScalarStyleT::YamlPlainScalarStyle => ScalarStyle::Plain,
                    sys::YamlScalarStyleT::YamlSingleQuotedScalarStyle => ScalarStyle::SingleQuoted,
                    sys::YamlScalarStyleT::YamlDoubleQuotedScalarStyle => ScalarStyle::DoubleQuoted,
                    sys::YamlScalarStyleT::YamlLiteralScalarStyle => ScalarStyle::Literal,
                    sys::YamlScalarStyleT::YamlFoldedScalarStyle => ScalarStyle::Folded,
                    _ => unreachable!(),
                },
                repr,
            })
        }
        sys::YamlSequenceStartEvent => {
            Event::SequenceStart(SequenceStart {
                anchor: optional_anchor(sys.data.sequence_start.anchor),
                tag: optional_tag(sys.data.sequence_start.tag),
            })
        }
        sys::YamlSequenceEndEvent => Event::SequenceEnd,
        sys::YamlMappingStartEvent => {
            Event::MappingStart(MappingStart {
                anchor: optional_anchor(sys.data.mapping_start.anchor),
                tag: optional_tag(sys.data.mapping_start.tag),
            })
        }
        sys::YamlMappingEndEvent => Event::MappingEnd,
        sys::YamlNoEvent => unreachable!(),
        _ => unreachable!(),
    }
}

unsafe fn optional_anchor(anchor: *const u8) -> Option<Anchor> {
    if anchor.is_null() {
        return None;
    }
    let ptr = NonNull::new(anchor as *mut i8)?;
    let cstr = CStr::from_ptr(ptr);
    Some(Anchor(Box::from(cstr.to_bytes())))
}

unsafe fn optional_tag(tag: *const u8) -> Option<Tag> {
    if tag.is_null() {
        return None;
    }
    let ptr = NonNull::new(tag as *mut i8)?;
    let cstr = CStr::from_ptr(ptr);
    Some(Tag(Box::from(cstr.to_bytes())))
}

unsafe fn optional_repr<'input>(
    sys: &sys::YamlEventT,
    input: &'input Cow<'input, [u8]>,
) -> Option<&'input [u8]> {
    let start = sys.start_mark.index as usize;
    let end = sys.end_mark.index as usize;
    Some(&input[start..end])
}

impl Debug for Scalar<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Scalar {
            anchor,
            tag,
            value,
            style,
            repr: _,
        } = self;

        struct LossySlice<'a>(&'a [u8]);

        impl Debug for LossySlice<'_> {
            fn fmt(
                &self,
                formatter: &mut fmt::Formatter<'_>,
            ) -> fmt::Result {
                safe_cstr::debug_lossy(self.0, formatter)
            }
        }

        formatter
            .debug_struct("Scalar")
            .field("anchor", anchor)
            .field("tag", tag)
            .field("value", &LossySlice(value))
            .field("style", style)
            .finish()
    }
}

impl Debug for Anchor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        safe_cstr::debug_lossy(&self.0, formatter)
    }
}

impl Drop for ParserPinned<'_> {
    fn drop(&mut self) {
        unsafe { sys::yaml_parser_delete(&mut self.sys) }
    }
}
