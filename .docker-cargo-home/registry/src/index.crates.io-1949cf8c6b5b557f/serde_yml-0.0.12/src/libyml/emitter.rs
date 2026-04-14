use crate::libyml::{self, util::Owned};
use ::libyml::api::ScalarEventData;
use ::libyml::document::{
    yaml_document_end_event_initialize,
    yaml_document_start_event_initialize,
};
use ::libyml::YamlEventT;
use ::libyml::YamlScalarStyleT::YamlLiteralScalarStyle;
use ::libyml::{
    yaml_emitter_delete, yaml_emitter_emit, yaml_emitter_flush,
    yaml_emitter_initialize, yaml_emitter_set_output,
    yaml_emitter_set_unicode, yaml_emitter_set_width,
    yaml_mapping_end_event_initialize,
    yaml_mapping_start_event_initialize, yaml_scalar_event_initialize,
    yaml_sequence_end_event_initialize,
    yaml_sequence_start_event_initialize,
    yaml_stream_end_event_initialize,
    yaml_stream_start_event_initialize, YamlAnyMappingStyle,
    YamlAnySequenceStyle, YamlEmitterT, YamlScalarStyleT,
    YamlSingleQuotedScalarStyle, YamlUtf8Encoding,
};
use std::fmt::Debug;
#[allow(clippy::unsafe_removed_from_name)]
use std::{
    ffi::c_void,
    io,
    mem::{self, MaybeUninit},
    ptr::{self, addr_of_mut},
    slice,
};

/// Errors that can occur during YAML emission.
#[derive(Debug)]
pub enum Error {
    /// Errors related to libyml.
    Libyml(libyml::error::Error),
    /// I/O errors.
    Io(io::Error),
}

/// A YAML emitter.
#[derive(Debug)]
pub struct Emitter<'a> {
    pin: Owned<EmitterPinned<'a>>,
}

/// Represents a pinned emitter for YAML serialization.
///
/// The `EmitterPinned` struct contains the necessary state and resources
/// for emitting YAML documents. It is pinned to a specific lifetime `'a`
/// to ensure that the `write` field remains valid throughout the lifetime
/// of the emitter.
///
/// # Fields
///
/// - `sys`: An instance of `YamlEmitterT` representing the underlying
///   emitter system.
/// - `write`: A boxed trait object implementing the `io::Write` trait,
///   used for writing the emitted YAML data. It is pinned to the lifetime
///   `'a` to ensure it remains valid for the duration of the emitter's
///   lifetime.
/// - `write_error`: An optional `io::Error` used to store any errors that
///   occur during the writing process.
///
/// # Lifetime
///
/// The `EmitterPinned` struct is parameterized by a lifetime `'a`, which
/// represents the lifetime of the `write` field. This ensures that the
/// `write` field remains valid for the entire lifetime of the `EmitterPinned`
/// instance.
pub struct EmitterPinned<'a> {
    sys: YamlEmitterT,
    write: Box<dyn io::Write + 'a>,
    write_error: Option<io::Error>,
}

impl Debug for EmitterPinned<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmitterPinned")
            .field("sys", &self.sys)
            .field("write_error", &self.write_error)
            .finish()
    }
}

/// YAML event types.
#[derive(Debug)]
pub enum Event<'a> {
    /// Start of a YAML stream.
    StreamStart,
    /// End of a YAML stream.
    StreamEnd,
    /// Start of a YAML document.
    DocumentStart,
    /// End of a YAML document.
    DocumentEnd,
    /// Scalar value.
    Scalar(Scalar<'a>),
    /// Start of a sequence.
    SequenceStart(Sequence),
    /// End of a sequence.
    SequenceEnd,
    /// Start of a mapping.
    MappingStart(Mapping),
    /// End of a mapping.
    MappingEnd,
}

/// Represents a scalar value in YAML.
#[derive(Debug)]
pub struct Scalar<'a> {
    /// Optional tag for the scalar.
    pub tag: Option<String>,
    /// Value of the scalar.
    pub value: &'a str,
    /// Style of the scalar.
    pub style: ScalarStyle,
}

/// Styles for YAML scalars.
#[derive(Clone, Copy, Debug)]
pub enum ScalarStyle {
    /// Any scalar style.
    Any,
    /// Double quoted scalar style.
    DoubleQuoted,
    /// Folded scalar style.
    Folded,
    /// Plain scalar style.
    Plain,
    /// Single quoted scalar style.
    SingleQuoted,
    /// Literal scalar style.
    Literal,
}

/// Represents a YAML sequence.
#[derive(Debug)]
pub struct Sequence {
    /// Optional tag for the sequence.
    pub tag: Option<String>,
}

/// Represents a YAML mapping.
#[derive(Debug)]
pub struct Mapping {
    /// Optional tag for the mapping.
    pub tag: Option<String>,
}

impl<'a> Emitter<'a> {
    /// Creates a new YAML emitter.
    pub fn new(write: Box<dyn io::Write + 'a>) -> Emitter<'a> {
        let owned = Owned::<EmitterPinned<'a>>::new_uninit();
        let pin = unsafe {
            let emitter = addr_of_mut!((*owned.ptr).sys);
            if yaml_emitter_initialize(emitter).fail {
                panic!(
                    "malloc error: {}",
                    libyml::Error::emit_error(emitter)
                );
            }
            yaml_emitter_set_unicode(emitter, true);
            yaml_emitter_set_width(emitter, -1);
            addr_of_mut!((*owned.ptr).write).write(write);
            addr_of_mut!((*owned.ptr).write_error).write(None);
            yaml_emitter_set_output(
                emitter,
                write_handler,
                owned.ptr.cast(),
            );
            Owned::assume_init(owned)
        };
        Emitter { pin }
    }

    /// Emits a YAML event.
    pub fn emit(&mut self, event: Event<'_>) -> Result<(), Error> {
        let mut sys_event = MaybeUninit::<YamlEventT>::uninit();
        let sys_event = sys_event.as_mut_ptr();
        unsafe {
            let emitter = addr_of_mut!((*self.pin.ptr).sys);
            let initialize_status = match event {
                Event::StreamStart => {
                    yaml_stream_start_event_initialize(
                        sys_event,
                        YamlUtf8Encoding,
                    )
                }
                Event::StreamEnd => {
                    yaml_stream_end_event_initialize(sys_event)
                }
                Event::DocumentStart => {
                    let version_directive = ptr::null_mut();
                    let tag_directives_start = ptr::null_mut();
                    let tag_directives_end = ptr::null_mut();
                    let implicit = true;
                    yaml_document_start_event_initialize(
                        sys_event,
                        version_directive,
                        tag_directives_start,
                        tag_directives_end,
                        implicit,
                    )
                }
                Event::DocumentEnd => {
                    let implicit = true;
                    yaml_document_end_event_initialize(
                        sys_event, implicit,
                    )
                }
                Event::Scalar(mut scalar) => {
                    let tag_ptr = scalar.tag.as_mut().map_or_else(
                        ptr::null,
                        |tag| {
                            tag.push('\0');
                            tag.as_ptr()
                        },
                    );
                    let value_ptr = scalar.value.as_ptr();
                    let length = scalar.value.len() as i32;
                    let plain_implicit = tag_ptr.is_null();
                    let quoted_implicit = tag_ptr.is_null();
                    let style = match scalar.style {
                        ScalarStyle::Any => {
                            YamlScalarStyleT::YamlAnyScalarStyle
                        }
                        ScalarStyle::DoubleQuoted => {
                            YamlScalarStyleT::YamlDoubleQuotedScalarStyle
                        }
                        ScalarStyle::Folded => {
                            YamlScalarStyleT::YamlFoldedScalarStyle
                        }
                        ScalarStyle::Plain => {
                            YamlScalarStyleT::YamlPlainScalarStyle
                        }
                        ScalarStyle::SingleQuoted => {
                            YamlSingleQuotedScalarStyle
                        }
                        ScalarStyle::Literal => YamlLiteralScalarStyle,
                    };
                    let event_data = ScalarEventData {
                        anchor: ptr::null(),
                        tag: tag_ptr,
                        value: value_ptr,
                        length,
                        plain_implicit,
                        quoted_implicit,
                        style,
                        _marker: core::marker::PhantomData,
                    };
                    yaml_scalar_event_initialize(sys_event, event_data)
                }
                Event::SequenceStart(mut sequence) => {
                    let tag_ptr = sequence.tag.as_mut().map_or_else(
                        ptr::null,
                        |tag| {
                            tag.push('\0');
                            tag.as_ptr()
                        },
                    );
                    let implicit = tag_ptr.is_null();
                    let style = YamlAnySequenceStyle;
                    yaml_sequence_start_event_initialize(
                        sys_event,
                        ptr::null(),
                        tag_ptr,
                        implicit,
                        style,
                    )
                }
                Event::SequenceEnd => {
                    yaml_sequence_end_event_initialize(sys_event)
                }
                Event::MappingStart(mut mapping) => {
                    let tag_ptr = mapping.tag.as_mut().map_or_else(
                        ptr::null,
                        |tag| {
                            tag.push('\0');
                            tag.as_ptr()
                        },
                    );
                    let implicit = tag_ptr.is_null();
                    let style = YamlAnyMappingStyle;
                    yaml_mapping_start_event_initialize(
                        sys_event,
                        ptr::null(),
                        tag_ptr,
                        implicit,
                        style,
                    )
                }
                Event::MappingEnd => {
                    yaml_mapping_end_event_initialize(sys_event)
                }
            };
            if initialize_status.fail {
                return Err(Error::Libyml(libyml::Error::emit_error(
                    emitter,
                )));
            }
            if yaml_emitter_emit(emitter, sys_event).fail {
                return Err(self.error());
            }
        }
        Ok(())
    }

    /// Flushes the YAML emitter.
    pub fn flush(&mut self) -> Result<(), Error> {
        unsafe {
            let emitter = addr_of_mut!((*self.pin.ptr).sys);
            if yaml_emitter_flush(emitter).fail {
                return Err(self.error());
            }
        }
        Ok(())
    }

    /// Retrieves the inner writer from the YAML emitter.
    #[allow(unused_mut)]
    pub fn into_inner(mut self) -> Box<dyn io::Write + 'a> {
        let sink = Box::new(io::sink());
        unsafe { mem::replace(&mut (*self.pin.ptr).write, sink) }
    }

    /// Retrieves the error from the YAML emitter.
    pub fn error(&mut self) -> Error {
        let emitter = unsafe { &mut *self.pin.ptr };
        if let Some(write_error) = emitter.write_error.take() {
            Error::Io(write_error)
        } else {
            Error::Libyml(unsafe {
                libyml::Error::emit_error(&emitter.sys)
            })
        }
    }
}

/// Writes data to a buffer using a provided callback function.
unsafe fn write_handler(
    data: *mut c_void,
    buffer: *mut u8,
    size: u64,
) -> i32 {
    let data = data.cast::<EmitterPinned<'_>>();
    match io::Write::write_all(unsafe { &mut *(*data).write }, unsafe {
        slice::from_raw_parts(buffer, size as usize)
    }) {
        Ok(()) => 1,
        Err(err) => {
            unsafe {
                (*data).write_error = Some(err);
            }
            0
        }
    }
}

impl Drop for EmitterPinned<'_> {
    /// Drops the YAML emitter, deallocating resources.
    fn drop(&mut self) {
        unsafe { yaml_emitter_delete(&mut self.sys) }
    }
}
