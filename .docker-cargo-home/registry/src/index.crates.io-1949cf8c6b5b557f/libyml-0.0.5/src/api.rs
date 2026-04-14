use crate::{
    externs::{memcpy, memset, strlen},
    internal::yaml_check_utf8,
    libc,
    memory::{yaml_free, yaml_malloc, yaml_strdup},
    ops::ForceAdd as _,
    success::{Success, FAIL, OK},
    yaml::{size_t, yaml_char_t},
    PointerExt, YamlAliasEvent, YamlAliasToken, YamlAnchorToken,
    YamlAnyEncoding, YamlBreakT, YamlEmitterStateT, YamlEmitterT,
    YamlEncodingT, YamlEventT,
    YamlEventTypeT::{
        YamlDocumentStartEvent, YamlScalarEvent, YamlStreamEndEvent,
    },
    YamlMappingEndEvent, YamlMappingStartEvent, YamlMappingStyleT,
    YamlMarkT, YamlParserT, YamlReadHandlerT, YamlScalarStyleT,
    YamlScalarToken, YamlSequenceEndEvent, YamlSequenceStartEvent,
    YamlSequenceStyleT, YamlStreamStartEvent, YamlTagDirectiveT,
    YamlTagDirectiveToken, YamlTagToken, YamlTokenT, YamlWriteHandlerT,
};
use core::{
    mem::size_of,
    ptr::{self, addr_of_mut},
};

const OUTPUT_BUFFER_SIZE: usize = 16384;
const OUTPUT_RAW_BUFFER_SIZE: usize = OUTPUT_BUFFER_SIZE * 2 + 2;

unsafe fn yaml_string_read_handler(
    data: *mut libc::c_void,
    buffer: *mut libc::c_uchar,
    mut size: size_t,
    size_read: *mut size_t,
) -> libc::c_int {
    let parser: *mut YamlParserT = data as *mut YamlParserT;
    if (*parser).input.string.current == (*parser).input.string.end {
        *size_read = 0_u64;
        return 1;
    }
    if size
        > (*parser)
            .input
            .string
            .end
            .c_offset_from((*parser).input.string.current)
            as size_t
    {
        size = (*parser)
            .input
            .string
            .end
            .c_offset_from((*parser).input.string.current)
            as size_t;
    }
    let _ = memcpy(
        buffer as *mut libc::c_void,
        (*parser).input.string.current as *const libc::c_void,
        size,
    );
    let fresh80 = addr_of_mut!((*parser).input.string.current);
    *fresh80 = (*fresh80).wrapping_offset(size as isize);
    *size_read = size;
    1
}

/// Set a string input.
///
/// This function sets the input source for the parser to a string buffer.
/// Note that the `input` pointer must be valid while the `parser` object
/// exists. The application is responsible for destroying `input` after
/// destroying the `parser`.
///
/// # Safety
///
/// - `parser` must be a valid, non-null pointer to a properly initialized `YamlParserT` struct.
/// - The `YamlParserT` struct must not have an input handler already set.
/// - `input` must be a valid, non-null pointer to a null-terminated string buffer.
/// - The `input` string buffer must remain valid and unmodified until the `parser` object is destroyed.
/// - The `YamlParserT` struct and its associated data structures must be properly aligned and have the expected memory layout.
///
pub unsafe fn yaml_parser_set_input_string(
    parser: *mut YamlParserT,
    input: *const libc::c_uchar,
    size: size_t,
) {
    assert!(!parser.is_null());
    assert!((*parser).read_handler.is_none());
    assert!(!input.is_null());

    (*parser).read_handler = Some(yaml_string_read_handler);
    (*parser).read_handler_data = parser as *mut libc::c_void;
    (*parser).input.string.start = input;
    (*parser).input.string.current = input;
    (*parser).input.string.end = input.wrapping_offset(size as isize);
}

/// Set a generic input handler.
///
/// This function sets a custom input handler for the parser.
///
/// # Safety
///
/// - `parser` must be a valid, non-null pointer to a properly initialized `YamlParserT` struct.
/// - The `YamlParserT` struct must not have an input handler already set.
/// - `handler` must be a valid function pointer that follows the signature of `YamlReadHandlerT`.
/// - `data` must be a valid pointer that will be passed to the `handler` function.
/// - The `YamlParserT` struct and its associated data structures must be properly aligned and have the expected memory layout.
///
pub unsafe fn yaml_parser_set_input(
    parser: *mut YamlParserT,
    handler: YamlReadHandlerT,
    data: *mut libc::c_void,
) {
    __assert!(!parser.is_null());
    __assert!(((*parser).read_handler).is_none());
    let fresh89 = addr_of_mut!((*parser).read_handler);
    *fresh89 = Some(handler);
    let fresh90 = addr_of_mut!((*parser).read_handler_data);
    *fresh90 = data;
}

/// Set the source encoding.
///
/// This function sets the expected encoding of the input source for the parser.
///
/// # Safety
///
/// - `parser` must be a valid, non-null pointer to a properly initialized `YamlParserT` struct.
/// - The `YamlParserT` struct must not have an encoding already set, or the encoding must be `YamlAnyEncoding`.
/// - The `YamlParserT` struct and its associated data structures must be properly aligned and have the expected memory layout.
///
pub unsafe fn yaml_parser_set_encoding(
    parser: *mut YamlParserT,
    encoding: YamlEncodingT,
) {
    __assert!(!parser.is_null());
    __assert!((*parser).encoding == YamlAnyEncoding);
    (*parser).encoding = encoding;
}

/// Initialize an emitter.
///
/// This function creates a new emitter object. An application is responsible
/// for destroying the object using the yaml_emitter_delete() function.
///
/// # Safety
///
/// - `emitter` must be a valid, non-null pointer to an uninitialized `YamlEmitterT` struct.
/// - The `YamlEmitterT` struct must be properly aligned and have the expected memory layout.
/// - The caller is responsible for properly destroying the emitter object using `yaml_emitter_delete`.
///
pub unsafe fn yaml_emitter_initialize(
    emitter: *mut YamlEmitterT,
) -> Success {
    __assert!(!emitter.is_null());
    let _ = memset(
        emitter as *mut libc::c_void,
        0,
        size_of::<YamlEmitterT>() as libc::c_ulong,
    );
    BUFFER_INIT!((*emitter).buffer, OUTPUT_BUFFER_SIZE);
    BUFFER_INIT!((*emitter).raw_buffer, OUTPUT_RAW_BUFFER_SIZE);
    STACK_INIT!((*emitter).states, YamlEmitterStateT);
    QUEUE_INIT!((*emitter).events, YamlEventT);
    STACK_INIT!((*emitter).indents, libc::c_int);
    STACK_INIT!((*emitter).tag_directives, YamlTagDirectiveT);
    OK
}

/// Destroy an emitter.
///
/// This function frees all memory associated with an emitter object, including
/// any dynamically allocated buffers, events, and other data structures.
///
/// # Safety
///
/// - `emitter` must be a valid, non-null pointer to a properly initialized `YamlEmitterT` struct.
/// - The `YamlEmitterT` struct and its associated data structures must have been properly initialized and their memory allocated correctly.
/// - The `YamlEmitterT` struct and its associated data structures must be properly aligned and have the expected memory layout.
/// - After calling this function, the `emitter` pointer should be considered invalid and should not be used again.
///
pub unsafe fn yaml_emitter_delete(emitter: *mut YamlEmitterT) {
    __assert!(!emitter.is_null());
    BUFFER_DEL!((*emitter).buffer);
    BUFFER_DEL!((*emitter).raw_buffer);
    STACK_DEL!((*emitter).states);
    while !QUEUE_EMPTY!((*emitter).events) {
        yaml_event_delete(addr_of_mut!(DEQUEUE!((*emitter).events)));
    }
    QUEUE_DEL!((*emitter).events);
    STACK_DEL!((*emitter).indents);
    while !STACK_EMPTY!((*emitter).tag_directives) {
        let tag_directive = POP!((*emitter).tag_directives);
        yaml_free(tag_directive.handle as *mut libc::c_void);
        yaml_free(tag_directive.prefix as *mut libc::c_void);
    }
    STACK_DEL!((*emitter).tag_directives);
    yaml_free((*emitter).anchors as *mut libc::c_void);
    let _ = memset(
        emitter as *mut libc::c_void,
        0,
        size_of::<YamlEmitterT>() as libc::c_ulong,
    );
}

unsafe fn yaml_string_write_handler(
    data: *mut libc::c_void,
    buffer: *mut libc::c_uchar,
    size: size_t,
) -> libc::c_int {
    let emitter: *mut YamlEmitterT = data as *mut YamlEmitterT;
    if (*emitter)
        .output
        .string
        .size
        .wrapping_sub(*(*emitter).output.string.size_written)
        < size
    {
        let _ =
            memcpy(
                (*emitter).output.string.buffer.wrapping_offset(
                    *(*emitter).output.string.size_written as isize,
                ) as *mut libc::c_void,
                buffer as *const libc::c_void,
                (*emitter).output.string.size.wrapping_sub(
                    *(*emitter).output.string.size_written,
                ),
            );
        *(*emitter).output.string.size_written =
            (*emitter).output.string.size;
        return 0;
    }
    let _ = memcpy(
        (*emitter).output.string.buffer.wrapping_offset(
            *(*emitter).output.string.size_written as isize,
        ) as *mut libc::c_void,
        buffer as *const libc::c_void,
        size,
    );
    let fresh153 =
        addr_of_mut!((*(*emitter).output.string.size_written));
    *fresh153 = (*fresh153).wrapping_add(size);
    1
}

/// Set a string output.
///
/// This function sets the output destination for the emitter to a string buffer.
/// The emitter will write the output characters to the `output` buffer of the
/// specified `size`. The emitter will set `size_written` to the number of written
/// bytes. If the buffer is smaller than required, the emitter produces the
/// YAML_write_ERROR error.
///
/// # Safety
///
/// - `emitter` must be a valid, non-null pointer to a properly initialized `YamlEmitterT` struct.
/// - The `YamlEmitterT` struct must not have an output handler already set.
/// - `output` must be a valid, non-null pointer to a writeable buffer of size `size`.
/// - `size_written` must be a valid, non-null pointer to a `size_t` variable.
/// - The `output` buffer must remain valid and unmodified until the emitter is destroyed or the output is reset.
/// - The `YamlEmitterT` struct and its associated data structures must be properly aligned and have the expected memory layout.
///
pub unsafe fn yaml_emitter_set_output_string(
    emitter: *mut YamlEmitterT,
    output: *mut libc::c_uchar,
    size: size_t,
    size_written: *mut size_t,
) {
    assert!(!emitter.is_null());
    assert!((*emitter).write_handler.is_none());
    assert!(!output.is_null());

    (*emitter).write_handler = Some(yaml_string_write_handler);
    (*emitter).write_handler_data = emitter as *mut libc::c_void;
    (*emitter).output.string.buffer = output;
    (*emitter).output.string.size = size;
    *size_written = 0;
}

/// Set a generic output handler.
///
/// This function sets a custom output handler for the emitter.
///
/// # Safety
///
/// - `emitter` must be a valid, non-null pointer to a properly initialized `YamlEmitterT` struct.
/// - The `YamlEmitterT` struct must not have an output handler already set.
/// - `handler` must be a valid function pointer that follows the signature of `YamlWriteHandlerT`.
/// - `data` must be a valid pointer that will be passed to the `handler` function.
/// - The `YamlEmitterT` struct and its associated data structures must be properly aligned and have the expected memory layout.
///
pub unsafe fn yaml_emitter_set_output(
    emitter: *mut YamlEmitterT,
    handler: YamlWriteHandlerT,
    data: *mut libc::c_void,
) {
    __assert!(!emitter.is_null());
    __assert!(((*emitter).write_handler).is_none());
    let fresh161 = addr_of_mut!((*emitter).write_handler);
    *fresh161 = Some(handler);
    let fresh162 = addr_of_mut!((*emitter).write_handler_data);
    *fresh162 = data;
}

/// Set the output encoding.
///
/// This function sets the encoding to be used for the output by the emitter.
///
/// # Safety
///
/// - `emitter` must be a valid, non-null pointer to a properly initialized `YamlEmitterT` struct.
/// - The `YamlEmitterT` struct must not have an encoding already set, or the encoding must be `YamlAnyEncoding`.
/// - The `YamlEmitterT` struct and its associated data structures must be properly aligned and have the expected memory layout.
///
pub unsafe fn yaml_emitter_set_encoding(
    emitter: *mut YamlEmitterT,
    encoding: YamlEncodingT,
) {
    __assert!(!emitter.is_null());
    __assert!((*emitter).encoding == YamlAnyEncoding);
    (*emitter).encoding = encoding;
}

/// Set if the output should be in the "canonical" format as in the YAML
/// specification.
///
/// This function sets whether the emitter should produce output in the canonical
/// format, as defined by the YAML specification.
///
/// # Safety
///
/// - `emitter` must be a valid, non-null pointer to a properly initialized `YamlEmitterT` struct.
/// - The `YamlEmitterT` struct and its associated data structures must be properly aligned and have the expected memory layout.
///
pub unsafe fn yaml_emitter_set_canonical(
    emitter: *mut YamlEmitterT,
    canonical: bool,
) {
    __assert!(!emitter.is_null());
    (*emitter).canonical = canonical;
}

/// Set the indentation increment.
///
/// This function sets the indentation increment to be used by the emitter when
/// emitting indented content.
///
/// # Safety
///
/// - `emitter` must be a valid, non-null pointer to a properly initialized `YamlEmitterT` struct.
/// - The `YamlEmitterT` struct and its associated data structures must be properly aligned and have the expected memory layout.
///
pub unsafe fn yaml_emitter_set_indent(
    emitter: *mut YamlEmitterT,
    indent: libc::c_int,
) {
    __assert!(!emitter.is_null());
    (*emitter).best_indent =
        if 1 < indent && indent < 10 { indent } else { 2 };
}

/// Set the preferred line width. -1 means unlimited.
///
/// This function sets the preferred line width for the emitter's output.
/// A value of -1 means that the line width is unlimited.
///
/// # Safety
///
/// - `emitter` must be a valid, non-null pointer to a properly initialized `YamlEmitterT` struct.
/// - The `YamlEmitterT` struct and its associated data structures must be properly aligned and have the expected memory layout.
///
pub unsafe fn yaml_emitter_set_width(
    emitter: *mut YamlEmitterT,
    width: libc::c_int,
) {
    __assert!(!emitter.is_null());
    (*emitter).best_width = if width >= 0 { width } else { -1 };
}

/// Set if unescaped non-ASCII characters are allowed.
///
/// This function sets whether the emitter should allow unescaped non-ASCII
/// characters in its output.
///
/// # Safety
///
/// - `emitter` must be a valid, non-null pointer to a properly initialized `YamlEmitterT` struct.
/// - The `YamlEmitterT` struct and its associated data structures must be properly aligned and have the expected memory layout.
///
pub unsafe fn yaml_emitter_set_unicode(
    emitter: *mut YamlEmitterT,
    unicode: bool,
) {
    __assert!(!emitter.is_null());
    (*emitter).unicode = unicode;
}

/// Set the preferred line break.
///
/// This function sets the preferred line break character to be used by the emitter.
///
/// # Safety
///
/// - `emitter` must be a valid, non-null pointer to a properly initialized `YamlEmitterT` struct.
/// - The `YamlEmitterT` struct and its associated data structures must be properly aligned and have the expected memory layout.
///
pub unsafe fn yaml_emitter_set_break(
    emitter: *mut YamlEmitterT,
    line_break: YamlBreakT,
) {
    __assert!(!emitter.is_null());
    (*emitter).line_break = line_break;
}

/// Free any memory allocated for a token object.
///
/// This function frees the dynamically allocated memory associated with a `YamlTokenT` struct,
/// such as strings for tag directives, aliases, anchors, tags, and scalar values.
///
/// # Safety
///
/// - `token` must be a valid, non-null pointer to a `YamlTokenT` struct.
/// - The `YamlTokenT` struct must have been properly initialized and its memory allocated correctly.
/// - The `YamlTokenT` struct must be properly aligned and have the expected memory layout.
///
pub unsafe fn yaml_token_delete(token: *mut YamlTokenT) {
    __assert!(!token.is_null());
    match (*token).type_ {
        YamlTagDirectiveToken => {
            yaml_free(
                (*token).data.tag_directive.handle as *mut libc::c_void,
            );
            yaml_free(
                (*token).data.tag_directive.prefix as *mut libc::c_void,
            );
        }
        YamlAliasToken => {
            yaml_free((*token).data.alias.value as *mut libc::c_void);
        }
        YamlAnchorToken => {
            yaml_free((*token).data.anchor.value as *mut libc::c_void);
        }
        YamlTagToken => {
            yaml_free((*token).data.tag.handle as *mut libc::c_void);
            yaml_free((*token).data.tag.suffix as *mut libc::c_void);
        }
        YamlScalarToken => {
            yaml_free((*token).data.scalar.value as *mut libc::c_void);
        }
        _ => {}
    }
    let _ = memset(
        token as *mut libc::c_void,
        0,
        size_of::<YamlTokenT>() as libc::c_ulong,
    );
}

/// Create the STREAM-START event.
///
/// This function initializes a `YamlEventT` struct with the type `YamlStreamStartEvent`.
/// It is used to signal the start of a YAML stream being emitted.
///
/// # Safety
///
/// - `event` must be a valid, non-null pointer to a `YamlEventT` struct that can be safely written to.
/// - The `YamlEventT` struct must be properly aligned and have the expected memory layout.
///
pub unsafe fn yaml_stream_start_event_initialize(
    event: *mut YamlEventT,
    encoding: YamlEncodingT,
) -> Success {
    let mark = YamlMarkT {
        index: 0_u64,
        line: 0_u64,
        column: 0_u64,
    };
    __assert!(!event.is_null());
    let _ = memset(
        event as *mut libc::c_void,
        0,
        size_of::<YamlEventT>() as libc::c_ulong,
    );
    (*event).type_ = YamlStreamStartEvent;
    (*event).start_mark = mark;
    (*event).end_mark = mark;
    (*event).data.stream_start.encoding = encoding;
    OK
}

/// Create the STREAM-END event.
///
/// This function initializes a `YamlEventT` struct with the type `YamlStreamEndEvent`.
/// It is used to signal the end of a YAML stream being emitted.
///
/// # Safety
///
/// - `event` must be a valid, non-null pointer to a `YamlEventT` struct that can be safely written to.
/// - The `YamlEventT` struct must be properly aligned and have the expected memory layout.
///
pub unsafe fn yaml_stream_end_event_initialize(
    event: *mut YamlEventT,
) -> Success {
    let mark = YamlMarkT {
        index: 0_u64,
        line: 0_u64,
        column: 0_u64,
    };
    __assert!(!event.is_null());
    let _ = memset(
        event as *mut libc::c_void,
        0,
        size_of::<YamlEventT>() as libc::c_ulong,
    );
    (*event).type_ = YamlStreamEndEvent;
    (*event).start_mark = mark;
    (*event).end_mark = mark;
    OK
}

/// Create an ALIAS event.
///
/// # Safety
///
/// - `event` must be a valid, non-null pointer to a `YamlEventT` struct that can be safely written to.
/// - `anchor` must be a valid, non-null pointer to a null-terminated UTF-8 string.
/// - The `YamlEventT` struct must be properly aligned and have the expected memory layout.
/// - The caller is responsible for freeing any dynamically allocated memory associated with the event using `yaml_event_delete`.
///
pub unsafe fn yaml_alias_event_initialize(
    event: *mut YamlEventT,
    anchor: *const yaml_char_t,
) -> Success {
    let mark = YamlMarkT {
        index: 0_u64,
        line: 0_u64,
        column: 0_u64,
    };
    __assert!(!event.is_null());
    __assert!(!anchor.is_null());
    if yaml_check_utf8(anchor, strlen(anchor as *mut libc::c_char)).fail
    {
        return FAIL;
    }
    let anchor_copy: *mut yaml_char_t = yaml_strdup(anchor);
    if anchor_copy.is_null() {
        return FAIL;
    }
    let _ = memset(
        event as *mut libc::c_void,
        0,
        size_of::<YamlEventT>() as libc::c_ulong,
    );
    (*event).type_ = YamlAliasEvent;
    (*event).start_mark = mark;
    (*event).end_mark = mark;
    let fresh167 = addr_of_mut!((*event).data.alias.anchor);
    *fresh167 = anchor_copy;
    OK
}

/// Create a SCALAR event.
///
/// The `style` argument may be ignored by the emitter.
///
/// Either the `tag` attribute or one of the `plain_implicit` and
/// `quoted_implicit` flags must be set.
///
/// # Safety
///
/// - `event` must be a valid, non-null pointer to a `YamlEventT` struct that can be safely written to.
/// - `data.value` must be a valid, non-null pointer to a null-terminated UTF-8 string.
/// - `data.anchor`, if not null, must be a valid pointer to a null-terminated UTF-8 string.
/// - `data.tag`, if not null, must be a valid pointer to a null-terminated UTF-8 string.
/// - The `YamlEventT` struct must be properly aligned and have the expected memory layout.
/// - The caller is responsible for freeing any dynamically allocated memory associated with the event using `yaml_event_delete`.
///
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct ScalarEventData<'a> {
    /// Anchor name or null.
    pub anchor: *const yaml_char_t,
    /// Tag or null.
    pub tag: *const yaml_char_t,
    /// Value.
    pub value: *const yaml_char_t,
    /// Value length.
    pub length: libc::c_int,
    /// Is the tag optional for the plain style?
    pub plain_implicit: bool,
    /// Is the tag optional for any non-plain style?
    pub quoted_implicit: bool,
    /// Scalar style.
    pub style: YamlScalarStyleT,
    /// Lifetime marker.
    pub _marker: core::marker::PhantomData<&'a ()>,
}

/// Create a SCALAR event.
///
/// The `style` argument may be ignored by the emitter.
///
/// Either the `tag` attribute or one of the `plain_implicit` and
/// `quoted_implicit` flags must be set.
///
/// # Safety
///
/// - `event` must be a valid, non-null pointer to a `YamlEventT` struct that can be safely written to.
/// - `value` must be a valid, non-null pointer to a null-terminated UTF-8 string.
/// - `anchor`, if not null, must be a valid pointer to a null-terminated UTF-8 string.
/// - `tag`, if not null, must be a valid pointer to a null-terminated UTF-8 string.
/// - The `YamlEventT` struct must be properly aligned and have the expected memory layout.
/// - The caller is responsible for freeing any dynamically allocated memory associated with the event using `yaml_event_delete`.
///
pub unsafe fn yaml_scalar_event_initialize(
    event: *mut YamlEventT,
    mut data: ScalarEventData<'_>,
) -> Success {
    let mut current_block: u64;
    let mark = YamlMarkT {
        index: 0_u64,
        line: 0_u64,
        column: 0_u64,
    };
    let mut anchor_copy: *mut yaml_char_t =
        ptr::null_mut::<yaml_char_t>();
    let mut tag_copy: *mut yaml_char_t = ptr::null_mut::<yaml_char_t>();
    let mut value_copy: *mut yaml_char_t =
        ptr::null_mut::<yaml_char_t>();

    __assert!(!event.is_null());
    __assert!(!data.value.is_null());

    if !data.anchor.is_null() {
        if yaml_check_utf8(
            data.anchor,
            strlen(data.anchor as *mut libc::c_char),
        )
        .fail
        {
            current_block = 16285396129609901221;
        } else {
            anchor_copy = yaml_strdup(data.anchor);
            if anchor_copy.is_null() {
                current_block = 16285396129609901221;
            } else {
                current_block = 8515828400728868193;
            }
        }
    } else {
        current_block = 8515828400728868193;
    }

    if current_block == 8515828400728868193 {
        if !data.tag.is_null() {
            if yaml_check_utf8(
                data.tag,
                strlen(data.tag as *mut libc::c_char),
            )
            .fail
            {
                current_block = 16285396129609901221;
            } else {
                tag_copy = yaml_strdup(data.tag);
                if tag_copy.is_null() {
                    current_block = 16285396129609901221;
                } else {
                    current_block = 12800627514080957624;
                }
            }
        } else {
            current_block = 12800627514080957624;
        }

        if current_block != 16285396129609901221 {
            if data.length < 0 {
                data.length = strlen(data.value as *mut libc::c_char)
                    as libc::c_int;
            }

            if yaml_check_utf8(data.value, data.length as size_t).ok {
                value_copy =
                    yaml_malloc(data.length.force_add(1) as size_t)
                        as *mut yaml_char_t;
                let _ = memcpy(
                    value_copy as *mut libc::c_void,
                    data.value as *const libc::c_void,
                    data.length as libc::c_ulong,
                );
                *value_copy.wrapping_offset(data.length as isize) =
                    b'\0';
                let _ = memset(
                    event as *mut libc::c_void,
                    0,
                    size_of::<YamlEventT>() as libc::c_ulong,
                );
                (*event).type_ = YamlScalarEvent;
                (*event).start_mark = mark;
                (*event).end_mark = mark;
                let fresh168 =
                    addr_of_mut!((*event).data.scalar.anchor);
                *fresh168 = anchor_copy;
                let fresh169 = addr_of_mut!((*event).data.scalar.tag);
                *fresh169 = tag_copy;
                let fresh170 = addr_of_mut!((*event).data.scalar.value);
                *fresh170 = value_copy;
                (*event).data.scalar.length = data.length as size_t;
                (*event).data.scalar.plain_implicit =
                    data.plain_implicit;
                (*event).data.scalar.quoted_implicit =
                    data.quoted_implicit;
                (*event).data.scalar.style = data.style;
                return OK;
            }
        }
    }

    yaml_free(anchor_copy as *mut libc::c_void);
    yaml_free(tag_copy as *mut libc::c_void);
    yaml_free(value_copy as *mut libc::c_void);
    FAIL
}

/// Create a SEQUENCE-START event.
///
/// The `style` argument may be ignored by the emitter.
///
/// Either the `tag` attribute or the `implicit` flag must be set.
///
/// # Safety
///
/// - `event` must be a valid, non-null pointer to a `YamlEventT` struct that can be safely written to.
/// - `anchor`, if not null, must be a valid pointer to a null-terminated UTF-8 string.
/// - `tag`, if not null, must be a valid pointer to a null-terminated UTF-8 string.
/// - The `YamlEventT` struct must be properly aligned and have the expected memory layout.
/// - The caller is responsible for freeing any dynamically allocated memory associated with the event using `yaml_event_delete`.
///
pub unsafe fn yaml_sequence_start_event_initialize(
    event: *mut YamlEventT,
    anchor: *const yaml_char_t,
    tag: *const yaml_char_t,
    implicit: bool,
    style: YamlSequenceStyleT,
) -> Success {
    let mut current_block: u64;
    let mark = YamlMarkT {
        index: 0_u64,
        line: 0_u64,
        column: 0_u64,
    };
    let mut anchor_copy: *mut yaml_char_t =
        ptr::null_mut::<yaml_char_t>();
    let mut tag_copy: *mut yaml_char_t = ptr::null_mut::<yaml_char_t>();
    __assert!(!event.is_null());
    if !anchor.is_null() {
        if yaml_check_utf8(anchor, strlen(anchor as *mut libc::c_char))
            .fail
        {
            current_block = 8817775685815971442;
        } else {
            anchor_copy = yaml_strdup(anchor);
            if anchor_copy.is_null() {
                current_block = 8817775685815971442;
            } else {
                current_block = 11006700562992250127;
            }
        }
    } else {
        current_block = 11006700562992250127;
    }
    if current_block == 11006700562992250127 {
        if !tag.is_null() {
            if yaml_check_utf8(tag, strlen(tag as *mut libc::c_char))
                .fail
            {
                current_block = 8817775685815971442;
            } else {
                tag_copy = yaml_strdup(tag);
                if tag_copy.is_null() {
                    current_block = 8817775685815971442;
                } else {
                    current_block = 7651349459974463963;
                }
            }
        } else {
            current_block = 7651349459974463963;
        }
        if current_block != 8817775685815971442 {
            let _ = memset(
                event as *mut libc::c_void,
                0,
                size_of::<YamlEventT>() as libc::c_ulong,
            );
            (*event).type_ = YamlSequenceStartEvent;
            (*event).start_mark = mark;
            (*event).end_mark = mark;
            let fresh171 =
                addr_of_mut!((*event).data.sequence_start.anchor);
            *fresh171 = anchor_copy;
            let fresh172 =
                addr_of_mut!((*event).data.sequence_start.tag);
            *fresh172 = tag_copy;
            (*event).data.sequence_start.implicit = implicit;
            (*event).data.sequence_start.style = style;
            return OK;
        }
    }
    yaml_free(anchor_copy as *mut libc::c_void);
    yaml_free(tag_copy as *mut libc::c_void);
    FAIL
}

/// Create a SEQUENCE-END event.
///
/// This function initializes a `YamlEventT` struct with the type `YamlSequenceEndEvent`.
/// It is used to signal the end of a sequence in the YAML document being emitted.
///
/// # Safety
///
/// - `event` must be a valid, non-null pointer to a `YamlEventT` struct that can be safely written to.
/// - The `YamlEventT` struct must be properly aligned and have the expected memory layout.
///
pub unsafe fn yaml_sequence_end_event_initialize(
    event: *mut YamlEventT,
) -> Success {
    let mark = YamlMarkT {
        index: 0_u64,
        line: 0_u64,
        column: 0_u64,
    };
    __assert!(!event.is_null());
    let _ = memset(
        event as *mut libc::c_void,
        0,
        size_of::<YamlEventT>() as libc::c_ulong,
    );
    (*event).type_ = YamlSequenceEndEvent;
    (*event).start_mark = mark;
    (*event).end_mark = mark;
    OK
}

/// Create a MAPPING-START event.
///
/// This function initializes a `YamlEventT` struct with the type `YamlMappingStartEvent`.
/// It is used to signal the start of a mapping (key-value pairs) in the YAML document being emitted.
///
/// The `style` argument may be ignored by the emitter.
///
/// Either the `tag` attribute or the `implicit` flag must be set.
///
/// # Safety
///
/// - `event` must be a valid, non-null pointer to a `YamlEventT` struct that can be safely written to.
/// - `anchor`, if not null, must be a valid pointer to a null-terminated UTF-8 string.
/// - `tag`, if not null, must be a valid pointer to a null-terminated UTF-8 string.
/// - The `YamlEventT` struct must be properly aligned and have the expected memory layout.
/// - The caller is responsible for freeing any dynamically allocated memory associated with the event using `yaml_event_delete`.
///
pub unsafe fn yaml_mapping_start_event_initialize(
    event: *mut YamlEventT,
    anchor: *const yaml_char_t,
    tag: *const yaml_char_t,
    implicit: bool,
    style: YamlMappingStyleT,
) -> Success {
    let mut current_block: u64;
    let mark = YamlMarkT {
        index: 0_u64,
        line: 0_u64,
        column: 0_u64,
    };
    let mut anchor_copy: *mut yaml_char_t =
        ptr::null_mut::<yaml_char_t>();
    let mut tag_copy: *mut yaml_char_t = ptr::null_mut::<yaml_char_t>();
    __assert!(!event.is_null());
    if !anchor.is_null() {
        if yaml_check_utf8(anchor, strlen(anchor as *mut libc::c_char))
            .fail
        {
            current_block = 14748279734549812740;
        } else {
            anchor_copy = yaml_strdup(anchor);
            if anchor_copy.is_null() {
                current_block = 14748279734549812740;
            } else {
                current_block = 11006700562992250127;
            }
        }
    } else {
        current_block = 11006700562992250127;
    }
    if current_block == 11006700562992250127 {
        if !tag.is_null() {
            if yaml_check_utf8(tag, strlen(tag as *mut libc::c_char))
                .fail
            {
                current_block = 14748279734549812740;
            } else {
                tag_copy = yaml_strdup(tag);
                if tag_copy.is_null() {
                    current_block = 14748279734549812740;
                } else {
                    current_block = 7651349459974463963;
                }
            }
        } else {
            current_block = 7651349459974463963;
        }
        if current_block != 14748279734549812740 {
            let _ = memset(
                event as *mut libc::c_void,
                0,
                size_of::<YamlEventT>() as libc::c_ulong,
            );
            (*event).type_ = YamlMappingStartEvent;
            (*event).start_mark = mark;
            (*event).end_mark = mark;
            let fresh173 =
                addr_of_mut!((*event).data.mapping_start.anchor);
            *fresh173 = anchor_copy;
            let fresh174 =
                addr_of_mut!((*event).data.mapping_start.tag);
            *fresh174 = tag_copy;
            (*event).data.mapping_start.implicit = implicit;
            (*event).data.mapping_start.style = style;
            return OK;
        }
    }
    yaml_free(anchor_copy as *mut libc::c_void);
    yaml_free(tag_copy as *mut libc::c_void);
    FAIL
}

/// Create a MAPPING-END event.
///
/// This function initializes a `YamlEventT` struct with the type `YamlMappingEndEvent`.
/// It is used to signal the end of a mapping (key-value pairs) in the YAML document being emitted.
///
/// # Safety
///
/// - `event` must be a valid, non-null pointer to a `YamlEventT` struct that can be safely written to.
/// - The `YamlEventT` struct must be properly aligned and have the expected memory layout.
///
pub unsafe fn yaml_mapping_end_event_initialize(
    event: *mut YamlEventT,
) -> Success {
    let mark = YamlMarkT {
        index: 0_u64,
        line: 0_u64,
        column: 0_u64,
    };
    __assert!(!event.is_null());
    let _ = memset(
        event as *mut libc::c_void,
        0,
        size_of::<YamlEventT>() as libc::c_ulong,
    );
    (*event).type_ = YamlMappingEndEvent;
    (*event).start_mark = mark;
    (*event).end_mark = mark;
    OK
}

/// Free any memory allocated for an event object.
///
/// This function frees the dynamically allocated memory associated with a `YamlEventT` struct,
/// such as strings for anchors, tags, and scalar values.
///
/// # Safety
///
/// - `event` must be a valid, non-null pointer to a `YamlEventT` struct.
/// - The `YamlEventT` struct must have been properly initialized and its memory allocated correctly.
/// - The `YamlEventT` struct must be properly aligned and have the expected memory layout.
///
pub unsafe fn yaml_event_delete(event: *mut YamlEventT) {
    let mut tag_directive: *mut YamlTagDirectiveT;
    __assert!(!event.is_null());
    match (*event).type_ {
        YamlDocumentStartEvent => {
            yaml_free(
                (*event).data.document_start.version_directive
                    as *mut libc::c_void,
            );
            tag_directive =
                (*event).data.document_start.tag_directives.start;
            while tag_directive
                != (*event).data.document_start.tag_directives.end
            {
                yaml_free((*tag_directive).handle as *mut libc::c_void);
                yaml_free((*tag_directive).prefix as *mut libc::c_void);
                tag_directive = tag_directive.wrapping_offset(1);
            }
            yaml_free(
                (*event).data.document_start.tag_directives.start
                    as *mut libc::c_void,
            );
        }
        YamlAliasEvent => {
            yaml_free((*event).data.alias.anchor as *mut libc::c_void);
        }
        YamlScalarEvent => {
            yaml_free((*event).data.scalar.anchor as *mut libc::c_void);
            yaml_free((*event).data.scalar.tag as *mut libc::c_void);
            yaml_free((*event).data.scalar.value as *mut libc::c_void);
        }
        YamlSequenceStartEvent => {
            yaml_free(
                (*event).data.sequence_start.anchor
                    as *mut libc::c_void,
            );
            yaml_free(
                (*event).data.sequence_start.tag as *mut libc::c_void,
            );
        }
        YamlMappingStartEvent => {
            yaml_free(
                (*event).data.mapping_start.anchor as *mut libc::c_void,
            );
            yaml_free(
                (*event).data.mapping_start.tag as *mut libc::c_void,
            );
        }
        _ => {}
    }
    let _ = memset(
        event as *mut libc::c_void,
        0,
        size_of::<YamlEventT>() as libc::c_ulong,
    );
}
