use crate::externs::{memcpy, memset, strcmp, strlen};
use crate::internal::yaml_stack_extend;
use crate::memory::{yaml_free, yaml_malloc, yaml_strdup};
use crate::ops::ForceAdd as _;
use crate::scanner::yaml_parser_fetch_more_tokens;
use crate::success::{Success, FAIL, OK};
use crate::yaml::{size_t, yaml_char_t};
use crate::{
    libc, YamlAliasEvent, YamlAliasToken, YamlAnchorToken,
    YamlBlockEndToken, YamlBlockEntryToken, YamlBlockMappingStartToken,
    YamlBlockMappingStyle, YamlBlockSequenceStartToken,
    YamlBlockSequenceStyle, YamlDocumentEndEvent, YamlDocumentEndToken,
    YamlDocumentStartEvent, YamlDocumentStartToken, YamlEventT,
    YamlFlowEntryToken, YamlFlowMappingEndToken,
    YamlFlowMappingStartToken, YamlFlowMappingStyle,
    YamlFlowSequenceEndToken, YamlFlowSequenceStartToken,
    YamlFlowSequenceStyle, YamlKeyToken, YamlMappingEndEvent,
    YamlMappingStartEvent, YamlMarkT, YamlNoError,
    YamlParseBlockMappingFirstKeyState, YamlParseBlockMappingKeyState,
    YamlParseBlockMappingValueState,
    YamlParseBlockNodeOrIndentlessSequenceState,
    YamlParseBlockNodeState, YamlParseBlockSequenceEntryState,
    YamlParseBlockSequenceFirstEntryState,
    YamlParseDocumentContentState, YamlParseDocumentEndState,
    YamlParseDocumentStartState, YamlParseEndState,
    YamlParseFlowMappingEmptyValueState,
    YamlParseFlowMappingFirstKeyState, YamlParseFlowMappingKeyState,
    YamlParseFlowMappingValueState, YamlParseFlowNodeState,
    YamlParseFlowSequenceEntryMappingEndState,
    YamlParseFlowSequenceEntryMappingKeyState,
    YamlParseFlowSequenceEntryMappingValueState,
    YamlParseFlowSequenceEntryState,
    YamlParseFlowSequenceFirstEntryState,
    YamlParseImplicitDocumentStartState,
    YamlParseIndentlessSequenceEntryState, YamlParseStreamStartState,
    YamlParserError, YamlParserT, YamlPlainScalarStyle,
    YamlScalarEvent, YamlScalarToken, YamlSequenceEndEvent,
    YamlSequenceStartEvent, YamlStreamEndEvent, YamlStreamEndToken,
    YamlStreamStartEvent, YamlStreamStartToken, YamlTagDirectiveT,
    YamlTagDirectiveToken, YamlTagToken, YamlTokenT, YamlValueToken,
    YamlVersionDirectiveT, YamlVersionDirectiveToken,
};
use core::mem::size_of;
use core::ptr::{self, addr_of_mut};

unsafe fn peek_token(parser: *mut YamlParserT) -> *mut YamlTokenT {
    if (*parser).token_available
        || yaml_parser_fetch_more_tokens(parser).ok
    {
        (*parser).tokens.head
    } else {
        ptr::null_mut::<YamlTokenT>()
    }
}

unsafe fn skip_token(parser: *mut YamlParserT) {
    (*parser).token_available = false;
    let fresh3 = addr_of_mut!((*parser).tokens_parsed);
    *fresh3 = (*fresh3).wrapping_add(1);
    (*parser).stream_end_produced =
        (*(*parser).tokens.head).type_ == YamlStreamEndToken;
    let fresh4 = addr_of_mut!((*parser).tokens.head);
    *fresh4 = (*fresh4).wrapping_offset(1);
}

/// Parse the input stream and produce the next parsing event.
///
/// This function should be called repeatedly to produce a sequence of events
/// corresponding to the input stream. The initial event will be of type
/// `YamlStreamStartEvent`, and the final event will be of type `YamlStreamEndEvent`.
///
/// # Safety
///
/// This function is unsafe because:
/// - It operates on raw pointers.
/// - It assumes certain memory layouts and alignments.
/// - It may cause undefined behavior if the input pointers are invalid or if the
///   function is misused.
///
/// # Arguments
///
/// * `parser` - A pointer to a properly initialized `YamlParserT` struct.
/// * `event` - A pointer to a `YamlEventT` struct that will be filled with the next event.
///
/// # Returns
///
/// Returns `OK` if an event was successfully parsed, or `FAIL` if:
/// - The stream has ended (stream_end_produced is true)
/// - There's an existing error in the parser
/// - The parser is in the end state
///
/// # Errors
///
/// This function will return `FAIL` if any of the above error conditions are met.
/// The caller should check the parser's error state for more details on the failure.
///
/// # Notes
///
/// - The caller is responsible for freeing any buffers associated with the produced
///   event using the `yaml_event_delete()` function.
/// - Do not alternate calls to `yaml_parser_parse()` with calls to `yaml_parser_scan()`
///   or `yaml_parser_load()`. Doing so will break the parser.
///
pub unsafe fn yaml_parser_parse(
    parser: *mut YamlParserT,
    event: *mut YamlEventT,
) -> Success {
    __assert!(!parser.is_null());
    __assert!(!event.is_null());
    let _ = memset(
        event as *mut libc::c_void,
        0,
        size_of::<YamlEventT>() as libc::c_ulong,
    );
    if (*parser).stream_end_produced {
        return FAIL;
    }
    if (*parser).error != YamlNoError {
        return FAIL;
    }
    if (*parser).state == YamlParseEndState {
        return FAIL;
    }
    yaml_parser_state_machine(parser, event)
}

unsafe fn yaml_parser_set_parser_error(
    parser: *mut YamlParserT,
    problem: *const libc::c_char,
    problem_mark: YamlMarkT,
) {
    (*parser).error = YamlParserError;
    let fresh0 = addr_of_mut!((*parser).problem);
    *fresh0 = problem;
    (*parser).problem_mark = problem_mark;
}

unsafe fn yaml_parser_set_parser_error_context(
    parser: *mut YamlParserT,
    context: *const libc::c_char,
    context_mark: YamlMarkT,
    problem: *const libc::c_char,
    problem_mark: YamlMarkT,
) {
    (*parser).error = YamlParserError;
    let fresh1 = addr_of_mut!((*parser).context);
    *fresh1 = context;
    (*parser).context_mark = context_mark;
    let fresh2 = addr_of_mut!((*parser).problem);
    *fresh2 = problem;
    (*parser).problem_mark = problem_mark;
}

unsafe fn yaml_parser_state_machine(
    parser: *mut YamlParserT,
    event: *mut YamlEventT,
) -> Success {
    match (*parser).state {
        YamlParseStreamStartState => {
            yaml_parser_parse_stream_start(parser, event)
        }
        YamlParseImplicitDocumentStartState => {
            yaml_parser_parse_document_start(parser, event, true)
        }
        YamlParseDocumentStartState => {
            yaml_parser_parse_document_start(parser, event, false)
        }
        YamlParseDocumentContentState => {
            yaml_parser_parse_document_content(parser, event)
        }
        YamlParseDocumentEndState => {
            yaml_parser_parse_document_end(parser, event)
        }
        YamlParseBlockNodeState => {
            yaml_parser_parse_node(parser, event, true, false)
        }
        YamlParseBlockNodeOrIndentlessSequenceState => {
            yaml_parser_parse_node(parser, event, true, true)
        }
        YamlParseFlowNodeState => {
            yaml_parser_parse_node(parser, event, false, false)
        }
        YamlParseBlockSequenceFirstEntryState => {
            yaml_parser_parse_block_sequence_entry(parser, event, true)
        }
        YamlParseBlockSequenceEntryState => {
            yaml_parser_parse_block_sequence_entry(parser, event, false)
        }
        YamlParseIndentlessSequenceEntryState => {
            yaml_parser_parse_indentless_sequence_entry(parser, event)
        }
        YamlParseBlockMappingFirstKeyState => {
            yaml_parser_parse_block_mapping_key(parser, event, true)
        }
        YamlParseBlockMappingKeyState => {
            yaml_parser_parse_block_mapping_key(parser, event, false)
        }
        YamlParseBlockMappingValueState => {
            yaml_parser_parse_block_mapping_value(parser, event)
        }
        YamlParseFlowSequenceFirstEntryState => {
            yaml_parser_parse_flow_sequence_entry(parser, event, true)
        }
        YamlParseFlowSequenceEntryState => {
            yaml_parser_parse_flow_sequence_entry(parser, event, false)
        }
        YamlParseFlowSequenceEntryMappingKeyState => {
            yaml_parser_parse_flow_sequence_entry_mapping_key(
                parser, event,
            )
        }
        YamlParseFlowSequenceEntryMappingValueState => {
            yaml_parser_parse_flow_sequence_entry_mapping_value(
                parser, event,
            )
        }
        YamlParseFlowSequenceEntryMappingEndState => {
            yaml_parser_parse_flow_sequence_entry_mapping_end(
                parser, event,
            )
        }
        YamlParseFlowMappingFirstKeyState => {
            yaml_parser_parse_flow_mapping_key(parser, event, true)
        }
        YamlParseFlowMappingKeyState => {
            yaml_parser_parse_flow_mapping_key(parser, event, false)
        }
        YamlParseFlowMappingValueState => {
            yaml_parser_parse_flow_mapping_value(parser, event, false)
        }
        YamlParseFlowMappingEmptyValueState => {
            yaml_parser_parse_flow_mapping_value(parser, event, true)
        }
        _ => FAIL,
    }
}

unsafe fn yaml_parser_parse_stream_start(
    parser: *mut YamlParserT,
    event: *mut YamlEventT,
) -> Success {
    let token: *mut YamlTokenT = peek_token(parser);
    if token.is_null() {
        return FAIL;
    }
    if (*token).type_ != YamlStreamStartToken {
        yaml_parser_set_parser_error(
            parser,
            b"did not find expected <stream-start>\0" as *const u8
                as *const libc::c_char,
            (*token).start_mark,
        );
        return FAIL;
    }
    (*parser).state = YamlParseImplicitDocumentStartState;
    let _ = memset(
        event as *mut libc::c_void,
        0,
        size_of::<YamlEventT>() as libc::c_ulong,
    );
    (*event).type_ = YamlStreamStartEvent;
    (*event).start_mark = (*token).start_mark;
    (*event).end_mark = (*token).start_mark;
    (*event).data.stream_start.encoding =
        (*token).data.stream_start.encoding;
    skip_token(parser);
    OK
}

unsafe fn yaml_parser_parse_document_start(
    parser: *mut YamlParserT,
    event: *mut YamlEventT,
    implicit: bool,
) -> Success {
    let mut token: *mut YamlTokenT;
    let mut version_directive: *mut YamlVersionDirectiveT =
        ptr::null_mut::<YamlVersionDirectiveT>();
    struct TagDirectives {
        start: *mut YamlTagDirectiveT,
        end: *mut YamlTagDirectiveT,
    }
    let mut tag_directives = TagDirectives {
        start: ptr::null_mut::<YamlTagDirectiveT>(),
        end: ptr::null_mut::<YamlTagDirectiveT>(),
    };
    token = peek_token(parser);
    if token.is_null() {
        return FAIL;
    }
    if !implicit {
        while (*token).type_ == YamlDocumentEndToken {
            skip_token(parser);
            token = peek_token(parser);
            if token.is_null() {
                return FAIL;
            }
        }
    }
    if implicit
        && (*token).type_ != YamlVersionDirectiveToken
        && (*token).type_ != YamlTagDirectiveToken
        && (*token).type_ != YamlDocumentStartToken
        && (*token).type_ != YamlStreamEndToken
    {
        if yaml_parser_process_directives(
            parser,
            ptr::null_mut::<*mut YamlVersionDirectiveT>(),
            ptr::null_mut::<*mut YamlTagDirectiveT>(),
            ptr::null_mut::<*mut YamlTagDirectiveT>(),
        )
        .fail
        {
            return FAIL;
        }
        PUSH!((*parser).states, YamlParseDocumentEndState);
        (*parser).state = YamlParseBlockNodeState;
        let _ = memset(
            event as *mut libc::c_void,
            0,
            size_of::<YamlEventT>() as libc::c_ulong,
        );
        (*event).type_ = YamlDocumentStartEvent;
        (*event).start_mark = (*token).start_mark;
        (*event).end_mark = (*token).start_mark;
        let fresh9 = addr_of_mut!(
            (*event).data.document_start.version_directive
        );
        *fresh9 = ptr::null_mut::<YamlVersionDirectiveT>();
        let fresh10 = addr_of_mut!(
            (*event).data.document_start.tag_directives.start
        );
        *fresh10 = ptr::null_mut::<YamlTagDirectiveT>();
        let fresh11 = addr_of_mut!(
            (*event).data.document_start.tag_directives.end
        );
        *fresh11 = ptr::null_mut::<YamlTagDirectiveT>();
        (*event).data.document_start.implicit = true;
        OK
    } else if (*token).type_ != YamlStreamEndToken {
        let end_mark: YamlMarkT;
        let start_mark: YamlMarkT = (*token).start_mark;
        if yaml_parser_process_directives(
            parser,
            addr_of_mut!(version_directive),
            addr_of_mut!(tag_directives.start),
            addr_of_mut!(tag_directives.end),
        )
        .fail
        {
            return FAIL;
        }
        token = peek_token(parser);
        if !token.is_null() {
            if (*token).type_ != YamlDocumentStartToken {
                yaml_parser_set_parser_error(
                    parser,
                    b"did not find expected <document start>\0"
                        as *const u8
                        as *const libc::c_char,
                    (*token).start_mark,
                );
            } else {
                PUSH!((*parser).states, YamlParseDocumentEndState);
                (*parser).state = YamlParseDocumentContentState;
                end_mark = (*token).end_mark;
                let _ = memset(
                    event as *mut libc::c_void,
                    0,
                    size_of::<YamlEventT>() as libc::c_ulong,
                );
                (*event).type_ = YamlDocumentStartEvent;
                (*event).start_mark = start_mark;
                (*event).end_mark = end_mark;
                let fresh14 = addr_of_mut!(
                    (*event).data.document_start.version_directive
                );
                *fresh14 = version_directive;
                let fresh15 = addr_of_mut!(
                    (*event).data.document_start.tag_directives.start
                );
                *fresh15 = tag_directives.start;
                let fresh16 = addr_of_mut!(
                    (*event).data.document_start.tag_directives.end
                );
                *fresh16 = tag_directives.end;
                (*event).data.document_start.implicit = false;
                skip_token(parser);
                tag_directives.end =
                    ptr::null_mut::<YamlTagDirectiveT>();
                tag_directives.start = tag_directives.end;
                return OK;
            }
        }
        yaml_free(version_directive as *mut libc::c_void);
        while tag_directives.start != tag_directives.end {
            yaml_free(
                (*tag_directives.end.wrapping_offset(-1_isize)).handle
                    as *mut libc::c_void,
            );
            yaml_free(
                (*tag_directives.end.wrapping_offset(-1_isize)).prefix
                    as *mut libc::c_void,
            );
            tag_directives.end = tag_directives.end.wrapping_offset(-1);
        }
        yaml_free(tag_directives.start as *mut libc::c_void);
        FAIL
    } else {
        (*parser).state = YamlParseEndState;
        let _ = memset(
            event as *mut libc::c_void,
            0,
            size_of::<YamlEventT>() as libc::c_ulong,
        );
        (*event).type_ = YamlStreamEndEvent;
        (*event).start_mark = (*token).start_mark;
        (*event).end_mark = (*token).end_mark;
        skip_token(parser);
        OK
    }
}

unsafe fn yaml_parser_parse_document_content(
    parser: *mut YamlParserT,
    event: *mut YamlEventT,
) -> Success {
    let token: *mut YamlTokenT = peek_token(parser);
    if token.is_null() {
        return FAIL;
    }
    if (*token).type_ == YamlVersionDirectiveToken
        || (*token).type_ == YamlTagDirectiveToken
        || (*token).type_ == YamlDocumentStartToken
        || (*token).type_ == YamlDocumentEndToken
        || (*token).type_ == YamlStreamEndToken
    {
        (*parser).state = POP!((*parser).states);
        yaml_parser_process_empty_scalar(event, (*token).start_mark)
    } else {
        yaml_parser_parse_node(parser, event, true, false)
    }
}

unsafe fn yaml_parser_parse_document_end(
    parser: *mut YamlParserT,
    event: *mut YamlEventT,
) -> Success {
    let mut end_mark: YamlMarkT;
    let mut implicit = true;
    let token: *mut YamlTokenT = peek_token(parser);
    if token.is_null() {
        return FAIL;
    }
    end_mark = (*token).start_mark;
    let start_mark: YamlMarkT = end_mark;
    if (*token).type_ == YamlDocumentEndToken {
        end_mark = (*token).end_mark;
        skip_token(parser);
        implicit = false;
    }
    while !STACK_EMPTY!((*parser).tag_directives) {
        let tag_directive = POP!((*parser).tag_directives);
        yaml_free(tag_directive.handle as *mut libc::c_void);
        yaml_free(tag_directive.prefix as *mut libc::c_void);
    }
    (*parser).state = YamlParseDocumentStartState;
    let _ = memset(
        event as *mut libc::c_void,
        0,
        size_of::<YamlEventT>() as libc::c_ulong,
    );
    (*event).type_ = YamlDocumentEndEvent;
    (*event).start_mark = start_mark;
    (*event).end_mark = end_mark;
    (*event).data.document_end.implicit = implicit;
    OK
}

unsafe fn yaml_parser_parse_node(
    parser: *mut YamlParserT,
    event: *mut YamlEventT,
    block: bool,
    indentless_sequence: bool,
) -> Success {
    let mut current_block: u64;
    let mut token: *mut YamlTokenT;
    let mut anchor: *mut yaml_char_t = ptr::null_mut::<yaml_char_t>();
    let mut tag_handle: *mut yaml_char_t =
        ptr::null_mut::<yaml_char_t>();
    let mut tag_suffix: *mut yaml_char_t =
        ptr::null_mut::<yaml_char_t>();
    let mut tag: *mut yaml_char_t = ptr::null_mut::<yaml_char_t>();
    let mut start_mark: YamlMarkT;
    let mut end_mark: YamlMarkT;
    let mut tag_mark = YamlMarkT {
        index: 0,
        line: 0,
        column: 0,
    };
    let implicit;
    token = peek_token(parser);
    if token.is_null() {
        return FAIL;
    }
    if (*token).type_ == YamlAliasToken {
        (*parser).state = POP!((*parser).states);
        let _ = memset(
            event as *mut libc::c_void,
            0,
            size_of::<YamlEventT>() as libc::c_ulong,
        );
        (*event).type_ = YamlAliasEvent;
        (*event).start_mark = (*token).start_mark;
        (*event).end_mark = (*token).end_mark;
        let fresh26 = addr_of_mut!((*event).data.alias.anchor);
        *fresh26 = (*token).data.alias.value;
        skip_token(parser);
        OK
    } else {
        end_mark = (*token).start_mark;
        start_mark = end_mark;
        if (*token).type_ == YamlAnchorToken {
            anchor = (*token).data.anchor.value;
            start_mark = (*token).start_mark;
            end_mark = (*token).end_mark;
            skip_token(parser);
            token = peek_token(parser);
            if token.is_null() {
                current_block = 17786380918591080555;
            } else if (*token).type_ == YamlTagToken {
                tag_handle = (*token).data.tag.handle;
                tag_suffix = (*token).data.tag.suffix;
                tag_mark = (*token).start_mark;
                end_mark = (*token).end_mark;
                skip_token(parser);
                token = peek_token(parser);
                if token.is_null() {
                    current_block = 17786380918591080555;
                } else {
                    current_block = 11743904203796629665;
                }
            } else {
                current_block = 11743904203796629665;
            }
        } else if (*token).type_ == YamlTagToken {
            tag_handle = (*token).data.tag.handle;
            tag_suffix = (*token).data.tag.suffix;
            tag_mark = (*token).start_mark;
            start_mark = tag_mark;
            end_mark = (*token).end_mark;
            skip_token(parser);
            token = peek_token(parser);
            if token.is_null() {
                current_block = 17786380918591080555;
            } else if (*token).type_ == YamlAnchorToken {
                anchor = (*token).data.anchor.value;
                end_mark = (*token).end_mark;
                skip_token(parser);
                token = peek_token(parser);
                if token.is_null() {
                    current_block = 17786380918591080555;
                } else {
                    current_block = 11743904203796629665;
                }
            } else {
                current_block = 11743904203796629665;
            }
        } else {
            current_block = 11743904203796629665;
        }
        if current_block == 11743904203796629665 {
            if !tag_handle.is_null() {
                if *tag_handle == 0 {
                    tag = tag_suffix;
                    yaml_free(tag_handle as *mut libc::c_void);
                    tag_suffix = ptr::null_mut::<yaml_char_t>();
                    tag_handle = tag_suffix;
                    current_block = 9437013279121998969;
                } else {
                    let mut tag_directive: *mut YamlTagDirectiveT;
                    tag_directive = (*parser).tag_directives.start;
                    loop {
                        if tag_directive == (*parser).tag_directives.top
                        {
                            current_block = 17728966195399430138;
                            break;
                        }
                        if strcmp(
                            (*tag_directive).handle
                                as *mut libc::c_char,
                            tag_handle as *mut libc::c_char,
                        ) == 0
                        {
                            let prefix_len: size_t = strlen(
                                (*tag_directive).prefix
                                    as *mut libc::c_char,
                            );
                            let suffix_len: size_t =
                                strlen(tag_suffix as *mut libc::c_char);
                            tag = yaml_malloc(
                                prefix_len
                                    .force_add(suffix_len)
                                    .force_add(1_u64),
                            )
                                as *mut yaml_char_t;
                            let _ = memcpy(
                                tag as *mut libc::c_void,
                                (*tag_directive).prefix
                                    as *const libc::c_void,
                                prefix_len,
                            );
                            let _ = memcpy(
                                tag.wrapping_offset(prefix_len as isize)
                                    as *mut libc::c_void,
                                tag_suffix as *const libc::c_void,
                                suffix_len,
                            );
                            *tag.wrapping_offset(
                                prefix_len.force_add(suffix_len)
                                    as isize,
                            ) = b'\0';
                            yaml_free(tag_handle as *mut libc::c_void);
                            yaml_free(tag_suffix as *mut libc::c_void);
                            tag_suffix = ptr::null_mut::<yaml_char_t>();
                            tag_handle = tag_suffix;
                            current_block = 17728966195399430138;
                            break;
                        } else {
                            tag_directive =
                                tag_directive.wrapping_offset(1);
                        }
                    }
                    if current_block != 17786380918591080555 {
                        if tag.is_null() {
                            yaml_parser_set_parser_error_context(
                                parser,
                                b"while parsing a node\0" as *const u8
                                    as *const libc::c_char,
                                start_mark,
                                b"found undefined tag handle\0"
                                    as *const u8
                                    as *const libc::c_char,
                                tag_mark,
                            );
                            current_block = 17786380918591080555;
                        } else {
                            current_block = 9437013279121998969;
                        }
                    }
                }
            } else {
                current_block = 9437013279121998969;
            }
            if current_block != 17786380918591080555 {
                implicit = tag.is_null() || *tag == 0;
                if indentless_sequence
                    && (*token).type_ == YamlBlockEntryToken
                {
                    end_mark = (*token).end_mark;
                    (*parser).state =
                        YamlParseIndentlessSequenceEntryState;
                    let _ = memset(
                        event as *mut libc::c_void,
                        0,
                        size_of::<YamlEventT>() as libc::c_ulong,
                    );
                    (*event).type_ = YamlSequenceStartEvent;
                    (*event).start_mark = start_mark;
                    (*event).end_mark = end_mark;
                    let fresh37 = addr_of_mut!(
                        (*event).data.sequence_start.anchor
                    );
                    *fresh37 = anchor;
                    let fresh38 =
                        addr_of_mut!((*event).data.sequence_start.tag);
                    *fresh38 = tag;
                    (*event).data.sequence_start.implicit = implicit;
                    (*event).data.sequence_start.style =
                        YamlBlockSequenceStyle;
                    return OK;
                } else if (*token).type_ == YamlScalarToken {
                    let mut plain_implicit = false;
                    let mut quoted_implicit = false;
                    end_mark = (*token).end_mark;
                    if (*token).data.scalar.style
                        == YamlPlainScalarStyle
                        && tag.is_null()
                        || !tag.is_null()
                            && strcmp(
                                tag as *mut libc::c_char,
                                b"!\0" as *const u8
                                    as *const libc::c_char,
                            ) == 0
                    {
                        plain_implicit = true;
                    } else if tag.is_null() {
                        quoted_implicit = true;
                    }
                    (*parser).state = POP!((*parser).states);
                    let _ = memset(
                        event as *mut libc::c_void,
                        0,
                        size_of::<YamlEventT>() as libc::c_ulong,
                    );
                    (*event).type_ = YamlScalarEvent;
                    (*event).start_mark = start_mark;
                    (*event).end_mark = end_mark;
                    let fresh40 =
                        addr_of_mut!((*event).data.scalar.anchor);
                    *fresh40 = anchor;
                    let fresh41 =
                        addr_of_mut!((*event).data.scalar.tag);
                    *fresh41 = tag;
                    let fresh42 =
                        addr_of_mut!((*event).data.scalar.value);
                    *fresh42 = (*token).data.scalar.value;
                    (*event).data.scalar.length =
                        (*token).data.scalar.length;
                    (*event).data.scalar.plain_implicit =
                        plain_implicit;
                    (*event).data.scalar.quoted_implicit =
                        quoted_implicit;
                    (*event).data.scalar.style =
                        (*token).data.scalar.style;
                    skip_token(parser);
                    return OK;
                } else if (*token).type_ == YamlFlowSequenceStartToken {
                    end_mark = (*token).end_mark;
                    (*parser).state =
                        YamlParseFlowSequenceFirstEntryState;
                    let _ = memset(
                        event as *mut libc::c_void,
                        0,
                        size_of::<YamlEventT>() as libc::c_ulong,
                    );
                    (*event).type_ = YamlSequenceStartEvent;
                    (*event).start_mark = start_mark;
                    (*event).end_mark = end_mark;
                    let fresh45 = addr_of_mut!(
                        (*event).data.sequence_start.anchor
                    );
                    *fresh45 = anchor;
                    let fresh46 =
                        addr_of_mut!((*event).data.sequence_start.tag);
                    *fresh46 = tag;
                    (*event).data.sequence_start.implicit = implicit;
                    (*event).data.sequence_start.style =
                        YamlFlowSequenceStyle;
                    return OK;
                } else if (*token).type_ == YamlFlowMappingStartToken {
                    end_mark = (*token).end_mark;
                    (*parser).state = YamlParseFlowMappingFirstKeyState;
                    let _ = memset(
                        event as *mut libc::c_void,
                        0,
                        size_of::<YamlEventT>() as libc::c_ulong,
                    );
                    (*event).type_ = YamlMappingStartEvent;
                    (*event).start_mark = start_mark;
                    (*event).end_mark = end_mark;
                    let fresh47 = addr_of_mut!(
                        (*event).data.mapping_start.anchor
                    );
                    *fresh47 = anchor;
                    let fresh48 =
                        addr_of_mut!((*event).data.mapping_start.tag);
                    *fresh48 = tag;
                    (*event).data.mapping_start.implicit = implicit;
                    (*event).data.mapping_start.style =
                        YamlFlowMappingStyle;
                    return OK;
                } else if block
                    && (*token).type_ == YamlBlockSequenceStartToken
                {
                    end_mark = (*token).end_mark;
                    (*parser).state =
                        YamlParseBlockSequenceFirstEntryState;
                    let _ = memset(
                        event as *mut libc::c_void,
                        0,
                        size_of::<YamlEventT>() as libc::c_ulong,
                    );
                    (*event).type_ = YamlSequenceStartEvent;
                    (*event).start_mark = start_mark;
                    (*event).end_mark = end_mark;
                    let fresh49 = addr_of_mut!(
                        (*event).data.sequence_start.anchor
                    );
                    *fresh49 = anchor;
                    let fresh50 =
                        addr_of_mut!((*event).data.sequence_start.tag);
                    *fresh50 = tag;
                    (*event).data.sequence_start.implicit = implicit;
                    (*event).data.sequence_start.style =
                        YamlBlockSequenceStyle;
                    return OK;
                } else if block
                    && (*token).type_ == YamlBlockMappingStartToken
                {
                    end_mark = (*token).end_mark;
                    (*parser).state =
                        YamlParseBlockMappingFirstKeyState;
                    let _ = memset(
                        event as *mut libc::c_void,
                        0,
                        size_of::<YamlEventT>() as libc::c_ulong,
                    );
                    (*event).type_ = YamlMappingStartEvent;
                    (*event).start_mark = start_mark;
                    (*event).end_mark = end_mark;
                    let fresh51 = addr_of_mut!(
                        (*event).data.mapping_start.anchor
                    );
                    *fresh51 = anchor;
                    let fresh52 =
                        addr_of_mut!((*event).data.mapping_start.tag);
                    *fresh52 = tag;
                    (*event).data.mapping_start.implicit = implicit;
                    (*event).data.mapping_start.style =
                        YamlBlockMappingStyle;
                    return OK;
                } else if !anchor.is_null() || !tag.is_null() {
                    let value: *mut yaml_char_t =
                        yaml_malloc(1_u64) as *mut yaml_char_t;
                    *value = b'\0';
                    (*parser).state = POP!((*parser).states);
                    let _ = memset(
                        event as *mut libc::c_void,
                        0,
                        size_of::<YamlEventT>() as libc::c_ulong,
                    );
                    (*event).type_ = YamlScalarEvent;
                    (*event).start_mark = start_mark;
                    (*event).end_mark = end_mark;
                    let fresh54 =
                        addr_of_mut!((*event).data.scalar.anchor);
                    *fresh54 = anchor;
                    let fresh55 =
                        addr_of_mut!((*event).data.scalar.tag);
                    *fresh55 = tag;
                    let fresh56 =
                        addr_of_mut!((*event).data.scalar.value);
                    *fresh56 = value;
                    (*event).data.scalar.length = 0_u64;
                    (*event).data.scalar.plain_implicit = implicit;
                    (*event).data.scalar.quoted_implicit = false;
                    (*event).data.scalar.style = YamlPlainScalarStyle;
                    return OK;
                } else {
                    yaml_parser_set_parser_error_context(
                        parser,
                        if block {
                            b"while parsing a block node\0" as *const u8
                                as *const libc::c_char
                        } else {
                            b"while parsing a flow node\0" as *const u8
                                as *const libc::c_char
                        },
                        start_mark,
                        b"did not find expected node content\0"
                            as *const u8
                            as *const libc::c_char,
                        (*token).start_mark,
                    );
                }
            }
        }
        yaml_free(anchor as *mut libc::c_void);
        yaml_free(tag_handle as *mut libc::c_void);
        yaml_free(tag_suffix as *mut libc::c_void);
        yaml_free(tag as *mut libc::c_void);
        FAIL
    }
}

unsafe fn yaml_parser_parse_block_sequence_entry(
    parser: *mut YamlParserT,
    event: *mut YamlEventT,
    first: bool,
) -> Success {
    let mut token: *mut YamlTokenT;
    if first {
        token = peek_token(parser);
        PUSH!((*parser).marks, (*token).start_mark);
        skip_token(parser);
    }
    token = peek_token(parser);
    if token.is_null() {
        return FAIL;
    }
    if (*token).type_ == YamlBlockEntryToken {
        let mark: YamlMarkT = (*token).end_mark;
        skip_token(parser);
        token = peek_token(parser);
        if token.is_null() {
            return FAIL;
        }
        if (*token).type_ != YamlBlockEntryToken
            && (*token).type_ != YamlBlockEndToken
        {
            PUSH!((*parser).states, YamlParseBlockSequenceEntryState);
            yaml_parser_parse_node(parser, event, true, false)
        } else {
            (*parser).state = YamlParseBlockSequenceEntryState;
            yaml_parser_process_empty_scalar(event, mark)
        }
    } else if (*token).type_ == YamlBlockEndToken {
        (*parser).state = POP!((*parser).states);
        let _ = POP!((*parser).marks);
        let _ = memset(
            event as *mut libc::c_void,
            0,
            size_of::<YamlEventT>() as libc::c_ulong,
        );
        (*event).type_ = YamlSequenceEndEvent;
        (*event).start_mark = (*token).start_mark;
        (*event).end_mark = (*token).end_mark;
        skip_token(parser);
        OK
    } else {
        yaml_parser_set_parser_error_context(
            parser,
            b"while parsing a block collection\0" as *const u8
                as *const libc::c_char,
            POP!((*parser).marks),
            b"did not find expected '-' indicator\0" as *const u8
                as *const libc::c_char,
            (*token).start_mark,
        );
        FAIL
    }
}

unsafe fn yaml_parser_parse_indentless_sequence_entry(
    parser: *mut YamlParserT,
    event: *mut YamlEventT,
) -> Success {
    let mut token: *mut YamlTokenT;
    token = peek_token(parser);
    if token.is_null() {
        return FAIL;
    }
    if (*token).type_ == YamlBlockEntryToken {
        let mark: YamlMarkT = (*token).end_mark;
        skip_token(parser);
        token = peek_token(parser);
        if token.is_null() {
            return FAIL;
        }
        if (*token).type_ != YamlBlockEntryToken
            && (*token).type_ != YamlKeyToken
            && (*token).type_ != YamlValueToken
            && (*token).type_ != YamlBlockEndToken
        {
            PUSH!(
                (*parser).states,
                YamlParseIndentlessSequenceEntryState
            );
            yaml_parser_parse_node(parser, event, true, false)
        } else {
            (*parser).state = YamlParseIndentlessSequenceEntryState;
            yaml_parser_process_empty_scalar(event, mark)
        }
    } else {
        (*parser).state = POP!((*parser).states);
        let _ = memset(
            event as *mut libc::c_void,
            0,
            size_of::<YamlEventT>() as libc::c_ulong,
        );
        (*event).type_ = YamlSequenceEndEvent;
        (*event).start_mark = (*token).start_mark;
        (*event).end_mark = (*token).start_mark;
        OK
    }
}

unsafe fn yaml_parser_parse_block_mapping_key(
    parser: *mut YamlParserT,
    event: *mut YamlEventT,
    first: bool,
) -> Success {
    let mut token: *mut YamlTokenT;
    if first {
        token = peek_token(parser);
        PUSH!((*parser).marks, (*token).start_mark);
        skip_token(parser);
    }
    token = peek_token(parser);
    if token.is_null() {
        return FAIL;
    }
    if (*token).type_ == YamlKeyToken {
        let mark: YamlMarkT = (*token).end_mark;
        skip_token(parser);
        token = peek_token(parser);
        if token.is_null() {
            return FAIL;
        }
        if (*token).type_ != YamlKeyToken
            && (*token).type_ != YamlValueToken
            && (*token).type_ != YamlBlockEndToken
        {
            PUSH!((*parser).states, YamlParseBlockMappingValueState);
            yaml_parser_parse_node(parser, event, true, true)
        } else {
            (*parser).state = YamlParseBlockMappingValueState;
            yaml_parser_process_empty_scalar(event, mark)
        }
    } else if (*token).type_ == YamlBlockEndToken {
        (*parser).state = POP!((*parser).states);
        let _ = POP!((*parser).marks);
        let _ = memset(
            event as *mut libc::c_void,
            0,
            size_of::<YamlEventT>() as libc::c_ulong,
        );
        (*event).type_ = YamlMappingEndEvent;
        (*event).start_mark = (*token).start_mark;
        (*event).end_mark = (*token).end_mark;
        skip_token(parser);
        OK
    } else {
        yaml_parser_set_parser_error_context(
            parser,
            b"while parsing a block mapping\0" as *const u8
                as *const libc::c_char,
            POP!((*parser).marks),
            b"did not find expected key\0" as *const u8
                as *const libc::c_char,
            (*token).start_mark,
        );
        FAIL
    }
}

unsafe fn yaml_parser_parse_block_mapping_value(
    parser: *mut YamlParserT,
    event: *mut YamlEventT,
) -> Success {
    let mut token: *mut YamlTokenT;
    token = peek_token(parser);
    if token.is_null() {
        return FAIL;
    }
    if (*token).type_ == YamlValueToken {
        let mark: YamlMarkT = (*token).end_mark;
        skip_token(parser);
        token = peek_token(parser);
        if token.is_null() {
            return FAIL;
        }
        if (*token).type_ != YamlKeyToken
            && (*token).type_ != YamlValueToken
            && (*token).type_ != YamlBlockEndToken
        {
            PUSH!((*parser).states, YamlParseBlockMappingKeyState);
            yaml_parser_parse_node(parser, event, true, true)
        } else {
            (*parser).state = YamlParseBlockMappingKeyState;
            yaml_parser_process_empty_scalar(event, mark)
        }
    } else {
        (*parser).state = YamlParseBlockMappingKeyState;
        yaml_parser_process_empty_scalar(event, (*token).start_mark)
    }
}

unsafe fn yaml_parser_parse_flow_sequence_entry(
    parser: *mut YamlParserT,
    event: *mut YamlEventT,
    first: bool,
) -> Success {
    let mut token: *mut YamlTokenT;
    if first {
        token = peek_token(parser);
        PUSH!((*parser).marks, (*token).start_mark);
        skip_token(parser);
    }
    token = peek_token(parser);
    if token.is_null() {
        return FAIL;
    }
    if (*token).type_ != YamlFlowSequenceEndToken {
        if !first {
            if (*token).type_ == YamlFlowEntryToken {
                skip_token(parser);
                token = peek_token(parser);
                if token.is_null() {
                    return FAIL;
                }
            } else {
                yaml_parser_set_parser_error_context(
                    parser,
                    b"while parsing a flow sequence\0" as *const u8
                        as *const libc::c_char,
                    POP!((*parser).marks),
                    b"did not find expected ',' or ']'\0" as *const u8
                        as *const libc::c_char,
                    (*token).start_mark,
                );
                return FAIL;
            }
        }
        if (*token).type_ == YamlKeyToken {
            (*parser).state = YamlParseFlowSequenceEntryMappingKeyState;
            let _ = memset(
                event as *mut libc::c_void,
                0,
                size_of::<YamlEventT>() as libc::c_ulong,
            );
            (*event).type_ = YamlMappingStartEvent;
            (*event).start_mark = (*token).start_mark;
            (*event).end_mark = (*token).end_mark;
            let fresh99 =
                addr_of_mut!((*event).data.mapping_start.anchor);
            *fresh99 = ptr::null_mut::<yaml_char_t>();
            let fresh100 =
                addr_of_mut!((*event).data.mapping_start.tag);
            *fresh100 = ptr::null_mut::<yaml_char_t>();
            (*event).data.mapping_start.implicit = true;
            (*event).data.mapping_start.style = YamlFlowMappingStyle;
            skip_token(parser);
            return OK;
        } else if (*token).type_ != YamlFlowSequenceEndToken {
            PUSH!((*parser).states, YamlParseFlowSequenceEntryState);
            return yaml_parser_parse_node(parser, event, false, false);
        }
    }
    (*parser).state = POP!((*parser).states);
    let _ = POP!((*parser).marks);
    let _ = memset(
        event as *mut libc::c_void,
        0,
        size_of::<YamlEventT>() as libc::c_ulong,
    );
    (*event).type_ = YamlSequenceEndEvent;
    (*event).start_mark = (*token).start_mark;
    (*event).end_mark = (*token).end_mark;
    skip_token(parser);
    OK
}

unsafe fn yaml_parser_parse_flow_sequence_entry_mapping_key(
    parser: *mut YamlParserT,
    event: *mut YamlEventT,
) -> Success {
    let token: *mut YamlTokenT = peek_token(parser);
    if token.is_null() {
        return FAIL;
    }
    if (*token).type_ != YamlValueToken
        && (*token).type_ != YamlFlowEntryToken
        && (*token).type_ != YamlFlowSequenceEndToken
    {
        PUSH!(
            (*parser).states,
            YamlParseFlowSequenceEntryMappingValueState
        );
        yaml_parser_parse_node(parser, event, false, false)
    } else {
        let mark: YamlMarkT = (*token).end_mark;
        skip_token(parser);
        (*parser).state = YamlParseFlowSequenceEntryMappingValueState;
        yaml_parser_process_empty_scalar(event, mark)
    }
}

unsafe fn yaml_parser_parse_flow_sequence_entry_mapping_value(
    parser: *mut YamlParserT,
    event: *mut YamlEventT,
) -> Success {
    let mut token: *mut YamlTokenT;
    token = peek_token(parser);
    if token.is_null() {
        return FAIL;
    }
    if (*token).type_ == YamlValueToken {
        skip_token(parser);
        token = peek_token(parser);
        if token.is_null() {
            return FAIL;
        }
        if (*token).type_ != YamlFlowEntryToken
            && (*token).type_ != YamlFlowSequenceEndToken
        {
            PUSH!(
                (*parser).states,
                YamlParseFlowSequenceEntryMappingEndState
            );
            return yaml_parser_parse_node(parser, event, false, false);
        }
    }
    (*parser).state = YamlParseFlowSequenceEntryMappingEndState;
    yaml_parser_process_empty_scalar(event, (*token).start_mark)
}

unsafe fn yaml_parser_parse_flow_sequence_entry_mapping_end(
    parser: *mut YamlParserT,
    event: *mut YamlEventT,
) -> Success {
    let token: *mut YamlTokenT = peek_token(parser);
    if token.is_null() {
        return FAIL;
    }
    (*parser).state = YamlParseFlowSequenceEntryState;
    let _ = memset(
        event as *mut libc::c_void,
        0,
        size_of::<YamlEventT>() as libc::c_ulong,
    );
    (*event).type_ = YamlMappingEndEvent;
    (*event).start_mark = (*token).start_mark;
    (*event).end_mark = (*token).start_mark;
    OK
}

unsafe fn yaml_parser_parse_flow_mapping_key(
    parser: *mut YamlParserT,
    event: *mut YamlEventT,
    first: bool,
) -> Success {
    let mut token: *mut YamlTokenT;
    if first {
        token = peek_token(parser);
        PUSH!((*parser).marks, (*token).start_mark);
        skip_token(parser);
    }
    token = peek_token(parser);
    if token.is_null() {
        return FAIL;
    }
    if (*token).type_ != YamlFlowMappingEndToken {
        if !first {
            if (*token).type_ == YamlFlowEntryToken {
                skip_token(parser);
                token = peek_token(parser);
                if token.is_null() {
                    return FAIL;
                }
            } else {
                yaml_parser_set_parser_error_context(
                    parser,
                    b"while parsing a flow mapping\0" as *const u8
                        as *const libc::c_char,
                    POP!((*parser).marks),
                    b"did not find expected ',' or '}'\0" as *const u8
                        as *const libc::c_char,
                    (*token).start_mark,
                );
                return FAIL;
            }
        }
        if (*token).type_ == YamlKeyToken {
            skip_token(parser);
            token = peek_token(parser);
            if token.is_null() {
                return FAIL;
            }
            if (*token).type_ != YamlValueToken
                && (*token).type_ != YamlFlowEntryToken
                && (*token).type_ != YamlFlowMappingEndToken
            {
                PUSH!((*parser).states, YamlParseFlowMappingValueState);
                return yaml_parser_parse_node(
                    parser, event, false, false,
                );
            } else {
                (*parser).state = YamlParseFlowMappingValueState;
                return yaml_parser_process_empty_scalar(
                    event,
                    (*token).start_mark,
                );
            }
        } else if (*token).type_ != YamlFlowMappingEndToken {
            PUSH!(
                (*parser).states,
                YamlParseFlowMappingEmptyValueState
            );
            return yaml_parser_parse_node(parser, event, false, false);
        }
    }
    (*parser).state = POP!((*parser).states);
    let _ = POP!((*parser).marks);
    let _ = memset(
        event as *mut libc::c_void,
        0,
        size_of::<YamlEventT>() as libc::c_ulong,
    );
    (*event).type_ = YamlMappingEndEvent;
    (*event).start_mark = (*token).start_mark;
    (*event).end_mark = (*token).end_mark;
    skip_token(parser);
    OK
}

unsafe fn yaml_parser_parse_flow_mapping_value(
    parser: *mut YamlParserT,
    event: *mut YamlEventT,
    empty: bool,
) -> Success {
    let mut token: *mut YamlTokenT;
    token = peek_token(parser);
    if token.is_null() {
        return FAIL;
    }
    if empty {
        (*parser).state = YamlParseFlowMappingKeyState;
        return yaml_parser_process_empty_scalar(
            event,
            (*token).start_mark,
        );
    }
    if (*token).type_ == YamlValueToken {
        skip_token(parser);
        token = peek_token(parser);
        if token.is_null() {
            return FAIL;
        }
        if (*token).type_ != YamlFlowEntryToken
            && (*token).type_ != YamlFlowMappingEndToken
        {
            PUSH!((*parser).states, YamlParseFlowMappingKeyState);
            return yaml_parser_parse_node(parser, event, false, false);
        }
    }
    (*parser).state = YamlParseFlowMappingKeyState;
    yaml_parser_process_empty_scalar(event, (*token).start_mark)
}

unsafe fn yaml_parser_process_empty_scalar(
    event: *mut YamlEventT,
    mark: YamlMarkT,
) -> Success {
    let value: *mut yaml_char_t =
        yaml_malloc(1_u64) as *mut yaml_char_t;
    *value = b'\0';
    let _ = memset(
        event as *mut libc::c_void,
        0,
        size_of::<YamlEventT>() as libc::c_ulong,
    );
    (*event).type_ = YamlScalarEvent;
    (*event).start_mark = mark;
    (*event).end_mark = mark;
    let fresh138 = addr_of_mut!((*event).data.scalar.anchor);
    *fresh138 = ptr::null_mut::<yaml_char_t>();
    let fresh139 = addr_of_mut!((*event).data.scalar.tag);
    *fresh139 = ptr::null_mut::<yaml_char_t>();
    let fresh140 = addr_of_mut!((*event).data.scalar.value);
    *fresh140 = value;
    (*event).data.scalar.length = 0_u64;
    (*event).data.scalar.plain_implicit = true;
    (*event).data.scalar.quoted_implicit = false;
    (*event).data.scalar.style = YamlPlainScalarStyle;
    OK
}

unsafe fn yaml_parser_process_directives(
    parser: *mut YamlParserT,
    version_directive_ref: *mut *mut YamlVersionDirectiveT,
    tag_directives_start_ref: *mut *mut YamlTagDirectiveT,
    tag_directives_end_ref: *mut *mut YamlTagDirectiveT,
) -> Success {
    let mut current_block: u64;
    let mut default_tag_directives: [YamlTagDirectiveT; 3] = [
        YamlTagDirectiveT {
            handle: b"!\0" as *const u8 as *const libc::c_char
                as *mut yaml_char_t,
            prefix: b"!\0" as *const u8 as *const libc::c_char
                as *mut yaml_char_t,
        },
        YamlTagDirectiveT {
            handle: b"!!\0" as *const u8 as *const libc::c_char
                as *mut yaml_char_t,
            prefix: b"tag:yaml.org,2002:\0" as *const u8
                as *const libc::c_char
                as *mut yaml_char_t,
        },
        YamlTagDirectiveT {
            handle: ptr::null_mut::<yaml_char_t>(),
            prefix: ptr::null_mut::<yaml_char_t>(),
        },
    ];
    let mut default_tag_directive: *mut YamlTagDirectiveT;
    let mut version_directive: *mut YamlVersionDirectiveT =
        ptr::null_mut::<YamlVersionDirectiveT>();
    struct TagDirectives {
        start: *mut YamlTagDirectiveT,
        end: *mut YamlTagDirectiveT,
        top: *mut YamlTagDirectiveT,
    }
    let mut tag_directives = TagDirectives {
        start: ptr::null_mut::<YamlTagDirectiveT>(),
        end: ptr::null_mut::<YamlTagDirectiveT>(),
        top: ptr::null_mut::<YamlTagDirectiveT>(),
    };
    let mut token: *mut YamlTokenT;
    STACK_INIT!(tag_directives, YamlTagDirectiveT);
    token = peek_token(parser);
    if !token.is_null() {
        loop {
            if !((*token).type_ == YamlVersionDirectiveToken
                || (*token).type_ == YamlTagDirectiveToken)
            {
                current_block = 16924917904204750491;
                break;
            }
            if (*token).type_ == YamlVersionDirectiveToken {
                if !version_directive.is_null() {
                    yaml_parser_set_parser_error(
                        parser,
                        b"found duplicate %YAML directive\0"
                            as *const u8
                            as *const libc::c_char,
                        (*token).start_mark,
                    );
                    current_block = 17143798186130252483;
                    break;
                } else if (*token).data.version_directive.major != 1
                    || (*token).data.version_directive.minor != 1
                        && (*token).data.version_directive.minor != 2
                {
                    yaml_parser_set_parser_error(
                        parser,
                        b"found incompatible YAML document\0"
                            as *const u8
                            as *const libc::c_char,
                        (*token).start_mark,
                    );
                    current_block = 17143798186130252483;
                    break;
                } else {
                    version_directive =
                        yaml_malloc(size_of::<YamlVersionDirectiveT>()
                            as libc::c_ulong)
                            as *mut YamlVersionDirectiveT;
                    (*version_directive).major =
                        (*token).data.version_directive.major;
                    (*version_directive).minor =
                        (*token).data.version_directive.minor;
                }
            } else if (*token).type_ == YamlTagDirectiveToken {
                let value = YamlTagDirectiveT {
                    handle: (*token).data.tag_directive.handle,
                    prefix: (*token).data.tag_directive.prefix,
                };
                if yaml_parser_append_tag_directive(
                    parser,
                    value,
                    false,
                    (*token).start_mark,
                )
                .fail
                {
                    current_block = 17143798186130252483;
                    break;
                }
                PUSH!(tag_directives, value);
            }
            skip_token(parser);
            token = peek_token(parser);
            if token.is_null() {
                current_block = 17143798186130252483;
                break;
            }
        }
        if current_block != 17143798186130252483 {
            default_tag_directive = default_tag_directives.as_mut_ptr();
            loop {
                if (*default_tag_directive).handle.is_null() {
                    current_block = 18377268871191777778;
                    break;
                }
                if yaml_parser_append_tag_directive(
                    parser,
                    *default_tag_directive,
                    true,
                    (*token).start_mark,
                )
                .fail
                {
                    current_block = 17143798186130252483;
                    break;
                }
                default_tag_directive =
                    default_tag_directive.wrapping_offset(1);
            }
            if current_block != 17143798186130252483 {
                if !version_directive_ref.is_null() {
                    *version_directive_ref = version_directive;
                }
                if !tag_directives_start_ref.is_null() {
                    if STACK_EMPTY!(tag_directives) {
                        *tag_directives_end_ref =
                            ptr::null_mut::<YamlTagDirectiveT>();
                        *tag_directives_start_ref =
                            *tag_directives_end_ref;
                        STACK_DEL!(tag_directives);
                    } else {
                        *tag_directives_start_ref =
                            tag_directives.start;
                        *tag_directives_end_ref = tag_directives.top;
                    }
                } else {
                    STACK_DEL!(tag_directives);
                }
                if version_directive_ref.is_null() {
                    yaml_free(version_directive as *mut libc::c_void);
                }
                return OK;
            }
        }
    }
    yaml_free(version_directive as *mut libc::c_void);
    while !STACK_EMPTY!(tag_directives) {
        let tag_directive = POP!(tag_directives);
        yaml_free(tag_directive.handle as *mut libc::c_void);
        yaml_free(tag_directive.prefix as *mut libc::c_void);
    }
    STACK_DEL!(tag_directives);
    FAIL
}

unsafe fn yaml_parser_append_tag_directive(
    parser: *mut YamlParserT,
    value: YamlTagDirectiveT,
    allow_duplicates: bool,
    mark: YamlMarkT,
) -> Success {
    let mut tag_directive: *mut YamlTagDirectiveT;
    let mut copy = YamlTagDirectiveT {
        handle: ptr::null_mut::<yaml_char_t>(),
        prefix: ptr::null_mut::<yaml_char_t>(),
    };
    tag_directive = (*parser).tag_directives.start;
    while tag_directive != (*parser).tag_directives.top {
        if strcmp(
            value.handle as *mut libc::c_char,
            (*tag_directive).handle as *mut libc::c_char,
        ) == 0
        {
            if allow_duplicates {
                return OK;
            }
            yaml_parser_set_parser_error(
                parser,
                b"found duplicate %TAG directive\0" as *const u8
                    as *const libc::c_char,
                mark,
            );
            return FAIL;
        }
        tag_directive = tag_directive.wrapping_offset(1);
    }
    copy.handle = yaml_strdup(value.handle);
    copy.prefix = yaml_strdup(value.prefix);
    PUSH!((*parser).tag_directives, copy);
    OK
}
