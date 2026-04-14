use crate::externs::{memset, strcmp};
use crate::fmt::WriteToPtr;
use crate::memory::yaml_free;
use crate::memory::yaml_malloc;
use crate::ops::ForceMul as _;
use crate::success::{Success, FAIL, OK};
use crate::yaml::{
    yaml_char_t, YamlAliasEvent, YamlAnchorsT, YamlAnyEncoding,
    YamlDocumentEndEvent, YamlDocumentStartEvent, YamlDocumentT,
    YamlEmitterT, YamlEventT, YamlMappingEndEvent, YamlMappingNode,
    YamlMappingStartEvent, YamlMarkT, YamlNodeItemT, YamlNodePairT,
    YamlNodeT, YamlScalarEvent, YamlScalarNode, YamlSequenceEndEvent,
    YamlSequenceNode, YamlSequenceStartEvent, YamlStreamEndEvent,
    YamlStreamStartEvent,
};
use crate::{
    libc, yaml_document_delete, yaml_emitter_emit, PointerExt,
};
use core::mem::{size_of, MaybeUninit};
use core::ptr::{self, addr_of_mut};

/// Start a YAML stream.
///
/// This function should be used before yaml_emitter_dump() is called.
///
/// # Safety
///
/// - `emitter` must be a valid, non-null pointer to a properly initialized `YamlEmitterT` struct.
/// - The `YamlEmitterT` struct must not be in an opened state.
/// - The `YamlEmitterT` struct must be properly aligned and have the expected memory layout.
///
pub unsafe fn yaml_emitter_open(emitter: *mut YamlEmitterT) -> Success {
    if emitter.is_null() {
        return FAIL;
    }

    // If the emitter is already opened, return FAIL
    if (*emitter).opened {
        return FAIL;
    }

    // If the emitter was previously closed, reset its state
    if (*emitter).closed {
        (*emitter).closed = false;
    }

    let mut event = MaybeUninit::<YamlEventT>::uninit();
    let event_ptr = event.as_mut_ptr();
    let mark = YamlMarkT {
        index: 0_u64,
        line: 0_u64,
        column: 0_u64,
    };

    let _ = memset(
        event_ptr as *mut libc::c_void,
        0,
        size_of::<YamlEventT>() as libc::c_ulong,
    );
    (*event_ptr).type_ = YamlStreamStartEvent;
    (*event_ptr).start_mark = mark;
    (*event_ptr).end_mark = mark;
    (*event_ptr).data.stream_start.encoding = YamlAnyEncoding;

    if yaml_emitter_emit(emitter, event_ptr).fail {
        return FAIL;
    }

    (*emitter).opened = true;
    (*emitter).closed = false;
    OK
}
/// Finish a YAML stream.
///
/// This function should be used after yaml_emitter_dump() is called.
///
/// # Safety
///
/// - `emitter` must be a valid, non-null pointer to a properly initialized `YamlEmitterT` struct.
/// - The `YamlEmitterT` struct must be in an opened state and not already closed.
/// - The `YamlEmitterT` struct must be properly aligned and have the expected memory layout.
///
pub unsafe fn yaml_emitter_close(
    emitter: *mut YamlEmitterT,
) -> Success {
    if emitter.is_null() {
        return FAIL;
    }

    // If the emitter is not opened, we don't need to close it
    if !(*emitter).opened {
        return OK;
    }

    // If the emitter is already closed, we don't need to close it again
    if (*emitter).closed {
        return OK;
    }

    let mut event = MaybeUninit::<YamlEventT>::uninit();
    let event = event.as_mut_ptr();
    let mark = YamlMarkT {
        index: 0_u64,
        line: 0_u64,
        column: 0_u64,
    };

    let _ = memset(
        event as *mut libc::c_void,
        0,
        size_of::<YamlEventT>() as libc::c_ulong,
    );
    (*event).type_ = YamlStreamEndEvent;
    (*event).start_mark = mark;
    (*event).end_mark = mark;
    if yaml_emitter_emit(emitter, event).fail {
        return FAIL;
    }
    (*emitter).closed = true;
    (*emitter).opened = false;
    OK
}

/// Emit a YAML document.
///
/// The document object may be generated using the yaml_parser_load() function or
/// the yaml_document_initialize() function. The emitter takes the
/// responsibility for the document object and destroys its content after it is
/// emitted. The document object is destroyed even if the function fails.
///
/// # Safety
///
/// - `emitter` must be a valid, non-null pointer to a properly initialized `YamlEmitterT` struct.
/// - `document` must be a valid, non-null pointer to a `YamlDocumentT` struct that can be safely read from and will be destroyed by the function.
/// - The `YamlEmitterT` and `YamlDocumentT` structs must be properly aligned and have the expected memory layout.
/// - The `YamlEmitterT` struct must be in a valid state to emit the provided document.
///
pub unsafe fn yaml_emitter_dump(
    emitter: *mut YamlEmitterT,
    document: *mut YamlDocumentT,
) -> Success {
    let mut event = MaybeUninit::<YamlEventT>::uninit();
    let event = event.as_mut_ptr();
    let mark = YamlMarkT {
        index: 0_u64,
        line: 0_u64,
        column: 0_u64,
    };

    __assert!(!emitter.is_null());
    __assert!(!document.is_null());

    let fresh0 = addr_of_mut!((*emitter).document);
    *fresh0 = document;

    if !(*emitter).opened && yaml_emitter_open(emitter).fail {
        return FAIL;
    }

    if STACK_EMPTY!((*document).nodes) {
        if yaml_emitter_close(emitter).ok {
            yaml_emitter_delete_document_and_anchors(emitter);
            return OK;
        }
    } else {
        __assert!((*emitter).opened);
        let fresh1 = addr_of_mut!((*emitter).anchors);
        *fresh1 = yaml_malloc(
            (size_of::<YamlAnchorsT>() as libc::c_ulong).force_mul(
                (*document)
                    .nodes
                    .top
                    .c_offset_from((*document).nodes.start)
                    as libc::c_ulong,
            ),
        ) as *mut YamlAnchorsT;

        let _ = memset(
            (*emitter).anchors as *mut libc::c_void,
            0,
            (size_of::<YamlAnchorsT>() as libc::c_ulong).force_mul(
                (*document)
                    .nodes
                    .top
                    .c_offset_from((*document).nodes.start)
                    as libc::c_ulong,
            ),
        );

        let _ = memset(
            event as *mut libc::c_void,
            0,
            size_of::<YamlEventT>() as libc::c_ulong,
        );
        (*event).type_ = YamlDocumentStartEvent;
        (*event).start_mark = mark;
        (*event).end_mark = mark;
        (*event).data.document_start.version_directive =
            (*document).version_directive;
        (*event).data.document_start.tag_directives.start =
            (*document).tag_directives.start;
        (*event).data.document_start.tag_directives.end =
            (*document).tag_directives.end;
        (*event).data.document_start.implicit =
            (*document).start_implicit;

        if yaml_emitter_emit(emitter, event).ok {
            yaml_emitter_anchor_node(emitter, 1);
            if yaml_emitter_dump_node(emitter, 1).ok {
                let _ = memset(
                    event as *mut libc::c_void,
                    0,
                    size_of::<YamlEventT>() as libc::c_ulong,
                );
                (*event).type_ = YamlDocumentEndEvent;
                (*event).start_mark = mark;
                (*event).end_mark = mark;
                (*event).data.document_end.implicit =
                    (*document).end_implicit;

                if yaml_emitter_emit(emitter, event).ok {
                    yaml_emitter_delete_document_and_anchors(emitter);
                    return OK;
                }
            }
        }
    }

    yaml_emitter_delete_document_and_anchors(emitter);
    FAIL
}

unsafe fn yaml_emitter_delete_document_and_anchors(
    emitter: *mut YamlEmitterT,
) {
    let mut index: libc::c_int;
    if (*emitter).anchors.is_null() {
        yaml_document_delete((*emitter).document);
        let fresh2 = addr_of_mut!((*emitter).document);
        *fresh2 = ptr::null_mut::<YamlDocumentT>();
        return;
    }
    index = 0;
    while (*(*emitter).document)
        .nodes
        .start
        .wrapping_offset(index as isize)
        < (*(*emitter).document).nodes.top
    {
        let mut node: YamlNodeT = *(*(*emitter).document)
            .nodes
            .start
            .wrapping_offset(index as isize);
        if !(*(*emitter).anchors.wrapping_offset(index as isize))
            .serialized
        {
            yaml_free(node.tag as *mut libc::c_void);
            if node.type_ == YamlScalarNode {
                yaml_free(node.data.scalar.value as *mut libc::c_void);
            }
        }
        if node.type_ == YamlSequenceNode {
            STACK_DEL!(node.data.sequence.items);
        }
        if node.type_ == YamlMappingNode {
            STACK_DEL!(node.data.mapping.pairs);
        }
        index += 1;
    }
    STACK_DEL!((*(*emitter).document).nodes);
    yaml_free((*emitter).anchors as *mut libc::c_void);
    let fresh6 = addr_of_mut!((*emitter).anchors);
    *fresh6 = ptr::null_mut::<YamlAnchorsT>();
    (*emitter).last_anchor_id = 0;
    let fresh7 = addr_of_mut!((*emitter).document);
    *fresh7 = ptr::null_mut::<YamlDocumentT>();
}

unsafe fn yaml_emitter_anchor_node_sub(
    emitter: *mut YamlEmitterT,
    index: libc::c_int,
) {
    (*((*emitter).anchors).offset((index - 1) as isize)).references +=
        1;
    if (*(*emitter).anchors.offset((index - 1) as isize)).references
        == 2
    {
        (*emitter).last_anchor_id += 1;
        (*(*emitter).anchors.offset((index - 1) as isize)).anchor =
            (*emitter).last_anchor_id;
    }
}

unsafe fn yaml_emitter_anchor_node(
    emitter: *mut YamlEmitterT,
    index: libc::c_int,
) {
    let node: *mut YamlNodeT = (*(*emitter).document)
        .nodes
        .start
        .wrapping_offset(index as isize)
        .wrapping_offset(-1_isize);
    let mut item: *mut YamlNodeItemT;
    let mut pair: *mut YamlNodePairT;
    let fresh8 = addr_of_mut!(
        (*((*emitter).anchors).wrapping_offset((index - 1) as isize))
            .references
    );
    *fresh8 += 1;
    if (*(*emitter).anchors.wrapping_offset((index - 1) as isize))
        .references
        == 1
    {
        match (*node).type_ {
            YamlSequenceNode => {
                item = (*node).data.sequence.items.start;
                while item < (*node).data.sequence.items.top {
                    yaml_emitter_anchor_node_sub(emitter, *item);
                    item = item.wrapping_offset(1);
                }
            }
            YamlMappingNode => {
                pair = (*node).data.mapping.pairs.start;
                while pair < (*node).data.mapping.pairs.top {
                    yaml_emitter_anchor_node_sub(emitter, (*pair).key);
                    yaml_emitter_anchor_node_sub(
                        emitter,
                        (*pair).value,
                    );
                    pair = pair.wrapping_offset(1);
                }
            }
            _ => {}
        }
    } else if (*(*emitter)
        .anchors
        .wrapping_offset((index - 1) as isize))
    .references
        == 2
    {
        let fresh9 = addr_of_mut!((*emitter).last_anchor_id);
        *fresh9 += 1;
        (*(*emitter).anchors.wrapping_offset((index - 1) as isize))
            .anchor = *fresh9;
    }
}

unsafe fn yaml_emitter_generate_anchor(
    _emitter: *mut YamlEmitterT,
    anchor_id: libc::c_int,
) -> *mut yaml_char_t {
    let anchor: *mut yaml_char_t =
        yaml_malloc(16_u64) as *mut yaml_char_t;
    write!(WriteToPtr::new(anchor), "id{:03}\0", anchor_id);
    anchor
}

/// Dumps a YAML node to the emitter.
///
/// This function is responsible for emitting a single YAML node from a document.
///
/// # Safety
///
/// - `emitter` must be a valid, non-null pointer to an initialized `YamlEmitterT` struct.
/// - `index` must be a valid index within the YAML document associated with the emitter.
/// - The caller must ensure that the node at `index` can be safely emitted without causing memory issues.
pub unsafe fn yaml_emitter_dump_node(
    emitter: *mut YamlEmitterT,
    index: libc::c_int,
) -> Success {
    let node: *mut YamlNodeT = (*(*emitter).document)
        .nodes
        .start
        .wrapping_offset(index as isize)
        .wrapping_offset(-1_isize);
    let anchor_id: libc::c_int =
        (*(*emitter).anchors.wrapping_offset((index - 1) as isize))
            .anchor;
    let mut anchor: *mut yaml_char_t = ptr::null_mut::<yaml_char_t>();
    if anchor_id != 0 {
        anchor = yaml_emitter_generate_anchor(emitter, anchor_id);
    }
    if (*(*emitter).anchors.wrapping_offset((index - 1) as isize))
        .serialized
    {
        return yaml_emitter_dump_alias(emitter, anchor);
    }
    (*(*emitter).anchors.wrapping_offset((index - 1) as isize))
        .serialized = true;
    match (*node).type_ {
        YamlScalarNode => {
            yaml_emitter_dump_scalar(emitter, node, anchor)
        }
        YamlSequenceNode => {
            yaml_emitter_dump_sequence(emitter, node, anchor)
        }
        YamlMappingNode => {
            yaml_emitter_dump_mapping(emitter, node, anchor)
        }
        _ => __assert!(false),
    }
}

unsafe fn yaml_emitter_dump_alias(
    emitter: *mut YamlEmitterT,
    anchor: *mut yaml_char_t,
) -> Success {
    let mut event = MaybeUninit::<YamlEventT>::uninit();
    let event = event.as_mut_ptr();
    let mark = YamlMarkT {
        index: 0_u64,
        line: 0_u64,
        column: 0_u64,
    };
    let _ = memset(
        event as *mut libc::c_void,
        0,
        size_of::<YamlEventT>() as libc::c_ulong,
    );
    (*event).type_ = YamlAliasEvent;
    (*event).start_mark = mark;
    (*event).end_mark = mark;
    (*event).data.alias.anchor = anchor;
    yaml_emitter_emit(emitter, event)
}

/// Dumps a YAML scalar node to the emitter.
///
/// This function handles emitting a scalar node, which is a single key-value pair.
///
/// # Safety
///
/// - `emitter` must be a valid, non-null pointer to an initialized `YamlEmitterT` struct.
/// - `node` must be a valid, non-null pointer to a `YamlNodeT` struct representing the scalar node.
/// - `anchor` must be a valid, non-null pointer to a `yaml_char_t` if provided, or null if no anchor is used.
/// - The caller must ensure that the node and anchor pointers are valid and properly aligned.
pub unsafe fn yaml_emitter_dump_scalar(
    emitter: *mut YamlEmitterT,
    node: *mut YamlNodeT,
    anchor: *mut yaml_char_t,
) -> Success {
    let mut event = MaybeUninit::<YamlEventT>::uninit();
    let event = event.as_mut_ptr();
    let mark = YamlMarkT {
        index: 0_u64,
        line: 0_u64,
        column: 0_u64,
    };
    let plain_implicit = strcmp(
        (*node).tag as *mut libc::c_char,
        b"tag:yaml.org,2002:str\0" as *const u8 as *const libc::c_char,
    ) == 0;
    let quoted_implicit = strcmp(
        (*node).tag as *mut libc::c_char,
        b"tag:yaml.org,2002:str\0" as *const u8 as *const libc::c_char,
    ) == 0;
    let _ = memset(
        event as *mut libc::c_void,
        0,
        size_of::<YamlEventT>() as libc::c_ulong,
    );
    (*event).type_ = YamlScalarEvent;
    (*event).start_mark = mark;
    (*event).end_mark = mark;
    (*event).data.scalar.anchor = anchor;
    (*event).data.scalar.tag = (*node).tag;
    (*event).data.scalar.value = (*node).data.scalar.value;
    (*event).data.scalar.length = (*node).data.scalar.length;
    (*event).data.scalar.plain_implicit = plain_implicit;
    (*event).data.scalar.quoted_implicit = quoted_implicit;
    (*event).data.scalar.style = (*node).data.scalar.style;
    yaml_emitter_emit(emitter, event)
}

/// Dumps a YAML sequence node to the emitter.
///
/// This function handles emitting a sequence node, which is a list of items.
///
/// # Safety
///
/// - `emitter` must be a valid, non-null pointer to an initialized `YamlEmitterT` struct.
/// - `node` must be a valid, non-null pointer to a `YamlNodeT` struct representing the sequence node.
/// - `anchor` must be a valid, non-null pointer to a `yaml_char_t` if provided, or null if no anchor is used.
/// - The caller must ensure that the node and anchor pointers are valid and properly aligned.
/// - The sequence node must contain a valid list of items that can be safely iterated and emitted.
pub unsafe fn yaml_emitter_dump_sequence(
    emitter: *mut YamlEmitterT,
    node: *mut YamlNodeT,
    anchor: *mut yaml_char_t,
) -> Success {
    let mut event = MaybeUninit::<YamlEventT>::uninit();
    let event = event.as_mut_ptr();
    let mark = YamlMarkT {
        index: 0_u64,
        line: 0_u64,
        column: 0_u64,
    };
    let implicit = strcmp(
        (*node).tag as *mut libc::c_char,
        b"tag:yaml.org,2002:seq\0" as *const u8 as *const libc::c_char,
    ) == 0;
    let mut item: *mut YamlNodeItemT;
    let _ = memset(
        event as *mut libc::c_void,
        0,
        size_of::<YamlEventT>() as libc::c_ulong,
    );
    (*event).type_ = YamlSequenceStartEvent;
    (*event).start_mark = mark;
    (*event).end_mark = mark;
    (*event).data.sequence_start.anchor = anchor;
    (*event).data.sequence_start.tag = (*node).tag;
    (*event).data.sequence_start.implicit = implicit;
    (*event).data.sequence_start.style = (*node).data.sequence.style;
    if yaml_emitter_emit(emitter, event).fail {
        return FAIL;
    }
    item = (*node).data.sequence.items.start;
    while item < (*node).data.sequence.items.top {
        if yaml_emitter_dump_node(emitter, *item).fail {
            return FAIL;
        }
        item = item.wrapping_offset(1);
    }
    let _ = memset(
        event as *mut libc::c_void,
        0,
        size_of::<YamlEventT>() as libc::c_ulong,
    );
    (*event).type_ = YamlSequenceEndEvent;
    (*event).start_mark = mark;
    (*event).end_mark = mark;
    yaml_emitter_emit(emitter, event)
}

/// Dumps a YAML mapping node to the emitter.
///
/// This function handles emitting a mapping node, which is a set of key-value pairs.
///
/// # Safety
///
/// - `emitter` must be a valid, non-null pointer to an initialized `YamlEmitterT` struct.
/// - `node` must be a valid, non-null pointer to a `YamlNodeT` struct representing the mapping node.
/// - `anchor` must be a valid, non-null pointer to a `yaml_char_t` if provided, or null if no anchor is used.
/// - The caller must ensure that the node and anchor pointers are valid and properly aligned.
/// - The mapping node must contain a valid set of key-value pairs that can be safely iterated and emitted.
pub unsafe fn yaml_emitter_dump_mapping(
    emitter: *mut YamlEmitterT,
    node: *mut YamlNodeT,
    anchor: *mut yaml_char_t,
) -> Success {
    let mut event = MaybeUninit::<YamlEventT>::uninit();
    let event = event.as_mut_ptr();
    let mark = YamlMarkT {
        index: 0_u64,
        line: 0_u64,
        column: 0_u64,
    };
    let implicit = strcmp(
        (*node).tag as *mut libc::c_char,
        b"tag:yaml.org,2002:map\0" as *const u8 as *const libc::c_char,
    ) == 0;
    let mut pair: *mut YamlNodePairT;
    let _ = memset(
        event as *mut libc::c_void,
        0,
        size_of::<YamlEventT>() as libc::c_ulong,
    );
    (*event).type_ = YamlMappingStartEvent;
    (*event).start_mark = mark;
    (*event).end_mark = mark;
    (*event).data.mapping_start.anchor = anchor;
    (*event).data.mapping_start.tag = (*node).tag;
    (*event).data.mapping_start.implicit = implicit;
    (*event).data.mapping_start.style = (*node).data.mapping.style;
    if yaml_emitter_emit(emitter, event).fail {
        return FAIL;
    }
    pair = (*node).data.mapping.pairs.start;
    while pair < (*node).data.mapping.pairs.top {
        if yaml_emitter_dump_node(emitter, (*pair).key).fail {
            return FAIL;
        }
        if yaml_emitter_dump_node(emitter, (*pair).value).fail {
            return FAIL;
        }
        pair = pair.wrapping_offset(1);
    }
    let _ = memset(
        event as *mut libc::c_void,
        0,
        size_of::<YamlEventT>() as libc::c_ulong,
    );
    (*event).type_ = YamlMappingEndEvent;
    (*event).start_mark = mark;
    (*event).end_mark = mark;
    yaml_emitter_emit(emitter, event)
}
