use crate::externs::{memcpy, memset, strlen};
use crate::internal::yaml_check_utf8;
use crate::internal::yaml_stack_extend;
use crate::memory::{yaml_free, yaml_malloc, yaml_strdup};
use crate::ops::ForceAdd;
use crate::success::{Success, FAIL, OK};
use crate::yaml::{size_t, yaml_char_t};
use crate::YamlEventT;
use crate::YamlEventTypeT::YamlDocumentEndEvent;
use crate::YamlEventTypeT::YamlDocumentStartEvent;
use crate::{
    libc, PointerExt, YamlDocumentT, YamlMappingNode,
    YamlMappingStyleT, YamlMarkT, YamlNodeItemT, YamlNodePairT,
    YamlNodeT, YamlScalarNode, YamlScalarStyleT, YamlSequenceNode,
    YamlSequenceStyleT, YamlTagDirectiveT, YamlVersionDirectiveT,
};
use core::mem::{size_of, MaybeUninit};
use core::ptr::{self, addr_of_mut};
/// Create a YAML document.
///
/// This function initializes a `YamlDocumentT` struct with the provided version directive,
/// tag directives, and implicit flags. It allocates memory for the document data and
/// copies the provided directives.
///
/// # Safety
///
/// - `document` must be a valid, non-null pointer to a `YamlDocumentT` struct that can be safely written to.
/// - `version_directive`, if not null, must point to a valid `YamlVersionDirectiveT` struct.
/// - `tag_directives_start` and `tag_directives_end` must be valid pointers to `YamlTagDirectiveT` structs, or both must be null.
/// - If `tag_directives_start` and `tag_directives_end` are not null, the range they define must contain valid `YamlTagDirectiveT` structs with non-null `handle` and `prefix` members, and the `handle` and `prefix` strings must be valid UTF-8.
/// - The `YamlDocumentT`, `YamlVersionDirectiveT`, and `YamlTagDirectiveT` structs must be properly aligned and have the expected memory layout.
/// - The caller is responsible for freeing the memory allocated for the document using `yaml_document_delete`.
///
pub unsafe fn yaml_document_initialize(
    document: *mut YamlDocumentT,
    version_directive: *mut YamlVersionDirectiveT,
    tag_directives_start: *mut YamlTagDirectiveT,
    tag_directives_end: *mut YamlTagDirectiveT,
    start_implicit: bool,
    end_implicit: bool,
) -> Success {
    let current_block: u64;
    struct Nodes {
        start: *mut YamlNodeT,
        end: *mut YamlNodeT,
        top: *mut YamlNodeT,
    }
    let mut nodes = Nodes {
        start: ptr::null_mut::<YamlNodeT>(),
        end: ptr::null_mut::<YamlNodeT>(),
        top: ptr::null_mut::<YamlNodeT>(),
    };
    let mut version_directive_copy: *mut YamlVersionDirectiveT =
        ptr::null_mut::<YamlVersionDirectiveT>();
    struct TagDirectivesCopy {
        start: *mut YamlTagDirectiveT,
        end: *mut YamlTagDirectiveT,
        top: *mut YamlTagDirectiveT,
    }
    let mut tag_directives_copy = TagDirectivesCopy {
        start: ptr::null_mut::<YamlTagDirectiveT>(),
        end: ptr::null_mut::<YamlTagDirectiveT>(),
        top: ptr::null_mut::<YamlTagDirectiveT>(),
    };
    let mut value = YamlTagDirectiveT {
        handle: ptr::null_mut::<yaml_char_t>(),
        prefix: ptr::null_mut::<yaml_char_t>(),
    };
    let mark = YamlMarkT {
        index: 0_u64,
        line: 0_u64,
        column: 0_u64,
    };
    __assert!(!document.is_null());
    __assert!(
        !tag_directives_start.is_null()
            && !tag_directives_end.is_null()
            || tag_directives_start == tag_directives_end
    );
    STACK_INIT!(nodes, YamlNodeT);
    if !version_directive.is_null() {
        version_directive_copy =
            yaml_malloc(
                size_of::<YamlVersionDirectiveT>() as libc::c_ulong
            ) as *mut YamlVersionDirectiveT;
        (*version_directive_copy).major = (*version_directive).major;
        (*version_directive_copy).minor = (*version_directive).minor;
    }
    if tag_directives_start != tag_directives_end {
        let mut tag_directive: *mut YamlTagDirectiveT;
        STACK_INIT!(tag_directives_copy, YamlTagDirectiveT);
        tag_directive = tag_directives_start;
        loop {
            if tag_directive == tag_directives_end {
                current_block = 14818589718467733107;
                break;
            }
            __assert!(!((*tag_directive).handle).is_null());
            __assert!(!((*tag_directive).prefix).is_null());
            if yaml_check_utf8(
                (*tag_directive).handle,
                strlen((*tag_directive).handle as *mut libc::c_char),
            )
            .fail
            {
                current_block = 8142820162064489797;
                break;
            }
            if yaml_check_utf8(
                (*tag_directive).prefix,
                strlen((*tag_directive).prefix as *mut libc::c_char),
            )
            .fail
            {
                current_block = 8142820162064489797;
                break;
            }
            value.handle = yaml_strdup((*tag_directive).handle);
            value.prefix = yaml_strdup((*tag_directive).prefix);
            if value.handle.is_null() || value.prefix.is_null() {
                current_block = 8142820162064489797;
                break;
            }
            PUSH!(tag_directives_copy, value);
            value.handle = ptr::null_mut::<yaml_char_t>();
            value.prefix = ptr::null_mut::<yaml_char_t>();
            tag_directive = tag_directive.wrapping_offset(1);
        }
    } else {
        current_block = 14818589718467733107;
    }
    if current_block != 8142820162064489797 {
        let _ = memset(
            document as *mut libc::c_void,
            0,
            size_of::<YamlDocumentT>() as libc::c_ulong,
        );
        let fresh176 = addr_of_mut!((*document).nodes.start);
        *fresh176 = nodes.start;
        let fresh177 = addr_of_mut!((*document).nodes.end);
        *fresh177 = nodes.end;
        let fresh178 = addr_of_mut!((*document).nodes.top);
        *fresh178 = nodes.start;
        let fresh179 = addr_of_mut!((*document).version_directive);
        *fresh179 = version_directive_copy;
        let fresh180 = addr_of_mut!((*document).tag_directives.start);
        *fresh180 = tag_directives_copy.start;
        let fresh181 = addr_of_mut!((*document).tag_directives.end);
        *fresh181 = tag_directives_copy.top;
        (*document).start_implicit = start_implicit;
        (*document).end_implicit = end_implicit;
        (*document).start_mark = mark;
        (*document).end_mark = mark;
        return OK;
    }
    STACK_DEL!(nodes);
    yaml_free(version_directive_copy as *mut libc::c_void);
    while !STACK_EMPTY!(tag_directives_copy) {
        let value = POP!(tag_directives_copy);
        yaml_free(value.handle as *mut libc::c_void);
        yaml_free(value.prefix as *mut libc::c_void);
    }
    STACK_DEL!(tag_directives_copy);
    yaml_free(value.handle as *mut libc::c_void);
    yaml_free(value.prefix as *mut libc::c_void);
    FAIL
}

/// Delete a YAML document and all its nodes.
///
/// This function frees the memory allocated for a `YamlDocumentT` struct and all its associated
/// nodes, including scalar values, sequences, and mappings.
///
/// # Safety
///
/// - `document` must be a valid, non-null pointer to a `YamlDocumentT` struct.
/// - The `YamlDocumentT` struct and its associated nodes must have been properly initialized and their memory allocated correctly.
/// - The `YamlDocumentT` struct and its associated nodes must be properly aligned and have the expected memory layout.
///
pub unsafe fn yaml_document_delete(document: *mut YamlDocumentT) {
    // Check if the document pointer is null
    if document.is_null() {
        return; // If the pointer is null, return early to avoid any dereferencing
    }

    let mut tag_directive: *mut YamlTagDirectiveT;

    // Proceed with deletion only if the document pointer is valid (non-null)
    while !STACK_EMPTY!((*document).nodes) {
        let mut node = POP!((*document).nodes);
        yaml_free(node.tag as *mut libc::c_void);
        match node.type_ {
            YamlScalarNode => {
                yaml_free(node.data.scalar.value as *mut libc::c_void);
            }
            YamlSequenceNode => {
                STACK_DEL!(node.data.sequence.items);
            }
            YamlMappingNode => {
                STACK_DEL!(node.data.mapping.pairs);
            }
            _ => {
                __assert!(false);
            }
        }
    }
    STACK_DEL!((*document).nodes);
    yaml_free((*document).version_directive as *mut libc::c_void);

    // Handle tag directives
    tag_directive = (*document).tag_directives.start;
    while tag_directive != (*document).tag_directives.end {
        yaml_free((*tag_directive).handle as *mut libc::c_void);
        yaml_free((*tag_directive).prefix as *mut libc::c_void);
        tag_directive = tag_directive.wrapping_offset(1);
    }
    yaml_free((*document).tag_directives.start as *mut libc::c_void);

    // Clear the memory of the document structure itself
    let _ = memset(
        document as *mut libc::c_void,
        0,
        size_of::<YamlDocumentT>() as libc::c_ulong,
    );
}

/// Get a node of a YAML document.
///
/// This function returns a pointer to the node at the specified `index` in the document's node
/// stack. The pointer returned by this function is valid until any of the functions modifying the
/// document are called.
///
/// Returns the node object or NULL if `index` is out of range.
///
/// # Safety
///
/// - `document` must be a valid, non-null pointer to a `YamlDocumentT` struct.
/// - `index` must be a valid index within the range of nodes in the `YamlDocumentT` struct.
/// - The `YamlDocumentT` struct and its associated nodes must be properly initialized and their memory allocated correctly.
/// - The `YamlDocumentT` struct and its associated nodes must be properly aligned and have the expected memory layout.
/// - The caller must not modify or free the returned pointer, as it is owned by the `YamlDocumentT` struct.
///
pub unsafe fn yaml_document_get_node(
    document: *mut YamlDocumentT,
    index: libc::c_int,
) -> *mut YamlNodeT {
    __assert!(!document.is_null());
    if index > 0
        && (*document).nodes.start.wrapping_offset(index as isize)
            <= (*document).nodes.top
    {
        return (*document)
            .nodes
            .start
            .wrapping_offset(index as isize)
            .wrapping_offset(-1_isize);
    }
    ptr::null_mut::<YamlNodeT>()
}

/// Get the root of a YAML document node.
///
/// This function returns a pointer to the root node of the YAML document. The root object is the
/// first object added to the document.
///
/// The pointer returned by this function is valid until any of the functions modifying the
/// document are called.
///
/// An empty document produced by the parser signifies the end of a YAML stream.
///
/// Returns the node object or NULL if the document is empty.
///
/// # Safety
///
/// - `document` must be a valid, non-null pointer to a `YamlDocumentT` struct.
/// - The `YamlDocumentT` struct and its associated nodes must be properly initialized and their memory allocated correctly.
/// - The `YamlDocumentT` struct and its associated nodes must be properly aligned and have the expected memory layout.
/// - The caller must not modify or free the returned pointer, as it is owned by the `YamlDocumentT` struct.
///
pub unsafe fn yaml_document_get_root_node(
    document: *mut YamlDocumentT,
) -> *mut YamlNodeT {
    __assert!(!document.is_null());
    if (*document).nodes.top != (*document).nodes.start {
        return (*document).nodes.start;
    }
    ptr::null_mut::<YamlNodeT>()
}

/// Create a SCALAR node and attach it to the document.
///
/// This function creates a new SCALAR node with the provided `tag`, `value`, and `style`, and
/// adds it to the document's node stack.
///
/// The `style` argument may be ignored by the emitter.
///
/// Returns the node id or 0 on error.
///
/// # Safety
///
/// - `document` must be a valid, non-null pointer to a `YamlDocumentT` struct.
/// - `value` must be a valid, non-null pointer to a null-terminated UTF-8 string.
/// - `tag`, if not null, must be a valid pointer to a null-terminated UTF-8 string.
/// - The `YamlDocumentT` struct and its associated nodes must be properly initialized and their memory allocated correctly.
/// - The `YamlDocumentT` struct and its associated nodes must be properly aligned and have the expected memory layout.
/// - The caller is responsible for freeing the memory allocated for the document using `yaml_document_delete`.
///
#[must_use]
pub unsafe fn yaml_document_add_scalar(
    document: *mut YamlDocumentT,
    mut tag: *const yaml_char_t,
    value: *const yaml_char_t,
    mut length: libc::c_int,
    style: YamlScalarStyleT,
) -> libc::c_int {
    let mark = YamlMarkT {
        index: 0_u64,
        line: 0_u64,
        column: 0_u64,
    };
    let mut tag_copy: *mut yaml_char_t = ptr::null_mut::<yaml_char_t>();
    let mut value_copy: *mut yaml_char_t =
        ptr::null_mut::<yaml_char_t>();
    let mut node = MaybeUninit::<YamlNodeT>::uninit();
    let node = node.as_mut_ptr();
    __assert!(!document.is_null());
    __assert!(!value.is_null());
    if tag.is_null() {
        tag = b"tag:yaml.org,2002:str\0" as *const u8
            as *const libc::c_char as *mut yaml_char_t;
    }
    if yaml_check_utf8(tag, strlen(tag as *mut libc::c_char)).ok {
        tag_copy = yaml_strdup(tag);
        if !tag_copy.is_null() {
            if length < 0 {
                length =
                    strlen(value as *mut libc::c_char) as libc::c_int;
            }
            if yaml_check_utf8(value, length as size_t).ok {
                value_copy = yaml_malloc(length.force_add(1) as size_t)
                    as *mut yaml_char_t;
                let _ = memcpy(
                    value_copy as *mut libc::c_void,
                    value as *const libc::c_void,
                    length as libc::c_ulong,
                );
                *value_copy.wrapping_offset(length as isize) = b'\0';
                let _ = memset(
                    node as *mut libc::c_void,
                    0,
                    size_of::<YamlNodeT>() as libc::c_ulong,
                );
                (*node).type_ = YamlScalarNode;
                (*node).tag = tag_copy;
                (*node).start_mark = mark;
                (*node).end_mark = mark;
                (*node).data.scalar.value = value_copy;
                (*node).data.scalar.length = length as size_t;
                (*node).data.scalar.style = style;
                PUSH!((*document).nodes, *node);
                return (*document)
                    .nodes
                    .top
                    .c_offset_from((*document).nodes.start)
                    as libc::c_int;
            }
        }
    }
    yaml_free(tag_copy as *mut libc::c_void);
    yaml_free(value_copy as *mut libc::c_void);
    0
}

/// Create a SEQUENCE node and attach it to the document.
///
/// This function creates a new SEQUENCE node with the provided `tag` and `style`, and adds it to
/// the document's node stack.
///
/// The `style` argument may be ignored by the emitter.
///
/// Returns the node id or 0 on error.
///
/// # Safety
///
/// - `document` must be a valid, non-null pointer to a `YamlDocumentT` struct.
/// - `tag`, if not null, must be a valid pointer to a null-terminated UTF-8 string.
/// - The `YamlDocumentT` struct and its associated nodes must be properly initialized and their memory allocated correctly.
/// - The `YamlDocumentT` struct and its associated nodes must be properly aligned and have the expected memory layout.
/// - The caller is responsible for freeing the memory allocated for the document using `yaml_document_delete`.
///
#[must_use]
pub unsafe fn yaml_document_add_sequence(
    document: *mut YamlDocumentT,
    mut tag: *const yaml_char_t,
    style: YamlSequenceStyleT,
) -> libc::c_int {
    let mark = YamlMarkT {
        index: 0_u64,
        line: 0_u64,
        column: 0_u64,
    };
    let mut tag_copy: *mut yaml_char_t = ptr::null_mut::<yaml_char_t>();
    struct Items {
        start: *mut YamlNodeItemT,
        end: *mut YamlNodeItemT,
        top: *mut YamlNodeItemT,
    }
    let mut items = Items {
        start: ptr::null_mut::<YamlNodeItemT>(),
        end: ptr::null_mut::<YamlNodeItemT>(),
        top: ptr::null_mut::<YamlNodeItemT>(),
    };
    let mut node = MaybeUninit::<YamlNodeT>::uninit();
    let node = node.as_mut_ptr();
    __assert!(!document.is_null());
    if tag.is_null() {
        tag = b"tag:yaml.org,2002:seq\0" as *const u8
            as *const libc::c_char as *mut yaml_char_t;
    }
    if yaml_check_utf8(tag, strlen(tag as *mut libc::c_char)).ok {
        tag_copy = yaml_strdup(tag);
        if !tag_copy.is_null() {
            STACK_INIT!(items, YamlNodeItemT);
            let _ = memset(
                node as *mut libc::c_void,
                0,
                size_of::<YamlNodeT>() as libc::c_ulong,
            );
            (*node).type_ = YamlSequenceNode;
            (*node).tag = tag_copy;
            (*node).start_mark = mark;
            (*node).end_mark = mark;
            (*node).data.sequence.items.start = items.start;
            (*node).data.sequence.items.end = items.end;
            (*node).data.sequence.items.top = items.start;
            (*node).data.sequence.style = style;
            PUSH!((*document).nodes, *node);
            return (*document)
                .nodes
                .top
                .c_offset_from((*document).nodes.start)
                as libc::c_int;
        }
    }
    STACK_DEL!(items);
    yaml_free(tag_copy as *mut libc::c_void);
    0
}

/// Create a MAPPING node and attach it to the document.
///
/// This function creates a new MAPPING node with the provided `tag` and `style`, and adds it to
/// the document's node stack.
///
/// The `style` argument may be ignored by the emitter.
///
/// Returns the node id or 0 on error.
///
/// # Safety
///
/// - `document` must be a valid, non-null pointer to a `YamlDocumentT` struct.
/// - `tag`, if not null, must be a valid pointer to a null-terminated UTF-8 string.
/// - The `YamlDocumentT` struct and its associated nodes must be properly initialized and their memory allocated correctly.
/// - The `YamlDocumentT` struct and its associated nodes must be properly aligned and have the expected memory layout.
/// - The caller is responsible for freeing the memory allocated for the document using `yaml_document_delete`.
///
#[must_use]
pub unsafe fn yaml_document_add_mapping(
    document: *mut YamlDocumentT,
    mut tag: *const yaml_char_t,
    style: YamlMappingStyleT,
) -> libc::c_int {
    let mark = YamlMarkT {
        index: 0_u64,
        line: 0_u64,
        column: 0_u64,
    };
    let mut tag_copy: *mut yaml_char_t = ptr::null_mut::<yaml_char_t>();
    struct Pairs {
        start: *mut YamlNodePairT,
        end: *mut YamlNodePairT,
        top: *mut YamlNodePairT,
    }
    let mut pairs = Pairs {
        start: ptr::null_mut::<YamlNodePairT>(),
        end: ptr::null_mut::<YamlNodePairT>(),
        top: ptr::null_mut::<YamlNodePairT>(),
    };
    let mut node = MaybeUninit::<YamlNodeT>::uninit();
    let node = node.as_mut_ptr();
    __assert!(!document.is_null());
    if tag.is_null() {
        tag = b"tag:yaml.org,2002:map\0" as *const u8
            as *const libc::c_char as *mut yaml_char_t;
    }
    if yaml_check_utf8(tag, strlen(tag as *mut libc::c_char)).ok {
        tag_copy = yaml_strdup(tag);
        if !tag_copy.is_null() {
            STACK_INIT!(pairs, YamlNodePairT);
            let _ = memset(
                node as *mut libc::c_void,
                0,
                size_of::<YamlNodeT>() as libc::c_ulong,
            );
            (*node).type_ = YamlMappingNode;
            (*node).tag = tag_copy;
            (*node).start_mark = mark;
            (*node).end_mark = mark;
            (*node).data.mapping.pairs.start = pairs.start;
            (*node).data.mapping.pairs.end = pairs.end;
            (*node).data.mapping.pairs.top = pairs.start;
            (*node).data.mapping.style = style;
            PUSH!((*document).nodes, *node);
            return (*document)
                .nodes
                .top
                .c_offset_from((*document).nodes.start)
                as libc::c_int;
        }
    }
    STACK_DEL!(pairs);
    yaml_free(tag_copy as *mut libc::c_void);
    0
}

/// Add an item to a SEQUENCE node.
///
/// This function adds a node with the given `item` id to the sequence node with the given
/// `sequence` id in the document.
///
/// # Safety
///
/// - `document` must be a valid, non-null pointer to a `YamlDocumentT` struct.
/// - `sequence` must be a valid index within the range of nodes in the `YamlDocumentT` struct, and the node at that index must be a `YamlSequenceNode`.
/// - `item` must be a valid index within the range of nodes in the `YamlDocumentT` struct.
/// - The `YamlDocumentT` struct and its associated nodes must be properly initialized and their memory allocated correctly.
/// - The `YamlDocumentT` struct and its associated nodes must be properly aligned and have the expected memory layout.
///
pub unsafe fn yaml_document_append_sequence_item(
    document: *mut YamlDocumentT,
    sequence: libc::c_int,
    item: libc::c_int,
) -> Success {
    __assert!(!document.is_null());
    __assert!(
        sequence > 0
            && ((*document).nodes.start)
                .wrapping_offset(sequence as isize)
                <= (*document).nodes.top
    );
    __assert!(
        (*((*document).nodes.start)
            .wrapping_offset((sequence - 1) as isize))
        .type_
            == YamlSequenceNode
    );
    __assert!(
        item > 0
            && ((*document).nodes.start).wrapping_offset(item as isize)
                <= (*document).nodes.top
    );
    PUSH!(
        (*((*document).nodes.start)
            .wrapping_offset((sequence - 1) as isize))
        .data
        .sequence
        .items,
        item
    );
    OK
}

/// Add a pair of a key and a value to a MAPPING node.
///
/// This function adds a key-value pair to the mapping node with the given `mapping` id in the
/// document. The `key` and `value` arguments are the ids of the nodes to be used as the key and
/// value, respectively.
///
/// # Safety
///
/// - `document` must be a valid, non-null pointer to a `YamlDocumentT` struct.
/// - `mapping` must be a valid index within the range of nodes in the `YamlDocumentT` struct, and the node at that index must be a `YamlMappingNode`.
/// - `key` and `value` must be valid indices within the range of nodes in the `YamlDocumentT` struct.
/// - The `YamlDocumentT` struct and its associated nodes must be properly initialized and their memory allocated correctly.
/// - The `YamlDocumentT` struct and its associated nodes must be properly aligned and have the expected memory layout.
///
pub unsafe fn yaml_document_append_mapping_pair(
    document: *mut YamlDocumentT,
    mapping: libc::c_int,
    key: libc::c_int,
    value: libc::c_int,
) -> Success {
    __assert!(!document.is_null());
    __assert!(
        mapping > 0
            && ((*document).nodes.start)
                .wrapping_offset(mapping as isize)
                <= (*document).nodes.top
    );
    __assert!(
        (*((*document).nodes.start)
            .wrapping_offset((mapping - 1) as isize))
        .type_
            == YamlMappingNode
    );
    __assert!(
        key > 0
            && ((*document).nodes.start).wrapping_offset(key as isize)
                <= (*document).nodes.top
    );
    __assert!(
        value > 0
            && ((*document).nodes.start)
                .wrapping_offset(value as isize)
                <= (*document).nodes.top
    );
    let pair = YamlNodePairT { key, value };
    PUSH!(
        (*((*document).nodes.start)
            .wrapping_offset((mapping - 1) as isize))
        .data
        .mapping
        .pairs,
        pair
    );
    OK
}

/// Create the DOCUMENT-END event.
///
/// The `implicit` argument is considered as a stylistic parameter and may be
/// ignored by the emitter.
///
/// # Safety
///
/// - `event` must be a valid, non-null pointer to a `YamlEventT` struct that can be safely written to.
/// - The `YamlEventT` struct must be properly aligned and have the expected memory layout.
///
pub unsafe fn yaml_document_end_event_initialize(
    event: *mut YamlEventT,
    implicit: bool,
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
    (*event).type_ = YamlDocumentEndEvent;
    (*event).start_mark = mark;
    (*event).end_mark = mark;
    (*event).data.document_end.implicit = implicit;
    OK
}

/// Create the DOCUMENT-START event.
///
/// The `implicit` argument is considered as a stylistic parameter and may be
/// ignored by the emitter.
///
/// # Safety
///
/// - `event` must be a valid, non-null pointer to a `YamlEventT` struct that can be safely written to.
/// - `version_directive`, if not null, must point to a valid `YamlVersionDirectiveT` struct.
/// - `tag_directives_start` and `tag_directives_end` must be valid pointers to `YamlTagDirectiveT` structs, or both must be null.
/// - If `tag_directives_start` and `tag_directives_end` are not null, the range they define must contain valid `YamlTagDirectiveT` structs with non-null `handle` and `prefix` members, and the `handle` and `prefix` strings must be valid UTF-8.
/// - The `YamlEventT`, `YamlVersionDirectiveT`, and `YamlTagDirectiveT` structs must be properly aligned and have the expected memory layout.
/// - The caller is responsible for freeing any dynamically allocated memory associated with the event using `yaml_event_delete`.
///
pub unsafe fn yaml_document_start_event_initialize(
    event: *mut YamlEventT,
    version_directive: *mut YamlVersionDirectiveT,
    tag_directives_start: *mut YamlTagDirectiveT,
    tag_directives_end: *mut YamlTagDirectiveT,
    implicit: bool,
) -> Success {
    let current_block: u64;
    let mark = YamlMarkT {
        index: 0_u64,
        line: 0_u64,
        column: 0_u64,
    };
    let mut version_directive_copy: *mut YamlVersionDirectiveT =
        ptr::null_mut::<YamlVersionDirectiveT>();
    struct TagDirectivesCopy {
        start: *mut YamlTagDirectiveT,
        end: *mut YamlTagDirectiveT,
        top: *mut YamlTagDirectiveT,
    }
    let mut tag_directives_copy = TagDirectivesCopy {
        start: ptr::null_mut::<YamlTagDirectiveT>(),
        end: ptr::null_mut::<YamlTagDirectiveT>(),
        top: ptr::null_mut::<YamlTagDirectiveT>(),
    };
    let mut value = YamlTagDirectiveT {
        handle: ptr::null_mut::<yaml_char_t>(),
        prefix: ptr::null_mut::<yaml_char_t>(),
    };
    __assert!(!event.is_null());
    __assert!(
        !tag_directives_start.is_null()
            && !tag_directives_end.is_null()
            || tag_directives_start == tag_directives_end
    );
    if !version_directive.is_null() {
        version_directive_copy =
            yaml_malloc(
                size_of::<YamlVersionDirectiveT>() as libc::c_ulong
            ) as *mut YamlVersionDirectiveT;
        (*version_directive_copy).major = (*version_directive).major;
        (*version_directive_copy).minor = (*version_directive).minor;
    }
    if tag_directives_start != tag_directives_end {
        let mut tag_directive: *mut YamlTagDirectiveT;
        STACK_INIT!(tag_directives_copy, YamlTagDirectiveT);
        tag_directive = tag_directives_start;
        loop {
            if tag_directive == tag_directives_end {
                current_block = 16203760046146113240;
                break;
            }
            __assert!(!((*tag_directive).handle).is_null());
            __assert!(!((*tag_directive).prefix).is_null());
            if yaml_check_utf8(
                (*tag_directive).handle,
                strlen((*tag_directive).handle as *mut libc::c_char),
            )
            .fail
            {
                current_block = 14964981520188694172;
                break;
            }
            if yaml_check_utf8(
                (*tag_directive).prefix,
                strlen((*tag_directive).prefix as *mut libc::c_char),
            )
            .fail
            {
                current_block = 14964981520188694172;
                break;
            }
            value.handle = yaml_strdup((*tag_directive).handle);
            value.prefix = yaml_strdup((*tag_directive).prefix);
            if value.handle.is_null() || value.prefix.is_null() {
                current_block = 14964981520188694172;
                break;
            }
            PUSH!(tag_directives_copy, value);
            value.handle = ptr::null_mut::<yaml_char_t>();
            value.prefix = ptr::null_mut::<yaml_char_t>();
            tag_directive = tag_directive.wrapping_offset(1);
        }
    } else {
        current_block = 16203760046146113240;
    }
    if current_block != 14964981520188694172 {
        let _ = memset(
            event as *mut libc::c_void,
            0,
            size_of::<YamlEventT>() as libc::c_ulong,
        );
        (*event).type_ = YamlDocumentStartEvent;
        (*event).start_mark = mark;
        (*event).end_mark = mark;
        let fresh164 = addr_of_mut!(
            (*event).data.document_start.version_directive
        );
        *fresh164 = version_directive_copy;
        let fresh165 = addr_of_mut!(
            (*event).data.document_start.tag_directives.start
        );
        *fresh165 = tag_directives_copy.start;
        let fresh166 = addr_of_mut!(
            (*event).data.document_start.tag_directives.end
        );
        *fresh166 = tag_directives_copy.top;
        (*event).data.document_start.implicit = implicit;
        return OK;
    }
    yaml_free(version_directive_copy as *mut libc::c_void);
    while !STACK_EMPTY!(tag_directives_copy) {
        let value = POP!(tag_directives_copy);
        yaml_free(value.handle as *mut libc::c_void);
        yaml_free(value.prefix as *mut libc::c_void);
    }
    STACK_DEL!(tag_directives_copy);
    yaml_free(value.handle as *mut libc::c_void);
    yaml_free(value.prefix as *mut libc::c_void);
    FAIL
}
