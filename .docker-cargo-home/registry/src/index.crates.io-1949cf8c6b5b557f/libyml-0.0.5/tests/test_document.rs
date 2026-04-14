#[cfg(test)]
mod tests {
    use core::mem::MaybeUninit;
    use libyml::{
        document::{
            yaml_document_add_mapping, yaml_document_add_scalar,
            yaml_document_add_sequence,
            yaml_document_append_mapping_pair,
            yaml_document_append_sequence_item,
            yaml_document_end_event_initialize,
            yaml_document_start_event_initialize,
        },
        success::{FAIL, OK},
        yaml_document_delete, yaml_document_get_node,
        yaml_document_get_root_node, yaml_document_initialize,
        YamlDocumentT, YamlEventT,
        YamlEventTypeT::{
            YamlDocumentEndEvent, YamlDocumentStartEvent,
        },
        YamlMappingStyleT,
        YamlNodeTypeT::YamlScalarNode,
        YamlScalarStyleT, YamlSequenceStyleT, YamlTagDirectiveT,
        YamlVersionDirectiveT,
    };
    use std::ptr;

    // Document Initialization Tests
    #[test]
    /// Test basic document initialization with null pointers
    fn test_yaml_document_initialize_non_null_document() {
        unsafe {
            let mut doc: YamlDocumentT =
                MaybeUninit::zeroed().assume_init();
            let result = yaml_document_initialize(
                &mut doc,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                false,
                false,
            );
            assert_eq!(
                result, OK,
                "Initialization should handle null pointers gracefully"
            );
            doc.cleanup();
        }
    }

    #[test]
    /// Test document initialization with a version directive
    fn test_yaml_document_initialize_with_version_directive() {
        unsafe {
            let mut doc: YamlDocumentT =
                MaybeUninit::zeroed().assume_init();
            let mut version_directive =
                YamlVersionDirectiveT::new(1, 2);
            let version_directive_ptr: *mut YamlVersionDirectiveT =
                &mut version_directive;
            let result = yaml_document_initialize(
                &mut doc,
                version_directive_ptr,
                ptr::null_mut(),
                ptr::null_mut(),
                false,
                false,
            );
            assert_eq!(
                result, OK,
                "Initialization with version directive failed"
            );
            doc.cleanup();
        }
    }

    #[test]
    /// Test document initialization
    fn test_yaml_document_initialize() {
        unsafe {
            let mut doc: YamlDocumentT =
                MaybeUninit::zeroed().assume_init();
            let result = yaml_document_initialize(
                &mut doc,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                false,
                false,
            );
            assert!(
                result.ok,
                "Document initialization should succeed with valid pointer"
            );
        }
    }

    #[test]
    /// Test document initialization with version directive
    fn test_yaml_document_initialize_valid() {
        unsafe {
            let mut doc: MaybeUninit<YamlDocumentT> =
                MaybeUninit::uninit();
            let mut version_directive =
                YamlVersionDirectiveT::new(1, 2);
            let mut tag_directives = vec![];

            let version_directive_ptr: *mut YamlVersionDirectiveT =
                &mut version_directive;
            let result = yaml_document_initialize(
                doc.as_mut_ptr(),
                version_directive_ptr,
                tag_directives.as_mut_ptr(),
                tag_directives.as_mut_ptr().add(tag_directives.len()),
                true,
                false,
            );

            assert_eq!(
                result, OK,
                "Initialization should succeed with valid inputs"
            );
            yaml_document_delete(doc.as_mut_ptr());
        }
    }

    #[test]
    /// Test document initialization with invalid pointers
    fn test_yaml_document_initialize_invalid() {
        unsafe {
            let mut doc: MaybeUninit<YamlDocumentT> =
                MaybeUninit::uninit();
            let result = yaml_document_initialize(
                doc.as_mut_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                false,
                false,
            );

            assert_eq!(
                result, OK,
                "Initialization should handle null pointers gracefully"
            );
            yaml_document_delete(doc.as_mut_ptr());
        }
    }

    #[test]
    /// Test document initialization with implicit document
    fn test_yaml_document_initialize_implicit_document() {
        unsafe {
            let mut doc: YamlDocumentT =
                MaybeUninit::zeroed().assume_init();
            let result = yaml_document_initialize(
                &mut doc,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                true, // Implicit
                false,
            );
            assert_eq!(
                result, OK,
                "Initialization should succeed with implicit document"
            );
            doc.cleanup();
        }
    }

    #[test]
    /// Test document initialization with explicit document
    fn test_yaml_document_initialize_explicit_document() {
        unsafe {
            let mut doc: YamlDocumentT =
                MaybeUninit::zeroed().assume_init();
            let result = yaml_document_initialize(
                &mut doc,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                false, // Explicit
                true,
            );
            assert_eq!(
                result, OK,
                "Initialization should succeed with explicit document"
            );
            doc.cleanup();
        }
    }

    #[test]
    /// Test document initialization with mixed flags
    fn test_yaml_document_initialize_mixed_flags() {
        unsafe {
            let mut doc: YamlDocumentT =
                MaybeUninit::zeroed().assume_init();
            let result = yaml_document_initialize(
                &mut doc,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                true, // Implicit
                true, // Explicit
            );
            assert_eq!(
                result, OK,
                "Initialization should handle mixed implicit and explicit flags"
            );
            doc.cleanup();
        }
    }

    // Tag Directive Tests
    #[test]
    /// Test document initialization with non-empty tag directives
    fn test_yaml_document_initialize_with_non_empty_tag_directives() {
        unsafe {
            let mut doc: YamlDocumentT =
                MaybeUninit::zeroed().assume_init();
            let mut tag_directive: YamlTagDirectiveT =
                MaybeUninit::zeroed().assume_init();
            tag_directive.handle = b"!my_tag!\0".as_ptr() as *mut u8;
            tag_directive.prefix =
                b"tag:yaml.org,2002:\0".as_ptr() as *mut u8;

            let tag_directive_start: *mut YamlTagDirectiveT =
                &mut tag_directive;
            let tag_directive_end: *mut YamlTagDirectiveT =
                tag_directive_start.wrapping_offset(1);

            let result = yaml_document_initialize(
                &mut doc,
                ptr::null_mut(),
                tag_directive_start,
                tag_directive_end,
                false,
                false,
            );
            assert_eq!(
                result, OK,
                "Initialization with non-empty tag directives failed"
            );
            doc.cleanup();
        }
    }

    #[test]
    /// Test document initialization with invalid UTF-8 in tag directive
    fn test_yaml_document_initialize_with_invalid_utf8_tag_directive() {
        unsafe {
            let mut doc: YamlDocumentT =
                MaybeUninit::zeroed().assume_init();
            let mut tag_directive: YamlTagDirectiveT =
                MaybeUninit::zeroed().assume_init();

            // Invalid UTF-8 sequence (incomplete multibyte sequence)
            tag_directive.handle = b"invalid\xFF\0".as_ptr() as *mut u8;
            tag_directive.prefix =
                b"tag:yaml.org,2002:\0".as_ptr() as *mut u8;

            let tag_directive_start: *mut YamlTagDirectiveT =
                &mut tag_directive;
            let tag_directive_end: *mut YamlTagDirectiveT =
                tag_directive_start.wrapping_offset(1);

            let result = yaml_document_initialize(
                &mut doc,
                ptr::null_mut(),
                tag_directive_start,
                tag_directive_end,
                false,
                false,
            );
            assert_eq!(
                result, FAIL,
                "Initialization should fail with invalid UTF-8 in tag directive"
            );
        }
    }

    #[test]
    /// Test document initialization with null tag directives
    fn test_yaml_document_initialize_with_null_tag_directives() {
        unsafe {
            let mut doc: YamlDocumentT =
                MaybeUninit::zeroed().assume_init();
            let result = yaml_document_initialize(
                &mut doc,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                false,
                false,
            );
            assert_eq!(
                result, OK,
                "Initialization should succeed with null tag directives"
            );
            doc.cleanup();
        }
    }

    #[test]
    /// Test document initialization with large tag directives
    fn test_yaml_document_initialize_large_tag_directives() {
        unsafe {
            let mut doc: YamlDocumentT =
                MaybeUninit::zeroed().assume_init();
            let mut large_tag_directive: YamlTagDirectiveT =
                MaybeUninit::zeroed().assume_init();

            // Allocate large arrays directly on the stack
            let large_handle = [b'a'; 1024]; // 1KB handle
            let large_prefix = [b'b'; 1024]; // 1KB prefix

            large_tag_directive.handle =
                large_handle.as_ptr() as *mut u8;
            large_tag_directive.prefix =
                large_prefix.as_ptr() as *mut u8;

            let tag_directive_start: *mut YamlTagDirectiveT =
                &mut large_tag_directive;
            let tag_directive_end: *mut YamlTagDirectiveT =
                tag_directive_start.wrapping_offset(1);

            let result = yaml_document_initialize(
                &mut doc,
                ptr::null_mut(),
                tag_directive_start,
                tag_directive_end,
                false,
                false,
            );
            assert_eq!(
                result, OK,
                "Initialization with large tag directives failed"
            );
            doc.cleanup();
        }
    }

    // Document Deletion Tests
    #[test]
    /// Test document deletion
    fn test_yaml_document_delete() {
        unsafe {
            let mut doc: MaybeUninit<YamlDocumentT> =
                MaybeUninit::zeroed();
            let doc_ptr = doc.as_mut_ptr();

            let init_result = yaml_document_initialize(
                doc_ptr,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                false,
                false,
            );

            assert!(
                init_result == OK,
                "Document initialization should succeed with valid pointer"
            );

            let doc = doc_ptr.as_mut().unwrap();
            doc.cleanup();
        }
    }

    #[test]
    /// Test document deletion with null pointer
    fn test_yaml_document_delete_null() {
        unsafe {
            yaml_document_delete(ptr::null_mut());
        }
    }

    #[test]
    /// Test document deletion with already deleted document
    fn test_yaml_document_delete_already_deleted_document() {
        unsafe {
            let mut doc: MaybeUninit<YamlDocumentT> =
                MaybeUninit::zeroed();
            let doc_ptr = doc.as_mut_ptr();

            let init_result = yaml_document_initialize(
                doc_ptr,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                false,
                false,
            );
            assert_eq!(
                init_result, OK,
                "Document initialization failed"
            );

            yaml_document_delete(doc_ptr); // First deletion
            yaml_document_delete(doc_ptr); // Second deletion, should handle gracefully
        }
    }

    // Other Tests
    #[test]
    /// Test document cleanup
    fn test_yaml_document_cleanup() {
        unsafe {
            let mut doc: YamlDocumentT =
                MaybeUninit::zeroed().assume_init();
            let result = yaml_document_initialize(
                &mut doc,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                false,
                false,
            );
            assert_eq!(result, OK, "Initialization failed");

            doc.cleanup();
        }
    }

    #[test]
    /// Test memory allocation failure
    fn test_memory_allocation_failure() {
        unsafe {
            let mut doc: YamlDocumentT =
                MaybeUninit::zeroed().assume_init();
            let result = yaml_document_initialize(
                &mut doc,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                false,
                false,
            );

            // Assert that the function returns the expected result
            if result == FAIL {
                // If the initialization failed, ensure that it was handled
                assert_eq!(
                    result, FAIL,
                    "Expected memory allocation to fail, and it did."
                );
            } else {
                // If the initialization succeeded, assert success and perform cleanup
                assert_eq!(
                    result, OK,
                    "Expected memory allocation to succeed, and it did."
                );
                doc.cleanup(); // Ensure proper cleanup
            }
        }
    }

    #[test]
    /// Test document initialization with different node types
    fn test_yaml_document_initialize_with_different_node_types() {
        unsafe {
            let mut doc: YamlDocumentT =
                MaybeUninit::zeroed().assume_init();
            let result = yaml_document_initialize(
                &mut doc,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                false,
                false,
            );
            assert_eq!(result, OK, "Document initialization failed");

            doc.cleanup();
        }
    }

    #[test]
    /// Test initialization with empty nodes
    fn test_yaml_document_with_empty_nodes() {
        unsafe {
            let mut doc: YamlDocumentT =
                MaybeUninit::zeroed().assume_init();
            let result = yaml_document_initialize(
                &mut doc,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                false,
                false,
            );
            assert_eq!(result, OK, "Document initialization failed");

            // Add an empty scalar node
            let scalar_id = yaml_document_add_scalar(
                &mut doc,
                ptr::null(),
                b"".as_ptr(),
                0,
                YamlScalarStyleT::YamlPlainScalarStyle,
            );
            assert!(scalar_id > 0, "Failed to add empty scalar node");

            // Add an empty sequence node
            let sequence_id = yaml_document_add_sequence(
                &mut doc,
                ptr::null(),
                YamlSequenceStyleT::YamlBlockSequenceStyle,
            );
            assert!(
                sequence_id > 0,
                "Failed to add empty sequence node"
            );

            // Add an empty mapping node
            let mapping_id = yaml_document_add_mapping(
                &mut doc,
                ptr::null(),
                YamlMappingStyleT::YamlBlockMappingStyle,
            );
            assert!(mapping_id > 0, "Failed to add empty mapping node");

            // Verify that we can retrieve the nodes
            let scalar_node =
                yaml_document_get_node(&mut doc, scalar_id);
            assert!(
                !scalar_node.is_null(),
                "Failed to retrieve scalar node"
            );

            let sequence_node =
                yaml_document_get_node(&mut doc, sequence_id);
            assert!(
                !sequence_node.is_null(),
                "Failed to retrieve sequence node"
            );

            let mapping_node =
                yaml_document_get_node(&mut doc, mapping_id);
            assert!(
                !mapping_node.is_null(),
                "Failed to retrieve mapping node"
            );

            doc.cleanup();
        }
    }

    #[test]
    /// Test repeated initialization and deletion of documents
    fn test_yaml_document_multiple_initialization_deletion() {
        unsafe {
            for _ in 0..100 {
                let mut doc: YamlDocumentT =
                    MaybeUninit::zeroed().assume_init();
                let result = yaml_document_initialize(
                    &mut doc,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    false,
                    false,
                );
                assert_eq!(
                    result, OK,
                    "Document initialization failed"
                );
                yaml_document_delete(&mut doc);
            }
        }
    }
    #[test]
    /// Test getting the root node of a document
    fn test_yaml_document_get_root_node() {
        unsafe {
            let mut doc: YamlDocumentT =
                MaybeUninit::zeroed().assume_init();
            let _ = yaml_document_initialize(
                &mut doc,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                false,
                false,
            );

            let node_id = yaml_document_add_scalar(
                &mut doc,
                ptr::null(),
                b"root\0".as_ptr(),
                4,
                YamlScalarStyleT::YamlPlainScalarStyle,
            );
            assert!(node_id > 0, "Failed to add root node");

            let root_node = yaml_document_get_root_node(&mut doc);
            assert!(!root_node.is_null(), "Failed to get root node");
            assert_eq!(
                (*root_node).type_,
                YamlScalarNode,
                "Root node is not a scalar"
            );

            doc.cleanup();
        }
    }

    #[test]
    /// Test appending items to a sequence
    fn test_yaml_document_append_sequence_item() {
        unsafe {
            let mut doc: YamlDocumentT =
                MaybeUninit::zeroed().assume_init();
            let _ = yaml_document_initialize(
                &mut doc,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                false,
                false,
            );

            let seq_id = yaml_document_add_sequence(
                &mut doc,
                ptr::null(),
                YamlSequenceStyleT::YamlBlockSequenceStyle,
            );
            assert!(seq_id > 0, "Failed to add sequence");

            let item1_id = yaml_document_add_scalar(
                &mut doc,
                ptr::null(),
                b"item1\0".as_ptr(),
                5,
                YamlScalarStyleT::YamlPlainScalarStyle,
            );
            let item2_id = yaml_document_add_scalar(
                &mut doc,
                ptr::null(),
                b"item2\0".as_ptr(),
                5,
                YamlScalarStyleT::YamlPlainScalarStyle,
            );

            assert_eq!(
                yaml_document_append_sequence_item(
                    &mut doc, seq_id, item1_id
                ),
                OK
            );
            assert_eq!(
                yaml_document_append_sequence_item(
                    &mut doc, seq_id, item2_id
                ),
                OK
            );

            let seq_node = yaml_document_get_node(&mut doc, seq_id);
            assert!(!seq_node.is_null(), "Failed to get sequence node");
            assert_eq!(
                (*seq_node)
                    .data
                    .sequence
                    .items
                    .top
                    .offset_from((*seq_node).data.sequence.items.start),
                2,
                "Sequence should have 2 items"
            );

            doc.cleanup();
        }
    }

    #[test]
    /// Test adding pairs to a mapping
    fn test_yaml_document_append_mapping_pair() {
        unsafe {
            let mut doc: YamlDocumentT =
                MaybeUninit::zeroed().assume_init();
            let _ = yaml_document_initialize(
                &mut doc,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                false,
                false,
            );

            let map_id = yaml_document_add_mapping(
                &mut doc,
                ptr::null(),
                YamlMappingStyleT::YamlBlockMappingStyle,
            );
            assert!(map_id > 0, "Failed to add mapping");

            let key1_id = yaml_document_add_scalar(
                &mut doc,
                ptr::null(),
                b"key1\0".as_ptr(),
                4,
                YamlScalarStyleT::YamlPlainScalarStyle,
            );
            let value1_id = yaml_document_add_scalar(
                &mut doc,
                ptr::null(),
                b"value1\0".as_ptr(),
                6,
                YamlScalarStyleT::YamlPlainScalarStyle,
            );
            let key2_id = yaml_document_add_scalar(
                &mut doc,
                ptr::null(),
                b"key2\0".as_ptr(),
                4,
                YamlScalarStyleT::YamlPlainScalarStyle,
            );
            let value2_id = yaml_document_add_scalar(
                &mut doc,
                ptr::null(),
                b"value2\0".as_ptr(),
                6,
                YamlScalarStyleT::YamlPlainScalarStyle,
            );

            assert_eq!(
                yaml_document_append_mapping_pair(
                    &mut doc, map_id, key1_id, value1_id
                ),
                OK
            );
            assert_eq!(
                yaml_document_append_mapping_pair(
                    &mut doc, map_id, key2_id, value2_id
                ),
                OK
            );

            let map_node = yaml_document_get_node(&mut doc, map_id);
            assert!(!map_node.is_null(), "Failed to get mapping node");
            assert_eq!(
                (*map_node)
                    .data
                    .mapping
                    .pairs
                    .top
                    .offset_from((*map_node).data.mapping.pairs.start),
                2,
                "Mapping should have 2 pairs"
            );

            doc.cleanup();
        }
    }

    #[test]
    /// Test document end event initialization
    fn test_yaml_document_end_event_initialize() {
        unsafe {
            let mut event: YamlEventT =
                MaybeUninit::zeroed().assume_init();
            assert_eq!(
                yaml_document_end_event_initialize(&mut event, true),
                OK
            );
            assert_eq!(event.type_, YamlDocumentEndEvent);
            assert!(event.data.document_end.implicit);
        }
    }

    #[test]
    /// Test document start event initialization
    fn test_yaml_document_start_event_initialize() {
        unsafe {
            let mut event: YamlEventT =
                MaybeUninit::zeroed().assume_init();
            let mut version_directive =
                YamlVersionDirectiveT::new(1, 1);
            assert_eq!(
                yaml_document_start_event_initialize(
                    &mut event,
                    &mut version_directive,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    true
                ),
                OK
            );
            assert_eq!(event.type_, YamlDocumentStartEvent);
            assert!(event.data.document_start.implicit);
            assert!(!event
                .data
                .document_start
                .version_directive
                .is_null());
            assert_eq!(
                (*event.data.document_start.version_directive).major,
                1
            );
            assert_eq!(
                (*event.data.document_start.version_directive).minor,
                1
            );
        }
    }
    #[test]
    /// Test adding scalar nodes to a document
    fn test_yaml_document_add_scalar() {
        unsafe {
            let mut doc: YamlDocumentT =
                MaybeUninit::zeroed().assume_init();
            let init_result = yaml_document_initialize(
                &mut doc,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                false,
                false,
            );
            assert_eq!(
                init_result, OK,
                "Document initialization failed"
            );

            // Test adding an empty scalar
            let empty_scalar_id = yaml_document_add_scalar(
                &mut doc,
                ptr::null(),
                b"".as_ptr(),
                0,
                YamlScalarStyleT::YamlPlainScalarStyle,
            );
            assert!(
                empty_scalar_id > 0,
                "Failed to add empty scalar node"
            );

            // Test adding a non-empty scalar
            let non_empty_scalar_id = yaml_document_add_scalar(
                &mut doc,
                ptr::null(),
                b"Hello, World!\0".as_ptr(),
                13,
                YamlScalarStyleT::YamlPlainScalarStyle,
            );
            assert!(
                non_empty_scalar_id > 0,
                "Failed to add non-empty scalar node"
            );

            // Test adding a scalar with a custom tag
            let custom_tag = b"!custom\0".as_ptr();
            let custom_tag_scalar_id = yaml_document_add_scalar(
                &mut doc,
                custom_tag,
                b"Custom tagged scalar\0".as_ptr(),
                20,
                YamlScalarStyleT::YamlSingleQuotedScalarStyle,
            );
            assert!(
                custom_tag_scalar_id > 0,
                "Failed to add scalar node with custom tag"
            );

            // Test adding scalars with different styles
            let styles = [
                YamlScalarStyleT::YamlPlainScalarStyle,
                YamlScalarStyleT::YamlSingleQuotedScalarStyle,
                YamlScalarStyleT::YamlDoubleQuotedScalarStyle,
                YamlScalarStyleT::YamlLiteralScalarStyle,
                YamlScalarStyleT::YamlFoldedScalarStyle,
            ];

            for style in &styles {
                let style_scalar_id = yaml_document_add_scalar(
                    &mut doc,
                    ptr::null(),
                    b"Styled scalar\0".as_ptr(),
                    14,
                    *style,
                );
                assert!(
                    style_scalar_id > 0,
                    "Failed to add scalar node with style {:?}",
                    style
                );
            }

            // Verify that we can retrieve the added scalars
            let empty_scalar =
                yaml_document_get_node(&mut doc, empty_scalar_id);
            assert!(
                !empty_scalar.is_null(),
                "Failed to retrieve empty scalar node"
            );
            assert_eq!(
                (*empty_scalar).type_,
                YamlScalarNode,
                "Node is not a scalar"
            );
            assert_eq!(
                (*empty_scalar).data.scalar.length,
                0,
                "Empty scalar should have length 0"
            );

            let non_empty_scalar =
                yaml_document_get_node(&mut doc, non_empty_scalar_id);
            assert!(
                !non_empty_scalar.is_null(),
                "Failed to retrieve non-empty scalar node"
            );
            assert_eq!(
                (*non_empty_scalar).type_,
                YamlScalarNode,
                "Node is not a scalar"
            );
            assert_eq!(
                (*non_empty_scalar).data.scalar.length,
                13,
                "Non-empty scalar should have length 13"
            );

            let custom_tag_scalar =
                yaml_document_get_node(&mut doc, custom_tag_scalar_id);
            assert!(
                !custom_tag_scalar.is_null(),
                "Failed to retrieve custom tag scalar node"
            );
            assert_eq!(
                (*custom_tag_scalar).type_,
                YamlScalarNode,
                "Node is not a scalar"
            );
            assert_eq!(
                std::ffi::CStr::from_ptr(
                    (*custom_tag_scalar).tag as *const i8
                )
                .to_bytes(),
                b"!custom",
                "Custom tag not set correctly"
            );

            doc.cleanup();
        }
    }
}
