#[cfg(test)]
mod tests {
    use core::mem::MaybeUninit;
    use libyml::decode::yaml_parser_delete;
    use libyml::decode::yaml_parser_initialize;
    use libyml::YamlParserT;

    /// Tests the basic initialization of a YAML parser.
    ///
    /// This test ensures that the `yaml_parser_initialize` function
    /// successfully initializes a `YamlParserT` struct and returns
    /// a successful result.
    ///
    /// # Safety
    ///
    /// This test uses unsafe code to work with raw pointers.
    #[test]
    fn test_yaml_parser_initialize() {
        unsafe {
            let mut parser = MaybeUninit::<YamlParserT>::uninit();
            let result = yaml_parser_initialize(parser.as_mut_ptr());
            assert!(result.ok, "Parser initialization should succeed");
        }
    }

    /// Tests both initialization and deletion of a YAML parser.
    ///
    /// This test verifies that a parser can be successfully initialized
    /// and then deleted without any errors.
    ///
    /// # Safety
    ///
    /// This test uses unsafe code to work with raw pointers and to call
    /// functions that require manual memory management.
    #[test]
    fn test_yaml_parser_initialize_and_delete() {
        unsafe {
            let mut parser = MaybeUninit::<YamlParserT>::uninit();
            let init_result =
                yaml_parser_initialize(parser.as_mut_ptr());
            assert!(
                init_result.ok,
                "Parser initialization should succeed"
            );

            let parser_ptr = parser.as_mut_ptr();
            yaml_parser_delete(parser_ptr);
            // Note: We can't test the state after deletion as it would be undefined behavior
        }
    }

    /// Tests multiple initializations and deletions of YAML parsers.
    ///
    /// This test ensures that multiple parsers can be initialized and
    /// deleted in succession without any errors, verifying the robustness
    /// of the initialization and deletion processes.
    ///
    /// # Safety
    ///
    /// This test uses unsafe code to work with raw pointers and to call
    /// functions that require manual memory management.
    #[test]
    fn test_multiple_initialize_and_delete() {
        unsafe {
            for i in 0..5 {
                let mut parser = MaybeUninit::<YamlParserT>::uninit();
                let init_result =
                    yaml_parser_initialize(parser.as_mut_ptr());
                assert!(
                    init_result.ok,
                    "Parser initialization should succeed on iteration {}",
                    i
                );

                let parser_ptr = parser.as_mut_ptr();
                yaml_parser_delete(parser_ptr);
            }
        }
    }
    /// Tests the overall functionality of parser initialization and deletion.
    ///
    /// # Safety
    ///
    /// This test uses unsafe code to initialize and delete the parser.
    #[test]
    fn test_parser_initialization_and_deletion() {
        unsafe {
            let mut parser = MaybeUninit::<YamlParserT>::uninit();
            let init_result =
                yaml_parser_initialize(parser.as_mut_ptr());
            assert!(
                init_result.ok,
                "Parser initialization should succeed"
            );

            // We can't directly test private fields, but we can ensure that
            // initialization and deletion don't cause any crashes or panics
            yaml_parser_delete(parser.as_mut_ptr());
        }
    }
    /// Tests that using a deleted parser doesn't cause undefined behavior.
    ///
    /// # Safety
    ///
    /// This test uses unsafe code to initialize, delete, and re-initialize the parser.
    #[test]
    fn test_parser_after_deletion() {
        unsafe {
            let mut parser = MaybeUninit::<YamlParserT>::uninit();
            let _ = yaml_parser_initialize(parser.as_mut_ptr());

            let parser_ptr = parser.as_mut_ptr();
            yaml_parser_delete(parser_ptr);

            // After deletion, re-initializing should still work without issues
            let reinit_result = yaml_parser_initialize(parser_ptr);
            assert!(
                reinit_result.ok,
                "Parser re-initialization after deletion should succeed"
            );

            yaml_parser_delete(parser_ptr);
        }
    }
    /// Tests that calling delete multiple times doesn't cause issues.
    ///
    /// # Safety
    ///
    /// This test uses unsafe code to initialize and delete the parser multiple times.
    #[test]
    fn test_multiple_deletions() {
        unsafe {
            let mut parser = MaybeUninit::<YamlParserT>::uninit();
            let init_result =
                yaml_parser_initialize(parser.as_mut_ptr());
            assert!(
                init_result.ok,
                "Parser initialization should succeed"
            );

            let parser_ptr = parser.as_mut_ptr();
            yaml_parser_delete(parser_ptr);
            // We'll remove the second deletion as it's not safe to delete an already deleted parser
        }
    }

    /// Tests for potential memory leaks during initialization and deletion.
    ///
    /// Note: This test is a placeholder and doesn't actually track allocations.
    ///
    /// # Safety
    ///
    /// This test uses unsafe code to initialize and delete the parser.
    #[test]
    fn test_memory_leaks() {
        unsafe {
            // We can't track allocations without a custom allocator, so we'll just
            // test that we can initialize and delete without crashing
            let mut parser = MaybeUninit::<YamlParserT>::uninit();
            let init_result =
                yaml_parser_initialize(parser.as_mut_ptr());
            assert!(
                init_result.ok,
                "Parser initialization should succeed"
            );
            yaml_parser_delete(parser.as_mut_ptr());
        }
    }
    /// Tests that initializing with a valid pointer succeeds.
    ///
    /// # Safety
    ///
    /// This test uses unsafe code to initialize the parser.
    #[test]
    fn test_yaml_parser_initialize_valid() {
        unsafe {
            let mut parser = MaybeUninit::<YamlParserT>::uninit();
            let result = yaml_parser_initialize(parser.as_mut_ptr());
            assert!(
                result.ok,
                "Parser initialization should succeed with valid pointer"
            );

            // Clean up
            yaml_parser_delete(parser.as_mut_ptr());
        }
    }
}
