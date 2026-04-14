#[cfg(test)]
mod tests {
    use core::ffi::c_char;
    use core::mem::MaybeUninit;
    use libyml::api::yaml_parser_set_input_string;
    use libyml::decode::yaml_parser_initialize;
    use libyml::loader::yaml_parser_set_composer_error;
    use libyml::success::is_success;
    use libyml::yaml::YamlErrorTypeT::YamlComposerError;
    use libyml::{
        yaml_document_delete, yaml_parser_delete, yaml_parser_load,
        YamlDocumentT, YamlMarkT, YamlParserT,
    };

    #[test]
    fn test_yaml_parser_load() {
        unsafe {
            let mut parser = MaybeUninit::<YamlParserT>::uninit();
            let mut document = MaybeUninit::<YamlDocumentT>::uninit();
            let input = b"key: value\n";

            // Initialize the parser
            assert!(is_success(yaml_parser_initialize(
                parser.as_mut_ptr()
            )));
            let parser = parser.assume_init_mut();

            // Set the input string
            yaml_parser_set_input_string(
                parser,
                input.as_ptr(),
                input.len() as u64,
            );

            // Load the document
            let result =
                yaml_parser_load(parser, document.as_mut_ptr());
            assert!(is_success(result));

            // Clean up
            yaml_document_delete(document.as_mut_ptr());
            yaml_parser_delete(parser);
        }
    }

    // Test for yaml_parser_set_composer_error
    #[test]
    fn test_yaml_parser_set_composer_error() {
        unsafe {
            let mut parser = MaybeUninit::<YamlParserT>::uninit();
            assert!(is_success(yaml_parser_initialize(
                parser.as_mut_ptr()
            )));
            let parser = parser.assume_init_mut();

            let problem =
                b"Test problem\0" as *const u8 as *const c_char;
            let problem_mark = YamlMarkT::default();

            // Call the function that sets the error
            let _ = yaml_parser_set_composer_error(
                parser,
                problem,
                problem_mark,
            );

            // Check if the error is set correctly
            assert_eq!(parser.error, YamlComposerError);
            assert_eq!(parser.problem, problem);
            assert_eq!(parser.problem_mark.index, problem_mark.index);
            assert_eq!(parser.problem_mark.line, problem_mark.line);
            assert_eq!(parser.problem_mark.column, problem_mark.column);

            // Clean up
            yaml_parser_delete(parser);
        }
    }
}
