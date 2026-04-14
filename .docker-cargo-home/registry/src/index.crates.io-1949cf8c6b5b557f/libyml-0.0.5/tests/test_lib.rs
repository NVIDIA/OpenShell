#![no_std]
#[cfg(test)]
mod tests {
    use core::mem::MaybeUninit;
    use libyml::success::is_success;
    use libyml::*;

    /// Tests the initialization and deletion of the YAML parser.
    #[test]
    fn test_parser_initialize_and_delete() {
        unsafe {
            let mut parser = MaybeUninit::<YamlParserT>::uninit();
            assert!(is_success(yaml_parser_initialize(
                parser.as_mut_ptr()
            )));
            let mut parser = parser.assume_init();
            yaml_parser_delete(&mut parser);
        }
    }

    /// Tests setting the input string for the YAML parser.
    #[test]
    fn test_parser_set_input_string() {
        unsafe {
            let mut parser = MaybeUninit::<YamlParserT>::uninit();
            assert!(is_success(yaml_parser_initialize(
                parser.as_mut_ptr()
            )));
            let mut parser = parser.assume_init();

            let input = b"key: value\n";
            yaml_parser_set_input_string(
                &mut parser,
                input.as_ptr(),
                input.len() as u64,
            );

            yaml_parser_delete(&mut parser);
        }
    }

    /// Tests parsing a simple YAML document.
    #[test]
    fn test_parser_parse_simple_document() {
        unsafe {
            let mut parser = MaybeUninit::<YamlParserT>::uninit();
            assert!(is_success(yaml_parser_initialize(
                parser.as_mut_ptr()
            )));
            let mut parser = parser.assume_init();

            let input = b"key: value\n";
            yaml_parser_set_input_string(
                &mut parser,
                input.as_ptr(),
                input.len() as u64,
            );

            let mut event = MaybeUninit::<YamlEventT>::uninit();
            assert!(is_success(yaml_parser_parse(
                &mut parser,
                event.as_mut_ptr()
            )));
            let _event = event.assume_init();

            yaml_parser_delete(&mut parser);
        }
    }

    /// Tests parsing of a complex YAML document with nested structures.
    #[test]
    fn test_complex_document() {
        unsafe {
            let mut parser = MaybeUninit::<YamlParserT>::uninit();
            assert!(is_success(yaml_parser_initialize(
                parser.as_mut_ptr()
            )));
            let mut parser = parser.assume_init();

            let input = b"
            parent:
                child1: value1
                child2:
                - list_item1
                - list_item2
            ";
            yaml_parser_set_input_string(
                &mut parser,
                input.as_ptr(),
                input.len() as u64,
            );

            let mut event = MaybeUninit::<YamlEventT>::uninit();
            assert!(is_success(yaml_parser_parse(
                &mut parser,
                event.as_mut_ptr()
            )));
            let _event = event.assume_init();

            yaml_parser_delete(&mut parser);
        }
    }
    /// Tests handling invalid YAML input.
    #[test]
    fn test_parser_handle_invalid_input() {
        unsafe {
            let mut parser = MaybeUninit::<YamlParserT>::uninit();
            assert!(is_success(yaml_parser_initialize(
                parser.as_mut_ptr()
            )));
            let mut parser = parser.assume_init();

            let input = b"invalid_yaml";
            yaml_parser_set_input_string(
                &mut parser,
                input.as_ptr(),
                input.len() as u64,
            );

            let mut event = MaybeUninit::<YamlEventT>::uninit();
            let result =
                yaml_parser_parse(&mut parser, event.as_mut_ptr());

            assert!(is_success(result));

            yaml_parser_delete(&mut parser);
        }
    }
}
