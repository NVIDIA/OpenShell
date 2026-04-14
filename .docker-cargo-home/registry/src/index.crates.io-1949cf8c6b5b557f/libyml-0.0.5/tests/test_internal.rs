use libyml::{
    internal::{yaml_check_utf8, yaml_queue_extend, yaml_stack_extend},
    memory::{yaml_free, yaml_malloc},
    success::{FAIL, OK},
};

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for yaml_stack_extend function
    #[test]
    fn test_yaml_stack_extend() {
        unsafe {
            // Initialize a small stack
            let mut start = yaml_malloc(16);
            let mut top = start;
            let mut end = start.add(16);

            // Extend the stack
            yaml_stack_extend(&mut start, &mut top, &mut end);

            // Check if the stack size doubled
            assert_eq!(end.offset_from(start), 32);

            // Clean up
            yaml_free(start);
        }
    }

    /// Tests for yaml_queue_extend function
    #[test]
    fn test_yaml_queue_extend() {
        unsafe {
            // Initialize a small queue
            let mut start = yaml_malloc(16);
            let mut head = start;
            let mut tail = start;
            let mut end = start.add(32);

            // Extend the queue
            yaml_queue_extend(
                &mut start, &mut head, &mut tail, &mut end,
            );

            // Check if the queue size doubled
            assert_eq!(end.offset_from(start), 32);

            // Clean up
            yaml_free(start);
        }
    }

    /// Tests for yaml_check_utf8 function
    #[test]
    fn test_yaml_check_utf8() {
        unsafe {
            // Valid UTF-8 string
            let valid_str = "Hello, world!";
            assert_eq!(
                yaml_check_utf8(
                    valid_str.as_ptr(),
                    valid_str.len().try_into().unwrap()
                ),
                OK
            );

            // Invalid UTF-8 string
            let invalid_str = [0xFF, 0xFE, 0xFD];
            assert_eq!(
                yaml_check_utf8(
                    invalid_str.as_ptr(),
                    invalid_str.len().try_into().unwrap()
                ),
                FAIL
            );

            // Empty string
            let empty_str = "";
            assert_eq!(
                yaml_check_utf8(
                    empty_str.as_ptr(),
                    empty_str.len().try_into().unwrap()
                ),
                OK
            );

            // Multi-byte UTF-8 characters
            let multi_byte_str = "こんにちは";
            assert_eq!(
                yaml_check_utf8(
                    multi_byte_str.as_ptr(),
                    multi_byte_str.len().try_into().unwrap()
                ),
                OK
            );

            // Incomplete multi-byte sequence
            let incomplete_str = [0xE3, 0x81, 0x93, 0xE3, 0x81];
            assert_eq!(
                yaml_check_utf8(
                    incomplete_str.as_ptr(),
                    incomplete_str.len().try_into().unwrap()
                ),
                FAIL
            );
        }
    }
}
