// ------------------------------------
// Buffer Management Macros
// ------------------------------------

/// Initializes a buffer with a given size.
///
/// # Parameters
///
/// * `buffer`: A mutable reference to a `YamlBufferT` struct that needs to be initialized.
/// * `size`: The size of the buffer in bytes.
///
/// # Return
///
/// This macro does not return a value. It initializes the provided buffer with the given size.
///
/// # Safety
///
/// This macro assumes that the `yaml_malloc` function is correctly implemented and handles memory allocation.
#[macro_export]
macro_rules! BUFFER_INIT {
    ($buffer:expr, $size:expr) => {{
        let start = addr_of_mut!($buffer.start);
        *start = yaml_malloc($size as size_t) as *mut yaml_char_t;
        let pointer = addr_of_mut!($buffer.pointer);
        *pointer = $buffer.start;
        let last = addr_of_mut!($buffer.last);
        *last = *pointer;
        let end = addr_of_mut!($buffer.end);
        *end = $buffer.start.wrapping_add($size);
    }};
}

/// Deletes the buffer and frees the allocated memory.
///
/// # Parameters
///
/// * `buffer`: A mutable reference to the buffer to be deleted.
///
/// # Return
///
/// This function does not return a value.
#[macro_export]
macro_rules! BUFFER_DEL {
    ($buffer:expr) => {{
        // Free the allocated memory
        yaml_free($buffer.start as *mut libc::c_void);

        // Set all pointers to null after freeing the memory
        $buffer.start = ptr::null_mut::<yaml_char_t>();
        $buffer.pointer = ptr::null_mut::<yaml_char_t>();
        $buffer.last = ptr::null_mut::<yaml_char_t>();
        $buffer.end = ptr::null_mut::<yaml_char_t>();
    }};
}

// ------------------------------------
// String Management Macros
// ------------------------------------

/// Assigns a new value to a `YamlStringT` struct.
///
/// This macro creates a new `YamlStringT` instance with the given start and end pointers.
/// The end pointer is calculated by offsetting the start pointer by the given length.
/// The pointer is set to the start pointer.
///
/// # Parameters
///
/// * `string`: A pointer to the start of the string.
/// * `length`: The length of the string.
///
/// # Return
///
/// A new `YamlStringT` instance with the given start, end, and pointer values.
#[macro_export]
macro_rules! STRING_ASSIGN {
    ($string:expr, $length:expr) => {
        YamlStringT {
            start: $string,
            end: $string.wrapping_offset($length as isize),
            pointer: $string,
        }
    };
}

/// Initializes a string for use with the yaml library.
///
/// This macro allocates memory for a string, initializes the start, pointer, and end pointers,
/// and sets the memory to all zeros.
///
/// # Parameters
///
/// * `$string`: A mutable reference to a `YamlStringT` struct, representing the string to be initialized.
///
/// # Return
///
/// This macro does not return a value.
#[macro_export]
macro_rules! STRING_INIT {
    ($string:expr) => {{
        $string.start = yaml_malloc(16) as *mut yaml_char_t;
        $string.pointer = $string.start;
        $string.end = $string.start.wrapping_add(16);
        let _ = memset($string.start as *mut libc::c_void, 0, 16);
    }};
}

/// Deletes a string and frees the allocated memory.
///
/// # Parameters
///
/// * `string`: A mutable reference to a `YamlStringT` struct representing the string to be deleted.
///
/// # Return
///
/// This function does not return a value.
///
/// # Safety
///
/// This function assumes that the `string` parameter is a valid pointer to a `YamlStringT` struct.
/// It calls the `yaml_free` function to free the allocated memory for the string.
#[macro_export]
macro_rules! STRING_DEL {
    ($string:expr) => {{
        yaml_free($string.start as *mut libc::c_void);
        $string.end = ptr::null_mut::<yaml_char_t>();
        $string.pointer = $string.end;
        $string.start = $string.pointer;
    }};
}

/// Extends the capacity of a string by reallocating memory if the current capacity is insufficient.
///
/// # Parameters
///
/// * `string`: A mutable reference to a `YamlStringT` struct representing the string.
///
/// # Return
///
/// This macro does not return a value. It extends the capacity of the string by reallocating memory if necessary.
#[macro_export]
macro_rules! STRING_EXTEND {
    ($string:expr) => {
        if $string.pointer.wrapping_add(5) >= $string.end {
            yaml_string_extend(
                addr_of_mut!($string.start),
                addr_of_mut!($string.pointer),
                addr_of_mut!($string.end),
            );
        }
    };
}

/// Clears the content of the string by setting the pointer to the start and filling the memory
/// from the start to the end with zeros.
///
/// # Parameters
///
/// * `string`: A mutable reference to a struct containing the start, pointer, and end pointers representing the string.
///
/// # Return
///
/// This macro does not return a value. It modifies the content of the string in place.
#[macro_export]
macro_rules! CLEAR {
    ($string:expr) => {{
        $string.pointer = $string.start;
        let _ = memset(
            $string.start as *mut libc::c_void,
            0,
            $string.end.offset_from($string.start) as libc::c_ulong,
        );
    }};
}

/// Joins two strings together by appending the contents of `string_b` to `string_a`.
///
/// # Parameters
///
/// * `string_a`: A mutable reference to the first string. Its contents will be modified.
/// * `string_b`: A mutable reference to the second string. Its contents will not be modified.
///
/// # Return
///
/// This macro does not return a value. It modifies the contents of `string_a` in-place.
#[macro_export]
macro_rules! JOIN {
    ($string_a:expr, $string_b:expr) => {{
        // Check the length to ensure we don't overflow
        let a_len = $string_a.pointer.offset_from($string_a.start) as usize;
        let b_len = $string_b.pointer.offset_from($string_b.start) as usize;

        // If the combined length would exceed available space, reallocate
        if a_len.checked_add(b_len).is_some() && $string_a.pointer.add(b_len) <= $string_a.end {
            yaml_string_join(
                addr_of_mut!($string_a.start),
                addr_of_mut!($string_a.pointer),
                addr_of_mut!($string_a.end),
                addr_of_mut!($string_b.start),
                addr_of_mut!($string_b.pointer),
                addr_of_mut!($string_b.end),
            );
            $string_b.pointer = $string_b.start;
        } else {
            panic!("String join would overflow memory bounds");
        }
    }};
}

/// This macro checks if the octet at the specified offset in the given string matches the provided octet.
///
/// # Parameters
///
/// * `string`: A reference to the string where the octet will be checked.
/// * `octet`: The octet to be checked.
/// * `offset`: The offset from the start of the string where the octet will be checked.
///
/// # Return
///
/// * `bool`: Returns `true` if the octet at the specified offset matches the provided octet, otherwise returns `false`.
#[macro_export]
macro_rules! CHECK_AT {
    ($string:expr, $octet:expr, $offset:expr) => {
        *$string.pointer.offset($offset) == $octet
    };
}

/// A macro that checks if the current byte in the given string matches a specific octet.
///
/// # Parameters
///
/// * `string`: A reference to the string to be checked.
/// * `octet`: The octet to be matched.
///
/// # Return
///
/// * `bool`: Returns `true` if the current byte in the string matches the given octet, otherwise `false`.
#[macro_export]
macro_rules! CHECK {
    ($string:expr, $octet:expr) => {
        *$string.pointer == $octet
    };
}

/// Checks if the current character in the string is an alphabetic character.
///
/// # Parameters
///
/// * `string`: A mutable reference to a struct containing a pointer to a byte array.
///
/// # Return
///
/// Returns `true` if the current character is an alphabetic character (A-Z, a-z, 0-9, '_', '-'),
/// and `false` otherwise.
#[macro_export]
macro_rules! IS_ALPHA {
    ($string:expr) => {
        *$string.pointer >= b'0' && *$string.pointer <= b'9'
            || *$string.pointer >= b'A' && *$string.pointer <= b'Z'
            || *$string.pointer >= b'a' && *$string.pointer <= b'z'
            || *$string.pointer == b'_'
            || *$string.pointer == b'-'
    };
}

/// Checks if the byte pointed to by the `pointer` in the given string is a digit (0-9).
///
/// # Parameters
///
/// * `string`: A reference to a struct containing a `pointer` field pointing to a byte in a string.
///
/// # Return value
///
/// Returns `true` if the byte pointed to by the `pointer` is a digit (0-9), and `false` otherwise.
#[macro_export]
macro_rules! IS_DIGIT {
    ($string:expr) => {
        *$string.pointer >= b'0' && *$string.pointer <= b'9'
    };
}

/// Converts the byte at the current pointer in the string to its corresponding integer value.
///
/// # Parameters
///
/// * `string`: A mutable reference to a struct containing a pointer to a byte array.
///
/// # Return
///
/// * Returns the integer value of the byte at the current pointer in the string.
///   The byte is assumed to be in the ASCII range (0-9), so the function subtracts the ASCII value of '0' (48)
///   to convert it to its integer representation.
#[macro_export]
macro_rules! AS_DIGIT {
    ($string:expr) => {
        (*$string.pointer - b'0') as libc::c_int
    };
}

/// Checks if the character at the given offset in the string is a hexadecimal digit.
///
/// # Parameters
///
/// * `string`: A reference to the string to check.
/// * `offset`: The offset in the string to check.
///
/// # Return
///
/// Returns `true` if the character at the given offset is a hexadecimal digit (0-9, A-F, a-f),
/// and `false` otherwise.
#[macro_export]
macro_rules! IS_HEX_AT {
    ($string:expr, $offset:expr) => {
        *$string.pointer.wrapping_offset($offset) >= b'0'
            && *$string.pointer.wrapping_offset($offset) <= b'9'
            || *$string.pointer.wrapping_offset($offset) >= b'A'
                && *$string.pointer.wrapping_offset($offset) <= b'F'
            || *$string.pointer.wrapping_offset($offset) >= b'a'
                && *$string.pointer.wrapping_offset($offset) <= b'f'
    };
}

/// Converts a hexadecimal character at a given offset in a string to its corresponding integer value.
///
/// # Parameters
///
/// * `string`: A reference to a string containing hexadecimal characters.
/// * `offset`: The offset in the string where the hexadecimal character is located.
///
/// # Return
///
/// An integer representing the hexadecimal value of the character at the given offset.
///
/// # Note
///
/// This macro assumes that the input string contains valid hexadecimal characters.
#[macro_export]
macro_rules! AS_HEX_AT {
    ($string:expr, $offset:expr) => {
        if *$string.pointer.wrapping_offset($offset) >= b'A'
            && *$string.pointer.wrapping_offset($offset) <= b'F'
        {
            *$string.pointer.wrapping_offset($offset) - b'A' + 10
        } else if *$string.pointer.wrapping_offset($offset) >= b'a'
            && *$string.pointer.wrapping_offset($offset) <= b'f'
        {
            *$string.pointer.wrapping_offset($offset) - b'a' + 10
        } else {
            *$string.pointer.wrapping_offset($offset) - b'0'
        } as libc::c_int
    };
}

/// Checks if the current character in the string is an ASCII character.
///
/// # Parameters
///
/// * `string`: A reference to a struct containing a pointer to the current character in the string.
///
/// # Return
///
/// Returns `true` if the current character is an ASCII character (i.e., its value is less than or equal to 0x7F),
/// and `false` otherwise.
#[macro_export]
macro_rules! IS_ASCII {
    ($string:expr) => {
        *$string.pointer <= b'\x7F'
    };
}

/// Checks if the character at the current pointer in the given string is printable.
///
/// # Parameters
///
/// * `string`: A reference to a struct containing a pointer to the current character in the string.
///
/// # Return
///
/// * `bool`: Returns `true` if the character is printable, and `false` otherwise.
///
/// # Details
///
/// This macro checks if the character at the current pointer in the given string is printable.
/// It considers various Unicode ranges and special characters to determine printability.
///
/// The macro uses pattern matching to check the byte value of the character and its position in the string.
/// It checks for ASCII printable characters, Unicode printable characters in specific ranges,
/// and special characters that are considered printable.
///
/// The macro returns `true` if the character is printable, and `false` otherwise.
#[macro_export]
macro_rules! IS_PRINTABLE {
    ($string:expr) => {
        match *$string.pointer {
            // ASCII
            0x0A | 0x20..=0x7E => true,
            // U+A0 ... U+BF
            0xC2 => match *$string.pointer.wrapping_offset(1) {
                0xA0..=0xBF => true,
                _ => false,
            },
            // U+C0 ... U+CFFF
            0xC3..=0xEC => true,
            // U+D000 ... U+D7FF
            0xED => match *$string.pointer.wrapping_offset(1) {
                0x00..=0x9F => true,
                _ => false,
            },
            // U+E000 ... U+EFFF
            0xEE => true,
            // U+F000 ... U+FFFD
            0xEF => match *$string.pointer.wrapping_offset(1) {
                0xBB => match *$string.pointer.wrapping_offset(2) {
                    // except U+FEFF
                    0xBF => false,
                    _ => true,
                },
                0xBF => match *$string.pointer.wrapping_offset(2) {
                    0xBE | 0xBF => false,
                    _ => true,
                },
                _ => true,
            },
            // U+10000 ... U+10FFFF
            0xF0..=0xF4 => true,
            _ => false,
        }
    };
}

/// Checks if the character at the specified offset in the given string is a null character (ASCII 0).
///
/// # Parameters
///
/// * `$string`: A reference to the string to check.
/// * `$offset`: The offset within the string to check.
///
/// # Return
///
/// Returns `true` if the character at the specified offset is a null character, and `false` otherwise.
#[macro_export]
macro_rules! IS_Z_AT {
    ($string:expr, $offset:expr) => {
        CHECK_AT!($string, b'\0', $offset)
    };
}

/// Checks if the character at the current pointer in the given string is a null character (ASCII 0).
///
/// # Parameters
///
/// * `$string`: A reference to the string to check.
///
/// # Return
///
/// * `bool`: Returns `true` if the character is a null character, and `false` otherwise.
#[macro_export]
macro_rules! IS_Z {
    ($string:expr) => {
        IS_Z_AT!($string, 0)
    };
}

/// Checks if the first three bytes of the given string form the UTF-8 byte order mark (BOM) for UTF-8 encoding.
///
/// # Parameters
///
/// * `string`: A reference to the string to check.
///
/// # Return
///
/// * `bool`: Returns `true` if the first three bytes of the string form the UTF-8 BOM, and `false` otherwise.
#[macro_export]
macro_rules! IS_BOM {
    ($string:expr) => {
        CHECK_AT!($string, b'\xEF', 0)
            && CHECK_AT!($string, b'\xBB', 1)
            && CHECK_AT!($string, b'\xBF', 2)
    };
}

/// Checks if the character at the specified offset in the given string is a space character (ASCII 0x20).
///
/// # Parameters
///
/// * `$string`: A reference to the string to check.
/// * `$offset`: The offset within the string to check.
///
/// # Return
///
/// * `bool`: Returns `true` if the character at the specified offset is a space character, and `false` otherwise.
#[macro_export]
macro_rules! IS_SPACE_AT {
    ($string:expr, $offset:expr) => {
        CHECK_AT!($string, b' ', $offset)
    };
}

/// Checks if the character at the current pointer in the given string is a space character (ASCII 0x20).
///
/// # Parameters
///
/// * `string`: A reference to the string to check.
///
/// # Return
///
/// * `bool`: Returns `true` if the character is a space character, and `false` otherwise.
#[macro_export]
macro_rules! IS_SPACE {
    ($string:expr) => {
        IS_SPACE_AT!($string, 0)
    };
}

/// Checks if the character at the specified offset in the given string is a tab character (ASCII 0x09).
///
/// # Parameters
///
/// * `$string`: A reference to the string to check.
/// * `$offset`: The offset within the string to check.
///
/// # Return
///
/// * `bool`: Returns `true` if the character at the specified offset is a tab character, and `false` otherwise.
#[macro_export]
macro_rules! IS_TAB_AT {
    ($string:expr, $offset:expr) => {
        CHECK_AT!($string, b'\t', $offset)
    };
}

/// Checks if the character at the current pointer in the given string is a tab character (ASCII 0x09).
///
/// # Parameters
///
/// * `string`: A reference to the string to check.
///
/// # Return
///
/// * `bool`: Returns `true` if the character is a tab character, and `false` otherwise.
#[macro_export]
macro_rules! IS_TAB {
    ($string:expr) => {
        IS_TAB_AT!($string, 0)
    };
}

/// Checks if the character at the specified offset in the given string is a space or tab character.
///
/// # Parameters
///
/// * `$string`: A reference to the string to check.
/// * `$offset`: The offset within the string to check.
///
/// # Return
///
/// * `bool`: Returns `true` if the character at the specified offset is a space or tab character, and `false` otherwise.
#[macro_export]
macro_rules! IS_BLANK_AT {
    ($string:expr, $offset:expr) => {
        IS_SPACE_AT!($string, $offset) || IS_TAB_AT!($string, $offset)
    };
}

/// Checks if the character at the current pointer in the given string is a space or tab character.
///
/// # Parameters
///
/// * `$string`: A reference to the string to check.
///
/// # Return
///
/// * `bool`: Returns `true` if the character is a space or tab character, and `false` otherwise.
#[macro_export]
macro_rules! IS_BLANK {
    ($string:expr) => {
        IS_BLANK_AT!($string, 0)
    };
}

/// Checks if the character at the specified offset in the given string is a line break character.
///
/// # Parameters
///
/// * `$string`: A reference to the string to check.
/// * `$offset`: The offset within the string to check.
///
/// # Return
///
/// Returns `true` if the character at the specified offset is a line break character (CR, LF, NEL, LS, PS),
/// and `false` otherwise.
#[macro_export]
macro_rules! IS_BREAK_AT {
    ($string:expr, $offset:expr) => {
        CHECK_AT!($string, b'\r', $offset)
            || CHECK_AT!($string, b'\n', $offset)
            || CHECK_AT!($string, b'\xC2', $offset)
                && CHECK_AT!(
                    $string,
                    b'\x85',
                    ($offset + 1).try_into().unwrap()
                )
            || CHECK_AT!($string, b'\xE2', $offset)
                && CHECK_AT!(
                    $string,
                    b'\x80',
                    ($offset + 1).try_into().unwrap()
                )
                && CHECK_AT!(
                    $string,
                    b'\xA8',
                    ($offset + 2).try_into().unwrap()
                )
            || CHECK_AT!($string, b'\xE2', $offset)
                && CHECK_AT!(
                    $string,
                    b'\x80',
                    ($offset + 1).try_into().unwrap()
                )
                && CHECK_AT!(
                    $string,
                    b'\xA9',
                    ($offset + 2).try_into().unwrap()
                )
    };
}

/// Checks if the character at the current pointer in the given string is a line break character.
///
/// # Parameters
///
/// * `string`: A reference to the string to check.
///
/// # Return
///
/// Returns `true` if the character is a line break character (CR, LF, NEL, LS, PS), and `false` otherwise.
#[macro_export]
macro_rules! IS_BREAK {
    ($string:expr) => {
        IS_BREAK_AT!($string, 0)
    };
}

/// Checks if the character at the current pointer in the given string is a carriage return followed by a line feed.
///
/// # Parameters
///
/// * `string`: A reference to the string to check.
///
/// # Return
///
/// Returns `true` if the character at the current pointer is a carriage return followed by a line feed, and `false` otherwise.
#[macro_export]
macro_rules! IS_CRLF {
    ($string:expr) => {
        CHECK_AT!($string, b'\r', 0) && CHECK_AT!($string, b'\n', 1)
    };
}

/// Checks if the character at the specified offset in the given string is a line break character or a null character.
///
/// # Parameters
///
/// * `string`: A reference to the string to check.
/// * `offset`: The offset within the string to check.
///
/// # Return
///
/// Returns `true` if the character at the specified offset is a line break character or a null character, and `false` otherwise.
#[macro_export]
macro_rules! IS_BREAKZ_AT {
    ($string:expr, $offset:expr) => {
        IS_BREAK_AT!($string, $offset) || IS_Z_AT!($string, $offset)
    };
}

/// Checks if the character at the current pointer in the given string is a line break character or a null character.
///
/// # Parameters
///
/// * `string`: A reference to the string to check.
///
/// # Return
///
/// Returns `true` if the character is a line break character (CR, LF, NEL, LS, PS) or a null character, and `false` otherwise.
#[macro_export]
macro_rules! IS_BREAKZ {
    ($string:expr) => {
        IS_BREAKZ_AT!($string, 0)
    };
}

/// Checks if the character at the specified offset in the given string is a space, tab, or line break character,
/// or if it is a null character.
///
/// # Parameters
///
/// * `$string`: A reference to the string to check.
/// * `$offset`: The offset within the string to check.
///
/// # Return
///
/// Returns `true` if the character at the specified offset is a space, tab, line break character, or null character,
/// and `false` otherwise.
#[macro_export]
macro_rules! IS_BLANKZ_AT {
    ($string:expr, $offset:expr) => {
        IS_BLANK_AT!($string, $offset)
            || IS_BREAKZ_AT!($string, $offset)
    };
}

/// Checks if the character at the current pointer in the given string is a space, tab, line break character,
/// or if it is a null character.
///
/// # Parameters
///
/// * `string`: A reference to the string to check.
///
/// # Return
///
/// Returns `true` if the character is a space, tab, line break character, or null character,
/// and `false` otherwise.
#[macro_export]
macro_rules! IS_BLANKZ {
    ($string:expr) => {
        IS_BLANKZ_AT!($string, 0)
    };
}

/// Returns the width of a Unicode character at the given offset in a string.
///
/// # Parameters
///
/// * `string`: A reference to the string containing the Unicode characters.
/// * `offset`: The offset in the string where the Unicode character is located.
///
/// # Return
///
/// The width of the Unicode character at the given offset. The width is determined by the first byte of the character:
/// - If the first byte is 0x00-0x7F, the width is 1.
/// - If the first byte is 0xC0-0xDF, the width is 2.
/// - If the first byte is 0xE0-0xEF, the width is 3.
/// - If the first byte is 0xF0-0xF7, the width is 4.
/// - If the first byte does not match any of the above patterns, the width is 0.
#[macro_export]
macro_rules! WIDTH_AT {
    ($string:expr, $offset:expr) => {
        if *$string.pointer.wrapping_offset($offset) & 0x80 == 0x00 {
            1
        } else if *$string.pointer.wrapping_offset($offset) & 0xE0
            == 0xC0
        {
            2
        } else if *$string.pointer.wrapping_offset($offset) & 0xF0
            == 0xE0
        {
            3
        } else if *$string.pointer.wrapping_offset($offset) & 0xF8
            == 0xF0
        {
            4
        } else {
            0
        }
    };
}

/// Returns the width of the Unicode character at the current position in a string.
///
/// This macro calculates the width of the Unicode character that the `pointer` in the given string is currently pointing to.
/// The width is determined by checking the first byte of the character at the current position in the string, using the
/// `WIDTH_AT!` macro with an offset of `0`.
///
/// # Parameters
///
/// * `string`: A reference to a struct containing a `pointer` field that points to a byte in a string.
///   This byte is expected to be the start of a Unicode character.
///
/// # Return
///
/// The width of the Unicode character at the current position of the `pointer` in the string:
///
/// - If the first byte is in the range `0x00` to `0x7F`, the width is 1 byte.
/// - If the first byte is in the range `0xC0` to `0xDF`, the width is 2 bytes.
/// - If the first byte is in the range `0xE0` to `0xEF`, the width is 3 bytes.
/// - If the first byte is in the range `0xF0` to `0xF7`, the width is 4 bytes.
/// - If the first byte does not match any of the above patterns, the width is 0, indicating an invalid or unsupported character.
///
/// # Safety
///
/// The caller must ensure that the `pointer` in the `string` is pointing to valid memory and that the memory contains a valid Unicode sequence.
/// Using this macro on an invalid or corrupted string may result in undefined behavior or incorrect results.
#[macro_export]
macro_rules! WIDTH {
    ($string:expr) => {
        WIDTH_AT!($string, 0)
    };
}

/// Moves the pointer of the given string to the next Unicode character.
///
/// This macro moves the pointer of the given string to the next Unicode character,
/// taking into account the width of the Unicode character. The width is determined
/// by the first byte of the character.
///
/// # Parameters
///
/// * `string`: A mutable reference to the string whose pointer will be moved.
///
/// # Return
///
/// This macro does not return a value. It moves the pointer of the given string
/// to the next Unicode character.
#[macro_export]
macro_rules! MOVE {
    ($string:expr) => {
        $string.pointer =
            $string.pointer.wrapping_offset(WIDTH!($string))
    };
}

/// Copies the content of a string to another string.
///
/// This macro copies the content of a string to another string. It handles different Unicode character
/// encodings by checking the first byte of the character. If the character is a single-byte character, it
/// is copied directly. If the character is a multi-byte character, it is copied byte by byte.
///
/// # Parameters
///
/// * `string_a`: A mutable reference to the destination string where the content will be copied.
/// * `string_b`: A mutable reference to the source string from which the content will be copied.
///
/// # Return
///
/// This macro does not return a value. It copies the content of a string to another string.
#[macro_export]
macro_rules! copy {
    ($string_a:expr, $string_b:expr) => {
        if *$string_b.pointer & 0x80 == 0x00 {
            *$string_a.pointer = *$string_b.pointer;
            $string_a.pointer = $string_a.pointer.wrapping_offset(1);
            $string_b.pointer = $string_b.pointer.wrapping_offset(1);
        } else if *$string_b.pointer & 0xE0 == 0xC0 {
            *$string_a.pointer = *$string_b.pointer;
            $string_a.pointer = $string_a.pointer.wrapping_offset(1);
            $string_b.pointer = $string_b.pointer.wrapping_offset(1);
            *$string_a.pointer = *$string_b.pointer;
            $string_a.pointer = $string_a.pointer.wrapping_offset(1);
            $string_b.pointer = $string_b.pointer.wrapping_offset(1);
        } else if *$string_b.pointer & 0xF0 == 0xE0 {
            *$string_a.pointer = *$string_b.pointer;
            $string_a.pointer = $string_a.pointer.wrapping_offset(1);
            $string_b.pointer = $string_b.pointer.wrapping_offset(1);
            *$string_a.pointer = *$string_b.pointer;
            $string_a.pointer = $string_a.pointer.wrapping_offset(1);
            $string_b.pointer = $string_b.pointer.wrapping_offset(1);
            *$string_a.pointer = *$string_b.pointer;
            $string_a.pointer = $string_a.pointer.wrapping_offset(1);
            $string_b.pointer = $string_b.pointer.wrapping_offset(1);
        } else if *$string_b.pointer & 0xF8 == 0xF0 {
            *$string_a.pointer = *$string_b.pointer;
            $string_a.pointer = $string_a.pointer.wrapping_offset(1);
            $string_b.pointer = $string_b.pointer.wrapping_offset(1);
            *$string_a.pointer = *$string_b.pointer;
            $string_a.pointer = $string_a.pointer.wrapping_offset(1);
            $string_b.pointer = $string_b.pointer.wrapping_offset(1);
            *$string_a.pointer = *$string_b.pointer;
            $string_a.pointer = $string_a.pointer.wrapping_offset(1);
            $string_b.pointer = $string_b.pointer.wrapping_offset(1);
            *$string_a.pointer = *$string_b.pointer;
            $string_a.pointer = $string_a.pointer.wrapping_offset(1);
            $string_b.pointer = $string_b.pointer.wrapping_offset(1);
        }
    };
}

// ------------------------------------
// Stack Management Macros
// ------------------------------------

/// Initializes a stack with a specified type and allocates memory for it.
///
/// # Parameters
///
/// * `stack`: A mutable reference to the stack to be initialized.
/// * `type`: The type of elements that will be stored in the stack.
///
/// # Return
///
/// This function does not return a value. It initializes the stack with the given type and allocates memory for it.
/// The memory is allocated using the `yaml_malloc` function, and the start, top, and end pointers of the stack are set accordingly.
#[macro_export]
macro_rules! STACK_INIT {
    ($stack:expr, $type:ty) => {{
        $stack.start =
            yaml_malloc(16 * size_of::<$type>() as libc::c_ulong)
                as *mut $type;
        $stack.top = $stack.start;
        $stack.end = $stack.start.offset(16_isize);
    }};
}

/// Deallocates the memory used by the stack and sets all pointers to null.
///
/// # Parameters
///
/// * `stack`: A mutable reference to the stack to be deallocated.
///
/// # Return
///
/// This function does not return a value. It deallocates the memory used by the stack and sets all pointers to null.
#[macro_export]
macro_rules! STACK_DEL {
    ($stack:expr) => {
        yaml_free($stack.start as *mut libc::c_void);
        $stack.end = ptr::null_mut();
        $stack.top = ptr::null_mut();
        $stack.start = ptr::null_mut();
    };
}

/// Checks if the stack has no elements.
///
/// This macro checks if the stack has no elements by comparing the start and top pointers.
/// If the start and top pointers are equal, it means the stack is empty and the function returns `true`.
/// Otherwise, it means the stack has elements and the function returns `false`.
///
/// # Parameters
///
/// * `stack`: A mutable reference to the stack to be checked.
///
/// # Return
///
/// * `true` if the stack is empty, i.e., the start and top pointers are equal.
/// * `false` if the stack is not empty, i.e., the start and top pointers are not equal.
#[macro_export]
macro_rules! STACK_EMPTY {
    ($stack:expr) => {
        $stack.start == $stack.top
    };
}

/// Checks if the stack has enough memory to push a new element.
///
/// This macro checks if the stack has enough memory to push a new element by comparing the distance
/// between the top and start pointers with the maximum allowed distance. If the distance is less than
/// the maximum allowed distance minus one, it means the stack has enough memory and the function
/// returns `OK`. Otherwise, it sets the error field of the context to `YamlMemoryError` and returns
/// `FAIL`.
///
/// # Parameters
///
/// * `$context`: A mutable reference to the context in which the stack is being used.
/// * `$stack`: A mutable reference to the stack being checked.
///
/// # Return
///
/// * `OK` if the stack has enough memory to push a new element.
/// * `FAIL` if the stack does not have enough memory to push a new element.
#[macro_export]
macro_rules! STACK_LIMIT {
    ($context:expr, $stack:expr) => {
        if $stack.top.c_offset_from($stack.start)
            < libc::c_int::MAX as isize - 1
        {
            OK
        } else {
            (*$context).error = YamlMemoryError;
            FAIL
        }
    };
}

/// Pushes a value onto the stack.
///
/// This macro pushes a value onto the stack. If the stack is full, it extends the stack by allocating
/// additional memory.
///
/// # Parameters
///
/// * `stack`: A mutable reference to the stack onto which the value will be pushed.
/// * `value`: The value to be pushed onto the stack.
///
/// # Return
///
/// This macro does not return a value. It pushes the value onto the stack.
#[macro_export]
macro_rules! PUSH {
    (do $stack:expr, $push:expr) => {{
        if $stack.top == $stack.end {
            yaml_stack_extend(
                addr_of_mut!($stack.start) as *mut *mut libc::c_void,
                addr_of_mut!($stack.top) as *mut *mut libc::c_void,
                addr_of_mut!($stack.end) as *mut *mut libc::c_void,
            );
        }
        $push;
        $stack.top = $stack.top.wrapping_offset(1);
    }};
    ($stack:expr, *$value:expr) => {
        PUSH!(do $stack, ptr::copy_nonoverlapping($value, $stack.top, 1))
    };
    ($stack:expr, $value:expr) => {
        PUSH!(do $stack, ptr::write($stack.top, $value))
    };
}

/// Removes and returns the last element from the stack.
///
/// # Parameters
///
/// * `stack`: A mutable reference to the stack from which the last element will be removed.
///
/// # Return
///
/// * The last element from the stack.
#[macro_export]
macro_rules! POP {
    ($stack:expr) => {
        *{
            $stack.top = $stack.top.offset(-1);
            $stack.top
        }
    };
}

// ------------------------------------
// Queue Management Macros
// ------------------------------------

/// Initializes a queue with a specified type and allocates memory for it.
///
/// # Parameters
///
/// * `queue`: A mutable reference to the queue to be initialized.
/// * `type`: The type of elements that will be stored in the queue.
///
/// # Return
///
/// This function does not return a value. It initializes the queue with the given type and allocates memory for it.
#[macro_export]
macro_rules! QUEUE_INIT {
    ($queue:expr, $type:ty) => {{
        $queue.start =
            yaml_malloc(16 * size_of::<$type>() as libc::c_ulong)
                as *mut $type;
        $queue.tail = $queue.start;
        $queue.head = $queue.tail;
        $queue.end = $queue.start.offset(16_isize);
    }};
}

/// Deallocates the memory used by the queue and sets all pointers to null.
///
/// # Parameters
///
/// * `queue`: A mutable reference to the queue to be deallocated.
///
/// # Return
///
/// This function does not return a value.
#[macro_export]
macro_rules! QUEUE_DEL {
    ($queue:expr) => {
        yaml_free($queue.start as *mut libc::c_void);
        $queue.end = ptr::null_mut();
        $queue.tail = ptr::null_mut();
        $queue.head = ptr::null_mut();
        $queue.start = ptr::null_mut();
    };
}

/// Checks if the queue is empty.
///
/// # Parameters
///
/// * `queue`: A mutable reference to the queue to be checked.
///
/// # Return
///
/// * `true` if the queue is empty, i.e., the head and tail pointers are equal.
/// * `false` if the queue is not empty, i.e., the head and tail pointers are not equal.
#[macro_export]
macro_rules! QUEUE_EMPTY {
    ($queue:expr) => {
        $queue.head == $queue.tail
    };
}

/// Enqueues a value onto the queue.
///
/// This macro enqueues a value onto the queue. If the queue is full, it extends the queue by allocating additional memory.
///
/// # Parameters
///
/// * `queue`: A mutable reference to the queue onto which the value will be enqueued.
/// * `value`: The value to be enqueued onto the queue. This can be a reference or a direct value.
///
/// # Return
///
/// This macro does not return a value. It enqueues the value onto the queue.
#[macro_export]
macro_rules! ENQUEUE {
    (do $queue:expr, $enqueue:expr) => {{
        if $queue.tail == $queue.end {
            yaml_queue_extend(
                addr_of_mut!($queue.start) as *mut *mut libc::c_void,
                addr_of_mut!($queue.head) as *mut *mut libc::c_void,
                addr_of_mut!($queue.tail) as *mut *mut libc::c_void,
                addr_of_mut!($queue.end) as *mut *mut libc::c_void,
            );
        }
        $enqueue;
        $queue.tail = $queue.tail.wrapping_offset(1);
    }};
    ($queue:expr, *$value:expr) => {
        ENQUEUE!(do $queue, ptr::copy_nonoverlapping($value, $queue.tail, 1))
    };
    ($queue:expr, $value:expr) => {
        ENQUEUE!(do $queue, ptr::write($queue.tail, $value))
    };
}

/// Removes and returns the first element from the queue.
///
/// # Parameters
///
/// * `queue`: A mutable reference to the queue from which the first element will be removed.
///
/// # Return
///
/// * The first element from the queue.
#[macro_export]
macro_rules! DEQUEUE {
    ($queue:expr) => {
        *{
            let head = $queue.head;
            $queue.head = $queue.head.wrapping_offset(1);
            head
        }
    };
}

/// Inserts a value into the queue at the specified index.
///
/// # Parameters
///
/// * `queue`: A mutable reference to the queue where the value will be inserted.
/// * `index`: The index at which the value will be inserted.
/// * `value`: The value to be inserted into the queue.
///
/// # Return
///
/// This macro does not return a value.
#[macro_export]
macro_rules! QUEUE_INSERT {
    ($queue:expr, $index:expr, $value:expr) => {{
        if $queue.tail == $queue.end {
            yaml_queue_extend(
                addr_of_mut!($queue.start) as *mut *mut libc::c_void,
                addr_of_mut!($queue.head) as *mut *mut libc::c_void,
                addr_of_mut!($queue.tail) as *mut *mut libc::c_void,
                addr_of_mut!($queue.end) as *mut *mut libc::c_void,
            );
        }
        let _ = memmove(
            $queue
                .head
                .wrapping_offset($index as isize)
                .wrapping_offset(1_isize)
                as *mut libc::c_void,
            $queue.head.wrapping_offset($index as isize)
                as *const libc::c_void,
            ($queue.tail.c_offset_from($queue.head) as libc::c_ulong)
                .wrapping_sub($index)
                .wrapping_mul(size_of::<YamlTokenT>() as libc::c_ulong),
        );
        *$queue.head.wrapping_offset($index as isize) = $value;
        let fresh14 = addr_of_mut!($queue.tail);
        *fresh14 = (*fresh14).wrapping_offset(1);
    }};
}
