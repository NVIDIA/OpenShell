use std::{
    fmt::{self, Debug, Display, Write as _},
    marker::PhantomData,
    ptr::NonNull,
    slice, str,
};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
/// A custom error type for CStr operations.
///
/// This struct represents an error that occurs during CStr operations.
///
/// # Implementations
///
/// This struct implements the `Display` and `std::error::Error` traits, which allows it to be printed and used as an error type.
///
///
pub struct CStrError;

impl Display for CStrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CStr error occurred")
    }
}

impl std::error::Error for CStrError {}

#[derive(Copy, Clone)]
/// Struct representing a C string.
pub struct CStr<'a> {
    ptr: NonNull<u8>,
    marker: PhantomData<&'a [u8]>,
}

unsafe impl Send for CStr<'_> {}
unsafe impl Sync for CStr<'_> {}

impl<'a> CStr<'a> {
    /// Creates a new `CStr` instance from a static byte slice that is null-terminated.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A static byte slice that must be null-terminated.
    ///
    /// # Returns
    ///
    /// A new `CStr` instance representing the input byte slice.
    ///
    /// # Errors
    ///
    /// This method will return a `CStrError` if the input `bytes` slice does not have a null terminator.
    pub fn from_bytes_with_nul(
        bytes: &'static [u8],
    ) -> Result<Self, CStrError> {
        if bytes.is_empty() {
            return Err(CStrError);
        }

        if bytes.last() != Some(&b'\0') {
            return Err(CStrError);
        }

        let ptr = NonNull::from(bytes).cast();
        Ok(Self::from_ptr(ptr))
    }

    /// Creates a new `CStr` instance from a `NonNull<i8>` raw pointer.
    ///
    /// # Arguments
    ///
    /// * `ptr` - A `NonNull<i8>` raw pointer to the null-terminated C-style string.
    ///
    /// # Returns
    ///
    /// A new `CStr` instance representing the input pointer.
    pub fn from_ptr(ptr: NonNull<i8>) -> Self {
        CStr {
            // Cast the input pointer to a `NonNull<u8>` pointer
            ptr: ptr.cast(),
            // Create a `PhantomData` marker to maintain the lifetime 'a
            marker: PhantomData,
        }
    }

    /// Calculates the length of the C-style string represented by the `CStr` instance.
    ///
    /// # Returns
    ///
    /// The length of the C-style string, not including the null terminator.
    pub fn len(self) -> usize {
        let start = self.ptr.as_ptr();
        let mut end = start;

        // Iterate over the C-style string until the null terminator is found
        while unsafe { *end != 0 } {
            end = unsafe { end.add(1) };
        }

        // Calculate the length of the C-style string, but only if the input is not empty
        if end != start {
            unsafe { end.offset_from(start) as usize }
        } else {
            0
        }
    }

    /// Checks if the C-style string represented by the `CStr` instance is empty.
    ///
    /// # Returns
    ///
    /// `true` if the C-style string is empty, `false` otherwise.
    pub fn is_empty(self) -> bool {
        self.len() == 0
    }

    /// Retrieves a reference to the underlying byte slice of the `CStr` instance.
    ///
    /// # Returns
    ///
    /// A borrowed reference to the byte slice represented by the `CStr` instance.
    pub fn to_bytes(self) -> &'a [u8] {
        let len = self.len();
        unsafe { slice::from_raw_parts(self.ptr.as_ptr(), len) }
    }
}

impl Display for CStr<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ptr = self.ptr.as_ptr();
        let len = self.len();
        let bytes = unsafe { slice::from_raw_parts(ptr, len) };
        display_lossy(bytes, formatter)
    }
}

impl Debug for CStr<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ptr = self.ptr.as_ptr();
        let len = self.len();
        let bytes = unsafe { slice::from_raw_parts(ptr, len) };
        debug_lossy(bytes, formatter)
    }
}

fn display_lossy(
    mut bytes: &[u8],
    formatter: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    loop {
        match str::from_utf8(bytes) {
            Ok(valid) => return formatter.write_str(valid),
            Err(utf8_error) => {
                let valid_up_to = utf8_error.valid_up_to();
                let valid = unsafe {
                    str::from_utf8_unchecked(&bytes[..valid_up_to])
                };
                formatter.write_str(valid)?;
                formatter.write_char(char::REPLACEMENT_CHARACTER)?;
                if let Some(error_len) = utf8_error.error_len() {
                    bytes = &bytes[valid_up_to + error_len..];
                } else {
                    return Ok(());
                }
            }
        }
    }
}

/// Debugs a C string by printing it in a format that can be used in debugging output.
///
/// # Arguments
///
/// * `bytes` - A reference to the byte slice that represents the C string.
/// * `formatter` - A mutable reference to the formatter where the debugged string will be written.
///
/// # Returns
///
/// A `Result` indicating whether the debugging was successful.
///
/// # Panics
///
/// This method will panic if the input `bytes` slice does not have a null terminator.
pub fn debug_lossy(
    mut bytes: &[u8],
    formatter: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    formatter.write_char('"')?;

    while !bytes.is_empty() {
        let from_utf8_result = str::from_utf8(bytes);
        let valid = match from_utf8_result {
            Ok(valid) => valid,
            Err(utf8_error) => {
                let valid_up_to = utf8_error.valid_up_to();
                unsafe {
                    str::from_utf8_unchecked(&bytes[..valid_up_to])
                }
            }
        };

        let mut written = 0;
        for (i, ch) in valid.char_indices() {
            let esc = ch.escape_debug();
            if esc.len() != 1 && ch != '\'' {
                formatter.write_str(&valid[written..i])?;
                for ch in esc {
                    formatter.write_char(ch)?;
                }
                written = i + ch.len_utf8();
            }
        }
        formatter.write_str(&valid[written..])?;

        match from_utf8_result {
            Ok(_valid) => break,
            Err(utf8_error) => {
                let end_of_broken =
                    if let Some(error_len) = utf8_error.error_len() {
                        valid.len() + error_len
                    } else {
                        bytes.len()
                    };
                for b in &bytes[valid.len()..end_of_broken] {
                    write!(formatter, "\\x{:02x}", b)?;
                }
                bytes = &bytes[end_of_broken..];
            }
        }
    }

    formatter.write_char('"')
}
